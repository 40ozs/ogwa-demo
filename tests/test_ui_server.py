"""The UI server: same-origin static files beside the API, strict headers, nothing else reachable."""

import io
import tempfile
import unittest
from pathlib import Path

from app.ui.server import STATIC_ROOT, UI_CSP, OgwaWebApp, StaticAssets
from tests.api_fixtures import ApiClient, World

V = "/api/v1"


def call(app, method, path, *, headers=None, body=b""):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "", "SERVER_NAME": "127.0.0.1",
               "SERVER_PORT": "8765", "wsgi.input": io.BytesIO(body), "wsgi.url_scheme": "http"}
    for name, value in (headers or {}).items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    captured = {}

    def start_response(status, response_headers):
        captured["status"] = int(status.split(" ", 1)[0])
        captured["headers"] = {k.lower(): v for k, v in response_headers}

    payload = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], payload


class UiServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()
        cls.app = OgwaWebApp(cls.world.api)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def test_index_and_every_asset_are_served_with_their_type(self):
        status, headers, body = call(self.app, "GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/html; charset=utf-8")
        self.assertIn(b'<script type="module" src="/ui/js/main.js">', body)
        expected = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}
        for path in sorted(self.app.assets.paths - {"/"}):
            with self.subTest(path=path):
                status, headers, body = call(self.app, "GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(headers["content-type"].startswith(expected[Path(path).suffix]))
                self.assertEqual(int(headers["content-length"]), len(body))

    def test_ui_responses_carry_a_strict_policy(self):
        for path in ("/", "/ui/js/main.js", "/nope"):
            with self.subTest(path=path):
                _, headers, _ = call(self.app, "GET", path)
                csp = headers["content-security-policy"]
                self.assertEqual(csp, UI_CSP)
                for directive in ("default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
                                  "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'",
                                  "require-trusted-types-for 'script'"):
                    self.assertIn(directive, csp)
                for weak in ("unsafe-inline", "unsafe-eval", "unsafe-hashes", "data:", "blob:", "*", "http:", "https:"):
                    self.assertNotIn(weak, csp)
                self.assertEqual(headers["x-content-type-options"], "nosniff")
                self.assertEqual(headers["x-frame-options"], "DENY")
                self.assertEqual(headers["cache-control"], "no-store")
                self.assertEqual(headers["referrer-policy"], "no-referrer")
                self.assertNotIn("access-control-allow-origin", headers)

    def test_nothing_outside_the_fixed_file_set_is_reachable(self):
        for path in ("/ui/../server.py", "/ui/%2e%2e/server.py", "/ui/js/../../server.py", "/ui/js/../index.html",
                     "/ui/", "/ui", "/ui/js", "/ui/js/main.js/", "/UI/js/main.js", "/ui\\js\\main.js", "/index.html",
                     "/favicon.ico", "/config/synthetic-idp.json", "/var/ogwa-local.sqlite3", "/app/ui/server.py",
                     "/api/v1x", "/apiv1/health", "//ui/js/main.js", "/ui/js/main.js%00"):
            with self.subTest(path=path):
                status, headers, body = call(self.app, "GET", path)
                self.assertEqual(status, 404)
                self.assertEqual(body, b"Not found.\n")

    def test_only_get_and_head_reach_ui_files(self):
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, _ = call(self.app, method, "/ui/js/main.js")
                self.assertEqual(status, 405)
                self.assertEqual(headers["allow"], "GET, HEAD")
        status, headers, body = call(self.app, "HEAD", "/")
        self.assertEqual((status, body), (200, b""))
        self.assertGreater(int(headers["content-length"]), 0)

    def test_api_requests_reach_the_api_unchanged(self):
        status, headers, body = call(self.app, "GET", f"{V}/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(headers["content-security-policy"], "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        status, _, body = call(self.app, "GET", f"{V}/no-such-thing")
        self.assertEqual(status, 404)
        self.assertIn(b'"NOT_FOUND"', body)
        status, _, body = call(self.app, "GET", f"{V}/dashboard")
        self.assertEqual(status, 401)

    def test_the_api_origin_check_still_applies_through_the_ui_server(self):
        body = b'{"subject": "synthetic.viewer.one"}'
        status, _, payload = call(self.app, "POST", f"{V}/session", body=body, headers={
            "Origin": "http://evil.example", "Content-Type": "application/json", "Content-Length": str(len(body))})
        self.assertEqual(status, 403)
        self.assertIn(b"ORIGIN_REFUSED", payload)

    def test_the_new_listings_are_read_only_and_paged(self):
        client = ApiClient(self.app)
        client.sign_in("synthetic.viewer.one")
        for path in ("/approvals", "/execution-jobs", "/dependency-findings"):
            with self.subTest(path=path):
                result = client.get(f"{V}{path}?limit=2")
                self.assertEqual(result.status, 200, result.json)
                self.assertLessEqual(len(result.json["items"]), 2)
                self.assertIn("nextCursor", result.json["page"])
                self.assertEqual(client.post(f"{V}{path}", {}).status, 405)
        jobs = client.get(f"{V}/execution-jobs?limit=200").json
        self.assertIs(jobs["executionAvailable"], False)
        self.assertTrue(jobs["items"])
        self.assertTrue(all(j["executed"] is False and j["dryRun"] is True for j in jobs["items"]))
        approvals = client.get(f"{V}/approvals?limit=200").json["items"]
        decided = [a["decidedAt"] for a in approvals]
        self.assertEqual(decided, sorted(decided, reverse=True))
        self.assertEqual(len(approvals), self.world.store.connection.execute("SELECT count(*) FROM approvals").fetchone()[0])
        findings = client.get(f"{V}/dependency-findings?limit=200").json["items"]
        self.assertEqual(len(findings), self.world.store.connection.execute(
            "SELECT count(*) FROM dependency_checks").fetchone()[0])
        self.assertTrue(all(f["kind"] == "DEPENDENCY" for f in findings))

    def test_a_file_of_unexpected_type_stops_the_ui_from_building(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text("<!doctype html>", encoding="utf-8")
            (root / "notes.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(ValueError):
                StaticAssets(root)
            (root / "notes.txt").unlink()
            (root / "index.html").unlink()
            with self.assertRaises(ValueError):
                StaticAssets(root)

    def test_the_static_root_is_inside_the_ui_package(self):
        self.assertEqual(STATIC_ROOT.parent.name, "ui")
        self.assertTrue((STATIC_ROOT / "index.html").is_file())


class ServeCommandTests(unittest.TestCase):
    def test_serve_serves_the_ui_beside_the_api(self):
        source = (Path(__file__).resolve().parents[1] / "app" / "api" / "__main__.py").read_text(encoding="utf-8")
        self.assertIn("make_local_server(OgwaWebApp(api), args.port)", source)


if __name__ == "__main__":
    unittest.main()
