import http.server
import json
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from app.core.errors import NetworkPolicyError
from app.core.http_client import (
    HttpPolicy,
    HttpResponse,
    RateLimitedError,
    ReadOnlyHttpClient,
    StdlibTransport,
    TransportError,
)
from app.core.modes import ExecutionMode
from tests.fakes import SYNTHETIC_OKTA_HOST, SYNTHETIC_OKTA_URL, FakeTransport, RecordingSleep, captured_logs

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _client(transport, *, mode=ExecutionMode.READ_ONLY_PRODUCTION, hosts=(SYNTHETIC_OKTA_HOST,), policy=None, sleep=None, rng=lambda: 0.5):
    return ReadOnlyHttpClient(
        mode=mode,
        http_policy=policy or HttpPolicy(),
        allowed_hosts=hosts,
        transport=transport,
        sleep=sleep or RecordingSleep(),
        rng=rng,
        now=lambda: FIXED_NOW,
    )


class HttpPolicyDefaultsTests(unittest.TestCase):
    def test_defaults_are_bounded_and_conservative(self):
        policy = HttpPolicy()
        self.assertLessEqual(policy.connect_timeout, 10)
        self.assertLessEqual(policy.read_timeout, 60)
        self.assertLessEqual(policy.max_concurrency, 2)
        self.assertTrue(policy.user_agent.startswith("OGWA/"))

    def test_out_of_range_values_are_rejected(self):
        for kwargs in (
            {"connect_timeout": 0},
            {"read_timeout": 600},
            {"max_concurrency": 16},
            {"max_retries": 10},
            {"max_retry_after": 3600},
            {"backoff_base": 0},
            {"user_agent": " "},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                HttpPolicy(**kwargs)

    def test_backoff_is_jittered_exponential_and_capped(self):
        policy = HttpPolicy(backoff_base=1.0, backoff_cap=8.0)
        self.assertEqual([policy.backoff_delay(i, lambda: 1.0) for i in range(5)], [1.0, 2.0, 4.0, 8.0, 8.0])
        self.assertEqual(policy.backoff_delay(2, lambda: 0.25), 1.0)
        self.assertEqual(policy.backoff_delay(2, lambda: 0.0), 0.0)


class RequestBehaviourTests(unittest.TestCase):
    def test_sends_user_agent_and_timeouts(self):
        transport = FakeTransport(HttpResponse(200))
        _client(transport).get(f"{SYNTHETIC_OKTA_URL}/api/v1/apps", headers={"User-Agent": "spoofed"})
        call = transport.calls[0]
        self.assertTrue(call["headers"]["User-Agent"].startswith("OGWA/"))
        self.assertEqual(call["connect_timeout"], HttpPolicy().connect_timeout)
        self.assertEqual(call["read_timeout"], HttpPolicy().read_timeout)

    def test_retries_transient_status_with_backoff(self):
        sleep = RecordingSleep()
        transport = FakeTransport(HttpResponse(503), HttpResponse(200))
        response = _client(transport, sleep=sleep).get(f"{SYNTHETIC_OKTA_URL}/x")
        self.assertEqual(response.status, 200)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(sleep.delays, [0.5 * HttpPolicy().backoff_base])

    def test_respects_retry_after_seconds(self):
        sleep = RecordingSleep()
        transport = FakeTransport(HttpResponse(429, {"Retry-After": "7"}), HttpResponse(200))
        _client(transport, sleep=sleep).get(f"{SYNTHETIC_OKTA_URL}/x")
        self.assertEqual(sleep.delays, [7.0])

    def test_respects_retry_after_http_date(self):
        sleep = RecordingSleep()
        when = format_datetime(FIXED_NOW + timedelta(seconds=12), usegmt=True)
        transport = FakeTransport(HttpResponse(429, {"Retry-After": when}), HttpResponse(200))
        _client(transport, sleep=sleep).get(f"{SYNTHETIC_OKTA_URL}/x")
        self.assertEqual(sleep.delays, [12.0])

    def test_non_ascii_digit_retry_after_is_unparseable_and_backs_off(self):
        for value in ("\u00b2", "\u0665"):  # superscript two; Arabic-Indic five
            with self.subTest(value=value):
                sleep = RecordingSleep()
                transport = FakeTransport(HttpResponse(429, {"Retry-After": value}), HttpResponse(200))
                self.assertEqual(_client(transport, sleep=sleep).get(f"{SYNTHETIC_OKTA_URL}/x").status, 200)
                self.assertEqual(sleep.delays, [0.5 * HttpPolicy().backoff_base])

    def test_excessive_retry_after_fails_instead_of_waiting(self):
        sleep = RecordingSleep()
        transport = FakeTransport(HttpResponse(429, {"Retry-After": "3600"}))
        with self.assertRaises(RateLimitedError):
            _client(transport, sleep=sleep).get(f"{SYNTHETIC_OKTA_URL}/x")
        self.assertEqual(sleep.delays, [])
        self.assertEqual(len(transport.calls), 1)

    def test_returns_last_response_when_retries_exhausted(self):
        policy = HttpPolicy(max_retries=2)
        transport = FakeTransport(HttpResponse(503), HttpResponse(503), HttpResponse(503))
        response = _client(transport, policy=policy).get(f"{SYNTHETIC_OKTA_URL}/x")
        self.assertEqual(response.status, 503)
        self.assertEqual(len(transport.calls), 3)

    def test_transport_errors_are_retried_then_raised(self):
        policy = HttpPolicy(max_retries=1)
        transport = FakeTransport(TransportError("timeout"), TransportError("timeout"))
        with captured_logs() as logs, self.assertRaises(TransportError):
            _client(transport, policy=policy).get(f"{SYNTHETIC_OKTA_URL}/x")
        self.assertEqual(len(transport.calls), 2)
        self.assertIn("http.transport_error", logs.getvalue())

    def test_client_errors_are_not_retried(self):
        for status in (400, 401, 403, 404, 500):
            transport = FakeTransport(HttpResponse(status))
            with self.subTest(status=status):
                self.assertEqual(_client(transport).get(f"{SYNTHETIC_OKTA_URL}/x").status, status)
                self.assertEqual(len(transport.calls), 1)

    def test_concurrency_is_limited(self):
        lock = threading.Lock()
        state = {"active": 0, "peak": 0}

        class SlowTransport:
            def send(self, *args, **kwargs):
                with lock:
                    state["active"] += 1
                    state["peak"] = max(state["peak"], state["active"])
                time.sleep(0.05)
                with lock:
                    state["active"] -= 1
                return HttpResponse(200)

        client = _client(SlowTransport(), policy=HttpPolicy(max_concurrency=2))
        threads = [threading.Thread(target=client.get, args=(f"{SYNTHETIC_OKTA_URL}/x",)) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertLessEqual(state["peak"], 2)


class DestinationPolicyTests(unittest.TestCase):
    def test_synthetic_mode_cannot_reach_non_loopback_hosts(self):
        with self.assertRaises(NetworkPolicyError):
            _client(FakeTransport(), mode=ExecutionMode.LOCAL_SYNTHETIC)
        client = _client(FakeTransport(), mode=ExecutionMode.LOCAL_SYNTHETIC, hosts=("127.0.0.1",))
        with self.assertRaises(NetworkPolicyError):
            client.get(f"{SYNTHETIC_OKTA_URL}/x")

    def test_rejects_unlisted_host_plain_http_and_embedded_credentials(self):
        transport = FakeTransport()
        client = _client(transport)
        for url in (
            "https://other.synthetic.example/x",
            "http://okta.synthetic.example/x",
            "https://user:pw@okta.synthetic.example/x",
            "/relative/path",
        ):
            with self.subTest(url=url), self.assertRaises(NetworkPolicyError):
                client.get(url)
        self.assertEqual(transport.calls, [])

    def test_requires_explicit_allowlist(self):
        with self.assertRaises(NetworkPolicyError):
            _client(FakeTransport(), hosts=())


class LoggingTests(unittest.TestCase):
    def test_logs_are_structured_and_omit_headers_and_query(self):
        transport = FakeTransport(HttpResponse(200))
        with captured_logs() as logs:
            _client(transport).get(
                f"{SYNTHETIC_OKTA_URL}/api/v1/apps?filter=synthetic-query-marker",
                headers={"Authorization": "SSWS synthetic-header-marker"},
            )
        output = logs.getvalue()
        record = json.loads(output.splitlines()[0])
        self.assertEqual(record["msg"], "http.response")
        self.assertEqual(record["fields"]["host"], SYNTHETIC_OKTA_HOST)
        self.assertEqual(record["fields"]["path"], "/api/v1/apps")
        self.assertEqual(record["fields"]["status"], 200)
        self.assertNotIn("synthetic-query-marker", output)
        self.assertNotIn("synthetic-header-marker", output)


class _LoopbackHandler(http.server.BaseHTTPRequestHandler):
    seen_user_agents: list[str] = []

    def do_GET(self):
        type(self).seen_user_agents.append(self.headers.get("User-Agent", ""))
        if self.path.startswith("/slow"):
            time.sleep(0.6)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except ConnectionError:
            pass  # the client deliberately gave up (timeout / size-cap tests)

    def log_message(self, *args):
        pass


class StdlibTransportLoopbackTests(unittest.TestCase):
    """Exercises the real transport against a throwaway server on 127.0.0.1 only."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
        cls.server.daemon_threads = True
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_over_loopback(self):
        client = ReadOnlyHttpClient(
            mode=ExecutionMode.LOCAL_SYNTHETIC, http_policy=HttpPolicy(), allowed_hosts=["127.0.0.1"]
        )
        response = client.get(f"{self.base}/ok")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body), {"ok": True})
        self.assertTrue(_LoopbackHandler.seen_user_agents[-1].startswith("OGWA/"))

    def test_read_timeout_is_enforced(self):
        with self.assertRaises(TransportError):
            StdlibTransport().send(
                "GET", f"{self.base}/slow", {}, None, connect_timeout=1.0, read_timeout=0.2, max_response_bytes=1024
            )

    def test_response_size_is_capped(self):
        with self.assertRaises(TransportError):
            StdlibTransport().send(
                "GET", f"{self.base}/ok", {}, None, connect_timeout=1.0, read_timeout=1.0, max_response_bytes=4
            )


if __name__ == "__main__":
    unittest.main()
