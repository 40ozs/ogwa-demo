"""Guards on the browser gate itself (owner decisions after P09). Runs in the standard check.

The browser suite (tests/browser, scripts/browser-check.ps1) is a required pre-pilot and
pre-release gate wherever a supported browser is available. These tests keep it honest
without starting a browser: its external-host blocking, its clean-page and CSP assertions,
and the gate's refusal to pass with skipped tests or without a browser must not be removed.
"""

import os
import re
import unittest
from pathlib import Path
from unittest import mock

from tests.browser import harness

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = (REPO / "tests" / "browser" / "test_operator_workflows.py").read_text(encoding="utf-8")
HARNESS = (REPO / "tests" / "browser" / "harness.py").read_text(encoding="utf-8")
GATE = (REPO / "scripts" / "browser-check.ps1").read_text(encoding="utf-8")
BROWSER_MODULES = sorted((REPO / "tests" / "browser").glob("test_*.py"))


class ExternalHostBlockingTests(unittest.TestCase):
    def test_every_host_but_loopback_is_unresolvable(self):
        self.assertIn("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1", harness.BROWSER_FLAGS)
        rules = [f for f in harness.BROWSER_FLAGS if f.startswith("--host-resolver-rules")]
        self.assertEqual(len(rules), 1, "exactly one resolver rule, and it is the lockdown")

    def test_a_target_only_makes_its_own_host_resolvable(self):
        # UI_BROWSER_TARGET (the Cloudflare Worker) adds exactly that one host to the lockdown.
        with mock.patch.dict("os.environ", {harness.TARGET_VAR: "https://ogwa-demo.example.workers.dev"}):
            rules = [f for f in harness.browser_flags() if f.startswith("--host-resolver-rules")]
            self.assertEqual(rules, ["--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1 , "
                                     "EXCLUDE ogwa-demo.example.workers.dev"])
            self.assertEqual(set(harness.browser_flags()) - set(rules), set(harness.BROWSER_FLAGS) - {
                "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"})
        with mock.patch.dict("os.environ", {harness.TARGET_VAR: "http://127.0.0.1:8787"}):
            self.assertEqual(harness.browser_flags(), harness.BROWSER_FLAGS)
        with mock.patch.dict("os.environ"):
            os.environ.pop(harness.TARGET_VAR, None)
            self.assertEqual(harness.browser_flags(), harness.BROWSER_FLAGS)
        for bad in ("https://host.example/path", "ftp://host.example", "https://user:pw@host.example", "host.example"):
            with mock.patch.dict("os.environ", {harness.TARGET_VAR: bad}), self.assertRaises(ValueError):
                harness.target()
        self.assertIn("*browser_flags()", HARNESS, "the browser is launched with the lockdown flags")

    def test_the_browser_runs_isolated(self):
        for flag in ("--headless=new", "--disable-background-networking", "--disable-component-update", "--disable-sync",
                     "--disable-extensions", "--no-first-run", "--no-pings"):
            with self.subTest(flag=flag):
                self.assertIn(flag, harness.BROWSER_FLAGS)
        for loosening in ("--remote-allow-origins", "--proxy-server", "--proxy-bypass", "--disable-web-security",
                          "--allow-running-insecure-content", "--ignore-certificate-errors"):
            with self.subTest(loosening=loosening):
                self.assertFalse(any(f.startswith(loosening) for f in harness.BROWSER_FLAGS))
        self.assertIn('tempfile.mkdtemp(prefix="ogwa-ui-browser-")', HARNESS, "a throw-away profile")
        self.assertIn("shutil.rmtree(self.profile", HARNESS, "deleted afterwards")

    def test_the_devtools_client_only_speaks_to_loopback(self):
        cdp = (REPO / "tests" / "browser" / "cdp.py").read_text(encoding="utf-8")
        self.assertIn('parsed.hostname not in ("127.0.0.1", "localhost")', cdp)

    def test_the_server_under_test_is_synthetic_and_never_var(self):
        # The classic world, or (for the Null Meridian views) the Null Meridian world; both in memory.
        self.assertIn("world = World(dataset=self.dataset)", HARNESS)
        self.assertIn('dataset: str = "classic"', HARNESS)
        fixtures = (Path(__file__).resolve().parent / "api_fixtures.py").read_text(encoding="utf-8")
        self.assertEqual(fixtures.count("(memory_target(), clock=self.clock)"), 2)
        self.assertNotRegex(HARNESS, r"var[/\\]ogwa|Store\.open")
        # The demo runtime (DemoServer) needs a demo store file. Its one database URL names a file
        # in its own throw-away directory, reset there by the demo reset and deleted afterwards.
        self.assertEqual(HARNESS.count("OGWA_DATABASE_URL"), 1)
        for needle in ('self.tmp = Path(tempfile.mkdtemp(prefix="ogwa-ui-demo-"))', 'root = self.tmp / "var"',
                       "\"OGWA_DATABASE_URL\": f\"sqlite:///{(root / 'ogwa-demo.sqlite3').as_posix()}\"",
                       "allowed_root=root", "shutil.rmtree(self.tmp, ignore_errors=True)",
                       'if not k.upper().startswith("OGWA_")'):
            with self.subTest(needle=needle):
                self.assertIn(needle, HARNESS)


class CleanPageAssertionTests(unittest.TestCase):
    def test_each_suite_ends_by_checking_origin_and_problems(self):
        classes = re.findall(r"^class (\w+)\(BrowserCase\):", WORKFLOWS, re.M)
        self.assertEqual(len(classes), 2)
        self.assertEqual(WORKFLOWS.count("def test_z_nothing_left_the_origin_and_nothing_failed(self):\n        self.assert_clean()"),
                         len(classes))
        for module in BROWSER_MODULES:
            text = module.read_text(encoding="utf-8")
            with self.subTest(module=module.name):
                classes = re.findall(r"^class (\w+)\(BrowserCase\):", text, re.M)
                self.assertEqual(text.count("def test_z_nothing_left_the_origin_and_nothing_failed(self):\n"
                                            "        self.assert_clean()"), len(classes))

    def test_assert_clean_checks_foreign_requests_and_page_problems(self):
        body = re.search(r"def assert_clean\(self\) -> None:\n(.*?)\n\n", WORKFLOWS, re.S).group(1)
        self.assertIn("requested_urls()", body)
        self.assertIn("self.assertEqual(foreign, [],", body)
        self.assertIn("self.assertEqual(self.browser.problems(), [],", body)

    def test_problems_covers_exceptions_console_errors_csp_and_5xx(self):
        body = re.search(r"def problems\(self\) -> list\[str\]:\n(.*?)\n    def ", HARNESS, re.S).group(1)
        for needle in ('"Runtime.exceptionThrown"', '"Runtime.consoleAPICalled"', '("error", "assert")',
                       '"Log.entryAdded"', '>= 500'):
            with self.subTest(needle=needle):
                self.assertIn(needle, body)
        # Only 4xx network log noise is set aside, never security (CSP) or javascript entries.
        self.assertIn('params["entry"].get("source") == "network"', body)
        self.assertNotIn('"security"', body)

    def test_the_csp_is_asserted_in_the_real_browser(self):
        self.assertIn('self.assertEqual(b.csp_probe(self.server.origin + "/"),\n'
                      '                         {"innerHTML": "TypeError", "violations": ["img-src", "style-src-attr"]})',
                      WORKFLOWS)


class GateScriptTests(unittest.TestCase):
    def test_the_gate_has_three_distinct_outcomes(self):
        for marker in ("GATE PASSED", "GATE FAILED", "GATE NOT RUN", "$code = 0", "$code = 1", "$code = 2", "exit $code"):
            with self.subTest(marker=marker):
                self.assertIn(marker, GATE)

    def test_skipped_tests_never_pass_the_gate(self):
        self.assertIn("$skipped = [regex]::Matches($text, '\\.\\.\\. skipped').Count", GATE)
        self.assertIn("if ($failed -or $skipped -or $text -notmatch '(?m)^OK\\s*$')", GATE)

    def test_the_gate_runs_every_browser_test_module(self):
        command = re.search(r"python -m unittest ((?:tests\.browser\.\w+ )+)-v", GATE)
        self.assertIsNotNone(command, "the gate's unittest command")
        self.assertEqual(sorted(command.group(1).split()),
                         sorted(f"tests.browser.{m.stem}" for m in BROWSER_MODULES))

    def test_no_early_return_can_skip_the_exit_code(self):
        self.assertIsNone(re.search(r"^\s*return\b", GATE, re.M), "a script-level return would bypass 'exit $code'")


if __name__ == "__main__":
    unittest.main()
