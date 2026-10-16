"""Runs the API client's JavaScript unit tests (tests/ui/api.test.mjs) under Node's built-in runner.

They pin the client's one resend: a POST is sent again only for the public demo's anonymous visitor, only
after a refusal the server makes before any handler runs (``UNAUTHENTICATED``, ``CSRF_FAILED``), and only
once. No network: the tests replace ``fetch``. Like tests/test_ui_assess.py, this fails without Node.
"""

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")


class UiApiJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
        env["NODE_OPTIONS"] = ""
        result = subprocess.run(
            [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "api.test.mjs")],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertEqual((counts.get("tests"), counts.get("pass"), counts.get("skipped")), (7, 7, 0), output)


if __name__ == "__main__":
    unittest.main()
