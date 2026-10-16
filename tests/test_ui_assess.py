"""Runs the UI's JavaScript unit tests (tests/ui/*.test.mjs) under Node's built-in runner.

The fixtures are produced here, by the real API over a freshly seeded synthetic world, so
the UI's wording is tested against what the server actually returns. Node is used only as
a local test runner (no packages, no network). These tests are part of the standard check
(owner decision): without Node this test fails rather than skips.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.api_fixtures import AUTOMATION, EXECUTOR, SECURITY, VIEWER, World

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
V = "/api/v1"
PRINCIPALS = {"VIEWER": VIEWER, "AUTOMATION": AUTOMATION, "SECURITY": SECURITY, "EXECUTOR": EXECUTOR}


def build_fixtures() -> dict:
    world = World()
    try:
        clients = {name: world.client(subject) for name, subject in PRINCIPALS.items()}
        reader = clients["SECURITY"]
        scenarios = {}
        for scenario in world.summary.scenarios:
            cid = scenario.candidate_id
            scenarios[scenario.key] = {
                "detail": {name: client.get(f"{V}/candidates/{cid}").json for name, client in clients.items()},
                "evidence": reader.get(f"{V}/candidates/{cid}/evidence").json,
                "approvals": reader.get(f"{V}/candidates/{cid}/approvals").json["items"],
                "jobs": reader.get(f"{V}/candidates/{cid}/execution-jobs").json["items"],
            }
        return {"scenarios": scenarios}
    finally:
        world.close()


class UiAssessJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "assess-fixtures.json"
            fixtures.write_text(json.dumps(build_fixtures()), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_ASSESS_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "assess.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertGreaterEqual(counts.get("tests", 0), 19, output)
        self.assertEqual((counts.get("fail"), counts.get("skipped"), counts.get("cancelled")), (0, 0, 0), output)
        self.assertEqual(counts.get("pass"), counts.get("tests"), output)


if __name__ == "__main__":
    unittest.main()
