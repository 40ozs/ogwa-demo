"""Runs the remediation-drill UI tests (tests/ui/drill.test.mjs) under Node's built-in runner.

The fixtures are what the real API returns: Null Meridian's NM-C11 dry run and
every catalog scenario, and the classic world's AD deletion under each scenario, plus the
server's scenario catalog. So the UI's wording is tested against real server output.
Synthetic data only; Node is used only as a local test runner (no packages, no network).
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.remediation.synthetic_provider import SCENARIOS
from tests.api_fixtures import EXECUTOR, VIEWER, World
from tests.test_remediation_api import approve_deletion, world
from tests.test_remediation_drill_api import post_drill

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
V = "/api/v1"


def _drills(w: World, candidate: str, approval: str, operation: str) -> dict:
    executor = w.client(EXECUTOR)
    out = {"DRY_RUN": post_drill(w, executor, candidate, approval, operation).json["drill"]}
    for key in SCENARIOS:
        out[key] = post_drill(w, executor, candidate, approval, operation, "SYNTHETIC_EXECUTION", key).json["drill"]
    return out


def build_fixtures() -> dict:
    nm = World(dataset="null-meridian")
    try:
        candidate = nm.candidate("NM-C11")
        approval = nm.client(VIEWER).get(f"{V}/candidates/{candidate}/approvals").json["items"][0]["id"]
        fixtures = {"catalog": nm.client(VIEWER).get(f"{V}/remediation-drill-scenarios").json,
                    "nmC11": _drills(nm, candidate, approval, "OKTA_GROUP_UNASSIGN")}
        # Whole responses (drill, policy, authorization, chain) for the walkthrough's runs.
        executor = nm.client(EXECUTOR)
        fixtures["nmC11Responses"] = {
            "DRY_RUN": post_drill(nm, executor, candidate, approval).json,
            "TIMEOUT_NOT_APPLIED": post_drill(nm, executor, candidate, approval, "OKTA_GROUP_UNASSIGN",
                                              "SYNTHETIC_EXECUTION", "TIMEOUT_NOT_APPLIED").json,
            "ACKNOWLEDGED_NOT_APPLIED": post_drill(nm, executor, candidate, approval, "OKTA_GROUP_UNASSIGN",
                                                   "SYNTHETIC_EXECUTION", "ACKNOWLEDGED_NOT_APPLIED").json}
    finally:
        nm.close()
    classic = world()
    try:
        candidate, approval = approve_deletion(classic)
        fixtures["classicDelete"] = _drills(classic, candidate, approval, "AD_GROUP_DELETE")
    finally:
        classic.close()
    return fixtures


class UiDrillJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "drill-fixtures.json"
            fixtures.write_text(json.dumps(build_fixtures()), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_DRILL_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "drill.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertGreaterEqual(counts.get("tests", 0), 10, output)
        self.assertEqual((counts.get("fail"), counts.get("skipped"), counts.get("cancelled")), (0, 0, 0), output)
        self.assertEqual(counts.get("pass"), counts.get("tests"), output)


if __name__ == "__main__":
    unittest.main()
