"""Runs the policy-version UI tests (tests/ui/policy.test.mjs) under Node's built-in runner (OGWA-DEMO-02).

The fixtures are what the real API returns over a freshly seeded Null Meridian store: every
candidate's detail (with its decision explanation), NM-C08's decision and approval history (judged
by NM-LIFECYCLE-004 v1.1.0, while v1.2.0 is in force), and the policy view. The classic world adds
one candidate under the unrecorded demo policy. Synthetic data only; Node is a local test runner
(no packages, no network).
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.api_fixtures import SECURITY, World

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
V = "/api/v1"


def build_fixtures() -> dict:
    out: dict = {}
    world = World(dataset="null-meridian")
    try:
        client = world.client(SECURITY)
        out["nullMeridian"] = {s.key: client.get(f"{V}/candidates/{s.candidate_id}").json
                               for s in world.summary.scenarios if s.candidate_id}
        c08 = world.candidate("NM-C08")
        out["decisionsNM_C08"] = client.get(f"{V}/candidates/{c08}/decisions").json["items"]
        out["approvalsNM_C08"] = client.get(f"{V}/candidates/{c08}/approvals").json["items"]
        out["policy"] = client.get(f"{V}/policy").json
    finally:
        world.close()
    classic = World()
    try:
        client = classic.client(SECURITY)
        first = classic.summary.scenarios[0].candidate_id
        out["classic"] = {"detail": client.get(f"{V}/candidates/{first}").json,
                          "decisions": client.get(f"{V}/candidates/{first}/decisions").json["items"]}
    finally:
        classic.close()
    return out


class UiPolicyJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "policy-fixtures.json"
            fixtures.write_text(json.dumps(build_fixtures()), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_POLICY_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "policy.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertGreaterEqual(counts.get("tests", 0), 8, output)
        self.assertEqual((counts.get("fail"), counts.get("skipped"), counts.get("cancelled")), (0, 0, 0), output)
        self.assertEqual(counts.get("pass"), counts.get("tests"), output)


if __name__ == "__main__":
    unittest.main()
