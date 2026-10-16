"""Runs the evidence-assessment UI tests (tests/ui/evidence.test.mjs) under Node's built-in runner.

The fixtures are what the real API returns for every candidate of both synthetic worlds
(classic and Null Meridian), plus Null Meridian's clean candidate NM-C01 after its unchanged
evidence is re-observed (fresh enough for approval), so the UI's wording is tested against
real server output, including the one path that may be eligible for a human's approval.
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

from tests.api_fixtures import SECURITY, World

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
V = "/api/v1"


def build_fixtures() -> dict:
    out: dict = {}
    for dataset, name in (("classic", "classic"), ("null-meridian", "nullMeridian")):
        world = World(dataset=dataset)
        try:
            client = world.client(SECURITY)
            out[name] = {s.key: client.get(f"{V}/candidates/{s.candidate_id}").json
                         for s in world.summary.scenarios if s.candidate_id}
            if dataset == "null-meridian":
                world.refresh_evidence(world.candidate("NM-C01"))
                out[name]["NM-C01-refreshed"] = client.get(f"{V}/candidates/{world.candidate('NM-C01')}").json
        finally:
            world.close()
    return out


class UiEvidenceJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "evidence-fixtures.json"
            fixtures.write_text(json.dumps(build_fixtures()), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_EVIDENCE_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "evidence.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertGreaterEqual(counts.get("tests", 0), 12, output)
        self.assertEqual((counts.get("fail"), counts.get("skipped"), counts.get("cancelled")), (0, 0, 0), output)
        self.assertEqual(counts.get("pass"), counts.get("tests"), output)


if __name__ == "__main__":
    unittest.main()
