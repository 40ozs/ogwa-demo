"""Runs the review presentation's JavaScript unit tests (tests/ui/review.test.mjs) under Node,
and checks that its tables cover every lifecycle state and every governance rule.

OGWA-UI-REVIEW-01. The fixtures come from the real API over a freshly seeded classic world: every
scenario's candidate, decision history, and evidence assessment, the dashboard's counts and server
clock, the dependency checks, and one candidate a person excluded through the API. So the review
statuses, the lifecycle stepper, and the impact wording are tested against what the server returns.
Like tests/test_ui_assess.py, this fails without Node.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.api_fixtures import AUTOMATION, SECURITY, World

REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEW_JS = (REPO_ROOT / "app" / "ui" / "static" / "js" / "review.js").read_text(encoding="utf-8")
NODE = shutil.which("node")
V = "/api/v1"


def review_fixtures() -> dict:
    from app.domain.lifecycle import LifecycleState

    world = World()
    try:
        reader = world.client(SECURITY)
        excluded = world.scenarios["S08"].candidate_id
        result = world.client(AUTOMATION).post(f"{V}/candidates/{excluded}/transitions",
                                               {"target": "EXCLUDED", "reason": "UI review fixture: excluded by a person"})
        assert result.status == 201, result.json
        scenarios = {}
        for scenario in world.summary.scenarios:
            cid = scenario.candidate_id
            detail = reader.get(f"{V}/candidates/{cid}").json
            scenarios[scenario.key] = {
                "candidate": detail["candidate"],
                "assessment": detail["evidenceAssessment"],
                "decisions": reader.get(f"{V}/candidates/{cid}/decisions").json["items"],
            }
        return {
            "states": [s.value for s in LifecycleState],
            "scenarios": scenarios,
            "excluded": "S08",
            "dashboard": reader.get(f"{V}/dashboard").json,
            "candidates": reader.get(f"{V}/candidates?limit=200").json["items"],
            "dependencyChecks": reader.get(f"{V}/dependency-findings?limit=200").json["items"],
            # OGWA-REVIEW-QUEUE-API-01: the server-side queue's rows and the approvals with usability.
            "queue": reader.get(f"{V}/review-queue?status=all&limit=50").json,
            "approvals": reader.get(f"{V}/approvals?limit=200").json["items"],
        }
    finally:
        world.close()


class ReviewTablesCoverTheDomain(unittest.TestCase):
    def test_every_lifecycle_state_has_one_review_status(self):
        from app.domain.lifecycle import LifecycleState

        block = re.search(r"const STATUS_OF = Object\.freeze\(\{(.*?)\}\);", REVIEW_JS, re.S).group(1)
        mapped = re.findall(r"\b([A-Z_]+): \"([a-z-]+)\"", block)
        self.assertEqual(sorted(s for s, _ in mapped), sorted(s.value for s in LifecycleState))
        self.assertEqual(len(mapped), len({s for s, _ in mapped}), "a state is mapped twice")
        # No review status claims that anything is ready: every step forward needs a named
        # person's decision or an observed change, and the server checks it again.
        self.assertNotRegex(REVIEW_JS, r"label: \"Ready")

    def test_every_governance_rule_has_plain_words(self):
        from app.governance.analysis import RULES

        block = re.search(r"export const RULE_LABEL = Object\.freeze\(\{(.*?)\}\);", REVIEW_JS, re.S).group(1)
        self.assertEqual(set(re.findall(r"^  ([A-Z_]+): \"", block, re.M)), set(RULES))


class UiReviewJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "review-fixtures.json"
            fixtures.write_text(json.dumps(review_fixtures()), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_REVIEW_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "review.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertGreaterEqual(counts.get("tests", 0), 15, output)
        self.assertEqual((counts.get("fail"), counts.get("skipped"), counts.get("cancelled")), (0, 0, 0), output)
        self.assertEqual(counts.get("pass"), counts.get("tests"), output)


if __name__ == "__main__":
    unittest.main()
