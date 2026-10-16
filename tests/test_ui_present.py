"""Runs the presentation rules' JavaScript unit tests (tests/ui/present.test.mjs) under Node.

The fixtures come from the real API over a seeded Null Meridian world: identity resolver
entries (a SID, two different AD groups that share a name, an unknown id), people of both
statuses, and an access route. So "common name first, raw id kept, unresolved shown" is proven
against what the server returns. Like tests/test_ui_assess.py, this fails without Node.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.api_fixtures import VIEWER, World

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
V = "/api/v1"


def present_fixtures() -> dict:
    world = World(dataset="null-meridian")
    try:
        client = world.client(VIEWER)
        get = lambda path: client.get(V + path).json  # noqa: E731
        named = [g for g in get("/directory-groups?q=finance-rw")["items"] if g["source"] == "AD"]
        details = [get(f"/directory-groups/{g['id']}")["group"] for g in named]
        all_staff = get(f"/directory-groups/{get('/directory-groups?q=all-staff')['items'][0]['id']}")["group"]
        unknown = "adg_" + "0" * 32
        refs = [all_staff["adSid"], *(d["adEvidenceId"] for d in details), unknown]
        person = get("/people?department=finance&status=ACTIVE&limit=1")["items"][0]
        access = get(f"/people/{person['id']}")["access"]
        return {
            "identities": get("/identities?ids=" + ",".join(refs))["items"],
            "allStaff": all_staff, "financeRw": details, "unknown": unknown,
            "active": get("/people?status=ACTIVE&limit=1")["items"][0],
            "deactivated": get("/people?status=TERMINATED&sort=terminationDate&order=desc&limit=1")["items"][0],
            "route": next(r for a in access for r in a["routes"] if len(r["chain"]) > 1),
        }
    finally:
        world.close()


class UiPresentJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "present-fixtures.json"
            fixtures.write_text(json.dumps(present_fixtures()), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_PRESENT_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "present.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped|cancelled) (\d+)\b", output)}
        self.assertGreaterEqual(counts.get("tests", 0), 12, output)
        self.assertEqual((counts.get("fail"), counts.get("skipped"), counts.get("cancelled")), (0, 0, 0), output)
        self.assertEqual(counts.get("pass"), counts.get("tests"), output)


if __name__ == "__main__":
    unittest.main()
