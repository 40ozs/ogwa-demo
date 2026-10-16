"""Runs the runtime indicator's JavaScript unit tests (tests/ui/runtime.test.mjs) under Node.

The fixtures are the real ``GET /health`` bodies of the demo runtime (over its default
dataset, Null Meridian) and the standard runtime, so "DEMO ENVIRONMENT" is proven to appear
in Demo Mode and not in production from what the servers actually return. Like
tests/test_ui_assess.py, this fails without Node.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.api_fixtures import World
from tests.test_demo_mode import DemoWorld

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")


def health_fixtures(tmp: Path) -> dict:
    demo, standard = DemoWorld(tmp, dataset=None), World()
    try:
        return {"demo": demo.client().get("/api/v1/health").json,
                "production": standard.client().get("/api/v1/health").json}
    finally:
        demo.close()
        standard.close()


class UiRuntimeJavaScriptTests(unittest.TestCase):
    def test_javascript_unit_tests_pass(self):
        self.assertIsNotNone(NODE, "Node.js is required: the UI's JavaScript unit tests are part of the standard check")
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = Path(tmp) / "runtime-fixtures.json"
            bodies = health_fixtures(Path(tmp))
            self.assertEqual((bodies["demo"]["organization"], bodies["demo"]["dataset"]["seed"]),
                             ("Null Meridian", "null-meridian-v1"), "the demo fixture is the canonical dataset")
            fixtures.write_text(json.dumps(bodies), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
            env["UI_RUNTIME_FIXTURES"] = str(fixtures)
            env["NODE_OPTIONS"] = ""
            result = subprocess.run(
                [NODE, "--test", "--test-reporter=spec", str(REPO_ROOT / "tests" / "ui" / "runtime.test.mjs")],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        counts = {name: int(n) for name, n in re.findall(r"\b(tests|pass|fail|skipped) (\d+)\b", output)}
        self.assertEqual((counts.get("tests"), counts.get("pass"), counts.get("skipped")), (5, 5, 0), output)


if __name__ == "__main__":
    unittest.main()
