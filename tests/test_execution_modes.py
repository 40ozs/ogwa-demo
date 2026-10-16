import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from app.core import build
from app.core.config import load_settings
from app.core.errors import ConfigError, ProductionMutationNotPermitted
from app.core.modes import ExecutionMode
from app.core.runtime_mode import DEMO_ONLY_MESSAGE
from app.core.safety import MutationPolicy
from app.core.startup import bootstrap
from tests.fakes import captured_logs

REPO_ROOT = Path(__file__).resolve().parents[1]


class OnlyModeTests(unittest.TestCase):
    def test_the_only_mode_is_local_synthetic(self):
        for environ in ({}, {"OGWA_EXECUTION_MODE": "   "}, {"OGWA_EXECUTION_MODE": " local_synthetic "}):
            with self.subTest(environ=environ):
                self.assertIs(load_settings(environ).mode, ExecutionMode.LOCAL_SYNTHETIC)

    def test_every_other_mode_is_refused_as_demo_only(self):
        for raw in ("READ_ONLY_PRODUCTION", "dry_run_mutation", "PRODUCTION", "READONLY", "LIVE", "1", "true"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError) as caught:
                load_settings({"OGWA_EXECUTION_MODE": raw})
            self.assertIn(DEMO_ONLY_MESSAGE, str(caught.exception))


class ProductionMutationRejectedTests(unittest.TestCase):
    def test_build_does_not_allow_production_mutation(self):
        self.assertFalse(build.BUILD_ALLOWS_PRODUCTION_MUTATION)

    def test_settings_loader_rejects_production_mutation(self):
        for raw in ("PRODUCTION_MUTATION", "production_mutation", " Production_Mutation "):
            with self.subTest(raw=raw), self.assertRaises(ProductionMutationNotPermitted):
                load_settings({"OGWA_EXECUTION_MODE": raw})

    def test_startup_rejects_production_mutation(self):
        with self.assertRaises(ProductionMutationNotPermitted):
            bootstrap({"OGWA_EXECUTION_MODE": "PRODUCTION_MUTATION"})

    def test_override_style_variables_are_rejected(self):
        attempts = (
            "OGWA_ALLOW_PRODUCTION_MUTATION",
            "OGWA_BUILD_ALLOWS_PRODUCTION_MUTATION",
            "OGWA_MUTATION_ENABLED",
            "OGWA_FORCE",
            "ogwa_i_know_what_i_am_doing",
        )
        for key in attempts:
            with self.subTest(key=key), self.assertRaises(ConfigError):
                load_settings({key: "true"})

    def test_mutation_policy_cannot_be_created_for_production_mutation(self):
        with self.assertRaises(ProductionMutationNotPermitted):
            MutationPolicy.for_mode(ExecutionMode.PRODUCTION_MUTATION)

    def test_command_line_refuses_to_start_in_production_mutation(self):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        env["OGWA_EXECUTION_MODE"] = "PRODUCTION_MUTATION"
        result = subprocess.run(
            [sys.executable, "-m", "app"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("startup refused", result.stderr)


class StartupBannerTests(unittest.TestCase):
    def test_banner_shows_the_demo_and_no_live_integration(self):
        with captured_logs() as logs:
            bootstrap({})
        record = json.loads(logs.getvalue().splitlines()[0])
        for part in ("runtime_mode=demo", "execution_mode=LOCAL_SYNTHETIC", "live_integrations=unavailable",
                     "production_mutation_permitted_by_build=false"):
            self.assertIn(part, record["msg"])
        self.assertEqual(record["level"], "INFO")

    def test_command_line_prints_banner_in_default_mode(self):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        result = subprocess.run(
            [sys.executable, "-m", "app"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("execution_mode=LOCAL_SYNTHETIC", result.stderr)


if __name__ == "__main__":
    unittest.main()
