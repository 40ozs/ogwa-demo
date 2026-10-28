import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from app.core import build
from app.core.config import load_settings
from app.core.errors import ConfigError, ProductionMutationNotPermitted
from app.core.modes import DEFAULT_MODE, ExecutionMode, parse_mode
from app.core.safety import MutationPolicy
from app.core.startup import bootstrap
from tests.fakes import SYNTHETIC_OKTA_TOKEN, captured_logs, read_only_env

REPO_ROOT = Path(__file__).resolve().parents[1]


class DefaultModeTests(unittest.TestCase):
    def test_default_mode_is_local_synthetic(self):
        self.assertIs(DEFAULT_MODE, ExecutionMode.LOCAL_SYNTHETIC)
        self.assertIs(load_settings({}).mode, ExecutionMode.LOCAL_SYNTHETIC)

    def test_blank_mode_means_default(self):
        self.assertIs(load_settings({"OGWA_EXECUTION_MODE": "   "}).mode, ExecutionMode.LOCAL_SYNTHETIC)

    def test_mode_names_are_trimmed_and_case_insensitive(self):
        self.assertIs(parse_mode("  read_only_production "), ExecutionMode.READ_ONLY_PRODUCTION)

    def test_unknown_mode_fails_closed(self):
        for raw in ("PRODUCTION", "READONLY", "LIVE", "1", "true"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                load_settings({"OGWA_EXECUTION_MODE": raw})

    def test_non_mutating_modes_load(self):
        for mode in ("LOCAL_SYNTHETIC", "READ_ONLY_PRODUCTION", "DRY_RUN_MUTATION"):
            with self.subTest(mode=mode):
                self.assertEqual(load_settings({"OGWA_EXECUTION_MODE": mode}).mode.value, mode)


class ProductionMutationRejectedTests(unittest.TestCase):
    def test_build_does_not_allow_production_mutation(self):
        self.assertFalse(build.BUILD_ALLOWS_PRODUCTION_MUTATION)

    def test_settings_loader_rejects_production_mutation(self):
        for raw in ("PRODUCTION_MUTATION", "production_mutation", " Production_Mutation "):
            with self.subTest(raw=raw), self.assertRaises(ProductionMutationNotPermitted):
                load_settings(read_only_env(OGWA_EXECUTION_MODE=raw))

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
            for mode in ("READ_ONLY_PRODUCTION", "PRODUCTION_MUTATION"):
                with self.subTest(key=key, mode=mode), self.assertRaises(ConfigError):
                    load_settings({"OGWA_EXECUTION_MODE": mode, key: "true"})

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
    def test_banner_shows_active_mode(self):
        with captured_logs() as logs:
            bootstrap({})
        record = json.loads(logs.getvalue().splitlines()[0])
        self.assertIn("execution_mode=LOCAL_SYNTHETIC", record["msg"])
        self.assertIn("production_mutation_permitted_by_build=false", record["msg"])
        self.assertEqual(record["level"], "INFO")

    def test_banner_for_production_reachable_mode_is_a_warning_without_secrets(self):
        with captured_logs() as logs:
            bootstrap(read_only_env())
        output = logs.getvalue()
        record = json.loads(output.splitlines()[0])
        self.assertEqual(record["level"], "WARNING")
        self.assertIn("execution_mode=READ_ONLY_PRODUCTION", record["msg"])
        self.assertEqual(record["fields"]["okta.api_token"], "<set>")
        self.assertNotIn(SYNTHETIC_OKTA_TOKEN, output)

    def test_command_line_prints_banner_in_default_mode(self):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        result = subprocess.run(
            [sys.executable, "-m", "app"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("execution_mode=LOCAL_SYNTHETIC", result.stderr)


if __name__ == "__main__":
    unittest.main()
