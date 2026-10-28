"""OGWA_RUNTIME_MODE: parsing, defaults, and the demo profile's configuration contract (Demo Mode)."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

from app.core.config import (
    DEFAULT_DEMO_DATASET,
    DEMO_DATABASE_URL,
    DEMO_FORBIDDEN_FOREIGN_CREDENTIALS,
    DEMO_FORBIDDEN_KEYS,
    KNOWN_KEYS,
    load_settings,
)
from app.core.database_url import parse_database_url
from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.core.runtime_mode import RuntimeMode, parse_runtime_mode
from app.core.startup import startup_banner

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO = {"OGWA_RUNTIME_MODE": "demo"}
SECRET_VALUE = "synthetic-secret-value-never-printed"


class RuntimeModeParsingTests(unittest.TestCase):
    def test_known_values(self):
        self.assertIs(parse_runtime_mode("production"), RuntimeMode.PRODUCTION)
        self.assertIs(parse_runtime_mode("demo"), RuntimeMode.DEMO)
        self.assertIs(parse_runtime_mode(" DEMO "), RuntimeMode.DEMO)

    def test_unset_is_the_standard_runtime_so_existing_deployments_are_unchanged(self):
        self.assertIs(parse_runtime_mode(None), RuntimeMode.PRODUCTION)
        self.assertIs(parse_runtime_mode("  "), RuntimeMode.PRODUCTION)
        self.assertIs(load_settings({}).runtime_mode, RuntimeMode.PRODUCTION)

    def test_unknown_values_fail_closed_and_never_fall_back(self):
        for raw in ("foobar", "prod", "demo-mode", "live", "PRODUCTION_MUTATION"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError) as caught:
                load_settings({"OGWA_RUNTIME_MODE": raw})
            self.assertIn("OGWA_RUNTIME_MODE", str(caught.exception))

    def test_startup_refuses_an_unknown_runtime_mode(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
        env["OGWA_RUNTIME_MODE"] = "foobar"
        result = subprocess.run([sys.executable, "-m", "app"], cwd=REPO_ROOT, env=env, capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Unknown OGWA_RUNTIME_MODE", result.stderr)

    def test_the_runtime_mode_is_announced(self):
        self.assertIn("runtime_mode=demo", startup_banner(load_settings(DEMO)))
        self.assertIn("runtime_mode=production", startup_banner(load_settings({})))

    def test_the_new_keys_are_known_and_documented(self):
        self.assertIn("OGWA_RUNTIME_MODE", KNOWN_KEYS)
        self.assertIn("OGWA_DEMO_DATASET", KNOWN_KEYS)


class ProductionRuntimeUnchangedTests(unittest.TestCase):
    def test_production_settings_are_exactly_as_before(self):
        settings = load_settings({})
        self.assertIs(settings.mode, ExecutionMode.LOCAL_SYNTHETIC)
        self.assertEqual(settings.database, parse_database_url(None))
        self.assertIsNone(settings.demo_dataset)
        self.assertFalse(settings.is_demo)

    def test_production_still_accepts_its_live_settings(self):
        settings = load_settings({"OGWA_RUNTIME_MODE": "production", "OGWA_EXECUTION_MODE": "READ_ONLY_PRODUCTION",
                                  "OGWA_OKTA_ORG_URL": "https://synthetic-org.okta.example",
                                  "OGWA_OKTA_API_TOKEN": SECRET_VALUE})
        self.assertIs(settings.mode, ExecutionMode.READ_ONLY_PRODUCTION)
        self.assertEqual(settings.okta_org_url, "https://synthetic-org.okta.example")

    def test_a_demo_dataset_outside_demo_is_a_contradiction(self):
        with self.assertRaises(ConfigError):
            load_settings({"OGWA_DEMO_DATASET": "classic"})


class DemoProfileTests(unittest.TestCase):
    def test_demo_needs_no_credentials_and_uses_its_own_store(self):
        settings = load_settings(DEMO)
        self.assertIs(settings.runtime_mode, RuntimeMode.DEMO)
        self.assertIs(settings.mode, ExecutionMode.LOCAL_SYNTHETIC)
        self.assertIsNone(settings.okta_api_token)
        self.assertIsNone(settings.aap_token)
        self.assertEqual(settings.database, parse_database_url(DEMO_DATABASE_URL))
        self.assertNotEqual(settings.database, parse_database_url(None))
        self.assertEqual(settings.demo_dataset, "genesee-press")

    def test_the_default_selector_is_the_dataset_registry_s_default(self):
        # app.core does not import the registry; this holds the two in step.
        from app.demo.datasets import DATASET_KEYS, DEFAULT_DATASET

        self.assertEqual(DEFAULT_DEMO_DATASET, DEFAULT_DATASET)
        self.assertIn(DEFAULT_DEMO_DATASET, DATASET_KEYS)

    def test_demo_runs_only_in_local_synthetic(self):
        self.assertIs(load_settings({**DEMO, "OGWA_EXECUTION_MODE": "LOCAL_SYNTHETIC"}).mode,
                      ExecutionMode.LOCAL_SYNTHETIC)
        for mode in ("READ_ONLY_PRODUCTION", "DRY_RUN_MUTATION"):
            with self.subTest(mode=mode), self.assertRaises(ConfigError):
                load_settings({**DEMO, "OGWA_EXECUTION_MODE": mode})

    def test_demo_refuses_every_live_integration_setting(self):
        values = {"OGWA_OKTA_ORG_URL": "http://127.0.0.1:9", "OGWA_OKTA_API_TOKEN": SECRET_VALUE,
                  "OGWA_AAP_URL": "http://127.0.0.1:9", "OGWA_AAP_TOKEN": SECRET_VALUE}
        self.assertEqual(set(values), set(DEMO_FORBIDDEN_KEYS))
        for key, value in values.items():
            with self.subTest(key=key), self.assertRaises(ConfigError) as caught:
                load_settings({**DEMO, key: value})
            self.assertIn(key, str(caught.exception))
            self.assertNotIn(SECRET_VALUE, str(caught.exception))

    def test_demo_refuses_foreign_production_credential_variables(self):
        for key in DEMO_FORBIDDEN_FOREIGN_CREDENTIALS:
            for spelled in (key, key.lower()):
                with self.subTest(key=spelled), self.assertRaises(ConfigError) as caught:
                    load_settings({**DEMO, spelled: SECRET_VALUE})
                self.assertNotIn(SECRET_VALUE, str(caught.exception))

    def test_demo_store_must_be_a_file_and_never_the_production_default(self):
        with self.assertRaises(ConfigError):
            load_settings({**DEMO, "OGWA_DATABASE_URL": "sqlite:///:memory:"})
        with self.assertRaises(ConfigError):
            load_settings({**DEMO, "OGWA_DATABASE_URL": "sqlite:///var/ogwa-local.sqlite3"})
        custom = load_settings({**DEMO, "OGWA_DATABASE_URL": "sqlite:///var/demo-copy.sqlite3"})
        self.assertEqual(custom.database.path.name, "demo-copy.sqlite3")

    def test_dataset_selection_is_validated(self):
        self.assertEqual(load_settings({**DEMO, "OGWA_DEMO_DATASET": "classic"}).demo_dataset, "classic")
        for bad in ("../etc", "Null Meridian", "x" * 80):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                load_settings({**DEMO, "OGWA_DEMO_DATASET": bad})

    def test_diagnostics_show_the_runtime_and_no_secret(self):
        diagnostics = load_settings(DEMO).diagnostics()
        self.assertEqual(diagnostics["runtime_mode"], "demo")
        self.assertEqual(diagnostics["demo.dataset"], "genesee-press")
        self.assertEqual(diagnostics["okta.api_token"], "<unset>")


if __name__ == "__main__":
    unittest.main()
