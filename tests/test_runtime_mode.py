"""Demo Mode only: the configuration contract, and every way a reviewer might try to leave it."""

import dataclasses
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

from app.core.config import (
    DEFAULT_DEMO_DATASET,
    FORBIDDEN_FOREIGN_CREDENTIALS,
    KNOWN_KEYS,
    LIVE_INTEGRATION_KEYS,
    Settings,
    load_settings,
)
from app.core.database_url import parse_database_url
from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.core.runtime_mode import DEMO_ONLY_MESSAGE, RuntimeMode, parse_runtime_mode
from app.core.startup import startup_banner

REPO_ROOT = Path(__file__).resolve().parents[1]
SECRET_VALUE = "synthetic-secret-value-never-printed"
# Modules and files of live integrations that earlier builds held. None may come back unreviewed.
REMOVED_MODULES = ("app.integrations.okta.client", "app.integrations.okta.auth", "app.integrations.okta.pacing",
                   "app.integrations.okta.usage", "app.integrations.okta.evidence", "app.integrations.aap",
                   "app.core.http_client", "app.core.http_mutation")
# Ways a reviewer might try to switch a demo into a live or production system.
ESCAPES = (
    {"OGWA_RUNTIME_MODE": "production"}, {"OGWA_RUNTIME_MODE": "live"}, {"OGWA_RUNTIME_MODE": "standard"},
    {"OGWA_RUNTIME_MODE": "PRODUCTION_MUTATION"}, {"OGWA_EXECUTION_MODE": "READ_ONLY_PRODUCTION"},
    {"OGWA_EXECUTION_MODE": "DRY_RUN_MUTATION"}, {"OGWA_EXECUTION_MODE": "PRODUCTION_MUTATION"},
    {"OGWA_LIVE_INTEGRATIONS": "true"}, {"OGWA_PRODUCTION": "true"}, {"OGWA_DEMO_MODE": "false"},
    {"OGWA_ENV": "production"}, {"OGWA_MODE": "production"},
    *({key: "http://127.0.0.1:9"} for key in LIVE_INTEGRATION_KEYS),
)


def _serve(environ: dict[str, str]) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
    return subprocess.run([sys.executable, "-m", "app.api", "serve", "--port", "0"], cwd=REPO_ROOT,
                          env={**env, **environ}, capture_output=True, text=True, timeout=60)


class RuntimeModeTests(unittest.TestCase):
    def test_the_only_runtime_mode_is_demo(self):
        self.assertEqual([m.value for m in RuntimeMode], ["demo"])
        for raw in (None, "", "  ", "demo", " DEMO "):
            with self.subTest(raw=raw):
                self.assertIs(parse_runtime_mode(raw), RuntimeMode.DEMO)
        self.assertIs(load_settings({}).runtime_mode, RuntimeMode.DEMO)

    def test_settings_cannot_hold_another_mode_or_a_live_setting(self):
        self.assertEqual({f.name for f in dataclasses.fields(Settings)}, {"demo_dataset", "log_level", "database"})
        settings = Settings()
        self.assertIs(settings.runtime_mode, RuntimeMode.DEMO)
        self.assertIs(settings.mode, ExecutionMode.LOCAL_SYNTHETIC)
        with self.assertRaises(TypeError):
            Settings(runtime_mode="production")  # type: ignore[call-arg]

    def test_the_runtime_mode_is_announced(self):
        banner = startup_banner(load_settings({}))
        self.assertIn("runtime_mode=demo", banner)
        self.assertIn("live_integrations=unavailable", banner)

    def test_the_known_keys_configure_only_the_demo(self):
        self.assertEqual(KNOWN_KEYS, {"OGWA_RUNTIME_MODE", "OGWA_EXECUTION_MODE", "OGWA_DEMO_DATASET",
                                      "OGWA_LOG_LEVEL", "OGWA_DATABASE_URL"})


class DemoOnlyEscapeTests(unittest.TestCase):
    """Not only the default: every attempted escape refuses startup with the demo-only message."""

    def test_every_attempt_to_select_a_live_or_production_runtime_is_refused(self):
        for environ in ESCAPES:
            with self.subTest(environ=environ), self.assertRaises(ConfigError) as caught:
                load_settings(environ)
            self.assertIn(DEMO_ONLY_MESSAGE, str(caught.exception))

    def test_live_credentials_are_refused_without_echoing_them(self):
        for key in (*LIVE_INTEGRATION_KEYS, *FORBIDDEN_FOREIGN_CREDENTIALS):
            for spelled in (key, key.lower()):
                with self.subTest(key=spelled), self.assertRaises(ConfigError) as caught:
                    load_settings({spelled: SECRET_VALUE})
                self.assertIn(DEMO_ONLY_MESSAGE, str(caught.exception))
                self.assertNotIn(SECRET_VALUE, str(caught.exception))

    def test_generic_production_variables_change_nothing(self):
        generic = {"PRODUCTION": "true", "LIVE_INTEGRATIONS": "true", "DEMO_MODE": "false", "ENV": "production",
                   "MODE": "production", "NODE_ENV": "production"}
        settings = load_settings(generic)
        self.assertEqual((settings.runtime_mode, settings.mode), (RuntimeMode.DEMO, ExecutionMode.LOCAL_SYNTHETIC))
        self.assertEqual(settings.diagnostics()["live_integrations"], "unavailable")

    def test_the_server_refuses_to_start_with_a_production_setting(self):
        for environ in ({"OGWA_RUNTIME_MODE": "production"}, {"OGWA_EXECUTION_MODE": "READ_ONLY_PRODUCTION"},
                        {"OGWA_OKTA_API_TOKEN": SECRET_VALUE}, {"OGWA_LIVE_INTEGRATIONS": "true"}):
            with self.subTest(environ=list(environ)):
                result = _serve(environ)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(DEMO_ONLY_MESSAGE, result.stderr)
                self.assertNotIn(SECRET_VALUE, result.stderr + result.stdout)

    def test_no_live_integration_module_or_worker_is_in_the_build(self):
        for name in REMOVED_MODULES:
            with self.subTest(module=name):
                self.assertIsNone(importlib.util.find_spec(name))
        self.assertFalse((REPO_ROOT / "worker" / "OGWA.ADReader").exists())


class DemoProfileTests(unittest.TestCase):
    def test_demo_needs_no_credentials_and_uses_its_own_store(self):
        settings = load_settings({})
        self.assertEqual(settings.database, parse_database_url("sqlite:///var/ogwa-demo.sqlite3"))
        self.assertEqual(settings.demo_dataset, "null-meridian")
        self.assertEqual(load_settings({"OGWA_RUNTIME_MODE": "demo"}), settings)

    def test_the_default_selector_is_the_dataset_registry_s_default(self):
        # app.core does not import the registry; this holds the two in step.
        from app.demo.datasets import DATASET_KEYS, DEFAULT_DATASET

        self.assertEqual(DEFAULT_DEMO_DATASET, DEFAULT_DATASET)
        self.assertIn(DEFAULT_DEMO_DATASET, DATASET_KEYS)

    def test_demo_store_must_be_a_file(self):
        with self.assertRaises(ConfigError):
            load_settings({"OGWA_DATABASE_URL": "sqlite:///:memory:"})
        custom = load_settings({"OGWA_DATABASE_URL": "sqlite:///var/demo-copy.sqlite3"})
        self.assertEqual(custom.database.path.name, "demo-copy.sqlite3")

    def test_dataset_selection_is_validated(self):
        self.assertEqual(load_settings({"OGWA_DEMO_DATASET": "classic"}).demo_dataset, "classic")
        for bad in ("../etc", "Null Meridian", "x" * 80):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                load_settings({"OGWA_DEMO_DATASET": bad})

    def test_diagnostics_show_the_runtime_and_no_secret(self):
        diagnostics = load_settings({}).diagnostics()
        self.assertEqual(diagnostics["runtime_mode"], "demo")
        self.assertEqual(diagnostics["demo.dataset"], "null-meridian")
        self.assertEqual(diagnostics["live_integrations"], "unavailable")


if __name__ == "__main__":
    unittest.main()
