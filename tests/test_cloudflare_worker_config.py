"""The Cloudflare Worker's configuration and entry module (cloudflare/worker).

The deployment needs Workers Paid (for CPU) and must use only the products it was reviewed with
(a Python Worker, Workers Static Assets, one D1 database) under its reviewed CPU cap, select the
demo runtime with OGWA's own configuration names, hold no secret or production setting, and keep the only
Cloudflare-specific code (the entry module) free of anything that could reach a live system.
"""

import ast
import json
import unittest
from datetime import date
from pathlib import Path

from app.cloudflare.__main__ import headers_file, worker_environment
from app.core.config import DEFAULT_DEMO_DATASET, KNOWN_KEYS, load_settings
from app.demo import datasets as registry
from app.ui.server import UI_HEADERS

REPO = Path(__file__).resolve().parents[1]
WORKER = REPO / "cloudflare" / "worker"
CONFIG = json.loads((WORKER / "wrangler.jsonc").read_text(encoding="utf-8"))
ENTRY = (WORKER / "src" / "entry.py").read_text(encoding="utf-8")
# Everything the configuration may set. Anything else (Containers, Durable Objects, Queues,
# KV, R2, AI, Hyperdrive, Browser Rendering, Smart Placement, routes on a zone, cron triggers
# that could reset the store) needs a new review before it is added.
REVIEWED_KEYS = {"name", "main", "compatibility_date", "compatibility_flags", "workers_dev", "preview_urls", "rules",
                 "assets", "d1_databases", "vars", "observability", "limits"}


class WorkerConfigTests(unittest.TestCase):
    def test_only_reviewed_products_are_configured(self):
        self.assertLessEqual(set(CONFIG), REVIEWED_KEYS)
        # The CPU guardrail (OGWA-CLOUDFLARE-COST-GUARD-02): 5,000 ms while GET /system/integrity used up to
        # 2,623 ms. Since OGWA-INTEGRITY-COST-03, 2,000 ms: ~2.4x the heaviest request measured under a 1,000 ms
        # trial cap (mapping inspection, 823 ms in a cold isolate; median 244 ms).
        self.assertEqual(CONFIG["limits"], {"cpu_ms": 2000})
        self.assertEqual(CONFIG["name"], "ogwa-demo")
        self.assertEqual(CONFIG["main"], "src/entry.py")
        self.assertEqual(CONFIG["assets"], {"directory": "public", "not_found_handling": "none"})
        self.assertEqual([(d["binding"], d["database_name"]) for d in CONFIG["d1_databases"]], [("DB", "ogwa-demo-3")])
        self.assertTrue(CONFIG["workers_dev"])
        self.assertFalse(CONFIG["preview_urls"], "no second, unreviewed URL")

    def test_python_workers_on_python_3_14(self):
        self.assertIn("python_workers", CONFIG["compatibility_flags"])
        # Python 3.14 (Pyodide 314.0.6) is the default from 2026-09-08; earlier Pyodide lacks the
        # fixes this deployment relies on.
        self.assertGreaterEqual(date.fromisoformat(CONFIG["compatibility_date"]), date(2026, 9, 8))
        self.assertNotIn("disable_python_external_sdk", CONFIG["compatibility_flags"])

    def test_the_vars_select_the_demo_with_ogwa_names_and_hold_no_secret(self):
        variables = CONFIG["vars"]
        self.assertEqual(variables, {"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": DEFAULT_DEMO_DATASET})
        self.assertLessEqual(set(variables), KNOWN_KEYS, "OGWA's own names, no aliases")
        self.assertEqual(DEFAULT_DEMO_DATASET, registry.DEFAULT_DATASET)
        settings = load_settings(variables)
        self.assertTrue(settings.is_demo)
        self.assertEqual(settings.demo_dataset, "genesee-press")
        self.assertIsNone(settings.okta_api_token)
        self.assertIsNone(settings.aap_token)
        self.assertEqual(worker_environment(WORKER), variables)

    def test_the_static_assets_carry_the_ui_headers(self):
        text = headers_file("demo")
        for path in ("/", "/index.html", "/ui/*"):
            self.assertIn(f"{path}\n", text)
        for name, value in UI_HEADERS:
            self.assertEqual(text.count(f"  {name}: {value}\n"), 3, name)
        self.assertEqual(text.count("  X-OGWA-Runtime-Mode: demo\n"), 3)

    def test_staged_copies_are_never_committed(self):
        ignored = (WORKER / ".gitignore").read_text(encoding="utf-8").splitlines()
        for entry in ("src/app/", "src/config/", "src/*.gz", "src/hosted-build.json", "public/", "python_modules/",
                      ".wrangler/", ".dev.vars", ".dev.vars.*"):
            self.assertIn(entry, ignored)
        pyproject = (WORKER / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", pyproject, "no third-party package")


class WorkerEntryTests(unittest.TestCase):
    def test_the_entry_imports_only_the_adapter_and_the_runtime_sdk(self):
        modules = set()
        for node in ast.walk(ast.parse(ENTRY)):
            if isinstance(node, ast.Import):
                modules |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module)
        self.assertEqual(modules, {"json", "logging", "pathlib", "workers", "js", "app.api.http",
                                   "app.cloudflare.hosted", "app.cloudflare.identity", "app.core.logging_setup"})

    def test_the_entry_cannot_reach_a_live_system(self):
        called = set()
        for node in ast.walk(ast.parse(ENTRY)):
            if isinstance(node, ast.Call):
                func = node.func
                called.add(func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", ""))
        self.assertFalse(called & {"fetch", "connect", "create_connection", "urlopen", "system", "Popen", "run",
                                   "spawn", "eval", "exec", "put", "delete"}, "no network, process, or write call")
        self.assertNotRegex(ENTRY, r"OKTA|AAP|_TOKEN|PASSWORD")

    def test_every_request_checks_d1_before_the_application_runs(self):
        fetch = ENTRY[ENTRY.index("async def fetch"):]
        order = [fetch.index(s) for s in ("check_environment", "check_schema", "check_d1", "HOSTED.handle")]
        self.assertEqual(order, sorted(order))
        self.assertIn("return _response(*HOSTED.unavailable())", fetch)
