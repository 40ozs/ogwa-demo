"""Demo Mode end to end: persistence isolation, the guarded demo reset, determinism, the real
API and UI over the demo store, the demo mutation policy, and isolation from every live system.

The dataset here is the classic 16-scenario lifecycle world (selector ``classic``, seed
namespace ``ogwa-synthetic-demo-v1``), selected explicitly through the dataset registry: it
covers every lifecycle state and can be compared route by route with the API built directly
over the same seed, without the demo layer (``tests.api_fixtures.World``). Its canonical ids come from ``app.demo.synthetic_world`` itself.
The canonical (default) demo dataset, Null Meridian, is covered end to end, with the same
isolation and mutation-policy checks, by ``tests/test_null_meridian_demo.py``. Every store
lives in a temporary directory.
"""

import contextlib
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.api.app import API_PREFIX
from app.api.local import build_local_api
from app.api.routes import ROUTES
from app.core.config import load_settings
from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.demo.synthetic_world import COLLECTOR, create_seeded_store
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction
from app.runtime import api as demo_api
from app.runtime.api import (
    BLOCKED,
    DEMO_MUTATION_POLICY,
    RUNTIME_HEADER,
    SIMULATION_NOTICE,
    build_demo_application,
    demo_routes,
)
from app.runtime.datasets import resolve_dataset
from app.runtime.demo_store import DemoPersistenceUnavailable, open_demo_store, reset_demo_store
from app.store.environment import DatabaseEnvironment
from app.store.reset import ResetRefused
from app.store.store import Store
from tests.api_fixtures import AUTOMATION, EXECUTOR, SECURITY, VIEWER, ApiClient, TickClock, World
from tests.store_fixtures import file_target, memory_target, table_dump
from tests.test_remediation_api import approve_okta, dry_run

DATASET = "classic"
V = API_PREFIX
REPO_ROOT = Path(__file__).resolve().parents[1]


def demo_settings(path: Path, dataset: str | None = DATASET, **extra: str):
    """Demo settings for a store at ``path``. ``dataset=None`` leaves OGWA_DEMO_DATASET unset (the default)."""
    selector = {} if dataset is None else {"OGWA_DEMO_DATASET": dataset}
    return load_settings({"OGWA_RUNTIME_MODE": "demo", **selector, "OGWA_DATABASE_URL": f"sqlite:///{path.as_posix()}",
                          **extra})


def canonical_world():
    """The dataset's own canonical seed, in memory: the reference every demo store must equal."""
    return create_seeded_store(memory_target())


class DemoWorld:
    """The demo application over a freshly reset demo store, with World's test interface.

    ``dataset`` is a registry selector; None serves the configured default (Null Meridian)."""

    def __init__(self, root: Path, dataset: str | None = DATASET, clock: TickClock | None = None) -> None:
        self.root = root / "var"
        self.settings = demo_settings(self.root / "ogwa-demo.sqlite3", dataset)
        self.dataset = resolve_dataset(self.settings.demo_dataset)
        # One clock for seeding and serving, exactly as tests.api_fixtures.World: from the dataset's "now".
        self.clock = clock or TickClock(self.dataset.entry.as_of + timedelta(hours=1))
        self.reset = reset_demo_store(self.settings, self.dataset, confirmed=True, allowed_root=self.root,
                                      clock=self.clock)
        self.app = build_demo_application(self.settings, clock=self.clock)
        self.api = self.app.web_app
        self.store = self.app.store
        self.summary = self.reset.summary  # the dataset's own seed summary (equal to the canonical seed's)
        self.scenarios = {s.key: s for s in self.summary.scenarios}

    candidate = World.candidate
    client = World.client
    fingerprint = World.fingerprint
    refresh_evidence = World.refresh_evidence

    def close(self) -> None:
        self.app.close()


@contextlib.contextmanager
def no_live_system():
    """Fail on any network connection or process launch. (This build has no live-system client to construct.)"""
    def refuse(name):
        return AssertionError(f"{name} was reached in Demo Mode")

    patches = [
        mock.patch.object(socket.socket, "connect", side_effect=refuse("socket.connect")),
        mock.patch.object(socket, "create_connection", side_effect=refuse("socket.create_connection")),
        mock.patch.object(subprocess, "Popen", side_effect=refuse("subprocess.Popen")),
        mock.patch.object(urllib.request, "urlopen", side_effect=refuse("urllib.request.urlopen")),
        mock.patch.object(http.client.HTTPConnection, "connect", side_effect=refuse("HTTPConnection.connect")),
        # Any other way of starting a process (a PowerShell AD worker, an AAP CLI, a shell).
        *(mock.patch.object(os, name, side_effect=refuse(f"os.{name}"))
          for name in ("system", "posix_spawn", "posix_spawnp", "execv", "execve") if hasattr(os, name)),
    ]
    with contextlib.ExitStack() as stack:
        spies = [stack.enter_context(p) for p in patches]
        yield spies
    for spy in spies:
        spy.assert_not_called()


class DemoTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ogwa-demo-test-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))


# --- persistence --------------------------------------------------------------------------


class DemoPersistenceTests(DemoTestCase):
    def path(self, name="ogwa-demo.sqlite3") -> Path:
        return self.tmp / "var" / name

    def test_a_missing_demo_store_is_a_startup_failure(self):
        settings = demo_settings(self.path())
        with self.assertRaises(DemoPersistenceUnavailable) as caught:
            build_demo_application(settings, clock=TickClock())
        self.assertIn("reset-demo", str(caught.exception))
        self.assertFalse(self.path().exists(), "a missing demo store is never created empty")

    def test_the_demo_never_opens_a_production_store(self):
        path = self.path()
        Store.initialize(file_target(path), environment=DatabaseEnvironment.PRODUCTION,
                         mode=ExecutionMode.READ_ONLY_PRODUCTION, actor=Actor(ActorKind.HUMAN, "synthetic-admin")).close()
        before = path.read_bytes()
        settings = demo_settings(path)
        with self.assertRaises(DemoPersistenceUnavailable):
            open_demo_store(settings, resolve_dataset(DATASET), clock=TickClock())
        with self.assertRaises(ResetRefused):
            reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=self.tmp / "var")
        self.assertEqual(path.read_bytes(), before, "the production store was not modified or deleted")

    def test_the_demo_reset_refuses_a_development_store(self):
        path = self.path()
        Store.initialize(file_target(path), environment=DatabaseEnvironment.DEVELOPMENT,
                         mode=ExecutionMode.LOCAL_SYNTHETIC, actor=Actor(ActorKind.HUMAN, "synthetic-admin")).close()
        with self.assertRaises(ResetRefused):
            reset_demo_store(demo_settings(path), resolve_dataset(DATASET), confirmed=True,
                             allowed_root=self.tmp / "var")
        self.assertTrue(path.exists())

    def test_the_demo_reset_runs_only_where_allowed(self):
        dataset = resolve_dataset(DATASET)
        with self.assertRaises(ResetRefused):
            reset_demo_store(demo_settings(self.path()), dataset, confirmed=False, allowed_root=self.tmp / "var")
        outside = self.tmp / "elsewhere" / "ogwa-demo.sqlite3"
        with self.assertRaises(ResetRefused):
            reset_demo_store(demo_settings(outside), dataset, confirmed=True, allowed_root=self.tmp / "var")
        self.assertFalse(self.path().exists())
        self.assertFalse(outside.exists())

    def test_an_interrupted_reset_leaves_no_partial_store_and_the_next_reset_recovers(self):
        # A first start stopped mid-seed (Ctrl+C, a container stop, a laptop sleep) must not leave a partial
        # store where the demo looks for one: the next start would skip the seed and refuse to serve it.
        path, var = self.path(), self.tmp / "var"
        child = ("import sys; from pathlib import Path; from app.runtime.datasets import resolve_dataset; "
                 "from app.runtime.demo_store import reset_demo_store; from tests.test_demo_mode import demo_settings; "
                 "reset_demo_store(demo_settings(Path(sys.argv[1]), 'null-meridian'), resolve_dataset('null-meridian'), "
                 "confirmed=True, allowed_root=Path(sys.argv[2]))")
        proc = subprocess.Popen([sys.executable, "-c", child, str(path), str(var)], cwd=REPO_ROOT)
        try:
            deadline = time.monotonic() + 120
            while proc.poll() is None and time.monotonic() < deadline:
                if var.is_dir() and any(p.stat().st_size > 500_000 for p in var.iterdir() if p.is_file()):
                    break  # well into the seed
                time.sleep(0.01)
        finally:
            proc.kill()
            proc.wait()
        self.assertNotEqual(proc.returncode, 0, "the seed finished before it could be interrupted")
        self.assertFalse(path.exists(), "an interrupted reset left a partial store")
        settings = demo_settings(path, "null-meridian")
        result = reset_demo_store(settings, resolve_dataset("null-meridian"), confirmed=True, allowed_root=var)
        self.assertEqual(result.audit_head, "sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41")
        self.assertEqual(sorted(p.name for p in var.iterdir()), [path.name], "nothing of the interrupted seed is left")
        store, _ = open_demo_store(settings, resolve_dataset("null-meridian"), clock=TickClock())
        store.close()

    def test_a_seed_that_is_interrupted_or_fails_validation_never_replaces_the_store(self):
        settings, var = demo_settings(self.path()), self.tmp / "var"
        head = reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=var).audit_head
        before = self.path().read_bytes()
        unverifiable = replace(resolve_dataset(DATASET), metadata=replace(resolve_dataset(DATASET).metadata,
                                                                          seed="some-other-dataset-v1"))
        with self.assertRaises(DemoPersistenceUnavailable):  # the seed's namespace is not the dataset's
            reset_demo_store(settings, unverifiable, confirmed=True, allowed_root=var)
        self.assertEqual(self.path().read_bytes(), before)
        with mock.patch.object(Store, "record_synthetic_seed", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=var)
        self.assertEqual(self.path().read_bytes(), before)
        self.assertEqual(reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=var)
                         .audit_head, head, "a later reset still succeeds")

    def test_a_store_holding_another_dataset_is_refused(self):
        settings = demo_settings(self.path())
        reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=self.tmp / "var")
        other = replace(resolve_dataset(DATASET), metadata=replace(resolve_dataset(DATASET).metadata,
                                                                   seed="some-other-dataset-v1"))
        with self.assertRaises(DemoPersistenceUnavailable) as caught:
            open_demo_store(settings, other, clock=TickClock())
        self.assertIn("not the configured", str(caught.exception))

    def test_a_tampered_demo_store_is_refused(self):
        settings = demo_settings(self.path())
        reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=self.tmp / "var")
        import sqlite3

        conn = sqlite3.connect(self.path())
        conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        triggers = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' "
                                               "AND tbl_name='audit_events'")]
        for name in triggers:
            conn.execute(f"DROP TRIGGER {name}")
        conn.execute("UPDATE audit_events SET details = '{}' WHERE sequence = 5")
        conn.commit()
        conn.close()
        with self.assertRaises(DemoPersistenceUnavailable):
            open_demo_store(settings, resolve_dataset(DATASET), clock=TickClock())


class DemoDeterminismTests(DemoTestCase):
    def test_reset_twice_restores_the_identical_canonical_state(self):
        settings = demo_settings(self.tmp / "var" / "ogwa-demo.sqlite3")
        dataset = resolve_dataset(DATASET)
        first = reset_demo_store(settings, dataset, confirmed=True, allowed_root=self.tmp / "var")
        with Store.open(settings.database, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            first_dump = table_dump(store)
            # A demo-local change, which the next reset must discard.
            store.record_governed_refusal(actor=Actor(ActorKind.HUMAN, "synthetic.viewer.one"),
                                          subject_id="cand_" + "0" * 32, details={"route": "test"},
                                          correlation_id="req_" + "1" * 32)
        second = reset_demo_store(settings, dataset, confirmed=True, allowed_root=self.tmp / "var")
        self.assertTrue(second.replaced_existing)
        with Store.open(settings.database, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            self.assertEqual(table_dump(store), first_dump)
        self.assertEqual(first.audit_head, second.audit_head)

    def test_demo_mode_does_not_alter_the_dataset_s_deterministic_output(self):
        settings = demo_settings(self.tmp / "var" / "ogwa-demo.sqlite3")
        result = reset_demo_store(settings, resolve_dataset(DATASET), confirmed=True, allowed_root=self.tmp / "var")
        reference, summary = canonical_world()
        try:
            self.assertEqual(result.audit_head, summary.audit_head)
            with Store.open(settings.database, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
                self.assertEqual(table_dump(store), table_dump(reference))
        finally:
            reference.close()


# --- the real application over the demo store --------------------------------------------


class DemoApplicationTests(DemoTestCase):
    def setUp(self):
        super().setUp()
        self.world = DemoWorld(self.tmp)
        self.addCleanup(self.world.close)
        self.standard = World()  # the API over the same seed without the demo layer, for comparison
        self.addCleanup(self.standard.close)

    def test_health_identifies_the_demo_without_anything_sensitive(self):
        result = self.world.client().get(f"{V}/health")
        self.assertEqual(result.status, 200)
        body = result.json
        self.assertEqual((body["status"], body["runtimeMode"], body["dataSource"]), ("ok", "demo", "synthetic"))
        self.assertEqual(body["organization"], "Synthetic Widgets Ltd (fictional)")
        self.assertEqual(body["dataset"], {"key": DATASET, "companyName": "Synthetic Widgets Ltd (fictional)",
                                           "primaryDomain": "corp.synthetic.example", "snapshotDate": "2026-03-02",
                                           "seed": "ogwa-synthetic-demo-v1", "synthetic": True})
        self.assertFalse(body["liveIntegrations"])
        self.assertEqual(result.header(RUNTIME_HEADER), "demo")
        text = str(body).lower()
        for leak in ("sqlite", str(self.tmp).lower(), "token", "secret", "password", "okta.com"):
            self.assertNotIn(leak, text)

    def test_the_api_without_the_demo_layer_is_unlabelled(self):
        health = self.standard.client().get(f"{V}/health").json
        health.pop("policyNotice", None)  # the existing label of the unrecorded policy, on every response
        self.assertEqual(health, {"status": "ok"})
        self.assertIs(self.standard.api.routes, ROUTES)
        self.assertIsNone(self.standard.client().get(f"{V}/health").header(RUNTIME_HEADER))

    def test_known_synthetic_records_are_served_by_the_shared_read_model(self):
        demo, standard = self.world.client(VIEWER), self.standard.client(VIEWER)
        s07 = self.world.store.load_candidate(self.world.candidate("S07"))
        group = demo.get(f"{V}/groups/{s07.okta_group_id}")
        self.assertEqual(group.status, 200, group.json)
        application_id = self.world.store.evidence_bundle(s07).assignments[0].application_id
        self.assertEqual(demo.get(f"{V}/applications/{application_id}").status, 200)
        for path in ("/applications", "/groups", "/mappings", "/dependency-findings", "/candidates", "/approvals",
                     "/execution-jobs", "/collector-runs", f"/groups/{s07.okta_group_id}",
                     f"/applications/{application_id}", f"/candidates/{s07.id}",
                     f"/candidates/{s07.id}/evidence"):
            with self.subTest(path=path):
                served, reference = demo.get(V + path), standard.get(V + path)
                self.assertEqual(served.status, 200, served.json)
                self.assertEqual(served.json, reference.json, "the demo serves the same data as the API without its layer")

    def test_correlation_runs_the_shared_engine_over_the_synthetic_directory(self):
        demo, standard = self.world.client(SECURITY), self.standard.client(SECURITY)
        expected = {"S01": ("RESOLVED", "EXACT_CONFIGURED_MAPPING"), "S08": ("REVIEW_REQUIRED", "NAME_ONLY"),
                    "S09": ("AMBIGUOUS", "AMBIGUOUS"), "S10": ("STALE", "NOT_FOUND")}
        for key in expected:
            group = self.world.store.load_candidate(self.world.candidate(key)).okta_group_id
            with self.subTest(scenario=key):
                served = demo.post(f"{V}/mappings/{group}/inspection", {})
                self.assertEqual(served.status, 200, served.json)
                self.assertEqual((served.json["outcome"], served.json["confidence"]), expected[key])
                reference = standard.post(f"{V}/mappings/{group}/inspection", {}).json
                self.assertEqual(served.json["evidenceFingerprint"], reference["evidenceFingerprint"])
                self.assertEqual(served.json["demo"]["classification"], "LOCAL")

    def test_governance_states_and_classification_come_from_the_dataset(self):
        demo = self.world.client(SECURITY)
        for scenario in self.world.summary.scenarios:
            with self.subTest(scenario=scenario.key):
                detail = demo.get(f"{V}/candidates/{scenario.candidate_id}")
                self.assertEqual(detail.status, 200)
                self.assertEqual(detail.json["candidate"]["state"], scenario.final_state.value)
        dashboard = demo.get(f"{V}/dashboard").json
        self.assertEqual(dashboard["runtime"]["runtimeMode"], "demo")
        self.assertEqual(dashboard["store"]["environment"], "SYNTHETIC")
        self.assertEqual(sum(dashboard["candidatesByState"].values()), len(self.world.summary.scenarios))

    def test_a_remediation_is_simulated_and_says_so(self):
        candidate, approval = approve_okta(self.world)
        result = dry_run(self.world, self.world.client(EXECUTOR), candidate, approval)
        self.assertEqual(result.status, 201, result.json)
        self.assertEqual(result.json["remediation"]["outcome"], "SIMULATED")
        self.assertEqual(result.json["demo"], {"classification": "SIMULATED", "notice": SIMULATION_NOTICE,
                                               "externalSystemsContacted": False})
        self.assertFalse(result.json["executed"])

    def test_execution_is_blocked_with_an_intentional_demo_response_and_audited(self):
        executor = self.world.client(EXECUTOR)
        job = self.world.store.connection.execute("SELECT id FROM execution_jobs LIMIT 1").fetchone()[0]
        with mock.patch.object(self.world.app.api.lifecycle, "execute",
                               side_effect=AssertionError("the lifecycle execute path was reached")):
            result = executor.post(f"{V}/execution-jobs/{job}/execute", {})
        self.assertEqual((result.status, result.code), (403, "DEMO_MODE_BLOCKED"))
        self.assertIn("demo environment", result.json["error"]["message"])
        chained = [e for e in self.world.store.audit_events() if e.action is AuditAction.GOVERNED_REQUEST_REFUSED]
        self.assertEqual(dict(chained[-1].details)["code"], "DEMO_MODE_BLOCKED")
        self.assertEqual(self.world.client(VIEWER).post(f"{V}/execution-jobs/{job}/execute", {}).code, "FORBIDDEN")

    def test_demo_local_decisions_change_only_the_demo_store(self):
        candidate = self.world.candidate("S07")
        security = self.world.client(SECURITY)
        before = self.standard.store.audit_head()
        result = security.post(f"{V}/candidates/{candidate}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "synthetic review",
            "expectedEvidenceFingerprint": self.world.fingerprint(security, candidate)})
        self.assertEqual(result.status, 201, result.json)
        self.assertEqual(result.json["demo"]["classification"], "LOCAL")
        self.assertEqual(self.standard.store.audit_head(), before)

    def test_the_runtime_mode_cannot_be_changed_through_the_api(self):
        admin = self.world.client("synthetic.admin.one")
        for method, path in (("POST", "/runtime"), ("POST", "/runtime-mode"), ("POST", "/system/runtime"),
                             ("GET", "/runtime?mode=production")):
            with self.subTest(path=path):
                self.assertEqual(admin.request(method, V + path, {} if method == "POST" else None).status, 404)
        # The only route whose path names "demo" or "runtime" is Null Meridian's read-only list of
        # portfolio scenarios. Any other such route must be reviewed and added here deliberately.
        named = [(r.method, r.pattern) for r in ROUTES if "runtime" in r.pattern or "demo" in r.pattern]
        self.assertEqual(named, [("GET", f"{V}/demo-scenarios")])
        scenarios = admin.get(f"{V}/demo-scenarios")
        self.assertEqual(scenarios.status, 200)
        self.assertEqual(scenarios.header(RUNTIME_HEADER), "demo", "answered by the demo runtime, unchanged by it")


class DemoIsolationTests(DemoTestCase):
    def test_no_live_system_is_reached_while_the_demo_is_built_and_used(self):
        with no_live_system():
            world = DemoWorld(self.tmp)
            try:
                viewer, security = world.client(VIEWER), world.client(SECURITY)
                for path in ("/health", "/dashboard", "/applications", "/groups", "/mappings", "/candidates",
                             "/dependency-findings", "/collector-runs", "/approvals", "/execution-jobs"):
                    self.assertEqual(viewer.get(V + path).status, 200, path)
                group = world.store.load_candidate(world.candidate("S09")).okta_group_id
                self.assertEqual(security.post(f"{V}/mappings/{group}/inspection", {}).status, 200)
                self.assertEqual(world.client(AUTOMATION).post(f"{V}/mappings/{group}/searches", {
                    "by": "name", "value": "SYNTH-APP-WIKI-EDITORS"}).status, 201)
                candidate, approval = approve_okta(world)
                self.assertEqual(dry_run(world, world.client(EXECUTOR), candidate, approval).status, 201)
                self.assertEqual(world.app.providers.okta.name, "SyntheticOktaProvider")
                self.assertEqual(world.app.providers.data_source, "synthetic")
            finally:
                world.close()

    def test_a_demo_process_imports_no_outbound_network_client(self):
        # For the default dataset (Null Meridian) and the classic world alike.
        for dataset in (None, DATASET):
            with self.subTest(dataset=dataset or "default"):
                self._assert_demo_process_imports_no_outbound_client(dataset)

    def _assert_demo_process_imports_no_outbound_client(self, dataset):
        code = (
            "import sys\n"
            "from app.core.config import load_settings\n"
            "from app.runtime.api import build_demo_application\n"
            "from app.runtime.datasets import resolve_dataset\n"
            "from app.runtime.demo_store import reset_demo_store\n"
            "from app.store.store import utc_now\n"
            "from pathlib import Path\n"
            "s = load_settings()\n"
            "reset_demo_store(s, resolve_dataset(s.demo_dataset), confirmed=True, allowed_root=Path(sys.argv[1]))\n"
            "d = build_demo_application(s, clock=utc_now)\n"
            "d.close()\n"
            "print(sorted(m for m in sys.modules if m in ('urllib.request', 'subprocess') or (m.startswith('app.')\n"
            "    and any(w in m for w in ('client', 'http_', 'integrations.aap', 'okta.auth', 'okta.usage', 'okta.pacing')))))\n")
        root = self.tmp / "var"
        env = {"PATH": "/usr/bin:/bin", "OGWA_RUNTIME_MODE": "demo",
               "OGWA_DATABASE_URL": f"sqlite:///{(root / 'ogwa-demo.sqlite3').as_posix()}",
               **({"OGWA_DEMO_DATASET": dataset} if dataset else {})}
        result = subprocess.run([sys.executable, "-c", code, str(root)], cwd=REPO_ROOT, env=env, capture_output=True,
                                text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "[]")

    def test_the_demo_refuses_to_start_with_production_credentials(self):
        for extra in ({"OGWA_OKTA_API_TOKEN": "synthetic-not-a-token"}, {"OKTA_CLIENT_SECRET": "synthetic-value"},
                      {"OGWA_AAP_URL": "http://127.0.0.1:9"}):
            with self.subTest(extra=list(extra)), self.assertRaises(ConfigError):
                demo_settings(self.tmp / "var" / "ogwa-demo.sqlite3", **extra)


# --- the demo mutation policy -------------------------------------------------------------


class DemoMutationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.profile = demo_api.RuntimeProfile("demo", "synthetic", resolve_dataset(DATASET).metadata)

    def test_every_post_route_is_classified(self):
        posts = {r.pattern[len(V):] for r in ROUTES if r.method == "POST"}
        self.assertEqual(posts, set(DEMO_MUTATION_POLICY))
        self.assertEqual([p for p, kind in DEMO_MUTATION_POLICY.items() if kind == BLOCKED],
                         ["/execution-jobs/{jobId}/execute"])

    def test_an_unclassified_post_route_stops_the_demo_build(self):
        extra = replace(ROUTES[1], pattern=V + "/candidates/{candidateId}/something-new")
        with self.assertRaises(ConfigError):
            demo_routes((*ROUTES, extra), self.profile)

    def test_access_rules_are_unchanged(self):
        routes = demo_routes(ROUTES, self.profile)
        self.assertEqual([(r.method, r.pattern, r.access, r.any_of, r.query, r.governed_subject) for r in routes],
                         [(r.method, r.pattern, r.access, r.any_of, r.query, r.governed_subject) for r in ROUTES])

    def test_the_api_builder_without_the_demo_layer_uses_the_plain_routes(self):
        store, _ = canonical_world()
        try:
            self.assertIs(build_local_api(store, clock=TickClock()).routes, ROUTES)
        finally:
            store.close()


# --- the UI indicator ---------------------------------------------------------------------


class DemoIndicatorStaticTests(unittest.TestCase):
    STATIC = REPO_ROOT / "app" / "ui" / "static"

    def test_the_indicator_is_hidden_until_the_demo_runtime_says_so(self):
        index = (self.STATIC / "index.html").read_text(encoding="utf-8")
        self.assertRegex(index, r'<details id="demo-indicator"[^>]*\bhidden\b')
        self.assertNotIn("DEMO ENVIRONMENT", index, "the label is never shown by the page itself")
        runtime = (self.STATIC / "js" / "runtime.js").read_text(encoding="utf-8")
        self.assertIn('export const DEMO_LABEL = "DEMO ENVIRONMENT";', runtime)
        self.assertIn('health.runtimeMode !== "demo"', runtime)
        self.assertNotIn("Null Meridian", runtime, "the organization comes from the dataset, not the UI")
        main = (self.STATIC / "js" / "main.js").read_text(encoding="utf-8")
        self.assertIn('demoIndicator(await api.get("/health"))', main)


if __name__ == "__main__":
    unittest.main()
