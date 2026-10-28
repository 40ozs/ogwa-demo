"""Demo Mode over its canonical dataset, Null Meridian: the runtime boundary and the dataset together.

Demo Mode (``app.runtime``) is the runtime and safety boundary; Null Meridian
(``app.demo.null_meridian``) is the canonical synthetic dataset. Demo Mode selects it as
``null-meridian`` through the one dataset registry (``app.demo.datasets``), seeds it with
``create_null_meridian_store``, and recognizes it by its seed namespace ``null-meridian-v1``.

Every expected value here comes from the dataset itself: its profile, its generator
(``build_dataset``), its committed manifest (docs/demo/null-meridian.manifest.json), the seed's
own expectations (``CANDIDATES``, ``EXPECTED_CONFIDENCE``), and the golden audit head pinned by
tests/test_null_meridian_seed.py. Nothing here restates the dataset, and every store lives in
a temporary directory.
"""

import contextlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from collections import Counter
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.api.app import API_PREFIX
from app.api.routes import ROUTES
from app.core.config import load_settings
from app.core.modes import ExecutionMode
from app.demo import datasets as registry
from app.demo.null_meridian import profile
from app.demo.null_meridian.dataset import build_dataset
from app.demo.null_meridian.world import CANDIDATES, EXPECTED_CONFIDENCE, NullMeridianWorld, create_null_meridian_store
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction
from app.domain.lifecycle import LifecycleState
from app.runtime import __main__ as runtime_cli
from app.runtime.api import (
    BLOCKED,
    DEMO_MUTATION_POLICY,
    LOCAL,
    LOCAL_NOTICE,
    RUNTIME_HEADER,
    SIMULATED,
    SIMULATION_NOTICE,
    build_demo_application,
)
from app.runtime.datasets import (
    NULL_MERIDIAN_KEY,
    NULL_MERIDIAN_MODULE,
    DatasetUnavailable,
    resolve_dataset,
)
from app.runtime.demo_store import DemoPersistenceUnavailable, open_demo_store, reset_demo_store
from app.store import __main__ as store_cli
from app.store import reset as reset_module
from app.store.environment import DatabaseEnvironment
from app.store.reset import ResetRefused
from app.store.store import Store, utc_now
from tests.api_fixtures import ADMIN, AUTOMATION, EXECUTOR, SECURITY, VIEWER, TickClock
from tests.store_fixtures import file_target, memory_target, table_dump
from tests.test_demo_mode import DemoWorld, demo_settings, no_live_system
from tests.test_null_meridian_seed import GOLDEN_AUDIT_HEAD, GOLDEN_CONFIDENCES
from tests.test_remediation_api import approve_okta, dry_run

V = API_PREFIX
REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((REPO_ROOT / "docs" / "demo" / "null-meridian.manifest.json").read_text(encoding="utf-8"))
DS = build_dataset()
# The contract Demo Mode must preserve, as the task states it. Asserted against the
# implementation's own profile and manifest, never used as a source of data.
CANONICAL = {"selector": "null-meridian", "seed": "null-meridian-v1", "company": "Null Meridian",
             "domain": "nullmeridian.info", "snapshot": "2026-10-01"}


def rows(table: str) -> list[dict]:
    """A columnar manifest table as dicts."""
    columns = MANIFEST[table]["columns"]
    return [dict(zip(columns, row)) for row in MANIFEST[table]["rows"]]


def manifest_group(name: str) -> dict:
    return next(g for g in rows("groups") if g["name"] == name)


def okta_ref(group_key: str) -> str:
    return NullMeridianWorld.okta_ref(group_key)


def paged(client, path: str) -> list[dict]:
    items, cursor = [], None
    while True:
        sep = "&" if "?" in path else "?"
        result = client.get(f"{V}{path}{sep}limit=200" + (f"&cursor={cursor}" if cursor else ""))
        assert result.status == 200, (path, result.json)
        items += result.json["items"]
        cursor = result.json["page"]["nextCursor"]
        if not cursor:
            return items


@contextlib.contextmanager
def without_null_meridian():
    """Make the Null Meridian implementation unimportable, as in a build without it."""
    names = ("app.demo.null_meridian", "app.demo.null_meridian.world", "app.demo.null_meridian.profile")
    saved = {n: sys.modules[n] for n in names if n in sys.modules}
    for name in names:
        sys.modules[name] = None  # type: ignore[assignment]  # import of a None entry raises ModuleNotFoundError
    try:
        yield
    finally:
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ogwa-nm-demo-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "var"
        self.root.mkdir()


# --- selection: the registry, the adapter, and failing closed -----------------------------------


class NullMeridianSelectionTests(TempDirCase):
    def test_null_meridian_is_selected_by_name_through_the_registry(self):
        # SYNTH-OGWA-01: the default is Genesee Press (tests/test_genesee_press.py); Null Meridian, the legacy
        # dataset, stays selectable by name until Genesee Press parity is accepted.
        self.assertEqual(load_settings({"OGWA_RUNTIME_MODE": "demo"}).demo_dataset, registry.DEFAULT_DATASET)
        self.assertEqual(registry.DEFAULT_DATASET, "genesee-press")
        settings = load_settings({"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": NULL_MERIDIAN_KEY})
        self.assertEqual(NULL_MERIDIAN_KEY, CANONICAL["selector"])
        dataset = resolve_dataset(settings.demo_dataset)
        from app.demo.null_meridian import world

        self.assertIs(dataset.seed_store, world.create_null_meridian_store)
        self.assertIs(dataset.entry.create, world.create_null_meridian_store)
        self.assertEqual((dataset.key, dataset.seed_namespace, dataset.entry.namespace),
                         (CANONICAL["selector"], CANONICAL["seed"], CANONICAL["seed"]))
        self.assertEqual(dataset.module, NULL_MERIDIAN_MODULE)

    def test_metadata_is_read_from_the_profile_and_matches_the_manifest_and_contract(self):
        m = resolve_dataset(NULL_MERIDIAN_KEY).metadata
        self.assertEqual((m.key, m.company_name, m.primary_domain, m.snapshot_date, m.seed),
                         (profile.DATASET_KEY, profile.COMPANY, profile.PRIMARY_DOMAIN, profile.SNAPSHOT_DATE,
                          profile.SEED))
        p = MANIFEST["profile"]
        self.assertEqual((p["dataset"], p["company"], p["primaryDomain"], p["snapshotDate"], p["seed"]),
                         (m.key, m.company_name, m.primary_domain, m.snapshot_date.isoformat(), m.seed))
        self.assertEqual((m.key, m.seed, m.company_name, m.primary_domain, m.snapshot_date.isoformat()),
                         tuple(CANONICAL.values()))
        self.assertTrue(m.synthetic and MANIFEST["synthetic"])

    def test_demo_mode_adapts_exactly_the_registry_s_datasets(self):
        from app.runtime import datasets as adapter

        self.assertEqual(set(adapter._ADAPTERS), set(registry.DATASET_KEYS), "one registry; an adapter for each entry")
        self.assertEqual(adapter.registered_keys(), registry.DATASET_KEYS)
        for key in registry.DATASET_KEYS:
            with self.subTest(dataset=key):
                dataset = resolve_dataset(key)
                self.assertEqual((dataset.key, dataset.seed_namespace), (key, registry.dataset(key).namespace))
                self.assertIs(dataset.seed_store, registry.dataset(key).create)
        with mock.patch.object(registry, "DATASET_KEYS", (*registry.DATASET_KEYS, "another")), \
                self.assertRaisesRegex(DatasetUnavailable, "no adapter"):
            resolve_dataset("another")

    def test_a_seed_namespace_is_not_a_selector(self):
        for namespace, selector in (("null-meridian-v1", "null-meridian"), ("ogwa-synthetic-demo-v1", "classic")):
            with self.subTest(namespace=namespace), self.assertRaises(DatasetUnavailable) as caught:
                resolve_dataset(namespace)
            self.assertIn(f"selected as {selector}", str(caught.exception))

    def test_an_absent_null_meridian_fails_closed_and_never_falls_back_to_classic(self):
        # A classic demo store is already in place at the configured path; it must not be served.
        path = self.root / "ogwa-demo.sqlite3"
        reset_demo_store(demo_settings(path, "classic"), resolve_dataset("classic"), confirmed=True,
                         allowed_root=self.root)
        before = path.read_bytes()
        settings = demo_settings(path, NULL_MERIDIAN_KEY)  # selected by name (the default is Genesee Press)
        with without_null_meridian():
            with self.assertRaises(DatasetUnavailable) as caught:
                resolve_dataset(NULL_MERIDIAN_KEY)
            self.assertIn(NULL_MERIDIAN_MODULE, str(caught.exception))
            self.assertIn("does not substitute another dataset", str(caught.exception))
            with self.assertRaises(DatasetUnavailable):
                build_demo_application(settings, clock=TickClock())
            code, _, err = run_runtime_cli(settings_env(path), self.root, "reset-demo", "--confirm-synthetic-reset")
            self.assertEqual(code, 2, err)
            self.assertIn(NULL_MERIDIAN_MODULE, err)
            self.assertIn("unavailable", runtime_cli_output(settings_env(path), self.root, "status"))
        self.assertEqual(path.read_bytes(), before, "the classic store was neither served, reseeded, nor deleted")
        self.assertIsNotNone(resolve_dataset(NULL_MERIDIAN_KEY), "restored after the simulated absence")

    def test_an_unknown_dataset_is_refused_before_anything_is_touched(self):
        path = self.root / "ogwa-demo.sqlite3"
        path.write_bytes(b"not a store")
        code, _, err = run_runtime_cli({**settings_env(path), "OGWA_DEMO_DATASET": "production"}, self.root,
                                       "reset-demo", "--confirm-synthetic-reset")
        self.assertEqual(code, 2)
        self.assertIn("unknown demo dataset", err)
        self.assertEqual(path.read_bytes(), b"not a store")


# --- persistence: the canonical reset, determinism, and store identity -----------------------------


def settings_env(path: Path) -> dict[str, str]:
    # The legacy dataset, named: Genesee Press is the default since SYNTH-OGWA-01 (tests/test_genesee_press.py).
    return {"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": NULL_MERIDIAN_KEY, "OGWA_DATABASE_URL": f"sqlite:///{path.as_posix()}"}


def run_runtime_cli(env: dict[str, str], root: Path, *args: str, cli=runtime_cli) -> tuple[int, str, str]:
    clean = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {**clean, **env}, clear=True), \
            mock.patch.object(reset_module, "DEFAULT_ALLOWED_ROOT", root), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


def runtime_cli_output(env, root, *args) -> str:
    return run_runtime_cli(env, root, *args)[1]


def representative(store: Store) -> dict:
    """Representative canonical records, read from a store: for comparing resets."""
    conn = store.connection
    one = lambda sql, *a: tuple(conn.execute(sql, a).fetchone())  # noqa: E731
    return {
        "employee": one("SELECT id, body FROM synthetic_directory_records WHERE kind = 'PERSON' AND sort_key = 'NM00001'"),
        "group": one("SELECT id, body FROM synthetic_directory_records WHERE kind = 'GROUP' AND ref_b = ?",
                     "app:crm:modern:user"),
        "application": one("SELECT a.id, o.digest FROM okta_applications a JOIN okta_application_observations o "
                           "ON o.application_id = a.id WHERE a.okta_app_id = ?",
                           next(a["oktaAppId"] for a in MANIFEST["applications"] if a["slug"] == "crm")),
        "candidates": tuple(conn.execute("SELECT id, state FROM candidates ORDER BY id").fetchall()),
        "seed": one("SELECT sequence, digest, details FROM audit_events WHERE action = 'SYNTHETIC_SEED_LOADED'"),
        "snapshot": one("SELECT dataset, seed, company, record_count, content_digest FROM synthetic_directory_snapshots"),
    }


class NullMeridianResetTests(TempDirCase):
    def test_two_resets_produce_the_identical_canonical_state(self):
        path = self.root / "ogwa-demo.sqlite3"
        settings, dataset = demo_settings(path, NULL_MERIDIAN_KEY), resolve_dataset(NULL_MERIDIAN_KEY)
        first = reset_demo_store(settings, dataset, confirmed=True, allowed_root=self.root)
        self.assertFalse(first.replaced_existing)
        with Store.open(settings.database, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            first_dump, first_records = table_dump(store), representative(store)
            # Demo-local activity, which the next reset must discard.
            store.record_governed_refusal(actor=Actor(ActorKind.HUMAN, "synthetic.viewer.one"),
                                          subject_id="cand_" + "0" * 32, details={"route": "test"},
                                          correlation_id="req_" + "1" * 32)
        second = reset_demo_store(settings, dataset, confirmed=True, allowed_root=self.root)
        self.assertTrue(second.replaced_existing)
        with Store.open(settings.database, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            self.assertEqual(table_dump(store), first_dump, "identical logical data")
            self.assertEqual(representative(store), first_records, "identical representative records")
        for result in (first, second):
            self.assertEqual(result.audit_head, GOLDEN_AUDIT_HEAD, "the dataset's pinned canonical audit head")
            self.assertEqual((result.report.seed_namespace, result.report.directory_dataset),
                             (CANONICAL["seed"], CANONICAL["selector"]))
            self.assertEqual(result.report.integrity.audit_head, GOLDEN_AUDIT_HEAD)
        self.assertEqual(first.report.directory_records, second.report.directory_records)

    def test_demo_mode_does_not_alter_the_dataset_s_deterministic_output(self):
        path = self.root / "ogwa-demo.sqlite3"
        reset_demo_store(demo_settings(path, NULL_MERIDIAN_KEY), resolve_dataset(NULL_MERIDIAN_KEY), confirmed=True,
                         allowed_root=self.root)
        reference, summary = create_null_meridian_store(memory_target())
        try:
            self.assertEqual(summary.audit_head, GOLDEN_AUDIT_HEAD)
            with Store.open(file_target(path), mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
                self.assertEqual(table_dump(store), table_dump(reference))
        finally:
            reference.close()

    def test_the_canonical_commands_reset_verify_and_reset_again(self):
        path = self.root / "ogwa-demo.sqlite3"
        env = settings_env(path)
        heads = []
        for round_ in (1, 2):
            with self.subTest(round=round_):
                code, out, err = run_runtime_cli(env, self.root, "reset-demo", "--confirm-synthetic-reset")
                self.assertEqual(code, 0, err)
                self.assertIn("for dataset null-meridian (Null Meridian, nullmeridian.info, snapshot 2026-10-01)", out)
                self.assertIn("seed_namespace: null-meridian-v1", out)
                self.assertIn("directory_dataset: null-meridian", out)
                self.assertIn("NM-C08  HOLD", out)
                heads.append(out.strip().splitlines()[-1])
                code, out, err = run_runtime_cli(env, self.root, "verify", "--expected-audit-head", GOLDEN_AUDIT_HEAD)
                self.assertEqual(code, 0, err)
                self.assertIn(f"OK: dataset null-meridian, audit_head {GOLDEN_AUDIT_HEAD}", out)
        self.assertEqual(heads, [f"audit_head: {GOLDEN_AUDIT_HEAD}"] * 2)
        code, _, err = run_runtime_cli(env, self.root, "verify", "--expected-audit-head", "sha256:" + "0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("DEMO STORE INVALID", err)
        status = runtime_cli_output(env, self.root, "status")
        self.assertIn("dataset[null-meridian]: available (seed null-meridian-v1, Null Meridian)", status)
        self.assertIn("demo_store:    present", status)

    def test_there_is_one_reset_command_for_the_demo_store(self):
        path = self.root / "ogwa-demo.sqlite3"
        env = settings_env(path)
        self.assertEqual(run_runtime_cli(env, self.root, "reset-demo", "--confirm-synthetic-reset")[0], 0)
        before = path.read_bytes()
        for dataset in ((), ("--dataset", "classic"), ("--dataset", "null-meridian")):
            with self.subTest(args=dataset):
                code, _, err = run_runtime_cli(env, self.root, "reset-demo", "--confirm-synthetic-reset", *dataset,
                                               cli=store_cli)
                self.assertEqual(code, 2)
                self.assertIn("python -m app.runtime reset-demo", err)
        self.assertEqual(path.read_bytes(), before, "the store CLI never reseeds the demo store")
        production = {"OGWA_DATABASE_URL": f"sqlite:///{path.as_posix()}"}
        code, _, err = run_runtime_cli(production, self.root, "reset-demo", "--confirm-synthetic-reset")
        self.assertEqual(code, 2)
        self.assertIn("OGWA_RUNTIME_MODE=demo", err)
        code, _, err = run_runtime_cli(env, self.root, "reset-demo")
        self.assertEqual(code, 2)
        self.assertIn("confirmation", err)
        self.assertEqual(path.read_bytes(), before)


class NullMeridianStoreIdentityTests(TempDirCase):
    """A demo store is accepted only when every piece of dataset identity evidence agrees."""

    @classmethod
    def setUpClass(cls):
        cls.shared = Path(tempfile.mkdtemp(prefix="ogwa-nm-identity-"))
        (cls.shared / "var").mkdir()
        cls.seeded = cls.shared / "var" / "seeded.sqlite3"
        reset_demo_store(demo_settings(cls.seeded, NULL_MERIDIAN_KEY), resolve_dataset(NULL_MERIDIAN_KEY), confirmed=True,
                         allowed_root=cls.shared / "var")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.shared, ignore_errors=True)

    def copy(self) -> Path:
        path = self.root / "ogwa-demo.sqlite3"
        shutil.copyfile(self.seeded, path)
        return path

    def refused(self, path: Path, dataset: str | None = None) -> str:
        with self.assertRaises(DemoPersistenceUnavailable) as caught:
            open_demo_store(demo_settings(path, dataset or NULL_MERIDIAN_KEY), resolve_dataset(dataset or NULL_MERIDIAN_KEY),
                            clock=utc_now)
        return str(caught.exception)

    def test_the_canonical_store_is_accepted_with_all_evidence_agreeing(self):
        store, report = open_demo_store(demo_settings(self.copy(), NULL_MERIDIAN_KEY), resolve_dataset(NULL_MERIDIAN_KEY),
                                        clock=utc_now)
        with store:
            snapshot = store.synthetic_directory()
            self.assertIs(store.marker.environment, DatabaseEnvironment.SYNTHETIC)
            self.assertEqual((snapshot.dataset, snapshot.seed, snapshot.company),
                             (CANONICAL["selector"], CANONICAL["seed"], CANONICAL["company"]))
            self.assertEqual(registry.dataset_of(store).key, CANONICAL["selector"])
        self.assertEqual((report.dataset, report.seed_namespace, report.directory_dataset),
                         (CANONICAL["selector"], CANONICAL["seed"], CANONICAL["selector"]))
        self.assertEqual(report.directory_records, snapshot.record_count)

    def test_a_store_of_the_wrong_synthetic_dataset_is_refused_both_ways(self):
        self.assertIn("not the configured dataset 'classic'", self.refused(self.copy(), "classic"))
        classic = self.root / "classic.sqlite3"
        reset_demo_store(demo_settings(classic, "classic"), resolve_dataset("classic"), confirmed=True,
                         allowed_root=self.root)
        self.assertIn("not the configured dataset 'null-meridian'", self.refused(classic))

    def test_the_seed_namespace_without_the_null_meridian_snapshot_is_refused(self):
        path = self.root / "ogwa-demo.sqlite3"
        store = Store.initialize(file_target(path), environment=DatabaseEnvironment.SYNTHETIC,
                                 mode=ExecutionMode.LOCAL_SYNTHETIC, actor=Actor(ActorKind.SYSTEM, "synthetic-seed"))
        with store:
            store.record_synthetic_seed(actor=Actor(ActorKind.SYSTEM, "synthetic-seed"), namespace=CANONICAL["seed"],
                                        scenario_count=0, as_of=profile.AS_OF)
        self.assertIn("holds dataset 'classic', not the configured 'null-meridian'", self.refused(path))

    def test_a_tampered_directory_snapshot_is_refused(self):
        path = self.copy()
        conn = sqlite3.connect(path)
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger' "
                                    "AND tbl_name = 'synthetic_directory_records'").fetchall():
            conn.execute(f"DROP TRIGGER {name}")
        conn.execute("UPDATE synthetic_directory_records SET body = '{\"tampered\": true}' "
                     "WHERE kind = 'PERSON' AND sort_key = 'NM00001'")
        conn.commit()
        conn.close()
        self.assertIn("failed verification", self.refused(path))

    def test_unmarked_missing_and_production_stores_are_refused(self):
        unmarked = self.root / "unmarked.sqlite3"
        conn = sqlite3.connect(unmarked)
        conn.execute("CREATE TABLE t (x)")
        conn.commit()
        conn.close()
        self.refused(unmarked)
        with self.assertRaises(ResetRefused):
            reset_demo_store(demo_settings(unmarked, NULL_MERIDIAN_KEY), resolve_dataset(NULL_MERIDIAN_KEY), confirmed=True,
                             allowed_root=self.root)
        self.assertTrue(unmarked.exists(), "an unmarked file is never deleted")
        missing = self.root / "missing.sqlite3"
        self.assertIn("reset-demo", self.refused(missing))
        self.assertFalse(missing.exists(), "a missing demo store is never created empty")
        production = self.root / "production.sqlite3"
        Store.initialize(file_target(production), environment=DatabaseEnvironment.PRODUCTION,
                         mode=ExecutionMode.READ_ONLY_PRODUCTION, actor=Actor(ActorKind.HUMAN, "synthetic-admin")).close()
        before = production.read_bytes()
        self.assertIn("PRODUCTION", self.refused(production))
        with self.assertRaises(ResetRefused):
            reset_demo_store(demo_settings(production, NULL_MERIDIAN_KEY), resolve_dataset(NULL_MERIDIAN_KEY), confirmed=True,
                             allowed_root=self.root)
        self.assertEqual(production.read_bytes(), before)


# --- the real application over the Null Meridian demo store ----------------------------------------


class NullMeridianDemoApplicationTests(unittest.TestCase):
    """Read-only checks through the integrated demo API and read model (one shared demo)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="ogwa-nm-demo-app-"))
        cls.world = DemoWorld(cls.tmp, dataset=NULL_MERIDIAN_KEY)
        cls.viewer = cls.world.client(VIEWER)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def get(self, path: str):
        result = self.viewer.get(V + path)
        self.assertEqual(result.status, 200, (path, result.json))
        return result.json

    def test_the_demo_serves_null_meridian_from_its_canonical_seed(self):
        self.assertEqual(self.world.dataset.key, CANONICAL["selector"])
        self.assertEqual(self.world.reset.audit_head, GOLDEN_AUDIT_HEAD)
        self.assertEqual(self.world.app.report.seed_namespace, CANONICAL["seed"])
        self.assertEqual(self.world.app.providers.okta.name, "SyntheticOktaProvider")

    def test_health_identifies_the_runtime_and_the_dataset_and_nothing_sensitive(self):
        result = self.world.client().get(f"{V}/health")
        body = result.json
        self.assertEqual((body["status"], body["runtimeMode"], body["dataSource"], body["organization"]),
                         ("ok", "demo", "synthetic", CANONICAL["company"]))
        self.assertEqual(body["dataset"], {"key": CANONICAL["selector"], "companyName": CANONICAL["company"],
                                           "primaryDomain": CANONICAL["domain"], "snapshotDate": CANONICAL["snapshot"],
                                           "seed": CANONICAL["seed"], "synthetic": True})
        self.assertFalse(body["liveIntegrations"])
        self.assertEqual(result.header(RUNTIME_HEADER), "demo")
        text = json.dumps(body).lower()
        for leak in ("sqlite", str(self.tmp).lower(), "token", "secret", "password", "okta.com", "var/"):
            self.assertNotIn(leak, text)
        dashboard = self.get("/dashboard")
        self.assertEqual(dashboard["runtime"], {k: body[k] for k in dashboard["runtime"]})
        self.assertEqual(dashboard["store"]["environment"], "SYNTHETIC")

    def test_every_read_route_answers_over_null_meridian(self):
        clients = [self.viewer, *(self.world.client(p) for p in (SECURITY, ADMIN, AUTOMATION, EXECUTOR))]
        for route in ROUTES:
            if route.method != "GET" or "{" in route.pattern:
                continue
            with self.subTest(route=route.pattern):
                statuses = [client.get(route.pattern).status for client in clients]
                self.assertIn(200, statuses, "answered for the principal whose role permits it")
                self.assertLessEqual(set(statuses), {200, 403}, "and refused, never failed, for the others")

    def test_representative_records_match_the_manifest(self):
        # A known employee: the first person in the manifest.
        person = rows("users")[0]
        pid = "psn_" + person["uuid"].replace("-", "")
        found = self.get(f"/people?q={person['employeeNumber'].lower()}")["items"]
        self.assertEqual([p["id"] for p in found], [pid])
        detail = self.get(f"/people/{pid}")
        self.assertEqual((detail["person"]["email"], detail["person"]["title"], detail["person"]["status"]),
                         (person["email"], person["title"], person["status"]))
        self.assertEqual(detail["history"][0]["kind"], "HIRED")
        self.assertTrue(detail["access"], "person access paths")

        # A known application and a known assignment of it.
        crm = next(a for a in MANIFEST["applications"] if a["slug"] == "crm")
        app = self.get(f"/applications/{crm['id']}")
        self.assertEqual((app["application"]["oktaAppId"], app["application"]["label"]),
                         (crm["oktaAppId"], crm["label"]))
        assignment = next(a for a in MANIFEST["assignments"] if a["application"] == "crm"
                          and a["group"] == "app:crm:modern:user")
        served = {a["id"]: a for a in app["assignments"]}
        self.assertIn(assignment["id"], served)
        self.assertEqual(served[assignment["id"]]["oktaGroupId"], okta_ref(assignment["group"]))
        self.assertEqual(served[assignment["id"]]["present"], assignment["present"])
        self.assertIn(assignment["id"], {a["id"] for a in app["profile"]["groupAssignments"]})

        # A known group: in the directory and in Okta evidence.
        group = manifest_group("sg-okta-crm-user")
        directory = self.get(f"/directory-groups?q={group['name']}")["items"]
        self.assertEqual([g["key"] for g in directory], [group["key"]])
        okta = self.get(f"/groups/{okta_ref(group['key'])}")
        self.assertEqual((okta["group"]["name"], okta["group"]["oktaGroupId"]), (group["oktaName"], group["oktaGroupId"]))
        self.assertEqual(okta["directory"]["id"], directory[0]["id"])

        # A known correlation case per kind the portfolio shows.
        for name in ("sg-okta-crm-user", "Finance-RW", "WikiV1-Users", "Okta_Fax_Users"):
            g = next(x for x in DS.groups if x.name == name and x.okta_visible)
            with self.subTest(correlation=name):
                mapping = self.get(f"/mappings/{okta_ref(g.key)}")["mapping"]
                self.assertEqual(mapping["confidence"], EXPECTED_CONFIDENCE[g.correlation_case].value)

        # A known governance finding.
        finding = next(f for f in DS.findings if f.code == "DEEP_NESTING" and f.subject_name == "sg-okta-warehouse-readonly")
        served = {f["id"]: f for f in paged(self.viewer, "/governance-findings?code=DEEP_NESTING")}
        self.assertEqual((served[finding.id]["severity"], served[finding.id]["subjectId"]),
                         (finding.severity, finding.subject_id))
        self.assertIn(finding.id, {f["id"] for f in self.get(f"/directory-groups/{finding.subject_id}")["findings"]})

        # A known lifecycle candidate.
        for key, state in (("NM-C08", "HOLD"), ("NM-C09", "PROTECTED"), ("NM-C04", "MAPPING_AMBIGUOUS")):
            with self.subTest(candidate=key):
                self.assertEqual(self.get(f"/candidates/{self.world.candidate(key)}")["candidate"]["state"], state)

    def test_the_real_correlation_engine_s_results_match_the_dataset(self):
        served = {m["oktaGroupId"]: m["confidence"] for m in paged(self.viewer, "/mappings")}
        visible = [g for g in DS.groups if g.okta_visible]
        self.assertEqual(len(served), len(visible))
        for g in visible:
            self.assertEqual(served[okta_ref(g.key)], EXPECTED_CONFIDENCE[g.correlation_case].value, g.name)
        self.assertEqual(dict(Counter(served.values())), GOLDEN_CONFIDENCES)
        # The ten correlation cases the dataset states, as its manifest records them.
        self.assertEqual(dict(Counter(g.correlation_case for g in visible)), MANIFEST["counts"]["correlationCases"])

    def test_governance_findings_and_posture_match_the_dataset(self):
        counts = self.get("/governance-findings?limit=1")["counts"]
        by_severity = {severity: sum(codes.values()) for severity, codes in counts.items()}
        self.assertEqual(by_severity, MANIFEST["counts"]["findingsBySeverity"])
        self.assertEqual(by_severity, dict(Counter(f.severity for f in DS.findings)))
        self.assertEqual({(s, c): n for s, codes in counts.items() for c, n in codes.items()},
                         dict(Counter((f.severity, f.code) for f in DS.findings)))
        groups = Counter(g["health"] for g in paged(self.viewer, "/directory-groups"))
        apps = Counter(a["health"] for a in self.get("/directory")["applications"])
        self.assertEqual(dict(groups), MANIFEST["counts"]["groupHealth"])
        self.assertEqual(groups + apps, Counter(DS.analysis.group_severity.values())
                         + Counter(DS.analysis.application_severity.values()))

    def test_lifecycle_candidates_keep_their_states(self):
        served = {c["id"]: c["state"] for c in paged(self.viewer, "/candidates")}
        self.assertEqual(len(served), len(CANDIDATES))
        for spec in CANDIDATES:
            with self.subTest(candidate=spec.key):
                self.assertEqual(served[self.world.candidate(spec.key)], spec.expected.value)
        self.assertTrue({LifecycleState.NEEDS_REVIEW, LifecycleState.HOLD, LifecycleState.PROTECTED,
                         LifecycleState.BLOCKED, LifecycleState.DEPENDENCY_BLOCKED} <= {s.expected for s in CANDIDATES})
        dashboard = self.get("/dashboard")
        self.assertEqual(sum(dashboard["candidatesByState"].values()), len(CANDIDATES))
        scenarios = self.get("/demo-scenarios")["items"]
        self.assertEqual([s["key"] for s in scenarios], [s.key for s in DS.scenarios])
        for s in scenarios:
            if s["candidateId"]:
                self.assertIn(s["candidateId"], served)

    def test_the_directory_views_have_the_whole_company(self):
        summary = self.get("/directory")
        self.assertTrue(summary["available"])
        self.assertEqual(summary["profile"]["company"], CANONICAL["company"])
        self.assertEqual(summary["counts"]["activeEmployees"], MANIFEST["counts"]["activeEmployees"])
        self.assertEqual(len(paged(self.viewer, "/people?status=ACTIVE")), MANIFEST["counts"]["activeEmployees"])
        self.assertEqual(len(summary["departments"]), len(MANIFEST["departments"]))
        self.assertEqual(len(summary["applications"]), len(MANIFEST["applications"]))


class NullMeridianDemoMutationTests(unittest.TestCase):
    """Demo-local, simulated, and blocked operations over Null Meridian (one demo for the class)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="ogwa-nm-demo-mut-"))
        cls.world = DemoWorld(cls.tmp, dataset=NULL_MERIDIAN_KEY)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_integrated_route_table_is_fully_classified(self):
        posts = {r.pattern[len(V):] for r in ROUTES if r.method == "POST"}
        self.assertEqual(posts, set(DEMO_MUTATION_POLICY), "every POST route has a demo classification")
        self.assertEqual([p for p, kind in DEMO_MUTATION_POLICY.items() if kind == BLOCKED],
                         ["/execution-jobs/{jobId}/execute"])
        directory = {"/directory", "/people", "/people/{personId}", "/directory-groups",
                     "/directory-groups/{directoryGroupId}", "/governance-findings", "/demo-scenarios"}
        methods = {(r.method, r.pattern[len(V):]) for r in ROUTES}
        self.assertEqual({p for m, p in methods if p in directory}, directory)
        self.assertFalse({(m, p) for m, p in methods if p in directory and m != "GET"},
                         "Null Meridian's routes are read-only")
        served = {(r.method, r.pattern): r.handler for r in self.world.app.api.routes}
        for route in ROUTES:
            if route.method == "GET" and route.pattern[len(V):] in directory:
                self.assertIs(served[("GET", route.pattern)], route.handler, "read routes are served unwrapped")

    def test_correlation_inspection_runs_the_real_engine_and_is_demo_local(self):
        security = self.world.client(SECURITY)
        cases = {}
        for g in DS.groups:
            if g.okta_visible:
                cases.setdefault(g.correlation_case, g)
        self.assertEqual(set(cases), set(MANIFEST["counts"]["correlationCases"]))
        for case, g in sorted(cases.items()):
            with self.subTest(case=case, group=g.name):
                result = security.post(f"{V}/mappings/{okta_ref(g.key)}/inspection", {})
                self.assertEqual(result.status, 200, result.json)
                self.assertEqual(result.json["confidence"], EXPECTED_CONFIDENCE[case].value)
                self.assertEqual(result.json["demo"], {"classification": LOCAL, "notice": LOCAL_NOTICE,
                                                       "externalSystemsContacted": False})

    def test_an_approval_is_demo_local_and_a_remediation_is_simulated(self):
        # Null Meridian's evidence was collected a week before its snapshot; as an operator would,
        # re-observe it (unchanged facts) so the approval gate's freshness rule is met.
        self.world.refresh_evidence(self.world.candidate("NM-C01"))
        candidate, approval = approve_okta(self.world, "NM-C01")
        result = dry_run(self.world, self.world.client(EXECUTOR), candidate, approval)
        self.assertEqual(result.status, 201, result.json)
        self.assertEqual(result.json["remediation"]["outcome"], "SIMULATED")
        self.assertEqual(result.json["demo"], {"classification": SIMULATED, "notice": SIMULATION_NOTICE,
                                               "externalSystemsContacted": False})
        self.assertFalse(result.json["executed"])
        approval_events = [e for e in self.world.store.audit_events() if e.subject_id == candidate]
        self.assertTrue(approval_events, "recorded in the demo store")

    def test_execution_is_blocked_before_the_lifecycle_and_audited(self):
        job = self.world.store.connection.execute("SELECT id FROM execution_jobs LIMIT 1").fetchone()[0]
        executor = self.world.client(EXECUTOR)
        with mock.patch.object(self.world.app.api.lifecycle, "execute",
                               side_effect=AssertionError("the lifecycle execute path was reached")):
            result = executor.post(f"{V}/execution-jobs/{job}/execute", {})
        self.assertEqual((result.status, result.code), (403, "DEMO_MODE_BLOCKED"))
        chained = [e for e in self.world.store.audit_events() if e.action is AuditAction.GOVERNED_REQUEST_REFUSED]
        self.assertEqual(dict(chained[-1].details)["code"], "DEMO_MODE_BLOCKED")
        executed = self.world.store.connection.execute(
            "SELECT count(*) FROM execution_job_status_events WHERE executed = 1").fetchone()[0]
        self.assertEqual(executed, 0, "no job was ever executed")


class NullMeridianDemoIsolationTests(TempDirCase):
    def test_no_live_system_is_reached_while_null_meridian_is_seeded_served_and_used(self):
        with no_live_system():
            world = DemoWorld(self.tmp, dataset=NULL_MERIDIAN_KEY)
            try:
                viewer, security = world.client(VIEWER), world.client(SECURITY)
                admin = world.client(ADMIN)
                for route in ROUTES:
                    if route.method == "GET" and "{" not in route.pattern:
                        self.assertIn(200, (viewer.get(route.pattern).status, admin.get(route.pattern).status,
                                            security.get(route.pattern).status), route.pattern)
                pid = "psn_" + rows("users")[0]["uuid"].replace("-", "")
                self.assertEqual(viewer.get(f"{V}/people/{pid}").status, 200)
                ambiguous = next(g for g in DS.groups if g.correlation_case == "MULTIPLE_MATCHES")
                self.assertEqual(security.post(f"{V}/mappings/{okta_ref(ambiguous.key)}/inspection", {}).status, 200)
                search = world.client(AUTOMATION).post(f"{V}/mappings/{okta_ref(ambiguous.key)}/searches",
                                                       {"by": "name", "value": ambiguous.name})
                self.assertEqual(search.status, 201, search.json)
                world.refresh_evidence(world.candidate("NM-C01"))
                candidate, approval = approve_okta(world, "NM-C01")
                self.assertEqual(dry_run(world, world.client(EXECUTOR), candidate, approval).status, 201)
                job = world.store.connection.execute("SELECT id FROM execution_jobs LIMIT 1").fetchone()[0]
                self.assertEqual(world.client(EXECUTOR).post(f"{V}/execution-jobs/{job}/execute", {}).code,
                                 "DEMO_MODE_BLOCKED")
                providers = world.app.providers
                self.assertEqual((providers.okta.name, providers.aap.name, type(providers.ad_directory).__name__),
                                 ("SyntheticOktaProvider", "DisabledAapProvider", "SyntheticMappingGateway"))
                self.assertEqual({e.adapter.value for e in providers.remediation_allowlist.entries}, {"SYNTHETIC"})
            finally:
                world.close()
        self.assertFalse([m for m in sys.modules if m.split(".")[0] in ("ldap", "ldap3")], "no LDAP library loaded")


class NullMeridianDemoClockTests(TempDirCase):
    def test_the_demo_world_clock_continues_from_the_seed(self):
        world = DemoWorld(self.tmp, dataset=NULL_MERIDIAN_KEY)
        try:
            newest = world.store.audit_events_page(limit=1)[0].occurred_at
            self.assertGreater(world.clock(), newest)
            self.assertLess(world.clock() - newest, timedelta(hours=1))
        finally:
            world.close()


if __name__ == "__main__":
    unittest.main()
