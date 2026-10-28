"""The Null Meridian dataset in a store: seeding, correlation, the directory snapshot, reset,
the operator API, and the guarantee that nothing contacts Okta, AD, or AAP."""

import ast
import contextlib
import io
import os
import socket
import sqlite3
import subprocess
import tempfile
import unittest
import urllib.request
from collections import Counter
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.core.modes import ExecutionMode
from app.demo.datasets import DATASET_KEYS, DEFAULT_DATASET, dataset, dataset_of
from app.demo.null_meridian.dataset import build_dataset
from app.demo.null_meridian.profile import AD_DNS_DOMAIN, AS_OF
from app.demo.null_meridian.world import CANDIDATES, POLICY, create_null_meridian_store, seed_null_meridian
from app.demo.synthetic_world import create_seeded_store
from app.domain.audit import AuditAction
from app.domain.evidence import EvidenceSource
from app.domain.model import OktaGroup
from app.store import __main__ as cli
from app.store import reset as reset_module
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreConflict, StoreError, StoreIntegrityError
from app.store.reset import reset_synthetic_store
from app.store.store import Store
from tests.api_fixtures import AUTOMATION, NO_ROLE, VIEWER, World
from tests.store_fixtures import file_target, memory_target, new_store, table_dump

REPO_ROOT = Path(__file__).resolve().parents[1]
V = "/api/v1"
# Golden: the audit head of a fresh Null Meridian seed by this build (schema 12). Any change to
# the dataset, the seed, or the store's write path moves it; update it (and the evidence report)
# only for an intended change.
GOLDEN_AUDIT_HEAD = "sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41"
# Golden: what the correlation engine proves for the 298 groups Okta sees.
GOLDEN_CONFIDENCES = {"EXACT_CONFIGURED_MAPPING": 201, "NOT_FOUND": 45, "UNVERIFIED_STABLE_ID": 42, "NAME_ONLY": 7,
                      "AMBIGUOUS": 3}


class SeededNullMeridianTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_null_meridian_store(memory_target())
        cls.by_key = {s.key: s for s in cls.summary.scenarios}
        cls.ds = build_dataset()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_golden_audit_head(self):
        self.assertEqual(self.summary.audit_head, GOLDEN_AUDIT_HEAD)
        self.assertEqual(self.summary.namespace, "null-meridian-v1")

    def test_candidates_reach_their_expected_states(self):
        self.assertEqual(len(self.store.candidate_ids()), len(CANDIDATES))
        for spec in CANDIDATES:
            with self.subTest(candidate=spec.key):
                self.assertIs(self.store.load_candidate(self.by_key[spec.key].candidate_id).state, spec.expected)
        refused = [e for e in self.store.audit_events() if e.action is AuditAction.TRANSITION_REFUSED]
        self.assertEqual([e.subject_id for e in refused], [self.by_key["NM-C06"].candidate_id])
        self.assertIn("NAME_ONLY", dict(refused[0].details)["problems"])

    def test_golden_correlation_outcomes(self):
        # One mapping per visible Okta group, counted at its latest observation. OGWA-DEMO-03:
        # NM-C11's evidence was collected again on the snapshot day, so the engine proved its
        # mapping a second time (same anchor, same answer); no other mapping was observed twice.
        latest = self.store.connection.execute(
            "SELECT o.confidence FROM identity_mapping_observations o WHERE o.observed_at = (SELECT max(p.observed_at) "
            "FROM identity_mapping_observations p WHERE p.mapping_id = o.mapping_id)").fetchall()
        confidences = Counter(r[0] for r in latest)
        self.assertEqual(dict(confidences), GOLDEN_CONFIDENCES)
        twice = self.store.connection.execute(
            "SELECT mapping_id, group_concat(confidence) FROM identity_mapping_observations GROUP BY mapping_id "
            "HAVING count(*) > 1").fetchall()
        recollected = self.store.evidence_bundle(self.store.load_candidate(self.by_key["NM-C11"].candidate_id)).mapping
        self.assertEqual([tuple(r) for r in twice],
                         [(recollected.id, "EXACT_CONFIGURED_MAPPING,EXACT_CONFIGURED_MAPPING")])
        visible = [g for g in self.ds.groups if g.okta_visible]
        self.assertEqual(sum(GOLDEN_CONFIDENCES.values()), len(visible))
        by_name = {}
        for row in self.store.connection.execute("SELECT id FROM okta_groups"):
            group = self.store.latest(OktaGroup, row[0])
            by_name.setdefault(group.name, []).append(group)
        read = self.store.connection.execute
        for name, expected in (("sg-okta-crm-user", "EXACT_CONFIGURED_MAPPING"),
                               ("SG-OKTA-VPN-USER", "EXACT_CONFIGURED_MAPPING"),  # normalized exact
                               ("GG_App_Wiki", "EXACT_CONFIGURED_MAPPING"),  # legacy name
                               ("sg-okta-payroll-user", "EXACT_CONFIGURED_MAPPING"),  # old AD group, new Okta group
                               ("WikiV1-Users", "NAME_ONLY"), ("sg-okta-etl-developer", "UNVERIFIED_STABLE_ID"),
                               ("Okta_Fax_Users", "NOT_FOUND"), ("Okta_CRM_Users", "NOT_FOUND")):
            with self.subTest(group=name):
                (group,) = by_name[name]
                row = read("SELECT o.confidence FROM identity_mappings m JOIN identity_mapping_observations o "
                           "ON o.mapping_id = m.id WHERE m.group_id = ?", (group.id,)).fetchone()
                self.assertEqual(row[0], expected)
        ambiguous = [g for g in by_name["Finance-RW"] if g.group_type.value == "OKTA_GROUP"]
        row = read("SELECT o.confidence FROM identity_mappings m JOIN identity_mapping_observations o "
                   "ON o.mapping_id = m.id WHERE m.group_id = ?", (ambiguous[0].id,)).fetchone()
        self.assertEqual(row[0], "AMBIGUOUS")

    def test_every_record_is_synthetic_and_fictional(self):
        conn = self.store.connection
        for table in ("okta_application_observations", "okta_group_observations", "ad_group_observations",
                      "assignment_observations", "usage_observations", "identity_mapping_observations",
                      "dependency_observations", "collector_runs"):
            sources = {r[0] for r in conn.execute(f"SELECT DISTINCT source FROM {table}")}
            self.assertEqual(sources, {EvidenceSource.SYNTHETIC.value}, table)
        self.assertEqual({r[0] for r in conn.execute("SELECT DISTINCT domain FROM ad_group_observations")},
                         {AD_DNS_DOMAIN})
        self.assertTrue(all(r[0].startswith("00gSYNTHNM") for r in conn.execute("SELECT okta_group_id FROM okta_groups")))
        self.assertTrue(all(r[0].startswith("0oaSYNTHNM") for r in conn.execute("SELECT okta_app_id FROM okta_applications")))
        modes = {r[0] for r in conn.execute("SELECT DISTINCT execution_mode FROM audit_events")}
        self.assertEqual(modes, {"LOCAL_SYNTHETIC"})
        self.assertEqual({r[0] for r in conn.execute("SELECT DISTINCT execution_mode FROM execution_jobs")},
                         {"DRY_RUN_MUTATION"})
        self.assertEqual(conn.execute("SELECT count(*) FROM execution_job_status_events WHERE executed = 1").fetchone()[0], 0)

    def test_directory_snapshot_is_complete_and_audited(self):
        info = self.store.synthetic_directory()
        self.assertEqual((info.dataset, info.seed, info.company, info.as_of), ("null-meridian", "null-meridian-v1",
                                                                              "Null Meridian", AS_OF))
        kinds = dict(self.store.connection.execute(
            "SELECT kind, count(*) FROM synthetic_directory_records GROUP BY kind").fetchall())
        self.assertEqual(kinds["PERSON"], len(self.ds.people))
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM synthetic_directory_records WHERE kind = 'PERSON' AND ref_b = 'ACTIVE'").fetchone()[0],
            1800)
        self.assertEqual(kinds["GROUP"], len(self.ds.groups))
        self.assertEqual(kinds["SCENARIO"], 10)
        report = self.store.verify_integrity(expected_audit_head=self.summary.audit_head)
        self.assertEqual(report.directory_records_checked, info.record_count)
        self.assertEqual(report.candidates_checked, len(CANDIDATES))
        last = self.store.audit_events()[-1]
        self.assertIs(last.action, AuditAction.SYNTHETIC_SEED_LOADED)
        self.assertEqual(dict(last.details)["directory_digest"], info.content_digest)
        self.assertIs(dataset_of(self.store).policy, POLICY)

    def test_the_snapshot_is_append_only_and_tampering_is_detected(self):
        store, _ = create_null_meridian_store(memory_target())
        self.addCleanup(store.close)
        conn = store.connection
        for sql in ("UPDATE synthetic_directory_records SET body = '{}' WHERE kind = 'PERSON'",
                    "DELETE FROM synthetic_directory_records WHERE kind = 'FINDING'",
                    "UPDATE synthetic_directory_snapshots SET seed = 'other'"):
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute(sql)
        with self.assertRaisesRegex(StoreConflict, "already holds"):
            store.record_synthetic_seed(actor=store.audit_events()[0].actor, namespace="x", scenario_count=0,
                                        as_of=AS_OF, directory=seed_snapshot_copy(store))
        conn.execute("DROP TRIGGER trg_synthetic_directory_records_no_update")
        conn.execute("UPDATE synthetic_directory_records SET body = '{\"tampered\":true}' "
                     "WHERE kind = 'PERSON' AND sort_key = 'NM00001'")
        with self.assertRaisesRegex(StoreIntegrityError, "synthetic directory"):
            store.verify_integrity()

    def test_a_snapshot_cannot_enter_a_non_synthetic_store(self):
        with new_store(environment=DatabaseEnvironment.DEVELOPMENT) as development:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "SYNTHETIC store"):
                development.connection.execute(
                    "INSERT INTO synthetic_directory_snapshots VALUES ('sdir_' || hex(randomblob(16)), 1, 'x', 'x', 'x', "
                    "'2026-10-01T00:00:00.000000Z', 0, 'sha256:' || lower(hex(randomblob(32))), "
                    "'2026-10-01T00:00:00.000000Z', 'req')")
            with self.assertRaisesRegex(StoreError, "SYNTHETIC store"):
                seed_null_meridian(development)


def seed_snapshot_copy(store: Store):
    from app.demo.null_meridian.world import directory_snapshot

    return directory_snapshot(build_dataset(), {})


class ReproducibilityTests(unittest.TestCase):
    def test_seeding_twice_gives_identical_databases(self):
        first, a = create_null_meridian_store(memory_target())
        second, b = create_null_meridian_store(memory_target())
        try:
            self.assertEqual(a, b)
            self.assertEqual(table_dump(first), table_dump(second))
        finally:
            first.close()
            second.close()

    def test_seed_refuses_a_non_empty_store(self):
        store, _ = create_seeded_store(memory_target())
        with store, self.assertRaisesRegex(StoreError, "empty store"):
            seed_null_meridian(store)


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "var"
        self.root.mkdir()
        self.target = file_target(self.root / "demo.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def reset(self, **kw):
        return reset_synthetic_store(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC, confirmed=True,
                                     allowed_root=self.root, **kw)

    def test_reset_returns_the_store_to_the_exact_canonical_state(self):
        self.reset(dataset="classic")  # some other state first
        result = self.reset(dataset="null-meridian")
        self.assertTrue(result.replaced_existing)
        self.assertEqual(result.summary.audit_head, GOLDEN_AUDIT_HEAD)
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            canonical = table_dump(store)
            # Activity after the seed: an operator re-observes evidence (as a collector would).
            group = store.latest(OktaGroup, store.connection.execute("SELECT id FROM okta_groups LIMIT 1").fetchone()[0])
            from dataclasses import replace
            store.record_evidence(replace(group, provenance=replace(group.provenance, observed_at=AS_OF + timedelta(hours=1))),
                                  actor=store.audit_events()[-1].actor)
        again = self.reset(dataset="null-meridian")
        self.assertEqual(again.summary.audit_head, GOLDEN_AUDIT_HEAD)
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            self.assertEqual(table_dump(store), canonical)
            store.verify_integrity(expected_audit_head=GOLDEN_AUDIT_HEAD)

    def test_an_unknown_dataset_is_refused_before_anything_is_touched(self):
        self.reset(dataset="null-meridian")
        before = self.target.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "unknown demo dataset"):
            self.reset(dataset="production")
        self.assertEqual(self.target.path.read_bytes(), before)

    def run_cli(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        env["OGWA_EXECUTION_MODE"] = "LOCAL_SYNTHETIC"
        env["OGWA_DATABASE_URL"] = f"sqlite:///{self.target.path.as_posix()}"
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(reset_module, "DEFAULT_ALLOWED_ROOT", self.root), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_cli_seeds_null_meridian_by_name(self):
        # SYNTH-OGWA-01: the CLI's default is Genesee Press (tests/test_genesee_press.py); the legacy dataset is named.
        self.assertEqual((DEFAULT_DATASET, DATASET_KEYS), ("genesee-press", ("genesee-press", "null-meridian", "classic")))
        code, out, _ = self.run_cli("reset-demo", "--confirm-synthetic-reset", "--dataset", "null-meridian")
        self.assertEqual(code, 0, out)
        self.assertIn("dataset null-meridian, seed null-meridian-v1", out)
        self.assertIn("NM-C08  HOLD", out)
        self.assertIn(GOLDEN_AUDIT_HEAD, out)
        code, out, _ = self.run_cli("status")
        self.assertIn("demo_dataset:   null-meridian (seed null-meridian-v1", out)
        code, out, _ = self.run_cli("verify", "--expected-audit-head", GOLDEN_AUDIT_HEAD)
        self.assertEqual(code, 0, out)
        self.assertIn("11 candidates verified, 31270 synthetic directory records", out)

    def test_reset_still_refuses_outside_local_synthetic(self):
        for mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION):
            with self.subTest(mode=mode), self.assertRaisesRegex(reset_module.ResetRefused, "LOCAL_SYNTHETIC"):
                reset_synthetic_store(self.target, mode=mode, confirmed=True, allowed_root=self.root,
                                      dataset="null-meridian")
        self.assertFalse(self.target.path.exists())


class NoLiveAccessTests(unittest.TestCase):
    """Seeding and serving the demo never opens a socket, a URL, or a process."""

    MODULES = sorted([*(REPO_ROOT / "app" / "demo" / "null_meridian").glob("*.py"), *(REPO_ROOT / "app" / "governance").glob("*.py"),
                      REPO_ROOT / "app" / "demo" / "datasets.py", REPO_ROOT / "app" / "api" / "directory.py"])
    FORBIDDEN = ("app.integrations", "app.core.http_client", "app.core.http_mutation", "app.remediation", "socket",
                 "urllib", "http", "subprocess", "ssl", "requests")

    def test_no_dataset_module_imports_a_network_integration_or_process_module(self):
        for path in self.MODULES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                for name in names:
                    with self.subTest(module=path.name, imports=name):
                        self.assertFalse(any(name == f or name.startswith(f + ".") for f in self.FORBIDDEN))

    def test_seeding_and_the_api_never_touch_the_network_or_spawn_processes(self):
        def refuse(*_a, **_k):
            raise AssertionError("a demo operation tried to reach the network or start a process")

        with mock.patch.object(socket.socket, "connect", refuse), mock.patch.object(socket, "create_connection", refuse), \
                mock.patch.object(urllib.request, "urlopen", refuse), mock.patch.object(subprocess, "Popen", refuse):
            world = World(dataset="null-meridian")
            try:
                client = world.client(AUTOMATION)
                for path in ("/directory", "/people?limit=5", "/directory-groups?health=ACTIONABLE", "/governance-findings",
                             "/demo-scenarios", "/dashboard", "/applications", "/groups", "/mappings", "/candidates"):
                    self.assertEqual(client.get(V + path).status, 200, path)
                crm = next(r[0] for r in world.store.connection.execute("SELECT id FROM okta_groups") if
                           world.store.latest(OktaGroup, r[0]).name == "sg-okta-crm-user")
                inspection = client.post(f"{V}/mappings/{crm}/inspection", {})
                self.assertEqual(inspection.status, 200, inspection.json)
                self.assertEqual(inspection.json["confidence"], "EXACT_CONFIGURED_MAPPING")
            finally:
                world.close()


class DirectoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")
        cls.client = cls.world.client(VIEWER)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def get(self, path):
        return self.client.get(V + path)

    def test_summary(self):
        body = self.get("/directory").json
        self.assertTrue(body["available"])
        self.assertEqual(body["profile"]["company"], "Null Meridian")
        self.assertEqual(body["counts"]["activeEmployees"], 1800)
        self.assertEqual(len(body["departments"]), 14)
        self.assertEqual(sum(1 for a in body["applications"] if a["status"] == "ACTIVE"), 76)

    def test_people_paging_and_filters(self):
        seen, cursor = 0, None
        while True:
            result = self.get(f"/people?status=ACTIVE&limit=200" + (f"&cursor={cursor}" if cursor else ""))
            self.assertEqual(result.status, 200)
            seen += len(result.json["items"])
            cursor = result.json["page"]["nextCursor"]
            if not cursor:
                break
        self.assertEqual(seen, 1800)
        data = self.get("/people?department=data&limit=200").json["items"]
        self.assertTrue(data and all(p["department"] == "data" for p in data))
        for bad in ("/people?status=SOMETIMES", "/people?department=Not%20A%20Slug", "/people?q=", "/people?extra=1",
                    "/directory-groups?health=GREAT", "/governance-findings?code=NOPE"):
            with self.subTest(query=bad):
                self.assertEqual(self.get(bad).status, 400)

    def test_person_detail_shows_history_and_access_paths(self):
        pid = self.get("/people?department=data&limit=1").json["items"][0]["id"]
        body = self.get(f"/people/{pid}").json
        self.assertEqual(body["history"][0]["kind"], "HIRED")
        self.assertTrue(body["access"])
        self.assertTrue(any(r["chain"] for a in body["access"] for r in a["routes"]))
        self.assertEqual(self.get("/people/psn_" + "0" * 32).status, 404)
        self.assertEqual(self.get("/people/not-an-id").status, 404)

    def test_group_detail_findings_and_scenarios(self):
        item = self.get("/directory-groups?q=sg-okta-warehouse-readonly").json["items"][0]
        body = self.get(f"/directory-groups/{item['id']}").json
        self.assertIn("DEEP_NESTING", {f["code"] for f in body["findings"]})
        self.assertEqual(body["children"][0]["name"], "OKTA-Warehouse-Readers")
        self.assertEqual(self.get("/directory-groups/dgrp_" + "0" * 32).status, 404)
        findings = self.get("/governance-findings?severity=ACTIONABLE&limit=200").json
        self.assertTrue(findings["items"] and all(f["severity"] == "ACTIONABLE" for f in findings["items"]))
        scenarios = self.get("/demo-scenarios").json["items"]
        self.assertEqual(len(scenarios), 10)
        for s in scenarios:
            if s["candidateId"]:
                self.assertEqual(self.get(f"/candidates/{s['candidateId']}").status, 200)

    def test_inventory_pages_link_into_the_directory(self):
        crm = next(a for a in self.get("/directory").json["applications"] if a["slug"] == "crm")
        detail = self.get(f"/applications/{crm['id']}").json
        self.assertEqual(len(detail["profile"]["directAssignments"]), 23)
        group = self.get("/groups?limit=1").json["items"][0]
        self.assertIsNotNone(self.get(f"/groups/{group['id']}").json["directory"])

    def test_a_principal_without_a_role_is_refused(self):
        client = self.world.client(NO_ROLE)
        for path in ("/directory", "/people", "/directory-groups", "/governance-findings", "/demo-scenarios"):
            self.assertEqual(client.get(V + path).status, 403, path)

    def test_the_classic_world_answers_without_a_snapshot(self):
        world = World()
        try:
            client = world.client(VIEWER)
            self.assertFalse(client.get(f"{V}/directory").json["available"])
            self.assertEqual(client.get(f"{V}/people").json["items"], [])
            self.assertEqual(client.get(f"{V}/demo-scenarios").json["items"], [])
            self.assertIsNone(client.get(f"{V}/applications/{world.store.connection.execute('SELECT id FROM okta_applications LIMIT 1').fetchone()[0]}").json["profile"])
        finally:
            world.close()

    def test_the_directory_view_only_selects(self):
        tree = ast.parse((REPO_ROOT / "app" / "api" / "directory.py").read_text(encoding="utf-8"))
        statements = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                first = node.args[0]
                text = first.value if isinstance(first, ast.Constant) else "".join(
                    v.value for v in getattr(first, "values", ()) if isinstance(v, ast.Constant))
                self.assertTrue(text.lstrip().upper().startswith("SELECT"), text)
                statements += 1
        self.assertGreaterEqual(statements, 2)


class DatasetRegistryTests(unittest.TestCase):
    def test_registry(self):
        self.assertEqual(dataset("classic").key, "classic")
        nm = dataset("null-meridian")
        self.assertEqual((nm.namespace, nm.as_of), ("null-meridian-v1", AS_OF))
        self.assertTrue(nm.correlation_path.is_file())
        with self.assertRaises(ValueError):
            dataset("live")


if __name__ == "__main__":
    unittest.main()
