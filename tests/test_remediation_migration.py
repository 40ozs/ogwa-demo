"""Migration 0010: the REMEDIATION_DRY_RUN_RECORDED audit action.

The audit table is rebuilt to extend its action list. Every row, digest, index, and guard
must survive byte for byte, and an anchored head must still verify.
"""

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from app.core.modes import ExecutionMode
from app.demo.synthetic_world import create_seeded_store
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction
from app.domain.remediation import RemediationOperation, RemediationOutcome
from app.remediation.engine import remediation_dry_run
from app.remediation.allowlist import load_allowlist
from app.api.local import SYNTHETIC_REMEDIATION_ALLOWLIST_PATH
from app.demo.synthetic_world import POLICY as DEMO_POLICY
from app.store.db import DIALECT_SQLITE, connect
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreConflict
from app.store.migrations import v0001_core_schema, v0002_append_only_guards, v0010_remediation_dry_runs
from app.store.migrator import upgrade
from app.store.store import Store
from tests.store_fixtures import build_held_at, file_target
from tests.test_evidence_incomplete_state import dump

TABLES = ("candidates", "decisions", "approvals", "execution_jobs", "execution_job_status_events", "audit_events",
          "mapping_reviews", "policy_versions", "collector_runs")
EXECUTOR = Actor(ActorKind.HUMAN, "synthetic.executor.one")


def simulated_okta_dry_run(store: Store, candidate_id: str):
    """A SIMULATED result for a seeded APPROVED candidate (S14), built without the API."""
    candidate = store.load_candidate(candidate_id)
    approval = store.approvals_for(candidate_id)[0]
    evidence = store.evidence_bundle(candidate)
    # Just after both the newest evidence and the approval: fresh, and the approval is in force.
    now = max([approval.decided_at, *(r.provenance.observed_at for r in evidence.records())]) + timedelta(minutes=1)
    result = remediation_dry_run(
        candidate=candidate, operation=RemediationOperation.OKTA_GROUP_UNASSIGN, target_ref=candidate.assignment_ids[0],
        evidence=evidence, approval=approval, policy=DEMO_POLICY, now=now, mode=ExecutionMode.LOCAL_SYNTHETIC,
        requested_by=EXECUTOR, requested_mode=None, environment=DatabaseEnvironment.SYNTHETIC,
        allowlist=load_allowlist(SYNTHETIC_REMEDIATION_ALLOWLIST_PATH, environment=DatabaseEnvironment.SYNTHETIC),
        correlation_id="req_" + "b" * 32)
    return result, approval


class RemediationAuditMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = file_target(Path(self.tmp.name) / "seeded.sqlite3")
        with build_held_at(9):
            store, self.summary = create_seeded_store(self.target)
            store.close()
        self.s14 = next(s.candidate_id for s in self.summary.scenarios if s.key == "S14")

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_row_and_the_anchored_head_survive(self):
        conn = connect(self.target)
        try:
            before = {t: dump(conn, t) for t in TABLES}
            self.assertTrue(before["audit_events"])
            self.assertEqual(upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of, target=10), [10])
            self.assertEqual({t: dump(conn, t) for t in TABLES}, before)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'audit_events_v%'").fetchall(),
                             [])
        finally:
            conn.close()
        # Verify the store exactly as 0010 left it (the build is held at 10; 0011 is tested separately).
        with build_held_at(10), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            report = store.verify_integrity(expected_audit_head=self.summary.audit_head)
            self.assertEqual((report.schema_version, report.audit_head), (10, self.summary.audit_head))

    def test_the_guards_and_indexes_are_recreated_byte_for_byte(self):
        conn = connect(self.target)
        try:
            upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of, target=10)
            triggers = {n: sql for n, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'")}
            expected = {s.split()[2]: s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                        if s.split("\n", 1)[0].endswith(" ON audit_events")}
            self.assertEqual(triggers, expected)
            self.assertEqual(set(expected), {"trg_audit_events_no_update", "trg_audit_events_no_delete",
                                             "trg_audit_chain"})
            indexes = {n: sql for n, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_events' "
                "AND sql IS NOT NULL")}
            self.assertEqual(indexes, {s.split()[2]: s for s in v0001_core_schema.STATEMENTS
                                       if s.startswith("CREATE INDEX ix_audit_")})
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("UPDATE audit_events SET details = '[]'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("DELETE FROM audit_events")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK|chain"):
                conn.execute("INSERT INTO audit_events SELECT 'aud_' || lower(hex(randomblob(16))), sequence + 1, "
                             "occurred_at, actor_kind, actor_id, 'EXECUTED_PRODUCTION', subject_id, details, digest, "
                             "digest, execution_mode, result, correlation_id, before_ref, after_ref FROM audit_events "
                             "ORDER BY sequence DESC LIMIT 1")
        finally:
            conn.close()

    def test_the_action_is_refused_before_0010_and_recorded_after(self):
        with build_held_at(9), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            result, approval = simulated_okta_dry_run(store, self.s14)
            self.assertIs(result.outcome, RemediationOutcome.SIMULATED, result.gates.problems())
            with self.assertRaisesRegex(StoreConflict, "CHECK"):
                store.record_remediation_dry_run(actor=EXECUTOR, candidate_id=self.s14, result=result,
                                                 approval_id=approval.id, evidence_fingerprint="sha256:" + "0" * 64,
                                                 correlation_id="req_" + "b" * 32)
        conn = connect(self.target)
        upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of)
        conn.close()
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            result, approval = simulated_okta_dry_run(store, self.s14)
            event = store.record_remediation_dry_run(actor=EXECUTOR, candidate_id=self.s14, result=result,
                                                     approval_id=approval.id, evidence_fingerprint="sha256:" + "0" * 64,
                                                     correlation_id="req_" + "b" * 32)
            self.assertIs(event.action, AuditAction.REMEDIATION_DRY_RUN_RECORDED)
            self.assertEqual(store.remediation_dry_runs(self.s14), (event,))
            self.assertEqual(dict(event.details)["executed"], "false")
            store.verify_integrity()

    def test_the_frozen_list_extends_0007_by_exactly_one_action(self):
        from app.store.migrations import v0007_governed_refusals  # noqa: PLC0415

        self.assertEqual(v0010_remediation_dry_runs.AUDIT_ACTIONS[: len(v0007_governed_refusals.AUDIT_ACTIONS)],
                         v0007_governed_refusals.AUDIT_ACTIONS)
        self.assertEqual(set(v0010_remediation_dry_runs.AUDIT_ACTIONS) - set(v0007_governed_refusals.AUDIT_ACTIONS),
                         {"REMEDIATION_DRY_RUN_RECORDED"})


class RecordRulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store, summary = create_seeded_store(file_target(Path(self.tmp.name) / "s.sqlite3"))
        self.s14 = next(s.candidate_id for s in summary.scenarios if s.key == "S14")
        self.s07 = next(s.candidate_id for s in summary.scenarios if s.key == "S07")
        self.result, self.approval = simulated_okta_dry_run(self.store, self.s14)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def record(self, **changes):
        fields = dict(actor=EXECUTOR, candidate_id=self.s14, result=self.result, approval_id=self.approval.id,
                      evidence_fingerprint="sha256:" + "0" * 64, correlation_id="req_" + "c" * 32)
        fields.update(changes)
        return self.store.record_remediation_dry_run(**fields)

    def test_only_a_human_can_record_and_only_against_a_recorded_approval_of_the_candidate(self):
        head = self.store.audit_head()
        with self.assertRaises(StoreConflict):
            self.record(actor=Actor(ActorKind.SYSTEM, "ogwa/x"))
        with self.assertRaises(StoreConflict):
            self.record(candidate_id=self.s07)  # S14's approval is not S07's
        with self.assertRaises(StoreConflict):
            self.record(approval_id="apr_" + "0" * 32)
        with self.assertRaises(TypeError):
            self.record(result={"outcome": "SIMULATED"})
        self.assertEqual(self.store.audit_head(), head)
        self.record()
        self.assertEqual(len(self.store.remediation_dry_runs(self.s14)), 1)


if __name__ == "__main__":
    unittest.main()
