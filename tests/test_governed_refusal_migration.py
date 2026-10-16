"""Migration 0007: the GOVERNED_REQUEST_REFUSED audit action.

The synthetic demo world is seeded into a schema-6 store (the build is held at 6 for the
seed) and then upgraded. Every audit event must be unchanged, the chain must verify, the
guards must survive the rebuild, and the new action must be refused before 0007.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.demo.synthetic_world import create_seeded_store
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction, AuditResult
from app.domain.ids import IdKind, new_id
from app.store.db import DIALECT_SQLITE, connect
from app.store.errors import StoreConflict
from app.store.migrations import v0002_append_only_guards, v0005_review_audit_actions, v0007_governed_refusals
from app.store.migrator import upgrade
from app.store.store import Store
from app.core.modes import ExecutionMode
from tests.store_fixtures import build_held_at, file_target, table_dump

PERSON = Actor(ActorKind.HUMAN, "synthetic.securityiam.one")


def held_at_schema_6():
    return build_held_at(6)


def audit_rows(conn: sqlite3.Connection) -> list[tuple]:
    columns = ", ".join(r[1] for r in conn.execute("PRAGMA table_info(audit_events)"))
    return [tuple(r) for r in conn.execute(f"SELECT {columns} FROM audit_events ORDER BY sequence")]


class GovernedRefusalMigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = file_target(Path(tmp.name) / "seeded.sqlite3")
        with held_at_schema_6():
            store, self.summary = create_seeded_store(self.target)
            store.close()

    def test_schema_6_refuses_the_new_action(self):
        with held_at_schema_6():
            store = Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC)
            try:
                with self.assertRaises(StoreConflict):
                    store.record_governed_refusal(actor=PERSON, subject_id="cand_x", details={"code": "FORBIDDEN"},
                                                  correlation_id=new_id(IdKind.REQUEST))
            finally:
                store.close()

    def test_events_are_preserved_and_the_chain_still_verifies(self):
        conn = connect(self.target)
        try:
            before = audit_rows(conn)
            self.assertEqual(upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of, target=7), [7])  # 0007 alone
            self.assertEqual(audit_rows(conn), before)
            self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name = 'audit_events_v7'").fetchone())
        finally:
            conn.close()
        # Verify the store exactly as 0007 left it (the build is held at 7; 0008 is tested separately).
        with build_held_at(7), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            report = store.verify_integrity(expected_audit_head=self.summary.audit_head)
        self.assertEqual(report.audit_head, self.summary.audit_head)

    def test_the_new_action_extends_the_same_chain_and_changes_nothing_else(self):
        conn = connect(self.target)
        upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of)
        conn.close()
        store = Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC)
        try:
            before = {t: rows for t, rows in table_dump(store).items() if t != "audit_events"}
            request_id = new_id(IdKind.REQUEST)
            event = store.record_governed_refusal(
                actor=PERSON, subject_id="cand_synthetic", correlation_id=request_id,
                details={"code": "SEPARATION_OF_DUTIES", "note": "token=synthetic-secret-value"})
            self.assertEqual((event.action, event.result, event.correlation_id),
                             (AuditAction.GOVERNED_REQUEST_REFUSED, AuditResult.REFUSED, request_id))
            self.assertNotIn("synthetic-secret-value", str(event.details))  # details are redacted
            self.assertEqual({t: rows for t, rows in table_dump(store).items() if t != "audit_events"}, before)
            store.verify_integrity()
            with self.assertRaises(StoreConflict):
                store.record_governed_refusal(actor=Actor(ActorKind.SYSTEM, "collector/synthetic"), subject_id="x",
                                              details={}, correlation_id=new_id(IdKind.REQUEST))
        finally:
            store.close()

    def test_guards_triggers_and_indexes_survive_the_rebuild(self):
        conn = connect(self.target)
        try:
            upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("UPDATE audit_events SET subject_id = 'edited'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("DELETE FROM audit_events")
            triggers = {name: sql for name, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'")}
            expected = {s.split()[2]: s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                        if s.split()[2] in ("trg_audit_events_no_update", "trg_audit_events_no_delete", "trg_audit_chain")}
            self.assertEqual(triggers, expected)
            indexes = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_events' AND sql IS NOT NULL")}
            self.assertEqual(indexes, {"ix_audit_subject", "ix_audit_correlation"})
        finally:
            conn.close()

    def test_action_list_only_grows(self):
        v5 = v0005_review_audit_actions.AUDIT_ACTIONS
        self.assertEqual(v0007_governed_refusals.AUDIT_ACTIONS[: len(v5)], v5)
        self.assertEqual(set(v0007_governed_refusals.AUDIT_ACTIONS) - set(v5), {"GOVERNED_REQUEST_REFUSED"})


if __name__ == "__main__":
    unittest.main()
