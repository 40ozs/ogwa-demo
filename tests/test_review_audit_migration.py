"""Migration 0005 (D41): dedicated review audit actions, with historical events preserved unchanged.

A schema-4 database is given a synthetic audit chain written the pre-0005 way (mapping and
policy reviews as APPROVAL_RECORDED with a "kind" detail), then upgraded. Every row must be
byte-for-byte identical afterwards, the chain must still verify, and the guards must still hold.
"""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction, AuditEvent, AuditResult, next_event, verify_chain
from app.store import codec
from app.store.db import DIALECT_SQLITE, connect
from app.store.migrations import v0002_append_only_guards, v0005_review_audit_actions
from app.store.migrator import upgrade
from tests.store_fixtures import memory_target

T = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
CLOCK = lambda: T  # noqa: E731
OPERATOR = Actor(ActorKind.HUMAN, "synthetic-reviewer-1")
LEGACY = [
    (AuditAction.STORE_INITIALIZED, {"environment": "SYNTHETIC"}),
    (AuditAction.APPROVAL_RECORDED, {"kind": "IDENTITY_MAPPING_REVIEW", "review_status": "PROPOSED"}),
    (AuditAction.APPROVAL_RECORDED, {"kind": "POLICY_VERSION", "policy_digest": "sha256:" + "b" * 64}),
    (AuditAction.EVIDENCE_RECORDED, {"kind": "AD_GROUP"}),
]


def insert(conn: sqlite3.Connection, event: AuditEvent) -> None:
    conn.execute(
        "INSERT INTO audit_events (id, sequence, occurred_at, actor_kind, actor_id, action, subject_id, details, "
        "previous_digest, digest, execution_mode, result, correlation_id, before_ref, after_ref) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event.id, event.sequence, codec.ts(event.occurred_at), event.actor.kind.value, event.actor.id,
         event.action.value, event.subject_id, codec.json_text([list(p) for p in event.details]),
         event.previous_digest, event.digest, event.execution_mode.value if event.execution_mode else None,
         event.result.value if event.result else None, event.correlation_id, event.before_ref, event.after_ref),
    )


def event_after(head: AuditEvent | None, action: AuditAction, details: dict, n: int) -> AuditEvent:
    return next_event(head, actor=OPERATOR, action=action, subject_id=f"synthetic-subject-{n}",
                      occurred_at=T + timedelta(minutes=n), details=details, execution_mode=ExecutionMode.LOCAL_SYNTHETIC,
                      result=AuditResult.SUCCEEDED, correlation_id=f"req-synthetic-{n}")


def rows(conn: sqlite3.Connection) -> list[tuple]:
    return [tuple(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY sequence")]


class ReviewAuditMigrationTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(memory_target())
        self.assertEqual(upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=4), [1, 2, 3, 4])
        self.events: list[AuditEvent] = []
        head = None
        for n, (action, details) in enumerate(LEGACY):
            head = event_after(head, action, details, n)
            insert(self.conn, head)
            self.events.append(head)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_schema_4_refuses_the_new_actions(self):
        new = event_after(self.events[-1], AuditAction.MAPPING_REVIEW_RECORDED, {"review_id": "x"}, 9)
        with self.assertRaises(sqlite3.IntegrityError):
            insert(self.conn, new)

    def test_historical_events_are_preserved_unchanged(self):
        before = rows(self.conn)
        self.assertEqual(upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=5), [5])
        self.assertEqual(rows(self.conn), before)
        legacy = [r for r in rows(self.conn) if r[5] == "APPROVAL_RECORDED"]
        self.assertEqual(len(legacy), 2)  # still APPROVAL_RECORDED with their "kind" details
        verify_chain(self.events, expected_head=self.events[-1].digest)

    def test_new_actions_extend_the_same_chain(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        head = self.events[-1]
        for n, action in enumerate((AuditAction.MAPPING_REVIEW_RECORDED, AuditAction.POLICY_REVIEW_RECORDED), start=10):
            head = event_after(head, action, {"synthetic": "yes"}, n)
            insert(self.conn, head)
            self.events.append(head)
        verify_chain(self.events, expected_head=head.digest)
        self.assertEqual([r[5] for r in rows(self.conn)][-2:], ["MAPPING_REVIEW_RECORDED", "POLICY_REVIEW_RECORDED"])

    def test_guards_survive_the_rebuild(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute("UPDATE audit_events SET subject_id = 'edited'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute("DELETE FROM audit_events")
        stray = event_after(None, AuditAction.MAPPING_REVIEW_RECORDED, {}, 20)  # does not extend the head
        with self.assertRaisesRegex(sqlite3.IntegrityError, "chain head"):
            insert(self.conn, stray)
        # A correctly chained row with an unknown action: only the rebuilt CHECK can refuse it.
        unknown = event_after(self.events[-1], AuditAction.EVIDENCE_RECORDED, {}, 22)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK constraint failed"):
            self.conn.execute(
                "INSERT INTO audit_events (id, sequence, occurred_at, actor_kind, actor_id, action, subject_id, details, "
                "previous_digest, digest) VALUES (?, ?, ?, 'HUMAN', 'synthetic', 'NOT_AN_ACTION', 's', '[]', ?, ?)",
                (unknown.id, unknown.sequence, codec.ts(unknown.occurred_at), unknown.previous_digest, unknown.digest))

    def test_triggers_and_indexes_are_recreated_verbatim(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        triggers = {name: sql for name, sql in self.conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'")}
        expected = {s.split()[2]: s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                    if s.split()[2] in ("trg_audit_events_no_update", "trg_audit_events_no_delete", "trg_audit_chain")}
        self.assertEqual(triggers, expected)
        indexes = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_events' AND sql IS NOT NULL")}
        self.assertEqual(indexes, {"ix_audit_subject", "ix_audit_correlation"})
        self.assertIsNone(self.conn.execute("SELECT name FROM sqlite_master WHERE name = 'audit_events_v5'").fetchone())

    def test_action_list_only_grows(self):
        from app.store.migrations.v0001_core_schema import AUDIT_ACTIONS as V1
        self.assertEqual(v0005_review_audit_actions.AUDIT_ACTIONS[: len(V1)], V1)
        self.assertEqual(set(v0005_review_audit_actions.AUDIT_ACTIONS) - set(V1),
                         {"MAPPING_REVIEW_RECORDED", "POLICY_REVIEW_RECORDED"})


if __name__ == "__main__":
    unittest.main()
