"""Migration 0011: the AD quarantine and deletion stages, on a store with legacy rows.

The store is seeded by the build as it was at schema 10, so it holds S12's legacy
``AD_RETIREMENT`` approval and dry-run job. The owner authorized 0011 on the local synthetic
store after a rehearsal on a copy, preserving the D95 audit chain (D150); these tests are
that rehearsal's contract:

- every row of every table survives verbatim, and the audit head is unchanged;
- legacy ``AD_RETIREMENT`` rows still load, and nothing new may use them (D148);
- the guards are recreated; a quarantined candidate can never stand before its quarantine
  (D144).
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.core.modes import ExecutionMode
from app.demo.synthetic_world import create_seeded_store, seeded_id
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalRecord, ApprovalStage
from app.domain.execution import JobKind
from app.domain.ids import IdKind
from app.store.db import DIALECT_SQLITE, connect
from app.store.errors import StoreConflict
from app.store.migrations import v0001_core_schema, v0002_append_only_guards
from app.store.migrations import v0011_ad_quarantine_deletion_stages as v0011
from app.store.migrator import upgrade
from app.store.store import Store
from tests.store_fixtures import build_held_at, file_target

TABLES = ("candidates", "approvals", "execution_jobs", "decisions", "audit_events", "candidate_assignments",
          "execution_job_targets", "execution_job_status_events")
NEW_COLUMNS = ("quarantine_approver_kind", "quarantine_approver_id", "quarantine_hold_until",
               "deletion_proposer_kind", "deletion_proposer_id", "deletion_proposed_at")
REBUILT = ("candidates", "approvals", "execution_jobs", "decisions")


def dump(conn: sqlite3.Connection, table: str, columns: tuple[str, ...] | None = None) -> list[tuple]:
    columns = columns or tuple(r[1] for r in conn.execute(f"PRAGMA table_info({table})"))
    names = ", ".join(columns)
    return [tuple(r) for r in conn.execute(f"SELECT {names} FROM {table} ORDER BY {names}")]


def objects(conn: sqlite3.Connection, kind: str) -> dict[str, str]:
    placeholders = ", ".join("?" for _ in REBUILT)
    return {n: sql for n, sql in conn.execute(
        f"SELECT name, sql FROM sqlite_master WHERE type = ? AND tbl_name IN ({placeholders}) AND sql IS NOT NULL",
        (kind, *REBUILT))}


class AdStagesMigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = file_target(Path(tmp.name) / "seeded.sqlite3")
        with build_held_at(10):
            store, self.summary = create_seeded_store(self.target)
            store.close()
        self.s12 = next(s.candidate_id for s in self.summary.scenarios if s.key == "S12")
        self.legacy_approval = seeded_id(IdKind.APPROVAL, "S12-ad")
        self.legacy_job = seeded_id(IdKind.EXECUTION_JOB, "S12-ad")

    def upgraded(self) -> sqlite3.Connection:
        conn = connect(self.target)
        self.addCleanup(conn.close)
        # 0011, then 0012 (the synthetic directory snapshot tables, which touch no existing table).
        self.assertEqual(upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of), [11, 12])
        return conn

    def test_the_seed_at_schema_10_holds_legacy_rows(self):
        conn = connect(self.target)
        try:
            stages = {r[0] for r in conn.execute("SELECT stage FROM approvals")}
            kinds = {r[0] for r in conn.execute("SELECT kind FROM execution_jobs")}
        finally:
            conn.close()
        self.assertIn("AD_RETIREMENT", stages)
        self.assertIn("AD_RETIREMENT", kinds)

    def test_every_row_survives_and_the_new_columns_start_null(self):
        conn = connect(self.target)
        old_candidate_columns = tuple(r[1] for r in conn.execute("PRAGMA table_info(candidates)"))
        self.assertEqual(old_candidate_columns, v0011._CANDIDATE_COLUMNS)
        before = {t: dump(conn, t) for t in TABLES}
        conn.close()
        conn = self.upgraded()
        after = {t: dump(conn, t, old_candidate_columns if t == "candidates" else None) for t in TABLES}
        self.assertEqual(after, before)
        self.assertEqual(set(dump(conn, "candidates", NEW_COLUMNS)), {(None,) * len(NEW_COLUMNS)})
        self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'ogwa_v0011_%'").fetchall(), [])

    def test_the_anchored_audit_head_still_verifies_and_legacy_rows_load(self):
        self.upgraded()
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            report = store.verify_integrity(expected_audit_head=self.summary.audit_head)
            self.assertEqual((report.schema_version, report.audit_head), (12, self.summary.audit_head))
            self.assertEqual(report.candidates_checked, 14)
            self.assertIs(store.load_approval(self.legacy_approval).stage, ApprovalStage.AD_RETIREMENT)
            self.assertIs(store.load_execution_job(self.legacy_job).kind, JobKind.AD_RETIREMENT)
            s12 = store.load_candidate(self.s12)
            self.assertEqual((s12.state.value, s12.quarantine_approver, s12.quarantine_hold_until),
                             ("REVALIDATION_REQUIRED", None, None))

    def test_nothing_new_may_use_the_legacy_stage(self):
        """D148, in the store and in the database itself."""
        conn = self.upgraded()
        legacy = conn.execute("SELECT * FROM approvals WHERE id = ?", (self.legacy_approval,)).fetchone()
        columns = legacy.keys()
        copy = dict(zip(columns, tuple(legacy)), id="apr_" + "f" * 32)
        names = ", ".join(copy)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "legacy approval stage"):
            conn.execute(f"INSERT INTO approvals ({names}) VALUES ({', '.join('?' for _ in copy)})", tuple(copy.values()))
        job = conn.execute("SELECT * FROM execution_jobs WHERE id = ?", (self.legacy_job,)).fetchone()
        copy = dict(zip(job.keys(), tuple(job)), id="job_" + "f" * 32)
        names = ", ".join(copy)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "legacy job kind"):
            conn.execute(f"INSERT INTO execution_jobs ({names}) VALUES ({', '.join('?' for _ in copy)})",
                         tuple(copy.values()))
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            approval = store.load_approval(self.legacy_approval)
            fresh = ApprovalRecord(
                id="apr_" + "e" * 32, candidate_id=self.s12, stage=ApprovalStage.AD_RETIREMENT,
                decision=ApprovalDecision.APPROVE, operator=Actor(ActorKind.HUMAN, "synthetic.reviewer.two"),
                decided_at=approval.decided_at, reason="a new legacy approval", evidence_fingerprint=approval.evidence_fingerprint,
                candidate_epoch=approval.candidate_epoch, expires_at=approval.expires_at)
            with self.assertRaisesRegex(StoreConflict, "legacy approval stage"):
                store.record_approval(fresh)

    def test_the_guards_are_recreated(self):
        conn = self.upgraded()
        triggers = objects(conn, "trigger")
        v0002 = {s.split()[2]: s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                 if s.startswith("CREATE TRIGGER ") and s.split("\n", 1)[0].split(" ON ")[-1] in REBUILT}
        self.assertEqual(len(v0002), 11)
        for name, sql in v0002.items():
            with self.subTest(trigger=name):
                if name == "trg_candidates_start_discovered":
                    self.assertTrue(triggers[name].startswith(sql.split("\nBEGIN")[0].rsplit(" OR NEW.okta", 1)[0]))
                    for column in ("quarantine_approver_kind", "quarantine_hold_until", "deletion_proposer_kind",
                                   "deletion_proposed_at"):
                        self.assertIn(f"NEW.{column} IS NOT NULL", triggers[name])
                else:
                    self.assertEqual(triggers[name], sql)
        self.assertEqual(set(triggers) - set(v0002), {"trg_approvals_no_legacy_stage",
                                                      "trg_execution_jobs_no_legacy_kind",
                                                      "trg_decisions_no_legacy_step"})
        indexes = objects(conn, "index")
        expected = {s.split()[2 if s.startswith("CREATE INDEX") else 3]: s for s in v0001_core_schema.STATEMENTS
                    if s.startswith(("CREATE INDEX ", "CREATE UNIQUE INDEX ")) and any(f" ON {t} " in s for t in REBUILT)}
        self.assertEqual(indexes, expected)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute("DELETE FROM approvals")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute("UPDATE decisions SET reason = 'rewritten'")

    def test_a_quarantined_candidate_cannot_stand_before_its_quarantine(self):
        """D144 in the schema: the CHECK, and a new candidate cannot start with stage records."""
        conn = self.upgraded()
        ddl = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'candidates'").fetchone()[0]
        self.assertIn("CHECK (quarantine_hold_until IS NULL OR (state NOT IN (", ddl)
        self.assertIn("'REVALIDATION_REQUIRED'", ddl)
        row = dict(conn.execute("SELECT * FROM candidates WHERE id = ?", (self.s12,)).fetchone())
        row.update(id="cand_" + "f" * 32, state="DISCOVERED", epoch=0, decision_count=0, hold_until=None,
                   blocked_from=None, okta_unassign_approver_kind=None, okta_unassign_approver_id=None,
                   quarantine_hold_until=row["updated_at"], group_id=row["group_id"])
        names = ", ".join(row)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(f"INSERT INTO candidates ({names}) VALUES ({', '.join('?' for _ in row)})", tuple(row.values()))

    def test_the_frozen_lists_extend_the_earlier_ones(self):
        self.assertEqual(v0011.APPROVAL_STAGES[:2], v0001_core_schema.APPROVAL_STAGES)
        self.assertEqual(v0011.JOB_KINDS[:2], v0001_core_schema.JOB_KINDS)
        self.assertIn(v0011.LEGACY_APPROVAL_STAGE, v0011.APPROVAL_STAGES)
        self.assertIn(v0011.LEGACY_STATE, v0011.LIFECYCLE_STATES)


if __name__ == "__main__":
    unittest.main()
