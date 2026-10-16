"""Database-level constraints, uniqueness, and append-only triggers, exercised with raw SQL.

These prove the schema refuses bad writes even when application code is bypassed.
"""

import sqlite3
import unittest

from app.core.modes import ExecutionMode
from app.demo.synthetic_world import SeedClock, create_seeded_store, seeded_id
from app.domain.ids import IdKind
from app.domain.lifecycle import LifecycleCandidate, LifecycleState
from app.store.environment import read_marker
from app.store.errors import StoreConflict
from app.store.migrations import v0002_append_only_guards
from app.store.store import Store
from tests.store_fixtures import memory_target

_SEEDED: sqlite3.Connection | None = None


def _seeded_copy() -> sqlite3.Connection:
    """A private in-memory copy of the seeded synthetic store."""
    global _SEEDED
    if _SEEDED is None:
        store, _ = create_seeded_store(memory_target())
        _SEEDED = store.connection
    copy = sqlite3.connect(":memory:", isolation_level=None)
    _SEEDED.backup(copy)
    copy.row_factory = sqlite3.Row
    copy.execute("PRAGMA foreign_keys = ON")
    return copy


def _row(conn, sql, params=()) -> dict:
    return dict(conn.execute(sql, params).fetchone())


def _insert(conn, table, values: dict) -> None:
    conn.execute(f"INSERT INTO {table} ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})", tuple(values.values()))


class ConstraintTestCase(unittest.TestCase):
    def setUp(self):
        self.conn = _seeded_copy()

    def tearDown(self):
        self.conn.close()

    def assertRefused(self, table, values, pattern="constraint|append-only|must"):
        with self.assertRaisesRegex(sqlite3.IntegrityError, pattern):
            _insert(self.conn, table, values)


class CheckConstraintTests(ConstraintTestCase):
    def _job(self) -> dict:
        return _row(self.conn, "SELECT * FROM execution_jobs WHERE id = ?", (seeded_id(IdKind.EXECUTION_JOB, "S14-okta"),))

    def test_jobs_cannot_be_recorded_in_production_mutation_or_read_only_mode(self):
        for mode in (ExecutionMode.PRODUCTION_MUTATION, ExecutionMode.READ_ONLY_PRODUCTION):
            with self.subTest(mode=mode):
                self.assertRefused("execution_jobs", {**self._job(), "id": "job_" + "a" * 32, "execution_mode": mode.value},
                                   "CHECK constraint failed")

    def test_dry_run_mode_job_must_be_a_dry_run(self):
        self.assertRefused("execution_jobs", {**self._job(), "id": "job_" + "b" * 32, "dry_run": 0}, "CHECK constraint failed")

    def _unfinished_job_status(self) -> dict:
        """A first status row for a new copy of a seeded job, so only the CHECK constraints apply."""
        job_id = "job_" + "0" * 32
        _insert(self.conn, "execution_jobs", {**self._job(), "id": job_id})
        status = _row(self.conn, "SELECT * FROM execution_job_status_events WHERE job_id = ? AND sequence = 0",
                      (seeded_id(IdKind.EXECUTION_JOB, "S14-okta"),))
        return {**status, "job_id": job_id}

    def test_executed_requires_succeeded_and_synthetic_targets(self):
        status = self._unfinished_job_status()
        finished = status["recorded_at"]
        for change in ({"executed": 1, "targets_synthetic": 0, "status": "SUCCEEDED", "finished_at": finished},
                       {"executed": 1, "targets_synthetic": 1, "status": "RUNNING"}):
            with self.subTest(change=change):
                self.assertRefused("execution_job_status_events", {**status, **change}, "CHECK constraint failed")

    def test_finished_statuses_need_finished_at(self):
        status = self._unfinished_job_status()
        self.assertRefused("execution_job_status_events", {**status, "status": "FAILED", "finished_at": None},
                           "CHECK constraint failed")

    def test_audit_events_refuse_production_mutation_mode(self):
        head = _row(self.conn, "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT 1")
        event = {**head, "id": "aud_" + "c" * 32, "sequence": head["sequence"] + 1, "previous_digest": head["digest"],
                 "digest": "sha256:" + "c" * 64, "execution_mode": ExecutionMode.PRODUCTION_MUTATION.value}
        self.assertRefused("audit_events", event, "CHECK constraint failed")

    def test_timestamps_must_be_canonical_utc(self):
        run = _row(self.conn, "SELECT * FROM collector_runs LIMIT 1")
        for bad in ("2026-01-01 00:00:00", "2026-01-01T00:00:00.000000+00:00", "2026-01-01T00:00:00Z"):
            with self.subTest(bad=bad):
                self.assertRefused("collector_runs", {**run, "id": "run_" + "d" * 32, "started_at": bad}, "CHECK constraint failed")

    def test_flags_are_zero_or_one(self):
        obs = _row(self.conn, "SELECT * FROM assignment_observations LIMIT 1")
        self.assertRefused("assignment_observations", {**obs, "observation_id": "obs_" + "e" * 32,
                                                        "observed_at": "2020-01-01T00:00:00.000000Z", "present": 2},
                           "CHECK constraint failed")

    def test_enums_and_internal_id_shapes(self):
        run = _row(self.conn, "SELECT * FROM collector_runs LIMIT 1")
        self.assertRefused("collector_runs", {**run, "id": "run_" + "f" * 32, "source": "SCRAPED_UI"}, "CHECK constraint failed")
        self.assertRefused("collector_runs", {**run, "id": "job_" + "f" * 32}, "CHECK constraint failed")

    def test_incomplete_collector_outcome_needs_an_error_code(self):
        run = _row(self.conn, "SELECT * FROM collector_runs LIMIT 1")
        _insert(self.conn, "collector_runs", {**run, "id": "run_" + "9" * 32})
        outcome = {"run_id": "run_" + "9" * 32, "finished_at": run["started_at"], "status": "PARTIAL",
                   "records_observed": 0, "error_code": None, "error_summary": None, "recorded_at": run["recorded_at"]}
        self.assertRefused("collector_run_outcomes", outcome, "CHECK constraint failed")

    def test_unresolved_mapping_cannot_name_an_ad_group(self):
        obs = _row(self.conn, "SELECT * FROM identity_mapping_observations WHERE confidence = 'AMBIGUOUS' LIMIT 1")
        ad_group = _row(self.conn, "SELECT id FROM ad_groups LIMIT 1")["id"]
        self.assertRefused("identity_mapping_observations", {**obs, "observation_id": "obs_" + "1" * 32,
                                                              "observed_at": "2020-01-01T00:00:00.000000Z",
                                                              "ad_group_id": ad_group}, "CHECK constraint failed")

    def test_approvals_must_be_human_and_expire_after_decision(self):
        approval = _row(self.conn, "SELECT * FROM approvals LIMIT 1")
        self.assertRefused("approvals", {**approval, "id": "apr_" + "2" * 32, "operator_kind": "SYSTEM"}, "CHECK constraint failed")
        self.assertRefused("approvals", {**approval, "id": "apr_" + "3" * 32, "expires_at": approval["decided_at"]},
                           "CHECK constraint failed")


class UniquenessTests(ConstraintTestCase):
    def test_external_and_natural_keys_are_unique(self):
        app = _row(self.conn, "SELECT * FROM okta_applications LIMIT 1")
        self.assertRefused("okta_applications", {**app, "id": "oapp_" + "4" * 32}, "UNIQUE")
        group = _row(self.conn, "SELECT * FROM okta_groups LIMIT 1")
        self.assertRefused("okta_groups", {**group, "id": "ogrp_" + "4" * 32}, "UNIQUE")
        assignment = _row(self.conn, "SELECT * FROM app_group_assignments LIMIT 1")
        self.assertRefused("app_group_assignments", {**assignment, "id": "asgn_" + "4" * 32}, "UNIQUE")
        ad_group = _row(self.conn, "SELECT * FROM ad_groups LIMIT 1")
        self.assertRefused("ad_groups", {**ad_group, "id": "adg_" + "4" * 32}, "UNIQUE")
        mapping = _row(self.conn, "SELECT * FROM identity_mappings LIMIT 1")
        self.assertRefused("identity_mappings", {**mapping, "id": "map_" + "4" * 32}, "UNIQUE")
        scope = _row(self.conn, "SELECT * FROM usage_scopes WHERE scope_key = '*' LIMIT 1")
        self.assertRefused("usage_scopes", {**scope, "id": "use_" + "4" * 32}, "UNIQUE")
        check = _row(self.conn, "SELECT * FROM dependency_checks LIMIT 1")
        self.assertRefused("dependency_checks", {**check, "id": "dep_" + "4" * 32}, "UNIQUE")

    def test_object_guid_must_be_canonical_lowercase(self):
        ad_group = _row(self.conn, "SELECT * FROM ad_groups LIMIT 1")
        self.assertRefused("ad_groups", {**ad_group, "id": "adg_" + "5" * 32, "object_guid": ad_group["object_guid"].upper()},
                           "CHECK constraint failed")

    def test_one_observation_per_object_and_instant(self):
        obs = _row(self.conn, "SELECT * FROM ad_group_observations LIMIT 1")
        self.assertRefused("ad_group_observations", {**obs, "observation_id": "obs_" + "6" * 32}, "UNIQUE")

    def test_decision_and_audit_sequences_are_unique(self):
        decision = _row(self.conn, "SELECT * FROM decisions WHERE sequence = 0 LIMIT 1")
        self.assertRefused("decisions", {**decision, "id": "dec_" + "7" * 32})
        head = _row(self.conn, "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT 1")
        self.assertRefused("audit_events", {**head, "id": "aud_" + "7" * 32, "digest": "sha256:" + "7" * 64})

    def test_one_open_candidate_per_group(self):
        open_candidate = _row(self.conn, "SELECT * FROM candidates WHERE state = 'DISCOVERED' LIMIT 1")
        self.assertRefused("candidates", {**open_candidate, "id": "cand_" + "8" * 32}, "UNIQUE")

    def test_a_terminal_candidate_does_not_block_a_new_one(self):
        store = Store(self.conn, mode=ExecutionMode.LOCAL_SYNTHETIC, marker=read_marker(self.conn), clock=SeedClock())
        protected = _row(self.conn, "SELECT * FROM candidates WHERE state = 'PROTECTED'")
        assignment = _row(self.conn, "SELECT assignment_id FROM candidate_assignments WHERE candidate_id = ?",
                          (protected["id"],))["assignment_id"]
        clock = SeedClock()
        candidate = LifecycleCandidate.discover(okta_group_id=protected["group_id"], assignment_ids=(assignment,),
                                                proposed_by=store.load_candidate(protected["id"]).proposed_by, now=clock())
        store.create_candidate(candidate)
        self.assertIs(store.load_candidate(candidate.id).state, LifecycleState.DISCOVERED)
        with self.assertRaisesRegex(StoreConflict, "UNIQUE"):
            store.create_candidate(LifecycleCandidate.discover(
                okta_group_id=protected["group_id"], assignment_ids=(assignment,), proposed_by=candidate.proposed_by,
                now=clock()))

    def test_foreign_keys_are_enforced(self):
        obs = _row(self.conn, "SELECT * FROM assignment_observations LIMIT 1")
        self.assertRefused("assignment_observations", {**obs, "observation_id": "obs_" + "9" * 32,
                                                        "assignment_id": "asgn_" + "9" * 32}, "FOREIGN KEY")


class AppendOnlyTests(ConstraintTestCase):
    def test_every_history_table_refuses_update_and_delete(self):
        for table in v0002_append_only_guards.APPEND_ONLY_TABLES:
            column = self.conn.execute(f"PRAGMA table_info({table})").fetchone()[1]
            self.assertGreater(self.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0, table)
            with self.subTest(table=table):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    self.conn.execute(f"UPDATE {table} SET {column} = {column}")
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    self.conn.execute(f"DELETE FROM {table}")

    def test_candidates_are_never_deleted(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "never deleted"):
            self.conn.execute("DELETE FROM candidates")

    def test_candidate_identity_is_immutable(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable|only together with a new decision"):
            self.conn.execute("UPDATE candidates SET group_id = group_id")
        # The identity trigger stands on its own: with the projection trigger removed it still refuses.
        self.conn.execute("DROP TRIGGER trg_candidates_follow_decisions")
        for column in ("group_id", "proposed_by_id", "created_at", "reason_codes"):
            with self.subTest(column=column), self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                self.conn.execute(f"UPDATE candidates SET {column} = {column}")

    def test_candidate_state_cannot_change_without_a_decision(self):
        candidate = _row(self.conn, "SELECT * FROM candidates WHERE state = 'NEEDS_REVIEW' LIMIT 1")
        for change in ("state = 'APPROVED'", "decision_count = decision_count + 1, state = 'APPROVED'", "epoch = epoch + 1"):
            with self.subTest(change=change):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "only together with a new decision"):
                    self.conn.execute(f"UPDATE candidates SET {change} WHERE id = ?", (candidate["id"],))

    def test_new_candidates_start_discovered(self):
        candidate = _row(self.conn, "SELECT * FROM candidates WHERE state = 'NEEDS_REVIEW' LIMIT 1")
        self.assertRefused("candidates", {**candidate, "id": "cand_" + "a" * 32, "group_id": candidate["group_id"]},
                           "start in DISCOVERED")

    def test_decisions_must_continue_from_the_current_state(self):
        candidate = _row(self.conn, "SELECT * FROM candidates WHERE state = 'NEEDS_REVIEW' LIMIT 1")
        last = _row(self.conn, "SELECT * FROM decisions WHERE candidate_id = ? ORDER BY sequence DESC LIMIT 1", (candidate["id"],))
        forged = {**last, "id": "dec_" + "b" * 32, "sequence": last["sequence"] + 1, "from_state": "CANDIDATE",
                  "to_state": "APPROVED"}
        self.assertRefused("decisions", forged, "continue from the current candidate state")
        skipped = {**forged, "sequence": last["sequence"] + 5, "from_state": "NEEDS_REVIEW"}
        self.assertRefused("decisions", skipped, "continue from the current candidate state")

    def test_audit_events_must_extend_the_chain_head(self):
        head = _row(self.conn, "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT 1")
        base = {**head, "id": "aud_" + "c" * 32, "digest": "sha256:" + "c" * 64}
        self.assertRefused("audit_events", {**base, "sequence": head["sequence"] + 2, "previous_digest": head["digest"]},
                           "extend the chain head")
        self.assertRefused("audit_events", {**base, "sequence": head["sequence"] + 1, "previous_digest": "sha256:" + "0" * 64},
                           "extend the chain head")

    def test_job_status_stops_once_finished(self):
        job_id = seeded_id(IdKind.EXECUTION_JOB, "S14-okta")
        last = _row(self.conn, "SELECT * FROM execution_job_status_events WHERE job_id = ? ORDER BY sequence DESC LIMIT 1",
                    (job_id,))
        self.assertEqual(last["status"], "FAILED")
        self.assertRefused("execution_job_status_events", {**last, "sequence": last["sequence"] + 1, "status": "RUNNING",
                                                            "finished_at": None}, "stop once the job has finished")

    def test_environment_marker_cannot_be_changed(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute("UPDATE store_metadata SET environment = 'PRODUCTION'")
        self.assertRefused("store_metadata", _row(self.conn, "SELECT * FROM store_metadata"), "UNIQUE|PRIMARY")


if __name__ == "__main__":
    unittest.main()
