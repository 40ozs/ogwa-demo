"""EVIDENCE_INCOMPLETE as its own lifecycle state (owner decisions after P09; migration 0009).

EVIDENCE_INCOMPLETE: required evidence was never fully or properly obtained.
STALE_EVIDENCE: once-complete evidence outlived its freshness window.
Neither is ever assigned by an operator.
"""

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from app.classification import LIFECYCLE_DIVERSIONS, Classification
from app.core.modes import ExecutionMode
from app.demo.synthetic_world import AS_OF, HOUR, POLICY as DEMO_POLICY, create_seeded_store
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction
from app.domain.evidence import ResultStatus
from app.domain.lifecycle import (
    BLOCKED_STATES,
    DIVERSION_TARGETS,
    EVIDENCE_CONDITION_STATES,
    TRANSITIONS,
    LifecycleState,
    TransitionRequest,
    apply_transition,
    recommend_diversion,
)
from app.store.db import DIALECT_SQLITE, connect
from app.store.errors import StoreConflict
from app.store.migrations import v0001_core_schema, v0002_append_only_guards, v0009_evidence_incomplete_state
from app.store.migrator import upgrade
from app.store.store import Store
from tests.api_fixtures import AUTOMATION, SECURITY, VIEWER, World
from tests.domain_fixtures import DAY, POLICY, REVIEWER, T0, ad_group, bundle
from tests.store_fixtures import build_held_at, file_target

S = LifecycleState
V = "/api/v1"
TABLES = ("candidates", "decisions", "candidate_assignments", "approvals", "execution_jobs", "audit_events")
COLLECTOR = Actor(ActorKind.SYSTEM, "collector/synthetic")


def dump(conn: sqlite3.Connection, table: str) -> list[tuple]:
    columns = ", ".join(r[1] for r in conn.execute(f"PRAGMA table_info({table})"))
    return [tuple(r) for r in conn.execute(f"SELECT {columns} FROM {table} ORDER BY {columns}")]


def stage_transition(store: Store, key_candidate: str, target: LifecycleState, actor=COLLECTOR):
    candidate = store.load_candidate(key_candidate)
    request = TransitionRequest(target=target, actor=actor, reason="synthetic: evidence condition observed",
                                now=AS_OF + 2 * HOUR, evidence=store.evidence_bundle(candidate))
    return store.transition(key_candidate, request, DEMO_POLICY, correlation_id="req_" + "a" * 32)


# --- migration 0009 ------------------------------------------------------------------------


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = file_target(Path(self.tmp.name) / "seeded.sqlite3")
        with build_held_at(8):
            store, self.summary = create_seeded_store(self.target)
            store.close()
        self.s07 = next(s.candidate_id for s in self.summary.scenarios if s.key == "S07")

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_row_is_preserved_and_the_store_verifies(self):
        conn = connect(self.target)
        try:
            before = {t: dump(conn, t) for t in TABLES}
            self.assertTrue(before["decisions"] and before["approvals"] and before["execution_jobs"])
            self.assertEqual(upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of, target=9), [9])
            self.assertEqual({t: dump(conn, t) for t in TABLES}, before)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'ogwa_v0009_%'").fetchall(), [])
        finally:
            conn.close()
        with build_held_at(9), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            report = store.verify_integrity(expected_audit_head=self.summary.audit_head)
            self.assertEqual((report.schema_version, report.audit_head), (9, self.summary.audit_head))
            self.assertEqual(report.candidates_checked, len(self.summary.scenarios))

    def test_guards_survive_the_rebuild_byte_for_byte(self):
        conn = connect(self.target)
        try:
            upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of, target=9)
            for table in ("candidates", "decisions"):
                triggers = {n: sql for n, sql in conn.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?", (table,))}
                expected = {s.split()[2]: s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                            if s.split("\n", 1)[0].endswith(f" ON {table}")}
                with self.subTest(table=table):
                    self.assertEqual(triggers, expected)
                    self.assertTrue(expected)
            indexes = {n: sql for n, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name IN ('candidates', 'decisions') "
                "AND sql IS NOT NULL")}
            self.assertEqual(indexes, {s.split()[3 if s.startswith("CREATE UNIQUE") else 2]: s
                                       for s in v0001_core_schema.STATEMENTS
                                       if s.startswith(("CREATE INDEX", "CREATE UNIQUE INDEX"))
                                       and (" ON candidates " in s or " ON decisions " in s)})
            with self.assertRaisesRegex(sqlite3.IntegrityError, "never deleted"):
                conn.execute("DELETE FROM candidates")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("UPDATE decisions SET reason = 'edited'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "state may change only together"):
                conn.execute("UPDATE candidates SET state = 'EVIDENCE_INCOMPLETE' WHERE id = ?", (self.s07,))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "start in DISCOVERED"):
                conn.execute("INSERT INTO candidates SELECT * FROM candidates WHERE state <> 'DISCOVERED' LIMIT 1")
            # A decision that continues correctly (so the trigger lets it through) to an unknown state.
            with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK"):
                conn.execute("INSERT INTO decisions (id, candidate_id, sequence, from_state, to_state, actor_kind, actor_id, "
                             "decided_at, reason, evidence_fingerprint, epoch, recorded_at, correlation_id) "
                             "SELECT 'dec_' || lower(hex(randomblob(16))), c.id, c.decision_count, c.state, 'NOT_A_STATE', "
                             "d.actor_kind, d.actor_id, d.decided_at, d.reason, d.evidence_fingerprint, d.epoch, "
                             "d.recorded_at, d.correlation_id FROM candidates c JOIN decisions d ON d.candidate_id = c.id "
                             "WHERE c.id = ? LIMIT 1", (self.s07,))
        finally:
            conn.close()

    def test_the_state_is_refused_before_0009_and_stored_after(self):
        with build_held_at(8), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            with self.assertRaisesRegex(StoreConflict, "CHECK"):
                stage_transition(store, self.s07, S.EVIDENCE_INCOMPLETE)
            self.assertIs(store.load_candidate(self.s07).state, S.NEEDS_REVIEW)
        conn = connect(self.target)
        upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of)
        conn.close()
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            stage_transition(store, self.s07, S.EVIDENCE_INCOMPLETE)
            loaded = store.load_candidate(self.s07)
            self.assertEqual((loaded.state, loaded.blocked_from), (S.EVIDENCE_INCOMPLETE, S.NEEDS_REVIEW))
            store.verify_integrity()

    def test_the_frozen_list_extends_v0001_by_exactly_one_state(self):
        self.assertEqual(set(v0009_evidence_incomplete_state.LIFECYCLE_STATES) - set(v0001_core_schema.LIFECYCLE_STATES),
                         {"EVIDENCE_INCOMPLETE"})


# --- lifecycle -----------------------------------------------------------------------------


class LifecycleTests(unittest.TestCase):
    def test_both_evidence_conditions_are_blocked_diversion_targets_closed_to_people(self):
        self.assertEqual(EVIDENCE_CONDITION_STATES, {S.STALE_EVIDENCE, S.EVIDENCE_INCOMPLETE})
        self.assertLessEqual(EVIDENCE_CONDITION_STATES, BLOCKED_STATES & DIVERSION_TARGETS)
        for (source, target), rule in TRANSITIONS.items():
            if target in EVIDENCE_CONDITION_STATES:
                with self.subTest(source=source, target=target):
                    self.assertEqual(rule.actors, {ActorKind.SYSTEM})
        others = {t for (_, t), r in TRANSITIONS.items() if ActorKind.HUMAN not in r.actors}
        self.assertEqual(others, EVIDENCE_CONDITION_STATES, "no other step is closed to people")

    def test_a_person_cannot_assign_either_condition_but_can_hold(self):
        from tests.test_lifecycle_state_machine import candidate_in

        for target in EVIDENCE_CONDITION_STATES:
            with self.subTest(target=target):
                request = TransitionRequest(target=target, actor=REVIEWER, reason="x", now=T0 + DAY, evidence=bundle(T0))
                with self.assertRaisesRegex(Exception, "HUMAN actors cannot"):
                    apply_transition(candidate_in(S.NEEDS_REVIEW), request, POLICY)
        held = apply_transition(candidate_in(S.NEEDS_REVIEW), TransitionRequest(
            target=S.BLOCKED, actor=REVIEWER, reason="x", now=T0 + DAY, evidence=bundle(T0)), POLICY)
        self.assertIs(held.candidate.state, S.BLOCKED)

    def test_a_person_may_still_lift_the_condition_once_the_evidence_clears(self):
        from tests.test_lifecycle_state_machine import candidate_in

        blocked = candidate_in(S.EVIDENCE_INCOMPLETE, blocked_from=S.CANDIDATE)
        result = apply_transition(blocked, TransitionRequest(target=S.CANDIDATE, actor=REVIEWER, reason="re-collected",
                                                             now=T0 + 2 * HOUR, evidence=bundle(T0)), POLICY)
        self.assertIs(result.candidate.state, S.CANDIDATE)
        partial = bundle(T0)
        partial = replace(partial, ad_group=replace(partial.ad_group, provenance=replace(
            partial.ad_group.provenance, result_status=ResultStatus.PARTIAL)))
        with self.assertRaisesRegex(Exception, "not decision-grade"):
            apply_transition(blocked, TransitionRequest(target=S.CANDIDATE, actor=REVIEWER, reason="too early",
                                                        now=T0 + 2 * HOUR, evidence=partial), POLICY)

    def test_recommendation_separates_incomplete_from_stale(self):
        from tests.test_lifecycle_state_machine import candidate_in

        c, at = candidate_in(S.NEEDS_REVIEW), T0 + HOUR
        fresh = bundle(T0)
        partial = replace(fresh, ad_group=replace(fresh.ad_group, provenance=replace(
            fresh.ad_group.provenance, result_status=ResultStatus.PARTIAL)))
        future = replace(fresh, ad_group=ad_group(at + DAY))
        old = bundle(T0 - 31 * DAY)
        old_and_partial = replace(old, ad_group=replace(old.ad_group, provenance=replace(
            old.ad_group.provenance, result_status=ResultStatus.PARTIAL)))
        cases = {"partial": (partial, S.EVIDENCE_INCOMPLETE), "future-dated": (future, S.EVIDENCE_INCOMPLETE),
                 "old": (old, S.STALE_EVIDENCE), "some old, one partial": (old_and_partial, S.STALE_EVIDENCE)}
        for name, (evidence, expected) in cases.items():
            with self.subTest(case=name):
                self.assertIs(recommend_diversion(c, evidence, at, POLICY)[0], expected)
        self.assertIsNone(recommend_diversion(c, fresh, at, POLICY))

    def test_future_dated_evidence_is_never_fresh_and_never_stale(self):
        # Owner decision after the P09 addendum: incomplete/invalid evidence with its own reason.
        from app.classification import ReasonCode
        from tests.classification_fixtures import NOW, run, world

        for age in (0, 45):  # beside fresh records, and beside records that are themselves old
            with self.subTest(other_records_days_old=age):
                bundle_ = replace(world(T0 - age * DAY), ad_group=ad_group(NOW + DAY))
                result = run(bundle_)
                future = [r for r in result.reasons if r.code is ReasonCode.EVIDENCE_FUTURE_DATED]
                self.assertEqual([r.subject for r in future], [bundle_.ad_group.id])
                self.assertNotIn(bundle_.ad_group.id, {r.subject for r in result.reasons
                                                       if r.code is ReasonCode.EVIDENCE_STALE})
                self.assertNotIn(ReasonCode.EVIDENCE_CURRENT, result.reason_codes)
                if age == 0:
                    self.assertIs(result.classification, Classification.EVIDENCE_INCOMPLETE)
                    self.assertIs(LIFECYCLE_DIVERSIONS[result.classification], S.EVIDENCE_INCOMPLETE)
        from tests.test_lifecycle_state_machine import candidate_in

        problem = recommend_diversion(candidate_in(S.NEEDS_REVIEW), replace(bundle(T0), ad_group=ad_group(T0 + 3 * DAY)),
                                      T0 + HOUR, POLICY)
        self.assertEqual(problem[0], S.EVIDENCE_INCOMPLETE)
        self.assertIn("in the future", problem[1])
        self.assertNotIn("stale", problem[1])

    def test_the_classifier_diverts_incomplete_evidence_to_its_own_state(self):
        self.assertIs(LIFECYCLE_DIVERSIONS[Classification.EVIDENCE_INCOMPLETE], S.EVIDENCE_INCOMPLETE)
        self.assertIs(LIFECYCLE_DIVERSIONS[Classification.STALE_EVIDENCE], S.STALE_EVIDENCE)


# --- API -----------------------------------------------------------------------------------


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def test_demo_classifications_tell_incomplete_from_stale(self):
        client = self.world.client(VIEWER)
        expected = {"S07": "EVIDENCE_INCOMPLETE", "S12": "EVIDENCE_INCOMPLETE", "S11": "STALE_EVIDENCE"}
        for key, state in expected.items():
            with self.subTest(scenario=key):
                body = client.get(f"{V}/candidates/{self.world.candidate(key)}").json
                self.assertEqual(body["classification"]["lifecycleDiversion"], state)

    def test_operators_cannot_assign_an_evidence_condition_and_the_refusal_is_chained(self):
        candidate = self.world.candidate("S07")
        for subject in (AUTOMATION, SECURITY):
            client = self.world.client(subject)
            detail = client.get(f"{V}/candidates/{candidate}").json["allowedActions"]["transitions"]
            offered = {t["target"]: t for t in detail}
            for target in ("STALE_EVIDENCE", "EVIDENCE_INCOMPLETE"):
                with self.subTest(subject=subject, target=target):
                    self.assertEqual((offered[target]["operatorAction"], offered[target]["permitted"],
                                      offered[target]["permission"]), (False, False, None))
                    result = client.post(f"{V}/candidates/{candidate}/transitions", {"target": target, "reason": "x"})
                    self.assertEqual((result.status, result.code), (403, "NOT_AN_OPERATOR_ACTION"), result.json)
                    self.assertIn("hold it (BLOCKED)", result.json["error"]["message"])
                    event = next(e for e in self.world.store.audit_events()
                                 if e.id == result.json["error"]["auditEventId"])
                    self.assertIs(event.action, AuditAction.GOVERNED_REQUEST_REFUSED)
            self.assertTrue(offered["BLOCKED"]["permitted"] and offered["BLOCKED"]["operatorAction"])
        self.assertIs(self.world.store.load_candidate(candidate).state, S.NEEDS_REVIEW)

    def test_the_approval_limit_comes_from_the_policy(self):
        client = self.world.client(VIEWER)
        hours = int(DEMO_POLICY.approval_max_ttl.total_seconds() // 3600)
        self.assertEqual(hours, 168)
        views = {
            "policy": client.get(f"{V}/policy").json["inForce"],
            "dashboard": client.get(f"{V}/dashboard").json["policy"],
            "candidate": client.get(f"{V}/candidates/{self.world.candidate('S07')}").json["policy"],
        }
        for name, view in views.items():
            with self.subTest(view=name):
                self.assertEqual(view["approvalMaxValidHours"], hours)


if __name__ == "__main__":
    unittest.main()
