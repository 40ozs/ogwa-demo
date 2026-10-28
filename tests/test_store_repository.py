"""The Store API: evidence history, lifecycle persistence, audit append behaviour, and guards."""

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from app.core.modes import ExecutionMode
from app.domain.approval import ApprovalDecision, ApprovalStage
from app.domain.audit import AuditAction, AuditResult
from app.domain.collection import CollectorErrorCode, CollectorRun, CollectorRunOutcome
from app.domain.errors import InvalidRecord, TransitionRefused
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.execution import JobKind, JobStatus
from app.domain.ids import IdKind
from app.domain.lifecycle import LifecycleState, TransitionRequest
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    IdentityMapping,
    MappingConfidence,
    OktaApplication,
    OktaGroup,
)
from app.store.codec import ts
from app.store.db import connect, transaction
from app.store.environment import DatabaseEnvironment
from app.store.errors import EnvironmentRefused, StoreConflict, StoreIntegrityError
from app.store.store import Store
from tests.domain_fixtures import (
    AD_ID,
    AD_ID_2,
    ASSIGNMENT_ID,
    DAY,
    HOUR,
    FOURTH_REVIEWER,
    POLICY,
    QUARANTINE_OUS,
    REVIEWER,
    SECOND_REVIEWER,
    SYSTEM,
    THIRD_REVIEWER,
    T0,
    Journey,
    ad_group,
    application,
    approval,
    assignment,
    blocking_finding,
    bundle,
    dependency,
    dry_run_job,
    fixed_id,
    mapping,
    new_candidate,
    okta_group,
    prov,
    usage,
)
from tests.store_fixtures import MutableClock, file_target, memory_target, new_store

S = LifecycleState


# Referenced records first: the store's foreign keys refuse dangling references.
RECORD_ORDER = (OktaApplication, OktaGroup, ADGroup, ApplicationGroupAssignment, ApplicationUsageObservation,
                IdentityMapping, DependencyEvidence)


def record_bundle(store: Store, evidence) -> None:
    for record in sorted(evidence.records(), key=lambda r: RECORD_ORDER.index(type(r))):
        if store.latest(type(record), record.id) != record:
            store.record_evidence(record, actor=SYSTEM)


class StoreJourney:
    """Drives the domain fixtures' forward path through the store instead of in memory."""

    def __init__(self, store: Store):
        self.store = store
        self.j = Journey()
        self.candidate = self.j.candidate
        record_bundle(store, self.j.pre)
        store.create_candidate(self.candidate)

    def step(self, target, at, *, actor=SYSTEM, evidence=None, approval_record=None, job=None, reason="synthetic step"):
        evidence = evidence or self.j.pre
        record_bundle(self.store, evidence)
        request = TransitionRequest(target=target, actor=actor, reason=reason, now=at, evidence=evidence,
                                    approval=approval_record, job=job, quarantine_ous=QUARANTINE_OUS)
        result = self.store.transition(self.candidate.id, request, POLICY)
        self.candidate = result.candidate
        return result

    def to(self, state):
        j = self.j
        j.candidate = self.candidate
        self.step(S.CANDIDATE, j.T_CANDIDATE)
        if state is S.CANDIDATE:
            return self
        self.step(S.NEEDS_REVIEW, j.T_REVIEW)
        if state is S.NEEDS_REVIEW:
            return self
        j.unassign_approval = approval(self.candidate, ApprovalStage.OKTA_UNASSIGN, j.T_APPROVE - timedelta(minutes=10), j.pre)
        self.store.record_approval(j.unassign_approval)
        self.step(S.APPROVED, j.T_APPROVE, actor=REVIEWER, approval_record=j.unassign_approval)
        if state is S.APPROVED:
            return self
        j.unassign_job = dry_run_job(self.candidate, JobKind.OKTA_UNASSIGN, j.unassign_approval, j.pre,
                                     j.T_APPROVE + timedelta(minutes=5), j.T_UNASSIGN_DRY_RUN - timedelta(minutes=5))
        self.store.record_execution_job(j.unassign_job)
        self.step(S.OKTA_UNASSIGN_DRY_RUN, j.T_UNASSIGN_DRY_RUN, approval_record=j.unassign_approval, job=j.unassign_job)
        self.step(S.HOLD, j.T_UNASSIGNED_SEEN, evidence=j.unassigned_evidence(), approval_record=j.unassign_approval,
                  job=j.unassign_job)
        if state is S.HOLD:
            return self
        self.step(S.REVALIDATION_REQUIRED, j.T_HOLD_ENDS, evidence=j.unassigned_evidence())
        if state is S.REVALIDATION_REQUIRED:
            return self
        # The AD quarantine, approved by a second reviewer (P10B).
        five = timedelta(minutes=5)
        j.post = j.post_hold_evidence()
        j.quarantine_approval = approval(self.candidate, ApprovalStage.AD_QUARANTINE, j.T_QUARANTINE_APPROVE, j.post,
                                         operator=SECOND_REVIEWER)
        self.store.record_approval(j.quarantine_approval)
        self.step(S.QUARANTINE_APPROVED, j.T_QUARANTINE_APPROVE + five, actor=SECOND_REVIEWER, evidence=j.post,
                  approval_record=j.quarantine_approval)
        j.quarantine_job = dry_run_job(self.candidate, JobKind.AD_QUARANTINE, j.quarantine_approval, j.post,
                                       j.T_QUARANTINE_APPROVE + 2 * five, j.T_QUARANTINE_DRY_RUN - five)
        self.store.record_execution_job(j.quarantine_job)
        self.step(S.QUARANTINE_DRY_RUN, j.T_QUARANTINE_DRY_RUN, evidence=j.post, approval_record=j.quarantine_approval,
                  job=j.quarantine_job)
        self.step(S.QUARANTINE_HOLD, j.T_QUARANTINE_SEEN, evidence=j.quarantined_evidence(),
                  approval_record=j.quarantine_approval, job=j.quarantine_job)
        if state is S.QUARANTINE_HOLD:
            return self
        # The AD deletion: proposed by a third reviewer, approved by a fourth (D143).
        self.step(S.DELETION_REVALIDATION_REQUIRED, j.T_QUARANTINE_HOLD_ENDS, evidence=j.quarantined_evidence())
        j.after_hold = j.post_quarantine_evidence()
        self.step(S.DELETION_PROPOSED, j.T_DELETION_PROPOSED, actor=THIRD_REVIEWER, evidence=j.after_hold)
        j.deletion_approval = approval(self.candidate, ApprovalStage.AD_DELETION, j.T_DELETION_APPROVE, j.after_hold,
                                       operator=FOURTH_REVIEWER)
        self.store.record_approval(j.deletion_approval)
        self.step(S.DELETION_APPROVED, j.T_DELETION_APPROVE + five, actor=FOURTH_REVIEWER, evidence=j.after_hold,
                  approval_record=j.deletion_approval)
        j.deletion_job = dry_run_job(self.candidate, JobKind.AD_DELETION, j.deletion_approval, j.after_hold,
                                     j.T_DELETION_APPROVE + 2 * five, j.T_DELETION_DRY_RUN - five)
        self.store.record_execution_job(j.deletion_job)
        self.step(S.DELETION_DRY_RUN, j.T_DELETION_DRY_RUN, evidence=j.after_hold, approval_record=j.deletion_approval,
                  job=j.deletion_job)
        self.step(S.RETIRED, j.T_RETIRED_SEEN, evidence=j.retired_evidence(), approval_record=j.deletion_approval,
                  job=j.deletion_job)
        return self


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = MutableClock()
        self.store = new_store(clock=self.clock)

    def tearDown(self):
        self.store.close()

    def audit_count(self) -> int:
        return len(self.store.audit_events())


class EvidenceRoundTripTests(StoreTestCase):
    def test_every_evidence_type_round_trips_exactly(self):
        records = [
            application(T0), okta_group(T0), assignment(T0), usage(T0, events=3), ad_group(T0, member_count=4),
            ad_group(T0, id=AD_ID_2, object_guid="5e1f0c3a-0000-4000-8000-000000000002", rid=4322),
            mapping(T0, confidence=MappingConfidence.AMBIGUOUS),
            dependency(T0, sorted(POLICY.required_dependency_kinds)[0], 1, findings=(blocking_finding(),)),
        ]
        for record in records:
            self.store.record_evidence(record, actor=SYSTEM)
        for record in records:
            with self.subTest(kind=record.KIND):
                stored = self.store.latest(type(record), record.id)
                self.assertEqual(stored, record)
                self.assertEqual(stored.digest, record.digest)

    def test_reobservation_appends_and_keeps_history(self):
        record_bundle(self.store, bundle(T0))
        first = self.store.history(ApplicationGroupAssignment, ASSIGNMENT_ID)[0]
        obs_id = self.store.record_evidence(assignment(T0 + DAY, present=False), actor=SYSTEM)
        history = self.store.history(ApplicationGroupAssignment, ASSIGNMENT_ID)
        self.assertEqual([a.present for a in history], [True, False])
        self.assertEqual(history[0], first)
        self.assertFalse(self.store.latest(ApplicationGroupAssignment, ASSIGNMENT_ID).present)
        event = self.store.audit_events()[-1]
        self.assertEqual(event.after_ref, f"observation:{obs_id}")
        self.assertTrue(event.before_ref.startswith("observation:obs_"))

    def test_late_arriving_older_observation_does_not_become_latest(self):
        record_bundle(self.store, bundle(T0))
        self.store.record_evidence(assignment(T0 - DAY, present=False), actor=SYSTEM)
        self.assertTrue(self.store.latest(ApplicationGroupAssignment, ASSIGNMENT_ID).present)

    def test_conflicting_identities_are_refused(self):
        self.store.record_evidence(application(T0), actor=SYSTEM)
        with self.assertRaisesRegex(StoreConflict, "different identity"):
            self.store.record_evidence(application(T0 + DAY, okta_app_id="0oaSYNTHOTHER01"), actor=SYSTEM)
        with self.assertRaisesRegex(StoreConflict, "UNIQUE"):
            self.store.record_evidence(application(T0, id=fixed_id(IdKind.OKTA_APPLICATION, 9)), actor=SYSTEM)

    def test_duplicate_observation_is_refused(self):
        self.store.record_evidence(application(T0), actor=SYSTEM)
        with self.assertRaisesRegex(StoreConflict, "UNIQUE"):
            self.store.record_evidence(application(T0, label="Renamed"), actor=SYSTEM)

    def test_references_must_be_recorded_first(self):
        with self.assertRaisesRegex(StoreConflict, "FOREIGN KEY"):
            self.store.record_evidence(assignment(T0), actor=SYSTEM)

    def test_future_observation_is_refused(self):
        with self.assertRaisesRegex(StoreConflict, "future"):
            self.store.record_evidence(application(self.clock.now + HOUR), actor=SYSTEM)

    def test_failed_write_leaves_no_trace(self):
        before = self.audit_count()
        with self.assertRaises(StoreConflict):
            self.store.record_evidence(assignment(T0), actor=SYSTEM)
        self.assertEqual(self.audit_count(), before)
        self.assertIsNone(self.store.latest(ApplicationGroupAssignment, ASSIGNMENT_ID))

    def test_bundle_selects_the_latest_relevant_evidence(self):
        record_bundle(self.store, bundle(T0))
        self.store.record_evidence(okta_group(T0, id=fixed_id(IdKind.OKTA_GROUP, 2), okta_group_id="00gSYNTHETIC0002"),
                                   actor=SYSTEM)  # unrelated group
        candidate = new_candidate()
        self.store.create_candidate(candidate)
        self.store.record_evidence(usage(T0 + DAY, events=2), actor=SYSTEM)
        evidence = self.store.evidence_bundle(candidate)
        self.assertEqual(evidence.okta_group.id, candidate.okta_group_id)
        self.assertEqual([u.event_count for u in evidence.usage], [2])
        self.assertEqual(evidence.mapping.ad_group_id, AD_ID)
        self.assertEqual(evidence.ad_group.id, AD_ID)
        self.assertEqual(len(evidence.dependencies), len(POLICY.required_dependency_kinds))


class LifecyclePersistenceTests(StoreTestCase):
    def test_full_journey_is_persisted_and_replayable(self):
        self.clock.advance(timedelta(days=10))  # the path now ends after two 30-day holds (P10B)
        journey = StoreJourney(self.store).to(S.RETIRED)
        loaded = self.store.load_candidate(journey.candidate.id)
        self.assertEqual(loaded, journey.candidate)
        decisions = self.store.decisions(loaded.id)
        self.assertEqual([d.to_state for d in decisions][-1], S.RETIRED)
        self.assertEqual(len(decisions), 14)
        self.assertEqual(loaded.okta_unassign_approver, REVIEWER)
        self.assertEqual((loaded.quarantine_approver, loaded.deletion_proposer), (SECOND_REVIEWER, THIRD_REVIEWER))
        self.assertEqual(loaded.quarantine_hold_until, Journey.T_QUARANTINE_SEEN + timedelta(days=30))
        self.assertEqual(loaded.deletion_proposed_at, Journey.T_DELETION_PROPOSED)
        report = self.store.verify_integrity()
        self.assertEqual(report.candidates_checked, 1)

    def test_transitions_are_audited_with_full_context(self):
        journey = StoreJourney(self.store).to(S.CANDIDATE)
        event = self.store.audit_events()[-1]
        decision = self.store.decisions(journey.candidate.id)[-1]
        self.assertIs(event.action, AuditAction.TRANSITION_APPLIED)
        self.assertEqual(event.actor, SYSTEM)
        self.assertEqual(event.subject_id, journey.candidate.id)
        self.assertIs(event.execution_mode, ExecutionMode.LOCAL_SYNTHETIC)
        self.assertIs(event.result, AuditResult.SUCCEEDED)
        self.assertEqual(event.before_ref, f"candidate:{journey.candidate.id}@DISCOVERED#e0")
        self.assertEqual(event.after_ref, f"decision:{decision.id}")
        stored = self.store.connection.execute("SELECT correlation_id FROM decisions WHERE id = ?", (decision.id,)).fetchone()
        self.assertEqual(stored[0], event.correlation_id)

    def test_refused_transition_is_audited_and_changes_nothing(self):
        journey = StoreJourney(self.store).to(S.NEEDS_REVIEW)
        evidence = bundle(Journey.T_REVIEW + HOUR, usage_events=4)
        record_bundle(self.store, evidence)
        decisions_before = len(self.store.decisions(journey.candidate.id))
        request = TransitionRequest(target=S.APPROVED, actor=REVIEWER, reason="try", now=Journey.T_REVIEW + 2 * HOUR,
                                    evidence=evidence)
        with self.assertRaises(TransitionRefused):
            self.store.transition(journey.candidate.id, request, POLICY)
        event = self.store.audit_events()[-1]
        self.assertIs(event.action, AuditAction.TRANSITION_REFUSED)
        self.assertIs(event.result, AuditResult.REFUSED)
        self.assertIn("sign-ins", dict(event.details)["problems"])
        self.assertIs(self.store.load_candidate(journey.candidate.id).state, S.NEEDS_REVIEW)
        self.assertEqual(len(self.store.decisions(journey.candidate.id)), decisions_before)

    def test_transition_must_cite_recorded_evidence_approval_and_job(self):
        journey = StoreJourney(self.store).to(S.NEEDS_REVIEW)
        unrecorded = replace(journey.j.pre, usage=(usage(Journey.T_REVIEW + HOUR),))
        request = TransitionRequest(target=S.BLOCKED, actor=SYSTEM, reason="x", now=Journey.T_REVIEW + HOUR, evidence=unrecorded)
        with self.assertRaisesRegex(StoreConflict, "has not been recorded"):
            self.store.transition(journey.candidate.id, request, POLICY)
        unrecorded_approval = approval(journey.candidate, ApprovalStage.OKTA_UNASSIGN, Journey.T_APPROVE, journey.j.pre)
        request = TransitionRequest(target=S.APPROVED, actor=REVIEWER, reason="x", now=Journey.T_APPROVE,
                                    evidence=journey.j.pre, approval=unrecorded_approval)
        with self.assertRaisesRegex(StoreConflict, "approval .* has not been recorded"):
            self.store.transition(journey.candidate.id, request, POLICY)

    def test_job_snapshot_must_be_the_latest_recorded_state(self):
        journey = StoreJourney(self.store).to(S.APPROVED)
        j = journey.j
        planned = dry_run_job(journey.candidate, JobKind.OKTA_UNASSIGN, j.unassign_approval, j.pre,
                              j.T_APPROVE + timedelta(minutes=5), None, status=JobStatus.PLANNED)
        self.store.record_execution_job(planned)
        claimed = replace(planned, status=JobStatus.SUCCEEDED, finished_at=j.T_UNASSIGN_DRY_RUN - timedelta(minutes=5))
        request = TransitionRequest(target=S.OKTA_UNASSIGN_DRY_RUN, actor=SYSTEM, reason="x", now=j.T_UNASSIGN_DRY_RUN,
                                    evidence=j.pre, approval=j.unassign_approval, job=claimed)
        with self.assertRaisesRegex(StoreConflict, "not its latest recorded state"):
            self.store.transition(journey.candidate.id, request, POLICY)

    def test_post_dated_transition_is_refused(self):
        journey = StoreJourney(self.store).to(S.HOLD)
        request = TransitionRequest(target=S.REVALIDATION_REQUIRED, actor=SYSTEM, reason="skip the hold",
                                    now=self.clock.now + 40 * DAY, evidence=journey.j.unassigned_evidence())
        with self.assertRaisesRegex(StoreConflict, "future"):
            self.store.transition(journey.candidate.id, request, POLICY)

    def test_candidate_must_reference_its_own_recorded_assignments(self):
        record_bundle(self.store, bundle(T0))
        other_group = okta_group(T0, id=fixed_id(IdKind.OKTA_GROUP, 2), okta_group_id="00gSYNTHETIC0002")
        self.store.record_evidence(other_group, actor=SYSTEM)
        candidate = replace(new_candidate(), okta_group_id=other_group.id)
        with self.assertRaisesRegex(StoreConflict, "not a recorded assignment"):
            self.store.create_candidate(candidate)
        with self.assertRaisesRegex(StoreConflict, "freshly discovered"):
            self.store.create_candidate(replace(new_candidate(), state=S.CANDIDATE))

    def test_one_open_candidate_per_group(self):
        record_bundle(self.store, bundle(T0))
        self.store.create_candidate(new_candidate())
        with self.assertRaisesRegex(StoreConflict, "UNIQUE"):
            self.store.create_candidate(new_candidate())


class TamperDetectionTests(StoreTestCase):
    """Simulates someone with DDL rights who removes a trigger and edits rows directly."""

    def setUp(self):
        super().setUp()
        self.journey = StoreJourney(self.store).to(S.NEEDS_REVIEW)
        self.conn = self.store.connection

    def test_state_written_directly_is_detected_on_load(self):
        self.conn.execute("DROP TRIGGER trg_candidates_follow_decisions")
        cid = self.journey.candidate.id
        # A self-consistent forged state is caught by replaying the decision history...
        self.conn.execute("UPDATE candidates SET state = 'CANDIDATE' WHERE id = ?", (cid,))
        with self.assertRaisesRegex(StoreIntegrityError, "history verification"):
            self.store.load_candidate(cid)
        # ...and an inconsistent one by record validation before that.
        self.conn.execute("UPDATE candidates SET state = 'APPROVED' WHERE id = ?", (cid,))
        with self.assertRaisesRegex(StoreIntegrityError, "invalid"):
            self.store.load_candidate(cid)

    def test_edited_observation_is_detected(self):
        self.conn.execute("DROP TRIGGER trg_ad_group_observations_no_update")
        self.conn.execute("UPDATE ad_group_observations SET member_count = 0, admin_count = 1")
        with self.assertRaisesRegex(StoreIntegrityError, "digest"):
            self.store.latest(ADGroup, AD_ID)
        with self.assertRaises(StoreIntegrityError):
            self.store.verify_integrity()

    def test_edited_audit_event_is_detected(self):
        self.conn.execute("DROP TRIGGER trg_audit_events_no_update")
        self.conn.execute("UPDATE audit_events SET actor_id = 'someone-else' WHERE sequence = 3")
        with self.assertRaisesRegex(StoreIntegrityError, "audit event 3"):
            self.store.verify_integrity()

    def test_rewritten_newest_event_is_detected_with_an_anchor(self):
        # Newest: an evidence event, which no row is bound to (a decision's event is, see ForgedApprovalTests).
        self.store.record_evidence(ad_group(T0, id=AD_ID_2, object_guid="5e1f0c3a-0000-4000-8000-000000000002",
                                            rid=4322), actor=SYSTEM)
        anchor = self.store.audit_head()[1]
        self.store.verify_integrity(expected_audit_head=anchor)
        self.conn.execute("DROP TRIGGER trg_audit_events_no_update")
        self.conn.execute("DROP TRIGGER trg_audit_events_no_delete")
        self.conn.execute("DELETE FROM audit_events WHERE sequence = (SELECT max(sequence) FROM audit_events)")
        self.store.verify_integrity()  # a truncated chain still links...
        with self.assertRaisesRegex(StoreIntegrityError, "anchored digest"):
            self.store.verify_integrity(expected_audit_head=anchor)  # ...but not to the anchor

    def test_deleted_decision_is_detected(self):
        self.conn.execute("DROP TRIGGER trg_decisions_no_delete")
        self.conn.execute("DELETE FROM decisions WHERE candidate_id = ? AND sequence = 1", (self.journey.candidate.id,))
        with self.assertRaises(StoreIntegrityError):
            self.store.load_candidate(self.journey.candidate.id)


class ForgedApprovalTests(StoreTestCase):
    """F08: a lifecycle decision, and the approval an approval step cites, count only as the audit
    chain records them. A forgery that leaves the anchored audit head unchanged must not verify."""

    FORGER = THIRD_REVIEWER

    def fresh(self, state):
        self.store.close()
        self.store = new_store(clock=self.clock)
        return StoreJourney(self.store).to(state), self.store.connection

    def assertExposed(self, candidate_id, anchor, pattern):
        self.assertEqual(self.store.audit_head()[1], anchor)  # the forgery did not touch the audit chain...
        with self.assertRaisesRegex(StoreIntegrityError, pattern):
            self.store.load_candidate(candidate_id)
        with self.assertRaisesRegex(StoreIntegrityError, pattern):
            self.store.verify_integrity(expected_audit_head=anchor)  # ...so the anchor alone cannot vouch for it

    def forge_approval_step(self, conn, candidate_id, actor, approval_id):
        """NEEDS_REVIEW -> APPROVED written with plain SQL that satisfies every trigger (none is dropped)."""
        last = conn.execute("SELECT * FROM decisions WHERE candidate_id = ? ORDER BY sequence DESC LIMIT 1",
                            (candidate_id,)).fetchone()
        conn.execute("INSERT INTO decisions (id, candidate_id, sequence, from_state, to_state, actor_kind, actor_id, "
                     "decided_at, reason, evidence_fingerprint, epoch, approval_id, recorded_at, correlation_id) "
                     "VALUES (?, ?, ?, 'NEEDS_REVIEW', 'APPROVED', ?, ?, ?, 'forged', ?, ?, ?, ?, ?)",
                     (fixed_id(IdKind.DECISION, 99), candidate_id, last["sequence"] + 1, actor.kind.value, actor.id,
                      last["decided_at"], last["evidence_fingerprint"], last["epoch"], approval_id, last["recorded_at"],
                      last["correlation_id"]))
        conn.execute("UPDATE candidates SET state = 'APPROVED', decision_count = decision_count + 1, updated_at = ?, "
                     "okta_unassign_approver_kind = ?, okta_unassign_approver_id = ? WHERE id = ?",
                     (last["decided_at"], actor.kind.value, actor.id, candidate_id))

    def test_legitimate_approvals_verify_at_every_stage(self):
        self.clock.advance(timedelta(days=10))  # the path ends after two 30-day holds
        journey, _ = self.fresh(S.RETIRED)
        cid = journey.candidate.id
        self.assertIs(self.store.load_candidate(cid).state, S.RETIRED)
        report = self.store.verify_integrity(expected_audit_head=self.store.audit_head()[1])
        self.assertEqual(report.candidates_checked, 1)
        recorded = self.store.approvals_for(cid)
        self.assertEqual({a.stage for a in recorded},
                         {ApprovalStage.OKTA_UNASSIGN, ApprovalStage.AD_QUARANTINE, ApprovalStage.AD_DELETION})
        for a in recorded:
            self.assertEqual(self.store.load_approval(a.id), a)

    def test_a_trigger_consistent_forged_approval_step_is_exposed(self):
        def recorded_by(operator):
            def record(journey, conn):
                legitimate = approval(journey.candidate, ApprovalStage.OKTA_UNASSIGN, journey.j.T_REVIEW, journey.j.pre,
                                      operator=operator)
                self.store.record_approval(legitimate)
                return legitimate.id
            return record

        def written_with_sql(journey, conn):
            forged = approval(journey.candidate, ApprovalStage.OKTA_UNASSIGN, journey.j.T_REVIEW, journey.j.pre,
                              operator=self.FORGER)
            conn.execute("INSERT INTO approvals (id, candidate_id, stage, decision, operator_kind, operator_id, decided_at, "
                         "reason, evidence_fingerprint, candidate_epoch, expires_at, recorded_at, correlation_id) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'req-forged')",
                         (forged.id, forged.candidate_id, forged.stage.value, forged.decision.value,
                          forged.operator.kind.value, forged.operator.id, ts(forged.decided_at), forged.reason,
                          forged.evidence_fingerprint, forged.candidate_epoch, ts(forged.expires_at),
                          ts(forged.decided_at)))
            return forged.id

        cases = {
            "no approval (the Phase A reproduction)": (lambda journey, conn: None, self.FORGER, "approval"),
            "an approval row written with plain SQL": (written_with_sql, self.FORGER, "audit"),
            "a recorded approval its operator never acted on": (recorded_by(REVIEWER), REVIEWER, "audit"),
            "a recorded approval given by someone else": (recorded_by(REVIEWER), self.FORGER, "audit"),
        }
        for name, (cite, actor, pattern) in cases.items():
            with self.subTest(name):
                journey, conn = self.fresh(S.NEEDS_REVIEW)
                approval_id = cite(journey, conn)
                anchor = self.store.audit_head()[1]
                self.forge_approval_step(conn, journey.candidate.id, actor, approval_id)
                self.assertExposed(journey.candidate.id, anchor, pattern)

    def test_an_edited_approval_step_is_exposed(self):
        def cite(stage=ApprovalStage.OKTA_UNASSIGN, **kw):
            def edit(journey, conn):
                other = approval(journey.candidate, stage, journey.j.T_REVIEW, journey.j.pre,
                                 id=fixed_id(IdKind.APPROVAL, 50), **kw)
                self.store.record_approval(other)
                return "UPDATE decisions SET approval_id = ? WHERE to_state = 'APPROVED'", (other.id,)
            return edit

        def column(sql, *params):
            return lambda journey, conn: (f"UPDATE decisions SET {sql} WHERE to_state = 'APPROVED'", params)

        cases = {
            "actor": (column("actor_id = ?", self.FORGER.id), "audit"),
            "reason": (column("reason = 'edited'"), "audit"),
            "evidence fingerprint": (column("evidence_fingerprint = ?", "sha256:" + "0" * 64), "audit"),
            "approval removed": (column("approval_id = NULL"), "approval"),
            "another stage's approval": (cite(ApprovalStage.AD_QUARANTINE), "approval"),
            "a rejection": (cite(decision=ApprovalDecision.REJECT), "approval"),
            "another operator's approval": (cite(operator=SECOND_REVIEWER), "approval"),
        }
        for name, (edit, pattern) in cases.items():
            with self.subTest(name):
                journey, conn = self.fresh(S.APPROVED)
                sql, params = edit(journey, conn)
                anchor = self.store.audit_head()[1]
                conn.execute("DROP TRIGGER trg_decisions_no_update")
                conn.execute(sql, params)
                if name == "actor":  # keep the candidate row consistent with the edited history
                    conn.execute("DROP TRIGGER trg_candidates_follow_decisions")
                    conn.execute("UPDATE candidates SET okta_unassign_approver_id = ?", (self.FORGER.id,))
                self.assertExposed(journey.candidate.id, anchor, pattern)

    def test_an_edited_approval_is_exposed(self):
        edits = {
            "operator": ("operator_id", self.FORGER.id),
            "decision": ("decision", "REJECT"),
            "stage": ("stage", "AD_QUARANTINE"),
            "candidate epoch": ("candidate_epoch", 1),
            "evidence fingerprint": ("evidence_fingerprint", "sha256:" + "0" * 64),
            "expiry": ("expires_at", "2099-01-01T00:00:00.000000Z"),
        }
        for name, (column, value) in edits.items():
            with self.subTest(name):
                journey, conn = self.fresh(S.APPROVED)
                approval_id = journey.j.unassign_approval.id
                anchor = self.store.audit_head()[1]
                conn.execute("DROP TRIGGER trg_approvals_no_update")
                conn.execute(f"UPDATE approvals SET {column} = ? WHERE id = ?", (value, approval_id))
                with self.assertRaisesRegex(StoreIntegrityError, "audit"):
                    self.store.load_approval(approval_id)
                self.assertExposed(journey.candidate.id, anchor, "audit")

    def test_a_decision_whose_audit_event_was_removed_is_exposed_even_without_an_anchor(self):
        journey, conn = self.fresh(S.APPROVED)
        conn.execute("DROP TRIGGER trg_audit_events_no_delete")
        conn.execute("DELETE FROM audit_events WHERE sequence = (SELECT max(sequence) FROM audit_events)")
        with self.assertRaisesRegex(StoreIntegrityError, "TRANSITION_APPLIED audit event"):
            self.store.verify_integrity()


class AuditAppendTests(StoreTestCase):
    def test_chain_is_contiguous_and_linked(self):
        StoreJourney(self.store).to(S.HOLD)
        events = self.store.audit_events()
        self.assertEqual([e.sequence for e in events], list(range(len(events))))
        for previous, event in zip(events, events[1:]):
            self.assertEqual(event.previous_digest, previous.digest)
            self.assertLessEqual(previous.occurred_at, event.occurred_at)
        self.assertIs(events[0].action, AuditAction.STORE_INITIALIZED)
        for event in events:
            with self.subTest(sequence=event.sequence):
                self.assertIs(event.execution_mode, ExecutionMode.LOCAL_SYNTHETIC)
                self.assertIsNotNone(event.result)
                self.assertTrue(event.correlation_id)

    def test_clock_stepping_backwards_never_breaks_order(self):
        record_bundle(self.store, bundle(T0))
        self.clock.advance(-timedelta(minutes=30))
        self.store.record_evidence(assignment(T0 + HOUR, present=False), actor=SYSTEM)
        events = self.store.audit_events()
        self.assertGreaterEqual(events[-1].occurred_at, events[-2].occurred_at)

    def test_each_operation_has_its_own_correlation_id_unless_given(self):
        record_bundle(self.store, bundle(T0))
        events = self.store.audit_events()[1:]
        self.assertEqual(len({e.correlation_id for e in events}), len(events))
        self.store.record_evidence(assignment(T0 + HOUR, present=False), actor=SYSTEM, correlation_id="req-synthetic.42")
        self.assertEqual(self.store.audit_events()[-1].correlation_id, "req-synthetic.42")
        with self.assertRaises(InvalidRecord):
            self.store.record_evidence(assignment(T0 + 2 * HOUR), actor=SYSTEM, correlation_id="bad id with spaces")

    def test_credentials_never_reach_the_audit_log(self):
        journey = StoreJourney(self.store).to(S.APPROVED)
        j = journey.j
        job = dry_run_job(journey.candidate, JobKind.OKTA_UNASSIGN, j.unassign_approval, j.pre,
                          j.T_APPROVE + timedelta(minutes=5), j.T_APPROVE + timedelta(minutes=20), status=JobStatus.FAILED)
        self.store.record_execution_job(job, external_ref="aap-synthetic-job-7",
                                        detail="worker said: api_token=synthetic-leaked-value-123 Bearer synthetic.jwt.value")
        stored = self.store.job_status_history(job.id)[-1].detail
        self.assertNotIn("synthetic-leaked-value-123", stored)
        self.assertNotIn("synthetic.jwt.value", stored)
        dump = "\n".join(str(tuple(r)) for r in self.store.connection.execute("SELECT * FROM audit_events"))
        self.assertNotIn("synthetic-leaked-value-123", dump)
        self.assertNotIn("synthetic.jwt.value", dump)
        self.assertIs(self.store.audit_events()[-1].result, AuditResult.FAILED)


class FailedCommitTests(unittest.TestCase):
    """A COMMIT that fails rolls back: nothing half-written stays visible, and the connection works again."""

    def test_a_constraint_failing_at_commit_rolls_back_and_the_connection_recovers(self):
        conn = connect(memory_target())
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent (id))")
        with self.assertRaises(sqlite3.IntegrityError):
            with transaction(conn):
                conn.execute("PRAGMA defer_foreign_keys = ON")  # the dangling reference fails at COMMIT
                conn.execute("INSERT INTO child (parent_id) VALUES (99)")
        self.assertFalse(conn.in_transaction)
        self.assertEqual(conn.execute("SELECT count(*) FROM child").fetchone()[0], 0)
        with transaction(conn):
            conn.execute("INSERT INTO parent (id) VALUES (1)")
            conn.execute("INSERT INTO child (parent_id) VALUES (1)")
        self.assertEqual(conn.execute("SELECT count(*) FROM child").fetchone()[0], 1)

    def test_a_busy_commit_rolls_back_and_the_store_keeps_working(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "store.sqlite3"
        store = new_store(file_target(path))
        self.addCleanup(store.close)
        store.connection.execute("PRAGMA busy_timeout = 0")  # report SQLITE_BUSY at once, not after 5 s
        head, events = store.audit_head(), len(store.audit_events())
        reader = sqlite3.connect(path, isolation_level=None)
        self.addCleanup(reader.close)
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM audit_events").fetchone()  # a shared lock: the writer cannot COMMIT
        with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
            store.record_evidence(application(T0), actor=SYSTEM)
        reader.execute("ROLLBACK")
        self.assertFalse(store.connection.in_transaction)
        self.assertIsNone(store.latest(OktaApplication, application(T0).id), "the failed write is not visible")
        self.assertEqual(store.audit_head(), head)
        store.record_evidence(application(T0), actor=SYSTEM)
        self.assertEqual(store.latest(OktaApplication, application(T0).id), application(T0))
        self.assertEqual(len(store.audit_events()), events + 1)
        report = store.verify_integrity(expected_audit_head=store.audit_head()[1])
        self.assertEqual((report.audit_events, report.observations_checked), (events + 1, 1))
        with Store.open(file_target(path), mode=ExecutionMode.LOCAL_SYNTHETIC) as other:
            self.assertEqual(other.audit_head(), store.audit_head(), "a second connection sees only the committed write")


class EnvironmentRuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_synthetic_store_accepts_only_synthetic_evidence(self):
        with new_store() as store:
            real = application(T0, provenance=prov(T0, source=EvidenceSource.OKTA_API))
            with self.assertRaisesRegex(EnvironmentRefused, "SYNTHETIC store"):
                store.record_evidence(real, actor=SYSTEM)
            configured = mapping(T0, confidence=MappingConfidence.EXACT_CONFIGURED_MAPPING)
            with self.assertRaisesRegex(EnvironmentRefused, "SYNTHETIC store"):
                store.record_evidence(configured, actor=SYSTEM)

    def test_production_store_refuses_synthetic_data_and_synthetic_mode(self):
        target = file_target(self.dir / "prod.sqlite3")
        with self.assertRaises(EnvironmentRefused):
            new_store(target, environment=DatabaseEnvironment.PRODUCTION)  # LOCAL_SYNTHETIC mode
        self.assertFalse(target.path.exists())
        with new_store(target, environment=DatabaseEnvironment.PRODUCTION, mode=ExecutionMode.READ_ONLY_PRODUCTION) as store:
            with self.assertRaisesRegex(EnvironmentRefused, "PRODUCTION store"):
                store.record_evidence(application(T0), actor=SYSTEM)
            store.record_evidence(application(T0, provenance=prov(T0, source=EvidenceSource.OKTA_API)), actor=SYSTEM)
        with self.assertRaises(EnvironmentRefused):
            Store.open(target, mode=ExecutionMode.LOCAL_SYNTHETIC)

    def test_synthetic_store_cannot_be_opened_for_real_discovery(self):
        target = file_target(self.dir / "synthetic.sqlite3")
        new_store(target).close()
        for mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION):
            with self.subTest(mode=mode), self.assertRaises(EnvironmentRefused):
                Store.open(target, mode=mode)

    def test_development_store_in_synthetic_mode_refuses_real_evidence(self):
        with new_store(environment=DatabaseEnvironment.DEVELOPMENT) as store:
            with self.assertRaisesRegex(EnvironmentRefused, "LOCAL_SYNTHETIC mode"):
                store.record_evidence(application(T0, provenance=prov(T0, source=EvidenceSource.OKTA_API)), actor=SYSTEM)
            store.record_evidence(application(T0), actor=SYSTEM)

    def test_execution_jobs_are_recorded_only_in_job_modes(self):
        target, clock = file_target(self.dir / "dev.sqlite3"), MutableClock()
        with new_store(target, environment=DatabaseEnvironment.DEVELOPMENT, clock=clock) as store:
            journey = StoreJourney(store).to(S.APPROVED)
        j = journey.j
        job = dry_run_job(journey.candidate, JobKind.OKTA_UNASSIGN, j.unassign_approval, j.pre,
                          j.T_APPROVE + timedelta(minutes=5), j.T_APPROVE + timedelta(minutes=20))
        with Store.open(target, mode=ExecutionMode.READ_ONLY_PRODUCTION, clock=clock) as store:
            head = store.audit_head()
            with self.assertRaisesRegex(EnvironmentRefused, "READ_ONLY_PRODUCTION"):
                store.record_execution_job(job)
            self.assertEqual(store.audit_head(), head)
            self.assertFalse(store.job_status_history(job.id))
        with Store.open(target, mode=ExecutionMode.LOCAL_SYNTHETIC, clock=clock) as store:
            store.record_execution_job(job)  # the same job, in a job mode
            self.assertIs(store.load_execution_job(job.id).status, JobStatus.SUCCEEDED)

    def test_production_mutation_store_cannot_exist(self):
        from app.core.errors import ProductionMutationNotPermitted

        with self.assertRaises(ProductionMutationNotPermitted):
            new_store(file_target(self.dir / "x.sqlite3"), environment=DatabaseEnvironment.PRODUCTION,
                      mode=ExecutionMode.PRODUCTION_MUTATION)
        self.assertFalse((self.dir / "x.sqlite3").exists())


class JobAndCollectorTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.journey = StoreJourney(self.store).to(S.APPROVED)
        j = self.journey.j
        self.planned = dry_run_job(self.journey.candidate, JobKind.OKTA_UNASSIGN, j.unassign_approval, j.pre,
                                   j.T_APPROVE + timedelta(minutes=5), None, status=JobStatus.PLANNED)
        self.finish = j.T_APPROVE + timedelta(minutes=30)

    def test_status_history_is_appended_and_kept(self):
        self.store.record_execution_job(self.planned)
        self.store.record_execution_job(replace(self.planned, status=JobStatus.RUNNING), external_ref="aap-synthetic-job-1")
        self.store.record_execution_job(replace(self.planned, status=JobStatus.SUCCEEDED, finished_at=self.finish))
        history = self.store.job_status_history(self.planned.id)
        self.assertEqual([h.status for h in history], [JobStatus.PLANNED, JobStatus.RUNNING, JobStatus.SUCCEEDED])
        self.assertIs(self.store.load_execution_job(self.planned.id).status, JobStatus.SUCCEEDED)

    def test_status_cannot_regress_or_change_after_finishing(self):
        self.store.record_execution_job(self.planned)
        self.store.record_execution_job(replace(self.planned, status=JobStatus.FAILED, finished_at=self.finish))
        with self.assertRaisesRegex(StoreConflict, "final"):
            self.store.record_execution_job(replace(self.planned, status=JobStatus.RUNNING))

    def test_job_request_fields_are_immutable(self):
        self.store.record_execution_job(self.planned)
        with self.assertRaisesRegex(StoreConflict, "cannot change"):
            self.store.record_execution_job(replace(self.planned, status=JobStatus.RUNNING, requested_by=REVIEWER))
        with self.assertRaisesRegex(StoreConflict, "cannot move"):
            self.store.record_execution_job(replace(self.planned, status=JobStatus.PLANNED))

    def test_job_needs_a_recorded_approval_of_its_candidate_and_known_targets(self):
        with self.assertRaisesRegex(StoreConflict, "recorded approval"):
            self.store.record_execution_job(replace(self.planned, approval_id=fixed_id(IdKind.APPROVAL, 99)))
        with self.assertRaisesRegex(StoreConflict, "not recorded"):
            self.store.record_execution_job(replace(self.planned, targets=(fixed_id(IdKind.ASSIGNMENT, 99),)))

    def _run(self, n=1, source=EvidenceSource.SYNTHETIC, mode=ExecutionMode.LOCAL_SYNTHETIC):
        return CollectorRun(id=fixed_id(IdKind.COLLECTOR_RUN, n), collector="okta-usage", collector_version="synthetic-1.0",
                            source=source, mode=mode, scope="synthetic:okta-usage", started_at=T0 + 3 * DAY, started_by=SYSTEM)

    def test_collector_run_lifecycle(self):
        run = self._run()
        self.store.start_collector_run(run)
        self.store.record_evidence(usage(T0 + 3 * DAY + HOUR), actor=SYSTEM, collector_run_id=run.id)
        outcome = CollectorRunOutcome(run.id, T0 + 3 * DAY + 2 * HOUR, ResultStatus.PARTIAL, 1, CollectorErrorCode.RATE_LIMITED,
                                      "HTTP 429; Retry-After exceeded the ceiling")
        self.store.finish_collector_run(outcome, actor=SYSTEM)
        self.assertEqual(self.store.collector_run_outcome(run.id), outcome)
        self.assertIs(self.store.audit_events()[-1].result, AuditResult.FAILED)
        with self.assertRaisesRegex(StoreConflict, "has finished"):
            self.store.record_evidence(usage(T0 + 3 * DAY + 3 * HOUR), actor=SYSTEM, collector_run_id=run.id)
        with self.assertRaisesRegex(StoreConflict, "UNIQUE|PRIMARY"):
            self.store.finish_collector_run(outcome, actor=SYSTEM)

    def test_collector_run_must_match_mode_and_source(self):
        with self.assertRaises(EnvironmentRefused):
            self.store.start_collector_run(self._run(mode=ExecutionMode.READ_ONLY_PRODUCTION))
        with self.assertRaises(EnvironmentRefused):
            self.store.start_collector_run(self._run(source=EvidenceSource.OKTA_API))

    def test_observation_must_belong_to_an_open_run_of_its_source(self):
        with self.assertRaisesRegex(StoreConflict, "not recorded"):
            self.store.record_evidence(usage(T0 + 3 * DAY), actor=SYSTEM, collector_run_id=fixed_id(IdKind.COLLECTOR_RUN, 5))
        self.store.start_collector_run(self._run())
        with self.assertRaisesRegex(StoreConflict, "predates"):
            self.store.record_evidence(usage(T0 + DAY), actor=SYSTEM, collector_run_id=fixed_id(IdKind.COLLECTOR_RUN, 1))


if __name__ == "__main__":
    unittest.main()
