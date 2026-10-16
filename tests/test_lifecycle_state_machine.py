"""The lifecycle state machine: the transition table, every guard, approvals, re-entry, and history."""

import itertools
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from app.core.modes import ExecutionMode
from app.domain.actors import ActorKind
from app.domain.approval import ApprovalDecision, ApprovalStage
from app.domain.audit import AuditAction, AuditTrail, verify_chain
from app.domain.errors import InvalidRecord, TransitionRefused
from app.domain.evidence import ResultStatus
from app.domain.execution import JobKind, JobStatus
from app.domain.ids import IdKind
from app.domain.lifecycle import (
    BLOCKED_STATES,
    DELETION_PROPOSED_STATES,
    DIVERSION_TARGETS,
    FORWARD_PATH,
    POST_QUARANTINE_STATES,
    POST_UNASSIGN_STATES,
    PRE_UNASSIGN_STATES,
    PROGRESSING_STATES,
    QUARANTINE_APPROVED_STATES,
    REENTRY_TARGETS,
    TERMINAL_STATES,
    TRANSITIONS,
    UNASSIGN_APPROVED_STATES,
    LifecycleCandidate,
    LifecycleState,
    TransitionRequest,
    allowed_targets,
    apply_and_audit,
    apply_transition,
    recommend_diversion,
    verify_history,
)
from app.domain.model import DependencyKind, MappingConfidence
from app.domain.policy import MANDATORY_DEPENDENCY_KINDS, LifecyclePolicy
from tests.domain_fixtures import (
    AD_ID_2,
    ASSIGNMENT_ID,
    DAY,
    GROUP_ID,
    HOUR,
    POLICY,
    QUARANTINE_OUS,
    REVIEWER,
    SECOND_REVIEWER,
    SYSTEM,
    T0,
    THIRD_REVIEWER,
    Journey,
    ad_group,
    approval,
    assignment,
    blocking_finding,
    bundle,
    dependencies,
    dependency,
    dry_run_job,
    fixed_id,
    mapping,
    new_candidate,
    usage,
)

S = LifecycleState
REPO_ROOT = Path(__file__).resolve().parents[1]
ALL_STATES = frozenset(LifecycleState)


def candidate_in(state: LifecycleState, blocked_from: LifecycleState | None = None, **kw) -> LifecycleCandidate:
    """Rehydrate a candidate in ``state`` (as a store would), satisfying the record invariants."""
    if state in BLOCKED_STATES and blocked_from is None:
        blocked_from = S.CANDIDATE
    needs_hold = state in POST_UNASSIGN_STATES or state is S.RETIRED or blocked_from in POST_UNASSIGN_STATES
    position = blocked_from or state
    proposed = position in DELETION_PROPOSED_STATES
    fields = dict(id=fixed_id(IdKind.CANDIDATE, 1), okta_group_id=GROUP_ID, assignment_ids=(ASSIGNMENT_ID,), state=state,
                  proposed_by=SYSTEM, created_at=T0, updated_at=T0, hold_until=T0 if needs_hold else None,
                  blocked_from=blocked_from if state in BLOCKED_STATES else None,
                  okta_unassign_approver=REVIEWER if position in UNASSIGN_APPROVED_STATES else None,
                  quarantine_approver=SECOND_REVIEWER if position in QUARANTINE_APPROVED_STATES else None,
                  quarantine_hold_until=T0 if position in POST_QUARANTINE_STATES else None,
                  deletion_proposer=THIRD_REVIEWER if proposed else None, deletion_proposed_at=T0 if proposed else None)
    fields.update(kw)
    return LifecycleCandidate(**fields)


def request(target, at, actor=SYSTEM, evidence=None, approval_record=None, job=None, reason="synthetic"):
    return TransitionRequest(target=target, actor=actor, reason=reason, now=at, evidence=evidence or bundle(T0),
                             approval=approval_record, job=job, quarantine_ous=QUARANTINE_OUS)


class RefusalAssertions(unittest.TestCase):
    def assertRefused(self, candidate, req, expected: str, policy=POLICY):
        with self.assertRaises(TransitionRefused) as ctx:
            apply_transition(candidate, req, policy)
        joined = " | ".join(ctx.exception.problems)
        self.assertIn(expected, joined)
        return ctx.exception


# --- The table itself ----------------------------------------------------------------


class TransitionTableTests(unittest.TestCase):
    def test_every_state_is_classified_exactly_once(self):
        groups = [PRE_UNASSIGN_STATES, POST_UNASSIGN_STATES, BLOCKED_STATES, TERMINAL_STATES]
        self.assertEqual(frozenset().union(*groups), ALL_STATES)
        for a, b in itertools.combinations(groups, 2):
            self.assertEqual(a & b, frozenset())

    def test_terminal_states_have_no_outgoing_transitions(self):
        for state in TERMINAL_STATES:
            with self.subTest(state=state):
                self.assertEqual(allowed_targets(state), frozenset())

    def test_progressing_states_only_move_one_step_forward(self):
        for (source, target), rule in TRANSITIONS.items():
            if rule.category == "legacy":
                continue  # history only; always refused (LegacyStageTests)
            if source in PROGRESSING_STATES and target in PROGRESSING_STATES | {S.RETIRED}:
                with self.subTest(source=source, target=target):
                    self.assertEqual(FORWARD_PATH.index(target), FORWARD_PATH.index(source) + 1)

    def test_forward_path_is_fully_present(self):
        for source, target in zip(FORWARD_PATH, FORWARD_PATH[1:]):
            with self.subTest(source=source):
                self.assertEqual(TRANSITIONS[(source, target)].category, "forward")

    def test_nothing_returns_to_discovered_and_gates_have_one_entrance(self):
        entrances = {t: {s for (s, t2) in TRANSITIONS if t2 is t} for t in ALL_STATES}
        self.assertEqual(entrances[S.DISCOVERED], set())
        self.assertEqual(entrances[S.APPROVED], {S.NEEDS_REVIEW})
        self.assertEqual(entrances[S.OKTA_UNASSIGN_DRY_RUN], {S.APPROVED})
        self.assertEqual(entrances[S.HOLD], {S.OKTA_UNASSIGN_DRY_RUN})
        self.assertEqual(entrances[S.QUARANTINE_APPROVED], {S.REVALIDATION_REQUIRED})
        self.assertEqual(entrances[S.QUARANTINE_DRY_RUN], {S.QUARANTINE_APPROVED})
        self.assertEqual(entrances[S.QUARANTINE_HOLD], {S.QUARANTINE_DRY_RUN})
        self.assertEqual(entrances[S.DELETION_PROPOSED], {S.DELETION_REVALIDATION_REQUIRED})
        self.assertEqual(entrances[S.DELETION_APPROVED], {S.DELETION_PROPOSED})
        self.assertEqual(entrances[S.DELETION_DRY_RUN], {S.DELETION_APPROVED})
        # The legacy single AD stage keeps its two edges, for history only (D148).
        self.assertEqual(entrances[S.RETIREMENT_DRY_RUN], {S.REVALIDATION_REQUIRED})
        self.assertEqual(entrances[S.RETIRED], {S.DELETION_DRY_RUN, S.RETIREMENT_DRY_RUN})
        self.assertEqual(entrances[S.CANDIDATE], {S.DISCOVERED} | BLOCKED_STATES)
        self.assertEqual(entrances[S.REVALIDATION_REQUIRED], {S.HOLD} | BLOCKED_STATES)
        self.assertEqual(entrances[S.DELETION_REVALIDATION_REQUIRED], {S.QUARANTINE_HOLD} | BLOCKED_STATES)

    def test_every_non_terminal_state_can_divert_to_every_safer_state(self):
        for source in PROGRESSING_STATES | BLOCKED_STATES:
            for target in DIVERSION_TARGETS - {source}:
                with self.subTest(source=source, target=target):
                    self.assertIn((source, target), TRANSITIONS)

    def test_human_only_transitions(self):
        for (source, target), rule in TRANSITIONS.items():
            human_only = (
                target in (S.APPROVED, S.QUARANTINE_APPROVED, S.DELETION_PROPOSED, S.DELETION_APPROVED, S.EXCLUDED,
                           S.REJECTED)
                or (source is S.BLOCKED and target in REENTRY_TARGETS)
            )
            with self.subTest(source=source, target=target):
                self.assertEqual(rule.actors == frozenset({ActorKind.HUMAN}), human_only)

    def test_every_unlisted_transition_is_refused_even_with_full_evidence(self):
        journey = Journey().to(S.RETIRED)
        evidence = journey.after_hold
        for source, target in itertools.product(ALL_STATES, ALL_STATES):
            if (source, target) in TRANSITIONS:
                continue
            candidate = candidate_in(source)
            req = request(target, T0 + 400 * DAY, actor=REVIEWER, evidence=evidence,
                          approval_record=journey.deletion_approval, job=journey.deletion_job)
            with self.subTest(source=source, target=target):
                with self.assertRaises(TransitionRefused) as ctx:
                    apply_transition(candidate, req, POLICY)
                self.assertIn("not a permitted transition", ctx.exception.problems[0])

    def test_lifecycle_document_lists_every_forward_transition_and_state(self):
        text = (REPO_ROOT / "docs" / "architecture" / "lifecycle-state-machine.md").read_text(encoding="utf-8")
        for (source, target), rule in TRANSITIONS.items():
            if rule.category == "forward":
                with self.subTest(source=source, target=target):
                    self.assertIn(f"`{source.value}` → `{target.value}`", text)
        for state in ALL_STATES:
            self.assertIn(f"`{state.value}`", text)


# --- Records and requests ------------------------------------------------------------


class CandidateRecordTests(unittest.TestCase):
    def test_discover_always_starts_in_discovered(self):
        c = new_candidate()
        self.assertIs(c.state, S.DISCOVERED)
        self.assertEqual(c.epoch, 0)

    def test_record_invariants(self):
        for kwargs in (
            {"state": S.BLOCKED, "blocked_from": None},
            {"state": S.CANDIDATE, "blocked_from": S.CANDIDATE},
            {"state": S.BLOCKED, "blocked_from": S.REJECTED},
            {"state": S.HOLD, "hold_until": None},
            {"state": S.RETIRED, "hold_until": None},
            # The AD stages' records.
            {"state": S.QUARANTINE_APPROVED, "hold_until": T0, "okta_unassign_approver": REVIEWER},
            {"state": S.REVALIDATION_REQUIRED, "hold_until": T0, "okta_unassign_approver": REVIEWER,
             "quarantine_approver": SECOND_REVIEWER},
            {"state": S.QUARANTINE_HOLD, "hold_until": T0, "okta_unassign_approver": REVIEWER,
             "quarantine_approver": SECOND_REVIEWER},
            {"state": S.DELETION_PROPOSED, "hold_until": T0, "okta_unassign_approver": REVIEWER,
             "quarantine_approver": SECOND_REVIEWER, "quarantine_hold_until": T0},
            {"state": S.HOLD, "hold_until": T0, "okta_unassign_approver": REVIEWER, "quarantine_hold_until": T0},
            {"state": S.QUARANTINE_APPROVED, "hold_until": T0, "okta_unassign_approver": REVIEWER,
             "quarantine_approver": REVIEWER},
            {"state": S.QUARANTINE_APPROVED, "hold_until": T0, "okta_unassign_approver": REVIEWER,
             "quarantine_approver": SYSTEM},
            {"state": S.STALE_EVIDENCE, "blocked_from": S.HOLD, "hold_until": None},
            {"updated_at": T0 - HOUR},
            {"assignment_ids": ()},
            {"epoch": -1},
            {"state": "CANDIDATE"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                replace(candidate_in(S.CANDIDATE), **kwargs)

    def test_request_requires_a_reason(self):
        for reason in ("", "   "):
            with self.subTest(reason=reason), self.assertRaises(InvalidRecord):
                request(S.CANDIDATE, T0, reason=reason)

    def test_request_dated_before_the_last_change_is_refused(self):
        c = Journey().to(S.CANDIDATE).candidate
        with self.assertRaises(TransitionRefused) as ctx:
            apply_transition(c, request(S.NEEDS_REVIEW, T0), POLICY)
        self.assertIn("dated before", " ".join(ctx.exception.problems))


# --- Happy path ----------------------------------------------------------------------


class HappyPathTests(unittest.TestCase):
    def test_full_forward_path_uses_only_dry_runs_and_observation(self):
        j = Journey().to(S.RETIRED)
        self.assertIs(j.candidate.state, S.RETIRED)
        self.assertEqual([d.to_state for d in j.decisions], list(FORWARD_PATH[1:]))
        for job in (j.unassign_job, j.quarantine_job, j.deletion_job):
            self.assertTrue(job.dry_run)
            self.assertFalse(job.executed)
            self.assertIs(job.mode, ExecutionMode.DRY_RUN_MUTATION)
        verify_history(j.candidate, j.decisions)

    def test_hold_sets_hold_until_from_policy(self):
        j = Journey().to(S.HOLD)
        self.assertEqual(j.candidate.hold_until, Journey.T_UNASSIGNED_SEEN + POLICY.hold_period)

    def test_decisions_reference_approval_job_and_fingerprint(self):
        j = Journey().to(S.OKTA_UNASSIGN_DRY_RUN)
        approved, dry_run = j.decisions[2], j.decisions[3]
        self.assertEqual(approved.approval_id, j.unassign_approval.id)
        self.assertEqual(approved.actor, REVIEWER)
        self.assertEqual(dry_run.execution_job_id, j.unassign_job.id)
        self.assertEqual(dry_run.evidence_fingerprint, j.unassign_approval.evidence_fingerprint)

    def test_each_exact_confidence_can_be_approved(self):
        for confidence in (MappingConfidence.EXACT_STABLE_ID, MappingConfidence.EXACT_DIRECTORY_SOURCE,
                           MappingConfidence.EXACT_CONFIGURED_MAPPING):
            with self.subTest(confidence=confidence):
                j = Journey()
                j.pre = bundle(T0, confidence=confidence)
                j.to(S.APPROVED)
                self.assertIs(j.candidate.state, S.APPROVED)

    def test_apply_and_audit_records_applied_and_refused_transitions(self):
        trail = AuditTrail()
        c = new_candidate()
        result = apply_and_audit(c, request(S.CANDIDATE, Journey.T_CANDIDATE), POLICY, trail)
        with self.assertRaises(TransitionRefused):
            apply_and_audit(result.candidate, request(S.APPROVED, Journey.T_REVIEW, actor=REVIEWER), POLICY, trail)
        actions = [e.action for e in trail.events]
        self.assertEqual(actions, [AuditAction.TRANSITION_APPLIED, AuditAction.TRANSITION_REFUSED])
        self.assertEqual(dict(trail.events[0].details)["decision_id"], result.decision.id)
        verify_chain(trail.events)


# --- DISCOVERED -> CANDIDATE ---------------------------------------------------------


class CandidacyGuardTests(RefusalAssertions):
    AT = Journey.T_CANDIDATE

    def check(self, evidence, expected, policy=POLICY):
        return self.assertRefused(new_candidate(), request(S.CANDIDATE, self.AT, evidence=evidence), expected, policy)

    def test_refusals(self):
        cases = [
            ("stale for REVIEW", bundle(T0 - 31 * DAY)),
            ("not decision-grade", bundle(T0, assignments=(assignment(T0, status=ResultStatus.PARTIAL),))),
            ("not decision-grade", bundle(T0, usage=(usage(T0, status=ResultStatus.FAILED),))),
            ("in the future", bundle(T0, usage=(usage(self.AT + HOUR),))),
            ("candidacy threshold", bundle(T0, usage_events=1)),
            ("shorter than", bundle(T0, usage=(usage(T0, window_days=60),))),
            ("no usage observation", bundle(T0, usage=())),
            ("is not present", bundle(T0, present=False)),
            ("no observation of assignment", bundle(T0, assignments=())),
            ("no Okta group observation", bundle(T0, okta_group=None)),
            ("different group", bundle(T0, assignments=(assignment(T0, okta_group_id=fixed_id(IdKind.OKTA_GROUP, 7)),))),
            ("protected", bundle(T0, ad_group=ad_group(T0, rid=512))),
            ("blocking dependency", bundle(T0, dependencies=(dependency(T0, DependencyKind.AD_ACL_REFERENCE, 1, (blocking_finding(),)),))),
            ("unrelated subject", bundle(T0, dependencies=(dependency(T0, DependencyKind.OTHER, 1, subject_id=AD_ID_2),))),
            ("not the mapped AD group", bundle(T0, ad_group=ad_group(T0, id=AD_ID_2))),
        ]
        for expected, evidence in cases:
            with self.subTest(expected=expected):
                self.check(evidence, expected)

    def test_low_usage_threshold_is_a_policy_choice_within_its_ceiling(self):
        lenient = LifecyclePolicy(max_usage_events_for_candidate=5)
        result = apply_transition(new_candidate(), request(S.CANDIDATE, self.AT, evidence=bundle(T0, usage_events=5)), lenient)
        self.assertIs(result.candidate.state, S.CANDIDATE)
        self.check(bundle(T0, usage_events=6), "candidacy threshold", lenient)

    def test_a_failed_dependency_check_does_not_block_candidacy(self):
        failed = dependency(T0, DependencyKind.GPO_REFERENCE, 1, status=ResultStatus.FAILED)
        result = apply_transition(new_candidate(), request(S.CANDIDATE, self.AT, evidence=bundle(T0, dependencies=(failed,))), POLICY)
        self.assertIs(result.candidate.state, S.CANDIDATE)


# --- CANDIDATE -> NEEDS_REVIEW -------------------------------------------------------


class ReviewGuardTests(RefusalAssertions):
    def test_requires_a_recorded_mapping(self):
        c = Journey().to(S.CANDIDATE).candidate
        self.assertRefused(c, request(S.NEEDS_REVIEW, Journey.T_REVIEW, evidence=bundle(T0, mapping=None, ad_group=None)),
                           "no identity mapping recorded")

    def test_inexact_mappings_may_still_be_investigated(self):
        for confidence in (MappingConfidence.NAME_ONLY, MappingConfidence.AMBIGUOUS, MappingConfidence.NOT_FOUND):
            with self.subTest(confidence=confidence):
                c = Journey().to(S.CANDIDATE).candidate
                result = apply_transition(c, request(S.NEEDS_REVIEW, Journey.T_REVIEW, evidence=bundle(T0, confidence=confidence)), POLICY)
                self.assertIs(result.candidate.state, S.NEEDS_REVIEW)


# --- NEEDS_REVIEW -> APPROVED --------------------------------------------------------


class ApprovalGuardTests(RefusalAssertions):
    AT = Journey.T_APPROVE

    def setUp(self):
        self.c = Journey().to(S.NEEDS_REVIEW).candidate

    def approve(self, evidence=None, actor=REVIEWER, at=None, **approval_kw):
        evidence = evidence or bundle(T0)
        decided = approval_kw.pop("decided_at", self.AT - timedelta(minutes=10))
        stage = approval_kw.pop("stage", ApprovalStage.OKTA_UNASSIGN)
        record = approval(self.c, stage, decided, evidence, **approval_kw)
        return request(S.APPROVED, at or self.AT, actor=actor, evidence=evidence, approval_record=record)

    def test_inexact_mapping_cannot_be_approved(self):
        for confidence in (MappingConfidence.NAME_ONLY, MappingConfidence.AMBIGUOUS, MappingConfidence.NOT_FOUND):
            with self.subTest(confidence=confidence):
                self.assertRefused(self.c, self.approve(bundle(T0, confidence=confidence)), "requires an exact mapping")

    def test_refusals(self):
        other_candidate = fixed_id(IdKind.CANDIDATE, 99)
        cases = [
            ("SYSTEM actors cannot", self.approve(actor=SYSTEM)),
            ("only the approving operator", self.approve(actor=SECOND_REVIEWER)),
            ("decision is REJECT", self.approve(decision=ApprovalDecision.REJECT)),
            ("not OKTA_UNASSIGN", self.approve(stage=ApprovalStage.AD_RETIREMENT)),
            ("different candidate", self.approve(candidate_id=other_candidate)),
            ("has expired", self.approve(decided_at=self.AT - 2 * DAY, ttl=DAY)),
            ("lifetime exceeds", self.approve(ttl=8 * DAY)),
            ("in the future", self.approve(decided_at=self.AT + HOUR)),
            ("stale for APPROVAL", self.approve(bundle(T0 - 8 * DAY), at=self.AT)),
            ("no longer exists", self.approve(bundle(T0, ad_group=ad_group(T0, exists=False)))),
            ("protected", self.approve(bundle(T0, ad_group=ad_group(T0, admin_count=True)))),
            ("blocking dependency", self.approve(bundle(T0, dependencies=(dependency(T0, DependencyKind.OKTA_OTHER_APP_ASSIGNMENT, 1, (blocking_finding(),)),)))),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.c, req, expected)

    def test_missing_approval_is_refused(self):
        self.assertRefused(self.c, request(S.APPROVED, self.AT, actor=REVIEWER), "no OKTA_UNASSIGN approval")

    def test_proposer_cannot_approve_their_own_candidate(self):
        j = Journey()
        j.candidate = new_candidate(proposed_by=REVIEWER)
        j.to(S.NEEDS_REVIEW)
        record = approval(j.candidate, ApprovalStage.OKTA_UNASSIGN, self.AT - HOUR, bundle(T0))
        self.assertRefused(j.candidate, request(S.APPROVED, self.AT, actor=REVIEWER, approval_record=record), "cannot approve it")

    def test_approval_is_invalidated_by_material_evidence_change(self):
        record = approval(self.c, ApprovalStage.OKTA_UNASSIGN, self.AT - HOUR, bundle(T0))
        changed = [
            bundle(T0, ad_group=ad_group(T0, member_count=12)),
            bundle(T0, dependencies=dependencies(T0, MANDATORY_DEPENDENCY_KINDS)),
            bundle(T0, confidence=MappingConfidence.EXACT_DIRECTORY_SOURCE),
        ]
        for evidence in changed:
            with self.subTest(evidence=evidence):
                req = request(S.APPROVED, self.AT, actor=REVIEWER, evidence=evidence, approval_record=record)
                self.assertRefused(self.c, req, "material evidence changed")

    def test_re_observed_identical_evidence_keeps_the_approval_valid(self):
        record = approval(self.c, ApprovalStage.OKTA_UNASSIGN, self.AT - HOUR, bundle(T0))
        req = request(S.APPROVED, self.AT, actor=REVIEWER, evidence=bundle(T0 + HOUR), approval_record=record)
        self.assertIs(apply_transition(self.c, req, POLICY).candidate.state, S.APPROVED)


# --- APPROVED -> OKTA_UNASSIGN_DRY_RUN -----------------------------------------------


class UnassignDryRunGuardTests(RefusalAssertions):
    def setUp(self):
        self.j = Journey().to(S.APPROVED)
        self.at = Journey.T_UNASSIGN_DRY_RUN

    def job(self, evidence=None, **kw):
        requested, finished = kw.pop("requested_at", Journey.T_APPROVE), kw.pop("finished_at", self.at - timedelta(minutes=5))
        kind = kw.pop("kind", JobKind.OKTA_UNASSIGN)
        return dry_run_job(self.j.candidate, kind, self.j.unassign_approval, evidence or self.j.pre, requested, finished, **kw)

    def req(self, job=None, evidence=None, at=None, approval_record=None):
        return request(S.OKTA_UNASSIGN_DRY_RUN, at or self.at, evidence=evidence or self.j.pre,
                       approval_record=approval_record or self.j.unassign_approval, job=job)

    def test_refusals(self):
        other_approval = replace(self.j.unassign_approval, id=fixed_id(IdKind.APPROVAL, 50))
        cases = [
            ("no OKTA_UNASSIGN dry-run job", self.req()),
            ("not a dry run", self.req(self.job(mode=ExecutionMode.LOCAL_SYNTHETIC, dry_run=False, executed=True, targets_synthetic=True))),
            ("dry run status is FAILED", self.req(self.job(status=JobStatus.FAILED))),
            ("dry run status is PLANNED", self.req(self.job(status=JobStatus.PLANNED, finished_at=None))),
            ("not OKTA_UNASSIGN", self.req(self.job(kind=JobKind.AD_RETIREMENT, targets=(ad_group(T0).id,)))),
            ("different candidate", self.req(self.job(candidate_id=fixed_id(IdKind.CANDIDATE, 42)))),
            ("different approval", self.req(self.job(approval_id=other_approval.id))),
            ("before the approval", self.req(self.job(requested_at=T0))),
            ("targets do not match", self.req(self.job(targets=(fixed_id(IdKind.ASSIGNMENT, 9),)))),
            ("changed since the dry run", self.req(self.job(evidence=bundle(T0, usage_events=0, applications=())))),
            ("stale for EXECUTION", self.req(self.job(), at=T0 + 2 * DAY)),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.j.candidate, req, expected)

    def test_approval_expiring_before_the_dry_run_is_refused(self):
        short = replace(self.j.unassign_approval, expires_at=self.at - HOUR)
        self.assertRefused(self.j.candidate, self.req(self.job(), approval_record=short), "has expired")


# --- OKTA_UNASSIGN_DRY_RUN -> HOLD ---------------------------------------------------


class HoldGuardTests(RefusalAssertions):
    def setUp(self):
        self.j = Journey().to(S.OKTA_UNASSIGN_DRY_RUN)

    def req(self, evidence, at=Journey.T_UNASSIGNED_SEEN, job="default"):
        job = self.j.unassign_job if job == "default" else job
        return request(S.HOLD, at, evidence=evidence, approval_record=self.j.unassign_approval, job=job)

    def test_refusals(self):
        before_dry_run = Journey.T_UNASSIGN_DRY_RUN - timedelta(minutes=30)
        cases = [
            ("is not absent", self.req(self.j.pre)),
            ("observed before the dry run finished", self.req(self.j.unassigned_evidence(before_dry_run), at=Journey.T_UNASSIGN_DRY_RUN)),
            ("stale for EXECUTION", self.req(self.j.unassigned_evidence(), at=Journey.T_UNASSIGNED_SEEN + 2 * DAY)),
            ("no OKTA_UNASSIGN dry-run job", self.req(self.j.unassigned_evidence(), job=None)),
            ("not decision-grade", self.req(replace(self.j.pre, assignments=(assignment(Journey.T_UNASSIGNED_SEEN, present=False, status=ResultStatus.PARTIAL),)))),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.j.candidate, req, expected)

    def test_removal_first_seen_after_the_approval_expired_is_refused(self):
        late = self.j.unassign_approval.expires_at + HOUR
        self.assertRefused(self.j.candidate, self.req(self.j.unassigned_evidence(late), at=late), "has expired")


# --- HOLD -> REVALIDATION_REQUIRED ---------------------------------------------------


class HoldPeriodTests(RefusalAssertions):
    def test_hold_must_elapse(self):
        j = Journey().to(S.HOLD)
        self.assertRefused(j.candidate, request(S.REVALIDATION_REQUIRED, Journey.T_HOLD_ENDS - timedelta(seconds=1)),
                           "hold period has not ended")
        result = apply_transition(j.candidate, request(S.REVALIDATION_REQUIRED, Journey.T_HOLD_ENDS), POLICY)
        self.assertIs(result.candidate.state, S.REVALIDATION_REQUIRED)


# The AD quarantine and deletion stages (REVALIDATION_REQUIRED -> ... -> DELETION_DRY_RUN),
# and the legacy single AD stage, are tested in tests/test_lifecycle_ad_stages.py.


# --- DELETION_DRY_RUN -> RETIRED -----------------------------------------------------


class RetiredGuardTests(RefusalAssertions):
    def setUp(self):
        self.j = Journey().to(S.DELETION_DRY_RUN)

    def req(self, evidence, at=Journey.T_RETIRED_SEEN):
        return request(S.RETIRED, at, evidence=evidence, approval_record=self.j.deletion_approval,
                       job=self.j.deletion_job)

    def test_refusals(self):
        before = Journey.T_DELETION_DRY_RUN - timedelta(minutes=30)
        cases = [
            ("still exists", self.req(self.j.after_hold)),
            ("observed before the dry run finished", self.req(self.j.retired_evidence(before), at=Journey.T_DELETION_DRY_RUN)),
            ("stale for EXECUTION", self.req(self.j.retired_evidence(), at=Journey.T_RETIRED_SEEN + 2 * DAY)),
            ("not exact", self.req(replace(self.j.retired_evidence(),
                                           mapping=mapping(Journey.T_HOLD_ENDS, confidence=MappingConfidence.NAME_ONLY)))),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.j.candidate, req, expected)

    def test_retired_is_terminal(self):
        j = Journey().to(S.RETIRED)
        for target in ALL_STATES:
            with self.subTest(target=target), self.assertRaises(TransitionRefused):
                apply_transition(j.candidate, request(target, Journey.T_RETIRED_SEEN + DAY, actor=REVIEWER), POLICY)


# --- Diversions ----------------------------------------------------------------------


class DiversionTests(RefusalAssertions):
    def test_every_diversion_needs_only_a_reason(self):
        empty = bundle(T0, okta_group=None, assignments=(), usage=(), mapping=None, ad_group=None, dependencies=())
        for source in PROGRESSING_STATES | BLOCKED_STATES:
            for target in DIVERSION_TARGETS - {source}:
                actor = REVIEWER if target in (S.EXCLUDED, S.REJECTED) else SYSTEM
                with self.subTest(source=source, target=target):
                    result = apply_transition(candidate_in(source), request(target, T0 + HOUR, actor=actor, evidence=empty), POLICY)
                    self.assertIs(result.candidate.state, target)

    def test_system_cannot_exclude_or_reject(self):
        for target in (S.EXCLUDED, S.REJECTED):
            with self.subTest(target=target):
                self.assertRefused(candidate_in(S.NEEDS_REVIEW), request(target, T0 + HOUR), "SYSTEM actors cannot")

    def test_blocked_from_records_the_progressing_state_left(self):
        c = apply_transition(candidate_in(S.APPROVED), request(S.STALE_EVIDENCE, T0 + HOUR), POLICY).candidate
        self.assertIs(c.blocked_from, S.APPROVED)
        c = apply_transition(c, request(S.DEPENDENCY_BLOCKED, T0 + 2 * HOUR), POLICY).candidate
        self.assertIs(c.blocked_from, S.APPROVED)
        c = apply_transition(c, request(S.PROTECTED, T0 + 3 * HOUR), POLICY).candidate
        self.assertIsNone(c.blocked_from)
        self.assertEqual(allowed_targets(c.state), frozenset())


# --- Re-entry ------------------------------------------------------------------------


class ReentryTests(RefusalAssertions):
    AT = T0 + 2 * HOUR

    def test_reentry_increments_epoch_and_voids_earlier_approvals(self):
        j = Journey().to(S.APPROVED)
        old_approval = j.unassign_approval
        j.step(S.STALE_EVIDENCE, Journey.T_APPROVE + HOUR)
        j.step(S.CANDIDATE, Journey.T_APPROVE + 2 * HOUR)
        self.assertEqual(j.candidate.epoch, 1)
        j.step(S.NEEDS_REVIEW, Journey.T_APPROVE + 3 * HOUR)
        req = request(S.APPROVED, Journey.T_APPROVE + 4 * HOUR, actor=REVIEWER, approval_record=old_approval)
        self.assertRefused(j.candidate, req, "current epoch")
        verify_history(j.candidate, j.decisions)

    def test_reentry_point_depends_on_where_the_block_happened(self):
        pre = candidate_in(S.STALE_EVIDENCE, blocked_from=S.APPROVED)
        self.assertRefused(pre, request(S.REVALIDATION_REQUIRED, self.AT), "only re-enter at CANDIDATE")
        post = candidate_in(S.STALE_EVIDENCE, blocked_from=S.HOLD)
        self.assertRefused(post, request(S.CANDIDATE, self.AT), "only re-enter at REVALIDATION_REQUIRED")

    def test_post_unassignment_reentry_requires_assignments_still_absent(self):
        post = candidate_in(S.STALE_EVIDENCE, blocked_from=S.HOLD)
        self.assertRefused(post, request(S.REVALIDATION_REQUIRED, self.AT, evidence=bundle(T0)), "is not absent")
        result = apply_transition(post, request(S.REVALIDATION_REQUIRED, self.AT, evidence=bundle(T0, present=False)), POLICY)
        self.assertIs(result.candidate.state, S.REVALIDATION_REQUIRED)
        self.assertEqual(result.candidate.epoch, 1)
        self.assertEqual(result.candidate.hold_until, post.hold_until)

    def test_post_unassignment_reentry_waits_for_the_hold(self):
        post = candidate_in(S.STALE_EVIDENCE, blocked_from=S.HOLD, hold_until=self.AT + DAY)
        self.assertRefused(post, request(S.REVALIDATION_REQUIRED, self.AT, evidence=bundle(T0, present=False)), "hold period")

    def test_blocking_condition_must_clear(self):
        cases = [
            (S.MAPPING_AMBIGUOUS, bundle(T0, confidence=MappingConfidence.AMBIGUOUS), "still unresolved"),
            (S.MAPPING_AMBIGUOUS, bundle(T0, confidence=MappingConfidence.NOT_FOUND), "still unresolved"),
            (S.DEPENDENCY_BLOCKED, bundle(T0, dependencies=(dependency(T0, DependencyKind.GPO_REFERENCE, 1, (blocking_finding(),)),)), "blocking dependency"),
            (S.STALE_EVIDENCE, bundle(T0 - 40 * DAY), "stale"),
        ]
        for state, evidence, expected in cases:
            with self.subTest(state=state, expected=expected):
                self.assertRefused(candidate_in(state), request(S.CANDIDATE, self.AT, evidence=evidence), expected)
        name_only = apply_transition(candidate_in(S.MAPPING_AMBIGUOUS),
                                     request(S.CANDIDATE, self.AT, evidence=bundle(T0, confidence=MappingConfidence.NAME_ONLY)), POLICY)
        self.assertIs(name_only.candidate.state, S.CANDIDATE)

    def test_generic_block_is_lifted_only_by_a_human(self):
        self.assertRefused(candidate_in(S.BLOCKED), request(S.CANDIDATE, self.AT), "SYSTEM actors cannot")
        result = apply_transition(candidate_in(S.BLOCKED), request(S.CANDIDATE, self.AT, actor=REVIEWER), POLICY)
        self.assertIs(result.candidate.state, S.CANDIDATE)


# --- Recommendations -----------------------------------------------------------------


class RecommendDiversionTests(unittest.TestCase):
    def test_priority_order(self):
        c = candidate_in(S.NEEDS_REVIEW)
        at = T0 + HOUR
        blocking = (dependency(T0, DependencyKind.AAP_REFERENCE, 1, (blocking_finding(),)),)
        cases = [
            (bundle(T0, ad_group=ad_group(T0, rid=519), dependencies=blocking), S.PROTECTED),
            (bundle(T0, confidence=MappingConfidence.AMBIGUOUS, dependencies=blocking), S.MAPPING_AMBIGUOUS),
            (bundle(T0, dependencies=blocking), S.DEPENDENCY_BLOCKED),
            (bundle(T0 - 31 * DAY), S.STALE_EVIDENCE),
        ]
        for evidence, expected in cases:
            with self.subTest(expected=expected):
                self.assertIs(recommend_diversion(c, evidence, at, POLICY)[0], expected)
        self.assertIsNone(recommend_diversion(c, bundle(T0), at, POLICY))

    def test_no_recommendation_outside_progressing_states(self):
        protected = bundle(T0, ad_group=ad_group(T0, rid=512))
        for state in BLOCKED_STATES | TERMINAL_STATES:
            with self.subTest(state=state):
                self.assertIsNone(recommend_diversion(candidate_in(state), protected, T0 + HOUR, POLICY))


# --- History -------------------------------------------------------------------------


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.j = Journey().to(S.RETIRED)

    def test_tampered_histories_are_rejected(self):
        d = self.j.decisions
        cases = {
            "skipped step": d[:2] + d[3:],
            "truncated": d[:-1],
            "wrong candidate": [replace(d[0], candidate_id=fixed_id(IdKind.CANDIDATE, 5)), *d[1:]],
            "out of order": [d[0], replace(d[1], decided_at=T0 - DAY), *d[2:]],
            "wrong epoch": [replace(d[0], epoch=1), *d[1:]],
            "system approval": [*d[:2], replace(d[2], actor=SYSTEM), *d[3:]],
            "impossible edge": [*d[:-1], replace(d[-1], from_state=S.HOLD)],
        }
        for name, history in cases.items():
            with self.subTest(name=name), self.assertRaises(InvalidRecord):
                verify_history(self.j.candidate, history)

    def test_state_written_without_history_is_detected(self):
        with self.assertRaises(InvalidRecord):
            verify_history(candidate_in(S.APPROVED), [])


if __name__ == "__main__":
    unittest.main()
