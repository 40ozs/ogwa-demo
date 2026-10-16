"""Write services behind the API: transitions, approvals, dry-run planning, mapping reviews.

Every operation follows the same order, and each step fails closed:

1. **Permission.** The principal's roles must grant the permission for this exact action.
2. **Fresh view.** Forward actions must name the evidence fingerprint the operator saw. If
   the stored evidence has changed since, the action is refused (``EVIDENCE_CHANGED``).
3. **Separation of duties (D11, D49, D143).** Per action and per principal, whatever roles
   the principal holds: the person who submitted a stage for approval cannot approve it;
   the Okta-stage approver cannot approve the AD quarantine; the AD deletion's approver is
   not the Okta-stage approver, the quarantine approver, or the deletion's proposer; and the
   approver of a stage cannot plan or record its dry run.
4. **Evidence rules.** An approval or a dry-run plan is checked by evaluating the
   lifecycle's own guard for the step it would authorize (``apply_transition`` is pure, so
   this records nothing). If the guard refuses, so does the API: an approver cannot
   approve, and an executor cannot plan, what the lifecycle would refuse.
5. **Record.** Through the store, in its audited transactions, with the request id as the
   correlation id.

Execution is dry-run planning only. ``DryRunPlanner`` holds a ``DRY_RUN_MUTATION``
mutation policy, which can only ever plan. ``PRODUCTION_MUTATION`` is refused before any
other check (D8).

The AD side has two governed stages. ``AD_QUARANTINE`` is approved in
``REVALIDATION_REQUIRED``; ``AD_DELETION`` in ``DELETION_PROPOSED``, after the post-quarantine
hold, a fresh revalidation, and a person's deletion proposal (a lifecycle step,
``DELETION_REVALIDATION_REQUIRED → DELETION_PROPOSED``, with ``LIFECYCLE_ADVANCE``). The legacy
single AD stage (``AD_RETIREMENT``) is history only: approving it, planning its job kind, or
recording its steps is refused with ``LEGACY_AD_RETIREMENT`` (D148).
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Protocol

from app.api.authz import Permission, Principal
from app.api.errors import ApiError, conflict, forbidden, not_found
from app.classification import CandidateSubject, ClassificationResult, classify
from app.classification.assessment import PendingStep, assess, next_stage
from app.classification.explanation import explain
from app.core.errors import ConfigError, MutationBlockedError
from app.core.modes import ExecutionMode
from app.core.safety import MutationCapableService, MutationDecision, MutationPolicy, MutationRequest
from app.correlation.review import MappingReviewService, ReviewRefused, SearchResult
from app.correlation.model import OktaGroupIdentity
from app.domain.actors import Actor, ActorKind
from app.domain.approval import (
    LEGACY_APPROVAL_STAGES,
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStage,
    approval_problems,
)
from app.domain.candidate_policy import CandidatePolicy
from app.domain.policy_release import DEMO_SOURCE, RECORDED_SOURCE, PolicyRef, PolicyRelease, release_for_digest
from app.domain.errors import InvalidRecord, TransitionRefused
from app.domain.execution import JOB_MODES, LEGACY_JOB_KINDS, ExecutionJob, JobKind, JobStatus
from app.domain.ids import IdKind, new_id
from app.domain.lifecycle import (
    LEGACY_PATH,
    TRANSITIONS,
    LifecycleCandidate,
    LifecycleState,
    TransitionRequest,
    apply_transition,
    stage_approval_rules,
)
from app.domain.policy import EvidenceBundle, evidence_fingerprint
from app.domain.quarantine import QuarantineOus
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreConflict
from app.store.store import Store

S = LifecycleState
P = Permission

# Forward steps an operator may request, and the permission each needs. The three
# "observed" steps (OKTA_UNASSIGN_DRY_RUN -> HOLD, QUARANTINE_DRY_RUN -> QUARANTINE_HOLD,
# DELETION_DRY_RUN -> RETIRED) are absent on purpose: they record that read-only discovery
# saw an approved change happen, which is a collector's job, not an operator's.
FORWARD_PERMISSIONS: dict[tuple[LifecycleState, LifecycleState], Permission] = {
    (S.DISCOVERED, S.CANDIDATE): P.LIFECYCLE_ADVANCE,
    (S.CANDIDATE, S.NEEDS_REVIEW): P.LIFECYCLE_ADVANCE,
    (S.NEEDS_REVIEW, S.APPROVED): P.APPROVAL_DECIDE,
    (S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN): P.EXECUTION_PLAN_DRY_RUN,
    (S.HOLD, S.REVALIDATION_REQUIRED): P.LIFECYCLE_ADVANCE,
    (S.REVALIDATION_REQUIRED, S.QUARANTINE_APPROVED): P.APPROVAL_DECIDE,
    (S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN): P.EXECUTION_PLAN_DRY_RUN,
    (S.QUARANTINE_HOLD, S.DELETION_REVALIDATION_REQUIRED): P.LIFECYCLE_ADVANCE,
    (S.DELETION_REVALIDATION_REQUIRED, S.DELETION_PROPOSED): P.LIFECYCLE_ADVANCE,  # the deletion proposal
    (S.DELETION_PROPOSED, S.DELETION_APPROVED): P.APPROVAL_DECIDE,
    (S.DELETION_APPROVED, S.DELETION_DRY_RUN): P.EXECUTION_PLAN_DRY_RUN,
}
OBSERVED_STEPS = frozenset({(S.OKTA_UNASSIGN_DRY_RUN, S.HOLD), (S.QUARANTINE_DRY_RUN, S.QUARANTINE_HOLD),
                            (S.DELETION_DRY_RUN, S.RETIRED)})
# The legacy single AD stage's steps: history only (D148). No operator may request them.
LEGACY_STEPS = frozenset(LEGACY_PATH)
# Where an executor may plan a lifecycle dry run: once a stage is approved.
PLANNABLE_STATES = frozenset({S.APPROVED, S.QUARANTINE_APPROVED, S.DELETION_APPROVED})
LIFECYCLE_WRITE_PERMISSIONS = frozenset(
    {P.LIFECYCLE_ADVANCE, P.LIFECYCLE_DIVERT, P.APPROVAL_DECIDE, P.EXECUTION_PLAN_DRY_RUN})

# Each governed approval stage: the state it is given in, the step its approval records
# (made by the approver), and its dry run's job kind. AD_RETIREMENT is not here (D148).
STAGES = {
    ApprovalStage.OKTA_UNASSIGN: (S.NEEDS_REVIEW, S.APPROVED, JobKind.OKTA_UNASSIGN),
    ApprovalStage.AD_QUARANTINE: (S.REVALIDATION_REQUIRED, S.QUARANTINE_APPROVED, JobKind.AD_QUARANTINE),
    ApprovalStage.AD_DELETION: (S.DELETION_PROPOSED, S.DELETION_APPROVED, JobKind.AD_DELETION),
}
STAGE_OF_APPROVED_STATE = {authorized: stage for stage, (_, authorized, _) in STAGES.items()}
JOB_STAGE = {kind: stage for stage, (_, _, kind) in STAGES.items()}
JOB_FROM_STATE = {kind: authorized for _, authorized, kind in STAGES.values()}
JOB_TO_STATE = {JobKind.OKTA_UNASSIGN: S.OKTA_UNASSIGN_DRY_RUN, JobKind.AD_QUARANTINE: S.QUARANTINE_DRY_RUN,
                JobKind.AD_DELETION: S.DELETION_DRY_RUN}
DRY_RUN_STATES = frozenset(JOB_TO_STATE.values())
PRECHECK_ACTOR_ID = "ogwa/api-precheck"
# The hypothetical approver of the evidence assessment's precheck. Its approval
# is built only to evaluate the lifecycle guard; it is never recorded and authorizes nothing.
ASSESSMENT_ACTOR = Actor(ActorKind.HUMAN, "ogwa/evidence-assessment-precheck")
MAX_APPROVAL_HOURS = 14 * 24


def is_operator_action(source: LifecycleState, target: LifecycleState) -> bool:
    """Whether a person may request (source, target) at all.

    Not the observed steps (discovery records them), and not a step the lifecycle closes to
    human actors: diversions to STALE_EVIDENCE or EVIDENCE_INCOMPLETE record what the
    evidence says and are never assigned by an operator (owner decision).
    Raises KeyError for a pair that is not in the lifecycle's transition table at all.
    """
    rule = TRANSITIONS[(source, target)]
    step = (source, target)
    return step not in OBSERVED_STEPS and step not in LEGACY_STEPS and ActorKind.HUMAN in rule.actors


def transition_permission(source: LifecycleState, target: LifecycleState) -> Permission | None:
    """The permission an operator needs for (source, target), or None if no operator may request it.

    Raises KeyError for a pair that is not in the lifecycle's transition table at all.
    """
    rule = TRANSITIONS[(source, target)]
    if ActorKind.HUMAN not in rule.actors or (source, target) in LEGACY_STEPS:
        return None
    if rule.category == "diversion":
        return P.LIFECYCLE_DIVERT
    if rule.category == "re-entry":
        return P.LIFECYCLE_ADVANCE
    return FORWARD_PERMISSIONS.get((source, target))


# --- policy in force -------------------------------------------------------------------


# Owner decision: every API/UI surface labels the unrecorded demo policy so.
DEMO_POLICY_LABEL = "DEMO POLICY — UNRECORDED"


@dataclass(frozen=True)
class PolicyInForce:
    policy: CandidatePolicy
    source: str  # RECORDED_SOURCE or DEMO_SOURCE
    version_id: str | None
    version_sequence: int | None = None
    # The named release whose rules these are, matched by digest; None when no
    # release carries them, which every surface reports as such.
    release: PolicyRelease | None = None

    @property
    def recorded(self) -> bool:
        return self.source == RECORDED_SOURCE

    @property
    def label(self) -> str:
        return f"RECORDED POLICY VERSION {self.version_sequence + 1}" if self.recorded else DEMO_POLICY_LABEL

    @property
    def ref(self) -> PolicyRef:
        """What a decision judged by this policy records about it."""
        return PolicyRef.of(policy_digest=self.policy.digest, source=self.source, version_id=self.version_id,
                            sequence=self.version_sequence, release=self.release)

    @property
    def approval_max_valid_hours(self) -> int:
        """The longest an approval may be valid under this policy, in whole hours (rounded down).
        The UI takes its limit from here; the server enforces the policy's own value."""
        return int(self.policy.lifecycle.approval_max_ttl.total_seconds() // 3600)

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "recorded": self.recorded, "source": self.source, "versionId": self.version_id,
                "versionSequence": self.version_sequence, "policyDigest": self.policy.digest,
                "policyId": self.release.policy_id if self.release else None,
                "version": self.release.version if self.release else None,
                "name": self.release.name if self.release else None,
                "release": self.release.summary() if self.release else None,
                "approvalMaxValidHours": self.approval_max_valid_hours}


def policy_in_force(store: Store) -> PolicyInForce:
    """The recorded policy version; in a SYNTHETIC store only, the demo world's own policy,
    labelled ``DEMO POLICY — UNRECORDED`` wherever it appears.

    Outside a SYNTHETIC store, no recorded version means no classification and no lifecycle
    write: OGWA never judges real data by unrecorded defaults (D32, D52).

    The release identity (policy id and version) comes only from a SYNTHETIC store's demo dataset,
    by exact digest. No production release is held in git (D32), so a production version has none.
    """
    version = store.active_policy_version()
    if version is not None:
        return PolicyInForce(version.policy, RECORDED_SOURCE, version.id, version.sequence,
                             release_for_digest(demo_releases(store), version.policy_digest))
    if store.marker.environment is DatabaseEnvironment.SYNTHETIC:
        from app.demo.datasets import dataset_of

        policy = CandidatePolicy(lifecycle=dataset_of(store).policy)
        return PolicyInForce(policy, DEMO_SOURCE, None, release=release_for_digest(demo_releases(store), policy.digest))
    raise conflict("POLICY_NOT_RECORDED", "No candidate policy version is recorded; classification and lifecycle "
                                          "changes are unavailable until one is approved (D52).")


def demo_releases(store: Store) -> tuple[PolicyRelease, ...]:
    """The synthetic policy releases of a SYNTHETIC store's demo dataset; none for any other store."""
    if store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
        return ()
    from app.demo.datasets import dataset_of

    return dataset_of(store).releases()


# --- dry-run planner -------------------------------------------------------------------


class DryRunPlanner(MutationCapableService):
    """Plans the changes a job would make. Its mutation policy is DRY_RUN_MUTATION, which
    can only answer PLAN_ONLY, so no operation is ever run; ``_never`` proves it."""

    def __init__(self) -> None:
        super().__init__(mutation_policy=MutationPolicy.for_mode(ExecutionMode.DRY_RUN_MUTATION))

    ACTIONS = {JobKind.OKTA_UNASSIGN: ("okta", "unassign_group_from_application"),
               JobKind.AD_QUARANTINE: ("ad", "move_group_to_quarantine"),
               JobKind.AD_DELETION: ("ad", "delete_group")}

    def plan(self, kind: JobKind, targets: tuple[str, ...]) -> list[str]:
        if kind not in self.ACTIONS:
            raise MutationBlockedError(f"{kind.value} is not a plannable job kind")
        system, action = self.ACTIONS[kind]
        planned = []
        for target in targets:
            outcome = self._perform(MutationRequest(system=system, action=action, target=target), self._never)
            if outcome.decision is not MutationDecision.PLAN_ONLY or outcome.executed:
                raise MutationBlockedError("dry-run planning produced something other than a plan")
            planned.append(f"{system}:{action}:{target}")
        return planned

    @staticmethod
    def _never() -> None:
        raise MutationBlockedError("a dry-run planner never executes")


# --- lifecycle service -----------------------------------------------------------------


class LifecycleService:
    def __init__(self, store: Store, *, clock: Callable[[], datetime], mode: ExecutionMode,
                 quarantine_ous: QuarantineOus | None = None) -> None:
        if quarantine_ous is not None and quarantine_ous.environment != store.marker.environment.value:
            raise ConfigError("the quarantine OU configuration is for a different store environment")
        self._store = store
        self._clock = clock
        self._mode = mode
        self._planner = DryRunPlanner()
        # The deployment's quarantine OUs (D136). Without them no AD-stage step can pass.
        self.quarantine_ous = quarantine_ous

    def request(self, **fields: Any) -> TransitionRequest:
        """A transition request carrying the deployment's quarantine OUs, never a caller's."""
        return TransitionRequest(**fields, quarantine_ous=self.quarantine_ous)

    # shared helpers ---------------------------------------------------------------------

    def load(self, candidate_id: str) -> LifecycleCandidate:
        if self._store.connection.execute("SELECT 1 FROM candidates WHERE id = ?", (candidate_id,)).fetchone() is None:
            raise not_found("candidate")
        return self._store.load_candidate(candidate_id)

    def _view(self, candidate: LifecycleCandidate) -> tuple[EvidenceBundle, str]:
        bundle = self._store.evidence_bundle(candidate)
        return bundle, evidence_fingerprint(bundle)

    @staticmethod
    def _require_fresh_view(expected: str | None, current: str) -> None:
        if expected is None:
            raise ApiError(422, "VALIDATION_FAILED", "expectedEvidenceFingerprint is required for this action.")
        if expected != current:
            raise conflict("EVIDENCE_CHANGED", "The evidence changed since you reviewed it. Reload and review again.")

    def _submitter(self, candidate: LifecycleCandidate, stage: ApprovalStage) -> Actor | None:
        """The person who moved the candidate into the state where ``stage`` is approved, this epoch."""
        entry_state = STAGES[stage][0]
        for decision in reversed(self._store.decisions(candidate.id)):
            if decision.epoch != candidate.epoch:
                break
            if decision.to_state is entry_state:
                return decision.actor
        return None

    def _approval(self, candidate: LifecycleCandidate, approval_id: str | None) -> ApprovalRecord | None:
        if approval_id is None:
            return None
        approval = self._store.load_approval(approval_id)
        if approval is None or approval.candidate_id != candidate.id:
            raise not_found("approval for this candidate")
        return approval

    def _job(self, candidate: LifecycleCandidate, job_id: str | None) -> ExecutionJob | None:
        if job_id is None:
            return None
        job = self._store.load_execution_job(job_id)
        if job is None or job.candidate_id != candidate.id:
            raise not_found("execution job for this candidate")
        return job

    def _hypothetical_job(self, candidate: LifecycleCandidate, bundle: EvidenceBundle, kind: JobKind,
                          approval: ApprovalRecord, fingerprint: str, now: datetime) -> ExecutionJob:
        """A successful dry run that is never recorded: used only to evaluate the guard."""
        targets = candidate.assignment_ids if kind is JobKind.OKTA_UNASSIGN else (
            (bundle.ad_group.id,) if bundle.ad_group is not None else ())
        if not targets:
            raise conflict("EVIDENCE_RULES_NOT_MET", "The lifecycle would refuse this step.",
                           ["no observation of the mapped AD group"])
        return ExecutionJob(
            id=new_id(IdKind.EXECUTION_JOB), candidate_id=candidate.id, kind=kind,
            mode=ExecutionMode.DRY_RUN_MUTATION, dry_run=True, status=JobStatus.SUCCEEDED,
            requested_by=Actor(ActorKind.SYSTEM, PRECHECK_ACTOR_ID), requested_at=now,
            approval_id=approval.id, evidence_fingerprint=fingerprint, targets=targets, finished_at=now,
        )

    @staticmethod
    def _guard(candidate: LifecycleCandidate, request: TransitionRequest, policy: PolicyInForce) -> None:
        """Evaluate the lifecycle guard for ``request`` without recording anything."""
        try:
            apply_transition(candidate, request, policy.policy.lifecycle)
        except TransitionRefused as refused:
            raise conflict("EVIDENCE_RULES_NOT_MET", "The lifecycle would refuse this step, so it cannot be "
                                                     "authorized.", refused.problems) from None

    def _transition(self, candidate_id: str, request: TransitionRequest, policy: PolicyInForce, correlation_id: str):
        try:
            return self._store.transition(candidate_id, request, policy.policy.lifecycle, correlation_id=correlation_id,
                                          policy_ref=policy.ref)
        except TransitionRefused as refused:
            raise conflict("TRANSITION_REFUSED", "The lifecycle refused the transition. The refusal was audited.",
                           refused.problems) from None
        except StoreConflict as exc:
            raise conflict("CONFLICT", str(exc)) from None

    # transitions -------------------------------------------------------------------------

    def transition(self, principal: Principal, candidate_id: str, *, target: LifecycleState, reason: str,
                   expected_fingerprint: str | None, approval_id: str | None, job_id: str | None,
                   request_id: str) -> dict[str, Any]:
        if not principal.permissions & LIFECYCLE_WRITE_PERMISSIONS:
            raise forbidden()
        candidate = self.load(candidate_id)
        source = candidate.state
        if (source, target) not in TRANSITIONS:
            raise conflict("TRANSITION_NOT_PERMITTED", f"{source.value} -> {target.value} is not a lifecycle transition.")
        if (source, target) in LEGACY_STEPS:
            raise legacy_ad_retirement()
        if (source, target) in OBSERVED_STEPS:
            raise forbidden(f"{source.value} -> {target.value} is recorded by read-only discovery when it observes the "
                            "approved change. It is not an operator action.", code="NOT_AN_OPERATOR_ACTION")
        if not is_operator_action(source, target):
            raise forbidden(f"{target.value} records what the evidence says; discovery and classification assign it, "
                            "never an operator. To stop this candidate, hold it (BLOCKED).",
                            code="NOT_AN_OPERATOR_ACTION")
        needed = transition_permission(source, target)
        if needed is None or not principal.can(needed):
            raise forbidden(f"{source.value} -> {target.value} needs the {needed.value if needed else '-'} permission.")
        policy = policy_in_force(self._store)
        bundle, fingerprint = self._view(candidate)
        category = TRANSITIONS[(source, target)].category
        if category != "diversion":  # a safer state needs only a reason (L-5)
            self._require_fresh_view(expected_fingerprint, fingerprint)
        approval = self._approval(candidate, approval_id)
        job = self._job(candidate, job_id)
        actor = principal.actor
        if target in STAGE_OF_APPROVED_STATE and approval is not None:
            self._check_approver(candidate, STAGE_OF_APPROVED_STATE[target], actor)
        if target in DRY_RUN_STATES and approval is not None and approval.operator == actor:
            raise forbidden("The approver of a stage cannot also record its dry run (D49).", code="SEPARATION_OF_DUTIES")
        request = self.request(target=target, actor=actor, reason=reason, now=self._clock(), evidence=bundle,
                               approval=approval, job=job)
        result = self._transition(candidate_id, request, policy, request_id)
        return {"candidate": result.candidate, "decision": result.decision, "policy": policy}

    # approvals ---------------------------------------------------------------------------

    def approver_conflicts(self, candidate: LifecycleCandidate, stage: ApprovalStage, approver: Actor) -> list[str]:
        """Why ``approver`` may not decide ``stage`` for this candidate (four-eyes, D11, D49, D143)."""
        problems = []
        if approver == candidate.proposed_by:
            problems.append("you proposed this candidate")
        # For AD_DELETION the submitter is the deletion's proposer, named below (D143).
        if stage is not ApprovalStage.AD_DELETION and self._submitter(candidate, stage) == approver:
            problems.append(f"you submitted this candidate for {stage.value} approval")
        for excluded, message in stage_approval_rules(candidate, stage).excluded_problems(stage, you=True):
            if excluded is not None and excluded == approver:
                problems.append(message)
        return problems

    def _check_approver(self, candidate: LifecycleCandidate, stage: ApprovalStage, approver: Actor) -> None:
        problems = self.approver_conflicts(candidate, stage, approver)
        if problems:
            raise ApiError(403, "SEPARATION_OF_DUTIES", "Four-eyes rule: someone else must approve this (D49).",
                           problems=problems)

    def decide_approval(self, principal: Principal, candidate_id: str, *, stage: ApprovalStage,
                        decision: ApprovalDecision, reason: str, expected_fingerprint: str, valid_hours: int | None,
                        request_id: str) -> dict[str, Any]:
        if not principal.can(P.APPROVAL_DECIDE):
            raise forbidden()
        if stage in LEGACY_APPROVAL_STAGES:
            raise legacy_ad_retirement()
        candidate = self.load(candidate_id)
        entry_state, authorized_state, _ = STAGES[stage]
        if candidate.state is not entry_state:
            raise conflict("INVALID_STATE", f"{stage.value} approvals are given in {entry_state.value}; the candidate "
                                            f"is {candidate.state.value}.")
        policy = policy_in_force(self._store)
        bundle, fingerprint = self._view(candidate)
        self._require_fresh_view(expected_fingerprint, fingerprint)
        actor = principal.actor
        self._check_approver(candidate, stage, actor)
        now = self._clock()
        max_ttl = policy.policy.lifecycle.approval_max_ttl
        ttl = max_ttl if valid_hours is None else timedelta(hours=valid_hours)
        if ttl > max_ttl:
            raise ApiError(422, "VALIDATION_FAILED", f"validForHours may not exceed the policy maximum {max_ttl}.")
        try:
            approval = ApprovalRecord(
                id=new_id(IdKind.APPROVAL), candidate_id=candidate.id, stage=stage, decision=decision, operator=actor,
                decided_at=now, reason=reason, evidence_fingerprint=fingerprint, candidate_epoch=candidate.epoch,
                expires_at=now + ttl,
            )
        except InvalidRecord as exc:
            raise ApiError(422, "VALIDATION_FAILED", str(exc)) from None
        if decision is ApprovalDecision.APPROVE:
            # Approvers cannot bypass evidence rules: evaluate the step this approval records.
            self._guard(candidate, self.request(target=authorized_state, actor=actor, reason=reason, now=now,
                                                evidence=bundle, approval=approval), policy)
        try:
            self._store.record_approval(approval, correlation_id=request_id, policy_ref=policy.ref)
        except StoreConflict as exc:
            raise conflict("CONFLICT", str(exc)) from None
        result: dict[str, Any] = {"approval": approval, "candidate": candidate, "decision": None, "policy": policy}
        if decision is ApprovalDecision.APPROVE:
            # The approver records the stage's approved state (APPROVED, QUARANTINE_APPROVED, or
            # DELETION_APPROVED); the guard runs again inside the store's transaction.
            request = self.request(target=authorized_state, actor=actor, reason=reason, now=self._clock(),
                                   evidence=bundle, approval=approval)
            applied = self._transition(candidate_id, request, policy, request_id)
            result.update(candidate=applied.candidate, decision=applied.decision)
        return result

    # execution ---------------------------------------------------------------------------

    def plan_dry_run(self, principal: Principal, candidate_id: str, *, kind: JobKind, approval_id: str,
                     expected_fingerprint: str, dry_run: bool, requested_mode: str | None,
                     request_id: str) -> dict[str, Any]:
        if requested_mode == ExecutionMode.PRODUCTION_MUTATION.value or not dry_run:
            raise production_mutation_refused()
        if not principal.can(P.EXECUTION_PLAN_DRY_RUN):
            raise forbidden()
        if requested_mode not in (None, ExecutionMode.DRY_RUN_MUTATION.value):
            raise ApiError(422, "VALIDATION_FAILED", "executionMode may only be DRY_RUN_MUTATION.")
        if self._mode not in JOB_MODES:
            raise forbidden(f"Execution jobs cannot be planned in {self._mode.value} mode.",
                            code="EXECUTION_MODE_NOT_AUTHORIZED")
        if kind in LEGACY_JOB_KINDS:
            raise legacy_ad_retirement()
        candidate = self.load(candidate_id)
        if candidate.state is not JOB_FROM_STATE[kind]:
            raise conflict("INVALID_STATE", f"A {kind.value} dry run is planned from {JOB_FROM_STATE[kind].value}; the "
                                            f"candidate is {candidate.state.value}.")
        policy = policy_in_force(self._store)
        bundle, fingerprint = self._view(candidate)
        self._require_fresh_view(expected_fingerprint, fingerprint)
        approval = self._approval(candidate, approval_id)
        actor = principal.actor
        if approval.operator == actor:
            raise forbidden("You approved this stage; a different person must plan its dry run (D49).",
                            code="SEPARATION_OF_DUTIES")
        now = self._clock()
        lifecycle = policy.policy.lifecycle
        stage = JOB_STAGE[kind]
        rules = stage_approval_rules(candidate, stage)
        problems = [*rules.unmet, *approval_problems(
            approval, candidate_id=candidate.id, candidate_epoch=candidate.epoch, proposed_by=candidate.proposed_by,
            stage=stage, now=now, max_ttl=lifecycle.approval_max_ttl, clock_skew=lifecycle.freshness.clock_skew,
            evidence_fingerprint=fingerprint, not_before=rules.not_before, given_after=rules.given_after,
            excluded_approvers=rules.excluded_problems(stage),
        )]
        if problems:
            raise conflict("APPROVAL_INVALID", "The approval does not authorize this dry run.", problems)
        hypothetical = self._hypothetical_job(candidate, bundle, kind, approval, fingerprint, now)
        self._guard(candidate, self.request(target=JOB_TO_STATE[kind], actor=actor, reason="dry-run precheck",
                                            now=now, evidence=bundle, approval=approval, job=hypothetical), policy)
        planned_actions = self._planner.plan(kind, hypothetical.targets)
        planned = replace(hypothetical, id=new_id(IdKind.EXECUTION_JOB), requested_by=actor, status=JobStatus.PLANNED,
                          finished_at=None)
        detail = f"dry run: {len(planned_actions)} change(s) planned, none executed"
        try:
            self._store.record_execution_job(planned, correlation_id=request_id)
            finished = replace(planned, status=JobStatus.SUCCEEDED, finished_at=self._clock())
            self._store.record_execution_job(finished, detail=detail, correlation_id=request_id)
        except StoreConflict as exc:
            raise conflict("CONFLICT", str(exc)) from None
        return {"job": self._store.load_execution_job(planned.id), "plannedActions": planned_actions, "policy": policy}

    def execute(self, principal: Principal, job_id: str) -> None:
        """The route shape for future remediation. This build refuses it for every principal,
        whatever roles or permissions they hold: there is no executor, and the build forbids
        production mutation (D8). Enabling it is a reviewed source change, never configuration."""
        raise production_mutation_refused()

    # classification ----------------------------------------------------------------------

    def _classification(self, candidate: LifecycleCandidate, bundle: EvidenceBundle,
                        now: datetime) -> tuple[ClassificationResult | None, PolicyInForce | None]:
        try:
            policy = policy_in_force(self._store)
        except ApiError:
            return None, None
        app_ids = tuple(dict.fromkeys(a.application_id for a in bundle.assignments))
        if not app_ids:
            return None, policy
        return classify(bundle, CandidateSubject(candidate.okta_group_id, app_ids), policy.policy, now), policy

    def classify(self, candidate: LifecycleCandidate, bundle: EvidenceBundle) -> dict[str, Any] | None:
        return self.classify_and_assess(candidate, bundle)[0]

    def classify_and_assess(self, candidate: LifecycleCandidate,
                            bundle: EvidenceBundle) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        """The classification (None if unavailable) and the evidence assessment, judged at one instant."""
        classification, assessment, _ = self.classify_assess_explain(candidate, bundle)
        return classification, assessment

    def classify_assess_explain(self, candidate: LifecycleCandidate, bundle: EvidenceBundle
                                ) -> tuple[dict[str, Any] | None, dict[str, Any], dict[str, Any]]:
        """The classification, the evidence assessment, and the explanation of its decision, all judged
        at one instant by one policy, which each of them names."""
        now = self._clock()
        result, policy = self._classification(candidate, bundle, now)
        classification = None if result is None else {**result.to_dict(), "policy": policy.to_dict()}
        pending = self.pending_step(candidate, bundle, policy, now)
        assessment = assess(candidate, bundle, result, policy.policy if policy else None, pending)
        ref = policy.ref if policy else None
        explanation = explain(assessment, result, policy.policy if policy else None, ref)
        return (classification, {**assessment.to_dict(), "policy": ref.to_dict() if ref else None},
                explanation.to_dict())

    def pending_step(self, candidate: LifecycleCandidate, bundle: EvidenceBundle, policy: PolicyInForce | None,
                     now: datetime) -> PendingStep:
        """The next approval step and, when it is open, whether the lifecycle guard would accept a
        named human's approval of it on this evidence. The guard is evaluated exactly as an
        approval request's precheck is (``decide_approval``), with an approval that is never
        recorded and that no one gave; nothing is written."""
        open_stage = next((s for s, (entry, _, _) in STAGES.items() if candidate.state is entry), None)
        if open_stage is None:
            return PendingStep(next_stage(candidate), open=False, evaluated=False, accepts=False)
        if policy is None:
            return PendingStep(open_stage, open=True, evaluated=False, accepts=False,
                               problems=("no candidate policy is in force, so nothing is judged (D52)",))
        _, authorized_state, _ = STAGES[open_stage]
        try:
            approval = ApprovalRecord(
                id=new_id(IdKind.APPROVAL), candidate_id=candidate.id, stage=open_stage,
                decision=ApprovalDecision.APPROVE, operator=ASSESSMENT_ACTOR, decided_at=now,
                reason="evidence assessment precheck: never recorded", evidence_fingerprint=evidence_fingerprint(bundle),
                candidate_epoch=candidate.epoch, expires_at=now + policy.policy.lifecycle.approval_max_ttl,
            )
            apply_transition(candidate, self.request(target=authorized_state, actor=ASSESSMENT_ACTOR,
                                                     reason="evidence assessment precheck", now=now, evidence=bundle,
                                                     approval=approval), policy.policy.lifecycle)
        except TransitionRefused as refused:
            return PendingStep(open_stage, open=True, evaluated=True, accepts=False, problems=tuple(refused.problems))
        except InvalidRecord as exc:
            return PendingStep(open_stage, open=True, evaluated=False, accepts=False, problems=(str(exc),))
        return PendingStep(open_stage, open=True, evaluated=True, accepts=True)


def production_mutation_refused() -> ApiError:
    return forbidden("This build plans dry runs only. PRODUCTION_MUTATION is not permitted and cannot be requested "
                     "(D8).", code="PRODUCTION_MUTATION_REFUSED")


def legacy_ad_retirement() -> ApiError:
    return conflict("LEGACY_AD_RETIREMENT",
                    "AD_RETIREMENT is the legacy single AD stage, which approved quarantine and deletion together. "
                    "Its records are history only: nothing new may be approved, planned, or recorded under it "
                    "(D148). Approve AD_QUARANTINE in REVALIDATION_REQUIRED; AD_DELETION is approved separately, "
                    "after the post-quarantine hold, a fresh revalidation, and a deletion proposal (D128-D147).")


# --- mapping reviews -------------------------------------------------------------------


class MappingReviewGateway(Protocol):
    """How the API reaches mapping review: the Okta identity of a stored group, and the
    review service (which needs an AD identity directory). The only implementation is the
    synthetic one (``app.demo.synthetic_directory``), wired in LOCAL_SYNTHETIC only. An API
    built without a gateway answers every mapping review action with
    ``MAPPING_REVIEW_UNAVAILABLE``. There is no production AD adapter."""

    service: MappingReviewService

    def okta_identity(self, okta_group_ref: str) -> OktaGroupIdentity | None:
        ...


MAX_SEARCHES_PER_SESSION = 20


class MappingReviews:
    def __init__(self, gateway: MappingReviewGateway | None) -> None:
        self._gateway = gateway
        self._searches: dict[str, tuple[str, SearchResult]] = {}  # search id -> (subject, result)

    @property
    def available(self) -> bool:
        return self._gateway is not None

    def _identity(self, okta_group_ref: str) -> tuple[MappingReviewService, OktaGroupIdentity]:
        if self._gateway is None:
            raise ApiError(503, "MAPPING_REVIEW_UNAVAILABLE", "Mapping review needs an AD identity directory, which "
                                                               "is not available in this build.")
        identity = self._gateway.okta_identity(okta_group_ref)
        if identity is None:
            raise not_found("Okta group")
        return self._gateway.service, identity

    @staticmethod
    def _refused(exc: ReviewRefused) -> ApiError:
        return conflict("REVIEW_REFUSED", "The mapping review was refused; nothing was recorded.", [str(exc)])

    def inspect(self, principal: Principal, okta_group_ref: str) -> Any:
        if not principal.permissions & {P.MAPPING_PROPOSE, P.MAPPING_APPROVE, P.MAPPING_REJECT}:
            raise forbidden()
        service, identity = self._identity(okta_group_ref)
        return service.inspect(identity)

    def search(self, principal: Principal, okta_group_ref: str, *, by: str, value: str, domain: str | None) -> tuple[str, SearchResult]:
        if not principal.can(P.MAPPING_PROPOSE):
            raise forbidden()
        service, identity = self._identity(okta_group_ref)
        try:
            result = service.search(identity, operator=principal.actor, by=by, value=value, domain=domain)
        except ReviewRefused as exc:
            raise self._refused(exc) from None
        mine = [k for k, (subject, _) in self._searches.items() if subject == principal.subject]
        for key in mine[: max(0, len(mine) - MAX_SEARCHES_PER_SESSION + 1)]:
            del self._searches[key]
        search_id = new_id(IdKind.REQUEST)
        self._searches[search_id] = (principal.subject, result)
        return search_id, result

    def select(self, principal: Principal, okta_group_ref: str, *, search_id: str, object_guid: str, reason: str):
        if not principal.can(P.MAPPING_PROPOSE):
            raise forbidden()
        service, identity = self._identity(okta_group_ref)
        owner, search = self._searches.get(search_id, (None, None))
        if owner != principal.subject:
            raise not_found("search result (search again)")
        try:
            return service.select(identity, operator=principal.actor, search=search, object_guid=object_guid,
                                  reason=reason)
        except ReviewRefused as exc:
            raise self._refused(exc) from None

    def approve(self, principal: Principal, okta_group_ref: str, *, object_guid: str, expected_fingerprint: str,
                reason: str):
        if not principal.can(P.MAPPING_APPROVE):
            raise forbidden()
        service, identity = self._identity(okta_group_ref)
        try:
            return service.approve(identity, operator=principal.actor, object_guid=object_guid,
                                   expected_fingerprint=expected_fingerprint, reason=reason)
        except ReviewRefused as exc:
            raise self._refused(exc) from None

    def reject(self, principal: Principal, okta_group_ref: str, *, object_guid: str, expected_fingerprint: str,
               reason: str):
        if not principal.can(P.MAPPING_REJECT):
            raise forbidden()
        service, identity = self._identity(okta_group_ref)
        try:
            return service.reject(identity, operator=principal.actor, object_guid=object_guid,
                                  expected_fingerprint=expected_fingerprint, reason=reason)
        except ReviewRefused as exc:
            raise self._refused(exc) from None
