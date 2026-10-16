"""The lifecycle state machine.

State changes only through ``apply_transition``, which looks the requested move up in the
closed ``TRANSITIONS`` table, checks who is asking, evaluates the move's guard against
the supplied evidence, approval, and job, and returns a new candidate plus a
``LifecycleDecision`` record. Anything not in the table is refused.

Moving forward requires proof. Moving to a safer state (blocked, protected, excluded,
rejected) requires only a reason, so a missing or broken collector can never prevent a
candidate from being stopped.

This build cannot change Okta or AD. HOLD, QUARANTINE_HOLD, and RETIRED are reached by
observing, through read-only discovery, that an approved change has happened, never by OGWA
making it.

The AD side has two governed stages (owner decisions D128–D155). The AD quarantine is
approved in REVALIDATION_REQUIRED, after the Okta hold. Once the quarantine is observed, a
30-day hold runs (D138). After it, the candidate is revalidated in
DELETION_REVALIDATION_REQUIRED, a person proposes the deletion on fresh post-hold evidence,
and a different person approves it (D139, D143). A candidate never returns from the
post-quarantine states to the pre-quarantine ones (D144). The original single AD stage
(REVALIDATION_REQUIRED -> RETIREMENT_DRY_RUN -> RETIRED, approved as AD_RETIREMENT) remains
only so that recorded history still verifies; its steps are refused (D148).
See docs/architecture/lifecycle-state-machine.md.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum

from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalRecord, ApprovalStage, approval_problems
from app.domain.audit import AuditAction, AuditResult, AuditTrail
from app.domain.errors import InvalidRecord, TransitionRefused
from app.domain.evidence import Evidence, EvidencePurpose, check_digest, freshness_problems
from app.domain.execution import ExecutionJob, JobKind, JobStatus
from app.domain.ids import IdKind, check_enum, check_id, check_ids, check_text, check_utc, new_id
from app.domain.model import (
    UNRESOLVED_CONFIDENCES,
    DependencyCoverage,
    DependencyEvidence,
)
from app.domain.policy import (
    EvidenceBundle,
    GroupOrigin,
    LifecyclePolicy,
    evidence_fingerprint,
    group_origin,
    protection_reasons,
)
from app.domain.quarantine import QuarantineOus, quarantine_location_problems


class LifecycleState(StrEnum):
    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    APPROVED = "APPROVED"
    OKTA_UNASSIGN_DRY_RUN = "OKTA_UNASSIGN_DRY_RUN"
    HOLD = "HOLD"
    REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"
    RETIREMENT_DRY_RUN = "RETIREMENT_DRY_RUN"
    RETIRED = "RETIRED"
    EXCLUDED = "EXCLUDED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    MAPPING_AMBIGUOUS = "MAPPING_AMBIGUOUS"
    DEPENDENCY_BLOCKED = "DEPENDENCY_BLOCKED"
    PROTECTED = "PROTECTED"
    # Once-complete evidence has outlived its freshness window (owner decision).
    STALE_EVIDENCE = "STALE_EVIDENCE"
    # Required evidence was never fully or properly obtained: a partial or failed result,
    # or a record dated in the future (owner decision; migration 0009).
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    # The AD stages (migration 0011): approved for quarantine, its dry run recorded,
    # the quarantine observed and its hold running, revalidation after that hold, deletion
    # proposed, deletion approved by someone else, the deletion dry run recorded.
    QUARANTINE_APPROVED = "QUARANTINE_APPROVED"
    QUARANTINE_DRY_RUN = "QUARANTINE_DRY_RUN"
    QUARANTINE_HOLD = "QUARANTINE_HOLD"
    DELETION_REVALIDATION_REQUIRED = "DELETION_REVALIDATION_REQUIRED"
    DELETION_PROPOSED = "DELETION_PROPOSED"
    DELETION_APPROVED = "DELETION_APPROVED"
    DELETION_DRY_RUN = "DELETION_DRY_RUN"


S = LifecycleState

# The hold after the quarantine is observed (owner decision D138). Not a candidate policy
# value: changing it is a reviewed source change.
QUARANTINE_HOLD_PERIOD = timedelta(days=30)

# Before the Okta assignment is removed / after it has been removed.
PRE_UNASSIGN_STATES = frozenset({S.DISCOVERED, S.CANDIDATE, S.NEEDS_REVIEW, S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN})
# After the unassignment, before the AD group is observed in quarantine. RETIREMENT_DRY_RUN
# is the legacy AD stage's dry run (history only, D148).
PRE_QUARANTINE_STATES = frozenset({S.HOLD, S.REVALIDATION_REQUIRED, S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN,
                                   S.RETIREMENT_DRY_RUN})
# After the quarantine was observed. Nothing leads from here back to the states above (D144).
POST_QUARANTINE_STATES = frozenset({S.QUARANTINE_HOLD, S.DELETION_REVALIDATION_REQUIRED, S.DELETION_PROPOSED,
                                    S.DELETION_APPROVED, S.DELETION_DRY_RUN})
POST_UNASSIGN_STATES = PRE_QUARANTINE_STATES | POST_QUARANTINE_STATES
PROGRESSING_STATES = PRE_UNASSIGN_STATES | POST_UNASSIGN_STATES
# States that exist only so that recorded history verifies (D148). Nothing new enters them.
LEGACY_STATES = frozenset({S.RETIREMENT_DRY_RUN})
# Non-progressing but resumable once the condition clears.
BLOCKED_STATES = frozenset({S.BLOCKED, S.MAPPING_AMBIGUOUS, S.DEPENDENCY_BLOCKED, S.STALE_EVIDENCE,
                            S.EVIDENCE_INCOMPLETE})
# What the evidence itself says, as judged by discovery and classification. An operator
# never assigns these (owner decision): a person who wants to stop a candidate
# holds it (BLOCKED).
EVIDENCE_CONDITION_STATES = frozenset({S.STALE_EVIDENCE, S.EVIDENCE_INCOMPLETE})
# No outgoing transitions. New evidence means a new candidate.
TERMINAL_STATES = frozenset({S.RETIRED, S.EXCLUDED, S.REJECTED, S.PROTECTED})
DIVERSION_TARGETS = BLOCKED_STATES | {S.EXCLUDED, S.REJECTED, S.PROTECTED}
# Where a blocked candidate re-enters: before the unassignment, after it but before the
# quarantine, and after the quarantine (D144, D145).
REENTRY_TARGETS = frozenset({S.CANDIDATE, S.REVALIDATION_REQUIRED, S.DELETION_REVALIDATION_REQUIRED})
# States in which the Okta unassignment has been approved; the approver is recorded.
UNASSIGN_APPROVED_STATES = frozenset({S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN, S.RETIRED}) | POST_UNASSIGN_STATES
# States in which the AD quarantine has been approved; the approver is recorded.
QUARANTINE_APPROVED_STATES = frozenset({S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN}) | POST_QUARANTINE_STATES
# States in which a deletion has been proposed; the proposer and the time are recorded.
DELETION_PROPOSED_STATES = frozenset({S.DELETION_PROPOSED, S.DELETION_APPROVED, S.DELETION_DRY_RUN})

FORWARD_PATH = (
    S.DISCOVERED,
    S.CANDIDATE,
    S.NEEDS_REVIEW,
    S.APPROVED,
    S.OKTA_UNASSIGN_DRY_RUN,
    S.HOLD,
    S.REVALIDATION_REQUIRED,
    S.QUARANTINE_APPROVED,
    S.QUARANTINE_DRY_RUN,
    S.QUARANTINE_HOLD,
    S.DELETION_REVALIDATION_REQUIRED,
    S.DELETION_PROPOSED,
    S.DELETION_APPROVED,
    S.DELETION_DRY_RUN,
    S.RETIRED,
)
# The legacy single AD stage. Kept so recorded history verifies; refused (D148).
LEGACY_PATH = ((S.REVALIDATION_REQUIRED, S.RETIREMENT_DRY_RUN), (S.RETIREMENT_DRY_RUN, S.RETIRED))
# The approval steps, each made by the operator who gave an approval of this stage.
APPROVAL_STEPS = {S.APPROVED: ApprovalStage.OKTA_UNASSIGN, S.QUARANTINE_APPROVED: ApprovalStage.AD_QUARANTINE,
                  S.DELETION_APPROVED: ApprovalStage.AD_DELETION}


_BEFORE_QUARANTINE_APPROVAL = PRE_UNASSIGN_STATES | (PRE_QUARANTINE_STATES - QUARANTINE_APPROVED_STATES)
_BEFORE_DELETION_PROPOSAL = PRE_UNASSIGN_STATES | PRE_QUARANTINE_STATES | (POST_QUARANTINE_STATES
                                                                          - DELETION_PROPOSED_STATES)


# --- Records -------------------------------------------------------------------------


@dataclass(frozen=True)
class LifecycleCandidate:
    """An Okta group whose assignment to one or more applications appears unused, and the
    AD group it maps to. Evidence for review, never authorization to change anything.
    """

    id: str
    okta_group_id: str
    assignment_ids: tuple[str, ...]
    state: LifecycleState
    proposed_by: Actor
    created_at: datetime
    updated_at: datetime
    epoch: int = 0  # incremented on every re-entry from a blocked state; voids older approvals
    hold_until: datetime | None = None
    blocked_from: LifecycleState | None = None  # the progressing state a blocked candidate left
    reason_codes: tuple[str, ...] = ()
    # Who approved the Okta unassignment. The AD approvers must differ (D11, D143).
    okta_unassign_approver: Actor | None = None
    # Who approved the AD quarantine. The deletion approver must differ (D143).
    quarantine_approver: Actor | None = None
    # When the post-quarantine hold ends: set once the quarantine is observed, never cleared.
    # Its presence means the candidate is past the quarantine and cannot go back (D144).
    quarantine_hold_until: datetime | None = None
    # Who proposed the deletion, and when. The deletion approver must differ (D143), and
    # must approve after the proposal (D146).
    deletion_proposer: Actor | None = None
    deletion_proposed_at: datetime | None = None

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.CANDIDATE, "id")
        check_id(self.okta_group_id, IdKind.OKTA_GROUP, "okta_group_id")
        check_ids(self.assignment_ids, IdKind.ASSIGNMENT, "assignment_ids")
        check_enum(self.state, LifecycleState, "state")
        if not isinstance(self.proposed_by, Actor):
            raise InvalidRecord("proposed_by must be an Actor")
        check_utc(self.created_at, "created_at")
        check_utc(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise InvalidRecord("updated_at cannot be before created_at")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 0:
            raise InvalidRecord("epoch must be a non-negative integer")
        if self.hold_until is not None:
            check_utc(self.hold_until, "hold_until")
        if not isinstance(self.reason_codes, tuple):
            raise InvalidRecord("reason_codes must be a tuple")
        for code in self.reason_codes:
            check_text(code, "reason_codes", max_length=100)

        if (self.state in BLOCKED_STATES) != (self.blocked_from is not None):
            raise InvalidRecord("blocked_from is set exactly when the state is a blocked state")
        if self.blocked_from is not None and self.blocked_from not in PROGRESSING_STATES:
            raise InvalidRecord("blocked_from must be a progressing state")
        unassigned = self.state in POST_UNASSIGN_STATES or self.state is S.RETIRED or self.blocked_from in POST_UNASSIGN_STATES
        if unassigned and self.hold_until is None:
            raise InvalidRecord(f"a candidate in {self.state.value} must have hold_until")
        for name in ("okta_unassign_approver", "quarantine_approver", "deletion_proposer"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, Actor) or value.kind is not ActorKind.HUMAN):
                raise InvalidRecord(f"{name} must be a human Actor")
        for name in ("quarantine_hold_until", "deletion_proposed_at"):
            if getattr(self, name) is not None:
                check_utc(getattr(self, name), name)
        position = self.blocked_from or self.state
        if position in UNASSIGN_APPROVED_STATES and self.okta_unassign_approver is None:
            raise InvalidRecord(f"a candidate in {self.state.value} must record okta_unassign_approver")
        if position in PRE_UNASSIGN_STATES - UNASSIGN_APPROVED_STATES and self.okta_unassign_approver is not None:
            raise InvalidRecord(f"a candidate in {self.state.value} has no Okta unassignment approval yet")
        # The AD stages' records: required once reached, absent before. Terminal states keep
        # whatever they had when they were reached.
        for name, required_in, absent_in in (
            ("quarantine_approver", QUARANTINE_APPROVED_STATES, _BEFORE_QUARANTINE_APPROVAL),
            ("quarantine_hold_until", POST_QUARANTINE_STATES, PRE_UNASSIGN_STATES | PRE_QUARANTINE_STATES),
            ("deletion_proposer", DELETION_PROPOSED_STATES, _BEFORE_DELETION_PROPOSAL),
            ("deletion_proposed_at", DELETION_PROPOSED_STATES, _BEFORE_DELETION_PROPOSAL),
        ):
            if position in required_in and getattr(self, name) is None:
                raise InvalidRecord(f"a candidate in {self.state.value} must record {name}")
            if position in absent_in and getattr(self, name) is not None:
                raise InvalidRecord(f"a candidate in {self.state.value} cannot have {name} yet")
        if (self.deletion_proposer is None) != (self.deletion_proposed_at is None):
            raise InvalidRecord("deletion_proposer and deletion_proposed_at are recorded together")
        if self.quarantine_hold_until is not None and self.quarantine_approver is None:
            raise InvalidRecord("a quarantined candidate must record quarantine_approver")
        if self.deletion_proposer is not None and self.quarantine_hold_until is None:
            raise InvalidRecord("a deletion can only have been proposed after the quarantine")
        if self.quarantine_approver is not None and self.quarantine_approver == self.okta_unassign_approver:
            raise InvalidRecord("the quarantine approver must differ from the Okta unassignment approver (D11)")

    @classmethod
    def discover(
        cls,
        *,
        okta_group_id: str,
        assignment_ids: tuple[str, ...],
        proposed_by: Actor,
        now: datetime,
        reason_codes: tuple[str, ...] = (),
    ) -> "LifecycleCandidate":
        """The only way to create a new candidate: always in DISCOVERED."""
        return cls(
            id=new_id(IdKind.CANDIDATE),
            okta_group_id=okta_group_id,
            assignment_ids=assignment_ids,
            state=S.DISCOVERED,
            proposed_by=proposed_by,
            created_at=now,
            updated_at=now,
            reason_codes=reason_codes,
        )


@dataclass(frozen=True)
class LifecycleDecision:
    """The durable record of one applied transition."""

    id: str
    candidate_id: str
    from_state: LifecycleState
    to_state: LifecycleState
    actor: Actor
    decided_at: datetime
    reason: str
    evidence_fingerprint: str
    epoch: int  # the candidate's epoch after the transition
    approval_id: str | None = None
    execution_job_id: str | None = None

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.DECISION, "id")
        check_id(self.candidate_id, IdKind.CANDIDATE, "candidate_id")
        check_enum(self.from_state, LifecycleState, "from_state")
        check_enum(self.to_state, LifecycleState, "to_state")
        if not isinstance(self.actor, Actor):
            raise InvalidRecord("actor must be an Actor")
        check_utc(self.decided_at, "decided_at")
        check_text(self.reason, "reason")
        check_digest(self.evidence_fingerprint, "evidence_fingerprint")
        if self.approval_id is not None:
            check_id(self.approval_id, IdKind.APPROVAL, "approval_id")
        if self.execution_job_id is not None:
            check_id(self.execution_job_id, IdKind.EXECUTION_JOB, "execution_job_id")


@dataclass(frozen=True)
class TransitionRequest:
    target: LifecycleState
    actor: Actor
    reason: str
    now: datetime
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    approval: ApprovalRecord | None = None
    job: ExecutionJob | None = None
    # The deployment's quarantine OUs (D136), supplied by the server, never by a request.
    # Without them no AD-stage step can pass.
    quarantine_ous: QuarantineOus | None = None

    def __post_init__(self) -> None:
        check_enum(self.target, LifecycleState, "target")
        if not isinstance(self.actor, Actor):
            raise InvalidRecord("actor must be an Actor")
        check_text(self.reason, "reason")
        check_utc(self.now, "now")
        if not isinstance(self.evidence, EvidenceBundle):
            raise InvalidRecord("evidence must be an EvidenceBundle")
        if self.approval is not None and not isinstance(self.approval, ApprovalRecord):
            raise InvalidRecord("approval must be an ApprovalRecord")
        if self.job is not None and not isinstance(self.job, ExecutionJob):
            raise InvalidRecord("job must be an ExecutionJob")
        if self.quarantine_ous is not None and not isinstance(self.quarantine_ous, QuarantineOus):
            raise InvalidRecord("quarantine_ous must be a QuarantineOus")


@dataclass(frozen=True)
class TransitionResult:
    candidate: LifecycleCandidate
    decision: LifecycleDecision


# --- Guard helpers -------------------------------------------------------------------

Guard = Callable[[LifecycleCandidate, TransitionRequest, LifecyclePolicy, str], list[str]]


def _consistency(c: LifecycleCandidate, ev: EvidenceBundle) -> list[str]:
    """The evidence must be about this candidate and internally consistent."""
    problems = []
    if ev.okta_group is None:
        problems.append("no Okta group observation supplied")
    elif ev.okta_group.id != c.okta_group_id:
        problems.append("Okta group observation is for a different group")
    for assignment_id in c.assignment_ids:
        a = ev.assignment(assignment_id)
        if a is None:
            problems.append(f"no observation of assignment {assignment_id}")
        elif a.okta_group_id != c.okta_group_id:
            problems.append(f"assignment {assignment_id} belongs to a different group")
    m = ev.mapping
    if m is not None:
        if m.okta_group_id != c.okta_group_id:
            problems.append("identity mapping is for a different Okta group")
        if ev.ad_group is not None and ev.ad_group.id != m.ad_group_id:
            problems.append("AD group observation is not the mapped AD group")
    elif ev.ad_group is not None:
        problems.append("AD group observation supplied without an identity mapping")
    related = {c.okta_group_id} | ({m.ad_group_id} if m is not None and m.ad_group_id else set())
    for d in ev.dependencies:
        if d.subject_id not in related:
            problems.append(f"dependency evidence {d.id} is about an unrelated subject")
    return problems


def _fresh(records: Iterable[Evidence], purpose: EvidencePurpose, now: datetime, policy: LifecyclePolicy) -> list[str]:
    problems = []
    for r in records:
        # An incomplete dependency check is not an error here; it simply does not count
        # toward coverage. Every other record must be complete and fresh.
        if isinstance(r, DependencyEvidence) and not r.provenance.decision_grade:
            continue
        problems.extend(freshness_problems(f"{r.KIND.value} {r.id}", r.provenance, purpose, now, policy.freshness))
    return problems


def _evidence_conditions(records: Iterable[Evidence], purpose: EvidencePurpose, now: datetime,
                         policy: LifecyclePolicy) -> tuple[list[str], list[str]]:
    """``_fresh``'s problems, split as the classifier splits them (owner decision).

    Incomplete: a record that was never properly obtained (a partial or failed result, or
    one dated in the future). Stale: a complete record that has outlived its window.
    """
    incomplete, stale = [], []
    for r in records:
        if isinstance(r, DependencyEvidence) and not r.provenance.decision_grade:
            continue
        problems = freshness_problems(f"{r.KIND.value} {r.id}", r.provenance, purpose, now, policy.freshness)
        if not problems:
            continue
        never_obtained = (not r.provenance.decision_grade
                          or r.provenance.observed_at > now + policy.freshness.clock_skew)
        (incomplete if never_obtained else stale).extend(problems)
    return incomplete, stale


def _candidate_assignments(c: LifecycleCandidate, ev: EvidenceBundle):
    return [a for a in (ev.assignment(i) for i in c.assignment_ids) if a is not None]


def _usage(c: LifecycleCandidate, ev: EvidenceBundle, purpose: EvidencePurpose, now: datetime, policy: LifecyclePolicy) -> list[str]:
    problems = []
    for app_id in dict.fromkeys(a.application_id for a in _candidate_assignments(c, ev)):
        u = ev.usage_for(app_id, c.okta_group_id)
        if u is None:
            problems.append(f"no usage observation for application {app_id}")
            continue
        problems.extend(freshness_problems(f"USAGE {u.id}", u.provenance, purpose, now, policy.freshness))
        if u.window < policy.min_usage_window:
            problems.append(f"usage window for {app_id} is shorter than {policy.min_usage_window}")
        if u.event_count > policy.max_usage_events_for_candidate:
            problems.append(
                f"application {app_id} had {u.event_count} sign-ins in the window "
                f"(candidacy threshold {policy.max_usage_events_for_candidate})"
            )
    return problems


def _protection(ev: EvidenceBundle, policy: LifecyclePolicy) -> list[str]:
    return [f"protected: {r}" for r in protection_reasons(ev, policy)]


def _blocking_dependencies(ev: EvidenceBundle) -> list[str]:
    return [
        f"blocking dependency ({d.kind.value}): {f.description}" for d in ev.dependencies for f in d.blocking_findings
    ]


def _exact_mapping(ev: EvidenceBundle) -> list[str]:
    m = ev.mapping
    if m is None:
        return ["no identity mapping recorded"]
    if not m.is_exact:
        return [f"mapping confidence {m.confidence.value} is not exact; this step requires an exact mapping"]
    if ev.ad_group is None:
        return ["no observation of the mapped AD group"]
    return []


def _assignments_present(c: LifecycleCandidate, ev: EvidenceBundle, expected: bool) -> list[str]:
    word = "present" if expected else "absent"
    return [f"assignment {a.id} is not {word}" for a in _candidate_assignments(c, ev) if a.present is not expected]


@dataclass(frozen=True)
class StageApprovalRules:
    """What an approval of one stage needs beyond its own record (D11, D130, D143, D146)."""

    not_before: datetime | None  # the stage's hold must have ended first
    given_after: datetime | None  # the stage's proposal must have come first
    excluded: tuple[tuple[Actor | None, str], ...]  # who may not approve the stage: (person, what they did)
    unmet: tuple[str, ...]  # what the candidate itself still lacks before anything can approve the stage

    def excluded_problems(self, stage: ApprovalStage, *, you: bool = False) -> tuple[tuple[Actor | None, str], ...]:
        """``excluded`` as messages: about the approver, or addressed to them."""
        who = "you" if you else "the approver"
        return tuple((actor, f"{who} {did}; {stage.value} needs a different approver") for actor, did in self.excluded)


def stage_approval_rules(c: LifecycleCandidate, stage: ApprovalStage) -> StageApprovalRules:
    """The candidate-side rules for an approval of ``stage``.

    The AD quarantine is approved after the Okta hold, by someone other than the Okta-stage
    approver (D11). The AD deletion is approved after the post-quarantine hold and after the
    deletion was proposed, by someone other than the Okta-stage approver, the quarantine
    approver, and the deletion's proposer (D130, D139, D143, D146).
    """
    okta = (c.okta_unassign_approver, "approved the Okta unassignment (D11, D143)")
    if stage is ApprovalStage.AD_QUARANTINE:
        unmet = () if c.hold_until is not None else ("the Okta unassignment's hold has not been recorded",)
        return StageApprovalRules(c.hold_until, None, (okta,), unmet)
    if stage is ApprovalStage.AD_DELETION:
        unmet = []
        if c.quarantine_hold_until is None:
            unmet.append("the AD group's quarantine has not been observed, so nothing can authorize its deletion "
                         "(D129, D130)")
        if c.deletion_proposed_at is None:
            unmet.append("no deletion has been proposed on fresh post-quarantine evidence (D139, D145)")
        return StageApprovalRules(c.quarantine_hold_until, c.deletion_proposed_at, (
            okta,
            (c.quarantine_approver, "approved the AD quarantine (D143)"),
            (c.deletion_proposer, "proposed the deletion (D143)"),
        ), tuple(unmet))
    return StageApprovalRules(None, None, (), ())


def _approval(c: LifecycleCandidate, r: TransitionRequest, p: LifecyclePolicy, stage: ApprovalStage, *,
              fingerprint: str | None, at: datetime | None = None) -> list[str]:
    rules = stage_approval_rules(c, stage)
    return [*rules.unmet, *approval_problems(
        r.approval,
        candidate_id=c.id,
        candidate_epoch=c.epoch,
        proposed_by=c.proposed_by,
        stage=stage,
        now=at or r.now,
        max_ttl=p.approval_max_ttl,
        clock_skew=p.freshness.clock_skew,
        evidence_fingerprint=fingerprint,
        not_before=rules.not_before,
        given_after=rules.given_after,
        excluded_approvers=rules.excluded_problems(stage),
    )]


def _approver_records_it(r: TransitionRequest) -> list[str]:
    if r.approval is not None and r.actor != r.approval.operator:
        return ["only the approving operator can record the approval transition"]
    return []


def _dry_run_job(c: LifecycleCandidate, r: TransitionRequest, p: LifecyclePolicy, kind: JobKind, *,
                 fingerprint: str | None, targets: Iterable[str]) -> list[str]:
    job = r.job
    if job is None:
        return [f"no {kind.value} dry-run job supplied"]
    problems = []
    if job.candidate_id != c.id:
        problems.append("job belongs to a different candidate")
    if job.kind is not kind:
        problems.append(f"job is {job.kind.value}, not {kind.value}")
    if not job.dry_run or job.executed:
        problems.append("job is not a dry run")
    if job.status is not JobStatus.SUCCEEDED:
        problems.append(f"dry run status is {job.status.value}")
    if r.approval is not None:
        if job.approval_id != r.approval.id:
            problems.append("job was planned under a different approval")
        if job.requested_at < r.approval.decided_at:
            problems.append("job was planned before the approval was given")
    if fingerprint is not None and job.evidence_fingerprint != fingerprint:
        problems.append("material evidence changed since the dry run")
    if set(job.targets) != set(targets):
        problems.append("job targets do not match the candidate")
    if job.finished_at is not None and job.finished_at > r.now + p.freshness.clock_skew:
        problems.append("job finished_at is in the future")
    return problems


def _observed_after_job(records: Iterable[Evidence], job: ExecutionJob | None) -> list[str]:
    if job is None or job.finished_at is None:
        return []
    return [f"{r.KIND.value} {r.id} was observed before the dry run finished" for r in records if r.provenance.observed_at < job.finished_at]


def _ad_workflow_origin(ev: EvidenceBundle, policy: LifecyclePolicy) -> list[str]:
    """Only AD-sourced groups may enter the AD-retirement workflow (owner decision D12)."""
    if ev.okta_group is None:
        return []  # reported by _consistency
    origin = group_origin(ev.okta_group, policy)
    if origin is GroupOrigin.AD_SOURCED:
        return []
    if origin is GroupOrigin.OKTA_ONLY:
        return ["Okta-only group: classified for review only; it cannot enter the AD-retirement workflow"]
    if origin is GroupOrigin.OTHER_SOURCE:
        return ["group was not imported through a configured AD integration; it cannot enter the AD-retirement workflow"]
    return ["built-in Okta group"]


def _pre_unassign(c: LifecycleCandidate, r: TransitionRequest, p: LifecyclePolicy, purpose: EvidencePurpose) -> list[str]:
    ev = r.evidence
    return [
        *_consistency(c, ev),
        *_fresh(ev.records(), purpose, r.now, p),
        *_assignments_present(c, ev, expected=True),
        *_usage(c, ev, purpose, r.now, p),
        *_protection(ev, p),
        *_blocking_dependencies(ev),
    ]


def _clearance(c: LifecycleCandidate, ev: EvidenceBundle) -> list[str]:
    """The condition that put the candidate in its blocked state must have cleared."""
    if c.state is S.MAPPING_AMBIGUOUS and (ev.mapping is None or ev.mapping.confidence in UNRESOLVED_CONFIDENCES):
        return ["identity mapping is still unresolved"]
    if c.state is S.DEPENDENCY_BLOCKED:
        return _blocking_dependencies(ev)
    return []


# --- Guards --------------------------------------------------------------------------


def _g_candidacy(c, r, p, fp):
    return _pre_unassign(c, r, p, EvidencePurpose.REVIEW)


def _g_ready_for_review(c, r, p, fp):
    problems = _pre_unassign(c, r, p, EvidencePurpose.REVIEW)
    if r.evidence.mapping is None:
        problems.append("no identity mapping recorded")
    return problems


def _g_approve(c, r, p, fp):
    problems = _pre_unassign(c, r, p, EvidencePurpose.APPROVAL)
    problems += _ad_workflow_origin(r.evidence, p)
    problems += _exact_mapping(r.evidence)
    if r.evidence.ad_group is not None and not r.evidence.ad_group.exists:
        problems.append("the mapped AD group no longer exists")
    problems += _approval(c, r, p, ApprovalStage.OKTA_UNASSIGN, fingerprint=fp)
    problems += _approver_records_it(r)
    return problems


def _g_unassign_dry_run(c, r, p, fp):
    problems = _pre_unassign(c, r, p, EvidencePurpose.EXECUTION)
    problems += _ad_workflow_origin(r.evidence, p)
    problems += _exact_mapping(r.evidence)
    problems += _approval(c, r, p, ApprovalStage.OKTA_UNASSIGN, fingerprint=fp)
    problems += _dry_run_job(c, r, p, JobKind.OKTA_UNASSIGN, fingerprint=fp, targets=c.assignment_ids)
    return problems


def _g_unassignment_observed(c, r, p, fp):
    ev = r.evidence
    assignments = _candidate_assignments(c, ev)
    problems = [*_consistency(c, ev), *_ad_workflow_origin(ev, p), *_assignments_present(c, ev, expected=False)]
    problems += _fresh(assignments, EvidencePurpose.EXECUTION, r.now, p)
    problems += _dry_run_job(c, r, p, JobKind.OKTA_UNASSIGN, fingerprint=None, targets=c.assignment_ids)
    problems += _observed_after_job(assignments, r.job)
    # The approval must still have been in force when the removal was first observed.
    first_seen = min((a.provenance.observed_at for a in assignments), default=r.now)
    problems += _approval(c, r, p, ApprovalStage.OKTA_UNASSIGN, fingerprint=None, at=first_seen)
    return problems


def _g_hold_elapsed(c, r, p, fp):
    if c.hold_until is None or r.now < c.hold_until:
        return ["the hold period has not ended"]
    return []


def _ad_target(ev: EvidenceBundle) -> tuple[str, ...]:
    return (ev.ad_group.id,) if ev.ad_group is not None else ()


def _membership_known_empty(ev: EvidenceBundle) -> list[str]:
    """Known members, or an unknown member count, block the AD stages (D132). The membership
    checks themselves count toward dependency coverage."""
    ad = ev.ad_group
    if ad is None or not ad.exists:
        return []
    if ad.member_count is None:
        return ["the AD group's direct member count is unknown; unknown membership blocks the AD stages (D132)"]
    if ad.member_count > 0:
        return [f"the AD group has {ad.member_count} direct member(s); members block the AD stages (D132)"]
    return []


def _observed_since(records: Iterable[Evidence], since: datetime | None) -> list[str]:
    """Every record must have been collected after ``since``, the end of the post-quarantine
    hold: deletion is decided on fresh post-hold evidence only (D130, D139, D145)."""
    if since is None:
        return []
    return [f"{r.KIND.value} {r.id} was observed before the post-quarantine hold ended; revalidation needs evidence "
            "collected after it (D130)" for r in records if r.provenance.observed_at < since]


def _ad_stage(c: LifecycleCandidate, r: TransitionRequest, p: LifecyclePolicy, purpose: EvidencePurpose, *,
              quarantined: bool) -> list[str]:
    """The evidence rules every AD-stage step shares: consistent, AD-sourced, fresh for
    ``purpose``; the assignments still absent; an exact mapping to an AD group that still
    exists; not protected; COMPLETE dependency coverage with no blocker (D131); no members
    (D132); and the group outside its quarantine OU before the quarantine, inside it after."""
    ev = r.evidence
    problems = [*_consistency(c, ev), *_ad_workflow_origin(ev, p), *_fresh(ev.records(), purpose, r.now, p)]
    problems += [f"{m} (re-added during the hold?)" for m in _assignments_present(c, ev, expected=False)]
    problems += _exact_mapping(ev)
    if ev.ad_group is not None and not ev.ad_group.exists:
        problems.append("the mapped AD group no longer exists")
    problems += _protection(ev, p)
    coverage = ev.dependency_coverage(p.required_dependency_kinds)
    if coverage is not DependencyCoverage.COMPLETE:
        problems.append(f"dependency coverage is {coverage.value}; the AD stages require COMPLETE (D131)")
    problems += _blocking_dependencies(ev)
    problems += _membership_known_empty(ev)
    if ev.ad_group is not None and ev.ad_group.exists:
        problems += quarantine_location_problems(ev.ad_group, r.quarantine_ous, quarantined=quarantined)
    return problems


def _post_quarantine(c: LifecycleCandidate, r: TransitionRequest, p: LifecyclePolicy,
                     purpose: EvidencePurpose) -> list[str]:
    return [*_ad_stage(c, r, p, purpose, quarantined=True), *_observed_since(r.evidence.records(),
                                                                             c.quarantine_hold_until)]


def _g_quarantine_approve(c, r, p, fp):
    problems = _ad_stage(c, r, p, EvidencePurpose.APPROVAL, quarantined=False)
    problems += _approval(c, r, p, ApprovalStage.AD_QUARANTINE, fingerprint=fp)
    problems += _approver_records_it(r)
    return problems


def _g_quarantine_dry_run(c, r, p, fp):
    problems = _ad_stage(c, r, p, EvidencePurpose.EXECUTION, quarantined=False)
    problems += _approval(c, r, p, ApprovalStage.AD_QUARANTINE, fingerprint=fp)
    problems += _dry_run_job(c, r, p, JobKind.AD_QUARANTINE, fingerprint=fp, targets=_ad_target(r.evidence))
    return problems


def _g_quarantine_observed(c, r, p, fp):
    ev = r.evidence
    problems = [*_consistency(c, ev), *_ad_workflow_origin(ev, p), *_exact_mapping(ev)]
    ad = ev.ad_group
    if ad is None:
        return problems
    if not ad.exists:
        problems.append("the mapped AD group no longer exists; a quarantine moves the group and never deletes it")
    else:
        problems += quarantine_location_problems(ad, r.quarantine_ous, quarantined=True)
    problems += _fresh([ad], EvidencePurpose.EXECUTION, r.now, p)
    problems += _dry_run_job(c, r, p, JobKind.AD_QUARANTINE, fingerprint=None, targets=(ad.id,))
    problems += _observed_after_job([ad], r.job)
    # The approval must still have been in force when the quarantine was first observed.
    problems += _approval(c, r, p, ApprovalStage.AD_QUARANTINE, fingerprint=None, at=ad.provenance.observed_at)
    return problems


def _g_quarantine_hold_elapsed(c, r, p, fp):
    """The end of the post-quarantine hold only opens revalidation; it authorizes nothing (D139)."""
    if c.quarantine_hold_until is None or r.now < c.quarantine_hold_until:
        return ["the post-quarantine hold has not ended (D138)"]
    return []


def _g_propose_deletion(c, r, p, fp):
    return [*_g_quarantine_hold_elapsed(c, r, p, fp), *_post_quarantine(c, r, p, EvidencePurpose.APPROVAL)]


def _g_deletion_approve(c, r, p, fp):
    problems = _post_quarantine(c, r, p, EvidencePurpose.APPROVAL)
    problems += _approval(c, r, p, ApprovalStage.AD_DELETION, fingerprint=fp)
    problems += _approver_records_it(r)
    return problems


def _g_deletion_dry_run(c, r, p, fp):
    problems = _post_quarantine(c, r, p, EvidencePurpose.EXECUTION)
    problems += _approval(c, r, p, ApprovalStage.AD_DELETION, fingerprint=fp)
    problems += _dry_run_job(c, r, p, JobKind.AD_DELETION, fingerprint=fp, targets=_ad_target(r.evidence))
    return problems


def _g_deletion_observed(c, r, p, fp):
    ev = r.evidence
    problems = [*_consistency(c, ev), *_ad_workflow_origin(ev, p), *_exact_mapping(ev)]
    ad = ev.ad_group
    if ad is None:
        return problems
    if ad.exists:
        problems.append("the mapped AD group still exists")
    problems += _fresh([ad], EvidencePurpose.EXECUTION, r.now, p)
    problems += _dry_run_job(c, r, p, JobKind.AD_DELETION, fingerprint=None, targets=(ad.id,))
    problems += _observed_after_job([ad], r.job)
    problems += _approval(c, r, p, ApprovalStage.AD_DELETION, fingerprint=None, at=ad.provenance.observed_at)
    return problems


LEGACY_STEP_PROBLEM = ("this is a step of the legacy single AD stage (AD_RETIREMENT), which approved quarantine and "
                       "deletion together; it is kept only so recorded history verifies. AD quarantine and AD "
                       "deletion are separate governed stages (D128, D147, D148)")


def _g_legacy(c, r, p, fp):
    return [LEGACY_STEP_PROBLEM]


def _g_divert(c, r, p, fp):
    return []  # moving to a safer state needs only a reason


def _g_reenter_candidate(c, r, p, fp):
    if c.blocked_from in POST_QUARANTINE_STATES:
        return ["the candidate was blocked after quarantine; it can only re-enter at DELETION_REVALIDATION_REQUIRED "
                "(D144, D145)"]
    if c.blocked_from not in PRE_UNASSIGN_STATES:
        return ["the candidate was blocked after unassignment; it can only re-enter at REVALIDATION_REQUIRED"]
    return [*_clearance(c, r.evidence), *_g_candidacy(c, r, p, fp)]


def _g_reenter_revalidation(c, r, p, fp):
    if c.blocked_from in POST_QUARANTINE_STATES:
        return ["the candidate was blocked after quarantine; it never returns to the pre-quarantine lifecycle and can "
                "only re-enter at DELETION_REVALIDATION_REQUIRED (D144, D145)"]
    if c.blocked_from not in PRE_QUARANTINE_STATES:
        return ["the candidate was blocked before unassignment; it can only re-enter at CANDIDATE"]
    ev = r.evidence
    return [
        *_clearance(c, ev),
        *_g_hold_elapsed(c, r, p, fp),
        *_consistency(c, ev),
        *_ad_workflow_origin(ev, p),
        *_fresh(ev.records(), EvidencePurpose.REVIEW, r.now, p),
        *_assignments_present(c, ev, expected=False),
        *_protection(ev, p),
    ]


def _g_reenter_deletion_revalidation(c, r, p, fp):
    """A resolved post-quarantine blocker: back to revalidation on fresh complete evidence,
    then a new proposal and a new approval (D145). Never earlier (D144)."""
    if c.blocked_from not in POST_QUARANTINE_STATES:
        where = "CANDIDATE" if c.blocked_from in PRE_UNASSIGN_STATES else "REVALIDATION_REQUIRED"
        return [f"the candidate was blocked before its quarantine was observed; it can only re-enter at {where}"]
    ev = r.evidence
    problems = [
        *_clearance(c, ev),
        *_g_quarantine_hold_elapsed(c, r, p, fp),
        *_consistency(c, ev),
        *_ad_workflow_origin(ev, p),
        *_fresh(ev.records(), EvidencePurpose.REVIEW, r.now, p),
        *_assignments_present(c, ev, expected=False),
        *_protection(ev, p),
        *_exact_mapping(ev),
    ]
    ad = ev.ad_group
    if ad is not None:
        if not ad.exists:
            problems.append("the mapped AD group no longer exists")
        else:
            problems += quarantine_location_problems(ad, r.quarantine_ous, quarantined=True)
    problems += _observed_since(ev.records(), c.quarantine_hold_until)
    return problems


# --- Transition table ----------------------------------------------------------------

ANY_ACTOR = frozenset(ActorKind)
HUMAN_ONLY = frozenset({ActorKind.HUMAN})
SYSTEM_ONLY = frozenset({ActorKind.SYSTEM})


@dataclass(frozen=True)
class TransitionRule:
    source: LifecycleState
    target: LifecycleState
    actors: frozenset[ActorKind]
    guard: Guard
    category: str  # "forward", "diversion", "re-entry", or "legacy" (history only; always refused)


def _build_transitions() -> dict[tuple[LifecycleState, LifecycleState], TransitionRule]:
    rules: dict[tuple[LifecycleState, LifecycleState], TransitionRule] = {}

    def add(source, target, actors, guard, category):
        rules[(source, target)] = TransitionRule(source, target, actors, guard, category)

    add(S.DISCOVERED, S.CANDIDATE, ANY_ACTOR, _g_candidacy, "forward")
    add(S.CANDIDATE, S.NEEDS_REVIEW, ANY_ACTOR, _g_ready_for_review, "forward")
    add(S.NEEDS_REVIEW, S.APPROVED, HUMAN_ONLY, _g_approve, "forward")
    add(S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN, ANY_ACTOR, _g_unassign_dry_run, "forward")
    add(S.OKTA_UNASSIGN_DRY_RUN, S.HOLD, ANY_ACTOR, _g_unassignment_observed, "forward")
    add(S.HOLD, S.REVALIDATION_REQUIRED, ANY_ACTOR, _g_hold_elapsed, "forward")
    # The AD quarantine (D147): approved by a person, dry run, observed, then its own hold.
    add(S.REVALIDATION_REQUIRED, S.QUARANTINE_APPROVED, HUMAN_ONLY, _g_quarantine_approve, "forward")
    add(S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN, ANY_ACTOR, _g_quarantine_dry_run, "forward")
    add(S.QUARANTINE_DRY_RUN, S.QUARANTINE_HOLD, ANY_ACTOR, _g_quarantine_observed, "forward")
    # The AD deletion (D129, D130): revalidation after the hold, a person's proposal, another
    # person's approval, dry run, observed.
    add(S.QUARANTINE_HOLD, S.DELETION_REVALIDATION_REQUIRED, ANY_ACTOR, _g_quarantine_hold_elapsed, "forward")
    add(S.DELETION_REVALIDATION_REQUIRED, S.DELETION_PROPOSED, HUMAN_ONLY, _g_propose_deletion, "forward")
    add(S.DELETION_PROPOSED, S.DELETION_APPROVED, HUMAN_ONLY, _g_deletion_approve, "forward")
    add(S.DELETION_APPROVED, S.DELETION_DRY_RUN, ANY_ACTOR, _g_deletion_dry_run, "forward")
    add(S.DELETION_DRY_RUN, S.RETIRED, ANY_ACTOR, _g_deletion_observed, "forward")
    # The legacy single AD stage: present so recorded history verifies, never applicable (D148).
    for source, target in LEGACY_PATH:
        add(source, target, ANY_ACTOR, _g_legacy, "legacy")

    for source in PROGRESSING_STATES | BLOCKED_STATES:
        for target in DIVERSION_TARGETS - {source}:
            if target in (S.EXCLUDED, S.REJECTED):
                actors = HUMAN_ONLY
            elif target in EVIDENCE_CONDITION_STATES:
                actors = SYSTEM_ONLY  # evidence conditions are observed, never assigned by a person
            else:
                actors = ANY_ACTOR
            add(source, target, actors, _g_divert, "diversion")

    for source in BLOCKED_STATES:
        # Lifting a generic BLOCKED needs a human; the specific blocks clear on evidence.
        actors = HUMAN_ONLY if source is S.BLOCKED else ANY_ACTOR
        add(source, S.CANDIDATE, actors, _g_reenter_candidate, "re-entry")
        add(source, S.REVALIDATION_REQUIRED, actors, _g_reenter_revalidation, "re-entry")
        add(source, S.DELETION_REVALIDATION_REQUIRED, actors, _g_reenter_deletion_revalidation, "re-entry")
    return rules


TRANSITIONS: dict[tuple[LifecycleState, LifecycleState], TransitionRule] = _build_transitions()


def allowed_targets(state: LifecycleState) -> frozenset[LifecycleState]:
    """Where ``state`` may go. Legacy steps are not offered: they are history only (D148)."""
    return frozenset(t for (s, t), rule in TRANSITIONS.items() if s is state and rule.category != "legacy")


# --- Applying transitions ------------------------------------------------------------


def apply_transition(candidate: LifecycleCandidate, request: TransitionRequest, policy: LifecyclePolicy) -> TransitionResult:
    """Return the candidate after the transition and the decision record, or raise TransitionRefused."""
    if not isinstance(candidate, LifecycleCandidate):
        raise TypeError("candidate must be a LifecycleCandidate")
    if not isinstance(request, TransitionRequest):
        raise TypeError("request must be a TransitionRequest")
    if not isinstance(policy, LifecyclePolicy):
        raise TypeError("policy must be a LifecyclePolicy")

    source, target = candidate.state, request.target
    rule = TRANSITIONS.get((source, target))
    if rule is None:
        raise TransitionRefused(source, target, [f"{source.value} -> {target.value} is not a permitted transition"])

    problems = []
    if request.actor.kind not in rule.actors:
        problems.append(f"{request.actor.kind.value} actors cannot request this transition")
    if request.now < candidate.updated_at:
        problems.append("the request is dated before the candidate's last change")
    fingerprint = evidence_fingerprint(request.evidence)
    problems += rule.guard(candidate, request, policy, fingerprint)
    if problems:
        raise TransitionRefused(source, target, problems)

    changes: dict = {"state": target, "updated_at": request.now}
    if target in BLOCKED_STATES:
        changes["blocked_from"] = candidate.blocked_from if source in BLOCKED_STATES else source
    else:
        changes["blocked_from"] = None
    if rule.category == "re-entry":
        changes["epoch"] = candidate.epoch + 1
        # A fresh approval cycle starts for the stage the candidate re-enters.
        if target is S.CANDIDATE:
            changes["okta_unassign_approver"] = None
        elif target is S.REVALIDATION_REQUIRED:
            changes["quarantine_approver"] = None
        elif target is S.DELETION_REVALIDATION_REQUIRED:
            changes["deletion_proposer"] = None  # a new proposal and approval are needed (D145)
            changes["deletion_proposed_at"] = None
    if target is S.APPROVED:
        changes["okta_unassign_approver"] = request.approval.operator
    if target is S.QUARANTINE_APPROVED:
        changes["quarantine_approver"] = request.approval.operator
    if target is S.HOLD:
        changes["hold_until"] = request.now + policy.hold_period
    if target is S.QUARANTINE_HOLD:
        changes["quarantine_hold_until"] = request.now + QUARANTINE_HOLD_PERIOD  # from the confirmed observation (D138)
    if target is S.DELETION_PROPOSED:
        changes["deletion_proposer"] = request.actor
        changes["deletion_proposed_at"] = request.now
    updated = replace(candidate, **changes)

    decision = LifecycleDecision(
        id=new_id(IdKind.DECISION),
        candidate_id=candidate.id,
        from_state=source,
        to_state=target,
        actor=request.actor,
        decided_at=request.now,
        reason=request.reason,
        evidence_fingerprint=fingerprint,
        epoch=updated.epoch,
        approval_id=request.approval.id if request.approval is not None else None,
        execution_job_id=request.job.id if request.job is not None else None,
    )
    return TransitionResult(updated, decision)


def apply_and_audit(
    candidate: LifecycleCandidate, request: TransitionRequest, policy: LifecyclePolicy, trail: AuditTrail
) -> TransitionResult:
    """``apply_transition`` that also records the outcome, including refusals."""
    try:
        result = apply_transition(candidate, request, policy)
    except TransitionRefused as refused:
        trail.append(
            actor=request.actor,
            action=AuditAction.TRANSITION_REFUSED,
            result=AuditResult.REFUSED,
            subject_id=candidate.id,
            occurred_at=request.now,
            details={"from": refused.source, "to": refused.target, "problems": " | ".join(refused.problems)},
        )
        raise
    trail.append(
        actor=request.actor,
        action=AuditAction.TRANSITION_APPLIED,
        result=AuditResult.SUCCEEDED,
        subject_id=candidate.id,
        occurred_at=request.now,
        details={
            "decision_id": result.decision.id,
            "from": result.decision.from_state,
            "to": result.decision.to_state,
            "reason": request.reason,
            "evidence_fingerprint": result.decision.evidence_fingerprint,
        },
    )
    return result


def recommend_diversion(
    candidate: LifecycleCandidate, evidence: EvidenceBundle, now: datetime, policy: LifecyclePolicy
) -> tuple[LifecycleState, str] | None:
    """The safer state a progressing candidate should move to, if any, and why.

    Priority: PROTECTED, then MAPPING_AMBIGUOUS, then DEPENDENCY_BLOCKED, then STALE_EVIDENCE,
    then EVIDENCE_INCOMPLETE (the classifier's precedence for the same two conditions).
    """
    if candidate.state not in PROGRESSING_STATES:
        return None
    if reasons := protection_reasons(evidence, policy):
        return S.PROTECTED, "; ".join(reasons)
    if evidence.mapping is not None and evidence.mapping.confidence in UNRESOLVED_CONFIDENCES:
        return S.MAPPING_AMBIGUOUS, f"identity mapping is {evidence.mapping.confidence.value}"
    if blocking := _blocking_dependencies(evidence):
        return S.DEPENDENCY_BLOCKED, "; ".join(blocking)
    incomplete, stale = _evidence_conditions(evidence.records(), EvidencePurpose.REVIEW, now, policy)
    if stale:
        return S.STALE_EVIDENCE, "; ".join(stale)
    if incomplete:
        return S.EVIDENCE_INCOMPLETE, "; ".join(incomplete)
    return None


def verify_history(candidate: LifecycleCandidate, decisions: Iterable[LifecycleDecision]) -> None:
    """Raise InvalidRecord unless ``decisions`` legally lead from DISCOVERED to the candidate's state.

    The store must use this when loading a candidate, so a state written directly to the
    database (bypassing ``apply_transition``) is detected.
    """
    state, epoch, last_time, approver = S.DISCOVERED, 0, candidate.created_at, None
    quarantine_approver = quarantine_hold_until = proposer = proposed_at = None
    for index, d in enumerate(decisions):
        if d.candidate_id != candidate.id:
            raise InvalidRecord(f"decision {index} belongs to a different candidate")
        if d.from_state is not state:
            raise InvalidRecord(f"decision {index} starts from {d.from_state.value}, expected {state.value}")
        rule = TRANSITIONS.get((d.from_state, d.to_state))
        if rule is None:
            raise InvalidRecord(f"decision {index} records an impossible transition")
        if d.actor.kind not in rule.actors:
            raise InvalidRecord(f"decision {index} was made by an actor kind that cannot make it")
        if d.to_state in APPROVAL_STEPS and d.approval_id is None:
            raise InvalidRecord(f"decision {index} is an approval step that cites no approval")
        if d.decided_at < last_time:
            raise InvalidRecord(f"decision {index} is out of time order")
        reentry = rule.category == "re-entry"
        epoch += 1 if reentry else 0
        if quarantine_hold_until is not None and d.to_state in PRE_UNASSIGN_STATES | PRE_QUARANTINE_STATES:
            raise InvalidRecord(f"decision {index} returns a quarantined candidate to the pre-quarantine lifecycle "
                                "(D144)")
        if d.to_state is S.APPROVED:
            approver = d.actor  # the APPROVED transition is made by the approver
        elif d.to_state is S.CANDIDATE and reentry:
            approver = None
        if d.to_state is S.QUARANTINE_APPROVED:  # made by the quarantine approver
            if d.actor == approver:
                raise InvalidRecord(f"decision {index}: the Okta-stage approver approved the quarantine (D11)")
            quarantine_approver = d.actor
        elif d.to_state is S.REVALIDATION_REQUIRED and reentry:
            quarantine_approver = None
        if d.to_state is S.QUARANTINE_HOLD:
            quarantine_hold_until = d.decided_at + QUARANTINE_HOLD_PERIOD
        if d.to_state is S.DELETION_PROPOSED:
            proposer, proposed_at = d.actor, d.decided_at
        elif d.to_state is S.DELETION_REVALIDATION_REQUIRED and reentry:
            proposer = proposed_at = None
        if d.to_state is S.DELETION_APPROVED and d.actor in (approver, quarantine_approver, proposer,
                                                              candidate.proposed_by):
            raise InvalidRecord(f"decision {index}: the deletion was approved by someone who may not approve it (D143)")
        if d.epoch != epoch:
            raise InvalidRecord(f"decision {index} records epoch {d.epoch}, expected {epoch}")
        state, last_time = d.to_state, d.decided_at
    if state is not candidate.state or epoch != candidate.epoch:
        raise InvalidRecord("decision history does not lead to the candidate's current state")
    if approver != candidate.okta_unassign_approver:
        raise InvalidRecord("decision history does not match the recorded Okta unassignment approver")
    if quarantine_approver != candidate.quarantine_approver:
        raise InvalidRecord("decision history does not match the recorded quarantine approver")
    if quarantine_hold_until != candidate.quarantine_hold_until:
        raise InvalidRecord("decision history does not match the recorded post-quarantine hold")
    if (proposer, proposed_at) != (candidate.deletion_proposer, candidate.deletion_proposed_at):
        raise InvalidRecord("decision history does not match the recorded deletion proposal")
