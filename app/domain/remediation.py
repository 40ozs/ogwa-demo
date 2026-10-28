"""Remediation: the one narrow interface through which OGWA would ever change Okta or AD.

A remediation request names exactly one operation on exactly one explicit target of one
lifecycle candidate. The operations are the changes the lifecycle anticipates:

- ``OKTA_GROUP_UNASSIGN``: remove one Okta group's assignment to one application (the
  ``OKTA_UNASSIGN`` stage);
- ``AD_GROUP_QUARANTINE``: move one AD group into its domain's configured quarantine OU
  (D136). It is authorized by an ``AD_QUARANTINE`` approval only, in ``QUARANTINE_APPROVED``
  or ``QUARANTINE_DRY_RUN`` (D147);
- ``AD_GROUP_DELETE``: delete one quarantined AD group. It is authorized by an
  ``AD_DELETION`` approval only, in ``DELETION_APPROVED`` or ``DELETION_DRY_RUN``: after the
  quarantine was observed, its 30-day hold ended, fresh evidence was collected, a person
  proposed the deletion, and a different person approved it (D129, D130, D138, D139, D143).
  No Okta or quarantine approval, and no legacy ``AD_RETIREMENT`` approval, ever authorizes
  it (D146, D148).

There is no unquarantine or restore operation (D149).

**This build performs none of them (D8).** Every request resolves to one of four outcomes,
and none of them changes an external system:

- ``SIMULATED``: an adapter computed the change against a synthetic model of the target;
- ``WHATIF``: the PowerShell worker ran under ``-WhatIf``, so ShouldProcess declined the change;
- ``VALIDATION_ONLY``: the request, its target, and the adapter's contract were validated;
  nothing was simulated, launched, or sent;
- ``BLOCKED``: a gate or the adapter refused.

There is no outcome for a performed change: ``RemediationOutcome`` has no such member, and a
``RemediationResult`` that claims ``executed`` or ``production_mutation`` cannot be built.

A dry run is refused unless every gate passes. ``evaluate_gates`` evaluates all of them, so
an operator sees every reason at once. The first eight are the P10 hard gates; the last two
are backstops that keep the remediation layer at least as strict as the rest of OGWA:

- ``EXECUTION_MODE_PERMITS_DRY_RUN``: the process can plan mutations (``LOCAL_SYNTHETIC`` or
  ``DRY_RUN_MUTATION``), and the request asks for no mode but ``DRY_RUN_MUTATION``;
- ``SINGLE_EXPLICIT_TARGET``: one target of the operation's kind, inside this candidate's
  scope, whose explicit identity is resolved from recorded evidence (never from a name or a
  pattern);
- ``EXACT_VERIFIED_MAPPING``: an ``EXACT_*`` mapping from a COMPLETE observation, naming an
  AD group that was observed, by objectGUID, to exist (name-only and unverified never pass);
- ``FRESH_EVIDENCE``: every record is COMPLETE, not future-dated, and inside the EXECUTION
  freshness window (24 hours at most, E-3);
- ``NOT_PROTECTED``: no protection reason, and protection is determinable (an incomplete AD
  record means unknown protection, which blocks and cannot be overridden: D21);
- ``VALID_APPROVAL``: an APPROVE decision for the operation's stage, candidate, and epoch,
  unexpired, and not by the candidate's proposer. For an AD operation it was given after the
  stage's hold, by a human who approved no earlier stage (D11); for a deletion also after
  the deletion was proposed, and not by its proposer (D143, D146);
- ``APPROVAL_FINGERPRINT_MATCHES``: the approval was given on exactly the current evidence;
- ``NO_DEPENDENCY_BLOCKER``: no blocking finding; membership evidence of the mapped AD group
  is complete and shows no member, for every operation (D132): COMPLETE
  ``AD_GROUP_MEMBERS`` and ``AD_NESTED_MEMBERSHIP`` checks and a known direct member count of
  zero; and, for AD operations, dependency coverage is COMPLETE (P-1, D131);
- ``SEPARATION_OF_DUTIES``: a named human requests it, and not the stage's approver (D49);
- ``LIFECYCLE_RULES``: the candidate is at the operation's stage, and the lifecycle's own
  rules for that stage hold (consistency, AD origin (D12), assignment presence, usage, and
  the group outside its quarantine OU for a quarantine, inside it for a deletion).

A request that fails any gate never reaches an adapter, so a blocked condition never yields
a plan (D133).

Changing the target's identity changes the evidence, so it fails
``APPROVAL_FINGERPRINT_MATCHES``; a target that is no longer the mapped group also fails
``SINGLE_EXPLICIT_TARGET``. Nothing here performs I/O (D-1).
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalRecord, ApprovalStage, approval_problems
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidencePurpose, freshness_problems, stable_digest
from app.domain.execution import JOB_MODES, ExecutionJob, JobKind, JobStatus
from app.domain.ids import IdKind, check_enum, check_id, check_text, new_id
from app.domain.lifecycle import (
    TRANSITIONS,
    LifecycleCandidate,
    LifecycleState,
    TransitionRequest,
    _ad_workflow_origin,
    _assignments_present,
    _consistency,
    stage_approval_rules,
)
from app.domain.model import DependencyCoverage, DependencyEvidence, DependencyKind
from app.domain.policy import EvidenceBundle, LifecyclePolicy, evidence_fingerprint, protection_reasons
from app.domain.quarantine import QuarantineOus, quarantine_location_problems

S = LifecycleState
PRECHECK_ACTOR = Actor(ActorKind.SYSTEM, "ogwa/remediation-precheck")
MAX_PLANNED_CHANGE_TEXT = 500


class RemediationOperation(StrEnum):
    OKTA_GROUP_UNASSIGN = "OKTA_GROUP_UNASSIGN"
    AD_GROUP_QUARANTINE = "AD_GROUP_QUARANTINE"
    AD_GROUP_DELETE = "AD_GROUP_DELETE"


class RemediationOutcome(StrEnum):
    """Everything a remediation can resolve to in this build. None is an execution."""

    SIMULATED = "SIMULATED"
    WHATIF = "WHATIF"
    VALIDATION_ONLY = "VALIDATION_ONLY"
    BLOCKED = "BLOCKED"


class TargetKind(StrEnum):
    OKTA_ASSIGNMENT = "OKTA_ASSIGNMENT"  # one (application, group) assignment, by its internal id
    AD_GROUP = "AD_GROUP"  # one AD group, by its internal id; identity is its objectGUID in its domain


class Gate(StrEnum):
    EXECUTION_MODE_PERMITS_DRY_RUN = "EXECUTION_MODE_PERMITS_DRY_RUN"
    SINGLE_EXPLICIT_TARGET = "SINGLE_EXPLICIT_TARGET"
    EXACT_VERIFIED_MAPPING = "EXACT_VERIFIED_MAPPING"
    FRESH_EVIDENCE = "FRESH_EVIDENCE"
    NOT_PROTECTED = "NOT_PROTECTED"
    VALID_APPROVAL = "VALID_APPROVAL"
    APPROVAL_FINGERPRINT_MATCHES = "APPROVAL_FINGERPRINT_MATCHES"
    NO_DEPENDENCY_BLOCKER = "NO_DEPENDENCY_BLOCKER"
    SEPARATION_OF_DUTIES = "SEPARATION_OF_DUTIES"
    LIFECYCLE_RULES = "LIFECYCLE_RULES"


# The P10 hard gates; the other two are backstops.
REQUIRED_GATES = (
    Gate.EXECUTION_MODE_PERMITS_DRY_RUN, Gate.SINGLE_EXPLICIT_TARGET, Gate.EXACT_VERIFIED_MAPPING,
    Gate.FRESH_EVIDENCE, Gate.NOT_PROTECTED, Gate.VALID_APPROVAL, Gate.APPROVAL_FINGERPRINT_MATCHES,
    Gate.NO_DEPENDENCY_BLOCKER,
)
# The modes in which a mutation may be planned. READ_ONLY_PRODUCTION cannot plan one, and
# PRODUCTION_MUTATION cannot exist in this build.
DRY_RUN_MODES = JOB_MODES


@dataclass(frozen=True)
class OperationSpec:
    operation: RemediationOperation
    # The one approval stage that authorizes it; no other stage's approval ever does (D146).
    stage: ApprovalStage
    target_kind: TargetKind
    # Where the candidate must be: the stage's approved state, or its dry run's.
    states: frozenset[LifecycleState]
    # The lifecycle step whose guard holds the stage's evidence rules, run as the last
    # backstop with a hypothetical successful dry run; and that dry run's job kind.
    guard_step: tuple[LifecycleState, LifecycleState]
    job_kind: JobKind
    summary: str

    @property
    def ad_operation(self) -> bool:
        return self.target_kind is TargetKind.AD_GROUP


OPERATIONS: dict[RemediationOperation, OperationSpec] = {
    spec.operation: spec
    for spec in (
        OperationSpec(RemediationOperation.OKTA_GROUP_UNASSIGN, ApprovalStage.OKTA_UNASSIGN, TargetKind.OKTA_ASSIGNMENT,
                      frozenset({S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN}), (S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN),
                      JobKind.OKTA_UNASSIGN, "remove one Okta group's assignment to one application"),
        OperationSpec(RemediationOperation.AD_GROUP_QUARANTINE, ApprovalStage.AD_QUARANTINE, TargetKind.AD_GROUP,
                      frozenset({S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN}),
                      (S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN), JobKind.AD_QUARANTINE,
                      "move one AD group into its domain's quarantine OU"),
        OperationSpec(RemediationOperation.AD_GROUP_DELETE, ApprovalStage.AD_DELETION, TargetKind.AD_GROUP,
                      frozenset({S.DELETION_APPROVED, S.DELETION_DRY_RUN}), (S.DELETION_APPROVED, S.DELETION_DRY_RUN),
                      JobKind.AD_DELETION, "delete one quarantined AD group"),
    )
}
# Membership evidence that must be complete, and empty, before any remediation (D132).
MEMBERSHIP_KINDS = (DependencyKind.AD_GROUP_MEMBERS, DependencyKind.AD_NESTED_MEMBERSHIP)
TARGET_ID_KINDS = {TargetKind.OKTA_ASSIGNMENT: IdKind.ASSIGNMENT, TargetKind.AD_GROUP: IdKind.AD_GROUP}


# --- records -------------------------------------------------------------------------


def _check_pairs(value: object, field_name: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(p, tuple) and len(p) == 2 and all(isinstance(x, str) and x for x in p) for p in value
    ):
        raise InvalidRecord(f"{field_name} must be a tuple of non-empty (str, str) pairs")
    if len({k for k, _ in value}) != len(value):
        raise InvalidRecord(f"{field_name} has a repeated key")
    return value


@dataclass(frozen=True)
class RemediationTarget:
    """The one object a remediation would change, with the explicit identity OGWA recorded
    for it. The worker re-verifies that identity live and refuses on any difference."""

    kind: TargetKind
    target_id: str  # internal id: an assignment (OKTA_ASSIGNMENT) or an AD group (AD_GROUP)
    identity: tuple[tuple[str, str], ...]  # sorted (name, value) pairs, every value present

    def __post_init__(self) -> None:
        check_enum(self.kind, TargetKind, "kind")
        check_id(self.target_id, TARGET_ID_KINDS[self.kind], "target_id")
        _check_pairs(self.identity, "identity")
        if not self.identity or list(self.identity) != sorted(self.identity):
            raise InvalidRecord("identity must be a non-empty, sorted tuple of pairs")

    @property
    def identity_digest(self) -> str:
        return stable_digest([self.kind.value, self.target_id, [list(p) for p in self.identity]])

    def value(self, name: str) -> str | None:
        return dict(self.identity).get(name)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "targetId": self.target_id, "identity": dict(self.identity),
                "identityDigest": self.identity_digest}


@dataclass(frozen=True)
class GateCheck:
    gate: Gate
    problems: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.problems


@dataclass(frozen=True)
class GateReport:
    """Every gate, in ``Gate`` order, each with its own problems."""

    checks: tuple[GateCheck, ...]

    def __post_init__(self) -> None:
        if tuple(c.gate for c in self.checks) != tuple(Gate):
            raise InvalidRecord("a gate report covers every gate exactly once, in order")

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failed(self) -> tuple[Gate, ...]:
        return tuple(c.gate for c in self.checks if not c.passed)

    def problems(self) -> tuple[str, ...]:
        return tuple(f"{c.gate.value}: {p}" for c in self.checks for p in c.problems)

    def to_dict(self) -> list[dict[str, Any]]:
        return [{"gate": c.gate.value, "passed": c.passed, "problems": list(c.problems)} for c in self.checks]


@dataclass(frozen=True)
class PlannedChange:
    """One change a remediation would make, described; never made in this build."""

    system: str  # "okta", "ad", or "aap"
    action: str  # e.g. "unassign_group_from_application", "move_group_to_quarantine", "delete_group"
    target_id: str
    summary: str
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.system not in ("okta", "ad", "aap"):
            raise InvalidRecord("system must be okta, ad, or aap")
        check_text(self.action, "action", max_length=100)
        check_text(self.target_id, "target_id", max_length=100)
        check_text(self.summary, "summary", max_length=MAX_PLANNED_CHANGE_TEXT)
        _check_pairs(self.details, "details")

    def to_dict(self) -> dict[str, Any]:
        return {"system": self.system, "action": self.action, "targetId": self.target_id, "summary": self.summary,
                "details": dict(self.details)}


@dataclass(frozen=True)
class RemediationResult:
    """What a remediation request resolved to. ``executed`` and ``production_mutation`` exist
    to be stated, and both must be False: this build never changes an external system."""

    operation: RemediationOperation
    outcome: RemediationOutcome
    adapter: str
    gates: GateReport
    target: RemediationTarget | None
    planned_changes: tuple[PlannedChange, ...] = ()
    notes: tuple[str, ...] = ()
    executed: bool = False
    production_mutation: bool = False

    def __post_init__(self) -> None:
        check_enum(self.operation, RemediationOperation, "operation")
        check_enum(self.outcome, RemediationOutcome, "outcome")
        check_text(self.adapter, "adapter", max_length=60)
        if not isinstance(self.gates, GateReport):
            raise InvalidRecord("gates must be a GateReport")
        if self.executed is not False or self.production_mutation is not False:
            raise InvalidRecord("this build never executes a remediation; production mutation is impossible (D8)")
        if not isinstance(self.planned_changes, tuple) or not all(isinstance(c, PlannedChange) for c in self.planned_changes):
            raise InvalidRecord("planned_changes must be a tuple of PlannedChange")
        if not isinstance(self.notes, tuple) or not all(isinstance(n, str) and n for n in self.notes):
            raise InvalidRecord("notes must be a tuple of non-empty strings")
        if self.outcome is RemediationOutcome.BLOCKED:
            if self.gates.passed and not self.notes:
                raise InvalidRecord("a BLOCKED result names a failed gate or the adapter's reason")
            if self.planned_changes:
                raise InvalidRecord("a BLOCKED result plans nothing")
        else:
            if not self.gates.passed:
                raise InvalidRecord(f"{self.outcome.value} requires every gate to pass")
            if self.target is None or not self.planned_changes:
                raise InvalidRecord(f"{self.outcome.value} names its target and the change it describes")
        if self.target is not None and not isinstance(self.target, RemediationTarget):
            raise InvalidRecord("target must be a RemediationTarget")

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation.value, "outcome": self.outcome.value, "adapter": self.adapter,
            "target": self.target.to_dict() if self.target else None,
            "gates": self.gates.to_dict(), "plannedChanges": [c.to_dict() for c in self.planned_changes],
            "notes": list(self.notes), "executed": False, "productionMutation": False,
        }


def blocked(operation: RemediationOperation, gates: GateReport, *, adapter: str, target: RemediationTarget | None = None,
            notes: Iterable[str] = ()) -> RemediationResult:
    return RemediationResult(operation, RemediationOutcome.BLOCKED, adapter, gates, target, notes=tuple(notes))


# --- target resolution -----------------------------------------------------------------


def resolve_target(candidate: LifecycleCandidate, operation: RemediationOperation, target_ref: object,
                   evidence: EvidenceBundle) -> tuple[RemediationTarget | None, list[str]]:
    """The request's one target, with its identity taken from recorded evidence, or why not."""
    spec = OPERATIONS[operation]
    id_kind = TARGET_ID_KINDS[spec.target_kind]
    try:
        check_id(target_ref, id_kind, "target")
    except InvalidRecord:
        return None, [f"{operation.value} names exactly one {spec.target_kind.value} target by its OGWA id "
                      f"({id_kind.value}_<32 hex>)"]
    if spec.target_kind is TargetKind.OKTA_ASSIGNMENT:
        return _okta_assignment_target(candidate, str(target_ref), evidence)
    return _ad_group_target(str(target_ref), evidence)


def _okta_assignment_target(candidate: LifecycleCandidate, ref: str,
                            ev: EvidenceBundle) -> tuple[RemediationTarget | None, list[str]]:
    if ref not in candidate.assignment_ids:
        return None, [f"assignment {ref} is not one of this candidate's assignments"]
    assignment = ev.assignment(ref)
    if assignment is None:
        return None, [f"no observation of assignment {ref}"]
    application = next((a for a in ev.applications if a.id == assignment.application_id), None)
    group = ev.okta_group
    problems = []
    if application is None:
        problems.append(f"no observation of application {assignment.application_id}")
    if group is None or group.id != candidate.okta_group_id or assignment.okta_group_id != group.id:
        problems.append("the assignment is not an observed assignment of this candidate's Okta group")
    if problems:
        return None, problems
    identity = tuple(sorted({
        "application_id": application.id, "assignment_id": assignment.id, "okta_app_id": application.okta_app_id,
        "okta_group_external_id": group.okta_group_id, "okta_group_id": group.id,
    }.items()))
    return RemediationTarget(TargetKind.OKTA_ASSIGNMENT, ref, identity), []


def _ad_group_target(ref: str, ev: EvidenceBundle) -> tuple[RemediationTarget | None, list[str]]:
    mapping, ad = ev.mapping, ev.ad_group
    if mapping is None or mapping.ad_group_id is None:
        return None, ["the candidate has no mapped AD group"]
    if ref != mapping.ad_group_id:
        return None, [f"{ref} is not the candidate's mapped AD group"]
    if ad is None or ad.id != ref:
        return None, [f"no observation of AD group {ref}"]
    if not ad.exists:
        return None, ["the target AD group was observed not to exist"]
    identity = tuple(sorted({
        "ad_group_id": ad.id, "distinguished_name": ad.distinguished_name, "domain": ad.domain.lower(),
        "object_guid": ad.object_guid, "sam_account_name": ad.sam_account_name, "sid": ad.sid,
    }.items()))
    return RemediationTarget(TargetKind.AD_GROUP, ref, identity), []


# --- gates ---------------------------------------------------------------------------


def _mode(mode: object, requested_mode: object) -> list[str]:
    problems = []
    if not isinstance(mode, ExecutionMode):
        problems.append("the execution mode is unknown")
    elif mode not in DRY_RUN_MODES:
        problems.append(f"{mode.value} cannot plan a mutation; a remediation dry run needs DRY_RUN_MUTATION planning")
    if requested_mode is not None and requested_mode is not ExecutionMode.DRY_RUN_MUTATION:
        label = requested_mode.value if isinstance(requested_mode, ExecutionMode) else "an unknown mode"
        problems.append(f"a remediation may request only DRY_RUN_MUTATION, not {label}")
    return problems


def _mapping(c: LifecycleCandidate, ev: EvidenceBundle) -> list[str]:
    m, ad = ev.mapping, ev.ad_group
    if m is None:
        return ["no identity mapping recorded"]
    problems = []
    if m.okta_group_id != c.okta_group_id:
        problems.append("the identity mapping is for a different Okta group")
    if not m.is_exact:
        problems.append(f"mapping confidence {m.confidence.value} is not exact; a remediation needs an exact mapping "
                        "(name-only and unverified identifiers never qualify)")
    if not m.provenance.decision_grade:
        problems.append(f"the mapping observation is {m.provenance.result_status.value}, not COMPLETE")
    if ad is None:
        problems.append("the mapped AD group has not been observed")
    elif ad.id != m.ad_group_id:
        problems.append("the observed AD group is not the mapped one")
    elif not ad.exists:
        problems.append("the mapped AD group was observed not to exist")
    return problems


def _fresh(ev: EvidenceBundle, now: datetime, policy: LifecyclePolicy) -> list[str]:
    problems = []
    for r in ev.records():
        # As in the lifecycle: an incomplete dependency check does not count toward coverage
        # (NO_DEPENDENCY_BLOCKER reports that); every other record must be usable.
        if isinstance(r, DependencyEvidence) and not r.provenance.decision_grade:
            continue
        problems.extend(freshness_problems(f"{r.KIND.value} {r.id}", r.provenance, EvidencePurpose.EXECUTION, now,
                                           policy.freshness))
    return problems


def _protection(ev: EvidenceBundle, policy: LifecyclePolicy) -> list[str]:
    problems = [f"protected: {r}" for r in protection_reasons(ev, policy)]
    if ev.okta_group is None:
        problems.append("the Okta group has not been observed, so its protection cannot be determined")
    if ev.ad_group is not None and not ev.ad_group.provenance.decision_grade:
        problems.append("the AD group observation is not COMPLETE, so its protection cannot be determined; "
                        "unknown protection blocks and cannot be overridden (D21)")
    return problems


def _approval(c: LifecycleCandidate, spec: OperationSpec, approval: ApprovalRecord | None, now: datetime,
              policy: LifecyclePolicy) -> list[str]:
    rules = stage_approval_rules(c, spec.stage)
    return [*rules.unmet, *approval_problems(
        approval, candidate_id=c.id, candidate_epoch=c.epoch, proposed_by=c.proposed_by, stage=spec.stage, now=now,
        max_ttl=policy.approval_max_ttl, clock_skew=policy.freshness.clock_skew,
        evidence_fingerprint=None,  # APPROVAL_FINGERPRINT_MATCHES reports a mismatch on its own
        not_before=rules.not_before, given_after=rules.given_after,
        excluded_approvers=rules.excluded_problems(spec.stage),
    )]


def _fingerprint(approval: ApprovalRecord | None, current: str) -> list[str]:
    if approval is None:
        return ["no approval to compare with the current evidence"]
    if approval.evidence_fingerprint != current:
        return [f"the approval was given on evidence {approval.evidence_fingerprint[:19]}…, but the evidence is now "
                f"{current[:19]}…; material evidence (or the target's identity) changed, so a new approval is needed"]
    return []


def _dependencies(spec: OperationSpec, ev: EvidenceBundle, policy: LifecyclePolicy) -> list[str]:
    problems = [f"blocking dependency ({d.kind.value}): {f.description}" for d in ev.dependencies
                for f in d.blocking_findings]
    problems += _membership(ev)
    if spec.ad_operation:
        coverage = ev.dependency_coverage(policy.required_dependency_kinds)
        if coverage is not DependencyCoverage.COMPLETE:
            problems.append(f"dependency coverage is {coverage.value}; an AD remediation requires COMPLETE")
    return problems


def _membership(ev: EvidenceBundle) -> list[str]:
    """Known members, or membership evidence that is missing or incomplete, block every
    operation, the Okta unassignment included (D132). The direct member count and the
    two membership checks stay separate facts (D20)."""
    mapped = ev.mapping.ad_group_id if ev.mapping is not None else None
    if mapped is None:
        return ["membership evidence is unknown: the candidate has no mapped AD group (D132)"]
    problems = []
    ad = ev.ad_group
    if ad is not None and ad.id == mapped and ad.exists:
        if ad.member_count is None:
            problems.append("the AD group's direct member count is unknown; unknown membership blocks every "
                            "remediation (D132)")
        elif ad.member_count > 0:
            problems.append(f"the AD group has {ad.member_count} direct member(s); members block every remediation "
                            "(D36, D132)")
    for kind in MEMBERSHIP_KINDS:
        check = next((d for d in ev.dependencies if d.kind is kind and d.subject_id == mapped), None)
        if check is None:
            problems.append(f"no {kind.value} check of the mapped AD group: unknown membership blocks every "
                            "remediation (D132)")
        elif not check.provenance.decision_grade:
            problems.append(f"the {kind.value} check is {check.provenance.result_status.value}: incomplete membership "
                            "evidence blocks every remediation (D132)")
    return problems


def _separation(approval: ApprovalRecord | None, requested_by: Actor) -> list[str]:
    problems = []
    if not isinstance(requested_by, Actor) or requested_by.kind is not ActorKind.HUMAN:
        problems.append("a remediation dry run is requested by a named human")
    elif approval is not None and approval.operator == requested_by:
        problems.append("the approver of this stage cannot request its remediation dry run (D49)")
    return problems


def _lifecycle(c: LifecycleCandidate, spec: OperationSpec, ev: EvidenceBundle, policy: LifecyclePolicy,
               quarantine_ous: QuarantineOus | None) -> list[str]:
    if c.state not in spec.states:
        allowed = " or ".join(sorted(s.value for s in spec.states))
        return [f"the candidate is {c.state.value}; {spec.operation.value} is dry-run only in {allowed}"]
    problems = [*_consistency(c, ev), *_ad_workflow_origin(ev, policy)]
    if spec.stage is ApprovalStage.OKTA_UNASSIGN:
        problems += _assignments_present(c, ev, expected=True)
        problems += _usage_rules(c, ev, policy)
    else:
        problems += [f"{m} (re-added during the hold?)" for m in _assignments_present(c, ev, expected=False)]
        if ev.ad_group is not None and ev.ad_group.exists:
            quarantined = spec.operation is RemediationOperation.AD_GROUP_DELETE
            problems += quarantine_location_problems(ev.ad_group, quarantine_ous, quarantined=quarantined)
    return problems


def _usage_rules(c: LifecycleCandidate, ev: EvidenceBundle, policy: LifecyclePolicy) -> list[str]:
    """The lifecycle's usage rules for unassignment, without its freshness check (which
    FRESH_EVIDENCE reports). The stage-guard backstop still runs the lifecycle's own copy."""
    problems = []
    applications = dict.fromkeys(a.application_id for a in ev.assignments if a.id in c.assignment_ids)
    for app_id in applications:
        u = ev.usage_for(app_id, c.okta_group_id)
        if u is None:
            problems.append(f"no usage observation for application {app_id}")
            continue
        if u.window < policy.min_usage_window:
            problems.append(f"usage window for {app_id} is shorter than {policy.min_usage_window}")
        if u.event_count > policy.max_usage_events_for_candidate:
            problems.append(f"application {app_id} had {u.event_count} sign-ins in the window "
                            f"(threshold {policy.max_usage_events_for_candidate})")
    return problems


def _stage_guard(c: LifecycleCandidate, spec: OperationSpec, ev: EvidenceBundle, approval: ApprovalRecord,
                 now: datetime, policy: LifecyclePolicy, fingerprint: str,
                 quarantine_ous: QuarantineOus | None) -> list[str]:
    """The lifecycle's own guard for the stage's evidence rules, with a successful hypothetical
    dry-run job: a rule the gates above miss still blocks. Records nothing."""
    targets = c.assignment_ids if spec.job_kind is JobKind.OKTA_UNASSIGN else (
        (ev.ad_group.id,) if ev.ad_group is not None else ())
    if not targets:
        return ["the stage's dry-run step has no target"]
    job = ExecutionJob(id=new_id(IdKind.EXECUTION_JOB), candidate_id=c.id, kind=spec.job_kind,
                       mode=ExecutionMode.DRY_RUN_MUTATION, dry_run=True, status=JobStatus.SUCCEEDED,
                       requested_by=PRECHECK_ACTOR, requested_at=now, approval_id=approval.id,
                       evidence_fingerprint=fingerprint, targets=targets, finished_at=now)
    rule = TRANSITIONS[spec.guard_step]
    request = TransitionRequest(target=spec.guard_step[1], actor=PRECHECK_ACTOR, reason="remediation gate precheck",
                                now=now, evidence=ev, approval=approval, job=job, quarantine_ous=quarantine_ous)
    return rule.guard(c, request, policy, fingerprint)


@dataclass(frozen=True)
class GateEvaluation:
    report: GateReport
    target: RemediationTarget | None
    fingerprint: str  # the evidence fingerprint the gates were evaluated on


def evaluate_gates(
    candidate: LifecycleCandidate,
    operation: RemediationOperation,
    target_ref: object,
    evidence: EvidenceBundle,
    approval: ApprovalRecord | None,
    policy: LifecyclePolicy,
    *,
    now: datetime,
    mode: object,
    requested_by: Actor,
    requested_mode: object = None,
    quarantine_ous: QuarantineOus | None = None,
) -> GateEvaluation:
    """Evaluate every gate. Pure: records nothing and reads nothing but its arguments.

    ``quarantine_ous`` is the deployment's quarantine OU configuration (D136); without it no
    AD operation passes."""
    if not isinstance(candidate, LifecycleCandidate) or not isinstance(evidence, EvidenceBundle):
        raise TypeError("evaluate_gates needs a LifecycleCandidate and an EvidenceBundle")
    if not isinstance(policy, LifecyclePolicy):
        raise TypeError("policy must be a LifecyclePolicy")
    check_enum(operation, RemediationOperation, "operation")
    if approval is not None and not isinstance(approval, ApprovalRecord):
        raise TypeError("approval must be an ApprovalRecord or None")
    spec = OPERATIONS[operation]
    fingerprint = evidence_fingerprint(evidence)
    target, target_problems = resolve_target(candidate, operation, target_ref, evidence)
    problems: dict[Gate, list[str]] = {
        Gate.EXECUTION_MODE_PERMITS_DRY_RUN: _mode(mode, requested_mode),
        Gate.SINGLE_EXPLICIT_TARGET: target_problems,
        Gate.EXACT_VERIFIED_MAPPING: _mapping(candidate, evidence),
        Gate.FRESH_EVIDENCE: _fresh(evidence, now, policy),
        Gate.NOT_PROTECTED: _protection(evidence, policy),
        Gate.VALID_APPROVAL: _approval(candidate, spec, approval, now, policy),
        Gate.APPROVAL_FINGERPRINT_MATCHES: _fingerprint(approval, fingerprint),
        Gate.NO_DEPENDENCY_BLOCKER: _dependencies(spec, evidence, policy),
        Gate.SEPARATION_OF_DUTIES: _separation(approval, requested_by),
        Gate.LIFECYCLE_RULES: _lifecycle(candidate, spec, evidence, policy, quarantine_ous),
    }
    if approval is not None and not any(problems.values()):
        problems[Gate.LIFECYCLE_RULES] = _stage_guard(candidate, spec, evidence, approval, now, policy, fingerprint,
                                                      quarantine_ous)
    report = GateReport(tuple(GateCheck(g, tuple(problems[g])) for g in Gate))
    return GateEvaluation(report, target, fingerprint)
