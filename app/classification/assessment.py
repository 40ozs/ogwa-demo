"""Evidence quality and the control decision it allows.

``assess`` answers, for one lifecycle candidate, the questions a reviewer asks before
anything is done to a group:

1. What is the proposed governance issue?
2. Which sources support it?
3. Which sources disagree, conflict, or are unavailable?
4. How sure is the identity mapping?
5. What decision can OGWA safely make now?
6. What evidence would it need to go further?

It is a reading of evidence the store already holds and of the classifier's own reasons.
It decides nothing the lifecycle does not: the classifier says which retirement conditions
are proven, the lifecycle guard (evaluated by the caller, see ``PendingStep``) says whether
the next approval could be recorded, and this module only puts both in front of a person,
per source. It adds one thing the classifier does not report: **conflicts**, where two
observations of the same fact disagree (for example, the AD group object lists members and
the membership read found none). A conflict is never resolved here; it is shown.

Rules that never bend:

- Every evidence state stays distinct. "Never collected", "the source could not be read",
  "a partial read", "the source says none", "the identity is not established", "two sources
  disagree", and "confirmed" are different facts and are never merged into one empty value.
- Missing, partial, failed, ambiguous, stale, or conflicting evidence never makes a
  candidate eligible. ``ELIGIBLE_FOR_HUMAN_APPROVAL`` needs every retirement condition proven
  by the classifier, no conflict, every required source decision-grade, an open approval
  step, and the lifecycle guard for that step accepting a named human's approval. Even then
  it is not an approval: a named human decides, and this build only plans dry runs (D8).
- Like the classifier, the module is pure: no I/O, no clock, no store, no network.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.classification.classifier import ClassificationResult
from app.classification.reasons import (
    REASON_EFFECTS,
    RETIREMENT_CANDIDATE_REQUIRES,
    Classification,
    Reason,
    ReasonCode,
)
from app.domain.approval import ApprovalStage
from app.domain.candidate_policy import CandidatePolicy
from app.domain.evidence import Evidence, EvidenceSource, ResultStatus
from app.domain.lifecycle import TERMINAL_STATES, LifecycleCandidate, LifecycleState
from app.domain.model import (
    COVERAGE_SOURCES,
    ApplicationGroupAssignment,
    DependencyEvidence,
    DependencyKind,
    FindingCode,
    IdentityMapping,
    MappingConfidence,
)
from app.domain.policy import EvidenceBundle

R = ReasonCode
C = Classification


class EvidenceState(StrEnum):
    """What one source says, as a fact about collection and content. Never merged."""

    CONFIRMED = "CONFIRMED"  # a complete read with a positive value (assigned, exists, exact, findings)
    REPORTS_NONE = "REPORTS_NONE"  # a complete read that says none: not assigned, 0 sign-ins, no finding, not found
    NOT_COLLECTED = "NOT_COLLECTED"  # no observation is recorded at all
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"  # an observation was attempted and FAILED: the source could not be read
    PARTIAL = "PARTIAL"  # the read was incomplete; positive facts count, absence is never proven
    NOT_COUNTED_SOURCE = "NOT_COUNTED_SOURCE"  # checked only by a source that never proves absence (attestation, D13)
    AMBIGUOUS = "AMBIGUOUS"  # the identity is not established (probable, name-only, ambiguous, not exact)
    CONFLICTING = "CONFLICTING"  # this observation disagrees with another one about the same fact


DECISION_GRADE_STATES = frozenset({EvidenceState.CONFIRMED, EvidenceState.REPORTS_NONE})


class Freshness(StrEnum):
    CURRENT = "CURRENT"  # decision-grade and within the policy's review window
    STALE = "STALE"  # complete once, older than the review window
    FUTURE_DATED = "FUTURE_DATED"  # dated beyond the clock-skew tolerance: invalid, neither fresh nor stale
    NOT_ASSESSED = "NOT_ASSESSED"  # nothing to judge: not collected, not decision-grade, or no classification


class Stance(StrEnum):
    SUPPORTS = "SUPPORTS"  # the observation supports the proposal
    DISAGREES = "DISAGREES"  # the observation is a reason not to act (members, use, a reference, protection)
    UNKNOWN = "UNKNOWN"  # the observation cannot support or refute it (missing, failed, ambiguous)


class IdentityState(StrEnum):
    CONFIRMED = "CONFIRMED"  # an EXACT_* mapping from a complete correlation
    PROBABLE = "PROBABLE"  # one AD object, but by name only or an unverified identifier (D37, D56)
    AMBIGUOUS = "AMBIGUOUS"  # several possible AD objects, or a confidence that is not exact
    NOT_FOUND = "NOT_FOUND"  # no AD counterpart (complete)
    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # no mapping evidence at all
    UNAVAILABLE = "UNAVAILABLE"  # the correlation did not finish (PARTIAL) or failed (FAILED)


class Decision(StrEnum):
    """What OGWA can safely conclude now. Only the last is not a non-action result."""

    TERMINAL = "TERMINAL"  # the candidate is terminal: nothing further is decided
    NO_ACTION_BLOCKED = "NO_ACTION_BLOCKED"  # a positive fact stops it: protected, members, in use, referenced
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"  # two required observations disagree
    AMBIGUOUS_IDENTITY = "AMBIGUOUS_IDENTITY"  # the AD counterpart is not established exactly
    BLOCKED_ON_REQUIRED_SOURCE = "BLOCKED_ON_REQUIRED_SOURCE"  # a required source could not be read
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # required evidence missing, partial, stale, or unproven
    NO_APPROVAL_OPEN = "NO_APPROVAL_OPEN"  # evidence aside, the lifecycle has no approval open in this state
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"  # evidence is decision-grade, but a person must judge
    LIFECYCLE_RULES_NOT_MET = "LIFECYCLE_RULES_NOT_MET"  # the lifecycle guard refuses the open step
    ELIGIBLE_FOR_HUMAN_APPROVAL = "ELIGIBLE_FOR_HUMAN_APPROVAL"  # may be put to a named human; not an approval


# Most restrictive first: the first that applies is the decision; all that apply are listed.
DECISION_PRECEDENCE: tuple[Decision, ...] = tuple(Decision)
NON_ACTION_DECISIONS = frozenset(Decision) - {Decision.ELIGIBLE_FOR_HUMAN_APPROVAL}

DECISION_LABEL: dict[Decision, str] = {
    Decision.TERMINAL: "No decision pending: terminal",
    Decision.NO_ACTION_BLOCKED: "No action: a positive fact stops this candidate",
    Decision.CONFLICTING_EVIDENCE: "No action: sources disagree",
    Decision.AMBIGUOUS_IDENTITY: "No action: identity not established",
    Decision.BLOCKED_ON_REQUIRED_SOURCE: "No action: a required source could not be read",
    Decision.INSUFFICIENT_EVIDENCE: "No action: insufficient evidence",
    Decision.NO_APPROVAL_OPEN: "No action: no approval is open in this state",
    Decision.MANUAL_REVIEW_REQUIRED: "Manual review required",
    Decision.LIFECYCLE_RULES_NOT_MET: "No action: the lifecycle would refuse the next step",
    Decision.ELIGIBLE_FOR_HUMAN_APPROVAL: "Eligible for a named human's approval (not an approval)",
}

# Classifications that are positive stopping facts (the classifier's PRECEDENCE, before evidence problems).
_STOPPING = frozenset({C.PROTECTED, C.ACTIVE, C.DEPENDENCY_BLOCKED, C.HAS_MEMBERS, C.NESTED_DEPENDENCY,
                       C.SHARED_OKTA_ASSIGNMENT})
# Classifier outcomes that describe evidence quality rather than a fact about the group.
_EVIDENCE_OUTCOMES = frozenset({C.EVIDENCE_INCOMPLETE, C.STALE_EVIDENCE, C.MAPPING_REQUIRED})

ALL_STAGES = (ApprovalStage.OKTA_UNASSIGN, ApprovalStage.AD_QUARANTINE, ApprovalStage.AD_DELETION)
AD_STAGES = (ApprovalStage.AD_QUARANTINE, ApprovalStage.AD_DELETION)
STAGE_LABEL = {ApprovalStage.OKTA_UNASSIGN: "Okta unassignment", ApprovalStage.AD_QUARANTINE: "AD quarantine",
               ApprovalStage.AD_DELETION: "AD deletion"}

# Which lifecycle stages' guards read each kind of item (app/domain/lifecycle.py). Every
# stage needs the Okta group, the candidate's assignments, the mapping, and the AD group
# (_consistency, _exact_mapping); only the Okta unassignment reads usage (_usage); only the AD
# stages require COMPLETE dependency coverage and a known-empty member count (D131, D132).
# The classifier's retirement conditions need all of them (``required``), a superset (P-8).
_NEEDED_FOR = {
    "okta-group": ALL_STAGES,
    "assignment": ALL_STAGES,
    "usage": (ApprovalStage.OKTA_UNASSIGN,),
    "mapping": ALL_STAGES,
    "ad-group": ALL_STAGES,
    "dependency": AD_STAGES,
    "application": (),
    "other-assignment": (),
}

_SYSTEM = {
    EvidenceSource.OKTA_API: "Okta",
    EvidenceSource.OKTA_SYSTEM_LOG: "Okta System Log",
    EvidenceSource.AD_VIA_AAP: "Active Directory (read-only AAP job)",
    EvidenceSource.CONFIGURED_MAPPING: "Reviewed mapping configuration",
    EvidenceSource.OPERATOR_ATTESTATION: "Operator attestation",
    EvidenceSource.SYNTHETIC: "Synthetic demo source",
}

_KIND_LABEL = {
    DependencyKind.OKTA_OTHER_APP_ASSIGNMENT: "Other Okta application assignments",
    DependencyKind.OKTA_POLICY_REFERENCE: "Okta policy and group-rule references",
    DependencyKind.AD_GROUP_MEMBERS: "AD members and primaryGroupID references",
    DependencyKind.AD_NESTED_MEMBERSHIP: "AD nesting (parents and member groups)",
    DependencyKind.AD_ACL_REFERENCE: "AD ACL references",
    DependencyKind.GPO_REFERENCE: "GPO references",
    DependencyKind.AAP_REFERENCE: "AAP references",
    DependencyKind.APPLICATION_CONFIGURATION: "Application-side configuration",
    DependencyKind.OTHER: "Other dependencies",
}

# Reason codes that belong to one item kind regardless of their subject.
_DEPENDENCY_REASONS = {
    R.AD_GROUP_EMPTY: DependencyKind.AD_GROUP_MEMBERS,
    R.AD_MEMBERSHIP_UNKNOWN: DependencyKind.AD_GROUP_MEMBERS,
    R.AD_NO_PARENT_GROUPS: DependencyKind.AD_NESTED_MEMBERSHIP,
    R.AD_NESTING_UNKNOWN: DependencyKind.AD_NESTED_MEMBERSHIP,
    R.SINGLE_OKTA_ASSIGNMENT: DependencyKind.OKTA_OTHER_APP_ASSIGNMENT,
    R.OTHER_ASSIGNMENTS_UNKNOWN: DependencyKind.OKTA_OTHER_APP_ASSIGNMENT,
}
_APP_REASONS = {
    "application": {R.APP_INACTIVE, R.APPLICATION_NOT_OBSERVED},
    "usage": {R.IN_USE, R.LOW_USAGE, R.NO_OBSERVED_USAGE, R.NO_RECENT_LOGIN, R.USAGE_WITHIN_RETIREMENT_THRESHOLD,
              R.USAGE_ABOVE_RETIREMENT_THRESHOLD, R.USAGE_WINDOW_COVERS_RETIREMENT, R.USAGE_WINDOW_REVIEW_ONLY,
              R.USAGE_WINDOW_TOO_SHORT, R.USAGE_NOT_OBSERVED},
    "assignment": {R.ASSIGNMENT_PRESENT, R.ASSIGNMENT_ABSENT, R.ASSIGNMENT_NOT_OBSERVED},
    "other-assignment": {R.SHARED_OKTA_ASSIGNMENT},
}
_OKTA_GROUP_REASONS = {R.OKTA_GROUP_NOT_OBSERVED, R.AD_SOURCED_GROUP, R.OKTA_ONLY_GROUP, R.NOT_AD_SOURCED}
_MAPPING_REASONS = {R.EXACT_MAPPING, R.MAPPING_MISSING, R.MAPPING_NAME_ONLY, R.MAPPING_AMBIGUOUS, R.MAPPING_NOT_FOUND,
                    R.MAPPING_UNVERIFIED_IDENTIFIER, R.MAPPING_NOT_EXACT}
_AD_GROUP_REASONS = {R.AD_GROUP_NOT_OBSERVED, R.AD_GROUP_NOT_FOUND, R.NOT_PROTECTED, R.PROTECTION_UNDETERMINED}
_RECORD_REASONS = {R.EVIDENCE_STALE, R.EVIDENCE_FUTURE_DATED, R.EVIDENCE_NOT_DECISION_GRADE, R.EVIDENCE_INCONSISTENT}


@dataclass(frozen=True)
class EvidenceItem:
    key: str  # stable within one assessment: okta-group, application:<id>, dependency:<KIND>, ...
    kind: str  # okta-group, application, assignment, other-assignment, usage, mapping, ad-group, dependency
    label: str
    system: str  # the system the observation came from, or would come from
    record_id: str | None
    source: str | None  # the provenance source, when a record exists
    result_status: str | None
    observed_at: datetime | None
    observation: str  # what the source says, in words
    state: EvidenceState
    base_state: EvidenceState  # the state before any conflict is applied
    freshness: Freshness
    stance: Stance
    required: bool  # needed by the classifier's retirement conditions under the policy in force
    needed_for: tuple[ApprovalStage, ...]  # lifecycle stages whose guards read this item
    reasons: tuple[str, ...] = ()  # the classifier's reason codes attached to this item
    conflicts: tuple[str, ...] = ()  # conflict codes this item takes part in

    @property
    def decision_grade(self) -> bool:
        return self.state in DECISION_GRADE_STATES and self.freshness is Freshness.CURRENT

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "kind": self.kind, "label": self.label, "system": self.system,
            "recordId": self.record_id, "source": self.source, "resultStatus": self.result_status,
            "observedAt": self.observed_at.isoformat() if self.observed_at else None,
            "observation": self.observation, "state": self.state.value, "baseState": self.base_state.value,
            "freshness": self.freshness.value, "stance": self.stance.value, "decisionGrade": self.decision_grade,
            "required": self.required, "neededFor": [s.value for s in self.needed_for],
            "reasons": list(self.reasons), "conflicts": list(self.conflicts),
        }


@dataclass(frozen=True)
class Conflict:
    code: str
    title: str
    summary: str
    item_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "title": self.title, "summary": self.summary, "itemKeys": list(self.item_keys)}


def _when(at: datetime) -> str:
    return at.strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class IdentityAssessment:
    state: IdentityState
    confidence: str | None
    decision_grade: bool
    detail: str
    matched_attributes: tuple[str, ...] = ()
    candidate_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "confidence": self.confidence, "decisionGrade": self.decision_grade,
                "detail": self.detail, "matchedAttributes": list(self.matched_attributes),
                "candidateCount": self.candidate_count}


@dataclass(frozen=True)
class PendingStep:
    """The candidate's next approval step and, when it is open, the lifecycle guard's answer.

    The caller evaluates the guard with the real ``apply_transition`` and a hypothetical,
    never-recorded approval (the same precheck an approval request gets), so this module
    never re-implements a guard.
    """

    stage: ApprovalStage | None  # None: terminal, nothing further
    open: bool  # the candidate is in the state where this stage is approved
    evaluated: bool  # the guard was evaluated
    accepts: bool  # the guard would accept a named human's approval on this evidence
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"stage": self.stage.value if self.stage else None,
                "label": STAGE_LABEL.get(self.stage) if self.stage else None,
                "open": self.open, "evaluated": self.evaluated, "accepts": self.accepts,
                "problems": list(self.problems)}


@dataclass(frozen=True)
class Constraint:
    decision: Decision
    detail: str
    item_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "label": DECISION_LABEL[self.decision], "detail": self.detail,
                "itemKeys": list(self.item_keys)}


@dataclass(frozen=True)
class EvidenceAssessment:
    candidate_id: str
    state: LifecycleState
    issue: dict[str, Any]
    items: tuple[EvidenceItem, ...]
    conflicts: tuple[Conflict, ...]
    identity: IdentityAssessment
    pending: PendingStep
    decision: Decision
    constraints: tuple[Constraint, ...]
    needed: tuple[str, ...]
    classification: str | None
    evidence_fingerprint: str | None
    assessed_at: datetime | None = None
    notes: tuple[str, ...] = field(default=())

    @property
    def eligible(self) -> bool:
        return self.decision is Decision.ELIGIBLE_FOR_HUMAN_APPROVAL

    def item(self, key: str) -> EvidenceItem:
        return next(i for i in self.items if i.key == key)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {s.value: 0 for s in EvidenceState}
        for i in self.items:
            counts[i.state.value] += 1
        return {
            "candidateId": self.candidate_id,
            "lifecycleState": self.state.value,
            "isApproval": False,
            "decision": {"code": self.decision.value, "label": DECISION_LABEL[self.decision],
                         "eligibleForHumanApproval": self.eligible, "autoRemediationEligible": False},
            "constraints": [c.to_dict() for c in self.constraints],
            "issue": self.issue,
            "identity": self.identity.to_dict(),
            "pendingStep": self.pending.to_dict(),
            "items": [i.to_dict() for i in self.items],
            "conflicts": [c.to_dict() for c in self.conflicts],
            "needed": list(self.needed),
            "stateCounts": counts,
            "classification": self.classification,
            "evidenceFingerprint": self.evidence_fingerprint,
            "assessedAt": self.assessed_at.isoformat() if self.assessed_at else None,
            "notes": list(self.notes),
        }


# --- the assessment ------------------------------------------------------------------------


def next_stage(candidate: LifecycleCandidate) -> ApprovalStage | None:
    """The next approval stage the candidate faces, from what its lifecycle has recorded."""
    if candidate.state in TERMINAL_STATES:
        return None
    if candidate.hold_until is None:
        return ApprovalStage.OKTA_UNASSIGN
    if candidate.quarantine_hold_until is None:
        return ApprovalStage.AD_QUARANTINE
    return ApprovalStage.AD_DELETION


def assess(candidate: LifecycleCandidate, bundle: EvidenceBundle, classification: ClassificationResult | None,
           policy: CandidatePolicy | None, pending: PendingStep) -> EvidenceAssessment:
    """Assess ``candidate``'s evidence. ``classification`` is None when the server could not classify."""
    if not isinstance(bundle, EvidenceBundle):
        raise TypeError("bundle must be an EvidenceBundle")
    if not isinstance(pending, PendingStep):
        raise TypeError("pending must be a PendingStep")
    reasons = classification.reasons if classification is not None else ()
    required_kinds = policy.lifecycle.required_dependency_kinds if policy is not None else frozenset(DependencyKind)
    app_ids = tuple(dict.fromkeys(a.application_id for a in bundle.assignments if a.id in candidate.assignment_ids))
    builder = _Builder(bundle, reasons, classification is not None)

    _okta_group(builder, bundle)
    for app_id in app_ids:
        _application(builder, bundle, app_id)
        _assignment(builder, bundle, candidate, app_id)
        _usage(builder, bundle, candidate, app_id)
    _other_assignments(builder, bundle, candidate, app_ids)
    _mapping(builder, bundle)
    _ad_group(builder, bundle)
    for kind in sorted(required_kinds | {d.kind for d in builder.related_dependencies()}):
        _dependency(builder, bundle, kind, kind in required_kinds)

    conflicts = _conflicts(builder, bundle, candidate, app_ids, reasons)
    items = builder.finish(conflicts)
    identity = _identity(bundle.mapping)
    constraints = _constraints(candidate, items, conflicts, identity, classification, pending)
    decision = constraints[0].decision if constraints else Decision.ELIGIBLE_FOR_HUMAN_APPROVAL
    return EvidenceAssessment(
        candidate_id=candidate.id, state=candidate.state, issue=_issue(candidate, bundle, app_ids), items=items,
        conflicts=conflicts, identity=identity, pending=pending, decision=decision, constraints=constraints,
        needed=_needed(items, conflicts, identity, pending, constraints),
        classification=classification.classification.value if classification else None,
        evidence_fingerprint=classification.evidence_fingerprint if classification else None,
        assessed_at=classification.classified_at if classification else None,
        notes=_notes(decision, pending),
    )


# --- items -----------------------------------------------------------------------------------


class _Builder:
    def __init__(self, bundle: EvidenceBundle, reasons: tuple[Reason, ...], classified: bool) -> None:
        self.bundle = bundle
        self.reasons = reasons
        self.classified = classified
        self.items: list[dict[str, Any]] = []

    def related_dependencies(self) -> list[DependencyEvidence]:
        m = self.bundle.mapping
        related = {self.bundle.okta_group.id} if self.bundle.okta_group else set()
        if m is not None and m.ad_group_id:
            related.add(m.ad_group_id)
        return [d for d in self.bundle.dependencies if d.subject_id in related]

    def claim(self, predicate) -> tuple[str, ...]:
        """The codes of the classifier's reasons that ``predicate`` attaches to an item."""
        return tuple(dict.fromkeys(r.code.value for r in self.reasons if predicate(r)))

    def record_reasons(self, record: Evidence | None) -> tuple[str, ...]:
        if record is None:
            return ()
        return self.claim(lambda r: r.code in _RECORD_REASONS and r.subject == record.id)

    def freshness(self, record: Evidence | None) -> Freshness:
        if record is None or not record.provenance.decision_grade or not self.classified:
            return Freshness.NOT_ASSESSED
        codes = {r.code for r in self.reasons if r.subject == record.id}
        if R.EVIDENCE_FUTURE_DATED in codes:
            return Freshness.FUTURE_DATED
        if R.EVIDENCE_STALE in codes:
            return Freshness.STALE
        return Freshness.CURRENT

    def add(self, *, key: str, kind: str, label: str, record: Evidence | None, observation: str,
            state: EvidenceState, stance: Stance, required: bool, reasons: tuple[str, ...] = (),
            system: str | None = None) -> None:
        p = record.provenance if record is not None else None
        codes = tuple(dict.fromkeys(reasons + self.record_reasons(record)))
        self.items.append(dict(
            key=key, kind=kind, label=label,
            system=system or (_SYSTEM.get(p.source, p.source.value) if p else "—"),
            record_id=record.id if record is not None else None,
            source=p.source.value if p else None, result_status=p.result_status.value if p else None,
            observed_at=p.observed_at if p else None, observation=observation, base_state=state,
            freshness=self.freshness(record), stance=stance, required=required,
            needed_for=_NEEDED_FOR[kind], reasons=codes))

    def finish(self, conflicts: tuple[Conflict, ...]) -> tuple[EvidenceItem, ...]:
        involved: dict[str, list[str]] = {}
        for c in conflicts:
            for key in c.item_keys:
                involved.setdefault(key, []).append(c.code)
        out = []
        for raw in self.items:
            codes = tuple(involved.get(raw["key"], ()))
            state = EvidenceState.CONFLICTING if codes else raw["base_state"]
            out.append(EvidenceItem(state=state, conflicts=codes, **raw))
        return tuple(out)


def _status_state(record: Evidence) -> EvidenceState | None:
    status = record.provenance.result_status
    if status is ResultStatus.FAILED:
        return EvidenceState.SOURCE_UNAVAILABLE
    if status is ResultStatus.PARTIAL:
        return EvidenceState.PARTIAL
    return None


def _reason_stance(codes: tuple[str, ...]) -> Stance:
    """A blocking fact disagrees; a supporting reason supports; evidence problems say nothing."""
    effects = [REASON_EFFECTS[ReasonCode(c)] for c in codes]
    if any(e.blocks and e.outcome not in _EVIDENCE_OUTCOMES for e in effects):
        return Stance.DISAGREES
    if any(not e.blocks for e in effects):
        return Stance.SUPPORTS
    return Stance.UNKNOWN


def _okta_group(b: _Builder, bundle: EvidenceBundle) -> None:
    g = bundle.okta_group
    codes = b.claim(lambda r: r.code in _OKTA_GROUP_REASONS
                    or (r.code is R.PROTECTED_GROUP and bundle.ad_group is None))
    if g is None:
        b.add(key="okta-group", kind="okta-group", label="Okta group", record=None, system="Okta",
              observation="No observation of the Okta group", state=EvidenceState.NOT_COLLECTED,
              stance=Stance.UNKNOWN, required=True, reasons=codes)
        return
    origin = f"imported from directory {g.source_directory_id}" if g.source_directory_id else "mastered in Okta"
    b.add(key="okta-group", kind="okta-group", label="Okta group", record=g,
          observation=f"{g.name} ({g.group_type.value}, {origin})",
          state=_status_state(g) or EvidenceState.CONFIRMED, stance=_reason_stance(codes), required=True, reasons=codes)


def _application(b: _Builder, bundle: EvidenceBundle, app_id: str) -> None:
    a = next((x for x in bundle.applications if x.id == app_id), None)
    codes = b.claim(lambda r: r.code in _APP_REASONS["application"] and r.subject == app_id)
    if a is None:
        b.add(key=f"application:{app_id}", kind="application", label="Okta application", record=None, system="Okta",
              observation="No observation of the application", state=EvidenceState.NOT_COLLECTED,
              stance=Stance.UNKNOWN, required=True, reasons=codes)
        return
    stance = Stance.SUPPORTS if R.APP_INACTIVE.value in codes else Stance.UNKNOWN
    b.add(key=f"application:{app_id}", kind="application", label=f"Okta application: {a.label}", record=a,
          observation=f"{a.status.value} in Okta", state=_status_state(a) or EvidenceState.CONFIRMED, stance=stance,
          required=True, reasons=codes)


def _candidate_assignment(bundle: EvidenceBundle, candidate: LifecycleCandidate,
                          app_id: str) -> ApplicationGroupAssignment | None:
    return next((a for a in bundle.assignments if a.application_id == app_id and a.id in candidate.assignment_ids), None)


def _assignment(b: _Builder, bundle: EvidenceBundle, candidate: LifecycleCandidate, app_id: str) -> None:
    a = _candidate_assignment(bundle, candidate, app_id)
    codes = b.claim(lambda r: r.code in _APP_REASONS["assignment"] and r.subject == app_id)
    if a is None:
        b.add(key=f"assignment:{app_id}", kind="assignment", label="Okta assignment", record=None, system="Okta",
              observation="No observation of the assignment", state=EvidenceState.NOT_COLLECTED,
              stance=Stance.UNKNOWN, required=True, reasons=codes)
        return
    unassigned = candidate.hold_until is not None  # the unassignment was observed: absence is the expected fact
    if a.present:
        observation, base = "Assigned (the access the proposal would remove exists)", EvidenceState.CONFIRMED
        stance = Stance.DISAGREES if unassigned else Stance.SUPPORTS
    else:
        observation, base = "Not assigned (a removal was observed)", EvidenceState.REPORTS_NONE
        stance = Stance.SUPPORTS if unassigned else Stance.DISAGREES
    b.add(key=f"assignment:{app_id}", kind="assignment", label="Okta assignment to the application", record=a,
          observation=observation, state=_status_state(a) or base, stance=stance, required=True, reasons=codes)


def _usage(b: _Builder, bundle: EvidenceBundle, candidate: LifecycleCandidate, app_id: str) -> None:
    u = bundle.usage_for(app_id, candidate.okta_group_id)
    codes = b.claim(lambda r: r.code in _APP_REASONS["usage"] and r.subject == app_id)
    if u is None:
        b.add(key=f"usage:{app_id}", kind="usage", label="Sign-in usage", record=None, system="Okta System Log",
              observation="No usage observation: missing usage is not zero usage", state=EvidenceState.NOT_COLLECTED,
              stance=Stance.UNKNOWN, required=True, reasons=codes)
        return
    scope = "group-attributed" if u.okta_group_id else "application-wide"
    last = f"; last {u.last_activity_at.date().isoformat()}" if u.last_activity_at else ""
    observation = f"{u.event_count} sign-in(s) by {u.distinct_user_count} user(s) in {u.window.days} days ({scope}{last})"
    status = _status_state(u)
    if status is not None and u.event_count == 0:
        observation += "; an incomplete read proves no absence of use"
    base = status or (EvidenceState.REPORTS_NONE if u.event_count == 0 else EvidenceState.CONFIRMED)
    b.add(key=f"usage:{app_id}", kind="usage", label=f"Sign-in usage ({scope})", record=u, observation=observation,
          state=base, stance=_reason_stance(codes), required=True, reasons=codes)


def _other_assignments(b: _Builder, bundle: EvidenceBundle, candidate: LifecycleCandidate,
                       app_ids: tuple[str, ...]) -> None:
    labels = {a.id: a.label for a in bundle.applications}
    for a in bundle.assignments:
        if a.okta_group_id != candidate.okta_group_id or a.application_id in app_ids:
            continue
        codes = b.claim(lambda r, x=a: r.code in _APP_REASONS["other-assignment"] and r.subject == x.application_id)
        name = labels.get(a.application_id, a.application_id)
        base = _status_state(a) or (EvidenceState.CONFIRMED if a.present else EvidenceState.REPORTS_NONE)
        b.add(key=f"other-assignment:{a.application_id}", kind="other-assignment",
              label=f"Okta assignment to another application: {name}", record=a,
              observation="Assigned: the group also grants this application" if a.present else "Not assigned",
              state=base, stance=Stance.DISAGREES if a.present else Stance.SUPPORTS, required=True, reasons=codes)


def _mapping(b: _Builder, bundle: EvidenceBundle) -> None:
    m = bundle.mapping
    codes = b.claim(lambda r: r.code in _MAPPING_REASONS)
    if m is None:
        b.add(key="mapping", kind="mapping", label="Identity mapping (Okta group to AD group)", record=None,
              system="OGWA correlation", observation="No identity mapping is recorded: the AD group is unknown",
              state=EvidenceState.NOT_COLLECTED, stance=Stance.UNKNOWN, required=True, reasons=codes)
        return
    status = _status_state(m)
    if m.is_exact:
        base, stance = EvidenceState.CONFIRMED, Stance.SUPPORTS
        observation = f"{m.confidence.value} on {', '.join(sorted(m.matched_attributes)) or 'its configuration'}"
    elif m.confidence is MappingConfidence.NOT_FOUND:
        base, stance, observation = EvidenceState.REPORTS_NONE, Stance.UNKNOWN, "NOT_FOUND: no AD counterpart was found"
    else:
        base, stance = EvidenceState.AMBIGUOUS, Stance.UNKNOWN
        observation = _identity(m).detail
    b.add(key="mapping", kind="mapping", label="Identity mapping (Okta group to AD group)", record=m,
          system="OGWA correlation", observation=observation, state=status or base, stance=stance, required=True,
          reasons=codes)


def _ad_group(b: _Builder, bundle: EvidenceBundle) -> None:
    ad, m = bundle.ad_group, bundle.mapping
    codes = b.claim(lambda r: r.code in _AD_GROUP_REASONS
                    or (r.code is R.PROTECTED_GROUP and ad is not None)
                    or (r.code is R.AD_DIRECT_MEMBERS and ad is not None and r.subject == ad.id))
    label = "AD group" if m is not None and m.is_exact else "AD group in evidence (not proven to be the counterpart)"
    if ad is None:
        if m is not None and not m.ad_group_id:
            state = EvidenceState.AMBIGUOUS if m.confidence is not MappingConfidence.NOT_FOUND \
                else EvidenceState.REPORTS_NONE
            observation = f"No AD group is identified: the mapping is {m.confidence.value}"
        else:
            state, observation = EvidenceState.NOT_COLLECTED, "No observation of the AD group"
        b.add(key="ad-group", kind="ad-group", label=label, record=None, system="Active Directory",
              observation=observation, state=state, stance=Stance.UNKNOWN, required=True, reasons=codes)
        return
    if not ad.exists:
        observation, base = "A complete objectGUID read found no such group", EvidenceState.REPORTS_NONE
    else:
        members = "member count unknown" if ad.member_count is None else f"{ad.member_count} member value(s)"
        flags = [name for name, on in (("adminCount", ad.admin_count),
                                       ("protected from accidental deletion", ad.protected_from_accidental_deletion),
                                       ("critical system object", ad.is_critical_system_object)) if on]
        observation = f"{ad.sam_account_name} exists; {members}; " + (
            f"protection: {', '.join(flags)}" if flags else "no protection marker")
        base = EvidenceState.CONFIRMED
    stance = _reason_stance(codes)
    if ad.exists and (ad.member_count or 0) > 0:
        stance = Stance.DISAGREES  # listed members are a positive fact, whatever the mapping says
    b.add(key="ad-group", kind="ad-group", label=label, record=ad, observation=observation,
          state=_status_state(ad) or base, stance=stance, required=True, reasons=codes)


def _counts(d: DependencyEvidence) -> bool:
    return d.provenance.decision_grade and d.provenance.source in COVERAGE_SOURCES


def _dependency(b: _Builder, bundle: EvidenceBundle, kind: DependencyKind, required: bool) -> None:
    okta_side = kind.value.startswith("OKTA_")
    subject = (bundle.okta_group.id if bundle.okta_group else None) if okta_side else (
        bundle.mapping.ad_group_id if bundle.mapping is not None else None)
    d = next((x for x in bundle.dependencies if x.kind is kind and x.subject_id == subject), None) if subject else None
    codes = b.claim(lambda r: (_DEPENDENCY_REASONS.get(r.code) is kind)
                    or (d is not None and r.subject == d.id and r.code not in _RECORD_REASONS))
    key, label = f"dependency:{kind.value}", _KIND_LABEL.get(kind, kind.value)
    system = "Okta" if okta_side else "Active Directory"
    if d is None:
        observation = "Never checked: unchecked is not clear" if subject else \
            "Cannot be checked until the AD group is established"
        b.add(key=key, kind="dependency", label=label, record=None, system=system, observation=observation,
              state=EvidenceState.NOT_COLLECTED, stance=Stance.UNKNOWN, required=required, reasons=codes)
        return
    blocking = d.blocking_findings
    if blocking:
        observation = "; ".join(f.description for f in blocking)
        base, stance = EvidenceState.CONFIRMED, Stance.DISAGREES  # a positive fact counts even from a partial read
    else:
        observation = "No blocking finding"
        base, stance = EvidenceState.REPORTS_NONE, Stance.SUPPORTS
        if not _counts(d):
            stance = Stance.UNKNOWN
    status = _status_state(d)
    if status is not None:
        base = status
        if not blocking:
            observation += f" in an incomplete ({d.provenance.result_status.value}) read: proves nothing absent"
    elif not blocking and d.provenance.source not in COVERAGE_SOURCES:
        base = EvidenceState.NOT_COUNTED_SOURCE
        observation += f" ({d.provenance.source.value}: can block, never proves absence, D13)"
    b.add(key=key, kind="dependency", label=label, record=d, observation=observation, state=base, stance=stance,
          required=required, reasons=codes)


# --- conflicts ------------------------------------------------------------------------------


def _conflicts(b: _Builder, bundle: EvidenceBundle, candidate: LifecycleCandidate, app_ids: tuple[str, ...],
               reasons: tuple[Reason, ...]) -> tuple[Conflict, ...]:
    out: list[Conflict] = []
    keys = {i["key"] for i in b.items}

    ad = bundle.ad_group
    members = next((d for d in bundle.dependencies if ad is not None and d.subject_id == ad.id
                    and d.kind is DependencyKind.AD_GROUP_MEMBERS), None)
    if ad is not None and ad.exists and ad.member_count is not None and members is not None \
            and "dependency:AD_GROUP_MEMBERS" in keys:
        # AD's member attribute and the membership read count the same values (the AD report converter).
        direct = any(f.code is FindingCode.AD_DIRECT_MEMBERS or (f.code is None and f.blocking)
                     for f in members.findings)
        record_has = ad.member_count > 0
        record_none = ad.member_count == 0 and ad.provenance.decision_grade
        read_none = _counts(members) and not direct
        if (record_has and read_none) or (record_none and direct):
            said = f"The AD group object lists {ad.member_count} member value(s)"
            found = "the membership read found direct members" if direct else "the membership read found none"
            out.append(Conflict("AD_MEMBERSHIP_DISAGREES", "AD membership reads disagree",
                                f"{said} (read {_when(ad.provenance.observed_at)}), but {found} "
                                f"(read {_when(members.provenance.observed_at)}). Either membership changed between "
                                "the reads or one read is wrong; OGWA does not choose a side.",
                                ("ad-group", "dependency:AD_GROUP_MEMBERS")))

    check = next((d for d in bundle.dependencies if bundle.okta_group is not None
                  and d.subject_id == bundle.okta_group.id and d.kind is DependencyKind.OKTA_OTHER_APP_ASSIGNMENT), None)
    others = [a for a in bundle.assignments if a.okta_group_id == candidate.okta_group_id
              and a.application_id not in app_ids and a.present]
    if check is not None and _counts(check) and not check.blocking_findings and others \
            and "dependency:OKTA_OTHER_APP_ASSIGNMENT" in keys:
        out.append(Conflict("OTHER_ASSIGNMENT_DISAGREES", "Okta assignment reads disagree",
                            f"The other-assignment check found no other application, but the assignment inventory "
                            f"shows the group assigned to {len(others)} other application(s)",
                            ("dependency:OKTA_OTHER_APP_ASSIGNMENT",
                             *(f"other-assignment:{a.application_id}" for a in others))))

    by_record = {i["record_id"]: i["key"] for i in b.items if i["record_id"]}
    for r in reasons:
        if r.code is R.EVIDENCE_INCONSISTENT:
            key = by_record.get(r.subject)
            out.append(Conflict("EVIDENCE_INCONSISTENT", "Evidence is inconsistent",
                                r.detail[:1].upper() + r.detail[1:], (key,) if key else ()))
    return tuple(out)


# --- identity -------------------------------------------------------------------------------


def _identity(m: IdentityMapping | None) -> IdentityAssessment:
    if m is None:
        return IdentityAssessment(IdentityState.NOT_ESTABLISHED, None, False,
                                  "No identity mapping is recorded, so which AD group this is remains unknown.")
    attrs = tuple(sorted(m.matched_attributes))
    if not m.provenance.decision_grade:
        return IdentityAssessment(IdentityState.UNAVAILABLE, m.confidence.value, False,
                                  f"The correlation did not finish ({m.provenance.result_status.value}); "
                                  f"{m.confidence.value} is not an answer.", attrs, len(m.candidate_ad_group_ids))
    if m.is_exact:
        return IdentityAssessment(IdentityState.CONFIRMED, m.confidence.value, True,
                                  f"{m.confidence.value} on {', '.join(attrs) or 'its configuration'}. An exact mapping "
                                  "identifies the AD group; it says nothing about whether changing it is safe.", attrs)
    if m.confidence is MappingConfidence.UNVERIFIED_STABLE_ID:
        return IdentityAssessment(IdentityState.PROBABLE, m.confidence.value, False,
                                  "Probable: Okta's directory objectSid resolves to one AD group, but that mechanism is "
                                  "not verified (D37, D56). It corroborates; it cannot establish the mapping.", attrs)
    if m.confidence is MappingConfidence.NAME_ONLY:
        return IdentityAssessment(IdentityState.PROBABLE, m.confidence.value, False,
                                  "Probable: only the names match. A name never proves which AD group this is.", attrs)
    if m.confidence is MappingConfidence.NOT_FOUND:
        return IdentityAssessment(IdentityState.NOT_FOUND, m.confidence.value, False,
                                  "No AD counterpart was found.", attrs)
    n = len(m.candidate_ad_group_ids)
    detail = (f"Ambiguous: {n} AD groups could be the counterpart; none is assumed."
              if m.confidence is MappingConfidence.AMBIGUOUS else f"Not exact: {m.confidence.value}.")
    return IdentityAssessment(IdentityState.AMBIGUOUS, m.confidence.value, False, detail, attrs, n)


# --- the decision ----------------------------------------------------------------------------


def _constraints(candidate: LifecycleCandidate, items: tuple[EvidenceItem, ...], conflicts: tuple[Conflict, ...],
                 identity: IdentityAssessment, classification: ClassificationResult | None,
                 pending: PendingStep) -> tuple[Constraint, ...]:
    out: list[Constraint] = []
    required = [i for i in items if i.required]
    if candidate.state in TERMINAL_STATES:
        out.append(Constraint(Decision.TERMINAL, f"The candidate is {candidate.state.value}, a terminal state: "
                                                 "new evidence would make a new candidate."))
    if classification is not None and classification.classification in _STOPPING:
        stops = [r.detail for r in classification.reasons
                 if r.blocks and r.outcome is classification.classification][:3]
        out.append(Constraint(Decision.NO_ACTION_BLOCKED, f"{classification.classification.value}: " + "; ".join(stops)))
    # A conflict about required items, or an inconsistency in the evidence itself, is material.
    material = [c for c in conflicts if not c.item_keys or any(i.key in c.item_keys and i.required for i in items)]
    for c in material:
        out.append(Constraint(Decision.CONFLICTING_EVIDENCE, c.summary, c.item_keys))
    if not identity.decision_grade:
        out.append(Constraint(Decision.AMBIGUOUS_IDENTITY, identity.detail, ("mapping",)))
    elif any(i.key == "ad-group" and i.base_state is EvidenceState.REPORTS_NONE for i in items):
        out.append(Constraint(Decision.AMBIGUOUS_IDENTITY, "The mapped AD group was not found by a complete objectGUID "
                                                           "read: the mapping no longer holds. Re-correlate.",
                              ("mapping", "ad-group")))
    unavailable = [i for i in required if i.base_state is EvidenceState.SOURCE_UNAVAILABLE]
    if unavailable:
        out.append(Constraint(Decision.BLOCKED_ON_REQUIRED_SOURCE,
                              "Could not be read: " + "; ".join(i.label for i in unavailable),
                              tuple(i.key for i in unavailable)))
    insufficient = [i for i in required if i.kind != "mapping" and i.base_state not in DECISION_GRADE_STATES
                    and i.base_state is not EvidenceState.SOURCE_UNAVAILABLE
                    and not (i.kind == "ad-group" and i.base_state is EvidenceState.AMBIGUOUS)]
    aged = [i for i in required if i.base_state in DECISION_GRADE_STATES
            and i.freshness in (Freshness.STALE, Freshness.FUTURE_DATED)]
    if insufficient or aged:
        parts = [f"{i.label}: {i.base_state.value.replace('_', ' ').lower()}" for i in insufficient]
        parts += [f"{i.label}: {i.freshness.value.replace('_', ' ').lower()}" for i in aged]
        out.append(Constraint(Decision.INSUFFICIENT_EVIDENCE, "; ".join(parts), tuple(i.key for i in insufficient + aged)))
    if classification is None:
        out.append(Constraint(Decision.INSUFFICIENT_EVIDENCE,
                              "No classification: no policy in force or no assignment evidence. Nothing is judged."))
    if candidate.state not in TERMINAL_STATES and not pending.open:
        step = STAGE_LABEL[pending.stage] if pending.stage else "nothing"
        out.append(Constraint(Decision.NO_APPROVAL_OPEN, f"No approval is open in {candidate.state.value}; the next "
                                                         f"approval the candidate faces is the {step}."))
    if classification is not None and classification.classification not in _STOPPING:
        if candidate.hold_until is None:
            held = [r.detail for r in classification.reasons if r.blocks]
            unproven: list[str] = []
            review = classification.classification is not C.RETIREMENT_CANDIDATE
        else:
            # After the observed unassignment the assignment's absence is the expected fact. The
            # classifier then stops at the review tier without listing unproven conditions, so
            # every retirement proof is required here explicitly; nothing else is waived.
            held = [r.detail for r in classification.reasons if r.blocks and r.code is not R.ASSIGNMENT_ABSENT]
            proven = {r.code for r in classification.reasons}
            unproven = sorted(code.value for code in RETIREMENT_CANDIDATE_REQUIRES if code not in proven)
            review = bool(held or unproven)
        cls = classification.classification
        # The classifier's own verdict, in the decision's terms: evidence problems are
        # insufficient evidence, an unproven mapping is an identity problem, the rest needs a person.
        kind = (Decision.INSUFFICIENT_EVIDENCE if cls in (C.EVIDENCE_INCOMPLETE, C.STALE_EVIDENCE)
                else Decision.AMBIGUOUS_IDENTITY if cls is C.MAPPING_REQUIRED else Decision.MANUAL_REVIEW_REQUIRED)
        said = any(c.decision is Decision.AMBIGUOUS_IDENTITY for c in out)
        if review and not (kind is Decision.AMBIGUOUS_IDENTITY and said):
            detail = "; ".join(held[:3] + ([f"not proven: {', '.join(unproven)}"] if unproven else []))
            out.append(Constraint(kind, f"The classifier holds this at {cls.value}" + (f": {detail}" if detail else ".")))
    if pending.open and (not pending.evaluated or not pending.accepts):
        detail = "; ".join(_guard_problems(pending.problems)[:4]) or "the guard was not evaluated"
        out.append(Constraint(Decision.LIFECYCLE_RULES_NOT_MET, f"{STAGE_LABEL[pending.stage]}: {detail}"))
    if not out and not all(i.decision_grade for i in required):
        # Defense in depth: eligibility is never inferred from evidence that is not decision-grade.
        out.append(Constraint(Decision.INSUFFICIENT_EVIDENCE, "A required observation is not decision-grade.",
                              tuple(i.key for i in required if not i.decision_grade)))
    order = {d: n for n, d in enumerate(DECISION_PRECEDENCE)}
    return tuple(sorted(out, key=lambda c: order[c.decision]))


def _lower(label: str) -> str:
    """Lower-case a label's first letter unless it starts an acronym ("AD ACL references")."""
    return label if label[:2].isupper() else label[:1].lower() + label[1:]


def _guard_problems(problems: tuple[str, ...]) -> list[str]:
    """The guard's problems, with per-record staleness folded into one line per purpose."""
    out, stale = [], {}
    for p in problems:
        record, sep, rest = p.partition(": evidence is stale for ")
        if sep:
            stale.setdefault(rest, []).append(record)
        else:
            out.append(p)
    for rest, records in stale.items():
        rest = rest.replace(", 0:00:00)", ")")  # "older than 7 days, 0:00:00" is a timedelta's text
        out.insert(0, f"{len(records)} record(s) are stale for {rest}: re-collect them before this step")
    return out


def _needed(items: tuple[EvidenceItem, ...], conflicts: tuple[Conflict, ...], identity: IdentityAssessment,
            pending: PendingStep, constraints: tuple[Constraint, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for c in conflicts:
        out.append(f"Resolve the conflict: {c.summary} Re-read both sources.")
    if not identity.decision_grade:
        out.append({
            IdentityState.PROBABLE: "Establish the AD counterpart exactly: an operator selects the AD object by stable "
                                    "identifier and a different operator approves it (D38).",
            IdentityState.AMBIGUOUS: "Establish which AD group is the counterpart: an operator selects one by stable "
                                     "identifier and a different operator approves it (D38).",
            IdentityState.NOT_FOUND: "Find the AD counterpart (re-correlate) or keep the group out of AD retirement.",
            IdentityState.NOT_ESTABLISHED: "Record an identity mapping: run the correlation for this Okta group.",
            IdentityState.UNAVAILABLE: "Re-run the correlation until every lookup completes.",
        }[identity.state])
    for i in items:
        if not i.required or i.kind == "mapping" or i.decision_grade:
            continue
        if i.kind == "ad-group" and i.base_state in (EvidenceState.AMBIGUOUS, EvidenceState.REPORTS_NONE):
            continue  # said by the identity line above
        base = i.base_state
        if base is EvidenceState.NOT_COLLECTED:
            out.append(f"Collect {_lower(i.label)}: no observation is recorded.")
        elif base is EvidenceState.SOURCE_UNAVAILABLE:
            out.append(f"Re-run {_lower(i.label)}: the last read failed; until a complete read is recorded nothing "
                       "is assumed.")
        elif base is EvidenceState.PARTIAL:
            out.append(f"Complete {_lower(i.label)}: the last read was partial and proves nothing absent.")
        elif base is EvidenceState.NOT_COUNTED_SOURCE:
            out.append(f"Check {_lower(i.label)} with a counting collector: an attestation never proves absence (D13).")
        elif i.freshness is Freshness.STALE:
            out.append(f"Re-collect {_lower(i.label)}: it is older than the review window.")
        elif i.freshness is Freshness.FUTURE_DATED:
            out.append(f"Explain or re-collect {_lower(i.label)}: its timestamp is in the future.")
    if pending.open and pending.evaluated and not pending.accepts:
        out += [f"Lifecycle ({STAGE_LABEL[pending.stage]}): {p}" for p in _guard_problems(pending.problems)]
    if not out and any(c.decision is Decision.NO_ACTION_BLOCKED for c in constraints):
        out.append("No evidence would clear this: a positive fact stops the candidate. Remove the dependency first.")
    return tuple(dict.fromkeys(out))


def _issue(candidate: LifecycleCandidate, bundle: EvidenceBundle, app_ids: tuple[str, ...]) -> dict[str, Any]:
    labels = {a.id: a.label for a in bundle.applications}
    apps = [labels.get(a, a) for a in app_ids]
    group = bundle.okta_group.name if bundle.okta_group else candidate.okta_group_id
    ad = bundle.ad_group.sam_account_name if bundle.ad_group is not None and bundle.ad_group.exists else None
    summary = (f"Remove the Okta group {group}'s assignment to {', '.join(apps) or 'its application'}; afterwards, "
               + (f"quarantine and then delete the AD group {ad}" if ad else "retire its AD counterpart")
               + ", each step separately approved by a different person.")
    return {"summary": summary, "oktaGroup": group, "applications": apps, "adGroup": ad,
            "candidateReasons": list(candidate.reason_codes),
            "steps": [STAGE_LABEL[s] for s in ALL_STAGES]}


def _notes(decision: Decision, pending: PendingStep) -> tuple[str, ...]:
    notes = ["An assessment is evidence for review, never an approval. OGWA plans dry runs only (D8); no automated "
             "remediation exists, so nothing here is eligible for automatic action."]
    if decision is not Decision.ELIGIBLE_FOR_HUMAN_APPROVAL and pending.open and pending.evaluated and pending.accepts:
        notes.append(f"The lifecycle's rules for the {STAGE_LABEL[pending.stage]} would still accept a named human's "
                     "approval: that step reads only part of this evidence. OGWA does not mark the proposal safe to "
                     "act on; the approver carries the judgment the evidence above cannot.")
    return tuple(notes)


__all__ = [
    "AD_STAGES", "ALL_STAGES", "DECISION_GRADE_STATES", "DECISION_LABEL", "DECISION_PRECEDENCE",
    "NON_ACTION_DECISIONS", "Conflict", "Constraint", "Decision", "EvidenceAssessment", "EvidenceItem",
    "EvidenceState", "Freshness", "IdentityAssessment", "IdentityState", "PendingStep", "Stance", "assess",
    "next_stage",
]
