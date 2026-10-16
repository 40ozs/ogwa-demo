"""Approvals are data, not a UI flag.

An ``ApprovalRecord`` binds a named human's decision to one candidate, one lifecycle
stage, one candidate epoch, and one evidence fingerprint, and it expires. When material
evidence changes the fingerprint changes, and the approval no longer applies.

The governed stages are the Okta unassignment, the AD quarantine, and the AD deletion
(owner decision D147). ``AD_RETIREMENT`` is the single AD stage earlier stores recorded. Its
rows are kept as legacy historical records, never rewritten, and they authorize nothing; no
new approval may use it (D148).
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from app.domain.actors import Actor, ActorKind
from app.domain.errors import InvalidRecord
from app.domain.evidence import check_digest
from app.domain.ids import IdKind, check_enum, check_id, check_text, check_utc


class ApprovalStage(StrEnum):
    OKTA_UNASSIGN = "OKTA_UNASSIGN"  # remove the group's assignment from the candidate applications
    AD_RETIREMENT = "AD_RETIREMENT"  # legacy (D148): quarantine and deletion in one approval; authorizes nothing
    AD_QUARANTINE = "AD_QUARANTINE"  # move the mapped AD group into its quarantine OU, after the hold period
    AD_DELETION = "AD_DELETION"  # delete the quarantined AD group, after the post-quarantine hold


# Stages whose stored approvals are history only (D148). Recording a new one is refused.
LEGACY_APPROVAL_STAGES = frozenset({ApprovalStage.AD_RETIREMENT})
GOVERNED_APPROVAL_STAGES = frozenset(ApprovalStage) - LEGACY_APPROVAL_STAGES
LEGACY_STAGE_PROBLEM = ("AD_RETIREMENT is a legacy approval stage: its approvals are historical records and "
                        "authorize nothing. AD quarantine and AD deletion are approved separately (D147, D148)")


class ApprovalDecision(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


@dataclass(frozen=True)
class ApprovalRecord:
    id: str
    candidate_id: str
    stage: ApprovalStage
    decision: ApprovalDecision
    operator: Actor
    decided_at: datetime
    reason: str
    evidence_fingerprint: str
    candidate_epoch: int
    expires_at: datetime

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.APPROVAL, "id")
        check_id(self.candidate_id, IdKind.CANDIDATE, "candidate_id")
        check_enum(self.stage, ApprovalStage, "stage")
        check_enum(self.decision, ApprovalDecision, "decision")
        if not isinstance(self.operator, Actor) or self.operator.kind is not ActorKind.HUMAN:
            raise InvalidRecord("an approval must be made by a named human operator")
        check_utc(self.decided_at, "decided_at")
        check_text(self.reason, "reason")
        check_digest(self.evidence_fingerprint, "evidence_fingerprint")
        if not isinstance(self.candidate_epoch, int) or isinstance(self.candidate_epoch, bool) or self.candidate_epoch < 0:
            raise InvalidRecord("candidate_epoch must be a non-negative integer")
        check_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.decided_at:
            raise InvalidRecord("expires_at must be after decided_at")


def approval_problems(
    approval: ApprovalRecord | None,
    *,
    candidate_id: str,
    candidate_epoch: int,
    proposed_by: Actor,
    stage: ApprovalStage,
    now: datetime,
    max_ttl: timedelta,
    clock_skew: timedelta,
    evidence_fingerprint: str | None,
    not_before: datetime | None = None,
    given_after: datetime | None = None,
    excluded_approvers: Iterable[tuple[Actor | None, str]] = (),
) -> list[str]:
    """Reasons ``approval`` does not authorize ``stage`` for this candidate; empty if it does.

    Pass ``evidence_fingerprint=None`` only when evidence is expected to have changed
    because of the approved action itself (recording that an approved change happened).
    ``not_before`` is when the stage's hold ended. ``given_after`` is when the stage was
    proposed: an approval decided earlier is not an approval of this proposal (D146).
    ``excluded_approvers`` pairs each person who may not approve this stage (an earlier
    stage's approver, the stage's proposer) with the reason (D11, D143).
    """
    if approval is None:
        return [f"no {stage.value} approval was supplied"]
    problems = []
    if stage in LEGACY_APPROVAL_STAGES or approval.stage in LEGACY_APPROVAL_STAGES:
        problems.append(LEGACY_STAGE_PROBLEM)
    if approval.candidate_id != candidate_id:
        problems.append("approval belongs to a different candidate")
    if approval.stage is not stage:
        problems.append(f"approval is for stage {approval.stage.value}, not {stage.value}")
    if approval.decision is not ApprovalDecision.APPROVE:
        problems.append(f"approval decision is {approval.decision.value}")
    if approval.candidate_epoch != candidate_epoch:
        problems.append("approval predates the candidate's current epoch (it was blocked and re-entered)")
    if approval.operator == proposed_by:
        problems.append("the operator who proposed the candidate cannot approve it")
    for excluded, reason in excluded_approvers:
        if excluded is not None and approval.operator == excluded:
            problems.append(reason)
    if approval.expires_at - approval.decided_at > max_ttl:
        problems.append(f"approval lifetime exceeds the policy maximum {max_ttl}")
    if approval.decided_at > now + clock_skew:
        problems.append("approval decided_at is in the future")
    if now >= approval.expires_at:
        problems.append("approval has expired")
    if not_before is not None and approval.decided_at < not_before:
        problems.append("approval was given before it was allowed (before the hold period ended)")
    if given_after is not None and approval.decided_at < given_after:
        problems.append("approval was given before this stage was proposed; the proposal needs a new approval (D146)")
    if evidence_fingerprint is not None and approval.evidence_fingerprint != evidence_fingerprint:
        problems.append("material evidence changed since the approval was given")
    return problems
