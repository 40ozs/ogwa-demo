"""Where a remediation's authority comes from: policy, decision, approval.

A remediation dry run or a synthetic drill rests on one human approval. The store records,
with every approval and lifecycle decision, the exact policy that judged it; the synthetic
drill re-evaluates the governed gates under the policy in force. This module joins the two,
from what the store already recorded and nothing else:

- the **policy in force** the request's gates are judged by now (``PolicyInForce``);
- the **approval** it cites: its ``APPROVAL_RECORDED`` event and the policy reference that
  event recorded;
- the **lifecycle decision** that applied that approval (the transition into the approved
  stage, whose ``approval_id`` is the approval's): its ``TRANSITION_APPLIED`` event and the
  policy reference it recorded.

Each recorded reference is read back exactly as recorded, never filled in from the policy in
force (PV-6), and is compared with the version in force:

- ``IN_FORCE``: recorded with the policy version in force now (same id, sequence, and digest);
- ``SUPERSEDED``: recorded with an earlier version;
- ``NOT_RECORDED``: recorded with no reference although a version is in force;
- ``UNRECORDED_POLICY``: no policy version is recorded at all (the classic world's unrecorded
  demo policy, D66), so there is no version to bind to.

**Binding rule (fail closed).** While a policy version is recorded, a remediation may rest only
on an approval, and a decision applying it, judged by that same version. An approval given under
a version a later release superseded authorizes nothing under the new one: a named human
approves again, which gives a new approval id and so a new operation id (what
``operation_id`` assumes, enforced here). Nothing here writes, and nothing here
judges evidence: the gates still do that.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.api.readmodel import actor_json, iso, policy_ref_json
from app.api.services import PolicyInForce, demo_releases
from app.domain.approval import ApprovalRecord
from app.domain.audit import AuditAction, AuditEvent
from app.domain.lifecycle import LifecycleCandidate, LifecycleDecision
from app.domain.policy_release import PolicyRef
from app.domain.remediation_execution import STATE_LABELS, operation_id
from app.remediation.drill import DrillReport
from app.store.store import Store


class Binding(StrEnum):
    IN_FORCE = "IN_FORCE"
    SUPERSEDED = "SUPERSEDED"
    NOT_RECORDED = "NOT_RECORDED"
    UNRECORDED_POLICY = "UNRECORDED_POLICY"


# Bindings a remediation may rest on. Anything else blocks it.
ACCEPTED_BINDINGS = frozenset({Binding.IN_FORCE, Binding.UNRECORDED_POLICY})

BINDING_TEXT = {
    Binding.IN_FORCE: "Judged by the policy version in force now.",
    Binding.SUPERSEDED: "Judged by an earlier policy version that a later release superseded.",
    Binding.NOT_RECORDED: "Recorded no policy, although a policy version is in force.",
    Binding.UNRECORDED_POLICY: "No policy version is recorded in this store (unrecorded demo policy), so there is "
                               "no version to bind to.",
}


def binding(recorded: PolicyRef | None, in_force: PolicyRef) -> Binding:
    """How a recorded reference stands against the policy in force. Exact: id, sequence, digest."""
    if not in_force.recorded:
        return Binding.UNRECORDED_POLICY
    if recorded is None:
        return Binding.NOT_RECORDED
    same = (recorded.source, recorded.version_id, recorded.sequence, recorded.policy_digest) == (
        in_force.source, in_force.version_id, in_force.sequence, in_force.policy_digest)
    return Binding.IN_FORCE if same else Binding.SUPERSEDED


@dataclass(frozen=True)
class RemediationAuthorization:
    """The chain from the policy in force to the approval a remediation cites. Read-only."""

    candidate_id: str
    in_force: PolicyInForce
    approval: ApprovalRecord
    approval_event: AuditEvent | None
    approval_policy: PolicyRef | None
    decision: LifecycleDecision | None
    decision_event: AuditEvent | None
    decision_policy: PolicyRef | None

    @property
    def approval_binding(self) -> Binding:
        return binding(self.approval_policy, self.in_force.ref)

    @property
    def decision_binding(self) -> Binding | None:
        return binding(self.decision_policy, self.in_force.ref) if self.decision is not None else None

    def problems(self) -> tuple[str, ...]:
        """Why this chain cannot authorize a remediation now; none if it can."""
        out = []
        now = self.in_force.release.name if self.in_force.release else self.in_force.label
        if self.approval_binding not in ACCEPTED_BINDINGS:
            out.append(f"approval {self.approval.id}: {BINDING_TEXT[self.approval_binding]} "
                       f"{_name(self.approval_policy)} is not {now}, the policy in force; a named human must approve "
                       "again under it")
        if self.decision_binding is not None and self.decision_binding not in ACCEPTED_BINDINGS:
            out.append(f"decision {self.decision.id}: {BINDING_TEXT[self.decision_binding]} "
                       f"{_name(self.decision_policy)} is not {now}, the policy in force")
        return tuple(out)

    @property
    def authorized(self) -> bool:
        return not self.problems()

    def to_dict(self, store: Store) -> dict[str, Any]:
        releases = demo_releases(store)
        decision = self.decision
        return {
            "candidateId": self.candidate_id,
            "policyInForce": self.in_force.to_dict(),
            "approval": {
                "id": self.approval.id, "stage": self.approval.stage.value, "decision": self.approval.decision.value,
                "operator": actor_json(self.approval.operator), "decidedAt": iso(self.approval.decided_at),
                "expiresAt": iso(self.approval.expires_at), "candidateEpoch": self.approval.candidate_epoch,
                "evidenceFingerprint": self.approval.evidence_fingerprint, **_event(self.approval_event),
                "policy": policy_ref_json(self.approval_policy, releases), "binding": self.approval_binding.value,
            },
            "decision": None if decision is None else {
                "id": decision.id, "from": decision.from_state.value, "to": decision.to_state.value,
                "actor": actor_json(decision.actor), "decidedAt": iso(decision.decided_at),
                "approvalId": decision.approval_id, **_event(self.decision_event),
                "policy": policy_ref_json(self.decision_policy, releases),
                "binding": self.decision_binding.value if self.decision_binding else None,
            },
            "authorized": self.authorized, "problems": list(self.problems()),
            "rule": "A remediation rests only on an approval, and the decision that applied it, judged by the policy "
                    "version in force. Each record shows the policy it recorded when it was made, never the policy in "
                    "force now.",
        }


def _name(ref: PolicyRef | None) -> str:
    if ref is None:
        return "No recorded policy"
    return ref.name or (f"recorded version {ref.sequence + 1}" if ref.recorded else "the unrecorded demo policy")


def _event(event: AuditEvent | None) -> dict[str, Any]:
    if event is None:
        return {"auditEventId": None, "auditSequence": None, "auditDigest": None}
    return {"auditEventId": event.id, "auditSequence": event.sequence, "auditDigest": event.digest}


def _policy_fields(ref: PolicyRef | None) -> dict[str, Any]:
    if ref is None:
        return {"policyId": None, "policyVersion": None, "policyVersionId": None, "policySequence": None,
                "policyDigest": None, "releaseDigest": None}
    return {"policyId": ref.policy_id, "policyVersion": ref.version, "policyVersionId": ref.version_id,
            "policySequence": ref.sequence, "policyDigest": ref.policy_digest, "releaseDigest": ref.release_digest}


def drill_chain(authorization: RemediationAuthorization, report: DrillReport) -> dict[str, Any]:
    """One drill's chain on one page, every link by its recorded identifier: the policy the gates
    were judged by, the decision and approval it rests on (with their audit sequences), the
    operation id every attempt carried, each attempt and its verification, the post-action read,
    and the final state. A reading of the drill and of recorded data; the drill itself records
    nothing (RX-9), so ``recorded`` is always false."""
    trace, decision = report.trace, authorization.decision
    return {
        **_policy_fields(authorization.in_force.ref),
        "decisionId": decision.id if decision else None,
        "decisionAuditSequence": authorization.decision_event.sequence if authorization.decision_event else None,
        "approvalId": authorization.approval.id,
        "approvalAuditSequence": authorization.approval_event.sequence if authorization.approval_event else None,
        "authorized": authorization.authorized,
        "operationId": report.change.operation_id if report.change else None,
        "executionMode": report.mode.value,
        "scenario": report.scenario.key if report.scenario else None,
        "submissions": trace.submissions if trace else 0,
        "attempts": list(trace.attempts()) if trace else [],
        "postActionVerification": (trace.post_action_verification()["result"] if trace else "NOT_REACHED"),
        "finalState": report.final_state.value,
        "finalLabel": STATE_LABELS[report.final_state],
        "succeeded": report.succeeded,
        "recorded": False,
    }


def recorded_dry_run_chain(store: Store, event: AuditEvent) -> dict[str, Any]:
    """A recorded governed dry run's chain, read back as recorded (PV-6): the policy its own event
    recorded (none if its event predates policy binding), the approval it cites, the decision
    that applied that approval, and the operation id of that approved change (the same id a drill
    of it carries). Never the policy in force now."""
    details = dict(event.details)
    approval_id = details.get("approval_id")
    decision = next((d for d in store.decisions(event.subject_id) if approval_id and d.approval_id == approval_id), None)
    op_id = None
    if all(details.get(k) for k in ("operation", "target_identity", "approval_id", "evidence_fingerprint")):
        op_id = operation_id(candidate_id=event.subject_id, operation=details["operation"],
                             target_identity_digest=details["target_identity"], approval_id=details["approval_id"],
                             evidence_fingerprint=details["evidence_fingerprint"])
    return {**_policy_fields(PolicyRef.from_audit_details(event.details)),
            "decisionId": decision.id if decision else None, "approvalId": approval_id, "operationId": op_id,
            "executionMode": "DRY_RUN", "auditSequence": event.sequence}


def remediation_authorization(store: Store, candidate: LifecycleCandidate, approval: ApprovalRecord,
                              in_force: PolicyInForce) -> RemediationAuthorization:
    """The chain for ``approval`` of ``candidate``, from recorded data only."""
    if approval.candidate_id != candidate.id:
        raise ValueError("the approval is not this candidate's")
    refs = store.recorded_policies(candidate.id)
    decision = next((d for d in store.decisions(candidate.id) if d.approval_id == approval.id), None)
    return RemediationAuthorization(
        candidate.id, in_force, approval,
        store.audit_event_for(AuditAction.APPROVAL_RECORDED, f"approval:{approval.id}"),
        refs.get(f"approval:{approval.id}"),
        decision,
        store.audit_event_for(AuditAction.TRANSITION_APPLIED, f"decision:{decision.id}") if decision else None,
        refs.get(f"decision:{decision.id}") if decision else None)


__all__ = ["ACCEPTED_BINDINGS", "BINDING_TEXT", "Binding", "RemediationAuthorization", "binding", "drill_chain",
           "recorded_dry_run_chain", "remediation_authorization"]
