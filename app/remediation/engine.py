"""One remediation dry run, end to end: gates, then the allowlist, then the adapter.

Nothing here reads or writes a store or contacts a system. The caller (the API service)
supplies the recorded evidence and approval and records the result.
"""

from collections.abc import Mapping
from datetime import datetime

from app.domain.actors import Actor
from app.domain.approval import ApprovalRecord
from app.domain.lifecycle import LifecycleCandidate
from app.domain.policy import EvidenceBundle, LifecyclePolicy
from app.domain.quarantine import QuarantineOus
from app.domain.remediation import (
    RemediationOperation,
    RemediationOutcome,
    RemediationResult,
    blocked,
    evaluate_gates,
)
from app.remediation.aap import TemplateMetadata
from app.remediation.adapters import RemediationPlan, adapter_for
from app.remediation.allowlist import RemediationAllowlist
from app.store.environment import DatabaseEnvironment

NO_ADAPTER = "NONE"


def remediation_dry_run(
    *,
    candidate: LifecycleCandidate,
    operation: RemediationOperation,
    target_ref: object,
    evidence: EvidenceBundle,
    approval: ApprovalRecord | None,
    policy: LifecyclePolicy,
    now: datetime,
    mode: object,
    requested_by: Actor,
    requested_mode: object,
    allowlist: RemediationAllowlist | None,
    environment: DatabaseEnvironment,
    correlation_id: str,
    observed_templates: Mapping[int, TemplateMetadata] | None = None,
    quarantine_ous: QuarantineOus | None = None,
) -> RemediationResult:
    """SIMULATED, WHATIF, or VALIDATION_ONLY if every gate passes and the adapter agrees;
    otherwise BLOCKED. Never anything else."""
    evaluation = evaluate_gates(candidate, operation, target_ref, evidence, approval, policy, now=now, mode=mode,
                                requested_by=requested_by, requested_mode=requested_mode,
                                quarantine_ous=quarantine_ous)
    report, target = evaluation.report, evaluation.target
    if not report.passed:
        return blocked(operation, report, adapter=NO_ADAPTER, target=target)
    entry = allowlist.entry(operation) if allowlist is not None else None
    if entry is None:
        return blocked(operation, report, adapter=NO_ADAPTER, target=target,
                       notes=(f"{operation.value} is not in the server-side remediation allowlist",))
    if allowlist.environment is not environment:
        return blocked(operation, report, adapter=NO_ADAPTER, target=target,
                       notes=("the remediation allowlist is for a different store environment",))
    adapter = adapter_for(entry, environment=environment, observed_templates=observed_templates)
    answer = adapter.dry_run(RemediationPlan(candidate.id, operation, target, evidence, entry, correlation_id,
                                             quarantine_ous))
    if answer.outcome is RemediationOutcome.BLOCKED:
        return blocked(operation, report, adapter=adapter.name, target=target, notes=answer.notes)
    return RemediationResult(operation, answer.outcome, adapter.name, report, target, answer.planned_changes,
                             answer.notes)
