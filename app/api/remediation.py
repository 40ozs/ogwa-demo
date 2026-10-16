"""Remediation dry runs behind the API. Dry runs only; nothing is ever executed.

One request asks for one operation on one target of one candidate. The order of checks
follows ``app.api.services`` and every step fails closed:

1. **Production mutation** is refused before anything else: ``executionMode:
   PRODUCTION_MUTATION`` or ``dryRun: false`` gets ``PRODUCTION_MUTATION_REFUSED`` (D8).
2. **Permission.** ``EXECUTION_PLAN_DRY_RUN`` (the EXECUTOR role, D61).
3. **Fresh view.** The request names the evidence fingerprint the operator saw.
4. **Separation of duties (D49).** The stage's approver cannot request its dry run.
5. **Gates, allowlist, adapter** (``app.remediation.engine``). Any failure answers 409
   ``REMEDIATION_BLOCKED`` with every gate's result; it is chained as
   ``GOVERNED_REQUEST_REFUSED`` like every refused governed request (D65).
6. **Record.** A SIMULATED, WHATIF, or VALIDATION_ONLY result is chained as
   ``REMEDIATION_DRY_RUN_RECORDED`` (migration 0010), with the request id as correlation id.

The request carries no template, script, command, OU, or host: the server-side allowlist
supplies all of them. There is no bulk form and no execute form.

**Synthetic drills.** ``drill`` runs the same checks 2 to 4, then
``app.remediation.drill``: the governed gates, allowlist, and synthetic adapter first (a
blocked request is 409 ``REMEDIATION_BLOCKED`` and builds nothing), then a dry run or a
scripted synthetic execution against an in-memory provider fixture. A drill records
nothing: no audit event, no job, no lifecycle move. It is not a governed state change, so
its refusals stay in the security log (D64, D72), like a mapping inspection's.

**Policy binding.** Once the governed gates pass, both a dry run and a drill
also need their authorization to hold (``app.api.authorization``): the approval, and the
decision that applied it, judged by the policy version in force. Otherwise 409
``APPROVAL_POLICY_NOT_IN_FORCE`` (a drill builds nothing; a dry run records nothing but its
chained refusal). A recorded dry run records the policy reference its gates were judged by,
checked in the write like a decision's, and every response names the chain: policy, decision,
approval, operation id.
"""

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from app.api.authorization import RemediationAuthorization, recorded_dry_run_chain, remediation_authorization
from app.api.authz import Permission, Principal
from app.api.errors import ApiError, conflict, forbidden, not_found
from app.api.readmodel import iso, policy_ref_json
from app.api.services import LifecycleService, demo_releases, policy_in_force, production_mutation_refused
from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.core.redaction import redact_text
from app.domain.audit import AuditEvent
from app.domain.policy import evidence_fingerprint
from app.domain.policy_release import PolicyRef
from app.domain.quarantine import QuarantineOus
from app.domain.remediation import RemediationOperation, RemediationOutcome, RemediationResult
from app.remediation.aap import TemplateMetadata
from app.remediation.allowlist import RemediationAllowlist
from app.remediation.drill import DrillMode, DrillReport, DrillUnauthorized, DrillUnavailable, run_drill
from app.remediation.engine import remediation_dry_run
from app.store.errors import StoreConflict
from app.store.store import Store

P = Permission
MAX_GATE_PROBLEM = 500


class RemediationBlocked(ApiError):
    """409 ``REMEDIATION_BLOCKED``: the outcome, and every gate with its own problems."""

    def __init__(self, result: RemediationResult) -> None:
        problems = [*result.gates.problems(), *(f"ADAPTER {result.adapter}: {note}" for note in result.notes)]
        super().__init__(409, "REMEDIATION_BLOCKED", "The remediation dry run is BLOCKED. Nothing was simulated, run, "
                                                     "or changed.", problems=problems)
        self.result = result

    def body(self, request_id: str) -> dict:
        body = super().body(request_id)
        body["error"]["outcome"] = RemediationOutcome.BLOCKED.value
        body["error"]["gates"] = [
            {"gate": c.gate.value, "passed": c.passed,
             "problems": [redact_text(p)[:MAX_GATE_PROBLEM] for p in c.problems]}
            for c in self.result.gates.checks]
        return body


class DrillBlocked(RemediationBlocked):
    """409 ``REMEDIATION_BLOCKED`` for a drill: the governed gates refused, so nothing was built."""

    def __init__(self, result: RemediationResult) -> None:
        super().__init__(result)
        self.message = ("The governed gates BLOCKED this drill. No synthetic provider was built and nothing was "
                        "submitted, simulated, or changed.")


class AuthorizationRefused(ApiError):
    """409 ``APPROVAL_POLICY_NOT_IN_FORCE``: the gates passed, but the approval (or the decision that
    applied it) was judged by a policy other than the version in force. Nothing was built,
    simulated, submitted, or recorded."""

    def __init__(self, authorization: RemediationAuthorization, problems: tuple[str, ...]) -> None:
        super().__init__(409, "APPROVAL_POLICY_NOT_IN_FORCE",
                         "The approval this remediation rests on was not judged by the policy version in force. "
                         "Nothing was simulated, submitted, or changed; a named human must approve again under it.",
                         problems=list(problems))
        self.authorization = authorization


class RemediationService:
    def __init__(self, store: Store, *, lifecycle: LifecycleService, clock: Callable[[], datetime],
                 mode: ExecutionMode, allowlist: RemediationAllowlist | None,
                 observed_templates: Mapping[int, TemplateMetadata] | None = None,
                 quarantine_ous: QuarantineOus | None = None) -> None:
        if allowlist is not None and allowlist.environment is not store.marker.environment:
            raise ConfigError("the remediation allowlist is for a different store environment")
        if quarantine_ous is not None and quarantine_ous.environment != store.marker.environment.value:
            raise ConfigError("the quarantine OU configuration is for a different store environment")
        self._quarantine_ous = quarantine_ous
        self._store = store
        self._lifecycle = lifecycle
        self._clock = clock
        self._mode = mode
        self._allowlist = allowlist
        self._observed_templates = dict(observed_templates or {})

    def dry_run(self, principal: Principal, candidate_id: str, *, operation: RemediationOperation, target_ref: str,
                approval_id: str, expected_fingerprint: str, dry_run: bool, requested_mode: str | None,
                request_id: str) -> dict[str, Any]:
        if requested_mode == ExecutionMode.PRODUCTION_MUTATION.value or dry_run is not True:
            raise production_mutation_refused()
        if not principal.can(P.EXECUTION_PLAN_DRY_RUN):
            raise forbidden()
        if requested_mode not in (None, ExecutionMode.DRY_RUN_MUTATION.value):
            raise ApiError(422, "VALIDATION_FAILED", "executionMode may only be DRY_RUN_MUTATION.")
        candidate = self._lifecycle.load(candidate_id)
        policy = policy_in_force(self._store)
        bundle = self._store.evidence_bundle(candidate)
        fingerprint = evidence_fingerprint(bundle)
        LifecycleService._require_fresh_view(expected_fingerprint, fingerprint)
        approval = self._store.load_approval(approval_id)
        if approval is None or approval.candidate_id != candidate.id:
            raise not_found("approval for this candidate")
        actor = principal.actor
        if approval.operator == actor:
            raise forbidden("You approved this stage; a different person must request its remediation dry run (D49).",
                            code="SEPARATION_OF_DUTIES")
        result = remediation_dry_run(
            candidate=candidate, operation=operation, target_ref=target_ref, evidence=bundle, approval=approval,
            policy=policy.policy.lifecycle, now=self._clock(), mode=self._mode, requested_by=actor,
            requested_mode=ExecutionMode(requested_mode) if requested_mode else None, allowlist=self._allowlist,
            environment=self._store.marker.environment, correlation_id=request_id,
            observed_templates=self._observed_templates, quarantine_ous=self._quarantine_ous)
        if result.outcome is RemediationOutcome.BLOCKED:
            raise RemediationBlocked(result)
        authorization = remediation_authorization(self._store, candidate, approval, policy)
        if not authorization.authorized:
            raise AuthorizationRefused(authorization, authorization.problems())
        try:
            event = self._store.record_remediation_dry_run(
                actor=actor, candidate_id=candidate.id, result=result, approval_id=approval.id,
                evidence_fingerprint=fingerprint, correlation_id=request_id, policy_ref=policy.ref,
                lifecycle_policy=policy.policy.lifecycle)
        except StoreConflict as exc:
            raise conflict("CONFLICT", str(exc)) from None
        return {"result": result, "event": event, "policy": policy, "authorization": authorization}

    def drill(self, principal: Principal, candidate_id: str, *, operation: RemediationOperation, target_ref: str,
              approval_id: str, expected_fingerprint: str, mode: DrillMode, scenario: str | None,
              request_id: str) -> dict[str, Any]:
        """One synthetic drill. Records nothing; see ``app.remediation.drill``."""
        if not principal.can(P.EXECUTION_PLAN_DRY_RUN):
            raise forbidden()
        candidate = self._lifecycle.load(candidate_id)
        policy = policy_in_force(self._store)
        bundle = self._store.evidence_bundle(candidate)
        LifecycleService._require_fresh_view(expected_fingerprint, evidence_fingerprint(bundle))
        approval = self._store.load_approval(approval_id)
        if approval is None or approval.candidate_id != candidate.id:
            raise not_found("approval for this candidate")
        if approval.operator == principal.actor:
            raise forbidden("You approved this stage; a different person must run its remediation drill (D49).",
                            code="SEPARATION_OF_DUTIES")
        authorization = remediation_authorization(self._store, candidate, approval, policy)

        def authorize() -> tuple[str, ...]:
            # Read again each time it is asked (at the start, and before a retry): a policy version
            # recorded meanwhile is the policy in force, and the approval must have been judged by it.
            return remediation_authorization(self._store, candidate, approval, policy_in_force(self._store)).problems()

        try:
            report: DrillReport = run_drill(
                mode=mode, scenario_key=scenario, candidate=candidate, operation=operation, target_ref=target_ref,
                evidence=bundle, approval=approval, policy=policy.policy.lifecycle, now=self._clock(),
                execution_mode=self._mode, requested_by=principal.actor, allowlist=self._allowlist,
                environment=self._store.marker.environment, correlation_id=request_id,
                quarantine_ous=self._quarantine_ous, authorize=authorize)
        except DrillUnavailable as exc:
            raise conflict("SYNTHETIC_DRILL_UNAVAILABLE", f"No synthetic drill can run here: {exc}.") from None
        except DrillUnauthorized as exc:
            raise AuthorizationRefused(authorization, exc.problems) from None
        if report.blocked:
            raise DrillBlocked(report.result)
        return {"report": report, "policy": policy, "authorization": authorization}

    def recorded(self, candidate_id: str) -> tuple[AuditEvent, ...]:
        candidate = self._lifecycle.load(candidate_id)
        return self._store.remediation_dry_runs(candidate.id)


_RECORD_FIELDS = {
    "operation": "operation", "outcome": "outcome", "adapter": "adapter", "target_kind": "targetKind",
    "target_id": "targetId", "target_identity": "targetIdentityDigest", "approval_id": "approvalId",
    "evidence_fingerprint": "evidenceFingerprint", "gates_passed": "gatesPassed", "planned_changes": "plannedChanges",
}


def remediation_record_json(event: AuditEvent, store: Store | None = None) -> dict[str, Any]:
    """A recorded dry run. With ``store`` it also names the policy its event recorded,
    as recorded (None: recorded before dry runs named their policy), and its chain."""
    details = dict(event.details)
    record = {name: details.get(key) for key, name in _RECORD_FIELDS.items()}
    out = {"auditEventId": event.id, "recordedAt": iso(event.occurred_at), "requestedBy": event.actor.id,
           "executionMode": event.execution_mode.value if event.execution_mode else None,
           "correlationId": event.correlation_id, **record, "executed": False, "productionMutation": False}
    if store is not None:
        out["policy"] = policy_ref_json(PolicyRef.from_audit_details(event.details), demo_releases(store))
        out["chain"] = recorded_dry_run_chain(store, event)
    return out
