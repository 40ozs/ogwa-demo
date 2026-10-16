"""The JSON contract between OGWA and the PowerShell remediation worker (OGWA.Remediation).

The worker takes one ``ogwa.remediation.request/v1`` document and answers with one
``ogwa.remediation.result/v1`` document. This module builds the request and
validates the result, strictly in both directions:

- a request names one operation, one explicit target (stable identifiers plus the identity
  OGWA expects, never a pattern), and a mode, which is ``WhatIf`` or ``ValidateOnly``. No
  request can ask the worker to change anything: the JSON boundary has no such mode;
- a result is refused unless it says ``executed: false`` and ``productionMutation: false``,
  comes from this worker and version, uses only known outcomes, checks, and block reasons,
  and answers for exactly the target that was asked about.

The constants here must match ``worker/OGWA.Remediation/contract.json`` (checked by tests).
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.domain.remediation import (
    OPERATIONS,
    PlannedChange,
    RemediationOperation,
    RemediationOutcome,
    RemediationTarget,
    TargetKind,
)

REQUEST_SCHEMA = "ogwa.remediation.request/v1"
RESULT_SCHEMA = "ogwa.remediation.result/v1"
WORKER_NAME = "OGWA.Remediation"
WORKER_VERSION = "0.1.0"
# The only modes the worker's JSON boundary accepts. There is no mode that changes anything.
WORKER_MODES = ("WhatIf", "ValidateOnly")
WORKER_OUTCOMES = {
    "WhatIf": RemediationOutcome.WHATIF,
    "Simulated": RemediationOutcome.SIMULATED,
    "ValidationOnly": RemediationOutcome.VALIDATION_ONLY,
    "Blocked": RemediationOutcome.BLOCKED,
}
TARGET_KEYS = {
    RemediationOperation.OKTA_GROUP_UNASSIGN: ("oktaAppId", "oktaGroupId"),
    RemediationOperation.AD_GROUP_QUARANTINE: ("objectGuid", "domain", "expectedSid", "expectedDistinguishedName",
                                               "quarantineOu"),
    RemediationOperation.AD_GROUP_DELETE: ("objectGuid", "domain", "expectedSid", "expectedDistinguishedName"),
}
PLANNED_ACTIONS = {
    RemediationOperation.OKTA_GROUP_UNASSIGN: "unassign_group_from_application",
    RemediationOperation.AD_GROUP_QUARANTINE: "move_group_to_quarantine",
    RemediationOperation.AD_GROUP_DELETE: "delete_group",
}
CHECK_CODES = frozenset({
    "REQUEST_VALID", "ADAPTER_SYNTHETIC", "TARGET_SYNTHETIC", "TARGET_RESOLVED", "IDENTITY_MATCHES", "NOT_PROTECTED",
    "NO_MEMBERS", "NO_PARENT_GROUPS", "QUARANTINE_OU_VALID", "ASSIGNMENT_PRESENT", "GROUP_NOT_BUILT_IN",
})
BLOCK_REASONS = frozenset({
    "INVALID_REQUEST", "WILDCARD_TARGET", "NO_PRODUCTION_ADAPTER", "NON_SYNTHETIC_TARGET", "TARGET_NOT_FOUND",
    "TARGET_AMBIGUOUS", "TARGET_IDENTITY_CHANGED", "PROTECTED_TARGET", "PROTECTION_UNDETERMINED", "HAS_MEMBERS",
    "HAS_PARENT_GROUPS", "ALREADY_IN_QUARANTINE", "QUARANTINE_OU_INVALID", "ASSIGNMENT_NOT_FOUND", "BUILT_IN_GROUP",
    "CONFIRMATION_DECLINED", "ADAPTER_FAILED",
})
RESULT_KEYS = frozenset({"schema", "worker", "operation", "outcome", "executed", "productionMutation", "correlationId",
                         "observedAt", "target", "checks", "plannedChanges", "blockedReasons"})
MAX_RESULT_CHARACTERS = 200_000
MAX_TEXT = 500
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


class WorkerContractError(ValueError):
    """A worker request or result does not match the contract."""


# --- requests ------------------------------------------------------------------------


def worker_request(operation: RemediationOperation, target: RemediationTarget, *, mode: str, correlation_id: str,
                   quarantine_ou: str | None = None) -> dict[str, Any]:
    """The request the worker would receive for this one target."""
    if mode not in WORKER_MODES:
        raise WorkerContractError(f"the worker accepts only these modes: {', '.join(WORKER_MODES)}")
    if not isinstance(correlation_id, str) or not _CORRELATION_RE.match(correlation_id):
        raise WorkerContractError("correlation_id must be 1-100 characters from [A-Za-z0-9._:-]")
    if not isinstance(target, RemediationTarget) or target.kind is not OPERATIONS[operation].target_kind:
        raise WorkerContractError(f"{operation.value} needs a {OPERATIONS[operation].target_kind.value} target")
    if target.kind is TargetKind.OKTA_ASSIGNMENT:
        document = {"oktaAppId": target.value("okta_app_id"), "oktaGroupId": target.value("okta_group_external_id")}
    else:
        document = {"objectGuid": target.value("object_guid"), "domain": target.value("domain"),
                    "expectedSid": target.value("sid"), "expectedDistinguishedName": target.value("distinguished_name")}
    if operation is RemediationOperation.AD_GROUP_QUARANTINE:
        if not quarantine_ou:
            raise WorkerContractError("a quarantine request names the domain's configured quarantine OU")
        document["quarantineOu"] = quarantine_ou
    elif quarantine_ou is not None:
        raise WorkerContractError("only a quarantine request names a quarantine OU")
    if any(not isinstance(v, str) or not v for v in document.values()):
        raise WorkerContractError("every target value is an explicit, non-empty identifier")
    return {"schema": REQUEST_SCHEMA, "operation": operation.value, "mode": mode, "correlationId": correlation_id,
            "target": document}


# --- results -------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkerCheck:
    code: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class WorkerResult:
    operation: RemediationOperation | None  # None only for a request the worker could not read
    outcome: RemediationOutcome
    correlation_id: str | None
    observed_at: datetime
    target: dict[str, str] | None
    checks: tuple[WorkerCheck, ...]
    planned_changes: tuple[PlannedChange, ...]
    blocked_reasons: tuple[str, ...]


def _text(value: Any, where: str, *, max_length: int = MAX_TEXT, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise WorkerContractError(f"{where} must be a string of 1-{max_length} characters")
    return value


def _object(value: Any, where: str, keys: frozenset[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise WorkerContractError(f"{where} must be an object")
    if keys is not None and set(value) != keys:
        raise WorkerContractError(f"{where} must have exactly: {', '.join(sorted(keys))}")
    return value


def parse_worker_result(text: str, *, expected: dict[str, Any] | None = None) -> WorkerResult:
    """Validate one result document. ``expected`` is the request it must answer, if known."""
    if not isinstance(text, str) or len(text) > MAX_RESULT_CHARACTERS:
        raise WorkerContractError(f"a worker result is a JSON text of at most {MAX_RESULT_CHARACTERS} characters")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise WorkerContractError("the worker result is not JSON") from None
    data = _object(data, "result", RESULT_KEYS)
    if data["schema"] != RESULT_SCHEMA:
        raise WorkerContractError(f"result.schema must be {RESULT_SCHEMA}")
    if _object(data["worker"], "result.worker", frozenset({"name", "version"})) != {
            "name": WORKER_NAME, "version": WORKER_VERSION}:
        raise WorkerContractError(f"the result must come from {WORKER_NAME} {WORKER_VERSION}")
    # Stated by the worker on every result, and refused here unless false: nothing ran.
    if data["executed"] is not False or data["productionMutation"] is not False:
        raise WorkerContractError("a worker result must state executed: false and productionMutation: false")
    if data["outcome"] not in WORKER_OUTCOMES:
        raise WorkerContractError(f"unknown worker outcome {str(data['outcome'])[:30]!r}")
    outcome = WORKER_OUTCOMES[data["outcome"]]
    reasons = data["blockedReasons"]
    if not isinstance(reasons, list) or not all(isinstance(r, str) and r in BLOCK_REASONS for r in reasons) \
            or len(set(reasons)) != len(reasons):
        raise WorkerContractError("result.blockedReasons must be distinct known reason codes")

    operation = None
    if data["operation"] is None:
        if outcome is not RemediationOutcome.BLOCKED or "INVALID_REQUEST" not in reasons or data["target"] is not None:
            raise WorkerContractError("only an unreadable request may omit the operation")
    elif data["operation"] in {o.value for o in RemediationOperation}:
        operation = RemediationOperation(data["operation"])
    else:
        raise WorkerContractError("result.operation is not a known operation")

    target = None
    if data["target"] is not None:
        if operation is None:
            raise WorkerContractError("a target needs an operation")
        target = _object(data["target"], "result.target", frozenset(TARGET_KEYS[operation]))
        for key, value in target.items():
            _text(value, f"result.target.{key}", max_length=1024)

    correlation = _text(data["correlationId"], "result.correlationId", max_length=100, allow_none=True)
    if correlation is not None and not _CORRELATION_RE.match(correlation):
        raise WorkerContractError("result.correlationId has characters outside [A-Za-z0-9._:-]")
    try:
        observed = datetime.strptime(str(data["observedAt"]), _TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        raise WorkerContractError("result.observedAt must be a UTC time like 2026-01-01T00:00:00Z") from None

    checks = []
    if not isinstance(data["checks"], list):
        raise WorkerContractError("result.checks must be a list")
    for index, raw in enumerate(data["checks"]):
        check = _object(raw, f"result.checks[{index}]", frozenset({"code", "passed", "detail"}))
        if check["code"] not in CHECK_CODES or not isinstance(check["passed"], bool):
            raise WorkerContractError(f"result.checks[{index}] has an unknown code or a non-boolean result")
        checks.append(WorkerCheck(check["code"], check["passed"],
                                  _text(check["detail"], f"result.checks[{index}].detail")))

    changes = []
    if not isinstance(data["plannedChanges"], list):
        raise WorkerContractError("result.plannedChanges must be a list")
    for index, raw in enumerate(data["plannedChanges"]):
        change = _object(raw, f"result.plannedChanges[{index}]", frozenset({"action", "summary", "details"}))
        if operation is None or change["action"] != PLANNED_ACTIONS[operation]:
            raise WorkerContractError(f"result.plannedChanges[{index}].action does not belong to the operation")
        details = _object(change["details"], f"result.plannedChanges[{index}].details")
        for key, value in details.items():
            _text(key, f"result.plannedChanges[{index}].details key", max_length=100)
            _text(value, f"result.plannedChanges[{index}].details.{key}", max_length=1024)
        target_id = (target.get("objectGuid") or f"{target.get('oktaAppId')}/{target.get('oktaGroupId')}") \
            if target else "-"
        changes.append(PlannedChange(
            system="okta" if operation is RemediationOperation.OKTA_GROUP_UNASSIGN else "ad",
            action=change["action"], target_id=target_id[:100],
            summary=_text(change["summary"], f"result.plannedChanges[{index}].summary"),
            details=tuple(sorted(details.items()))))

    if outcome is RemediationOutcome.BLOCKED:
        if not reasons or changes:
            raise WorkerContractError("a Blocked result names its reasons and plans nothing")
    elif reasons or not changes or target is None:
        raise WorkerContractError(f"a {data['outcome']} result names its target and its planned change, "
                                  "and no block reason")

    if expected is not None:
        # A Blocked answer to an unreadable target (invalid or a pattern) does not echo it.
        if data["operation"] != expected.get("operation") or (target is not None and target != expected.get("target")):
            raise WorkerContractError("the worker answered for a different operation or target")
        if correlation != expected.get("correlationId"):
            raise WorkerContractError("the worker answered a different request")
        # The JSON boundary has two modes, and each admits only its own outcome or Blocked.
        # Nothing that crossed it can come back Simulated.
        admitted = {"WhatIf": RemediationOutcome.WHATIF, "ValidateOnly": RemediationOutcome.VALIDATION_ONLY}
        if outcome not in (admitted.get(expected.get("mode")), RemediationOutcome.BLOCKED):
            raise WorkerContractError(f"a {expected.get('mode')!s:.20} request cannot come back {data['outcome']}")
    return WorkerResult(operation, outcome, correlation, observed, target, tuple(checks), tuple(changes),
                        tuple(reasons))
