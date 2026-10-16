"""Append-only, hash-chained audit events.

Each event's digest covers its content and the previous event's digest, so editing,
removing, or reordering a stored event breaks verification. Detail values are passed
through redaction before they are recorded.

An event records who (``actor``) did what (``action``) to which target (``subject_id``),
when, in which execution mode, with what result, under which correlation id, and short
references to the state before and after. References point at stored records (for
example ``decision:<id>``); they never embed API responses or credentials.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from functools import cached_property

from app.core.modes import ExecutionMode
from app.core.redaction import REDACTED, SENSITIVE_KEY, redact_text
from app.domain.actors import Actor
from app.domain.errors import InvalidRecord
from app.domain.evidence import check_digest, stable_digest
from app.domain.ids import IdKind, check_enum, check_id, check_text, check_utc, new_id

MAX_DETAIL_VALUE = 1000
MAX_REF_LENGTH = 200
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


class AuditAction(StrEnum):
    TRANSITION_APPLIED = "TRANSITION_APPLIED"
    TRANSITION_REFUSED = "TRANSITION_REFUSED"
    APPROVAL_RECORDED = "APPROVAL_RECORDED"
    EXECUTION_JOB_RECORDED = "EXECUTION_JOB_RECORDED"
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    CANDIDATE_CREATED = "CANDIDATE_CREATED"
    EXECUTION_JOB_STATUS_RECORDED = "EXECUTION_JOB_STATUS_RECORDED"
    COLLECTOR_RUN_STARTED = "COLLECTOR_RUN_STARTED"
    COLLECTOR_RUN_FINISHED = "COLLECTOR_RUN_FINISHED"
    STORE_INITIALIZED = "STORE_INITIALIZED"
    SYNTHETIC_SEED_LOADED = "SYNTHETIC_SEED_LOADED"
    # Migration 0005 (D41). Events recorded before it keep APPROVAL_RECORDED with a "kind"
    # detail (IDENTITY_MAPPING_REVIEW or POLICY_VERSION) and are never rewritten.
    MAPPING_REVIEW_RECORDED = "MAPPING_REVIEW_RECORDED"
    POLICY_REVIEW_RECORDED = "POLICY_REVIEW_RECORDED"
    # Migration 0007 (owner decision): an authenticated, well-formed request to
    # change governed state that policy or authorization refused. Nothing else changed.
    GOVERNED_REQUEST_REFUSED = "GOVERNED_REQUEST_REFUSED"
    # Migration 0010: a remediation dry run that passed every gate and was answered
    # SIMULATED, WHATIF, or VALIDATION_ONLY. Nothing outside OGWA changed; a BLOCKED one is a
    # refusal and is chained as GOVERNED_REQUEST_REFUSED instead.
    REMEDIATION_DRY_RUN_RECORDED = "REMEDIATION_DRY_RUN_RECORDED"


class AuditResult(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    REFUSED = "REFUSED"  # a guard or policy declined the action; nothing changed
    FAILED = "FAILED"  # the action was attempted and failed


@dataclass(frozen=True)
class AuditEvent:
    id: str
    sequence: int
    occurred_at: datetime
    actor: Actor
    action: AuditAction
    subject_id: str
    details: tuple[tuple[str, str], ...]
    previous_digest: str | None
    execution_mode: ExecutionMode | None = None
    result: AuditResult | None = None
    correlation_id: str | None = None
    before_ref: str | None = None
    after_ref: str | None = None

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.AUDIT_EVENT, "id")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 0:
            raise InvalidRecord("sequence must be a non-negative integer")
        check_utc(self.occurred_at, "occurred_at")
        if not isinstance(self.actor, Actor):
            raise InvalidRecord("actor must be an Actor")
        check_enum(self.action, AuditAction, "action")
        check_text(self.subject_id, "subject_id", max_length=100)
        if not isinstance(self.details, tuple) or not all(
            isinstance(pair, tuple) and len(pair) == 2 and all(isinstance(p, str) for p in pair)
            for pair in self.details
        ):
            raise InvalidRecord("details must be a tuple of (str, str) pairs")
        if (self.sequence == 0) != (self.previous_digest is None):
            raise InvalidRecord("only the first event has no previous_digest")
        if self.previous_digest is not None:
            check_digest(self.previous_digest, "previous_digest")
        if self.execution_mode is not None:
            check_enum(self.execution_mode, ExecutionMode, "execution_mode")
        if self.result is not None:
            check_enum(self.result, AuditResult, "result")
        if self.correlation_id is not None and (
            not isinstance(self.correlation_id, str) or not _CORRELATION_RE.match(self.correlation_id)
        ):
            raise InvalidRecord("correlation_id must be 1-100 characters from [A-Za-z0-9._:-]")
        for name in ("before_ref", "after_ref"):
            if getattr(self, name) is not None:
                check_text(getattr(self, name), name, max_length=MAX_REF_LENGTH)

    @cached_property
    def digest(self) -> str:
        return stable_digest(
            {
                "id": self.id,
                "sequence": self.sequence,
                "occurred_at": self.occurred_at,
                "actor": [self.actor.kind, self.actor.id],
                "action": self.action,
                "subject_id": self.subject_id,
                "details": [list(pair) for pair in self.details],
                "previous_digest": self.previous_digest,
                "execution_mode": self.execution_mode,
                "result": self.result,
                "correlation_id": self.correlation_id,
                "before_ref": self.before_ref,
                "after_ref": self.after_ref,
            }
        )


def clean_details(details: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    cleaned = []
    for key, value in sorted(details.items()):
        text = REDACTED if SENSITIVE_KEY.search(str(key)) else redact_text(str(value))
        if len(text) > MAX_DETAIL_VALUE:
            text = text[: MAX_DETAIL_VALUE - 3] + "..."
        cleaned.append((redact_text(str(key)), text))
    return tuple(cleaned)


def next_event(
    previous: AuditEvent | None,
    *,
    actor: Actor,
    action: AuditAction,
    subject_id: str,
    occurred_at: datetime,
    details: Mapping[str, object] | None = None,
    execution_mode: ExecutionMode | None = None,
    result: AuditResult | None = None,
    correlation_id: str | None = None,
    before_ref: str | None = None,
    after_ref: str | None = None,
) -> AuditEvent:
    """The event that follows ``previous`` in a chain (the first event if it is None)."""
    if previous is not None and occurred_at < previous.occurred_at:
        raise InvalidRecord("audit events must be appended in time order")
    return AuditEvent(
        id=new_id(IdKind.AUDIT_EVENT),
        sequence=previous.sequence + 1 if previous else 0,
        occurred_at=occurred_at,
        actor=actor,
        action=action,
        subject_id=subject_id,
        details=clean_details(details or {}),
        previous_digest=previous.digest if previous else None,
        execution_mode=execution_mode,
        result=result,
        correlation_id=correlation_id,
        before_ref=redact_text(before_ref) if before_ref is not None else None,
        after_ref=redact_text(after_ref) if after_ref is not None else None,
    )


class AuditTrail:
    """In-memory append-only trail. ``app.store`` persists the same chain durably."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def append(self, **fields) -> AuditEvent:
        """Append the next event; accepts the keyword arguments of ``next_event``."""
        event = next_event(self._events[-1] if self._events else None, **fields)
        self._events.append(event)
        return event


def verify_chain(events: tuple[AuditEvent, ...] | list[AuditEvent], *, expected_head: str | None = None) -> None:
    """Raise InvalidRecord if the events are not an unbroken chain from sequence 0.

    The chain alone cannot detect a change to the newest event; pass ``expected_head``
    (the last digest, anchored somewhere the store cannot rewrite) to cover that too.
    """
    previous: AuditEvent | None = None
    for index, event in enumerate(events):
        # Recompute rather than trust a cached digest that may have been tampered with.
        recomputed = AuditEvent(**{f: getattr(event, f) for f in AuditEvent.__dataclass_fields__})
        if event.sequence != index:
            raise InvalidRecord(f"audit event {index} has sequence {event.sequence}")
        expected_previous = previous.digest if previous else None
        if event.previous_digest != expected_previous:
            raise InvalidRecord(f"audit chain broken at sequence {index}")
        previous = recomputed
    if expected_head is not None and (previous is None or previous.digest != expected_head):
        raise InvalidRecord("audit chain head does not match the anchored digest")
