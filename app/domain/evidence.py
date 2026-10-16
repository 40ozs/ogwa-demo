"""Evidence provenance, stable digests, and the freshness policy.

Every observation that can drive a lifecycle decision carries a ``Provenance``: where it
came from, when, what was queried, which collector produced it, and whether the query
completed. A destructive step never relies on evidence that is stale, future-dated, or
incomplete.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, StrEnum
from functools import cached_property
from typing import Any, ClassVar

from app.domain.errors import InvalidRecord
from app.domain.ids import check_enum, check_text, check_utc

DIGEST_PREFIX = "sha256:"


class EvidenceSource(StrEnum):
    OKTA_API = "OKTA_API"  # Okta management API (apps, groups, assignments)
    OKTA_SYSTEM_LOG = "OKTA_SYSTEM_LOG"  # Okta System Log API (usage)
    AD_VIA_AAP = "AD_VIA_AAP"  # AD read by a read-only AAP job / PowerShell worker
    CONFIGURED_MAPPING = "CONFIGURED_MAPPING"  # reviewed, version-controlled mapping configuration
    OPERATOR_ATTESTATION = "OPERATOR_ATTESTATION"  # a named human's recorded manual check
    SYNTHETIC = "SYNTHETIC"  # tests and local demos only


class ResultStatus(StrEnum):
    # The query finished and its result is fully represented. An empty result is COMPLETE.
    COMPLETE = "COMPLETE"
    # Truncated, paging interrupted, a domain unreachable, or otherwise incomplete.
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class EvidenceKind(StrEnum):
    OKTA_APPLICATION = "OKTA_APPLICATION"
    OKTA_GROUP = "OKTA_GROUP"
    ASSIGNMENT = "ASSIGNMENT"
    USAGE = "USAGE"
    AD_GROUP = "AD_GROUP"
    IDENTITY_MAPPING = "IDENTITY_MAPPING"
    DEPENDENCY = "DEPENDENCY"


class EvidencePurpose(StrEnum):
    # Becoming or remaining a candidate; human investigation.
    REVIEW = "REVIEW"
    # A human approving the next step.
    APPROVAL = "APPROVAL"
    # A dry run, recording an observed change, or any destructive step.
    EXECUTION = "EXECUTION"


@dataclass(frozen=True)
class Provenance:
    source: EvidenceSource
    observed_at: datetime
    scope: str  # what was queried, e.g. "okta:group:<id>:apps"; synthetic in tests and docs
    collector_version: str
    result_status: ResultStatus

    def __post_init__(self) -> None:
        check_enum(self.source, EvidenceSource, "source")
        check_utc(self.observed_at, "observed_at")
        check_text(self.scope, "scope", max_length=500)
        check_text(self.collector_version, "collector_version", max_length=100)
        check_enum(self.result_status, ResultStatus, "result_status")

    @property
    def decision_grade(self) -> bool:
        return self.result_status is ResultStatus.COMPLETE


class Evidence:
    """Mixin for observation records: a kind, a provenance, and a digest of material fields.

    ``material()`` lists only the fields whose change should invalidate an approval.
    Collection timestamps are deliberately excluded, so re-observing identical facts does
    not invalidate an approval; freshness is checked separately.
    """

    KIND: ClassVar[EvidenceKind]
    id: str
    provenance: Provenance

    def material(self) -> dict[str, Any]:
        raise NotImplementedError

    @cached_property
    def digest(self) -> str:
        return stable_digest({"kind": self.KIND.value, "id": self.id, "material": self.material()})


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return check_utc(value, "datetime").astimezone(timezone.utc).isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        # Sort by canonical text so sets of mixed or nested values still order deterministically.
        return sorted((json.loads(_canonical(v)) for v in value), key=_canonical)
    raise TypeError(f"Cannot digest value of type {type(value).__name__}")


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_encode)


def stable_digest(payload: Any) -> str:
    """SHA-256 over canonical JSON (sorted keys, no whitespace). Order-independent for sets."""
    text = _canonical(payload)
    return DIGEST_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.startswith(DIGEST_PREFIX) or len(value) != len(DIGEST_PREFIX) + 64:
        raise InvalidRecord(f"{field} must be a {DIGEST_PREFIX}<64 hex> digest")
    return value


# Hard ceilings. A policy may tighten these but never loosen them.
FRESHNESS_CEILINGS: dict[EvidencePurpose, timedelta] = {
    EvidencePurpose.REVIEW: timedelta(days=90),
    EvidencePurpose.APPROVAL: timedelta(days=14),
    EvidencePurpose.EXECUTION: timedelta(hours=24),
}
MAX_CLOCK_SKEW = timedelta(minutes=15)


@dataclass(frozen=True)
class FreshnessPolicy:
    review: timedelta = timedelta(days=30)
    approval: timedelta = timedelta(days=7)
    execution: timedelta = timedelta(hours=24)
    clock_skew: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        for purpose in EvidencePurpose:
            age = self.max_age(purpose)
            if not isinstance(age, timedelta) or age <= timedelta(0):
                raise InvalidRecord(f"{purpose.value} max age must be a positive timedelta")
            if age > FRESHNESS_CEILINGS[purpose]:
                raise InvalidRecord(f"{purpose.value} max age exceeds the ceiling {FRESHNESS_CEILINGS[purpose]}")
        if not self.execution <= self.approval <= self.review:
            raise InvalidRecord("freshness must tighten with risk: execution <= approval <= review")
        if not isinstance(self.clock_skew, timedelta) or not timedelta(0) <= self.clock_skew <= MAX_CLOCK_SKEW:
            raise InvalidRecord(f"clock_skew must be between 0 and {MAX_CLOCK_SKEW}")

    def max_age(self, purpose: EvidencePurpose) -> timedelta:
        return {
            EvidencePurpose.REVIEW: self.review,
            EvidencePurpose.APPROVAL: self.approval,
            EvidencePurpose.EXECUTION: self.execution,
        }[purpose]


def freshness_problems(
    label: str, provenance: Provenance, purpose: EvidencePurpose, now: datetime, policy: FreshnessPolicy
) -> list[str]:
    """Reasons this observation cannot support a decision for ``purpose``; empty if it can."""
    check_utc(now, "now")
    problems = []
    if not provenance.decision_grade:
        problems.append(f"{label}: result {provenance.result_status.value} is not decision-grade")
    if provenance.observed_at > now + policy.clock_skew:
        problems.append(f"{label}: observed_at is in the future")
    elif now - provenance.observed_at > policy.max_age(purpose):
        problems.append(f"{label}: evidence is stale for {purpose.value} (older than {policy.max_age(purpose)})")
    return problems
