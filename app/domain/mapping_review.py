"""Human review of Okta-to-AD identity mappings.

A ``MappingReview`` is one append-only event in the mapping registry of one Okta group:
an operator proposed a pairing (by selecting an AD object from bounded search results),
approved an exact verified pairing, or rejected one. The registry never changes a record;
a later event supersedes the earlier one, and the chain is checked on every append
(``review_append_problems``).

A review is a record of a human decision about identity evidence. It is not authority to
change anything in Okta or AD.
"""

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.domain.actors import Actor, ActorKind
from app.domain.errors import InvalidRecord
from app.domain.evidence import check_digest, stable_digest
from app.domain.ids import IdKind, check_enum, check_external_id, check_id, check_text, check_utc
from app.domain.model import EXACT_CONFIDENCES, MappingConfidence

_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")
REGISTRY_REF_PREFIX = "ogwa-mapping-registry:"


class MappingMethod(StrEnum):
    """How the pairing was established. Strongest first."""

    # A reviewed, version-controlled mapping configuration names the pair.
    CONFIGURED = "CONFIGURED"
    # Okta's AD integration carries the group's objectSid, and AD resolves it uniquely.
    DIRECTORY_SOURCE_SID = "DIRECTORY_SOURCE_SID"
    # As above with the objectGUID. Unreachable while OBJECT_GUID_DECODING_VERIFIED is False (D23, D30).
    DIRECTORY_SOURCE_GUID = "DIRECTORY_SOURCE_GUID"
    # A human picked the AD object from bounded search results; a second human approved it.
    OPERATOR_SELECTED = "OPERATOR_SELECTED"
    # Names match, nothing stronger. Review only; never approvable.
    NAME_MATCH = "NAME_MATCH"


class ReviewStatus(StrEnum):
    PROPOSED = "PROPOSED"  # an operator selected this pairing; a different operator must approve it
    APPROVED = "APPROVED"  # a human confirmed an exact, verified pairing
    REJECTED = "REJECTED"  # a human refused this pairing (or withdrew an earlier approval)


# The confidence each method yields when the pairing is exact. NAME_MATCH is never exact.
METHOD_CONFIDENCE: dict[MappingMethod, MappingConfidence] = {
    MappingMethod.CONFIGURED: MappingConfidence.EXACT_CONFIGURED_MAPPING,
    MappingMethod.DIRECTORY_SOURCE_SID: MappingConfidence.EXACT_STABLE_ID,
    MappingMethod.DIRECTORY_SOURCE_GUID: MappingConfidence.EXACT_STABLE_ID,
    MappingMethod.OPERATOR_SELECTED: MappingConfidence.EXACT_CONFIGURED_MAPPING,
    MappingMethod.NAME_MATCH: MappingConfidence.NAME_ONLY,
}


def canonical_guid(value: object, field: str = "object_guid") -> str:
    try:
        canonical = str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        raise InvalidRecord(f"{field} must be a UUID") from None
    if canonical != value:
        raise InvalidRecord(f"{field} must be in canonical lowercase form")
    return canonical


def check_sid(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SID_RE.match(value):
        raise InvalidRecord(f"{field} must be a SID")
    return value


@dataclass(frozen=True)
class MappingReview:
    id: str
    okta_group_ref: str  # internal id of the Okta group
    okta_group_id: str  # Okta's id, for the operator
    okta_group_name: str  # the Okta name when reviewed, to detect a later rename
    sequence: int  # position in this Okta group's review chain, from 0
    supersedes: str | None  # the previous review of this Okta group; None only for the first
    ad_object_guid: str
    ad_sid: str
    ad_distinguished_name: str  # when reviewed, to detect a later rename or move
    ad_sam_account_name: str
    ad_domain: str
    method: MappingMethod
    confidence: MappingConfidence  # the confidence the pairing has (or would have, if PROPOSED)
    review_status: ReviewStatus
    verified_at: datetime  # when a complete AD lookup last confirmed this identity
    evidence_fingerprint: str  # the correlation evidence the operator saw
    decided_by: Actor
    decided_at: datetime
    reason: str
    configuration_ref: str | None = None  # CONFIGURED only: the configuration entry

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.MAPPING_REVIEW, "id")
        check_id(self.okta_group_ref, IdKind.OKTA_GROUP, "okta_group_ref")
        check_external_id(self.okta_group_id, "okta_group_id")
        check_text(self.okta_group_name, "okta_group_name", max_length=300)
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 0:
            raise InvalidRecord("sequence must be a non-negative integer")
        if (self.sequence == 0) != (self.supersedes is None):
            raise InvalidRecord("only the first review (sequence 0) has no superseded review")
        if self.supersedes is not None:
            check_id(self.supersedes, IdKind.MAPPING_REVIEW, "supersedes")
        canonical_guid(self.ad_object_guid, "ad_object_guid")
        check_sid(self.ad_sid, "ad_sid")
        check_text(self.ad_distinguished_name, "ad_distinguished_name", max_length=1000)
        check_text(self.ad_sam_account_name, "ad_sam_account_name", max_length=256)
        check_text(self.ad_domain, "ad_domain", max_length=255)
        if self.ad_domain != self.ad_domain.lower():
            raise InvalidRecord("ad_domain must be lowercase")
        check_enum(self.method, MappingMethod, "method")
        check_enum(self.confidence, MappingConfidence, "confidence")
        check_enum(self.review_status, ReviewStatus, "review_status")
        check_utc(self.verified_at, "verified_at")
        check_digest(self.evidence_fingerprint, "evidence_fingerprint")
        if not isinstance(self.decided_by, Actor) or self.decided_by.kind is not ActorKind.HUMAN:
            raise InvalidRecord("a mapping review is always a human decision")
        check_utc(self.decided_at, "decided_at")
        check_text(self.reason, "reason")
        if self.verified_at > self.decided_at:
            raise InvalidRecord("verified_at cannot be after decided_at")

        if self.confidence is not METHOD_CONFIDENCE[self.method]:
            raise InvalidRecord(f"method {self.method.value} yields {METHOD_CONFIDENCE[self.method].value}")
        if self.review_status is ReviewStatus.APPROVED and self.confidence not in EXACT_CONFIDENCES:
            raise InvalidRecord("only an exact pairing can be approved")
        if self.review_status is ReviewStatus.PROPOSED and self.method is not MappingMethod.OPERATOR_SELECTED:
            raise InvalidRecord("only an operator selection is recorded as PROPOSED")
        if (self.method is MappingMethod.CONFIGURED) != (self.configuration_ref is not None):
            raise InvalidRecord("configuration_ref is required for, and only valid on, CONFIGURED reviews")
        if self.configuration_ref is not None:
            check_text(self.configuration_ref, "configuration_ref", max_length=300)

    @property
    def registry_ref(self) -> str:
        """How an emitted IdentityMapping cites this review as its reviewed configuration."""
        return REGISTRY_REF_PREFIX + self.id

    def same_identity(self, object_guid: str, sid: str | None) -> bool:
        return self.ad_object_guid == object_guid and (sid is None or self.ad_sid == sid)

    def material(self) -> dict[str, Any]:
        return {
            "okta_group_ref": self.okta_group_ref, "sequence": self.sequence, "supersedes": self.supersedes,
            "ad_object_guid": self.ad_object_guid, "ad_sid": self.ad_sid, "method": self.method,
            "confidence": self.confidence, "review_status": self.review_status,
            "evidence_fingerprint": self.evidence_fingerprint, "decided_by": str(self.decided_by),
        }

    @property
    def digest(self) -> str:
        return stable_digest(self.material())


def current_approval(history: tuple[MappingReview, ...]) -> MappingReview | None:
    """The approval in force: the latest APPROVED review not later rejected for the same AD object."""
    approval = None
    for review in history:
        if review.review_status is ReviewStatus.APPROVED:
            approval = review
        elif review.review_status is ReviewStatus.REJECTED and approval is not None \
                and review.ad_object_guid == approval.ad_object_guid:
            approval = None
    return approval


def rejected_guids(history: tuple[MappingReview, ...]) -> frozenset[str]:
    """AD objects whose latest review for this Okta group is a rejection."""
    latest: dict[str, ReviewStatus] = {}
    for review in history:
        latest[review.ad_object_guid] = review.review_status
    return frozenset(guid for guid, status in latest.items() if status is ReviewStatus.REJECTED)


def pending_selection(history: tuple[MappingReview, ...]) -> MappingReview | None:
    """An operator selection awaiting a second operator: the latest review, if PROPOSED."""
    if history and history[-1].review_status is ReviewStatus.PROPOSED:
        return history[-1]
    return None


def review_append_problems(history: tuple[MappingReview, ...], review: MappingReview) -> list[str]:
    """Why ``review`` cannot extend ``history`` (one Okta group's chain, oldest first)."""
    problems = []
    if not isinstance(review, MappingReview):
        return ["review must be a MappingReview"]
    if any(r.okta_group_ref != review.okta_group_ref for r in history):
        problems.append("history belongs to a different Okta group")
    if any(r.id == review.id for r in history):
        problems.append(f"review {review.id} is already recorded")
    if review.sequence != len(history):
        problems.append(f"review sequence {review.sequence} does not continue the chain (expected {len(history)})")
    expected_parent = history[-1].id if history else None
    if review.supersedes != expected_parent:
        problems.append("review must supersede the latest review of this Okta group")
    if history:
        latest = history[-1]
        if review.decided_at < latest.decided_at:
            problems.append("review cannot be dated before the review it supersedes")
        if review.okta_group_id != latest.okta_group_id:
            problems.append("Okta group id differs from the earlier reviews")
    if review.review_status is ReviewStatus.APPROVED and review.method is MappingMethod.OPERATOR_SELECTED:
        latest = history[-1] if history else None
        same = latest is not None and latest.ad_object_guid == review.ad_object_guid and latest.ad_sid == review.ad_sid
        if same and latest.review_status is ReviewStatus.PROPOSED:
            if latest.decided_by == review.decided_by:
                problems.append("the operator who selected a pairing cannot also approve it")
        elif not (same and latest.review_status is ReviewStatus.APPROVED
                  and latest.method is MappingMethod.OPERATOR_SELECTED):
            # Otherwise only a re-approval of the same approved identity, which acknowledges drift.
            problems.append("an operator-selected pairing can be approved only as the pending selection")
    return problems
