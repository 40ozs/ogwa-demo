"""Observation entities: Okta applications, groups, assignments, usage, AD groups,
identity mappings, and dependency evidence.

Each record has a stable internal ``id`` and carries external identifiers as attributes.
A record is one observation; re-observing the same object (or, for usage and dependency
checks, the same scope) produces a new record with the same ``id`` and a new
``provenance``. Stable ids keep the evidence fingerprint stable when nothing material
has changed.
"""

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from app.domain.errors import InvalidRecord
from app.domain.evidence import Evidence, EvidenceKind, EvidenceSource, Provenance
from app.domain.ids import (
    IdKind,
    check_enum,
    check_external_id,
    check_id,
    check_ids,
    check_text,
    check_utc,
)

_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")
BUILTIN_SID_PREFIX = "S-1-5-32-"
# Domain RIDs below 1000 are well-known (Domain Admins 512, Schema Admins 518, Enterprise
# Admins 519, ...). Matching by RID is locale-independent, unlike matching by name.
FIRST_ORDINARY_RID = 1000


def _check_provenance(value: object) -> Provenance:
    if not isinstance(value, Provenance):
        raise InvalidRecord("provenance must be a Provenance")
    return value


def _check_count(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InvalidRecord(f"{field} must be a non-negative integer")
    return value


def _check_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidRecord(f"{field} must be a bool")
    return value


# --- Okta ----------------------------------------------------------------------------


class OktaAppStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class OktaGroupType(StrEnum):
    OKTA_GROUP = "OKTA_GROUP"  # mastered in Okta
    APP_GROUP = "APP_GROUP"  # imported from a directory or app integration (e.g. AD)
    BUILT_IN = "BUILT_IN"  # e.g. "Everyone"; always protected


@dataclass(frozen=True)
class OktaApplication(Evidence):
    KIND = EvidenceKind.OKTA_APPLICATION

    id: str
    okta_app_id: str
    label: str
    status: OktaAppStatus
    sign_on_mode: str
    provenance: Provenance

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.OKTA_APPLICATION, "id")
        check_external_id(self.okta_app_id, "okta_app_id")
        check_text(self.label, "label", max_length=200)
        check_enum(self.status, OktaAppStatus, "status")
        check_text(self.sign_on_mode, "sign_on_mode", max_length=100)
        _check_provenance(self.provenance)

    def material(self) -> dict[str, Any]:
        # The label is display-only; renaming an app does not change the evidence.
        return {"okta_app_id": self.okta_app_id, "status": self.status, "sign_on_mode": self.sign_on_mode}


@dataclass(frozen=True)
class OktaGroup(Evidence):
    KIND = EvidenceKind.OKTA_GROUP

    id: str
    okta_group_id: str
    name: str
    group_type: OktaGroupType
    provenance: Provenance
    # Populated for APP_GROUP groups imported from a directory integration.
    source_directory_id: str | None = None  # Okta app instance id of the directory integration
    directory_external_id: str | None = None  # the directory's immutable id (AD objectGUID)
    directory_qualified_name: str | None = None  # e.g. DOMAIN\sAMAccountName
    # Okta's copy of the AD group's objectSid (profile.objectSid), as the directory
    # integration reported it. Unverified source metadata (migration 0008): until P11
    # verifies the mechanism (D37) it may corroborate an exact mapping, never establish one.
    directory_object_sid_unverified: str | None = None

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.OKTA_GROUP, "id")
        check_external_id(self.okta_group_id, "okta_group_id")
        check_text(self.name, "name", max_length=300)
        check_enum(self.group_type, OktaGroupType, "group_type")
        _check_provenance(self.provenance)
        if self.source_directory_id is not None:
            check_external_id(self.source_directory_id, "source_directory_id")
        if self.directory_external_id is not None:
            check_text(self.directory_external_id, "directory_external_id", max_length=100)
        if self.directory_qualified_name is not None:
            check_text(self.directory_qualified_name, "directory_qualified_name", max_length=300)
        sid = self.directory_object_sid_unverified
        if sid is not None and (not isinstance(sid, str) or len(sid) > 200 or not _SID_RE.match(sid)):
            raise InvalidRecord("directory_object_sid_unverified is not a valid SID")
        directory_fields = (self.source_directory_id, self.directory_external_id, self.directory_qualified_name,
                            self.directory_object_sid_unverified)
        if self.group_type is not OktaGroupType.APP_GROUP and any(f is not None for f in directory_fields):
            raise InvalidRecord("directory attributes are only valid on APP_GROUP groups")

    def material(self) -> dict[str, Any]:
        material = {
            "okta_group_id": self.okta_group_id,
            "group_type": self.group_type,
            "source_directory_id": self.source_directory_id,
            "directory_external_id": self.directory_external_id,
            "directory_qualified_name": self.directory_qualified_name,
        }
        # Added by 0008. Only when present, so an observation without it keeps the digest
        # (and every evidence fingerprint) it had before.
        if self.directory_object_sid_unverified is not None:
            material["directory_object_sid_unverified"] = self.directory_object_sid_unverified
        return material


@dataclass(frozen=True)
class ApplicationGroupAssignment(Evidence):
    """Whether a group is assigned to an application, as of ``provenance.observed_at``.

    The ``id`` is stable per (application, group) pair, so an observation that the
    assignment is gone (``present=False``) has the same id as the earlier one.
    """

    KIND = EvidenceKind.ASSIGNMENT

    id: str
    application_id: str
    okta_group_id: str
    present: bool
    provenance: Provenance

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.ASSIGNMENT, "id")
        check_id(self.application_id, IdKind.OKTA_APPLICATION, "application_id")
        check_id(self.okta_group_id, IdKind.OKTA_GROUP, "okta_group_id")
        _check_bool(self.present, "present")
        _check_provenance(self.provenance)

    def material(self) -> dict[str, Any]:
        return {"application_id": self.application_id, "okta_group_id": self.okta_group_id, "present": self.present}


@dataclass(frozen=True)
class ApplicationUsageObservation(Evidence):
    """Sign-in activity for an application over a window.

    ``okta_group_id`` is None for application-wide usage, or set when usage is
    attributed to members of one group. The ``id`` is stable per (application, group
    scope), so a rolling re-collection keeps the same id.
    """

    KIND = EvidenceKind.USAGE

    id: str
    application_id: str
    okta_group_id: str | None
    window_start: datetime
    window_end: datetime
    event_count: int
    distinct_user_count: int
    last_activity_at: datetime | None
    provenance: Provenance

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.USAGE_OBSERVATION, "id")
        check_id(self.application_id, IdKind.OKTA_APPLICATION, "application_id")
        if self.okta_group_id is not None:
            check_id(self.okta_group_id, IdKind.OKTA_GROUP, "okta_group_id")
        check_utc(self.window_start, "window_start")
        check_utc(self.window_end, "window_end")
        _check_count(self.event_count, "event_count")
        _check_count(self.distinct_user_count, "distinct_user_count")
        _check_provenance(self.provenance)
        if self.window_end <= self.window_start:
            raise InvalidRecord("window_end must be after window_start")
        if self.window_end > self.provenance.observed_at:
            raise InvalidRecord("window_end cannot be later than observed_at")
        if self.distinct_user_count > self.event_count:
            raise InvalidRecord("distinct_user_count cannot exceed event_count")
        if self.last_activity_at is not None:
            check_utc(self.last_activity_at, "last_activity_at")
            if self.last_activity_at > self.window_end:
                raise InvalidRecord("last_activity_at cannot be after window_end")
            if self.event_count == 0 and self.last_activity_at >= self.window_start:
                raise InvalidRecord("last_activity_at inside the window contradicts event_count 0")

    @property
    def window(self) -> timedelta:
        return self.window_end - self.window_start

    def material(self) -> dict[str, Any]:
        # The window length is material; its absolute position is not, so a rolling
        # re-collection that finds the same activity does not invalidate an approval.
        return {
            "application_id": self.application_id,
            "okta_group_id": self.okta_group_id,
            "window_days": self.window.days,
            "event_count": self.event_count,
            "distinct_user_count": self.distinct_user_count,
            "last_activity_at": self.last_activity_at,
        }


# --- Active Directory ----------------------------------------------------------------


@dataclass(frozen=True)
class ADGroup(Evidence):
    """An AD group resolved by objectGUID against its own domain.

    ``exists=False`` records a complete lookup by objectGUID that found no object.
    """

    KIND = EvidenceKind.AD_GROUP

    id: str
    object_guid: str  # canonical lowercase UUID
    domain: str  # DNS name of the owning domain
    exists: bool
    provenance: Provenance
    sid: str | None = None
    distinguished_name: str | None = None
    sam_account_name: str | None = None
    admin_count: bool = False
    protected_from_accidental_deletion: bool = False
    is_critical_system_object: bool = False
    member_count: int | None = None

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.AD_GROUP, "id")
        try:
            canonical = str(uuid.UUID(self.object_guid))
        except (TypeError, ValueError, AttributeError):
            raise InvalidRecord("object_guid must be a UUID") from None
        if canonical != self.object_guid:
            raise InvalidRecord("object_guid must be in canonical lowercase form")
        check_text(self.domain, "domain", max_length=255)
        _check_bool(self.exists, "exists")
        _check_provenance(self.provenance)
        for name in ("admin_count", "protected_from_accidental_deletion", "is_critical_system_object"):
            _check_bool(getattr(self, name), name)
        if self.member_count is not None:
            _check_count(self.member_count, "member_count")
        if self.exists:
            if self.sid is None or not _SID_RE.match(self.sid):
                raise InvalidRecord("an existing AD group needs a valid sid")
            check_text(self.distinguished_name, "distinguished_name", max_length=1000)
            check_text(self.sam_account_name, "sam_account_name", max_length=256)
        elif self.sid is not None and not _SID_RE.match(self.sid):
            raise InvalidRecord("sid is not a valid SID")

    @property
    def well_known_rid(self) -> int | None:
        """The RID if this SID is a well-known (builtin or RID < 1000) group, else None."""
        if self.sid is None:
            return None
        rid = int(self.sid.rsplit("-", 1)[1])
        if self.sid.startswith(BUILTIN_SID_PREFIX) or rid < FIRST_ORDINARY_RID:
            return rid
        return None

    def material(self) -> dict[str, Any]:
        # member_count is material: a group that gains members is no longer the group
        # that was reviewed.
        return {
            "object_guid": self.object_guid,
            "domain": self.domain.lower(),
            "exists": self.exists,
            "sid": self.sid,
            "distinguished_name": self.distinguished_name,
            "sam_account_name": self.sam_account_name,
            "admin_count": self.admin_count,
            "protected_from_accidental_deletion": self.protected_from_accidental_deletion,
            "is_critical_system_object": self.is_critical_system_object,
            "member_count": self.member_count,
        }


# --- Identity mapping ----------------------------------------------------------------


class MappingConfidence(StrEnum):
    # The Okta group carries the AD group's immutable id (objectGUID or objectSid).
    EXACT_STABLE_ID = "EXACT_STABLE_ID"
    # The Okta group was imported by a known AD integration and matches exactly one
    # object in that integration's domain by its directory attributes.
    EXACT_DIRECTORY_SOURCE = "EXACT_DIRECTORY_SOURCE"
    # A reviewed mapping configuration names the pair explicitly.
    EXACT_CONFIGURED_MAPPING = "EXACT_CONFIGURED_MAPPING"
    # Names match, nothing stronger. Supports human investigation only.
    NAME_ONLY = "NAME_ONLY"
    # A stable identifier (the directory-source objectSid) resolves to exactly one AD group,
    # but the mechanism is not yet verified against real AD (D37, D56). Not exact, and not a
    # name match: review evidence only. Recorded from migration 0006.
    UNVERIFIED_STABLE_ID = "UNVERIFIED_STABLE_ID"
    # More than one AD group could be the counterpart.
    AMBIGUOUS = "AMBIGUOUS"
    # No AD counterpart was found.
    NOT_FOUND = "NOT_FOUND"


EXACT_CONFIDENCES = frozenset(
    {
        MappingConfidence.EXACT_STABLE_ID,
        MappingConfidence.EXACT_DIRECTORY_SOURCE,
        MappingConfidence.EXACT_CONFIGURED_MAPPING,
    }
)
UNRESOLVED_CONFIDENCES = frozenset({MappingConfidence.AMBIGUOUS, MappingConfidence.NOT_FOUND})
STABLE_ID_ATTRIBUTES = frozenset({"objectGUID", "objectSid"})


@dataclass(frozen=True)
class IdentityMapping(Evidence):
    KIND = EvidenceKind.IDENTITY_MAPPING

    id: str
    okta_group_id: str
    confidence: MappingConfidence
    ad_group_id: str | None
    reason: str
    provenance: Provenance
    matched_attributes: tuple[str, ...] = ()
    candidate_ad_group_ids: tuple[str, ...] = ()  # AMBIGUOUS only: every possible counterpart
    configuration_ref: str | None = None  # EXACT_CONFIGURED_MAPPING only

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.IDENTITY_MAPPING, "id")
        check_id(self.okta_group_id, IdKind.OKTA_GROUP, "okta_group_id")
        check_enum(self.confidence, MappingConfidence, "confidence")
        check_text(self.reason, "reason")
        _check_provenance(self.provenance)
        if not isinstance(self.matched_attributes, tuple) or not all(
            isinstance(a, str) and a for a in self.matched_attributes
        ):
            raise InvalidRecord("matched_attributes must be a tuple of non-empty strings")
        check_ids(self.candidate_ad_group_ids, IdKind.AD_GROUP, "candidate_ad_group_ids", allow_empty=True)
        if self.configuration_ref is not None:
            check_text(self.configuration_ref, "configuration_ref", max_length=300)

        c = self.confidence
        if c in UNRESOLVED_CONFIDENCES:
            if self.ad_group_id is not None:
                raise InvalidRecord(f"{c.value} mapping must not name an ad_group_id")
        else:
            check_id(self.ad_group_id, IdKind.AD_GROUP, "ad_group_id")
            if not self.matched_attributes:
                raise InvalidRecord(f"{c.value} mapping must record matched_attributes")
        if c is MappingConfidence.AMBIGUOUS:
            if len(self.candidate_ad_group_ids) < 2:
                raise InvalidRecord("AMBIGUOUS mapping must list at least two candidate AD groups")
        elif self.candidate_ad_group_ids:
            raise InvalidRecord("candidate_ad_group_ids is only valid on AMBIGUOUS mappings")
        stable_id_kinds = (MappingConfidence.EXACT_STABLE_ID, MappingConfidence.UNVERIFIED_STABLE_ID)
        if c in stable_id_kinds and not STABLE_ID_ATTRIBUTES & set(self.matched_attributes):
            raise InvalidRecord(f"{c.value} mapping must match on objectGUID or objectSid")
        if c is MappingConfidence.NAME_ONLY and STABLE_ID_ATTRIBUTES & set(self.matched_attributes):
            raise InvalidRecord("a match on a stable id is not NAME_ONLY")
        if c is MappingConfidence.EXACT_CONFIGURED_MAPPING:
            if self.configuration_ref is None:
                raise InvalidRecord("EXACT_CONFIGURED_MAPPING needs a configuration_ref")
            if self.provenance.source not in (EvidenceSource.CONFIGURED_MAPPING, EvidenceSource.SYNTHETIC):
                raise InvalidRecord("EXACT_CONFIGURED_MAPPING must come from CONFIGURED_MAPPING")
        elif self.configuration_ref is not None:
            raise InvalidRecord("configuration_ref is only valid on EXACT_CONFIGURED_MAPPING")

    @property
    def is_exact(self) -> bool:
        return self.confidence in EXACT_CONFIDENCES

    def material(self) -> dict[str, Any]:
        # The reason text is explanatory; rewording it is not a material change.
        return {
            "okta_group_id": self.okta_group_id,
            "confidence": self.confidence,
            "ad_group_id": self.ad_group_id,
            "matched_attributes": sorted(self.matched_attributes),
            "candidate_ad_group_ids": sorted(self.candidate_ad_group_ids),
            "configuration_ref": self.configuration_ref,
        }


# --- Dependencies --------------------------------------------------------------------


class DependencyKind(StrEnum):
    OKTA_OTHER_APP_ASSIGNMENT = "OKTA_OTHER_APP_ASSIGNMENT"  # group still assigned to other apps
    OKTA_POLICY_REFERENCE = "OKTA_POLICY_REFERENCE"  # sign-on/MFA policies, group rules
    AD_GROUP_MEMBERS = "AD_GROUP_MEMBERS"  # the AD group still has members
    AD_NESTED_MEMBERSHIP = "AD_NESTED_MEMBERSHIP"  # member of, or contains, other groups
    AD_ACL_REFERENCE = "AD_ACL_REFERENCE"  # file shares, OU delegation, other ACLs
    GPO_REFERENCE = "GPO_REFERENCE"  # security filtering, restricted groups, preferences
    AAP_REFERENCE = "AAP_REFERENCE"  # inventories, RBAC, surveys referencing the group
    APPLICATION_CONFIGURATION = "APPLICATION_CONFIGURATION"  # app-side config naming the group
    OTHER = "OTHER"


class DependencyCoverage(StrEnum):
    COMPLETE = "COMPLETE"  # every required kind was checked with a complete result
    PARTIAL = "PARTIAL"  # some required kinds were checked
    UNKNOWN = "UNKNOWN"  # no required kind was checked


class FindingCode(StrEnum):
    """What a finding is, for findings whose meaning a policy must tell apart (P07).

    Direct members, nested members, parent groups, and primaryGroupID references stay
    separate facts (owner decision D20). A finding without a code still blocks if it is
    blocking; it is classified by its dependency kind only.
    """

    AD_DIRECT_MEMBERS = "AD_DIRECT_MEMBERS"  # the group's member attribute has values
    AD_PRIMARY_GROUP_REFERENCES = "AD_PRIMARY_GROUP_REFERENCES"  # objects use it as their primary group
    AD_PARENT_GROUP = "AD_PARENT_GROUP"  # the group is a member of another group
    AD_MEMBER_GROUPS = "AD_MEMBER_GROUPS"  # the group contains other groups
    AD_NESTED_PRINCIPALS = "AD_NESTED_PRINCIPALS"  # principals reachable through member groups
    AD_NESTING_CYCLE = "AD_NESTING_CYCLE"  # informational
    OKTA_OTHER_APP_ASSIGNMENT = "OKTA_OTHER_APP_ASSIGNMENT"  # the group is assigned to another application


# The dependency kind each finding code belongs to.
FINDING_CODE_KINDS: dict[FindingCode, DependencyKind] = {
    FindingCode.AD_DIRECT_MEMBERS: DependencyKind.AD_GROUP_MEMBERS,
    FindingCode.AD_PRIMARY_GROUP_REFERENCES: DependencyKind.AD_GROUP_MEMBERS,
    FindingCode.AD_PARENT_GROUP: DependencyKind.AD_NESTED_MEMBERSHIP,
    FindingCode.AD_MEMBER_GROUPS: DependencyKind.AD_NESTED_MEMBERSHIP,
    FindingCode.AD_NESTED_PRINCIPALS: DependencyKind.AD_NESTED_MEMBERSHIP,
    FindingCode.AD_NESTING_CYCLE: DependencyKind.AD_NESTED_MEMBERSHIP,
    FindingCode.OKTA_OTHER_APP_ASSIGNMENT: DependencyKind.OKTA_OTHER_APP_ASSIGNMENT,
}


@dataclass(frozen=True)
class DependencyFinding:
    description: str
    blocking: bool
    reference: str | None = None
    code: FindingCode | None = None

    def __post_init__(self) -> None:
        check_text(self.description, "description", max_length=500)
        _check_bool(self.blocking, "blocking")
        if self.reference is not None:
            check_text(self.reference, "reference", max_length=500)
        if self.code is not None:
            check_enum(self.code, FindingCode, "code")

    def material(self) -> list:
        # The code is appended only when set, so uncoded findings keep their P03 digests.
        return [self.description, self.blocking, self.reference or "", *([self.code.value] if self.code else [])]


@dataclass(frozen=True)
class DependencyEvidence(Evidence):
    """The result of checking one dependency kind for one subject.

    No findings with a COMPLETE result is positive evidence that the kind was checked and
    nothing was found. That is different from never checking. The ``id`` is stable per
    (subject, kind).
    """

    KIND = EvidenceKind.DEPENDENCY

    id: str
    subject_id: str  # internal id of the Okta group or AD group that was checked
    kind: DependencyKind
    findings: tuple[DependencyFinding, ...]
    provenance: Provenance

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.DEPENDENCY_EVIDENCE, "id")
        if not isinstance(self.subject_id, str) or not self.subject_id.startswith(
            (IdKind.OKTA_GROUP.value + "_", IdKind.AD_GROUP.value + "_")
        ):
            raise InvalidRecord("subject_id must be an Okta group or AD group id")
        check_id(self.subject_id, IdKind(self.subject_id.split("_", 1)[0]), "subject_id")
        check_enum(self.kind, DependencyKind, "kind")
        if not isinstance(self.findings, tuple) or not all(isinstance(f, DependencyFinding) for f in self.findings):
            raise InvalidRecord("findings must be a tuple of DependencyFinding")
        for f in self.findings:
            if f.code is not None and FINDING_CODE_KINDS[f.code] is not self.kind:
                raise InvalidRecord(f"finding code {f.code.value} does not belong to {self.kind.value} evidence")
        _check_provenance(self.provenance)

    @property
    def blocking_findings(self) -> tuple[DependencyFinding, ...]:
        return tuple(f for f in self.findings if f.blocking)

    def material(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "kind": self.kind,
            "findings": sorted(f.material() for f in self.findings),
        }


# Sources whose checks count toward coverage. An OPERATOR_ATTESTATION is still recorded,
# and its blocking findings still block, but it never covers a kind: a manual statement
# cannot turn PARTIAL into COMPLETE (owner decision D13). Allowlist, so a new source
# counts only after review.
COVERAGE_SOURCES = frozenset(
    {EvidenceSource.OKTA_API, EvidenceSource.OKTA_SYSTEM_LOG, EvidenceSource.AD_VIA_AAP, EvidenceSource.SYNTHETIC}
)


def assess_dependency_coverage(
    evidence: tuple[DependencyEvidence, ...], required_kinds: frozenset[DependencyKind]
) -> DependencyCoverage:
    """Coverage is derived from the automated checks performed, never asserted directly."""
    if not required_kinds:
        raise InvalidRecord("required_kinds must not be empty")
    covered = {
        e.kind for e in evidence if e.provenance.decision_grade and e.provenance.source in COVERAGE_SOURCES
    }
    if required_kinds <= covered:
        return DependencyCoverage.COMPLETE
    if required_kinds & covered:
        return DependencyCoverage.PARTIAL
    return DependencyCoverage.UNKNOWN
