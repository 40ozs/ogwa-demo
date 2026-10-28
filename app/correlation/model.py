"""Inputs and outputs of Okta-to-AD identity correlation.

Every type here is a frozen, validated value. Nothing in this module performs I/O.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from functools import cached_property
from typing import Any, Mapping

from app.domain.errors import InvalidRecord
from app.domain.evidence import stable_digest
from app.domain.ids import IdKind, check_enum, check_external_id, check_id, check_text, check_utc
from app.domain.mapping_review import MappingMethod, MappingReview, canonical_guid, check_sid
from app.domain.model import MappingConfidence, OktaGroupType
from app.integrations.ad.contract import LookupKind
from app.integrations.okta.models import OktaGroupRecord
from app.integrations.okta.normalize import OBJECT_GUID_DECODING_VERIFIED

CORRELATION_VERSION = "ogwa-correlation/1"

# Owner decision D37: a directory-source objectSid match (Okta's AD integration carries
# the SID and AD resolves it) may count as exact only after P11 validates the mechanism
# against a known AD-backed Okta group and records it in a run report. Until then such a
# match is review evidence (UNVERIFIED_IDENTIFIER / UNVERIFIED_STABLE_ID, D56), never a name
# match and never exact; it can still corroborate an exact mapping established another way. Changing this is a reviewed source change,
# like OBJECT_GUID_DECODING_VERIFIED; tests pin it.
DIRECTORY_SOURCE_SID_VERIFIED = False
_DNS_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_NETBIOS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!@#$%^&')(.\-_{}~]{0,14}$")

# Lookups one correlation may issue. Each is one bounded worker request.
DEFAULT_MAX_LOOKUPS = 10
MAX_LOOKUPS_CEILING = 16
# Candidates kept from one name search; the worker's maxAmbiguousCandidates ceiling is 25.
DEFAULT_MAX_CANDIDATES = 10
MAX_CANDIDATES_CEILING = 25


def check_domain(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _DNS_RE.match(value):
        raise InvalidRecord(f"{field_name} must be a lowercase DNS domain name")
    return value


def _same_text(a: str | None, b: str | None) -> bool:
    """AD compares names and DNs case-insensitively."""
    return a is not None and b is not None and a.casefold() == b.casefold()


# --- Okta side -----------------------------------------------------------------------


@dataclass(frozen=True)
class OktaGroupIdentity:
    """What correlation may use from one Okta group observation.

    ``directory_object_guid`` is set only when the Okta-derived objectGUID decoding is
    verified (``OBJECT_GUID_DECODING_VERIFIED``, D23/D30). Until then it is always None,
    so no correlation path can rest on it.
    """

    okta_group_ref: str  # internal ogrp id
    okta_group_id: str
    name: str
    group_type: OktaGroupType
    observed_at: datetime
    complete: bool  # the Okta observation was COMPLETE
    source_app_id: str | None = None
    directory_object_sid: str | None = None
    directory_object_guid: str | None = None
    directory_qualified_name: str | None = None  # DOMAIN\sAMAccountName
    distinguished_name: str | None = None
    sam_account_name: str | None = None

    def __post_init__(self) -> None:
        check_id(self.okta_group_ref, IdKind.OKTA_GROUP, "okta_group_ref")
        check_external_id(self.okta_group_id, "okta_group_id")
        check_text(self.name, "name", max_length=300)
        check_enum(self.group_type, OktaGroupType, "group_type")
        check_utc(self.observed_at, "observed_at")
        if not isinstance(self.complete, bool):
            raise InvalidRecord("complete must be a bool")
        directory = (self.source_app_id, self.directory_object_sid, self.directory_object_guid,
                     self.directory_qualified_name, self.distinguished_name, self.sam_account_name)
        if self.group_type is not OktaGroupType.APP_GROUP and any(v is not None for v in directory):
            raise InvalidRecord("directory attributes are only valid on APP_GROUP groups")
        if self.source_app_id is not None:
            check_external_id(self.source_app_id, "source_app_id")
        if self.directory_object_sid is not None:
            check_sid(self.directory_object_sid, "directory_object_sid")
        if self.directory_object_guid is not None:
            if not OBJECT_GUID_DECODING_VERIFIED:
                raise InvalidRecord("an Okta-derived objectGUID cannot be used until its decoding is verified (D30)")
            canonical_guid(self.directory_object_guid, "directory_object_guid")
        for name in ("directory_qualified_name", "distinguished_name", "sam_account_name"):
            value = getattr(self, name)
            if value is not None:
                check_text(value, name, max_length=1000)

    @classmethod
    def from_record(cls, record: OktaGroupRecord, *, okta_group_ref: str, observed_at: datetime,
                    complete: bool) -> "OktaGroupIdentity":
        """From a normalized Okta group. The unverified decoded GUID is dropped (D23, D30)."""
        directory: dict[str, Any] = {}
        if record.group_type.value == OktaGroupType.APP_GROUP.value:
            directory = dict(
                source_app_id=record.source_app_id,
                directory_object_sid=record.directory_object_sid,
                directory_object_guid=record.directory_object_guid_unverified if OBJECT_GUID_DECODING_VERIFIED else None,
                directory_qualified_name=record.directory_qualified_name,
                distinguished_name=record.distinguished_name,
                sam_account_name=record.sam_account_name,
            )
        return cls(okta_group_ref=okta_group_ref, okta_group_id=record.okta_group_id, name=record.name,
                   group_type=OktaGroupType(record.group_type.value), observed_at=observed_at, complete=complete,
                   **directory)

    @property
    def qualified_sam(self) -> tuple[str | None, str | None]:
        """(NetBIOS domain, sAMAccountName) from DOMAIN\\name, or (None, None)."""
        value = self.directory_qualified_name
        if value is None or value.count("\\") != 1:
            return None, None
        netbios, sam = value.split("\\")
        return (netbios or None), (sam or None)

    @property
    def effective_sam(self) -> str | None:
        return self.sam_account_name or self.qualified_sam[1]

    def material(self) -> dict[str, Any]:
        return {
            "okta_group_ref": self.okta_group_ref, "okta_group_id": self.okta_group_id, "name": self.name,
            "group_type": self.group_type, "complete": self.complete, "source_app_id": self.source_app_id,
            "directory_object_sid": self.directory_object_sid, "directory_object_guid": self.directory_object_guid,
            "directory_qualified_name": self.directory_qualified_name,
            "distinguished_name": self.distinguished_name, "sam_account_name": self.sam_account_name,
        }


# --- configuration -------------------------------------------------------------------


@dataclass(frozen=True)
class DirectorySource:
    """An Okta AD integration (app instance) and the AD domain it imports groups from."""

    okta_app_id: str
    domain: str
    netbios_name: str | None = None

    def __post_init__(self) -> None:
        check_external_id(self.okta_app_id, "okta_app_id")
        check_domain(self.domain, "domain")
        if self.netbios_name is not None and not _NETBIOS_RE.match(self.netbios_name):
            raise InvalidRecord("netbios_name is not a NetBIOS domain name")


@dataclass(frozen=True)
class ConfiguredMapping:
    """One entry of the reviewed, version-controlled mapping configuration."""

    okta_group_id: str
    ad_object_guid: str
    configuration_ref: str  # where the entry lives, e.g. "config/mappings.json#payroll"
    ad_sid: str | None = None
    domain: str | None = None

    def __post_init__(self) -> None:
        check_external_id(self.okta_group_id, "okta_group_id")
        canonical_guid(self.ad_object_guid, "ad_object_guid")
        check_text(self.configuration_ref, "configuration_ref", max_length=300)
        if self.ad_sid is not None:
            check_sid(self.ad_sid, "ad_sid")
        if self.domain is not None:
            check_domain(self.domain, "domain")


@dataclass(frozen=True)
class CorrelationConfig:
    directory_sources: tuple[DirectorySource, ...] = ()
    configured_mappings: tuple[ConfiguredMapping, ...] = ()
    max_lookups: int = DEFAULT_MAX_LOOKUPS
    max_candidates: int = DEFAULT_MAX_CANDIDATES

    def __post_init__(self) -> None:
        if not isinstance(self.directory_sources, tuple) or not all(isinstance(s, DirectorySource) for s in self.directory_sources):
            raise InvalidRecord("directory_sources must be a tuple of DirectorySource")
        if not isinstance(self.configured_mappings, tuple) or not all(
            isinstance(m, ConfiguredMapping) for m in self.configured_mappings
        ):
            raise InvalidRecord("configured_mappings must be a tuple of ConfiguredMapping")
        source_ids = [s.okta_app_id for s in self.directory_sources]
        if len(set(source_ids)) != len(source_ids):
            raise InvalidRecord("a directory source is configured twice")
        group_ids = [m.okta_group_id for m in self.configured_mappings]
        if len(set(group_ids)) != len(group_ids):
            raise InvalidRecord("an Okta group has more than one configured mapping")
        for name, value, ceiling in (("max_lookups", self.max_lookups, MAX_LOOKUPS_CEILING),
                                     ("max_candidates", self.max_candidates, MAX_CANDIDATES_CEILING)):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ceiling:
                raise InvalidRecord(f"{name} must be an integer from 1 to {ceiling}")

    def source(self, okta_app_id: str | None) -> DirectorySource | None:
        return next((s for s in self.directory_sources if s.okta_app_id == okta_app_id), None)

    def configured(self, okta_group_id: str) -> ConfiguredMapping | None:
        return next((m for m in self.configured_mappings if m.okta_group_id == okta_group_id), None)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CorrelationConfig":
        """Strict parse of the JSON configuration shape. Unknown keys are refused."""
        if not isinstance(data, Mapping):
            raise InvalidRecord("correlation configuration must be an object")
        allowed = {"directorySources", "configuredMappings", "maxLookups", "maxCandidates"}
        if set(data) - allowed:
            raise InvalidRecord(f"unknown correlation configuration keys: {sorted(set(data) - allowed)}")

        def entries(key: str, keys: set[str], required: set[str]) -> list[Mapping[str, Any]]:
            value = data.get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, Mapping) for v in value):
                raise InvalidRecord(f"{key} must be a list of objects")
            for entry in value:
                if set(entry) - keys or required - set(entry):
                    raise InvalidRecord(f"{key} entries take {sorted(keys)} and require {sorted(required)}")
            return value

        sources = tuple(
            DirectorySource(okta_app_id=e["oktaAppId"], domain=e["domain"], netbios_name=e.get("netbiosName"))
            for e in entries("directorySources", {"oktaAppId", "domain", "netbiosName"}, {"oktaAppId", "domain"})
        )
        mappings = tuple(
            ConfiguredMapping(okta_group_id=e["oktaGroupId"], ad_object_guid=e["adObjectGuid"],
                              configuration_ref=e["configurationRef"], ad_sid=e.get("adSid"), domain=e.get("domain"))
            for e in entries("configuredMappings", {"oktaGroupId", "adObjectGuid", "adSid", "domain", "configurationRef"},
                             {"oktaGroupId", "adObjectGuid", "configurationRef"})
        )
        return cls(directory_sources=sources, configured_mappings=mappings,
                   max_lookups=data.get("maxLookups", DEFAULT_MAX_LOOKUPS),
                   max_candidates=data.get("maxCandidates", DEFAULT_MAX_CANDIDATES))


# --- AD side -------------------------------------------------------------------------


@dataclass(frozen=True)
class ADIdentity:
    """The identity of one AD group as a lookup reported it."""

    object_guid: str
    object_sid: str | None
    distinguished_name: str
    sam_account_name: str | None
    domain: str

    def __post_init__(self) -> None:
        canonical_guid(self.object_guid, "object_guid")
        if self.object_sid is not None:
            check_sid(self.object_sid, "object_sid")
        check_text(self.distinguished_name, "distinguished_name", max_length=1000)
        if self.sam_account_name is not None:
            check_text(self.sam_account_name, "sam_account_name", max_length=256)
        check_domain(self.domain, "domain")

    def material(self) -> dict[str, Any]:
        return {"object_guid": self.object_guid, "object_sid": self.object_sid,
                "distinguished_name": self.distinguished_name, "sam_account_name": self.sam_account_name,
                "domain": self.domain}


class LookupStatus(StrEnum):
    RESOLVED = "RESOLVED"  # exactly one group
    NOT_FOUND = "NOT_FOUND"  # every domain in scope searched; nothing matched
    AMBIGUOUS = "AMBIGUOUS"  # more than one group matched
    INCOMPLETE = "INCOMPLETE"  # a domain in scope could not be searched
    FAILED = "FAILED"  # the lookup could not be performed or its answer could not be trusted


@dataclass(frozen=True)
class ADIdentityLookup:
    """One bounded, exact-match AD lookup and its answer."""

    by: LookupKind
    value: str
    domain: str | None
    status: LookupStatus
    observed_at: datetime
    candidates: tuple[ADIdentity, ...] = ()
    candidates_truncated: bool = False
    searched_domains: tuple[str, ...] = ()
    unsearched_domains: tuple[str, ...] = ()
    error: str | None = None

    def __post_init__(self) -> None:
        check_enum(self.by, LookupKind, "by")
        check_text(self.value, "value", max_length=1024)
        if self.domain is not None:
            check_domain(self.domain, "domain")
        check_enum(self.status, LookupStatus, "status")
        check_utc(self.observed_at, "observed_at")
        if not isinstance(self.candidates, tuple) or not all(isinstance(c, ADIdentity) for c in self.candidates):
            raise InvalidRecord("candidates must be a tuple of ADIdentity")
        guids = [c.object_guid for c in self.candidates]
        if len(set(guids)) != len(guids):
            raise InvalidRecord("candidates repeat an AD object")
        if self.status is LookupStatus.RESOLVED and len(self.candidates) != 1:
            raise InvalidRecord("a RESOLVED lookup has exactly one candidate")
        if self.status is LookupStatus.NOT_FOUND and (self.candidates or self.unsearched_domains):
            raise InvalidRecord("a NOT_FOUND lookup has no candidates and no unsearched domains")
        if self.status is LookupStatus.AMBIGUOUS and len(self.candidates) < 2:
            raise InvalidRecord("an AMBIGUOUS lookup has at least two candidates")

    @property
    def complete(self) -> bool:
        """Decision-grade: answered, every domain in scope searched, nothing cut off.

        Stricter than the worker for stable identifiers: the worker treats one objectGUID
        or SID hit as unique even if another domain was unreachable. Correlation never
        resolves while any domain in scope is unsearched.
        """
        return (
            self.status in (LookupStatus.RESOLVED, LookupStatus.NOT_FOUND, LookupStatus.AMBIGUOUS)
            and not self.unsearched_domains
            and not self.candidates_truncated
        )

    @property
    def resolved(self) -> ADIdentity | None:
        return self.candidates[0] if self.status is LookupStatus.RESOLVED else None

    def material(self) -> dict[str, Any]:
        return {
            "by": self.by, "value": self.value, "domain": self.domain, "status": self.status,
            "candidates": sorted(c.object_guid for c in self.candidates),
            "candidates_truncated": self.candidates_truncated,
            "unsearched_domains": sorted(self.unsearched_domains),
        }


# --- results -------------------------------------------------------------------------


class CorrelationOutcome(StrEnum):
    RESOLVED = "RESOLVED"  # one exact, verified AD counterpart
    REVIEW_REQUIRED = "REVIEW_REQUIRED"  # one counterpart by name only (NAME_ONLY)
    # One counterpart by a stable identifier whose mechanism is not verified yet (D37, D56).
    UNVERIFIED_IDENTIFIER = "UNVERIFIED_IDENTIFIER"
    AMBIGUOUS = "AMBIGUOUS"  # several possible counterparts
    NOT_FOUND = "NOT_FOUND"  # no counterpart; every domain in scope searched
    STALE = "STALE"  # a previously verified or configured mapping no longer holds
    CONFLICT = "CONFLICT"  # evidence disagrees, or Okta metadata is inconsistent
    INCOMPLETE = "INCOMPLETE"  # a lookup or the Okta observation was incomplete


class OktaSourceState(StrEnum):
    VERIFIABLE = "VERIFIABLE"  # imported by a configured AD integration and carries a stable id
    ABSENT = "ABSENT"  # AD-sourced, but no stable identifier
    INCONSISTENT = "INCONSISTENT"  # the directory attributes contradict each other or the source
    UNCONFIGURED_SOURCE = "UNCONFIGURED_SOURCE"  # APP_GROUP from a source that is not a configured AD integration
    NOT_DIRECTORY = "NOT_DIRECTORY"  # mastered in Okta
    BUILT_IN = "BUILT_IN"  # e.g. Everyone; no AD counterpart


class DriftKind(StrEnum):
    OKTA_GROUP_RENAMED = "OKTA_GROUP_RENAMED"
    AD_GROUP_RENAMED = "AD_GROUP_RENAMED"  # sAMAccountName changed since review
    AD_GROUP_MOVED = "AD_GROUP_MOVED"  # DN changed since review (move or CN rename)
    OKTA_DIRECTORY_METADATA_STALE = "OKTA_DIRECTORY_METADATA_STALE"  # Okta's copy of a name or DN lags AD
    AD_GROUP_CHANGED_DOMAIN = "AD_GROUP_CHANGED_DOMAIN"  # objectGUID now lives in another domain
    AD_SID_MISMATCH = "AD_SID_MISMATCH"  # the object found by objectGUID has a different SID
    IDENTITY_REASSIGNED = "IDENTITY_REASSIGNED"  # a mapped SID now resolves to a different object
    MAPPING_UNRESOLVABLE = "MAPPING_UNRESOLVABLE"  # a verified or configured identity no longer resolves
    DUPLICATE_CANDIDATES = "DUPLICATE_CANDIDATES"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"  # evidence sources resolve to different AD objects
    REJECTED_PAIRING = "REJECTED_PAIRING"  # an operator rejected this pairing
    OKTA_SOURCE_CHANGED = "OKTA_SOURCE_CHANGED"  # Okta's directory metadata no longer supports the approval
    OKTA_METADATA_INCONSISTENT = "OKTA_METADATA_INCONSISTENT"
    CONFIGURATION_REMOVED = "CONFIGURATION_REMOVED"  # an approved configured mapping is no longer configured


# Drift that only needs to be seen: the stable identifiers still agree.
INFORMATIONAL_DRIFT = frozenset({
    DriftKind.OKTA_GROUP_RENAMED,
    DriftKind.AD_GROUP_RENAMED,
    DriftKind.AD_GROUP_MOVED,
    DriftKind.OKTA_DIRECTORY_METADATA_STALE,
})


@dataclass(frozen=True)
class DriftFinding:
    kind: DriftKind
    detail: str

    def __post_init__(self) -> None:
        check_enum(self.kind, DriftKind, "kind")
        check_text(self.detail, "detail", max_length=500)

    @property
    def blocking(self) -> bool:
        return self.kind not in INFORMATIONAL_DRIFT


@dataclass(frozen=True)
class ClaimCheck:
    """One source's claim about the AD counterpart, and what AD said about it."""

    method: MappingMethod | None  # None for a stored approval re-verified by its stable ids
    basis: str  # "configured", "directory-source", "approved-review", "pending-selection"
    claimed_guid: str | None
    claimed_sid: str | None
    target: ADIdentity | None  # the AD object the claim resolves to, if it resolves
    complete: bool  # every lookup behind the check was decision-grade
    drift: tuple[DriftFinding, ...] = ()

    @property
    def blocked(self) -> bool:
        return any(d.blocking for d in self.drift)


@dataclass(frozen=True)
class CorrelationResult:
    okta: OktaGroupIdentity
    outcome: CorrelationOutcome
    okta_source: OktaSourceState
    confidence: MappingConfidence
    evaluated_at: datetime
    method: MappingMethod | None = None
    target: ADIdentity | None = None  # RESOLVED / REVIEW_REQUIRED / UNVERIFIED_IDENTIFIER only
    candidates: tuple[ADIdentity, ...] = ()  # every AD object this correlation considered possible
    matched_attributes: tuple[str, ...] = ()
    configuration_ref: str | None = None
    drift: tuple[DriftFinding, ...] = ()
    reasons: tuple[str, ...] = ()
    claims: tuple[ClaimCheck, ...] = ()
    lookups: tuple[ADIdentityLookup, ...] = ()
    approval: MappingReview | None = None  # the approval in force, if any
    pending: ClaimCheck | None = None  # verification of a pending operator selection
    previously_rejected: tuple[str, ...] = field(default=())  # candidate GUIDs an operator rejected

    @property
    def is_exact(self) -> bool:
        return self.outcome is CorrelationOutcome.RESOLVED

    @property
    def blocking_drift(self) -> tuple[DriftFinding, ...]:
        return tuple(d for d in self.drift if d.blocking)

    @cached_property
    def evidence_fingerprint(self) -> str:
        """Digest of everything an operator decision rests on. Timestamps excluded."""
        return stable_digest({
            "version": CORRELATION_VERSION,
            "okta": self.okta.material(),
            "outcome": self.outcome,
            "okta_source": self.okta_source,
            "confidence": self.confidence,
            "method": self.method,
            "target": self.target.material() if self.target else None,
            "candidates": sorted((c.material() for c in self.candidates), key=lambda m: m["object_guid"]),
            "matched_attributes": sorted(self.matched_attributes),
            "configuration_ref": self.configuration_ref,
            "drift": sorted([d.kind.value, d.detail] for d in self.drift),
            "lookups": sorted((lk.material() for lk in self.lookups), key=stable_digest),
            "approval": self.approval.id if self.approval else None,
            "pending": self.pending.target.material() if self.pending and self.pending.target else None,
            "previously_rejected": sorted(self.previously_rejected),
        })
