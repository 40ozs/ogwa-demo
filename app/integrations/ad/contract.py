"""The JSON contract between OGWA and a read-only AD reader.

OGWA never talks to Active Directory itself, and this build includes no AD reader. A request
is an ``ogwa.ad.group-read-request/v1`` document and a reader answers with one
``ogwa.ad.group-report/v1`` document. This module validates both directions strictly:
unknown keys, missing keys, wrong types, and out-of-range values are refused, so contract
drift fails closed instead of being read as "no members" or "not protected". The golden
fixtures in tests/fixtures/ad are synthetic reports in this form.
See docs/architecture/ad-integration.md.
"""

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any

REQUEST_SCHEMA = "ogwa.ad.group-read-request/v1"
REPORT_SCHEMA = "ogwa.ad.group-report/v1"
WORKER_NAME = "OGWA.ADReader"
WORKER_VERSION = "0.1.0"
COLLECTOR_VERSION = f"{WORKER_NAME}/{WORKER_VERSION}"

MAX_REPORT_CHARACTERS = 5_000_000
MAX_LOOKUP_VALUE_LENGTH = 1024

_SID_RE = re.compile(r"^S-1-[0-9]+(-[0-9]+)+$")
_DNS_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_INDICATOR_RE = re.compile(
    r"^(BuiltinDomainSid|AdminCount|CriticalSystemObject|ProtectedFromAccidentalDeletion"
    r"|WellKnownRid:[0-9]+|NestedInWellKnownGroup:S-1-[0-9]+(-[0-9]+)+)$"
)
_MAX_ERROR = 300


class ContractError(ValueError):
    """A request or worker report does not match the contract."""


class LookupKind(StrEnum):
    OBJECT_GUID = "objectGUID"
    OBJECT_SID = "objectSid"
    DISTINGUISHED_NAME = "distinguishedName"
    SAM_ACCOUNT_NAME = "samAccountName"
    NAME = "name"  # name or sAMAccountName; investigation only


@dataclass(frozen=True)
class LimitBounds:
    default: int
    ceiling: int


LIMITS: Mapping[str, LimitBounds] = MappingProxyType(
    {
        "maxDirectMembers": LimitBounds(1000, 5000),
        "maxNestedGroups": LimitBounds(100, 500),
        "maxNestingDepth": LimitBounds(10, 20),
        "maxPrimaryGroupReferences": LimitBounds(50, 1000),
        "maxParentGroups": LimitBounds(200, 1000),
        "maxAmbiguousCandidates": LimitBounds(10, 25),
    }
)
INCLUDE_KEYS = ("directMembers", "nestedMembers", "primaryGroupReferences", "memberOf")


class ResolutionStatus(StrEnum):
    RESOLVED = "Resolved"  # exactly one group, proven unique
    NOT_FOUND = "NotFound"  # every domain in scope was searched; no match
    AMBIGUOUS = "Ambiguous"  # more than one group matches
    INCONCLUSIVE = "Inconclusive"  # a domain in scope could not be searched
    FAILED = "Failed"  # a query failed, or the worker could not run
    INVALID_REQUEST = "InvalidRequest"


class SectionStatus(StrEnum):
    COMPLETE = "Complete"
    TRUNCATED = "Truncated"  # a limit was reached; counts are lower bounds
    PARTIAL = "Partial"  # something in scope could not be read
    FAILED = "Failed"
    NOT_REQUESTED = "NotRequested"
    NOT_APPLICABLE = "NotApplicable"  # the group was not resolved


class ProtectionFactsStatus(StrEnum):
    DETERMINED = "Determined"
    UNDETERMINED = "Undetermined"


MEMBER_CLASSES = ("user", "computer", "group", "foreignSecurityPrincipal", "contact", "managedServiceAccount", "other")


# --- Request -------------------------------------------------------------------------


@dataclass(frozen=True)
class ADReadRequest:
    """One read request for the worker. Prefer ``objectGUID`` or ``objectSid``."""

    by: LookupKind
    value: str
    domain: str | None = None
    include_direct_members: bool = True
    include_nested_members: bool = True
    include_primary_group_references: bool = True
    include_member_of: bool = True
    limits: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            by = LookupKind(self.by)
        except ValueError:
            raise ContractError(f"unknown lookup kind {self.by!r}") from None
        object.__setattr__(self, "by", by)
        object.__setattr__(self, "value", _lookup_value(by, self.value))
        if self.domain is not None:
            if not isinstance(self.domain, str) or not _DNS_RE.match(self.domain.lower()):
                raise ContractError("domain must be a DNS domain name")
            object.__setattr__(self, "domain", self.domain.lower())
        for name in ("include_direct_members", "include_nested_members", "include_primary_group_references", "include_member_of"):
            if not isinstance(getattr(self, name), bool):
                raise ContractError(f"{name} must be a bool")
        if self.include_nested_members and not self.include_direct_members:
            raise ContractError("nested members require direct members")
        if not isinstance(self.limits, Mapping):
            raise ContractError("limits must be a mapping")
        unknown = set(self.limits) - set(LIMITS)
        if unknown:
            raise ContractError(f"unknown limits: {sorted(unknown)}")
        resolved = {}
        for name, bounds in LIMITS.items():
            value = self.limits.get(name, bounds.default)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= bounds.ceiling:
                raise ContractError(f"limit {name} must be an integer from 1 to {bounds.ceiling}")
            resolved[name] = value
        object.__setattr__(self, "limits", MappingProxyType(resolved))

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": REQUEST_SCHEMA,
            "lookup": {"by": self.by.value, "value": self.value, "domain": self.domain},
            "include": {
                "directMembers": self.include_direct_members,
                "nestedMembers": self.include_nested_members,
                "primaryGroupReferences": self.include_primary_group_references,
                "memberOf": self.include_member_of,
            },
            "limits": dict(self.limits),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), separators=(",", ":"))

    @classmethod
    def from_payload(cls, payload: object) -> "ADReadRequest":
        data = _object(payload, "request", ("schema", "lookup", "include", "limits"))
        if data["schema"] != REQUEST_SCHEMA:
            raise ContractError(f"request.schema must be {REQUEST_SCHEMA!r}")
        lookup = _object(data["lookup"], "request.lookup", ("by", "value", "domain"))
        include = _object(data["include"], "request.include", INCLUDE_KEYS)
        limits = _object(data["limits"], "request.limits", tuple(LIMITS))
        request = cls(
            by=_str(lookup["by"], "request.lookup.by"),
            value=_str(lookup["value"], "request.lookup.value", max_length=MAX_LOOKUP_VALUE_LENGTH),
            domain=_str(lookup["domain"], "request.lookup.domain", nullable=True),
            include_direct_members=_bool(include["directMembers"], "request.include.directMembers"),
            include_nested_members=_bool(include["nestedMembers"], "request.include.nestedMembers"),
            include_primary_group_references=_bool(include["primaryGroupReferences"], "request.include.primaryGroupReferences"),
            include_member_of=_bool(include["memberOf"], "request.include.memberOf"),
            limits={k: _int(v, f"request.limits.{k}") for k, v in limits.items()},
        )
        if request.to_payload() != data:
            raise ContractError("request echo is not in normalized form")
        return request


def _lookup_value(by: LookupKind, value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_LOOKUP_VALUE_LENGTH
        or _CONTROL_RE.search(value)
        or value.strip() != value
    ):
        raise ContractError("lookup value must be 1-1024 characters without control characters or surrounding spaces")
    if by is LookupKind.OBJECT_GUID:
        try:
            return str(uuid.UUID(value))
        except ValueError:
            raise ContractError("lookup value is not a GUID") from None
    if by is LookupKind.OBJECT_SID and not _SID_RE.match(value):
        raise ContractError("lookup value is not a SID")
    if by is LookupKind.DISTINGUISHED_NAME and not re.search(r"(^|,)DC=", value, re.IGNORECASE):
        raise ContractError("lookup value is not a distinguished name")
    return value


# --- Report --------------------------------------------------------------------------


@dataclass(frozen=True)
class GroupRef:
    object_guid: str
    object_sid: str | None
    distinguished_name: str
    sam_account_name: str | None
    domain: str


@dataclass(frozen=True)
class DomainContact:
    dns_name: str
    contacted: bool
    reachable: bool | None  # None: not contacted in this run
    error: str | None


@dataclass(frozen=True)
class Resolution:
    status: ResolutionStatus
    matched_by: LookupKind | None
    searched_domains: tuple[str, ...]
    unsearched_domains: tuple[str, ...]
    candidates: tuple[GroupRef, ...]
    candidates_truncated: bool
    error: str | None


@dataclass(frozen=True)
class GroupFacts:
    object_guid: str
    object_sid: str
    rid: int
    domain_sid: str
    builtin_domain: bool
    distinguished_name: str
    sam_account_name: str
    name: str
    domain: str
    group_scope: str
    group_category: str
    admin_count: int | None
    is_critical_system_object: bool
    protected_from_accidental_deletion: bool | None  # None: could not be read
    primary_group_token: int | None
    when_created: datetime | None
    when_changed: datetime | None


@dataclass(frozen=True)
class DirectMembers:
    status: SectionStatus
    count: int | None  # number of member values (exact when read)
    by_class: Mapping[str, int]  # of the members that were classified
    member_groups: tuple[GroupRef, ...]
    unresolved: int
    error: str | None


@dataclass(frozen=True)
class NestedMembers:
    status: SectionStatus
    groups_traversed: int
    max_depth_observed: int
    principal_count: int | None  # principals plus primary-group references reached through member groups
    principal_count_is_lower_bound: bool
    cycle_detected: bool
    unexpanded_references: int
    error: str | None


@dataclass(frozen=True)
class PrimaryGroupReferences:
    status: SectionStatus
    primary_group_token: int | None
    count: int | None
    count_is_lower_bound: bool
    searched_domain: str | None
    error: str | None


@dataclass(frozen=True)
class ParentGroups:
    status: SectionStatus
    count: int | None
    count_is_lower_bound: bool
    parents: tuple[GroupRef, ...]
    searched_domains: tuple[str, ...]
    unsearched_domains: tuple[str, ...]
    error: str | None


@dataclass(frozen=True)
class ProtectionFacts:
    status: ProtectionFactsStatus
    indicators: tuple[str, ...]
    error: str | None


@dataclass(frozen=True)
class ADGroupReport:
    worker_version: str
    observed_at: datetime
    request: ADReadRequest | None
    forest_name: str | None
    forest_domains: tuple[str, ...]
    domains: tuple[DomainContact, ...]
    resolution: Resolution
    group: GroupFacts | None
    direct_members: DirectMembers
    nested_members: NestedMembers
    primary_group_references: PrimaryGroupReferences
    member_of: ParentGroups
    protection: ProtectionFacts

    @property
    def resolved(self) -> bool:
        return self.resolution.status is ResolutionStatus.RESOLVED and self.group is not None


def parse_group_report(text: str) -> ADGroupReport:
    """Parse and validate one worker report. Raises ``ContractError`` on any deviation."""
    if not isinstance(text, str):
        raise ContractError("report must be text")
    if len(text) > MAX_REPORT_CHARACTERS:
        raise ContractError("report is too large")
    try:
        payload = json.loads(text)
    except ValueError:
        raise ContractError("report is not valid JSON") from None
    return report_from_payload(payload)


def report_from_payload(payload: object) -> ADGroupReport:
    data = _object(
        payload,
        "report",
        (
            "schema", "worker", "observedAt", "request", "forest", "domains", "resolution", "group",
            "directMembers", "nestedMembers", "primaryGroupReferences", "memberOf", "protection",
        ),
    )
    if data["schema"] != REPORT_SCHEMA:
        raise ContractError(f"report.schema must be {REPORT_SCHEMA!r}")
    worker = _object(data["worker"], "report.worker", ("name", "version", "readOnly"))
    if worker["name"] != WORKER_NAME:
        raise ContractError(f"report.worker.name must be {WORKER_NAME!r}")
    if worker["version"] != WORKER_VERSION:
        raise ContractError(f"unsupported worker version {worker['version']!r}")
    if worker["readOnly"] is not True:
        raise ContractError("report.worker.readOnly must be true")

    request = None if data["request"] is None else ADReadRequest.from_payload(data["request"])
    if data["forest"] is None:
        forest_name, forest_domains = None, ()
    else:
        forest = _object(data["forest"], "report.forest", ("name", "domains"))
        forest_name = _domain(forest["name"], "report.forest.name")
        forest_domains = _domains(forest["domains"], "report.forest.domains")

    resolution = _resolution(data["resolution"])
    if resolution.status is ResolutionStatus.INVALID_REQUEST:
        if data["group"] is not None:
            raise ContractError("an invalid request cannot report a group")
    elif request is None:
        raise ContractError("report.request is required unless the request was invalid")
    group = None if data["group"] is None else _group(data["group"])
    if resolution.status is ResolutionStatus.RESOLVED and group is None:
        raise ContractError("a resolved report must include the group")
    if resolution.status is not ResolutionStatus.RESOLVED and group is not None:
        raise ContractError("only a resolved report may include a group")

    return ADGroupReport(
        worker_version=worker["version"],
        observed_at=_time(data["observedAt"], "report.observedAt"),
        request=request,
        forest_name=forest_name,
        forest_domains=forest_domains,
        domains=tuple(_domain_contact(d, f"report.domains[{i}]") for i, d in enumerate(_list(data["domains"], "report.domains"))),
        resolution=resolution,
        group=group,
        direct_members=_direct_members(data["directMembers"]),
        nested_members=_nested_members(data["nestedMembers"]),
        primary_group_references=_primary_group_references(data["primaryGroupReferences"]),
        member_of=_parent_groups(data["memberOf"]),
        protection=_protection(data["protection"]),
    )


def _resolution(value: object) -> Resolution:
    where = "report.resolution"
    data = _object(value, where, ("status", "matchedBy", "searchedDomains", "unsearchedDomains", "candidates", "candidatesTruncated", "error"))
    matched_by = _str(data["matchedBy"], f"{where}.matchedBy", nullable=True)
    return Resolution(
        status=_enum(data["status"], ResolutionStatus, f"{where}.status"),
        matched_by=None if matched_by is None else _enum(matched_by, LookupKind, f"{where}.matchedBy"),
        searched_domains=_domains(data["searchedDomains"], f"{where}.searchedDomains"),
        unsearched_domains=_domains(data["unsearchedDomains"], f"{where}.unsearchedDomains"),
        candidates=_refs(data["candidates"], f"{where}.candidates"),
        candidates_truncated=_bool(data["candidatesTruncated"], f"{where}.candidatesTruncated"),
        error=_error(data["error"], f"{where}.error"),
    )


def _group(value: object) -> GroupFacts:
    where = "report.group"
    data = _object(
        value,
        where,
        (
            "objectGUID", "objectSid", "rid", "domainSid", "builtinDomain", "distinguishedName", "samAccountName",
            "name", "domain", "groupScope", "groupCategory", "adminCount", "isCriticalSystemObject",
            "protectedFromAccidentalDeletion", "primaryGroupToken", "whenCreated", "whenChanged",
        ),
    )
    sid = _sid(data["objectSid"], f"{where}.objectSid")
    rid = _int(data["rid"], f"{where}.rid")
    domain_sid = _sid(data["domainSid"], f"{where}.domainSid")
    if sid != f"{domain_sid}-{rid}":
        raise ContractError(f"{where}: objectSid does not match domainSid and rid")
    builtin = _bool(data["builtinDomain"], f"{where}.builtinDomain")
    if builtin != sid.startswith("S-1-5-32-"):
        raise ContractError(f"{where}.builtinDomain does not match objectSid")
    pfad = data["protectedFromAccidentalDeletion"]
    return GroupFacts(
        object_guid=_guid(data["objectGUID"], f"{where}.objectGUID"),
        object_sid=sid,
        rid=rid,
        domain_sid=domain_sid,
        builtin_domain=builtin,
        distinguished_name=_str(data["distinguishedName"], f"{where}.distinguishedName", max_length=1000),
        sam_account_name=_str(data["samAccountName"], f"{where}.samAccountName", max_length=256),
        name=_str(data["name"], f"{where}.name", max_length=256),
        domain=_domain(data["domain"], f"{where}.domain"),
        group_scope=_choice(data["groupScope"], ("DomainLocal", "Global", "Universal"), f"{where}.groupScope"),
        group_category=_choice(data["groupCategory"], ("Security", "Distribution"), f"{where}.groupCategory"),
        admin_count=_int(data["adminCount"], f"{where}.adminCount", nullable=True),
        is_critical_system_object=_bool(data["isCriticalSystemObject"], f"{where}.isCriticalSystemObject"),
        protected_from_accidental_deletion=None if pfad is None else _bool(pfad, f"{where}.protectedFromAccidentalDeletion"),
        primary_group_token=_int(data["primaryGroupToken"], f"{where}.primaryGroupToken", nullable=True),
        when_created=_time(data["whenCreated"], f"{where}.whenCreated", nullable=True),
        when_changed=_time(data["whenChanged"], f"{where}.whenChanged", nullable=True),
    )


def _direct_members(value: object) -> DirectMembers:
    where = "report.directMembers"
    data = _object(value, where, ("status", "count", "byClass", "memberGroups", "unresolved", "error"))
    by_class = _object(data["byClass"], f"{where}.byClass", MEMBER_CLASSES)
    return DirectMembers(
        status=_enum(data["status"], SectionStatus, f"{where}.status"),
        count=_int(data["count"], f"{where}.count", nullable=True),
        by_class=MappingProxyType({k: _int(by_class[k], f"{where}.byClass.{k}") for k in MEMBER_CLASSES}),
        member_groups=_refs(data["memberGroups"], f"{where}.memberGroups"),
        unresolved=_int(data["unresolved"], f"{where}.unresolved"),
        error=_error(data["error"], f"{where}.error"),
    )


def _nested_members(value: object) -> NestedMembers:
    where = "report.nestedMembers"
    data = _object(
        value,
        where,
        ("status", "groupsTraversed", "maxDepthObserved", "principalCount", "principalCountIsLowerBound", "cycleDetected", "unexpandedReferences", "error"),
    )
    return NestedMembers(
        status=_enum(data["status"], SectionStatus, f"{where}.status"),
        groups_traversed=_int(data["groupsTraversed"], f"{where}.groupsTraversed"),
        max_depth_observed=_int(data["maxDepthObserved"], f"{where}.maxDepthObserved"),
        principal_count=_int(data["principalCount"], f"{where}.principalCount", nullable=True),
        principal_count_is_lower_bound=_bool(data["principalCountIsLowerBound"], f"{where}.principalCountIsLowerBound"),
        cycle_detected=_bool(data["cycleDetected"], f"{where}.cycleDetected"),
        unexpanded_references=_int(data["unexpandedReferences"], f"{where}.unexpandedReferences"),
        error=_error(data["error"], f"{where}.error"),
    )


def _primary_group_references(value: object) -> PrimaryGroupReferences:
    where = "report.primaryGroupReferences"
    data = _object(value, where, ("status", "primaryGroupToken", "count", "countIsLowerBound", "searchedDomain", "error"))
    domain = data["searchedDomain"]
    return PrimaryGroupReferences(
        status=_enum(data["status"], SectionStatus, f"{where}.status"),
        primary_group_token=_int(data["primaryGroupToken"], f"{where}.primaryGroupToken", nullable=True),
        count=_int(data["count"], f"{where}.count", nullable=True),
        count_is_lower_bound=_bool(data["countIsLowerBound"], f"{where}.countIsLowerBound"),
        searched_domain=None if domain is None else _domain(domain, f"{where}.searchedDomain"),
        error=_error(data["error"], f"{where}.error"),
    )


def _parent_groups(value: object) -> ParentGroups:
    where = "report.memberOf"
    data = _object(value, where, ("status", "count", "countIsLowerBound", "parents", "searchedDomains", "unsearchedDomains", "error"))
    return ParentGroups(
        status=_enum(data["status"], SectionStatus, f"{where}.status"),
        count=_int(data["count"], f"{where}.count", nullable=True),
        count_is_lower_bound=_bool(data["countIsLowerBound"], f"{where}.countIsLowerBound"),
        parents=_refs(data["parents"], f"{where}.parents"),
        searched_domains=_domains(data["searchedDomains"], f"{where}.searchedDomains"),
        unsearched_domains=_domains(data["unsearchedDomains"], f"{where}.unsearchedDomains"),
        error=_error(data["error"], f"{where}.error"),
    )


def _protection(value: object) -> ProtectionFacts:
    where = "report.protection"
    data = _object(value, where, ("status", "indicators", "error"))
    indicators = tuple(_str(i, f"{where}.indicators") for i in _list(data["indicators"], f"{where}.indicators"))
    for indicator in indicators:
        if not _INDICATOR_RE.match(indicator):
            raise ContractError(f"{where}: unknown indicator {indicator[:80]!r}")
    return ProtectionFacts(
        status=_enum(data["status"], ProtectionFactsStatus, f"{where}.status"),
        indicators=indicators,
        error=_error(data["error"], f"{where}.error"),
    )


def _domain_contact(value: object, where: str) -> DomainContact:
    data = _object(value, where, ("dnsName", "contacted", "reachable", "error"))
    reachable = data["reachable"]
    contact = DomainContact(
        dns_name=_domain(data["dnsName"], f"{where}.dnsName"),
        contacted=_bool(data["contacted"], f"{where}.contacted"),
        reachable=None if reachable is None else _bool(reachable, f"{where}.reachable"),
        error=_error(data["error"], f"{where}.error"),
    )
    if contact.contacted != (contact.reachable is not None):
        raise ContractError(f"{where}: reachable must be set exactly when the domain was contacted")
    return contact


def _refs(value: object, where: str) -> tuple[GroupRef, ...]:
    refs = []
    for i, item in enumerate(_list(value, where)):
        data = _object(item, f"{where}[{i}]", ("objectGUID", "objectSid", "distinguishedName", "samAccountName", "domain"))
        sid = data["objectSid"]
        refs.append(
            GroupRef(
                object_guid=_guid(data["objectGUID"], f"{where}[{i}].objectGUID"),
                object_sid=None if sid is None else _sid(sid, f"{where}[{i}].objectSid"),
                distinguished_name=_str(data["distinguishedName"], f"{where}[{i}].distinguishedName", max_length=1000),
                sam_account_name=_str(data["samAccountName"], f"{where}[{i}].samAccountName", nullable=True, max_length=256),
                domain=_domain(data["domain"], f"{where}[{i}].domain"),
            )
        )
    return tuple(refs)


# --- Primitive validators ------------------------------------------------------------


def _object(value: object, where: str, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{where} must be an object")
    extra = sorted(set(value) - set(keys))
    missing = sorted(set(keys) - set(value))
    if extra or missing:
        raise ContractError(f"{where}: unexpected keys {extra[:5]}, missing keys {missing[:5]}")
    return value


def _list(value: object, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{where} must be a list")
    return value


def _str(value: object, where: str, *, nullable: bool = False, max_length: int = 2000) -> Any:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ContractError(f"{where} must be a non-empty string of at most {max_length} characters")
    return value


def _error(value: object, where: str) -> str | None:
    return _str(value, where, nullable=True, max_length=_MAX_ERROR)


def _int(value: object, where: str, *, nullable: bool = False) -> Any:
    if value is None and nullable:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{where} must be a non-negative integer")
    return value


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{where} must be true or false")
    return value


def _enum(value: object, enum: type[StrEnum], where: str) -> Any:
    try:
        return enum(value)
    except ValueError:
        raise ContractError(f"{where} has an unknown value {str(value)[:40]!r}") from None


def _choice(value: object, choices: tuple[str, ...], where: str) -> str:
    if value not in choices:
        raise ContractError(f"{where} must be one of {choices}")
    return value  # type: ignore[return-value]


def _guid(value: object, where: str) -> str:
    try:
        canonical = str(uuid.UUID(value))  # type: ignore[arg-type]
    except (TypeError, ValueError, AttributeError):
        raise ContractError(f"{where} must be a GUID") from None
    if canonical != value:
        raise ContractError(f"{where} must be a canonical lowercase GUID")
    return canonical


def _sid(value: object, where: str) -> str:
    if not isinstance(value, str) or not _SID_RE.match(value):
        raise ContractError(f"{where} must be a SID")
    return value


def _domain(value: object, where: str) -> str:
    if not isinstance(value, str) or not _DNS_RE.match(value):
        raise ContractError(f"{where} must be a lowercase DNS domain name")
    return value


def _domains(value: object, where: str) -> tuple[str, ...]:
    return tuple(_domain(d, f"{where}[{i}]") for i, d in enumerate(_list(value, where)))


def _time(value: object, where: str, *, nullable: bool = False) -> Any:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ContractError(f"{where} must be a UTC timestamp")
    try:
        return datetime.strptime(value, _TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ContractError(f"{where} must be a UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)") from None
