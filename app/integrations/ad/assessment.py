"""What a worker report means: explicit emptiness facts and protection status.

Emptiness is three separate facts, each YES, NO, or UNKNOWN, and never one boolean:

- ``NoDirectMembers``: the group's ``member`` attribute has no values;
- ``NoNestedMembers``: no principal, and no primary-group reference, is reachable through
  the group's member groups;
- ``NoPrimaryGroupReferences``: no object in the group's domain has ``primaryGroupID``
  equal to the group's RID.

A group is ``EMPTY`` (definition ``ogwa-ad-empty/v1``) only when all three are YES. Any
NO makes it ``NOT_EMPTY``; otherwise it is ``UNDETERMINED``. Emptiness says nothing about
protection or dependencies outside membership: an empty group can still be protected.

Protection is derived from durable identity first (builtin-domain SID, RID below 1000,
nesting in such a group), then supporting attributes (``adminCount``,
``isCriticalSystemObject``, ``ProtectedFromAccidentalDeletion``), then configuration
(object GUID/SID denylist, names, DN subtrees, per-domain policy). Anything that cannot
be read makes protection ``UNDETERMINED``, and only ``NOT_PROTECTED`` permits retirement.
"""

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from app.integrations.ad.contract import (
    ADGroupReport,
    ContractError,
    ProtectionFactsStatus,
    SectionStatus,
)

EMPTINESS_DEFINITION = "ogwa-ad-empty/v1"

BUILTIN_SID_PREFIX = "S-1-5-32-"
FIRST_ORDINARY_RID = 1000

# Privileged groups whose RID is assigned per domain (>= 1000), so they cannot be found by
# RID. Matched by name as supporting evidence only; a name match can add protection,
# never remove it: the well-known privileged groups.
DEFAULT_PRIVILEGED_NAMES = frozenset({"dnsadmins", "dnsupdateproxy"})

_SID_RE = re.compile(r"^S-1-[0-9]+(-[0-9]+)+$")
_DNS_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class Fact(StrEnum):
    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"


class EmptinessVerdict(StrEnum):
    EMPTY = "EMPTY"
    NOT_EMPTY = "NOT_EMPTY"
    UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True)
class EmptinessAssessment:
    no_direct_members: Fact
    no_nested_members: Fact
    no_primary_group_references: Fact
    verdict: EmptinessVerdict
    evidence: tuple[str, ...]  # what was observed, one statement per fact
    definition: str = EMPTINESS_DEFINITION


def assess_emptiness(report: ADGroupReport) -> EmptinessAssessment:
    if not report.resolved:
        reason = f"group not resolved ({report.resolution.status.value})"
        return EmptinessAssessment(Fact.UNKNOWN, Fact.UNKNOWN, Fact.UNKNOWN, EmptinessVerdict.UNDETERMINED, (reason,))

    direct = report.direct_members
    direct_fact = _count_fact(direct.status, direct.count)
    direct_note = f"NoDirectMembers={direct_fact.value}: {direct.count} member value(s), {direct.status.value}"

    nested = report.nested_members
    nested_fact = _count_fact(nested.status, nested.principal_count)
    bound = " (lower bound)" if nested.principal_count_is_lower_bound else ""
    nested_note = (
        f"NoNestedMembers={nested_fact.value}: {nested.principal_count}{bound} principal(s) reachable through "
        f"{nested.groups_traversed} member group(s), {nested.status.value}"
    )

    primary = report.primary_group_references
    primary_fact = _count_fact(primary.status, primary.count)
    bound = " (lower bound)" if primary.count_is_lower_bound else ""
    primary_note = (
        f"NoPrimaryGroupReferences={primary_fact.value}: {primary.count}{bound} object(s) with primaryGroupID="
        f"{primary.primary_group_token}, {primary.status.value}"
    )

    facts = (direct_fact, nested_fact, primary_fact)
    if Fact.NO in facts:
        verdict = EmptinessVerdict.NOT_EMPTY
    elif all(f is Fact.YES for f in facts):
        verdict = EmptinessVerdict.EMPTY
    else:
        verdict = EmptinessVerdict.UNDETERMINED
    return EmptinessAssessment(direct_fact, nested_fact, primary_fact, verdict, (direct_note, nested_note, primary_note))


def _count_fact(status: SectionStatus, count: int | None) -> Fact:
    # A positive count is a fact even when the read stopped early (it is a lower bound).
    # Zero proves absence only when the read was complete.
    if status in (SectionStatus.NOT_REQUESTED, SectionStatus.NOT_APPLICABLE, SectionStatus.FAILED) or count is None:
        return Fact.UNKNOWN
    if count > 0:
        return Fact.NO
    return Fact.YES if status is SectionStatus.COMPLETE else Fact.UNKNOWN


# --- Protection ------------------------------------------------------------------------


class ProtectionStatus(StrEnum):
    PROTECTED = "PROTECTED"
    NOT_PROTECTED = "NOT_PROTECTED"
    UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True)
class DomainProtectionPolicy:
    retirement_allowed: bool
    protected_dn_suffixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.retirement_allowed, bool):
            raise ContractError("retirementAllowed must be true or false")
        if not isinstance(self.protected_dn_suffixes, tuple) or not all(
            isinstance(s, str) and s and re.search(r"(^|,)DC=", s, re.IGNORECASE) for s in self.protected_dn_suffixes
        ):
            raise ContractError("protectedDnSuffixes must be distinguished names")


@dataclass(frozen=True)
class ADProtectionPolicy:
    """OGWA's protection policy for AD groups. A domain absent from ``governed_domains``
    is not governed: every group in it is UNDETERMINED (fail closed)."""

    governed_domains: Mapping[str, DomainProtectionPolicy]
    protected_object_guids: frozenset[str] = frozenset()
    protected_sids: frozenset[str] = frozenset()
    protected_names: frozenset[str] = frozenset()
    effective_protected_names: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        domains = {}
        for name, policy in dict(self.governed_domains).items():
            if not isinstance(name, str) or not _DNS_RE.match(name.lower()) or not isinstance(policy, DomainProtectionPolicy):
                raise ContractError("governed_domains maps DNS domain names to DomainProtectionPolicy")
            domains[name.lower()] = policy
        object.__setattr__(self, "governed_domains", MappingProxyType(domains))
        guids = set()
        for guid in self.protected_object_guids:
            guids.add(_canonical_guid(guid))
        object.__setattr__(self, "protected_object_guids", frozenset(guids))
        if not all(isinstance(s, str) and _SID_RE.match(s) for s in self.protected_sids):
            raise ContractError("protected_sids must be SIDs")
        object.__setattr__(self, "protected_sids", frozenset(self.protected_sids))
        if not all(isinstance(n, str) and n.strip() for n in self.protected_names):
            raise ContractError("protected_names must be non-empty strings")
        names = frozenset(n.strip().casefold() for n in self.protected_names)
        object.__setattr__(self, "protected_names", names)
        # The built-in names cannot be dropped by configuration.
        object.__setattr__(self, "effective_protected_names", names | DEFAULT_PRIVILEGED_NAMES)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ADProtectionPolicy":
        """Build from a protection-policy mapping. Unknown keys are refused."""
        keys = {"governedDomains", "protectedObjectGuids", "protectedSids", "protectedNames"}
        if not isinstance(data, Mapping) or set(data) - keys or "governedDomains" not in data:
            raise ContractError(f"AD protection policy must have governedDomains and only these keys: {sorted(keys)}")
        domains = {}
        for name, entry in dict(data["governedDomains"]).items():
            if not isinstance(entry, Mapping) or set(entry) - {"retirementAllowed", "protectedDnSuffixes"}:
                raise ContractError(f"governedDomains[{name!r}] has unknown keys")
            domains[name] = DomainProtectionPolicy(
                retirement_allowed=entry.get("retirementAllowed"),
                protected_dn_suffixes=tuple(entry.get("protectedDnSuffixes", ())),
            )
        return cls(
            governed_domains=domains,
            protected_object_guids=frozenset(data.get("protectedObjectGuids", ())),
            protected_sids=frozenset(data.get("protectedSids", ())),
            protected_names=frozenset(data.get("protectedNames", ())),
        )


@dataclass(frozen=True)
class ProtectionAssessment:
    status: ProtectionStatus
    reasons: tuple[str, ...]  # why the group is protected
    gaps: tuple[str, ...]  # what could not be determined
    # Reasons the domain ADGroup record can express (well-known SID, adminCount,
    # ProtectedFromAccidentalDeletion, critical system object).
    record_expressible: bool

    @property
    def blocks_retirement(self) -> bool:
        return self.status is not ProtectionStatus.NOT_PROTECTED


def assess_protection(report: ADGroupReport, policy: ADProtectionPolicy) -> ProtectionAssessment:
    if not report.resolved:
        return ProtectionAssessment(
            ProtectionStatus.UNDETERMINED, (), (f"group not resolved ({report.resolution.status.value})",), False
        )
    group = report.group
    assert group is not None
    reasons: list[str] = []
    expressible = False
    gaps: list[str] = []

    if group.builtin_domain or group.rid < FIRST_ORDINARY_RID:
        reasons.append(f"well-known SID (RID {group.rid})")
        expressible = True
    if group.admin_count:
        reasons.append("adminCount is set (AdminSDHolder-protected)")
        expressible = True
    if group.is_critical_system_object:
        reasons.append("critical system object")
        expressible = True
    if group.protected_from_accidental_deletion is True:
        reasons.append("ProtectedFromAccidentalDeletion")
        expressible = True
    elif group.protected_from_accidental_deletion is None:
        gaps.append("ProtectedFromAccidentalDeletion could not be read")

    if group.object_guid in policy.protected_object_guids or group.object_sid in policy.protected_sids:
        reasons.append("on the configured protected list")
    if {group.sam_account_name.casefold(), group.name.casefold()} & policy.effective_protected_names:
        reasons.append("name is on the privileged-name list")

    member_of = report.member_of
    for parent in member_of.parents:
        if parent.object_sid and _is_well_known(parent.object_sid):
            reasons.append(f"member of well-known group {parent.object_sid}")
        elif parent.object_guid in policy.protected_object_guids or parent.object_sid in policy.protected_sids:
            reasons.append(f"member of configured protected group {parent.object_guid}")
    if member_of.status is not SectionStatus.COMPLETE:
        gaps.append(f"parent groups not fully read ({member_of.status.value})")

    domain_policy = policy.governed_domains.get(group.domain)
    if domain_policy is None:
        gaps.append(f"domain {group.domain} has no OGWA protection policy")
    else:
        if not domain_policy.retirement_allowed:
            reasons.append(f"domain policy forbids retirement in {group.domain}")
        dn = group.distinguished_name.casefold()
        for suffix in domain_policy.protected_dn_suffixes:
            s = suffix.casefold()
            if dn == s or dn.endswith("," + s):
                reasons.append(f"under protected container {suffix}")

    # The worker's indicators are supporting evidence. Any it reports that OGWA did not
    # derive itself still count (union, never subtraction).
    derived = _derived_indicators(report)
    for indicator in report.protection.indicators:
        if indicator not in derived:
            reasons.append(f"worker indicator {indicator}")
    if report.protection.status is ProtectionFactsStatus.UNDETERMINED:
        gaps.append(f"worker could not determine protection facts: {report.protection.error or 'no reason given'}")

    if reasons:
        status = ProtectionStatus.PROTECTED
    elif gaps:
        status = ProtectionStatus.UNDETERMINED
    else:
        status = ProtectionStatus.NOT_PROTECTED
    return ProtectionAssessment(status, tuple(dict.fromkeys(reasons)), tuple(dict.fromkeys(gaps)), expressible)


def _is_well_known(sid: str) -> bool:
    rid = int(sid.rsplit("-", 1)[1])
    return sid.startswith(BUILTIN_SID_PREFIX) or rid < FIRST_ORDINARY_RID


def _derived_indicators(report: ADGroupReport) -> set[str]:
    group = report.group
    assert group is not None
    derived = set()
    if group.builtin_domain:
        derived.add("BuiltinDomainSid")
    if group.rid < FIRST_ORDINARY_RID:
        derived.add(f"WellKnownRid:{group.rid}")
    if group.admin_count:
        derived.add("AdminCount")
    if group.is_critical_system_object:
        derived.add("CriticalSystemObject")
    if group.protected_from_accidental_deletion is True:
        derived.add("ProtectedFromAccidentalDeletion")
    for parent in report.member_of.parents:
        if parent.object_sid and _is_well_known(parent.object_sid):
            derived.add(f"NestedInWellKnownGroup:{parent.object_sid}")
    return derived


def _canonical_guid(value: object) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        raise ContractError("protected_object_guids must be GUIDs") from None
