"""Lifecycle policy, the evidence bundle a decision is made on, and its fingerprint."""

import re
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum

from app.domain.errors import InvalidRecord
from app.domain.evidence import (
    Evidence,
    FreshnessPolicy,
    stable_digest,
)
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyCoverage,
    DependencyEvidence,
    DependencyKind,
    IdentityMapping,
    OktaApplication,
    OktaGroup,
    OktaGroupType,
    assess_dependency_coverage,
)

# Dependency kinds a policy may never drop from the required set.
MANDATORY_DEPENDENCY_KINDS = frozenset(
    {
        DependencyKind.OKTA_OTHER_APP_ASSIGNMENT,
        DependencyKind.OKTA_POLICY_REFERENCE,
        DependencyKind.AD_GROUP_MEMBERS,
        DependencyKind.AD_NESTED_MEMBERSHIP,
    }
)
DEFAULT_REQUIRED_DEPENDENCY_KINDS = frozenset(DependencyKind) - {DependencyKind.OTHER}

# Floors and ceilings. A policy may be stricter, never looser.
MIN_USAGE_WINDOW_FLOOR = timedelta(days=30)
MAX_USAGE_EVENTS_CEILING = 5  # the conventional low-usage threshold
MIN_HOLD_PERIOD = timedelta(days=7)
APPROVAL_TTL_BOUNDS = (timedelta(hours=1), timedelta(days=14))

# The exact shape of what a protected identifier is matched against (F11). Anything else could
# never match, so it is refused rather than kept as an entry that protects nothing.
# shortcut: F12's stricter shared SID/id helpers (fullmatch, ASCII digits) would replace these; adopt them if F12 lands.
_PROTECTED_SHAPES = {
    "protected_okta_group_ids": re.compile(r"[A-Za-z0-9]{1,64}"),
    "protected_ad_object_guids": re.compile(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"),
    "protected_ad_sids": re.compile(r"S-1-[0-9]+(-[0-9]+)+"),
}


@dataclass(frozen=True)
class LifecyclePolicy:
    freshness: FreshnessPolicy = field(default_factory=FreshnessPolicy)
    # Okta's System Log keeps about 90 days.
    # A longer window cannot be observed completely.
    min_usage_window: timedelta = timedelta(days=90)
    max_usage_events_for_candidate: int = 0
    hold_period: timedelta = timedelta(days=30)
    approval_max_ttl: timedelta = timedelta(days=7)
    required_dependency_kinds: frozenset[DependencyKind] = DEFAULT_REQUIRED_DEPENDENCY_KINDS
    # Configured protected list. Owned by the AD/Identity platform owner, changed only
    # with Security/IAM review (owner decision D10). Additive only: nothing in the policy
    # can remove the built-in protections in protection_reasons().
    protected_okta_group_ids: frozenset[str] = frozenset()  # external Okta group ids
    protected_ad_object_guids: frozenset[str] = frozenset()
    protected_ad_sids: frozenset[str] = frozenset()
    # Okta app instance ids of the Active Directory integrations. Only APP_GROUP groups
    # imported through one of these are AD-sourced. Empty means none is known, so no
    # group can enter the AD-retirement workflow (fail closed).
    ad_directory_source_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.freshness, FreshnessPolicy):
            raise InvalidRecord("freshness must be a FreshnessPolicy")
        if self.min_usage_window < MIN_USAGE_WINDOW_FLOOR:
            raise InvalidRecord(f"min_usage_window must be at least {MIN_USAGE_WINDOW_FLOOR}")
        if not isinstance(self.max_usage_events_for_candidate, int) or not (
            0 <= self.max_usage_events_for_candidate <= MAX_USAGE_EVENTS_CEILING
        ):
            raise InvalidRecord(f"max_usage_events_for_candidate must be 0-{MAX_USAGE_EVENTS_CEILING}")
        if self.hold_period < MIN_HOLD_PERIOD:
            raise InvalidRecord(f"hold_period must be at least {MIN_HOLD_PERIOD}")
        low, high = APPROVAL_TTL_BOUNDS
        if not low <= self.approval_max_ttl <= high:
            raise InvalidRecord(f"approval_max_ttl must be between {low} and {high}")
        if not MANDATORY_DEPENDENCY_KINDS <= self.required_dependency_kinds:
            raise InvalidRecord("required_dependency_kinds must include every mandatory kind")
        for name in ("protected_okta_group_ids", "protected_ad_object_guids", "protected_ad_sids", "ad_directory_source_ids"):
            if not isinstance(getattr(self, name), frozenset):
                raise InvalidRecord(f"{name} must be a frozenset")
        for name, shape in _PROTECTED_SHAPES.items():
            if not all(isinstance(v, str) and shape.fullmatch(v) for v in getattr(self, name)):
                raise InvalidRecord(f"{name} holds a value that is not {shape.pattern}")
        # A GUID names the same group in any letter case; ADGroup.object_guid is lowercase.
        object.__setattr__(self, "protected_ad_object_guids", frozenset(g.lower() for g in self.protected_ad_object_guids))


@dataclass(frozen=True)
class EvidenceBundle:
    """The current evidence for one candidate. At most one record per object or scope."""

    okta_group: OktaGroup | None = None
    applications: tuple[OktaApplication, ...] = ()
    assignments: tuple[ApplicationGroupAssignment, ...] = ()
    usage: tuple[ApplicationUsageObservation, ...] = ()
    mapping: IdentityMapping | None = None
    ad_group: ADGroup | None = None
    dependencies: tuple[DependencyEvidence, ...] = ()

    def __post_init__(self) -> None:
        for name, cls in (
            ("applications", OktaApplication),
            ("assignments", ApplicationGroupAssignment),
            ("usage", ApplicationUsageObservation),
            ("dependencies", DependencyEvidence),
        ):
            records = getattr(self, name)
            if not isinstance(records, tuple) or not all(isinstance(r, cls) for r in records):
                raise InvalidRecord(f"{name} must be a tuple of {cls.__name__}")
        for name, cls in (("okta_group", OktaGroup), ("mapping", IdentityMapping), ("ad_group", ADGroup)):
            value = getattr(self, name)
            if value is not None and not isinstance(value, cls):
                raise InvalidRecord(f"{name} must be a {cls.__name__}")
        _require_unique("applications", [a.id for a in self.applications])
        _require_unique("assignments", [a.id for a in self.assignments])
        _require_unique("usage scopes", [(u.application_id, u.okta_group_id) for u in self.usage])
        _require_unique("dependency checks", [(d.subject_id, d.kind) for d in self.dependencies])

    def records(self) -> list[Evidence]:
        single = [r for r in (self.okta_group, self.mapping, self.ad_group) if r is not None]
        return [*single, *self.applications, *self.assignments, *self.usage, *self.dependencies]

    def assignment(self, assignment_id: str) -> ApplicationGroupAssignment | None:
        return next((a for a in self.assignments if a.id == assignment_id), None)

    def usage_for(self, application_id: str, okta_group_id: str) -> ApplicationUsageObservation | None:
        """Group-attributed usage if present, else application-wide usage."""
        scoped = [u for u in self.usage if u.application_id == application_id]
        return next((u for u in scoped if u.okta_group_id == okta_group_id), None) or next(
            (u for u in scoped if u.okta_group_id is None), None
        )

    def dependency_coverage(self, required: frozenset[DependencyKind]) -> DependencyCoverage:
        return assess_dependency_coverage(self.dependencies, required)


def _require_unique(name: str, keys: list) -> None:
    if len(set(keys)) != len(keys):
        raise InvalidRecord(f"evidence bundle has more than one record for the same {name}")


def evidence_fingerprint(bundle: EvidenceBundle) -> str:
    """Digest of the material content and completeness of every record in the bundle.

    Re-observing identical facts gives the same fingerprint. Any material change, or a
    change in a record's result status, gives a different one.
    """
    items = sorted([r.KIND.value, r.id, r.provenance.result_status.value, r.digest] for r in bundle.records())
    return stable_digest(items)


class GroupOrigin(StrEnum):
    AD_SOURCED = "AD_SOURCED"  # imported through a configured AD integration
    OKTA_ONLY = "OKTA_ONLY"  # mastered in Okta; separate lifecycle, not yet defined (D12)
    OTHER_SOURCE = "OTHER_SOURCE"  # imported from a source not configured as AD
    BUILT_IN = "BUILT_IN"  # e.g. "Everyone"; always protected


def group_origin(group: OktaGroup, policy: LifecyclePolicy) -> GroupOrigin:
    if group.group_type is OktaGroupType.BUILT_IN:
        return GroupOrigin.BUILT_IN
    if group.group_type is OktaGroupType.OKTA_GROUP:
        return GroupOrigin.OKTA_ONLY
    if group.source_directory_id in policy.ad_directory_source_ids:
        return GroupOrigin.AD_SOURCED
    return GroupOrigin.OTHER_SOURCE


def protection_reasons(bundle: EvidenceBundle, policy: LifecyclePolicy) -> list[str]:
    """Why this candidate's groups are protected. Any reason stops progress for good."""
    reasons = []
    group = bundle.okta_group
    if group is not None:
        if group.group_type is OktaGroupType.BUILT_IN:
            reasons.append("Okta built-in group")
        if group.okta_group_id in policy.protected_okta_group_ids:
            reasons.append("Okta group is on the configured protected list")
    ad = bundle.ad_group
    if ad is not None:
        if ad.well_known_rid is not None:
            reasons.append(f"AD group has a well-known SID (RID {ad.well_known_rid})")
        if ad.admin_count:
            reasons.append("AD group has adminCount set (AdminSDHolder-protected)")
        if ad.protected_from_accidental_deletion:
            reasons.append("AD group is ProtectedFromAccidentalDeletion")
        if ad.is_critical_system_object:
            reasons.append("AD group is a critical system object")
        if ad.object_guid in policy.protected_ad_object_guids or (ad.sid and ad.sid in policy.protected_ad_sids):
            reasons.append("AD group is on the configured protected list")
    return reasons
