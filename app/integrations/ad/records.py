"""Turn a worker report into domain evidence and a collector-run result.

This is the only place where AD worker reports become ``app.domain`` records:

- ``ADGroup``: identity and protection attributes, keyed by objectGUID;
- ``DependencyEvidence`` of kind ``AD_GROUP_MEMBERS`` (direct members and primary-group
  references) and ``AD_NESTED_MEMBERSHIP`` (parent groups, member groups, nested
  principals).

Rules:

- Provenance is COMPLETE only when every section behind a record was read completely.
  Anything less is PARTIAL or FAILED, so it can never drive a decision (E-2).
- The ADGroup record is never allowed to look less protected than the assessment. When
  protection is UNDETERMINED, or PROTECTED only for reasons the record cannot express
  (nesting in a privileged group, configuration, domain policy), the record is PARTIAL
  and ``not_decision_grade`` says why. The collector then diverts the candidate to
  PROTECTED or leaves it blocked.
- ``exists=False`` is emitted only for an objectGUID lookup that searched every domain.
  A name that is not found proves nothing about any particular group.
- Internal ids are derived from (forest, objectGUID), so re-observing a group yields the
  same record id even after a rename or move.
- Owner decision D19: live behaviors not yet verified against real AD cannot
  contribute to COMPLETE evidence from a real source (``AD_VIA_AAP``). See
  ``VERIFIED_LIVE_BEHAVIORS``. Synthetic evidence is unaffected: the synthetic directory
  is exact by construction.
"""

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from app.core.modes import ExecutionMode
from app.domain.collection import CollectorErrorCode
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.ids import IdKind, check_text
from app.domain.model import ADGroup, DependencyEvidence, DependencyFinding, DependencyKind, FindingCode
from app.integrations.ad.assessment import (
    ADProtectionPolicy,
    EmptinessAssessment,
    ProtectionAssessment,
    ProtectionStatus,
    assess_emptiness,
    assess_protection,
)
from app.integrations.ad.contract import (
    COLLECTOR_VERSION,
    ADGroupReport,
    LookupKind,
    ResolutionStatus,
    SectionStatus,
)

EVIDENCE_SOURCES = frozenset({EvidenceSource.AD_VIA_AAP, EvidenceSource.SYNTHETIC})
MAX_PARENT_FINDINGS = 20


class LiveBehavior(StrEnum):
    # A group with LARGE_GROUP_THRESHOLD member values or more may be cut off by ranged
    # retrieval or ADWS limits.
    LARGE_GROUP_COMPLETENESS = "LARGE_GROUP_COMPLETENESS"
    # (member=<DN>) finds parent groups held by another domain's domain controller.
    CROSS_DOMAIN_PARENT_LOOKUP = "CROSS_DOMAIN_PARENT_LOOKUP"
    # The read-only identity can read ProtectedFromAccidentalDeletion (security descriptor).
    DELETION_PROTECTION_READABILITY = "DELETION_PROTECTION_READABILITY"


# Owner decision D19: none of these is verified until it is proven against real AD, which
# this build cannot read. Adding a member is a reviewed source change; tests pin this set.
VERIFIED_LIVE_BEHAVIORS: frozenset[LiveBehavior] = frozenset()
# The default LDAP MaxValRange: from here on, member values come back in ranges.
LARGE_GROUP_THRESHOLD = 1500


def evidence_source_for_mode(mode: ExecutionMode) -> EvidenceSource:
    """Synthetic runs record SYNTHETIC evidence; read-only runs against AD record AD_VIA_AAP."""
    if mode is ExecutionMode.LOCAL_SYNTHETIC:
        return EvidenceSource.SYNTHETIC
    if mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION):
        return EvidenceSource.AD_VIA_AAP
    raise ValueError(f"{mode.value} cannot collect AD evidence")


class ADStableIds:
    """Internal ids derived from (forest, kind, external key). Same input, same id."""

    def __init__(self, forest: str) -> None:
        self._namespace = "ad:" + check_text(forest, "forest", max_length=255).lower()

    def id_for(self, kind: IdKind, external_key: str) -> str:
        check_text(external_key, "external_key", max_length=300)
        digest = hashlib.sha256(f"{self._namespace}|{kind.value}|{external_key}".encode()).hexdigest()
        return f"{kind.value}_{digest[:32]}"

    def ad_group(self, object_guid: str) -> str:
        return self.id_for(IdKind.AD_GROUP, object_guid.lower())

    def dependency(self, ad_group_id: str, kind: DependencyKind) -> str:
        return self.id_for(IdKind.DEPENDENCY_EVIDENCE, f"{ad_group_id}:{kind.value}")


@dataclass(frozen=True)
class ADEvidence:
    ad_group: ADGroup | None
    dependencies: tuple[DependencyEvidence, ...]
    emptiness: EmptinessAssessment
    protection: ProtectionAssessment
    not_decision_grade: tuple[str, ...]  # why ad_group is not COMPLETE (empty when it is)
    unverified_live_behaviors: tuple[LiveBehavior, ...] = ()  # D19 gates applied to this evidence


def ad_evidence(report: ADGroupReport, *, policy: ADProtectionPolicy, source: EvidenceSource, ids: ADStableIds) -> ADEvidence:
    if source not in EVIDENCE_SOURCES:
        raise ValueError(f"AD evidence must come from {sorted(s.value for s in EVIDENCE_SOURCES)}")
    emptiness = assess_emptiness(report)
    protection = assess_protection(report, policy)

    if report.resolved:
        unverified = _unverified_live_behaviors(report, source)
        protection = _with_unverified_protection(protection, unverified)
        group, gaps = _resolved_group(report, protection, source, ids, unverified)
        dependencies = _dependencies(report, group.id, source, ids, unverified)
        return ADEvidence(group, dependencies, emptiness, protection, gaps, tuple(sorted(unverified)))

    request = report.request
    if (
        report.resolution.status is ResolutionStatus.NOT_FOUND
        and request is not None
        and request.by is LookupKind.OBJECT_GUID
        and not report.resolution.unsearched_domains
    ):
        domain = request.domain or report.forest_name
        assert domain is not None
        missing = ADGroup(
            id=ids.ad_group(request.value),
            object_guid=request.value,
            domain=domain,
            exists=False,
            provenance=_provenance(source, report.observed_at, f"ad:{domain}:objectGUID={request.value}", ResultStatus.COMPLETE),
        )
        return ADEvidence(missing, (), emptiness, protection, ())
    reason = f"no AD group record: lookup {report.resolution.status.value}"
    return ADEvidence(None, (), emptiness, protection, (reason,))


def _is_large(count: int | None) -> bool:
    return (count or 0) >= LARGE_GROUP_THRESHOLD


def _unverified_live_behaviors(report: ADGroupReport, source: EvidenceSource) -> set[LiveBehavior]:
    """The unverified live behaviors this report depends on (D19). None for synthetic data."""
    if source is EvidenceSource.SYNTHETIC:
        return set()
    used = {LiveBehavior.DELETION_PROTECTION_READABILITY}
    if len(report.forest_domains) > 1 and report.member_of.status is not SectionStatus.NOT_REQUESTED:
        used.add(LiveBehavior.CROSS_DOMAIN_PARENT_LOOKUP)
    if _is_large(report.direct_members.count) or _is_large(report.nested_members.principal_count):
        used.add(LiveBehavior.LARGE_GROUP_COMPLETENESS)
    return used - VERIFIED_LIVE_BEHAVIORS


def _unverified_reason(behavior: LiveBehavior) -> str:
    return f"{behavior.value} is not verified against real AD (owner decision D19; P11)"


def _with_unverified_protection(protection: ProtectionAssessment, unverified: set[LiveBehavior]) -> ProtectionAssessment:
    # Unverified deletion-protection reads or parent lookups leave protection unknown, and
    # unknown protection is fail-closed (D21). Positive reasons still make it PROTECTED.
    gaps = tuple(_unverified_reason(b) for b in sorted(unverified) if b is not LiveBehavior.LARGE_GROUP_COMPLETENESS)
    if not gaps:
        return protection
    status = ProtectionStatus.PROTECTED if protection.reasons else ProtectionStatus.UNDETERMINED
    return replace(protection, status=status, gaps=tuple(dict.fromkeys(protection.gaps + gaps)))


def _resolved_group(
    report: ADGroupReport,
    protection: ProtectionAssessment,
    source: EvidenceSource,
    ids: ADStableIds,
    unverified: set[LiveBehavior],
) -> tuple[ADGroup, tuple[str, ...]]:
    g = report.group
    assert g is not None
    gaps: list[str] = []
    if LiveBehavior.LARGE_GROUP_COMPLETENESS in unverified and _is_large(report.direct_members.count):
        gaps.append("member_count: " + _unverified_reason(LiveBehavior.LARGE_GROUP_COMPLETENESS))
    if protection.status is ProtectionStatus.UNDETERMINED:
        gaps.extend(protection.gaps)
    elif protection.status is ProtectionStatus.PROTECTED and not protection.record_expressible:
        gaps.append("protected for reasons the AD group record cannot express: " + "; ".join(protection.reasons))
    direct = report.direct_members
    record = ADGroup(
        id=ids.ad_group(g.object_guid),
        object_guid=g.object_guid,
        domain=g.domain,
        exists=True,
        provenance=_provenance(
            source,
            report.observed_at,
            f"ad:{g.domain}:objectGUID={g.object_guid}",
            ResultStatus.PARTIAL if gaps else ResultStatus.COMPLETE,
        ),
        sid=g.object_sid,
        distinguished_name=g.distinguished_name,
        sam_account_name=g.sam_account_name,
        admin_count=bool(g.admin_count),
        protected_from_accidental_deletion=g.protected_from_accidental_deletion is True,
        is_critical_system_object=g.is_critical_system_object,
        member_count=direct.count if direct.status in (SectionStatus.COMPLETE, SectionStatus.TRUNCATED) else None,
    )
    return record, tuple(dict.fromkeys(gaps))


def _dependencies(
    report: ADGroupReport, ad_group_id: str, source: EvidenceSource, ids: ADStableIds, unverified: set[LiveBehavior]
) -> tuple[DependencyEvidence, ...]:
    g = report.group
    assert g is not None and report.request is not None
    request = report.request
    scope = f"ad:{g.domain}:objectGUID={g.object_guid}"
    large_unverified = LiveBehavior.LARGE_GROUP_COMPLETENESS in unverified
    members_gated = large_unverified and _is_large(report.direct_members.count)
    nesting_gated = LiveBehavior.CROSS_DOMAIN_PARENT_LOOKUP in unverified or (
        large_unverified and _is_large(report.nested_members.principal_count)
    )
    records = []

    if request.include_direct_members or request.include_primary_group_references:
        direct, primary = report.direct_members, report.primary_group_references
        findings = []
        if direct.count:
            classes = ", ".join(f"{n} {name}" for name, n in direct.by_class.items() if n)
            unresolved = f", {direct.unresolved} unresolved" if direct.unresolved else ""
            findings.append(DependencyFinding(f"{direct.count} direct member value(s) ({classes or 'not classified'}{unresolved})", True,
                                              code=FindingCode.AD_DIRECT_MEMBERS))
        if primary.count:
            plus = "+" if primary.count_is_lower_bound else ""
            findings.append(
                DependencyFinding(
                    f"{primary.count}{plus} object(s) use this group as their primary group (primaryGroupID {primary.primary_group_token})",
                    True,
                    code=FindingCode.AD_PRIMARY_GROUP_REFERENCES,
                )
            )
        records.append(
            DependencyEvidence(
                id=ids.dependency(ad_group_id, DependencyKind.AD_GROUP_MEMBERS),
                subject_id=ad_group_id,
                kind=DependencyKind.AD_GROUP_MEMBERS,
                findings=tuple(findings),
                provenance=_provenance(source, report.observed_at, scope + ":members", _gated(_combined((direct.status, primary.status)), members_gated)),
            )
        )

    if request.include_nested_members or request.include_member_of:
        nested, member_of, direct = report.nested_members, report.member_of, report.direct_members
        findings = []
        for parent in member_of.parents[:MAX_PARENT_FINDINGS]:
            label = parent.sam_account_name or parent.distinguished_name
            findings.append(DependencyFinding(f"member of group {label[:300]} ({parent.domain})", True, parent.distinguished_name[:500],
                                              FindingCode.AD_PARENT_GROUP))
        if len(member_of.parents) > MAX_PARENT_FINDINGS:
            findings.append(DependencyFinding(f"member of {len(member_of.parents) - MAX_PARENT_FINDINGS} more group(s)", True,
                                              code=FindingCode.AD_PARENT_GROUP))
        if direct.by_class.get("group"):
            findings.append(DependencyFinding(f"contains {direct.by_class['group']} member group(s)", True,
                                              code=FindingCode.AD_MEMBER_GROUPS))
        if nested.principal_count:
            plus = "+" if nested.principal_count_is_lower_bound else ""
            findings.append(DependencyFinding(f"{nested.principal_count}{plus} principal(s) reachable through member groups", True,
                                              code=FindingCode.AD_NESTED_PRINCIPALS))
        if nested.cycle_detected:
            findings.append(DependencyFinding("group nesting contains a cycle", False, code=FindingCode.AD_NESTING_CYCLE))
        records.append(
            DependencyEvidence(
                id=ids.dependency(ad_group_id, DependencyKind.AD_NESTED_MEMBERSHIP),
                subject_id=ad_group_id,
                kind=DependencyKind.AD_NESTED_MEMBERSHIP,
                findings=tuple(findings),
                provenance=_provenance(source, report.observed_at, scope + ":nesting", _gated(_combined((nested.status, member_of.status)), nesting_gated)),
            )
        )
    return tuple(records)


def _gated(status: ResultStatus, depends_on_unverified: bool) -> ResultStatus:
    # D19: an unverified live behavior caps a COMPLETE result at PARTIAL.
    return ResultStatus.PARTIAL if depends_on_unverified and status is ResultStatus.COMPLETE else status


def _combined(statuses: tuple[SectionStatus, ...]) -> ResultStatus:
    # A kind is checked completely only if every section behind it was read completely.
    if all(s is SectionStatus.COMPLETE for s in statuses):
        return ResultStatus.COMPLETE
    if all(s in (SectionStatus.FAILED, SectionStatus.NOT_APPLICABLE) for s in statuses):
        return ResultStatus.FAILED
    return ResultStatus.PARTIAL


def _provenance(source: EvidenceSource, observed_at: datetime, scope: str, status: ResultStatus) -> Provenance:
    return Provenance(source=source, observed_at=observed_at, scope=scope[:500], collector_version=COLLECTOR_VERSION, result_status=status)


@dataclass(frozen=True)
class ADCollectorResult:
    """The facts a ``CollectorRunOutcome`` needs for one report."""

    status: ResultStatus
    error_code: CollectorErrorCode | None
    error_summary: str | None


def collector_result(report: ADGroupReport, evidence: ADEvidence) -> ADCollectorResult:
    resolution = report.resolution
    summary = (resolution.error or resolution.status.value)[:300]
    if resolution.status is ResolutionStatus.INCONCLUSIVE:
        return ADCollectorResult(ResultStatus.PARTIAL, CollectorErrorCode.DOMAIN_UNREACHABLE, summary)
    if resolution.status in (ResolutionStatus.FAILED, ResolutionStatus.INVALID_REQUEST):
        return ADCollectorResult(ResultStatus.FAILED, CollectorErrorCode.OTHER, summary)
    records = ([evidence.ad_group] if evidence.ad_group else []) + list(evidence.dependencies)
    if all(r.provenance.result_status is ResultStatus.COMPLETE for r in records):
        return ADCollectorResult(ResultStatus.COMPLETE, None, None)
    unreachable = any(d.reachable is False for d in report.domains)
    code = CollectorErrorCode.DOMAIN_UNREACHABLE if unreachable else CollectorErrorCode.OTHER
    incomplete = [s for s in evidence.not_decision_grade] or ["a section was not read completely"]
    return ADCollectorResult(ResultStatus.PARTIAL, code, "; ".join(incomplete)[:300])
