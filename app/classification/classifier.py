"""Classify one Okta group / application relationship from its evidence.

``classify`` is a pure function of the evidence bundle, the subject, the policy, and the
time. It reads nothing, writes nothing, and contacts nothing. It collects every reason it
can prove (``Reason``), then picks the classification:

1. the first forced outcome in ``PRECEDENCE``, if any reason forces one;
2. otherwise, if any reason blocks retirement, the usage review tier
   (``LOW_USAGE_REVIEW`` or ``INACTIVE_REVIEW``);
3. otherwise ``RETIREMENT_CANDIDATE``, but only if every reason in
   ``RETIREMENT_CANDIDATE_REQUIRES`` (and, per application, ``..._PER_APPLICATION``) is
   present. A missing proof adds ``REQUIRED_CONDITION_UNPROVEN`` instead.

Rules that never bend:

- Positive facts count even from incomplete evidence (a partial read that found members
  still found members). Negative facts ("no members", "no other assignment") need a
  COMPLETE result from a counting source. An attestation never proves a negative (D13).
- A blocking finding is never dropped: it is classified by its code, or by its kind if it
  has no code.
- Dependency coverage that is not COMPLETE prohibits AD deletion. The result is held at
  review; the invariant is never weakened to produce a candidate.
- A ``RETIREMENT_CANDIDATE`` is evidence for human review. It is not an approval, and
  nothing here can approve, schedule, or perform a change.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.classification.coverage import CoverageReport, coverage_report
from app.classification.reasons import (
    PRECEDENCE,
    RETIREMENT_CANDIDATE_REQUIRES,
    RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION,
    Classification,
    Reason,
    ReasonCode,
    UsageTier,
)
from app.domain.candidate_policy import CandidatePolicy
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidencePurpose
from app.domain.ids import IdKind, check_id, check_ids, check_utc
from app.domain.lifecycle import LifecycleState
from app.domain.model import (
    COVERAGE_SOURCES,
    ApplicationGroupAssignment,
    DependencyCoverage,
    DependencyEvidence,
    DependencyFinding,
    DependencyKind,
    FindingCode,
    MappingConfidence,
    OktaAppStatus,
)
from app.domain.policy import EvidenceBundle, GroupOrigin, evidence_fingerprint, group_origin, protection_reasons

R = ReasonCode
C = Classification

# The lifecycle state a progressing candidate with this classification should be diverted
# to. None: no diversion (the classification does not stop a candidate by itself, or a
# human decides, as for ACTIVE).
LIFECYCLE_DIVERSIONS: dict[Classification, LifecycleState | None] = {
    C.PROTECTED: LifecycleState.PROTECTED,
    C.MAPPING_REQUIRED: LifecycleState.MAPPING_AMBIGUOUS,
    C.DEPENDENCY_BLOCKED: LifecycleState.DEPENDENCY_BLOCKED,
    C.HAS_MEMBERS: LifecycleState.DEPENDENCY_BLOCKED,
    C.NESTED_DEPENDENCY: LifecycleState.DEPENDENCY_BLOCKED,
    C.SHARED_OKTA_ASSIGNMENT: LifecycleState.DEPENDENCY_BLOCKED,
    C.STALE_EVIDENCE: LifecycleState.STALE_EVIDENCE,
    # Incomplete is not stale (owner decision): its own state since migration 0009.
    C.EVIDENCE_INCOMPLETE: LifecycleState.EVIDENCE_INCOMPLETE,
    C.ACTIVE: None,
    C.LOW_USAGE_REVIEW: None,
    C.INACTIVE_REVIEW: None,
    C.RETIREMENT_CANDIDATE: None,
}

_FINDING_REASONS: dict[FindingCode, ReasonCode] = {
    FindingCode.AD_DIRECT_MEMBERS: R.AD_DIRECT_MEMBERS,
    FindingCode.AD_PRIMARY_GROUP_REFERENCES: R.AD_PRIMARY_GROUP_REFERENCES,
    FindingCode.AD_PARENT_GROUP: R.AD_PARENT_GROUP,
    FindingCode.AD_MEMBER_GROUPS: R.AD_MEMBER_GROUPS,
    FindingCode.AD_NESTED_PRINCIPALS: R.AD_NESTED_PRINCIPALS,
    FindingCode.AD_NESTING_CYCLE: R.AD_NESTING_FINDING,  # only reached when marked blocking
    FindingCode.OKTA_OTHER_APP_ASSIGNMENT: R.SHARED_OKTA_ASSIGNMENT,
}
_KIND_REASONS: dict[DependencyKind, ReasonCode] = {
    DependencyKind.AD_GROUP_MEMBERS: R.AD_MEMBERSHIP_FINDING,
    DependencyKind.AD_NESTED_MEMBERSHIP: R.AD_NESTING_FINDING,
    DependencyKind.OKTA_OTHER_APP_ASSIGNMENT: R.SHARED_OKTA_ASSIGNMENT,
}
_TIER_ORDER = (UsageTier.INACTIVE, UsageTier.LOW, UsageTier.ACTIVE)


@dataclass(frozen=True)
class CandidateSubject:
    """The relationship being classified: one Okta group and the applications it is assigned to."""

    okta_group_id: str  # internal id
    application_ids: tuple[str, ...]  # internal ids

    def __post_init__(self) -> None:
        check_id(self.okta_group_id, IdKind.OKTA_GROUP, "okta_group_id")
        check_ids(self.application_ids, IdKind.OKTA_APPLICATION, "application_ids")


@dataclass(frozen=True)
class ClassificationResult:
    subject: CandidateSubject
    classification: Classification
    reasons: tuple[Reason, ...]
    usage_tier: UsageTier | None
    coverage: CoverageReport
    policy_digest: str
    evidence_fingerprint: str
    classified_at: datetime

    @property
    def reason_codes(self) -> tuple[str, ...]:
        """Distinct reason codes, in the order first proven. Suitable for ``LifecycleCandidate.reason_codes``."""
        return tuple(dict.fromkeys(r.code.value for r in self.reasons))

    @property
    def blockers(self) -> tuple[Reason, ...]:
        return tuple(r for r in self.reasons if r.blocks)

    @property
    def ad_deletion_prohibited(self) -> bool:
        """True unless every retirement condition, including COMPLETE coverage, is proven.

        False does not authorize anything: it only means a human may consider the
        candidate under the lifecycle's approvals, hold, and dry runs.
        """
        return not (
            self.classification is C.RETIREMENT_CANDIDATE and self.coverage.overall is DependencyCoverage.COMPLETE
        )

    @property
    def lifecycle_diversion(self) -> LifecycleState | None:
        return LIFECYCLE_DIVERSIONS[self.classification]

    def explain(self) -> str:
        lines = [self.classification.value]
        lines += [f"- {r.code.value}: {r.detail}" for r in self.reasons]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "isApproval": False,
            "adDeletionProhibited": self.ad_deletion_prohibited,
            "lifecycleDiversion": self.lifecycle_diversion.value if self.lifecycle_diversion else None,
            "subject": {"oktaGroupId": self.subject.okta_group_id, "applicationIds": list(self.subject.application_ids)},
            "usageTier": self.usage_tier.value if self.usage_tier else None,
            "reasonCodes": list(self.reason_codes),
            "reasons": [r.to_dict() for r in self.reasons],
            "dependencyCoverage": self.coverage.to_dict(),
            "policyDigest": self.policy_digest,
            "evidenceFingerprint": self.evidence_fingerprint,
            "classifiedAt": self.classified_at.isoformat(),
        }


class _Collector:
    def __init__(self) -> None:
        self.reasons: list[Reason] = []

    def add(self, code: ReasonCode, detail: str, subject: str | None = None) -> None:
        reason = Reason(code, detail[:500], subject)
        if reason not in self.reasons:
            self.reasons.append(reason)

    def has(self, code: ReasonCode, subject: str | None = None) -> bool:
        return any(r.code is code and (subject is None or r.subject == subject) for r in self.reasons)


def classify(bundle: EvidenceBundle, subject: CandidateSubject, policy: CandidatePolicy, now: datetime) -> ClassificationResult:
    if not isinstance(bundle, EvidenceBundle):
        raise TypeError("bundle must be an EvidenceBundle")
    if not isinstance(subject, CandidateSubject):
        raise TypeError("subject must be a CandidateSubject")
    if not isinstance(policy, CandidatePolicy):
        raise TypeError("policy must be a CandidatePolicy")
    try:
        check_utc(now, "now")
    except InvalidRecord as exc:
        raise TypeError(str(exc)) from None

    out = _Collector()
    _consistency(out, bundle, subject)
    _freshness(out, bundle, policy, now)
    tier = _usage(out, bundle, subject, policy, now)
    _assignments(out, bundle, subject)
    _protection(out, bundle, policy)
    _findings(out, bundle, subject)
    _origin_mapping_and_membership(out, bundle, subject, policy)
    coverage = coverage_report(_related_dependencies(bundle, subject), policy.lifecycle.required_dependency_kinds)
    if coverage.overall is DependencyCoverage.COMPLETE:
        out.add(R.DEPENDENCY_COVERAGE_COMPLETE, "every required dependency kind was checked completely")
    else:
        missing = ", ".join(k.value for k in coverage.missing)
        out.add(R.DEPENDENCY_COVERAGE_INCOMPLETE,
                f"coverage {coverage.overall.value}; not covered: {missing}. AD deletion stays prohibited")

    classification = _decide(out, subject, tier)
    return ClassificationResult(
        subject=subject,
        classification=classification,
        reasons=tuple(out.reasons),
        usage_tier=tier,
        coverage=coverage,
        policy_digest=policy.digest,
        evidence_fingerprint=evidence_fingerprint(bundle),
        classified_at=now,
    )


def _decide(out: _Collector, subject: CandidateSubject, tier: UsageTier | None) -> Classification:
    forced = {r.outcome for r in out.reasons if r.outcome is not None}
    for outcome in PRECEDENCE:
        if outcome in forced:
            return outcome
    if tier is None:
        out.add(R.REQUIRED_CONDITION_UNPROVEN, "the usage tier could not be determined")
        return C.EVIDENCE_INCOMPLETE
    review = C.LOW_USAGE_REVIEW if tier is UsageTier.LOW else C.INACTIVE_REVIEW
    if any(r.blocks for r in out.reasons):
        return review
    unproven = sorted(code.value for code in RETIREMENT_CANDIDATE_REQUIRES if not out.has(code))
    for app_id in subject.application_ids:
        unproven += [f"{code.value} ({app_id})" for code in sorted(RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION)
                     if not out.has(code, app_id)]
    if unproven:
        out.add(R.REQUIRED_CONDITION_UNPROVEN, "not proven: " + ", ".join(unproven))
        return C.EVIDENCE_INCOMPLETE
    return C.RETIREMENT_CANDIDATE


# --- passes --------------------------------------------------------------------------


def _related_subjects(bundle: EvidenceBundle, subject: CandidateSubject) -> set[str]:
    related = {subject.okta_group_id}
    if bundle.mapping is not None and bundle.mapping.ad_group_id:
        related.add(bundle.mapping.ad_group_id)
    return related


def _related_dependencies(bundle: EvidenceBundle, subject: CandidateSubject) -> tuple[DependencyEvidence, ...]:
    related = _related_subjects(bundle, subject)
    return tuple(d for d in bundle.dependencies if d.subject_id in related)


def _consistency(out: _Collector, bundle: EvidenceBundle, subject: CandidateSubject) -> None:
    group = bundle.okta_group
    if group is not None and group.id != subject.okta_group_id:
        out.add(R.EVIDENCE_INCONSISTENT, "the Okta group observation is for a different group", group.id)
    m = bundle.mapping
    if m is not None and m.okta_group_id != subject.okta_group_id:
        out.add(R.EVIDENCE_INCONSISTENT, "the identity mapping is for a different Okta group", m.id)
    if bundle.ad_group is not None and (m is None or m.ad_group_id != bundle.ad_group.id):
        out.add(R.EVIDENCE_INCONSISTENT, "the AD group observation is not the mapped AD group", bundle.ad_group.id)
    related = _related_subjects(bundle, subject)
    for d in bundle.dependencies:
        if d.subject_id not in related:
            out.add(R.EVIDENCE_INCONSISTENT, f"dependency evidence {d.kind.value} is about an unrelated subject", d.id)


def _freshness(out: _Collector, bundle: EvidenceBundle, policy: CandidatePolicy, now: datetime) -> None:
    fresh = policy.lifecycle.freshness
    max_age = fresh.max_age(EvidencePurpose.REVIEW)
    clean = True
    for record in bundle.records():
        label = f"{record.KIND.value} {record.id}"
        p = record.provenance
        if not p.decision_grade:
            # An incomplete dependency check does not count toward coverage or prove a
            # negative fact; that is reported where it matters, not as a record problem.
            if not isinstance(record, DependencyEvidence):
                out.add(R.EVIDENCE_NOT_DECISION_GRADE, f"{label}: result {p.result_status.value}", record.id)
                clean = False
            continue
        if p.observed_at > now + fresh.clock_skew:
            out.add(R.EVIDENCE_FUTURE_DATED, f"{label}: observed_at is in the future", record.id)
            clean = False
        elif now - p.observed_at > max_age:
            out.add(R.EVIDENCE_STALE, f"{label}: observed {(now - p.observed_at).days} days ago (review limit {max_age.days} days)",
                    record.id)
            clean = False
    if clean:
        out.add(R.EVIDENCE_CURRENT, f"every record is complete and observed within {max_age.days} days")


def _usage(out: _Collector, bundle: EvidenceBundle, subject: CandidateSubject, policy: CandidatePolicy,
           now: datetime) -> UsageTier | None:
    lifecycle = policy.lifecycle
    tiers: list[UsageTier] = []
    for app_id in subject.application_ids:
        app = next((a for a in bundle.applications if a.id == app_id), None)
        status_tier = None
        if app is None:
            out.add(R.APPLICATION_NOT_OBSERVED, "no observation of the application", app_id)
        elif app.status is OktaAppStatus.INACTIVE:
            out.add(R.APP_INACTIVE, f"application {app.label!r} is INACTIVE in Okta", app_id)
            status_tier = UsageTier.INACTIVE
        u = bundle.usage_for(app_id, subject.okta_group_id)
        if u is None:
            out.add(R.USAGE_NOT_OBSERVED, "no usage observation for the application", app_id)
            if status_tier:
                tiers.append(status_tier)
            continue

        scope = "group-attributed" if u.okta_group_id else "application-wide"
        last = u.last_activity_at.date().isoformat() if u.last_activity_at else "none in window"
        summary = (f"{u.event_count} sign-in(s), {u.distinct_user_count} user(s) in a {u.window.days}-day "
                   f"{scope} window; last observed sign-in {last}")
        cap = policy.low_usage_max_unique_users
        above_low = u.event_count > policy.low_usage_max_sign_ins or (cap is not None and u.distinct_user_count > cap)
        tier: UsageTier | None = None
        if above_low:
            # A positive count is a fact even when the read was incomplete.
            recent = u.last_activity_at is None or now - u.last_activity_at <= policy.recent_login_window
            if recent:
                tier = UsageTier.ACTIVE
                if status_tier is None:
                    out.add(R.IN_USE, f"{summary}; above the low-usage threshold "
                                      f"({policy.low_usage_max_sign_ins} sign-ins)", app_id)
            else:
                tier = UsageTier.LOW
                out.add(R.NO_RECENT_LOGIN, f"{summary}; no sign-in in the last {policy.recent_login_window.days} days",
                        app_id)
        elif u.provenance.decision_grade:
            if u.window < policy.review_min_usage_window:
                out.add(R.USAGE_WINDOW_TOO_SHORT, f"{summary}; a usage signal needs at least "
                                                  f"{policy.review_min_usage_window.days} days", app_id)
            elif u.event_count == 0:
                tier = UsageTier.INACTIVE
                out.add(R.NO_OBSERVED_USAGE, summary, app_id)
            else:
                tier = UsageTier.LOW
                out.add(R.LOW_USAGE, f"{summary}; at or below the low-usage threshold "
                                     f"({policy.low_usage_max_sign_ins} sign-ins)", app_id)
        if status_tier is not None:
            tier = status_tier

        if u.event_count > lifecycle.max_usage_events_for_candidate:
            out.add(R.USAGE_ABOVE_RETIREMENT_THRESHOLD, f"{u.event_count} sign-in(s) exceed the retirement "
                                                        f"threshold of {lifecycle.max_usage_events_for_candidate}", app_id)
        elif u.provenance.decision_grade:
            out.add(R.USAGE_WITHIN_RETIREMENT_THRESHOLD, f"{u.event_count} sign-in(s), retirement threshold "
                                                         f"{lifecycle.max_usage_events_for_candidate}", app_id)
        if u.provenance.decision_grade:
            if u.window >= lifecycle.min_usage_window:
                out.add(R.USAGE_WINDOW_COVERS_RETIREMENT,
                        f"{u.window.days}-day window covers the {lifecycle.min_usage_window.days}-day retirement window",
                        app_id)
            elif u.window >= policy.review_min_usage_window:
                out.add(R.USAGE_WINDOW_REVIEW_ONLY,
                        f"{u.window.days}-day window is shorter than the {lifecycle.min_usage_window.days}-day "
                        "retirement window: review signal only (D27)", app_id)
        if tier is not None:
            tiers.append(tier)
    return max(tiers, key=_TIER_ORDER.index) if tiers else None


def _assignment(bundle: EvidenceBundle, app_id: str, group_id: str) -> ApplicationGroupAssignment | None:
    return next((a for a in bundle.assignments if a.application_id == app_id and a.okta_group_id == group_id), None)


def _assignments(out: _Collector, bundle: EvidenceBundle, subject: CandidateSubject) -> None:
    for app_id in subject.application_ids:
        a = _assignment(bundle, app_id, subject.okta_group_id)
        if a is None:
            out.add(R.ASSIGNMENT_NOT_OBSERVED, "no observation of the group's assignment to the application", app_id)
        elif a.present:
            out.add(R.ASSIGNMENT_PRESENT, "the group is assigned to the application", app_id)
        else:
            out.add(R.ASSIGNMENT_ABSENT, "the group is no longer assigned to the application; nothing to unassign",
                    app_id)

    labels = {a.id: a.label for a in bundle.applications}
    others = [a for a in bundle.assignments if a.okta_group_id == subject.okta_group_id
              and a.application_id not in subject.application_ids and a.present]
    for a in others:
        name = labels.get(a.application_id, a.application_id)
        out.add(R.SHARED_OKTA_ASSIGNMENT, f"the group is also assigned to application {name!r}", a.application_id)
    check = next((d for d in bundle.dependencies if d.subject_id == subject.okta_group_id
                  and d.kind is DependencyKind.OKTA_OTHER_APP_ASSIGNMENT), None)
    proven_single = (check is not None and _counts(check) and not check.blocking_findings and not others)
    if proven_single:
        out.add(R.SINGLE_OKTA_ASSIGNMENT, "a complete check found no other application assignment")
    elif not others and not (check is not None and check.blocking_findings):
        out.add(R.OTHER_ASSIGNMENTS_UNKNOWN, "no complete check of the group's other application assignments")


def _protection(out: _Collector, bundle: EvidenceBundle, policy: CandidatePolicy) -> None:
    for reason in protection_reasons(bundle, policy.lifecycle):
        out.add(R.PROTECTED_GROUP, reason)


def _findings(out: _Collector, bundle: EvidenceBundle, subject: CandidateSubject) -> None:
    """Every blocking finding on a related subject becomes a blocking reason."""
    for d in _related_dependencies(bundle, subject):
        for f in d.findings:
            if f.blocking:
                out.add(_finding_reason(d, f), f"{d.kind.value}: {f.description}", d.id)
            elif f.code is FindingCode.AD_NESTING_CYCLE:
                out.add(R.AD_NESTING_CYCLE, f.description, d.id)


def _finding_reason(d: DependencyEvidence, f: DependencyFinding) -> ReasonCode:
    if f.code is not None:
        return _FINDING_REASONS[f.code]
    return _KIND_REASONS.get(d.kind, R.DEPENDENCY_FINDING)


def _counts(d: DependencyEvidence) -> bool:
    """Whether a check can prove a negative: complete, and from a counting source."""
    return d.provenance.decision_grade and d.provenance.source in COVERAGE_SOURCES


def _origin_mapping_and_membership(out: _Collector, bundle: EvidenceBundle, subject: CandidateSubject,
                                   policy: CandidatePolicy) -> None:
    group = bundle.okta_group
    if group is None:
        out.add(R.OKTA_GROUP_NOT_OBSERVED, "no observation of the Okta group", subject.okta_group_id)
        return
    origin = group_origin(group, policy.lifecycle)
    if origin is GroupOrigin.BUILT_IN:
        return  # PROTECTED_GROUP already says why
    if origin is GroupOrigin.OKTA_ONLY:
        out.add(R.OKTA_ONLY_GROUP, "mastered in Okta: review only; its lifecycle is not defined (D12)")
        return
    if origin is GroupOrigin.OTHER_SOURCE:
        out.add(R.NOT_AD_SOURCED, "not imported through a configured AD integration; cannot enter AD retirement")
        return
    out.add(R.AD_SOURCED_GROUP, "imported through a configured AD integration")

    m = bundle.mapping
    if m is None:
        out.add(R.MAPPING_MISSING, "no identity mapping to an AD group has been recorded")
        return
    if m.confidence is MappingConfidence.NAME_ONLY:
        out.add(R.MAPPING_NAME_ONLY, "names match, nothing stronger; name-only mapping never supports retirement", m.id)
        return
    if m.confidence is MappingConfidence.AMBIGUOUS:
        out.add(R.MAPPING_AMBIGUOUS, f"{len(m.candidate_ad_group_ids)} possible AD counterparts", m.id)
        return
    if m.confidence is MappingConfidence.NOT_FOUND:
        out.add(R.MAPPING_NOT_FOUND, "no AD counterpart was found", m.id)
        return
    if m.confidence is MappingConfidence.UNVERIFIED_STABLE_ID:
        out.add(R.MAPPING_UNVERIFIED_IDENTIFIER, "a directory-source objectSid resolves to one AD group, but the "
                "mechanism is not verified until P11 (D37, D56); not exact", m.id)
        return
    if not m.is_exact:
        out.add(R.MAPPING_NOT_EXACT, f"mapping confidence {m.confidence.value} is not exact", m.id)
        return
    out.add(R.EXACT_MAPPING, f"{m.confidence.value} on {', '.join(sorted(m.matched_attributes))}", m.id)

    ad = bundle.ad_group
    if ad is None or ad.id != m.ad_group_id:
        out.add(R.AD_GROUP_NOT_OBSERVED, "no observation of the mapped AD group", m.ad_group_id)
        return
    if not ad.exists:
        out.add(R.AD_GROUP_NOT_FOUND, "a complete objectGUID lookup found no AD group: re-correlate", ad.id)
        return
    if ad.provenance.decision_grade:
        if not out.has(R.PROTECTED_GROUP):
            out.add(R.NOT_PROTECTED, "no built-in, configured, or AD protection applies", ad.id)
    else:
        out.add(R.PROTECTION_UNDETERMINED,
                "the AD group record is not complete, so protection may be undetermined (D21)", ad.id)
    _membership(out, bundle, ad)


def _membership(out: _Collector, bundle: EvidenceBundle, ad) -> None:
    def check(kind: DependencyKind) -> DependencyEvidence | None:
        return next((d for d in bundle.dependencies if d.subject_id == ad.id and d.kind is kind), None)

    members, nesting = check(DependencyKind.AD_GROUP_MEMBERS), check(DependencyKind.AD_NESTED_MEMBERSHIP)
    if (ad.member_count or 0) > 0 and not out.has(R.AD_DIRECT_MEMBERS):
        out.add(R.AD_DIRECT_MEMBERS, f"the AD group record has {ad.member_count} direct member value(s)", ad.id)
    if ad.member_count is None:
        # An unread member attribute is unknown, never zero; the AD stages refuse it too (D132).
        out.add(R.AD_MEMBERSHIP_UNKNOWN, "the AD group record's direct member count is unknown; unknown is not zero",
                ad.id)

    def none_except(d: DependencyEvidence | None, allowed: set[FindingCode]) -> bool:
        # True only if a counting check found no blocking finding other than ``allowed`` codes.
        return d is not None and _counts(d) and all(f.code in allowed for f in d.blocking_findings)

    # Emptiness needs a known zero member count (``member_count or 0`` would read unknown as zero).
    no_direct = none_except(members, {FindingCode.AD_PRIMARY_GROUP_REFERENCES}) and ad.member_count == 0
    no_primary = none_except(members, {FindingCode.AD_DIRECT_MEMBERS})
    no_nested = none_except(nesting, {FindingCode.AD_PARENT_GROUP})
    no_parents = none_except(nesting, {FindingCode.AD_MEMBER_GROUPS, FindingCode.AD_NESTED_PRINCIPALS})

    if members is None or not _counts(members):
        out.add(R.AD_MEMBERSHIP_UNKNOWN, "direct members and primaryGroupID references were not read completely", ad.id)
    if nesting is None or not _counts(nesting):
        out.add(R.AD_NESTING_UNKNOWN, "parent groups and nested members were not read completely", ad.id)
    if no_direct and no_primary and no_nested:
        out.add(R.AD_GROUP_EMPTY, "no direct members, no primaryGroupID references, no principals through member "
                                  "groups (ogwa-ad-empty/v1)", ad.id)
    if no_parents:
        out.add(R.AD_NO_PARENT_GROUPS, "the AD group is not a member of any other group", ad.id)
