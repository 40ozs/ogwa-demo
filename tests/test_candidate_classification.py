"""Candidate classification. Synthetic fixtures only (tests/classification_fixtures.py).

The central property: RETIREMENT_CANDIDATE needs every safety condition. Removing,
degrading, or contradicting any single one of them stops promotion.
"""

import ast
import random
import unittest
from dataclasses import replace
from pathlib import Path

from app.classification import (
    LIFECYCLE_DIVERSIONS,
    PRECEDENCE,
    PRODUCTION_COLLECTORS,
    REASON_EFFECTS,
    RETIREMENT_CANDIDATE_REQUIRES,
    RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION,
    CandidateSubject,
    Classification,
    KindStatus,
    Reason,
    ReasonCode,
    UsageTier,
    classify,
    coverage_report,
    production_coverage_gaps,
)
from app.domain.candidate_policy import CandidatePolicy
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.lifecycle import LifecycleCandidate, LifecycleState, TransitionRequest, apply_transition
from app.domain.model import (
    ApplicationUsageObservation,
    DependencyCoverage,
    DependencyKind,
    MappingConfidence,
    OktaAppStatus,
    OktaGroupType,
)
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS, LifecyclePolicy, protection_reasons
from tests.classification_fixtures import (
    APP_ID_2,
    ASSIGNMENT_ID_2,
    CPOLICY,
    DIRECT_MEMBERS,
    GPO,
    MEMBER_GROUPS,
    NESTED_PRINCIPALS,
    NESTING_CYCLE,
    NOW,
    OKTA_KINDS,
    OTHER_APP,
    PARENT_GROUP,
    PRIMARY_GROUP,
    SUBJECT,
    UNCODED,
    USAGE_ID_2,
    check,
    run,
    with_check,
    world,
)
from tests.domain_fixtures import (
    AD_ID,
    APP_ID,
    ASSIGNMENT_ID,
    DAY,
    GROUP_ID,
    POLICY,
    SYNTHETIC_AD_SOURCE_ID,
    SYSTEM,
    T0,
    ad_group,
    application,
    assignment,
    mapping,
    okta_group,
    prov,
    usage,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
C = Classification
R = ReasonCode
K = DependencyKind
AD_KINDS = DEFAULT_REQUIRED_DEPENDENCY_KINDS - OKTA_KINDS


def _members(*findings, status=ResultStatus.COMPLETE, source=EvidenceSource.SYNTHETIC):
    return lambda b: with_check(b, K.AD_GROUP_MEMBERS, check(T0, K.AD_GROUP_MEMBERS, findings, status, source))


def _nesting(*findings, status=ResultStatus.COMPLETE, source=EvidenceSource.SYNTHETIC):
    return lambda b: with_check(b, K.AD_NESTED_MEMBERSHIP, check(T0, K.AD_NESTED_MEMBERSHIP, findings, status, source))


def _other_apps(*findings, status=ResultStatus.COMPLETE, source=EvidenceSource.SYNTHETIC):
    kind = K.OKTA_OTHER_APP_ASSIGNMENT
    return lambda b: with_check(b, kind, check(T0, kind, findings, status, source))


def _usage(**kw):
    return lambda b: replace(b, usage=(usage(T0, **kw),))


def _set(**fields):
    return lambda b: replace(b, **fields)


# One missing or contradicted safety condition per row:
# (name, change to the candidate world, expected classification, a reason code that must explain it)
SINGLE_CONDITION_CASES = [
    # Usage and application
    ("application in use", _usage(events=50), C.ACTIVE, R.IN_USE),
    ("low usage above the retirement threshold", _usage(events=3), C.LOW_USAGE_REVIEW, R.USAGE_ABOVE_RETIREMENT_THRESHOLD),
    ("heavy use but no recent login",
     _usage(events=50, last_activity_at=T0 - 60 * DAY), C.LOW_USAGE_REVIEW, R.NO_RECENT_LOGIN),
    ("usage window shorter than the retirement window", _usage(window_days=60), C.INACTIVE_REVIEW, R.USAGE_WINDOW_REVIEW_ONLY),
    ("usage window too short for any signal", _usage(window_days=10), C.EVIDENCE_INCOMPLETE, R.USAGE_WINDOW_TOO_SHORT),
    ("usage not observed", _set(usage=()), C.EVIDENCE_INCOMPLETE, R.USAGE_NOT_OBSERVED),
    ("usage observation partial", _usage(status=ResultStatus.PARTIAL), C.EVIDENCE_INCOMPLETE, R.EVIDENCE_NOT_DECISION_GRADE),
    ("usage observation failed", _usage(status=ResultStatus.FAILED), C.EVIDENCE_INCOMPLETE, R.EVIDENCE_NOT_DECISION_GRADE),
    ("application not observed", _set(applications=()), C.EVIDENCE_INCOMPLETE, R.APPLICATION_NOT_OBSERVED),
    # Okta assignment
    ("assignment not observed", _set(assignments=()), C.EVIDENCE_INCOMPLETE, R.ASSIGNMENT_NOT_OBSERVED),
    ("assignment already removed", _set(assignments=(assignment(T0, present=False),)), C.INACTIVE_REVIEW, R.ASSIGNMENT_ABSENT),
    ("assigned to another application (observed)",
     lambda b: replace(b, assignments=b.assignments + (
         assignment(T0, id=ASSIGNMENT_ID_2, application_id=APP_ID_2),)), C.SHARED_OKTA_ASSIGNMENT, R.SHARED_OKTA_ASSIGNMENT),
    ("assigned to another application (dependency finding)",
     _other_apps(OTHER_APP), C.SHARED_OKTA_ASSIGNMENT, R.SHARED_OKTA_ASSIGNMENT),
    ("other assignments not checked",
     lambda b: with_check(b, K.OKTA_OTHER_APP_ASSIGNMENT, None), C.INACTIVE_REVIEW, R.OTHER_ASSIGNMENTS_UNKNOWN),
    ("other assignments checked partially",
     _other_apps(status=ResultStatus.PARTIAL), C.INACTIVE_REVIEW, R.OTHER_ASSIGNMENTS_UNKNOWN),
    ("other assignments only attested (D13)",
     _other_apps(source=EvidenceSource.OPERATOR_ATTESTATION), C.INACTIVE_REVIEW, R.OTHER_ASSIGNMENTS_UNKNOWN),
    ("other-assignment check recorded on the AD group",
     lambda b: with_check(b, K.OKTA_OTHER_APP_ASSIGNMENT, check(T0, K.OKTA_OTHER_APP_ASSIGNMENT, subject_id=AD_ID)),
     C.INACTIVE_REVIEW, R.OTHER_ASSIGNMENTS_UNKNOWN),
    # Group origin
    ("Okta group not observed", _set(okta_group=None), C.EVIDENCE_INCOMPLETE, R.OKTA_GROUP_NOT_OBSERVED),
    ("Okta-mastered group",
     _set(okta_group=okta_group(T0, group_type=OktaGroupType.OKTA_GROUP, source_directory_id=None,
                                directory_external_id=None, directory_qualified_name=None)),
     C.INACTIVE_REVIEW, R.OKTA_ONLY_GROUP),
    ("imported from an unconfigured directory",
     _set(okta_group=okta_group(T0, source_directory_id="0oaSYNTHOTHER01")), C.INACTIVE_REVIEW, R.NOT_AD_SOURCED),
    # Mapping
    ("no identity mapping", _set(mapping=None, ad_group=None), C.MAPPING_REQUIRED, R.MAPPING_MISSING),
    ("name-only mapping",
     _set(mapping=mapping(T0, confidence=MappingConfidence.NAME_ONLY)), C.MAPPING_REQUIRED, R.MAPPING_NAME_ONLY),
    ("ambiguous mapping",
     _set(mapping=mapping(T0, confidence=MappingConfidence.AMBIGUOUS), ad_group=None), C.MAPPING_REQUIRED, R.MAPPING_AMBIGUOUS),
    ("no AD counterpart",
     _set(mapping=mapping(T0, confidence=MappingConfidence.NOT_FOUND), ad_group=None), C.MAPPING_REQUIRED, R.MAPPING_NOT_FOUND),
    ("unverified directory-source identifier (D56)",
     _set(mapping=mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID, matched_attributes=("objectSid", "samAccountName"))),
     C.MAPPING_REQUIRED, R.MAPPING_UNVERIFIED_IDENTIFIER),
    ("mapped AD group not observed", _set(ad_group=None), C.EVIDENCE_INCOMPLETE, R.AD_GROUP_NOT_OBSERVED),
    ("mapped AD group no longer exists", _set(ad_group=ad_group(T0, exists=False)), C.MAPPING_REQUIRED, R.AD_GROUP_NOT_FOUND),
    ("mapping for another Okta group",
     _set(mapping=mapping(T0, okta_group_id="ogrp_" + "f" * 32)), C.EVIDENCE_INCOMPLETE, R.EVIDENCE_INCONSISTENT),
    # Protection
    ("Okta built-in group",
     _set(okta_group=okta_group(T0, group_type=OktaGroupType.BUILT_IN, source_directory_id=None,
                                directory_external_id=None, directory_qualified_name=None)), C.PROTECTED, R.PROTECTED_GROUP),
    ("adminCount", _set(ad_group=ad_group(T0, admin_count=True)), C.PROTECTED, R.PROTECTED_GROUP),
    ("ProtectedFromAccidentalDeletion",
     _set(ad_group=ad_group(T0, protected_from_accidental_deletion=True)), C.PROTECTED, R.PROTECTED_GROUP),
    ("critical system object", _set(ad_group=ad_group(T0, is_critical_system_object=True)), C.PROTECTED, R.PROTECTED_GROUP),
    ("well-known RID", _set(ad_group=ad_group(T0, rid=512)), C.PROTECTED, R.PROTECTED_GROUP),
    ("AD record incomplete, protection undetermined (D21)",
     _set(ad_group=ad_group(T0, provenance=prov(T0, ResultStatus.PARTIAL))), C.EVIDENCE_INCOMPLETE, R.PROTECTION_UNDETERMINED),
    # AD membership (D20: separate facts)
    ("direct members", _members(DIRECT_MEMBERS), C.HAS_MEMBERS, R.AD_DIRECT_MEMBERS),
    ("direct members on the AD group record only", _set(ad_group=ad_group(T0, member_count=2)), C.HAS_MEMBERS, R.AD_DIRECT_MEMBERS),
    ("primaryGroupID references", _members(PRIMARY_GROUP), C.HAS_MEMBERS, R.AD_PRIMARY_GROUP_REFERENCES),
    ("uncoded membership finding", _members(UNCODED), C.HAS_MEMBERS, R.AD_MEMBERSHIP_FINDING),
    ("members found by a partial read", _members(DIRECT_MEMBERS, status=ResultStatus.PARTIAL), C.HAS_MEMBERS, R.AD_DIRECT_MEMBERS),
    ("membership not checked",
     lambda b: with_check(b, K.AD_GROUP_MEMBERS, None), C.EVIDENCE_INCOMPLETE, R.AD_MEMBERSHIP_UNKNOWN),
    ("membership read partially", _members(status=ResultStatus.PARTIAL), C.EVIDENCE_INCOMPLETE, R.AD_MEMBERSHIP_UNKNOWN),
    ("emptiness only attested (D13)",
     _members(source=EvidenceSource.OPERATOR_ATTESTATION), C.EVIDENCE_INCOMPLETE, R.AD_MEMBERSHIP_UNKNOWN),
    ("parent group", _nesting(PARENT_GROUP), C.NESTED_DEPENDENCY, R.AD_PARENT_GROUP),
    ("member groups", _nesting(MEMBER_GROUPS), C.NESTED_DEPENDENCY, R.AD_MEMBER_GROUPS),
    ("principals through member groups", _nesting(NESTED_PRINCIPALS), C.NESTED_DEPENDENCY, R.AD_NESTED_PRINCIPALS),
    ("uncoded nesting finding", _nesting(UNCODED), C.NESTED_DEPENDENCY, R.AD_NESTING_FINDING),
    ("nesting not checked",
     lambda b: with_check(b, K.AD_NESTED_MEMBERSHIP, None), C.EVIDENCE_INCOMPLETE, R.AD_NESTING_UNKNOWN),
    ("nesting read failed", _nesting(status=ResultStatus.FAILED), C.EVIDENCE_INCOMPLETE, R.AD_NESTING_UNKNOWN),
    # Other dependencies
    ("GPO reference",
     lambda b: with_check(b, K.GPO_REFERENCE, check(T0, K.GPO_REFERENCE, (GPO,))), C.DEPENDENCY_BLOCKED, R.DEPENDENCY_FINDING),
    ("attested blocking ACL reference (attestations still block)",
     lambda b: with_check(b, K.AD_ACL_REFERENCE, check(T0, K.AD_ACL_REFERENCE, (GPO,), source=EvidenceSource.OPERATOR_ATTESTATION)),
     C.DEPENDENCY_BLOCKED, R.DEPENDENCY_FINDING),
    ("dependency evidence about an unrelated subject",
     lambda b: with_check(b, K.OTHER, check(T0, K.OTHER, subject_id="adg_" + "e" * 32)),
     C.EVIDENCE_INCOMPLETE, R.EVIDENCE_INCONSISTENT),
    # Freshness
    ("stale evidence", lambda b: world(T0 - 45 * DAY), C.STALE_EVIDENCE, R.EVIDENCE_STALE),
    # Future-dated evidence was never properly obtained: incomplete, not stale (owner decision).
    ("future-dated evidence", _set(ad_group=ad_group(NOW + DAY)), C.EVIDENCE_INCOMPLETE, R.EVIDENCE_FUTURE_DATED),
]
SINGLE_CONDITION_CASES += [
    (f"{kind.value} not checked", (lambda k: lambda b: with_check(b, k, None))(kind), C.INACTIVE_REVIEW,
     R.DEPENDENCY_COVERAGE_INCOMPLETE)
    for kind in sorted(DEFAULT_REQUIRED_DEPENDENCY_KINDS - {K.AD_GROUP_MEMBERS, K.AD_NESTED_MEMBERSHIP,
                                                            K.OKTA_OTHER_APP_ASSIGNMENT})
]


class BaselineTests(unittest.TestCase):
    def test_complete_synthetic_world_is_a_retirement_candidate(self):
        r = run(world())
        self.assertIs(r.classification, C.RETIREMENT_CANDIDATE)
        self.assertFalse(r.blockers)
        self.assertIs(r.coverage.overall, DependencyCoverage.COMPLETE)
        self.assertLessEqual({c.value for c in RETIREMENT_CANDIDATE_REQUIRES}, set(r.reason_codes))
        self.assertIs(r.usage_tier, UsageTier.INACTIVE)
        self.assertFalse(r.ad_deletion_prohibited)
        self.assertIsNone(r.lifecycle_diversion)

    def test_the_example_reasons_appear_for_an_inactive_app(self):
        b = world(applications=(application(T0, status=OktaAppStatus.INACTIVE),))
        r = run(b)
        self.assertIs(r.classification, C.RETIREMENT_CANDIDATE)
        for code in ("APP_INACTIVE", "NO_OBSERVED_USAGE", "AD_GROUP_EMPTY", "SINGLE_OKTA_ASSIGNMENT", "EXACT_MAPPING"):
            self.assertIn(code, r.reason_codes)
        text = r.explain()
        self.assertTrue(text.startswith("RETIREMENT_CANDIDATE\n- "))
        self.assertIn("APP_INACTIVE: application 'Synthetic App' is INACTIVE in Okta", text)

    def test_a_candidate_is_not_an_approval(self):
        d = run(world()).to_dict()
        self.assertIs(d["isApproval"], False)
        self.assertEqual(d["classification"], "RETIREMENT_CANDIDATE")
        self.assertEqual(d["policyDigest"], CPOLICY.digest)
        self.assertTrue(all(isinstance(r["code"], str) and r["detail"] for r in d["reasons"]))
        result = run(world())
        public = {n for n in dir(result) if not n.startswith("_")}
        for verb in ("approve", "apply", "execute", "retire", "delete", "unassign", "transition"):
            self.assertFalse([n for n in public if verb in n], verb)

    def test_classification_is_deterministic(self):
        self.assertEqual(run(world()).to_dict(), run(world()).to_dict())


class SingleMissingConditionTests(unittest.TestCase):
    """Regression: any one missing safety condition prevents promotion."""

    def test_each_case_stops_promotion(self):
        for name, change, expected, code in SINGLE_CONDITION_CASES:
            with self.subTest(name):
                r = run(change(world()))
                self.assertEqual(r.classification, expected, r.explain())
                self.assertIn(code.value, r.reason_codes, r.explain())
                self.assertNotEqual(r.classification, C.RETIREMENT_CANDIDATE)
                self.assertTrue(r.ad_deletion_prohibited)
                self.assertTrue(r.blockers, "a non-candidate must name what blocks it")

    def test_removing_any_single_record_stops_promotion(self):
        base = world()
        for field in ("okta_group", "mapping", "ad_group"):
            with self.subTest(field):
                self.assertNotEqual(run(replace(base, **{field: None})).classification, C.RETIREMENT_CANDIDATE)
        for field in ("applications", "assignments", "usage", "dependencies"):
            records = getattr(base, field)
            for i, record in enumerate(records):
                with self.subTest(field=field, record=record.id):
                    reduced = replace(base, **{field: records[:i] + records[i + 1:]})
                    self.assertNotEqual(run(reduced).classification, C.RETIREMENT_CANDIDATE)

    def test_degrading_any_single_record_stops_promotion(self):
        base = world()
        for status in (ResultStatus.PARTIAL, ResultStatus.FAILED):
            for record in base.records():
                with self.subTest(status=status.value, record=f"{record.KIND.value} {record.id}"):
                    changed = _replace_record(base, record, replace(record, provenance=replace(record.provenance, result_status=status)))
                    self.assertNotEqual(run(changed).classification, C.RETIREMENT_CANDIDATE)

    def test_aging_any_single_record_stops_promotion(self):
        base = world()
        for record in base.records():
            with self.subTest(record=f"{record.KIND.value} {record.id}"):
                old = record.provenance.observed_at - 31 * DAY
                if isinstance(record, ApplicationUsageObservation):
                    aged = usage(old)  # the window moves with the observation
                else:
                    aged = replace(record, provenance=replace(record.provenance, observed_at=old))
                r = run(_replace_record(base, record, aged))
                self.assertIs(r.classification, C.STALE_EVIDENCE)

    def test_attestation_never_proves_a_negative(self):
        base = world()
        for record in base.dependencies:
            with self.subTest(kind=record.kind.value):
                attested = replace(record, provenance=replace(record.provenance, source=EvidenceSource.OPERATOR_ATTESTATION))
                self.assertNotEqual(run(_replace_record(base, record, attested)).classification, C.RETIREMENT_CANDIDATE)

    def test_random_combinations_never_promote(self):
        rng = random.Random(20261005)
        changes = [change for _, change, _, _ in SINGLE_CONDITION_CASES]
        for trial in range(300):
            picked = rng.sample(changes, rng.randint(1, 4))
            b = world()
            try:
                for change in picked:
                    b = change(b)
            except Exception:  # an invalid combination (e.g. duplicate records) proves nothing
                continue
            with self.subTest(trial=trial):
                r = run(b)
                self.assertNotEqual(r.classification, C.RETIREMENT_CANDIDATE, r.explain())
                self.assertTrue(r.ad_deletion_prohibited)


#  A proof of absence never appears next to evidence of presence.
CONTRADICTIONS = {
    R.AD_GROUP_EMPTY: {R.AD_DIRECT_MEMBERS, R.AD_PRIMARY_GROUP_REFERENCES, R.AD_MEMBERSHIP_FINDING, R.AD_MEMBER_GROUPS,
                       R.AD_NESTED_PRINCIPALS, R.AD_NESTING_FINDING, R.AD_MEMBERSHIP_UNKNOWN, R.AD_NESTING_UNKNOWN},
    R.AD_NO_PARENT_GROUPS: {R.AD_PARENT_GROUP, R.AD_NESTING_FINDING, R.AD_NESTING_UNKNOWN},
    R.SINGLE_OKTA_ASSIGNMENT: {R.SHARED_OKTA_ASSIGNMENT, R.OTHER_ASSIGNMENTS_UNKNOWN},
    R.NOT_PROTECTED: {R.PROTECTED_GROUP, R.PROTECTION_UNDETERMINED},
    R.DEPENDENCY_COVERAGE_COMPLETE: {R.DEPENDENCY_COVERAGE_INCOMPLETE},
    R.EVIDENCE_CURRENT: {R.EVIDENCE_STALE, R.EVIDENCE_FUTURE_DATED, R.EVIDENCE_NOT_DECISION_GRADE},
    R.USAGE_WITHIN_RETIREMENT_THRESHOLD: {R.USAGE_ABOVE_RETIREMENT_THRESHOLD},
    R.NO_OBSERVED_USAGE: {R.IN_USE, R.LOW_USAGE, R.NO_RECENT_LOGIN},
    R.EXACT_MAPPING: {R.MAPPING_MISSING, R.MAPPING_NAME_ONLY, R.MAPPING_AMBIGUOUS, R.MAPPING_NOT_FOUND,
                      R.MAPPING_UNVERIFIED_IDENTIFIER, R.MAPPING_NOT_EXACT},
}


class ExplanationConsistencyTests(unittest.TestCase):
    def _check(self, r):
        codes = {ReasonCode(c) for c in r.reason_codes}
        for proof, opposites in CONTRADICTIONS.items():
            if proof in codes:
                self.assertFalse(codes & opposites, f"{proof.value} next to {sorted(c.value for c in codes & opposites)}")

    def test_single_condition_cases_never_contradict_themselves(self):
        for name, change, _, _ in SINGLE_CONDITION_CASES:
            with self.subTest(name):
                self._check(run(change(world())))

    def test_random_combinations_never_contradict_themselves(self):
        rng = random.Random(7)
        changes = [change for _, change, _, _ in SINGLE_CONDITION_CASES]
        for trial in range(300):
            b = world()
            try:
                for change in rng.sample(changes, rng.randint(1, 4)):
                    b = change(b)
            except Exception:
                continue
            with self.subTest(trial=trial):
                self._check(run(b))


def _replace_record(bundle, old, new):
    if bundle.okta_group is old:
        return replace(bundle, okta_group=new)
    if bundle.mapping is old:
        return replace(bundle, mapping=new)
    if bundle.ad_group is old:
        return replace(bundle, ad_group=new)
    for field in ("applications", "assignments", "usage", "dependencies"):
        records = getattr(bundle, field)
        if any(r is old for r in records):
            return replace(bundle, **{field: tuple(new if r is old else r for r in records)})
    raise AssertionError("record not in bundle")


class DependencyCoverageTests(unittest.TestCase):
    def test_incomplete_coverage_holds_at_review_and_prohibits_deletion(self):
        b = with_check(world(), K.AAP_REFERENCE, None)
        r = run(b)
        self.assertIs(r.classification, C.INACTIVE_REVIEW)
        self.assertTrue(r.ad_deletion_prohibited)
        self.assertIs(r.coverage.overall, DependencyCoverage.PARTIAL)
        self.assertEqual(r.coverage.missing, (K.AAP_REFERENCE,))
        reason = next(x for x in r.reasons if x.code is R.DEPENDENCY_COVERAGE_INCOMPLETE)
        self.assertIn("AAP_REFERENCE", reason.detail)
        self.assertIn("prohibited", reason.detail)

    def test_coverage_matches_the_lifecycle_definition(self):
        b = world()
        for drop in [None, *sorted(DEFAULT_REQUIRED_DEPENDENCY_KINDS)]:
            bundle = b if drop is None else with_check(b, drop, None)
            with self.subTest(drop=drop):
                self.assertIs(run(bundle).coverage.overall,
                              bundle.dependency_coverage(CPOLICY.lifecycle.required_dependency_kinds))

    def test_coverage_is_unknown_when_nothing_is_checked(self):
        r = run(world(dependencies=()))
        self.assertIs(r.coverage.overall, DependencyCoverage.UNKNOWN)
        self.assertEqual(set(r.coverage.missing), set(DEFAULT_REQUIRED_DEPENDENCY_KINDS))
        self.assertIs(r.classification, C.EVIDENCE_INCOMPLETE)  # the AD membership facts are unknown

    def test_per_kind_status(self):
        b = with_check(world(), K.GPO_REFERENCE, check(T0, K.GPO_REFERENCE, status=ResultStatus.PARTIAL))
        b = with_check(b, K.AAP_REFERENCE, check(T0, K.AAP_REFERENCE, source=EvidenceSource.OPERATOR_ATTESTATION))
        b = with_check(b, K.AD_ACL_REFERENCE, None)
        status = {k.kind: k.status for k in coverage_report(b.dependencies, DEFAULT_REQUIRED_DEPENDENCY_KINDS).kinds}
        self.assertIs(status[K.GPO_REFERENCE], KindStatus.NOT_DECISION_GRADE)
        self.assertIs(status[K.AAP_REFERENCE], KindStatus.NOT_COUNTED_SOURCE)
        self.assertIs(status[K.AD_ACL_REFERENCE], KindStatus.NOT_CHECKED)
        self.assertIs(status[K.AD_GROUP_MEMBERS], KindStatus.COVERED)

    def test_no_dependency_domain_is_covered_from_production_yet(self):
        # Pinned like VERIFIED_LIVE_BEHAVIORS: no live collector exists, so nothing is live-verified.
        self.assertEqual(set(PRODUCTION_COLLECTORS), set(DependencyKind))
        self.assertFalse([k for k, c in PRODUCTION_COLLECTORS.items() if c is not None and c.live_verified])
        with_collector = {k for k, c in PRODUCTION_COLLECTORS.items() if c is not None}
        self.assertEqual(with_collector, {K.AD_GROUP_MEMBERS, K.AD_NESTED_MEMBERSHIP})
        self.assertEqual(set(production_coverage_gaps(DEFAULT_REQUIRED_DEPENDENCY_KINDS)),
                         set(DEFAULT_REQUIRED_DEPENDENCY_KINDS))

    def test_ad_via_aap_evidence_counts_when_complete(self):
        # The classifier treats AD_VIA_AAP like any counting source. It is the D19 gate in
        # app/integrations/ad/records.py that keeps live results PARTIAL.
        b = world()
        for kind in (K.AD_GROUP_MEMBERS, K.AD_NESTED_MEMBERSHIP):
            b = with_check(b, kind, check(T0, kind, source=EvidenceSource.AD_VIA_AAP))
        self.assertIs(run(b).classification, C.RETIREMENT_CANDIDATE)


class UsageTests(unittest.TestCase):
    def test_tiers(self):
        cases = [(0, UsageTier.INACTIVE, C.RETIREMENT_CANDIDATE), (1, UsageTier.LOW, C.LOW_USAGE_REVIEW),
                 (5, UsageTier.LOW, C.LOW_USAGE_REVIEW), (6, UsageTier.ACTIVE, C.ACTIVE)]
        for events, tier, expected in cases:
            with self.subTest(events=events):
                r = run(_usage(events=events)(world()))
                self.assertIs(r.usage_tier, tier)
                self.assertIs(r.classification, expected)

    def test_inactive_app_with_recent_use_is_inactive_review(self):
        b = world(applications=(application(T0, status=OktaAppStatus.INACTIVE),), usage=(usage(T0, events=40),))
        r = run(b)
        self.assertIs(r.classification, C.INACTIVE_REVIEW)
        self.assertIn("USAGE_ABOVE_RETIREMENT_THRESHOLD", r.reason_codes)
        self.assertNotIn("IN_USE", r.reason_codes)

    def test_partial_usage_with_high_counts_is_still_active(self):
        r = run(_usage(events=50, status=ResultStatus.PARTIAL)(world()))
        self.assertIs(r.classification, C.ACTIVE)

    def test_group_attributed_usage_is_preferred(self):
        group_scoped = usage(T0, events=40, id=USAGE_ID_2, okta_group_id=GROUP_ID)
        r = run(world(usage=(usage(T0), group_scoped)))
        self.assertIs(r.classification, C.ACTIVE)
        self.assertIn("group-attributed", next(x for x in r.reasons if x.code is R.IN_USE).detail)

    def test_every_application_in_the_subject_must_qualify(self):
        app2 = application(T0, id=APP_ID_2, okta_app_id="0oaSYNTHAPP0002", label="Synthetic App 2")
        asg2 = assignment(T0, id=ASSIGNMENT_ID_2, application_id=APP_ID_2)
        subject = CandidateSubject(GROUP_ID, (APP_ID, APP_ID_2))
        quiet = world(applications=(application(T0), app2), assignments=(assignment(T0), asg2),
                      usage=(usage(T0), usage(T0, id=USAGE_ID_2, application_id=APP_ID_2)))
        self.assertIs(run(quiet, subject=subject).classification, C.RETIREMENT_CANDIDATE)
        busy = replace(quiet, usage=(usage(T0), usage(T0, events=9, id=USAGE_ID_2, application_id=APP_ID_2)))
        self.assertIs(run(busy, subject=subject).classification, C.ACTIVE)
        no_usage = replace(quiet, usage=(usage(T0),))
        self.assertIs(run(no_usage, subject=subject).classification, C.EVIDENCE_INCOMPLETE)

    def test_thresholds_come_from_policy(self):
        b = _usage(events=3)(world())
        self.assertIs(run(b).classification, C.LOW_USAGE_REVIEW)
        strict = CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=2)
        self.assertIs(run(b, policy=strict).classification, C.ACTIVE)
        users = CandidatePolicy(lifecycle=POLICY, low_usage_max_unique_users=0)
        self.assertIs(run(b, policy=users).classification, C.ACTIVE)  # 1 distinct user > 0
        lenient = CandidatePolicy(lifecycle=replace(POLICY, max_usage_events_for_candidate=3))
        self.assertIs(run(b, policy=lenient).classification, C.RETIREMENT_CANDIDATE)
        short = _usage(window_days=60)(world())
        self.assertIs(run(short).classification, C.INACTIVE_REVIEW)
        shorter_review = CandidatePolicy(lifecycle=POLICY, review_min_usage_window=61 * DAY)
        self.assertIs(run(short, policy=shorter_review).classification, C.EVIDENCE_INCOMPLETE)
        stale_login = _usage(events=50, last_activity_at=T0 - 20 * DAY)(world())
        self.assertIs(run(stale_login).classification, C.ACTIVE)
        recent = CandidatePolicy(lifecycle=POLICY, recent_login_window=10 * DAY)
        self.assertIs(run(stale_login, policy=recent).classification, C.LOW_USAGE_REVIEW)
        self.assertNotEqual(run(b, policy=strict).policy_digest, run(b).policy_digest)


class PrecedenceTests(unittest.TestCase):
    def test_positive_blockers_outrank_evidence_problems(self):
        members_and_stale = _members(DIRECT_MEMBERS)(world(T0 - 45 * DAY))
        self.assertIs(run(members_and_stale).classification, C.HAS_MEMBERS)

    def test_protected_outranks_everything(self):
        b = _members(DIRECT_MEMBERS)(_usage(events=50)(world(ad_group=ad_group(T0, admin_count=True))))
        r = run(b)
        self.assertIs(r.classification, C.PROTECTED)
        self.assertIn("IN_USE", r.reason_codes)
        self.assertIn("AD_DIRECT_MEMBERS", r.reason_codes)

    def test_order(self):
        self.assertEqual(run(_members(DIRECT_MEMBERS)(_usage(events=50)(world()))).classification, C.ACTIVE)
        self.assertEqual(run(_nesting(PARENT_GROUP)(_members(DIRECT_MEMBERS)(world()))).classification, C.HAS_MEMBERS)
        b = with_check(_other_apps(OTHER_APP)(world()), K.GPO_REFERENCE, check(T0, K.GPO_REFERENCE, (GPO,)))
        self.assertEqual(run(b).classification, C.DEPENDENCY_BLOCKED)
        shared_unmapped = _other_apps(OTHER_APP)(world(mapping=None, ad_group=None))
        self.assertEqual(run(shared_unmapped).classification, C.SHARED_OKTA_ASSIGNMENT)

    def test_every_blocking_finding_is_reported(self):
        b = _members(DIRECT_MEMBERS, PRIMARY_GROUP)(_nesting(PARENT_GROUP, NESTED_PRINCIPALS, NESTING_CYCLE)(world()))
        codes = run(b).reason_codes
        for code in ("AD_DIRECT_MEMBERS", "AD_PRIMARY_GROUP_REFERENCES", "AD_PARENT_GROUP", "AD_NESTED_PRINCIPALS",
                     "AD_NESTING_CYCLE"):
            self.assertIn(code, codes)
        self.assertNotIn("AD_GROUP_EMPTY", codes)
        self.assertNotIn("AD_NO_PARENT_GROUPS", codes)

    def test_parent_groups_and_emptiness_are_separate_facts(self):
        r = run(_nesting(PARENT_GROUP)(world()))
        self.assertIn("AD_GROUP_EMPTY", r.reason_codes)  # no members, no nested principals
        self.assertNotIn("AD_NO_PARENT_GROUPS", r.reason_codes)
        r = run(_members(PRIMARY_GROUP)(world()))
        self.assertNotIn("AD_GROUP_EMPTY", r.reason_codes)
        self.assertIn("AD_NO_PARENT_GROUPS", r.reason_codes)

    def test_informational_cycle_alone_does_not_block(self):
        self.assertIs(run(_nesting(NESTING_CYCLE)(world())).classification, C.RETIREMENT_CANDIDATE)

    def test_lifecycle_diversions(self):
        self.assertEqual(set(LIFECYCLE_DIVERSIONS), set(Classification))
        cases = {C.PROTECTED: LifecycleState.PROTECTED, C.MAPPING_REQUIRED: LifecycleState.MAPPING_AMBIGUOUS,
                 C.HAS_MEMBERS: LifecycleState.DEPENDENCY_BLOCKED, C.STALE_EVIDENCE: LifecycleState.STALE_EVIDENCE,
                 C.EVIDENCE_INCOMPLETE: LifecycleState.EVIDENCE_INCOMPLETE, C.RETIREMENT_CANDIDATE: None, C.ACTIVE: None}
        for classification, state in cases.items():
            self.assertIs(LIFECYCLE_DIVERSIONS[classification], state)


class LifecycleAgreementTests(unittest.TestCase):
    """A RETIREMENT_CANDIDATE always satisfies the lifecycle's own evidence guards."""

    def _bundles(self):
        yield world()
        yield world(applications=(application(T0, status=OktaAppStatus.INACTIVE),))
        yield _nesting(NESTING_CYCLE)(world())
        yield world(mapping=mapping(T0, confidence=MappingConfidence.EXACT_CONFIGURED_MAPPING))
        for _, change, _, _ in SINGLE_CONDITION_CASES:
            yield change(world())

    def test_candidates_pass_the_candidacy_guard_and_retirement_evidence_checks(self):
        candidates = 0
        for bundle in self._bundles():
            r = run(bundle)
            if r.classification is not C.RETIREMENT_CANDIDATE:
                continue
            candidates += 1
            c = LifecycleCandidate.discover(okta_group_id=GROUP_ID, assignment_ids=(ASSIGNMENT_ID,), proposed_by=SYSTEM,
                                            now=T0, reason_codes=r.reason_codes)
            apply_transition(c, TransitionRequest(LifecycleState.CANDIDATE, SYSTEM, "classified", NOW, bundle), POLICY)
            self.assertIs(bundle.dependency_coverage(POLICY.required_dependency_kinds), DependencyCoverage.COMPLETE)
            self.assertEqual(protection_reasons(bundle, POLICY), [])
            self.assertTrue(bundle.mapping.is_exact and bundle.ad_group.exists)
            self.assertFalse([d for d in bundle.dependencies if d.blocking_findings])
        self.assertGreaterEqual(candidates, 3)


class ReasonTableTests(unittest.TestCase):
    def test_every_code_has_one_fixed_effect(self):
        self.assertEqual(set(REASON_EFFECTS), set(ReasonCode))
        for code, effect in REASON_EFFECTS.items():
            if effect.outcome is not None:
                self.assertTrue(effect.blocks, code)
                self.assertIn(effect.outcome, PRECEDENCE, code)

    def test_required_reasons_are_supporting(self):
        for code in RETIREMENT_CANDIDATE_REQUIRES | RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION:
            self.assertFalse(REASON_EFFECTS[code].blocks, code)

    def test_precedence_names_every_forced_outcome_once(self):
        forced = {e.outcome for e in REASON_EFFECTS.values() if e.outcome is not None}
        self.assertEqual(set(PRECEDENCE), forced)
        self.assertEqual(len(PRECEDENCE), len(set(PRECEDENCE)))
        self.assertNotIn(C.RETIREMENT_CANDIDATE, PRECEDENCE)

    def test_reason_detail_is_validated(self):
        with self.assertRaises(Exception):
            Reason(R.EXACT_MAPPING, "")
        with self.assertRaises(TypeError):
            Reason("EXACT_MAPPING", "x")  # type: ignore[arg-type]

    def test_missing_proof_is_never_promoted(self):
        # If a required proof were ever silently skipped, the result is EVIDENCE_INCOMPLETE.
        from app.classification import classifier

        original = classifier._membership
        try:
            classifier._membership = lambda out, bundle, ad: None
            r = run(world())
        finally:
            classifier._membership = original
        self.assertIs(r.classification, C.EVIDENCE_INCOMPLETE)
        self.assertIn("REQUIRED_CONDITION_UNPROVEN", r.reason_codes)
        self.assertIn("AD_GROUP_EMPTY", next(x for x in r.reasons if x.code is R.REQUIRED_CONDITION_UNPROVEN).detail)


class MappingConfidenceCoverageTests(unittest.TestCase):
    def test_only_exact_confidences_yield_exact_mapping(self):
        # Every confidence, including any added later, is either exact or a mapping problem.
        for confidence in MappingConfidence:
            with self.subTest(confidence.value):
                kw = {}
                if confidence is MappingConfidence.UNVERIFIED_STABLE_ID:
                    kw["matched_attributes"] = ("objectSid",)
                m = mapping(T0, confidence=confidence, **kw)
                b = world(mapping=m, ad_group=ad_group(T0) if m.ad_group_id else None)
                codes = run(b).reason_codes
                self.assertEqual("EXACT_MAPPING" in codes, m.is_exact)
                if not m.is_exact:
                    self.assertIs(run(b).classification, C.MAPPING_REQUIRED)

    def test_unverified_identifier_is_not_called_name_only(self):
        m = mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID, matched_attributes=("objectSid",))
        codes = run(world(mapping=m)).reason_codes
        self.assertIn("MAPPING_UNVERIFIED_IDENTIFIER", codes)
        self.assertNotIn("MAPPING_NAME_ONLY", codes)


class InputTests(unittest.TestCase):
    def test_arguments_are_type_checked(self):
        with self.assertRaises(TypeError):
            classify(world(), SUBJECT, POLICY, NOW)  # a LifecyclePolicy is not a CandidatePolicy
        with self.assertRaises(TypeError):
            classify(world(), SUBJECT, CPOLICY, NOW.replace(tzinfo=None))
        with self.assertRaises(Exception):
            CandidateSubject(GROUP_ID, ())

    def test_default_policy_fails_closed_without_configured_ad_sources(self):
        r = run(world(), policy=CandidatePolicy(lifecycle=LifecyclePolicy()))
        self.assertIs(r.classification, C.INACTIVE_REVIEW)
        self.assertIn("NOT_AD_SOURCED", r.reason_codes)
        self.assertNotEqual(SYNTHETIC_AD_SOURCE_ID, "")


class StaticSafetyTests(unittest.TestCase):
    FORBIDDEN_PREFIXES = ("socket", "http", "urllib", "subprocess", "requests", "httpx", "app.core.http",
                          "app.core.safety", "app.integrations", "app.store", "app.correlation")

    def test_classification_imports_nothing_that_reads_or_writes_externally(self):
        for path in (REPO_ROOT / "app" / "classification").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            with self.subTest(path=path.name):
                self.assertFalse([m for m in imported if m.startswith(self.FORBIDDEN_PREFIXES)])
                self.assertTrue(all(m.startswith(("app.", "dataclasses", "datetime", "enum", "typing")) for m in imported),
                                imported)


if __name__ == "__main__":
    unittest.main()
