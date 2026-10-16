"""Invariants of individual domain records, evidence freshness, coverage, approvals, jobs, and audit."""

import ast
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from app.core.errors import ProductionMutationNotPermitted
from app.core.modes import ExecutionMode
from app.domain.approval import ApprovalDecision, ApprovalStage, approval_problems
from app.domain.audit import AuditAction, AuditTrail, verify_chain
from app.domain.errors import InvalidRecord
from app.domain.evidence import (
    EvidencePurpose,
    EvidenceSource,
    FreshnessPolicy,
    ResultStatus,
    freshness_problems,
    stable_digest,
)
from app.domain.execution import JobKind, JobStatus
from app.domain.ids import IdKind, check_id, new_id
from app.domain.model import (
    DependencyCoverage,
    DependencyKind,
    MappingConfidence,
    OktaGroupType,
    assess_dependency_coverage,
)
from app.domain.policy import (
    DEFAULT_REQUIRED_DEPENDENCY_KINDS,
    MANDATORY_DEPENDENCY_KINDS,
    EvidenceBundle,
    LifecyclePolicy,
    evidence_fingerprint,
    protection_reasons,
)
from tests.domain_fixtures import (
    AD_ID,
    AD_ID_2,
    ASSIGNMENT_ID,
    DAY,
    GROUP_ID,
    HOUR,
    POLICY,
    REVIEWER,
    SYNTHETIC_DOMAIN_SID,
    SYNTHETIC_GUID,
    SYSTEM,
    T0,
    ad_group,
    application,
    approval,
    assignment,
    bundle,
    dependencies,
    dependency,
    dry_run_job,
    fixed_id,
    mapping,
    new_candidate,
    okta_group,
    prov,
    usage,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class IdTests(unittest.TestCase):
    def test_new_ids_are_prefixed_and_unique(self):
        a, b = new_id(IdKind.CANDIDATE), new_id(IdKind.CANDIDATE)
        self.assertNotEqual(a, b)
        self.assertEqual(check_id(a, IdKind.CANDIDATE, "id"), a)

    def test_external_or_wrong_kind_ids_are_rejected_as_internal_ids(self):
        for bogus in ("00gSYNTHETIC0001", new_id(IdKind.AD_GROUP), "cand_xyz", None, ""):
            with self.subTest(bogus=bogus), self.assertRaises(InvalidRecord):
                check_id(bogus, IdKind.CANDIDATE, "id")


class ProvenanceAndDigestTests(unittest.TestCase):
    def test_naive_datetimes_are_rejected(self):
        with self.assertRaises(InvalidRecord):
            replace(prov(T0), observed_at=datetime(2026, 1, 1))

    def test_provenance_fields_are_required(self):
        for field, value in (("scope", " "), ("collector_version", ""), ("source", "OKTA_API"), ("result_status", "COMPLETE")):
            with self.subTest(field=field), self.assertRaises(InvalidRecord):
                replace(prov(T0), **{field: value})

    def test_only_complete_results_are_decision_grade(self):
        self.assertTrue(prov(T0).decision_grade)
        self.assertFalse(prov(T0, ResultStatus.PARTIAL).decision_grade)
        self.assertFalse(prov(T0, ResultStatus.FAILED).decision_grade)

    def test_stable_digest_is_order_independent_and_content_sensitive(self):
        self.assertEqual(stable_digest({"a": 1, "b": {2, 1}}), stable_digest({"b": {1, 2}, "a": 1}))
        self.assertNotEqual(stable_digest({"a": 1}), stable_digest({"a": 2}))
        self.assertTrue(stable_digest({}).startswith("sha256:"))

    def test_digest_ignores_collection_time_and_display_labels(self):
        self.assertEqual(okta_group(T0).digest, okta_group(T0 + DAY).digest)
        self.assertEqual(application(T0).digest, application(T0, label="Renamed").digest)
        self.assertEqual(usage(T0).digest, usage(T0 + DAY).digest)  # rolling window, same length and activity

    def test_digest_changes_on_material_change(self):
        self.assertNotEqual(assignment(T0).digest, assignment(T0, present=False).digest)
        self.assertNotEqual(usage(T0).digest, usage(T0, events=1).digest)
        self.assertNotEqual(ad_group(T0).digest, ad_group(T0, member_count=3).digest)
        self.assertNotEqual(mapping(T0).digest, mapping(T0, confidence=MappingConfidence.NAME_ONLY).digest)


class FreshnessTests(unittest.TestCase):
    def test_defaults_tighten_with_risk(self):
        f = FreshnessPolicy()
        self.assertLess(f.execution, f.approval)
        self.assertLess(f.approval, f.review)
        self.assertLessEqual(f.execution, timedelta(hours=24))

    def test_ceilings_and_ordering_cannot_be_loosened(self):
        for kwargs in (
            {"execution": timedelta(hours=25)},
            {"approval": timedelta(days=15)},
            {"review": timedelta(days=91)},
            {"execution": timedelta(days=2), "approval": timedelta(days=1)},
            {"execution": timedelta(0)},
            {"clock_skew": timedelta(hours=1)},
            {"clock_skew": timedelta(seconds=-1)},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                FreshnessPolicy(**kwargs)

    def test_age_boundaries(self):
        f = FreshnessPolicy()
        p = prov(T0)
        self.assertEqual(freshness_problems("x", p, EvidencePurpose.EXECUTION, T0 + f.execution, f), [])
        stale = freshness_problems("x", p, EvidencePurpose.EXECUTION, T0 + f.execution + timedelta(seconds=1), f)
        self.assertIn("stale", stale[0])
        # Fresh for review is not fresh for execution.
        self.assertEqual(freshness_problems("x", p, EvidencePurpose.REVIEW, T0 + 2 * DAY, f), [])
        self.assertTrue(freshness_problems("x", p, EvidencePurpose.EXECUTION, T0 + 2 * DAY, f))

    def test_future_dated_evidence_is_rejected_beyond_skew(self):
        f = FreshnessPolicy()
        self.assertEqual(freshness_problems("x", prov(T0 + f.clock_skew), EvidencePurpose.REVIEW, T0, f), [])
        problems = freshness_problems("x", prov(T0 + f.clock_skew + timedelta(seconds=1)), EvidencePurpose.REVIEW, T0, f)
        self.assertIn("future", problems[0])

    def test_incomplete_results_are_never_fresh_enough(self):
        for status in (ResultStatus.PARTIAL, ResultStatus.FAILED):
            with self.subTest(status=status):
                problems = freshness_problems("x", prov(T0, status), EvidencePurpose.REVIEW, T0, FreshnessPolicy())
                self.assertIn("not decision-grade", problems[0])


class ObservationInvariantTests(unittest.TestCase):
    def test_usage_window_rules(self):
        for kwargs in (
            {"window_end": T0 + HOUR},  # after observed_at
            {"window_start": T0, "window_end": T0},
            {"event_count": 1, "distinct_user_count": 2},
            {"event_count": -1},
            {"event_count": True},
            {"last_activity_at": T0 - DAY},  # activity inside the window with 0 events
            {"okta_group_id": "00gSYNTHETIC0001"},  # external id where an internal id is required
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                usage(T0, **kwargs)

    def test_ad_group_rules(self):
        for kwargs in (
            {"object_guid": SYNTHETIC_GUID.upper()},
            {"object_guid": "not-a-guid"},
            {"sid": None},
            {"sid": "S-1-x"},
            {"distinguished_name": None},
            {"member_count": -1},
            {"admin_count": "yes"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                ad_group(T0, **kwargs)
        self.assertFalse(ad_group(T0, exists=False).exists)

    def test_well_known_rid_detection(self):
        self.assertIsNone(ad_group(T0, rid=4321).well_known_rid)
        self.assertEqual(ad_group(T0, rid=512).well_known_rid, 512)
        self.assertEqual(ad_group(T0, sid="S-1-5-32-544").well_known_rid, 544)

    def test_directory_attributes_only_on_app_groups(self):
        with self.assertRaises(InvalidRecord):
            okta_group(T0, group_type=OktaGroupType.OKTA_GROUP)
        okta_group(T0, group_type=OktaGroupType.OKTA_GROUP, source_directory_id=None, directory_external_id=None,
                   directory_qualified_name=None)


class IdentityMappingTests(unittest.TestCase):
    def test_every_confidence_has_a_valid_form(self):
        for confidence in MappingConfidence:
            with self.subTest(confidence=confidence):
                self.assertIs(mapping(T0, confidence=confidence).confidence, confidence)

    def test_only_exact_confidences_are_exact(self):
        exact = {c for c in MappingConfidence if mapping(T0, confidence=c).is_exact}
        self.assertEqual(exact, {MappingConfidence.EXACT_STABLE_ID, MappingConfidence.EXACT_DIRECTORY_SOURCE,
                                 MappingConfidence.EXACT_CONFIGURED_MAPPING})

    def test_mapping_rules(self):
        cases = [
            (MappingConfidence.AMBIGUOUS, {"ad_group_id": AD_ID}),
            (MappingConfidence.AMBIGUOUS, {"candidate_ad_group_ids": (AD_ID,)}),
            (MappingConfidence.NOT_FOUND, {"ad_group_id": AD_ID}),
            (MappingConfidence.EXACT_STABLE_ID, {"ad_group_id": None}),
            (MappingConfidence.EXACT_STABLE_ID, {"matched_attributes": ("sAMAccountName",)}),
            (MappingConfidence.EXACT_STABLE_ID, {"matched_attributes": ()}),
            (MappingConfidence.EXACT_STABLE_ID, {"candidate_ad_group_ids": (AD_ID, AD_ID_2)}),
            (MappingConfidence.EXACT_STABLE_ID, {"configuration_ref": "mappings/x"}),
            (MappingConfidence.EXACT_STABLE_ID, {"reason": "  "}),
            (MappingConfidence.NAME_ONLY, {"matched_attributes": ("objectGUID",)}),
            (MappingConfidence.EXACT_CONFIGURED_MAPPING, {"configuration_ref": None}),
            (MappingConfidence.EXACT_CONFIGURED_MAPPING, {"provenance": prov(T0, source=EvidenceSource.OKTA_API)}),
        ]
        for confidence, kwargs in cases:
            with self.subTest(confidence=confidence, kwargs=kwargs), self.assertRaises(InvalidRecord):
                mapping(T0, confidence=confidence, **kwargs)


class DependencyCoverageTests(unittest.TestCase):
    def test_complete_partial_unknown(self):
        required = DEFAULT_REQUIRED_DEPENDENCY_KINDS
        self.assertIs(assess_dependency_coverage(dependencies(T0), required), DependencyCoverage.COMPLETE)
        some = dependencies(T0, kinds=MANDATORY_DEPENDENCY_KINDS)
        self.assertIs(assess_dependency_coverage(some, required), DependencyCoverage.PARTIAL)
        self.assertIs(assess_dependency_coverage((), required), DependencyCoverage.UNKNOWN)

    def test_failed_or_partial_checks_do_not_count(self):
        checks = list(dependencies(T0))
        checks[0] = dependency(T0, checks[0].kind, 99, status=ResultStatus.FAILED)
        self.assertIs(assess_dependency_coverage(tuple(checks), DEFAULT_REQUIRED_DEPENDENCY_KINDS), DependencyCoverage.PARTIAL)
        only_failed = (dependency(T0, DependencyKind.AD_GROUP_MEMBERS, 1, status=ResultStatus.PARTIAL),)
        self.assertIs(assess_dependency_coverage(only_failed, DEFAULT_REQUIRED_DEPENDENCY_KINDS), DependencyCoverage.UNKNOWN)

    def test_empty_requirement_is_rejected(self):
        with self.assertRaises(InvalidRecord):
            assess_dependency_coverage((), frozenset())

    def test_dependency_subject_must_be_a_group(self):
        with self.assertRaises(InvalidRecord):
            dependency(T0, DependencyKind.OTHER, 1, subject_id=ASSIGNMENT_ID)
        dependency(T0, DependencyKind.OTHER, 1, subject_id=GROUP_ID)


class PolicyTests(unittest.TestCase):
    def test_policy_cannot_be_loosened(self):
        for kwargs in (
            {"min_usage_window": timedelta(days=29)},
            {"max_usage_events_for_candidate": 6},
            {"max_usage_events_for_candidate": -1},
            {"hold_period": timedelta(days=6)},
            {"approval_max_ttl": timedelta(days=15)},
            {"approval_max_ttl": timedelta(minutes=5)},
            {"required_dependency_kinds": frozenset({DependencyKind.OTHER})},
            {"required_dependency_kinds": MANDATORY_DEPENDENCY_KINDS - {DependencyKind.AD_GROUP_MEMBERS}},
            {"protected_ad_sids": {"S-1-5-32-544"}},  # mutable set
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                LifecyclePolicy(**kwargs)

    def test_protection_reasons(self):
        protected_guid = LifecyclePolicy(protected_ad_object_guids=frozenset({SYNTHETIC_GUID}))
        protected_sid = LifecyclePolicy(protected_ad_sids=frozenset({f"{SYNTHETIC_DOMAIN_SID}-4321"}))
        protected_okta = LifecyclePolicy(protected_okta_group_ids=frozenset({"00gSYNTHETIC0001"}))
        builtin_okta = okta_group(T0, group_type=OktaGroupType.BUILT_IN, source_directory_id=None,
                                  directory_external_id=None, directory_qualified_name=None)
        cases = [
            (POLICY, bundle(T0, ad_group=ad_group(T0, rid=512)), "well-known SID"),
            (POLICY, bundle(T0, ad_group=ad_group(T0, sid="S-1-5-32-544")), "well-known SID"),
            (POLICY, bundle(T0, ad_group=ad_group(T0, admin_count=True)), "adminCount"),
            (POLICY, bundle(T0, ad_group=ad_group(T0, protected_from_accidental_deletion=True)), "ProtectedFromAccidentalDeletion"),
            (POLICY, bundle(T0, ad_group=ad_group(T0, is_critical_system_object=True)), "critical system object"),
            (POLICY, bundle(T0, okta_group=builtin_okta), "built-in"),
            (protected_guid, bundle(T0), "protected list"),
            (protected_sid, bundle(T0), "protected list"),
            (protected_okta, bundle(T0), "protected list"),
        ]
        for policy, evidence, expected in cases:
            with self.subTest(expected=expected):
                self.assertTrue(any(expected in r for r in protection_reasons(evidence, policy)))
        self.assertEqual(protection_reasons(bundle(T0), POLICY), [])

    def test_protected_identifiers_match_their_evidence_or_are_refused(self):
        """F11: a GUID protects its AD group in any letter case; an entry that could never match is refused,
        never kept as one that protects nothing."""
        upper = SYNTHETIC_GUID.upper()
        for guid in (SYNTHETIC_GUID, upper, upper[:4] + SYNTHETIC_GUID[4:]):
            with self.subTest(guid=guid):
                policy = LifecyclePolicy(protected_ad_object_guids=frozenset({guid}))
                self.assertEqual(policy.protected_ad_object_guids, {SYNTHETIC_GUID})  # ADGroup.object_guid's form
                self.assertTrue(any("protected list" in r for r in protection_reasons(bundle(T0), policy)))
        sid = f"{SYNTHETIC_DOMAIN_SID}-4321"
        refused = {
            "protected_ad_object_guids": (
                "{" + SYNTHETIC_GUID + "}", SYNTHETIC_GUID.replace("-", ""), "urn:uuid:" + SYNTHETIC_GUID,
                SYNTHETIC_GUID + "\n", " " + SYNTHETIC_GUID, SYNTHETIC_GUID[:-2] + "_1",  # uuid.UUID reads "_1" as 1
                SYNTHETIC_GUID[:-1] + "١", SYNTHETIC_GUID[:-1], "not-a-guid"),
            "protected_ad_sids": (sid + "\n", "s" + sid[1:], sid[:-1] + "١", " " + sid, "S-1-5", "S-1-5-", "x"),
            "protected_okta_group_ids": ("00gSYNTHETIC0001\n", "00g-SYNTHETIC", "0" * 65, "00g١"),
        }
        for name, values in refused.items():
            for value in values:
                with self.subTest(field=name, value=value), self.assertRaises(InvalidRecord):
                    LifecyclePolicy(**{name: frozenset({value})})
        # SIDs and Okta ids are matched exactly as AD and Okta write them.
        self.assertEqual(LifecyclePolicy(protected_ad_sids=frozenset({sid})).protected_ad_sids, {sid})
        self.assertEqual(LifecyclePolicy(protected_okta_group_ids=frozenset({"00gSynth01"})).protected_okta_group_ids,
                         {"00gSynth01"})


class EvidenceBundleTests(unittest.TestCase):
    def test_duplicates_are_rejected(self):
        for kwargs in (
            {"assignments": (assignment(T0), assignment(T0, present=False))},
            {"usage": (usage(T0), usage(T0, id=fixed_id(IdKind.USAGE_OBSERVATION, 2)))},
            {"dependencies": (dependency(T0, DependencyKind.OTHER, 1), dependency(T0, DependencyKind.OTHER, 2))},
        ):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(InvalidRecord):
                EvidenceBundle(**kwargs)

    def test_wrong_record_types_are_rejected(self):
        with self.assertRaises(InvalidRecord):
            EvidenceBundle(assignments=[assignment(T0)])
        with self.assertRaises(InvalidRecord):
            EvidenceBundle(mapping=ad_group(T0))

    def test_usage_prefers_group_scoped_observation(self):
        scoped = usage(T0, id=fixed_id(IdKind.USAGE_OBSERVATION, 2), okta_group_id=GROUP_ID, events=3)
        b = EvidenceBundle(usage=(usage(T0), scoped))
        self.assertIs(b.usage_for(scoped.application_id, GROUP_ID), scoped)

    def test_fingerprint_is_stable_under_re_observation(self):
        self.assertEqual(evidence_fingerprint(bundle(T0)), evidence_fingerprint(bundle(T0 + DAY)))

    def test_fingerprint_changes_on_material_or_status_change(self):
        base = evidence_fingerprint(bundle(T0))
        variants = [
            bundle(T0, usage_events=1),
            bundle(T0, present=False),
            bundle(T0, confidence=MappingConfidence.NAME_ONLY),
            bundle(T0, ad_group=ad_group(T0, member_count=5)),
            bundle(T0, dep_kinds=MANDATORY_DEPENDENCY_KINDS),
            bundle(T0, assignments=(assignment(T0, status=ResultStatus.PARTIAL),)),
            bundle(T0, applications=()),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertNotEqual(evidence_fingerprint(variant), base)


class ApprovalRecordTests(unittest.TestCase):
    def setUp(self):
        self.candidate = new_candidate()
        self.evidence = bundle(T0)

    def test_record_invariants(self):
        good = approval(self.candidate, ApprovalStage.OKTA_UNASSIGN, T0, self.evidence)
        for kwargs in (
            {"operator": SYSTEM},
            {"expires_at": T0},
            {"reason": ""},
            {"evidence_fingerprint": "abc"},
            {"candidate_epoch": -1},
            {"decision": "APPROVE"},
            {"candidate_id": GROUP_ID},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                replace(good, **kwargs)

    def _problems(self, record, now=T0 + HOUR, fingerprint=None, **kw):
        args = dict(candidate_id=self.candidate.id, candidate_epoch=0, proposed_by=SYSTEM, stage=ApprovalStage.OKTA_UNASSIGN,
                    now=now, max_ttl=POLICY.approval_max_ttl, clock_skew=POLICY.freshness.clock_skew,
                    evidence_fingerprint=fingerprint or evidence_fingerprint(self.evidence))
        args.update(kw)
        return approval_problems(record, **args)

    def test_valid_approval_has_no_problems(self):
        self.assertEqual(self._problems(approval(self.candidate, ApprovalStage.OKTA_UNASSIGN, T0, self.evidence)), [])

    def test_each_invalidating_condition(self):
        base = approval(self.candidate, ApprovalStage.OKTA_UNASSIGN, T0, self.evidence)
        cases = [
            ("no OKTA_UNASSIGN approval", None, {}),
            ("different candidate", replace(base, candidate_id=fixed_id(IdKind.CANDIDATE, 9)), {}),
            ("stage", replace(base, stage=ApprovalStage.AD_RETIREMENT), {}),
            ("decision is REJECT", replace(base, decision=ApprovalDecision.REJECT), {}),
            ("epoch", base, {"candidate_epoch": 1}),
            ("proposed the candidate", base, {"proposed_by": REVIEWER}),
            ("lifetime exceeds", replace(base, expires_at=T0 + 8 * DAY), {}),
            ("future", replace(base, decided_at=T0 + 2 * HOUR, expires_at=T0 + DAY), {}),
            ("expired", base, {"now": base.expires_at}),
            ("before it was allowed", base, {"not_before": T0 + HOUR}),
            ("material evidence changed", base, {"fingerprint": evidence_fingerprint(bundle(T0, usage_events=1))}),
        ]
        for expected, record, kw in cases:
            with self.subTest(expected=expected):
                problems = self._problems(record, **kw)
                self.assertTrue(any(expected in p for p in problems), problems)


class ExecutionJobTests(unittest.TestCase):
    def setUp(self):
        self.candidate = new_candidate()
        self.evidence = bundle(T0)
        self.approval = approval(self.candidate, ApprovalStage.OKTA_UNASSIGN, T0, self.evidence)

    def _job(self, **kw):
        requested_at, finished_at = kw.pop("requested_at", T0), kw.pop("finished_at", T0 + HOUR)
        return dry_run_job(self.candidate, JobKind.OKTA_UNASSIGN, self.approval, self.evidence, requested_at, finished_at, **kw)

    def test_production_mutation_jobs_cannot_exist_in_this_build(self):
        with self.assertRaises(ProductionMutationNotPermitted):
            self._job(mode=ExecutionMode.PRODUCTION_MUTATION, dry_run=False, executed=True)
        with self.assertRaises(ProductionMutationNotPermitted):
            self._job(mode=ExecutionMode.PRODUCTION_MUTATION)

    def test_real_execution_cannot_be_recorded(self):
        for kwargs in (
            {"mode": ExecutionMode.READ_ONLY_PRODUCTION},
            {"mode": ExecutionMode.DRY_RUN_MUTATION, "dry_run": False},
            {"dry_run": True, "executed": True},
            {"mode": ExecutionMode.LOCAL_SYNTHETIC, "dry_run": False, "executed": True, "targets_synthetic": False},
            {"mode": ExecutionMode.LOCAL_SYNTHETIC, "dry_run": False, "executed": True, "targets_synthetic": True,
             "status": JobStatus.FAILED},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                self._job(**kwargs)
        synthetic = self._job(mode=ExecutionMode.LOCAL_SYNTHETIC, dry_run=False, executed=True, targets_synthetic=True)
        self.assertTrue(synthetic.executed)

    def test_job_shape_rules(self):
        for kwargs in (
            {"targets": ()},
            {"targets": (ASSIGNMENT_ID, ASSIGNMENT_ID)},
            {"targets": (AD_ID,)},  # wrong id kind for an Okta unassignment
            {"finished_at": None},
            {"finished_at": T0 - HOUR},
            {"status": JobStatus.RUNNING},  # unfinished job with finished_at
            {"requested_by": "someone"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRecord):
                self._job(**kwargs)
        with self.assertRaises(InvalidRecord):
            dry_run_job(self.candidate, JobKind.AD_RETIREMENT, self.approval, self.evidence, T0, T0 + HOUR, targets=(AD_ID, AD_ID_2))
        self.assertIsNone(self._job(status=JobStatus.PLANNED, finished_at=None).finished_at)


class AuditTrailTests(unittest.TestCase):
    def _trail(self, n=3):
        trail = AuditTrail()
        for i in range(n):
            trail.append(actor=SYSTEM, action=AuditAction.EVIDENCE_RECORDED, subject_id=f"subject-{i}",
                         occurred_at=T0 + i * HOUR, details={"n": i})
        return trail

    def test_chain_verifies(self):
        trail = self._trail()
        verify_chain(trail.events, expected_head=trail.events[-1].digest)
        self.assertIsNone(trail.events[0].previous_digest)
        self.assertEqual(trail.events[1].previous_digest, trail.events[0].digest)

    def test_tampering_is_detected(self):
        events = list(self._trail().events)
        edited = replace(events[0], details=(("n", "999"),))
        cases = {
            "edited": [edited, *events[1:]],
            "removed": [events[0], events[2]],
            "reordered": [events[1], events[0], events[2]],
        }
        for name, sequence in cases.items():
            with self.subTest(name=name), self.assertRaises(InvalidRecord):
                verify_chain(sequence)
        last_edited = [*events[:2], replace(events[2], subject_id="other")]
        verify_chain(last_edited)  # undetectable without an anchor...
        with self.assertRaises(InvalidRecord):
            verify_chain(last_edited, expected_head=events[2].digest)  # ...detected with one

    def test_details_are_redacted(self):
        trail = AuditTrail()
        event = trail.append(actor=SYSTEM, action=AuditAction.EVIDENCE_RECORDED, subject_id="s", occurred_at=T0,
                             details={"note": "header was Bearer synthetic-value-abcdef", "api_token": "synthetic-value-0001"})
        text = repr(event.details)
        self.assertNotIn("synthetic-value", text)

    def test_events_must_be_appended_in_time_order(self):
        trail = self._trail(1)
        with self.assertRaises(InvalidRecord):
            trail.append(actor=SYSTEM, action=AuditAction.EVIDENCE_RECORDED, subject_id="s", occurred_at=T0 - HOUR)


class DomainPurityTests(unittest.TestCase):
    """The domain package performs no I/O and cannot reach mutation code."""

    FORBIDDEN = {
        "socket", "http", "http.client", "urllib", "urllib.request", "subprocess", "requests", "httpx",
        "app.core.safety", "os", "shutil", "sqlite3",
    }

    def test_domain_modules_import_nothing_forbidden(self):
        for path in (REPO_ROOT / "app" / "domain").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            with self.subTest(path=path.name):
                self.assertEqual(imported & self.FORBIDDEN, set())


if __name__ == "__main__":
    unittest.main()
