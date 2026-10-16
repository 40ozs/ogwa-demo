"""Policy configuration, auditable versions, finding codes, and AD evidence end to end.

Synthetic only. The AD reports are the golden AD fixtures in tests/fixtures/ad.
"""

import json
import sqlite3
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from app.classification import Classification, ReasonCode, classify
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction
from app.domain.candidate_policy import (
    POLICY_FORMAT,
    CandidatePolicy,
    PolicyRole,
    PolicyVersion,
    canonical_json,
    version_append_problems,
)
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, stable_digest
from app.domain.ids import IdKind
from app.domain.model import DependencyEvidence, DependencyFinding, DependencyKind, FindingCode
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS, LifecyclePolicy
from app.integrations.ad import ADStableIds, ad_evidence
from app.store.errors import StoreConflict
from tests.classification_fixtures import CPOLICY, NOW, SUBJECT, check, run, with_check, world
from tests.domain_fixtures import AD_ID, DAY, POLICY, REVIEWER, SECOND_REVIEWER, SYSTEM, T0, fixed_id, prov
from tests.store_fixtures import new_store
from tests.test_ad_integration import CORP, policy as ad_policy, report

K = DependencyKind
THIRD_REVIEWER = Actor(ActorKind.HUMAN, "synthetic-reviewer-3")


def version(policy: CandidatePolicy, n: int, previous=None, *, at=T0 + DAY, proposed_by=REVIEWER,
            approved_by=SECOND_REVIEWER, reason="synthetic policy change", proposer_role=PolicyRole.IDENTITY_AUTOMATION,
            approver_role=PolicyRole.SECURITY_IAM) -> PolicyVersion:
    return PolicyVersion.create(policy, id=fixed_id(IdKind.POLICY_VERSION, n), previous=previous, proposed_by=proposed_by,
                                proposer_role=proposer_role, approved_by=approved_by, approver_role=approver_role,
                                decided_at=at, reason=reason)


class PolicyBoundsTests(unittest.TestCase):
    def test_defaults(self):
        p = CandidatePolicy()
        self.assertEqual(p.low_usage_max_sign_ins, 5)  # the low-usage threshold
        self.assertIsNone(p.low_usage_max_unique_users)
        self.assertEqual(p.lifecycle.min_usage_window, timedelta(days=90))  # D27
        self.assertEqual(p.lifecycle.ad_directory_source_ids, frozenset())  # fail closed

    def test_out_of_bounds_values_are_refused(self):
        bad = [
            dict(low_usage_max_sign_ins=-1),
            dict(low_usage_max_sign_ins=1001),
            dict(low_usage_max_sign_ins=True),
            dict(lifecycle=replace(POLICY, max_usage_events_for_candidate=5), low_usage_max_sign_ins=4),
            dict(low_usage_max_unique_users=6),
            dict(low_usage_max_unique_users=-1),
            dict(review_min_usage_window=timedelta(days=6)),
            dict(review_min_usage_window=timedelta(days=91)),
            dict(recent_login_window=timedelta(hours=12)),
            dict(recent_login_window=timedelta(days=91)),
            dict(lifecycle="not a policy"),
        ]
        for kwargs in bad:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(InvalidRecord):
                    CandidatePolicy(**kwargs)


class PolicyDocumentTests(unittest.TestCase):
    def test_round_trip_is_exact(self):
        p = CandidatePolicy(
            lifecycle=replace(POLICY, protected_okta_group_ids=frozenset({"00gSYNTHPROT01"}),
                              protected_ad_object_guids=frozenset({"5e1f0c3a-0000-4000-8000-0000000000ff"})),
            low_usage_max_sign_ins=3, low_usage_max_unique_users=2, review_min_usage_window=timedelta(days=14),
            recent_login_window=timedelta(days=21),
        )
        again = CandidatePolicy.from_json(p.canonical_json())
        self.assertEqual(again, p)
        self.assertEqual(again.digest, p.digest)
        self.assertEqual(p.digest, stable_digest(json.loads(p.canonical_json())))

    def test_protected_guids_are_canonical_in_the_document(self):
        """F11: an upper-case GUID is the same policy as its canonical form; a malformed one is refused."""
        canonical = json.loads(CandidatePolicy().canonical_json())
        canonical["protected"]["adObjectGuids"] = ["5e1f0c3a-0000-4000-8000-0000000000ff"]
        written = json.loads(json.dumps(canonical))
        written["protected"]["adObjectGuids"] = ["5E1F0C3A-0000-4000-8000-0000000000FF"]
        policy = CandidatePolicy.from_document(written)
        self.assertEqual(policy, CandidatePolicy.from_document(canonical))
        self.assertEqual(json.loads(policy.canonical_json()), canonical)
        written["protected"]["adObjectGuids"] = ["{5E1F0C3A-0000-4000-8000-0000000000FF}"]
        with self.assertRaises(InvalidRecord):
            CandidatePolicy.from_document(written)

    def test_digest_changes_with_any_threshold(self):
        base = CPOLICY.digest
        for changed in (CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=4),
                        CandidatePolicy(lifecycle=replace(POLICY, hold_period=timedelta(days=31))),
                        CandidatePolicy(lifecycle=replace(POLICY, ad_directory_source_ids=frozenset()))):
            self.assertNotEqual(changed.digest, base)

    def _doc(self):
        return CPOLICY.to_document()

    def test_strict_document(self):
        def mutate(f):
            d = json.loads(json.dumps(self._doc()))
            f(d)
            return json.dumps(d)

        cases = {
            "unknown top-level key": lambda d: d.update(extra=1),
            "missing key": lambda d: d.pop("protected"),
            "unknown nested key": lambda d: d["usage"].update(lowUsageMaxLogins=5),
            "wrong format": lambda d: d.update(format="ogwa-candidate-policy/v0"),
            "bool as integer": lambda d: d["usage"].update(lowUsageMaxSignIns=True),
            "float": lambda d: d["usage"].update(lowUsageMaxSignIns=5.0),
            "unknown dependency kind": lambda d: d["requiredDependencyKinds"].append("DNS_REFERENCE"),
            "mandatory kind dropped": lambda d: d["requiredDependencyKinds"].remove("AD_GROUP_MEMBERS"),
            "retirement window below floor": lambda d: d["usage"].update(retirementWindowDays=29),
            "retirement threshold above ceiling": lambda d: d["usage"].update(retirementMaxSignIns=6),
            "freshness above ceiling": lambda d: d["freshness"].update(reviewHours=24 * 91),
            "duplicate list entry": lambda d: d["adDirectorySourceIds"].append(d["adDirectorySourceIds"][0]),
            "empty string": lambda d: d["protected"]["adSids"].append(" "),
        }
        for name, f in cases.items():
            with self.subTest(name):
                with self.assertRaises(InvalidRecord):
                    CandidatePolicy.from_json(mutate(f))

    def test_json_level_refusals(self):
        text = CPOLICY.canonical_json()
        for bad in ("not json", text.replace('"format"', '"format":"x","format"', 1), '{"x": NaN}', "x" * 100_001):
            with self.subTest(bad=bad[:40]):
                with self.assertRaises(InvalidRecord):
                    CandidatePolicy.from_json(bad)

    def test_document_is_complete_and_explicit(self):
        doc = self._doc()
        self.assertEqual(doc["format"], POLICY_FORMAT)
        self.assertEqual(doc["usage"]["retirementWindowDays"], 90)
        self.assertEqual(doc["requiredDependencyKinds"], sorted(k.value for k in DEFAULT_REQUIRED_DEPENDENCY_KINDS))
        self.assertIsNone(doc["usage"]["lowUsageMaxUniqueUsers"])

    def test_non_whole_units_cannot_be_serialized(self):
        p = CandidatePolicy(lifecycle=POLICY, review_min_usage_window=timedelta(days=10, hours=1))
        with self.assertRaises(InvalidRecord):
            p.to_document()


class PolicyVersionTests(unittest.TestCase):
    def test_valid_version(self):
        v = version(CPOLICY, 1)
        self.assertEqual(v.policy, CPOLICY)
        self.assertEqual(v.policy_digest, CPOLICY.digest)
        self.assertEqual(version_append_problems((), v), [])

    def test_four_eyes_and_humans_only(self):
        with self.assertRaisesRegex(InvalidRecord, "other than its proposer"):
            version(CPOLICY, 1, approved_by=REVIEWER)
        with self.assertRaisesRegex(InvalidRecord, "human"):
            version(CPOLICY, 1, proposed_by=SYSTEM)
        with self.assertRaisesRegex(InvalidRecord, "human"):
            version(CPOLICY, 1, approved_by=SYSTEM)

    def test_identity_automation_proposes_and_security_iam_approves(self):
        # D33. Roles are recorded on every version and checked by the domain and the database.
        with self.assertRaisesRegex(InvalidRecord, "proposed by IDENTITY_AUTOMATION"):
            version(CPOLICY, 1, proposer_role=PolicyRole.SECURITY_IAM)
        with self.assertRaisesRegex(InvalidRecord, "approved by SECURITY_IAM"):
            version(CPOLICY, 1, approver_role=PolicyRole.IDENTITY_AUTOMATION)
        with self.assertRaises(InvalidRecord):
            version(CPOLICY, 1, proposer_role="IDENTITY_AUTOMATION")  # type: ignore[arg-type]

    def test_document_must_be_canonical_and_match_its_digest(self):
        v = version(CPOLICY, 1)
        with self.assertRaisesRegex(InvalidRecord, "digest"):
            replace(v, policy_digest=CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=4).digest)
        with self.assertRaisesRegex(InvalidRecord, "canonical"):
            replace(v, document=json.dumps(CPOLICY.to_document(), indent=2))
        with self.assertRaises(InvalidRecord):
            replace(v, document="{}")

    def test_chain_rules(self):
        v1 = version(CPOLICY, 1)
        changed = CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=3)
        v2 = version(changed, 2, v1, at=T0 + 2 * DAY)
        self.assertEqual(version_append_problems((v1,), v2), [])
        self.assertTrue(version_append_problems((), v2))  # does not continue an empty chain
        self.assertTrue(version_append_problems((v1,), version(CPOLICY, 2, v1, at=T0 + 2 * DAY)))  # unchanged
        self.assertTrue(version_append_problems((v1,), version(changed, 2, v1, at=T0)))  # back-dated
        self.assertTrue(version_append_problems((v1,), v1))  # already recorded


class PolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = new_store()

    def tearDown(self):
        self.store.close()

    def test_versions_persist_with_audit_and_integrity(self):
        self.assertIsNone(self.store.active_policy_version())
        v1 = version(CPOLICY, 1)
        self.store.record_policy_version(v1)
        changed = CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=3)
        v2 = version(changed, 2, v1, at=T0 + 2 * DAY, proposed_by=SECOND_REVIEWER, approved_by=THIRD_REVIEWER)
        self.store.record_policy_version(v2)
        self.assertEqual(self.store.policy_versions(), [v1, v2])
        self.assertEqual(self.store.active_policy_version(), v2)
        self.assertEqual(self.store.active_policy_version().policy, changed)
        events = [e for e in self.store.audit_events() if e.action is AuditAction.POLICY_REVIEW_RECORDED]  # D41
        self.assertEqual(len(events), 2)
        self.assertFalse([e for e in self.store.audit_events() if e.action is AuditAction.APPROVAL_RECORDED])
        last = events[-1]
        self.assertEqual(last.actor, THIRD_REVIEWER)
        details = dict(last.details)
        self.assertEqual((details["proposer_role"], details["approver_role"]), ("IDENTITY_AUTOMATION", "SECURITY_IAM"))
        self.assertEqual((v2.proposer_role, v2.approver_role), (PolicyRole.IDENTITY_AUTOMATION, PolicyRole.SECURITY_IAM))
        self.assertEqual(details["policy_digest"], changed.digest)
        self.assertEqual(details["previous_digest"], CPOLICY.digest)
        self.assertEqual(details["proposed_by"], str(SECOND_REVIEWER))
        self.assertEqual(last.before_ref, f"policy_version:{v1.id}")
        self.store.verify_integrity()

    def test_store_refuses_bad_versions(self):
        v1 = version(CPOLICY, 1)
        self.store.record_policy_version(v1)
        with self.assertRaisesRegex(StoreConflict, "unchanged"):
            self.store.record_policy_version(version(CPOLICY, 2, v1, at=T0 + 2 * DAY))
        with self.assertRaisesRegex(StoreConflict, "future"):
            self.store.record_policy_version(
                version(CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=3), 2, v1, at=T0 + 365 * DAY))
        with self.assertRaisesRegex(StoreConflict, "continue the chain"):
            self.store.record_policy_version(version(CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=3), 2))

    def test_database_guards(self):
        v1 = version(CPOLICY, 1)
        self.store.record_policy_version(v1)
        conn = self.store.connection
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute("UPDATE policy_versions SET reason = 'edited'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute("DELETE FROM policy_versions")
        row = dict(conn.execute("SELECT * FROM policy_versions").fetchone())
        changed = CandidatePolicy(lifecycle=POLICY, low_usage_max_sign_ins=3)
        insert = lambda **kw: conn.execute(  # noqa: E731
            f"INSERT INTO policy_versions ({', '.join({**row, **kw})}) VALUES ({', '.join('?' for _ in {**row, **kw})})",
            tuple({**row, **kw}.values()))
        nxt = dict(id=fixed_id(IdKind.POLICY_VERSION, 2), sequence=1, supersedes=v1.id,
                   policy_digest=changed.digest, document=changed.canonical_json())
        with self.assertRaisesRegex(sqlite3.IntegrityError, "extend"):
            insert(**{**nxt, "sequence": 5})
        with self.assertRaisesRegex(sqlite3.IntegrityError, "extend"):
            insert(**{**nxt, "policy_digest": v1.policy_digest, "document": v1.document})  # unchanged
        with self.assertRaises(sqlite3.IntegrityError):
            insert(**{**nxt, "approved_by_id": row["proposed_by_id"]})  # self-approval
        with self.assertRaises(sqlite3.IntegrityError):
            insert(**{**nxt, "approved_by_kind": "SYSTEM"})
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Security/IAM approver"):
            insert(**{**nxt, "approved_by_role": None})
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Security/IAM approver"):
            insert(**{**nxt, "proposed_by_role": None})
        with self.assertRaises(sqlite3.IntegrityError):
            insert(**{**nxt, "approved_by_role": "IDENTITY_AUTOMATION"})
        with self.assertRaises(sqlite3.IntegrityError):
            insert(**{**nxt, "proposed_by_role": "SECURITY_IAM"})
        insert(**nxt)  # the same row with valid roles is accepted


class FindingCodeTests(unittest.TestCase):
    def test_uncoded_findings_keep_their_digest(self):
        f = DependencyFinding("synthetic", True, "ref")
        d = DependencyEvidence(id=fixed_id(IdKind.DEPENDENCY_EVIDENCE, 1), subject_id=AD_ID, kind=K.AD_ACL_REFERENCE,
                               findings=(f,), provenance=prov(T0))
        # The original material formula, unchanged for findings without a code.
        p03 = stable_digest({"kind": "DEPENDENCY", "id": d.id, "material": {
            "subject_id": AD_ID, "kind": K.AD_ACL_REFERENCE, "findings": [["synthetic", True, "ref"]]}})
        self.assertEqual(d.digest, p03)
        coded = replace(d, kind=K.AD_GROUP_MEMBERS,
                        findings=(replace(f, code=FindingCode.AD_DIRECT_MEMBERS),))
        self.assertNotEqual(coded.digest, replace(d, kind=K.AD_GROUP_MEMBERS).digest)

    def test_code_must_match_the_kind(self):
        with self.assertRaisesRegex(InvalidRecord, "does not belong"):
            check(T0, K.AD_GROUP_MEMBERS, (DependencyFinding("x", True, code=FindingCode.AD_PARENT_GROUP),))
        with self.assertRaises(InvalidRecord):
            DependencyFinding("x", True, code="AD_PARENT_GROUP")  # type: ignore[arg-type]

    def test_codes_round_trip_through_the_store(self):
        store = new_store()
        try:
            b = world()
            store.record_evidence(b.ad_group, actor=SYSTEM)
            coded = check(T0, K.AD_NESTED_MEMBERSHIP, (
                DependencyFinding("member of group SYNTH-PARENT", True, "CN=SYNTH-PARENT", FindingCode.AD_PARENT_GROUP),
                DependencyFinding("group nesting contains a cycle", False, code=FindingCode.AD_NESTING_CYCLE),
                DependencyFinding("uncoded", True),
            ))
            store.record_evidence(coded, actor=SYSTEM)
            loaded = store.latest(DependencyEvidence, coded.id)
            self.assertEqual(loaded, coded)
            self.assertEqual(loaded.digest, coded.digest)
            store.verify_integrity()
            with self.assertRaises(sqlite3.IntegrityError):
                store.connection.execute(
                    "INSERT INTO dependency_findings (observation_id, ordinal, description, blocking, reference, code) "
                    "SELECT observation_id, 9, 'x', 1, NULL, 'NOT_A_CODE' FROM dependency_findings LIMIT 1")
        finally:
            store.close()


class GoldenADReportTests(unittest.TestCase):
    """Golden AD reports, through ad_evidence, into the classifier."""

    def _classify(self, name, source=EvidenceSource.SYNTHETIC):
        r = report(name)
        e = ad_evidence(r, policy=ad_policy(), source=source, ids=ADStableIds(CORP))
        self.assertIsNotNone(e.ad_group)
        ad = replace(e.ad_group, id=AD_ID, provenance=replace(e.ad_group.provenance, observed_at=T0))
        deps = tuple(replace(d, subject_id=AD_ID, provenance=replace(d.provenance, observed_at=T0)) for d in e.dependencies)
        b = world(ad_group=ad)
        for d in deps:
            b = with_check(b, d.kind, d)
        return e, run(b)

    def test_findings_carry_codes(self):
        e, _ = self._classify("primary-group-dependency")
        codes = {f.code for d in e.dependencies for f in d.findings}
        self.assertIn(FindingCode.AD_PRIMARY_GROUP_REFERENCES, codes)
        e, _ = self._classify("nested-group")
        codes = {f.code for d in e.dependencies for f in d.findings}
        self.assertTrue(codes & {FindingCode.AD_PARENT_GROUP, FindingCode.AD_MEMBER_GROUPS, FindingCode.AD_NESTED_PRINCIPALS})
        self.assertNotIn(None, codes)

    def test_scenarios(self):
        expected = {
            "primary-group-dependency": (Classification.HAS_MEMBERS, {"AD_PRIMARY_GROUP_REFERENCES"}),
            "nested-group": (Classification.HAS_MEMBERS, {"AD_DIRECT_MEMBERS", "AD_PARENT_GROUP", "AD_MEMBER_GROUPS",
                                                          "AD_NESTED_PRINCIPALS", "AD_NESTING_CYCLE"}),
            "unique-group": (Classification.HAS_MEMBERS, {"AD_DIRECT_MEMBERS"}),
            "protected-group": (Classification.PROTECTED, {"PROTECTED_GROUP", "AD_PARENT_GROUP"}),
        }
        for name, (classification, codes) in expected.items():
            with self.subTest(name):
                _, r = self._classify(name)
                self.assertIs(r.classification, classification, r.explain())
                self.assertLessEqual(codes, set(r.reason_codes))
                if classification is Classification.PROTECTED:
                    self.assertNotIn("NOT_PROTECTED", r.reason_codes)

    def test_normal_empty_group(self):
        _, r = self._classify("normal-empty-group")
        self.assertIs(r.classification, Classification.RETIREMENT_CANDIDATE, r.explain())
        self.assertIn("AD_GROUP_EMPTY", r.reason_codes)

    def test_live_ad_evidence_cannot_promote_before_p11(self):
        # The same report read from real AD (AD_VIA_AAP) is capped at PARTIAL by D19.
        e, r = self._classify("normal-empty-group", source=EvidenceSource.AD_VIA_AAP)
        self.assertTrue(e.unverified_live_behaviors)
        self.assertIs(r.classification, Classification.EVIDENCE_INCOMPLETE, r.explain())
        self.assertIn("PROTECTION_UNDETERMINED", r.reason_codes)
        self.assertTrue(r.ad_deletion_prohibited)

    def test_classification_cites_the_active_policy(self):
        store = new_store()
        try:
            v = version(CPOLICY, 1)
            store.record_policy_version(v)
            r = classify(world(), SUBJECT, store.active_policy_version().policy, NOW)
            self.assertEqual(r.policy_digest, v.policy_digest)
            self.assertIs(r.classification, Classification.RETIREMENT_CANDIDATE)
            self.assertEqual(canonical_json(CPOLICY.to_document()), v.document)
        finally:
            store.close()

    def test_reason_codes_fit_a_lifecycle_candidate(self):
        r = run(world())
        self.assertTrue(all(len(code) <= 100 for code in r.reason_codes))
        self.assertIn(ReasonCode.EXACT_MAPPING.value, r.reason_codes)

    def test_default_lifecycle_policy_documents(self):
        self.assertEqual(CandidatePolicy.from_json(CandidatePolicy(lifecycle=LifecyclePolicy()).canonical_json()).lifecycle,
                         LifecyclePolicy())


class TemplateAndFloorTests(unittest.TestCase):
    """D32/D34/D35: the git template is policy v1; floors and ceilings live in code."""

    TEMPLATE = Path(__file__).resolve().parents[1] / "config" / "candidate-policy.template.json"
    # D35: v1 is the original defaults, unchanged. A different digest means a default changed,
    # which needs an owner decision and a new policy version, never a silent edit.
    V1_DIGEST = "sha256:911a0f0afdd9ea8e6713c5c0a280a885c5be6b47545a1d8a3288d86932ae7307"

    def _template(self) -> dict:
        return json.loads(self.TEMPLATE.read_text(encoding="utf-8"))

    def test_template_is_policy_v1(self):
        policy = CandidatePolicy.from_json(self.TEMPLATE.read_text(encoding="utf-8"))
        self.assertEqual(policy, CandidatePolicy())
        self.assertEqual(policy.digest, self.V1_DIGEST)
        self.assertEqual(policy.lifecycle.min_usage_window, timedelta(days=90))
        self.assertEqual(policy.low_usage_max_sign_ins, 5)

    def test_template_carries_no_environment_values(self):
        doc = self._template()
        self.assertEqual(doc["adDirectorySourceIds"], [])
        self.assertEqual(doc["protected"], {"adObjectGuids": [], "adSids": [], "oktaGroupIds": []})

    def test_floors_and_ceilings_cannot_be_weakened_by_a_document(self):
        weakenings = {
            "retirement window below 30 days": ("usage", "retirementWindowDays", 29),
            "retirement threshold above 5": ("usage", "retirementMaxSignIns", 6),
            "low-usage threshold above 1000": ("usage", "lowUsageMaxSignIns", 1001),
            "review window below 7 days": ("usage", "reviewMinWindowDays", 6),
            "recent-login window below 1 day": ("usage", "recentLoginWindowDays", 0),
            "review freshness above 90 days": ("freshness", "reviewHours", 24 * 90 + 1),
            "approval freshness above 14 days": ("freshness", "approvalHours", 24 * 14 + 1),
            "execution freshness above 24 hours": ("freshness", "executionHours", 25),
            "clock skew above 15 minutes": ("freshness", "clockSkewMinutes", 16),
            "hold period below 7 days": ("lifecycle", "holdPeriodDays", 6),
            "approval TTL above 14 days": ("lifecycle", "approvalMaxTtlHours", 24 * 14 + 1),
        }
        for name, (section, key, value) in weakenings.items():
            with self.subTest(name):
                doc = self._template()
                doc[section][key] = value
                with self.assertRaises(InvalidRecord):
                    CandidatePolicy.from_document(doc)
        for kind in ("AD_GROUP_MEMBERS", "AD_NESTED_MEMBERSHIP", "OKTA_OTHER_APP_ASSIGNMENT", "OKTA_POLICY_REFERENCE"):
            with self.subTest(f"mandatory kind {kind} dropped"):
                doc = self._template()
                doc["requiredDependencyKinds"].remove(kind)
                with self.assertRaises(InvalidRecord):
                    CandidatePolicy.from_document(doc)
        with self.subTest("floors are not configurable"):
            doc = self._template()
            doc["floors"] = {"retirementWindowDays": 1}
            with self.assertRaises(InvalidRecord):
                CandidatePolicy.from_document(doc)


if __name__ == "__main__":
    unittest.main()
