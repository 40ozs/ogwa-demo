"""The explanation of a control decision, under the exact policy that produced it.

- Complete evidence: every condition satisfied, eligible only for a named human's approval.
- NM-C10 (ambiguous, conflicting, unreadable, missing): manual review forced by the evidence, and
  no missing input is ever shown as a satisfied (or a failed) condition.
- The same evidence judged by NM-LIFECYCLE-004 v1.1.0 and v1.2.0: a different outcome, each
  explanation naming its own version and stating the rule with that version's numbers.
- The explanation never disagrees with the decision: over DEMO-01's whole degradation matrix.

Synthetic data only.
"""

import ast
import unittest
from pathlib import Path
from unittest import mock

from app.api.services import PolicyInForce
from app.classification.assessment import Decision
from app.classification.explanation import (
    EVIDENCE_DECISIONS,
    NEXT_STEP_KEY,
    RULES,
    ConditionStatus,
    explain,
)
from app.classification.reasons import RETIREMENT_CANDIDATE_REQUIRES, RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION
from app.demo.null_meridian import policy as nm_policy
from app.domain.policy_release import DEMO_SOURCE, RECORDED_SOURCE, PolicyRef
from tests.api_fixtures import SECURITY, World
from tests.classification_fixtures import CPOLICY, world
from tests.test_evidence_assessment import _degradations, run

REPO_ROOT = Path(__file__).resolve().parents[1]
V = "/api/v1"
S = ConditionStatus
REF = PolicyRef.of(policy_digest=CPOLICY.digest, source=DEMO_SOURCE)


def explained(bundle, **kw):
    a, result = run(bundle, **kw)
    return explain(a, result, CPOLICY, REF), a, result


def statuses(explanation) -> dict[str, ConditionStatus]:
    return {c.key: c.status for c in explanation.conditions}


class RuleCatalogueTests(unittest.TestCase):
    def test_every_retirement_condition_of_the_classifier_is_explained(self):
        """The explanation covers exactly the classifier's own proofs, so it cannot omit one."""
        self.assertEqual({r.proof for r in RULES if not r.per_application}, set(RETIREMENT_CANDIDATE_REQUIRES))
        self.assertEqual({r.proof for r in RULES if r.per_application}, set(RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION))
        for rule in RULES:
            with self.subTest(rule=rule.key):
                self.assertFalse(rule.fails & rule.unknown, "a code means one thing")
                self.assertNotIn(rule.proof, rule.fails | rule.unknown)


class CompleteEvidenceTests(unittest.TestCase):
    def test_complete_evidence_satisfies_every_condition_and_is_only_eligible(self):
        e, a, result = explained(world())
        self.assertIs(e.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL)
        self.assertEqual(set(statuses(e).values()), {S.SATISFIED})
        self.assertEqual(len(e.conditions), len(RULES) + 1)
        self.assertFalse(e.review_forced_by_evidence)
        self.assertEqual(e.review_reasons, ())
        self.assertIn("not an approval", e.what_would_change[0])
        body = e.to_dict()
        self.assertEqual(body["isApproval"], False)
        self.assertEqual(body["policy"], REF.to_dict())
        self.assertEqual(body["conditionCounts"], {"SATISFIED": len(RULES) + 1, "NOT_SATISFIED": 0, "NOT_PROVEN": 0,
                                                   "NOT_APPLICABLE": 0})
        self.assertEqual(body["decision"]["code"], "ELIGIBLE_FOR_HUMAN_APPROVAL")

    def test_each_condition_states_its_rule_with_the_policy_s_numbers(self):
        e, _, _ = explained(world())
        rules = {c.key: c.rule for c in e.conditions}
        lc = CPOLICY.lifecycle
        self.assertIn(f"{lc.min_usage_window.days} days", rules["USAGE_WINDOW_COVERS_RETIREMENT"])
        self.assertIn(f"At most {lc.max_usage_events_for_candidate} sign-in", rules["USAGE_WITHIN_RETIREMENT_THRESHOLD"])
        self.assertIn(f"{int(lc.freshness.review.total_seconds() // 3600)} h", rules["EVIDENCE_CURRENT"])
        self.assertIn(f"{int(lc.freshness.approval.total_seconds() // 3600)} h", rules[NEXT_STEP_KEY])
        self.assertIn(str(len(lc.required_dependency_kinds)), rules["DEPENDENCY_COVERAGE_COMPLETE"])

    def test_inputs_that_mattered_are_named(self):
        e, a, _ = explained(world())
        keys = {i.key for i in a.items}
        by_key = {c.key: c for c in e.conditions}
        self.assertEqual(by_key["EXACT_MAPPING"].evidence, ("mapping", "ad-group"))
        self.assertIn("dependency:AD_GROUP_MEMBERS", by_key["AD_GROUP_EMPTY"].evidence)
        usage = next(k for k in keys if k.startswith("usage:"))
        self.assertEqual(by_key["USAGE_WITHIN_RETIREMENT_THRESHOLD"].evidence, (usage,))
        for c in e.conditions:
            with self.subTest(condition=c.key):
                self.assertTrue(c.evidence, "every condition names what it read")
                self.assertLessEqual(set(c.evidence), keys)

    def test_mismatched_inputs_are_refused(self):
        a, result = run(world())
        other = PolicyRef.of(policy_digest="sha256:" + "1" * 64, source=DEMO_SOURCE)
        with self.assertRaises(ValueError):
            explain(a, result, CPOLICY, other)
        with self.assertRaises(TypeError):
            explain(a, result, CPOLICY, None)
        with self.assertRaises(TypeError):
            explain(result, result, CPOLICY, REF)

    def test_no_classification_means_no_condition_is_proven(self):
        a = run(world())[0]
        bare = explain(type(a)(**{**a.__dict__, "classification": None}), None, CPOLICY, REF)
        self.assertTrue(all(c.status in (S.NOT_PROVEN, S.SATISFIED) for c in bare.conditions))
        self.assertTrue(all(c.status is S.NOT_PROVEN for c in bare.conditions if c.key != NEXT_STEP_KEY))


class ExplanationAgreesWithTheDecisionTests(unittest.TestCase):
    """Over every single weakened record (DEMO-01's matrix), the explanation never contradicts the decision."""

    def check(self, label, e, a, result):
        codes = {(r.code, r.subject) for r in result.reasons}
        for c in e.conditions:
            rule = next((r for r in RULES if r.key == c.key), None)
            if rule is None or c.status is S.NOT_APPLICABLE:
                continue
            recorded = {code for code, subject in codes if c.application_id is None or subject == c.application_id}
            if c.status is S.SATISFIED:
                self.assertIn(rule.proof, recorded, f"{label}: {c.key} satisfied without its proof")
            if c.status is S.NOT_SATISFIED:
                self.assertTrue(rule.fails & recorded, f"{label}: {c.key} failed without a contradicting fact")
        unmet = [c for c in e.conditions if c.status in (S.NOT_SATISFIED, S.NOT_PROVEN)]
        if e.decision is Decision.ELIGIBLE_FOR_HUMAN_APPROVAL:
            self.assertEqual(unmet, [], label)
        else:
            self.assertTrue(unmet or e.review_forced_by_evidence, f"{label}: refused with nothing to show why")
        self.assertEqual(e.review_forced_by_evidence, any(c.decision in EVIDENCE_DECISIONS for c in a.constraints))
        if a.needed:
            self.assertEqual(e.what_would_change, a.needed, label)

    def test_every_single_degradation(self):
        base = world()
        for label, change in _degradations():
            with self.subTest(label):
                e, a, result = explained(change(base))
                self.assertIsNot(e.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL, label)
                self.check(label, e, a, result)

    def test_missing_evidence_is_never_satisfied_or_failed(self):
        """Absent records leave their conditions NOT_PROVEN: neither proof nor contradiction."""
        from dataclasses import replace
        base = world()
        for field, conditions in (("mapping", ("EXACT_MAPPING", "NOT_PROTECTED", "AD_GROUP_EMPTY")),
                                  ("usage", ("USAGE_WITHIN_RETIREMENT_THRESHOLD", "USAGE_WINDOW_COVERS_RETIREMENT")),
                                  ("assignments", ("ASSIGNMENT_PRESENT",))):
            with self.subTest(field):
                bundle = replace(base, **{field: None if field == "mapping" else ()})
                e, _, _ = explained(bundle)
                got = statuses(e)
                for key in conditions:
                    self.assertIs(got[key], S.NOT_PROVEN, f"{field}: {key}")


class NullMeridianExplanationTests(unittest.TestCase):
    """Through the real API over the seeded store."""

    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")
        cls.client = cls.world.client(SECURITY)
        cls.v110, cls.v120 = cls.world.store.policy_versions()
        cls.r110, cls.r120 = nm_policy.releases()

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def detail(self, key):
        return self.client.get(f"{V}/candidates/{self.world.candidate(key)}").json

    def conditions(self, body):
        return {c["key"]: c for c in body["decisionExplanation"]["conditions"]}

    def test_every_surface_names_the_same_exact_policy_version(self):
        for scenario in self.world.summary.scenarios:
            if not scenario.candidate_id:
                continue
            with self.subTest(scenario.key):
                body = self.client.get(f"{V}/candidates/{scenario.candidate_id}").json
                e = body["decisionExplanation"]
                self.assertEqual(body["policy"]["name"], "NM-LIFECYCLE-004 v1.2.0")
                self.assertEqual(e["policy"]["name"], "NM-LIFECYCLE-004 v1.2.0")
                self.assertEqual(body["evidenceAssessment"]["policy"], e["policy"])
                self.assertEqual(e["policy"]["versionId"], self.v120.id)
                self.assertEqual(body["classification"]["policyDigest"], e["policy"]["policyDigest"])
                self.assertEqual(e["decision"]["code"], body["evidenceAssessment"]["decision"]["code"])

    def test_nm_c10_manual_review_is_forced_by_the_evidence(self):
        body = self.detail("NM-C10")
        e, c = body["decisionExplanation"], self.conditions(body)
        self.assertEqual(e["decision"]["code"], "CONFLICTING_EVIDENCE")
        self.assertTrue(e["manualReview"]["forcedByEvidence"])
        self.assertEqual([b["decision"] for b in e["manualReview"]["because"]],
                         ["CONFLICTING_EVIDENCE", "AMBIGUOUS_IDENTITY", "BLOCKED_ON_REQUIRED_SOURCE", "INSUFFICIENT_EVIDENCE"])
        self.assertEqual(c["EXACT_MAPPING"]["status"], "NOT_PROVEN")
        self.assertIn("not verified", c["EXACT_MAPPING"]["detail"])
        for key in ("NOT_PROTECTED", "AD_GROUP_EMPTY", "AD_NO_PARENT_GROUPS"):
            self.assertEqual(c[key]["status"], "NOT_PROVEN", key)
            self.assertIn("Not judged", c[key]["detail"], key)
        self.assertEqual(c["DEPENDENCY_COVERAGE_COMPLETE"]["status"], "NOT_PROVEN")
        self.assertEqual(c["SINGLE_OKTA_ASSIGNMENT"]["status"], "SATISFIED", "a complete check that found none")
        self.assertEqual(e["whatWouldChange"], body["evidenceAssessment"]["needed"])
        self.assertTrue(e["whatWouldChange"][0].startswith("Resolve the conflict"))

    def test_nm_c01_complete_evidence_is_refused_only_by_the_step_s_rules(self):
        body = self.detail("NM-C01")
        e, c = body["decisionExplanation"], self.conditions(body)
        self.assertEqual(e["decision"]["code"], "LIFECYCLE_RULES_NOT_MET")
        self.assertFalse(e["manualReview"]["forcedByEvidence"])
        self.assertEqual({k for k, v in c.items() if v["status"] != "SATISFIED"}, {NEXT_STEP_KEY})
        self.assertEqual(c[NEXT_STEP_KEY]["status"], "NOT_SATISFIED")
        self.assertIn("168 h", c[NEXT_STEP_KEY]["rule"])
        self.assertIn("stale for APPROVAL", c[NEXT_STEP_KEY]["detail"])

    def test_the_same_evidence_under_v1_1_0_gives_a_different_named_outcome(self):
        """Had 1.1.0 stayed in force, NM-C01 would be eligible: its 14-day approval window
        accepts the week-old evidence. Each explanation names its own version and numbers."""
        old = PolicyInForce(self.v110.policy, RECORDED_SOURCE, self.v110.id, self.v110.sequence, self.r110)
        with mock.patch("app.api.services.policy_in_force", return_value=old):
            under_old = self.detail("NM-C01")
        under_new = self.detail("NM-C01")
        e_old, e_new = under_old["decisionExplanation"], under_new["decisionExplanation"]
        self.assertEqual((e_old["policy"]["name"], e_new["policy"]["name"]),
                         ("NM-LIFECYCLE-004 v1.1.0", "NM-LIFECYCLE-004 v1.2.0"))
        self.assertEqual((e_old["decision"]["code"], e_new["decision"]["code"]),
                         ("ELIGIBLE_FOR_HUMAN_APPROVAL", "LIFECYCLE_RULES_NOT_MET"))
        step_old, step_new = self.conditions(under_old)[NEXT_STEP_KEY], self.conditions(under_new)[NEXT_STEP_KEY]
        self.assertEqual((step_old["status"], step_new["status"]), ("SATISFIED", "NOT_SATISFIED"))
        self.assertIn("336 h", step_old["rule"])
        self.assertIn("168 h", step_new["rule"])
        # The retirement conditions are the same in both versions, and so is their evidence.
        same = lambda body: {k: (v["status"], v["evidence"]) for k, v in self.conditions(body).items()  # noqa: E731
                             if k != NEXT_STEP_KEY}
        self.assertEqual(same(under_old), same(under_new))

    def test_nm_c08_after_the_unassignment(self):
        body = self.detail("NM-C08")
        c = self.conditions(body)
        self.assertEqual(body["decisionExplanation"]["decision"]["code"], "NO_APPROVAL_OPEN")
        app_rows = [v for v in body["decisionExplanation"]["conditions"] if v["key"] == "ASSIGNMENT_PRESENT"]
        self.assertEqual([v["status"] for v in app_rows], ["NOT_APPLICABLE"])
        self.assertEqual(c[NEXT_STEP_KEY]["status"], "NOT_APPLICABLE")
        self.assertIn("AD quarantine", c[NEXT_STEP_KEY]["detail"])
        # Nothing in the evidence is missing: the answer says what decides it instead of "nothing".
        self.assertEqual(body["evidenceAssessment"]["needed"], [])
        self.assertEqual(len(body["decisionExplanation"]["whatWouldChange"]), 1)
        self.assertTrue(body["decisionExplanation"]["whatWouldChange"][0].startswith("Not an evidence question."))
        self.assertIn("AD quarantine", body["decisionExplanation"]["whatWouldChange"][0])

    def test_reading_the_explanation_writes_nothing(self):
        head = self.world.store.audit_head()
        for key in ("NM-C01", "NM-C08", "NM-C10"):
            self.detail(key)
        self.assertEqual(self.world.store.audit_head(), head)


class ClassicWorldTests(unittest.TestCase):
    """The classic world keeps its unrecorded demo policy (D66), now explained too."""

    def test_unrecorded_policy_is_labelled_and_unnamed(self):
        w = World()
        try:
            client = w.client(SECURITY)
            for s in w.summary.scenarios:
                body = client.get(f"{V}/candidates/{s.candidate_id}").json
                with self.subTest(s.key):
                    self.assertEqual(body["policy"]["label"], "DEMO POLICY — UNRECORDED")
                    self.assertEqual(body["policyNotice"], "DEMO POLICY — UNRECORDED")
                    e = body["decisionExplanation"]
                    self.assertEqual((e["policy"]["source"], e["policy"]["name"], e["policy"]["recorded"]),
                                     ("UNRECORDED_SYNTHETIC_DEMO", None, False))
                    self.assertEqual(e["decision"]["code"], body["evidenceAssessment"]["decision"]["code"])
            seeded = client.get(f"{V}/candidates/{w.summary.scenarios[0].candidate_id}/decisions").json["items"]
            self.assertTrue(seeded and all(d["policy"] is None for d in seeded),
                            "decisions recorded without a reference say so; none is filled in")
        finally:
            w.close()


class PurityTests(unittest.TestCase):
    def test_the_explanation_module_reads_and_writes_nothing_external(self):
        tree = ast.parse((REPO_ROOT / "app" / "classification" / "explanation.py").read_text(encoding="utf-8"))
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        forbidden = ("app.store", "app.integrations", "app.correlation", "app.api", "app.remediation", "app.runtime",
                     "app.demo", "socket", "urllib", "http", "subprocess", "sqlite3", "os", "requests", "pathlib")
        for module in modules:
            with self.subTest(module=module):
                self.assertFalse(any(module == f or module.startswith(f + ".") for f in forbidden), module)


if __name__ == "__main__":
    unittest.main()
