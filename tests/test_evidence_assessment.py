"""OGWA-DEMO-01: evidence quality and the control decision it allows.

The invariant under test: missing, failed, partial, stale, ambiguous, or conflicting required
evidence never becomes permission to act. ``ELIGIBLE_FOR_HUMAN_APPROVAL`` (still not an
approval) needs the classifier's every retirement condition, no conflict, every required
source decision-grade, and the real lifecycle guard accepting a named human's approval.

Synthetic data only: the P07 classification fixtures, and the Null Meridian and classic
synthetic worlds through the real API.
"""

import ast
import random
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from app.api.services import DEMO_SOURCE, LifecycleService, PolicyInForce
from app.classification import Classification, classify
from app.classification.assessment import (
    DECISION_PRECEDENCE,
    Decision,
    EvidenceState,
    Freshness,
    IdentityState,
    PendingStep,
    Stance,
    assess,
)
from app.core.modes import ExecutionMode
from app.domain.approval import ApprovalStage
from app.domain.evidence import EvidenceKind, EvidenceSource, ResultStatus
from app.domain.lifecycle import LifecycleState, TransitionRequest
from app.domain.model import DependencyKind, MappingConfidence
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS
from tests.api_fixtures import SECURITY, World
from tests.classification_fixtures import (
    APP_ID_2,
    ASSIGNMENT_ID_2,
    CPOLICY,
    DIRECT_MEMBERS,
    NOW,
    SUBJECT,
    check,
    with_check,
    world,
)
from tests.domain_fixtures import (
    DAY,
    GROUP_ID,
    QUARANTINE_OUS,
    REVIEWER,
    T0,
    assignment,
    mapping,
    new_candidate,
    usage,
)
from tests.store_fixtures import memory_target

REPO_ROOT = Path(__file__).resolve().parents[1]
K = DependencyKind
S = EvidenceState
V = "/api/v1"
NEEDS_REVIEW = replace(new_candidate(T0), state=LifecycleState.NEEDS_REVIEW)
ELIGIBLE = Decision.ELIGIBLE_FOR_HUMAN_APPROVAL


def pending(candidate, bundle, now=NOW, policy=CPOLICY) -> PendingStep:
    """The API's own pending-step evaluation (the real guard), with the synthetic quarantine OUs."""
    host = SimpleNamespace(request=lambda **fields: TransitionRequest(**fields, quarantine_ous=QUARANTINE_OUS))
    return LifecycleService.pending_step(host, candidate, bundle, PolicyInForce(policy, DEMO_SOURCE, None), now)


def run(bundle, candidate=NEEDS_REVIEW, now=NOW, step: PendingStep | None = None):
    result = classify(bundle, SUBJECT, CPOLICY, now)
    return assess(candidate, bundle, result, CPOLICY, step or pending(candidate, bundle, now)), result


def aged(record, at):
    return replace(record, provenance=replace(record.provenance, observed_at=at))


def status(record, value: ResultStatus):
    return replace(record, provenance=replace(record.provenance, result_status=value))


def states(assessment) -> dict[str, EvidenceState]:
    return {i.key: i.state for i in assessment.items}


class CleanWorldTests(unittest.TestCase):
    """Confirmed identity and complete required evidence."""

    def test_confirmed_identity_and_complete_evidence_is_eligible_for_a_human_only(self):
        a, result = run(world())
        self.assertIs(result.classification, Classification.RETIREMENT_CANDIDATE)
        self.assertIs(a.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL)
        self.assertEqual(a.constraints, ())
        self.assertIs(a.identity.state, IdentityState.CONFIRMED)
        self.assertTrue(a.pending.open and a.pending.evaluated and a.pending.accepts, a.pending.problems)
        self.assertEqual(a.conflicts, ())
        self.assertEqual(a.needed, ())
        self.assertTrue(all(i.decision_grade for i in a.items if i.required))
        self.assertLessEqual({i.state for i in a.items}, {S.CONFIRMED, S.REPORTS_NONE})
        body = a.to_dict()
        self.assertEqual((body["isApproval"], body["decision"]["autoRemediationEligible"]), (False, False))
        self.assertTrue(body["decision"]["eligibleForHumanApproval"])
        self.assertIn("never an approval", " ".join(body["notes"]))

    def test_every_required_kind_and_record_is_an_item(self):
        a, _ = run(world())
        keys = set(states(a))
        self.assertLessEqual({f"dependency:{k.value}" for k in DEFAULT_REQUIRED_DEPENDENCY_KINDS}, keys)
        self.assertLessEqual({"okta-group", "mapping", "ad-group"}, keys)
        self.assertTrue(any(k.startswith("usage:") for k in keys) and any(k.startswith("assignment:") for k in keys))
        self.assertTrue(all(a.item(k).required for k in keys))
        # Only the AD stages read dependency coverage; only the Okta stage reads usage (the guards).
        self.assertEqual(a.item("dependency:AD_GROUP_MEMBERS").needed_for,
                         (ApprovalStage.AD_QUARANTINE, ApprovalStage.AD_DELETION))
        usage_key = next(k for k in keys if k.startswith("usage:"))
        self.assertEqual(a.item(usage_key).needed_for, (ApprovalStage.OKTA_UNASSIGN,))


class IdentityTests(unittest.TestCase):
    """Probable, ambiguous, absent, and unfinished identities stay distinct and never eligible."""

    CASES = [
        (MappingConfidence.NAME_ONLY, IdentityState.PROBABLE),
        (MappingConfidence.UNVERIFIED_STABLE_ID, IdentityState.PROBABLE),
        (MappingConfidence.AMBIGUOUS, IdentityState.AMBIGUOUS),
        (MappingConfidence.NOT_FOUND, IdentityState.NOT_FOUND),
    ]

    def test_non_exact_identities(self):
        details = set()
        for confidence, expected in self.CASES:
            with self.subTest(confidence=confidence):
                unresolved = confidence in (MappingConfidence.AMBIGUOUS, MappingConfidence.NOT_FOUND)
                b = world(mapping=mapping(T0, confidence=confidence))
                if unresolved:
                    b = replace(b, ad_group=None, dependencies=tuple(d for d in b.dependencies if d.subject_id == GROUP_ID))
                a, _ = run(b)
                self.assertIs(a.identity.state, expected)
                self.assertFalse(a.identity.decision_grade)
                self.assertIs(a.decision, Decision.AMBIGUOUS_IDENTITY, a.constraints)
                self.assertFalse(a.pending.accepts)
                self.assertTrue(any("not exact" in p for p in a.pending.problems), a.pending.problems)
                expected_state = S.REPORTS_NONE if confidence is MappingConfidence.NOT_FOUND else S.AMBIGUOUS
                self.assertIs(a.item("mapping").state, expected_state)
                self.assertIs(a.item("mapping").stance, Stance.UNKNOWN)
                details.add(a.identity.detail)
        self.assertEqual(len(details), len(self.CASES), "each identity state is worded differently")

    def test_missing_and_unfinished_mappings(self):
        a, _ = run(world(mapping=None, ad_group=None,
                         dependencies=tuple(d for d in world().dependencies if d.subject_id == GROUP_ID)))
        self.assertIs(a.identity.state, IdentityState.NOT_ESTABLISHED)
        self.assertIs(a.item("mapping").state, S.NOT_COLLECTED)
        self.assertIs(a.item("dependency:AD_GROUP_MEMBERS").state, S.NOT_COLLECTED)
        self.assertIn("until the AD group is established", a.item("dependency:AD_GROUP_MEMBERS").observation)
        for value in (ResultStatus.PARTIAL, ResultStatus.FAILED):
            a, _ = run(world(mapping=status(mapping(T0), value)))
            self.assertIs(a.identity.state, IdentityState.UNAVAILABLE)
            self.assertIsNot(a.decision, ELIGIBLE)

    def test_a_vanished_ad_group_is_not_an_established_identity(self):
        b = world()
        a, _ = run(replace(b, ad_group=replace(b.ad_group, exists=False, sid=None, distinguished_name=None,
                                               sam_account_name=None, member_count=None)))
        self.assertIs(a.item("ad-group").state, S.REPORTS_NONE)
        self.assertIn(Decision.AMBIGUOUS_IDENTITY, [c.decision for c in a.constraints])
        self.assertIsNot(a.decision, ELIGIBLE)


class DistinctStateTests(unittest.TestCase):
    """No evidence collected, source unavailable, says none, partial, attested, and confirmed stay apart."""

    def test_no_assignment_is_not_an_uncollected_assignment(self):
        absent, _ = run(world(assignments=(assignment(T0, present=False),)))
        missing, _ = run(world(assignments=()))
        key = next(k for k in states(absent) if k.startswith("assignment:"))
        self.assertIs(absent.item(key).state, S.REPORTS_NONE)
        self.assertIn("Not assigned", absent.item(key).observation)
        # With no assignment record the candidate has no application under review at all.
        self.assertNotIn(key, states(missing))
        self.assertIsNot(absent.decision, ELIGIBLE)
        self.assertIsNot(missing.decision, ELIGIBLE)

    def test_a_check_that_found_nothing_differs_from_one_never_run_or_failed(self):
        kind = K.AD_ACL_REFERENCE
        key = f"dependency:{kind.value}"
        base = world()
        found_none = run(base)[0].item(key)
        never = run(with_check(base, kind, None))[0].item(key)
        failed = run(with_check(base, kind, check(T0, kind, (), ResultStatus.FAILED)))[0].item(key)
        partial = run(with_check(base, kind, check(T0, kind, (), ResultStatus.PARTIAL)))[0].item(key)
        attested = run(with_check(base, kind, check(T0, kind, (), source=EvidenceSource.OPERATOR_ATTESTATION)))[0].item(key)
        self.assertEqual([found_none.state, never.state, failed.state, partial.state, attested.state],
                         [S.REPORTS_NONE, S.NOT_COLLECTED, S.SOURCE_UNAVAILABLE, S.PARTIAL, S.NOT_COUNTED_SOURCE])
        self.assertEqual(found_none.stance, Stance.SUPPORTS)
        for item in (never, failed, partial, attested):
            self.assertFalse(item.decision_grade)
            self.assertIsNot(item.stance, Stance.SUPPORTS)
        self.assertEqual(len({i.observation for i in (found_none, never, failed, partial, attested)}), 5)
        self.assertIsNone(never.record_id)
        self.assertEqual((failed.result_status, partial.result_status), ("FAILED", "PARTIAL"))

    def test_zero_use_differs_from_unobserved_and_unfinished_use(self):
        base = world()
        zero = run(base)[0]
        key = next(k for k in states(zero) if k.startswith("usage:"))
        self.assertIs(zero.item(key).state, S.REPORTS_NONE)
        self.assertIs(zero.item(key).stance, Stance.SUPPORTS)
        missing = run(replace(base, usage=()))[0].item(key)
        self.assertIs(missing.state, S.NOT_COLLECTED)
        self.assertIn("missing usage is not zero usage", missing.observation)
        partial = run(replace(base, usage=(status(base.usage[0], ResultStatus.PARTIAL),)))[0].item(key)
        self.assertIs(partial.state, S.PARTIAL)
        self.assertIs(partial.stance, Stance.UNKNOWN)
        self.assertIn("proves no absence of use", partial.observation)

    def test_required_source_unavailable_blocks_on_that_source(self):
        a, _ = run(with_check(world(), K.AD_NESTED_MEMBERSHIP, check(T0, K.AD_NESTED_MEMBERSHIP, (), ResultStatus.FAILED)))
        self.assertIs(a.decision, Decision.BLOCKED_ON_REQUIRED_SOURCE, a.constraints)
        self.assertIn("dependency:AD_NESTED_MEMBERSHIP", a.constraints[0].item_keys)
        self.assertTrue(any(n.startswith("Re-run AD nesting") for n in a.needed), a.needed)
        b = world()
        a, _ = run(replace(b, ad_group=status(b.ad_group, ResultStatus.FAILED)))
        self.assertIs(a.item("ad-group").state, S.SOURCE_UNAVAILABLE)
        self.assertIsNot(a.decision, ELIGIBLE)

    def test_partial_stale_and_future_dated_evidence_is_insufficient(self):
        b = world()
        for label, bundle in (
                ("partial ACL scan", with_check(b, K.AD_ACL_REFERENCE, check(T0, K.AD_ACL_REFERENCE, (), ResultStatus.PARTIAL))),
                ("stale application", replace(b, applications=(aged(b.applications[0], T0 - 40 * DAY),))),
                ("future-dated Okta group", replace(b, okta_group=aged(b.okta_group, NOW + 2 * DAY)))):
            with self.subTest(label):
                a, _ = run(bundle)
                self.assertIs(a.decision, Decision.INSUFFICIENT_EVIDENCE, a.constraints)
        a, _ = run(replace(b, applications=(aged(b.applications[0], T0 - 40 * DAY),)))
        self.assertIs(a.item(next(k for k in states(a) if k.startswith("application:"))).freshness, Freshness.STALE)
        a, _ = run(replace(b, okta_group=aged(b.okta_group, NOW + 2 * DAY)))
        self.assertIs(a.item("okta-group").freshness, Freshness.FUTURE_DATED)


class ConflictTests(unittest.TestCase):
    def test_ad_object_lists_members_but_the_membership_read_found_none(self):
        b = world()
        conflicted = replace(b, ad_group=replace(b.ad_group, member_count=2))
        # With an exact mapping the classifier takes the positive fact: members stop the candidate.
        a, result = run(conflicted)
        self.assertIs(result.classification, Classification.HAS_MEMBERS)
        self.assertEqual([c.code for c in a.conflicts], ["AD_MEMBERSHIP_DISAGREES"])
        self.assertIs(a.decision, Decision.NO_ACTION_BLOCKED)
        self.assertIn(Decision.CONFLICTING_EVIDENCE, [c.decision for c in a.constraints])
        self.assertEqual((a.item("ad-group").state, a.item("ad-group").base_state), (S.CONFLICTING, S.CONFIRMED))
        members = a.item("dependency:AD_GROUP_MEMBERS")
        self.assertEqual((members.state, members.base_state), (S.CONFLICTING, S.REPORTS_NONE))
        self.assertFalse(members.decision_grade)
        # With a merely probable mapping the classifier never looks at membership; the conflict
        # is still shown and leads the decision.
        a, result = run(replace(conflicted, mapping=mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID)))
        self.assertIs(result.classification, Classification.MAPPING_REQUIRED)
        self.assertIs(a.decision, Decision.CONFLICTING_EVIDENCE)
        self.assertTrue(any(n.startswith("Resolve the conflict") for n in a.needed))

    def test_the_reverse_disagreement_and_the_consistent_case(self):
        b = world()
        reverse = with_check(b, K.AD_GROUP_MEMBERS, check(T0, K.AD_GROUP_MEMBERS, (DIRECT_MEMBERS,)))
        self.assertEqual([c.code for c in run(reverse)[0].conflicts], ["AD_MEMBERSHIP_DISAGREES"])
        consistent = replace(reverse, ad_group=replace(b.ad_group, member_count=2))
        a, _ = run(consistent)
        self.assertEqual(a.conflicts, (), "the P05 converter's own shape is never a conflict")
        self.assertIs(a.decision, Decision.NO_ACTION_BLOCKED)
        # An unread member count conflicts with nothing, and is not decision-grade either.
        unknown = replace(b, ad_group=replace(b.ad_group, member_count=None))
        self.assertEqual(run(unknown)[0].conflicts, ())

    def test_other_assignment_check_contradicted_by_the_inventory(self):
        b = world()
        other = assignment(T0, id=ASSIGNMENT_ID_2, application_id=APP_ID_2)
        a, _ = run(replace(b, assignments=b.assignments + (other,)))
        self.assertEqual([c.code for c in a.conflicts], ["OTHER_ASSIGNMENT_DISAGREES"])
        self.assertIs(a.item(f"other-assignment:{APP_ID_2}").state, S.CONFLICTING)
        self.assertIsNot(a.decision, ELIGIBLE)

    def test_inconsistent_evidence_is_a_conflict(self):
        b = world()
        stray = check(T0, K.AAP_REFERENCE, subject_id=APP_ID_2.replace("oapp", "adg"))
        a, _ = run(replace(b, dependencies=b.dependencies + (replace(stray, id=stray.id[:-1] + "f"),)))
        self.assertIn("EVIDENCE_INCONSISTENT", [c.code for c in a.conflicts])
        self.assertIs(a.decision, Decision.CONFLICTING_EVIDENCE)


def _degradations():
    """(label, change) for every way a single required record can be missing or weakened."""
    b = world()
    out = []
    single = {"okta_group": b.okta_group, "mapping": b.mapping, "ad_group": b.ad_group}
    multi = {"applications": b.applications[0], "assignments": b.assignments[0], "usage": b.usage[0]}

    def weaken(name, record, value):
        if name in single:
            return lambda x: replace(x, **{name: value(record)})
        return lambda x: replace(x, **{name: (value(record),)})

    def at(when):
        # A usage observation's window ends when it was observed; move both together.
        return lambda r: usage(when) if r.KIND is EvidenceKind.USAGE else aged(r, when)

    for name, record in {**single, **multi}.items():
        out.append((f"{name}: missing", (lambda x, n=name: replace(x, **{n: None if n in single else ()}))))
        for label, value in (("PARTIAL", lambda r: status(r, ResultStatus.PARTIAL)),
                             ("FAILED", lambda r: status(r, ResultStatus.FAILED)),
                             ("stale", at(T0 - 40 * DAY)),
                             ("future-dated", at(NOW + 2 * DAY))):
            out.append((f"{name}: {label}", weaken(name, record, value)))
    for confidence in (MappingConfidence.NAME_ONLY, MappingConfidence.UNVERIFIED_STABLE_ID):
        out.append((f"mapping: {confidence.value}", lambda x, c=confidence: replace(x, mapping=mapping(T0, confidence=c))))
    out.append(("ad_group: member count unknown", lambda x: replace(x, ad_group=replace(x.ad_group, member_count=None))))
    out.append(("assignment: absent", lambda x: replace(x, assignments=(assignment(T0, present=False),))))
    for kind in sorted(DEFAULT_REQUIRED_DEPENDENCY_KINDS):
        out.append((f"{kind.value}: never checked", lambda x, k=kind: with_check(x, k, None)))
        for label, record in (("PARTIAL", check(T0, kind, (), ResultStatus.PARTIAL)),
                              ("FAILED", check(T0, kind, (), ResultStatus.FAILED)),
                              ("attestation only", check(T0, kind, (), source=EvidenceSource.OPERATOR_ATTESTATION)),
                              ("stale", check(T0 - 40 * DAY, kind)),
                              ("future-dated", check(NOW + 2 * DAY, kind))):
            out.append((f"{kind.value}: {label}", lambda x, k=kind, r=record: with_check(x, k, r)))
    return out


class NoEligibilityFromMissingDataTests(unittest.TestCase):
    """The central invariant, over every single weakened record and random combinations."""

    def assert_not_eligible(self, a, result, label):
        self.assertIsNot(a.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL, label)
        self.assertTrue(a.constraints, label)
        body = a.to_dict()
        self.assertEqual((body["decision"]["eligibleForHumanApproval"], body["decision"]["autoRemediationEligible"],
                          body["isApproval"]), (False, False, False), label)

    def test_every_single_degradation_is_refused(self):
        cases = _degradations()
        self.assertGreater(len(cases), 60)
        for label, change in cases:
            with self.subTest(label):
                bundle = change(world())
                a, result = run(bundle)
                self.assert_not_eligible(a, result, label)

    def test_even_if_the_guard_accepted_weak_evidence_is_never_eligible(self):
        """Defense in depth: the assessment's own rules hold even against a guard that says yes."""
        yes = PendingStep(ApprovalStage.OKTA_UNASSIGN, open=True, evaluated=True, accepts=True)
        for label, change in _degradations():
            with self.subTest(label):
                a, result = run(change(world()), step=yes)
                self.assert_not_eligible(a, result, label)

    def test_random_combinations(self):
        cases = _degradations()
        rng = random.Random(20261014)
        for n in range(300):
            picked = rng.sample(cases, rng.randint(1, 3))
            bundle = world()
            try:
                for _, change in picked:
                    bundle = change(bundle)
                a, result = run(bundle)
            except Exception as exc:  # a combination that cannot be a bundle at all proves nothing either way
                self.assertNotIsInstance(exc, AssertionError)
                continue
            with self.subTest(n=n, picked=[p for p, _ in picked]):
                self.assert_not_eligible(a, result, str([p for p, _ in picked]))

    def test_eligible_implies_the_classifier_and_the_guard_agree(self):
        a, result = run(world())
        self.assertIs(a.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL)
        self.assertIs(result.classification, Classification.RETIREMENT_CANDIDATE)
        self.assertTrue(a.pending.accepts)
        refused = PendingStep(ApprovalStage.OKTA_UNASSIGN, open=True, evaluated=True, accepts=False,
                              problems=("synthetic refusal",))
        self.assertIs(run(world(), step=refused)[0].decision, Decision.LIFECYCLE_RULES_NOT_MET)
        closed = PendingStep(ApprovalStage.OKTA_UNASSIGN, open=False, evaluated=False, accepts=False)
        self.assertIs(run(world(), step=closed)[0].decision, Decision.NO_APPROVAL_OPEN)

    def test_after_the_unassignment_only_the_expected_absence_is_waived(self):
        b = replace(world(), assignments=(assignment(T0, present=False),))
        unassigned = replace(NEEDS_REVIEW, state=LifecycleState.REVALIDATION_REQUIRED, hold_until=T0 - DAY,
                             okta_unassign_approver=REVIEWER)
        yes = PendingStep(ApprovalStage.AD_QUARANTINE, open=True, evaluated=True, accepts=True)
        a, _ = run(b, candidate=unassigned, step=yes)
        self.assertIs(a.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL, a.constraints)
        key = next(k for k in states(a) if k.startswith("assignment:"))
        self.assertIs(a.item(key).stance, Stance.SUPPORTS, "after the unassignment, absence is what was expected")
        # A remaining review hold (some use) or an unproven retirement condition is not waived.
        for label, bundle, expected in (
                ("low use", replace(b, usage=(replace(b.usage[0], event_count=3, distinct_user_count=1,
                                                      last_activity_at=T0 - DAY),)), Decision.MANUAL_REVIEW_REQUIRED),
                ("parents unproven", with_check(b, K.AD_NESTED_MEMBERSHIP, None), Decision.INSUFFICIENT_EVIDENCE)):
            with self.subTest(label):
                a, _ = run(bundle, candidate=unassigned, step=yes)
                self.assertIsNot(a.decision, Decision.ELIGIBLE_FOR_HUMAN_APPROVAL)
                self.assertIn(expected, [c.decision for c in a.constraints])

    def test_no_classification_means_nothing_is_judged(self):
        b = world()
        a = assess(NEEDS_REVIEW, b, None, None, pending(NEEDS_REVIEW, b))
        self.assertIs(a.decision, Decision.INSUFFICIENT_EVIDENCE)
        self.assertTrue(all(i.freshness is Freshness.NOT_ASSESSED for i in a.items))
        self.assertTrue(all(not i.decision_grade for i in a.items))

    def test_terminal_and_precedence(self):
        protected = replace(NEEDS_REVIEW, state=LifecycleState.PROTECTED)
        a, _ = run(world(), candidate=protected, step=PendingStep(None, False, False, False))
        self.assertIs(a.decision, Decision.TERMINAL)
        self.assertEqual(DECISION_PRECEDENCE[0], Decision.TERMINAL)
        self.assertEqual(DECISION_PRECEDENCE[-1], Decision.ELIGIBLE_FOR_HUMAN_APPROVAL)
        order = [c.decision for c in run(replace(world(), ad_group=None))[0].constraints]
        self.assertEqual(order, sorted(order, key=DECISION_PRECEDENCE.index))


class UnknownMemberCountRegressionTests(unittest.TestCase):
    """Found by the degradation matrix: the classifier read an unknown AD member count as zero
    (``member_count or 0``) and proved AD_GROUP_EMPTY, so missing data produced a
    RETIREMENT_CANDIDATE and an eligible assessment. Unknown is now never zero."""

    def test_an_unknown_member_count_proves_nothing(self):
        b = world()
        unknown = replace(b, ad_group=replace(b.ad_group, member_count=None))
        a, result = run(unknown)
        self.assertIs(result.classification, Classification.EVIDENCE_INCOMPLETE)
        self.assertNotIn("AD_GROUP_EMPTY", result.reason_codes)
        self.assertIn("AD_MEMBERSHIP_UNKNOWN", result.reason_codes)
        self.assertTrue(result.ad_deletion_prohibited)
        self.assertIs(a.decision, Decision.INSUFFICIENT_EVIDENCE)
        self.assertIn("member count unknown", a.item("ad-group").observation)
        # A known zero still proves it.
        self.assertIn("AD_GROUP_EMPTY", run(b)[1].reason_codes)


class NullMeridianScenarioTests(unittest.TestCase):
    """NM-C10, the reviewer-facing scenario, through the real API over the seeded store."""

    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")
        cls.client = cls.world.client(SECURITY)
        cls.c10 = cls.world.candidate("NM-C10")

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def detail(self, key):
        return self.client.get(f"{V}/candidates/{self.world.candidate(key)}").json

    def test_nm_c10_shows_every_state_and_refuses_every_decision(self):
        body = self.detail("NM-C10")
        a = body["evidenceAssessment"]
        self.assertEqual(body["candidate"]["state"], "NEEDS_REVIEW")
        self.assertEqual(body["classification"]["classification"], "MAPPING_REQUIRED")
        self.assertEqual(a["decision"]["code"], "CONFLICTING_EVIDENCE")
        self.assertEqual([c["decision"] for c in a["constraints"]][:4],
                         ["CONFLICTING_EVIDENCE", "AMBIGUOUS_IDENTITY", "BLOCKED_ON_REQUIRED_SOURCE", "INSUFFICIENT_EVIDENCE"])
        self.assertEqual(a["identity"]["state"], "PROBABLE")
        self.assertEqual(a["identity"]["confidence"], "UNVERIFIED_STABLE_ID")
        by_key = {i["key"]: i["state"] for i in a["items"]}
        expected = {
            "okta-group": "CONFIRMED", "mapping": "AMBIGUOUS", "ad-group": "CONFLICTING",
            "dependency:AD_GROUP_MEMBERS": "CONFLICTING", "dependency:AD_NESTED_MEMBERSHIP": "SOURCE_UNAVAILABLE",
            "dependency:AD_ACL_REFERENCE": "PARTIAL", "dependency:GPO_REFERENCE": "NOT_COLLECTED",
            "dependency:AAP_REFERENCE": "NOT_COLLECTED", "dependency:APPLICATION_CONFIGURATION": "NOT_COLLECTED",
            "dependency:OKTA_OTHER_APP_ASSIGNMENT": "REPORTS_NONE", "dependency:OKTA_POLICY_REFERENCE": "REPORTS_NONE",
        }
        self.assertEqual({k: by_key[k] for k in expected}, expected)
        app_keys = [k for k in by_key if k.split(":")[0] in ("application", "assignment", "usage")]
        self.assertEqual(sorted(by_key[k] for k in app_keys), ["CONFIRMED", "CONFIRMED", "REPORTS_NONE"])
        self.assertEqual(a["pendingStep"], {**a["pendingStep"], "stage": "OKTA_UNASSIGN", "open": True,
                                            "evaluated": True, "accepts": False})
        self.assertTrue(any("not exact" in p for p in a["pendingStep"]["problems"]))
        self.assertEqual((a["isApproval"], a["decision"]["autoRemediationEligible"]), (False, False))
        self.assertFalse(body["allowedActions"]["planDryRun"])

    def test_the_server_refuses_the_approval_and_records_nothing(self):
        approvals = self.world.store.connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        fingerprint = self.detail("NM-C10")["evidenceFingerprint"]
        result = self.client.post(f"{V}/candidates/{self.c10}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "synthetic attempt on conflicting evidence",
            "expectedEvidenceFingerprint": fingerprint})
        self.assertEqual((result.status, result.code), (409, "EVIDENCE_RULES_NOT_MET"), result.json)
        self.assertEqual(self.world.store.connection.execute("SELECT count(*) FROM approvals").fetchone()[0], approvals)
        self.assertIs(self.world.store.load_candidate(self.c10).state, LifecycleState.NEEDS_REVIEW)

    def test_reading_the_assessment_writes_nothing(self):
        head = self.world.store.audit_head()
        approvals = self.world.store.connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        for key in ("NM-C01", "NM-C10", "NM-C08", "NM-C09"):
            self.detail(key)
        self.assertEqual(self.world.store.audit_head(), head)
        self.assertEqual(self.world.store.connection.execute("SELECT count(*) FROM approvals").fetchone()[0], approvals)

    def test_eligibility_agrees_with_the_real_approval_path(self):
        world = World(dataset="null-meridian")
        try:
            client = world.client(SECURITY)
            cid = world.candidate("NM-C01")
            stale = client.get(f"{V}/candidates/{cid}").json
            self.assertEqual(stale["evidenceAssessment"]["decision"]["code"], "LIFECYCLE_RULES_NOT_MET")
            request = {"stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "synthetic review",
                       "expectedEvidenceFingerprint": stale["evidenceFingerprint"]}
            self.assertEqual(client.post(f"{V}/candidates/{cid}/approvals", request).code, "EVIDENCE_RULES_NOT_MET")
            world.refresh_evidence(cid)
            fresh = client.get(f"{V}/candidates/{cid}").json
            self.assertEqual(fresh["evidenceAssessment"]["decision"]["code"], "ELIGIBLE_FOR_HUMAN_APPROVAL")
            result = client.post(f"{V}/candidates/{cid}/approvals",
                                 {**request, "expectedEvidenceFingerprint": fresh["evidenceFingerprint"]})
            self.assertEqual(result.status, 201, result.json)
        finally:
            world.close()

    def test_the_scenario_is_deterministic(self):
        from app.demo.null_meridian.world import create_null_meridian_store

        def assessment():
            store, summary = create_null_meridian_store(memory_target())
            try:
                cid = next(s.candidate_id for s in summary.scenarios if s.key == "NM-C10")
                service = LifecycleService(store, clock=lambda: summary.as_of + 2 * DAY, mode=ExecutionMode.LOCAL_SYNTHETIC)
                candidate = store.load_candidate(cid)
                return service.classify_and_assess(candidate, store.evidence_bundle(candidate))[1], summary.audit_head
            finally:
                store.close()

        first, second = assessment(), assessment()
        self.assertEqual(first, second)
        self.assertEqual(first[0]["decision"]["code"], "CONFLICTING_EVIDENCE")


class ClassicWorldTests(unittest.TestCase):
    def test_every_classic_scenario_is_assessed_and_none_is_eligible_on_weak_evidence(self):
        world = World()
        try:
            client = world.client(SECURITY)
            seen = {}
            for s in world.summary.scenarios:
                a = client.get(f"{V}/candidates/{s.candidate_id}").json["evidenceAssessment"]
                seen[s.key] = a["decision"]["code"]
                weak = [i["key"] for i in a["items"] if i["required"] and not i["decisionGrade"]]
                if a["decision"]["code"] == "ELIGIBLE_FOR_HUMAN_APPROVAL":
                    self.assertEqual(weak, [], s.key)
                    self.assertTrue(a["pendingStep"]["accepts"], s.key)
            self.assertEqual(seen["S07"], "INSUFFICIENT_EVIDENCE")   # coverage UNKNOWN
            self.assertEqual(seen["S08"], "AMBIGUOUS_IDENTITY")      # name-only
            self.assertEqual(seen["S06"], "TERMINAL")                # protected
            self.assertEqual(seen["S03"], "NO_ACTION_BLOCKED")       # shared assignment
            self.assertEqual(seen["S13"], "AMBIGUOUS_IDENTITY")      # AD lookup timed out: no mapping
            self.assertEqual(seen["S12"], "INSUFFICIENT_EVIDENCE")   # partial ACL coverage at the AD stage
        finally:
            world.close()


class PurityTests(unittest.TestCase):
    def test_the_assessment_module_reads_and_writes_nothing_external(self):
        tree = ast.parse((REPO_ROOT / "app" / "classification" / "assessment.py").read_text(encoding="utf-8"))
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        forbidden = ("app.store", "app.integrations", "app.correlation", "app.api", "app.remediation", "app.runtime",
                     "socket", "urllib", "http", "subprocess", "sqlite3", "os", "requests")
        for module in modules:
            with self.subTest(module=module):
                self.assertFalse(any(module == f or module.startswith(f + ".") for f in forbidden), module)


if __name__ == "__main__":
    unittest.main()
