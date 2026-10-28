"""Owner decisions after P10 (D121-D134), at the operator API over a seeded synthetic world.

- D128-D130: one AD approval never authorizes both quarantine and deletion; deletion is a
  separate governed stage. P10B modelled that stage (tests/test_lifecycle_ad_stages.py and
  tests/test_p10b_ad_stages_api.py); here, the quarantine approval still never authorizes a
  deletion, and the legacy single AD stage can be neither approved, planned, nor recorded.
- D131, D132: membership evidence must be complete and show no member for every
  remediation; complete AD dependency coverage is needed for AD operations only.
- D133: a blocked condition never yields a plan, and never reaches an adapter.

The AAP identity rules (D124, D125) are tested in tests/test_aap_discovery.py.
"""

import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from app.demo.synthetic_world import COLLECTOR
from app.domain.audit import AuditAction
from app.domain.lifecycle import LifecycleState
from app.domain.model import DependencyCoverage, DependencyKind
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS
from app.remediation import engine
from tests.api_fixtures import APPROVER_EXECUTOR, AUTOMATION, EXECUTOR, SECURITY, SECURITY_2, VIEWER, World
from tests.test_remediation_api import approve_ad, approve_okta, chained, dry_run, events, failed_gates

V = "/api/v1"
S = LifecycleState
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "remediation"


class DeletionStageTests(unittest.TestCase):
    """D128-D130, as P10B enforces them (D147, D148)."""

    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.candidate, self.approval = approve_ad(self.world)  # S01 in QUARANTINE_APPROVED
        self.executor = self.world.client(EXECUTOR)

    def test_the_quarantine_approval_authorizes_quarantine_and_never_deletion(self):
        quarantine = dry_run(self.world, self.executor, self.candidate, self.approval, "AD_GROUP_QUARANTINE")
        self.assertEqual(quarantine.json["remediation"]["outcome"], "SIMULATED")
        for subject in (EXECUTOR, APPROVER_EXECUTOR):
            with self.subTest(subject=subject):
                deletion = dry_run(self.world, self.world.client(subject), self.candidate, self.approval,
                                   "AD_GROUP_DELETE")
                self.assertEqual((deletion.status, deletion.code), (409, "REMEDIATION_BLOCKED"))
                self.assertEqual(failed_gates(deletion), {"VALID_APPROVAL", "LIFECYCLE_RULES"})
                self.assertTrue(any("not AD_DELETION" in p for p in deletion.json["error"]["problems"]))
        recorded = [dict(e.details)["operation"] for e in events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED)]
        self.assertEqual(recorded, ["AD_GROUP_QUARANTINE"])

    def test_the_legacy_single_ad_stage_can_be_neither_approved_planned_nor_recorded(self):
        s12 = self.world.candidate("S12")  # REVALIDATION_REQUIRED
        security = self.world.client(SECURITY)
        approved = security.post(f"{V}/candidates/{s12}/approvals", {
            "stage": "AD_RETIREMENT", "decision": "APPROVE", "reason": "synthetic attempt",
            "expectedEvidenceFingerprint": self.world.fingerprint(security, s12)})
        self.assertEqual((approved.status, approved.code), (409, "LEGACY_AD_RETIREMENT"))
        jobs = self.world.api.read.job_ids_for(self.candidate)
        planned = self.executor.post(f"{V}/candidates/{self.candidate}/execution-jobs", {
            "kind": "AD_RETIREMENT", "approvalId": self.approval,
            "expectedEvidenceFingerprint": self.world.fingerprint(self.executor, self.candidate)})
        self.assertEqual((planned.status, planned.code), (409, "LEGACY_AD_RETIREMENT"))
        self.assertNotIn("plannedActions", planned.json)
        self.assertEqual([e.action for e in chained(self.world, planned)], [AuditAction.GOVERNED_REQUEST_REFUSED])
        self.assertEqual(self.world.api.read.job_ids_for(self.candidate), jobs)
        recorded = self.executor.post(f"{V}/candidates/{s12}/transitions", {
            "target": "RETIREMENT_DRY_RUN", "reason": "synthetic attempt",
            "expectedEvidenceFingerprint": self.world.fingerprint(self.executor, s12)})
        self.assertEqual((recorded.status, recorded.code), (409, "LEGACY_AD_RETIREMENT"))
        self.assertIs(self.world.store.load_candidate(s12).state, S.REVALIDATION_REQUIRED)
        self.assertEqual([a.stage.value for a in self.world.store.approvals_for(s12)][-1], "AD_QUARANTINE")

    def test_operators_are_offered_each_stage_dry_run_and_never_the_legacy_step(self):
        detail = self.executor.get(f"{V}/candidates/{self.candidate}").json["allowedActions"]
        self.assertTrue(detail["planDryRun"])  # the quarantine dry run, in QUARANTINE_APPROVED
        s12 = self.world.candidate("S12")
        s12_actions = self.executor.get(f"{V}/candidates/{s12}").json["allowedActions"]
        self.assertFalse(s12_actions["planDryRun"])
        for actions in (detail, s12_actions):
            self.assertNotIn("RETIREMENT_DRY_RUN", {t["target"] for t in actions["transitions"]})
        s14 = self.world.candidate("S14")  # APPROVED: the Okta stage's dry run is still offered
        self.assertTrue(self.executor.get(f"{V}/candidates/{s14}").json["allowedActions"]["planDryRun"])

    def test_the_quarantine_approval_is_given_by_a_second_human(self):
        approvals = self.world.store.approvals_for(self.candidate)
        self.assertEqual([(a.stage.value, a.operator.id) for a in approvals][-1], ("AD_QUARANTINE", SECURITY_2))


class MembershipEvidenceTests(unittest.TestCase):
    """D131, D132."""

    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.executor = self.world.client(EXECUTOR)

    def test_unknown_membership_blocks_the_okta_unassignment(self):
        candidate, approval = approve_okta(self.world, membership=False)  # S07: no dependency check at all
        result = dry_run(self.world, self.executor, candidate, approval)
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertEqual(failed_gates(result), {"NO_DEPENDENCY_BLOCKER"})
        problems = " | ".join(result.json["error"]["problems"])
        for kind in ("AD_GROUP_MEMBERS", "AD_NESTED_MEMBERSHIP"):
            self.assertIn(f"no {kind} check", problems)

    def test_membership_evidence_alone_is_enough_for_the_okta_unassignment(self):
        candidate, approval = approve_okta(self.world)  # records only the two membership checks
        bundle = self.world.store.evidence_bundle(self.world.store.load_candidate(candidate))
        self.assertIsNot(bundle.dependency_coverage(DEFAULT_REQUIRED_DEPENDENCY_KINDS), DependencyCoverage.COMPLETE)
        result = dry_run(self.world, self.executor, candidate, approval)
        self.assertEqual(result.json["remediation"]["outcome"], "SIMULATED")  # D131

    def test_known_members_or_an_incomplete_membership_check_block_every_operation(self):
        cases = {}
        okta, okta_approval = approve_okta(self.world)
        ad, ad_approval = approve_ad(self.world)
        for candidate, approval, operation in ((okta, okta_approval, "OKTA_GROUP_UNASSIGN"),
                                               (ad, ad_approval, "AD_GROUP_QUARANTINE")):
            bundle = self.world.store.evidence_bundle(self.world.store.load_candidate(candidate))
            self.world.store.record_evidence(replace(bundle.ad_group, member_count=2, provenance=replace(
                bundle.ad_group.provenance, observed_at=self.world.clock())), actor=COLLECTOR)
            cases[operation] = dry_run(self.world, self.executor, candidate, approval, operation)
        for operation, result in cases.items():
            with self.subTest(operation=operation):
                self.assertEqual(result.code, "REMEDIATION_BLOCKED")
                self.assertIn("NO_DEPENDENCY_BLOCKER", failed_gates(result))
                self.assertTrue(any("2 direct member(s)" in p for p in result.json["error"]["problems"]))
        w = World()
        self.addCleanup(w.close)
        candidate, approval = approve_ad(w)
        bundle = w.store.evidence_bundle(w.store.load_candidate(candidate))
        nested = next(d for d in bundle.dependencies if d.kind is DependencyKind.AD_NESTED_MEMBERSHIP)
        w.store.record_evidence(replace(nested, provenance=replace(nested.provenance, observed_at=w.clock(),
                                                                   result_status=nested.provenance.result_status.PARTIAL)),
                                actor=COLLECTOR)
        result = dry_run(w, w.client(EXECUTOR), candidate, approval, "AD_GROUP_QUARANTINE")
        self.assertTrue(any("AD_NESTED_MEMBERSHIP check is PARTIAL" in p for p in result.json["error"]["problems"]))


class BlockedNeverPlansTests(unittest.TestCase):
    """D133."""

    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)

    def test_a_blocked_request_never_reaches_an_adapter_and_carries_no_plan(self):
        candidate, approval = approve_okta(self.world, membership=False)
        ad, ad_approval = approve_ad(self.world)
        executor = self.world.client(EXECUTOR)
        with mock.patch.object(engine, "adapter_for", side_effect=AssertionError("a blocked request reached an adapter")):
            blocked = [dry_run(self.world, executor, candidate, approval),
                       dry_run(self.world, executor, ad, ad_approval, "AD_GROUP_DELETE")]
        for result in blocked:
            with self.subTest(code=result.code):
                self.assertEqual((result.status, result.json["error"]["outcome"]), (409, "BLOCKED"))
                text = json.dumps(result.json)
                for planned in ("plannedChanges", "plannedActions", "launch", "extra_vars", "payload"):
                    self.assertNotIn(planned, text)
        self.assertEqual(events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED), [])

    def test_blocked_worker_results_plan_nothing(self):
        results = [json.loads(p.read_text(encoding="utf-8")) for p in FIXTURES.glob("*.result.json")]
        blocked = [r for r in results if r["outcome"] == "Blocked"]
        self.assertGreaterEqual(len(blocked), 6)
        self.assertEqual({len(r["plannedChanges"]) for r in blocked}, {0})

    def test_a_refused_lifecycle_dry_run_plans_nothing(self):
        executor = self.world.client(EXECUTOR)
        s07 = self.world.candidate("S07")  # NEEDS_REVIEW: nothing approved yet
        result = executor.post(f"{V}/candidates/{s07}/execution-jobs", {
            "kind": "OKTA_UNASSIGN", "approvalId": "apr_" + "0" * 32,
            "expectedEvidenceFingerprint": self.world.fingerprint(executor, s07)})
        self.assertEqual(result.status, 409)
        self.assertNotIn("plannedActions", result.json)
        self.assertEqual(self.world.api.read.job_ids_for(s07), [])


class ReadersTests(unittest.TestCase):
    def test_a_viewer_and_an_automation_user_see_the_refusal_reasons_but_cannot_act(self):
        world = World()
        self.addCleanup(world.close)
        candidate, approval = approve_ad(world)
        for subject in (VIEWER, AUTOMATION):
            result = dry_run(world, world.client(subject), candidate, approval, "AD_GROUP_DELETE")
            with self.subTest(subject=subject):
                self.assertEqual((result.status, result.code), (403, "FORBIDDEN"))


if __name__ == "__main__":
    unittest.main()
