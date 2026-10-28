"""OGWA-DEMO-04: the policy lane (OGWA-DEMO-02) and the remediation lane (OGWA-DEMO-03), integrated.

Proves, over the real seed, store, API, and drill:

1. a remediation (governed dry run or synthetic drill) names the exact policy version, decision,
   and approval that authorized it, by their recorded identifiers;
2. a recorded remediation keeps its own policy version after a newer one is recorded, and an
   approval judged by a superseded version authorizes nothing under the new one (refused before
   any fixture exists, at the start and before a retry; refused in the store's write too);
3. the integrated Null Meridian seed is chronological: every decision and approval records the
   release in force on its own date, and a seed in the wrong order is caught;
4. NM-C11 is fresh enough for the drill at the demo's clock, and stops being drillable once its
   evidence leaves the 24-hour EXECUTION window;
5. NM-C10 cannot enter a drill by any route: no approval, no borrowed approval, and a forged
   approval is blocked by the gates before a provider fixture exists;
6. POST_ACTION_VERIFIED cannot exist without the post-action predicate;
7. the committed audit sample is exactly what the application serializes, and is sanitized;
8. dry run and synthetic execution are worded and toned so they can never be confused.

Synthetic data only; nothing external is contacted (``no_live_system``).
"""

import json
import re
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.api.authorization import ACCEPTED_BINDINGS, Binding, binding
from app.api.services import policy_in_force
from app.core.modes import ExecutionMode
from app.demo.null_meridian import audit_sample
from app.demo.null_meridian import policy as nm_policy
from app.demo.null_meridian.walkthrough import DISCLOSURES, PARTS
from app.demo.null_meridian.world import AS_OF, RECOLLECTED, create_null_meridian_store, policy_chronology_problems
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalRecord, ApprovalStage
from app.domain.errors import InvalidRecord
from app.domain.ids import IdKind, new_id
from app.domain.policy import evidence_fingerprint
from app.domain.policy_release import POLICY_DETAIL_KEYS, PolicyRef
from app.domain.remediation import RemediationOperation
from app.domain.remediation_execution import (
    STATE_LABELS,
    ExecutionState,
    ExecutionStep,
    ExecutionTrace,
    Reason,
    TargetObservation,
)
from app.remediation import drill as drill_module
from app.remediation.drill import MODE_BANNERS, DrillMode, run_drill
from app.store.errors import StoreConflict, StoreError
from tests.api_fixtures import EXECUTOR, SECURITY, VIEWER, World
from tests.store_fixtures import memory_target, table_dump
from tests.test_demo_mode import no_live_system
from tests.test_policy_release import newer_release
from tests.test_remediation_drill_api import post_drill

V = "/api/v1"
X = ExecutionState
O = TargetObservation
REPO = Path(__file__).resolve().parents[1]


def nm_world() -> World:
    return World(dataset="null-meridian")


def approval_of(w: World, key: str) -> str | None:
    items = w.client(VIEWER).get(f"{V}/candidates/{w.candidate(key)}/approvals").json["items"]
    return items[0]["id"] if items else None


def governed_dry_run(w: World, client, candidate: str, approval: str):
    return client.post(f"{V}/candidates/{candidate}/remediation-dry-runs", {
        "operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": w.store.load_candidate(candidate).assignment_ids[0]},
        "approvalId": approval, "expectedEvidenceFingerprint": w.fingerprint(client, candidate)})


def record_newer_version(w: World):
    newer = newer_release()
    w.store.record_policy_version(nm_policy.policy_version(newer, id=new_id(IdKind.POLICY_VERSION),
                                                           previous=w.store.active_policy_version()))
    return newer


# --- 1. the chain names the exact policy, decision, and approval -------------------------------------


class PolicyToRemediationLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = nm_world()
        cls.candidate = cls.w.candidate("NM-C11")
        cls.approval = approval_of(cls.w, "NM-C11")
        with no_live_system():
            cls.result = post_drill(cls.w, cls.w.client(EXECUTOR), cls.candidate, cls.approval,
                                 mode="SYNTHETIC_EXECUTION", scenario="TIMEOUT_NOT_APPLIED")

    @classmethod
    def tearDownClass(cls):
        cls.w.close()

    def test_a_drill_names_the_policy_version_decision_and_approval_that_authorized_it(self):
        self.assertEqual(self.result.status, 200, self.result.json)
        chain, auth = self.result.json["chain"], self.result.json["authorization"]
        store = self.w.store
        in_force = policy_in_force(store)
        self.assertEqual((chain["policyId"], chain["policyVersion"], chain["policyVersionId"], chain["policySequence"],
                          chain["policyDigest"], chain["releaseDigest"]),
                         ("NM-LIFECYCLE-004", "1.2.0", in_force.version_id, 1, in_force.policy.digest,
                          in_force.release.release_digest))
        decision = next(d for d in store.decisions(self.candidate) if d.approval_id == self.approval)
        self.assertEqual((chain["decisionId"], chain["approvalId"]), (decision.id, self.approval))
        # Each link's audit sequence is the event that recorded it, with that event's own policy reference.
        events = {e.sequence: e for e in store.audit_events()}
        self.assertEqual(events[chain["decisionAuditSequence"]].after_ref, f"decision:{decision.id}")
        self.assertEqual(events[chain["approvalAuditSequence"]].after_ref, f"approval:{self.approval}")
        for link in ("decision", "approval"):
            recorded = PolicyRef.from_audit_details(events[auth[link]["auditSequence"]].details)
            self.assertEqual((recorded.policy_id, recorded.version, recorded.version_id),
                             ("NM-LIFECYCLE-004", "1.2.0", in_force.version_id), link)
            self.assertEqual((auth[link]["policy"]["version"], auth[link]["binding"]), ("1.2.0", "IN_FORCE"), link)
        self.assertEqual(auth["decision"]["to"], "APPROVED")
        self.assertTrue(auth["authorized"])
        self.assertEqual(auth["problems"], [])

    def test_the_chain_carries_mode_attempts_outcomes_verification_and_final_state(self):
        chain, drill = self.result.json["chain"], self.result.json["drill"]
        self.assertEqual(chain["operationId"], drill["operationId"])
        self.assertTrue(re.fullmatch(r"rop_[0-9a-f]{32}", chain["operationId"]))
        self.assertEqual((chain["executionMode"], chain["scenario"], chain["submissions"]),
                         ("SYNTHETIC_EXECUTION", "TIMEOUT_NOT_APPLIED", 2))
        self.assertEqual([(a["attempt"], a["answer"], a["verification"], a["next"]) for a in chain["attempts"]],
                         [(1, "TIMEOUT", "NOT_APPLIED", "RETRY_PERMITTED"), (2, "APPLIED", None, "EXECUTED")])
        self.assertEqual((chain["postActionVerification"], chain["finalState"], chain["finalLabel"], chain["succeeded"],
                          chain["recorded"]), ("CONFIRMED", "POST_ACTION_VERIFIED", "POST-ACTION VERIFIED", True, False))
        # Every attempt of the run carried the chain's operation id.
        self.assertTrue(all(chain["operationId"] in s["detail"] for s in drill["steps"]
                            if s["state"] == "EXECUTION_REQUESTED"))

    def test_a_recorded_dry_run_records_its_policy_and_shares_the_drills_operation_id(self):
        w = nm_world()
        try:
            executor = w.client(EXECUTOR)
            candidate, approval = w.candidate("NM-C11"), approval_of(w, "NM-C11")
            drill = post_drill(w, executor, candidate, approval).json
            result = governed_dry_run(w, executor, candidate, approval)
            self.assertEqual(result.status, 201, result.json)
            event = w.store.remediation_dry_runs(candidate)[-1]
            recorded = PolicyRef.from_audit_details(event.details)
            self.assertEqual(recorded, policy_in_force(w.store).ref, "the event records the policy its gates ran under")
            self.assertEqual({k for k, _ in event.details} & set(POLICY_DETAIL_KEYS), set(POLICY_DETAIL_KEYS))
            listed = w.client(VIEWER).get(f"{V}/candidates/{candidate}/remediation-dry-runs").json["items"][-1]
            self.assertEqual((listed["policy"]["version"], listed["chain"]["policyVersion"]), ("1.2.0", "1.2.0"))
            self.assertEqual(listed["chain"]["operationId"], drill["chain"]["operationId"])
            self.assertEqual(listed["chain"]["decisionId"], drill["chain"]["decisionId"])
            self.assertEqual(result.json["record"]["chain"], listed["chain"])
            w.store.verify_integrity()
        finally:
            w.close()


# --- 2. history keeps its version; a superseded approval authorizes nothing --------------------------


class HistoricalBindingTests(unittest.TestCase):
    def test_a_recorded_remediation_never_points_at_a_newer_policy_version(self):
        w = nm_world()
        try:
            executor = w.client(EXECUTOR)
            candidate, approval = w.candidate("NM-C11"), approval_of(w, "NM-C11")
            self.assertEqual(governed_dry_run(w, executor, candidate, approval).status, 201)
            before = w.client(VIEWER).get(f"{V}/candidates/{candidate}/remediation-dry-runs").json["items"]
            record_newer_version(w)
            self.assertEqual(policy_in_force(w.store).version_sequence, 2, "1.3.0 is in force now")
            after = w.client(VIEWER).get(f"{V}/candidates/{candidate}/remediation-dry-runs").json["items"]
            self.assertEqual(after, before, "a newer version changes nothing a recorded dry run shows")
            self.assertEqual((after[-1]["policy"]["version"], after[-1]["chain"]["policySequence"]), ("1.2.0", 1))
            decisions = w.client(VIEWER).get(f"{V}/candidates/{candidate}/decisions").json["items"]
            self.assertEqual([d["policy"]["version"] for d in decisions], ["1.1.0", "1.1.0", "1.2.0"])
        finally:
            w.close()

    def test_an_approval_judged_by_a_superseded_version_authorizes_no_drill_and_builds_nothing(self):
        w = nm_world()
        try:
            candidate, approval = w.candidate("NM-C11"), approval_of(w, "NM-C11")
            record_newer_version(w)
            before = table_dump(w.store)
            built = []
            original = drill_module.SyntheticProviderFixture.from_evidence
            with mock.patch.object(drill_module.SyntheticProviderFixture, "from_evidence",
                                   side_effect=lambda *a, **k: built.append(1) or original(*a, **k)):
                for mode, scenario in (("DRY_RUN", None), ("SYNTHETIC_EXECUTION", "TIMEOUT_NOT_APPLIED")):
                    result = post_drill(w, w.client(EXECUTOR), candidate, approval, mode=mode, scenario=scenario)
                    self.assertEqual((result.status, result.code), (409, "APPROVAL_POLICY_NOT_IN_FORCE"), result.json)
                    self.assertTrue(any("judged by an earlier policy version" in p.lower() or "superseded" in p.lower()
                                        for p in result.json["error"]["problems"]), result.json)
            self.assertEqual(built, [], "no provider fixture was built")
            self.assertEqual(table_dump(w.store), before, "a refused drill records nothing")
            # The governed dry run is refused the same way, and its refusal is chained (a governed route).
            refused = governed_dry_run(w, w.client(EXECUTOR), candidate, approval)
            self.assertEqual((refused.status, refused.code), (409, "APPROVAL_POLICY_NOT_IN_FORCE"))
            self.assertEqual(w.store.remediation_dry_runs(candidate), ())
            self.assertEqual(w.store.audit_events()[-1].action.value, "GOVERNED_REQUEST_REFUSED")
        finally:
            w.close()

    def test_the_store_refuses_a_dry_run_record_judged_by_a_superseded_version(self):
        w = nm_world()
        try:
            candidate = w.store.load_candidate(w.candidate("NM-C11"))
            stale_ref = policy_in_force(w.store).ref
            # The real governed result, then a newer version, then a write that names the old one.
            from app.remediation.engine import remediation_dry_run

            approval = w.store.load_approval(approval_of(w, "NM-C11"))
            result = remediation_dry_run(
                candidate=candidate, operation=RemediationOperation.OKTA_GROUP_UNASSIGN,
                target_ref=candidate.assignment_ids[0], evidence=w.store.evidence_bundle(candidate), approval=approval,
                policy=policy_in_force(w.store).policy.lifecycle, now=w.clock(), mode=w.store.mode,
                requested_by=Actor(ActorKind.HUMAN, EXECUTOR), requested_mode=None,
                allowlist=w.api.remediation._allowlist, environment=w.store.marker.environment, correlation_id="req-t")
            self.assertEqual(result.outcome.value, "SIMULATED")
            record_newer_version(w)
            head = w.store.audit_head()
            with self.assertRaises(StoreConflict):
                w.store.record_remediation_dry_run(
                    actor=Actor(ActorKind.HUMAN, EXECUTOR), candidate_id=candidate.id, result=result,
                    approval_id=approval.id, evidence_fingerprint=evidence_fingerprint(w.store.evidence_bundle(candidate)),
                    correlation_id="req-t", policy_ref=stale_ref)
            self.assertEqual(w.store.audit_head(), head, "nothing was written")
        finally:
            w.close()

    def test_the_binding_is_asked_again_before_a_retry(self):
        w = nm_world()
        try:
            candidate = w.store.load_candidate(w.candidate("NM-C11"))
            asked = []

            def authorize():
                asked.append(1)
                return () if len(asked) == 1 else ("policy version 3 was recorded during the run",)

            report = run_drill(
                mode=DrillMode.SYNTHETIC_EXECUTION, scenario_key="TIMEOUT_NOT_APPLIED", candidate=candidate,
                operation=RemediationOperation.OKTA_GROUP_UNASSIGN, target_ref=candidate.assignment_ids[0],
                evidence=w.store.evidence_bundle(candidate), approval=w.store.load_approval(approval_of(w, "NM-C11")),
                policy=policy_in_force(w.store).policy.lifecycle, now=w.clock(),
                execution_mode=ExecutionMode.LOCAL_SYNTHETIC, requested_by=Actor(ActorKind.HUMAN, EXECUTOR),
                allowlist=w.api.remediation._allowlist, environment=w.store.marker.environment,
                correlation_id="req-t", authorize=authorize)
            self.assertEqual([s.state for s in report.trace.steps],
                             [X.EXECUTION_REQUESTED, X.OUTCOME_UNKNOWN, X.VERIFYING, X.RETRY_PERMITTED, X.BLOCKED])
            self.assertIs(report.trace.steps[-1].reason, Reason.GATES_BLOCKED_ON_RETRY)
            self.assertEqual(report.trace.steps[-1].problems,
                             ("AUTHORIZATION: policy version 3 was recorded during the run",))
            self.assertEqual((report.trace.submissions, report.mutations_applied, len(asked)), (1, 0, 2))
        finally:
            w.close()

    def test_binding_is_exact_and_fails_closed(self):
        w = nm_world()
        try:
            in_force = policy_in_force(w.store).ref
            v110 = w.store.recorded_policies(w.candidate("NM-C08"))
            old = next(iter(v110.values()))
            self.assertIs(binding(in_force, in_force), Binding.IN_FORCE)
            self.assertIs(binding(old, in_force), Binding.SUPERSEDED)
            self.assertIs(binding(None, in_force), Binding.NOT_RECORDED)
            self.assertIs(binding(replace(in_force, sequence=0), in_force), Binding.SUPERSEDED, "same digest, other version")
            self.assertEqual(ACCEPTED_BINDINGS, {Binding.IN_FORCE, Binding.UNRECORDED_POLICY})
        finally:
            w.close()


# --- 3. the seed chronology ----------------------------------------------------------------------------


class SeedChronologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_null_meridian_store(memory_target())
        cls.ids = {s.key: s.candidate_id for s in cls.summary.scenarios}

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_every_seeded_decision_and_approval_records_the_release_in_force_on_its_date(self):
        self.assertEqual(policy_chronology_problems(self.store, tuple(self.ids.values()), nm_policy.releases()), [])

    def test_nm_c11_is_triaged_under_1_1_0_and_approved_under_1_2_0(self):
        cid = self.ids["NM-C11"]
        refs = self.store.recorded_policies(cid)
        v110, v120 = nm_policy.releases()
        rows = [(d.to_state.value, d.decided_at, refs[f"decision:{d.id}"].version) for d in self.store.decisions(cid)]
        self.assertEqual([(s, v) for s, _, v in rows], [("CANDIDATE", "1.1.0"), ("NEEDS_REVIEW", "1.1.0"),
                                                       ("APPROVED", "1.2.0")])
        self.assertTrue(all(at < v120.effective_from for s, at, v in rows if v == "1.1.0"))
        self.assertTrue(all(v120.effective_from <= at < AS_OF for s, at, v in rows if v == "1.2.0"))
        (approval,) = self.store.approvals_for(cid)
        self.assertEqual(refs[f"approval:{approval.id}"].version, "1.2.0")
        self.assertTrue(v120.effective_from <= approval.decided_at < AS_OF)
        # And the order of the audit chain agrees: v1.2.0 is recorded before the snapshot-day records,
        # and after every triage decision.
        events = self.store.audit_events()
        reviews = [e.sequence for e in events if e.action.value == "POLICY_REVIEW_RECORDED"]
        approval_event = next(e.sequence for e in events if e.after_ref == f"approval:{approval.id}")
        triage = [e.sequence for e in events if e.action.value == "TRANSITION_APPLIED"
                  and PolicyRef.from_audit_details(e.details).version == "1.1.0"]
        self.assertEqual(len(reviews), 2)
        self.assertLess(max(triage), reviews[1], "every 1.1.0 decision precedes the 1.2.0 record")
        self.assertLess(reviews[1], approval_event, "1.2.0 is recorded before NM-C11's approval")

    def test_a_seed_in_the_wrong_order_is_caught(self):
        v110, v120 = nm_policy.releases()
        cids = tuple(self.ids.values())
        # As if 1.2.0 had taken effect before the triage: every triage record names the wrong release.
        early = replace(v120, effective_from=v110.effective_from + timedelta(days=1))
        problems = policy_chronology_problems(self.store, cids, (v110, early))
        self.assertTrue(problems and all("1.2.0 was in force" in p for p in problems), problems[:3])
        # As if 1.2.0 took effect after the snapshot: NM-C11's approval and decision name a future release.
        late = replace(v120, effective_from=AS_OF + timedelta(days=1))
        problems = policy_chronology_problems(self.store, cids, (v110, late))
        self.assertEqual(len(problems), 2, problems)
        self.assertTrue(all("records NM-LIFECYCLE-004 v1.2.0, but NM-LIFECYCLE-004 v1.1.0 was in force" in p
                            for p in problems))

    def test_the_naive_merge_order_is_refused_by_the_seed(self):
        """OGWA-DEMO-03's snapshot day before OGWA-DEMO-02's later release (the naive merge) fails."""
        from app.demo.null_meridian.dataset import build_dataset
        from app.demo.null_meridian.world import NullMeridianWorld
        from app.demo.synthetic_world import SeedClock
        from app.domain.ids import deterministic_ids
        from app.store.environment import DatabaseEnvironment
        from app.store.store import Store

        store = Store.initialize(memory_target(), environment=DatabaseEnvironment.SYNTHETIC,
                                 mode=ExecutionMode.LOCAL_SYNTHETIC, actor=Actor(ActorKind.SYSTEM, "seed"),
                                 clock=SeedClock(AS_OF + timedelta(hours=1)))
        try:
            first, later = nm_policy.releases()
            with deterministic_ids("null-meridian-v1:seed"):
                world = NullMeridianWorld(store, build_dataset())
                world.inventory()
                world.record_policy(first)
                world.candidates()
                world.snapshot_day()  # too early: 1.2.0 is not recorded yet
                problems = policy_chronology_problems(store, tuple(world.candidate_ids.values()), (first, later))
                self.assertEqual(len(problems), 2, problems)
                last = max(d.decided_at for c in world.candidate_ids.values() for d in store.decisions(c))
                self.assertGreaterEqual(last, later.effective_from, "DEMO-02's own guard would refuse 1.2.0 here")
        finally:
            store.close()

    def test_the_seed_refuses_its_own_chronology_errors(self):
        with mock.patch("app.demo.null_meridian.world.policy_chronology_problems", return_value=["x"]):
            with self.assertRaisesRegex(StoreError, "seeded policy chronology is wrong: x"):
                create_null_meridian_store(memory_target())


# --- 4. NM-C11 is fresh enough, and only while it is -------------------------------------------------


class NmC11FreshnessTests(unittest.TestCase):
    def test_fresh_at_the_demo_clock_and_blocked_once_the_execution_window_passes(self):
        w = nm_world()
        try:
            candidate, approval = w.candidate("NM-C11"), approval_of(w, "NM-C11")
            bundle = w.store.evidence_bundle(w.store.load_candidate(candidate))
            observed = {r.provenance.observed_at for r in bundle.records()}
            self.assertTrue(all(RECOLLECTED <= at <= RECOLLECTED + timedelta(minutes=10) for at in observed), observed)
            self.assertLess(w.clock.now - RECOLLECTED, timedelta(hours=24), "inside the 24 h EXECUTION window")
            self.assertGreater(w.store.load_approval(approval).expires_at, w.clock.now)
            detail = w.client(VIEWER).get(f"{V}/candidates/{candidate}").json
            items = detail["evidenceAssessment"]["items"]
            self.assertTrue(all(i["freshness"] == "CURRENT" for i in items if i["required"]),
                            [(i["key"], i["freshness"]) for i in items if i["required"]])
            self.assertEqual(post_drill(w, w.client(EXECUTOR), candidate, approval).status, 200)
            # 24 hours after re-collection the gates refuse it, as they would in production.
            w.clock.advance(RECOLLECTED + timedelta(hours=24, minutes=1) - w.clock.now)
            late = post_drill(w, w.client(EXECUTOR), candidate, approval)
            self.assertEqual((late.status, late.code), (409, "REMEDIATION_BLOCKED"))
            fresh = next(g for g in late.json["error"]["gates"] if g["gate"] == "FRESH_EVIDENCE")
            self.assertFalse(fresh["passed"])
        finally:
            w.close()


# --- 5. NM-C10 can never reach a drill -----------------------------------------------------------------


class NmC10NeverDrillsTests(unittest.TestCase):
    def test_no_route_takes_nm_c10_into_a_drill(self):
        w = nm_world()
        try:
            candidate = w.candidate("NM-C10")
            security, executor = w.client(SECURITY), w.client(EXECUTOR)
            detail = security.get(f"{V}/candidates/{candidate}").json
            assessment = detail["evidenceAssessment"]
            self.assertEqual((assessment["decision"]["code"], assessment["decision"]["autoRemediationEligible"]),
                             ("CONFLICTING_EVIDENCE", False))
            self.assertTrue(detail["decisionExplanation"]["manualReview"]["forcedByEvidence"])
            self.assertIsNone(approval_of(w, "NM-C10"), "no approval exists")
            refused = security.post(f"{V}/candidates/{candidate}/approvals", {
                "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "try",
                "expectedEvidenceFingerprint": detail["evidenceFingerprint"]})
            self.assertEqual((refused.status, refused.code), (409, "EVIDENCE_RULES_NOT_MET"))
            self.assertTrue(any("is not exact" in p for p in refused.json["error"]["problems"]))
            self.assertIsNone(approval_of(w, "NM-C10"), "the refusal recorded no approval")
            borrowed = post_drill(w, executor, candidate, approval_of(w, "NM-C11"))
            self.assertEqual((borrowed.status, borrowed.code), (404, "NOT_FOUND"), "another candidate's approval")
            # A forged approval (never stored) handed straight to the drill engine: the gates block it,
            # and no provider fixture is ever built.
            record = w.store.load_candidate(candidate)
            bundle = w.store.evidence_bundle(record)
            forged = ApprovalRecord(id=new_id(IdKind.APPROVAL), candidate_id=candidate, stage=ApprovalStage.OKTA_UNASSIGN,
                                    decision=ApprovalDecision.APPROVE, operator=Actor(ActorKind.HUMAN, SECURITY),
                                    decided_at=w.clock.now, reason="forged", evidence_fingerprint=evidence_fingerprint(bundle),
                                    candidate_epoch=record.epoch, expires_at=w.clock.now + timedelta(hours=24))
            for mode, scenario in ((DrillMode.DRY_RUN, None), (DrillMode.SYNTHETIC_EXECUTION, "NO_FAULT")):
                report = run_drill(
                    mode=mode, scenario_key=scenario, candidate=record, operation=RemediationOperation.OKTA_GROUP_UNASSIGN,
                    target_ref=record.assignment_ids[0], evidence=bundle, approval=forged,
                    policy=policy_in_force(w.store).policy.lifecycle, now=w.clock(),
                    execution_mode=ExecutionMode.LOCAL_SYNTHETIC, requested_by=Actor(ActorKind.HUMAN, EXECUTOR),
                    allowlist=w.api.remediation._allowlist, environment=w.store.marker.environment,
                    correlation_id="req-t", authorize=lambda: ())
                self.assertTrue(report.blocked)
                self.assertIsNone(report.trace, "no fixture, no step")
                failed = {c.gate.value for c in report.result.gates.checks if not c.passed}
                self.assertTrue({"EXACT_VERIFIED_MAPPING", "FRESH_EVIDENCE", "LIFECYCLE_RULES"} <= failed, failed)
        finally:
            w.close()


# --- 6. success needs the post-action predicate --------------------------------------------------------


class PostActionPredicateTests(unittest.TestCase):
    T0 = AS_OF

    def trace(self, **verified):
        s = lambda seq, state, **kw: ExecutionStep(seq, state, self.T0 + timedelta(seconds=seq), kw.pop("reason", Reason.SUBMITTED),
                                                   "test", **kw)
        steps = (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.EXECUTED),
                 s(3, X.POST_ACTION_VERIFIED, **{"reason": Reason.MATCHES_EXPECTED_STATE, "observation": O.APPLIED,
                                                 "reads": (True,), **verified}))
        return ExecutionTrace(steps)

    def test_post_action_verified_needs_the_read_the_after_state_and_an_unchanged_scope(self):
        self.assertTrue(self.trace().succeeded)
        for label, forged in {
            "the target still in its before-state": {"observation": O.NOT_APPLIED},
            "the target changed by something else": {"observation": O.DIVERGED},
            "no read at all": {"observation": O.UNREADABLE, "reads": ()},
            "only failed reads": {"reads": (False, False)},
            "another change in scope": {"differences": ("asg:x.present: expected true, observed false",)},
            "the wrong reason": {"reason": Reason.ACKNOWLEDGED},
        }.items():
            with self.subTest(label), self.assertRaisesRegex(InvalidRecord, "post-action predicate"):
                self.trace(**forged)

    def test_every_verified_api_drill_carries_the_predicate(self):
        w = nm_world()
        try:
            candidate, approval = w.candidate("NM-C11"), approval_of(w, "NM-C11")
            from app.remediation.synthetic_provider import SCENARIOS

            for key in SCENARIOS:
                drill = post_drill(w, w.client(EXECUTOR), candidate, approval, mode="SYNTHETIC_EXECUTION",
                                   scenario=key).json["drill"]
                last = drill["steps"][-1]
                with self.subTest(key):
                    if drill["succeeded"]:
                        self.assertEqual((last["state"], last["reason"], last["observation"], last["differences"]),
                                         ("POST_ACTION_VERIFIED", "MATCHES_EXPECTED_STATE", "APPLIED", []))
                        self.assertTrue(any(r["succeeded"] for r in last["reads"]))
                        self.assertEqual(drill["postActionVerification"]["result"], "CONFIRMED")
                    else:
                        self.assertNotEqual(last["state"], "POST_ACTION_VERIFIED")
                        self.assertNotEqual(drill["postActionVerification"]["result"], "CONFIRMED")
                        self.assertNotIn("VERIFIED", drill["finalLabel"].replace("VERIFICATION", ""))
        finally:
            w.close()


# --- 7. the audit sample is the application's own output ----------------------------------------------


class AuditSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with no_live_system():
            cls.text = audit_sample.render(audit_sample.build_audit_sample())
        cls.sample = json.loads(cls.text)

    def test_the_committed_sample_is_exactly_what_this_build_generates(self):
        committed = audit_sample.DEFAULT_PATH.read_text(encoding="utf-8")
        self.assertEqual(committed, self.text, "regenerate: python -m app.demo.null_meridian.audit_sample --write")
        self.assertEqual(audit_sample.DEFAULT_PATH, REPO / "docs" / "demo" / "samples" / "ogwa-audit-sample.json")

    def test_the_sample_captures_the_whole_chain(self):
        s, b = self.sample, self.sample["scenarioB"]
        self.assertEqual((s["format"], s["synthetic"]), ("ogwa-audit-sample/v1", True))
        self.assertEqual(s["policy"]["inForce"]["name"], "NM-LIFECYCLE-004 v1.2.0")
        self.assertEqual([v["release"]["version"] for v in s["policy"]["versions"]], ["1.1.0", "1.2.0"])
        self.assertEqual(b["evidenceSnapshot"]["evidenceFingerprint"], b["approvals"]["items"][0]["evidenceFingerprint"])
        self.assertEqual(b["decisionExplanation"]["policy"]["version"], "1.2.0")
        self.assertEqual(b["dryRun"]["drill"]["finalState"], "DRY_RUN")
        self.assertFalse(b["dryRun"]["drill"]["provider"]["stateChanged"])
        run = b["syntheticExecution"]
        self.assertEqual([st["state"] for st in run["drill"]["steps"]],
                         ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "RETRY_PERMITTED",
                          "EXECUTION_REQUESTED", "EXECUTED", "POST_ACTION_VERIFIED"])
        self.assertEqual(run["chain"]["policyVersion"], "1.2.0")
        self.assertEqual(b["auditHeadBeforeDrills"]["digest"], b["auditHeadAfterDrills"]["digest"],
                         "the drills recorded nothing")
        governed = b["governedDryRunRecorded"]["record"]["chain"]
        self.assertEqual((governed["operationId"], governed["decisionId"], governed["policyVersion"]),
                         (run["chain"]["operationId"], run["chain"]["decisionId"], "1.2.0"))
        actions = [e["action"] for e in b["auditChain"]["events"]]
        self.assertEqual(actions, ["CANDIDATE_CREATED", "TRANSITION_APPLIED", "TRANSITION_APPLIED", "APPROVAL_RECORDED",
                                   "TRANSITION_APPLIED", "REMEDIATION_DRY_RUN_RECORDED"])
        for event in b["auditChain"]["events"][1:]:
            self.assertIn("policy_release", event["details"], event["action"])
        a = s["scenarioA"]
        self.assertEqual(a["evidenceAssessment"]["decision"]["code"], "CONFLICTING_EVIDENCE")
        self.assertEqual(a["approvalAttempt"]["status"], 409)
        self.assertEqual(a["approvalsAfter"]["items"], [])
        self.assertEqual(s["dataset"]["auditHeadAfterSeed"]["digest"],
                         "sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41")

    def test_the_sample_is_sanitized(self):
        text = self.text
        notes = " ".join(self.sample["notes"])
        body = text.replace(json.dumps(notes)[1:-1], "")
        for pattern in (r"(?i)bearer\s", r"(?i)set-cookie", r"(?i)csrfToken", r"(?i)password", r"(?i)\bssws\b",
                        r"(?i)api[_-]?key", r"https?://", r"\b\d{1,3}(\.\d{1,3}){3}\b"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, body), pattern)
        domains = set(re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|info|local|internal|corp)\b",
                                 text.lower()))
        self.assertLessEqual(domains, {"nullmeridian.info", "corp.nullmeridian.info"}, domains)
        emails = set(re.findall(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", text.lower()))
        self.assertTrue(all(e.endswith("@nullmeridian.info") for e in emails), emails)
        for subject in re.findall(r'"id": "(synthetic\.[a-z0-9.]+)"', text):
            self.assertTrue(subject.startswith("synthetic."), subject)


# --- 8. dry run and synthetic execution can never be confused -----------------------------------------


class DryRunVsExecutionWordingTests(unittest.TestCase):
    def test_the_server_words_each_mode_unmistakably(self):
        self.assertEqual(MODE_BANNERS["DRY_RUN"]["headline"], "DRY RUN — NO STATE CHANGED")
        self.assertEqual(MODE_BANNERS["SYNTHETIC_EXECUTION"]["headline"], "SYNTHETIC EXECUTION")
        self.assertTrue(MODE_BANNERS["SYNTHETIC_EXECUTION"]["detail"].startswith(
            "No external provider or persistent environment was modified."))
        self.assertNotRegex(MODE_BANNERS["SYNTHETIC_EXECUTION"]["headline"] + MODE_BANNERS["SYNTHETIC_EXECUTION"]["detail"],
                            "DRY RUN|NO STATE CHANGED")
        self.assertEqual(STATE_LABELS[X.OUTCOME_UNKNOWN], "OUTCOME UNKNOWN — VERIFYING")
        self.assertEqual(STATE_LABELS[X.POST_ACTION_VERIFIED], "POST-ACTION VERIFIED")
        for state, label in STATE_LABELS.items():
            if state is not X.DRY_RUN:
                self.assertNotIn("DRY RUN", label, state)
            if state is not X.POST_ACTION_VERIFIED:
                self.assertNotIn("POST-ACTION VERIFIED", label, state)

    def test_the_ui_uses_the_servers_headlines_and_tones_them_apart(self):
        drill_js = (REPO / "app" / "ui" / "static" / "js" / "drill.js").read_text(encoding="utf-8")
        found = dict(re.findall(r'(DRY_RUN|SYNTHETIC_EXECUTION): "([^"]+)"',
                                re.search(r"MODE_HEADLINE = Object\.freeze\(\{(.*?)\}\)", drill_js, re.S).group(1)))
        self.assertEqual(found, {k: v["headline"] for k, v in MODE_BANNERS.items()})
        self.assertIn('tone: drill.mode === "DRY_RUN" ? "neutral" : "caution"', drill_js)
        candidate_js = (REPO / "app" / "ui" / "static" / "js" / "views" / "candidate.js").read_text(encoding="utf-8")
        self.assertLess(candidate_js.index('"banner drill-mode-banner"'), candidate_js.index('"banner drill-banner"'),
                        "the mode banner is rendered before the outcome")


# --- the walkthrough ----------------------------------------------------------------------------------


class WalkthroughTests(unittest.TestCase):
    def test_the_walkthrough_points_at_real_candidates_and_real_sections(self):
        candidate_js = (REPO / "app" / "ui" / "static" / "js" / "views" / "candidate.js").read_text(encoding="utf-8")
        self.assertEqual([p["candidateKey"] for p in PARTS], ["NM-C10", "NM-C11"])
        for part in PARTS:
            for step in part["steps"]:
                if step["section"]:
                    self.assertIn(json.dumps(step["section"]), candidate_js, step["section"])
        self.assertEqual(len(DISCLOSURES), 4)
        w = nm_world()
        try:
            guide = w.client(VIEWER).get(f"{V}/demo-scenarios").json["walkthrough"]
            self.assertEqual([(p["candidateKey"], p["candidateId"]) for p in guide["parts"]],
                             [("NM-C10", w.candidate("NM-C10")), ("NM-C11", w.candidate("NM-C11"))])
        finally:
            w.close()
        classic = World()
        try:
            self.assertIsNone(classic.client(VIEWER).get(f"{V}/demo-scenarios").json["walkthrough"])
        finally:
            classic.close()


if __name__ == "__main__":
    unittest.main()
