"""At the operator API: the AD quarantine, hold, revalidation, and deletion stages, over a
seeded synthetic world in LOCAL_SYNTHETIC (D152). Nothing is executed anywhere (D153).

One candidate (S01) walks the whole path through the API, each step by the principal the
owner's decisions allow, and each forbidden shortcut is tried on the way:

- the quarantine is approved by a second human and dry-run by an executor; discovery, not an
  operator, records the observed quarantine, and the 30-day hold starts from it (D138);
- the end of the hold authorizes nothing: only revalidation opens (D139);
- the deletion is proposed by one person and approved by another, who is neither the
  proposer nor an earlier approver (D143), then dry-run by an executor; discovery, not an
  operator, would record the deletion;
- a candidate blocked after quarantine never returns before it (D144);
- the quarantine OUs are read-only deployment configuration (D136).
"""

import unittest
from dataclasses import replace
from datetime import timedelta

from app.api.authz import ROLE_PERMISSIONS, Permission
from app.api.routes import ROUTES
from app.api.services import policy_in_force
from app.demo.synthetic_world import COLLECTOR
from app.domain.lifecycle import QUARANTINE_HOLD_PERIOD, LifecycleState, TransitionRequest
from tests.api_fixtures import AUTOMATION, DUAL, EXECUTOR, SECURITY, SECURITY_2, VIEWER, World
from tests.test_remediation_api import approve_ad

V = "/api/v1"
S = LifecycleState
QUARANTINE_OU = "OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example"


class AdStagesWalk:
    """Drives one candidate through the AD stages via the API (and discovery where it must)."""

    def __init__(self, test: unittest.TestCase, world: World):
        self.t, self.w = test, world
        self.candidate, self.quarantine_approval = approve_ad(world)  # S01, approved by SECURITY_2

    def post(self, subject: str, path: str, body: dict, *, fingerprint: bool = True):
        client = self.w.client(subject)
        if fingerprint:
            body = {**body, "expectedEvidenceFingerprint": self.w.fingerprint(client, self.candidate)}
        return client.post(f"{V}/candidates/{self.candidate}{path}", body)

    def ok(self, result, status: int = 201):
        self.t.assertEqual(result.status, status, result.json)
        return result

    def state(self) -> S:
        return self.w.store.load_candidate(self.candidate).state

    def plan(self, kind: str, approval: str) -> str:
        planned = self.ok(self.post(EXECUTOR, "/execution-jobs", {"kind": kind, "approvalId": approval}))
        job = planned.json["job"]
        self.t.assertEqual((job["dryRun"], job["executed"], job["status"]), (True, False, "SUCCEEDED"))
        return job["id"]

    def discovery(self, target: S, *, approval: str, job: str) -> None:
        """What read-only discovery records when it observes an approved change (never an operator)."""
        candidate = self.w.store.load_candidate(self.candidate)
        self.w.store.transition(self.candidate, TransitionRequest(
            target=target, actor=COLLECTOR, reason="synthetic discovery observed the change", now=self.w.clock(),
            evidence=self.w.store.evidence_bundle(candidate), approval=self.w.store.load_approval(approval),
            job=self.w.store.load_execution_job(job), quarantine_ous=self.w.api.lifecycle.quarantine_ous),
            policy_in_force(self.w.store).policy.lifecycle)

    def observe_quarantined(self) -> None:
        ad = self.w.store.evidence_bundle(self.w.store.load_candidate(self.candidate)).ad_group
        moved = replace(ad, distinguished_name=f"CN={ad.sam_account_name},{QUARANTINE_OU}",
                        provenance=replace(ad.provenance, observed_at=self.w.clock()))
        self.w.store.record_evidence(moved, actor=COLLECTOR)


class FullPathTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.walk = AdStagesWalk(self, self.world)

    def test_quarantine_hold_proposal_and_deletion_each_need_their_own_people(self):
        walk, w = self.walk, self.world
        self.assertIs(walk.state(), S.QUARANTINE_APPROVED)

        # The quarantine: a dry run by an executor, then discovery observes the move.
        job = walk.plan("AD_QUARANTINE", walk.quarantine_approval)
        walk.ok(walk.post(EXECUTOR, "/transitions", {"target": "QUARANTINE_DRY_RUN", "reason": "dry run planned",
                                                       "approvalId": walk.quarantine_approval, "jobId": job}))
        walk.observe_quarantined()
        refused = walk.post(AUTOMATION, "/transitions", {"target": "QUARANTINE_HOLD", "reason": "x",
                                                         "approvalId": walk.quarantine_approval, "jobId": job})
        self.assertEqual((refused.status, refused.code), (403, "NOT_AN_OPERATOR_ACTION"))
        walk.discovery(S.QUARANTINE_HOLD, approval=walk.quarantine_approval, job=job)
        held = w.store.load_candidate(walk.candidate)
        self.assertEqual(held.quarantine_hold_until, held.updated_at + QUARANTINE_HOLD_PERIOD)

        # During the hold, and when it ends, nothing is authorized (D138, D139).
        early = walk.post(SECURITY, "/approvals", {"stage": "AD_DELETION", "decision": "APPROVE", "reason": "x"})
        self.assertEqual((early.status, early.code), (409, "INVALID_STATE"))
        early = walk.post(AUTOMATION, "/transitions", {"target": "DELETION_REVALIDATION_REQUIRED", "reason": "x"})
        self.assertEqual(early.code, "TRANSITION_REFUSED")
        self.assertTrue(any("hold has not ended" in p for p in early.json["error"]["problems"]))
        w.clock.advance(QUARANTINE_HOLD_PERIOD + timedelta(hours=1))
        w.refresh_evidence(walk.candidate)  # fresh evidence, collected after the hold ended
        walk.ok(walk.post(AUTOMATION, "/transitions", {"target": "DELETION_REVALIDATION_REQUIRED",
                                                       "reason": "post-quarantine hold ended"}))
        detail = w.client(SECURITY).get(f"{V}/candidates/{walk.candidate}").json["allowedActions"]
        self.assertEqual((detail["approvals"], detail["planDryRun"]), ([], False))

        # The proposal, by a person who also holds the approver role (D143: then they may not approve).
        walk.ok(walk.post(DUAL, "/transitions", {"target": "DELETION_PROPOSED", "reason": "fresh evidence is clean"}))
        self.assertEqual(w.store.load_candidate(walk.candidate).deletion_proposer.id, DUAL)
        for person, expected in ((DUAL, "you proposed the deletion"), (SECURITY_2, "you approved the AD quarantine")):
            with self.subTest(person=person):
                refused = walk.post(person, "/approvals", {"stage": "AD_DELETION", "decision": "APPROVE",
                                                           "reason": "x"})
                self.assertEqual((refused.status, refused.code), (403, "SEPARATION_OF_DUTIES"))
                self.assertTrue(any(expected in p for p in refused.json["error"]["problems"]), refused.json)
        reused = walk.post(EXECUTOR, "/execution-jobs", {"kind": "AD_DELETION", "approvalId": walk.quarantine_approval})
        self.assertEqual(reused.status, 409)  # the quarantine approval never backs a deletion (D146)

        # A different person approves; an executor plans and records the deletion dry run.
        approved = walk.ok(walk.post(SECURITY, "/approvals", {"stage": "AD_DELETION", "decision": "APPROVE",
                                                               "reason": "independent deletion review"}))
        deletion_approval = approved.json["approval"]["id"]
        self.assertIs(walk.state(), S.DELETION_APPROVED)
        job = walk.plan("AD_DELETION", deletion_approval)
        planned = w.store.load_execution_job(job)
        self.assertEqual((planned.kind.value, planned.dry_run, planned.executed), ("AD_DELETION", True, False))
        walk.ok(walk.post(EXECUTOR, "/transitions", {"target": "DELETION_DRY_RUN", "reason": "dry run planned",
                                                       "approvalId": deletion_approval, "jobId": job}))
        refused = walk.post(AUTOMATION, "/transitions", {"target": "RETIRED", "reason": "x",
                                                         "approvalId": deletion_approval, "jobId": job})
        self.assertEqual((refused.status, refused.code), (403, "NOT_AN_OPERATOR_ACTION"))

        # Nothing was deleted: the group is still recorded, and every job is an unexecuted dry run.
        bundle = w.store.evidence_bundle(w.store.load_candidate(walk.candidate))
        self.assertTrue(bundle.ad_group.exists)
        for job_id in w.api.read.job_ids_for(walk.candidate):
            recorded = w.store.load_execution_job(job_id)
            self.assertEqual((recorded.dry_run, recorded.executed), (True, False))
        executed = w.client(EXECUTOR).post(f"{V}/execution-jobs/{job}/execute", {})
        self.assertEqual((executed.status, executed.code), (403, "PRODUCTION_MUTATION_REFUSED"))
        self.assertEqual(w.store.verify_integrity().candidates_checked, 16)


class PostQuarantineBlockTests(unittest.TestCase):
    """D144, D145 at the API: S15 is in its post-quarantine hold."""

    def test_a_candidate_blocked_after_quarantine_never_returns_before_it(self):
        w = World()
        self.addCleanup(w.close)
        s15 = w.candidate("S15")
        automation = w.client(AUTOMATION)

        def move(target):
            return automation.post(f"{V}/candidates/{s15}/transitions", {
                "target": target, "reason": "synthetic", "expectedEvidenceFingerprint": w.fingerprint(automation, s15)})

        self.assertEqual(move("BLOCKED").status, 201)
        for target, expected in (("REVALIDATION_REQUIRED", "never returns to the pre-quarantine lifecycle"),
                                 ("CANDIDATE", "only re-enter at DELETION_REVALIDATION_REQUIRED"),
                                 ("DELETION_REVALIDATION_REQUIRED", "post-quarantine hold has not ended")):
            with self.subTest(target=target):
                refused = move(target)
                self.assertEqual(refused.code, "TRANSITION_REFUSED")
                self.assertTrue(any(expected in p for p in refused.json["error"]["problems"]), refused.json)
        candidate = w.store.load_candidate(s15)
        self.assertEqual((candidate.state, candidate.blocked_from), (S.BLOCKED, S.QUARANTINE_HOLD))
        self.assertIsNotNone(candidate.quarantine_hold_until)


class QuarantineConfigurationTests(unittest.TestCase):
    """D136: deployment-controlled; shown read-only; no operator can change it."""

    def test_the_quarantine_ou_is_shown_but_no_route_reads_it_back_for_editing_or_changes_it(self):
        w = World()
        self.addCleanup(w.close)
        for route in ROUTES:
            self.assertNotIn("quarantine", route.pattern.lower())
            self.assertNotIn("config", route.pattern.lower())
        detail = w.client(VIEWER).get(f"{V}/candidates/{w.candidate('S15')}").json
        self.assertEqual(detail["quarantine"], {"domain": "corp.synthetic.example", "quarantineOu": QUARANTINE_OU,
                                                "inQuarantine": True})
        s12 = w.client(VIEWER).get(f"{V}/candidates/{w.candidate('S12')}").json
        self.assertIs(s12["quarantine"]["inQuarantine"], False)

    def test_no_role_may_execute_and_no_role_can_change_configuration(self):
        for role, permissions in ROLE_PERMISSIONS.items():
            with self.subTest(role=role):
                self.assertNotIn(Permission.EXECUTION_EXECUTE, permissions)
        self.assertFalse(any(p.name.startswith(("CONFIG", "POLICY_WRITE", "QUARANTINE")) for p in Permission))


if __name__ == "__main__":
    unittest.main()
