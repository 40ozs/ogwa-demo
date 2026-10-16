"""The AD quarantine, post-quarantine hold, revalidation, and deletion stages, in the
lifecycle itself (owner decisions D128–D155). LOCAL_SYNTHETIC data only; nothing executes.

- quarantine and deletion are separate stages, each approved separately (D128, D129, D147);
- the deletion approver is not the deletion's proposer, the quarantine approver, or the
  Okta-stage approver (D143);
- a candidate blocked after quarantine never returns to the pre-quarantine lifecycle, and a
  resolved post-quarantine blocker leads to DELETION_REVALIDATION_REQUIRED, fresh complete
  evidence, and a new proposal and approval (D144, D145, D155);
- no Okta, quarantine, or legacy approval ever authorizes a deletion (D146, D148);
- the post-quarantine hold is 30 days from the confirmed quarantine observation, and its end
  authorizes nothing (D138, D139);
- the legacy single AD stage is history only (D148).
"""

import unittest
from dataclasses import replace
from datetime import timedelta

from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalStage
from app.domain.errors import InvalidRecord
from app.domain.evidence import ResultStatus
from app.domain.execution import JobKind
from app.domain.lifecycle import (
    LEGACY_PATH,
    LEGACY_STEP_PROBLEM,
    POST_QUARANTINE_STATES,
    PRE_QUARANTINE_STATES,
    PRE_UNASSIGN_STATES,
    QUARANTINE_HOLD_PERIOD,
    TRANSITIONS,
    LifecycleState,
    TransitionRequest,
    allowed_targets,
    apply_transition,
    stage_approval_rules,
    verify_history,
)
from app.domain.model import MappingConfidence
from app.domain.policy import MANDATORY_DEPENDENCY_KINDS
from app.domain.quarantine import QuarantineOus, dn_parts
from tests.domain_fixtures import (
    AD_ID_2,
    DAY,
    FOURTH_REVIEWER,
    HOUR,
    POLICY,
    QUARANTINE_OUS,
    REVIEWER,
    SECOND_REVIEWER,
    SYNTHETIC_DOMAIN,
    SYSTEM,
    THIRD_REVIEWER,
    Journey,
    ad_group,
    approval,
    blocking_finding,
    dependencies,
    dependency,
    dry_run_job,
)
from tests.test_lifecycle_state_machine import RefusalAssertions, candidate_in

S = LifecycleState
MIN = timedelta(minutes=1)


def request(target, at, *, actor=SYSTEM, evidence, approval_record=None, job=None, quarantine_ous=QUARANTINE_OUS):
    return TransitionRequest(target=target, actor=actor, reason="synthetic AD-stage step", now=at, evidence=evidence,
                             approval=approval_record, job=job, quarantine_ous=quarantine_ous)


# --- the quarantine OU configuration (D136) ----------------------------------------------------


class QuarantineOuTests(unittest.TestCase):
    def test_a_group_is_in_quarantine_only_as_a_direct_child_of_its_domains_ou(self):
        at = Journey.T_HOLD_ENDS
        self.assertTrue(QUARANTINE_OUS.in_quarantine(ad_group(at, quarantined=True)))
        self.assertFalse(QUARANTINE_OUS.in_quarantine(ad_group(at)))
        nested = ad_group(at, distinguished_name="CN=SYNTH-GROUP-001,OU=Deeper,OU=OGWA-Quarantine,DC=corp,DC=synthetic,"
                                                 "DC=example")
        self.assertFalse(QUARANTINE_OUS.in_quarantine(nested))
        spaced = ad_group(at, distinguished_name="CN=SYNTH-GROUP-001, ou=ogwa-quarantine, DC=Corp,DC=synthetic,DC=example")
        self.assertTrue(QUARANTINE_OUS.in_quarantine(spaced))
        escaped = ad_group(at, distinguished_name="CN=SYNTH\\,GROUP,OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example")
        self.assertTrue(QUARANTINE_OUS.in_quarantine(escaped))
        self.assertIsNone(QUARANTINE_OUS.in_quarantine(ad_group(at, domain="other.synthetic.example")))
        self.assertIsNone(QUARANTINE_OUS.in_quarantine(ad_group(at, exists=False)))

    def test_the_configuration_is_strict(self):
        good = (SYNTHETIC_DOMAIN, "OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example")
        for ous in (
            (),
            ((SYNTHETIC_DOMAIN, "OU=Q,DC=other,DC=example"),),  # outside the domain
            ((SYNTHETIC_DOMAIN, "CN=Q,DC=corp,DC=synthetic,DC=example"),),  # not an OU
            ((SYNTHETIC_DOMAIN, "DC=corp,DC=synthetic,DC=example"),),  # the domain itself
            ((SYNTHETIC_DOMAIN, "OU=*,DC=corp,DC=synthetic,DC=example"),),  # a wildcard
            (("CORP.synthetic.example", good[1]),),  # not lowercase
            (good, good),  # a domain twice
        ):
            with self.subTest(ous=ous), self.assertRaises(InvalidRecord):
                QuarantineOus("SYNTHETIC", ous)
        with self.assertRaises(InvalidRecord):
            QuarantineOus("STAGING", (good,))
        self.assertIsNone(dn_parts("CN=x\\"))


# --- REVALIDATION_REQUIRED -> QUARANTINE_APPROVED --------------------------------------------


class QuarantineApprovalGuardTests(RefusalAssertions):
    AT = Journey.T_QUARANTINE_APPROVE + 5 * MIN

    def setUp(self):
        self.j = Journey().to(S.REVALIDATION_REQUIRED)

    def req(self, evidence=None, *, operator=SECOND_REVIEWER, actor=None, stage=ApprovalStage.AD_QUARANTINE,
            decided_at=Journey.T_QUARANTINE_APPROVE, quarantine_ous=QUARANTINE_OUS, **approval_kw):
        evidence = evidence or self.j.post_hold_evidence()
        record = approval(self.j.candidate, stage, decided_at, evidence, operator=operator, **approval_kw)
        return request(S.QUARANTINE_APPROVED, self.AT, actor=actor or operator, evidence=evidence,
                       approval_record=record, quarantine_ous=quarantine_ous)

    def test_a_second_human_approves_the_quarantine_on_complete_evidence(self):
        result = apply_transition(self.j.candidate, self.req(), POLICY)
        self.assertIs(result.candidate.state, S.QUARANTINE_APPROVED)
        self.assertEqual(result.candidate.quarantine_approver, SECOND_REVIEWER)
        self.assertIsNone(result.candidate.quarantine_hold_until)

    def test_refusals(self):
        post = self.j.post_hold_evidence
        at = Journey.T_HOLD_ENDS
        blocking = list(dependencies(at))
        blocking[0] = dependency(at, blocking[0].kind, 1, (blocking_finding(),))
        failed = list(dependencies(at))
        failed[0] = dependency(at, failed[0].kind, 1, status=ResultStatus.FAILED)
        cases = [
            ("re-added during the hold", self.req(post(present=True))),
            ("requires an exact mapping", self.req(post(confidence=MappingConfidence.NAME_ONLY))),
            ("no identity mapping", self.req(post(mapping=None, ad_group=None))),
            ("protected", self.req(post(ad_group=ad_group(at, protected_from_accidental_deletion=True)))),
            ("blocking dependency", self.req(post(dependencies=tuple(blocking)))),
            ("coverage is PARTIAL", self.req(post(dep_kinds=MANDATORY_DEPENDENCY_KINDS))),
            ("coverage is PARTIAL", self.req(post(dependencies=tuple(failed)))),
            ("coverage is UNKNOWN", self.req(post(dep_kinds=frozenset()))),
            ("no longer exists", self.req(post(ad_exists=False))),
            ("direct member count is unknown", self.req(post(ad_group=ad_group(at, member_count=None)))),
            ("3 direct member(s)", self.req(post(ad_group=ad_group(at, member_count=3)))),
            ("stale for APPROVAL", self.req(post(at=at - 8 * DAY), decided_at=at)),
            ("not AD_QUARANTINE", self.req(stage=ApprovalStage.OKTA_UNASSIGN)),
            ("legacy approval stage", self.req(stage=ApprovalStage.AD_RETIREMENT)),
            ("before the hold period ended", self.req(decided_at=at - HOUR)),
            ("approved the Okta unassignment", self.req(operator=REVIEWER)),
            ("only the approving operator", self.req(actor=THIRD_REVIEWER)),
            ("already in its quarantine OU", self.req(post(quarantined=True))),
            ("no quarantine OU configuration", self.req(quarantine_ous=None)),
            ("no quarantine OU is configured for", self.req(post(ad_group=ad_group(at, domain="other.synthetic.example")))),
            ("approval decision is REJECT", self.req(decision=ApprovalDecision.REJECT)),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.j.candidate, req, expected)

    def test_a_system_actor_cannot_approve(self):
        self.assertRefused(self.j.candidate, self.req(actor=SYSTEM), "SYSTEM actors cannot")


# --- QUARANTINE_APPROVED -> QUARANTINE_DRY_RUN -> QUARANTINE_HOLD ----------------------------


class QuarantineDryRunAndObservationTests(RefusalAssertions):
    def setUp(self):
        self.j = Journey().to(S.QUARANTINE_APPROVED)

    def dry_run_req(self, kind=JobKind.AD_QUARANTINE, record=None, evidence=None, **job_kw):
        record = record or self.j.quarantine_approval
        evidence = evidence or self.j.post
        job = dry_run_job(self.j.candidate, kind, record, job_kw.pop("job_evidence", evidence),
                          Journey.T_QUARANTINE_APPROVE + 10 * MIN, Journey.T_QUARANTINE_DRY_RUN - 5 * MIN, **job_kw)
        return request(S.QUARANTINE_DRY_RUN, Journey.T_QUARANTINE_DRY_RUN, evidence=evidence, approval_record=record,
                       job=job)

    def test_the_dry_run_needs_a_quarantine_job_under_the_quarantine_approval(self):
        self.assertIs(apply_transition(self.j.candidate, self.dry_run_req(), POLICY).candidate.state,
                      S.QUARANTINE_DRY_RUN)
        cases = [
            ("not AD_QUARANTINE", self.dry_run_req(kind=JobKind.AD_DELETION)),
            ("targets do not match", self.dry_run_req(targets=(AD_ID_2,))),
            ("changed since the dry run",
             self.dry_run_req(job_evidence=self.j.post_hold_evidence(confidence=MappingConfidence.EXACT_DIRECTORY_SOURCE))),
            ("stale for EXECUTION", request(S.QUARANTINE_DRY_RUN, Journey.T_QUARANTINE_DRY_RUN + 2 * DAY,
                                            evidence=self.j.post, approval_record=self.j.quarantine_approval,
                                            job=self.dry_run_req().job)),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.j.candidate, req, expected)

    def test_the_hold_starts_from_the_confirmed_observation_and_lasts_30_days(self):
        j = Journey().to(S.QUARANTINE_HOLD)
        self.assertEqual(QUARANTINE_HOLD_PERIOD, timedelta(days=30))
        self.assertEqual(j.candidate.quarantine_hold_until, Journey.T_QUARANTINE_SEEN + QUARANTINE_HOLD_PERIOD)
        self.assertEqual(j.candidate.quarantine_approver, SECOND_REVIEWER)

    def test_the_quarantine_is_recorded_only_when_observed_in_the_quarantine_ou(self):
        j = Journey().to(S.QUARANTINE_DRY_RUN)

        def observed(evidence, at=Journey.T_QUARANTINE_SEEN, ous=QUARANTINE_OUS):
            return request(S.QUARANTINE_HOLD, at, evidence=evidence, approval_record=j.quarantine_approval,
                           job=j.quarantine_job, quarantine_ous=ous)

        cases = [
            ("not in its domain's quarantine OU", observed(replace(j.post, ad_group=ad_group(Journey.T_QUARANTINE_SEEN)))),
            ("never deletes it", observed(replace(j.post, ad_group=ad_group(Journey.T_QUARANTINE_SEEN, exists=False)))),
            ("observed before the dry run finished",
             observed(j.quarantined_evidence(Journey.T_QUARANTINE_DRY_RUN - HOUR), at=Journey.T_QUARANTINE_DRY_RUN)),
            ("stale for EXECUTION", observed(j.quarantined_evidence(), at=Journey.T_QUARANTINE_SEEN + 2 * DAY)),
            ("no quarantine OU configuration", observed(j.quarantined_evidence(), ous=None)),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(j.candidate, req, expected)
        self.assertNotIn(S.QUARANTINE_HOLD, {t for t in allowed_targets(S.QUARANTINE_APPROVED)})


# --- QUARANTINE_HOLD -> DELETION_REVALIDATION_REQUIRED ----------------------------------------


class QuarantineHoldTests(RefusalAssertions):
    def test_the_hold_must_elapse(self):
        j = Journey().to(S.QUARANTINE_HOLD)
        self.assertRefused(j.candidate, request(S.DELETION_REVALIDATION_REQUIRED,
                                                Journey.T_QUARANTINE_HOLD_ENDS - timedelta(seconds=1),
                                                evidence=j.quarantined_evidence()),
                           "post-quarantine hold has not ended (D138)")
        j._to_deletion_revalidation_required()
        self.assertIs(j.candidate.state, S.DELETION_REVALIDATION_REQUIRED)

    def test_the_end_of_the_hold_authorizes_nothing(self):
        """D139: after the hold only revalidation is open; no approval or dry run is reachable."""
        j = Journey().to(S.DELETION_REVALIDATION_REQUIRED)
        self.assertEqual(allowed_targets(S.QUARANTINE_HOLD) - {S.DELETION_REVALIDATION_REQUIRED},
                         allowed_targets(S.QUARANTINE_HOLD) & (POST_QUARANTINE_STATES.__class__(
                             {S.BLOCKED, S.MAPPING_AMBIGUOUS, S.DEPENDENCY_BLOCKED, S.STALE_EVIDENCE,
                              S.EVIDENCE_INCOMPLETE, S.EXCLUDED, S.REJECTED, S.PROTECTED})))
        later = Journey.T_QUARANTINE_HOLD_ENDS + DAY
        evidence = j.post_quarantine_evidence(later)
        deletion = approval(j.candidate, ApprovalStage.AD_DELETION, later, evidence, operator=FOURTH_REVIEWER)
        for target in (S.DELETION_APPROVED, S.DELETION_DRY_RUN, S.RETIRED):
            with self.subTest(target=target):
                self.assertRefused(j.candidate, request(target, later + HOUR, actor=FOURTH_REVIEWER, evidence=evidence,
                                                        approval_record=deletion), "not a permitted transition")


# --- DELETION_REVALIDATION_REQUIRED -> DELETION_PROPOSED ---------------------------------------


class DeletionProposalGuardTests(RefusalAssertions):
    AT = Journey.T_DELETION_PROPOSED

    def setUp(self):
        self.j = Journey().to(S.DELETION_REVALIDATION_REQUIRED)

    def req(self, evidence=None, actor=THIRD_REVIEWER, at=None, ous=QUARANTINE_OUS):
        return request(S.DELETION_PROPOSED, at or self.AT, actor=actor,
                       evidence=evidence or self.j.post_quarantine_evidence(), quarantine_ous=ous)

    def test_a_person_proposes_on_fresh_complete_post_hold_evidence(self):
        result = apply_transition(self.j.candidate, self.req(), POLICY)
        self.assertIs(result.candidate.state, S.DELETION_PROPOSED)
        self.assertEqual((result.candidate.deletion_proposer, result.candidate.deletion_proposed_at),
                         (THIRD_REVIEWER, self.AT))

    def test_refusals(self):
        fresh = self.j.post_quarantine_evidence
        at = Journey.T_QUARANTINE_HOLD_ENDS
        cases = [
            ("SYSTEM actors cannot", self.req(actor=SYSTEM)),
            ("observed before the post-quarantine hold ended", self.req(fresh(at - HOUR))),
            ("not in its domain's quarantine OU", self.req(fresh(quarantined=False))),
            ("coverage is PARTIAL", self.req(fresh(dep_kinds=MANDATORY_DEPENDENCY_KINDS))),
            ("2 direct member(s)", self.req(fresh(ad_group=ad_group(at, quarantined=True, member_count=2)))),
            ("protected", self.req(fresh(ad_group=ad_group(at, quarantined=True, admin_count=True)))),
            ("no longer exists", self.req(fresh(ad_exists=False))),
            ("re-added during the hold", self.req(fresh(present=True))),
            ("no quarantine OU configuration", self.req(ous=None)),
            ("stale for APPROVAL", self.req(at=at + 8 * DAY)),
        ]
        for expected, req in cases:
            with self.subTest(expected=expected):
                self.assertRefused(self.j.candidate, req, expected)


# --- DELETION_PROPOSED -> DELETION_APPROVED ----------------------------------------------------


class DeletionApprovalGuardTests(RefusalAssertions):
    """D143 and D146: a new, independent deletion approval, never a reused one."""

    AT = Journey.T_DELETION_APPROVE + 5 * MIN

    def setUp(self):
        self.j = Journey().to(S.DELETION_PROPOSED)

    def req(self, *, operator=FOURTH_REVIEWER, stage=ApprovalStage.AD_DELETION, decided_at=Journey.T_DELETION_APPROVE,
            record=None, evidence=None, **approval_kw):
        evidence = evidence or self.j.after_hold
        record = record or approval(self.j.candidate, stage, decided_at, evidence, operator=operator, **approval_kw)
        return request(S.DELETION_APPROVED, self.AT, actor=record.operator, evidence=evidence, approval_record=record)

    def test_a_fourth_person_approves_the_deletion(self):
        result = apply_transition(self.j.candidate, self.req(), POLICY)
        self.assertIs(result.candidate.state, S.DELETION_APPROVED)

    def test_the_approver_must_differ_from_the_proposer_and_both_earlier_approvers(self):
        """D143."""
        cases = {
            THIRD_REVIEWER: "proposed the deletion",
            SECOND_REVIEWER: "approved the AD quarantine",
            REVIEWER: "approved the Okta unassignment",
        }
        for operator, expected in cases.items():
            with self.subTest(operator=operator.id):
                self.assertRefused(self.j.candidate, self.req(operator=operator), expected)

    def test_earlier_approvals_never_authorize_a_deletion(self):
        """D146: the Okta approval, the quarantine approval, and a legacy AD_RETIREMENT approval."""
        for record, expected in (
            (self.j.unassign_approval, "not AD_DELETION"),
            (self.j.quarantine_approval, "not AD_DELETION"),
            (approval(self.j.candidate, ApprovalStage.AD_RETIREMENT, Journey.T_DELETION_APPROVE, self.j.after_hold,
                      operator=FOURTH_REVIEWER), "legacy approval stage"),
        ):
            with self.subTest(stage=record.stage):
                self.assertRefused(self.j.candidate, self.req(record=replace(record, operator=FOURTH_REVIEWER)), expected)

    def test_an_approval_given_before_the_proposal_or_the_hold_end_is_not_this_proposals_approval(self):
        self.assertRefused(self.j.candidate, self.req(decided_at=Journey.T_DELETION_PROPOSED - MIN),
                           "before this stage was proposed")
        self.assertRefused(self.j.candidate, self.req(decided_at=Journey.T_QUARANTINE_HOLD_ENDS - MIN),
                           "before the hold period ended")

    def test_the_approval_is_bound_to_the_post_hold_evidence(self):
        changed = self.j.post_quarantine_evidence(ad_group=ad_group(Journey.T_QUARANTINE_HOLD_ENDS, quarantined=True,
                                                                    sam_account_name="SYNTH-RENAMED"))
        record = approval(self.j.candidate, ApprovalStage.AD_DELETION, Journey.T_DELETION_APPROVE, self.j.after_hold,
                          operator=FOURTH_REVIEWER)
        self.assertRefused(self.j.candidate, request(S.DELETION_APPROVED, self.AT, actor=FOURTH_REVIEWER,
                                                     evidence=changed, approval_record=record),
                           "material evidence changed")

    def test_the_rules_name_every_excluded_approver(self):
        rules = stage_approval_rules(self.j.candidate, ApprovalStage.AD_DELETION)
        self.assertEqual([a for a, _ in rules.excluded], [REVIEWER, SECOND_REVIEWER, THIRD_REVIEWER])
        self.assertEqual((rules.not_before, rules.given_after, rules.unmet),
                         (self.j.candidate.quarantine_hold_until, Journey.T_DELETION_PROPOSED, ()))
        before = Journey().to(S.QUARANTINE_HOLD).candidate
        self.assertEqual(len(stage_approval_rules(before, ApprovalStage.AD_DELETION).unmet), 1)


# --- DELETION_APPROVED -> DELETION_DRY_RUN -----------------------------------------------------


class DeletionDryRunGuardTests(RefusalAssertions):
    def setUp(self):
        self.j = Journey().to(S.DELETION_APPROVED)

    def req(self, kind=JobKind.AD_DELETION, record=None):
        record = record or self.j.deletion_approval
        job = dry_run_job(self.j.candidate, kind, record, self.j.after_hold, Journey.T_DELETION_APPROVE + 10 * MIN,
                          Journey.T_DELETION_DRY_RUN - 5 * MIN)
        return request(S.DELETION_DRY_RUN, Journey.T_DELETION_DRY_RUN, evidence=self.j.after_hold,
                       approval_record=record, job=job)

    def test_only_a_deletion_job_under_the_deletion_approval(self):
        self.assertIs(apply_transition(self.j.candidate, self.req(), POLICY).candidate.state, S.DELETION_DRY_RUN)
        self.assertRefused(self.j.candidate, self.req(kind=JobKind.AD_QUARANTINE), "not AD_DELETION")
        self.assertRefused(self.j.candidate, self.req(record=self.j.quarantine_approval), "not AD_DELETION")


# --- re-entry after a block (D144, D145) -------------------------------------------------------


class PostQuarantineReentryTests(RefusalAssertions):
    def blocked_after(self, state):
        j = Journey().to(state)
        j.step(S.DEPENDENCY_BLOCKED, j.decisions[-1].decided_at + HOUR)
        return j

    def test_a_candidate_blocked_after_quarantine_never_returns_before_it(self):
        for state in sorted(POST_QUARANTINE_STATES):
            with self.subTest(state=state):
                j = self.blocked_after(state)
                at = j.candidate.updated_at + HOUR
                evidence = j.post_quarantine_evidence(at)
                for target, expected in ((S.CANDIDATE, "only re-enter at DELETION_REVALIDATION_REQUIRED"),
                                         (S.REVALIDATION_REQUIRED, "never returns to the pre-quarantine lifecycle")):
                    self.assertRefused(j.candidate, request(target, at, actor=REVIEWER, evidence=evidence), expected)

    def test_a_candidate_blocked_before_quarantine_cannot_skip_it(self):
        for state in sorted(PRE_QUARANTINE_STATES - {S.RETIREMENT_DRY_RUN}):
            with self.subTest(state=state):
                j = self.blocked_after(state)
                at = j.candidate.updated_at + HOUR
                self.assertRefused(j.candidate, request(S.DELETION_REVALIDATION_REQUIRED, at, actor=REVIEWER,
                                                        evidence=j.post_quarantine_evidence(at)),
                                   "blocked before its quarantine was observed")

    def test_a_resolved_post_quarantine_blocker_needs_fresh_evidence_then_a_new_proposal_and_approval(self):
        """D145: the earlier proposal and deletion approval are void after re-entry."""
        j = self.blocked_after(S.DELETION_APPROVED)
        old_approval = j.deletion_approval
        at = j.candidate.updated_at + HOUR
        stale_view = j.after_hold  # collected before the block, still post-hold
        self.assertRefused(j.candidate, request(S.DELETION_REVALIDATION_REQUIRED, at + 40 * DAY, actor=REVIEWER,
                                                evidence=stale_view), "stale for REVIEW")
        fresh = j.post_quarantine_evidence(at)
        j.step(S.DELETION_REVALIDATION_REQUIRED, at + MIN, actor=REVIEWER, evidence=fresh)
        self.assertEqual(j.candidate.epoch, 1)
        self.assertIsNone(j.candidate.deletion_proposer)
        self.assertEqual(j.candidate.quarantine_approver, SECOND_REVIEWER)  # the quarantine stays recorded
        # The old deletion approval cannot be used, even after a new proposal.
        self.assertRefused(j.candidate, request(S.DELETION_APPROVED, at + 2 * MIN, actor=FOURTH_REVIEWER,
                                                evidence=fresh, approval_record=old_approval), "not a permitted")
        j.step(S.DELETION_PROPOSED, at + 3 * MIN, actor=THIRD_REVIEWER, evidence=fresh)
        reused = replace(old_approval, evidence_fingerprint=approval(j.candidate, ApprovalStage.AD_DELETION, at,
                                                                     fresh).evidence_fingerprint)
        exc = self.assertRefused(j.candidate, request(S.DELETION_APPROVED, at + 4 * MIN, actor=FOURTH_REVIEWER,
                                                      evidence=fresh, approval_record=reused), "current epoch")
        self.assertTrue(any("before this stage was proposed" in p for p in exc.problems))
        new = approval(j.candidate, ApprovalStage.AD_DELETION, at + 4 * MIN, fresh, operator=FOURTH_REVIEWER)
        j.step(S.DELETION_APPROVED, at + 5 * MIN, actor=FOURTH_REVIEWER, evidence=fresh, approval_record=new)
        self.assertIs(j.candidate.state, S.DELETION_APPROVED)
        verify_history(j.candidate, j.decisions)

    def test_reentry_waits_for_the_hold_and_needs_the_group_still_in_quarantine(self):
        j = self.blocked_after(S.QUARANTINE_HOLD)
        early = j.candidate.updated_at + HOUR
        self.assertRefused(j.candidate, request(S.DELETION_REVALIDATION_REQUIRED, early, actor=REVIEWER,
                                                evidence=j.quarantined_evidence(early)), "post-quarantine hold")
        after = Journey.T_QUARANTINE_HOLD_ENDS + HOUR
        self.assertRefused(j.candidate, request(S.DELETION_REVALIDATION_REQUIRED, after, actor=REVIEWER,
                                                evidence=j.post_quarantine_evidence(after, quarantined=False)),
                           "no restore path")
        self.assertRefused(j.candidate, request(S.DELETION_REVALIDATION_REQUIRED, after, actor=REVIEWER,
                                                evidence=j.quarantined_evidence(Journey.T_QUARANTINE_SEEN + DAY)),
                           "observed before the post-quarantine hold ended")

    def test_a_pre_quarantine_reentry_clears_the_quarantine_approver(self):
        j = self.blocked_after(S.QUARANTINE_APPROVED)
        at = j.candidate.updated_at + HOUR
        j.step(S.REVALIDATION_REQUIRED, at, actor=REVIEWER, evidence=j.post_hold_evidence(at))
        self.assertIsNone(j.candidate.quarantine_approver)
        verify_history(j.candidate, j.decisions)


# --- the legacy single AD stage (D148) ---------------------------------------------------------


class LegacyStageTests(RefusalAssertions):
    def test_its_steps_are_in_the_table_for_history_only_and_always_refused(self):
        j = Journey().to(S.REVALIDATION_REQUIRED)
        post = j.post_hold_evidence()
        legacy = approval(j.candidate, ApprovalStage.AD_RETIREMENT, Journey.T_QUARANTINE_APPROVE, post,
                          operator=SECOND_REVIEWER)
        job = dry_run_job(j.candidate, JobKind.AD_RETIREMENT, legacy, post, Journey.T_QUARANTINE_APPROVE + MIN,
                          Journey.T_QUARANTINE_DRY_RUN - MIN)
        exc = self.assertRefused(j.candidate, request(S.RETIREMENT_DRY_RUN, Journey.T_QUARANTINE_DRY_RUN, evidence=post,
                                                      approval_record=legacy, job=job), "legacy single AD stage")
        self.assertEqual(list(exc.problems), [LEGACY_STEP_PROBLEM])
        stuck = candidate_in(S.RETIREMENT_DRY_RUN)
        gone = replace(post, ad_group=ad_group(Journey.T_RETIRED_SEEN, exists=False))
        self.assertRefused(stuck, request(S.RETIRED, Journey.T_RETIRED_SEEN, evidence=gone), "legacy single AD stage")
        for source, target in LEGACY_PATH:
            self.assertEqual(TRANSITIONS[(source, target)].category, "legacy")
            self.assertNotIn(target, allowed_targets(source))

    def test_recorded_legacy_history_still_verifies(self):
        """A candidate whose history went through the legacy stage loads unchanged."""
        j = Journey().to(S.REVALIDATION_REQUIRED)
        from app.domain.lifecycle import LifecycleDecision  # noqa: PLC0415
        from app.domain.ids import IdKind, new_id  # noqa: PLC0415

        last = j.decisions[-1]
        steps = [replace(last, id=new_id(IdKind.DECISION), from_state=S.REVALIDATION_REQUIRED,
                         to_state=S.RETIREMENT_DRY_RUN, decided_at=last.decided_at + HOUR),
                 replace(last, id=new_id(IdKind.DECISION), from_state=S.RETIREMENT_DRY_RUN, to_state=S.RETIRED,
                         decided_at=last.decided_at + DAY)]
        self.assertTrue(all(isinstance(d, LifecycleDecision) for d in steps))
        retired = replace(j.candidate, state=S.RETIRED, updated_at=steps[-1].decided_at)
        verify_history(retired, [*j.decisions, *steps])
        # Such a legacy candidate can be stopped, and re-enters before the quarantine.
        stuck = candidate_in(S.STALE_EVIDENCE, blocked_from=S.RETIREMENT_DRY_RUN)
        self.assertRefused(stuck, request(S.DELETION_REVALIDATION_REQUIRED, Journey.T_HOLD_ENDS, actor=REVIEWER,
                                          evidence=j.post_hold_evidence()), "only re-enter at REVALIDATION_REQUIRED")


# --- history (D11, D143, D144) -----------------------------------------------------------------


class AdStageHistoryTests(unittest.TestCase):
    def setUp(self):
        self.j = Journey().to(S.RETIRED)
        self.by_target = {d.to_state: i for i, d in enumerate(self.j.decisions)}

    def tampered(self, target, **changes):
        d = list(self.j.decisions)
        i = self.by_target[target]
        d[i] = replace(d[i], **changes)
        return d

    def test_separation_of_duties_is_checked_from_the_recorded_history(self):
        cases = {
            "deletion approved by its proposer": self.tampered(S.DELETION_APPROVED, actor=THIRD_REVIEWER),
            "deletion approved by the quarantine approver": self.tampered(S.DELETION_APPROVED, actor=SECOND_REVIEWER),
            "deletion approved by the Okta approver": self.tampered(S.DELETION_APPROVED, actor=REVIEWER),
            "quarantine approved by the Okta approver": self.tampered(S.QUARANTINE_APPROVED, actor=REVIEWER),
        }
        for name, history in cases.items():
            with self.subTest(name=name), self.assertRaises(InvalidRecord):
                verify_history(self.j.candidate, history)

    def test_recorded_stage_fields_must_match_the_history(self):
        c = self.j.candidate
        for changes in ({"quarantine_approver": FOURTH_REVIEWER},
                        {"quarantine_hold_until": c.quarantine_hold_until + HOUR},
                        {"deletion_proposer": FOURTH_REVIEWER},
                        {"deletion_proposed_at": c.deletion_proposed_at + HOUR}):
            with self.subTest(changes=changes), self.assertRaises(InvalidRecord):
                verify_history(replace(c, **changes), self.j.decisions)

    def test_a_history_returning_a_quarantined_candidate_before_the_quarantine_is_rejected(self):
        d = list(self.j.decisions[: self.by_target[S.QUARANTINE_HOLD] + 1])
        hold = d[-1]
        back = [replace(hold, id="dec_" + "a" * 32, from_state=S.QUARANTINE_HOLD, to_state=S.BLOCKED,
                        actor=REVIEWER, decided_at=hold.decided_at + HOUR),
                replace(hold, id="dec_" + "b" * 32, from_state=S.BLOCKED, to_state=S.REVALIDATION_REQUIRED,
                        actor=REVIEWER, decided_at=hold.decided_at + 2 * HOUR, epoch=1)]
        with self.assertRaises(InvalidRecord) as ctx:
            verify_history(self.j.candidate, [*d, *back])
        self.assertIn("pre-quarantine", str(ctx.exception))

    def test_a_record_with_a_quarantine_cannot_stand_before_it(self):
        with self.assertRaises(InvalidRecord):
            candidate_in(S.REVALIDATION_REQUIRED, quarantine_hold_until=Journey.T_QUARANTINE_HOLD_ENDS)
        with self.assertRaises(InvalidRecord):
            candidate_in(S.BLOCKED, blocked_from=S.HOLD, quarantine_approver=SECOND_REVIEWER,
                         quarantine_hold_until=Journey.T_QUARANTINE_HOLD_ENDS)


class NoDeletionPathIsProductionTests(unittest.TestCase):
    def test_every_ad_stage_job_is_a_dry_run(self):
        j = Journey().to(S.RETIRED)
        for job in (j.quarantine_job, j.deletion_job):
            self.assertTrue(job.dry_run)
            self.assertFalse(job.executed)
        self.assertTrue(all(s not in PRE_UNASSIGN_STATES for s in POST_QUARANTINE_STATES))
        human = Actor(ActorKind.HUMAN, "synthetic-reviewer-9")
        self.assertNotIn(human, (REVIEWER, SECOND_REVIEWER, THIRD_REVIEWER, FOURTH_REVIEWER))


if __name__ == "__main__":
    unittest.main()
