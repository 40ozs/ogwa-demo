"""Remediation gates and records, at the domain level (pure; no store, no API).

Each test starts from a scenario where every gate passes, changes exactly one thing, and
checks that the matching gate, and the result, refuse. Synthetic data only.
"""

import ast
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalStage
from app.domain.errors import InvalidRecord
from app.domain.evidence import ResultStatus
from app.domain.lifecycle import LifecycleState
from app.domain.model import DependencyKind, MappingConfidence, OktaGroupType
from app.domain.remediation import (
    OPERATIONS,
    REQUIRED_GATES,
    Gate,
    GateCheck,
    GateReport,
    PlannedChange,
    RemediationOperation,
    RemediationOutcome,
    RemediationResult,
    RemediationTarget,
    TargetKind,
    evaluate_gates,
    resolve_target,
)
from tests.domain_fixtures import (
    AD_ID,
    AD_ID_2,
    ASSIGNMENT_ID,
    DAY,
    FOURTH_REVIEWER,
    HOUR,
    POLICY,
    QUARANTINE_OUS,
    REVIEWER,
    SECOND_REVIEWER,
    SYNTHETIC_DOMAIN_SID,
    THIRD_REVIEWER,
    Journey,
    ad_group,
    approval,
    blocking_finding,
    bundle,
    dependency,
    fixed_id,
)
from app.domain.ids import IdKind

S = LifecycleState
O = RemediationOperation
REPO_ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = Actor(ActorKind.HUMAN, "synthetic-executor-1")


class OktaStage:
    """A candidate APPROVED for Okta unassignment: every gate passes for OKTA_GROUP_UNASSIGN."""

    def __init__(self):
        self.journey = Journey().to(S.APPROVED)
        self.candidate = self.journey.candidate
        self.evidence = self.journey.pre
        self.approval = self.journey.unassign_approval
        self.now = Journey.T_APPROVE + HOUR
        self.operation = O.OKTA_GROUP_UNASSIGN
        self.target = ASSIGNMENT_ID

    def gates(self, **changes):
        args = dict(candidate=self.candidate, operation=self.operation, target_ref=self.target, evidence=self.evidence,
                    approval=self.approval, policy=POLICY, now=self.now, mode=ExecutionMode.DRY_RUN_MUTATION,
                    requested_by=EXECUTOR, requested_mode=None, quarantine_ous=QUARANTINE_OUS)
        args.update(changes)
        positional = [args.pop(k) for k in ("candidate", "operation", "target_ref", "evidence", "approval", "policy")]
        return evaluate_gates(*positional, **args)


class AdStage(OktaStage):
    """A candidate in QUARANTINE_APPROVED, approved by a second human: every gate passes for
    AD_GROUP_QUARANTINE."""

    def __init__(self):
        self.journey = Journey().to(S.QUARANTINE_APPROVED)
        self.candidate = self.journey.candidate
        self.evidence = self.journey.post
        self.approval = self.journey.quarantine_approval
        self.now = Journey.T_QUARANTINE_APPROVE + HOUR
        self.operation = O.AD_GROUP_QUARANTINE
        self.target = AD_ID


class DeletionStage(OktaStage):
    """A candidate in DELETION_APPROVED: quarantined, held 30 days, revalidated, proposed by a
    third human, and approved by a fourth. Every gate passes for AD_GROUP_DELETE."""

    def __init__(self):
        self.journey = Journey().to(S.DELETION_APPROVED)
        self.candidate = self.journey.candidate
        self.evidence = self.journey.after_hold
        self.approval = self.journey.deletion_approval
        self.now = Journey.T_DELETION_APPROVE + HOUR
        self.operation = O.AD_GROUP_DELETE
        self.target = AD_ID


def failed(evaluation) -> set[Gate]:
    return set(evaluation.report.failed)


class OutcomeVocabularyTests(unittest.TestCase):
    def test_the_outcomes_are_exactly_the_four_non_executing_ones(self):
        self.assertEqual({o.value for o in RemediationOutcome}, {"SIMULATED", "WHATIF", "VALIDATION_ONLY", "BLOCKED"})
        for name in ("EXECUTED_PRODUCTION", "EXECUTED", "PRODUCTION", "APPLIED", "SUCCEEDED"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                RemediationOutcome(name)
        self.assertFalse(any("EXECUT" in o.value or "PRODUCTION" in o.value for o in RemediationOutcome))

    def test_the_required_gates_are_the_eight_p10_gates(self):
        self.assertEqual(set(REQUIRED_GATES), {
            Gate.EXACT_VERIFIED_MAPPING, Gate.FRESH_EVIDENCE, Gate.NOT_PROTECTED, Gate.VALID_APPROVAL,
            Gate.APPROVAL_FINGERPRINT_MATCHES, Gate.NO_DEPENDENCY_BLOCKER, Gate.EXECUTION_MODE_PERMITS_DRY_RUN,
            Gate.SINGLE_EXPLICIT_TARGET})
        self.assertEqual(set(Gate) - set(REQUIRED_GATES), {Gate.SEPARATION_OF_DUTIES, Gate.LIFECYCLE_RULES})

    def test_operations_map_to_their_stage_and_one_target_kind(self):
        self.assertEqual({o: (s.stage, s.target_kind, s.states) for o, s in OPERATIONS.items()}, {
            O.OKTA_GROUP_UNASSIGN: (ApprovalStage.OKTA_UNASSIGN, TargetKind.OKTA_ASSIGNMENT,
                                    frozenset({S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN})),
            # Quarantine and deletion are separate stages, each with its own approval (D147).
            O.AD_GROUP_QUARANTINE: (ApprovalStage.AD_QUARANTINE, TargetKind.AD_GROUP,
                                    frozenset({S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN})),
            O.AD_GROUP_DELETE: (ApprovalStage.AD_DELETION, TargetKind.AD_GROUP,
                                frozenset({S.DELETION_APPROVED, S.DELETION_DRY_RUN})),
        })
        self.assertNotIn(ApprovalStage.AD_RETIREMENT, {s.stage for s in OPERATIONS.values()})


class ResultRecordTests(unittest.TestCase):
    def setUp(self):
        stage = OktaStage()
        self.evaluation = stage.gates()
        self.assertTrue(self.evaluation.report.passed, self.evaluation.report.problems())
        self.change = PlannedChange("okta", "unassign_group_from_application", ASSIGNMENT_ID, "Remove the assignment.")

    def result(self, **kw):
        fields = dict(operation=O.OKTA_GROUP_UNASSIGN, outcome=RemediationOutcome.SIMULATED, adapter="SYNTHETIC",
                      gates=self.evaluation.report, target=self.evaluation.target, planned_changes=(self.change,))
        fields.update(kw)
        return RemediationResult(**fields)

    def test_a_result_can_never_claim_an_execution(self):
        for field in ("executed", "production_mutation"):
            for value in (True, 1, "true"):
                with self.subTest(field=field, value=value), self.assertRaises(InvalidRecord):
                    self.result(**{field: value})
        ok = self.result()
        self.assertEqual((ok.executed, ok.production_mutation), (False, False))
        self.assertEqual((ok.to_dict()["executed"], ok.to_dict()["productionMutation"]), (False, False))

    def test_a_non_blocked_outcome_needs_every_gate_a_target_and_a_change(self):
        failing = GateReport(tuple(GateCheck(g, ("x",) if g is Gate.FRESH_EVIDENCE else ()) for g in Gate))
        for outcome in (RemediationOutcome.SIMULATED, RemediationOutcome.WHATIF, RemediationOutcome.VALIDATION_ONLY):
            with self.subTest(outcome=outcome):
                with self.assertRaises(InvalidRecord):
                    self.result(outcome=outcome, gates=failing)
                with self.assertRaises(InvalidRecord):
                    self.result(outcome=outcome, planned_changes=())
                with self.assertRaises(InvalidRecord):
                    self.result(outcome=outcome, target=None)

    def test_a_blocked_result_plans_nothing_and_says_why(self):
        with self.assertRaises(InvalidRecord):
            self.result(outcome=RemediationOutcome.BLOCKED)  # gates passed, a change, no reason
        with self.assertRaises(InvalidRecord):
            self.result(outcome=RemediationOutcome.BLOCKED, planned_changes=())  # no reason at all
        blocked = self.result(outcome=RemediationOutcome.BLOCKED, planned_changes=(), notes=("adapter refused",))
        self.assertEqual(blocked.planned_changes, ())

    def test_a_gate_report_covers_every_gate_once_in_order(self):
        with self.assertRaises(InvalidRecord):
            GateReport(tuple(GateCheck(g) for g in list(Gate)[:-1]))
        with self.assertRaises(InvalidRecord):
            GateReport(tuple(GateCheck(g) for g in reversed(list(Gate))))


class HappyPathTests(unittest.TestCase):
    def test_every_gate_passes_for_each_authorizable_operation(self):
        for stage in (OktaStage(), AdStage(), DeletionStage()):
            with self.subTest(operation=stage.operation):
                evaluation = stage.gates()
                self.assertEqual(evaluation.report.problems(), ())
                self.assertEqual(evaluation.target.target_id, stage.target)

    def test_gates_hold_in_the_states_after_the_dry_run_step_too(self):
        okta = OktaStage()
        okta.candidate = replace(okta.candidate, state=S.OKTA_UNASSIGN_DRY_RUN)
        self.assertTrue(okta.gates().report.passed)

    def test_the_target_identity_comes_from_evidence(self):
        stage = AdStage()
        identity = dict(stage.gates().target.identity)
        ad = stage.evidence.ad_group
        self.assertEqual(identity, {"ad_group_id": ad.id, "object_guid": ad.object_guid, "domain": ad.domain,
                                    "sid": ad.sid, "distinguished_name": ad.distinguished_name,
                                    "sam_account_name": ad.sam_account_name})
        okta = dict(OktaStage().gates().target.identity)
        self.assertEqual(set(okta), {"application_id", "assignment_id", "okta_app_id", "okta_group_external_id",
                                     "okta_group_id"})


class ExecutionModeGateTests(unittest.TestCase):
    def test_only_modes_that_can_plan_pass(self):
        stage = OktaStage()
        for mode in (ExecutionMode.DRY_RUN_MUTATION, ExecutionMode.LOCAL_SYNTHETIC):
            with self.subTest(mode=mode):
                self.assertNotIn(Gate.EXECUTION_MODE_PERMITS_DRY_RUN, failed(stage.gates(mode=mode)))
        for mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.PRODUCTION_MUTATION, "DRY_RUN_MUTATION", None):
            with self.subTest(mode=mode):
                self.assertIn(Gate.EXECUTION_MODE_PERMITS_DRY_RUN, failed(stage.gates(mode=mode)))

    def test_a_request_can_name_no_mode_but_dry_run(self):
        stage = OktaStage()
        self.assertTrue(stage.gates(requested_mode=ExecutionMode.DRY_RUN_MUTATION).report.passed)
        for requested in (ExecutionMode.PRODUCTION_MUTATION, ExecutionMode.READ_ONLY_PRODUCTION,
                          ExecutionMode.LOCAL_SYNTHETIC, "PRODUCTION_MUTATION"):
            with self.subTest(requested=requested):
                self.assertEqual(failed(stage.gates(requested_mode=requested)), {Gate.EXECUTION_MODE_PERMITS_DRY_RUN})


class SingleExplicitTargetTests(unittest.TestCase):
    def test_the_target_must_be_one_id_of_the_operations_kind_in_scope(self):
        okta, ad = OktaStage(), AdStage()
        cases = [
            (okta, AD_ID), (okta, [ASSIGNMENT_ID]), (okta, (ASSIGNMENT_ID,)), (okta, "*"), (okta, ""), (okta, None),
            (okta, fixed_id(IdKind.ASSIGNMENT, 99)), (ad, ASSIGNMENT_ID), (ad, AD_ID_2), (ad, [AD_ID]), (ad, "adg_*"),
        ]
        for stage, target in cases:
            with self.subTest(operation=stage.operation, target=target):
                evaluation = stage.gates(target_ref=target)
                self.assertIn(Gate.SINGLE_EXPLICIT_TARGET, failed(evaluation))
                self.assertIsNone(evaluation.target)

    def test_a_target_cannot_be_built_from_a_pattern_or_without_identity(self):
        for identity in ((), (("sid", ""),), (("b", "1"), ("a", "2"))):
            with self.subTest(identity=identity), self.assertRaises(InvalidRecord):
                RemediationTarget(TargetKind.AD_GROUP, AD_ID, identity)
        with self.assertRaises(InvalidRecord):
            RemediationTarget(TargetKind.AD_GROUP, "adg_*", (("a", "1"),))


class MappingGateTests(unittest.TestCase):
    def test_only_an_exact_complete_mapping_of_an_existing_group_passes(self):
        stage = AdStage()
        for confidence in (MappingConfidence.NAME_ONLY, MappingConfidence.UNVERIFIED_STABLE_ID):
            with self.subTest(confidence=confidence):
                matched = ("sAMAccountName",) if confidence is MappingConfidence.NAME_ONLY else ("objectSid",)
                evidence = replace(stage.evidence, mapping=replace(stage.evidence.mapping, confidence=confidence,
                                                                  matched_attributes=matched))
                self.assertIn(Gate.EXACT_VERIFIED_MAPPING, failed(stage.gates(evidence=evidence)))
        partial = replace(stage.evidence.mapping, provenance=replace(stage.evidence.mapping.provenance,
                                                                     result_status=ResultStatus.PARTIAL))
        self.assertIn(Gate.EXACT_VERIFIED_MAPPING, failed(stage.gates(evidence=replace(stage.evidence, mapping=partial))))
        gone = replace(stage.evidence, ad_group=ad_group(stage.evidence.ad_group.provenance.observed_at, exists=False))
        self.assertIn(Gate.EXACT_VERIFIED_MAPPING, failed(stage.gates(evidence=gone)))
        self.assertIn(Gate.EXACT_VERIFIED_MAPPING, failed(stage.gates(evidence=replace(stage.evidence, mapping=None,
                                                                                      ad_group=None))))


class FreshEvidenceTests(unittest.TestCase):
    def test_stale_evidence_invalidates_an_otherwise_valid_approval(self):
        stage = OktaStage()
        later = stage.evidence.okta_group.provenance.observed_at + DAY + HOUR  # past the 24-hour EXECUTION window
        evaluation = stage.gates(now=later)
        self.assertIn(Gate.FRESH_EVIDENCE, failed(evaluation))
        self.assertNotIn(Gate.VALID_APPROVAL, failed(evaluation))  # the approval itself is still in force
        self.assertTrue(any("stale" in p for p in evaluation.report.problems()))

    def test_incomplete_and_future_dated_evidence_fail(self):
        stage = AdStage()
        ad = stage.evidence.ad_group
        partial = replace(ad, provenance=replace(ad.provenance, result_status=ResultStatus.PARTIAL))
        future = replace(ad, provenance=replace(ad.provenance, observed_at=stage.now + DAY))
        for record in (partial, future):
            with self.subTest(status=record.provenance.result_status):
                self.assertIn(Gate.FRESH_EVIDENCE, failed(stage.gates(evidence=replace(stage.evidence, ad_group=record))))


class ProtectionGateTests(unittest.TestCase):
    def test_every_protection_reason_blocks(self):
        stage = AdStage()
        at = stage.evidence.ad_group.provenance.observed_at
        protected = {
            "adminCount": ad_group(at, admin_count=True),
            "deletion protection": ad_group(at, protected_from_accidental_deletion=True),
            "critical": ad_group(at, is_critical_system_object=True),
            "well-known RID": ad_group(at, rid=512),
            "builtin SID": ad_group(at, sid="S-1-5-32-544"),
        }
        for label, record in protected.items():
            with self.subTest(label=label):
                self.assertIn(Gate.NOT_PROTECTED, failed(stage.gates(evidence=replace(stage.evidence, ad_group=record))))
        configured = replace(POLICY, protected_ad_object_guids=frozenset({stage.evidence.ad_group.object_guid}))
        self.assertIn(Gate.NOT_PROTECTED, failed(stage.gates(policy=configured)))

    def test_protection_that_cannot_be_determined_blocks(self):
        stage = AdStage()
        ad = stage.evidence.ad_group
        partial = replace(ad, provenance=replace(ad.provenance, result_status=ResultStatus.PARTIAL))
        self.assertIn(Gate.NOT_PROTECTED, failed(stage.gates(evidence=replace(stage.evidence, ad_group=partial))))

    def test_a_built_in_okta_group_is_protected_for_the_okta_operation(self):
        stage = OktaStage()
        group = replace(stage.evidence.okta_group, group_type=OktaGroupType.BUILT_IN, source_directory_id=None,
                        directory_external_id=None, directory_qualified_name=None)
        self.assertIn(Gate.NOT_PROTECTED, failed(stage.gates(evidence=replace(stage.evidence, okta_group=group))))


class ApprovalGateTests(unittest.TestCase):
    def test_each_invalid_approval_fails_the_approval_gate(self):
        stage = AdStage()
        a = stage.approval
        cases = {
            "missing": None,
            "rejected": replace(a, decision=ApprovalDecision.REJECT),
            "wrong stage": replace(a, stage=ApprovalStage.OKTA_UNASSIGN),
            "expired": replace(a, expires_at=a.decided_at + timedelta(minutes=30)),  # lapsed before stage.now
            "other candidate": replace(a, candidate_id=fixed_id(IdKind.CANDIDATE, 77)),
            "old epoch": replace(a, candidate_epoch=a.candidate_epoch + 1),
            "before the hold ended": replace(a, decided_at=Journey.T_HOLD_ENDS - HOUR, expires_at=stage.now + DAY),
            "same approver as the Okta stage (D11)": replace(a, operator=REVIEWER),
            "legacy AD_RETIREMENT": replace(a, stage=ApprovalStage.AD_RETIREMENT),
            "a deletion approval": replace(a, stage=ApprovalStage.AD_DELETION),
        }
        for label, record in cases.items():
            with self.subTest(label=label):
                self.assertIn(Gate.VALID_APPROVAL, failed(stage.gates(approval=record)))

    def test_the_deletion_approval_is_independent_and_new(self):
        """D143, D146: not by the proposer or an earlier approver; not given before the proposal."""
        stage = DeletionStage()
        a = stage.approval
        cases = {
            "by the deletion proposer": replace(a, operator=THIRD_REVIEWER),
            "by the quarantine approver": replace(a, operator=SECOND_REVIEWER),
            "by the Okta approver": replace(a, operator=REVIEWER),
            "before the proposal": replace(a, decided_at=Journey.T_DELETION_PROPOSED - HOUR),
            "before the post-quarantine hold ended": replace(a, decided_at=Journey.T_QUARANTINE_HOLD_ENDS - HOUR),
            "the quarantine approval": stage.journey.quarantine_approval,
            "the Okta approval": stage.journey.unassign_approval,
            "legacy AD_RETIREMENT": replace(a, stage=ApprovalStage.AD_RETIREMENT),
        }
        for label, record in cases.items():
            with self.subTest(label=label):
                self.assertIn(Gate.VALID_APPROVAL, failed(stage.gates(approval=record)))
        self.assertEqual(failed(stage.gates()), set())


class FingerprintAndIdentityTests(unittest.TestCase):
    def test_a_material_evidence_change_fails_the_fingerprint_gate(self):
        stage = OktaStage()
        changed = replace(stage.evidence, usage=(replace(stage.evidence.usage[0], event_count=0, distinct_user_count=0,
                                                         window_start=stage.evidence.usage[0].window_start - DAY),))
        self.assertEqual(failed(stage.gates(evidence=changed)), {Gate.APPROVAL_FINGERPRINT_MATCHES})

    def test_changing_the_target_identity_invalidates_the_approval(self):
        stage = AdStage()
        ad = stage.evidence.ad_group
        changes = {
            "objectSid": replace(ad, sid=f"{SYNTHETIC_DOMAIN_SID}-9999"),
            "distinguishedName (renamed or moved)": replace(ad, distinguished_name="CN=SYNTH-OTHER,OU=Groups,DC=corp,"
                                                                                   "DC=synthetic,DC=example"),
            "sAMAccountName": replace(ad, sam_account_name="SYNTH-OTHER"),
            "objectGUID": replace(ad, object_guid="5e1f0c3a-0000-4000-8000-000000000099"),
            "domain": replace(ad, domain="emea.synthetic.example"),
        }
        approved_identity = stage.gates().target.identity_digest
        for label, record in changes.items():
            with self.subTest(label=label):
                evaluation = stage.gates(evidence=replace(stage.evidence, ad_group=record))
                self.assertIn(Gate.APPROVAL_FINGERPRINT_MATCHES, failed(evaluation))
                self.assertFalse(evaluation.report.passed)
                self.assertNotEqual(evaluation.target.identity_digest, approved_identity)

    def test_a_mapping_repointed_to_another_group_invalidates_target_and_approval(self):
        stage = AdStage()
        other = ad_group(stage.evidence.ad_group.provenance.observed_at, id=AD_ID_2,
                         object_guid="5e1f0c3a-0000-4000-8000-000000000002", rid=4322)
        moved = replace(stage.evidence, mapping=replace(stage.evidence.mapping, ad_group_id=AD_ID_2), ad_group=other,
                        dependencies=tuple(replace(d, subject_id=AD_ID_2) if d.subject_id == AD_ID else d
                                           for d in stage.evidence.dependencies))
        evaluation = stage.gates(evidence=moved)
        self.assertTrue({Gate.SINGLE_EXPLICIT_TARGET, Gate.APPROVAL_FINGERPRINT_MATCHES} <= failed(evaluation))
        self.assertIsNone(evaluation.target)


class DependencyGateTests(unittest.TestCase):
    def test_a_blocking_finding_blocks_every_operation(self):
        for stage in (OktaStage(), AdStage(), DeletionStage()):
            at = stage.evidence.ad_group.provenance.observed_at
            deps = tuple(dependency(at, d.kind, n, findings=(blocking_finding(),) if d.kind is DependencyKind.AD_ACL_REFERENCE
                                    else ()) for n, d in enumerate(stage.evidence.dependencies, start=1))
            with self.subTest(operation=stage.operation):
                self.assertIn(Gate.NO_DEPENDENCY_BLOCKER, failed(stage.gates(evidence=replace(stage.evidence,
                                                                                           dependencies=deps))))

    def test_members_or_an_unknown_member_count_block_every_operation(self):
        for stage in (OktaStage(), AdStage(), DeletionStage()):
            for count in (3, None):
                ad = replace(stage.evidence.ad_group, member_count=count)
                with self.subTest(operation=stage.operation, count=count):
                    self.assertIn(Gate.NO_DEPENDENCY_BLOCKER,
                                  failed(stage.gates(evidence=replace(stage.evidence, ad_group=ad))))

    def test_ad_operations_need_complete_coverage_and_okta_unassignment_does_not(self):
        okta, ad = OktaStage(), AdStage()
        partial_kinds = tuple(d for d in ad.evidence.dependencies if d.kind is not DependencyKind.AD_ACL_REFERENCE)
        self.assertIn(Gate.NO_DEPENDENCY_BLOCKER, failed(ad.gates(evidence=replace(ad.evidence, dependencies=partial_kinds))))
        okta_partial = tuple(d for d in okta.evidence.dependencies if d.kind is not DependencyKind.AD_ACL_REFERENCE)
        evaluation = okta.gates(evidence=replace(okta.evidence, dependencies=okta_partial))
        self.assertNotIn(Gate.NO_DEPENDENCY_BLOCKER, failed(evaluation))  # D131


class MembershipEvidenceTests(unittest.TestCase):
    """D132: known members, or missing or incomplete membership evidence, block every operation."""

    def stages(self):
        return (OktaStage(), AdStage(), DeletionStage())

    def test_a_missing_membership_check_blocks_every_operation(self):
        for kind in (DependencyKind.AD_GROUP_MEMBERS, DependencyKind.AD_NESTED_MEMBERSHIP):
            for stage in self.stages():
                without = tuple(d for d in stage.evidence.dependencies if d.kind is not kind)
                with self.subTest(kind=kind, operation=stage.operation):
                    evaluation = stage.gates(evidence=replace(stage.evidence, dependencies=without))
                    self.assertIn(Gate.NO_DEPENDENCY_BLOCKER, failed(evaluation))
                    self.assertTrue(any(f"no {kind.value} check" in p and "D132" in p
                                        for p in evaluation.report.problems()))

    def test_an_incomplete_membership_check_blocks_every_operation(self):
        for status in (ResultStatus.PARTIAL, ResultStatus.FAILED):
            for stage in self.stages():
                deps = tuple(replace(d, provenance=replace(d.provenance, result_status=status))
                             if d.kind is DependencyKind.AD_NESTED_MEMBERSHIP else d for d in stage.evidence.dependencies)
                with self.subTest(status=status, operation=stage.operation):
                    evaluation = stage.gates(evidence=replace(stage.evidence, dependencies=deps))
                    self.assertTrue(any(f"is {status.value}: incomplete membership" in p
                                        for p in evaluation.report.problems()))

    def test_a_membership_check_of_another_subject_does_not_count(self):
        for stage in self.stages():
            deps = tuple(replace(d, subject_id=AD_ID_2) if d.kind is DependencyKind.AD_GROUP_MEMBERS else d
                         for d in stage.evidence.dependencies)
            with self.subTest(operation=stage.operation):
                self.assertIn(Gate.NO_DEPENDENCY_BLOCKER,
                              failed(stage.gates(evidence=replace(stage.evidence, dependencies=deps))))

    def test_complete_empty_membership_evidence_passes_for_the_okta_unassignment(self):
        # Only the membership kinds and the Okta-side checks: no AD coverage is needed (D131, D132).
        stage = OktaStage()
        keep = {DependencyKind.AD_GROUP_MEMBERS, DependencyKind.AD_NESTED_MEMBERSHIP}
        minimal = tuple(d for d in stage.evidence.dependencies if d.kind in keep)
        self.assertNotIn(Gate.NO_DEPENDENCY_BLOCKER, failed(stage.gates(evidence=replace(stage.evidence,
                                                                                        dependencies=minimal))))


class DeletionStageTests(unittest.TestCase):
    """D128-D130, D143-D147: quarantine and deletion are separate stages. Only an AD_DELETION
    approval, in the deletion stage, with the group in its quarantine OU, authorizes a deletion
    dry run; nothing else does."""

    def test_the_approval_that_authorizes_quarantine_never_authorizes_deletion(self):
        quarantine = AdStage()
        self.assertTrue(quarantine.gates().report.passed)
        deletion = quarantine.gates(operation=O.AD_GROUP_DELETE)  # the same candidate, evidence, and approval
        self.assertEqual(failed(deletion), {Gate.VALID_APPROVAL, Gate.LIFECYCLE_RULES})
        self.assertTrue(any("not AD_DELETION" in p for p in deletion.report.problems()))

    def test_no_other_approval_and_no_other_state_can_reach_deletion(self):
        stage = DeletionStage()
        legacy = approval(stage.candidate, ApprovalStage.AD_RETIREMENT, Journey.T_DELETION_APPROVE, stage.evidence,
                          operator=Actor(ActorKind.HUMAN, "synthetic-fifth-reviewer"))
        for record in (stage.journey.quarantine_approval, stage.journey.unassign_approval, legacy, None):
            with self.subTest(approval=record and record.stage):
                self.assertIn(Gate.VALID_APPROVAL, failed(stage.gates(approval=record)))
        for state in (S.REVALIDATION_REQUIRED, S.QUARANTINE_APPROVED, S.QUARANTINE_HOLD,
                      S.DELETION_REVALIDATION_REQUIRED, S.DELETION_PROPOSED):
            candidate = Journey().to(state).candidate
            with self.subTest(state=state):
                self.assertIn(Gate.LIFECYCLE_RULES, failed(stage.gates(candidate=candidate)))
        legacy_state = replace(AdStage().candidate, state=S.RETIREMENT_DRY_RUN, quarantine_approver=None)
        self.assertIn(Gate.LIFECYCLE_RULES, failed(stage.gates(candidate=legacy_state)))

    def test_a_deletion_needs_the_group_in_its_quarantine_ou(self):
        stage = DeletionStage()
        moved_out = replace(stage.evidence, ad_group=ad_group(stage.evidence.ad_group.provenance.observed_at))
        evaluation = stage.gates(evidence=moved_out)
        self.assertIn(Gate.LIFECYCLE_RULES, failed(evaluation))
        self.assertTrue(any("not in its domain's quarantine OU" in p for p in evaluation.report.problems()))
        self.assertIn(Gate.LIFECYCLE_RULES, failed(stage.gates(quarantine_ous=None)))

    def test_a_quarantine_needs_the_group_outside_it_and_a_configured_ou(self):
        stage = AdStage()
        inside = replace(stage.evidence, ad_group=ad_group(stage.evidence.ad_group.provenance.observed_at,
                                                           quarantined=True))
        self.assertIn(Gate.LIFECYCLE_RULES, failed(stage.gates(evidence=inside)))
        evaluation = stage.gates(quarantine_ous=None)
        self.assertIn(Gate.LIFECYCLE_RULES, failed(evaluation))
        self.assertTrue(any("D136" in p for p in evaluation.report.problems()))

    def test_a_blocked_deletion_still_resolves_its_target_but_plans_nothing(self):
        evaluation = AdStage().gates(operation=O.AD_GROUP_DELETE)
        self.assertEqual(evaluation.target.target_id, AD_ID)  # the explicit target is still checked
        with self.assertRaises(InvalidRecord):
            RemediationResult(O.AD_GROUP_DELETE, RemediationOutcome.SIMULATED, "SYNTHETIC", evaluation.report,
                              evaluation.target, (PlannedChange("ad", "delete_group", AD_ID, "Delete."),))

    def test_the_deletion_stage_passes_every_gate_with_its_own_approval(self):
        stage = DeletionStage()
        self.assertEqual(stage.gates().report.problems(), ())
        dry_run = replace(stage.candidate, state=S.DELETION_DRY_RUN)
        self.assertTrue(stage.gates(candidate=dry_run).report.passed)
        self.assertNotIn(FOURTH_REVIEWER, (REVIEWER, SECOND_REVIEWER, THIRD_REVIEWER))


class SeparationAndLifecycleTests(unittest.TestCase):
    def test_the_approver_or_a_system_actor_cannot_request_it(self):
        stage = AdStage()
        self.assertEqual(failed(stage.gates(requested_by=SECOND_REVIEWER)), {Gate.SEPARATION_OF_DUTIES})
        self.assertIn(Gate.SEPARATION_OF_DUTIES, failed(stage.gates(requested_by=Actor(ActorKind.SYSTEM, "ogwa/x"))))

    def test_the_candidate_must_be_at_the_operations_stage(self):
        okta, ad = OktaStage(), AdStage()
        self.assertIn(Gate.LIFECYCLE_RULES, failed(okta.gates(operation=O.AD_GROUP_DELETE, target_ref=AD_ID)))
        self.assertIn(Gate.LIFECYCLE_RULES, failed(ad.gates(operation=O.OKTA_GROUP_UNASSIGN, target_ref=ASSIGNMENT_ID)))
        elsewhere = [Journey().to(state).candidate for state in (S.NEEDS_REVIEW, S.HOLD, S.RETIRED)]
        elsewhere += [replace(okta.candidate, state=S.BLOCKED, blocked_from=S.APPROVED),
                      replace(okta.candidate, state=S.PROTECTED)]
        for candidate in elsewhere:
            with self.subTest(state=candidate.state):
                self.assertIn(Gate.LIFECYCLE_RULES, failed(okta.gates(candidate=candidate)))

    def test_lifecycle_rules_are_checked_too(self):
        okta = OktaStage()
        okta_only = replace(okta.evidence.okta_group, group_type=OktaGroupType.OKTA_GROUP, source_directory_id=None,
                            directory_external_id=None, directory_qualified_name=None)
        self.assertIn(Gate.LIFECYCLE_RULES, failed(okta.gates(evidence=replace(okta.evidence, okta_group=okta_only))))
        removed = bundle(okta.evidence.okta_group.provenance.observed_at, present=False)
        self.assertIn(Gate.LIFECYCLE_RULES, failed(okta.gates(evidence=removed)))
        used = bundle(okta.evidence.okta_group.provenance.observed_at, usage_events=3)
        self.assertIn(Gate.LIFECYCLE_RULES, failed(okta.gates(evidence=used)))
        ad = AdStage()
        readded = replace(ad.evidence, assignments=(replace(ad.evidence.assignments[0], present=True),))
        self.assertIn(Gate.LIFECYCLE_RULES, failed(ad.gates(evidence=readded)))

    def test_every_gate_is_evaluated_so_every_reason_is_reported(self):
        stage = OktaStage()
        evaluation = stage.gates(mode=ExecutionMode.READ_ONLY_PRODUCTION, requested_by=REVIEWER,
                                 now=stage.now + 2 * DAY, target_ref=AD_ID)
        self.assertTrue({Gate.EXECUTION_MODE_PERMITS_DRY_RUN, Gate.SEPARATION_OF_DUTIES, Gate.FRESH_EVIDENCE,
                         Gate.SINGLE_EXPLICIT_TARGET} <= failed(evaluation))


class PurityTests(unittest.TestCase):
    def test_the_remediation_domain_module_performs_no_io(self):
        tree = ast.parse((REPO_ROOT / "app" / "domain" / "remediation.py").read_text(encoding="utf-8"))
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual({m for m in imported if not m.startswith(("app.domain", "app.core.modes", "collections",
                                                                   "dataclasses", "datetime", "enum", "typing"))}, set())

    def test_resolution_is_read_only(self):
        stage = AdStage()
        before = (stage.candidate, stage.evidence)
        resolve_target(stage.candidate, O.AD_GROUP_DELETE, AD_ID, stage.evidence)
        stage.gates()
        self.assertEqual((stage.candidate, stage.evidence), before)


if __name__ == "__main__":
    unittest.main()
