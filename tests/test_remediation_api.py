"""Remediation dry runs through the operator API, over a seeded synthetic world.

Five safety properties each have a class here:

- ``ValidApprovalCannotMutateProductionTests``: a fully valid approval yields only
  SIMULATED or VALIDATION_ONLY; no network, socket, process, or execution path is touched;
- ``ProductionMutationSelectionTests``: every way of asking for production mutation is
  refused;
- ``StaleEvidenceTests``: stale evidence invalidates an approval that is otherwise in force;
- ``TargetIdentityTests``: a changed target identity invalidates the approval;
- ``ProtectedGroupTests``: no operator, role, permission, or field overrides protection.

``AntiFootgunTests`` covers the controls: one explicit target, no bulk or execute route,
no browser-chosen template, the server-side allowlist, and the audit trail.
"""

import ast
import http.client
import json
import socket
import subprocess
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.api import authz
from app.api.authz import ROLE_PERMISSIONS, Permission, Principal, Role
from app.api.local import build_local_api
from app.api.routes import ROUTES
from app.api.services import DEMO_SOURCE, PolicyInForce
from app.core.config import load_settings
from app.core.errors import ConfigError, ProductionMutationNotPermitted
from app.core.modes import ExecutionMode
from app.core.safety import MutationPolicy
from app.demo.synthetic_world import COLLECTOR
from app.demo.synthetic_world import POLICY as DEMO_LIFECYCLE_POLICY
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction, AuditResult
from app.domain.candidate_policy import CandidatePolicy
from app.domain.errors import InvalidRecord
from app.domain.ids import IdKind, new_id
from app.domain.lifecycle import LifecycleState
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.model import DependencyEvidence
from app.domain.remediation import MEMBERSHIP_KINDS, Gate, RemediationOperation, RemediationOutcome, RemediationResult
from app.remediation import adapters
from app.remediation.aap import SurveyQuestion, TemplateKind, TemplateMetadata
from app.remediation.allowlist import ALLOWLIST_FORMAT, parse_allowlist
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreConflict
from tests.api_fixtures import (
    ADMIN,
    ALL_PRINCIPALS,
    APPROVER_EXECUTOR,
    AUTOMATION,
    DUAL,
    EXECUTOR,
    SECURITY,
    SECURITY_2,
    VIEWER,
    World,
)

V = "/api/v1"
S = LifecycleState
REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEWED_PLAYBOOK = "playbooks/ogwa_remediation_whatif.yml"
REVIEWED_REVISION = "5e7e70005e7e70005e7e70005e7e70005e7e7000"
QUARANTINE_OU = "OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example"


def world(allowlist=None, templates=None) -> World:
    """A seeded synthetic world. Its API uses the given allowlist, or the synthetic config file."""
    w = World()
    if allowlist is not None or templates is not None:
        w.api = build_local_api(w.store, clock=w.clock, logger=w.api.log, remediation_allowlist=allowlist,
                                remediation_templates=templates)
    return w


def record_membership(w: World, candidate: str) -> None:
    """Record COMPLETE, empty membership checks of the candidate's mapped AD group (D132).

    S07 is seeded with no dependency check at all; a remediation needs at least these."""
    bundle = w.store.evidence_bundle(w.store.load_candidate(candidate))
    have = {d.kind for d in bundle.dependencies if d.subject_id == bundle.ad_group.id}
    for kind in MEMBERSHIP_KINDS:
        if kind not in have:
            w.store.record_evidence(DependencyEvidence(
                new_id(IdKind.DEPENDENCY_EVIDENCE), bundle.ad_group.id, kind, (),
                Provenance(EvidenceSource.SYNTHETIC, w.clock(), f"synthetic:deps:test:{kind.value}", "synthetic-test-1.0",
                           ResultStatus.COMPLETE)), actor=COLLECTOR)


def approve_okta(w: World, key: str = "S07", approver: str = SECURITY, membership: bool = True) -> tuple[str, str]:
    """Approve the Okta unassignment of a NEEDS_REVIEW scenario; (candidate id, approval id).

    With ``membership``, complete membership evidence is recorded first (D132)."""
    candidate = w.candidate(key)
    if membership:
        record_membership(w, candidate)
    client = w.client(approver)
    result = client.post(f"{V}/candidates/{candidate}/approvals", {
        "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "synthetic review",
        "expectedEvidenceFingerprint": w.fingerprint(client, candidate)})
    assert result.status == 201, result.json
    w.refresh_evidence(candidate)
    return candidate, result.json["approval"]["id"]


def approve_ad(w: World, approver: str = SECURITY_2) -> tuple[str, str]:
    """Walk S01 from its hold to an AD_QUARANTINE approval, which moves it to
    QUARANTINE_APPROVED; (candidate id, approval id)."""
    candidate = w.candidate("S01")
    w.clock.advance(timedelta(days=29))  # past S01's hold period
    w.refresh_evidence(candidate)
    automation = w.client(AUTOMATION)
    result = automation.post(f"{V}/candidates/{candidate}/transitions", {
        "target": "REVALIDATION_REQUIRED", "reason": "hold ended",
        "expectedEvidenceFingerprint": w.fingerprint(automation, candidate)})
    assert result.status == 201, result.json
    client = w.client(approver)
    result = client.post(f"{V}/candidates/{candidate}/approvals", {
        "stage": "AD_QUARANTINE", "decision": "APPROVE", "reason": "synthetic review",
        "expectedEvidenceFingerprint": w.fingerprint(client, candidate)})
    assert result.status == 201, result.json
    return candidate, result.json["approval"]["id"]


def approve_deletion(w: World, approver: str = SECURITY) -> tuple[str, str]:
    """Approve S16's proposed deletion, which moves it to DELETION_APPROVED; (candidate id,
    approval id). S16 was quarantined, held 30 days, revalidated, and proposed by a third
    reviewer; ``approver`` approved none of its stages (D143)."""
    candidate = w.candidate("S16")
    client = w.client(approver)
    result = client.post(f"{V}/candidates/{candidate}/approvals", {
        "stage": "AD_DELETION", "decision": "APPROVE", "reason": "synthetic deletion review",
        "expectedEvidenceFingerprint": w.fingerprint(client, candidate)})
    assert result.status == 201, result.json
    return candidate, result.json["approval"]["id"]


def target_of(w: World, candidate: str, operation: str) -> dict:
    loaded = w.store.load_candidate(candidate)
    if operation == "OKTA_GROUP_UNASSIGN":
        return {"assignmentId": loaded.assignment_ids[0]}
    return {"adGroupId": w.store.evidence_bundle(loaded).ad_group.id}


def dry_run(w: World, client, candidate: str, approval: str, operation: str = "OKTA_GROUP_UNASSIGN", **extra):
    # The fingerprint the operator saw, read by a viewer: a principal without any role
    # cannot read it, and must still be refused by the remediation route itself.
    body = {"operation": operation, "target": target_of(w, candidate, operation), "approvalId": approval,
            "expectedEvidenceFingerprint": w.fingerprint(w.client(VIEWER), candidate)}
    body.update(extra)
    return client.post(f"{V}/candidates/{candidate}/remediation-dry-runs", body)


def events(w: World, action: AuditAction, subject: str | None = None):
    return [e for e in w.store.audit_events() if e.action is action and (subject is None or e.subject_id == subject)]


def chained(w: World, result):
    request_id = result.header("x-request-id")
    return [e for e in w.store.audit_events() if e.correlation_id == request_id]


def failed_gates(result) -> set[str]:
    return {g["gate"] for g in result.json["error"]["gates"] if not g["passed"]}


def aap_allowlist(template_id: int = 4101):
    return parse_allowlist({
        "format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC",
        "operations": {
            "OKTA_GROUP_UNASSIGN": {"adapter": "SYNTHETIC"},
            "AD_GROUP_QUARANTINE": {"adapter": "AAP", "jobTemplateId": template_id,
                                    "jobTemplateName": "SYNTHETIC OGWA AD group quarantine (WhatIf)",
                                    "requestVariable": "ogwa_remediation_request",
                                    "reviewedPlaybook": REVIEWED_PLAYBOOK, "reviewedProjectId": 7,
                                    "reviewedProjectRevision": REVIEWED_REVISION},
        }}, environment=DatabaseEnvironment.SYNTHETIC)


def observed_template(template_id: int = 4101, **changes) -> TemplateMetadata:
    fields = dict(kind=TemplateKind.JOB_TEMPLATE, template_id=template_id,
                  name="SYNTHETIC OGWA AD group quarantine (WhatIf)", job_type="check", playbook=REVIEWED_PLAYBOOK,
                  project_id=7, ask_job_type_on_launch=False, ask_variables_on_launch=False,
                  ask_scm_branch_on_launch=False, ask_inventory_on_launch=False, ask_credential_on_launch=False,
                  survey_enabled=True, survey=(SurveyQuestion("ogwa_remediation_request", "textarea", True),),
                  project_revision=REVIEWED_REVISION)
    fields.update(changes)
    return TemplateMetadata(**fields)


# --- proof 1: a valid approval still cannot cause production mutation ---------------------


class ValidApprovalCannotMutateProductionTests(unittest.TestCase):
    def setUp(self):
        self.world = world()
        self.addCleanup(self.world.close)

    def assert_nothing_changed_outside_ogwa(self, candidate, state, jobs_before):
        """The candidate did not move, and no execution job was planned or recorded."""
        self.assertIs(self.world.store.load_candidate(candidate).state, state)
        self.assertEqual(self.world.api.read.job_ids_for(candidate), jobs_before)

    def test_a_valid_okta_approval_is_only_simulated(self):
        candidate, approval = approve_okta(self.world)
        jobs = self.world.api.read.job_ids_for(candidate)
        result = dry_run(self.world, self.world.client(EXECUTOR), candidate, approval)
        self.assertEqual(result.status, 201, result.json)
        body = result.json
        self.assertEqual(body["remediation"]["outcome"], "SIMULATED")
        self.assertEqual((body["executed"], body["productionMutation"]), (False, False))
        self.assertEqual((body["remediation"]["executed"], body["remediation"]["productionMutation"]), (False, False))
        self.assertTrue(all(g["passed"] for g in body["remediation"]["gates"]))
        self.assert_nothing_changed_outside_ogwa(candidate, S.APPROVED, jobs)
        recorded = events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED, candidate)
        self.assertEqual(len(recorded), 1)
        details = dict(recorded[0].details)
        self.assertEqual((details["outcome"], details["executed"], details["production_mutation"]),
                         ("SIMULATED", "false", "false"))
        self.assertEqual(body["auditEventId"], recorded[0].id)

    def test_a_valid_ad_approval_only_simulates_quarantine_and_never_authorizes_deletion(self):
        candidate, approval = approve_ad(self.world)
        jobs = self.world.api.read.job_ids_for(candidate)  # the seed's Okta dry run
        executor = self.world.client(EXECUTOR)
        result = dry_run(self.world, executor, candidate, approval, "AD_GROUP_QUARANTINE")
        self.assertEqual(result.status, 201, result.json)
        self.assertEqual(result.json["remediation"]["outcome"], "SIMULATED")
        self.assertEqual(result.json["remediation"]["plannedChanges"][0]["action"], "move_group_to_quarantine")
        deletion = dry_run(self.world, executor, candidate, approval, "AD_GROUP_DELETE")  # same approval (D128)
        self.assertEqual((deletion.status, deletion.code), (409, "REMEDIATION_BLOCKED"))
        self.assertEqual(failed_gates(deletion), {"VALID_APPROVAL", "LIFECYCLE_RULES"})
        self.assertNotIn("plannedChanges", json.dumps(deletion.json))
        moved = result.json["remediation"]["plannedChanges"][0]["details"]["after.distinguishedName"]
        self.assertTrue(moved.endswith(",OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example"), moved)
        self.assert_nothing_changed_outside_ogwa(candidate, S.QUARANTINE_APPROVED, jobs)
        group = self.world.store.evidence_bundle(self.world.store.load_candidate(candidate)).ad_group
        self.assertTrue(group.exists)  # the store still records the group as present: nothing was deleted

    def test_a_valid_deletion_approval_only_simulates_the_deletion(self):
        """The deletion stage's own approval yields a SIMULATED plan, and nothing more."""
        candidate, approval = approve_deletion(self.world)
        jobs = self.world.api.read.job_ids_for(candidate)
        executor = self.world.client(EXECUTOR)
        result = dry_run(self.world, executor, candidate, approval, "AD_GROUP_DELETE")
        self.assertEqual(result.status, 201, result.json)
        remediation = result.json["remediation"]
        self.assertEqual((remediation["outcome"], remediation["executed"], remediation["productionMutation"]),
                         ("SIMULATED", False, False))
        self.assertEqual(remediation["plannedChanges"][0]["action"], "delete_group")
        quarantine = dry_run(self.world, executor, candidate, approval, "AD_GROUP_QUARANTINE")
        self.assertEqual(failed_gates(quarantine), {"VALID_APPROVAL", "LIFECYCLE_RULES"})
        self.assert_nothing_changed_outside_ogwa(candidate, S.DELETION_APPROVED, jobs)
        group = self.world.store.evidence_bundle(self.world.store.load_candidate(candidate)).ad_group
        self.assertTrue(group.exists)  # still recorded as present: OGWA deleted nothing

    def test_no_socket_connection_or_process_is_used(self):
        candidate, approval = approve_okta(self.world)
        executor = self.world.client(EXECUTOR)
        boom = AssertionError("a remediation dry run tried to reach outside the process")
        with mock.patch.object(socket.socket, "connect", side_effect=boom) as connect, \
                mock.patch.object(socket, "create_connection", side_effect=boom) as create, \
                mock.patch.object(http.client.HTTPConnection, "connect", side_effect=boom) as http_connect, \
                mock.patch.object(subprocess, "Popen", side_effect=boom) as popen:
            result = dry_run(self.world, executor, candidate, approval)
        self.assertEqual(result.status, 201, result.json)
        for patched in (connect, create, http_connect, popen):
            patched.assert_not_called()

    def test_every_adapter_only_plans(self):
        candidate, approval = approve_okta(self.world)
        executor = self.world.client(EXECUTOR)
        with mock.patch.object(adapters.RemediationAdapter, "_never",
                               side_effect=AssertionError("an adapter executed")) as never, \
                self.assertLogs("ogwa.mutation", level="INFO") as logs:
            result = dry_run(self.world, executor, candidate, approval)
        self.assertEqual(result.status, 201, result.json)
        never.assert_not_called()
        decisions = [r.ogwa["decision"] for r in logs.records if hasattr(r, "ogwa")]
        self.assertEqual(decisions, ["PLAN_ONLY"])
        for adapter in (adapters.SyntheticRemediationAdapter(), adapters.AapRemediationAdapter()):
            with self.subTest(adapter=adapter.name):
                self.assertIs(adapter.mutation_policy.mode, ExecutionMode.DRY_RUN_MUTATION)

    def test_even_every_permission_cannot_turn_a_dry_run_into_an_execution(self):
        candidate, approval = approve_okta(self.world)
        jobs = self.world.api.read.job_ids_for(candidate)
        everything = {role: frozenset(Permission) for role in ROLE_PERMISSIONS}
        with mock.patch.dict(authz.ROLE_PERMISSIONS, everything):
            client = self.world.client(DUAL)  # holds every permission now, and did not approve
            result = dry_run(self.world, client, candidate, approval)
            self.assertEqual(result.json["remediation"]["outcome"], "SIMULATED")
            job = self.world.api.read.job_ids_for(self.world.candidate("S14"))[0]
            refused = client.post(f"{V}/execution-jobs/{job}/execute", {})
            self.assertEqual((refused.status, refused.code), (403, "PRODUCTION_MUTATION_REFUSED"))
        self.assert_nothing_changed_outside_ogwa(candidate, S.APPROVED, jobs)

    def test_the_aap_path_validates_a_reviewed_template_and_never_launches(self):
        w = world(aap_allowlist(), {4101: observed_template()})
        self.addCleanup(w.close)
        candidate, approval = approve_ad(w)
        boom = AssertionError("the AAP adapter tried to send")
        with mock.patch.object(socket.socket, "connect", side_effect=boom), \
                mock.patch.object(http.client.HTTPConnection, "connect", side_effect=boom):
            result = dry_run(w, w.client(EXECUTOR), candidate, approval, "AD_GROUP_QUARANTINE")
        self.assertEqual(result.status, 201, result.json)
        remediation = result.json["remediation"]
        self.assertEqual((remediation["outcome"], remediation["adapter"]), ("VALIDATION_ONLY", "AAP"))
        change = remediation["plannedChanges"][0]
        self.assertEqual((change["system"], change["action"]), ("aap", "launch_job_template"))
        self.assertIn("Not sent", change["summary"])
        self.assertEqual(change["details"]["worker_mode"], "WhatIf")
        self.assertFalse(hasattr(adapters.AapRemediationAdapter(), "_http"))

    def test_an_aap_template_that_is_not_known_read_only_is_blocked(self):
        cases = {
            "not observed": {},
            "run mode": {4101: observed_template(job_type="run")},
            "job type switchable at launch": {4101: observed_template(ask_job_type_on_launch=True)},
            "playbook revision drifted": {4101: observed_template(project_revision="0" * 40)},
            "extra variables at launch": {4101: observed_template(ask_variables_on_launch=True)},
            "workflow": {4101: observed_template(kind=TemplateKind.WORKFLOW_JOB_TEMPLATE, job_type=None)},
        }
        for label, templates in cases.items():
            with self.subTest(label=label):
                w = world(aap_allowlist(), templates)
                candidate, approval = approve_ad(w)
                result = dry_run(w, w.client(EXECUTOR), candidate, approval, "AD_GROUP_QUARANTINE")
                self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"), result.json)
                self.assertEqual(result.json["error"]["outcome"], "BLOCKED")
                self.assertTrue(any(p.startswith("ADAPTER AAP:") for p in result.json["error"]["problems"]))
                self.assertEqual(events(w, AuditAction.REMEDIATION_DRY_RUN_RECORDED), [])
                w.close()

    def test_the_store_cannot_record_an_execution_or_a_blocked_dry_run(self):
        candidate, approval = approve_okta(self.world)
        result = dry_run(self.world, self.world.client(EXECUTOR), candidate, approval)
        self.assertEqual(result.status, 201)
        from app.domain.remediation import blocked, evaluate_gates  # noqa: PLC0415
        from app.api.services import policy_in_force  # noqa: PLC0415
        loaded = self.world.store.load_candidate(candidate)
        bundle = self.world.store.evidence_bundle(loaded)
        evaluation = evaluate_gates(loaded, RemediationOperation.OKTA_GROUP_UNASSIGN, loaded.assignment_ids[0], bundle,
                                    self.world.store.load_approval(approval),
                                    policy_in_force(self.world.store).policy.lifecycle, now=self.world.clock(),
                                    mode=ExecutionMode.LOCAL_SYNTHETIC, requested_by=Actor(ActorKind.HUMAN, EXECUTOR))
        with self.assertRaises(InvalidRecord):
            RemediationResult(RemediationOperation.OKTA_GROUP_UNASSIGN, RemediationOutcome.SIMULATED, "SYNTHETIC",
                              evaluation.report, evaluation.target, executed=True)
        refusal = blocked(RemediationOperation.OKTA_GROUP_UNASSIGN, evaluation.report, adapter="NONE",
                          notes=("synthetic refusal",))
        with self.assertRaisesRegex(StoreConflict, "refusal"):
            self.world.store.record_remediation_dry_run(
                actor=Actor(ActorKind.HUMAN, EXECUTOR), candidate_id=candidate, result=refusal, approval_id=approval,
                evidence_fingerprint=evaluation.fingerprint, correlation_id=new_id(IdKind.REQUEST))


# --- proof 2: selecting production mutation is rejected -----------------------------------


class ProductionMutationSelectionTests(unittest.TestCase):
    def setUp(self):
        self.world = world()
        self.addCleanup(self.world.close)
        self.candidate, self.approval = approve_okta(self.world)

    def test_production_mutation_and_non_dry_runs_are_refused_before_anything_else(self):
        for subject in (EXECUTOR, APPROVER_EXECUTOR):
            client = self.world.client(subject)
            for extra in ({"executionMode": "PRODUCTION_MUTATION"}, {"dryRun": False},
                          {"executionMode": "PRODUCTION_MUTATION", "dryRun": False},
                          {"executionMode": "PRODUCTION_MUTATION", "operation": "NOT_AN_OPERATION"}):
                with self.subTest(subject=subject, extra=extra):
                    result = dry_run(self.world, client, self.candidate, self.approval, **extra)
                    self.assertEqual((result.status, result.code), (403, "PRODUCTION_MUTATION_REFUSED"), result.json)
                    self.assertEqual([e.action for e in chained(self.world, result)],
                                     [AuditAction.GOVERNED_REQUEST_REFUSED])
        self.assertEqual(events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED), [])

    def test_principals_without_the_execution_function_get_an_ordinary_refusal(self):
        for subject in (VIEWER, AUTOMATION, SECURITY, ADMIN, DUAL):
            client = self.world.client(subject)
            with self.subTest(subject=subject):
                result = dry_run(self.world, client, self.candidate, self.approval,
                                 executionMode="PRODUCTION_MUTATION")
                self.assertEqual((result.status, result.code), (403, "FORBIDDEN"))
                self.assertEqual(chained(self.world, result), [])  # D64: stays in the security log

    def test_no_other_mode_can_be_requested(self):
        client = self.world.client(EXECUTOR)
        for mode in ("READ_ONLY_PRODUCTION", "LOCAL_SYNTHETIC", "production_mutation", "EXECUTE", 1, True):
            with self.subTest(mode=mode):
                result = dry_run(self.world, client, self.candidate, self.approval, executionMode=mode)
                self.assertEqual((result.status, result.code), (422, "VALIDATION_FAILED"))
        ok = dry_run(self.world, client, self.candidate, self.approval, executionMode="DRY_RUN_MUTATION", dryRun=True)
        self.assertEqual(ok.json["remediation"]["outcome"], "SIMULATED")

    def test_no_field_can_select_execution(self):
        client = self.world.client(EXECUTOR)
        for field, value in (("outcome", "EXECUTED_PRODUCTION"), ("execute", True), ("force", True),
                             ("mode", "PRODUCTION"), ("whatIf", False), ("adapter", "AAP"), ("templateId", 1),
                             ("jobTemplateId", 1), ("extraVars", {"x": 1}), ("script", "Remove-Item"),
                             ("command", "x"), ("powershell", "x"), ("productionMutation", True)):
            with self.subTest(field=field):
                result = dry_run(self.world, client, self.candidate, self.approval, **{field: value})
                self.assertEqual((result.status, result.code), (422, "VALIDATION_FAILED"))
        self.assertEqual(events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED), [])

    def test_every_layer_below_the_api_refuses_production_mutation_too(self):
        with self.assertRaises(ProductionMutationNotPermitted):
            MutationPolicy.for_mode(ExecutionMode.PRODUCTION_MUTATION)
        with self.assertRaises(ConfigError):
            load_settings({"OGWA_EXECUTION_MODE": "PRODUCTION_MUTATION"})
        claims = self.world.api.identity.authenticate({"subject": EXECUTOR}, now=self.world.clock())
        principal = Principal(claims, frozenset({Role.EXECUTOR}))
        with self.assertRaises(Exception) as caught:
            self.world.api.remediation.dry_run(
                principal, self.candidate, operation=RemediationOperation.OKTA_GROUP_UNASSIGN,
                target_ref=self.world.store.load_candidate(self.candidate).assignment_ids[0],
                approval_id=self.approval, expected_fingerprint="sha256:" + "0" * 64, dry_run=True,
                requested_mode="PRODUCTION_MUTATION", request_id=new_id(IdKind.REQUEST))
        self.assertEqual(getattr(caught.exception, "code", None), "PRODUCTION_MUTATION_REFUSED")


# --- proof 3: stale evidence invalidates the approval ------------------------------------


class StaleEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.world = world()
        self.addCleanup(self.world.close)
        self.candidate, self.approval = approve_okta(self.world)
        self.executor = self.world.client(EXECUTOR)

    def test_stale_evidence_blocks_an_approval_that_is_still_in_force(self):
        self.assertEqual(dry_run(self.world, self.executor, self.candidate, self.approval).status, 201)
        self.world.clock.advance(timedelta(hours=25))  # past the 24-hour EXECUTION window; the approval runs 7 days
        result = dry_run(self.world, self.executor, self.candidate, self.approval)
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        gates = failed_gates(result)
        self.assertIn("FRESH_EVIDENCE", gates)
        self.assertNotIn("VALID_APPROVAL", gates)
        self.assertNotIn("APPROVAL_FINGERPRINT_MATCHES", gates)
        self.assertEqual(chained(self.world, result)[0].action, AuditAction.GOVERNED_REQUEST_REFUSED)
        # Re-observing the same facts restores freshness without a new approval.
        self.world.refresh_evidence(self.candidate)
        again = dry_run(self.world, self.executor, self.candidate, self.approval)
        self.assertEqual(again.json["remediation"]["outcome"], "SIMULATED")

    def test_a_material_change_voids_the_approval(self):
        loaded = self.world.store.load_candidate(self.candidate)
        usage = self.world.store.evidence_bundle(loaded).usage[0]
        # Still zero sign-ins, over a window one day longer: a material change that breaks no rule.
        self.world.store.record_evidence(replace(usage, window_start=usage.window_start - timedelta(days=1),
                                                 provenance=replace(usage.provenance, observed_at=self.world.clock())),
                                         actor=COLLECTOR)
        result = dry_run(self.world, self.executor, self.candidate, self.approval)
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertIn("APPROVAL_FINGERPRINT_MATCHES", failed_gates(result))

    def test_an_out_of_date_view_is_refused_before_the_gates(self):
        body = {"operation": "OKTA_GROUP_UNASSIGN", "target": target_of(self.world, self.candidate, "OKTA_GROUP_UNASSIGN"),
                "approvalId": self.approval, "expectedEvidenceFingerprint": "sha256:" + "1" * 64}
        result = self.executor.post(f"{V}/candidates/{self.candidate}/remediation-dry-runs", body)
        self.assertEqual((result.status, result.code), (409, "EVIDENCE_CHANGED"))


# --- proof 4: changing the target identity invalidates the approval ----------------------


class TargetIdentityTests(unittest.TestCase):
    def setUp(self):
        self.world = world()
        self.addCleanup(self.world.close)
        self.candidate, self.approval = approve_ad(self.world)
        self.executor = self.world.client(EXECUTOR)
        self.group = self.world.store.evidence_bundle(self.world.store.load_candidate(self.candidate)).ad_group

    def observe(self, **changes):
        self.world.store.record_evidence(replace(self.group, provenance=replace(
            self.group.provenance, observed_at=self.world.clock()), **changes), actor=COLLECTOR)

    def test_a_renamed_or_moved_group_is_no_longer_the_approved_target(self):
        first = dry_run(self.world, self.executor, self.candidate, self.approval, "AD_GROUP_QUARANTINE")
        approved_identity = first.json["remediation"]["target"]["identityDigest"]
        self.observe(distinguished_name="CN=SYNTH-RENAMED,OU=Groups,DC=corp,DC=synthetic,DC=example",
                     sam_account_name="SYNTH-RENAMED")
        result = dry_run(self.world, self.executor, self.candidate, self.approval, "AD_GROUP_QUARANTINE")
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertIn("APPROVAL_FINGERPRINT_MATCHES", failed_gates(result))
        # A new approval of the new identity is needed, and records a different identity. The
        # quarantine was already approved, so the candidate is held, re-enters revalidation, and
        # is approved again (a new epoch voids the old approval).
        automation = self.world.client(AUTOMATION)
        for target in ("BLOCKED", "REVALIDATION_REQUIRED"):
            moved = automation.post(f"{V}/candidates/{self.candidate}/transitions", {
                "target": target, "reason": "the group was renamed; review it again",
                "expectedEvidenceFingerprint": self.world.fingerprint(automation, self.candidate)})
            self.assertEqual(moved.status, 201, moved.json)
        client = self.world.client(SECURITY)
        renewed = client.post(f"{V}/candidates/{self.candidate}/approvals", {
            "stage": "AD_QUARANTINE", "decision": "APPROVE", "reason": "synthetic re-review",
            "expectedEvidenceFingerprint": self.world.fingerprint(client, self.candidate)})
        self.assertEqual(renewed.status, 201, renewed.json)
        second = dry_run(self.world, self.executor, self.candidate, renewed.json["approval"]["id"], "AD_GROUP_QUARANTINE")
        self.assertEqual(second.status, 201, second.json)
        self.assertNotEqual(second.json["remediation"]["target"]["identityDigest"], approved_identity)

    def test_a_changed_objectsid_is_no_longer_the_approved_target(self):
        self.observe(sid=self.group.sid.rsplit("-", 1)[0] + "-9999")
        result = dry_run(self.world, self.executor, self.candidate, self.approval, "AD_GROUP_QUARANTINE")
        self.assertIn("APPROVAL_FINGERPRINT_MATCHES", failed_gates(result))

    def test_a_target_other_than_the_mapped_group_is_refused(self):
        other = self.world.store.evidence_bundle(self.world.store.load_candidate(self.world.candidate("S07"))).ad_group
        body = {"operation": "AD_GROUP_QUARANTINE", "target": {"adGroupId": other.id}, "approvalId": self.approval,
                "expectedEvidenceFingerprint": self.world.fingerprint(self.executor, self.candidate)}
        result = self.executor.post(f"{V}/candidates/{self.candidate}/remediation-dry-runs", body)
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertIn("SINGLE_EXPLICIT_TARGET", failed_gates(result))


# --- proof 5: protection cannot be overridden by operators -------------------------------


class ProtectedGroupTests(unittest.TestCase):
    def setUp(self):
        self.world = world()
        self.addCleanup(self.world.close)
        self.candidate, self.approval = approve_okta(self.world)
        guid = self.world.store.evidence_bundle(self.world.store.load_candidate(self.candidate)).ad_group.object_guid
        # The AD group joins the configured protected list (D10) after the approval was given,
        # so the evidence, and the approval's fingerprint, are unchanged.
        protected = CandidatePolicy(lifecycle=replace(DEMO_LIFECYCLE_POLICY,
                                                      protected_ad_object_guids=frozenset({guid})))
        patcher = mock.patch("app.api.remediation.policy_in_force",
                             return_value=PolicyInForce(protected, DEMO_SOURCE, None))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_protected_target_is_blocked_for_every_principal(self):
        for subject in ALL_PRINCIPALS:
            client = self.world.client(subject)
            with self.subTest(subject=subject):
                result = dry_run(self.world, client, self.candidate, self.approval)
                if subject in (EXECUTOR, APPROVER_EXECUTOR):
                    self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
                    self.assertEqual(failed_gates(result), {"NOT_PROTECTED"})
                else:
                    self.assertEqual((result.status, result.code), (403, "FORBIDDEN"))
        self.assertEqual(events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED), [])

    def test_no_field_role_or_permission_overrides_protection(self):
        executor = self.world.client(EXECUTOR)
        for field in ("overrideProtection", "override", "force", "ignoreProtection", "bypass", "acknowledgeRisk"):
            with self.subTest(field=field):
                result = dry_run(self.world, executor, self.candidate, self.approval, **{field: True})
                self.assertEqual((result.status, result.code), (422, "VALIDATION_FAILED"))
        self.assertFalse([p for p in Permission if any(w in p.value for w in ("OVERRIDE", "BYPASS", "FORCE"))])
        everything = {role: frozenset(Permission) for role in ROLE_PERMISSIONS}
        with mock.patch.dict(authz.ROLE_PERMISSIONS, everything):
            for subject in (DUAL, ADMIN, EXECUTOR):
                with self.subTest(subject=subject):
                    result = dry_run(self.world, self.world.client(subject), self.candidate, self.approval)
                    self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
                    self.assertIn("NOT_PROTECTED", failed_gates(result))

    def test_protection_observed_in_evidence_blocks_too(self):
        bundle = self.world.store.evidence_bundle(self.world.store.load_candidate(self.candidate))
        group = bundle.ad_group
        self.world.store.record_evidence(replace(group, admin_count=True, provenance=replace(
            group.provenance, observed_at=self.world.clock())), actor=COLLECTOR)
        result = dry_run(self.world, self.world.client(EXECUTOR), self.candidate, self.approval)
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertIn("NOT_PROTECTED", failed_gates(result))


# --- anti-footgun controls ---------------------------------------------------------------


class AntiFootgunTests(unittest.TestCase):
    def setUp(self):
        self.world = world()
        self.addCleanup(self.world.close)
        self.candidate, self.approval = approve_okta(self.world)
        self.executor = self.world.client(EXECUTOR)

    def post(self, **body):
        fields = {"operation": "OKTA_GROUP_UNASSIGN", "approvalId": self.approval,
                  "expectedEvidenceFingerprint": self.world.fingerprint(self.executor, self.candidate)}
        fields.update(body)
        return self.executor.post(f"{V}/candidates/{self.candidate}/remediation-dry-runs", fields)

    def test_a_request_names_exactly_one_explicit_target(self):
        assignment = self.world.store.load_candidate(self.candidate).assignment_ids[0]
        for target in ([{"assignmentId": assignment}], [assignment], assignment, {}, None,
                       {"assignmentId": assignment, "adGroupId": "adg_" + "0" * 32},
                       {"assignmentIds": [assignment]}, {"adGroupId": "adg_" + "0" * 32},
                       {"assignmentId": "asgn_*"}, {"assignmentId": [assignment]}):
            with self.subTest(target=target):
                result = self.post(target=target)
                self.assertEqual((result.status, result.code), (422, "VALIDATION_FAILED"))
        other = self.world.store.load_candidate(self.world.candidate("S14")).assignment_ids[0]
        result = self.post(target={"assignmentId": other})
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertIn("SINGLE_EXPLICIT_TARGET", failed_gates(result))

    def test_there_is_no_bulk_remediation_and_no_remediation_execute_route(self):
        remediation = [(r.method, r.pattern[len(V):]) for r in ROUTES if "remediation" in r.pattern]
        # The synthetic drill: one candidate, one target, against an in-memory
        # provider fixture, recording nothing. It is neither a bulk route nor an execute route.
        self.assertEqual(sorted(remediation), [("GET", "/candidates/{candidateId}/remediation-dry-runs"),
                                               ("GET", "/remediation-drill-scenarios"),
                                               ("POST", "/candidates/{candidateId}/remediation-drills"),
                                               ("POST", "/candidates/{candidateId}/remediation-dry-runs")])
        for method, pattern in remediation:
            with self.subTest(route=pattern):
                self.assertNotIn("execute", pattern)
                self.assertLessEqual(pattern.count("{"), 1, "one subject at most")
        from app.api.routes import DRILL_FIELDS
        self.assertEqual(DRILL_FIELDS, {"operation", "target", "approvalId", "expectedEvidenceFingerprint", "mode",
                                        "scenario"}, "a drill carries no execution mode, flag, template, or fault")
        for route in ROUTES:
            if route.method == "POST" and route.governed_subject:
                with self.subTest(route=route.pattern):
                    self.assertEqual(route.pattern.count("{"), 1, "a governed write names exactly one subject")
        source = (REPO_ROOT / "app" / "api" / "routes.py").read_text(encoding="utf-8")
        handler = next(n for n in ast.walk(ast.parse(source))
                       if isinstance(n, ast.FunctionDef) and n.name == "post_remediation_dry_run")
        allowed = next(k for k in ast.walk(handler) if isinstance(k, ast.keyword) and k.arg == "allowed")
        self.assertEqual(ast.literal_eval(allowed.value), {"operation", "target", "approvalId",
                                                           "expectedEvidenceFingerprint", "dryRun", "executionMode"})

    def test_templates_and_adapters_come_only_from_the_server_side_allowlist(self):
        config = json.loads((REPO_ROOT / "config" / "remediation-allowlist.synthetic.json").read_text(encoding="utf-8"))
        self.assertEqual({e["adapter"] for e in config["operations"].values()}, {"SYNTHETIC"})
        self.assertNotIn("jobTemplateId", json.dumps(config))
        w = world(parse_allowlist({"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC",
                                   "operations": {}}, environment=DatabaseEnvironment.SYNTHETIC))
        self.addCleanup(w.close)
        candidate, approval = approve_okta(w)
        result = dry_run(w, w.client(EXECUTOR), candidate, approval)
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertTrue(any("not in the server-side remediation allowlist" in p for p in result.json["error"]["problems"]))
        production = {"format": ALLOWLIST_FORMAT, "environment": "PRODUCTION",
                      "operations": {"AD_GROUP_DELETE": {"adapter": "SYNTHETIC"}}}
        with self.assertRaises(ConfigError):
            parse_allowlist(production, environment=DatabaseEnvironment.PRODUCTION)
        with self.assertRaises(ConfigError):
            build_local_api(self.world.store, clock=self.world.clock, remediation_allowlist=parse_allowlist(
                {**production, "operations": {}}, environment=DatabaseEnvironment.PRODUCTION))

    def test_a_blocked_request_is_chained_with_its_operation_and_target_and_changes_nothing(self):
        self.world.clock.advance(timedelta(hours=25))
        result = self.post(target=target_of(self.world, self.candidate, "OKTA_GROUP_UNASSIGN"))
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"))
        self.assertEqual(result.json["error"]["outcome"], "BLOCKED")
        self.assertEqual([g["gate"] for g in result.json["error"]["gates"]], [g.value for g in Gate])
        events_of_request = chained(self.world, result)
        self.assertEqual(len(events_of_request), 1)
        event = events_of_request[0]
        self.assertEqual((event.action, event.result, event.subject_id),
                         (AuditAction.GOVERNED_REQUEST_REFUSED, AuditResult.REFUSED, self.candidate))
        details = dict(event.details)
        self.assertEqual((details["code"], details["request.operation"]), ("REMEDIATION_BLOCKED", "OKTA_GROUP_UNASSIGN"))
        self.assertEqual(details["request.target.assignmentId"],
                         self.world.store.load_candidate(self.candidate).assignment_ids[0])
        self.assertEqual(events(self.world, AuditAction.REMEDIATION_DRY_RUN_RECORDED), [])
        self.assertIs(self.world.store.load_candidate(self.candidate).state, S.APPROVED)

    def test_a_dry_run_is_chained_once_and_listed_for_readers(self):
        result = self.post(target=target_of(self.world, self.candidate, "OKTA_GROUP_UNASSIGN"))
        self.assertEqual(result.status, 201, result.json)
        self.assertEqual([e.action for e in chained(self.world, result)], [AuditAction.REMEDIATION_DRY_RUN_RECORDED])
        listing = self.world.client(VIEWER).get(f"{V}/candidates/{self.candidate}/remediation-dry-runs").json
        self.assertFalse(listing["executionAvailable"])
        self.assertEqual([(i["operation"], i["outcome"], i["requestedBy"], i["executed"]) for i in listing["items"]],
                         [("OKTA_GROUP_UNASSIGN", "SIMULATED", EXECUTOR, False)])
        self.assertEqual(listing["items"][0]["approvalId"], self.approval)
        viewer = self.world.client(VIEWER).post(f"{V}/candidates/{self.candidate}/remediation-dry-runs", {})
        self.assertEqual((viewer.status, viewer.code), (403, "FORBIDDEN"))
        self.assertEqual(chained(self.world, viewer), [])
        self.world.store.verify_integrity()

    def test_the_approver_cannot_request_the_dry_run_of_their_own_stage(self):
        w = world()
        self.addCleanup(w.close)
        candidate, approval = approve_okta(w, approver=APPROVER_EXECUTOR)
        result = dry_run(w, w.client(APPROVER_EXECUTOR), candidate, approval)
        self.assertEqual((result.status, result.code), (403, "SEPARATION_OF_DUTIES"))
        self.assertEqual(dry_run(w, w.client(EXECUTOR), candidate, approval).status, 201)

    def test_an_unknown_approval_or_another_candidates_approval_is_not_found(self):
        other = self.world.store.approvals_for(self.world.candidate("S14"))[0].id
        for approval in (new_id(IdKind.APPROVAL), other):
            with self.subTest(approval=approval):
                result = self.post(target=target_of(self.world, self.candidate, "OKTA_GROUP_UNASSIGN"), approvalId=approval)
                self.assertEqual((result.status, result.code), (404, "NOT_FOUND"))


if __name__ == "__main__":
    unittest.main()
