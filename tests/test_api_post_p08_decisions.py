"""Owner decisions: role boundaries, chained governed refusals, the demo-policy
label, and the synthetic AD directory wired into the running API.

Synthetic only: in-memory seeded stores and the store-backed synthetic directory. No
directory, identity provider, or other external system is contacted.
"""

import ast
import json
import unittest
from pathlib import Path
from unittest import mock

from app.api.authz import ROLE_PERMISSIONS, WRITE_PERMISSIONS, Permission, Role
from app.api.routes import ROUTES
from app.api.services import DEMO_POLICY_LABEL
from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.correlation.model import LookupStatus
from app.demo.synthetic_directory import StoreSyntheticDirectory, SyntheticMappingGateway, okta_group_identity
from app.domain.actors import Actor, ActorKind
from app.domain.audit import AuditAction, AuditResult
from app.domain.candidate_policy import PolicyRole, PolicyVersion
from app.domain.ids import IdKind, new_id
from app.domain.model import ADGroup, OktaGroup
from app.integrations.ad.contract import LookupKind
from app.store.environment import DatabaseEnvironment
from tests.api_fixtures import (
    ADMIN,
    AUTOMATION,
    DUAL,
    EXECUTOR,
    SECURITY,
    SECURITY_2,
    VIEWER,
    ApiClient,
    World,
)
from tests.store_fixtures import new_store
from tests.test_remediation_api import approve_ad

P = Permission
V = "/api/v1"
API_DIR = Path(__file__).resolve().parents[1] / "app" / "api"
LIFECYCLE_AUTHORITY = {P.LIFECYCLE_ADVANCE, P.LIFECYCLE_DIVERT, P.APPROVAL_DECIDE, P.EXECUTION_PLAN_DRY_RUN,
                       P.EXECUTION_EXECUTE}
MAPPING_POWERS = {P.MAPPING_PROPOSE, P.MAPPING_APPROVE, P.MAPPING_REJECT}


# --- role boundaries -------------------------------------------------------------------


class RoleDecisionTests(unittest.TestCase):
    def test_viewer_is_strictly_read_only(self):
        self.assertEqual(ROLE_PERMISSIONS[Role.VIEWER], {P.READ_INVENTORY})

    def test_executor_only_plans_dry_runs(self):
        self.assertEqual(ROLE_PERMISSIONS[Role.EXECUTOR], {P.READ_INVENTORY, P.EXECUTION_PLAN_DRY_RUN})
        self.assertFalse(ROLE_PERMISSIONS[Role.EXECUTOR] & (MAPPING_POWERS | {P.APPROVAL_DECIDE}))

    def test_administrator_has_no_lifecycle_authority(self):
        self.assertEqual(ROLE_PERMISSIONS[Role.ADMINISTRATOR], {P.READ_INVENTORY, P.READ_AUDIT, P.READ_SYSTEM})
        self.assertFalse(ROLE_PERMISSIONS[Role.ADMINISTRATOR] & (LIFECYCLE_AUTHORITY | MAPPING_POWERS | WRITE_PERMISSIONS))

    def test_nothing_is_inherited_from_a_role_name(self):
        """Code checks permissions, never role names, so no role can imply another's powers."""
        for path in sorted(API_DIR.glob("*.py")):
            if path.name == "authz.py":
                continue  # the role table itself
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "Role":
                    self.fail(f"{path.name} refers to Role.{node.attr}")

    def test_executor_plans_only_for_an_already_approved_stage(self):
        world = World()
        self.addCleanup(world.close)
        executor = world.client(EXECUTOR)
        s12 = world.candidate("S12")  # REVALIDATION_REQUIRED: its quarantine is not approved
        okta_approval = world.store.approvals_for(s12)[0].id
        jobs_before = world.api.read.job_ids_for(s12)
        result = executor.post(f"{V}/candidates/{s12}/execution-jobs", {
            "kind": "AD_QUARANTINE", "approvalId": okta_approval,
            "expectedEvidenceFingerprint": world.fingerprint(executor, s12)})
        self.assertEqual(result.code, "INVALID_STATE")
        self.assertEqual(world.api.read.job_ids_for(s12), jobs_before)
        # Once the quarantine is approved, an earlier stage's approval still cannot back its dry run.
        s01, _ = approve_ad(world)
        okta_approval = world.store.approvals_for(s01)[0].id
        jobs_before = world.api.read.job_ids_for(s01)
        result = executor.post(f"{V}/candidates/{s01}/execution-jobs", {
            "kind": "AD_QUARANTINE", "approvalId": okta_approval,
            "expectedEvidenceFingerprint": world.fingerprint(executor, s01)})
        self.assertEqual(result.code, "APPROVAL_INVALID")
        self.assertTrue(any("not AD_QUARANTINE" in p for p in result.json["error"]["problems"]))
        self.assertEqual(world.api.read.job_ids_for(s01), jobs_before)
        group = world.store.load_candidate(s12).okta_group_id
        for path in (f"/candidates/{s12}/approvals", f"/mappings/{group}/selections", f"/mappings/{group}/approvals"):
            self.assertEqual(executor.post(V + path, {}).code, "FORBIDDEN")


# --- governed refusals in the audit chain ----------------------------------------------


class GovernedRefusalAuditTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.s07 = self.world.candidate("S07")

    def chained(self, result):
        """The audit events written under this request's id."""
        request_id = result.header("x-request-id")
        return [e for e in self.world.store.audit_events() if e.correlation_id == request_id]

    def assert_chained(self, result, subject, principal, code):
        self.assertEqual(result.code, code, result.json)
        events = self.chained(result)
        self.assertEqual(len(events), 1, events)
        event = events[0]
        self.assertEqual((event.action, event.result, event.actor, event.subject_id),
                         (AuditAction.GOVERNED_REQUEST_REFUSED, AuditResult.REFUSED,
                          Actor(ActorKind.HUMAN, principal), subject))
        details = dict(event.details)
        self.assertEqual(details["code"], code)
        self.assertEqual(result.json["error"]["auditEventId"], event.id)
        return details

    def test_policy_and_authorization_refusals_of_valid_requests_are_chained(self):
        security, executor, automation = (self.world.client(s) for s in (SECURITY, EXECUTOR, AUTOMATION))
        fp = self.world.fingerprint(security, self.s07)
        s08 = self.world.candidate("S08")
        details = self.assert_chained(security.post(f"{V}/candidates/{s08}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "private operator note SYNTH-NOTE-42",
            "expectedEvidenceFingerprint": self.world.fingerprint(security, s08)}), s08, SECURITY, "EVIDENCE_RULES_NOT_MET")
        self.assertEqual((details["request.stage"], details["request.decision"]), ("OKTA_UNASSIGN", "APPROVE"))
        self.assertNotIn("request.reason", details)  # free-text reasons are not kept
        self.assertNotIn("SYNTH-NOTE-42", json.dumps(details))
        self.assert_chained(security.post(f"{V}/candidates/{self.s07}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "x",
            "expectedEvidenceFingerprint": "sha256:" + "0" * 64}), self.s07, SECURITY, "EVIDENCE_CHANGED")
        self.assert_chained(automation.post(f"{V}/candidates/{self.s07}/transitions", {
            "target": "APPROVED", "reason": "x", "expectedEvidenceFingerprint": fp}), self.s07, AUTOMATION, "FORBIDDEN")
        self.assert_chained(automation.post(f"{V}/candidates/{self.s07}/transitions", {
            "target": "RETIRED", "reason": "x", "expectedEvidenceFingerprint": fp}), self.s07, AUTOMATION,
            "TRANSITION_NOT_PERMITTED")
        self.assert_chained(executor.post(f"{V}/candidates/{self.s07}/execution-jobs", {
            "kind": "OKTA_UNASSIGN", "approvalId": new_id(IdKind.APPROVAL), "expectedEvidenceFingerprint": fp,
            "dryRun": False}), self.s07, EXECUTOR, "PRODUCTION_MUTATION_REFUSED")
        self.assert_chained(executor.post(f"{V}/candidates/{self.s07}/execution-jobs", {
            "kind": "OKTA_UNASSIGN", "approvalId": new_id(IdKind.APPROVAL), "expectedEvidenceFingerprint": fp}),
            self.s07, EXECUTOR, "INVALID_STATE")
        job = self.world.api.read.job_ids_for(self.world.candidate("S14"))[0]
        self.assert_chained(executor.post(f"{V}/execution-jobs/{job}/execute", {}), job, EXECUTOR,
                            "PRODUCTION_MUTATION_REFUSED")
        self.world.store.verify_integrity()

    def test_four_eyes_refusals_are_chained(self):
        automation, dual = self.world.client(AUTOMATION), self.world.client(DUAL)
        path = f"{V}/candidates/{self.s07}/transitions"
        automation.post(path, {"target": "BLOCKED", "reason": "pause"})
        fp = self.world.fingerprint(automation, self.s07)
        automation.post(path, {"target": "CANDIDATE", "reason": "resume", "expectedEvidenceFingerprint": fp})
        dual.post(path, {"target": "NEEDS_REVIEW", "reason": "submit", "expectedEvidenceFingerprint": fp})
        result = dual.post(f"{V}/candidates/{self.s07}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "mine", "expectedEvidenceFingerprint": fp})
        details = self.assert_chained(result, self.s07, DUAL, "SEPARATION_OF_DUTIES")
        self.assertIn("submitted", details["problems"])

    def test_generic_malformed_and_unauthenticated_failures_stay_in_the_security_log(self):
        before = len(self.world.store.audit_events())
        viewer, security = self.world.client(VIEWER), self.world.client(SECURITY)
        fp = self.world.fingerprint(security, self.s07)
        body = {"stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "x", "expectedEvidenceFingerprint": fp}
        path = f"{V}/candidates/{self.s07}/approvals"
        job = self.world.api.read.job_ids_for(self.world.candidate("S14"))[0]
        attempts = [
            ApiClient(self.world.api).post(path, body),  # unauthenticated
            viewer.post(path, body),  # generic: the role lacks the route's permission
            security.post(path, body, csrf=False),  # CSRF
            security.post(path, body, headers={"Origin": "https://attacker.synthetic.example"}),
            security.post(path, {**body, "force": True}),  # malformed: unknown field
            security.request("POST", path, raw=b"{not json"),
            security.post(f"{V}/candidates/cand_{'0' * 32}/approvals", body),  # no such candidate
            self.world.client(ADMIN).post(f"{V}/candidates/{self.s07}/transitions",  # generic: no lifecycle role
                                          {"target": "EXCLUDED", "reason": "x"}),
            viewer.post(f"{V}/execution-jobs/{job}/execute", {}),  # generic: not the execution function
            security.post(f"{V}/execution-jobs/{job}/execute", {}),
        ]
        self.assertEqual([a.status for a in attempts], [401, 403, 403, 403, 422, 400, 404, 403, 403, 403])
        self.assertEqual([a.code for a in attempts[-2:]], ["FORBIDDEN", "FORBIDDEN"])
        self.assertTrue(all("auditEventId" not in a.json["error"] for a in attempts))
        self.assertEqual(len(self.world.store.audit_events()), before)
        refused = [json.loads(line) for line in self.world.log.lines if '"api.refused"' in line]
        self.assertGreaterEqual(len(refused), 5)

    def test_refused_transitions_are_chained_once_by_the_lifecycle(self):
        automation = self.world.client(AUTOMATION)
        s04 = self.world.candidate("S04")
        result = automation.post(f"{V}/candidates/{s04}/transitions", {
            "target": "CANDIDATE", "reason": "x", "expectedEvidenceFingerprint": self.world.fingerprint(automation, s04)})
        self.assertEqual(result.code, "TRANSITION_REFUSED")
        self.assertEqual([e.action for e in self.chained(result)], [AuditAction.TRANSITION_REFUSED])

    def test_searches_are_not_governed_state_changes(self):
        automation = self.world.client(AUTOMATION)
        group = self.world.store.load_candidate(self.s07).okta_group_id
        result = automation.post(f"{V}/mappings/{group}/searches", {"by": "anr", "value": "x"})
        self.assertEqual(result.code, "REVIEW_REFUSED")
        self.assertEqual(self.chained(result), [])

    def test_a_failure_to_chain_never_changes_the_refusal(self):
        executor = self.world.client(EXECUTOR)
        job = self.world.api.read.job_ids_for(self.world.candidate("S14"))[0]
        with mock.patch.object(self.world.store, "record_governed_refusal", side_effect=RuntimeError("disk full")):
            result = executor.post(f"{V}/execution-jobs/{job}/execute", {})
        self.assertEqual((result.status, result.code), (403, "PRODUCTION_MUTATION_REFUSED"))
        self.assertNotIn("auditEventId", result.json["error"])
        self.assertTrue(any("api.refusal_audit_failed" in line for line in self.world.log.lines))

    def test_governed_routes_are_exactly_the_state_changing_ones(self):
        governed = {(r.method, r.pattern[len(V):]) for r in ROUTES if r.governed_subject}
        self.assertEqual(governed, {
            ("POST", "/candidates/{candidateId}/transitions"), ("POST", "/candidates/{candidateId}/approvals"),
            ("POST", "/candidates/{candidateId}/execution-jobs"), ("POST", "/execution-jobs/{jobId}/execute"),
            ("POST", "/mappings/{groupId}/selections"), ("POST", "/mappings/{groupId}/approvals"),
            ("POST", "/mappings/{groupId}/rejections"),
            ("POST", "/candidates/{candidateId}/remediation-dry-runs"),  # Chains its dry run or its refusal
        })


# --- the demo-policy label -------------------------------------------------------------


class DemoPolicyLabelTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.s07 = self.world.candidate("S07")

    def test_every_response_is_labelled_while_the_demo_policy_is_in_force(self):
        params = {"candidateId": self.s07, "groupId": self.world.store.load_candidate(self.s07).okta_group_id,
                  "applicationId": self.world.store.connection.execute("SELECT id FROM okta_applications LIMIT 1").fetchone()[0],
                  "jobId": self.world.api.read.job_ids_for(self.world.candidate("S14"))[0]}
        for subject in (None, VIEWER, ADMIN):
            for route in ROUTES:
                if route.pattern.endswith("/logout"):
                    continue
                client = self.world.client(subject) if subject else ApiClient(self.world.api)
                path = route.pattern
                for name, value in params.items():
                    path = path.replace("{" + name + "}", value)
                result = client.get(path) if route.method == "GET" else client.post(path, {})
                with self.subTest(subject=subject, route=f"{route.method} {route.pattern}"):
                    self.assertEqual(result.json.get("policyNotice"), DEMO_POLICY_LABEL)
                    self.assertEqual(result.header("x-ogwa-policy-status"), "DEMO-UNRECORDED")
        self.assertEqual(DEMO_POLICY_LABEL, "DEMO POLICY — UNRECORDED")

    def test_policy_views_carry_the_label(self):
        viewer = self.world.client(VIEWER)
        expected = {"label": DEMO_POLICY_LABEL, "recorded": False}
        views = [viewer.get(f"{V}/dashboard").json["policy"], viewer.get(f"{V}/policy").json["inForce"],
                 viewer.get(f"{V}/candidates/{self.s07}").json["policy"],
                 viewer.get(f"{V}/candidates/{self.s07}").json["classification"]["policy"],
                 viewer.get(f"{V}/candidates/{self.s07}/dependencies").json["policy"]]
        security = self.world.client(SECURITY)
        approved = security.post(f"{V}/candidates/{self.s07}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "x",
            "expectedEvidenceFingerprint": self.world.fingerprint(security, self.s07)})
        views.append(approved.json["policy"])
        for view in views:
            self.assertEqual({k: view[k] for k in expected}, expected)

    def test_a_recorded_policy_removes_the_demo_label(self):
        from app.demo.synthetic_world import POLICY
        from app.domain.candidate_policy import CandidatePolicy

        version = PolicyVersion.create(
            CandidatePolicy(lifecycle=POLICY), id=new_id(IdKind.POLICY_VERSION), previous=None,
            proposed_by=Actor(ActorKind.HUMAN, AUTOMATION), proposer_role=PolicyRole.IDENTITY_AUTOMATION,
            approved_by=Actor(ActorKind.HUMAN, SECURITY_2), approver_role=PolicyRole.SECURITY_IAM,
            decided_at=self.world.clock(), reason="synthetic v1 for a label test")
        self.world.store.record_policy_version(version)
        result = self.world.client(VIEWER).get(f"{V}/dashboard")
        self.assertNotIn("policyNotice", result.json)
        self.assertIsNone(result.header("x-ogwa-policy-status"))
        self.assertEqual((result.json["policy"]["label"], result.json["policy"]["recorded"]),
                         ("RECORDED POLICY VERSION 1", True))


# --- the synthetic AD directory in the running API -------------------------------------


class SyntheticDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.directory = StoreSyntheticDirectory(self.world.store, clock=self.world.clock)

    def group_of(self, key):
        return self.world.store.load_candidate(self.world.candidate(key)).okta_group_id

    def test_exists_only_for_local_synthetic_data(self):
        stores = [new_store(environment=DatabaseEnvironment.PRODUCTION, mode=ExecutionMode.READ_ONLY_PRODUCTION),
                  new_store(environment=DatabaseEnvironment.DEVELOPMENT, mode=ExecutionMode.LOCAL_SYNTHETIC)]
        for store in stores:
            self.addCleanup(store.close)
            with self.subTest(environment=store.marker.environment):
                with self.assertRaises(ConfigError):
                    StoreSyntheticDirectory(store, clock=self.world.clock)
                with self.assertRaises(ConfigError):
                    SyntheticMappingGateway(store, clock=self.world.clock)

    def test_lookups_follow_the_worker_rules(self):
        conn = self.world.store.connection
        ad = [self.world.store.latest(ADGroup, r[0]) for r in conn.execute("SELECT id FROM ad_groups ORDER BY id")]
        live = next(g for g in ad if g.exists)
        self.assertEqual(self.directory.lookup(LookupKind.OBJECT_GUID, live.object_guid.upper(), None).status,
                         LookupStatus.RESOLVED)
        self.assertEqual(self.directory.lookup(LookupKind.OBJECT_SID, live.sid, None).searched_domains, (live.domain,))
        ambiguous = self.directory.lookup(LookupKind.SAM_ACCOUNT_NAME, "SYNTH-APP-WIKI-EDITORS", None)
        self.assertEqual(ambiguous.status, LookupStatus.AMBIGUOUS)
        self.assertEqual(len({c.domain for c in ambiguous.candidates}), 2)
        scoped = self.directory.lookup(LookupKind.SAM_ACCOUNT_NAME, "SYNTH-APP-WIKI-EDITORS", "emea.synthetic.example")
        self.assertEqual(scoped.status, LookupStatus.RESOLVED)
        gone = next(g for g in ad if not g.exists)
        self.assertEqual(self.directory.lookup(LookupKind.OBJECT_GUID, gone.object_guid, None).status,
                         LookupStatus.NOT_FOUND)
        with mock.patch.object(StoreSyntheticDirectory, "_groups", side_effect=RuntimeError("boom")):
            self.assertEqual(self.directory.lookup(LookupKind.NAME, "x", None).status, LookupStatus.FAILED)
        # A group observed deleted is gone, even if the observation keeps its last-known DN.
        from dataclasses import replace
        from app.demo.synthetic_world import COLLECTOR
        deleted = replace(live, exists=False, provenance=replace(live.provenance, observed_at=self.world.clock()))
        self.world.store.record_evidence(deleted, actor=COLLECTOR)
        self.assertEqual(self.directory.lookup(LookupKind.OBJECT_GUID, live.object_guid, None).status,
                         LookupStatus.NOT_FOUND)

    def test_the_okta_derived_guid_never_reaches_correlation(self):
        group = self.world.store.latest(OktaGroup, self.group_of("S07"))
        self.assertIsNotNone(group.directory_external_id)  # Okta's rendering of the objectGUID is stored...
        identity = okta_group_identity(group)
        self.assertIsNone(identity.directory_object_guid)  # ...but stays unverified (D23, D30)
        # Okta's objectSid (0008) is passed on, for the engine to treat as unverified (D37).
        self.assertEqual(identity.directory_object_sid, group.directory_object_sid_unverified)

    def test_ambiguous_mapping_is_resolved_end_to_end_by_two_people(self):
        automation, security = self.world.client(AUTOMATION), self.world.client(SECURITY)
        group = self.group_of("S09")
        first = automation.post(f"{V}/mappings/{group}/inspection", {}).json
        self.assertEqual((first["outcome"], len(first["candidates"])), ("AMBIGUOUS", 2))
        search = automation.post(f"{V}/mappings/{group}/searches", {"by": "samAccountName",
                                                                    "value": "SYNTH-APP-WIKI-EDITORS"}).json
        emea = next(c for c in search["candidates"] if c["domain"] == "emea.synthetic.example")
        proposed = automation.post(f"{V}/mappings/{group}/selections", {
            "searchId": search["searchId"], "objectGuid": emea["objectGuid"], "reason": "owner confirmed (synthetic)"})
        self.assertEqual((proposed.status, proposed.json["review"]["reviewStatus"]), (201, "PROPOSED"))
        inspection = security.post(f"{V}/mappings/{group}/inspection", {}).json
        self.assertEqual(inspection["approvableObjectGuid"], emea["objectGuid"])
        approved = security.post(f"{V}/mappings/{group}/approvals", {
            "objectGuid": emea["objectGuid"], "expectedEvidenceFingerprint": inspection["evidenceFingerprint"],
            "reason": "second pair of eyes"})
        self.assertEqual(approved.status, 201, approved.json)
        after = security.post(f"{V}/mappings/{group}/inspection", {}).json
        self.assertEqual((after["outcome"], after["confidence"], after["target"]["objectGuid"]),
                         ("RESOLVED", "EXACT_CONFIGURED_MAPPING", emea["objectGuid"]))
        registry = self.world.client(VIEWER).get(f"{V}/mappings/{group}").json["registry"]
        self.assertEqual([r["reviewStatus"] for r in registry["reviews"]], ["PROPOSED", "APPROVED"])
        self.assertEqual(registry["currentApprovalId"], approved.json["review"]["id"])
        actions = [e.action for e in self.world.store.audit_events() if e.subject_id == group]
        self.assertEqual(actions[-2:], [AuditAction.MAPPING_REVIEW_RECORDED, AuditAction.MAPPING_REVIEW_RECORDED])
        self.world.store.verify_integrity()

    def test_name_only_pairing_cannot_be_approved_and_the_refusal_is_chained(self):
        security = self.world.client(SECURITY)
        group = self.group_of("S08")
        inspection = security.post(f"{V}/mappings/{group}/inspection", {}).json
        self.assertEqual(inspection["confidence"], "NAME_ONLY")
        self.assertIsNone(inspection["approvableObjectGuid"])
        result = security.post(f"{V}/mappings/{group}/approvals", {
            "objectGuid": inspection["target"]["objectGuid"],
            "expectedEvidenceFingerprint": inspection["evidenceFingerprint"], "reason": "looks right"})
        self.assertEqual(result.code, "REVIEW_REFUSED")
        self.assertEqual(self.world.store.mapping_reviews(group), [])
        event = next(e for e in self.world.store.audit_events() if e.id == result.json["error"]["auditEventId"])
        self.assertEqual((event.action, event.subject_id), (AuditAction.GOVERNED_REQUEST_REFUSED, group))


if __name__ == "__main__":
    unittest.main()
