"""API contract: response shape, validation, pagination, lifecycle flow, mapping review.

Synthetic only. Requests are handed to the WSGI application in-process, except one smoke
test that serves on 127.0.0.1 with an ephemeral port. No external system is contacted.
"""

import ast
import http.client
import json
import os
import re
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.api import __main__ as api_main
from app.api.app import OgwaApi, Route
from app.api.authz import Permission
from app.api.errors import ApiError
from app.api.http import MAX_BODY_BYTES, SECURITY_HEADERS
from app.api.local import make_local_server
from app.api.routes import ROUTES
from app.api.validation import MAX_PAGE_SIZE, encode_cursor
from app.correlation.review import InMemoryMappingRegistry, MappingReviewService
from app.core.modes import ExecutionMode
from app.domain.audit import AuditAction, AuditResult
from app.domain.lifecycle import LifecycleState
from app.integrations.ad.contract import LookupKind
from app.store.errors import StoreIntegrityError
from tests.api_fixtures import (
    ADMIN,
    AUTOMATION,
    AUTOMATION_2,
    DUAL,
    EXECUTOR,
    SECURITY,
    SECURITY_2,
    VIEWER,
    ApiClient,
    World,
)
from tests.correlation_fixtures import Clock, SyntheticDirectory, ad_group, config, okta_native_group

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "app" / "api"
V = "/api/v1"
S = LifecycleState
REQUEST_ID = re.compile(r"^req_[0-9a-f]{32}$")


class ResponseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def setUp(self):
        self.client = self.world.client(AUTOMATION)

    def assert_error(self, result, status, code):
        self.assertEqual((result.status, result.code), (status, code), result.json)
        error = result.json["error"]
        self.assertEqual(error["requestId"], result.header("x-request-id"))
        self.assertTrue(error["message"])

    def test_every_response_has_a_request_id_and_security_headers(self):
        for result in (self.client.get(f"{V}/dashboard"), self.client.get(f"{V}/nowhere"),
                       ApiClient(self.world.api).get(f"{V}/health")):
            self.assertRegex(result.header("x-request-id"), REQUEST_ID)
            for name, value in SECURITY_HEADERS:
                self.assertEqual(result.header(name), value)
            self.assertTrue(result.header("content-type").startswith("application/json"))
        ids = {self.client.get(f"{V}/health").header("x-request-id") for _ in range(5)}
        self.assertEqual(len(ids), 5)

    def test_routing_errors(self):
        self.assert_error(self.client.get(f"{V}/nowhere"), 404, "NOT_FOUND")
        self.assert_error(self.client.get("/admin"), 404, "NOT_FOUND")
        result = self.client.request("DELETE", f"{V}/candidates")
        self.assert_error(result, 405, "METHOD_NOT_ALLOWED")
        self.assertEqual(result.header("allow"), "GET")
        self.assert_error(self.client.request("PUT", f"{V}/session"), 405, "METHOD_NOT_ALLOWED")
        self.assert_error(self.client.get(f"{V}/candidates/cand_not-an-id"), 404, "NOT_FOUND")
        self.assert_error(self.client.get(f"{V}/candidates/ogrp_{'0' * 32}"), 404, "NOT_FOUND")
        self.assert_error(self.client.get(f"{V}/candidates/cand_{'0' * 32}"), 404, "NOT_FOUND")

    def test_body_validation(self):
        path = f"{V}/candidates/{self.world.candidate('S07')}/transitions"
        cases = [
            (dict(raw=b"{not json"), 400, "MALFORMED_REQUEST"),
            (dict(raw=b'{"target": "BLOCKED", "target": "EXCLUDED"}'), 400, "MALFORMED_REQUEST"),
            (dict(raw=b'{"reason": NaN}'), 400, "MALFORMED_REQUEST"),
            (dict(raw=b"[1, 2]"), 400, "MALFORMED_REQUEST"),
            (dict(raw=b"\xff\xfe"), 400, "MALFORMED_REQUEST"),
            (dict(raw=b"x" * (MAX_BODY_BYTES + 1)), 413, "PAYLOAD_TOO_LARGE"),
            (dict(raw=b"target=BLOCKED", content_type="application/x-www-form-urlencoded"), 415,
             "UNSUPPORTED_MEDIA_TYPE"),
            (dict(raw=b"{}", content_type="text/plain"), 415, "UNSUPPORTED_MEDIA_TYPE"),
            (dict(body={"target": "BLOCKED", "reason": "x", "force": True}), 422, "VALIDATION_FAILED"),
            (dict(body={"target": "NOT_A_STATE", "reason": "x"}), 422, "VALIDATION_FAILED"),
            (dict(body={"target": "BLOCKED", "reason": ""}), 422, "VALIDATION_FAILED"),
            (dict(body={"target": "BLOCKED", "reason": "x" * 1001}), 422, "VALIDATION_FAILED"),
            (dict(body={"target": "CANDIDATE", "reason": "x", "expectedEvidenceFingerprint": "md5:00"}), 422,
             "VALIDATION_FAILED"),
            (dict(body={"target": "BLOCKED", "reason": "x", "approvalId": "apr_short"}), 422, "VALIDATION_FAILED"),
        ]
        for kwargs, status, code in cases:
            with self.subTest(kwargs=str(kwargs)[:60]):
                self.assert_error(self.client.request("POST", path, **kwargs), status, code)
        self.assertIs(self.world.store.load_candidate(self.world.candidate("S07")).state, S.NEEDS_REVIEW)

    def test_missing_content_length_is_refused(self):
        environ = {"REQUEST_METHOD": "POST", "PATH_INFO": f"{V}/session", "QUERY_STRING": "",
                   "CONTENT_TYPE": "application/json", "wsgi.input": __import__("io").BytesIO(b"{}")}
        captured = {}
        body = self.world.api(environ, lambda status, headers: captured.update(status=status))
        self.assertTrue(captured["status"].startswith("411"))
        self.assertEqual(json.loads(b"".join(body))["error"]["code"], "LENGTH_REQUIRED")

    def test_query_validation_and_bounded_pagination(self):
        for query, code in (("limit=0", "MALFORMED_REQUEST"), (f"limit={MAX_PAGE_SIZE + 1}", "MALFORMED_REQUEST"),
                            ("limit=-1", "MALFORMED_REQUEST"), ("limit=ten", "MALFORMED_REQUEST"),
                            ("limit=%C2%B2", "MALFORMED_REQUEST"), ("limit=%D9%A5", "MALFORMED_REQUEST"),
                            ("cursor=bogus", "MALFORMED_REQUEST"), (f"cursor={encode_cursor(10 ** 6)}", "MALFORMED_REQUEST"),
                            ("limit=2&limit=3", "MALFORMED_REQUEST"), ("sort=name", "MALFORMED_REQUEST"),
                            ("state=nope", "MALFORMED_REQUEST")):
            with self.subTest(query=query):
                self.assert_error(self.client.get(f"{V}/candidates?{query}"), 400, code)
        self.assertEqual(self.client.get(f"{V}/candidates").json["page"]["limit"], 50)

    def test_pages_cover_every_record_exactly_once(self):
        expected = [r[0] for r in self.world.store.connection.execute("SELECT id FROM okta_applications ORDER BY id")]
        seen, cursor = [], None
        for _ in range(len(expected) + 1):
            result = self.client.get(f"{V}/applications?limit=2" + (f"&cursor={cursor}" if cursor else ""))
            self.assertLessEqual(len(result.json["items"]), 2)
            seen += [item["id"] for item in result.json["items"]]
            cursor = result.json["page"]["nextCursor"]
            if cursor is None:
                break
        self.assertEqual(seen, expected)
        filtered = self.client.get(f"{V}/candidates?state=DEPENDENCY_BLOCKED").json["items"]
        self.assertEqual({c["state"] for c in filtered}, {"DEPENDENCY_BLOCKED"})
        self.assertEqual(len(filtered), 3)

    def test_unexpected_exceptions_reveal_nothing(self):
        def boom(ctx):
            raise RuntimeError("password=synthetic-hunter2 token=synthetic-abc123 at C:\\secret\\path")

        def broken(ctx):
            raise StoreIntegrityError("candidate cand_x failed history verification: secret=synthetic-zzz")

        routes = (Route("GET", f"{V}/boom", boom, "permission", frozenset({Permission.READ_INVENTORY})),
                  Route("GET", f"{V}/broken", broken, "permission", frozenset({Permission.READ_INVENTORY})))
        api = OgwaApi(store=self.world.store, identity=self.world.api.identity, bindings=self.world.api.bindings,
                      clock=self.world.clock, mode=ExecutionMode.LOCAL_SYNTHETIC, routes=routes,
                      sessions=self.world.api.sessions, logger=self.world.api.log)
        client = ApiClient(api)
        client.cookie = self.client.cookie
        for path, code in (("/boom", "INTERNAL_ERROR"), ("/broken", "INTEGRITY_FAILURE")):
            with self.subTest(path=path):
                result = client.get(V + path)
                self.assert_error(result, 500, code)
                text = json.dumps(result.json)
                for leaked in ("hunter2", "abc123", "zzz", "Traceback", "RuntimeError", "C:\\\\secret", "cand_x"):
                    self.assertNotIn(leaked, text)
        logged = "\n".join(self.world.log.lines)
        self.assertIn("api.internal_error", logged)
        self.assertNotIn("synthetic-hunter2", logged)
        self.assertNotIn("synthetic-abc123", logged)

    def test_routes_must_declare_access(self):
        handler = ROUTES[0].handler
        for kwargs in (dict(access="open"), dict(access="permission"), dict(access="public",
                                                                           any_of=frozenset({Permission.READ_INVENTORY}))):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Route("GET", f"{V}/x", handler, **kwargs)
        with self.assertRaises(ValueError):
            Route("DELETE", f"{V}/x", handler, "public")
        keys = [(r.method, r.pattern) for r in ROUTES]
        self.assertEqual(len(keys), len(set(keys)))


class ReadEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()
        cls.client = cls.world.client(VIEWER)
        cls.s07 = cls.world.candidate("S07")

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def test_dashboard_states_the_safety_posture(self):
        body = self.client.get(f"{V}/dashboard").json
        self.assertEqual(body["safety"], {"executionMode": "LOCAL_SYNTHETIC", "externalMutation": "synthetic targets only",
                                          "productionMutationPermittedByBuild": False,
                                          "executionRoutes": "DRY_RUN_PLANNING_ONLY"})
        self.assertEqual(sum(body["candidatesByState"].values()), 16)
        # S07 and S08 await the Okta stage, S12 the AD quarantine, and S16 the AD deletion.
        self.assertEqual(body["awaitingApproval"], {"OKTA_UNASSIGN": 2, "AD_QUARANTINE": 1, "AD_DELETION": 1})
        self.assertEqual(body["policy"]["source"], "UNRECORDED_SYNTHETIC_DEMO")
        self.assertEqual(body["store"]["environment"], "SYNTHETIC")
        self.assertGreater(body["collectors"]["incomplete"], 0)  # S13's timeout and rate limit

    def test_candidate_detail_is_evidence_not_authorization(self):
        body = self.client.get(f"{V}/candidates/{self.s07}").json
        self.assertFalse(body["classification"]["isApproval"])
        self.assertIn("never authorization", body["note"])
        self.assertRegex(body["evidenceFingerprint"], r"^sha256:[0-9a-f]{64}$")
        actions = body["allowedActions"]
        self.assertTrue(actions["transitions"])
        self.assertFalse(any(t["permitted"] for t in actions["transitions"]))  # a viewer may do nothing
        self.assertFalse(actions["approvals"][0]["permitted"])

    def test_candidate_sub_resources(self):
        evidence = self.client.get(f"{V}/candidates/{self.s07}/evidence").json
        self.assertEqual(evidence["mapping"]["confidence"], "EXACT_CONFIGURED_MAPPING")
        self.assertEqual(evidence["evidenceFingerprint"],
                         self.client.get(f"{V}/candidates/{self.s07}").json["evidenceFingerprint"])
        self.assertIn("provenance", evidence["oktaGroup"])
        dependencies = self.client.get(f"{V}/candidates/{self.world.candidate('S04')}/dependencies").json
        self.assertTrue(any(f["blocking"] for d in dependencies["findings"] for f in d["findings"]))
        self.assertIn(dependencies["coverage"]["overall"], ("PARTIAL", "UNKNOWN", "COMPLETE"))
        decisions = self.client.get(f"{V}/candidates/{self.s07}/decisions").json["items"]
        self.assertEqual([d["to"] for d in decisions], ["CANDIDATE", "NEEDS_REVIEW"])
        s14 = self.world.candidate("S14")
        approvals = self.client.get(f"{V}/candidates/{s14}/approvals").json["items"]
        self.assertEqual(approvals[0]["stage"], "OKTA_UNASSIGN")
        jobs = self.client.get(f"{V}/candidates/{s14}/execution-jobs").json["items"]
        self.assertEqual(jobs[0]["status"], "FAILED")
        self.assertEqual([e["status"] for e in jobs[0]["statusHistory"]], ["PLANNED", "RUNNING", "FAILED"])
        self.assertEqual(self.client.get(f"{V}/execution-jobs/{jobs[0]['id']}").json["job"]["id"], jobs[0]["id"])

    def test_inventory_and_collectors(self):
        group_id = self.world.store.load_candidate(self.s07).okta_group_id
        group = self.client.get(f"{V}/groups/{group_id}").json
        self.assertEqual(group["candidateIds"], [self.s07])
        self.assertEqual(group["mapping"]["adGroupId"], group["adGroup"]["id"])
        app_id = group["assignments"][0]["applicationId"]
        self.assertEqual(self.client.get(f"{V}/applications/{app_id}").json["application"]["id"], app_id)
        mapping = self.client.get(f"{V}/mappings/{group_id}").json
        self.assertEqual(mapping["registry"]["reviews"], [])
        self.assertTrue(mapping["reviewActionsAvailable"])  # the synthetic AD directory is wired in LOCAL_SYNTHETIC
        runs = self.client.get(f"{V}/collector-runs?limit=100").json
        self.assertEqual(len(runs["items"]), runs["summary"]["runs"])
        self.assertTrue(any(r["outcome"] and r["outcome"]["errorCode"] == "RATE_LIMITED" for r in runs["items"]))
        policy = self.client.get(f"{V}/policy").json
        self.assertEqual((policy["inForce"]["source"], policy["versions"]), ("UNRECORDED_SYNTHETIC_DEMO", []))

    def test_audit_and_system_views(self):
        auditor = self.world.client(ADMIN)
        page = auditor.get(f"{V}/audit-events?limit=5").json
        sequences = [e["sequence"] for e in page["items"]]
        self.assertEqual(sequences, sorted(sequences, reverse=True))
        self.assertIsNotNone(page["page"]["nextCursor"])
        scoped = auditor.get(f"{V}/candidates/{self.s07}/audit-events").json["items"]
        self.assertTrue(scoped and all(e["subjectId"] == self.s07 for e in scoped))
        integrity = auditor.get(f"{V}/system/integrity").json
        self.assertEqual(integrity["candidatesChecked"], 16)
        bindings = auditor.get(f"{V}/system/role-bindings").json
        self.assertEqual({b["role"] for b in bindings["bindings"]},
                         {"VIEWER", "IDENTITY_AUTOMATION", "SECURITY_IAM", "EXECUTOR", "ADMINISTRATOR"})


class LifecycleFlowTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.s07 = self.world.candidate("S07")

    def events(self, request_id):
        return [e for e in self.world.store.audit_events() if e.correlation_id == request_id]

    def test_approve_plan_and_record_the_okta_dry_run(self):
        security, executor, automation = (self.world.client(s) for s in (SECURITY, EXECUTOR, AUTOMATION))
        fp = self.world.fingerprint(security, self.s07)
        approved = security.post(f"{V}/candidates/{self.s07}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "synthetic review complete",
            "expectedEvidenceFingerprint": fp, "validForHours": 48})
        self.assertEqual(approved.status, 201, approved.json)
        self.assertEqual(approved.json["candidate"]["state"], "APPROVED")
        approval = approved.json["approval"]
        self.assertEqual((approval["operator"]["id"], approval["evidenceFingerprint"]), (SECURITY, fp))
        events = self.events(approved.header("x-request-id"))
        self.assertEqual([e.action for e in events], [AuditAction.APPROVAL_RECORDED, AuditAction.TRANSITION_APPLIED])
        self.assertTrue(all(e.actor.id == SECURITY for e in events))

        self.world.refresh_evidence(self.s07)  # dry runs need evidence under 24 hours old
        self.assertEqual(self.world.fingerprint(executor, self.s07), fp)  # re-observation is not a material change
        planned = executor.post(f"{V}/candidates/{self.s07}/execution-jobs", {
            "kind": "OKTA_UNASSIGN", "approvalId": approval["id"], "expectedEvidenceFingerprint": fp,
            "dryRun": True, "executionMode": "DRY_RUN_MUTATION"})
        self.assertEqual(planned.status, 201, planned.json)
        job = planned.json["job"]
        self.assertEqual((job["status"], job["dryRun"], job["executed"], job["executionMode"]),
                         ("SUCCEEDED", True, False, "DRY_RUN_MUTATION"))
        self.assertEqual(planned.json["plannedActions"],
                         [f"okta:unassign_group_from_application:{t}" for t in job["targets"]])
        self.assertFalse(planned.json["executed"])
        self.assertEqual(job["requestedBy"]["id"], EXECUTOR)
        self.assertEqual({e.action for e in self.events(planned.header("x-request-id"))},
                         {AuditAction.EXECUTION_JOB_RECORDED, AuditAction.EXECUTION_JOB_STATUS_RECORDED})

        moved = executor.post(f"{V}/candidates/{self.s07}/transitions", {
            "target": "OKTA_UNASSIGN_DRY_RUN", "reason": "dry run succeeded", "expectedEvidenceFingerprint": fp,
            "approvalId": approval["id"], "jobId": job["id"]})
        self.assertEqual(moved.status, 201, moved.json)
        self.assertEqual(moved.json["decision"]["executionJobId"], job["id"])

        for client in (automation, executor):
            observed = client.post(f"{V}/candidates/{self.s07}/transitions", {
                "target": "HOLD", "reason": "pretend it happened", "expectedEvidenceFingerprint": fp,
                "approvalId": approval["id"], "jobId": job["id"]})
            self.assertEqual((observed.status, observed.code), (403, "NOT_AN_OPERATOR_ACTION"))
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.OKTA_UNASSIGN_DRY_RUN)
        self.world.store.verify_integrity()

    def test_safer_moves_need_only_a_reason_and_forward_moves_need_a_fresh_view(self):
        automation = self.world.client(AUTOMATION)
        path = f"{V}/candidates/{self.s07}/transitions"
        self.assertEqual(automation.post(path, {"target": "BLOCKED", "reason": "hold on"}).status, 201)
        missing = automation.post(path, {"target": "CANDIDATE", "reason": "resume"})
        self.assertEqual((missing.status, missing.code), (422, "VALIDATION_FAILED"))
        stale = automation.post(path, {"target": "CANDIDATE", "reason": "resume",
                                       "expectedEvidenceFingerprint": "sha256:" + "2" * 64})
        self.assertEqual((stale.status, stale.code), (409, "EVIDENCE_CHANGED"))
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.BLOCKED)

    def test_lifecycle_refusals_are_explained_and_audited(self):
        automation = self.world.client(AUTOMATION)
        s04 = self.world.candidate("S04")  # DEPENDENCY_BLOCKED: the AD group still has members
        fp = self.world.fingerprint(automation, s04)
        result = automation.post(f"{V}/candidates/{s04}/transitions", {
            "target": "CANDIDATE", "reason": "try again", "expectedEvidenceFingerprint": fp})
        self.assertEqual((result.status, result.code), (409, "TRANSITION_REFUSED"))
        self.assertTrue(result.json["error"]["problems"])
        refused = self.events(result.header("x-request-id"))
        self.assertEqual([(e.action, e.result, e.actor.id) for e in refused],
                         [(AuditAction.TRANSITION_REFUSED, AuditResult.REFUSED, AUTOMATION)])
        not_in_table = automation.post(f"{V}/candidates/{self.s07}/transitions", {
            "target": "RETIRED", "reason": "skip ahead", "expectedEvidenceFingerprint": fp})
        self.assertEqual((not_in_table.status, not_in_table.code), (409, "TRANSITION_NOT_PERMITTED"))
        wrong_role = automation.post(f"{V}/candidates/{self.s07}/transitions", {
            "target": "APPROVED", "reason": "x", "expectedEvidenceFingerprint": self.world.fingerprint(automation, self.s07)})
        self.assertEqual((wrong_role.status, wrong_role.code), (403, "FORBIDDEN"))
        executor = self.world.client(EXECUTOR)
        diversion = executor.post(f"{V}/candidates/{self.s07}/transitions", {"target": "EXCLUDED", "reason": "x"})
        self.assertEqual(diversion.code, "FORBIDDEN")  # executors plan dry runs; they do not steer the lifecycle

    def test_security_iam_can_reject_without_moving_the_candidate(self):
        security = self.world.client(SECURITY_2)
        result = security.post(f"{V}/candidates/{self.s07}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "REJECT", "reason": "owner still needs it",
            "expectedEvidenceFingerprint": self.world.fingerprint(security, self.s07)})
        self.assertEqual(result.status, 201, result.json)
        self.assertIsNone(result.json["decision"])
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.NEEDS_REVIEW)


HR = ad_group(4, "SYNTH-App-HR")


class SyntheticMappingGateway:
    """A mapping-review gateway over the synthetic directory (tests only)."""

    def __init__(self) -> None:
        self.clock = Clock()
        self.directory = SyntheticDirectory([HR], clock=self.clock)
        self.service = MappingReviewService(directory=self.directory, config=config(),
                                            registry=InMemoryMappingRegistry(), clock=self.clock)
        self.groups = {g.okta_group_ref: g for g in (okta_native_group(3, "SYNTH-App-HR"),
                                                       okta_native_group(5, "SYNTH-App-HR"))}

    def okta_identity(self, okta_group_ref):
        self.clock.advance(timedelta(seconds=1))
        return self.groups.get(okta_group_ref)


class MappingReviewApiTests(unittest.TestCase):
    def setUp(self):
        self.gateway = SyntheticMappingGateway()
        self.world = World(mapping_gateway=self.gateway)
        self.addCleanup(self.world.close)
        self.group, self.other_group = list(self.gateway.groups)

    def search(self, client, group):
        result = client.post(f"{V}/mappings/{group}/searches", {"by": LookupKind.NAME.value, "value": "SYNTH-App-HR"})
        self.assertEqual(result.status, 201, result.json)
        return result.json["searchId"]

    def test_selection_and_approval_are_separate_people_and_roles(self):
        automation, security = self.world.client(AUTOMATION), self.world.client(SECURITY)
        search_id = self.search(automation, self.group)
        selection = {"searchId": search_id, "objectGuid": HR.object_guid, "reason": "owner confirmed (synthetic)"}
        self.assertEqual(security.post(f"{V}/mappings/{self.group}/selections", selection).code, "FORBIDDEN")
        self.assertEqual(self.world.client(AUTOMATION_2).post(f"{V}/mappings/{self.group}/selections", selection).code,
                         "NOT_FOUND")  # a search result belongs to whoever ran it
        proposed = automation.post(f"{V}/mappings/{self.group}/selections", selection)
        self.assertEqual((proposed.status, proposed.json["review"]["reviewStatus"]), (201, "PROPOSED"))
        inspection = security.post(f"{V}/mappings/{self.group}/inspection", {}).json
        self.assertEqual(inspection["approvableObjectGuid"], HR.object_guid)
        approval = {"objectGuid": HR.object_guid, "expectedEvidenceFingerprint": inspection["evidenceFingerprint"],
                    "reason": "second pair of eyes"}
        self.assertEqual(automation.post(f"{V}/mappings/{self.group}/approvals", approval).code, "FORBIDDEN")
        approved = security.post(f"{V}/mappings/{self.group}/approvals", approval)
        self.assertEqual(approved.status, 201, approved.json)
        self.assertEqual((approved.json["review"]["reviewStatus"], approved.json["review"]["decidedBy"]["id"]),
                         ("APPROVED", SECURITY))

    def test_one_person_holding_both_roles_cannot_select_and_approve(self):
        dual = self.world.client(DUAL)
        search_id = self.search(dual, self.other_group)
        self.assertEqual(dual.post(f"{V}/mappings/{self.other_group}/selections", {
            "searchId": search_id, "objectGuid": HR.object_guid, "reason": "mine"}).status, 201)
        fp = dual.post(f"{V}/mappings/{self.other_group}/inspection", {}).json["evidenceFingerprint"]
        result = dual.post(f"{V}/mappings/{self.other_group}/approvals",
                           {"objectGuid": HR.object_guid, "expectedEvidenceFingerprint": fp, "reason": "also mine"})
        self.assertEqual((result.status, result.code), (409, "REVIEW_REFUSED"))
        self.assertTrue(any("cannot also approve" in p for p in result.json["error"]["problems"]))

    def test_mapping_review_is_unavailable_without_a_directory(self):
        world = World(synthetic_directory=False)
        self.addCleanup(world.close)
        group = world.store.load_candidate(world.candidate("S07")).okta_group_id
        result = world.client(SECURITY).post(f"{V}/mappings/{group}/inspection", {})
        self.assertEqual((result.status, result.code), (503, "MAPPING_REVIEW_UNAVAILABLE"))


class LocalServerTests(unittest.TestCase):
    def test_serves_on_loopback_only(self):
        world = World()
        self.addCleanup(world.close)
        server = make_local_server(world.api, 0)
        host, port = server.server_address[:2]
        self.assertEqual(host, "127.0.0.1")
        seen = {}

        def client():  # the server runs on this test's thread, as `serve` runs on the main thread
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                connection.request("GET", f"{V}/health")
                response = connection.getresponse()
                seen.update(status=response.status, request_id=response.getheader("X-Request-Id"),
                            policy=response.getheader("X-OGWA-Policy-Status"), body=json.loads(response.read()))
                connection.close()
            finally:
                server.shutdown()

        thread = threading.Thread(target=client, daemon=True)
        thread.start()
        try:
            server.serve_forever()
        finally:
            server.server_close()
            thread.join(timeout=10)
        self.assertEqual(seen["status"], 200)
        self.assertRegex(seen["request_id"], REQUEST_ID)
        self.assertEqual(seen["body"], {"status": "ok", "policyNotice": "DEMO POLICY — UNRECORDED"})
        self.assertEqual(seen["policy"], "DEMO-UNRECORDED")

    def test_privileged_ports_are_refused(self):
        world = World()
        self.addCleanup(world.close)
        for port in (80, 443, 70000):
            with self.subTest(port=port), self.assertRaises(ValueError):
                make_local_server(world.api, port)

    def test_cli_refuses_modes_other_than_local_synthetic(self):
        environ = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        environ["OGWA_EXECUTION_MODE"] = "READ_ONLY_PRODUCTION"
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(api_main, "configure_logging"), \
                mock.patch.object(api_main, "make_local_server") as serve, \
                self.assertLogs("ogwa", level="WARNING") as logs:
            self.assertEqual(api_main.main(["serve", "--port", "0"]), 2)
        serve.assert_not_called()
        self.assertTrue(any("LOCAL_SYNTHETIC" in line and "refused" in line for line in logs.output))


class StaticSafetyTests(unittest.TestCase):
    def test_read_model_only_selects(self):
        tree = ast.parse((API_DIR / "readmodel.py").read_text(encoding="utf-8"))
        statements = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                first = node.args[0]
                text = first.value if isinstance(first, ast.Constant) else "".join(
                    v.value for v in first.values if isinstance(v, ast.Constant))
                self.assertTrue(text.lstrip().upper().startswith("SELECT"), text)
                statements += 1
        self.assertGreater(statements, 5)

    def test_api_imports_no_network_mutation_or_integration_module(self):
        forbidden = ("app.integrations", "http.client",
                     "urllib.request", "subprocess", "socket", "ssl", "requests")
        for path in sorted(API_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module or ""] if isinstance(node, ast.ImportFrom) else []
                for name in names:
                    with self.subTest(module=path.name, imports=name):
                        self.assertFalse(any(name == f or name.startswith(f + ".") for f in forbidden))

    def test_api_error_bodies_carry_only_safe_fields(self):
        error = ApiError(403, "FORBIDDEN", "Authorization: Bearer synthetic-value-123456789", problems=["token=abc"])
        body = json.dumps(error.body("req_" + "0" * 32))
        self.assertNotIn("synthetic-value-123456789", body)
        self.assertNotIn("abc", body)


if __name__ == "__main__":
    unittest.main()
