"""The hosted (Cloudflare Worker) demo application, driven outside Cloudflare.

``app.cloudflare.hosted.HostedDemo`` is what the Worker runs: the real demo application over
an in-memory, read-only copy of the validated Null Meridian demo store. These tests build it
from the bytes of a demo store reset by the demo reset, exactly as ``python -m app.cloudflare
build`` and the Worker do, and prove the deployment's safety properties: the store cannot
change, persisting requests are refused and nothing is recorded, D1 must hold exactly the
served store, the Worker's environment goes through the demo profile, and no live system is
reached. Expected values come from the dataset (its manifest and golden audit head).
"""

import asyncio
import base64
import gzip
import json
import sqlite3
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from app.api.app import API_PREFIX
from app.api.authz import Permission as P
from app.api.identity import PrincipalClaims
from app.api.sessions import SignedSessionManager
from app.cloudflare.hosted import (
    SESSION_KEY_NAME,
    HostedDemo,
    NoAssets,
    VisitorSessions,
    read_gzip_image,
    wsgi_environ,
)
from app.cloudflare.identity import SCHEMA_SQL, read_identity
from app.core.config import load_settings
from app.core.errors import OgwaSafetyError
from app.runtime.api import (
    DEMO_MUTATION_POLICY,
    DRILL_SCOPE_MESSAGE,
    NO_SIGN_IN_MESSAGE,
    NON_PERSISTING,
    NOTHING_RECORDED_NOTICE,
    READ_ONLY_MESSAGE,
    RUNTIME_HEADER,
    VISITOR_METHOD,
    VISITOR_SUBJECT,
    RuntimeProfile,
    demo_routes,
)
from app.api.routes import ROUTES
from app.runtime.datasets import resolve_dataset
from app.runtime.demo_store import DemoPersistenceUnavailable, open_demo_image, reset_demo_store
from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.store.db import connect_image
from app.store.errors import StoreIntegrityError
from app.store.store import Store, utc_now
from app.demo.null_meridian.world import CANDIDATES
from tests.test_demo_mode import no_live_system
from tests.test_null_meridian_demo import manifest_group, okta_ref
from tests.test_null_meridian_seed import GOLDEN_AUDIT_HEAD

REPO = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((REPO / "docs" / "demo" / "null-meridian.manifest.json").read_text(encoding="utf-8"))
ENVIRONMENT = {"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": "null-meridian"}
KEY = {SESSION_KEY_NAME: "ab" * 32}  # the Worker secret that signs session cookies (test value)
ORIGIN = "https://ogwa-demo.example.workers.dev"
V = API_PREFIX
GROUP = okta_ref(manifest_group("sg-okta-crm-user")["key"])  # the manifest's representative group

_TMP: tempfile.TemporaryDirectory | None = None
IMAGE = b""
CLASSIC_IMAGE = b""


def setUpModule():
    global _TMP, IMAGE, CLASSIC_IMAGE
    _TMP = tempfile.TemporaryDirectory(prefix="ogwa-cf-hosted-")
    IMAGE = demo_image(Path(_TMP.name), "null-meridian")
    CLASSIC_IMAGE = demo_image(Path(_TMP.name), "classic")


def tearDownModule():
    _TMP.cleanup()


def demo_image(root: Path, dataset: str) -> bytes:
    var = root / dataset / "var"
    var.mkdir(parents=True)
    path = var / "ogwa-demo.sqlite3"
    settings = load_settings({"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": dataset,
                              "OGWA_DATABASE_URL": f"sqlite:///{path.as_posix()}"})
    reset_demo_store(settings, resolve_dataset(dataset), confirmed=True, allowed_root=var)
    return path.read_bytes()


def identity_row(hosted: HostedDemo, **changes) -> dict:
    return {**hosted.identity.to_json(), **changes}


class Client:
    """Requests the way the Worker passes them to ``HostedDemo.handle``."""

    def __init__(self, hosted: HostedDemo, origin: str = ORIGIN) -> None:
        self.hosted, self.origin, self.cookie, self.csrf = hosted, origin, None, None

    def request(self, method: str, path: str, body: dict | None = None, origin: str | None = None):
        headers = [("host", self.origin.split("//", 1)[1])]
        data = b""
        if body is not None:
            data = json.dumps(body).encode()
            headers += [("content-type", "application/json"), ("content-length", str(len(data))),
                        ("origin", origin or self.origin)]
        if self.cookie:
            headers.append(("cookie", self.cookie))
        if self.csrf and method == "POST":
            headers.append(("x-ogwa-csrf", self.csrf))
        status, response_headers, payload = self.hosted.handle(method, self.origin + path, headers, data)
        for name, value in response_headers:
            if name.lower() == "set-cookie":
                self.cookie = value.split(";", 1)[0]
        return status, dict(response_headers), (json.loads(payload) if payload.startswith(b"{") else payload)

    def visit(self) -> dict:
        """The public demo's only entry: GET /session gives a new visitor an anonymous session."""
        status, _, body = self.request("GET", f"{V}/session")
        assert status == 200, status
        self.csrf = body["csrfToken"]
        return body["principal"]

    def as_fixture(self, subject: str) -> None:
        """Test only: a session for a synthetic IdP principal, minted directly. The public demo has no route to
        one, and once the Worker's environment is checked (``VisitorSessions``) it refuses one."""
        api = self.hosted.app.api
        token, session = api.sessions.create(api.identity.authenticate({"subject": subject}, now=api.clock()))
        self.cookie, self.csrf = f"__Host-ogwa-session={token}", session.csrf_token

    def scenario(self, key: str) -> str:
        return next(s["candidateId"] for s in self.request("GET", f"{V}/demo-scenarios")[2]["items"]
                    if s.get("candidateKey") == key)

    def audit_head(self) -> int:
        return self.hosted.app.store.audit_head()[0]


class HostedDemoBuildTests(unittest.TestCase):
    def test_the_image_opens_read_only_validated_and_at_the_golden_head(self):
        hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT, expected={"audit_head": GOLDEN_AUDIT_HEAD})
        self.addCleanup(hosted.app.close)
        self.assertTrue(hosted.app.store.read_only)
        self.assertEqual(hosted.identity.audit_head, GOLDEN_AUDIT_HEAD)
        self.assertEqual((hosted.identity.dataset, hosted.identity.seed, hosted.identity.company, hosted.identity.environment),
                         ("null-meridian", "null-meridian-v1", "Null Meridian", "SYNTHETIC"))
        report = hosted.app.report
        self.assertEqual((report.dataset, report.seed_namespace, report.integrity.audit_head),
                         ("null-meridian", "null-meridian-v1", GOLDEN_AUDIT_HEAD))
        with self.assertRaises(sqlite3.OperationalError):
            hosted.app.store.connection.execute("DELETE FROM synthetic_directory_records")
        with self.assertRaises(sqlite3.OperationalError):  # the append-only triggers never even run
            hosted.app.store.connection.execute("INSERT INTO policy_versions (id) VALUES ('x')")

    def test_an_image_that_is_not_the_built_store_is_refused(self):
        hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)
        self.addCleanup(hosted.app.close)
        with self.assertRaises(OgwaSafetyError):
            HostedDemo(lambda: IMAGE, ENVIRONMENT, expected={"identity": identity_row(hosted, audit_sequence=1)})
        with self.assertRaises(OgwaSafetyError):
            HostedDemo(lambda: IMAGE, ENVIRONMENT, expected={"schema": "sha256:" + "0" * 64})
        with self.assertRaises(DemoPersistenceUnavailable):  # validate_demo_store pins the head
            HostedDemo(lambda: IMAGE, ENVIRONMENT, expected={"audit_head": "sha256:" + "0" * 64})

    def test_the_demo_store_checks_apply_to_an_image(self):
        settings = load_settings(ENVIRONMENT)
        nm = resolve_dataset("null-meridian")
        with self.assertRaisesRegex(DemoPersistenceUnavailable, "ogwa-synthetic-demo-v1"):
            open_demo_image(settings, nm, lambda: CLASSIC_IMAGE, clock=utc_now)
        tampered = sqlite3.connect(":memory:", isolation_level=None)  # autocommit: serialize() sees the change
        self.addCleanup(tampered.close)
        tampered.deserialize(IMAGE)
        tampered.execute("DROP TRIGGER trg_synthetic_directory_records_no_update")
        tampered.execute("UPDATE synthetic_directory_records SET body = replace(body, 'a', 'b') WHERE rowid = 7")
        with self.assertRaisesRegex(DemoPersistenceUnavailable, "failed verification"):
            open_demo_image(settings, nm, tampered.serialize, clock=utc_now)
        with self.assertRaises(DemoPersistenceUnavailable):
            open_demo_image(settings, nm, lambda: b"not a database" * 100, clock=utc_now)

    def test_only_the_demo_runtime_builds(self):
        with self.assertRaises(OgwaSafetyError):
            HostedDemo(lambda: IMAGE, {"OGWA_DEMO_DATASET": "null-meridian"})

    def test_building_and_serving_reach_no_live_system(self):
        with no_live_system():
            hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)
            self.addCleanup(hosted.app.close)
            client = Client(hosted)
            client.as_fixture("synthetic.automation.one")
            for path in ("/health", "/directory", "/people?status=ACTIVE", "/governance-findings", "/mappings",
                         "/candidates", "/applications", "/groups"):
                self.assertEqual(client.request("GET", V + path)[0], 200, path)
            self.assertEqual(client.request("POST", f"{V}/mappings/{GROUP}/inspection", {})[0], 200)
        self.assertEqual(type(hosted.app.providers.aap).__name__, "DisabledAapProvider")
        self.assertEqual(type(hosted.app.providers.okta).__name__, "SyntheticOktaProvider")


class HostedDemoChecksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)

    @classmethod
    def tearDownClass(cls):
        cls.hosted.app.close()

    def test_d1_must_hold_exactly_the_served_store(self):
        h = self.hosted
        self.assertTrue(h.check_d1(identity_row(h)))
        self.assertTrue(h.check_d1(identity_row(h, audit_sequence=float(h.identity.audit_sequence))))
        for field, value in (("audit_head", "sha256:" + "1" * 64), ("audit_sequence", 1404),
                             ("store_instance_id", "req_" + "0" * 32), ("environment", "PRODUCTION"),
                             ("dataset", "classic"), ("directory_digest", None), ("schema_version", 11)):
            with self.subTest(field=field):
                self.assertFalse(h.check_d1(identity_row(h, **{field: value})))
        self.assertFalse(h.check_d1(None))
        self.assertFalse(h.check_d1({"audit_head": h.identity.audit_head}))

    def test_d1_must_hold_the_complete_schema(self):
        h = HostedDemo(lambda: IMAGE, ENVIRONMENT)
        self.addCleanup(h.app.close)
        rows = [dict(r) for r in h.app.store.connection.execute(SCHEMA_SQL)]
        self.assertTrue(h.schema_check_due())
        self.assertFalse(h.check_schema([r for r in rows if r["type"] != "trigger"]), "a partial bootstrap")
        self.assertFalse(h.schema_check_due(), "a failed check waits before retrying")
        self.assertFalse(h.check_schema(None))
        self.assertTrue(h.check_schema(list(reversed(rows))))
        self.assertFalse(h.schema_check_due(), "checked once per isolate")
        altered = [dict(r, sql=r["sql"] + " ") if r["name"] == "audit_events" else r for r in rows]
        self.assertFalse(h.check_schema(altered))

    def test_the_worker_environment_goes_through_the_demo_profile(self):
        h = self.hosted
        self.assertTrue(h.check_environment({**ENVIRONMENT, **KEY, "UNRELATED": "x"}))
        self.assertIsInstance(h.app.api.sessions, VisitorSessions)
        refused = ({**ENVIRONMENT, "OKTA_API_TOKEN": "x"}, {**ENVIRONMENT, "OGWA_AAP_URL": "https://aap.example"},
                   {**ENVIRONMENT, "OGWA_OKTA_API_TOKEN": "x"}, {**ENVIRONMENT, "LDAP_BIND_PASSWORD": "x"},
                   {**ENVIRONMENT, "OGWA_DEMO_DATASET": "classic"}, {"OGWA_DEMO_DATASET": "null-meridian"},
                   {**ENVIRONMENT, "OGWA_UNKNOWN": "x"})
        for environment in refused:
            with self.subTest(environment=sorted(environment)):
                self.assertFalse(h.check_environment({**environment, **KEY}))
        for key in ({}, {SESSION_KEY_NAME: "ab" * 31}, {SESSION_KEY_NAME: "zz" * 32}, {SESSION_KEY_NAME: ""}):
            with self.subTest(key=sorted(key)):
                self.assertFalse(h.check_environment({**ENVIRONMENT, **key}), "no usable signing key, nothing served")
        self.assertTrue(h.check_environment({**ENVIRONMENT, **KEY}))

    def test_unavailable_serves_nothing(self):
        status, headers, payload = self.hosted.unavailable()
        self.assertEqual(status, 503)
        body = json.loads(payload)
        self.assertEqual(body["error"]["code"], "DEMO_STORE_UNAVAILABLE")
        self.assertRegex(body["error"]["requestId"], r"^req_[0-9a-f]{32}$")
        self.assertEqual(dict(headers)[RUNTIME_HEADER], "demo")
        self.assertNotIn("Null Meridian", payload.decode())


class HostedDemoRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)

    @classmethod
    def tearDownClass(cls):
        cls.hosted.app.close()

    def setUp(self):
        self.client = Client(self.hosted)
        self.head = self.client.audit_head()

    def tearDown(self):
        self.assertEqual(self.client.audit_head(), self.head, "the hosted store never changes")

    def test_health_names_the_dataset_and_the_runtime(self):
        status, headers, body = self.client.request("GET", f"{V}/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers[RUNTIME_HEADER], "demo")
        self.assertEqual((body["organization"], body["dataset"]["seed"], body["liveIntegrations"], body["publicDemo"]),
                         ("Null Meridian", "null-meridian-v1", False, True))

    def test_the_real_views_serve_the_canonical_dataset(self):
        self.client.visit()
        directory = self.client.request("GET", f"{V}/directory")[2]
        self.assertEqual(directory["counts"], MANIFEST["counts"])
        people = self.client.request("GET", f"{V}/people?q=NM00001")[2]["items"]
        self.assertEqual(len(people), 1)
        self.assertEqual(self.client.request("GET", f"{V}/people/{people[0]['id']}")[0], 200)
        self.assertEqual(len(self.client.request("GET", f"{V}/candidates")[2]["items"]), len(CANDIDATES))
        self.assertEqual(self.client.request("GET", f"{V}/mappings/{GROUP}")[0], 200)

    def test_a_visitor_is_an_anonymous_viewer_and_no_one_can_sign_in(self):
        status, headers, body = self.client.request("GET", f"{V}/session")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Set-Cookie"].startswith("__Host-ogwa-session="))
        principal = body["principal"]
        self.assertEqual((principal["subject"], principal["authenticationMethod"], principal["roles"],
                          principal["permissions"]), (VISITOR_SUBJECT, VISITOR_METHOD, ["VIEWER"], ["READ_INVENTORY"]))
        self.assertEqual(principal["publicDrillCandidates"], [self.client.scenario("NM-C11")])
        status, headers, again = self.client.request("GET", f"{V}/session")
        self.assertEqual((status, again["csrfToken"]), (200, body["csrfToken"]), "the same session")
        self.assertNotIn("Set-Cookie", headers)
        other = Client(self.hosted)
        self.assertNotEqual(other.visit() and other.csrf, body["csrfToken"], "each visitor gets their own session")
        for subject in ("synthetic.viewer.one", "synthetic.executor.one", "synthetic.securityiam.one",
                        "synthetic.automation.one", "synthetic.admin.one", VISITOR_SUBJECT):
            with self.subTest(subject=subject):
                status, headers, answer = self.client.request("POST", f"{V}/session", {"subject": subject})
                self.assertEqual((status, answer["error"]["code"], answer["error"]["message"]),
                                 (403, "PUBLIC_DEMO_NO_SIGN_IN", NO_SIGN_IN_MESSAGE))
                self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(self.client.request("GET", f"{V}/session")[2]["principal"]["subject"], VISITOR_SUBJECT)
        status, _, body = self.client.request("POST", f"{V}/session", {"subject": "synthetic.viewer.one"},
                                              origin="https://elsewhere.example")
        self.assertEqual((status, body["error"]["code"]), (403, "ORIGIN_REFUSED"))
        for path in ("/audit-events?limit=1", "/system/integrity", "/system/role-bindings"):
            with self.subTest(path=path):
                self.assertEqual(self.client.request("GET", V + path)[0], 403, "a viewer's permissions only")

    def test_every_persisting_request_is_refused_and_nothing_is_recorded(self):
        # Every visitor gets the read-only explanation, not a bare 403 for a role it lacks.
        candidate = self._candidate("NEEDS_REVIEW")
        group = GROUP
        attempts = [
            (f"/candidates/{candidate}/approvals", {"stage": "OKTA_UNASSIGN", "decision": "APPROVE",
                                                   "reason": "x", "validHours": 24, "acknowledged": True}),
            (f"/candidates/{candidate}/transitions", {"to": "BLOCKED", "reason": "x"}),
            (f"/candidates/{candidate}/transitions", {"to": "HOLD", "reason": "x"}),
            (f"/mappings/{group}/approvals", {"objectGuid": "x", "expectedEvidenceFingerprint": "x", "reason": "x"}),
            (f"/mappings/{group}/rejections", {"objectGuid": "x", "expectedEvidenceFingerprint": "x", "reason": "x"}),
            (f"/mappings/{group}/selections", {"searchId": "x", "objectGuid": "x", "reason": "x"}),
            (f"/candidates/{candidate}/execution-jobs", {"kind": "OKTA_UNASSIGN", "dryRun": True}),
            (f"/candidates/{candidate}/remediation-dry-runs", {"operation": "x"}),
        ]
        client = self._visitor()
        before = self._state(client, candidate)
        for path, body in attempts:
            with self.subTest(path=path, body=body):
                status, _, answer = client.request("POST", V + path, body)
                self.assertEqual((status, answer["error"]["code"]), (403, "DEMO_READ_ONLY"))
                self.assertEqual(answer["error"]["message"], READ_ONLY_MESSAGE)
                self.assertNotIn("auditEventId", answer["error"], "a read-only store chains nothing")
        self.assertEqual(self._state(client, candidate), before)
        missing_csrf = Client(self.hosted)
        missing_csrf.visit()
        missing_csrf.csrf = None
        status, _, answer = missing_csrf.request("POST", V + attempts[0][0], attempts[0][1])
        self.assertEqual((status, answer["error"]["code"]), (403, "CSRF_FAILED"), "CSRF is still checked first")

    def test_a_visitor_drills_nm_c11_and_nothing_else_and_it_records_nothing(self):
        # OGWA-DEMO-03: NM-C11 is approved on evidence fresh at the demo's clock. Its drill changes
        # only an in-memory provider fixture, so the read-only demo serves it (tearDown: the
        # audit head never moves). OGWA-DEMO-HOSTED-ANON-01: an anonymous visitor runs it, on NM-C11 only.
        visitor = self._visitor()
        candidate = visitor.scenario("NM-C11")
        detail = visitor.request("GET", f"{V}/candidates/{candidate}")[2]
        approval = visitor.request("GET", f"{V}/candidates/{candidate}/approvals")[2]["items"][0]
        body = {"operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": detail["candidate"]["assignmentIds"][0]},
                "approvalId": approval["id"], "expectedEvidenceFingerprint": detail["evidenceFingerprint"]}
        before = self._state(visitor, candidate)
        with no_live_system():
            status, _, answer = visitor.request("POST", f"{V}/candidates/{candidate}/remediation-drills",
                                                {**body, "mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"})
            self.assertEqual(status, 200, answer)
            drill = answer["drill"]
            self.assertEqual([s["state"] for s in drill["steps"]], [
                "EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "RETRY_PERMITTED", "EXECUTION_REQUESTED",
                "EXECUTED", "POST_ACTION_VERIFIED"])
            ledger = drill["provider"]["ledger"]
            self.assertEqual([(e["actor"], e["applied"]) for e in ledger],
                             [(drill["operationId"], False), (drill["operationId"], True)], "one operation id, retried")
            self.assertEqual((drill["provider"]["mutationsApplied"], drill["recorded"]), (1, False))
            self.assertEqual(answer["demo"]["notice"], NOTHING_RECORDED_NOTICE)
            status, _, dry = visitor.request("POST", f"{V}/candidates/{candidate}/remediation-drills",
                                             {**body, "mode": "DRY_RUN"})
            self.assertEqual((status, dry["drill"]["finalState"], dry["drill"]["submissions"]), (200, "DRY_RUN", 0))
        self.assertEqual(self._state(visitor, candidate), before)
        # The drill is the only thing the visitor's NM-C11 grant reaches, and it never becomes the session's.
        session = visitor.request("GET", f"{V}/session")[2]["principal"]
        self.assertEqual((session["roles"], session["permissions"]), (["VIEWER"], ["READ_INVENTORY"]))
        for path, request in ((f"/candidates/{candidate}/execution-jobs", {"kind": "OKTA_UNASSIGN", "dryRun": True}),
                              (f"/candidates/{candidate}/approvals", {"stage": "OKTA_UNASSIGN", "decision": "APPROVE",
                                                                     "reason": "x", "validHours": 24,
                                                                     "acknowledged": True})):
            self.assertEqual(visitor.request("POST", V + path, request)[2]["error"]["code"], "DEMO_READ_ONLY")
        self.assertEqual(visitor.request("POST", f"{V}/mappings/{GROUP}/inspection", {})[0], 403)
        for mode in ({"mode": "DRY_RUN"}, {"mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"},
                     {"mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED",
                      "executionMode": "PRODUCTION_MUTATION"}):
            with self.subTest(mode=mode):
                status, _, answer = visitor.request("POST", f"{V}/candidates/{candidate}/remediation-drills",
                                                    {**body, **mode, "approvalId": "apr_" + "0" * 32})
                self.assertIn(status, (403, 404, 422), answer)
                self.assertNotIn("drill", answer)

    def test_nm_c11s_drill_grant_reaches_no_other_candidate(self):
        visitor = self._visitor()
        c11, c10 = visitor.scenario("NM-C11"), visitor.scenario("NM-C10")
        approval = visitor.request("GET", f"{V}/candidates/{c11}/approvals")[2]["items"][0]["id"]
        others = [c["id"] for c in visitor.request("GET", f"{V}/candidates")[2]["items"] if c["id"] != c11]
        self.assertIn(c10, others)
        before = {c: self._state(visitor, c) for c in (c10, c11)}
        for candidate in others:
            detail = visitor.request("GET", f"{V}/candidates/{candidate}")[2]
            target = {"assignmentId": (detail["candidate"]["assignmentIds"] or ["asg_" + "0" * 32])[0]}
            for approval_id in (approval, "apr_" + "0" * 32):  # borrowed from NM-C11, and forged
                for mode in ({"mode": "DRY_RUN"}, {"mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"}):
                    with self.subTest(candidate=candidate, approval=approval_id[:12], mode=mode["mode"]):
                        status, _, answer = visitor.request("POST", f"{V}/candidates/{candidate}/remediation-drills", {
                            "operation": "OKTA_GROUP_UNASSIGN", "target": target, "approvalId": approval_id,
                            "expectedEvidenceFingerprint": detail["evidenceFingerprint"], **mode})
                        self.assertEqual((status, answer["error"]["code"], answer["error"]["message"]),
                                         (403, "PUBLIC_DRILL_SCOPE", DRILL_SCOPE_MESSAGE))
                        self.assertNotIn("drill", answer)
        self.assertEqual({c: self._state(visitor, c) for c in (c10, c11)}, before)
        nm_c10 = visitor.request("GET", f"{V}/candidates/{c10}")[2]
        self.assertEqual((nm_c10["candidate"]["state"], nm_c10["evidenceAssessment"]["decision"]["code"]),
                         ("NEEDS_REVIEW", "CONFLICTING_EVIDENCE"))

    def test_the_public_walkthrough_names_no_synthetic_principal(self):
        guide = self._visitor().request("GET", f"{V}/demo-scenarios")[2]["walkthrough"]
        text = json.dumps(guide)
        for phrase in ("synthetic.executor", "synthetic.securityiam", "synthetic.viewer", "Sign in", "Signed in"):
            self.assertNotIn(phrase, text)
        self.assertEqual([p["candidateKey"] for p in guide["parts"] if p.get("publicDrill")], ["NM-C11"])
        self.assertIn("No sign-in is needed", text)

    def test_inspection_and_search_need_a_mapping_role_no_visitor_has(self):
        client = self._visitor()
        for path, body in ((f"/mappings/{GROUP}/inspection", {}),
                           (f"/mappings/{GROUP}/searches", {"by": "SAM_ACCOUNT_NAME", "value": "crm-users"})):
            with self.subTest(path=path):
                status, _, answer = client.request("POST", V + path, body)
                self.assertEqual((status, answer["error"]["code"]), (403, "FORBIDDEN"))

    def test_execution_stays_refused(self):
        status, _, body = self._visitor().request("POST", f"{V}/execution-jobs/job_{'0' * 32}/execute", {})
        self.assertEqual((status, body["error"]["code"]), (403, "DEMO_MODE_BLOCKED"))

    def test_paths_outside_the_api_are_not_found(self):
        for path in ("/", "/ui/js/main.js", "/index.html", "/../config/synthetic-idp.json"):
            with self.subTest(path=path):
                self.assertEqual(self.client.request("GET", path)[0], 404)

    def _visitor(self) -> Client:
        client = Client(self.hosted)
        client.visit()
        return client

    def _candidate(self, state: str) -> str:
        items = self._visitor().request("GET", f"{V}/candidates")[2]["items"]
        return next(c["id"] for c in items if c["state"] == state)

    @staticmethod
    def _state(client: Client, candidate: str) -> tuple:
        """What a visitor can see of a candidate's governed state, and the dashboard's audit head."""
        reads = [client.request("GET", f"{V}/candidates/{candidate}{tail}")[2]
                 for tail in ("", "/decisions", "/approvals", "/execution-jobs", "/remediation-dry-runs")]
        store = client.request("GET", f"{V}/dashboard")[2]["store"]
        return (reads[0]["candidate"]["state"], json.dumps(reads[1:], sort_keys=True), store["auditEvents"],
                store["auditHead"])


class HostedIntegrityTests(unittest.TestCase):
    """``GET /system/integrity`` in the hosted demo (OGWA-INTEGRITY-COST-03): the store cannot change, so
    the route serves the full verification made when the image was opened instead of re-running it."""

    def setUp(self):
        self.spy = mock.patch.object(Store, "verify_integrity", autospec=True, side_effect=Store.verify_integrity)

    def test_the_route_serves_the_verification_made_when_the_image_was_opened(self):
        with self.spy as verify:
            hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT, expected={"audit_head": GOLDEN_AUDIT_HEAD})
            self.addCleanup(hosted.app.close)
            self.assertEqual(verify.call_count, 1, "the real verifier ran once, at load")
            self.assertEqual(verify.call_args.kwargs, {"expected_audit_head": GOLDEN_AUDIT_HEAD})
            loaded = hosted.app.report.integrity
            self.assertEqual(loaded.audit_head, hosted.identity.audit_head, "bound to the identity D1 must match")
            admin = Client(hosted)
            admin.as_fixture("synthetic.admin.one")
            bodies = [admin.request("GET", f"{V}/system/integrity") for _ in range(20)]
            self.assertEqual(verify.call_count, 1, "repeated requests verify nothing again")
        self.assertEqual({status for status, _, _ in bodies}, {200})
        fresh = hosted.app.store.verify_integrity()
        self.assertEqual(fresh, loaded)
        self.assertEqual(bodies[-1][2], {
            "schemaVersion": fresh.schema_version, "environment": "SYNTHETIC", "auditEvents": fresh.audit_events,
            "auditHead": GOLDEN_AUDIT_HEAD, "observationsChecked": fresh.observations_checked,
            "candidatesChecked": fresh.candidates_checked})  # recorded policy versions: no unrecorded notice
        visitor = Client(hosted)
        visitor.visit()
        self.assertEqual(visitor.request("GET", f"{V}/system/integrity")[0], 403, "authorization is unchanged")
        # The per-request D1 check is independent of the report (entry.py runs it before the application).
        self.assertFalse(hosted.check_d1(identity_row(hosted, audit_head="sha256:" + "1" * 64)))

    def test_concurrent_first_requests_verify_nothing_again(self):
        # An isolate interleaves requests only at its awaits (the D1 queries, entry.py), never inside
        # handle(), and it starts from the deploy-time snapshot, where the load-time report already is.
        hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)
        self.addCleanup(hosted.app.close)
        clients = [Client(hosted) for _ in range(10)]
        for client in clients:
            client.as_fixture("synthetic.admin.one")

        async def fetch(client):
            await asyncio.sleep(0)  # the D1 identity query
            self.assertTrue(hosted.check_d1(identity_row(hosted)))
            return client.request("GET", f"{V}/system/integrity")[0]

        async def burst():
            return await asyncio.gather(*(fetch(c) for c in clients))

        with self.spy as verify:
            statuses = asyncio.run(burst())
        self.assertEqual((statuses, verify.call_count), ([200] * 10, 0))

    def test_a_changed_store_is_verified_again_and_a_failure_is_never_kept(self):
        store = Store._from_connection(connect_image(IMAGE), mode=ExecutionMode.LOCAL_SYNTHETIC, clock=utc_now)
        self.addCleanup(store.close)
        first = store.verify_integrity()
        conn = store.connection
        with self.spy as verify:
            self.assertIs(store.verified_integrity(), first)
            conn.execute("PRAGMA query_only = OFF")
            store.verified_integrity()
            self.assertEqual(verify.call_count, 1, "a store that can change is verified on every call")
            store.record_governed_refusal(actor=Actor(ActorKind.HUMAN, "synthetic.viewer.one"),
                                          subject_id="cand_" + "0" * 32, details={"route": "test"},
                                          correlation_id="req_" + "1" * 32)
            conn.execute("PRAGMA query_only = ON")
            second = store.verified_integrity()
            self.assertEqual(verify.call_count, 2, "a new audit head is verified again")
            self.assertEqual((second.audit_events, second.audit_head), (first.audit_events + 1, store.audit_head()[1]))
            self.assertIs(store.verified_integrity(), second)
            # A change the audit chain does not see (its guard trigger dropped) is verified again, and fails.
            conn.execute("PRAGMA query_only = OFF")
            conn.execute("DROP TRIGGER trg_synthetic_directory_records_no_update")
            conn.execute("UPDATE synthetic_directory_records SET body = replace(body, 'a', 'b') WHERE rowid = 7")
            conn.execute("PRAGMA query_only = ON")
            for _ in range(2):
                with self.assertRaises(StoreIntegrityError):
                    store.verified_integrity()
            self.assertEqual(verify.call_count, 4, "a failed verification is never kept")

    def test_operator_verification_always_runs_in_full(self):
        hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)
        self.addCleanup(hosted.app.close)
        store = hosted.app.store
        with mock.patch.object(Store, "_verify_synthetic_directory", autospec=True,
                               side_effect=Store._verify_synthetic_directory) as directory:
            store.verify_integrity()
            store.verify_integrity()
            self.assertEqual(directory.call_count, 2)
        with self.assertRaises(StoreIntegrityError):  # a pinned head is still checked
            store.verify_integrity(expected_audit_head="sha256:" + "0" * 64)


class SignedSessionTests(unittest.TestCase):
    """Consecutive requests reach different isolates: a session made by one must work in another."""

    @classmethod
    def setUpClass(cls):
        cls.a, cls.b, cls.other = (HostedDemo(lambda: IMAGE, ENVIRONMENT) for _ in range(3))
        for hosted, key in ((cls.a, KEY), (cls.b, KEY), (cls.other, {SESSION_KEY_NAME: "cd" * 32})):
            assert hosted.check_environment({**ENVIRONMENT, **key})

    @classmethod
    def tearDownClass(cls):
        for hosted in (cls.a, cls.b, cls.other):
            hosted.app.close()

    def moved(self, client: Client, hosted: HostedDemo) -> Client:
        other = Client(hosted)
        other.cookie, other.csrf = client.cookie, client.csrf
        return other

    def test_a_session_signed_by_one_isolate_works_in_another(self):
        client = Client(self.a)
        client.visit()
        there = self.moved(client, self.b)
        status, headers, body = there.request("GET", f"{V}/session")
        self.assertEqual((status, body["principal"]["subject"]), (200, VISITOR_SUBJECT))
        self.assertEqual(body["csrfToken"], client.csrf)
        self.assertNotIn("Set-Cookie", headers, "the same session, not a new one")
        nm_c11 = there.scenario("NM-C11")
        status, _, answer = there.request("POST", f"{V}/candidates/{nm_c11}/transitions", {"to": "BLOCKED", "reason": "x"})
        self.assertEqual(answer["error"]["code"], "DEMO_READ_ONLY", "CSRF holds too")
        self.assertEqual(there.request("GET", f"{V}/candidates")[0], 200)
        elsewhere = self.moved(client, self.other)
        self.assertEqual(elsewhere.request("GET", f"{V}/candidates")[0], 401, "another deployment's key")
        self.assertNotEqual(elsewhere.visit() and elsewhere.csrf, client.csrf, "it starts a new visitor session")

    def test_a_cookie_signed_for_any_other_principal_is_refused(self):
        # Before the demo became anonymous, its sign-in issued cookies for any synthetic principal under
        # the same key. Such a cookie is refused like a forged one, so no elevated session survives.
        manager = SignedSessionManager(bytes.fromhex(KEY[SESSION_KEY_NAME]))
        api = self.a.app.api
        for subject in ("synthetic.admin.one", "synthetic.executor.one", "synthetic.securityiam.one",
                        "synthetic.viewer.one"):
            with self.subTest(subject=subject):
                token, _ = manager.create(api.identity.authenticate({"subject": subject}, now=api.clock()))
                client = Client(self.a)
                client.cookie = f"__Host-ogwa-session={token}"
                for path in ("/candidates", "/system/integrity", "/audit-events?limit=1"):
                    self.assertEqual(client.request("GET", V + path)[0], 401, path)
                self.assertEqual(client.visit()["subject"], VISITOR_SUBJECT, "GET /session starts a visitor's")

    def test_a_forged_or_altered_session_is_refused(self):
        client = Client(self.a)
        client.visit()
        version, payload, mac = client.cookie.split("=", 1)[1].split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["groups"] = ["00gSYNTHOGWASECIAM"]  # a viewer claiming the approvers' group
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        for token in (f"{version}.{forged}.{mac}", f"{version}.{payload}.{mac[:-2]}AA", f"v0.{payload}.{mac}",
                      f"{version}.{payload}", "x" * 3000, ""):
            with self.subTest(token=token[:20]):
                status = self.moved(client, self.b)
                status.cookie = f"__Host-ogwa-session={token}"
                self.assertEqual(status.request("GET", f"{V}/candidates")[0], 401)
                self.assertEqual(status.visit()["roles"], ["VIEWER"], "never the forged group's role")

    def test_sessions_expire_and_sign_out_ends_the_session_where_it_ran(self):
        now = [1_000_000.0]
        manager = SignedSessionManager(b"k" * 32, absolute_timeout=600, clock=lambda: now[0])
        claims = PrincipalClaims("urn:ogwa:synthetic-idp", "synthetic.viewer.one", "Viewer", frozenset({"00gSYNTH"}),
                                 utc_now(), "synthetic")
        token, session = manager.create(claims)
        self.assertEqual(manager.get(token).claims, claims)
        now[0] += 601
        self.assertIsNone(manager.get(token), "the absolute lifetime")
        now[0] = 1_000_000.0 - 400
        self.assertIsNone(manager.get(token), "issued in the future")
        now[0] = 1_000_000.0
        manager.revoke(token)
        self.assertIsNone(manager.get(token))
        with self.assertRaises(ValueError):
            SignedSessionManager(b"short")

    def test_an_idle_session_expires_and_use_renews_it_up_to_the_absolute_lifetime(self):
        now = [1_000_000.0]
        manager = SignedSessionManager(b"k" * 32, idle_timeout=100, absolute_timeout=600, clock=lambda: now[0])
        claims = PrincipalClaims("urn:ogwa:synthetic-idp", "synthetic.viewer.one", "Viewer", frozenset({"00gSYNTH"}),
                                 utc_now(), "synthetic")
        token, created = manager.create(claims)
        self.assertEqual(manager.cookie_max_age, 100)
        now[0] += 59
        self.assertIsNone(manager.renew(manager.get(token)), "renewed at most once a minute")
        now[0] += 2
        renewed = manager.renew(manager.get(token))
        self.assertNotEqual(renewed, token)
        session = manager.get(renewed)
        self.assertEqual((session.claims, session.csrf_token, session.created), (claims, created.csrf_token,
                                                                                created.created))
        now[0] = 1_000_000.0 + 101
        self.assertIsNone(manager.get(token), "idle: not renewed within the idle timeout")
        self.assertIsNotNone(manager.get(renewed))
        while now[0] + 60 <= 1_000_000.0 + 600:
            now[0] += 60
            renewed = manager.renew(manager.get(renewed))
        now[0] = 1_000_000.0 + 601
        self.assertIsNone(manager.get(renewed), "renewal never extends the absolute lifetime")

    def test_the_hosted_cookie_has_a_max_age_and_is_renewed_but_never_after_sign_out(self):
        now = [1_000_000.0]
        hosted = self.a
        original = hosted.app.api.sessions
        hosted.app.api.sessions = VisitorSessions(bytes.fromhex(KEY[SESSION_KEY_NAME]), clock=lambda: now[0])
        self.addCleanup(setattr, hosted.app.api, "sessions", original)
        client = Client(hosted)
        status, headers, body = client.request("GET", f"{V}/session")
        self.assertEqual(status, 200)
        self.assertIn("; Max-Age=900", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        client.csrf = body["csrfToken"]
        first = client.cookie
        now[0] += 120
        status, headers, _ = client.request("GET", f"{V}/candidates")
        self.assertEqual(status, 200)
        self.assertIn("; Max-Age=900", headers["Set-Cookie"])
        self.assertNotEqual(client.cookie, first)
        now[0] += 120
        status, headers, _ = client.request("POST", f"{V}/session/logout", {})
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"], "only the cleared cookie, never a renewed one")
        self.assertEqual(client.request("GET", f"{V}/candidates")[0], 401)
        self.assertNotEqual(client.visit() and client.csrf, body["csrfToken"], "a new anonymous session")


class ReadOnlyRoutePolicyTests(unittest.TestCase):
    def test_every_post_route_is_either_non_persisting_or_refused(self):
        profile = RuntimeProfile("demo", "synthetic", resolve_dataset("null-meridian").metadata)
        normal = {(r.method, r.pattern): r for r in demo_routes(ROUTES, profile)}
        read_only = {(r.method, r.pattern): r for r in demo_routes(ROUTES, profile, read_only=True)}
        self.assertEqual(normal.keys(), read_only.keys(), "the same routes")
        posts = {pattern[len(V):] for method, pattern in read_only if method == "POST"}
        self.assertEqual(posts, set(DEMO_MUTATION_POLICY))
        self.assertLessEqual(NON_PERSISTING, posts)
        session_only = ("session", frozenset())
        for path in posts:
            with self.subTest(path=path):
                route, before = read_only[("POST", V + path)], normal[("POST", V + path)]
                access = (route.access, route.any_of)
                if path == "/session":
                    self.assertEqual((route.handler.__name__, access), ("_no_sign_in", ("public", frozenset())))
                elif path == "/candidates/{candidateId}/remediation-drills":
                    self.assertEqual((route.handler.__name__, access), ("drill", ("permission", {P.READ_INVENTORY})))
                elif DEMO_MUTATION_POLICY[path] == "BLOCKED":
                    self.assertEqual((route.handler.__name__, access), ("blocked", session_only), "it refuses everyone")
                elif path in NON_PERSISTING:
                    self.assertEqual(access, (before.access, before.any_of), "unchanged")
                else:
                    self.assertEqual((route.handler.__name__, access), ("_read_only", session_only))
        for key, route in read_only.items():
            if key[0] != "GET":
                continue
            with self.subTest(route=key[1]):
                if key[1] == f"{V}/session":
                    self.assertEqual((route.access, route.handler.__name__), ("public", "_visitor_session"))
                    continue
                self.assertEqual((route.access, route.any_of), (normal[key].access, normal[key].any_of))
                if key[1] not in (f"{V}/health", f"{V}/dashboard"):
                    self.assertIs(route.handler, normal[key].handler)


class GzipImageTests(unittest.TestCase):
    def test_the_image_is_decompressed_into_a_buffer_of_its_recorded_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.gz"
            path.write_bytes(gzip.compress(IMAGE, mtime=0))
            image = read_gzip_image(path)
            self.assertIsInstance(image, bytearray)
            self.assertEqual(image, IMAGE)
            truncated = path.read_bytes()[:-1000] + path.read_bytes()[-8:]
            for bad in (truncated, gzip.compress(b"x" * 10) + gzip.compress(b"y"), b"not gzip at all"):
                path.write_bytes(bad)
                with self.assertRaises((ValueError, EOFError, zlib.error)):
                    read_gzip_image(path)


class WsgiEnvironTests(unittest.TestCase):
    def test_a_request_becomes_the_environ_wsgiref_would_build(self):
        env = wsgi_environ("post", "https://h.example/api/v1/people/psn_1%2F2?q=a%20b",
                           [("Content-Type", "application/json"), ("Content-Length", "2"), ("X-Thing", "1"),
                            ("x-thing", "2"), ("Cookie", "a=b")], b"{}")
        self.assertEqual((env["REQUEST_METHOD"], env["PATH_INFO"], env["QUERY_STRING"]),
                         ("POST", "/api/v1/people/psn_1/2", "q=a%20b"))
        self.assertEqual((env["SERVER_NAME"], env["SERVER_PORT"], env["wsgi.url_scheme"]), ("h.example", "443", "https"))
        self.assertEqual((env["CONTENT_TYPE"], env["CONTENT_LENGTH"]), ("application/json", "2"))
        self.assertEqual(env["HTTP_X_THING"], "1,2")
        self.assertEqual(env["HTTP_COOKIE"], "a=b")
        self.assertEqual(env["wsgi.input"].read(), b"{}")
        self.assertEqual(wsgi_environ("GET", "http://127.0.0.1:8787/", [], b"")["SERVER_PORT"], "8787")

    def test_the_worker_serves_no_ui_file_itself(self):
        self.assertIsNone(NoAssets().get("/"))
        self.assertEqual(NoAssets.paths, frozenset())


class HostedClockTests(unittest.TestCase):
    def test_the_demo_clock_starts_at_the_first_request_from_the_newest_audit_event(self):
        hosted = HostedDemo(lambda: IMAGE, ENVIRONMENT)
        self.addCleanup(hosted.app.close)
        newest = hosted.app.store.audit_events_page(limit=1)[0].occurred_at
        self.assertEqual(hosted.clock.start_at, newest)
        Client(hosted).request("GET", f"{V}/health")
        now = hosted.clock()
        self.assertGreaterEqual(now, newest)
        self.assertLess((now - newest).total_seconds(), 60)

