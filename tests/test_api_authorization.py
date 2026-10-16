"""Authorization boundaries: roles, bindings, authentication, separation of duties.

Synthetic only. The API runs in-process over a seeded in-memory SYNTHETIC store; no
socket, identity provider, directory, or other external system is involved.
"""

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from app.api import authz
from app.api.app import OgwaApi
from app.api.authz import (
    ROLE_PERMISSIONS,
    WRITE_PERMISSIONS,
    Permission,
    Principal,
    Role,
    load_role_bindings,
    parse_role_bindings,
)
from app.api.identity import (
    SYNTHETIC_ISSUER,
    AuthenticationFailed,
    PrincipalClaims,
    SyntheticIdentityAdapter,
    load_synthetic_directory,
)
from app.api.local import SYNTHETIC_IDP_PATH, SYNTHETIC_ROLE_BINDINGS_PATH
from app.api.routes import ROUTES
from app.api.services import (
    FORWARD_PERMISSIONS,
    LEGACY_STEPS,
    OBSERVED_STEPS,
    DryRunPlanner,
    LifecycleService,
    transition_permission,
)
from app.api.sessions import SESSION_COOKIE, SessionManager
from app.core.errors import ConfigError, MutationBlockedError
from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalRecord, ApprovalStage
from app.domain.audit import AuditAction
from app.domain.execution import JobKind
from app.domain.ids import IdKind, new_id
from app.domain.lifecycle import EVIDENCE_CONDITION_STATES, TRANSITIONS, LifecycleState
from app.domain.model import ApplicationUsageObservation
from app.store.environment import DatabaseEnvironment
from tests.api_fixtures import (
    ADMIN,
    ALL_PRINCIPALS,
    APPROVER_EXECUTOR,
    AUTOMATION,
    AUTOMATION_2,
    DUAL,
    EXECUTOR,
    LOOKALIKE,
    NO_ROLE,
    SECURITY,
    SECURITY_2,
    VIEWER,
    ApiClient,
    TickClock,
    World,
)

P = Permission
S = LifecycleState
V = "/api/v1"


def _claims(subject: str, *groups: str, issuer: str = SYNTHETIC_ISSUER) -> PrincipalClaims:
    from datetime import datetime, timezone
    return PrincipalClaims(issuer, subject, subject, frozenset(groups), datetime(2026, 3, 2, tzinfo=timezone.utc),
                           "synthetic")


def _bindings_document(**changes):
    document = json.loads(SYNTHETIC_ROLE_BINDINGS_PATH.read_text(encoding="utf-8"))
    document.update(changes)
    return document


# --- the role model --------------------------------------------------------------------


class RoleModelTests(unittest.TestCase):
    def test_every_role_has_a_fixed_permission_set(self):
        self.assertEqual(set(ROLE_PERMISSIONS), set(Role))

    def test_separation_of_duties_is_a_property_of_the_role_table(self):
        exclusive = [
            {P.APPROVAL_DECIDE, P.EXECUTION_PLAN_DRY_RUN},  # approve vs. execute
            {P.LIFECYCLE_ADVANCE, P.APPROVAL_DECIDE},  # submit vs. approve
            {P.MAPPING_PROPOSE, P.MAPPING_APPROVE},  # select vs. approve a mapping
        ]
        for role, permissions in ROLE_PERMISSIONS.items():
            for pair in exclusive:
                with self.subTest(role=role, pair=pair):
                    self.assertFalse(pair <= permissions)

    def test_read_only_and_administrator_roles_hold_no_write_permission(self):
        self.assertEqual(ROLE_PERMISSIONS[Role.VIEWER], {P.READ_INVENTORY})
        self.assertEqual(ROLE_PERMISSIONS[Role.ADMINISTRATOR] & WRITE_PERMISSIONS, frozenset())

    def test_real_execution_is_granted_to_no_role(self):
        for role, permissions in ROLE_PERMISSIONS.items():
            with self.subTest(role=role):
                self.assertNotIn(P.EXECUTION_EXECUTE, permissions)

    def test_every_lifecycle_transition_has_an_explicit_operator_rule(self):
        for (source, target), rule in TRANSITIONS.items():
            with self.subTest(source=source, target=target):
                needed = transition_permission(source, target)
                if (source, target) in OBSERVED_STEPS:
                    self.assertIsNone(needed)  # recorded by discovery, never by an operator
                elif (source, target) in LEGACY_STEPS:
                    self.assertIsNone(needed)  # the legacy single AD stage: history only (D148)
                elif ActorKind.HUMAN not in rule.actors:
                    # Evidence conditions are never assigned by an operator (owner decision).
                    self.assertIn(target, EVIDENCE_CONDITION_STATES)
                    self.assertIsNone(needed)
                elif rule.category == "diversion":
                    self.assertIs(needed, P.LIFECYCLE_DIVERT)
                elif rule.category == "re-entry":
                    self.assertIs(needed, P.LIFECYCLE_ADVANCE)
                else:
                    self.assertIs(needed, FORWARD_PERMISSIONS[(source, target)])
        self.assertIs(transition_permission(S.NEEDS_REVIEW, S.APPROVED), P.APPROVAL_DECIDE)
        self.assertIs(transition_permission(S.APPROVED, S.OKTA_UNASSIGN_DRY_RUN), P.EXECUTION_PLAN_DRY_RUN)
        # The AD stages: approvals by APPROVAL_DECIDE, dry runs by EXECUTION_PLAN_DRY_RUN,
        # the deletion proposal by LIFECYCLE_ADVANCE; the quarantine and deletion are observed.
        self.assertIs(transition_permission(S.REVALIDATION_REQUIRED, S.QUARANTINE_APPROVED), P.APPROVAL_DECIDE)
        self.assertIs(transition_permission(S.QUARANTINE_APPROVED, S.QUARANTINE_DRY_RUN), P.EXECUTION_PLAN_DRY_RUN)
        self.assertIsNone(transition_permission(S.QUARANTINE_DRY_RUN, S.QUARANTINE_HOLD))
        self.assertIs(transition_permission(S.QUARANTINE_HOLD, S.DELETION_REVALIDATION_REQUIRED), P.LIFECYCLE_ADVANCE)
        self.assertIs(transition_permission(S.DELETION_REVALIDATION_REQUIRED, S.DELETION_PROPOSED),
                      P.LIFECYCLE_ADVANCE)
        self.assertIs(transition_permission(S.DELETION_PROPOSED, S.DELETION_APPROVED), P.APPROVAL_DECIDE)
        self.assertIs(transition_permission(S.DELETION_APPROVED, S.DELETION_DRY_RUN), P.EXECUTION_PLAN_DRY_RUN)
        self.assertIsNone(transition_permission(S.DELETION_DRY_RUN, S.RETIRED))
        # The legacy single AD stage's steps have no operator permission at all (D148).
        self.assertIsNone(transition_permission(S.REVALIDATION_REQUIRED, S.RETIREMENT_DRY_RUN))
        self.assertIsNone(transition_permission(S.RETIREMENT_DRY_RUN, S.RETIRED))
        self.assertEqual(LEGACY_STEPS, {(S.REVALIDATION_REQUIRED, S.RETIREMENT_DRY_RUN),
                                        (S.RETIREMENT_DRY_RUN, S.RETIRED)})


# --- role bindings (D47, D48) ----------------------------------------------------------


class RoleBindingTests(unittest.TestCase):
    def setUp(self):
        self.bindings = load_role_bindings(SYNTHETIC_ROLE_BINDINGS_PATH, environment=DatabaseEnvironment.SYNTHETIC)
        self.directory = load_synthetic_directory(SYNTHETIC_IDP_PATH)

    def roles(self, subject):
        principal = self.directory.principals[subject]
        return self.bindings.roles_for(_claims(subject, *principal.groups))

    def test_roles_come_from_stable_group_ids(self):
        self.assertEqual(self.roles(VIEWER), {Role.VIEWER})
        self.assertEqual(self.roles(SECURITY), {Role.SECURITY_IAM})
        self.assertEqual(self.roles(DUAL), {Role.IDENTITY_AUTOMATION, Role.SECURITY_IAM})

    def test_a_group_with_a_matching_display_name_grants_nothing(self):
        lookalike = next(iter(self.directory.principals[LOOKALIKE].groups))
        security = next(iter(self.directory.principals[SECURITY].groups))
        self.assertEqual(self.directory.group_names[lookalike], self.directory.group_names[security])
        self.assertEqual(self.roles(LOOKALIKE), frozenset())
        self.assertEqual(self.roles(NO_ROLE), frozenset())

    def test_claims_from_another_issuer_grant_nothing(self):
        groups = self.directory.principals[SECURITY].groups
        self.assertEqual(self.bindings.roles_for(_claims(SECURITY, *groups, issuer="https://idp.synthetic.example")),
                         frozenset())

    def test_every_binding_names_a_group_of_the_synthetic_directory(self):
        for binding in self.bindings.bindings:
            self.assertIn(binding.idp_group_id, self.directory.group_names)

    def test_bindings_are_strict(self):
        env = DatabaseEnvironment.SYNTHETIC
        name_binding = {"displayName": "Security IAM (synthetic)", "role": "SECURITY_IAM", "note": "x"}
        refusals = {
            "by name (D47)": _bindings_document(bindings=[name_binding]),
            "unknown role": _bindings_document(bindings=[{"idpGroupId": "00gSYNTHX", "role": "ROOT", "note": ""}]),
            "duplicate": _bindings_document(bindings=[{"idpGroupId": "00gSYNTHX", "role": "VIEWER", "note": ""}] * 2),
            "extra key": {**_bindings_document(), "allowOverride": True},
            "format": _bindings_document(format="ogwa-role-bindings/v0"),
            "environment": _bindings_document(environment="PRODUCTION"),
        }
        for label, document in refusals.items():
            with self.subTest(label), self.assertRaises(ConfigError) as caught:
                parse_role_bindings(document, environment=env)
            if label == "by name (D47)":
                self.assertIn("never a group name", str(caught.exception))
        with self.assertRaises(ConfigError):
            load_role_bindings(SYNTHETIC_ROLE_BINDINGS_PATH, environment=DatabaseEnvironment.PRODUCTION)

    def test_no_route_can_change_bindings_or_policy(self):
        for route in ROUTES:
            if route.method == "POST":
                self.assertNotIn("binding", route.pattern)
                self.assertNotIn("policy", route.pattern)
                self.assertNotIn("role", route.pattern)
        self.assertFalse(self.bindings.to_dict()["editable"])


# --- identity adapter (D50, D51) -------------------------------------------------------


class IdentityAdapterTests(unittest.TestCase):
    def setUp(self):
        self.directory = load_synthetic_directory(SYNTHETIC_IDP_PATH)

    def test_synthetic_adapter_exists_only_for_local_synthetic_data(self):
        for mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION):
            with self.subTest(mode=mode), self.assertRaises(ConfigError):
                SyntheticIdentityAdapter(self.directory, mode=mode, environment=DatabaseEnvironment.SYNTHETIC)
        for environment in (DatabaseEnvironment.DEVELOPMENT, DatabaseEnvironment.PRODUCTION):
            with self.subTest(environment=environment), self.assertRaises(ConfigError):
                SyntheticIdentityAdapter(self.directory, mode=ExecutionMode.LOCAL_SYNTHETIC, environment=environment)

    def test_synthetic_sign_in_is_strict(self):
        from datetime import datetime, timezone
        adapter = SyntheticIdentityAdapter(self.directory, mode=ExecutionMode.LOCAL_SYNTHETIC,
                                           environment=DatabaseEnvironment.SYNTHETIC)
        now = datetime(2026, 3, 2, tzinfo=timezone.utc)
        for credential in ({"subject": "synthetic.nobody"}, {"subject": SECURITY, "groups": ["00gSYNTHOGWAADMIN"]},
                           {"subject": SECURITY, "password": "x"}, {}, {"subject": 7}):
            with self.subTest(credential=credential), self.assertRaises(AuthenticationFailed):
                adapter.authenticate(credential, now=now)
        claims = adapter.authenticate({"subject": SECURITY}, now=now)
        self.assertEqual((claims.issuer, claims.method), (SYNTHETIC_ISSUER, "synthetic"))

    def test_synthetic_directory_holds_only_synthetic_identifiers(self):
        document = json.loads(SYNTHETIC_IDP_PATH.read_text(encoding="utf-8"))
        bad_subject = json.loads(json.dumps(document))
        bad_subject["principals"][0]["subject"] = "jane.doe"
        bad_group = json.loads(json.dumps(document))
        bad_group["groups"][0]["id"] = "00g1a2b3c4d5e6f7g8h9"
        for label, data in (("subject", bad_subject), ("group", bad_group)):
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "idp.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ConfigError):
                    load_synthetic_directory(path)

    def test_api_refuses_every_mode_but_local_synthetic(self):
        world = World()
        self.addCleanup(world.close)
        for mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION):
            with self.subTest(mode=mode), self.assertRaisesRegex(ConfigError, "D50"):
                OgwaApi(store=world.store, identity=world.api.identity, bindings=world.api.bindings,
                        clock=world.clock, mode=mode)

    def test_api_refuses_a_production_store_even_with_matching_bindings(self):
        from tests.store_fixtures import new_store

        store = new_store(environment=DatabaseEnvironment.PRODUCTION, mode=ExecutionMode.READ_ONLY_PRODUCTION)
        self.addCleanup(store.close)
        bindings = parse_role_bindings(_bindings_document(environment="PRODUCTION"),
                                       environment=DatabaseEnvironment.PRODUCTION)
        identity = mock.Mock(issuer=SYNTHETIC_ISSUER)  # no production adapter exists; a stand-in for the check
        with self.assertRaisesRegex(ConfigError, "D50"):
            OgwaApi(store=store, identity=identity, bindings=bindings, clock=TickClock(),
                    mode=ExecutionMode.READ_ONLY_PRODUCTION)

    def test_api_refuses_bindings_for_another_issuer(self):
        world = World()
        self.addCleanup(world.close)
        other = replace(world.api.bindings, issuer="https://idp.synthetic.example")
        with self.assertRaises(ConfigError):
            OgwaApi(store=world.store, identity=world.api.identity, bindings=other, clock=world.clock,
                    mode=ExecutionMode.LOCAL_SYNTHETIC)


# --- authentication, sessions, CSRF ----------------------------------------------------


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.s07 = self.world.candidate("S07")

    def test_identity_headers_are_never_trusted(self):
        client = ApiClient(self.world.api)
        for header in ("X-Remote-User", "X-Forwarded-User", "X-OGWA-Principal", "X-Authenticated-User", "Remote-User"):
            with self.subTest(header=header):
                result = client.get(f"{V}/candidates", headers={header: SECURITY})
                self.assertEqual((result.status, result.code), (401, "UNAUTHENTICATED"))

    def test_authorization_headers_are_refused_even_with_a_valid_session(self):
        client = self.world.client(VIEWER)
        for value in ("Bearer synthetic-token-value", "Basic c3ludGhldGljOng=", "SSWS synthetic"):
            with self.subTest(value=value.split()[0]):
                result = client.get(f"{V}/candidates", headers={"Authorization": value})
                self.assertEqual((result.status, result.code), (401, "UNSUPPORTED_AUTHENTICATION"))

    def test_forged_and_missing_cookies_authenticate_nothing(self):
        client = ApiClient(self.world.api)
        for cookie in (None, "forged", "a" * 43, "x" * 500):
            client.cookie = cookie
            with self.subTest(cookie=(cookie or "")[:8]):
                self.assertEqual(client.get(f"{V}/session").status, 401)

    def test_sign_in_failures(self):
        client = ApiClient(self.world.api)
        for body in ({"subject": "synthetic.unknown"}, {"subject": SECURITY, "roles": ["SECURITY_IAM"]}, {}):
            with self.subTest(body=body):
                result = client.post(f"{V}/session", body)
                self.assertEqual((result.status, result.code), (401, "AUTHENTICATION_FAILED"))
                self.assertIsNone(result.header("set-cookie"))

    def test_session_cookie_is_host_only_secure_httponly_strict(self):
        cookie = self.world.client().sign_in(VIEWER).header("set-cookie")
        name, _, attributes = cookie.partition(";")
        self.assertTrue(name.startswith(SESSION_COOKIE + "="))
        parts = {p.strip() for p in attributes.split(";")}
        self.assertTrue({"Path=/", "Secure", "HttpOnly", "SameSite=Strict"} <= parts)
        self.assertFalse(any(p.lower().startswith("domain") for p in parts))
        self.assertFalse(any(p.startswith("Max-Age") for p in parts), "server-side sessions track idleness themselves")

    def test_sign_in_issues_a_new_session_and_revokes_the_presented_one(self):
        client = self.world.client(VIEWER)
        old = client.cookie
        client.sign_in(VIEWER)
        self.assertNotEqual(client.cookie, old)
        stale = ApiClient(self.world.api)
        stale.cookie = old
        self.assertEqual(stale.get(f"{V}/session").status, 401)

    def test_sessions_store_only_token_hashes(self):
        client = self.world.client(VIEWER)
        self.assertNotIn(client.cookie, self.world.api.sessions._sessions)
        self.assertNotIn(client.cookie, repr(self.world.api.sessions._sessions))

    def test_sign_out_revokes_and_needs_csrf(self):
        client = self.world.client(VIEWER)
        self.assertEqual(client.post(f"{V}/session/logout", csrf=False).code, "CSRF_FAILED")
        result = client.post(f"{V}/session/logout")
        self.assertEqual(result.status, 200)
        self.assertIn("Max-Age=0", result.header("set-cookie"))
        self.assertEqual(client.get(f"{V}/session").status, 401)

    def test_sessions_expire_when_idle_and_absolutely(self):
        now = [0.0]
        manager = SessionManager(idle_timeout=60, absolute_timeout=300, monotonic=lambda: now[0])
        token, _ = manager.create(_claims(VIEWER))
        now[0] = 59
        self.assertIsNotNone(manager.get(token))
        now[0] = 120
        self.assertIsNone(manager.get(token))  # idle
        token, _ = manager.create(_claims(VIEWER))
        for step in range(1, 6):
            now[0] = 120 + step * 50  # active every 50 s, up to 250 s after creation
            self.assertIsNotNone(manager.get(token))
        now[0] = 120 + 301
        self.assertIsNone(manager.get(token))  # absolute lifetime, despite activity

    def test_writes_need_the_session_csrf_token(self):
        client = self.world.client(SECURITY)
        other = self.world.client(SECURITY_2)
        fingerprint = self.world.fingerprint(client, self.s07)
        body = {"stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "synthetic",
                "expectedEvidenceFingerprint": fingerprint}
        for label, csrf_value in (("missing", None), ("wrong", "x" * 43), ("another session's", other.csrf)):
            with self.subTest(label):
                headers = {"X-OGWA-CSRF": csrf_value} if csrf_value else {}
                result = client.post(f"{V}/candidates/{self.s07}/approvals", body, csrf=False, headers=headers)
                self.assertEqual((result.status, result.code), (403, "CSRF_FAILED"))
        self.assertEqual(self.world.store.approvals_for(self.s07), [])

    def test_cross_site_posts_are_refused(self):
        client = self.world.client(SECURITY)
        for headers in ({"Origin": "https://attacker.synthetic.example"}, {"Origin": "null"},
                        {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}):
            with self.subTest(headers=headers):
                result = client.post(f"{V}/candidates/{self.s07}/transitions", {}, headers=headers)
                self.assertEqual((result.status, result.code), (403, "ORIGIN_REFUSED"))
        result = ApiClient(self.world.api).post(f"{V}/session", {"subject": VIEWER},
                                                headers={"Origin": "https://attacker.synthetic.example"})
        self.assertEqual(result.code, "ORIGIN_REFUSED")  # login CSRF too

    def test_same_origin_posts_are_accepted(self):
        from app.api.local import build_local_api
        api = build_local_api(self.world.store, clock=self.world.clock, port=8765)
        client = ApiClient(api)
        result = client.post(f"{V}/session", {"subject": VIEWER}, headers={"Origin": "http://127.0.0.1:8765",
                                                                            "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(result.status, 201)


# --- every route, every principal -----------------------------------------------------

# For these routes, exactly these principals pass the permission check.
EXPECTED_ACCESS = {
    ("GET", "/candidates"): {VIEWER, AUTOMATION, AUTOMATION_2, SECURITY, SECURITY_2, EXECUTOR, ADMIN, DUAL,
                             APPROVER_EXECUTOR},
    ("GET", "/audit-events"): {AUTOMATION, AUTOMATION_2, SECURITY, SECURITY_2, ADMIN, DUAL, APPROVER_EXECUTOR},
    ("GET", "/system/role-bindings"): {ADMIN},
    ("GET", "/system/integrity"): {ADMIN},
    ("POST", "/candidates/{candidateId}/transitions"): {AUTOMATION, AUTOMATION_2, SECURITY, SECURITY_2, EXECUTOR,
                                                        DUAL, APPROVER_EXECUTOR},
    ("POST", "/candidates/{candidateId}/approvals"): {SECURITY, SECURITY_2, DUAL, APPROVER_EXECUTOR},
    ("POST", "/candidates/{candidateId}/execution-jobs"): {EXECUTOR, APPROVER_EXECUTOR},
    ("POST", "/execution-jobs/{jobId}/execute"): {EXECUTOR, APPROVER_EXECUTOR},  # then refused by the build
    ("GET", "/candidates/{candidateId}/remediation-dry-runs"): {VIEWER, AUTOMATION, AUTOMATION_2, SECURITY, SECURITY_2,
                                                                EXECUTOR, ADMIN, DUAL, APPROVER_EXECUTOR},
    ("POST", "/candidates/{candidateId}/remediation-dry-runs"): {EXECUTOR, APPROVER_EXECUTOR},  # dry run only
    ("POST", "/mappings/{groupId}/searches"): {AUTOMATION, AUTOMATION_2, DUAL},
    ("POST", "/mappings/{groupId}/selections"): {AUTOMATION, AUTOMATION_2, DUAL},
    ("POST", "/mappings/{groupId}/approvals"): {SECURITY, SECURITY_2, DUAL, APPROVER_EXECUTOR},
    ("POST", "/mappings/{groupId}/rejections"): {AUTOMATION, AUTOMATION_2, SECURITY, SECURITY_2, DUAL,
                                                 APPROVER_EXECUTOR},
}


class RouteAccessMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()
        conn = cls.world.store.connection
        candidate = cls.world.candidate("S07")
        cls.params = {
            "candidateId": candidate,
            "groupId": cls.world.store.load_candidate(candidate).okta_group_id,
            "applicationId": conn.execute("SELECT id FROM okta_applications ORDER BY id LIMIT 1").fetchone()[0],
            "jobId": conn.execute("SELECT id FROM execution_jobs ORDER BY id LIMIT 1").fetchone()[0],
            # The classic world has no directory snapshot: these answer 404, never 500 (or 200).
            "personId": "psn_" + "0" * 32,
            "directoryGroupId": "dgrp_" + "0" * 32,
        }

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def path(self, route):
        path = route.pattern
        for name, value in self.params.items():
            path = path.replace("{" + name + "}", value)
        return path

    def call(self, client, route):
        return client.get(self.path(route)) if route.method == "GET" else client.post(self.path(route), {})

    def test_anonymous_callers_reach_only_public_routes(self):
        for route in ROUTES:
            with self.subTest(route=f"{route.method} {route.pattern}"):
                result = self.call(ApiClient(self.world.api), route)
                if route.access == "public":
                    self.assertNotEqual(result.status, 403)
                else:
                    self.assertEqual((result.status, result.code), (401, "UNAUTHENTICATED"))

    def test_every_route_enforces_its_permission_for_every_principal(self):
        for subject in ALL_PRINCIPALS:
            for route in ROUTES:
                if route.access == "public":
                    continue
                client = self.world.client(subject)  # fresh session: some routes (logout) end it
                roles = self.world.api.bindings.roles_for(self.world.api.sessions.get(client.cookie).claims)
                permissions = Principal(_claims(subject), roles).permissions
                with self.subTest(subject=subject, route=f"{route.method} {route.pattern}"):
                    result = self.call(client, route)
                    self.assertNotEqual(result.status, 401)
                    self.assertNotEqual(result.status, 500, result.json)
                    if route.access == "permission" and not permissions & route.any_of:
                        self.assertEqual((result.status, result.code), (403, "FORBIDDEN"))
                    elif route.pattern.endswith("/execute"):
                        self.assertEqual((result.status, result.code), (403, "PRODUCTION_MUTATION_REFUSED"))
                    else:
                        self.assertNotEqual(result.code, "FORBIDDEN")
                    key = (route.method, route.pattern[len(V):])
                    if key in EXPECTED_ACCESS:
                        self.assertEqual(result.code != "FORBIDDEN", subject in EXPECTED_ACCESS[key])

    def test_principals_without_a_role_can_only_see_their_session(self):
        for subject in (LOOKALIKE, NO_ROLE):
            client = self.world.client(subject)
            me = client.get(f"{V}/session")
            self.assertEqual((me.status, me.json["principal"]["roles"]), (200, []))
            for route in ROUTES:
                if route.access == "permission":
                    with self.subTest(subject=subject, route=route.pattern):
                        self.assertEqual(self.call(client, route).code, "FORBIDDEN")

    def test_refusals_are_logged_with_the_principal_and_no_secret(self):
        client = self.world.client(VIEWER)
        client.post(f"{V}/candidates/{self.params['candidateId']}/approvals", {})
        refused = [json.loads(line) for line in self.world.log.lines if '"api.refused"' in line]
        self.assertTrue(any(r["fields"]["principal"] == VIEWER and r["fields"]["code"] == "FORBIDDEN" for r in refused))
        self.assertFalse(any(client.cookie in line or client.csrf in line for line in self.world.log.lines))


# --- separation of duties and evidence rules -------------------------------------------


def approve_body(fingerprint, stage="OKTA_UNASSIGN", decision="APPROVE", **extra):
    return {"stage": stage, "decision": decision, "reason": "synthetic review", "expectedEvidenceFingerprint": fingerprint,
            **extra}


class SeparationOfDutiesTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.s07 = self.world.candidate("S07")

    def approve_s07(self, subject=SECURITY):
        client = self.world.client(subject)
        result = client.post(f"{V}/candidates/{self.s07}/approvals", approve_body(self.world.fingerprint(client, self.s07)))
        self.assertEqual(result.status, 201, result.json)
        return result.json["approval"]["id"]

    def plan(self, client, approval_id, candidate=None, **extra):
        candidate = candidate or self.s07
        body = {"kind": "OKTA_UNASSIGN", "approvalId": approval_id,
                "expectedEvidenceFingerprint": self.world.fingerprint(client, candidate), "dryRun": True, **extra}
        return client.post(f"{V}/candidates/{candidate}/execution-jobs", body)

    def test_read_only_users_cannot_approve(self):
        for subject in (VIEWER, ADMIN, EXECUTOR, AUTOMATION):
            client = self.world.client(subject)
            with self.subTest(subject=subject):
                result = client.post(f"{V}/candidates/{self.s07}/approvals",
                                     approve_body(self.world.fingerprint(client, self.s07)))
                self.assertEqual((result.status, result.code), (403, "FORBIDDEN"))
                result = client.post(f"{V}/candidates/{self.s07}/transitions",
                                     {"target": "APPROVED", "reason": "x",
                                      "expectedEvidenceFingerprint": self.world.fingerprint(client, self.s07)})
                self.assertEqual(result.status, 403)
        self.assertEqual(self.world.store.approvals_for(self.s07), [])
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.NEEDS_REVIEW)

    def test_the_submitter_cannot_approve_even_holding_both_roles(self):
        automation = self.world.client(AUTOMATION)
        dual = self.world.client(DUAL)
        # Stop, lift, and resubmit S07 so that a human (DUAL) is the submitter of this epoch.
        self.assertEqual(automation.post(f"{V}/candidates/{self.s07}/transitions",
                                         {"target": "BLOCKED", "reason": "pause for synthetic check"}).status, 201)
        fp = self.world.fingerprint(automation, self.s07)
        self.assertEqual(automation.post(f"{V}/candidates/{self.s07}/transitions",
                                         {"target": "CANDIDATE", "reason": "resume", "expectedEvidenceFingerprint": fp}
                                         ).status, 201)
        result = dual.post(f"{V}/candidates/{self.s07}/transitions",
                           {"target": "NEEDS_REVIEW", "reason": "submit", "expectedEvidenceFingerprint": fp})
        self.assertEqual(result.status, 201, result.json)
        detail = dual.get(f"{V}/candidates/{self.s07}").json["allowedActions"]["approvals"][0]
        self.assertFalse(detail["permitted"])
        result = dual.post(f"{V}/candidates/{self.s07}/approvals", approve_body(fp))
        self.assertEqual((result.status, result.code), (403, "SEPARATION_OF_DUTIES"))
        self.assertEqual(self.world.store.approvals_for(self.s07), [])
        self.assertEqual(self.world.client(SECURITY).post(f"{V}/candidates/{self.s07}/approvals",
                                                          approve_body(fp)).status, 201)

    def test_the_proposer_cannot_approve(self):
        candidate = self.world.store.load_candidate(self.s07)
        me = Actor(ActorKind.HUMAN, SECURITY)
        self.assertEqual(self.world.api.lifecycle.approver_conflicts(candidate, ApprovalStage.OKTA_UNASSIGN, me), [])
        conflicts = self.world.api.lifecycle.approver_conflicts(replace(candidate, proposed_by=me),
                                                                ApprovalStage.OKTA_UNASSIGN, me)
        self.assertIn("you proposed this candidate", conflicts)

    def test_services_check_permissions_themselves(self):
        """Defence in depth: the services refuse a caller without the permission even if a
        route forgot its static check."""
        from app.api.errors import ApiError
        from app.api.services import MappingReviews

        viewer = Principal(_claims(VIEWER), frozenset({Role.VIEWER}))
        lifecycle, mappings = self.world.api.lifecycle, MappingReviews(None)
        fp = "sha256:" + "0" * 64
        calls = {
            "transition": lambda: lifecycle.transition(viewer, self.s07, target=S.BLOCKED, reason="x",
                                                       expected_fingerprint=None, approval_id=None, job_id=None,
                                                       request_id=new_id(IdKind.REQUEST)),
            "approval": lambda: lifecycle.decide_approval(viewer, self.s07, stage=ApprovalStage.OKTA_UNASSIGN,
                                                          decision=ApprovalDecision.APPROVE, reason="x",
                                                          expected_fingerprint=fp, valid_hours=None,
                                                          request_id=new_id(IdKind.REQUEST)),
            "plan": lambda: lifecycle.plan_dry_run(viewer, self.s07, kind=JobKind.OKTA_UNASSIGN,
                                                   approval_id=new_id(IdKind.APPROVAL), expected_fingerprint=fp,
                                                   dry_run=True, requested_mode=None,
                                                   request_id=new_id(IdKind.REQUEST)),
            "mapping inspect": lambda: mappings.inspect(viewer, self.s07),
            "mapping search": lambda: mappings.search(viewer, self.s07, by="name", value="x", domain=None),
            "mapping select": lambda: mappings.select(viewer, self.s07, search_id="x", object_guid="x", reason="x"),
            "mapping approve": lambda: mappings.approve(viewer, self.s07, object_guid="x", expected_fingerprint=fp,
                                                        reason="x"),
            "mapping reject": lambda: mappings.reject(viewer, self.s07, object_guid="x", expected_fingerprint=fp,
                                                      reason="x"),
        }
        for label, call in calls.items():
            with self.subTest(label), self.assertRaises(ApiError) as caught:
                call()
            self.assertEqual(caught.exception.code, "FORBIDDEN")
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.NEEDS_REVIEW)

    def test_quarantine_approver_must_differ_from_the_okta_approver(self):
        candidate = self.world.store.load_candidate(self.world.candidate("S12"))
        lifecycle = self.world.api.lifecycle
        me = Actor(ActorKind.HUMAN, SECURITY)
        self.assertEqual(lifecycle.approver_conflicts(candidate, ApprovalStage.AD_QUARANTINE, me), [])
        conflicts = lifecycle.approver_conflicts(replace(candidate, okta_unassign_approver=me),
                                                 ApprovalStage.AD_QUARANTINE, me)
        self.assertTrue(any("D11" in c for c in conflicts))

    def test_deletion_approver_must_differ_from_the_proposer_and_both_earlier_approvers(self):
        """D143, in what allowedActions tells each person."""
        s16 = self.world.store.load_candidate(self.world.candidate("S16"))  # DELETION_PROPOSED
        lifecycle = self.world.api.lifecycle
        self.assertEqual(lifecycle.approver_conflicts(s16, ApprovalStage.AD_DELETION,
                                                      Actor(ActorKind.HUMAN, SECURITY)), [])
        for person, expected in ((s16.deletion_proposer, "you proposed the deletion"),
                                 (s16.quarantine_approver, "you approved the AD quarantine"),
                                 (s16.okta_unassign_approver, "you approved the Okta unassignment")):
            with self.subTest(person=person.id):
                conflicts = lifecycle.approver_conflicts(s16, ApprovalStage.AD_DELETION, person)
                self.assertTrue(any(expected in c and "D143" in c for c in conflicts), conflicts)

    def test_approvers_cannot_bypass_evidence_rules(self):
        client = self.world.client(SECURITY)
        s08 = self.world.candidate("S08")  # NEEDS_REVIEW with a name-only mapping
        result = client.post(f"{V}/candidates/{s08}/approvals", approve_body(self.world.fingerprint(client, s08)))
        self.assertEqual((result.status, result.code), (409, "EVIDENCE_RULES_NOT_MET"))
        self.assertTrue(any("NAME_ONLY" in p for p in result.json["error"]["problems"]))
        s12 = self.world.candidate("S12")  # REVALIDATION_REQUIRED with partial dependency coverage
        result = client.post(f"{V}/candidates/{s12}/approvals",
                             approve_body(self.world.fingerprint(client, s12), stage="AD_QUARANTINE"))
        self.assertEqual((result.status, result.code), (409, "EVIDENCE_RULES_NOT_MET"))
        self.assertTrue(any("COMPLETE" in p for p in result.json["error"]["problems"]))
        s03 = self.world.candidate("S03")  # DEPENDENCY_BLOCKED
        result = client.post(f"{V}/candidates/{s03}/approvals", approve_body(self.world.fingerprint(client, s03)))
        self.assertEqual((result.status, result.code), (409, "INVALID_STATE"))
        result = client.post(f"{V}/candidates/{self.s07}/approvals", approve_body("sha256:" + "0" * 64))
        self.assertEqual((result.status, result.code), (409, "EVIDENCE_CHANGED"))
        result = client.post(f"{V}/candidates/{self.s07}/approvals",
                             approve_body(self.world.fingerprint(client, self.s07), validForHours=24 * 15))
        self.assertEqual(result.status, 422)
        for candidate in (s08, s12, s03, self.s07):
            self.assertEqual([a for a in self.world.store.approvals_for(candidate) if a.operator.id == SECURITY], [])
        recorded = [e for e in self.world.store.audit_events() if e.action is AuditAction.APPROVAL_RECORDED
                    and e.actor.id == SECURITY]
        self.assertEqual(recorded, [])

    def test_the_approver_cannot_plan_or_record_the_dry_run(self):
        approval = self.approve_s07(APPROVER_EXECUTOR)
        self.world.refresh_evidence(self.s07)
        both = self.world.client(APPROVER_EXECUTOR)
        result = self.plan(both, approval)
        self.assertEqual((result.status, result.code), (403, "SEPARATION_OF_DUTIES"))
        executor = self.world.client(EXECUTOR)
        planned = self.plan(executor, approval)
        self.assertEqual(planned.status, 201, planned.json)
        result = both.post(f"{V}/candidates/{self.s07}/transitions", {
            "target": "OKTA_UNASSIGN_DRY_RUN", "reason": "x", "approvalId": approval,
            "jobId": planned.json["job"]["id"], "expectedEvidenceFingerprint": self.world.fingerprint(both, self.s07)})
        self.assertEqual((result.status, result.code), (403, "SEPARATION_OF_DUTIES"))
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.APPROVED)

    def test_executors_cannot_execute_without_a_valid_approval(self):
        executor = self.world.client(EXECUTOR)
        result = self.plan(executor, new_id(IdKind.APPROVAL))  # not approved yet; S07 is NEEDS_REVIEW
        self.assertEqual((result.status, result.code), (409, "INVALID_STATE"))
        approval = self.approve_s07()
        self.world.refresh_evidence(self.s07)
        cases = {
            "unknown approval": (self.plan(executor, new_id(IdKind.APPROVAL)), 404, "NOT_FOUND"),
            "another candidate's approval": (
                self.plan(executor, self.world.store.approvals_for(self.world.candidate("S14"))[0].id), 404, "NOT_FOUND"),
            "stale view": (executor.post(f"{V}/candidates/{self.s07}/execution-jobs", {
                "kind": "OKTA_UNASSIGN", "approvalId": approval, "expectedEvidenceFingerprint": "sha256:" + "1" * 64}),
                409, "EVIDENCE_CHANGED"),
            "missing approval": (executor.post(f"{V}/candidates/{self.s07}/execution-jobs", {
                "kind": "OKTA_UNASSIGN", "expectedEvidenceFingerprint": self.world.fingerprint(executor, self.s07)}),
                422, "VALIDATION_FAILED"),
        }
        # A REJECT decision for the same stage does not authorize anything.
        candidate = self.world.store.load_candidate(self.s07)
        reject = ApprovalRecord(id=new_id(IdKind.APPROVAL), candidate_id=self.s07, stage=ApprovalStage.OKTA_UNASSIGN,
                                decision=ApprovalDecision.REJECT, operator=Actor(ActorKind.HUMAN, SECURITY_2),
                                decided_at=self.world.clock(), reason="synthetic rejection",
                                evidence_fingerprint=self.world.fingerprint(executor, self.s07),
                                candidate_epoch=candidate.epoch, expires_at=self.world.clock() + timedelta(days=1))
        self.world.store.record_approval(reject)
        cases["rejection"] = (self.plan(executor, reject.id), 409, "APPROVAL_INVALID")
        for label, (result, status, code) in cases.items():
            with self.subTest(label):
                self.assertEqual((result.status, result.code), (status, code), result.json)
        self.assertEqual(self.world.api.read.job_ids_for(self.s07), [])
        # Expiry: the same valid approval stops authorizing once it lapses.
        self.world.clock.advance(timedelta(days=8))
        self.world.refresh_evidence(self.s07)
        result = self.plan(executor, approval)
        self.assertEqual((result.status, result.code), (409, "APPROVAL_INVALID"))
        self.assertTrue(any("expired" in p for p in result.json["error"]["problems"]))

    def test_a_material_evidence_change_voids_the_approval_for_execution(self):
        approval = self.approve_s07()
        bundle = self.world.store.evidence_bundle(self.world.store.load_candidate(self.s07))
        usage = bundle.usage[0]
        changed = replace(usage, event_count=usage.event_count + 1,
                          provenance=replace(usage.provenance, observed_at=self.world.clock()))
        self.assertIsInstance(changed, ApplicationUsageObservation)
        from app.demo.synthetic_world import COLLECTOR
        self.world.store.record_evidence(changed, actor=COLLECTOR)
        self.world.refresh_evidence(self.s07)
        result = self.plan(self.world.client(EXECUTOR), approval)
        self.assertEqual(result.code, "APPROVAL_INVALID")
        self.assertTrue(any("material evidence changed" in p for p in result.json["error"]["problems"]))

    def test_administrators_cannot_override_safety(self):
        admin = self.world.client(ADMIN)
        fp = self.world.fingerprint(admin, self.s07)
        attempts = [
            (f"/candidates/{self.s07}/approvals", approve_body(fp)),
            (f"/candidates/{self.s07}/transitions", {"target": "APPROVED", "reason": "admin override",
                                                     "expectedEvidenceFingerprint": fp}),
            (f"/candidates/{self.s07}/transitions", {"target": "EXCLUDED", "reason": "admin override"}),
            (f"/candidates/{self.s07}/execution-jobs", {"kind": "OKTA_UNASSIGN", "approvalId": new_id(IdKind.APPROVAL),
                                                        "expectedEvidenceFingerprint": fp}),
        ]
        for path, body in attempts:
            with self.subTest(path=path, target=body.get("target")):
                self.assertEqual(admin.post(V + path, body).code, "FORBIDDEN")
        policy = admin.get(f"{V}/policy").json
        self.assertFalse(policy["editableViaApi"])
        self.assertFalse(admin.get(f"{V}/system/role-bindings").json["editable"])
        self.assertIs(self.world.store.load_candidate(self.s07).state, S.NEEDS_REVIEW)


# --- production mutation ---------------------------------------------------------------


class ProductionMutationRefusalTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.s14 = self.world.candidate("S14")  # APPROVED; its earlier dry run failed
        self.approval = self.world.store.approvals_for(self.s14)[0].id

    def body(self, client, **extra):
        return {"kind": "OKTA_UNASSIGN", "approvalId": self.approval,
                "expectedEvidenceFingerprint": self.world.fingerprint(client, self.s14), **extra}

    def test_non_dry_run_and_production_mutation_requests_are_refused_outright(self):
        before = self.world.api.read.job_ids_for(self.s14)
        for subject in (EXECUTOR, VIEWER, SECURITY):
            client = self.world.client(subject)
            for extra in ({"dryRun": False}, {"executionMode": "PRODUCTION_MUTATION"},
                          {"dryRun": False, "executionMode": "PRODUCTION_MUTATION"}):
                with self.subTest(subject=subject, extra=extra):
                    result = client.post(f"{V}/candidates/{self.s14}/execution-jobs", self.body(client, **extra))
                    self.assertEqual(result.status, 403)
                    if subject == EXECUTOR:
                        self.assertEqual(result.code, "PRODUCTION_MUTATION_REFUSED")
        client = self.world.client(EXECUTOR)
        result = client.post(f"{V}/candidates/{self.s14}/execution-jobs",
                             self.body(client, executionMode="READ_ONLY_PRODUCTION"))
        self.assertEqual(result.code, "VALIDATION_FAILED")
        self.assertEqual(self.world.api.read.job_ids_for(self.s14), before)

    def test_execute_route_refuses_everyone_even_with_the_permission(self):
        job = self.world.api.read.job_ids_for(self.s14)[0]
        granted = {role: permissions | {P.EXECUTION_EXECUTE} for role, permissions in ROLE_PERMISSIONS.items()}
        with mock.patch.dict(authz.ROLE_PERMISSIONS, granted):
            for subject in ALL_PRINCIPALS:
                with self.subTest(subject=subject):
                    client = self.world.client(subject)
                    has_role = bool(self.world.api.bindings.roles_for(self.world.api.sessions.get(client.cookie).claims))
                    result = client.post(f"{V}/execution-jobs/{job}/execute", {})
                    self.assertEqual((result.status, result.code),
                                     (403, "PRODUCTION_MUTATION_REFUSED" if has_role else "FORBIDDEN"))

    def test_planning_is_refused_in_a_mode_that_cannot_record_jobs(self):
        service = LifecycleService(self.world.store, clock=self.world.clock, mode=ExecutionMode.READ_ONLY_PRODUCTION)
        principal = Principal(_claims(EXECUTOR), frozenset({Role.EXECUTOR}))
        with self.assertRaises(Exception) as caught:
            service.plan_dry_run(principal, self.s14, kind=JobKind.OKTA_UNASSIGN, approval_id=self.approval,
                                 expected_fingerprint="sha256:" + "0" * 64, dry_run=True, requested_mode=None,
                                 request_id=new_id(IdKind.REQUEST))
        self.assertEqual(getattr(caught.exception, "code", None), "EXECUTION_MODE_NOT_AUTHORIZED")

    def test_dry_run_planner_can_only_plan(self):
        planner = DryRunPlanner()
        self.assertIs(planner.mutation_policy.mode, ExecutionMode.DRY_RUN_MUTATION)
        expected = {JobKind.AD_QUARANTINE: "ad:move_group_to_quarantine:adg_", JobKind.AD_DELETION: "ad:delete_group:adg_"}
        for kind, prefix in expected.items():
            with self.subTest(kind=kind),                     mock.patch.object(DryRunPlanner, "_never", side_effect=AssertionError("executed")) as never:
                actions = planner.plan(kind, (new_id(IdKind.AD_GROUP),))
                never.assert_not_called()
                self.assertEqual(len(actions), 1)
                self.assertTrue(actions[0].startswith(prefix))
        with self.assertRaises(MutationBlockedError):  # the legacy kind plans nothing (D148)
            planner.plan(JobKind.AD_RETIREMENT, (new_id(IdKind.AD_GROUP),))


if __name__ == "__main__":
    unittest.main()
