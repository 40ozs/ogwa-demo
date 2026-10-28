"""P10: read-only AAP discovery and the template safety classifier.

Every AAP answer here is synthetic and served by an in-process fake transport over a
reserved ``.example`` host; nothing contacts AAP. The fake records every request, so the
tests can prove that discovery only ever sends GET.
"""

import ast
import json
import unittest
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import load_settings
from app.core.http_client import HttpPolicy, HttpResponse, ReadOnlyHttpClient, TransportError
from app.core.modes import ExecutionMode
from app.core.secret import Secret
from app.integrations.aap import AapDiscoveryError, AapIdentityRefused, AapReadOnlyClient
from app.remediation.aap import (
    ReviewedTemplate,
    SurveyQuestion,
    TemplateKind,
    TemplateMetadata,
    TemplateSafety,
    classify_template,
)
from tests.fakes import SYNTHETIC_AAP_TOKEN, SYNTHETIC_AAP_URL, read_only_env

REPO_ROOT = Path(__file__).resolve().parents[1]
REVISION = "5e7e70005e7e70005e7e70005e7e70005e7e7000"
# What AAP reports a read-only identity may do to a template: nothing.
READ_ONLY_CAPABILITIES = {"edit": False, "delete": False, "start": False, "schedule": False, "copy": False}
OGWA_PLAYBOOK = "playbooks/ogwa_remediation_whatif.yml"
PIN = ReviewedTemplate(template_id=4101, name="SYNTHETIC OGWA AD group delete (WhatIf)", playbook=OGWA_PLAYBOOK,
                       project_id=7, project_revision=REVISION, survey_variables=("ogwa_remediation_request",))


def job_template(template_id, name, *, job_type="check", playbook="playbooks/synthetic.yml", project=7, survey=False,
                 **flags):
    raw = {"id": template_id, "name": name, "job_type": job_type, "playbook": playbook, "project": project,
           "inventory": 3, "ask_job_type_on_launch": False, "ask_variables_on_launch": False,
           "ask_scm_branch_on_launch": False, "ask_inventory_on_launch": False, "ask_credential_on_launch": False,
           "survey_enabled": survey, "description": "synthetic",
           "summary_fields": {"user_capabilities": READ_ONLY_CAPABILITIES}}
    raw.update(flags)
    return raw


class RoutingTransport:
    """Answers by path and query; records every call. Anything unrouted is a test failure."""

    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.calls: list[dict] = []

    def send(self, method, url, headers, body, *, connect_timeout, read_timeout, max_response_bytes):
        parts = urlsplit(url)
        key = parts.path + (f"?{parts.query}" if parts.query else "")
        self.calls.append({"method": method, "url": url, "key": key, "headers": dict(headers), "body": body})
        if key not in self.routes:
            raise AssertionError(f"unexpected request {method} {key}")
        answer = self.routes[key]
        if isinstance(answer, HttpResponse):
            return answer
        return HttpResponse(200, {"Content-Type": "application/json"}, json.dumps(answer).encode())


ME = "/api/v2/me/"
ROLES = "/api/v2/users/7/roles/?page_size=100&order_by=id"
TEAMS = "/api/v2/users/7/teams/?page_size=100&order_by=id"
TEAM_ROLES = "/api/v2/teams/31/roles/?page_size=100&order_by=id"


def role(name, resource_type="job_template"):
    return {"id": 900, "name": name, "summary_fields": {"resource_type": resource_type,
                                                        "resource_name": "SYNTHETIC object"}}


def page(*results, following=None):
    return {"count": len(results), "next": following, "results": list(results)}
JT1 = "/api/v2/job_templates/?page_size=100&order_by=id"
JT2 = "/api/v2/job_templates/?order_by=id&page=2&page_size=100"
WF1 = "/api/v2/workflow_job_templates/?page_size=100&order_by=id"


def me(superuser=False, auditor=True):
    return {"count": 1, "results": [{"id": 7, "username": "synthetic.aap.reader",
                                      "email": "synthetic.aap.reader@synthetic.example", "first_name": "Synthetic",
                                      "is_superuser": superuser, "is_system_auditor": auditor}]}


def world_routes(**overrides):
    routes = {
        ME: me(),
        ROLES: page(role("Read"), role("Member", "organization")),
        TEAMS: page({"id": 31, "name": "SYNTHETIC OGWA readers"}),
        TEAM_ROLES: page(role("Auditor", "organization")),
        JT1: {"count": 4, "next": JT2, "results": [
            job_template(4101, "SYNTHETIC OGWA AD group delete (WhatIf)", playbook=OGWA_PLAYBOOK, survey=True),
            job_template(4102, "SYNTHETIC Linux provisioning", job_type="run"),
        ]},
        JT2: {"count": 4, "next": None, "results": [
            job_template(4103, "SYNTHETIC vcenter tag dump (check)"),
            job_template(4104, "SYNTHETIC patching", ask_job_type_on_launch=True),
        ]},
        "/api/v2/job_templates/4101/survey_spec/": {"name": "", "description": "", "spec": [
            {"question_name": "request", "variable": "ogwa_remediation_request", "type": "textarea", "required": True,
             "default": "synthetic-default-must-not-be-kept"},
        ]},
        "/api/v2/projects/7/": {"id": 7, "name": "synthetic project", "scm_revision": REVISION},
        WF1: {"count": 1, "next": None, "results": [
            {"id": 5001, "name": "SYNTHETIC OGWA quarantine then delete", "survey_enabled": True,
             "ask_variables_on_launch": False, "ask_inventory_on_launch": False,
             "summary_fields": {"user_capabilities": READ_ONLY_CAPABILITIES}},
        ]},
        "/api/v2/workflow_job_templates/5001/survey_spec/": {"spec": [
            {"variable": "approver_password", "type": "password", "required": True, "default": "$encrypted$"},
        ]},
    }
    routes.update(overrides)
    return routes


def client(routes, mode=ExecutionMode.READ_ONLY_PRODUCTION, **kwargs):
    transport = RoutingTransport(routes)
    http = ReadOnlyHttpClient(mode=mode, http_policy=HttpPolicy(), allowed_hosts=[urlsplit(SYNTHETIC_AAP_URL).hostname],
                              transport=transport, sleep=lambda s: None)
    return AapReadOnlyClient(base_url=SYNTHETIC_AAP_URL, token=Secret(SYNTHETIC_AAP_TOKEN), http=http, **kwargs), transport


class DiscoveryTests(unittest.TestCase):
    def test_discovery_classifies_every_template_and_sends_only_get(self):
        aap, transport = client(world_routes())
        report = aap.discover(reviewed=(PIN,))
        self.assertTrue(report.complete, report.problems)
        safety = {c.template.template_id: c.safety for c in report.classifications}
        self.assertEqual(safety, {4101: TemplateSafety.KNOWN_READ_ONLY, 4102: TemplateSafety.MUTATION_CAPABLE,
                                  4103: TemplateSafety.UNKNOWN, 4104: TemplateSafety.MUTATION_CAPABLE,
                                  5001: TemplateSafety.UNKNOWN})
        self.assertEqual({c["method"] for c in transport.calls}, {"GET"})
        self.assertEqual({c["body"] for c in transport.calls}, {None})
        self.assertEqual([c["key"] for c in transport.calls[:4]], [ME, ROLES, TEAMS, TEAM_ROLES])
        self.assertFalse(any("launch" in c["key"] or "/jobs/" in c["key"] for c in transport.calls))
        summary = report.to_dict()
        self.assertEqual(summary["launched"], 0)
        self.assertEqual([c["template"]["id"] for c in summary["candidates"]], [4101, 5001])

    def test_the_identity_must_hold_only_read_only_roles(self):
        """D125: an OGWA identity must not be able to launch, create, update, delete, or administer."""
        writers = ("Admin", "Execute", "Update", "Use", "Approve", "Job Template Admin", "Project Admin",
                   "Inventory Admin", "Credential Admin", "Workflow Admin", "Notification Admin", "Ad Hoc", None)
        for name in writers:
            for where in (ROLES, TEAM_ROLES):
                with self.subTest(role=name, where=where):
                    routes = world_routes(**{where: page(role("Read"), {"id": 901, "name": name})})
                    aap, transport = client(routes)
                    with self.assertRaisesRegex(AapIdentityRefused, "D125"):
                        aap.discover()
                    self.assertFalse(any("templates" in c["key"] for c in transport.calls))

    def test_roles_that_cannot_be_read_completely_refuse_the_identity(self):
        for where in (ROLES, TEAMS, TEAM_ROLES):
            with self.subTest(where=where):
                routes = world_routes(**{where: {"count": 2, "next": "https://elsewhere.synthetic.example/x",
                                                 "results": []}})
                aap, transport = client(routes)
                with self.assertRaises(AapIdentityRefused):
                    aap.discover()
                self.assertFalse(any("templates" in c["key"] for c in transport.calls))
        aap, _ = client(world_routes(**{ROLES: HttpResponse(403)}))
        with self.assertRaises(AapDiscoveryError):
            aap.discover()

    def test_system_auditor_is_accepted_as_the_most_an_identity_may_hold(self):
        aap, _ = client(world_routes(**{ME: me(auditor=True), ROLES: page(), TEAMS: page()}))
        report = aap.discover(reviewed=(PIN,))
        self.assertTrue(report.complete, report.problems)
        identity = report.to_dict()["identity"]
        self.assertEqual((identity["isSystemAuditor"], identity["readOnlyVerified"], identity["roles"]), (True, True, []))
        verified = client(world_routes())[0].discover().identity
        self.assertEqual(verified.roles, ("Auditor", "Member", "Read"))

    def test_a_template_the_identity_could_change_stops_discovery(self):
        for capability in ("start", "edit", "delete", "copy", "schedule"):
            with self.subTest(capability=capability):
                routes = world_routes()
                capable = job_template(4102, "SYNTHETIC Linux provisioning", job_type="run",
                                       summary_fields={"user_capabilities": {**READ_ONLY_CAPABILITIES, capability: True}})
                routes[JT1] = {**routes[JT1], "results": [routes[JT1]["results"][0], capable]}
                aap, transport = client(routes)
                with self.assertRaisesRegex(AapIdentityRefused, capability):
                    aap.discover()
                keys = [c["key"] for c in transport.calls]
                # Stopped as soon as the listing was read: no survey, project, or workflow request.
                self.assertFalse([k for k in keys if "survey_spec" in k or "projects" in k or "workflow" in k], keys)

    def test_unreported_capabilities_leave_the_report_partial(self):
        routes = world_routes()
        silent = job_template(4103, "SYNTHETIC vcenter tag dump (check)")
        del silent["summary_fields"]
        routes[JT2] = {**routes[JT2], "results": [silent, routes[JT2]["results"][1]]}
        report = client(routes)[0].discover(reviewed=(PIN,))
        self.assertFalse(report.complete)
        self.assertTrue(any("4103" in p and "unconfirmed" in p for p in report.problems))

    def test_a_superuser_identity_is_refused_before_anything_is_listed(self):
        aap, transport = client(world_routes(**{ME: me(superuser=True)}))
        with self.assertRaises(AapIdentityRefused):
            aap.discover()
        self.assertEqual([c["key"] for c in transport.calls], [ME])

    def test_no_name_email_default_or_secret_is_kept(self):
        aap, _ = client(world_routes())
        text = json.dumps(aap.discover(reviewed=(PIN,)).to_dict())
        for kept_nowhere in ("synthetic.aap.reader", "@synthetic.example", "Synthetic", "synthetic-default-must-not-be-kept",
                             "$encrypted$", SYNTHETIC_AAP_TOKEN):
            self.assertNotIn(kept_nowhere, text)
        self.assertIn('"secret": true', text)  # the password question is recorded only as secret

    def test_the_token_is_sent_as_a_bearer_header_and_never_logged(self):
        aap, transport = client(world_routes())
        with self.assertLogs("ogwa.http", level="INFO") as logs:
            aap.discover()
        self.assertTrue(all(c["headers"]["Authorization"] == f"Bearer {SYNTHETIC_AAP_TOKEN}" for c in transport.calls))
        self.assertFalse(any(SYNTHETIC_AAP_TOKEN in line for line in logs.output))

    def test_pagination_stays_on_the_same_origin_and_path_and_never_repeats(self):
        cases = {
            "another host": "https://elsewhere.synthetic.example/api/v2/job_templates/?page=2",
            "another path": "/api/v2/jobs/?page=2",
            "a loop": JT1,
        }
        for label, following in cases.items():
            with self.subTest(label=label):
                routes = world_routes()
                routes[JT1] = {**routes[JT1], "next": following}
                aap, transport = client(routes)
                report = aap.discover(reviewed=(PIN,))
                self.assertFalse(report.complete)
                self.assertTrue(any("job_templates listing" in p for p in report.problems))
                self.assertFalse(any("elsewhere" in c["url"] or "/api/v2/jobs/" in c["key"] for c in transport.calls))
        aap, _ = client(world_routes(), max_pages=1)
        self.assertFalse(aap.discover().complete)

    def test_a_template_that_cannot_be_read_is_a_problem_never_safe(self):
        routes = world_routes()
        broken = job_template(4105, "SYNTHETIC broken")
        del broken["ask_job_type_on_launch"]
        routes[JT2] = {**routes[JT2], "results": [*routes[JT2]["results"], broken]}
        aap, _ = client(routes)
        report = aap.discover(reviewed=(PIN,))
        self.assertFalse(report.complete)
        self.assertNotIn(4105, {c.template.template_id for c in report.classifications})
        self.assertTrue(any("4105" in p for p in report.problems))

    def test_an_unreadable_survey_or_revision_keeps_a_pinned_template_unknown(self):
        for override in ({"/api/v2/job_templates/4101/survey_spec/": {"spec": "not a list"}},
                         {"/api/v2/projects/7/": {"id": 7, "scm_revision": ""}},
                         {"/api/v2/projects/7/": HttpResponse(404)}):
            with self.subTest(override=list(override)[0]):
                aap, _ = client(world_routes(**override))
                safety = {c.template.template_id: c.safety for c in aap.discover(reviewed=(PIN,)).classifications}
                self.assertIs(safety[4101], TemplateSafety.UNKNOWN)

    def test_each_survey_answer_is_classified_and_not_found_is_never_empty(self):
        spec = "/api/v2/job_templates/4101/survey_spec/"
        read = {
            "200 empty object": ({}, ()),
            "200 one question": ({"spec": [{"variable": "v1", "type": "text", "required": True}]},
                                 (SurveyQuestion("v1", "text", True),)),
            "200 malformed spec": ({"spec": "not a list"}, None),
            "404 not found": (HttpResponse(404), None),
        }
        for name, (answer, expected) in read.items():
            with self.subTest(answer=name):
                aap, _ = client({spec: answer})
                self.assertEqual(aap.survey(TemplateKind.JOB_TEMPLATE, 4101), expected)
        for answer in (HttpResponse(401), HttpResponse(403), HttpResponse(500), HttpResponse(200, {}, b"not json")):
            with self.subTest(answer=answer.status):
                aap, _ = client({spec: answer})
                with self.assertRaises(AapDiscoveryError):
                    aap.survey(TemplateKind.JOB_TEMPLATE, 4101)

    def test_a_pinned_empty_survey_that_answers_not_found_stays_unknown(self):
        pin = replace(PIN, survey_variables=())
        for answer, safety in (({}, TemplateSafety.KNOWN_READ_ONLY), (HttpResponse(404), TemplateSafety.UNKNOWN)):
            with self.subTest(answer=getattr(answer, "status", "200 {}")):
                aap, _ = client(world_routes(**{"/api/v2/job_templates/4101/survey_spec/": answer}))
                found = {c.template.template_id: c for c in aap.discover(reviewed=(pin,)).classifications}[4101]
                self.assertIs(found.safety, safety)
                self.assertEqual(found.template.survey, None if safety is TemplateSafety.UNKNOWN else ())

    def test_a_survey_that_was_not_read_makes_discovery_partial(self):
        """F10 owner decision: a survey read as {} is empty and the report can be COMPLETE; a survey that was
        not read keeps its template UNKNOWN and makes the report PARTIAL."""
        pin, spec = replace(PIN, survey_variables=()), "/api/v2/job_templates/4101/survey_spec/"

        def discover(routes, **kwargs):
            report = client(world_routes(**routes))[0].discover(reviewed=(pin,), **kwargs)
            return report, {c.template.template_id: c for c in report.classifications}[4101]

        report, found = discover({spec: {}})
        self.assertEqual((report.to_dict()["status"], found.safety, found.template.survey),
                         ("COMPLETE", TemplateSafety.KNOWN_READ_ONLY, ()), report.problems)
        for name, routes, kwargs in (("404", {spec: HttpResponse(404)}, {}),
                                     ("malformed spec", {spec: {"spec": "not a list"}}, {}),
                                     ("unusable question", {spec: {"spec": [{"variable": "v1", "type": "nope"}]}}, {}),
                                     ("over the survey budget", {}, {"max_surveys": 0})):
            with self.subTest(name):
                report, found = discover(routes, **kwargs)
                self.assertEqual((report.to_dict()["status"], found.safety, found.template.survey),
                                 ("PARTIAL", TemplateSafety.UNKNOWN, None))
                self.assertTrue(any(p.startswith("job_template 4101: its survey") for p in report.problems),
                                report.problems)
        # A refusal, a server error, an answer that is not JSON, or a broken connection is stronger still:
        # discovery stops and no report claims anything (unchanged).
        for answer in (HttpResponse(401), HttpResponse(403), HttpResponse(500), HttpResponse(200, {}, b"not json")):
            with self.subTest(answer=answer.status), self.assertRaises(AapDiscoveryError):
                discover({spec: answer})
        aap, transport = client(world_routes())
        send = transport.send

        def reset_on_the_survey(method, url, *args, **kwargs):
            if url.endswith(spec):
                raise TransportError("synthetic connection reset")
            return send(method, url, *args, **kwargs)

        transport.send = reset_on_the_survey
        with self.assertRaises(TransportError):
            aap.discover(reviewed=(pin,))

    def test_refusals_and_bad_answers_stop_discovery(self):
        for answer in (HttpResponse(401), HttpResponse(403), HttpResponse(500),
                       HttpResponse(200, {}, b"<html>not json</html>"), {"results": []}, {"results": [me()["results"][0]] * 2}):
            with self.subTest(answer=getattr(answer, "status", str(answer)[:30])):
                aap, _ = client(world_routes(**{ME: answer}))
                with self.assertRaises(AapDiscoveryError):
                    aap.discover()

    def test_the_request_budget_is_enforced(self):
        aap, transport = client(world_routes(), max_requests=5)
        with self.assertRaisesRegex(AapDiscoveryError, "budget"):
            aap.discover()
        self.assertEqual(len(transport.calls), 5)

    def test_from_settings_needs_a_url_a_token_and_a_discovery_mode(self):
        settings = load_settings(read_only_env())
        aap = AapReadOnlyClient.from_settings(settings, transport=RoutingTransport(world_routes()))
        self.assertTrue(aap.discover().complete)
        for env in (read_only_env(OGWA_AAP_TOKEN=""), read_only_env(OGWA_AAP_URL="")):
            with self.subTest(env=sorted(k for k, v in env.items() if not v)), self.assertRaises(AapDiscoveryError):
                AapReadOnlyClient.from_settings(load_settings(env))
        dry_run = load_settings(read_only_env(OGWA_EXECUTION_MODE="DRY_RUN_MUTATION"))
        with self.assertRaises(AapDiscoveryError):
            AapReadOnlyClient.from_settings(dry_run)


class BoundaryTests(unittest.TestCase):
    def test_the_client_cannot_send_anything_but_get(self):
        for name in ("post", "put", "patch", "delete", "launch", "relaunch", "create", "copy"):
            self.assertFalse(hasattr(AapReadOnlyClient, name), name)
        aap, transport = client(world_routes())
        self.assertIsInstance(aap._http, ReadOnlyHttpClient)
        with self.assertRaises(Exception):
            aap._http._send_once("POST", SYNTHETIC_AAP_URL + "/api/v2/job_templates/4101/launch/", None, b"{}", 1)
        self.assertEqual(transport.calls, [])

    def test_the_package_imports_no_mutation_path(self):
        for path in (REPO_ROOT / "app" / "integrations" / "aap").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {
                a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            with self.subTest(path=path.name):
                self.assertEqual(modules & {"app.core.http_mutation", "app.core.safety", "subprocess", "socket"}, set())
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name, check="no launch path"):
                self.assertNotIn("/launch", text)
                self.assertNotRegex(text, r"\.(?:post|put|patch|delete)\(")

    def test_the_api_cannot_reach_the_discovery_client(self):
        for path in (REPO_ROOT / "app" / "api").glob("*.py"):
            self.assertNotIn("app.integrations", path.read_text(encoding="utf-8"), path.name)

    def test_discovery_refuses_modes_that_could_mutate(self):
        for mode in (ExecutionMode.DRY_RUN_MUTATION,):
            http = ReadOnlyHttpClient(mode=mode, http_policy=HttpPolicy(), allowed_hosts=["aap.synthetic.example"],
                                      transport=RoutingTransport({}))
            with self.subTest(mode=mode), self.assertRaises(AapDiscoveryError):
                AapReadOnlyClient(base_url=SYNTHETIC_AAP_URL, token=Secret(SYNTHETIC_AAP_TOKEN), http=http)


class ClassifierTests(unittest.TestCase):
    def meta(self, **changes) -> TemplateMetadata:
        fields = dict(kind=TemplateKind.JOB_TEMPLATE, template_id=4101, name=PIN.name, job_type="check",
                      playbook=OGWA_PLAYBOOK, project_id=7, ask_job_type_on_launch=False, ask_variables_on_launch=False,
                      ask_scm_branch_on_launch=False, ask_inventory_on_launch=False, ask_credential_on_launch=False,
                      survey_enabled=True, survey=(SurveyQuestion("ogwa_remediation_request", "textarea", True),),
                      project_revision=REVISION)
        fields.update(changes)
        return TemplateMetadata(**fields)

    def test_known_read_only_needs_check_mode_and_an_exact_reviewed_match(self):
        self.assertIs(classify_template(self.meta(), (PIN,)).safety, TemplateSafety.KNOWN_READ_ONLY)
        self.assertIs(classify_template(self.meta(), ()).safety, TemplateSafety.UNKNOWN)
        self.assertIs(classify_template(self.meta(), (replace(PIN, template_id=4102),)).safety, TemplateSafety.UNKNOWN)

    def test_run_mode_or_a_switchable_job_type_is_mutation_capable_even_when_pinned(self):
        for changes in ({"job_type": "run"}, {"ask_job_type_on_launch": True}):
            with self.subTest(changes=changes):
                self.assertIs(classify_template(self.meta(**changes), (PIN,)).safety, TemplateSafety.MUTATION_CAPABLE)

    def test_any_drift_from_the_reviewed_record_is_unknown(self):
        drift = ({"name": "renamed"}, {"playbook": "playbooks/other.yml"}, {"project_id": 8}, {"project_revision": None},
                 {"project_revision": "0" * 40}, {"survey": None},
                 {"survey": (SurveyQuestion("other_variable", "text", True),)}, {"ask_variables_on_launch": True},
                 {"ask_scm_branch_on_launch": True}, {"ask_inventory_on_launch": True}, {"ask_credential_on_launch": True},
                 {"job_type": "scan"})
        for changes in drift:
            with self.subTest(changes=changes):
                self.assertIs(classify_template(self.meta(**changes), (PIN,)).safety, TemplateSafety.UNKNOWN)

    def test_a_workflow_is_never_known_read_only(self):
        workflow = self.meta(kind=TemplateKind.WORKFLOW_JOB_TEMPLATE, job_type=None, playbook=None, project_id=None)
        result = classify_template(workflow, (PIN,))
        self.assertIs(result.safety, TemplateSafety.UNKNOWN)
        self.assertIn("workflow", result.reasons[0])
        self.assertFalse(result.launchable_for_what_if)

    def test_relevance_is_triage_only(self):
        unrelated = self.meta(name="SYNTHETIC vcenter tag dump", playbook="playbooks/tags.yml")
        related = self.meta(name="SYNTHETIC Okta group cleanup", playbook="playbooks/cleanup.yml", job_type="run")
        self.assertEqual(classify_template(unrelated).relevance, ())
        self.assertEqual(classify_template(related).relevance, ("okta",))
        self.assertIs(classify_template(related).safety, TemplateSafety.MUTATION_CAPABLE)
        self.assertEqual(classify_template(self.meta()).to_dict()["launched"], False)

    def test_survey_questions_keep_no_defaults_or_choices(self):
        question = SurveyQuestion("approver_password", "password", True)
        self.assertTrue(question.secret)
        self.assertEqual(set(vars(question)), {"variable", "type", "required"})
        with self.assertRaises(ValueError):
            SurveyQuestion("x", "javascript", True)


if __name__ == "__main__":
    unittest.main()
