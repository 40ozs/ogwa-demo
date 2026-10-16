"""The remediation allowlist, the adapters, and the worker contract (both directions).

The worker-contract tests read the golden request/result pairs that
tests/powershell/Test-OgwaRemediation.ps1 produces, so the Python parser and the PowerShell
worker are tested against the same documents.
"""

import ast
import json
import re
import unittest
from dataclasses import replace
from pathlib import Path

from app.core.errors import ConfigError, MutationBlockedError
from app.core.modes import ExecutionMode
from app.domain.evidence import EvidenceSource
from app.domain.quarantine import QuarantineOus
from app.domain.remediation import (
    RemediationOperation,
    RemediationOutcome,
    RemediationTarget,
    TargetKind,
    resolve_target,
)
from app.remediation import worker as contract
from app.remediation.adapters import (
    AapRemediationAdapter,
    RemediationPlan,
    SyntheticRemediationAdapter,
    adapter_for,
    split_rdn,
)
from app.remediation.allowlist import ALLOWLIST_FORMAT, AdapterKind, load_allowlist, parse_allowlist
from app.remediation.quarantine import SYNTHETIC_QUARANTINE_OUS_PATH, load_quarantine_ous, parse_quarantine_ous
from app.remediation.worker import WorkerContractError, parse_worker_result, worker_request
from app.store.environment import DatabaseEnvironment
from tests.domain_fixtures import AD_ID, ASSIGNMENT_ID, QUARANTINE_OUS, prov
from tests.test_remediation_api import observed_template
from tests.test_remediation_gates import AdStage, DeletionStage, OktaStage

O = RemediationOperation
REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "remediation"
WORKER = REPO_ROOT / "worker" / "OGWA.Remediation"
SYNTHETIC = DatabaseEnvironment.SYNTHETIC
CORP_OU = "OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example"


def allowlist(operations: dict, environment=SYNTHETIC):
    return parse_allowlist({"format": ALLOWLIST_FORMAT, "environment": environment.value, "operations": operations},
                           environment=environment)


def aap_entry(**changes) -> dict:
    entry = {"adapter": "AAP", "jobTemplateId": 4101, "jobTemplateName": "SYNTHETIC OGWA AD group quarantine (WhatIf)",
             "requestVariable": "ogwa_remediation_request", "reviewedPlaybook": "playbooks/ogwa_remediation_whatif.yml",
             "reviewedProjectId": 7, "reviewedProjectRevision": "5e7e70005e7e70005e7e70005e7e70005e7e7000"}
    entry.update(changes)
    return entry


def plan(stage, entry, operation=None, *, quarantine_ous=QUARANTINE_OUS, gated=True) -> RemediationPlan:
    """A plan for an adapter. Normally every gate passed first, as in the engine. ``gated=False``
    builds it from the resolved target alone, to test an adapter's own refusals for evidence
    the gates would already have stopped."""
    operation = operation or stage.operation
    if gated:
        evaluation = stage.gates(operation=operation)
        assert evaluation.report.passed, evaluation.report.problems()
        target = evaluation.target
    else:
        target, problems = resolve_target(stage.candidate, operation, stage.target, stage.evidence)
        assert target is not None, problems
    return RemediationPlan(stage.candidate.id, operation, target, stage.evidence, entry, "req_synthetic_1",
                           quarantine_ous)


class AllowlistTests(unittest.TestCase):
    def test_the_synthetic_config_loads_and_names_no_template(self):
        loaded = load_allowlist(REPO_ROOT / "config" / "remediation-allowlist.synthetic.json", environment=SYNTHETIC)
        self.assertEqual({e.operation for e in loaded.entries}, set(O))
        self.assertEqual({e.adapter for e in loaded.entries}, {AdapterKind.SYNTHETIC})
        self.assertTrue(all(e.aap is None for e in loaded.entries))
        # The quarantine OUs are separate deployment configuration (D136), not in the allowlist.
        ous = load_quarantine_ous(SYNTHETIC_QUARANTINE_OUS_PATH, environment=SYNTHETIC)
        self.assertEqual(ous.ou_for("corp.synthetic.example"), CORP_OU)

    def test_a_v1_allowlist_naming_quarantine_ous_is_refused_with_a_pointer(self):
        v1 = {"format": "ogwa-remediation-allowlist/v1", "environment": "SYNTHETIC",
              "operations": {"AD_GROUP_QUARANTINE": {"adapter": "SYNTHETIC", "quarantineOus": {
                  "corp.synthetic.example": CORP_OU}}}}
        with self.assertRaisesRegex(ConfigError, "D136"):
            parse_allowlist(v1, environment=SYNTHETIC)
        with self.assertRaises(ConfigError):
            allowlist({"AD_GROUP_QUARANTINE": {"adapter": "SYNTHETIC", "quarantineOus": {
                "corp.synthetic.example": CORP_OU}}})

    def test_the_format_is_strict(self):
        good = {"OKTA_GROUP_UNASSIGN": {"adapter": "SYNTHETIC"}}
        bad = [
            {"format": "v0", "environment": "SYNTHETIC", "operations": good},
            {"format": ALLOWLIST_FORMAT, "environment": "PRODUCTION", "operations": good},
            {"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC", "operations": good, "extra": 1},
            {"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC", "operations": [good]},
            {"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC", "operations": {"RUN_SCRIPT": {"adapter": "SYNTHETIC"}}},
            {"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC", "operations": {"AD_GROUP_DELETE": {"adapter": "SHELL"}}},
            {"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC",
             "operations": {"AD_GROUP_DELETE": {"adapter": "SYNTHETIC", "script": "x"}}},
            {"format": ALLOWLIST_FORMAT, "environment": "SYNTHETIC",
             "operations": {"AD_GROUP_DELETE": {"adapter": "SYNTHETIC", "quarantineOus": {}}}},
        ]
        for data in bad:
            with self.subTest(data=json.dumps(data)[:120]), self.assertRaises(ConfigError):
                parse_allowlist(data, environment=SYNTHETIC)

    def test_the_synthetic_adapter_is_refused_outside_a_synthetic_environment(self):
        with self.assertRaisesRegex(ConfigError, "SYNTHETIC environment"):
            allowlist({"AD_GROUP_DELETE": {"adapter": "SYNTHETIC"}}, environment=DatabaseEnvironment.PRODUCTION)
        production = allowlist({"AD_GROUP_DELETE": aap_entry()}, environment=DatabaseEnvironment.PRODUCTION)
        with self.assertRaises(MutationBlockedError):
            adapter_for(replace(production.entry(O.AD_GROUP_DELETE), adapter=AdapterKind.SYNTHETIC),
                        environment=DatabaseEnvironment.PRODUCTION)

    def test_quarantine_ous_are_explicit_ous_inside_their_domain(self):
        def config(ous, **changes):
            data = {"format": "ogwa-quarantine-ous/v1", "environment": "SYNTHETIC", "quarantineOus": ous}
            data.update(changes)
            return parse_quarantine_ous(data, environment=SYNTHETIC)

        self.assertEqual(config({"corp.synthetic.example": CORP_OU}).ou_for("CORP.synthetic.example"), CORP_OU)
        for ous in ({"corp.synthetic.example": "OU=*,DC=corp,DC=synthetic,DC=example"},
                    {"corp.synthetic.example": "CN=Users,DC=corp,DC=synthetic,DC=example"},
                    {"corp.synthetic.example": "OU=Q,DC=emea,DC=synthetic,DC=example"},
                    {"CORP.SYNTHETIC.EXAMPLE": CORP_OU}, {"corp.synthetic.example": ""}, {}, []):
            with self.subTest(ous=ous), self.assertRaises(ConfigError):
                config(ous)
        for changes in ({"format": "ogwa-quarantine-ous/v0"}, {"environment": "PRODUCTION"}, {"extra": 1}):
            with self.subTest(changes=changes), self.assertRaises(ConfigError):
                config({"corp.synthetic.example": CORP_OU}, **changes)

    def test_an_aap_binding_is_complete_and_bounded(self):
        entry = allowlist({"AD_GROUP_DELETE": aap_entry()}).entry(O.AD_GROUP_DELETE)
        self.assertEqual((entry.aap.template_id, entry.aap.reviewed.survey_variables),
                         (4101, ("ogwa_remediation_request",)))
        for change in ({"jobTemplateId": 0}, {"jobTemplateId": "4101"}, {"jobTemplateId": True},
                       {"requestVariable": "Bad Name"}, {"reviewedProjectRevision": "main"},
                       {"reviewedPlaybook": ""}, {"jobTemplateName": "x" * 600}):
            with self.subTest(change=change), self.assertRaises(ConfigError):
                allowlist({"AD_GROUP_DELETE": aap_entry(**change)})
        incomplete = aap_entry()
        del incomplete["reviewedProjectRevision"]
        with self.assertRaises(ConfigError):
            allowlist({"AD_GROUP_DELETE": incomplete})


class SyntheticAdapterTests(unittest.TestCase):
    def entry(self, operation, **extra):
        raw = {"adapter": "SYNTHETIC", **extra}
        return allowlist({operation.value: raw}).entry(operation)

    def test_each_operation_is_simulated_from_evidence(self):
        adapter = SyntheticRemediationAdapter()
        okta = adapter.dry_run(plan(OktaStage(), self.entry(O.OKTA_GROUP_UNASSIGN)))
        self.assertEqual((okta.outcome, okta.planned_changes[0].action),
                         (RemediationOutcome.SIMULATED, "unassign_group_from_application"))
        delete = adapter.dry_run(plan(DeletionStage(), self.entry(O.AD_GROUP_DELETE)))
        self.assertEqual(delete.planned_changes[0].action, "delete_group")
        quarantine = adapter.dry_run(plan(AdStage(), self.entry(O.AD_GROUP_QUARANTINE)))
        details = dict(quarantine.planned_changes[0].details)
        self.assertEqual(details["after.distinguishedName"], f"CN=SYNTH-GROUP-001,{CORP_OU}")

    def test_it_refuses_evidence_that_is_not_synthetic(self):
        stage = AdStage()
        stage.evidence = replace(stage.evidence, ad_group=replace(stage.evidence.ad_group,
                                                                  provenance=prov(stage.evidence.ad_group.provenance.observed_at,
                                                                                  source=EvidenceSource.AD_VIA_AAP)))
        stage.approval = replace(stage.approval, evidence_fingerprint=stage.gates().fingerprint)
        answer = SyntheticRemediationAdapter().dry_run(plan(stage, self.entry(O.AD_GROUP_QUARANTINE)))
        self.assertIs(answer.outcome, RemediationOutcome.BLOCKED)
        self.assertIn("synthetic targets only", answer.notes[0])

    def test_quarantine_needs_a_configured_ou_in_the_groups_domain(self):
        stage = AdStage()
        emea_only = QuarantineOus("SYNTHETIC", (("emea.synthetic.example", "OU=Q,DC=emea,DC=synthetic,DC=example"),))
        for ous in (emea_only, None):
            with self.subTest(ous=ous):
                answer = SyntheticRemediationAdapter().dry_run(plan(stage, self.entry(O.AD_GROUP_QUARANTINE),
                                                                    quarantine_ous=ous, gated=False))
                self.assertIs(answer.outcome, RemediationOutcome.BLOCKED)
        # The gates already refuse a group that is in its quarantine OU; the adapter refuses it too.
        already = replace(stage.evidence.ad_group, distinguished_name=f"CN=SYNTH-GROUP-001,{CORP_OU}")
        stage.evidence = replace(stage.evidence, ad_group=already)
        answer = SyntheticRemediationAdapter().dry_run(plan(stage, self.entry(O.AD_GROUP_QUARANTINE), gated=False))
        self.assertEqual(answer.notes, ("the group is already in the quarantine OU",))

    def test_distinguished_names_split_at_the_first_unescaped_comma(self):
        self.assertEqual(split_rdn("CN=A\\, B,OU=X,DC=y"), ("CN=A\\, B", "OU=X,DC=y"))
        self.assertEqual(split_rdn("CN=A\\\\,OU=X"), ("CN=A\\\\", "OU=X"))
        self.assertEqual(split_rdn("DC=y"), ("DC=y", ""))

    def test_an_entry_for_another_operation_is_refused(self):
        answer = SyntheticRemediationAdapter().dry_run(plan(AdStage(), self.entry(O.OKTA_GROUP_UNASSIGN),
                                                            operation=O.AD_GROUP_QUARANTINE))
        self.assertIs(answer.outcome, RemediationOutcome.BLOCKED)


class AapAdapterTests(unittest.TestCase):
    def setUp(self):
        self.entry = allowlist({"AD_GROUP_QUARANTINE": aap_entry()}).entry(O.AD_GROUP_QUARANTINE)
        self.plan = plan(AdStage(), self.entry)

    def test_a_reviewed_what_if_template_is_validated_and_not_launched(self):
        answer = AapRemediationAdapter({4101: observed_template()}).dry_run(self.plan)
        self.assertIs(answer.outcome, RemediationOutcome.VALIDATION_ONLY)
        details = dict(answer.planned_changes[0].details)
        self.assertEqual((details["job_type"], details["worker_mode"]), ("check", "WhatIf"))
        self.assertRegex(details["launch_payload_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertIn("never sent", answer.notes[0])

    def test_anything_short_of_a_reviewed_what_if_template_is_blocked(self):
        cases = {
            "not observed": {},
            "another template observed": {4102: observed_template(template_id=4102)},
            "run mode": {4101: observed_template(job_type="run")},
            "renamed": {4101: observed_template(name="something else")},
            "survey without the request variable": {4101: observed_template(survey=())},
            "password-typed request variable": {4101: observed_template(survey=(
                observed_template().survey[0].__class__("ogwa_remediation_request", "password", True),))},
        }
        for label, observed in cases.items():
            with self.subTest(label=label):
                self.assertIs(AapRemediationAdapter(observed).dry_run(self.plan).outcome, RemediationOutcome.BLOCKED)

    def test_the_adapter_holds_no_way_to_reach_aap(self):
        adapter = AapRemediationAdapter({4101: observed_template()})
        self.assertEqual({k for k in vars(adapter) if not k.startswith("_mutation")}, {"_observed"})
        for name in ("get", "post", "launch", "send", "request"):
            self.assertFalse(hasattr(adapter, name), name)


class PackageBoundaryTests(unittest.TestCase):
    FORBIDDEN = ("app.integrations", "http", "urllib", "socket",
                 "ssl", "subprocess", "requests", "httpx", "ctypes", "os")

    def test_the_remediation_package_cannot_reach_a_network_or_a_process(self):
        for path in sorted((REPO_ROOT / "app" / "remediation").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module or ""] if isinstance(node, ast.ImportFrom) else []
                for name in names:
                    with self.subTest(module=path.name, imports=name):
                        self.assertFalse(any(name == f or name.startswith(f + ".") for f in self.FORBIDDEN))


# --- the worker contract ---------------------------------------------------------------


def golden(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


BOUNDARY = ("whatif-ad-group-delete", "whatif-ad-group-quarantine", "whatif-okta-group-unassign",
            "validation-only-ad-group-delete", "blocked-protected-group", "blocked-identity-changed",
            "blocked-no-production-adapter", "blocked-execute-mode-refused", "blocked-wildcard-target",
            "blocked-unknown-operation")


class WorkerContractTests(unittest.TestCase):
    def test_the_constants_match_the_workers_contract_file(self):
        data = json.loads((WORKER / "contract.json").read_text(encoding="utf-8"))
        self.assertEqual((data["requestSchema"], data["resultSchema"], data["workerName"], data["workerVersion"]),
                         (contract.REQUEST_SCHEMA, contract.RESULT_SCHEMA, contract.WORKER_NAME, contract.WORKER_VERSION))
        self.assertEqual(tuple(data["modes"]), contract.WORKER_MODES)
        self.assertEqual(set(data["outcomes"]), set(contract.WORKER_OUTCOMES))
        self.assertEqual({k: tuple(v) for k, v in data["operations"].items()},
                         {o.value: keys for o, keys in contract.TARGET_KEYS.items()})
        self.assertEqual(data["plannedActions"], {o.value: a for o, a in contract.PLANNED_ACTIONS.items()})
        self.assertEqual(set(data["checkCodes"]), contract.CHECK_CODES)
        self.assertEqual(set(data["blockReasons"]), contract.BLOCK_REASONS)

    def test_the_golden_results_parse_to_their_outcomes(self):
        expected = {"whatif": RemediationOutcome.WHATIF, "validation": RemediationOutcome.VALIDATION_ONLY,
                    "blocked": RemediationOutcome.BLOCKED, "simulated": RemediationOutcome.SIMULATED}
        for path in sorted(FIXTURES.glob("*.result.json")):
            with self.subTest(fixture=path.name):
                result = parse_worker_result(path.read_text(encoding="utf-8"))
                self.assertIs(result.outcome, expected[path.name.split("-")[0]])

    def test_boundary_results_answer_exactly_their_request(self):
        for name in BOUNDARY:
            request = json.loads(golden(f"{name}.request.json"))
            with self.subTest(fixture=name):
                if request["mode"] not in contract.WORKER_MODES or request["operation"] not in contract.PLANNED_ACTIONS:
                    unreadable = parse_worker_result(golden(f"{name}.result.json"))
                    self.assertEqual(unreadable.blocked_reasons, ("INVALID_REQUEST",))
                    self.assertIsNone(unreadable.target)
                    continue
                result = parse_worker_result(golden(f"{name}.result.json"), expected=request)
                if result.target is not None:
                    self.assertEqual(result.target, request["target"])
        reasons = {name: parse_worker_result(golden(f"{name}.result.json")).blocked_reasons for name in BOUNDARY
                   if name.startswith("blocked")}
        self.assertEqual(reasons, {
            "blocked-protected-group": ("PROTECTED_TARGET",), "blocked-identity-changed": ("TARGET_IDENTITY_CHANGED",),
            "blocked-no-production-adapter": ("NO_PRODUCTION_ADAPTER",),
            "blocked-execute-mode-refused": ("INVALID_REQUEST",), "blocked-wildcard-target": ("WILDCARD_TARGET",),
            "blocked-unknown-operation": ("INVALID_REQUEST",)})
        self.assertIsNone(parse_worker_result(golden("blocked-unknown-operation.result.json")).operation)

    def test_a_tampered_result_is_refused(self):
        base = json.loads(golden("whatif-ad-group-delete.result.json"))
        request = json.loads(golden("whatif-ad-group-delete.request.json"))
        tampered = {
            "executed": {**base, "executed": True},
            "production mutation": {**base, "productionMutation": True},
            "executed as text": {**base, "executed": "false"},
            "unknown outcome": {**base, "outcome": "EXECUTED_PRODUCTION"},
            "another worker": {**base, "worker": {"name": "OGWA.Remediation", "version": "9.9.9"}},
            "extra key": {**base, "launched": False},
            "unknown block reason": {**base, "outcome": "Blocked", "plannedChanges": [], "blockedReasons": ["OVERRIDDEN"]},
            "blocked with a change": {**base, "outcome": "Blocked", "blockedReasons": ["PROTECTED_TARGET"]},
            "what-if without a change": {**base, "plannedChanges": []},
            "foreign action": {**base, "plannedChanges": [{**base["plannedChanges"][0], "action": "run_script"}]},
            "unknown check": {**base, "checks": [{"code": "OVERRIDE", "passed": True, "detail": "x"}]},
        }
        for label, document in tampered.items():
            with self.subTest(label=label), self.assertRaises(WorkerContractError):
                parse_worker_result(json.dumps(document), expected=request)
        other_target = {**request, "target": {**request["target"], "objectGuid": "5e7e7000-0000-4000-8000-000000700099"}}
        with self.assertRaises(WorkerContractError):
            parse_worker_result(golden("whatif-ad-group-delete.result.json"), expected=other_target)
        simulated_through_the_boundary = {**base, "outcome": "Simulated"}
        with self.assertRaisesRegex(WorkerContractError, "cannot come back Simulated"):
            parse_worker_result(json.dumps(simulated_through_the_boundary), expected=request)
        for text in ("", "[]", "not json", "x" * (contract.MAX_RESULT_CHARACTERS + 1)):
            with self.subTest(text=text[:10]), self.assertRaises(WorkerContractError):
                parse_worker_result(text)

    def test_requests_carry_one_explicit_target_and_no_mode_that_changes_anything(self):
        ad = AdStage().gates().target
        request = worker_request(O.AD_GROUP_DELETE, ad, mode="WhatIf", correlation_id="req_x")
        self.assertEqual(set(request["target"]), set(contract.TARGET_KEYS[O.AD_GROUP_DELETE]))
        self.assertEqual(request["target"]["objectGuid"], ad.value("object_guid"))
        for mode in ("Execute", "Simulate", "Apply", "", "whatif"):
            with self.subTest(mode=mode), self.assertRaises(WorkerContractError):
                worker_request(O.AD_GROUP_DELETE, ad, mode=mode, correlation_id="req_x")
        with self.assertRaises(WorkerContractError):
            worker_request(O.AD_GROUP_QUARANTINE, ad, mode="WhatIf", correlation_id="req_x")  # no OU
        with self.assertRaises(WorkerContractError):
            worker_request(O.AD_GROUP_DELETE, ad, mode="WhatIf", correlation_id="req_x", quarantine_ou=CORP_OU)
        okta = OktaStage().gates().target
        with self.assertRaises(WorkerContractError):
            worker_request(O.AD_GROUP_DELETE, okta, mode="WhatIf", correlation_id="req_x")
        self.assertEqual(worker_request(O.OKTA_GROUP_UNASSIGN, okta, mode="ValidateOnly", correlation_id="req_x")["target"],
                         {"oktaAppId": okta.value("okta_app_id"), "oktaGroupId": okta.value("okta_group_external_id")})

    def test_golden_fixtures_hold_only_synthetic_identities(self):
        for path in FIXTURES.glob("*.json"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(fixture=path.name):
                for guid in re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text):
                    self.assertTrue(guid.startswith("5e7e7000-0000-4000-8000-"), guid)
                for sid in re.findall(r"S-1-5-21-[0-9-]+", text):
                    self.assertTrue(sid.startswith("S-1-5-21-1000000001-1000000002-1000000003-"), sid)
                for dc in re.findall(r"DC=[^\"]+", text):
                    self.assertTrue(dc.endswith("DC=synthetic,DC=example"), dc)
                for okta_id in re.findall(r"\b0o[a-z][A-Za-z0-9]+|\b00g[A-Za-z0-9]+", text):
                    self.assertIn("SYNTH", okta_id)


class TargetRecordTests(unittest.TestCase):
    def test_a_target_is_one_internal_id_of_its_kind(self):
        with self.assertRaises(Exception):
            RemediationTarget(TargetKind.AD_GROUP, ASSIGNMENT_ID, (("a", "b"),))
        with self.assertRaises(Exception):
            RemediationTarget(TargetKind.OKTA_ASSIGNMENT, AD_ID, (("a", "b"),))
        self.assertEqual(RemediationTarget(TargetKind.AD_GROUP, AD_ID, (("a", "b"),)).value("a"), "b")
        self.assertIs(ExecutionMode.DRY_RUN_MUTATION, SyntheticRemediationAdapter().mutation_policy.mode)


if __name__ == "__main__":
    unittest.main()
