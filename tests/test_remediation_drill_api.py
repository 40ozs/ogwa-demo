"""OGWA-DEMO-03: synthetic remediation drills through the operator API.

A drill runs the governed remediation path first (every gate, the allowlist, the synthetic
adapter), then a dry run or a scripted synthetic execution against an in-memory provider
fixture. These tests hold it to the acceptance gates:

- ``DryRunDrillTests``: a dry run performs zero mutations and says so;
- ``SyntheticExecutionTests``: every scenario, for all three operations, ends where its
  script says; only the target changes, and only inside the fixture;
- ``UncertainOutcomeTests``: a timeout is verified, never retried blind; a duplicate is never
  submitted; verification failure is never a success;
- ``GateTests``: a blocked request builds nothing; the gates are evaluated again before a
  retry, on the real evidence;
- ``RecordsNothingTests``: a drill writes nothing to the store and contacts nothing;
- ``RefusalTests``: production mutation, malformed requests, separation of duties;
- ``NullMeridianDrillTests``: the drill is reachable in the default demo dataset (NM-C11),
  and NM-C10 stays unreachable.
"""

import unittest
from datetime import timedelta
from unittest import mock

from app.api.services import policy_in_force
from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.evidence import EvidencePurpose
from app.domain.remediation import RemediationOperation
from app.domain.remediation_execution import STATE_LABELS
from app.remediation import drill as drill_module
from app.remediation.drill import DrillMode, DrillUnavailable, run_drill
from app.remediation.synthetic_provider import SCENARIOS, SyntheticProviderFixture
from tests.api_fixtures import APPROVER_EXECUTOR, EXECUTOR, SECURITY, VIEWER, World
from tests.store_fixtures import table_dump
from tests.test_demo_mode import no_live_system
from tests.test_remediation_api import approve_ad, approve_deletion, approve_okta, target_of, world

V = "/api/v1"
OPERATIONS = {"OKTA_GROUP_UNASSIGN": approve_okta, "AD_GROUP_QUARANTINE": approve_ad,
              "AD_GROUP_DELETE": approve_deletion}


def body(w: World, candidate: str, approval: str, operation: str, mode: str = "DRY_RUN", scenario: str | None = None,
         **extra) -> dict:
    payload = {"operation": operation, "target": target_of(w, candidate, operation), "approvalId": approval,
               "expectedEvidenceFingerprint": w.fingerprint(w.client(VIEWER), candidate), "mode": mode}
    if scenario is not None:
        payload["scenario"] = scenario
    payload.update(extra)
    return payload


def post_drill(w: World, client, candidate: str, approval: str, operation: str = "OKTA_GROUP_UNASSIGN",
               mode: str = "DRY_RUN", scenario: str | None = None, **extra):
    return client.post(f"{V}/candidates/{candidate}/remediation-drills",
                       body(w, candidate, approval, operation, mode, scenario, **extra))


def states(result) -> list[str]:
    return [s["state"] for s in result.json["drill"]["steps"]]


class DrillCase(unittest.TestCase):
    operation = "OKTA_GROUP_UNASSIGN"

    def setUp(self):
        self.world = world()
        self.candidate, self.approval = OPERATIONS[self.operation](self.world)
        self.executor = self.world.client(EXECUTOR)

    def tearDown(self):
        self.world.close()

    def drill(self, mode="DRY_RUN", scenario=None, operation=None, client=None, **extra):
        return post_drill(self.world, client or self.executor, self.candidate, self.approval,
                          operation or self.operation, mode, scenario, **extra)


class DryRunDrillTests(DrillCase):
    def test_a_dry_run_changes_nothing_and_says_so(self):
        result = self.drill()
        self.assertEqual(result.status, 200, result.json)
        d = result.json["drill"]
        self.assertEqual((d["mode"], d["finalState"], d["finalLabel"]), ("DRY_RUN", "DRY_RUN", "DRY RUN — NO STATE CHANGED"))
        p = d["provider"]
        self.assertEqual((p["stateChanged"], p["mutationsApplied"], p["ledger"]), (False, 0, []))
        self.assertEqual((p["digestBefore"], p["stateBefore"]), (p["digestAfter"], p["stateAfter"]))
        self.assertEqual((d["submissions"], d["succeeded"], d["recorded"], d["productionMutation"]), (0, False, False, False))
        self.assertIn("Nothing was submitted", d["steps"][0]["detail"])

    def test_a_dry_run_never_submits_and_its_fixture_can_only_plan(self):
        built = []
        original = SyntheticProviderFixture.__init__

        def spy(fixture, *args, **kwargs):
            built.append(kwargs["mutation_policy"].mode)
            original(fixture, *args, **kwargs)

        with mock.patch.object(SyntheticProviderFixture, "__init__", spy), \
                mock.patch.object(SyntheticProviderFixture, "submit", side_effect=AssertionError("submitted")) as submit:
            result = self.drill()
        self.assertEqual(result.status, 200, result.json)
        submit.assert_not_called()
        self.assertEqual(built, [ExecutionMode.DRY_RUN_MUTATION])


class SyntheticExecutionTests(unittest.TestCase):
    def test_every_scenario_ends_where_its_script_says_for_every_operation(self):
        for operation, approve in OPERATIONS.items():
            w = world()
            try:
                candidate, approval = approve(w)
                executor = w.client(EXECUTOR)
                for key, s in SCENARIOS.items():
                    with self.subTest(operation=operation, scenario=key):
                        result = post_drill(w, executor, candidate, approval, operation, "SYNTHETIC_EXECUTION", key)
                        self.assertEqual(result.status, 200, result.json)
                        d = result.json["drill"]
                        self.assertEqual(d["finalState"], s.expected_final.value)
                        self.assertEqual(d["succeeded"], s.expected_final.value == "POST_ACTION_VERIFIED")
                        self.assertEqual(d["scenario"]["key"], key)
                        self.assertLessEqual(d["provider"]["mutationsApplied"], 1)
                        for step in d["steps"]:
                            self.assertEqual(step["label"], STATE_LABELS[drill_module.X(step["state"])])
                        changed = {k for k in d["provider"]["stateBefore"]
                                   if d["provider"]["stateBefore"][k] != d["provider"]["stateAfter"].get(k)}
                        self.assertLessEqual(changed, {d["plannedTransition"]["targetKey"]},
                                             "only the planned target changes")
                        self.assertEqual(bool(changed), d["provider"]["mutationsApplied"] == 1)
            finally:
                w.close()

    def test_an_executed_drill_changes_only_the_synthetic_fixture(self):
        w = world()
        try:
            candidate, approval = approve_okta(w)
            before = table_dump(w.store)
            result = post_drill(w, w.client(EXECUTOR), candidate, approval, mode="SYNTHETIC_EXECUTION", scenario="NO_FAULT")
            d = result.json["drill"]
            self.assertEqual((d["finalLabel"], d["provider"]["stateChanged"]), ("POST-ACTION VERIFIED", True))
            target = d["plannedTransition"]["targetKey"]
            self.assertEqual((d["provider"]["stateBefore"][target]["present"], d["provider"]["stateAfter"][target]["present"]),
                             (True, False))
            self.assertEqual(table_dump(w.store), before, "the store, assignment evidence included, is unchanged")
            self.assertTrue(w.store.evidence_bundle(w.store.load_candidate(candidate)).assignments[0].present)
            self.assertEqual((d["syntheticOnly"], d["productionMutation"], d["externalSystemsContacted"], d["recorded"],
                              d["lifecycleChanged"]), (True, False, False, False, False))
            self.assertNotIn("executed", d, "a drill never uses the governed record's executed field")
        finally:
            w.close()


class UncertainOutcomeTests(DrillCase):
    def test_a_timeout_that_applied_nothing_is_verified_then_retried_once(self):
        result = self.drill("SYNTHETIC_EXECUTION", "TIMEOUT_NOT_APPLIED")
        self.assertEqual(states(result), ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "RETRY_PERMITTED",
                                          "EXECUTION_REQUESTED", "EXECUTED", "POST_ACTION_VERIFIED"])
        d = result.json["drill"]
        steps = d["steps"]
        self.assertEqual((steps[1]["answer"], steps[2]["observation"], steps[3]["reason"]),
                         ("TIMEOUT", "NOT_APPLIED", "VERIFIED_NOT_APPLIED"))
        self.assertEqual([(e["actor"], e["applied"]) for e in d["provider"]["ledger"]],
                         [(d["operationId"], False), (d["operationId"], True)], "the retry reuses the operation id")
        self.assertEqual((d["submissions"], d["provider"]["mutationsApplied"], d["succeeded"]), (2, 1, True))

    def test_a_timeout_that_applied_the_change_is_never_resubmitted(self):
        result = self.drill("SYNTHETIC_EXECUTION", "TIMEOUT_AFTER_APPLY")
        self.assertEqual(states(result), ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "EXECUTED",
                                          "POST_ACTION_VERIFIED"])
        d = result.json["drill"]
        self.assertEqual((d["submissions"], d["provider"]["mutationsApplied"]), (1, 1))
        self.assertEqual(len(d["provider"]["ledger"]), 1, "no duplicate submission reached the provider")

    def test_an_unverifiable_outcome_stays_unknown(self):
        result = self.drill("SYNTHETIC_EXECUTION", "TIMEOUT_UNVERIFIABLE")
        d = result.json["drill"]
        self.assertEqual((d["finalState"], d["steps"][-1]["reason"], d["succeeded"], d["submissions"]),
                         ("RETRY_NOT_PERMITTED", "OUTCOME_STILL_UNKNOWN", False, 1))
        self.assertEqual(d["steps"][2]["reads"], [{"succeeded": False}, {"succeeded": False}])

    def test_a_failed_post_action_verification_is_never_reported_as_success(self):
        result = self.drill("SYNTHETIC_EXECUTION", "ACKNOWLEDGED_NOT_APPLIED")
        d = result.json["drill"]
        self.assertEqual(states(result), ["EXECUTION_REQUESTED", "EXECUTED", "VERIFICATION_FAILED"])
        self.assertEqual((d["succeeded"], d["finalLabel"]), (False, "VERIFICATION FAILED — NOT A SUCCESS"))
        self.assertEqual(d["provider"]["mutationsApplied"], 0)


class GateTests(DrillCase):
    def test_a_blocked_request_builds_no_provider(self):
        self.world.clock.advance(timedelta(hours=25))  # the evidence is now past the EXECUTION window
        with mock.patch.object(SyntheticProviderFixture, "__init__", side_effect=AssertionError("built")):
            result = self.drill("SYNTHETIC_EXECUTION", "NO_FAULT")
        self.assertEqual((result.status, result.code), (409, "REMEDIATION_BLOCKED"), result.json)
        self.assertIn("No synthetic provider was built", result.json["error"]["message"])
        self.assertIn("FRESH_EVIDENCE", {g["gate"] for g in result.json["error"]["gates"] if not g["passed"]})
        self.assertEqual(result.json["error"]["outcome"], "BLOCKED")

    def test_the_gates_are_evaluated_again_before_the_retry(self):
        # Age the evidence to 15 seconds inside the 24-hour EXECUTION window: the first
        # attempt passes the gates; its 30-second timeout pushes the retry past the window.
        policy = policy_in_force(self.world.store).policy.lifecycle
        window = policy.freshness.max_age(EvidencePurpose.EXECUTION)
        bundle = self.world.store.evidence_bundle(self.world.store.load_candidate(self.candidate))
        oldest = min(r.provenance.observed_at for r in bundle.records())
        self.world.clock.now = oldest + window - timedelta(seconds=15)
        result = self.drill("SYNTHETIC_EXECUTION", "TIMEOUT_NOT_APPLIED")
        self.assertEqual(result.status, 200, result.json)
        self.assertEqual(states(result), ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "RETRY_PERMITTED",
                                          "BLOCKED"])
        last = result.json["drill"]["steps"][-1]
        self.assertEqual(last["reason"], "GATES_BLOCKED_ON_RETRY")
        self.assertTrue(any(p.startswith("FRESH_EVIDENCE") for p in last["problems"]), last["problems"])
        self.assertEqual(result.json["drill"]["provider"]["mutationsApplied"], 0)


class RecordsNothingTests(DrillCase):
    def test_no_drill_writes_to_the_store_or_reaches_a_live_system(self):
        before = table_dump(self.world.store)
        state = self.world.store.load_candidate(self.candidate).state
        with no_live_system():
            for key in (None, *SCENARIOS):
                with self.subTest(scenario=key):
                    result = self.drill("SYNTHETIC_EXECUTION" if key else "DRY_RUN", key)
                    self.assertEqual(result.status, 200, result.json)
        self.assertEqual(table_dump(self.world.store), before, "no audit event, job, decision, or evidence")
        self.assertIs(self.world.store.load_candidate(self.candidate).state, state)

    def test_a_refused_drill_is_not_chained_either(self):
        before = self.world.store.audit_head()
        self.world.clock.advance(timedelta(hours=25))
        self.assertEqual(self.drill("SYNTHETIC_EXECUTION", "NO_FAULT").status, 409)
        self.assertEqual(self.drill(client=self.world.client(VIEWER)).status, 403)
        self.assertEqual(self.world.store.audit_head(), before, "a drill is not a governed state change (D72)")


class RefusalTests(DrillCase):
    def test_production_mutation_is_refused_before_anything_else(self):
        for extra in ({"executionMode": "PRODUCTION_MUTATION"}, {"dryRun": False}):
            with self.subTest(extra=extra):
                result = self.drill(**extra)
                self.assertEqual((result.status, result.code), (403, "PRODUCTION_MUTATION_REFUSED"))
        garbage = self.executor.post(f"{V}/candidates/{self.candidate}/remediation-drills",
                                     {"executionMode": "PRODUCTION_MUTATION", "operation": "x"})
        self.assertEqual((garbage.status, garbage.code), (403, "PRODUCTION_MUTATION_REFUSED"))

    def test_a_request_cannot_carry_its_own_faults_mode_or_adapter(self):
        cases = {
            "unknown scenario": dict(mode="SYNTHETIC_EXECUTION", scenario="RANDOM_FAILURE"),
            "execution without a scenario": dict(mode="SYNTHETIC_EXECUTION"),
            "a dry run with a scenario": dict(mode="DRY_RUN", scenario="NO_FAULT"),
            "unknown mode": dict(mode="EXECUTE"),
            "fault script": dict(mode="SYNTHETIC_EXECUTION", scenario="NO_FAULT", faults=["APPLY"]),
            "dry-run flag": dict(dryRun=True),
            "execution mode": dict(executionMode="DRY_RUN_MUTATION"),
            "adapter": dict(adapter="AAP"),
        }
        for label, extra in cases.items():
            with self.subTest(label):
                mode = extra.pop("mode", "DRY_RUN")
                scenario = extra.pop("scenario", None)
                result = self.drill(mode, scenario, **extra)
                self.assertEqual((result.status, result.code), (422, "VALIDATION_FAILED"), result.json)
        listed = self.executor.post(f"{V}/candidates/{self.candidate}/remediation-drills",
                                    {**body(self.world, self.candidate, self.approval, self.operation),
                                     "target": [target_of(self.world, self.candidate, self.operation)]})
        self.assertEqual((listed.status, listed.code), (422, "VALIDATION_FAILED"))

    def test_only_the_dry_run_planning_permission_may_drill(self):
        result = self.drill(client=self.world.client(VIEWER))
        self.assertEqual((result.status, result.code), (403, "FORBIDDEN"))
        result = self.drill(client=self.world.client(SECURITY))
        self.assertEqual((result.status, result.code), (403, "FORBIDDEN"), "approval power is not drill power")

    def test_a_stale_view_is_refused(self):
        result = self.drill(expectedEvidenceFingerprint="sha256:" + "0" * 64)
        self.assertEqual((result.status, result.code), (409, "EVIDENCE_CHANGED"))

    def test_drills_run_only_in_local_synthetic(self):
        w = self.world
        candidate = w.store.load_candidate(self.candidate)
        common = dict(mode=DrillMode.DRY_RUN, scenario_key=None, candidate=candidate,
                      operation=RemediationOperation.OKTA_GROUP_UNASSIGN, target_ref=candidate.assignment_ids[0],
                      evidence=w.store.evidence_bundle(candidate), approval=w.store.load_approval(self.approval),
                      policy=policy_in_force(w.store).policy.lifecycle, now=w.clock(),
                      requested_by=Actor(ActorKind.HUMAN, EXECUTOR), allowlist=w.api.remediation._allowlist,
                      environment=w.store.marker.environment, correlation_id="req-test")
        for mode in (ExecutionMode.DRY_RUN_MUTATION, ExecutionMode.READ_ONLY_PRODUCTION):
            with self.subTest(mode=mode), self.assertRaises(DrillUnavailable):
                run_drill(**common, execution_mode=mode)
        self.assertEqual(run_drill(**common, execution_mode=ExecutionMode.LOCAL_SYNTHETIC).final_state.value, "DRY_RUN")


class SeparationOfDutiesTests(unittest.TestCase):
    def test_the_stage_approver_cannot_run_its_drill(self):
        w = world()
        try:
            candidate, approval = approve_okta(w, approver=APPROVER_EXECUTOR)
            result = post_drill(w, w.client(APPROVER_EXECUTOR), candidate, approval)
            self.assertEqual((result.status, result.code), (403, "SEPARATION_OF_DUTIES"))
            self.assertEqual(post_drill(w, w.client(EXECUTOR), candidate, approval).status, 200)
        finally:
            w.close()


class ScenarioCatalogTests(unittest.TestCase):
    def test_the_catalog_is_the_servers_and_readable_by_any_reader(self):
        w = world()
        try:
            result = w.client(VIEWER).get(f"{V}/remediation-drill-scenarios")
            self.assertEqual(result.status, 200)
            self.assertEqual([s["key"] for s in result.json["items"]], list(SCENARIOS))
            self.assertEqual(result.json["labels"], {s.value: label for s, label in STATE_LABELS.items()})
            self.assertEqual(result.json["modes"], ["DRY_RUN", "SYNTHETIC_EXECUTION"])
            self.assertEqual(w.client(VIEWER).post(f"{V}/candidates/{w.candidate('S07')}/remediation-drills", {}).status,
                             403)
        finally:
            w.close()


class NullMeridianDrillTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def nm_approval(self, key: str) -> tuple[str, str | None]:
        candidate = self.world.candidate(key)
        items = self.world.client(VIEWER).get(f"{V}/candidates/{candidate}/approvals").json["items"]
        return candidate, (items[0]["id"] if items else None)

    def test_nm_c11_is_drillable_at_the_demo_clock_without_refreshing_anything(self):
        candidate, approval = self.nm_approval("NM-C11")
        before = table_dump(self.world.store)
        executor = self.world.client(EXECUTOR)
        dry = post_drill(self.world, executor, candidate, approval)
        self.assertEqual((dry.status, dry.json["drill"]["finalState"]), (200, "DRY_RUN"), dry.json)
        run = post_drill(self.world, executor, candidate, approval, mode="SYNTHETIC_EXECUTION",
                         scenario="TIMEOUT_NOT_APPLIED")
        self.assertEqual(run.status, 200, run.json)
        self.assertEqual(run.json["drill"]["finalState"], "POST_ACTION_VERIFIED")
        self.assertEqual(table_dump(self.world.store), before)
        self.assertEqual(self.world.store.load_candidate(candidate).state.value, "APPROVED")

    def test_no_other_candidate_can_be_drilled(self):
        executor = self.world.client(EXECUTOR)
        drillable = []
        for scenario in self.world.summary.scenarios:
            candidate, approval = self.nm_approval(scenario.key)
            if approval is None:
                continue  # no approval at all: nothing to start a drill from (NM-C10 among them)
            result = post_drill(self.world, executor, candidate, approval)
            if result.status == 200:
                drillable.append(scenario.key)
            else:
                self.assertEqual(result.code, "REMEDIATION_BLOCKED", (scenario.key, result.json))
        self.assertEqual(drillable, ["NM-C11"])
        _, nm_c10_approval = self.nm_approval("NM-C10")
        self.assertIsNone(nm_c10_approval, "NM-C10 has no approval, so no drill or retry can ever start from it")


if __name__ == "__main__":
    unittest.main()
