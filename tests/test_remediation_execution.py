"""The remediation execution state machine, the synthetic provider fixture, and a
run driven step by step. Pure and in memory: no store, no API, no network.

The invariants (RX-1 to RX-10, docs/security/safety-invariants.md):

- ``TransitionTableTests``: the table is closed; an unknown outcome leads only to verification;
  a resubmission is reachable only through RETRY_PERMITTED; success only from EXECUTED.
- ``RetryDecisionTests``: only a read that shows the before-state permits a retry.
- ``TraceTests``: a recorded run that breaks an invariant cannot be built.
- ``ProviderFixtureTests``: the idempotency key and the precondition refuse without a change;
  a plan-only policy applies nothing; nothing is random.
- ``ExecutionRunTests``: out-of-order calls are refused before the provider is touched;
  duplicates never happen; verification failures are never successes.
"""

import ast
import itertools
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.errors import MutationBlockedError
from app.core.modes import ExecutionMode
from app.core.safety import MutationCapableService, MutationPolicy
from app.domain.errors import InvalidRecord
from app.domain.remediation_execution import (
    MAX_SUBMISSIONS,
    OPERATION_ID_PREFIX,
    STATE_LABELS,
    SUCCESS_STATE,
    TERMINAL_STATES,
    TRANSITIONS,
    ExecutionState,
    ExecutionStep,
    ExecutionStepRefused,
    ExecutionTrace,
    PlannedTransition,
    Reason,
    TargetObservation,
    check_transition,
    operation_id,
    retry_decision,
    scope_differences,
)
from app.remediation.drill import ExecutionRun
from app.remediation.synthetic_provider import (
    SCENARIOS,
    FaultKind,
    FaultScript,
    SyntheticProviderFixture,
    applied_state,
)

X = ExecutionState
O = TargetObservation
REPO_ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 1, 13, 0, tzinfo=timezone.utc)
KEY = "okta-assignment:asgn_" + "1" * 32
OTHER = "okta-assignment:asgn_" + "2" * 32
OP = operation_id(candidate_id="cand_" + "a" * 32, operation="OKTA_GROUP_UNASSIGN",
                  target_identity_digest="sha256:" + "b" * 64, approval_id="apr_" + "c" * 32,
                  evidence_fingerprint="sha256:" + "d" * 64)
CHANGE = PlannedTransition.of(OP, KEY, {"present": True}, {"present": False}, "Remove one synthetic assignment.")
AD_KEY = "ad-group:00000000-0000-4000-8000-000000000001"
DN = "CN=SYNTH-X,OU=Groups,DC=corp,DC=synthetic,DC=example"
MOVED = "CN=SYNTH-X,OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example"
QUARANTINE = PlannedTransition.of(OP, AD_KEY, {"exists": True, "distinguishedName": DN},
                                  {"exists": True, "distinguishedName": MOVED}, "Move one synthetic group.")


def objects(present: bool = True) -> dict:
    return {KEY: {"present": present, "oktaAppId": "0oaSYNTHA"}, OTHER: {"present": True, "oktaAppId": "0oaSYNTHB"},
            AD_KEY: {"exists": True, "distinguishedName": DN, "objectGuid": "00000000-0000-4000-8000-000000000001",
                     "domain": "corp.synthetic.example"}}


def fixture(script: FaultScript | str = "NO_FAULT", *, mode=ExecutionMode.LOCAL_SYNTHETIC, objs=None):
    script = SCENARIOS[script] if isinstance(script, str) else script
    return SyntheticProviderFixture(objects() if objs is None else objs, script=script,
                                    mutation_policy=MutationPolicy.for_mode(mode), start=T0)


def script(*submissions: FaultKind, unreadable=(), outside=()) -> FaultScript:
    return FaultScript("TEST", "test", "a test script", tuple(submissions), frozenset(unreadable), tuple(outside))


def run_of(provider, change=CHANGE, problems=()) -> ExecutionRun:
    return ExecutionRun(provider, change, recheck=lambda at: tuple(problems))


def states(trace: ExecutionTrace) -> list[str]:
    return [s.state.value for s in trace.steps]


# --- the table -------------------------------------------------------------------------------


class TransitionTableTests(unittest.TestCase):
    def test_every_state_is_either_in_the_table_or_terminal(self):
        self.assertEqual(set(TRANSITIONS) - {None} | TERMINAL_STATES, set(ExecutionState))
        self.assertEqual(TERMINAL_STATES, {X.DRY_RUN, X.BLOCKED, X.RETRY_NOT_PERMITTED, X.POST_ACTION_VERIFIED,
                                           X.VERIFICATION_FAILED})
        for state in TERMINAL_STATES:
            for target in ExecutionState:
                with self.subTest(state=state, target=target), self.assertRaises(ExecutionStepRefused):
                    check_transition(state, target)

    def test_the_table_is_closed(self):
        for current, target in itertools.product([None, *ExecutionState], ExecutionState):
            allowed = target in TRANSITIONS.get(current, frozenset())
            with self.subTest(current=current, target=target):
                if allowed:
                    check_transition(current, target)
                else:
                    with self.assertRaises(ExecutionStepRefused):
                        check_transition(current, target)

    def test_an_unknown_outcome_leads_only_to_verification(self):
        self.assertEqual(TRANSITIONS[X.OUTCOME_UNKNOWN], {X.VERIFYING})

    def test_a_submission_follows_only_the_start_or_a_permitted_retry(self):
        sources = {s for s, targets in TRANSITIONS.items() if X.EXECUTION_REQUESTED in targets}
        self.assertEqual(sources, {None, X.RETRY_PERMITTED})
        self.assertEqual({s for s, t in TRANSITIONS.items() if X.RETRY_PERMITTED in t}, {X.VERIFYING})

    def test_success_follows_only_an_execution(self):
        self.assertEqual({s for s, t in TRANSITIONS.items() if SUCCESS_STATE in t}, {X.EXECUTED})
        self.assertNotIn(X.EXECUTED, TERMINAL_STATES, "an execution is never the end of a run")

    def test_dry_run_and_execution_labels_cannot_be_confused(self):
        labels = list(STATE_LABELS.values())
        self.assertEqual(set(STATE_LABELS), set(ExecutionState))
        self.assertEqual(len(set(labels)), len(labels))
        self.assertEqual(STATE_LABELS[X.DRY_RUN], "DRY RUN — NO STATE CHANGED")
        self.assertEqual(STATE_LABELS[X.EXECUTED], "EXECUTED — SYNTHETIC DEMO")
        self.assertEqual(STATE_LABELS[X.OUTCOME_UNKNOWN], "OUTCOME UNKNOWN — VERIFYING")
        self.assertEqual(STATE_LABELS[X.POST_ACTION_VERIFIED], "POST-ACTION VERIFIED")
        for state, label in STATE_LABELS.items():
            if state is not X.DRY_RUN:
                with self.subTest(state=state):
                    self.assertNotIn("DRY RUN", label)
                    self.assertNotIn("NO STATE CHANGED", label)
        self.assertNotIn("VERIFIED", STATE_LABELS[X.VERIFICATION_FAILED].replace("VERIFICATION FAILED", ""))


class RetryDecisionTests(unittest.TestCase):
    def test_only_a_read_showing_the_before_state_permits_a_retry(self):
        for observation, submissions in itertools.product(O, range(0, MAX_SUBMISSIONS + 2)):
            state, reason, detail = retry_decision(observation, submissions=submissions)
            with self.subTest(observation=observation, submissions=submissions):
                self.assertTrue(detail)
                if state is X.RETRY_PERMITTED:
                    self.assertIs(observation, O.NOT_APPLIED)
                    self.assertLess(submissions, MAX_SUBMISSIONS)
                if observation is O.APPLIED:
                    self.assertEqual((state, reason), (X.EXECUTED, Reason.CONFIRMED_APPLIED))
                if observation is O.UNREADABLE:
                    self.assertEqual((state, reason), (X.RETRY_NOT_PERMITTED, Reason.OUTCOME_STILL_UNKNOWN))
                if observation is O.DIVERGED:
                    self.assertEqual((state, reason), (X.RETRY_NOT_PERMITTED, Reason.TARGET_CHANGED_OUTSIDE_RUN))
        self.assertEqual(retry_decision(O.NOT_APPLIED, submissions=MAX_SUBMISSIONS)[1], Reason.ATTEMPT_LIMIT_REACHED)

    def test_a_planned_transition_classifies_what_a_read_shows(self):
        self.assertIs(CHANGE.classify({"present": True}), O.NOT_APPLIED)
        self.assertIs(CHANGE.classify({"present": False}), O.APPLIED)
        self.assertIs(CHANGE.classify({}), O.DIVERGED)
        self.assertIs(CHANGE.classify(None), O.UNREADABLE)
        self.assertIs(QUARANTINE.classify({"exists": True, "distinguishedName": "CN=SYNTH-X,OU=Elsewhere"}), O.DIVERGED)
        with self.assertRaises(InvalidRecord):
            PlannedTransition.of(OP, KEY, {"present": True}, {"present": True}, "no change")
        with self.assertRaises(InvalidRecord):
            PlannedTransition.of("op-1", KEY, {"present": True}, {"present": False}, "a bad id")

    def test_the_operation_id_is_the_idempotency_key_of_one_approved_change(self):
        base = dict(candidate_id="cand_" + "a" * 32, operation="OKTA_GROUP_UNASSIGN",
                    target_identity_digest="sha256:" + "b" * 64, approval_id="apr_" + "c" * 32,
                    evidence_fingerprint="sha256:" + "d" * 64)
        self.assertEqual(operation_id(**base), operation_id(**base))
        self.assertTrue(operation_id(**base).startswith(OPERATION_ID_PREFIX))
        for name in base:
            with self.subTest(changed=name):
                changed = {**base, name: base[name][:-1] + "e"}
                self.assertNotEqual(operation_id(**changed), operation_id(**base))

    def test_scope_differences_name_every_unexpected_change(self):
        before = objects()
        self.assertEqual(scope_differences(before, before), ())
        after = {**before, OTHER: {**before[OTHER], "present": False}}
        self.assertEqual(scope_differences(before, after), (f"{OTHER}.present: expected true, observed false",))
        self.assertEqual(scope_differences({KEY: {}}, {}), (f"{KEY}: missing",))


class TraceTests(unittest.TestCase):
    def step(self, seq, state, *, at=0, **kw):
        if state is X.POST_ACTION_VERIFIED:
            # The post-action predicate verify_trace requires, so each case below
            # breaks only the invariant it names.
            kw = {"reason": Reason.MATCHES_EXPECTED_STATE, "observation": O.APPLIED, "reads": (True,), **kw}
        kw.setdefault("reason", Reason.SUBMITTED)
        return ExecutionStep(seq, state, T0 + timedelta(seconds=at), detail="test", **kw)

    def test_a_valid_trace_is_accepted(self):
        trace = ExecutionTrace((
            self.step(1, X.EXECUTION_REQUESTED, attempt=1), self.step(2, X.OUTCOME_UNKNOWN, at=30),
            self.step(3, X.VERIFYING, at=31, observation=O.NOT_APPLIED), self.step(4, X.RETRY_PERMITTED, at=31),
            self.step(5, X.EXECUTION_REQUESTED, at=33, attempt=2), self.step(6, X.EXECUTED, at=35),
            self.step(7, X.POST_ACTION_VERIFIED, at=36)))
        self.assertTrue(trace.succeeded)
        self.assertEqual(trace.submissions, 2)

    def test_traces_that_break_an_invariant_cannot_be_built(self):
        s = self.step
        bad = {
            "retry after an unreadable verification": (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.OUTCOME_UNKNOWN),
                                                       s(3, X.VERIFYING, observation=O.UNREADABLE),
                                                       s(4, X.RETRY_PERMITTED), s(5, X.EXECUTION_REQUESTED, attempt=2),
                                                       s(6, X.EXECUTED), s(7, X.POST_ACTION_VERIFIED)),
            "executed after a read that showed nothing applied": (
                s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.OUTCOME_UNKNOWN), s(3, X.VERIFYING, observation=O.NOT_APPLIED),
                s(4, X.EXECUTED), s(5, X.POST_ACTION_VERIFIED)),
            "a resubmission straight after a timeout": (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.OUTCOME_UNKNOWN),
                                                        s(3, X.EXECUTION_REQUESTED, attempt=2)),
            "success without an execution": (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.POST_ACTION_VERIFIED)),
            "a run that stops while executed": (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.EXECUTED)),
            "a run that stops with the outcome unknown": (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.OUTCOME_UNKNOWN)),
            "a third submission": (s(1, X.EXECUTION_REQUESTED, attempt=1), s(2, X.OUTCOME_UNKNOWN),
                                   s(3, X.VERIFYING, observation=O.NOT_APPLIED), s(4, X.RETRY_PERMITTED),
                                   s(5, X.EXECUTION_REQUESTED, attempt=2), s(6, X.OUTCOME_UNKNOWN),
                                   s(7, X.VERIFYING, observation=O.NOT_APPLIED), s(8, X.RETRY_PERMITTED),
                                   s(9, X.EXECUTION_REQUESTED, attempt=3)),
            "time going back": (s(1, X.EXECUTION_REQUESTED, attempt=1, at=10), s(2, X.EXECUTED, at=5),
                                s(3, X.POST_ACTION_VERIFIED, at=6)),
            "a dry run that goes on to execute": (s(1, X.DRY_RUN), s(2, X.EXECUTION_REQUESTED, attempt=1)),
            "an empty run": (),
        }
        for label, steps in bad.items():
            with self.subTest(label), self.assertRaises(InvalidRecord):
                ExecutionTrace(steps)


# --- the provider fixture ---------------------------------------------------------------------


class ProviderFixtureTests(unittest.TestCase):
    def test_only_a_synthetic_or_plan_only_policy_is_accepted(self):
        with self.assertRaises(MutationBlockedError):
            fixture(mode=ExecutionMode.READ_ONLY_PRODUCTION)
        for mode in (ExecutionMode.LOCAL_SYNTHETIC, ExecutionMode.DRY_RUN_MUTATION):
            with self.subTest(mode=mode):
                self.assertIs(fixture(mode=mode).mutation_policy.mode, mode)

    def test_it_holds_nothing_outside_the_process(self):
        provider = fixture()
        self.assertEqual({k for k in vars(provider) if not k.startswith("_mutation")},
                         {"_objects", "_script", "_now", "_reads", "_submissions", "_applied_operations", "_ledger"})
        for name in ("store", "client", "get", "post", "launch", "send", "request", "connection"):
            self.assertFalse(hasattr(provider, name), name)

    def test_an_applied_operation_id_is_never_applied_twice(self):
        provider = fixture()
        self.assertEqual(provider.submit(CHANGE).code, "APPLIED")
        after = provider.digest()
        restored = PlannedTransition.of(OP, KEY, {"present": False}, {"present": True}, "same id, other change")
        result = provider.submit(restored)
        self.assertEqual((result.answer.value, result.code), ("REFUSED", "DUPLICATE_OPERATION"))
        self.assertEqual(provider.digest(), after)
        self.assertEqual(provider.mutations_applied, 1)

    def test_a_submission_on_a_failed_precondition_changes_nothing(self):
        provider = fixture(objs=objects(present=False))
        before = provider.digest()
        result = provider.submit(CHANGE)
        self.assertEqual((result.answer.value, result.code), ("REFUSED", "PRECONDITION_FAILED"))
        self.assertEqual((provider.digest(), provider.mutations_applied), (before, 0))

    def test_a_plan_only_policy_applies_nothing_even_when_asked(self):
        provider = fixture(mode=ExecutionMode.DRY_RUN_MUTATION)
        before = provider.digest()
        result = provider.submit(CHANGE)
        self.assertEqual((result.answer.value, result.code), ("REFUSED", "PLAN_ONLY_POLICY"))
        self.assertEqual((provider.digest(), provider.mutations_applied), (before, 0))

    def test_each_fault_does_what_it_says(self):
        expected = {FaultKind.APPLY: ("APPLIED", True), FaultKind.TIMEOUT_BEFORE_APPLY: ("TIMEOUT", False),
                    FaultKind.TIMEOUT_AFTER_APPLY: ("TIMEOUT", True), FaultKind.ACK_WITHOUT_APPLY: ("APPLIED", False)}
        for fault, (answer, applied) in expected.items():
            with self.subTest(fault=fault):
                provider = fixture(script(fault))
                self.assertEqual(provider.submit(CHANGE).answer.value, answer)
                self.assertEqual(provider.snapshot()[KEY]["present"], not applied)
                self.assertEqual(provider.mutations_applied, int(applied))

    def test_a_scripted_read_failure_fails_and_others_succeed(self):
        provider = fixture(script(unreadable={2}))
        self.assertIsNotNone(provider.read(KEY))
        self.assertIsNone(provider.read(KEY))
        self.assertIsNotNone(provider.read_scope())

    def test_a_deleted_object_keeps_only_its_identity(self):
        delete = PlannedTransition.of(OP, AD_KEY, {"exists": True}, {"exists": False}, "Delete one synthetic group.")
        self.assertEqual(applied_state(objects()[AD_KEY], delete), {
            "exists": False, "objectGuid": "00000000-0000-4000-8000-000000000001", "domain": "corp.synthetic.example"})

    def test_the_same_script_gives_the_same_run(self):
        a, b = (run_of(fixture("TIMEOUT_NOT_APPLIED")).drive() for _ in range(2))
        self.assertEqual([s.to_dict() for s in a.steps], [s.to_dict() for s in b.steps])

    def test_nothing_in_the_execution_path_is_random_or_reads_the_wall_clock(self):
        for path in ("app/remediation/synthetic_provider.py", "app/remediation/drill.py",
                     "app/domain/remediation_execution.py"):
            tree = ast.parse((REPO_ROOT / path).read_text(encoding="utf-8"))
            imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            # The only clock is the fixture's synthetic one (provider.now()); nothing reads the
            # wall clock or waits.
            wall_clock = [f"{n.func.value.id}.{n.func.attr}" for n in ast.walk(tree)
                          if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                          and isinstance(n.func.value, ast.Name) and n.func.value.id in ("datetime", "date", "time")]
            with self.subTest(path=path):
                self.assertFalse(imported & {"random", "secrets", "time", "uuid", "app.store.store", "app.api"})
                self.assertEqual(wall_clock, [])

    def test_every_catalog_scenario_is_deterministic_and_documented(self):
        for key, s in SCENARIOS.items():
            with self.subTest(scenario=key):
                self.assertEqual(s.key, key)
                self.assertIsNotNone(s.expected_final)
                self.assertTrue(s.title and s.description)
                self.assertFalse(s.outside_change, "no catalog scenario changes things outside the run")


class MutationCapableInventoryTests(unittest.TestCase):
    def test_only_the_fixture_may_hold_a_policy_that_can_execute(self):
        # Every mutation-capable component receives its policy by injection. The planner and the
        # remediation adapters build their own DRY_RUN_MUTATION policy, and this build has no
        # mutating HTTP client. So the synthetic provider fixture is the one component the
        # application builds with a policy that can execute, and only against synthetic targets.
        import app.api.services  # noqa: F401  (registers DryRunPlanner)
        import app.remediation.adapters  # noqa: F401
        from app.api.services import DryRunPlanner
        from app.remediation.adapters import AapRemediationAdapter, SyntheticRemediationAdapter

        def subclasses(cls):
            for sub in cls.__subclasses__():
                yield sub
                yield from subclasses(sub)

        found = {c.__qualname__ for c in subclasses(MutationCapableService) if c.__module__.startswith("app.")}
        self.assertEqual(found, {"DryRunPlanner", "RemediationAdapter", "SyntheticRemediationAdapter",
                                 "AapRemediationAdapter", "SyntheticProviderFixture"})
        for component in (DryRunPlanner(), SyntheticRemediationAdapter(), AapRemediationAdapter()):
            with self.subTest(component=type(component).__name__):
                self.assertIs(component.mutation_policy.mode, ExecutionMode.DRY_RUN_MUTATION)
        # That no application module imports an outbound client is test_mutation_safety's AST check.


# --- a run, step by step -------------------------------------------------------------------------


class ExecutionRunTests(unittest.TestCase):
    def test_the_catalog_scenarios_end_where_they_say(self):
        for key, s in SCENARIOS.items():
            provider = fixture(key)
            trace = run_of(provider).drive()
            with self.subTest(scenario=key):
                self.assertIs(trace.final_state, s.expected_final)
                self.assertEqual(trace.succeeded, s.expected_final is X.POST_ACTION_VERIFIED)
                self.assertLessEqual(provider.mutations_applied, 1, "never more than the one planned change")

    def test_a_timeout_never_leads_straight_to_a_resubmission(self):
        provider = fixture("TIMEOUT_NOT_APPLIED")
        run = run_of(provider)
        run.request()
        run.receive()
        self.assertIs(run.state, X.OUTCOME_UNKNOWN)
        ledger = provider.ledger
        for call in (run.request, run.receive, run.decide, run.post_verify):
            with self.subTest(call=call.__name__), self.assertRaises(ExecutionStepRefused):
                call()
        self.assertEqual(provider.ledger, ledger, "a refused step never reaches the provider")
        run.verify()
        self.assertIs(run.steps[-1].observation, O.NOT_APPLIED)
        self.assertIs(run.decide().state, X.RETRY_PERMITTED)

    def test_verification_tells_applied_from_not_applied(self):
        for key, observation, after in (("TIMEOUT_NOT_APPLIED", O.NOT_APPLIED, X.RETRY_PERMITTED),
                                        ("TIMEOUT_AFTER_APPLY", O.APPLIED, X.EXECUTED)):
            with self.subTest(scenario=key):
                trace = run_of(fixture(key)).drive()
                verifying = next(s for s in trace.steps if s.state is X.VERIFYING)
                self.assertIs(verifying.observation, observation)
                self.assertIs(trace.steps[trace.steps.index(verifying) + 1].state, after)

    def test_an_applied_change_whose_answer_was_lost_is_not_resubmitted(self):
        provider = fixture("TIMEOUT_AFTER_APPLY")
        trace = run_of(provider).drive()
        self.assertEqual(states(trace), ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "EXECUTED",
                                         "POST_ACTION_VERIFIED"])
        self.assertEqual(trace.submissions, 1)
        self.assertEqual([e.applied for e in provider.ledger], [True])

    def test_a_retry_carries_the_same_operation_id_and_applies_once(self):
        provider = fixture("TIMEOUT_NOT_APPLIED")
        trace = run_of(provider).drive()
        self.assertEqual(trace.submissions, 2)
        self.assertEqual([(e.actor, e.applied) for e in provider.ledger], [(OP, False), (OP, True)])

    def test_the_gates_are_evaluated_again_before_a_retry(self):
        provider = fixture("TIMEOUT_NOT_APPLIED")
        asked = []

        def recheck(at):
            asked.append(at)
            return ("FRESH_EVIDENCE: the evidence is now older than 24 hours",)

        trace = ExecutionRun(provider, CHANGE, recheck=recheck).drive()
        self.assertEqual(states(trace)[-2:], ["RETRY_PERMITTED", "BLOCKED"])
        self.assertIs(trace.steps[-1].reason, Reason.GATES_BLOCKED_ON_RETRY)
        self.assertEqual(len(asked), 1)
        self.assertGreater(asked[0], T0, "re-checked at the retry's time, not the first attempt's")
        self.assertEqual((trace.submissions, provider.mutations_applied), (1, 0))

    def test_an_unreadable_outcome_is_never_retried_or_called_a_success(self):
        provider = fixture("TIMEOUT_UNVERIFIABLE")
        trace = run_of(provider).drive()
        self.assertEqual(states(trace), ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "RETRY_NOT_PERMITTED"])
        self.assertEqual(trace.steps[2].reads, (False, False))
        self.assertIs(trace.steps[-1].reason, Reason.OUTCOME_STILL_UNKNOWN)
        self.assertFalse(trace.succeeded)
        self.assertEqual(trace.submissions, 1)

    def test_the_attempt_limit_holds(self):
        trace = run_of(fixture("REPEATED_TIMEOUT")).drive()
        self.assertEqual(trace.submissions, MAX_SUBMISSIONS)
        self.assertIs(trace.steps[-1].reason, Reason.ATTEMPT_LIMIT_REACHED)

    def test_an_acknowledgement_without_the_change_fails_verification(self):
        trace = run_of(fixture("ACKNOWLEDGED_NOT_APPLIED")).drive()
        self.assertEqual(states(trace), ["EXECUTION_REQUESTED", "EXECUTED", "VERIFICATION_FAILED"])
        self.assertIs(trace.steps[-1].reason, Reason.TARGET_NOT_IN_EXPECTED_STATE)
        self.assertFalse(trace.succeeded)
        self.assertNotEqual(trace.steps[-1].label, "POST-ACTION VERIFIED")

    def test_a_post_action_read_that_fails_is_never_a_success(self):
        trace = run_of(fixture(script(FaultKind.APPLY, unreadable={2, 3}))).drive()
        self.assertEqual(states(trace), ["EXECUTION_REQUESTED", "EXECUTED", "VERIFICATION_FAILED"])
        self.assertIs(trace.steps[-1].reason, Reason.POST_ACTION_UNREADABLE)

    def test_an_unexpected_change_elsewhere_in_scope_fails_verification(self):
        provider = fixture()
        run = run_of(provider)
        run.request()
        run.receive()
        provider._change(OTHER, lambda: {**provider.snapshot()[OTHER], "present": False}, action="collateral")
        step = run.post_verify()
        self.assertEqual((step.state, step.reason), (X.VERIFICATION_FAILED, Reason.UNEXPECTED_CHANGE_IN_SCOPE))
        self.assertIn(f"{OTHER}.present: expected true, observed false", step.differences)

    def test_a_change_made_outside_the_run_is_observed_not_duplicated(self):
        # A person removed the assignment by hand while the run's submission timed out.
        provider = fixture(script(FaultKind.TIMEOUT_BEFORE_APPLY, outside=(("present", False),)))
        trace = run_of(provider).drive()
        self.assertEqual(states(trace), ["EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "EXECUTED",
                                         "POST_ACTION_VERIFIED"])
        self.assertEqual([(e.actor, e.applied) for e in provider.ledger], [(OP, False), ("outside-this-run", True)])

    def test_a_target_changed_elsewhere_outside_the_run_is_not_retried(self):
        provider = fixture(script(FaultKind.TIMEOUT_BEFORE_APPLY,
                                  outside=(("distinguishedName", "CN=SYNTH-X,OU=Elsewhere,DC=corp"),)))
        trace = run_of(provider, QUARANTINE).drive()
        self.assertEqual(states(trace)[-1], "RETRY_NOT_PERMITTED")
        self.assertIs(trace.steps[-1].reason, Reason.TARGET_CHANGED_OUTSIDE_RUN)
        self.assertEqual(trace.submissions, 1)

    def test_a_target_not_in_its_before_state_is_never_submitted(self):
        provider = fixture(objs=objects(present=False))
        trace = run_of(provider).drive()
        self.assertEqual((states(trace), trace.steps[0].reason), (["BLOCKED"], Reason.PRECONDITION_NOT_MET))
        self.assertEqual(provider.ledger, ())

    def test_a_finished_run_takes_no_further_step(self):
        provider = fixture()
        run = run_of(provider)
        run.drive()
        for call in (run.request, run.receive, run.verify, run.decide, run.post_verify):
            with self.subTest(call=call.__name__), self.assertRaises(ExecutionStepRefused):
                call()
        self.assertEqual(provider.mutations_applied, 1)


if __name__ == "__main__":
    unittest.main()
