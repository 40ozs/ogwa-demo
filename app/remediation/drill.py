"""The synthetic execution drill: remediation as a controlled state transition (OGWA-DEMO-03).

A drill takes one remediation request (one operation, one target, the approval, the
evidence the operator saw) through the real governed path first, ``remediation_dry_run``:
every gate, the server-side allowlist, and the synthetic adapter. A request that path
blocks never reaches a provider (D133). One it accepts is then run against a fresh
``SyntheticProviderFixture`` built from the candidate's recorded synthetic evidence:

- ``DRY_RUN``: the plan is computed against the fixture's current state. Nothing is
  submitted. The fixture holds a DRY_RUN_MUTATION policy, so it could not apply a change
  even if asked, and its state digest is the same before and after;
- ``SYNTHETIC_EXECUTION``: an ``ExecutionRun`` submits the change and follows the closed
  state machine of ``app.domain.remediation_execution`` under a named, deterministic fault
  scenario: an unknown outcome is verified, a retry happens only when a read proves the
  change was not applied (and the gates pass again), and success needs a post-action read.

What a drill never does: write to the store (not even an audit event), move the lifecycle,
create an ``ExecutionJob``, produce a ``RemediationOutcome`` other than the governed dry
run's own, or contact anything. The fixture is discarded when the drill returns. Drills run
only in ``LOCAL_SYNTHETIC`` over a SYNTHETIC store, with SYNTHETIC evidence and the SYNTHETIC
adapter; anything else is refused before a fixture exists.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.core.errors import MutationBlockedError
from app.core.modes import ExecutionMode
from app.core.safety import MutationPolicy
from app.domain.actors import Actor
from app.domain.approval import ApprovalRecord
from app.domain.lifecycle import LifecycleCandidate
from app.domain.policy import EvidenceBundle, LifecyclePolicy, evidence_fingerprint
from app.domain.quarantine import QuarantineOus
from app.domain.remediation import (
    PlannedChange,
    RemediationOperation,
    RemediationOutcome,
    RemediationResult,
    RemediationTarget,
)
from app.domain.remediation_execution import (
    MAX_SUBMISSIONS,
    MAX_VERIFICATION_READS,
    OBSERVATION_PHRASES,
    TERMINAL_STATES,
    ExecutionState,
    ExecutionStep,
    ExecutionStepRefused,
    ExecutionTrace,
    PlannedTransition,
    Reason,
    SubmissionAnswer,
    TargetObservation,
    check_transition,
    operation_id,
    retry_decision,
    scope_differences,
)
from app.remediation.allowlist import RemediationAllowlist
from app.remediation.engine import remediation_dry_run
from app.remediation.synthetic_provider import (
    NO_FAULT_KEY,
    SCENARIOS,
    FaultScript,
    SubmissionResult,
    SyntheticProviderFixture,
    ad_group_key,
    assignment_key,
    expected_scope,
)
from app.store.environment import DatabaseEnvironment

X = ExecutionState
O = RemediationOperation
DRILL_NOTICE = ("Synthetic drill: run against an in-memory provider fixture built from this candidate's recorded "
                "synthetic evidence, then discarded. Nothing was recorded; the demo store, the lifecycle, Okta, Active "
                "Directory, and AAP are unchanged.")
LEDGER_NOTE = ("The fixture's own record of what happened inside it. OGWA's steps above come only from its reads and "
               "the provider's answers; this record is shown so a reviewer can check them against the truth.")


class DrillMode(StrEnum):
    DRY_RUN = "DRY_RUN"
    SYNTHETIC_EXECUTION = "SYNTHETIC_EXECUTION"


class DrillUnavailable(Exception):
    """A drill cannot run here: wrong execution mode, store, evidence, adapter, or scenario."""


class DrillUnauthorized(Exception):
    """The governed gates passed, but the authorization they rest on does not (OGWA-DEMO-04):
    the approval, or the decision that applied it, was not judged by the policy version in
    force. Raised before any provider fixture exists, so nothing was built or submitted."""

    def __init__(self, problems: tuple[str, ...]) -> None:
        super().__init__("; ".join(problems))
        self.problems = tuple(problems)


# What a reviewer must never be able to miss about a drill's mode (OGWA-DEMO-04). The server
# words it, every response carries it, and the UI shows it above everything else in the result.
MODE_BANNERS = {
    "DRY_RUN": {
        "headline": "DRY RUN — NO STATE CHANGED",
        "detail": "Planned against a synthetic provider fixture and not submitted. Nothing changed, not even "
                  "inside the fixture; no external provider or persistent environment was contacted or modified.",
    },
    "SYNTHETIC_EXECUTION": {
        "headline": "SYNTHETIC EXECUTION",
        "detail": "No external provider or persistent environment was modified. The change was submitted only to "
                  "an in-memory synthetic provider fixture, under a scripted, deterministic fault scenario; the "
                  "fixture was discarded when this answer was built, and nothing was recorded.",
    },
}


def planned_transition(operation: RemediationOperation, target: RemediationTarget, change: PlannedChange,
                       op_id: str) -> PlannedTransition:
    """The one fixture change that the governed dry run's planned change describes."""
    if operation is O.OKTA_GROUP_UNASSIGN:
        return PlannedTransition.of(op_id, assignment_key(target.target_id), {"present": True}, {"present": False},
                                    change.summary)
    key = ad_group_key(target.value("object_guid") or "")
    if operation is O.AD_GROUP_QUARANTINE:
        details = dict(change.details)
        return PlannedTransition.of(op_id, key, {"exists": True, "distinguishedName": details["before.distinguishedName"]},
                                    {"exists": True, "distinguishedName": details["after.distinguishedName"]},
                                    change.summary)
    return PlannedTransition.of(op_id, key, {"exists": True}, {"exists": False}, change.summary)


# --- one run, step by step -------------------------------------------------------------------


class ExecutionRun:
    """One synthetic execution. Each method takes exactly one step, and checks the transition
    table before it touches the provider, so an out-of-order call (a resubmission from
    OUTCOME_UNKNOWN, a success without a post-action read) is refused and changes nothing.

    ``recheck(at)`` re-evaluates the governed gates at ``at`` and returns their problems; a
    retry is submitted only if it returns none."""

    def __init__(self, provider: SyntheticProviderFixture, change: PlannedTransition, *,
                 recheck: Callable[[datetime], tuple[str, ...]]) -> None:
        self._provider = provider
        self._change = change
        self._recheck = recheck
        self._steps: list[ExecutionStep] = []
        self._pending: SubmissionResult | None = None
        self._baseline: dict[str, dict[str, Any]] | None = None

    @property
    def state(self) -> ExecutionState | None:
        return self._steps[-1].state if self._steps else None

    @property
    def submissions(self) -> int:
        return sum(1 for s in self._steps if s.state is X.EXECUTION_REQUESTED)

    @property
    def steps(self) -> tuple[ExecutionStep, ...]:
        return tuple(self._steps)

    def _enter(self, state: ExecutionState, reason: Reason, detail: str, *, at: datetime | None = None,
               **fields: Any) -> ExecutionStep:
        check_transition(self.state, state)
        step = ExecutionStep(len(self._steps) + 1, state, at or self._provider.now(), reason, detail, **fields)
        self._steps.append(step)
        return step

    def _require(self, state: ExecutionState) -> None:
        if self.state is not state:
            here = self.state.value if self.state is not None else "the start of a run"
            raise ExecutionStepRefused(f"this step needs {state.value}; the run is at {here}")

    # --- the steps ---------------------------------------------------------------------

    def request(self) -> ExecutionStep:
        """Submit the change: at the start, or as the retry RETRY_PERMITTED allowed. The gates
        (on a retry) and the precondition are checked first; either can block it."""
        check_transition(self.state, X.EXECUTION_REQUESTED)
        retry = self.state is X.RETRY_PERMITTED
        if retry:
            problems = self._recheck(self._provider.now())
            if problems:
                return self._enter(X.BLOCKED, Reason.GATES_BLOCKED_ON_RETRY,
                                   "The gates were evaluated again before the retry and no longer pass; the retry was "
                                   "not submitted.", problems=tuple(problems))
        scope = self._provider.read_scope()
        if scope is None:
            return self._enter(X.BLOCKED, Reason.PRECONDITION_UNREADABLE,
                               "The target could not be read, so its precondition could not be confirmed; nothing was "
                               "submitted.", reads=(False,))
        if self._baseline is None:
            self._baseline = scope
        observed = scope.get(self._change.target_key, {})
        observation = self._change.classify(observed)
        if observation is not TargetObservation.NOT_APPLIED:
            return self._enter(X.BLOCKED, Reason.PRECONDITION_NOT_MET,
                               f"The target is {OBSERVATION_PHRASES[observation]}, not in the planned before-state; "
                               "nothing was submitted.", observation=observation, observed=observed,
                               reads=(True,))
        at = self._provider.now()
        attempt = self.submissions + 1
        self._pending = self._provider.submit(self._change)
        return self._enter(X.EXECUTION_REQUESTED, Reason.SUBMITTED,
                           f"{'Retry' if retry else 'Attempt'} {attempt} of at most {MAX_SUBMISSIONS} submitted to the "
                           f"synthetic provider with operation id {self._change.operation_id}, on the precondition "
                           f"that the target is still {self._change.describe('before')}.",
                           at=at, attempt=attempt, observation=observation, observed=observed, reads=(True,))

    def receive(self) -> ExecutionStep:
        """Take the provider's answer to the last submission."""
        self._require(X.EXECUTION_REQUESTED)
        result, self._pending = self._pending, None
        if result is None:  # pragma: no cover - request() always leaves an answer
            raise ExecutionStepRefused("no submission is waiting for an answer")
        attempt = self.submissions
        if result.answer is SubmissionAnswer.APPLIED:
            return self._enter(X.EXECUTED, Reason.ACKNOWLEDGED,
                               "The synthetic provider says the change was applied. That is not yet a success: a "
                               "post-action read must confirm it.", attempt=attempt, answer=result.answer,
                               answer_detail=result.detail)
        if result.answer is SubmissionAnswer.TIMEOUT:
            return self._enter(X.OUTCOME_UNKNOWN, Reason.TIMED_OUT,
                               f"The provider did not answer: {result.detail}. The change may or may not have been "
                               "applied: nothing is assumed, and nothing is resubmitted until a read says which.",
                               attempt=attempt, answer=result.answer, answer_detail=result.detail)
        return self._enter(X.RETRY_NOT_PERMITTED, Reason.PROVIDER_REFUSED,
                           f"The provider refused ({result.code}: {result.detail}). A refusal is not retried.",
                           attempt=attempt, answer=result.answer, answer_detail=result.detail)

    def verify(self) -> ExecutionStep:
        """After an unknown outcome: read the target to find out what happened."""
        check_transition(self.state, X.VERIFYING)
        reads, observed = [], None
        for _ in range(MAX_VERIFICATION_READS):
            value = self._provider.read(self._change.target_key)
            reads.append(value is not None)
            if value is not None:
                observed = value
                break
        observation = self._change.classify(observed)
        details = {
            TargetObservation.NOT_APPLIED: "The target is still in the planned before-state: the change was not applied.",
            TargetObservation.APPLIED: "The target is in the planned after-state: the change was applied.",
            TargetObservation.DIVERGED: "The target is in neither planned state: something else changed it.",
            TargetObservation.UNREADABLE: f"All {len(reads)} reads failed: the outcome is still unknown.",
        }
        return self._enter(X.VERIFYING, Reason.READ_TARGET, details[observation], observation=observation,
                           observed=observed, reads=tuple(reads))

    def decide(self) -> ExecutionStep:
        """After a verification: executed, retry permitted, or retry not permitted."""
        self._require(X.VERIFYING)
        observation = self._steps[-1].observation
        if observation is None:  # pragma: no cover - verify() always records what it read
            raise ExecutionStepRefused("a verification step records what it read")
        state, reason, detail = retry_decision(observation, submissions=self.submissions)
        return self._enter(state, reason, detail)

    def post_verify(self) -> ExecutionStep:
        """After EXECUTED: read the whole scope; only the planned change may have happened."""
        self._require(X.EXECUTED)
        reads, scope = [], None
        for _ in range(MAX_VERIFICATION_READS):
            value = self._provider.read_scope()
            reads.append(value is not None)
            if value is not None:
                scope = value
                break
        if scope is None or self._baseline is None:
            return self._enter(X.VERIFICATION_FAILED, Reason.POST_ACTION_UNREADABLE,
                               "The post-action state could not be read, so the change is not confirmed. Success is "
                               "never assumed.", reads=tuple(reads))
        observed = scope.get(self._change.target_key, {})
        observation = self._change.classify(observed)
        differences = scope_differences(expected_scope(self._baseline, self._change), scope)
        if observation is not TargetObservation.APPLIED:
            return self._enter(X.VERIFICATION_FAILED, Reason.TARGET_NOT_IN_EXPECTED_STATE,
                               f"The target is {OBSERVATION_PHRASES[observation]}, not in the planned after-state "
                               f"({self._change.describe('after')}). This run did not succeed.",
                               observation=observation, observed=observed, reads=tuple(reads), differences=differences)
        if differences:
            return self._enter(X.VERIFICATION_FAILED, Reason.UNEXPECTED_CHANGE_IN_SCOPE,
                               "The target changed as planned, but something else in scope changed too. This run did "
                               "not succeed.", observation=observation, observed=observed, reads=tuple(reads),
                               differences=differences)
        return self._enter(X.POST_ACTION_VERIFIED, Reason.MATCHES_EXPECTED_STATE,
                           f"The target is in the planned after-state ({self._change.describe('after')}), and nothing else "
                           "in scope changed.", observation=observation, observed=observed, reads=tuple(reads))

    def drive(self) -> ExecutionTrace:
        """The safe policy, to the end: submit; on an unknown outcome verify, then decide; retry
        only if permitted; post-verify anything executed."""
        if self.state is None:
            self.request()
        steps = {X.EXECUTION_REQUESTED: self.receive, X.OUTCOME_UNKNOWN: self.verify, X.VERIFYING: self.decide,
                 X.RETRY_PERMITTED: self.request, X.EXECUTED: self.post_verify}
        while (state := self.state) is not None and state not in TERMINAL_STATES:
            steps[state]()
        return self.trace()

    def trace(self) -> ExecutionTrace:
        return ExecutionTrace(tuple(self._steps))


# --- the drill ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class DrillReport:
    mode: DrillMode
    scenario: FaultScript | None
    candidate_id: str
    result: RemediationResult  # the governed dry run the drill started from
    change: PlannedTransition | None
    trace: ExecutionTrace | None  # None only when the governed path BLOCKED the request
    state_before: Mapping[str, Mapping[str, Any]] | None = None
    state_after: Mapping[str, Mapping[str, Any]] | None = None
    digest_before: str | None = None
    digest_after: str | None = None
    ledger: tuple = ()

    @property
    def blocked(self) -> bool:
        return self.result.outcome is RemediationOutcome.BLOCKED

    @property
    def final_state(self) -> ExecutionState:
        return self.trace.final_state if self.trace is not None else X.BLOCKED

    @property
    def succeeded(self) -> bool:
        return self.trace is not None and self.trace.succeeded

    @property
    def mutations_applied(self) -> int:
        return sum(1 for e in self.ledger if e.applied)

    def to_dict(self) -> dict[str, Any]:
        trace = self.trace
        return {
            "mode": self.mode.value, "scenario": self.scenario.to_dict() if self.scenario else None,
            "candidateId": self.candidate_id, "operation": self.result.operation.value,
            "target": self.result.target.to_dict() if self.result.target else None,
            "operationId": self.change.operation_id if self.change else None,
            "plannedTransition": self.change.to_dict() if self.change else None,
            "plannedChanges": [c.to_dict() for c in self.result.planned_changes],
            "gates": self.result.gates.to_dict(), "governedOutcome": self.result.outcome.value,
            "steps": [s.to_dict() for s in trace.steps] if trace else [],
            "finalState": self.final_state.value, "finalLabel": trace.steps[-1].label if trace else None,
            "succeeded": self.succeeded, "submissions": trace.submissions if trace else 0,
            "maxSubmissions": MAX_SUBMISSIONS,
            "provider": {
                "name": SyntheticProviderFixture.name, "synthetic": True,
                "stateBefore": self.state_before, "stateAfter": self.state_after,
                "digestBefore": self.digest_before, "digestAfter": self.digest_after,
                "stateChanged": self.digest_before != self.digest_after,
                "mutationsApplied": self.mutations_applied, "ledger": [e.to_dict() for e in self.ledger],
                "ledgerNote": LEDGER_NOTE,
            },
            "syntheticOnly": True, "productionMutation": False, "externalSystemsContacted": False,
            "recorded": False, "lifecycleChanged": False, "notice": DRILL_NOTICE,
            "modeBanner": MODE_BANNERS[self.mode.value],
            "attempts": list(trace.attempts()) if trace else [],
            "postActionVerification": trace.post_action_verification() if trace else
            {"result": "NOT_REACHED", "reason": None, "observation": None, "differences": []},
        }


def scenario(key: str | None) -> FaultScript:
    if key is None:
        return SCENARIOS[NO_FAULT_KEY]
    found = SCENARIOS.get(key)
    if found is None:
        raise DrillUnavailable(f"unknown drill scenario {key[:40]!r}; one of: {', '.join(SCENARIOS)}")
    return found


def run_drill(
    *,
    mode: DrillMode,
    scenario_key: str | None,
    candidate: LifecycleCandidate,
    operation: RemediationOperation,
    target_ref: object,
    evidence: EvidenceBundle,
    approval: ApprovalRecord | None,
    policy: LifecyclePolicy,
    now: datetime,
    execution_mode: object,
    requested_by: Actor,
    allowlist: RemediationAllowlist | None,
    environment: DatabaseEnvironment,
    correlation_id: str,
    quarantine_ous: QuarantineOus | None = None,
    authorize: Callable[[], tuple[str, ...]] | None = None,
) -> DrillReport:
    """One drill. A request the governed path blocks comes back with no trace and nothing
    built; every other one comes back with its whole trace.

    ``authorize`` (OGWA-DEMO-04) returns why the request's authorization (the approval and the
    decision that applied it, against the policy in force) does not hold; none if it does. It is
    asked after the gates pass and before any fixture exists (``DrillUnauthorized``), and again
    with the gates before a retry is submitted."""
    if not isinstance(mode, DrillMode):
        raise DrillUnavailable("the drill mode is DRY_RUN or SYNTHETIC_EXECUTION")
    if execution_mode is not ExecutionMode.LOCAL_SYNTHETIC:
        raise DrillUnavailable("a synthetic drill runs only in LOCAL_SYNTHETIC")
    if environment is not DatabaseEnvironment.SYNTHETIC:
        raise DrillUnavailable("a synthetic drill runs only over a SYNTHETIC store")
    if mode is DrillMode.DRY_RUN and scenario_key is not None:
        raise DrillUnavailable("a dry run submits nothing, so it takes no fault scenario")
    if mode is DrillMode.SYNTHETIC_EXECUTION and scenario_key is None:
        raise DrillUnavailable("a synthetic execution names its fault scenario")
    script = scenario(scenario_key)

    def governed(at: datetime) -> RemediationResult:
        return remediation_dry_run(
            candidate=candidate, operation=operation, target_ref=target_ref, evidence=evidence, approval=approval,
            policy=policy, now=at, mode=execution_mode, requested_by=requested_by, requested_mode=None,
            allowlist=allowlist, environment=environment, correlation_id=correlation_id, quarantine_ous=quarantine_ous)

    result = governed(now)
    if result.outcome is RemediationOutcome.BLOCKED:
        return DrillReport(mode, script if scenario_key else None, candidate.id, result, None, None)
    unauthorized = authorize() if authorize is not None else ()
    if unauthorized:
        raise DrillUnauthorized(tuple(unauthorized))
    if result.outcome is not RemediationOutcome.SIMULATED or result.adapter != "SYNTHETIC":
        raise DrillUnavailable(f"a synthetic drill needs the SYNTHETIC adapter's SIMULATED plan, not {result.adapter} "
                               f"{result.outcome.value}")
    # A SIMULATED result names its target (RemediationResult refuses one that does not), and
    # VALID_APPROVAL passed, so there is an approval.
    target = result.target
    if target is None or approval is None:  # pragma: no cover - see above
        raise DrillUnavailable("a simulated plan names its target and rests on an approval")
    op_id = operation_id(candidate_id=candidate.id, operation=operation.value,
                         target_identity_digest=target.identity_digest, approval_id=approval.id,
                         evidence_fingerprint=evidence_fingerprint(evidence))
    change = planned_transition(operation, target, result.planned_changes[0], op_id)
    fixture_mode = ExecutionMode.DRY_RUN_MUTATION if mode is DrillMode.DRY_RUN else ExecutionMode.LOCAL_SYNTHETIC
    provider = SyntheticProviderFixture.from_evidence(evidence, script=script, start=now,
                                                      mutation_policy=MutationPolicy.for_mode(fixture_mode))
    before, digest_before = provider.snapshot(), provider.digest()
    if mode is DrillMode.DRY_RUN:
        trace = _dry_run(provider, change)
        if provider.digest() != digest_before or provider.ledger:
            raise MutationBlockedError("a dry-run drill changed the synthetic provider")  # pragma: no cover
    else:
        def recheck(at: datetime) -> tuple[str, ...]:
            again = governed(at)
            if again.outcome is RemediationOutcome.BLOCKED:
                return again.gates.problems() + tuple(f"ADAPTER {again.adapter}: {n}" for n in again.notes)
            return tuple(f"AUTHORIZATION: {p}" for p in (authorize() if authorize is not None else ()))

        trace = ExecutionRun(provider, change, recheck=recheck).drive()
    return DrillReport(mode, script if scenario_key else None, candidate.id, result, change, trace, before,
                       provider.snapshot(), digest_before, provider.digest(), provider.ledger)


def _dry_run(provider: SyntheticProviderFixture, change: PlannedTransition) -> ExecutionTrace:
    """Read the target and describe the change. Never submits."""
    scope = provider.read_scope()
    at = provider.now()
    if scope is None:  # pragma: no cover - no catalog scenario fails the first read
        step = ExecutionStep(1, X.BLOCKED, at, Reason.PRECONDITION_UNREADABLE,
                             "The target could not be read; nothing was planned or submitted.", reads=(False,))
        return ExecutionTrace((step,))
    observed = scope.get(change.target_key, {})
    observation = change.classify(observed)
    if observation is not TargetObservation.NOT_APPLIED:
        step = ExecutionStep(1, X.BLOCKED, at, Reason.PRECONDITION_NOT_MET,
                             "The target is not in the planned before-state, so the change would not apply. Nothing "
                             "was submitted.", observation=observation, observed=observed, reads=(True,))
        return ExecutionTrace((step,))
    step = ExecutionStep(1, X.DRY_RUN, at, Reason.PLANNED_NOT_SUBMITTED,
                         f"Planned, not submitted: {change.summary} The target would go from {change.describe('before')} to "
                         f"{change.describe('after')}. Nothing was submitted and the synthetic provider's state is "
                         "unchanged.",
                         observation=observation, observed=observed, reads=(True,))
    return ExecutionTrace((step,))


__all__ = ["DRILL_NOTICE", "MODE_BANNERS", "DrillMode", "DrillReport", "DrillUnauthorized", "DrillUnavailable",
           "ExecutionRun", "planned_transition", "run_drill", "scenario"]
