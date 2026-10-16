"""What executing a remediation means: a controlled state transition, not a button click.

The governed remediation path performs no change (D8, D153): every
``RemediationOutcome`` is a plan, no ``ExecutionJob`` is ever executed, and the execute route
refuses everyone. None of that changes here. This module defines the execution semantics a
future executing build would need, as a closed state machine, so that the synthetic
execution drill (``app.remediation.drill``) can prove them against an in-memory synthetic
provider fixture. The drill is the only thing that drives it. Nothing here performs I/O.

States (each has exactly one meaning):

- ``DRY_RUN``: the change was computed against the provider's current state. Nothing was
  submitted and no state changed. Terminal.
- ``BLOCKED``: a gate, the allowlist, the environment, or the precondition refused, so this
  submission was not made. Terminal.
- ``EXECUTION_REQUESTED``: one attempt was submitted, carrying the operation id (the
  idempotency key) and the precondition (the target's expected before-state).
- ``OUTCOME_UNKNOWN``: the answer did not say whether the change was applied (a timeout).
  Nothing is assumed, and nothing is resubmitted from here.
- ``VERIFYING``: OGWA read the target's current state to find out what happened.
- ``RETRY_PERMITTED``: that read proved the change was not applied (the target is still in
  its before-state) and an attempt remains. It is permission to try again, not an attempt:
  the gates are evaluated again, and the precondition read again, when the retry is submitted.
- ``RETRY_NOT_PERMITTED``: a retry would be unsafe or cannot be justified (the outcome is
  still unknown, the target changed outside this run, the provider refused, or the attempt
  limit was reached). Terminal; a person reconciles.
- ``EXECUTED``: the change was applied, as the provider acknowledged or a read proved.
  Never final: only a post-action verification can end a run successfully.
- ``POST_ACTION_VERIFIED``: a read after the change found the target in its planned
  after-state and everything else in scope unchanged. Terminal; the only success.
- ``VERIFICATION_FAILED``: that read found something else, or could not be made. Terminal;
  never reported as a success.

The invariants (RX-1 to RX-10 in docs/security/safety-invariants.md) follow from the table:
an unknown outcome leads only to verification; a resubmission is reachable only through
``RETRY_PERMITTED``, which only a read showing the before-state grants; success is reachable
only from ``EXECUTED`` through a post-action read.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.domain.errors import InvalidRecord
from app.domain.evidence import DIGEST_PREFIX, stable_digest
from app.domain.ids import check_utc

# One first attempt and at most one retry. A source constant, not configuration.
MAX_SUBMISSIONS = 2
# Reads are safe to repeat; a verification makes at most this many before it gives up.
MAX_VERIFICATION_READS = 2


class ExecutionState(StrEnum):
    DRY_RUN = "DRY_RUN"
    BLOCKED = "BLOCKED"
    EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    VERIFYING = "VERIFYING"
    RETRY_PERMITTED = "RETRY_PERMITTED"
    RETRY_NOT_PERMITTED = "RETRY_NOT_PERMITTED"
    EXECUTED = "EXECUTED"
    POST_ACTION_VERIFIED = "POST_ACTION_VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


X = ExecutionState

# What a reviewer reads. Dry run and execution can never share a label.
STATE_LABELS: dict[ExecutionState, str] = {
    X.DRY_RUN: "DRY RUN — NO STATE CHANGED",
    X.BLOCKED: "BLOCKED — NOT SUBMITTED",
    X.EXECUTION_REQUESTED: "EXECUTION REQUESTED — SYNTHETIC DEMO",
    X.OUTCOME_UNKNOWN: "OUTCOME UNKNOWN — VERIFYING",
    X.VERIFYING: "VERIFYING — READING SYNTHETIC PROVIDER STATE",
    X.RETRY_PERMITTED: "RETRY PERMITTED — VERIFIED NOT APPLIED",
    X.RETRY_NOT_PERMITTED: "RETRY NOT PERMITTED — NEEDS A PERSON",
    X.EXECUTED: "EXECUTED — SYNTHETIC DEMO",
    X.POST_ACTION_VERIFIED: "POST-ACTION VERIFIED",
    X.VERIFICATION_FAILED: "VERIFICATION FAILED — NOT A SUCCESS",
}

# The closed transition table. ``None`` is the start of a run. Anything not listed is refused.
TRANSITIONS: dict[ExecutionState | None, frozenset[ExecutionState]] = {
    None: frozenset({X.DRY_RUN, X.BLOCKED, X.EXECUTION_REQUESTED}),
    X.EXECUTION_REQUESTED: frozenset({X.EXECUTED, X.OUTCOME_UNKNOWN, X.RETRY_NOT_PERMITTED}),
    X.OUTCOME_UNKNOWN: frozenset({X.VERIFYING}),
    X.VERIFYING: frozenset({X.EXECUTED, X.RETRY_PERMITTED, X.RETRY_NOT_PERMITTED}),
    X.RETRY_PERMITTED: frozenset({X.EXECUTION_REQUESTED, X.BLOCKED}),
    X.EXECUTED: frozenset({X.POST_ACTION_VERIFIED, X.VERIFICATION_FAILED}),
}
TERMINAL_STATES = frozenset(s for s in ExecutionState if s not in TRANSITIONS)
SUCCESS_STATE = X.POST_ACTION_VERIFIED


class SubmissionAnswer(StrEnum):
    """What the provider said about one submission."""

    APPLIED = "APPLIED"  # it says the change was applied (a read still has to confirm it)
    TIMEOUT = "TIMEOUT"  # no answer in time: the change may or may not have been applied
    REFUSED = "REFUSED"  # a definitive refusal: this submission changed nothing


class TargetObservation(StrEnum):
    """What a read of the target showed, compared with the planned change."""

    NOT_APPLIED = "NOT_APPLIED"  # still in the before-state
    APPLIED = "APPLIED"  # in the planned after-state
    DIVERGED = "DIVERGED"  # in neither: something else changed it
    UNREADABLE = "UNREADABLE"  # no read succeeded: still unknown


# A read's result in a sentence: "The target is {phrase}."
OBSERVATION_PHRASES: dict[TargetObservation, str] = {
    TargetObservation.NOT_APPLIED: "still in its planned before-state",
    TargetObservation.APPLIED: "in its planned after-state",
    TargetObservation.DIVERGED: "in neither planned state",
    TargetObservation.UNREADABLE: "unreadable",
}


class Reason(StrEnum):
    """Why a step was taken. Stable codes for the API, the UI, and tests."""

    PLANNED_NOT_SUBMITTED = "PLANNED_NOT_SUBMITTED"
    GATES_BLOCKED = "GATES_BLOCKED"
    GATES_BLOCKED_ON_RETRY = "GATES_BLOCKED_ON_RETRY"
    PRECONDITION_NOT_MET = "PRECONDITION_NOT_MET"
    PRECONDITION_UNREADABLE = "PRECONDITION_UNREADABLE"
    SUBMITTED = "SUBMITTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    TIMED_OUT = "TIMED_OUT"
    PROVIDER_REFUSED = "PROVIDER_REFUSED"
    READ_TARGET = "READ_TARGET"
    CONFIRMED_APPLIED = "CONFIRMED_APPLIED"
    VERIFIED_NOT_APPLIED = "VERIFIED_NOT_APPLIED"
    OUTCOME_STILL_UNKNOWN = "OUTCOME_STILL_UNKNOWN"
    TARGET_CHANGED_OUTSIDE_RUN = "TARGET_CHANGED_OUTSIDE_RUN"
    ATTEMPT_LIMIT_REACHED = "ATTEMPT_LIMIT_REACHED"
    MATCHES_EXPECTED_STATE = "MATCHES_EXPECTED_STATE"
    TARGET_NOT_IN_EXPECTED_STATE = "TARGET_NOT_IN_EXPECTED_STATE"
    UNEXPECTED_CHANGE_IN_SCOPE = "UNEXPECTED_CHANGE_IN_SCOPE"
    POST_ACTION_UNREADABLE = "POST_ACTION_UNREADABLE"


class ExecutionStepRefused(InvalidRecord):
    """A step the transition table does not allow from the run's current state."""


def check_transition(current: ExecutionState | None, target: ExecutionState) -> None:
    allowed = TRANSITIONS.get(current)
    if allowed is None:  # only a terminal state is missing from the table (None, the start, is in it)
        raise ExecutionStepRefused(f"{current} is terminal; nothing follows it")
    if target not in allowed:
        here = current.value if current is not None else "the start of a run"
        raise ExecutionStepRefused(f"{target.value} cannot follow {here}; allowed: "
                                   f"{', '.join(sorted(s.value for s in allowed))}")


# --- the planned change ---------------------------------------------------------------------


def _frozen(fields: Mapping[str, Any], name: str) -> tuple[tuple[str, Any], ...]:
    if not isinstance(fields, Mapping) or not fields:
        raise InvalidRecord(f"{name} names at least one field")
    for key, value in fields.items():
        if not isinstance(key, str) or not key or not isinstance(value, (str, bool, int)):
            raise InvalidRecord(f"{name} maps field names to plain values")
    return tuple(sorted(fields.items()))


@dataclass(frozen=True)
class PlannedTransition:
    """The one change a run may make: one target, from one state to another.

    ``before`` is the precondition (compare-and-set: the provider refuses a submission whose
    target is not in it); ``after`` is the state a post-action read must find. Both name only
    the fields the change touches."""

    operation_id: str
    target_key: str
    before: tuple[tuple[str, Any], ...]
    after: tuple[tuple[str, Any], ...]
    summary: str

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not self.operation_id.startswith(OPERATION_ID_PREFIX) \
                or len(self.operation_id) != len(OPERATION_ID_PREFIX) + 32:
            raise InvalidRecord(f"operation_id must be {OPERATION_ID_PREFIX}<32 hex>")
        if not isinstance(self.target_key, str) or not self.target_key:
            raise InvalidRecord("target_key must be a non-empty string")
        if dict(self.before).keys() != dict(self.after).keys():
            raise InvalidRecord("before and after name the same fields")
        if self.before == self.after:
            raise InvalidRecord("a planned transition changes something")

    @classmethod
    def of(cls, operation_id: str, target_key: str, before: Mapping[str, Any], after: Mapping[str, Any],
           summary: str) -> "PlannedTransition":
        return cls(operation_id, target_key, _frozen(before, "before"), _frozen(after, "after"), summary)

    def classify(self, observed: Mapping[str, Any] | None) -> TargetObservation:
        if observed is None:
            return TargetObservation.UNREADABLE
        if all(observed.get(k) == v for k, v in self.before):
            return TargetObservation.NOT_APPLIED
        if all(observed.get(k) == v for k, v in self.after):
            return TargetObservation.APPLIED
        return TargetObservation.DIVERGED

    def describe(self, which: str) -> str:
        """``before`` or ``after`` in words, for a reviewer: ``present = false``."""
        pairs = self.before if which == "before" else self.after
        return ", ".join(f"{k} = {str(v).lower() if isinstance(v, bool) else v}" for k, v in pairs)

    def to_dict(self) -> dict[str, Any]:
        return {"operationId": self.operation_id, "targetKey": self.target_key, "before": dict(self.before),
                "after": dict(self.after), "summary": self.summary}


OPERATION_ID_PREFIX = "rop_"


def operation_id(*, candidate_id: str, operation: str, target_identity_digest: str, approval_id: str,
                 evidence_fingerprint: str) -> str:
    """The idempotency key of one approved change: the same candidate, operation, target
    identity, approval, and evidence always give the same id, so every attempt (and every
    run) of that change carries it, and a provider can refuse to apply it twice."""
    digest = stable_digest(["ogwa.remediation.operation/v1", candidate_id, operation, target_identity_digest,
                            approval_id, evidence_fingerprint])
    return OPERATION_ID_PREFIX + digest[len(DIGEST_PREFIX):][:32]


# --- decisions ----------------------------------------------------------------------------


def retry_decision(observation: TargetObservation, *, submissions: int,
                   max_submissions: int = MAX_SUBMISSIONS) -> tuple[ExecutionState, Reason, str]:
    """After an unknown outcome and a verification: what may happen next. Pure.

    Only a read that shows the before-state permits a retry. A read that could not be made
    never does: resubmitting a change that may already have been applied could apply it twice."""
    if observation is TargetObservation.APPLIED:
        return (X.EXECUTED, Reason.CONFIRMED_APPLIED,
                "The target is in the planned after-state: the change was applied (by the earlier attempt, or outside "
                "this run). It is not resubmitted.")
    if observation is TargetObservation.UNREADABLE:
        return (X.RETRY_NOT_PERMITTED, Reason.OUTCOME_STILL_UNKNOWN,
                "No read of the target succeeded, so whether the change was applied is still unknown. A retry without "
                "that proof could apply it twice; a person must reconcile.")
    if observation is TargetObservation.DIVERGED:
        return (X.RETRY_NOT_PERMITTED, Reason.TARGET_CHANGED_OUTSIDE_RUN,
                "The target is in neither the planned before-state nor the after-state: something outside this run "
                "changed it. Nothing is resubmitted; a person must reconcile.")
    if submissions >= max_submissions:
        return (X.RETRY_NOT_PERMITTED, Reason.ATTEMPT_LIMIT_REACHED,
                f"The change was verified not applied, but {submissions} of {max_submissions} attempts have been "
                "made. A person decides what happens next.")
    return (X.RETRY_PERMITTED, Reason.VERIFIED_NOT_APPLIED,
            "The target is still in the planned before-state: the change was verified not applied, so one retry "
            "with the same operation id is safe. The gates and the precondition are checked again before it is "
            "submitted.")


def scope_differences(expected: Mapping[str, Mapping[str, Any]],
                      observed: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    """Every difference between the expected and the observed state of the run's scope."""
    differences = []
    for key in sorted(set(expected) | set(observed)):
        want, got = expected.get(key), observed.get(key)
        if want is None or got is None:
            differences.append(f"{key}: {'unexpected object' if want is None else 'missing'}")
            continue
        for name in sorted(set(want) | set(got)):
            if want.get(name) != got.get(name):
                differences.append(f"{key}.{name}: expected {json.dumps(want.get(name))}, "
                                   f"observed {json.dumps(got.get(name))}")
    return tuple(differences)


# --- the record of a run ------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionStep:
    """One step of a run: the state entered, when, and why. Reads and answers are recorded
    with the step that made them."""

    seq: int
    state: ExecutionState
    at: datetime
    reason: Reason
    detail: str
    attempt: int | None = None
    answer: SubmissionAnswer | None = None
    answer_detail: str | None = None
    observation: TargetObservation | None = None
    observed: Mapping[str, Any] | None = None
    reads: tuple[bool, ...] = ()  # each read this step made: True if it succeeded
    problems: tuple[str, ...] = ()
    differences: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.state, ExecutionState) or not isinstance(self.reason, Reason):
            raise InvalidRecord("a step names its state and reason")
        check_utc(self.at, "at")
        if not isinstance(self.detail, str) or not self.detail:
            raise InvalidRecord("a step explains itself")

    @property
    def label(self) -> str:
        return STATE_LABELS[self.state]

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "state": self.state.value, "label": self.label,
            "at": self.at.strftime("%Y-%m-%dT%H:%M:%SZ"), "reason": self.reason.value, "detail": self.detail,
            "attempt": self.attempt, "answer": self.answer.value if self.answer else None,
            "answerDetail": self.answer_detail,
            "observation": self.observation.value if self.observation else None,
            "observed": dict(self.observed) if self.observed is not None else None,
            "reads": [{"succeeded": r} for r in self.reads], "problems": list(self.problems),
            "differences": list(self.differences),
        }


@dataclass(frozen=True)
class ExecutionTrace:
    """A whole run, checked against the transition table and the run invariants."""

    steps: tuple[ExecutionStep, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        verify_trace(self.steps)

    @property
    def final_state(self) -> ExecutionState:
        return self.steps[-1].state

    @property
    def succeeded(self) -> bool:
        return self.final_state is SUCCESS_STATE

    @property
    def submissions(self) -> int:
        return sum(1 for s in self.steps if s.state is X.EXECUTION_REQUESTED)

    def attempts(self) -> tuple[dict[str, Any], ...]:
        """Each submission with what came of it, read off the steps: the provider's
        answer, the verification read after an unknown outcome, and the state that followed. A
        reading of the trace, never a second record of it."""
        out: list[dict[str, Any]] = []
        for step in self.steps:
            if step.state is X.EXECUTION_REQUESTED:
                out.append({"attempt": step.attempt, "submittedAt": step.to_dict()["at"], "answer": None,
                            "verification": None, "next": None})
            elif out and step.state is not X.EXECUTION_REQUESTED:
                current = out[-1]
                if step.answer is not None and current["answer"] is None:
                    current["answer"] = step.answer.value
                if step.state is X.VERIFYING:
                    current["verification"] = step.observation.value if step.observation else None
                if step.state in (X.EXECUTED, X.RETRY_PERMITTED, X.RETRY_NOT_PERMITTED, X.BLOCKED) \
                        and current["next"] is None:
                    current["next"] = step.state.value
        return tuple(out)

    def post_action_verification(self) -> dict[str, Any]:
        """The post-action read's result: CONFIRMED only for POST_ACTION_VERIFIED (whose step carries
        the predicate ``verify_trace`` requires), FAILED for VERIFICATION_FAILED, and otherwise
        NOT_REACHED: nothing was executed, so there was nothing to verify."""
        last = self.steps[-1]
        if last.state is X.POST_ACTION_VERIFIED:
            result = "CONFIRMED"
        elif last.state is X.VERIFICATION_FAILED:
            result = "FAILED"
        else:
            return {"result": "NOT_REACHED", "reason": None, "observation": None, "differences": []}
        return {"result": result, "reason": last.reason.value,
                "observation": last.observation.value if last.observation else None,
                "differences": list(last.differences)}


# What a POST_ACTION_VERIFIED step must carry: the read that found the target in its planned
# after-state, and nothing else in scope changed. Without it the state is refused.
def post_action_predicate_problems(step: ExecutionStep) -> tuple[str, ...]:
    problems = []
    if step.reason is not Reason.MATCHES_EXPECTED_STATE:
        problems.append(f"its reason is {step.reason.value}, not {Reason.MATCHES_EXPECTED_STATE.value}")
    if step.observation is not TargetObservation.APPLIED:
        problems.append("its read did not find the target in the planned after-state")
    if not any(step.reads):
        problems.append("it made no successful read")
    if step.differences:
        problems.append("something else in scope changed")
    return tuple(problems)


def verify_trace(steps: Iterable[ExecutionStep]) -> None:
    """Refuse a trace that the table, or a run invariant, does not allow."""
    steps = tuple(steps)
    if not steps:
        raise InvalidRecord("a run has at least one step")
    current: ExecutionState | None = None
    submissions = 0
    last_verification: TargetObservation | None = None
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, ExecutionStep) or step.seq != index:
            raise InvalidRecord("steps are numbered from 1, in order")
        if index > 1 and step.at < steps[index - 2].at:
            raise InvalidRecord("steps never go back in time")
        check_transition(current, step.state)
        if step.state is X.EXECUTION_REQUESTED:
            submissions += 1
            if submissions > MAX_SUBMISSIONS:
                raise InvalidRecord(f"a run submits at most {MAX_SUBMISSIONS} times")
            if step.attempt != submissions:
                raise InvalidRecord("each submission names its attempt number")
        if step.state is X.VERIFYING:
            last_verification = step.observation
        if step.state is X.RETRY_PERMITTED and last_verification is not TargetObservation.NOT_APPLIED:
            raise InvalidRecord("a retry is permitted only after a read showed the change not applied")
        if step.state is X.EXECUTED and current is X.VERIFYING and last_verification is not TargetObservation.APPLIED:
            raise InvalidRecord("a verification reports EXECUTED only after a read showed the change applied")
        if step.state is X.POST_ACTION_VERIFIED:
            problems = post_action_predicate_problems(step)
            if problems:
                raise InvalidRecord("POST_ACTION_VERIFIED needs the post-action predicate: " + "; ".join(problems))
        current = step.state
    if current not in TERMINAL_STATES:
        raise InvalidRecord(f"a run ends in a terminal state, not {current}")
