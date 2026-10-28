"""The synthetic provider fixture: the only thing a remediation drill can ever change (OGWA-DEMO-03).

A fixture is an in-memory model of the objects one candidate's remediation would touch, its
Okta group's application assignments and its mapped AD group, copied from the candidate's
recorded SYNTHETIC evidence when a drill starts. It lives for one drill and is then thrown
away. It holds no store, no client, and no reference to anything outside the process, so a
change to it changes nothing else: not the evidence store, not the lifecycle, not the audit
chain, and no external system.

It behaves like a provider a careful executor would have to deal with:

- **an idempotency key**: every submission carries the change's operation id, and an id
  that was already applied is refused without a change;
- **a precondition** (compare-and-set): a submission whose target is not in the planned
  before-state is refused without a change;
- **scripted faults**: a ``FaultScript`` decides, deterministically, what each submission
  does (applied and acknowledged; timed out before or after applying; acknowledged without
  applying) and which reads fail. Nothing is random;
- **a synthetic clock**: each call advances it by a fixed duration, so a run's steps carry
  realistic times without anyone waiting.

Every change goes through ``MutationCapableService._perform`` with the mutation policy the
caller injects (P01): in ``LOCAL_SYNTHETIC``, against a synthetic target, the policy says
EXECUTE; in ``DRY_RUN_MUTATION`` it can only plan, so nothing is applied at all. Any other
policy is refused when the fixture is built. The ledger is the fixture's own record of what
happened inside it. A drill never consults it to decide anything; it is reported so that a
reviewer, and the tests, can check OGWA's reads against the truth.
"""

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar

from app.core.errors import MutationBlockedError
from app.core.modes import ExecutionMode
from app.core.safety import MutationCapableService, MutationPolicy, MutationRequest
from app.domain.evidence import EvidenceSource, stable_digest
from app.domain.policy import EvidenceBundle
from app.domain.remediation_execution import ExecutionState, PlannedTransition, SubmissionAnswer, TargetObservation

# How long each call takes on the fixture's synthetic clock.
SUBMIT_DURATION = timedelta(seconds=2)
TIMEOUT_DURATION = timedelta(seconds=30)
READ_DURATION = timedelta(seconds=1)
FAILED_READ_DURATION = timedelta(seconds=10)
# The policies a fixture may hold: one that can execute against synthetic targets, and one
# that can only plan.
FIXTURE_MODES = frozenset({ExecutionMode.LOCAL_SYNTHETIC, ExecutionMode.DRY_RUN_MUTATION})
OUTSIDE_ACTOR = "outside-this-run"


class FaultKind(StrEnum):
    """What one submission does inside the fixture."""

    APPLY = "APPLY"  # applied, and acknowledged
    TIMEOUT_BEFORE_APPLY = "TIMEOUT_BEFORE_APPLY"  # nothing applied; no answer in time
    TIMEOUT_AFTER_APPLY = "TIMEOUT_AFTER_APPLY"  # applied; the acknowledgement was lost
    ACK_WITHOUT_APPLY = "ACK_WITHOUT_APPLY"  # acknowledged as applied; nothing applied


@dataclass(frozen=True)
class FaultScript:
    """A deterministic fault scenario.

    ``submissions``: what the 1st, 2nd, ... submission does; any later one is ``APPLY``.
    ``unreadable_reads``: the numbers (1-based, counting every read) of the reads that fail.
    ``outside_change``: fields set on the target, as if by a person outside the run, right
    after the first submission (tests use it; no catalog scenario does).
    ``expected_final``: the state the drill must end in; the tests hold the engine to it."""

    key: str
    title: str
    description: str
    submissions: tuple[FaultKind, ...] = ()
    unreadable_reads: frozenset[int] = frozenset()
    outside_change: tuple[tuple[str, Any], ...] = ()
    expected_final: ExecutionState | None = None

    def fault(self, submission: int) -> FaultKind:
        return self.submissions[submission - 1] if submission <= len(self.submissions) else FaultKind.APPLY

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "title": self.title, "description": self.description,
                "submissions": [f.value for f in self.submissions], "unreadableReads": sorted(self.unreadable_reads),
                "expectedFinalState": self.expected_final.value if self.expected_final else None}


X = ExecutionState
NO_FAULT_KEY = "NO_FAULT"

# The closed catalog a drill request may name. A request cannot describe its own faults.
SCENARIOS: dict[str, FaultScript] = {s.key: s for s in (
    FaultScript(NO_FAULT_KEY, "No fault",
                "The provider applies the change and says so. A post-action read confirms it.",
                (FaultKind.APPLY,), expected_final=X.POST_ACTION_VERIFIED),
    FaultScript("TIMEOUT_NOT_APPLIED", "Timeout, change not applied: verified, then retried",
                "The first submission times out before the provider applies anything. OGWA does not assume either "
                "outcome: it reads the target, finds it unchanged, re-checks the gates and the precondition, and "
                "retries once with the same operation id. The retry is applied, and a post-action read confirms it.",
                (FaultKind.TIMEOUT_BEFORE_APPLY, FaultKind.APPLY), expected_final=X.POST_ACTION_VERIFIED),
    FaultScript("TIMEOUT_AFTER_APPLY", "Timeout, change already applied: never resubmitted",
                "The provider applies the change, but its answer is lost and the call times out. The read finds "
                "the change already made, so OGWA does not resubmit it (that would be a duplicate); a post-action "
                "read confirms the state.",
                (FaultKind.TIMEOUT_AFTER_APPLY,), expected_final=X.POST_ACTION_VERIFIED),
    FaultScript("TIMEOUT_UNVERIFIABLE", "Timeout, provider unreadable: outcome stays unknown",
                "The submission times out, and both verification reads fail. Whether the change was applied is "
                "still unknown, so OGWA neither retries nor reports success; a person must reconcile.",
                (FaultKind.TIMEOUT_BEFORE_APPLY,), frozenset({2, 3}), expected_final=X.RETRY_NOT_PERMITTED),
    FaultScript("REPEATED_TIMEOUT", "Two timeouts: the retry limit holds",
                "Both submissions time out without applying anything. Each is verified; after the second, the "
                "attempt limit stops a third, and a person decides what happens next.",
                (FaultKind.TIMEOUT_BEFORE_APPLY, FaultKind.TIMEOUT_BEFORE_APPLY), expected_final=X.RETRY_NOT_PERMITTED),
    FaultScript("ACKNOWLEDGED_NOT_APPLIED", "Acknowledged, but not applied: verification fails",
                "The provider says the change was applied, but it was not. The post-action read finds the target "
                "unchanged, so the run ends VERIFICATION_FAILED and is never reported as a success.",
                (FaultKind.ACK_WITHOUT_APPLY,), expected_final=X.VERIFICATION_FAILED),
)}


@dataclass(frozen=True)
class SubmissionResult:
    answer: SubmissionAnswer
    code: str
    detail: str


@dataclass(frozen=True)
class LedgerEntry:
    """What really happened inside the fixture for one call that could change it."""

    seq: int
    at: datetime
    actor: str  # the operation id that was submitted, or OUTSIDE_ACTOR
    target_key: str
    fault: FaultKind | None
    applied: bool
    answer: SubmissionAnswer | None
    code: str

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "at": self.at.strftime("%Y-%m-%dT%H:%M:%SZ"), "actor": self.actor,
                "targetKey": self.target_key, "fault": self.fault.value if self.fault else None,
                "applied": self.applied, "answer": self.answer.value if self.answer else None, "code": self.code}


def applied_state(current: Mapping[str, Any], change: PlannedTransition) -> dict[str, Any]:
    """The target's state once ``change`` is applied. A deleted object keeps only its identity."""
    after = {**current, **dict(change.after)}
    if after.get("exists") is False:
        after = {k: v for k, v in after.items() if k in ("objectGuid", "domain", "exists")}
    return after


def expected_scope(baseline: Mapping[str, Mapping[str, Any]], change: PlannedTransition) -> dict[str, dict[str, Any]]:
    """The scope a correct run leaves behind: the baseline with only the planned change made."""
    expected = {k: dict(v) for k, v in baseline.items()}
    if change.target_key in expected:
        expected[change.target_key] = applied_state(expected[change.target_key], change)
    return expected


def assignment_key(assignment_id: str) -> str:
    return f"okta-assignment:{assignment_id}"


def ad_group_key(object_guid: str) -> str:
    return f"ad-group:{object_guid}"


class SyntheticProviderFixture(MutationCapableService):
    name: ClassVar[str] = "SYNTHETIC_PROVIDER_FIXTURE"

    def __init__(self, objects: Mapping[str, Mapping[str, Any]], *, script: FaultScript, mutation_policy: MutationPolicy,
                 start: datetime) -> None:
        super().__init__(mutation_policy=mutation_policy)
        if mutation_policy.mode not in FIXTURE_MODES:
            raise MutationBlockedError(f"a synthetic provider fixture cannot hold a {mutation_policy.mode.value} policy")
        if not isinstance(script, FaultScript):
            raise TypeError("script must be a FaultScript")
        self._objects: dict[str, dict[str, Any]] = copy.deepcopy({k: dict(v) for k, v in objects.items()})
        self._script = script
        self._now = start
        self._reads = 0
        self._submissions = 0
        self._applied_operations: set[str] = set()
        self._ledger: list[LedgerEntry] = []

    @classmethod
    def from_evidence(cls, evidence: EvidenceBundle, *, script: FaultScript, mutation_policy: MutationPolicy,
                      start: datetime) -> "SyntheticProviderFixture":
        """A fixture holding what the candidate's recorded synthetic evidence says exists."""
        if not isinstance(evidence, EvidenceBundle):
            raise TypeError("evidence must be an EvidenceBundle")
        if any(r.provenance.source is not EvidenceSource.SYNTHETIC for r in evidence.records()):
            raise MutationBlockedError("a synthetic provider fixture is built from SYNTHETIC evidence only")
        objects: dict[str, dict[str, Any]] = {}
        applications = {a.id: a for a in evidence.applications}
        group = evidence.okta_group
        for a in evidence.assignments:
            app = applications.get(a.application_id)
            objects[assignment_key(a.id)] = {
                "applicationId": a.application_id, "oktaAppId": app.okta_app_id if app else None,
                "oktaGroupId": group.okta_group_id if group and group.id == a.okta_group_id else None,
                "present": a.present}
        ad = evidence.ad_group
        if ad is not None:
            state: dict[str, Any] = {"objectGuid": ad.object_guid, "domain": ad.domain.lower(), "exists": ad.exists}
            if ad.exists:
                state.update(distinguishedName=ad.distinguished_name, sid=ad.sid, samAccountName=ad.sam_account_name)
            objects[ad_group_key(ad.object_guid)] = state
        return cls({k: {n: v for n, v in o.items() if v is not None} for k, o in objects.items()}, script=script,
                   mutation_policy=mutation_policy, start=start)

    # --- what a caller can do ------------------------------------------------------------

    def now(self) -> datetime:
        return self._now

    def read(self, key: str) -> dict[str, Any] | None:
        """The target's current state, or None if this read fails (as scripted)."""
        if not self._read_succeeds():
            return None
        value = self._objects.get(key)
        return copy.deepcopy(value) if value is not None else {}

    def read_scope(self) -> dict[str, dict[str, Any]] | None:
        """Every object in the fixture's scope in one read, or None if it fails."""
        if not self._read_succeeds():
            return None
        return copy.deepcopy(self._objects)

    def submit(self, change: PlannedTransition) -> SubmissionResult:
        """Submit one change. The fault script decides what it does; the operation id and the
        precondition are checked first, and either refusal changes nothing."""
        if not isinstance(change, PlannedTransition):
            raise TypeError("change must be a PlannedTransition")
        self._submissions += 1
        n = self._submissions
        if change.operation_id in self._applied_operations:
            return self._refuse(change, "DUPLICATE_OPERATION",
                                f"operation {change.operation_id} was already applied; nothing was changed")
        current = self._objects.get(change.target_key)
        if current is None or change.classify(current) is not TargetObservation.NOT_APPLIED:
            return self._refuse(change, "PRECONDITION_FAILED",
                                "the target is not in the planned before-state; nothing was changed")
        fault = self._script.fault(n)
        applied = False
        if fault in (FaultKind.APPLY, FaultKind.TIMEOUT_AFTER_APPLY):
            applied = self._change(change.target_key, lambda: applied_state(current, change), action="apply")
            if not applied:
                return self._refuse(change, "PLAN_ONLY_POLICY",
                                    "this fixture's mutation policy can only plan; nothing was changed", fault=fault)
            self._applied_operations.add(change.operation_id)
        timed_out = fault in (FaultKind.TIMEOUT_BEFORE_APPLY, FaultKind.TIMEOUT_AFTER_APPLY)
        answer = SubmissionAnswer.TIMEOUT if timed_out else SubmissionAnswer.APPLIED
        self._now += TIMEOUT_DURATION if timed_out else SUBMIT_DURATION
        self._record(change.operation_id, change.target_key, fault, applied, answer, fault.value)
        if self._script.outside_change and n == 1:
            target = self._objects.get(change.target_key, {})
            changed = self._change(change.target_key, lambda: {**target, **dict(self._script.outside_change)},
                                   action="outside")
            self._record(OUTSIDE_ACTOR, change.target_key, None, changed, None, "OUTSIDE_CHANGE")
        if timed_out:
            return SubmissionResult(answer, "TIMEOUT", f"timed out after {int(TIMEOUT_DURATION.total_seconds())} s")
        return SubmissionResult(answer, "APPLIED", "acknowledged")

    # --- the fixture's own record (never read by a drill to decide anything) ---------------

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._objects)

    def digest(self) -> str:
        return stable_digest(self._objects)

    @property
    def ledger(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._ledger)

    @property
    def mutations_applied(self) -> int:
        return sum(1 for e in self._ledger if e.applied)

    @property
    def script(self) -> FaultScript:
        return self._script

    # --- internals -----------------------------------------------------------------------

    def _read_succeeds(self) -> bool:
        self._reads += 1
        failed = self._reads in self._script.unreadable_reads
        self._now += FAILED_READ_DURATION if failed else READ_DURATION
        return not failed

    def _change(self, key: str, new_state, *, action: str) -> bool:
        """Change one object through the P01 mutation policy. True if it was changed."""
        system = "okta" if key.startswith("okta-") else "ad"

        def operation() -> None:
            self._objects[key] = new_state()

        outcome = self._perform(MutationRequest(system=system, action=f"synthetic_fixture_{action}", target=key,
                                                target_is_synthetic=True), operation)
        return outcome.executed

    def _refuse(self, change: PlannedTransition, code: str, detail: str,
                fault: FaultKind | None = None) -> SubmissionResult:
        self._now += SUBMIT_DURATION
        self._record(change.operation_id, change.target_key, fault, False, SubmissionAnswer.REFUSED, code)
        return SubmissionResult(SubmissionAnswer.REFUSED, code, detail)

    def _record(self, actor: str, key: str, fault: FaultKind | None, applied: bool, answer: SubmissionAnswer | None,
                code: str) -> None:
        self._ledger.append(LedgerEntry(len(self._ledger) + 1, self._now, actor, key, fault, applied, answer, code))
