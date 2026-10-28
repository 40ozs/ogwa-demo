"""The OGWA store: durable evidence, lifecycle, approvals, jobs, collector runs, and audit.

Rules enforced here, on top of the schema's constraints and triggers:

- Every write runs in one transaction together with its audit event. The audit log is
  one hash chain; each event records actor, action, target, time, execution mode,
  result, correlation id, and before/after references.
- Evidence is append-only. A re-observation adds a row; the previous one is kept.
- Candidate state changes only through ``apply_transition``. The decision is appended and
  the candidate projection updated in the same transaction, and every load replays the
  decision history (``verify_history``) so a state written directly is detected.
- Refused transitions are audited too.
- A transition may cite only evidence, approvals, and jobs that are already recorded.
- Timestamps supplied by callers may not lie in the future, so a hold period or an
  approval window cannot be skipped by post-dating a request.
- The environment marker decides which modes may open the store and which evidence
  sources may be written (synthetic and real data never mix).

Nothing here contacts a network service or changes an external system.
"""

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.database_url import DatabaseTarget
from app.core.modes import ExecutionMode, assert_mode_permitted_by_build
from app.core.redaction import redact_text
from app.domain.actors import Actor, ActorKind
from app.domain.approval import LEGACY_APPROVAL_STAGES, LEGACY_STAGE_PROBLEM, ApprovalDecision, ApprovalRecord, ApprovalStage
from app.domain.audit import AuditAction, AuditEvent, AuditResult, clean_details, next_event, verify_chain
from app.domain.candidate_policy import PolicyRole, PolicyVersion, version_append_problems
from app.domain.collection import CollectorErrorCode, CollectorRun, CollectorRunOutcome
from app.domain.errors import InvalidRecord, TransitionRefused
from app.domain.evidence import Evidence, EvidenceSource, Provenance, ResultStatus
from app.domain.execution import FINISHED_STATUSES, JOB_MODES, LEGACY_JOB_KINDS, ExecutionJob, JobKind, JobStatus
from app.domain.ids import IdKind, new_id
from app.domain.lifecycle import (
    APPROVAL_STEPS,
    LifecycleCandidate,
    LifecycleDecision,
    LifecycleState,
    TransitionRequest,
    TransitionResult,
    apply_transition,
    verify_history,
)
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    IdentityMapping,
    MappingConfidence,
    OktaApplication,
    OktaGroup,
)
from app.domain.mapping_review import MappingMethod, MappingReview, ReviewStatus, review_append_problems
from app.domain.policy import EvidenceBundle
from app.domain.policy_release import RECORDED_SOURCE, PolicyRef, strip_policy_details
from app.domain.remediation import RemediationOutcome, RemediationResult
from app.governance.snapshot import DirectorySnapshot, SnapshotRecord, content_digest
from app.store import codec
from app.store.codec import parse_ts, ts
from app.store.db import DIALECT_SQLITE, connect, transaction
from app.store.environment import (
    DatabaseEnvironment,
    StoreMarker,
    check_mode_permitted,
    check_source_permitted,
    read_marker,
    write_marker,
)
from app.store.errors import EnvironmentRefused, MigrationError, StoreConflict, StoreError, StoreIntegrityError
from app.store.evidence_tables import SPECS, EvidenceSpec, spec_for
from app.store.migrations import LATEST_VERSION
from app.store.migrator import upgrade, verify_applied

# How far a caller-supplied timestamp may run ahead of the store clock.
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_JOB_DETAIL = 300
MAX_EXTERNAL_REF = 200

_JOB_PROGRESSION: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.PLANNED: frozenset({JobStatus.RUNNING, JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.REFUSED}),
    JobStatus.RUNNING: frozenset({JobStatus.SUCCEEDED, JobStatus.FAILED}),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# What the audit chain records of a decision and of an approval: written with the row, checked on load (F08).
def _decision_details(d: LifecycleDecision) -> dict:
    return {"decision_id": d.id, "from": d.from_state, "to": d.to_state, "reason": d.reason,
            "evidence_fingerprint": d.evidence_fingerprint}


def _approval_details(a: ApprovalRecord) -> dict:
    return {"approval_id": a.id, "stage": a.stage, "decision": a.decision, "candidate_epoch": a.candidate_epoch,
            "evidence_fingerprint": a.evidence_fingerprint, "expires_at": ts(a.expires_at)}


@dataclass(frozen=True)
class JobStatusEvent:
    sequence: int
    status: JobStatus
    executed: bool
    targets_synthetic: bool
    finished_at: datetime | None
    external_ref: str | None
    detail: str | None
    recorded_at: datetime


@dataclass(frozen=True)
class IntegrityReport:
    schema_version: int
    environment: DatabaseEnvironment
    audit_events: int
    audit_head: str | None
    observations_checked: int
    candidates_checked: int
    directory_records_checked: int = 0


@dataclass(frozen=True)
class DirectorySnapshotInfo:
    """The synthetic directory snapshot a store holds (0012), without its records."""

    id: str
    dataset: str
    seed: str
    company: str
    as_of: datetime
    record_count: int
    content_digest: str
    loaded_at: datetime


def _actor(row: sqlite3.Row, prefix: str) -> Actor | None:
    kind = row[f"{prefix}_kind"]
    return None if kind is None else Actor(ActorKind(kind), row[f"{prefix}_id"])


def _ad_stage_columns(candidate: LifecycleCandidate) -> dict[str, Any]:
    """The candidate columns of the AD quarantine and deletion stages (migration 0011)."""
    quarantine, proposer = candidate.quarantine_approver, candidate.deletion_proposer
    return {
        "quarantine_approver_kind": quarantine.kind.value if quarantine else None,
        "quarantine_approver_id": quarantine.id if quarantine else None,
        "quarantine_hold_until": ts(candidate.quarantine_hold_until),
        "deletion_proposer_kind": proposer.kind.value if proposer else None,
        "deletion_proposer_id": proposer.id if proposer else None,
        "deletion_proposed_at": ts(candidate.deletion_proposed_at),
    }


def _ad_stage_fields(row: sqlite3.Row) -> dict[str, Any]:
    """``_ad_stage_columns`` read back as LifecycleCandidate fields."""
    return {
        "quarantine_approver": _actor(row, "quarantine_approver"),
        "quarantine_hold_until": parse_ts(row["quarantine_hold_until"]),
        "deletion_proposer": _actor(row, "deletion_proposer"),
        "deletion_proposed_at": parse_ts(row["deletion_proposed_at"]),
    }


def _insert(conn: sqlite3.Connection, table: str, values: dict[str, Any]) -> None:
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values()))


class Store:
    """Use ``Store.open`` or ``Store.initialize``; the constructor assumes a verified connection."""

    def __init__(self, conn: sqlite3.Connection, *, mode: ExecutionMode, marker: StoreMarker,
                 clock: Callable[[], datetime] = utc_now) -> None:
        assert_mode_permitted_by_build(mode)
        check_mode_permitted(marker.environment, mode)
        self._conn = conn
        self.mode = mode
        self.marker = marker
        self._clock = clock
        self._verified: tuple[tuple, IntegrityReport] | None = None  # see verified_integrity
        # Validated policy versions by their exact stored row (append-only rows; see _policy_version_from_row).
        self._policy_versions: dict[tuple, PolicyVersion] = {}

    # --- lifecycle of the store itself -------------------------------------------------

    @classmethod
    def open(cls, target: DatabaseTarget, *, mode: ExecutionMode, clock: Callable[[], datetime] = utc_now) -> "Store":
        conn = connect(target)
        try:
            return cls._from_connection(conn, mode=mode, clock=clock)
        except BaseException:
            conn.close()
            raise

    @classmethod
    def _from_connection(cls, conn: sqlite3.Connection, *, mode: ExecutionMode, clock) -> "Store":
        version = verify_applied(conn, DIALECT_SQLITE)
        if version != LATEST_VERSION:
            raise MigrationError(f"schema is at version {version}, this build needs {LATEST_VERSION}; run the upgrade command")
        marker = read_marker(conn)
        if marker is None:
            raise EnvironmentRefused("database has no OGWA environment marker; it is not an initialized OGWA store")
        return cls(conn, mode=mode, marker=marker, clock=clock)

    @classmethod
    def initialize(cls, target: DatabaseTarget, *, environment: DatabaseEnvironment, mode: ExecutionMode, actor: Actor,
                   clock: Callable[[], datetime] = utc_now, correlation_id: str | None = None) -> "Store":
        """Create a new, empty, marked store. Refuses to touch an existing file."""
        assert_mode_permitted_by_build(mode)
        check_mode_permitted(environment, mode)
        if target.path is not None and target.path.exists():
            raise StoreError(f"{target.path} already exists; refusing to initialize over it")
        conn = connect(target, create=True)
        try:
            upgrade(conn, DIALECT_SQLITE, clock=clock)
            marker = StoreMarker(environment, new_id(IdKind.REQUEST), clock(), actor)
            store = cls(conn, mode=mode, marker=marker, clock=clock)
            with store._write():
                write_marker(conn, marker)
                store._audit(actor=actor, action=AuditAction.STORE_INITIALIZED, subject_id=marker.store_instance_id,
                             details={"environment": environment.value, "schema_version": LATEST_VERSION},
                             correlation_id=correlation_id, after_ref=f"store:{environment.value}")
            return store
        except BaseException:
            conn.close()
            raise

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def read_only(self) -> bool:
        """True for a store SQLite refuses to change (``PRAGMA query_only``, ``app.store.db.connect_image``)."""
        return bool(self._conn.execute("PRAGMA query_only").fetchone()[0])

    @property
    def connection(self) -> sqlite3.Connection:
        """For read-only inspection (reports, tests). Writes must go through the methods."""
        return self._conn

    # --- internals ---------------------------------------------------------------------

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise StoreError("store clock must return timezone-aware datetimes")
        return now

    def _not_future(self, value: datetime, what: str) -> None:
        if value > self._now() + MAX_FUTURE_SKEW:
            raise StoreConflict(f"{what} is in the future relative to the store clock")

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        try:
            with transaction(self._conn):
                yield self._conn
        except sqlite3.IntegrityError as exc:
            raise StoreConflict(f"database refused the write: {exc}") from None

    def _one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()

    # --- audit -------------------------------------------------------------------------

    def _audit(self, *, actor: Actor, action: AuditAction, subject_id: str, details: dict | None = None,
               result: AuditResult = AuditResult.SUCCEEDED, correlation_id: str | None = None,
               before_ref: str | None = None, after_ref: str | None = None) -> AuditEvent:
        head = self._audit_head_event()
        occurred = self._now()
        if head is not None and occurred < head.occurred_at:
            occurred = head.occurred_at  # never let a clock step backwards break append order
        event = next_event(
            head, actor=actor, action=action, subject_id=subject_id, occurred_at=occurred, details=details,
            execution_mode=self.mode, result=result, correlation_id=correlation_id or new_id(IdKind.REQUEST),
            before_ref=before_ref, after_ref=after_ref,
        )
        _insert(self._conn, "audit_events", {
            "id": event.id, "sequence": event.sequence, "occurred_at": ts(event.occurred_at),
            "actor_kind": event.actor.kind.value, "actor_id": event.actor.id, "action": event.action.value,
            "subject_id": event.subject_id, "details": codec.json_text([list(p) for p in event.details]),
            "previous_digest": event.previous_digest, "digest": event.digest,
            "execution_mode": event.execution_mode.value if event.execution_mode else None,
            "result": event.result.value if event.result else None, "correlation_id": event.correlation_id,
            "before_ref": event.before_ref, "after_ref": event.after_ref,
        })
        return event

    def _audit_from_row(self, row: sqlite3.Row) -> AuditEvent:
        try:
            details = codec.parse_json(row["details"])
            event = AuditEvent(
                id=row["id"], sequence=row["sequence"], occurred_at=parse_ts(row["occurred_at"]),
                actor=Actor(ActorKind(row["actor_kind"]), row["actor_id"]), action=AuditAction(row["action"]),
                subject_id=row["subject_id"], details=tuple(tuple(p) for p in details),
                previous_digest=row["previous_digest"],
                execution_mode=ExecutionMode(row["execution_mode"]) if row["execution_mode"] else None,
                result=AuditResult(row["result"]) if row["result"] else None, correlation_id=row["correlation_id"],
                before_ref=row["before_ref"], after_ref=row["after_ref"],
            )
        except (InvalidRecord, ValueError, TypeError) as exc:
            raise StoreIntegrityError(f"audit event {row['sequence']} is malformed: {exc}") from None
        if event.digest != row["digest"]:
            raise StoreIntegrityError(f"audit event {row['sequence']} does not match its stored digest")
        return event

    def _require_audited(self, action: AuditAction, ref: str, subject_id: str, actor: Actor, details: dict) -> None:
        """Raise unless exactly one ``action`` event records ``ref``, by ``actor``, with these details (F08).

        Rows that agree only with other rows prove nothing to someone who can write the file. Bound to
        the chain, a forged or edited row either fails here or changes the anchored audit head.

        Decision and approval events may also carry the policy reference they were judged by
        (OGWA-DEMO-02). It lives only in the event, so it is compared apart from the row's details:
        those must still match exactly, and the reference must be complete and valid."""
        rows = self._conn.execute("SELECT * FROM audit_events WHERE subject_id = ? AND action = ? AND after_ref = ?",
                                  (subject_id, action.value, ref)).fetchall()
        events = [self._audit_from_row(r) for r in rows]
        if len(events) != 1 or events[0].actor != actor or (
                strip_policy_details(events[0].details) != clean_details(details)):
            raise StoreIntegrityError(f"{ref} does not match its {action.value} audit event")
        try:
            PolicyRef.from_audit_details(events[0].details)
        except InvalidRecord as exc:
            raise StoreIntegrityError(f"{ref}: its audit event's policy reference is invalid: {exc}") from None

    def recorded_policies(self, candidate_id: str | None = None, *,
                          approval_ids: tuple[str, ...] = ()) -> dict[str, PolicyRef]:
        """The policy each decision and approval was judged by, as recorded with it, keyed by
        ``decision:<id>`` / ``approval:<id>``: every one of ``candidate_id``'s, or the approvals named.
        Records made without one are absent: nothing is filled in from the policy in force now."""
        actions = (AuditAction.TRANSITION_APPLIED.value, AuditAction.APPROVAL_RECORDED.value)
        if candidate_id is not None:
            rows = self._conn.execute("SELECT * FROM audit_events WHERE subject_id = ? AND action IN (?, ?) "
                                      "ORDER BY sequence", (candidate_id, *actions)).fetchall()
        else:
            if len(approval_ids) > 500:
                raise ValueError("at most 500 approvals at a time")
            refs = [f"approval:{a}" for a in approval_ids]
            rows = self._conn.execute(
                f"SELECT * FROM audit_events WHERE action = ? AND after_ref IN ({', '.join('?' * len(refs))}) "
                "ORDER BY sequence", (AuditAction.APPROVAL_RECORDED.value, *refs)).fetchall() if refs else []
        out = {}
        for row in rows:
            event = self._audit_from_row(row)
            try:
                ref = PolicyRef.from_audit_details(event.details)
            except InvalidRecord as exc:
                raise StoreIntegrityError(f"audit event {event.sequence}: invalid policy reference: {exc}") from None
            if ref is not None and event.after_ref:
                out[event.after_ref] = ref
        return out

    def _check_policy_ref(self, ref: PolicyRef | None, lifecycle_policy=None) -> dict:
        """Inside a write: refuse a decision judged by anything but the policy in force now, and
        return the reference's audit details (none without a reference).

        A recorded reference must name the latest recorded version, by id, sequence, and digest, and
        the lifecycle rules applied must be that version's own. An unrecorded reference is only
        possible while no version is recorded. Either way a policy recorded between reading the
        policy and writing the decision makes the write fail instead of naming a superseded policy."""
        if ref is None:
            return {}
        if not isinstance(ref, PolicyRef):
            raise TypeError("policy_ref must be a PolicyRef")
        active = self.active_policy_version()
        if ref.source == RECORDED_SOURCE:
            if active is None or (active.id, active.sequence, active.policy_digest) != (
                    ref.version_id, ref.sequence, ref.policy_digest):
                raise StoreConflict("the decision names a policy version that is not the version in force")
            if lifecycle_policy is not None and lifecycle_policy != active.policy.lifecycle:
                raise StoreConflict("the decision was judged by rules other than the policy version in force")
        elif active is not None:
            raise StoreConflict(f"policy version {active.sequence + 1} is recorded; a decision cannot be judged by "
                                "the unrecorded demo policy")
        return ref.audit_details()

    def _audit_head_event(self) -> AuditEvent | None:
        row = self._one("SELECT * FROM audit_events ORDER BY sequence DESC LIMIT 1")
        return None if row is None else self._audit_from_row(row)

    def audit_events(self) -> tuple[AuditEvent, ...]:
        rows = self._conn.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        return tuple(self._audit_from_row(r) for r in rows)

    def audit_head(self) -> tuple[int, str] | None:
        row = self._one("SELECT sequence, digest FROM audit_events ORDER BY sequence DESC LIMIT 1")
        return None if row is None else (row["sequence"], row["digest"])

    def audit_events_page(self, *, limit: int, offset: int = 0, subject_id: str | None = None,
                          oldest_first: bool = False) -> tuple[AuditEvent, ...]:
        """A bounded page of audit events, newest first unless ``oldest_first``, each checked
        against its stored digest (P08)."""
        if not 1 <= limit <= 1000 or offset < 0:
            raise StoreError("audit page limit must be 1-1000 and offset non-negative")
        where, params = ("WHERE subject_id = ? ", (subject_id,)) if subject_id is not None else ("", ())
        rows = self._conn.execute(
            f"SELECT * FROM audit_events {where}ORDER BY sequence {'ASC' if oldest_first else 'DESC'} LIMIT ? OFFSET ?",
            (*params, limit, offset)
        ).fetchall()
        return tuple(self._audit_from_row(r) for r in rows)

    def record_governed_refusal(self, *, actor: Actor, subject_id: str, details: dict[str, object],
                                correlation_id: str, before_ref: str | None = None) -> AuditEvent:
        """Chain a refused governed request (migration 0007). Records the refusal only; it
        changes no other table. Details are redacted like every audit detail."""
        if not isinstance(actor, Actor) or actor.kind is not ActorKind.HUMAN:
            raise StoreConflict("a governed request is made by an authenticated human")
        with self._write():
            return self._audit(actor=actor, action=AuditAction.GOVERNED_REQUEST_REFUSED, subject_id=subject_id,
                               details=details, result=AuditResult.REFUSED, correlation_id=correlation_id,
                               before_ref=before_ref)

    # --- remediation dry runs (P10) ------------------------------------------------------

    def record_remediation_dry_run(self, *, actor: Actor, candidate_id: str, result: RemediationResult,
                                   approval_id: str, evidence_fingerprint: str, correlation_id: str,
                                   policy_ref: PolicyRef | None = None, lifecycle_policy=None) -> AuditEvent:
        """Chain a remediation dry run that passed every gate (migration 0010).

        The audit event is the record; no other table changes. Its outcome can only be
        SIMULATED, WHATIF, or VALIDATION_ONLY: a BLOCKED dry run is a refusal (chained as
        GOVERNED_REQUEST_REFUSED), and no result can claim an execution.

        With ``policy_ref`` (OGWA-DEMO-04), the event also records the policy its gates were judged
        by, which must be the policy in force (``_check_policy_ref``, as for a decision), so a
        recorded dry run names its policy version for good, whatever is in force later."""
        if not isinstance(actor, Actor) or actor.kind is not ActorKind.HUMAN:
            raise StoreConflict("a remediation dry run is requested by an authenticated human")
        if not isinstance(result, RemediationResult):
            raise TypeError("result must be a RemediationResult")
        if result.outcome is RemediationOutcome.BLOCKED:
            raise StoreConflict("a BLOCKED remediation is a refusal; it is chained as GOVERNED_REQUEST_REFUSED")
        if result.executed or result.production_mutation:  # RemediationResult already refuses both
            raise StoreConflict("this build records no executed remediation")
        if self.mode not in JOB_MODES:
            raise EnvironmentRefused(f"a remediation dry run cannot be recorded in {self.mode.value} mode")
        if self._one("SELECT 1 FROM candidates WHERE id = ?", (candidate_id,)) is None:
            raise StoreConflict("the remediation's candidate is not recorded")
        approval = self.load_approval(approval_id)
        if approval is None or approval.candidate_id != candidate_id:
            raise StoreConflict("a remediation dry run must cite a recorded approval of its candidate")
        target = result.target
        details = {
            "operation": result.operation, "outcome": result.outcome, "adapter": result.adapter,
            "target_kind": target.kind, "target_id": target.target_id, "target_identity": target.identity_digest,
            "approval_id": approval_id, "evidence_fingerprint": evidence_fingerprint,
            "gates_passed": f"{len(result.gates.checks)}/{len(result.gates.checks)}",
            "planned_changes": " | ".join(c.summary for c in result.planned_changes),
            "executed": "false", "production_mutation": "false",
        }
        with self._write():
            details.update(self._check_policy_ref(policy_ref, lifecycle_policy))
            return self._audit(actor=actor, action=AuditAction.REMEDIATION_DRY_RUN_RECORDED, subject_id=candidate_id,
                               details=details, correlation_id=correlation_id, before_ref=f"approval:{approval_id}",
                               after_ref=f"remediation:{result.operation.value}:{result.outcome.value}")

    def audit_event_for(self, action: AuditAction, after_ref: str) -> AuditEvent | None:
        """The one audit event of ``action`` that recorded ``after_ref`` (``approval:<id>``,
        ``decision:<id>``), checked against its digest; None if there is none (OGWA-DEMO-04)."""
        rows = self._conn.execute("SELECT * FROM audit_events WHERE action = ? AND after_ref = ? ORDER BY sequence",
                                  (AuditAction(action).value, after_ref)).fetchall()
        if len(rows) > 1:
            raise StoreIntegrityError(f"{after_ref} has {len(rows)} {AuditAction(action).value} audit events")
        return self._audit_from_row(rows[0]) if rows else None

    def remediation_dry_runs(self, candidate_id: str) -> tuple[AuditEvent, ...]:
        """A candidate's recorded remediation dry runs, oldest first, each checked against its digest."""
        rows = self._conn.execute(
            "SELECT * FROM audit_events WHERE subject_id = ? AND action = ? ORDER BY sequence",
            (candidate_id, AuditAction.REMEDIATION_DRY_RUN_RECORDED.value),
        ).fetchall()
        return tuple(self._audit_from_row(r) for r in rows)

    # --- collector runs ----------------------------------------------------------------

    def start_collector_run(self, run: CollectorRun, *, correlation_id: str | None = None) -> None:
        if not isinstance(run, CollectorRun):
            raise TypeError("run must be a CollectorRun")
        if run.mode is not self.mode:
            raise EnvironmentRefused(f"a {run.mode.value} collector run cannot be recorded by a {self.mode.value} store")
        check_source_permitted(self.marker.environment, self.mode, run.source)
        self._not_future(run.started_at, "collector run start")
        with self._write():
            _insert(self._conn, "collector_runs", {
                "id": run.id, "collector": run.collector, "collector_version": run.collector_version,
                "source": run.source.value, "execution_mode": run.mode.value, "scope": run.scope,
                "started_at": ts(run.started_at), "started_by_kind": run.started_by.kind.value,
                "started_by_id": run.started_by.id, "recorded_at": ts(self._now()),
            })
            self._audit(actor=run.started_by, action=AuditAction.COLLECTOR_RUN_STARTED, subject_id=run.id,
                        details={"collector": run.collector, "source": run.source, "scope": run.scope},
                        correlation_id=correlation_id, after_ref=f"collector_run:{run.id}")

    def finish_collector_run(self, outcome: CollectorRunOutcome, *, actor: Actor, correlation_id: str | None = None) -> None:
        if not isinstance(outcome, CollectorRunOutcome):
            raise TypeError("outcome must be a CollectorRunOutcome")
        run = self.collector_run(outcome.run_id)
        if run is None:
            raise StoreConflict(f"collector run {outcome.run_id} is not recorded")
        if outcome.finished_at < run.started_at:
            raise StoreConflict("a collector run cannot finish before it started")
        self._not_future(outcome.finished_at, "collector run finish")
        result = AuditResult.SUCCEEDED if outcome.status is ResultStatus.COMPLETE else AuditResult.FAILED
        with self._write():
            _insert(self._conn, "collector_run_outcomes", {
                "run_id": outcome.run_id, "finished_at": ts(outcome.finished_at), "status": outcome.status.value,
                "records_observed": outcome.records_observed,
                "error_code": outcome.error_code.value if outcome.error_code else None,
                "error_summary": outcome.error_summary, "recorded_at": ts(self._now()),
            })
            details = {"status": outcome.status, "records_observed": outcome.records_observed}
            if outcome.error_code is not None:
                details["error_code"] = outcome.error_code
            self._audit(actor=actor, action=AuditAction.COLLECTOR_RUN_FINISHED, subject_id=outcome.run_id,
                        details=details, result=result, correlation_id=correlation_id,
                        before_ref=f"collector_run:{run.id}", after_ref=f"collector_run_outcome:{run.id}")

    def collector_run(self, run_id: str) -> CollectorRun | None:
        row = self._one("SELECT * FROM collector_runs WHERE id = ?", (run_id,))
        if row is None:
            return None
        return CollectorRun(
            id=row["id"], collector=row["collector"], collector_version=row["collector_version"],
            source=EvidenceSource(row["source"]), mode=ExecutionMode(row["execution_mode"]), scope=row["scope"],
            started_at=parse_ts(row["started_at"]), started_by=_actor(row, "started_by"),
        )

    def collector_run_outcome(self, run_id: str) -> CollectorRunOutcome | None:
        row = self._one("SELECT * FROM collector_run_outcomes WHERE run_id = ?", (run_id,))
        if row is None:
            return None
        return CollectorRunOutcome(
            run_id=row["run_id"], finished_at=parse_ts(row["finished_at"]), status=ResultStatus(row["status"]),
            records_observed=row["records_observed"],
            error_code=CollectorErrorCode(row["error_code"]) if row["error_code"] else None,
            error_summary=row["error_summary"],
        )

    def _check_run_accepts(self, run_id: str, provenance: Provenance) -> None:
        run = self.collector_run(run_id)
        if run is None:
            raise StoreConflict(f"collector run {run_id} is not recorded")
        if self._one("SELECT 1 FROM collector_run_outcomes WHERE run_id = ?", (run_id,)):
            raise StoreConflict(f"collector run {run_id} has finished; it cannot add observations")
        if run.source is not provenance.source:
            raise StoreConflict(f"collector run {run_id} collects {run.source.value}, not {provenance.source.value}")
        if provenance.observed_at < run.started_at - MAX_FUTURE_SKEW:
            raise StoreConflict(f"observation predates collector run {run_id}")

    # --- evidence ----------------------------------------------------------------------

    def record_evidence(self, record: Evidence, *, actor: Actor, collector_run_id: str | None = None,
                        correlation_id: str | None = None) -> str:
        """Append one observation. Returns its observation id."""
        spec = spec_for(record)
        provenance = record.provenance
        check_source_permitted(self.marker.environment, self.mode, provenance.source)
        self._not_future(provenance.observed_at, "observed_at")
        now = self._now()
        observation_id = new_id(IdKind.OBSERVATION)
        with self._write():
            if collector_run_id is not None:
                self._check_run_accepts(collector_run_id, provenance)
            previous = self._ensure_anchor(spec, record, now)
            _insert(self._conn, spec.observation_table, {
                "observation_id": observation_id, spec.entity_column: record.id,
                **spec.observation_values(record),
                "source": provenance.source.value, "observed_at": ts(provenance.observed_at), "scope": provenance.scope,
                "collector_version": provenance.collector_version, "result_status": provenance.result_status.value,
                "collector_run_id": collector_run_id, "digest": record.digest, "recorded_at": ts(now),
            })
            if spec.write_children is not None:
                spec.write_children(self._conn, observation_id, record)
            self._audit(
                actor=actor, action=AuditAction.EVIDENCE_RECORDED, subject_id=record.id,
                details={"kind": record.KIND, "observation_id": observation_id, "digest": record.digest,
                         "source": provenance.source, "result_status": provenance.result_status,
                         "collector_run_id": collector_run_id or "-"},
                correlation_id=correlation_id,
                before_ref=f"observation:{previous}" if previous else None, after_ref=f"observation:{observation_id}",
            )
        return observation_id

    def _ensure_anchor(self, spec: EvidenceSpec, record: Evidence, now: datetime) -> str | None:
        """Create the anchor or check its immutable key. Returns the latest observation id, if any."""
        expected = spec.anchor_values(record)
        anchor = self._one(f"SELECT * FROM {spec.anchor_table} WHERE id = ?", (record.id,))
        if anchor is None:
            _insert(self._conn, spec.anchor_table, {"id": record.id, **expected, "recorded_at": ts(now)})
            return None
        stored = {k: anchor[k] for k in expected}
        if stored != expected:
            raise StoreConflict(f"{record.KIND.value} {record.id} is already recorded with a different identity {stored}")
        latest = self._one(
            f"SELECT observation_id FROM {spec.observation_table} WHERE {spec.entity_column} = ? "
            "ORDER BY observed_at DESC LIMIT 1", (record.id,),
        )
        return latest["observation_id"] if latest else None

    def _build(self, spec: EvidenceSpec, anchor: sqlite3.Row, obs: sqlite3.Row) -> Evidence:
        try:
            record = spec.build(self._conn, anchor, obs)
        except (InvalidRecord, ValueError, TypeError) as exc:
            raise StoreIntegrityError(f"stored observation {obs['observation_id']} is invalid: {exc}") from None
        if record.digest != obs["digest"]:
            raise StoreIntegrityError(f"stored observation {obs['observation_id']} does not match its digest")
        return record

    def _observations(self, spec: EvidenceSpec, record_id: str, *, latest_only: bool) -> list[Evidence]:
        anchor = self._one(f"SELECT * FROM {spec.anchor_table} WHERE id = ?", (record_id,))
        if anchor is None:
            return []
        sql = f"SELECT * FROM {spec.observation_table} WHERE {spec.entity_column} = ? ORDER BY observed_at"
        if latest_only:
            sql = sql.replace("ORDER BY observed_at", "ORDER BY observed_at DESC LIMIT 1")
        return [self._build(spec, anchor, row) for row in self._conn.execute(sql, (record_id,)).fetchall()]

    def latest(self, cls: type, record_id: str) -> Evidence | None:
        records = self._observations(spec_for(cls), record_id, latest_only=True)
        return records[0] if records else None

    def history(self, cls: type, record_id: str) -> list[Evidence]:
        """Every observation of one record, oldest first."""
        return self._observations(spec_for(cls), record_id, latest_only=False)

    def _require_recorded(self, records: list[Evidence]) -> None:
        for record in records:
            spec = spec_for(record)
            row = self._one(
                f"SELECT digest FROM {spec.observation_table} WHERE {spec.entity_column} = ? AND observed_at = ?",
                (record.id, ts(record.provenance.observed_at)),
            )
            if row is None or row["digest"] != record.digest:
                raise StoreConflict(f"{record.KIND.value} {record.id} as supplied has not been recorded in the store")

    def evidence_bundle(self, candidate: LifecycleCandidate) -> EvidenceBundle:
        """The latest recorded evidence relevant to one candidate."""
        group = self.latest(OktaGroup, candidate.okta_group_id)
        assignments = [a for a in (self.latest(ApplicationGroupAssignment, i) for i in candidate.assignment_ids) if a]
        app_ids = list(dict.fromkeys(a.application_id for a in assignments))
        applications = [a for a in (self.latest(OktaApplication, i) for i in app_ids) if a]
        usage = []
        for app_id in app_ids:
            rows = self._conn.execute(
                "SELECT id FROM usage_scopes WHERE application_id = ? AND (group_id IS NULL OR group_id = ?) ORDER BY scope_key",
                (app_id, candidate.okta_group_id),
            ).fetchall()
            usage += [u for u in (self.latest(ApplicationUsageObservation, r["id"]) for r in rows) if u]
        mapping_row = self._one("SELECT id FROM identity_mappings WHERE group_id = ?", (candidate.okta_group_id,))
        mapping = self.latest(IdentityMapping, mapping_row["id"]) if mapping_row else None
        ad_group = self.latest(ADGroup, mapping.ad_group_id) if mapping and mapping.ad_group_id else None
        subjects = [candidate.okta_group_id] + ([mapping.ad_group_id] if mapping and mapping.ad_group_id else [])
        dependency_rows = self._conn.execute(
            f"SELECT id FROM dependency_checks WHERE subject_id IN ({', '.join('?' for _ in subjects)}) ORDER BY subject_id, kind",
            tuple(subjects),
        ).fetchall()
        dependencies = [d for d in (self.latest(DependencyEvidence, r["id"]) for r in dependency_rows) if d]
        return EvidenceBundle(
            okta_group=group, applications=tuple(applications), assignments=tuple(assignments), usage=tuple(usage),
            mapping=mapping, ad_group=ad_group, dependencies=tuple(dependencies),
        )

    # --- candidates and decisions ------------------------------------------------------

    def create_candidate(self, candidate: LifecycleCandidate, *, correlation_id: str | None = None) -> None:
        if not isinstance(candidate, LifecycleCandidate):
            raise TypeError("candidate must be a LifecycleCandidate")
        if candidate.state is not LifecycleState.DISCOVERED or candidate.epoch or candidate.updated_at != candidate.created_at:
            raise StoreConflict("a new candidate must be freshly discovered (use LifecycleCandidate.discover)")
        self._not_future(candidate.created_at, "candidate created_at")
        with self._write():
            if self._one("SELECT 1 FROM okta_groups WHERE id = ?", (candidate.okta_group_id,)) is None:
                raise StoreConflict(f"Okta group {candidate.okta_group_id} has not been recorded")
            for assignment_id in candidate.assignment_ids:
                row = self._one("SELECT group_id FROM app_group_assignments WHERE id = ?", (assignment_id,))
                if row is None or row["group_id"] != candidate.okta_group_id:
                    raise StoreConflict(f"assignment {assignment_id} is not a recorded assignment of the candidate's group")
            _insert(self._conn, "candidates", {
                "id": candidate.id, "group_id": candidate.okta_group_id,
                "proposed_by_kind": candidate.proposed_by.kind.value, "proposed_by_id": candidate.proposed_by.id,
                "created_at": ts(candidate.created_at), "reason_codes": codec.json_text(list(candidate.reason_codes)),
                "state": candidate.state.value, "epoch": 0, "hold_until": None, "blocked_from": None,
                "okta_unassign_approver_kind": None, "okta_unassign_approver_id": None,
                "updated_at": ts(candidate.updated_at), "decision_count": 0, **_ad_stage_columns(candidate),
            })
            for assignment_id in candidate.assignment_ids:
                _insert(self._conn, "candidate_assignments", {"candidate_id": candidate.id, "assignment_id": assignment_id})
            self._audit(actor=candidate.proposed_by, action=AuditAction.CANDIDATE_CREATED, subject_id=candidate.id,
                        details={"okta_group_id": candidate.okta_group_id, "assignment_ids": ",".join(candidate.assignment_ids),
                                 "reason_codes": ",".join(candidate.reason_codes)},
                        correlation_id=correlation_id, after_ref=f"candidate:{candidate.id}@DISCOVERED#e0")

    def candidate_ids(self) -> list[str]:
        return [r["id"] for r in self._conn.execute("SELECT id FROM candidates ORDER BY created_at, id").fetchall()]

    def decisions(self, candidate_id: str) -> list[LifecycleDecision]:
        rows = self._conn.execute("SELECT * FROM decisions WHERE candidate_id = ? ORDER BY sequence", (candidate_id,)).fetchall()
        try:
            return [
                LifecycleDecision(
                    id=r["id"], candidate_id=r["candidate_id"], from_state=LifecycleState(r["from_state"]),
                    to_state=LifecycleState(r["to_state"]), actor=_actor(r, "actor"), decided_at=parse_ts(r["decided_at"]),
                    reason=r["reason"], evidence_fingerprint=r["evidence_fingerprint"], epoch=r["epoch"],
                    approval_id=r["approval_id"], execution_job_id=r["execution_job_id"],
                )
                for r in rows
            ]
        except (InvalidRecord, ValueError) as exc:
            raise StoreIntegrityError(f"a stored decision of {candidate_id} is invalid: {exc}") from None

    def load_candidate(self, candidate_id: str) -> LifecycleCandidate:
        """Load a candidate and prove its stored state by replaying its decisions."""
        row = self._one("SELECT * FROM candidates WHERE id = ?", (candidate_id,))
        if row is None:
            raise StoreError(f"candidate {candidate_id} is not recorded")
        assignments = self._conn.execute(
            "SELECT assignment_id FROM candidate_assignments WHERE candidate_id = ? ORDER BY assignment_id", (candidate_id,)
        ).fetchall()
        try:
            candidate = LifecycleCandidate(
                id=row["id"], okta_group_id=row["group_id"], assignment_ids=tuple(a["assignment_id"] for a in assignments),
                state=LifecycleState(row["state"]), proposed_by=_actor(row, "proposed_by"),
                created_at=parse_ts(row["created_at"]), updated_at=parse_ts(row["updated_at"]), epoch=row["epoch"],
                hold_until=parse_ts(row["hold_until"]),
                blocked_from=LifecycleState(row["blocked_from"]) if row["blocked_from"] else None,
                reason_codes=codec.str_tuple(row["reason_codes"]),
                okta_unassign_approver=_actor(row, "okta_unassign_approver"), **_ad_stage_fields(row),
            )
        except (InvalidRecord, ValueError) as exc:
            raise StoreIntegrityError(f"stored candidate {candidate_id} is invalid: {exc}") from None
        decisions = self.decisions(candidate_id)
        if len(decisions) != row["decision_count"]:
            raise StoreIntegrityError(f"candidate {candidate_id} decision count does not match its decisions")
        try:
            verify_history(candidate, decisions)
        except InvalidRecord as exc:
            raise StoreIntegrityError(f"candidate {candidate_id} failed history verification: {exc}") from None
        for d in decisions:
            self._require_audited(AuditAction.TRANSITION_APPLIED, f"decision:{d.id}", candidate_id, d.actor,
                                  _decision_details(d))
            if d.to_state in APPROVAL_STEPS:
                cited = self.load_approval(d.approval_id)  # checked against its own audit event
                if cited is None or (cited.candidate_id, cited.stage, cited.decision, cited.operator,
                                     cited.candidate_epoch) != (candidate_id, APPROVAL_STEPS[d.to_state],
                                                                ApprovalDecision.APPROVE, d.actor, d.epoch):
                    raise StoreIntegrityError(f"candidate {candidate_id}: decision {d.id} does not cite the approval "
                                              "its step needs")
        last_change = decisions[-1].decided_at if decisions else candidate.created_at
        if candidate.updated_at != last_change:
            raise StoreIntegrityError(f"candidate {candidate_id} updated_at does not match its last decision")
        return candidate

    def transition(self, candidate_id: str, request: TransitionRequest, policy, *,
                   correlation_id: str | None = None, policy_ref: PolicyRef | None = None) -> TransitionResult:
        """Apply a lifecycle transition and record it, or record the refusal and re-raise it.

        With ``policy_ref``, the decision (or the refusal) records the policy that judged it, and is
        refused if that is not the policy in force (``_check_policy_ref``)."""
        correlation_id = correlation_id or new_id(IdKind.REQUEST)
        candidate = self.load_candidate(candidate_id)
        self._not_future(request.now, "transition time")
        self._require_recorded(request.evidence.records())
        if request.approval is not None and self.load_approval(request.approval.id) != request.approval:
            raise StoreConflict(f"approval {request.approval.id} as supplied has not been recorded")
        if request.job is not None and self.load_execution_job(request.job.id) != request.job:
            raise StoreConflict(f"execution job {request.job.id} as supplied is not its latest recorded state")
        before = f"candidate:{candidate.id}@{candidate.state.value}#e{candidate.epoch}"
        try:
            result = apply_transition(candidate, request, policy)
        except TransitionRefused as refused:
            with self._write():
                judged_by = self._check_policy_ref(policy_ref, policy)
                self._audit(actor=request.actor, action=AuditAction.TRANSITION_REFUSED, subject_id=candidate.id,
                            details={"from": refused.source, "to": refused.target, "reason": request.reason,
                                     "problems": " | ".join(refused.problems), **judged_by},
                            result=AuditResult.REFUSED, correlation_id=correlation_id, before_ref=before)
            raise
        updated, decision = result.candidate, result.decision
        with self._write():
            judged_by = self._check_policy_ref(policy_ref, policy)
            row = self._one("SELECT decision_count, state FROM candidates WHERE id = ?", (candidate.id,))
            if row["state"] != candidate.state.value:
                raise StoreConflict(f"candidate {candidate.id} changed while the transition was evaluated")
            _insert(self._conn, "decisions", {
                "id": decision.id, "candidate_id": decision.candidate_id, "sequence": row["decision_count"],
                "from_state": decision.from_state.value, "to_state": decision.to_state.value,
                "actor_kind": decision.actor.kind.value, "actor_id": decision.actor.id,
                "decided_at": ts(decision.decided_at), "reason": decision.reason,
                "evidence_fingerprint": decision.evidence_fingerprint, "epoch": decision.epoch,
                "approval_id": decision.approval_id, "execution_job_id": decision.execution_job_id,
                "recorded_at": ts(self._now()), "correlation_id": correlation_id,
            })
            approver = updated.okta_unassign_approver
            values = {
                "state": updated.state.value, "epoch": updated.epoch, "hold_until": ts(updated.hold_until),
                "blocked_from": updated.blocked_from.value if updated.blocked_from else None,
                "okta_unassign_approver_kind": approver.kind.value if approver else None,
                "okta_unassign_approver_id": approver.id if approver else None,
                **_ad_stage_columns(updated), "updated_at": ts(updated.updated_at),
            }
            assignments = ", ".join(f"{column} = ?" for column in values)
            cursor = self._conn.execute(
                f"UPDATE candidates SET {assignments}, decision_count = decision_count + 1 "
                "WHERE id = ? AND decision_count = ?",
                (*values.values(), candidate.id, row["decision_count"]),
            )
            if cursor.rowcount != 1:
                raise StoreConflict(f"candidate {candidate.id} changed while the transition was recorded")
            self._audit(actor=request.actor, action=AuditAction.TRANSITION_APPLIED, subject_id=candidate.id,
                        details={**_decision_details(decision), **judged_by}, correlation_id=correlation_id,
                        before_ref=before, after_ref=f"decision:{decision.id}")
        return result

    # --- approvals ---------------------------------------------------------------------

    def record_approval(self, approval: ApprovalRecord, *, correlation_id: str | None = None,
                        policy_ref: PolicyRef | None = None) -> None:
        """Record a human's approval decision. With ``policy_ref``, it records the policy its precheck
        was judged by, which must be the policy in force (``_check_policy_ref``)."""
        if not isinstance(approval, ApprovalRecord):
            raise TypeError("approval must be an ApprovalRecord")
        if approval.stage in LEGACY_APPROVAL_STAGES:
            raise StoreConflict(LEGACY_STAGE_PROBLEM)
        self._not_future(approval.decided_at, "approval decided_at")
        correlation_id = correlation_id or new_id(IdKind.REQUEST)
        with self._write():
            if self._one("SELECT 1 FROM candidates WHERE id = ?", (approval.candidate_id,)) is None:
                raise StoreConflict(f"candidate {approval.candidate_id} is not recorded")
            judged_by = self._check_policy_ref(policy_ref)
            _insert(self._conn, "approvals", {
                "id": approval.id, "candidate_id": approval.candidate_id, "stage": approval.stage.value,
                "decision": approval.decision.value, "operator_kind": approval.operator.kind.value,
                "operator_id": approval.operator.id, "decided_at": ts(approval.decided_at), "reason": approval.reason,
                "evidence_fingerprint": approval.evidence_fingerprint, "candidate_epoch": approval.candidate_epoch,
                "expires_at": ts(approval.expires_at), "recorded_at": ts(self._now()), "correlation_id": correlation_id,
            })
            self._audit(actor=approval.operator, action=AuditAction.APPROVAL_RECORDED, subject_id=approval.candidate_id,
                        details={**_approval_details(approval), **judged_by}, correlation_id=correlation_id,
                        after_ref=f"approval:{approval.id}")

    def _approval_from_row(self, row: sqlite3.Row) -> ApprovalRecord:
        try:
            approval = ApprovalRecord(
                id=row["id"], candidate_id=row["candidate_id"], stage=ApprovalStage(row["stage"]),
                decision=ApprovalDecision(row["decision"]), operator=_actor(row, "operator"),
                decided_at=parse_ts(row["decided_at"]), reason=row["reason"],
                evidence_fingerprint=row["evidence_fingerprint"], candidate_epoch=row["candidate_epoch"],
                expires_at=parse_ts(row["expires_at"]),
            )
        except (InvalidRecord, ValueError) as exc:
            raise StoreIntegrityError(f"stored approval {row['id']} is invalid: {exc}") from None
        self._require_audited(AuditAction.APPROVAL_RECORDED, f"approval:{approval.id}", approval.candidate_id,
                              approval.operator, _approval_details(approval))
        return approval

    def load_approval(self, approval_id: str) -> ApprovalRecord | None:
        row = self._one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        return None if row is None else self._approval_from_row(row)

    def approvals_for(self, candidate_id: str) -> list[ApprovalRecord]:
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE candidate_id = ? ORDER BY decided_at, id", (candidate_id,)
        ).fetchall()
        return [self._approval_from_row(r) for r in rows]

    # --- identity-mapping reviews (P06) ------------------------------------------------

    def record_mapping_review(self, review: MappingReview, *, correlation_id: str | None = None) -> None:
        """Append one human review to its Okta group's mapping chain. Never changes an earlier review."""
        if not isinstance(review, MappingReview):
            raise TypeError("review must be a MappingReview")
        self._not_future(review.decided_at, "mapping review decided_at")
        correlation_id = correlation_id or new_id(IdKind.REQUEST)
        with self._write():
            group = self.latest(OktaGroup, review.okta_group_ref)
            if group is None:
                raise StoreConflict(f"Okta group {review.okta_group_ref} has not been recorded")
            if group.okta_group_id != review.okta_group_id:
                raise StoreConflict("the review names a different Okta group id than the recorded group")
            problems = review_append_problems(tuple(self.mapping_reviews(review.okta_group_ref)), review)
            if problems:
                raise StoreConflict("; ".join(problems))
            _insert(self._conn, "mapping_reviews", {
                "id": review.id, "okta_group_ref": review.okta_group_ref, "okta_group_id": review.okta_group_id,
                "okta_group_name": review.okta_group_name, "sequence": review.sequence, "supersedes": review.supersedes,
                "ad_object_guid": review.ad_object_guid, "ad_sid": review.ad_sid,
                "ad_distinguished_name": review.ad_distinguished_name,
                "ad_sam_account_name": review.ad_sam_account_name, "ad_domain": review.ad_domain,
                "method": review.method.value, "confidence": review.confidence.value,
                "review_status": review.review_status.value, "verified_at": ts(review.verified_at),
                "evidence_fingerprint": review.evidence_fingerprint, "decided_by_kind": review.decided_by.kind.value,
                "decided_by_id": review.decided_by.id, "decided_at": ts(review.decided_at), "reason": review.reason,
                "configuration_ref": review.configuration_ref, "recorded_at": ts(self._now()),
                "correlation_id": correlation_id,
            })
            # Migration 0005 (D41). Reviews audited before it keep APPROVAL_RECORDED with
            # kind IDENTITY_MAPPING_REVIEW; those events are never rewritten.
            self._audit(actor=review.decided_by, action=AuditAction.MAPPING_REVIEW_RECORDED,
                        subject_id=review.okta_group_ref,
                        details={"review_id": review.id,
                                 "review_status": review.review_status, "method": review.method,
                                 "confidence": review.confidence, "ad_object_guid": review.ad_object_guid,
                                 "evidence_fingerprint": review.evidence_fingerprint},
                        correlation_id=correlation_id,
                        before_ref=f"mapping_review:{review.supersedes}" if review.supersedes else None,
                        after_ref=f"mapping_review:{review.id}")

    def _mapping_review_from_row(self, row: sqlite3.Row) -> MappingReview:
        try:
            return MappingReview(
                id=row["id"], okta_group_ref=row["okta_group_ref"], okta_group_id=row["okta_group_id"],
                okta_group_name=row["okta_group_name"], sequence=row["sequence"], supersedes=row["supersedes"],
                ad_object_guid=row["ad_object_guid"], ad_sid=row["ad_sid"],
                ad_distinguished_name=row["ad_distinguished_name"], ad_sam_account_name=row["ad_sam_account_name"],
                ad_domain=row["ad_domain"], method=MappingMethod(row["method"]),
                confidence=MappingConfidence(row["confidence"]), review_status=ReviewStatus(row["review_status"]),
                verified_at=parse_ts(row["verified_at"]), evidence_fingerprint=row["evidence_fingerprint"],
                decided_by=_actor(row, "decided_by"), decided_at=parse_ts(row["decided_at"]), reason=row["reason"],
                configuration_ref=row["configuration_ref"],
            )
        except (InvalidRecord, ValueError) as exc:
            raise StoreIntegrityError(f"stored mapping review {row['id']} is invalid: {exc}") from None

    def mapping_reviews(self, okta_group_ref: str) -> list[MappingReview]:
        """One Okta group's mapping reviews, oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM mapping_reviews WHERE okta_group_ref = ? ORDER BY sequence", (okta_group_ref,)
        ).fetchall()
        return [self._mapping_review_from_row(r) for r in rows]

    def _verify_mapping_reviews(self) -> int:
        checked = 0
        refs = [r[0] for r in self._conn.execute("SELECT DISTINCT okta_group_ref FROM mapping_reviews ORDER BY 1")]
        for ref in refs:
            chain: tuple[MappingReview, ...] = ()
            for review in self.mapping_reviews(ref):
                problems = review_append_problems(chain, review)
                if problems:
                    raise StoreIntegrityError(f"mapping review chain of {ref} is broken: {'; '.join(problems)}")
                chain += (review,)
                checked += 1
        return checked

    # --- candidate-classification policy versions (P07) --------------------------------

    def record_policy_version(self, version: PolicyVersion, *, correlation_id: str | None = None) -> None:
        """Append one approved policy configuration. Never changes an earlier version."""
        if not isinstance(version, PolicyVersion):
            raise TypeError("version must be a PolicyVersion")
        self._not_future(version.decided_at, "policy version decided_at")
        correlation_id = correlation_id or new_id(IdKind.REQUEST)
        with self._write():
            history = tuple(self.policy_versions())
            problems = version_append_problems(history, version)
            if problems:
                raise StoreConflict("; ".join(problems))
            _insert(self._conn, "policy_versions", {
                "id": version.id, "sequence": version.sequence, "supersedes": version.supersedes,
                "policy_digest": version.policy_digest, "document": version.document,
                "proposed_by_kind": version.proposed_by.kind.value, "proposed_by_id": version.proposed_by.id,
                "approved_by_kind": version.approved_by.kind.value, "approved_by_id": version.approved_by.id,
                "proposed_by_role": version.proposer_role.value, "approved_by_role": version.approver_role.value,
                "decided_at": ts(version.decided_at), "reason": version.reason, "recorded_at": ts(self._now()),
                "correlation_id": correlation_id,
            })
            # Migration 0005 (D41): policy reviews have their own audit action.
            previous = history[-1] if history else None
            self._audit(actor=version.approved_by, action=AuditAction.POLICY_REVIEW_RECORDED, subject_id=version.id,
                        details={"sequence": str(version.sequence),
                                 "policy_digest": version.policy_digest,
                                 "previous_digest": previous.policy_digest if previous else "-",
                                 "proposed_by": str(version.proposed_by),
                                 "proposer_role": version.proposer_role, "approver_role": version.approver_role,
                                 "reason": version.reason[:500]},
                        correlation_id=correlation_id,
                        before_ref=f"policy_version:{version.supersedes}" if version.supersedes else None,
                        after_ref=f"policy_version:{version.id}")

    def _policy_version_from_row(self, row: sqlite3.Row) -> PolicyVersion:
        """The validated version a row holds. Memoized by the row's exact content: the same row always
        validates to the same immutable value, and a changed row is a different key, so it is
        validated afresh (and fails if invalid). The policy in force is read on every request."""
        key = tuple(row)
        cached = self._policy_versions.get(key)
        if cached is None:
            cached = self._policy_versions[key] = self._parse_policy_version(row)
        return cached

    def _parse_policy_version(self, row: sqlite3.Row) -> PolicyVersion:
        try:
            return PolicyVersion(
                id=row["id"], sequence=row["sequence"], supersedes=row["supersedes"],
                policy_digest=row["policy_digest"], document=row["document"],
                proposed_by=_actor(row, "proposed_by"), approved_by=_actor(row, "approved_by"),
                decided_at=parse_ts(row["decided_at"]), reason=row["reason"],
                proposer_role=PolicyRole(row["proposed_by_role"]), approver_role=PolicyRole(row["approved_by_role"]),
            )
        except (InvalidRecord, ValueError) as exc:
            raise StoreIntegrityError(f"stored policy version {row['id']} is invalid: {exc}") from None

    def policy_versions(self) -> list[PolicyVersion]:
        """Every approved policy version, oldest first."""
        rows = self._conn.execute("SELECT * FROM policy_versions ORDER BY sequence").fetchall()
        return [self._policy_version_from_row(r) for r in rows]

    def active_policy_version(self) -> PolicyVersion | None:
        """The policy in force: the latest approved version, or None if none was recorded."""
        row = self._one("SELECT * FROM policy_versions ORDER BY sequence DESC LIMIT 1")
        return None if row is None else self._policy_version_from_row(row)

    def _verify_policy_versions(self) -> int:
        chain: tuple[PolicyVersion, ...] = ()
        for version in self.policy_versions():
            problems = version_append_problems(chain, version)
            if problems:
                raise StoreIntegrityError(f"policy version chain is broken: {'; '.join(problems)}")
            chain += (version,)
        return len(chain)

    # --- execution jobs ----------------------------------------------------------------

    def record_execution_job(self, job: ExecutionJob, *, external_ref: str | None = None, detail: str | None = None,
                             correlation_id: str | None = None) -> None:
        """Record a job's first state, or append its next status. Earlier states are kept."""
        if not isinstance(job, ExecutionJob):
            raise TypeError("job must be an ExecutionJob")
        if self.mode not in JOB_MODES:
            raise EnvironmentRefused(f"an execution job cannot be recorded in {self.mode.value} mode")
        if self.marker.environment is DatabaseEnvironment.PRODUCTION and (
            job.mode is ExecutionMode.LOCAL_SYNTHETIC or job.targets_synthetic
        ):
            raise EnvironmentRefused("synthetic jobs cannot be recorded in a PRODUCTION store")
        if external_ref is not None and not (0 < len(external_ref) <= MAX_EXTERNAL_REF):
            raise StoreConflict(f"external_ref must be 1-{MAX_EXTERNAL_REF} characters")
        if detail is not None:
            detail = redact_text(detail)
            if not (0 < len(detail) <= MAX_JOB_DETAIL):
                raise StoreConflict(f"detail must be 1-{MAX_JOB_DETAIL} characters")
        self._not_future(job.requested_at, "job requested_at")
        if job.finished_at is not None:
            self._not_future(job.finished_at, "job finished_at")
        correlation_id = correlation_id or new_id(IdKind.REQUEST)
        result = {JobStatus.FAILED: AuditResult.FAILED, JobStatus.REFUSED: AuditResult.REFUSED}.get(job.status, AuditResult.SUCCEEDED)
        with self._write():
            existing = self._one("SELECT 1 FROM execution_jobs WHERE id = ?", (job.id,))
            if existing is None:
                sequence = 0
                self._insert_job(job)
                action, before = AuditAction.EXECUTION_JOB_RECORDED, None
            else:
                previous = self.load_execution_job(job.id)
                self._check_job_update(previous, job)
                sequence = len(self.job_status_history(job.id))
                action, before = AuditAction.EXECUTION_JOB_STATUS_RECORDED, f"job:{job.id}#{sequence - 1}:{previous.status.value}"
            _insert(self._conn, "execution_job_status_events", {
                "job_id": job.id, "sequence": sequence, "status": job.status.value, "executed": codec.flag(job.executed),
                "targets_synthetic": codec.flag(job.targets_synthetic), "finished_at": ts(job.finished_at),
                "external_ref": external_ref, "detail": detail, "recorded_at": ts(self._now()),
                "correlation_id": correlation_id,
            })
            details = {"job_id": job.id, "kind": job.kind, "mode": job.mode, "dry_run": job.dry_run, "status": job.status}
            if external_ref:
                details["external_ref"] = external_ref
            if detail:
                details["detail"] = detail
            self._audit(actor=job.requested_by, action=action, subject_id=job.candidate_id, details=details, result=result,
                        correlation_id=correlation_id, before_ref=before, after_ref=f"job:{job.id}#{sequence}:{job.status.value}")

    def _insert_job(self, job: ExecutionJob) -> None:
        if job.kind in LEGACY_JOB_KINDS:
            raise StoreConflict("AD_RETIREMENT is a legacy job kind; new jobs use AD_QUARANTINE or AD_DELETION (D148)")
        approval = self.load_approval(job.approval_id)
        if approval is None or approval.candidate_id != job.candidate_id:
            raise StoreConflict(f"job {job.id} must reference a recorded approval of its candidate")
        if approval.stage.value != job.kind.value:
            # A job runs under its own stage's approval only: no other stage's approval is reused (D146).
            raise StoreConflict(f"a {job.kind.value} job must reference an {job.kind.value} approval, not "
                                f"{approval.stage.value}")
        target_table = "app_group_assignments" if job.kind is JobKind.OKTA_UNASSIGN else "ad_groups"
        for target in job.targets:
            if self._one(f"SELECT 1 FROM {target_table} WHERE id = ?", (target,)) is None:
                raise StoreConflict(f"job target {target} is not recorded")
        _insert(self._conn, "execution_jobs", {
            "id": job.id, "candidate_id": job.candidate_id, "kind": job.kind.value, "execution_mode": job.mode.value,
            "dry_run": codec.flag(job.dry_run), "requested_by_kind": job.requested_by.kind.value,
            "requested_by_id": job.requested_by.id, "requested_at": ts(job.requested_at), "approval_id": job.approval_id,
            "evidence_fingerprint": job.evidence_fingerprint, "recorded_at": ts(self._now()),
        })
        for target in job.targets:
            _insert(self._conn, "execution_job_targets", {"job_id": job.id, "target_id": target})

    @staticmethod
    def _check_job_update(previous: ExecutionJob, job: ExecutionJob) -> None:
        for name in ("candidate_id", "kind", "mode", "dry_run", "requested_by", "requested_at", "approval_id",
                     "evidence_fingerprint"):
            if getattr(previous, name) != getattr(job, name):
                raise StoreConflict(f"job {job.id} {name} cannot change after it is recorded")
        if set(previous.targets) != set(job.targets):
            raise StoreConflict(f"job {job.id} targets cannot change after it is recorded")
        if previous.status in FINISHED_STATUSES:
            raise StoreConflict(f"job {job.id} has finished ({previous.status.value}); its status is final")
        if job.status not in _JOB_PROGRESSION[previous.status]:
            raise StoreConflict(f"job {job.id} cannot move from {previous.status.value} to {job.status.value}")

    def job_status_history(self, job_id: str) -> list[JobStatusEvent]:
        rows = self._conn.execute(
            "SELECT * FROM execution_job_status_events WHERE job_id = ? ORDER BY sequence", (job_id,)
        ).fetchall()
        return [
            JobStatusEvent(r["sequence"], JobStatus(r["status"]), codec.unflag(r["executed"]),
                           codec.unflag(r["targets_synthetic"]), parse_ts(r["finished_at"]), r["external_ref"],
                           r["detail"], parse_ts(r["recorded_at"]))
            for r in rows
        ]

    def load_execution_job(self, job_id: str) -> ExecutionJob | None:
        """The job as of its latest recorded status."""
        row = self._one("SELECT * FROM execution_jobs WHERE id = ?", (job_id,))
        if row is None:
            return None
        history = self.job_status_history(job_id)
        if not history:
            raise StoreIntegrityError(f"job {job_id} has no status history")
        latest = history[-1]
        targets = self._conn.execute(
            "SELECT target_id FROM execution_job_targets WHERE job_id = ? ORDER BY target_id", (job_id,)
        ).fetchall()
        try:
            return ExecutionJob(
                id=row["id"], candidate_id=row["candidate_id"], kind=JobKind(row["kind"]),
                mode=ExecutionMode(row["execution_mode"]), dry_run=codec.unflag(row["dry_run"]), status=latest.status,
                requested_by=_actor(row, "requested_by"), requested_at=parse_ts(row["requested_at"]),
                approval_id=row["approval_id"], evidence_fingerprint=row["evidence_fingerprint"],
                targets=tuple(t["target_id"] for t in targets), executed=latest.executed,
                targets_synthetic=latest.targets_synthetic, finished_at=latest.finished_at,
            )
        except (InvalidRecord, ValueError) as exc:
            raise StoreIntegrityError(f"stored job {job_id} is invalid: {exc}") from None

    # --- synthetic seeding -------------------------------------------------------------

    def record_synthetic_seed(self, *, actor: Actor, namespace: str, scenario_count: int, as_of: datetime,
                              directory: DirectorySnapshot | None = None) -> None:
        """Audit that a synthetic seed was loaded. Only a SYNTHETIC store accepts it.

        With ``directory``, the seed's directory snapshot (0012) is written in the same
        transaction, and the audit event carries its record count and content digest. A
        store holds at most one snapshot.
        """
        if self.marker.environment is not DatabaseEnvironment.SYNTHETIC:
            raise EnvironmentRefused("only a SYNTHETIC store can record a synthetic seed")
        details: dict[str, object] = {"namespace": namespace, "scenarios": scenario_count, "as_of": ts(as_of)}
        snapshot_id = None
        if directory is not None:
            if self.synthetic_directory() is not None:
                raise StoreConflict("this store already holds a synthetic directory snapshot")
            snapshot_id = new_id(IdKind.SYNTHETIC_DIRECTORY)
            details.update({"directory_dataset": directory.dataset, "directory_records": len(directory.records),
                            "directory_digest": directory.digest})
        now = self._now()
        with self._write():
            correlation_id = new_id(IdKind.REQUEST)
            if directory is not None:
                _insert(self._conn, "synthetic_directory_snapshots", {
                    "id": snapshot_id, "singleton": 1, "dataset": directory.dataset, "seed": directory.seed,
                    "company": directory.company, "as_of": ts(directory.as_of), "record_count": len(directory.records),
                    "content_digest": directory.digest, "loaded_at": ts(now), "correlation_id": correlation_id})
                self._conn.executemany(
                    "INSERT INTO synthetic_directory_records (snapshot_id, kind, id, sort_key, ref_a, ref_b, body) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [(snapshot_id, r.kind, r.id, r.sort_key, r.ref_a, r.ref_b, r.body) for r in directory.records])
            self._audit(actor=actor, action=AuditAction.SYNTHETIC_SEED_LOADED, subject_id=self.marker.store_instance_id,
                        details=details, correlation_id=correlation_id,
                        after_ref=f"seed:{namespace}" + (f"+directory:{snapshot_id}" if snapshot_id else ""))

    def _has_directory_tables(self) -> bool:
        # Absent below schema 12 (only a build held at an older schema, in tests, sees that).
        return self._one("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'synthetic_directory_snapshots'") \
            is not None

    def synthetic_directory(self) -> DirectorySnapshotInfo | None:
        if not self._has_directory_tables():
            return None
        row = self._one("SELECT * FROM synthetic_directory_snapshots WHERE singleton = 1")
        if row is None:
            return None
        return DirectorySnapshotInfo(row["id"], row["dataset"], row["seed"], row["company"], parse_ts(row["as_of"]),
                                     row["record_count"], row["content_digest"], parse_ts(row["loaded_at"]))

    def _verify_synthetic_directory(self, events: tuple[AuditEvent, ...]) -> int:
        """The snapshot's records must match its recorded digest, and the audit chain must vouch for it."""
        if not self._has_directory_tables():
            return 0
        info = self.synthetic_directory()
        if info is None:
            if self._one("SELECT 1 FROM synthetic_directory_records LIMIT 1") is not None:
                raise StoreIntegrityError("synthetic directory records exist without a snapshot")
            return 0
        rows = self._conn.execute(
            "SELECT kind, id, sort_key, ref_a, ref_b, body FROM synthetic_directory_records WHERE snapshot_id = ?",
            (info.id,)).fetchall()
        others = self._one("SELECT count(*) AS n FROM synthetic_directory_records WHERE snapshot_id <> ?", (info.id,))
        try:
            records = [SnapshotRecord(r["kind"], r["id"], r["sort_key"], r["ref_a"], r["ref_b"], r["body"]) for r in rows]
        except InvalidRecord as exc:
            raise StoreIntegrityError(f"synthetic directory record is malformed: {exc}") from None
        if others["n"] or len(records) != info.record_count or content_digest(records) != info.content_digest:
            raise StoreIntegrityError("synthetic directory snapshot does not match its recorded digest")
        vouched = [e for e in events if e.action is AuditAction.SYNTHETIC_SEED_LOADED
                   and dict(e.details).get("directory_digest") == info.content_digest]
        if len(vouched) != 1:
            raise StoreIntegrityError("no audit event records the synthetic directory snapshot's digest")
        return len(records)

    # --- verification ------------------------------------------------------------------

    def verify_integrity(self, *, expected_audit_head: str | None = None) -> IntegrityReport:
        """Re-verify migrations, the audit chain, every observation digest, every candidate history, and
        every mapping-review chain, and the policy-version chain."""
        version = verify_applied(self._conn, DIALECT_SQLITE)
        events = self.audit_events()
        try:
            verify_chain(events, expected_head=expected_audit_head)
        except InvalidRecord as exc:
            raise StoreIntegrityError(f"audit chain verification failed: {exc}") from None
        observations = 0
        for spec in SPECS:
            rows = self._conn.execute(
                f"SELECT o.*, a.id AS anchor_id FROM {spec.observation_table} o "
                f"JOIN {spec.anchor_table} a ON a.id = o.{spec.entity_column} ORDER BY o.observation_id"
            ).fetchall()
            for row in rows:
                anchor = self._one(f"SELECT * FROM {spec.anchor_table} WHERE id = ?", (row["anchor_id"],))
                self._build(spec, anchor, row)
                observations += 1
        candidates = self.candidate_ids()
        for candidate_id in candidates:
            self.load_candidate(candidate_id)
        self._verify_mapping_reviews()
        self._verify_policy_versions()
        directory = self._verify_synthetic_directory(events)
        head = self.audit_head()
        report = IntegrityReport(version, self.marker.environment, len(events), head[1] if head else None,
                                 observations, len(candidates), directory)
        if self.read_only:
            self._verified = ((head, self._conn.total_changes), report)
        return report

    def verified_integrity(self) -> IntegrityReport:
        """``verify_integrity``'s report, re-verified only when the store could have changed.

        A read-only store (``read_only``: the hosted demo's in-memory image) keeps the report of its
        last full verification while its audit head and its connection's row-change count are still
        what they were then: nothing else can write that copy. Any other store is verified in full on
        every call, and a failed verification is never kept. Operator checks call ``verify_integrity``."""
        if self._verified and self.read_only and self._verified[0] == (self.audit_head(), self._conn.total_changes):
            return self._verified[1]
        return self.verify_integrity()
