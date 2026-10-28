"""Execution job records.

An ``ExecutionJob`` records a planned or performed change for a candidate. In this build
a job can only be a dry run or a synthetic-target execution: a record claiming a real
production change cannot be constructed. This mirrors ``MutationCapableService._perform``
in app/core/safety.py.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.core.modes import ExecutionMode, assert_mode_permitted_by_build
from app.domain.actors import Actor
from app.domain.errors import InvalidRecord
from app.domain.evidence import check_digest
from app.domain.ids import IdKind, check_enum, check_id, check_utc


class JobKind(StrEnum):
    OKTA_UNASSIGN = "OKTA_UNASSIGN"
    AD_RETIREMENT = "AD_RETIREMENT"  # legacy (D148): history only; no new job may use it
    AD_QUARANTINE = "AD_QUARANTINE"  # move the AD group into its quarantine OU (P10B)
    AD_DELETION = "AD_DELETION"  # delete the quarantined AD group (P10B)


# Kinds whose stored jobs are history only. Recording a new one is refused (D148).
LEGACY_JOB_KINDS = frozenset({JobKind.AD_RETIREMENT})
AD_JOB_KINDS = frozenset({JobKind.AD_RETIREMENT, JobKind.AD_QUARANTINE, JobKind.AD_DELETION})


class JobStatus(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REFUSED = "REFUSED"


FINISHED_STATUSES = frozenset({JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.REFUSED})
# The modes that may record a mutation job. READ_ONLY_PRODUCTION cannot plan mutations,
# and PRODUCTION_MUTATION is refused by the build check below.
JOB_MODES = frozenset({ExecutionMode.LOCAL_SYNTHETIC, ExecutionMode.DRY_RUN_MUTATION})


@dataclass(frozen=True)
class ExecutionJob:
    id: str
    candidate_id: str
    kind: JobKind
    mode: ExecutionMode
    dry_run: bool
    status: JobStatus
    requested_by: Actor
    requested_at: datetime
    approval_id: str
    evidence_fingerprint: str
    targets: tuple[str, ...]  # internal ids: assignment ids (OKTA_UNASSIGN) or the AD group id
    executed: bool = False
    targets_synthetic: bool = False
    finished_at: datetime | None = None

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.EXECUTION_JOB, "id")
        check_id(self.candidate_id, IdKind.CANDIDATE, "candidate_id")
        check_enum(self.kind, JobKind, "kind")
        check_enum(self.mode, ExecutionMode, "mode")
        assert_mode_permitted_by_build(self.mode)
        if self.mode not in JOB_MODES:
            raise InvalidRecord(f"{self.mode.value} cannot record a mutation job")
        check_enum(self.status, JobStatus, "status")
        if not isinstance(self.requested_by, Actor):
            raise InvalidRecord("requested_by must be an Actor")
        check_utc(self.requested_at, "requested_at")
        check_id(self.approval_id, IdKind.APPROVAL, "approval_id")
        check_digest(self.evidence_fingerprint, "evidence_fingerprint")
        if not isinstance(self.targets, tuple) or not self.targets or len(set(self.targets)) != len(self.targets):
            raise InvalidRecord("targets must be a non-empty tuple without duplicates")
        target_kind = IdKind.AD_GROUP if self.kind in AD_JOB_KINDS else IdKind.ASSIGNMENT
        for target in self.targets:
            check_id(target, target_kind, "targets")
        if self.kind in AD_JOB_KINDS and len(self.targets) != 1:
            raise InvalidRecord(f"an {self.kind.value} job targets exactly one AD group")
        for name in ("dry_run", "executed", "targets_synthetic"):
            if not isinstance(getattr(self, name), bool):
                raise InvalidRecord(f"{name} must be a bool")
        if self.mode is ExecutionMode.DRY_RUN_MUTATION and not self.dry_run:
            raise InvalidRecord("DRY_RUN_MUTATION jobs must be dry runs")
        if self.dry_run and self.executed:
            raise InvalidRecord("a dry run cannot have executed")
        if self.executed and not (self.mode is ExecutionMode.LOCAL_SYNTHETIC and self.targets_synthetic):
            raise InvalidRecord("this build only records executions against synthetic targets")
        if self.executed and self.status is not JobStatus.SUCCEEDED:
            raise InvalidRecord("executed is only valid on a SUCCEEDED job")
        if self.status in FINISHED_STATUSES:
            check_utc(self.finished_at, "finished_at")
            if self.finished_at < self.requested_at:
                raise InvalidRecord("finished_at cannot be before requested_at")
        elif self.finished_at is not None:
            raise InvalidRecord(f"a {self.status.value} job has not finished")
