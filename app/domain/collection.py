"""Collector runs: one execution of a read-only discovery collector.

A run is recorded when it starts and given exactly one outcome when it finishes. The
outcome says whether the run completed, and if not, why (timeout, rate limiting, ...),
so incomplete evidence is visible rather than silently missing. Error summaries are
short and redacted; full API responses are never recorded.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.core.modes import ExecutionMode, assert_mode_permitted_by_build
from app.core.redaction import redact_text
from app.domain.actors import Actor
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.ids import IdKind, check_enum, check_id, check_text, check_utc

MAX_ERROR_SUMMARY = 300


class CollectorErrorCode(StrEnum):
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    HTTP_ERROR = "HTTP_ERROR"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    PAGING_INTERRUPTED = "PAGING_INTERRUPTED"
    DOMAIN_UNREACHABLE = "DOMAIN_UNREACHABLE"
    OTHER = "OTHER"


@dataclass(frozen=True)
class CollectorRun:
    id: str
    collector: str  # e.g. "okta-usage"
    collector_version: str
    source: EvidenceSource
    mode: ExecutionMode
    scope: str
    started_at: datetime
    started_by: Actor

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.COLLECTOR_RUN, "id")
        check_text(self.collector, "collector", max_length=100)
        check_text(self.collector_version, "collector_version", max_length=100)
        check_enum(self.source, EvidenceSource, "source")
        check_enum(self.mode, ExecutionMode, "mode")
        assert_mode_permitted_by_build(self.mode)
        check_text(self.scope, "scope", max_length=500)
        check_utc(self.started_at, "started_at")
        if not isinstance(self.started_by, Actor):
            raise InvalidRecord("started_by must be an Actor")


@dataclass(frozen=True)
class CollectorRunOutcome:
    run_id: str
    finished_at: datetime
    status: ResultStatus
    records_observed: int
    error_code: CollectorErrorCode | None = None
    error_summary: str | None = None

    def __post_init__(self) -> None:
        check_id(self.run_id, IdKind.COLLECTOR_RUN, "run_id")
        check_utc(self.finished_at, "finished_at")
        check_enum(self.status, ResultStatus, "status")
        if not isinstance(self.records_observed, int) or isinstance(self.records_observed, bool) or self.records_observed < 0:
            raise InvalidRecord("records_observed must be a non-negative integer")
        if self.error_code is not None:
            check_enum(self.error_code, CollectorErrorCode, "error_code")
        if (self.status is ResultStatus.COMPLETE) != (self.error_code is None):
            raise InvalidRecord("an error_code is required exactly when the run did not complete")
        if self.error_summary is not None:
            check_text(self.error_summary, "error_summary", max_length=MAX_ERROR_SUMMARY)
            if redact_text(self.error_summary) != self.error_summary:
                raise InvalidRecord("error_summary must not contain credential-shaped text")
