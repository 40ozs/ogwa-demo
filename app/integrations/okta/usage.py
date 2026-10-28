"""Application usage from the Okta System Log, in bounded windows.

Usage evidence is **counts only**: sign-in events, distinct users, the latest observed
sign-in, and whether the evidence is complete. User ids are held in memory only to count
distinct users, and never leave this module.

Zero observed sign-ins is **not** evidence that an application is unused or safe to
retire. ``USAGE_CAVEATS`` lists why. The lifecycle policy, human review, and dependency
evidence decide; this module only observes.

The requested window is split into slices (``chunk``) so that a failure affects only the
slices it touches and is visible per application. Evidence is complete only when every
slice for the application completed, the window lies inside System Log retention and
outside the ingestion lag, and no event was unreadable.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from app.domain.collection import CollectorErrorCode
from app.domain.evidence import ResultStatus
from app.integrations.okta.client import OktaReadOnlyClient, okta_timestamp
from app.integrations.okta.normalize import SsoEvent, is_okta_id

# Okta documents about 90 days of System Log retention. An older window start cannot be
# fully observed.
SYSTEM_LOG_RETENTION = timedelta(days=90)
# Events can take a short time to become queryable. A window ending this close to "now"
# may be missing its newest events.
INGESTION_LAG = timedelta(minutes=10)
DEFAULT_CHUNK = timedelta(days=7)
# The lifecycle's retirement window (LifecyclePolicy.min_usage_window). Decision D27: it
# stays 90 days. Native System Log retention cannot satisfy it on its own.
RETIREMENT_USAGE_WINDOW = timedelta(days=90)
MIN_CHUNK = timedelta(hours=1)
MAX_APPS_PER_COLLECTION = 500

USAGE_CAVEATS: tuple[str, ...] = (
    "Counts only successful user.authentication.sso events. API-only, provisioning, "
    "service-account, bookmark/SWA, and token-refresh use may produce no such event.",
    "Zero observed sign-ins is not evidence that the application is unused or safe to retire.",
    "Sign-ins outside Okta (local accounts, other IdPs) are invisible here.",
)


class UsageSignal(StrEnum):
    """What one usage record can support. It is never an authorization to retire."""

    # Incomplete evidence. It supports nothing beyond "collect again".
    INCOMPLETE = "INCOMPLETE"
    # Complete, but shorter than the retirement window. It may prompt a low-usage review
    # and cannot satisfy the 90-day retirement requirement.
    REVIEW_SIGNAL_ONLY = "REVIEW_SIGNAL_ONLY"
    # Complete over the full retirement window. Native retention alone cannot produce
    # this (a 90-day window always starts before the horizon once the ingestion lag is
    # cleared). It needs a longer-retention source, which is not implemented.
    COVERS_RETIREMENT_WINDOW = "COVERS_RETIREMENT_WINDOW"


class UsageStrategy(StrEnum):
    # One filtered query per application per slice (target.id eq "<app>"). Narrow and
    # cheap per app; the default for bounded probes and small sets.
    PER_APPLICATION = "PER_APPLICATION"
    # One org-wide SSO stream per slice, aggregated for the requested apps. Fewer
    # requests for many apps, but every page carries other apps' events. Reserved for
    # the full collection (P11) once a bounded probe has proven it safe.
    ORG_WIDE = "ORG_WIDE"


@dataclass(frozen=True)
class SliceResult:
    window_start: datetime
    window_end: datetime
    okta_app_id: str | None  # None for an org-wide slice
    status: ResultStatus
    pages: int
    events: int
    error_code: CollectorErrorCode | None = None
    error_summary: str | None = None


@dataclass(frozen=True)
class ApplicationUsageEvidence:
    okta_app_id: str
    window_start: datetime
    window_end: datetime
    sign_in_count: int
    unique_user_count: int
    last_observed_sign_in: datetime | None
    evidence_complete: bool
    incomplete_reasons: tuple[str, ...]
    slices_complete: int
    slices_total: int
    caveats: tuple[str, ...] = field(default=USAGE_CAVEATS)

    @property
    def signal(self) -> UsageSignal:
        if not self.evidence_complete:
            return UsageSignal.INCOMPLETE
        if self.window_end - self.window_start < RETIREMENT_USAGE_WINDOW:
            return UsageSignal.REVIEW_SIGNAL_ONLY
        return UsageSignal.COVERS_RETIREMENT_WINDOW


@dataclass(frozen=True)
class UsageCollection:
    window_start: datetime
    window_end: datetime
    strategy: UsageStrategy
    evidence: tuple[ApplicationUsageEvidence, ...]
    slices: tuple[SliceResult, ...]
    events_scanned: int
    events_unattributed: int  # events with no requested AppInstance target
    malformed_events: int

    @property
    def status(self) -> ResultStatus:
        if all(e.evidence_complete for e in self.evidence):
            return ResultStatus.COMPLETE
        if any(s.status is not ResultStatus.FAILED for s in self.slices):
            return ResultStatus.PARTIAL
        return ResultStatus.FAILED

    def for_app(self, okta_app_id: str) -> ApplicationUsageEvidence | None:
        return next((e for e in self.evidence if e.okta_app_id == okta_app_id), None)


class _Tally:
    __slots__ = ("count", "users", "last", "missing_actor", "out_of_window", "reasons", "slices_ok", "slices")

    def __init__(self) -> None:
        self.count = 0
        self.users: set[str] = set()
        self.last: datetime | None = None
        self.missing_actor = 0
        self.out_of_window = 0
        self.reasons: list[str] = []
        self.slices_ok = 0
        self.slices = 0


def slice_window(start: datetime, end: datetime, chunk: timedelta) -> list[tuple[datetime, datetime]]:
    if chunk < MIN_CHUNK:
        raise ValueError(f"chunk must be at least {MIN_CHUNK}")
    slices, cursor = [], start
    while cursor < end:
        upper = min(cursor + chunk, end)
        slices.append((cursor, upper))
        cursor = upper
    return slices


def window_limitations(start: datetime, end: datetime, now: datetime, *,
                       retention: timedelta = SYSTEM_LOG_RETENTION,
                       ingestion_lag: timedelta = INGESTION_LAG) -> list[str]:
    """Reasons a window cannot be observed completely at ``now``; empty if it can."""
    reasons = []
    if start < now - retention:
        reasons.append(f"window starts before the System Log retention horizon ({retention.days} days); "
                       "older sign-ins cannot be observed")
    if end > now - ingestion_lag:
        reasons.append(f"window ends within the System Log ingestion lag ({ingestion_lag}); "
                       "the newest events may be missing")
    return reasons


def collect_application_usage(
    client: OktaReadOnlyClient,
    okta_app_ids: Iterable[str],
    window_start: datetime,
    window_end: datetime,
    *,
    now: datetime,
    chunk: timedelta = DEFAULT_CHUNK,
    strategy: UsageStrategy = UsageStrategy.PER_APPLICATION,
    retention: timedelta = SYSTEM_LOG_RETENTION,
    ingestion_lag: timedelta = INGESTION_LAG,
) -> UsageCollection:
    app_ids = tuple(dict.fromkeys(okta_app_ids))
    if not app_ids:
        raise ValueError("at least one application id is required")
    if len(app_ids) > MAX_APPS_PER_COLLECTION:
        raise ValueError(f"at most {MAX_APPS_PER_COLLECTION} applications per collection")
    for app_id in app_ids:
        if not is_okta_id(app_id):
            raise ValueError("application ids must be Okta ids")
    for value in (window_start, window_end, now):
        if value.utcoffset() is None:
            raise ValueError("window bounds and now must be timezone-aware")
    if window_end <= window_start:
        raise ValueError("window_end must be after window_start")
    if window_end > now:
        raise ValueError("window_end must not be in the future")

    tallies = {app_id: _Tally() for app_id in app_ids}
    limitations = window_limitations(window_start, window_end, now, retention=retention, ingestion_lag=ingestion_lag)
    for tally in tallies.values():
        tally.reasons.extend(limitations)

    counters = {"scanned": 0, "unattributed": 0}
    slices: list[SliceResult] = []

    def sink_for(lo: datetime, hi: datetime, wanted: frozenset[str]):
        def sink(event: SsoEvent) -> None:
            counters["scanned"] += 1
            hits = [a for a in event.app_ids if a in wanted]
            if not hits:
                counters["unattributed"] += 1
                return
            for app_id in dict.fromkeys(hits):
                tally = tallies[app_id]
                if not lo <= event.published < hi:
                    tally.out_of_window += 1
                    continue
                tally.count += 1
                if event.actor_id is None:
                    tally.missing_actor += 1
                else:
                    tally.users.add(event.actor_id)
                if tally.last is None or event.published > tally.last:
                    tally.last = event.published
        return sink

    malformed = 0
    for lo, hi in slice_window(window_start, window_end, chunk):
        targets = [(a, frozenset({a})) for a in app_ids] if strategy is UsageStrategy.PER_APPLICATION \
            else [(None, frozenset(app_ids))]
        for app_filter, wanted in targets:
            listing = client.stream_sso_events(lo, hi, sink_for(lo, hi, wanted), app_id=app_filter)
            malformed += listing.malformed_records
            slices.append(SliceResult(lo, hi, app_filter, listing.status, listing.pages, listing.record_count,
                                      listing.error_code, listing.error_summary))
            for app_id in wanted:
                tally = tallies[app_id]
                tally.slices += 1
                if listing.complete:
                    tally.slices_ok += 1
                else:
                    span = f"{okta_timestamp(lo)}/{okta_timestamp(hi)}"
                    tally.reasons.append(f"slice {span} is {listing.status.value}: "
                                         f"{listing.error_summary or listing.stop_reason or 'incomplete'}")

    evidence = []
    for app_id, tally in tallies.items():
        reasons = list(tally.reasons)
        if tally.missing_actor:
            reasons.append(f"{tally.missing_actor} event(s) had no actor id; unique_user_count is a lower bound")
        if tally.out_of_window:
            reasons.append(f"{tally.out_of_window} event(s) fell outside the requested slice and were not counted")
        evidence.append(ApplicationUsageEvidence(
            okta_app_id=app_id, window_start=window_start, window_end=window_end,
            sign_in_count=tally.count, unique_user_count=len(tally.users), last_observed_sign_in=tally.last,
            evidence_complete=not reasons, incomplete_reasons=tuple(reasons),
            slices_complete=tally.slices_ok, slices_total=tally.slices,
        ))
    return UsageCollection(
        window_start=window_start, window_end=window_end, strategy=strategy, evidence=tuple(evidence),
        slices=tuple(slices), events_scanned=counters["scanned"], events_unattributed=counters["unattributed"],
        malformed_events=malformed,
    )
