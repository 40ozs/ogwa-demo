"""Turn normalized Okta results into domain evidence and collector-run outcomes.

This is the only place where Okta results become ``app.domain`` records. Rules:

- Provenance is COMPLETE only when the listing or collection that produced the record
  was complete. Anything less is PARTIAL or FAILED, so it can never drive a decision (E-2).
- Assignment absence (``present=False``) is emitted only from a COMPLETE listing. A
  group missing from a partial listing proves nothing.
- Internal ids are derived deterministically from the Okta org and the external id
  (``StableIdResolver``), so re-observing an object yields the same record id.
"""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.domain.collection import MAX_ERROR_SUMMARY, CollectorErrorCode, CollectorRunOutcome
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.ids import IdKind, check_text
from app.domain.model import (
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    OktaApplication,
    OktaAppStatus,
    OktaGroup,
    OktaGroupType,
)
from app.integrations.okta.client import COLLECTOR_VERSION, OktaReadOnlyClient
from app.integrations.okta.models import Listing, Lookup, OktaAppGroupAssignmentRecord, OktaAppRecord, OktaGroupRecord
from app.integrations.okta.normalize import OBJECT_GUID_DECODING_VERIFIED
from app.integrations.okta.usage import ApplicationUsageEvidence, UsageCollection


class StableIdResolver:
    """Internal ids derived from (Okta org, kind, external key). Same input, same id."""

    def __init__(self, namespace: str) -> None:
        self._namespace = check_text(namespace, "namespace", max_length=255).lower()

    def id_for(self, kind: IdKind, external_key: str) -> str:
        check_text(external_key, "external_key", max_length=300)
        digest = hashlib.sha256(f"{self._namespace}|{kind.value}|{external_key}".encode()).hexdigest()
        return f"{kind.value}_{digest[:32]}"

    def application(self, okta_app_id: str) -> str:
        return self.id_for(IdKind.OKTA_APPLICATION, okta_app_id)

    def group(self, okta_group_id: str) -> str:
        return self.id_for(IdKind.OKTA_GROUP, okta_group_id)

    def assignment(self, okta_app_id: str, okta_group_id: str) -> str:
        return self.id_for(IdKind.ASSIGNMENT, f"{okta_app_id}:{okta_group_id}")

    def usage(self, okta_app_id: str) -> str:
        return self.id_for(IdKind.USAGE_OBSERVATION, f"{okta_app_id}:*")


def _provenance(source: EvidenceSource, observed_at: datetime, scope: str, status: ResultStatus) -> Provenance:
    return Provenance(source=source, observed_at=observed_at, scope=scope[:500],
                      collector_version=COLLECTOR_VERSION, result_status=status)


def application_evidence(record: OktaAppRecord, *, ids: StableIdResolver, observed_at: datetime,
                         scope: str, status: ResultStatus) -> OktaApplication:
    return OktaApplication(
        id=ids.application(record.okta_app_id),
        okta_app_id=record.okta_app_id,
        label=(record.label or record.okta_app_id)[:200],  # display-only, not material
        status=OktaAppStatus(record.status.value),
        sign_on_mode=(record.sign_on_mode or "UNKNOWN")[:100],
        provenance=_provenance(EvidenceSource.OKTA_API, observed_at, scope, status),
    )


def group_evidence(record: OktaGroupRecord, *, ids: StableIdResolver, observed_at: datetime,
                   scope: str, status: ResultStatus) -> OktaGroup:
    group_type = OktaGroupType(record.group_type.value)
    directory = {}
    if group_type is OktaGroupType.APP_GROUP:
        directory = dict(
            source_directory_id=record.source_app_id,
            # The decoded objectGUID only once its decoding is verified (P11). Until then,
            # and for an externalId in an unrecognised format, it is left out rather than
            # stored as if it were a stable AD identifier.
            directory_external_id=record.directory_object_guid_unverified if OBJECT_GUID_DECODING_VERIFIED else None,
            directory_qualified_name=record.directory_qualified_name[:300] if record.directory_qualified_name else None,
            # profile.objectSid, kept as unverified source metadata (migration 0008). Until P11
            # verifies the mechanism it can corroborate a mapping, never establish one (D37).
            directory_object_sid_unverified=record.directory_object_sid,
        )
    return OktaGroup(
        id=ids.group(record.okta_group_id), okta_group_id=record.okta_group_id, name=record.name[:300],
        group_type=group_type, provenance=_provenance(EvidenceSource.OKTA_API, observed_at, scope, status),
        **directory,
    )


def assignment_evidence(
    listing: Listing[OktaAppGroupAssignmentRecord],
    okta_app_id: str,
    *,
    ids: StableIdResolver,
    observed_at: datetime,
    previously_present: Iterable[str] = (),
) -> list[ApplicationGroupAssignment]:
    """Presence for each listed group; absence for previously present groups, but only
    when the listing is COMPLETE."""
    status = listing.status
    present = {r.okta_group_id for r in listing.items}
    records = [
        ApplicationGroupAssignment(
            id=ids.assignment(okta_app_id, group_id), application_id=ids.application(okta_app_id),
            okta_group_id=ids.group(group_id), present=True,
            provenance=_provenance(EvidenceSource.OKTA_API, observed_at, listing.scope, status),
        )
        for group_id in sorted(present)
    ]
    if listing.complete:
        for group_id in sorted(set(previously_present) - present):
            records.append(ApplicationGroupAssignment(
                id=ids.assignment(okta_app_id, group_id), application_id=ids.application(okta_app_id),
                okta_group_id=ids.group(group_id), present=False,
                provenance=_provenance(EvidenceSource.OKTA_API, observed_at, listing.scope, status),
            ))
    return records


def usage_evidence(usage: ApplicationUsageEvidence, *, ids: StableIdResolver,
                   observed_at: datetime) -> ApplicationUsageObservation:
    days = (usage.window_end - usage.window_start).days
    status = ResultStatus.COMPLETE if usage.evidence_complete else ResultStatus.PARTIAL
    return ApplicationUsageObservation(
        id=ids.usage(usage.okta_app_id), application_id=ids.application(usage.okta_app_id), okta_group_id=None,
        window_start=usage.window_start, window_end=usage.window_end, event_count=usage.sign_in_count,
        distinct_user_count=usage.unique_user_count, last_activity_at=usage.last_observed_sign_in,
        provenance=_provenance(EvidenceSource.OKTA_SYSTEM_LOG, observed_at,
                               f"okta:logs:sso:app:{usage.okta_app_id}:{days}d", status),
    )


# --- collector run summaries ---------------------------------------------------------


@dataclass(frozen=True)
class CollectorRunSummary:
    """What one collector session did. Counts and codes only; no payloads or identifiers."""

    collector: str
    collector_version: str
    started_at: datetime
    finished_at: datetime
    status: ResultStatus
    records_observed: int
    results_total: int
    results_complete: int
    requests_attempted: int
    request_budget: int
    retries: int
    rate_limited_responses: int
    server_errors: int
    transport_errors: int
    throttle_pauses: int
    waited_seconds: float
    halted: bool
    error_code: CollectorErrorCode | None
    error_summary: str | None

    def to_outcome(self, run_id: str) -> CollectorRunOutcome:
        return CollectorRunOutcome(
            run_id=run_id, finished_at=self.finished_at, status=self.status,
            records_observed=self.records_observed,
            error_code=None if self.status is ResultStatus.COMPLETE else (self.error_code or CollectorErrorCode.OTHER),
            error_summary=None if self.status is ResultStatus.COMPLETE else self.error_summary,
        )


Result = Listing | Lookup | UsageCollection


def _result_facts(result: Result) -> tuple[ResultStatus, int, CollectorErrorCode | None, str | None]:
    if isinstance(result, Listing):
        return result.status, result.record_count, result.error_code, result.error_summary
    if isinstance(result, Lookup):
        return result.status, int(result.found), result.error_code, result.error_summary
    if isinstance(result, UsageCollection):
        failing = next((s for s in result.slices if s.status is not ResultStatus.COMPLETE), None)
        reasons = next((e.incomplete_reasons[0] for e in result.evidence if e.incomplete_reasons), None)
        code = failing.error_code if failing else (None if result.status is ResultStatus.COMPLETE else CollectorErrorCode.OTHER)
        return result.status, len(result.evidence), code, (failing.error_summary if failing else reasons)
    raise TypeError(f"unsupported result type {type(result).__name__}")


def summarize_run(client: OktaReadOnlyClient, *, collector: str, started_at: datetime, finished_at: datetime,
                  results: Iterable[Result]) -> CollectorRunSummary:
    facts = [_result_facts(r) for r in results]
    statuses = [f[0] for f in facts]
    halted = client.halted
    if facts and all(s is ResultStatus.COMPLETE for s in statuses) and halted is None:
        status = ResultStatus.COMPLETE
    elif facts and all(s is ResultStatus.FAILED for s in statuses):
        status = ResultStatus.FAILED
    elif not facts:
        status = ResultStatus.FAILED
    else:
        status = ResultStatus.PARTIAL
    first_problem = next((f for f in facts if f[0] is not ResultStatus.COMPLETE), None)
    code = halted.code if halted is not None else (first_problem[2] if first_problem else None)
    summary = str(halted) if halted is not None else (first_problem[3] if first_problem else None)
    if status is not ResultStatus.COMPLETE and summary is None:
        summary = "no results were collected" if not facts else "one or more results were incomplete"
    stats = client.stats
    return CollectorRunSummary(
        collector=collector, collector_version=COLLECTOR_VERSION, started_at=started_at, finished_at=finished_at,
        status=status, records_observed=sum(f[1] for f in facts), results_total=len(facts),
        results_complete=sum(s is ResultStatus.COMPLETE for s in statuses),
        requests_attempted=stats.attempts, request_budget=client.pacing.max_requests, retries=stats.retries,
        rate_limited_responses=stats.rate_limited_responses, server_errors=stats.server_errors,
        transport_errors=stats.transport_errors, throttle_pauses=stats.throttle_pauses,
        waited_seconds=round(stats.waited_seconds, 3), halted=halted is not None,
        error_code=None if status is ResultStatus.COMPLETE else code,
        error_summary=None if status is ResultStatus.COMPLETE else (summary or "")[:MAX_ERROR_SUMMARY] or None,
    )
