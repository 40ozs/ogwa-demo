"""The AD side of correlation: a narrow, read-only identity-lookup port.

Correlation never queries AD itself. It asks an ``ADIdentityDirectory`` for exact-match
lookups. The production implementation will be ``ReportBackedDirectory`` over the P05
worker contract, run by a read-only AAP job: each lookup is one ``ADReadRequest`` with
every membership section switched off, so the worker only resolves identity. P06 wires it
only to synthetic reports (D22); there is no transport to a real directory in this build.

``BoundedLookups`` caps and de-duplicates the lookups of one correlation. When the budget
is spent, further lookups FAIL rather than run, so a correlation can never fan out.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from app.correlation.model import ADIdentity, ADIdentityLookup, LookupStatus
from app.integrations.ad.contract import (
    ADGroupReport,
    ADReadRequest,
    ContractError,
    LookupKind,
    ResolutionStatus,
    parse_group_report,
)

_MAX_ERROR = 300

_STATUS = {
    ResolutionStatus.RESOLVED: LookupStatus.RESOLVED,
    ResolutionStatus.NOT_FOUND: LookupStatus.NOT_FOUND,
    ResolutionStatus.AMBIGUOUS: LookupStatus.AMBIGUOUS,
    ResolutionStatus.INCONCLUSIVE: LookupStatus.INCOMPLETE,
    ResolutionStatus.FAILED: LookupStatus.FAILED,
    ResolutionStatus.INVALID_REQUEST: LookupStatus.FAILED,
}


class ADIdentityDirectory(Protocol):
    def lookup(self, by: LookupKind, value: str, domain: str | None) -> ADIdentityLookup:
        """One exact-match lookup. Must never raise for directory problems; report FAILED instead."""
        ...


def failed_lookup(by: LookupKind, value: str, domain: str | None, observed_at: datetime, error: str) -> ADIdentityLookup:
    return ADIdentityLookup(by=by, value=value, domain=domain, status=LookupStatus.FAILED, observed_at=observed_at,
                            error=error[:_MAX_ERROR])


def identity_lookup_from_report(report: ADGroupReport) -> ADIdentityLookup:
    """The identity part of a worker report: resolution status and candidates only."""
    request = report.request
    if request is None:
        raise ContractError("the report has no request echo; it cannot be matched to a lookup")
    resolution = report.resolution
    candidates = tuple(
        ADIdentity(object_guid=c.object_guid, object_sid=c.object_sid, distinguished_name=c.distinguished_name,
                   sam_account_name=c.sam_account_name, domain=c.domain.lower())
        for c in resolution.candidates
    )
    status = _STATUS[resolution.status]
    if status is LookupStatus.RESOLVED and len(candidates) != 1:
        status, candidates = LookupStatus.FAILED, ()
    return ADIdentityLookup(
        by=request.by, value=request.value, domain=request.domain, status=status, observed_at=report.observed_at,
        candidates=candidates if status is not LookupStatus.FAILED else (),
        candidates_truncated=resolution.candidates_truncated,
        searched_domains=tuple(d.lower() for d in resolution.searched_domains),
        unsearched_domains=tuple(d.lower() for d in resolution.unsearched_domains),
        error=(resolution.error or None) and resolution.error[:_MAX_ERROR],
    )


class ReportBackedDirectory:
    """Identity lookups through the P05 worker contract.

    ``run_worker`` takes the request JSON and returns the report JSON. In production it
    will launch the approved read-only AAP job template; no such job exists yet (P05 §7),
    and P06 passes only synthetic reports.
    """

    def __init__(self, run_worker: Callable[[str], str], *, clock: Callable[[], datetime], max_candidates: int = 10) -> None:
        self._run_worker = run_worker
        self._clock = clock
        self._max_candidates = max_candidates

    def request_for(self, by: LookupKind, value: str, domain: str | None) -> ADReadRequest:
        return ADReadRequest(
            by=by, value=value, domain=domain,
            include_direct_members=False, include_nested_members=False,
            include_primary_group_references=False, include_member_of=False,
            limits={"maxAmbiguousCandidates": self._max_candidates},
        )

    def lookup(self, by: LookupKind, value: str, domain: str | None) -> ADIdentityLookup:
        try:
            request = self.request_for(by, value, domain)
        except ContractError as exc:
            return failed_lookup(by, value[:1024] or "-", None, self._clock(), f"request refused: {exc}")
        try:
            report = parse_group_report(self._run_worker(request.to_json()))
        except ContractError as exc:
            return failed_lookup(request.by, request.value, request.domain, self._clock(), f"unusable worker report: {exc}")
        except Exception as exc:  # the worker transport failed; never guess an answer
            return failed_lookup(request.by, request.value, request.domain, self._clock(),
                                 f"worker did not answer: {type(exc).__name__}")
        echo = report.request
        if echo is None or (echo.by, echo.value, echo.domain) != (request.by, request.value, request.domain):
            return failed_lookup(request.by, request.value, request.domain, report.observed_at,
                                 "worker report answers a different lookup")
        return identity_lookup_from_report(report)


class BoundedLookups:
    """The lookups of one correlation: de-duplicated, counted, and capped."""

    def __init__(self, directory: ADIdentityDirectory, *, max_lookups: int, clock: Callable[[], datetime]) -> None:
        self._directory = directory
        self._max = max_lookups
        self._clock = clock
        self._cache: dict[tuple[LookupKind, str, str | None], ADIdentityLookup] = {}
        self.performed = 0  # lookups sent to the directory
        self.refused = 0  # lookups refused because the budget was spent
        self.results: list[ADIdentityLookup] = []  # every distinct answer, in order

    def lookup(self, by: LookupKind, value: str, domain: str | None = None) -> ADIdentityLookup:
        key = (by, value.lower() if by in (LookupKind.OBJECT_GUID, LookupKind.OBJECT_SID) else value, domain)
        if key in self._cache:
            return self._cache[key]
        if self.performed >= self._max:
            self.refused += 1
            result = failed_lookup(by, value, domain, self._clock(), "lookup budget for this correlation is exhausted")
        else:
            self.performed += 1
            try:
                result = self._directory.lookup(by, value, domain)
            except Exception as exc:  # a misbehaving port is a failed lookup, never an answer
                result = failed_lookup(by, value, domain, self._clock(), f"directory raised {type(exc).__name__}")
            if not isinstance(result, ADIdentityLookup) or (result.by, result.domain) != (by, domain) \
                    or result.value.casefold() != value.casefold():
                result = failed_lookup(by, value, domain, self._clock(), "directory answered a different lookup")
        self._cache[key] = result
        self.results.append(result)
        return result
