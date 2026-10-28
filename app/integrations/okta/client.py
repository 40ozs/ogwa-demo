"""Read-only Okta management API client.

Supported, documented endpoints only (no UI scraping), all GET:

| Operation | Endpoint | Scope |
| --- | --- | --- |
| list / get applications | ``/api/v1/apps``, ``/api/v1/apps/{id}`` | okta.apps.read |
| application group assignments | ``/api/v1/apps/{id}/groups`` | okta.apps.read |
| group metadata | ``/api/v1/groups/{id}`` | okta.groups.read |
| group members (id and status only) | ``/api/v1/groups/{id}/users`` | okta.groups.read |
| System Log, bounded window | ``/api/v1/logs?since=…&until=…`` | okta.logs.read |

One client is one collector session: it has one request budget, runs serially, and
stops sending after a halting error (see ``pacing.py``). Every result reports whether
it is complete. A failure partway through a listing yields PARTIAL, never a silently
short COMPLETE.
"""

import json
import logging
import random
import re
import time
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypeVar
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from app.core.config import Settings
from app.core.http_client import HttpPolicy, HttpResponse, ReadOnlyHttpClient, Transport, is_loopback_host
from app.core.modes import ExecutionMode
from app.core.redaction import redact_text
from app.domain.collection import MAX_ERROR_SUMMARY, CollectorErrorCode
from app.domain.evidence import ResultStatus
from app.integrations.okta.auth import (
    SCOPE_APPS_READ,
    SCOPE_GROUPS_READ,
    SCOPE_LOGS_READ,
    OktaCredentialError,
    OktaCredentialProvider,
    authorization_header,
)
from app.integrations.okta.models import (
    AppStatus,
    Listing,
    Lookup,
    OktaAppGroupAssignmentRecord,
    OktaAppRecord,
    OktaGroupMemberRecord,
    OktaGroupRecord,
    StopReason,
)
from app.integrations.okta.normalize import (
    MalformedRecord,
    SsoEvent,
    is_okta_id,
    normalize_app,
    normalize_assignment,
    normalize_group,
    normalize_member,
    normalize_sso_event,
)
from app.integrations.okta.pacing import (
    OktaAuthError,
    OktaBudgetExhausted,
    OktaRateLimited,
    OktaRequestError,
    OktaRequestExecutor,
    OktaTimeout,
    PacingPolicy,
    RequestStats,
)

R = TypeVar("R")

COLLECTOR_VERSION = "okta-readonly/0.1.0"

APPS_PAGE_LIMIT = 200  # Okta's maximum for /api/v1/apps and /apps/{id}/groups
MEMBERS_PAGE_LIMIT = 200
LOG_PAGE_LIMIT = 1000  # Okta's maximum for /api/v1/logs
DEFAULT_MAX_MEMBERS = 2000

SSO_SUCCESS_FILTER = 'eventType eq "user.authentication.sso" and outcome.result eq "SUCCESS"'

_NEXT_LINK_RE = re.compile(r'<([^>]*)>\s*;\s*rel="?next"?', re.IGNORECASE)

_STOP_FOR_ERROR: dict[type, StopReason] = {
    OktaAuthError: StopReason.AUTHENTICATION,
    OktaRateLimited: StopReason.RATE_LIMITED,
    OktaTimeout: StopReason.TIMEOUT,
    OktaBudgetExhausted: StopReason.BUDGET_EXHAUSTED,
}

_log = logging.getLogger("ogwa.okta")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _summary(text: str) -> str:
    return redact_text(text)[:MAX_ERROR_SUMMARY]


def okta_timestamp(value: datetime) -> str:
    """UTC ISO-8601 with milliseconds and a Z suffix, as the System Log expects."""
    if value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _page_key(url: str) -> tuple:
    """A URL's identity for cycle detection: case-folded host, path, and sorted query.

    Cosmetic differences (host case, parameter order) do not hide a repeated page.
    """
    parts = urlsplit(url)
    return (parts.scheme, (parts.hostname or "").lower(), parts.port, parts.path,
            tuple(sorted(parse_qsl(parts.query, keep_blank_values=True))))


def _require_id(value: str, what: str) -> str:
    # Validated before it is placed in a URL path or a filter expression.
    if not is_okta_id(value):
        raise ValueError(f"{what} must be an Okta id (1-64 alphanumeric characters)")
    return value


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of the single-read probe. Holds no object names or identifiers."""

    ok: bool
    http_status: int | None
    items_returned: int
    granted_scopes: tuple[str, ...]
    rate_limit_remaining: int | None
    rate_limit_limit: int | None
    error_summary: str | None


class OktaReadOnlyClient:
    def __init__(
        self,
        *,
        org_url: str,
        mode: ExecutionMode,
        http_policy: HttpPolicy,
        credentials: OktaCredentialProvider,
        pacing: PacingPolicy | None = None,
        transport: Transport | None = None,
        logger: logging.Logger | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
        now: Callable[[], datetime] = _utcnow,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        parts = urlsplit(org_url)
        host = (parts.hostname or "").lower()
        if not host:
            raise ValueError("org_url must be an absolute URL")
        if parts.path.strip("/") or parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("org_url must be a bare origin such as https://<org>.okta.com")
        if parts.scheme != "https" and not (parts.scheme == "http" and is_loopback_host(host)):
            raise ValueError("org_url must use https")
        if credentials is None:
            raise TypeError("credentials are required; see app/integrations/okta/auth.py")
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._origin_key = (parts.scheme, host, parts.port)
        self._credentials = credentials
        self._now = now
        self._log = logger or _log
        self.pacing = pacing or PacingPolicy()
        http = ReadOnlyHttpClient(
            mode=mode,
            http_policy=OktaRequestExecutor.underlying_policy(http_policy),
            allowed_hosts=[host],
            transport=transport,
            logger=logger,
            sleep=sleep,
            rng=rng,
            now=now,
        )
        self._executor = OktaRequestExecutor(
            http=http, pacing=self.pacing, max_retries=http_policy.max_retries, backoff=http_policy,
            sleep=sleep, rng=rng, now=now, monotonic=monotonic,
        )

    @classmethod
    def from_settings(cls, settings: Settings, *, credentials: OktaCredentialProvider, **kwargs: Any) -> "OktaReadOnlyClient":
        if not settings.okta_org_url:
            raise ValueError("OGWA_OKTA_ORG_URL is not configured")
        # OGWA_OKTA_API_TOKEN (SSWS) is deliberately not used here; see auth.py and decision D6.
        return cls(org_url=settings.okta_org_url, mode=settings.mode, http_policy=settings.http,
                   credentials=credentials, **kwargs)

    # --- session state -----------------------------------------------------------------

    @property
    def stats(self) -> RequestStats:
        return self._executor.stats

    @property
    def halted(self) -> OktaRequestError | None:
        return self._executor.halted

    @property
    def budget_remaining(self) -> int:
        return self._executor.budget_remaining

    # --- plumbing ----------------------------------------------------------------------

    def _url(self, path: str, params: dict[str, str] | None = None) -> str:
        return self._origin + path + (f"?{urlencode(params, quote_via=quote)}" if params else "")

    def _authorization(self, scope: str) -> Callable[[], str]:
        def header() -> str:
            try:
                return authorization_header(self._credentials, scope, self._now())
            except OktaCredentialError as exc:
                raise self._executor.halt(OktaAuthError(str(exc))) from None
        return header

    def _get(self, url: str, scope: str, path: str) -> HttpResponse:
        return self._executor.get(url, authorization=self._authorization(scope), path_for_errors=path)

    def _next_link(self, response: HttpResponse, expected_path: str) -> tuple[str | None, bool]:
        """The validated next-page URL (or None), and whether a next link was unsafe."""
        header = response.header("Link")
        if not header:
            return None, False
        match = _NEXT_LINK_RE.search(header)
        if match is None:
            return None, False
        url = match.group(1)
        parts = urlsplit(url)
        same_origin = (parts.scheme, (parts.hostname or "").lower(), parts.port) == self._origin_key
        if not same_origin or parts.path != expected_path or parts.username or parts.password:
            return None, True
        return url, False

    def _paginate(
        self,
        *,
        scope_label: str,
        path: str,
        params: dict[str, str],
        scope: str,
        parse: Callable[[Any], R],
        key: Callable[[R], Hashable] | None = None,
        sink: Callable[[R], None] | None = None,
        max_items: int | None = None,
        stop_on_empty_page: bool = False,
    ) -> Listing[R]:
        items: list[R] = []
        keys: set[Hashable] = set()
        pages = accepted = malformed = duplicates = 0
        visited: set[tuple] = set()
        url: str | None = self._url(path, params)
        stop: StopReason | None = None
        code: CollectorErrorCode | None = None
        summary: str | None = None

        while url is not None:
            page_key = _page_key(url)
            if page_key in visited:
                stop, code, summary = StopReason.UNSAFE_NEXT_LINK, CollectorErrorCode.PAGING_INTERRUPTED, \
                    f"{scope_label}: pagination repeated a page"
                break
            visited.add(page_key)
            try:
                response = self._get(url, scope, path)
            except OktaRequestError as exc:
                stop = _STOP_FOR_ERROR.get(type(exc), StopReason.HTTP_ERROR)
                code, summary = exc.code, _summary(f"{scope_label}: {exc}")
                break
            if response.status == 404:
                stop, code, summary = StopReason.NOT_FOUND, CollectorErrorCode.HTTP_ERROR, \
                    f"{scope_label}: HTTP 404 (the object may have been deleted)"
                break
            try:
                body = json.loads(response.body.decode("utf-8")) if response.body else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                body = None
            if not isinstance(body, list):
                stop, code, summary = StopReason.MALFORMED_PAGE, CollectorErrorCode.PAGING_INTERRUPTED, \
                    f"{scope_label}: page {pages + 1} was not a JSON array"
                break
            pages += 1
            for raw in body:
                try:
                    record = parse(raw)
                except MalformedRecord:
                    malformed += 1
                    continue
                if key is not None:
                    k = key(record)
                    if k in keys:
                        duplicates += 1
                        continue
                    keys.add(k)
                if max_items is not None and accepted >= max_items:
                    stop, code, summary = StopReason.ITEM_LIMIT, CollectorErrorCode.PAGING_INTERRUPTED, \
                        f"{scope_label}: more than {max_items} records; stopped at the limit"
                    break
                accepted += 1
                if sink is not None:
                    sink(record)
                else:
                    items.append(record)
            if stop is not None:
                break
            if stop_on_empty_page and not body:
                break
            url, unsafe = self._next_link(response, path)
            if unsafe:
                stop, code, summary = StopReason.UNSAFE_NEXT_LINK, CollectorErrorCode.PAGING_INTERRUPTED, \
                    f"{scope_label}: next link left the expected origin or endpoint; not followed"

        notes: list[str] = []
        if stop is None and malformed:
            code, summary = CollectorErrorCode.OTHER, f"{scope_label}: {malformed} record(s) could not be parsed"
        if stop is None and duplicates:
            code = code or CollectorErrorCode.PAGING_INTERRUPTED
            notes.append(f"{duplicates} duplicate record(s) across pages; the listing may have changed while paging")
            summary = summary or f"{scope_label}: duplicate records across pages"
        if stop is None and not malformed and not duplicates:
            status = ResultStatus.COMPLETE
        elif pages == 0:
            status = ResultStatus.FAILED
        else:
            status = ResultStatus.PARTIAL
        listing = Listing(
            scope=scope_label, items=tuple(items), status=status, pages=pages, record_count=accepted,
            malformed_records=malformed, duplicates_dropped=duplicates, stop_reason=stop,
            error_code=None if status is ResultStatus.COMPLETE else code,
            error_summary=None if status is ResultStatus.COMPLETE else summary, notes=tuple(notes),
        )
        self._log.info("okta.listing", extra={"ogwa": {
            "scope": scope_label, "status": status.value, "pages": pages, "records": accepted,
            "malformed": malformed, "duplicates": duplicates, "stop_reason": stop.value if stop else None,
        }})
        return listing

    def _lookup(self, *, scope_label: str, path: str, scope: str, parse: Callable[[Any], R]) -> Lookup[R]:
        try:
            response = self._get(self._url(path), scope, path)
        except OktaRequestError as exc:
            return Lookup(scope=scope_label, item=None, found=False, status=ResultStatus.FAILED,
                          error_code=exc.code, error_summary=_summary(f"{scope_label}: {exc}"))
        if response.status == 404:
            return Lookup(scope=scope_label, item=None, found=False, status=ResultStatus.COMPLETE)
        try:
            item = parse(json.loads(response.body.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, MalformedRecord) as exc:
            return Lookup(scope=scope_label, item=None, found=False, status=ResultStatus.FAILED,
                          error_code=CollectorErrorCode.OTHER, error_summary=_summary(f"{scope_label}: unreadable response ({exc})"))
        return Lookup(scope=scope_label, item=item, found=True, status=ResultStatus.COMPLETE)

    # --- applications ------------------------------------------------------------------

    def list_applications(self, *, status: AppStatus | None = None) -> Listing[OktaAppRecord]:
        params = {"limit": str(APPS_PAGE_LIMIT)}
        label = "okta:apps"
        if status is not None:
            params["filter"] = f'status eq "{AppStatus(status).value}"'
            label = f"okta:apps:status={status.value}"
        return self._paginate(scope_label=label, path="/api/v1/apps", params=params, scope=SCOPE_APPS_READ,
                              parse=normalize_app, key=lambda r: r.okta_app_id)

    def get_application(self, app_id: str) -> Lookup[OktaAppRecord]:
        _require_id(app_id, "app_id")
        return self._lookup(scope_label=f"okta:app:{app_id}", path=f"/api/v1/apps/{app_id}",
                            scope=SCOPE_APPS_READ, parse=normalize_app)

    def list_application_group_assignments(
        self, app_id: str, *, expand_groups: bool = False
    ) -> Listing[OktaAppGroupAssignmentRecord]:
        """Groups assigned to one app. ``expand_groups`` embeds group metadata (fewer calls)."""
        _require_id(app_id, "app_id")
        params = {"limit": str(APPS_PAGE_LIMIT)}
        if expand_groups:
            params["expand"] = "group"
        return self._paginate(
            scope_label=f"okta:app:{app_id}:groups", path=f"/api/v1/apps/{app_id}/groups", params=params,
            scope=SCOPE_APPS_READ, parse=lambda raw: normalize_assignment(raw, app_id),
            key=lambda r: r.okta_group_id,
        )

    # --- groups ------------------------------------------------------------------------

    def get_group(self, group_id: str) -> Lookup[OktaGroupRecord]:
        _require_id(group_id, "group_id")
        return self._lookup(scope_label=f"okta:group:{group_id}", path=f"/api/v1/groups/{group_id}",
                            scope=SCOPE_GROUPS_READ, parse=normalize_group)

    def list_group_members(self, group_id: str, *, max_members: int = DEFAULT_MAX_MEMBERS) -> Listing[OktaGroupMemberRecord]:
        """Member user ids and statuses only. Stops PARTIAL above ``max_members``."""
        _require_id(group_id, "group_id")
        if not 1 <= max_members <= 50_000:
            raise ValueError("max_members must be 1..50000")
        return self._paginate(
            scope_label=f"okta:group:{group_id}:members", path=f"/api/v1/groups/{group_id}/users",
            params={"limit": str(MEMBERS_PAGE_LIMIT)}, scope=SCOPE_GROUPS_READ, parse=normalize_member,
            key=lambda r: r.okta_user_id, max_items=max_members,
        )

    # --- System Log ----------------------------------------------------------------------

    def stream_sso_events(
        self,
        window_start: datetime,
        window_end: datetime,
        sink: Callable[[SsoEvent], None],
        *,
        app_id: str | None = None,
    ) -> Listing[SsoEvent]:
        """Stream successful SSO events in [window_start, window_end) to ``sink``, oldest first.

        Bounded query (``since`` and ``until`` both set), so pagination ends. An empty page
        also ends it, even if a next link is present. Events are not kept in memory.
        """
        if window_end <= window_start:
            raise ValueError("window_end must be after window_start")
        filter_expr = SSO_SUCCESS_FILTER
        label = f"okta:logs:sso:{okta_timestamp(window_start)}/{okta_timestamp(window_end)}"
        if app_id is not None:
            _require_id(app_id, "app_id")
            filter_expr += f' and target.id eq "{app_id}"'
            label += f":app:{app_id}"
        params = {
            "since": okta_timestamp(window_start),
            "until": okta_timestamp(window_end),
            "filter": filter_expr,
            "sortOrder": "ASCENDING",
            "limit": str(LOG_PAGE_LIMIT),
        }
        return self._paginate(scope_label=label, path="/api/v1/logs", params=params, scope=SCOPE_LOGS_READ,
                              parse=normalize_sso_event, sink=sink, stop_on_empty_page=True)

    # --- probe ---------------------------------------------------------------------------

    def probe(self) -> ProbeResult:
        """One bounded read (``GET /api/v1/apps?limit=1``) that reports only status and headroom.

        Requires a client whose request budget is exactly 1, so a retry cannot turn the
        probe into more than one request.
        """
        if self.pacing.max_requests != 1 or self.stats.attempts:
            raise ValueError("probe() needs a fresh client built with PacingPolicy(max_requests=1)")
        try:
            scopes = tuple(sorted(self._credentials.current_grant(self._now()).scopes))
        except Exception:  # the probe reports, it does not raise
            scopes = ()
        path = "/api/v1/apps"
        try:
            response = self._get(self._url(path, {"limit": "1"}), SCOPE_APPS_READ, path)
        except OktaRequestError as exc:
            return ProbeResult(False, exc.status, 0, scopes, self.stats.last_rate_limit_remaining,
                               self.stats.last_rate_limit_limit, _summary(str(exc)))
        try:
            body = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = None
        ok = response.status == 200 and isinstance(body, list)
        return ProbeResult(ok, response.status, len(body) if isinstance(body, list) else 0, scopes,
                           self.stats.last_rate_limit_remaining, self.stats.last_rate_limit_limit,
                           None if ok else f"unexpected response (HTTP {response.status})")
