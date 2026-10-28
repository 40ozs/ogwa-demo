"""Request pacing for the Okta client: budget, retries, rate limits, and halting.

The shared ``ReadOnlyHttpClient`` (GET/HEAD only) does the I/O. Here it is built with
``max_retries=0`` so that this module owns retries. That way every attempt counts
against the request budget, and Okta's ``X-Rate-Limit-*`` headers, which the generic
client does not know about, drive the waits.

Rules:

- GET only. Retries apply to 429, 500, 502, 503, 504, and transport failures, at most
  ``max_retries`` times per request.
- The wait before a retry is ``Retry-After`` if present, else ``X-Rate-Limit-Reset``,
  else full-jitter exponential backoff. Header-derived waits get up to 1 s of added
  jitter.
- A wait longer than ``max_wait_seconds`` is not taken. The session halts with
  RATE_LIMITED instead.
- Proactive throttle: when ``X-Rate-Limit-Remaining`` falls to the reserve, the next
  request waits for the reset. Okta rate limits are shared with every other
  integration in the org, so OGWA leaves a reserve rather than draining the bucket.
- Budget: every attempt, including retries, uses one unit. When the budget is spent
  the session halts.
- After an authentication failure, a refused long wait, or an exhausted budget, the
  session sends nothing more.
"""

import math
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from app.core.http_client import HttpPolicy, HttpResponse, ReadOnlyHttpClient, TransportError, parse_retry_after
from app.domain.collection import CollectorErrorCode

RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})

MAX_REQUEST_BUDGET = 10_000
MAX_WAIT_CEILING_SECONDS = 300.0
MAX_MIN_INTERVAL_SECONDS = 10.0


class OktaRequestError(Exception):
    """A request did not produce usable data. ``code`` maps to the collector outcome."""

    code: CollectorErrorCode = CollectorErrorCode.OTHER

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class OktaAuthError(OktaRequestError):
    code = CollectorErrorCode.AUTHENTICATION_FAILED


class OktaRateLimited(OktaRequestError):
    code = CollectorErrorCode.RATE_LIMITED


class OktaTimeout(OktaRequestError):
    code = CollectorErrorCode.TIMEOUT


class OktaHttpError(OktaRequestError):
    code = CollectorErrorCode.HTTP_ERROR


class OktaBudgetExhausted(OktaRequestError):
    code = CollectorErrorCode.PAGING_INTERRUPTED


@dataclass(frozen=True)
class PacingPolicy:
    max_requests: int = 500  # request budget for one client (one collector run)
    min_interval_seconds: float = 0.2  # serial pacing between requests
    rate_limit_reserve_fraction: float = 0.2  # leave this share of each bucket to the org
    rate_limit_reserve_minimum: int = 5
    max_wait_seconds: float = 60.0  # longest single wait accepted (Retry-After / reset)

    def __post_init__(self) -> None:
        if isinstance(self.max_requests, bool) or not isinstance(self.max_requests, int) or not 1 <= self.max_requests <= MAX_REQUEST_BUDGET:
            raise ValueError(f"max_requests must be 1..{MAX_REQUEST_BUDGET}")
        if not 0 <= self.min_interval_seconds <= MAX_MIN_INTERVAL_SECONDS:
            raise ValueError(f"min_interval_seconds must be 0..{MAX_MIN_INTERVAL_SECONDS}")
        if not 0 <= self.rate_limit_reserve_fraction < 1:
            raise ValueError("rate_limit_reserve_fraction must be in [0, 1)")
        if isinstance(self.rate_limit_reserve_minimum, bool) or not 0 <= self.rate_limit_reserve_minimum <= 1000:
            raise ValueError("rate_limit_reserve_minimum must be 0..1000")
        if not 1 <= self.max_wait_seconds <= MAX_WAIT_CEILING_SECONDS:
            raise ValueError(f"max_wait_seconds must be 1..{MAX_WAIT_CEILING_SECONDS:g}")

    def reserve(self, limit: int | None) -> int:
        share = math.ceil(limit * self.rate_limit_reserve_fraction) if limit else 0
        return max(self.rate_limit_reserve_minimum, share)


@dataclass
class RequestStats:
    """Counters for one client. Never holds payloads, identifiers, or headers."""

    attempts: int = 0
    successes: int = 0
    not_found: int = 0
    retries: int = 0
    rate_limited_responses: int = 0
    server_errors: int = 0
    transport_errors: int = 0
    throttle_pauses: int = 0
    waited_seconds: float = 0.0
    last_rate_limit_remaining: int | None = None
    last_rate_limit_limit: int | None = None
    status_counts: dict[int, int] = field(default_factory=dict)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _int_header(response: HttpResponse, name: str) -> int | None:
    raw = response.header(name)
    if raw is None:
        return None
    raw = raw.split(",")[0].strip()
    return int(raw) if raw.isascii() and raw.isdigit() else None


class OktaRequestExecutor:
    """Serial GET executor with budget, retries, throttling, and halting."""

    def __init__(
        self,
        *,
        http: ReadOnlyHttpClient,
        pacing: PacingPolicy,
        max_retries: int,
        backoff: HttpPolicy,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
        now: Callable[[], datetime] = _utcnow,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if http.http_policy.max_retries != 0:
            raise ValueError("the underlying client must not retry; this executor owns retries")
        self._http = http
        self._pacing = pacing
        self._max_retries = max_retries
        self._backoff = backoff
        self._sleep = sleep
        self._rng = rng
        self._now = now
        self._monotonic = monotonic
        self._last_sent: float | None = None
        self._throttle_until_epoch: int | None = None
        self.stats = RequestStats()
        self.halted: OktaRequestError | None = None

    @staticmethod
    def underlying_policy(policy: HttpPolicy) -> HttpPolicy:
        return replace(policy, max_retries=0)

    @property
    def budget_remaining(self) -> int:
        return self._pacing.max_requests - self.stats.attempts

    def halt(self, error: OktaRequestError) -> OktaRequestError:
        self.halted = error
        return error

    def _wait(self, seconds: float) -> None:
        if seconds > 0:
            self.stats.waited_seconds += seconds
            self._sleep(seconds)

    def _header_wait(self, response: HttpResponse) -> float | None:
        """Seconds to wait from Retry-After, else X-Rate-Limit-Reset; None if neither is usable."""
        now = self._now()
        delay = parse_retry_after(response.header("Retry-After"), now)
        if delay is None:
            reset = _int_header(response, "X-Rate-Limit-Reset")
            if reset is not None:
                delay = max(0.0, reset - now.timestamp() + 1.0)
        return delay

    def _before_send(self) -> None:
        if self.halted is not None:
            raise self.halted
        if self.stats.attempts >= self._pacing.max_requests:
            raise self.halt(OktaBudgetExhausted(f"request budget of {self._pacing.max_requests} exhausted"))
        if self._throttle_until_epoch is not None:
            delay = max(0.0, self._throttle_until_epoch - self._now().timestamp() + 1.0)
            self._throttle_until_epoch = None
            if delay > self._pacing.max_wait_seconds:
                raise self.halt(OktaRateLimited(
                    f"rate-limit reserve reached and the reset is {delay:.0f}s away, above the "
                    f"permitted {self._pacing.max_wait_seconds:.0f}s"))
            self.stats.throttle_pauses += 1
            self._wait(delay)
        if self._last_sent is not None and self._pacing.min_interval_seconds:
            gap = self._pacing.min_interval_seconds - (self._monotonic() - self._last_sent)
            self._wait(gap)

    def _observe_rate_limit(self, response: HttpResponse) -> None:
        remaining = _int_header(response, "X-Rate-Limit-Remaining")
        limit = _int_header(response, "X-Rate-Limit-Limit")
        reset = _int_header(response, "X-Rate-Limit-Reset")
        if remaining is None:
            return
        self.stats.last_rate_limit_remaining = remaining
        self.stats.last_rate_limit_limit = limit
        if remaining <= self._pacing.reserve(limit) and reset is not None:
            self._throttle_until_epoch = reset

    def get(self, url: str, *, authorization: Callable[[], str], path_for_errors: str) -> HttpResponse:
        """GET ``url``. Returns a 2xx or 404 response; raises OktaRequestError otherwise."""
        for retry_index in range(self._max_retries + 1):
            final = retry_index == self._max_retries
            self._before_send()
            headers = {"Authorization": authorization()}
            self.stats.attempts += 1
            self._last_sent = self._monotonic()
            try:
                response = self._http.get(url, headers=headers)
            except TransportError as exc:
                self.stats.transport_errors += 1
                timed_out = isinstance(exc.__cause__, TimeoutError)
                if final:
                    kind = OktaTimeout if timed_out else OktaHttpError
                    raise kind(f"{'timeout' if timed_out else 'transport failure'} on {path_for_errors} "
                               f"after {retry_index + 1} attempt(s)") from None
                delay = self._backoff.backoff_delay(retry_index, self._rng)
            else:
                status = response.status
                self.stats.status_counts[status] = self.stats.status_counts.get(status, 0) + 1
                self._observe_rate_limit(response)
                if 200 <= status < 300:
                    self.stats.successes += 1
                    return response
                if status == 404:
                    self.stats.not_found += 1
                    return response
                if status in (401, 403):
                    raise self.halt(OktaAuthError(
                        f"HTTP {status} on {path_for_errors}; the credential was refused or lacks permission",
                        status=status))
                if status not in RETRYABLE_STATUSES:
                    raise OktaHttpError(f"HTTP {status} on {path_for_errors}", status=status)
                if status == 429:
                    self.stats.rate_limited_responses += 1
                else:
                    self.stats.server_errors += 1
                if final:
                    if status == 429:
                        raise self.halt(OktaRateLimited(
                            f"HTTP 429 on {path_for_errors} after {retry_index + 1} attempt(s)", status=status))
                    raise OktaHttpError(f"HTTP {status} on {path_for_errors} after {retry_index + 1} attempt(s)",
                                        status=status)
                delay = self._header_wait(response)
                if delay is None:
                    delay = self._backoff.backoff_delay(retry_index, self._rng)
                else:
                    delay += self._rng()  # spread clients that share a reset instant
                if delay > self._pacing.max_wait_seconds:
                    raise self.halt(OktaRateLimited(
                        f"server asked for a {delay:.0f}s wait on {path_for_errors}, above the permitted "
                        f"{self._pacing.max_wait_seconds:.0f}s", status=status))
                # A retry wait already covers the reset; do not also throttle before the retry.
                self._throttle_until_epoch = None
            self.stats.retries += 1
            self._wait(delay)
        raise AssertionError("unreachable")
