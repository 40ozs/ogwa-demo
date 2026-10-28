"""Shared outbound HTTP policy and the read-only HTTP client.

Discovery code imports ``ReadOnlyHttpClient`` from here; it exposes GET and HEAD only.
State-changing requests live in ``app.core.http_mutation`` and require an injected
``MutationPolicy``. This module deliberately does not import that module or the
mutation policy.
"""

import email.utils
import http.client
import ipaddress
import logging
import random
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

from app import __version__
from app.core.errors import MutationBlockedError, NetworkPolicyError
from app.core.modes import ExecutionMode

SAFE_METHODS = frozenset({"GET", "HEAD"})
RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})

# Hard ceilings. Configuration may tighten these but can never exceed them.
CONNECT_TIMEOUT_BOUNDS = (0.5, 30.0)
READ_TIMEOUT_BOUNDS = (1.0, 120.0)
MAX_RETRIES_BOUNDS = (0, 5)
MAX_CONCURRENCY_BOUNDS = (1, 4)
MAX_RETRY_AFTER_BOUNDS = (1.0, 300.0)
MAX_RESPONSE_BYTES_BOUNDS = (1, 200 * 1024 * 1024)

DEFAULT_USER_AGENT = f"OGWA/{__version__} (identity-lifecycle-governance)"

_log = logging.getLogger("ogwa.http")


class TransportError(Exception):
    """The request could not be completed (connect/TLS/read failure or timeout)."""


class RateLimitedError(Exception):
    """The server asked us to back off for longer than policy allows."""


def _require_within(name: str, value: float, bounds: tuple[float, float]) -> None:
    low, high = bounds
    if isinstance(value, bool) or not (low <= value <= high):
        raise ValueError(f"{name}={value!r} is outside the permitted range {low}..{high}")


@dataclass(frozen=True)
class HttpPolicy:
    connect_timeout: float = 5.0
    read_timeout: float = 30.0
    max_retries: int = 3
    max_concurrency: int = 2
    backoff_base: float = 0.5
    backoff_cap: float = 30.0
    max_retry_after: float = 120.0
    max_response_bytes: int = 50 * 1024 * 1024
    user_agent: str = DEFAULT_USER_AGENT

    def __post_init__(self) -> None:
        _require_within("connect_timeout", self.connect_timeout, CONNECT_TIMEOUT_BOUNDS)
        _require_within("read_timeout", self.read_timeout, READ_TIMEOUT_BOUNDS)
        _require_within("max_retries", self.max_retries, MAX_RETRIES_BOUNDS)
        _require_within("max_concurrency", self.max_concurrency, MAX_CONCURRENCY_BOUNDS)
        _require_within("max_retry_after", self.max_retry_after, MAX_RETRY_AFTER_BOUNDS)
        _require_within("max_response_bytes", self.max_response_bytes, MAX_RESPONSE_BYTES_BOUNDS)
        if not (0 < self.backoff_base <= self.backoff_cap <= 60):
            raise ValueError("backoff must satisfy 0 < backoff_base <= backoff_cap <= 60")
        if not self.user_agent.strip():
            raise ValueError("user_agent must not be blank")

    def backoff_delay(self, retry_index: int, rng: Callable[[], float]) -> float:
        """Full-jitter exponential backoff: uniform(0, min(cap, base * 2**retry_index))."""
        return rng() * min(self.backoff_cap, self.backoff_base * (2**retry_index))


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", {k.lower(): v for k, v in self.headers.items()})

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Transport(Protocol):
    def send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        *,
        connect_timeout: float,
        read_timeout: float,
        max_response_bytes: int,
    ) -> HttpResponse: ...


class StdlibTransport:
    """http.client transport with separate connect and read timeouts and a response size cap."""

    def send(self, method, url, headers, body, *, connect_timeout, read_timeout, max_response_bytes):
        parts = urlsplit(url)
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                parts.hostname, parts.port, timeout=connect_timeout, context=ssl.create_default_context()
            )
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=connect_timeout)
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            conn.connect()
            conn.sock.settimeout(read_timeout)
            conn.request(method, target, body=body, headers=dict(headers))
            response = conn.getresponse()
            data = response.read(max_response_bytes + 1)
            if len(data) > max_response_bytes:
                raise TransportError(f"Response from {parts.hostname} exceeded {max_response_bytes} bytes")
            return HttpResponse(response.status, combine_headers(response.getheaders()), data)
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"{type(exc).__name__} contacting {parts.hostname}") from exc
        finally:
            conn.close()


def combine_headers(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Header pairs to a dict keyed by lowercase name; repeated fields are joined with ", ".

    RFC 9110 §5.3 permits combining repeated list-valued fields this way. A plain dict()
    keeps only the last copy, which silently loses one of Okta's separate
    ``Link: rel="self"`` and ``Link: rel="next"`` headers and so truncates pagination.
    """
    combined: dict[str, str] = {}
    for name, value in pairs:
        key = name.lower()
        combined[key] = f"{combined[key]}, {value}" if key in combined else value
    return combined


def is_loopback_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_retry_after(value: str | None, now: datetime) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date), or None."""
    if value is None or not value.strip():
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():  # str.isdigit alone accepts '²' and '٥'
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - now).total_seconds())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _BaseHttpClient:
    """Destination checks, timeouts, concurrency limit, and redacted structured logging."""

    _allows_unsafe_methods = False

    def __init__(
        self,
        *,
        mode: ExecutionMode,
        http_policy: HttpPolicy,
        allowed_hosts: Iterable[str],
        transport: Transport | None = None,
        logger: logging.Logger | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if not isinstance(mode, ExecutionMode):
            raise TypeError("mode must be an ExecutionMode")
        if not isinstance(http_policy, HttpPolicy):
            raise TypeError("http_policy must be an HttpPolicy")
        hosts = frozenset(h.strip().lower() for h in allowed_hosts if h and h.strip())
        if not hosts:
            raise NetworkPolicyError("allowed_hosts must name at least one host; there is no default allowlist")
        if mode is ExecutionMode.LOCAL_SYNTHETIC and any(not is_loopback_host(h) for h in hosts):
            raise NetworkPolicyError("LOCAL_SYNTHETIC mode may only allowlist loopback hosts")
        self._mode = mode
        self._http_policy = http_policy
        self._allowed_hosts = hosts
        self._transport = transport or StdlibTransport()
        self._log = logger or _log
        self._sleep = sleep
        self._rng = rng
        self._now = now
        self._slots = threading.BoundedSemaphore(http_policy.max_concurrency)

    @property
    def mode(self) -> ExecutionMode:
        return self._mode

    @property
    def http_policy(self) -> HttpPolicy:
        return self._http_policy

    def _check_destination(self, url: str) -> SplitResult:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            raise NetworkPolicyError("URL has no host")
        if parts.username is not None or parts.password is not None:
            raise NetworkPolicyError("URLs must not embed credentials")
        loopback = is_loopback_host(host)
        if self._mode is ExecutionMode.LOCAL_SYNTHETIC and not loopback:
            raise NetworkPolicyError("LOCAL_SYNTHETIC mode may only contact loopback hosts")
        if parts.scheme != "https" and not (loopback and parts.scheme == "http"):
            raise NetworkPolicyError("HTTPS is required for non-loopback hosts")
        if host not in self._allowed_hosts:
            raise NetworkPolicyError(f"Host {host!r} is not in this client's allowlist")
        return parts

    def _send_once(
        self, method: str, url: str, headers: Mapping[str, str] | None, body: bytes | None, attempt: int
    ) -> HttpResponse:
        method = method.upper()
        if method not in SAFE_METHODS and not self._allows_unsafe_methods:
            raise MutationBlockedError(f"{method} is not available on a read-only client")
        parts = self._check_destination(url)
        outgoing = {"Accept": "application/json"}
        if headers:
            outgoing.update(headers)
        outgoing["User-Agent"] = self._http_policy.user_agent
        # Query strings can carry filters with identifiers; log the path only. Headers are never logged.
        fields = {"method": method, "host": parts.hostname, "path": parts.path or "/", "attempt": attempt}
        started = time.monotonic()
        with self._slots:
            try:
                response = self._transport.send(
                    method,
                    url,
                    outgoing,
                    body,
                    connect_timeout=self._http_policy.connect_timeout,
                    read_timeout=self._http_policy.read_timeout,
                    max_response_bytes=self._http_policy.max_response_bytes,
                )
            except TransportError as exc:
                elapsed = round((time.monotonic() - started) * 1000)
                self._log.warning("http.transport_error", extra={"ogwa": {**fields, "error": str(exc), "elapsed_ms": elapsed}})
                raise
        elapsed = round((time.monotonic() - started) * 1000)
        self._log.info("http.response", extra={"ogwa": {**fields, "status": response.status, "elapsed_ms": elapsed}})
        return response

    def _request_safe(self, method: str, url: str, headers: Mapping[str, str] | None) -> HttpResponse:
        """Send a safe (GET/HEAD) request, retrying transient failures with jittered backoff."""
        policy = self._http_policy
        for retry_index in range(policy.max_retries + 1):
            final = retry_index == policy.max_retries
            try:
                response = self._send_once(method, url, headers, None, retry_index + 1)
            except TransportError:
                if final:
                    raise
                delay = policy.backoff_delay(retry_index, self._rng)
            else:
                if response.status not in RETRYABLE_STATUSES or final:
                    return response
                retry_after = parse_retry_after(response.header("Retry-After"), self._now())
                if retry_after is None:
                    delay = policy.backoff_delay(retry_index, self._rng)
                elif retry_after > policy.max_retry_after:
                    raise RateLimitedError(
                        f"Server requested a {retry_after:.0f}s wait, above the permitted "
                        f"{policy.max_retry_after:.0f}s; not retrying"
                    )
                else:
                    delay = retry_after
            self._log.info(
                "http.retry",
                extra={"ogwa": {"method": method, "attempt": retry_index + 1, "delay_seconds": round(delay, 3)}},
            )
            self._sleep(delay)
        raise AssertionError("unreachable")


class ReadOnlyHttpClient(_BaseHttpClient):
    """GET/HEAD-only client for discovery. It has no method that sends a state-changing request."""

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
        return self._request_safe("GET", url, headers)

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
        return self._request_safe("HEAD", url, headers)
