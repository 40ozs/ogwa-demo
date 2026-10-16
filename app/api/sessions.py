"""Server-side sessions.

The browser holds only an opaque random token in a ``__Host-`` cookie (Secure, HttpOnly,
SameSite=Strict). The server keeps a SHA-256 of the token, never the token itself, so the
session table cannot be replayed if it leaks. Sessions expire after an idle period and an
absolute lifetime measured on a monotonic clock, and each carries its own CSRF token.

Sessions live in process memory: restarting the service signs everyone out. That suits a
single local process (D50). ``SignedSessionManager`` is the hosted demo's alternative for a
deployment that runs many processes with no shared memory (docs/deployment/cloudflare-demo.md).
"""

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from app.api.identity import PrincipalClaims

SESSION_COOKIE = "__Host-ogwa-session"
CSRF_HEADER = "X-OGWA-CSRF"
IDLE_TIMEOUT_SECONDS = 15 * 60
ABSOLUTE_TIMEOUT_SECONDS = 8 * 60 * 60
MAX_SESSIONS = 1000
_TOKEN_BYTES = 32


@dataclass
class Session:
    key: str  # sha256 of the cookie token
    claims: PrincipalClaims
    csrf_token: str
    created: float
    last_seen: float


class SessionManager:
    cookie_max_age: int | None = None  # the cookie lives as long as the browser keeps it

    def __init__(self, *, idle_timeout: float = IDLE_TIMEOUT_SECONDS, absolute_timeout: float = ABSOLUTE_TIMEOUT_SECONDS,
                 max_sessions: int = MAX_SESSIONS, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._idle = idle_timeout
        self._absolute = absolute_timeout
        self._max = max_sessions
        self._monotonic = monotonic
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, claims: PrincipalClaims) -> tuple[str, Session]:
        """A new session with a fresh token (never reuses one: no session fixation)."""
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        now = self._monotonic()
        session = Session(self._key(token), claims, secrets.token_urlsafe(_TOKEN_BYTES), now, now)
        with self._lock:
            self._expire(now)
            if len(self._sessions) >= self._max:
                oldest = min(self._sessions.values(), key=lambda s: s.last_seen)
                del self._sessions[oldest.key]
            self._sessions[session.key] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
        if not token or len(token) > 200:
            return None
        now = self._monotonic()
        with self._lock:
            session = self._sessions.get(self._key(token))
            if session is None:
                return None
            if now - session.last_seen > self._idle or now - session.created > self._absolute:
                del self._sessions[session.key]
                return None
            session.last_seen = now
            return session

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._key(token), None)

    def renew(self, session: Session) -> str | None:
        """A replacement token to send with the response, if the cookie itself must be renewed.
        Never here: the server tracks idleness itself."""
        return None

    def _expire(self, now: float) -> None:
        for key in [k for k, s in self._sessions.items()
                    if now - s.last_seen > self._idle or now - s.created > self._absolute]:
            del self._sessions[key]

    @staticmethod
    def csrf_matches(session: Session, presented: str | None) -> bool:
        return bool(presented) and hmac.compare_digest(session.csrf_token.encode(), presented.encode())


MIN_SIGNING_KEY_BYTES = 32
MAX_SIGNED_TOKEN = 2048
MAX_REVOKED = 10_000
RENEW_AFTER_SECONDS = 60
_SIGNED_VERSION = "v1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SignedSessionManager(SessionManager):
    """Sessions carried by the cookie itself, for a deployment with many processes and no shared
    memory (the Cloudflare-hosted demo, where consecutive requests reach different isolates).

    The token is ``v1.<payload>.<mac>``: the payload holds the principal's claims, the session's
    CSRF token, its issue time, and the time the token was last renewed; the MAC (HMAC-SHA256 under
    the deployment's key) makes it unforgeable and unalterable. The browser still holds it only in
    the ``__Host-``, HttpOnly, SameSite=Strict cookie, with the idle timeout as its Max-Age.

    Idleness is measured from the last renewal, on the wall clock: a signed-in response more than
    ``RENEW_AFTER_SECONDS`` after it carries a renewed token (same session, same CSRF token). A token
    not renewed within the idle timeout is refused, and so is any token past the absolute lifetime.

    One thing the in-memory manager does that this one cannot: revoke a token everywhere. Signing
    out clears the cookie, and the process that served the sign-out refuses the token afterwards, but
    another process would still accept a copy until it goes idle or reaches the absolute lifetime.
    """

    def __init__(self, key: bytes, *, idle_timeout: float = IDLE_TIMEOUT_SECONDS,
                 absolute_timeout: float = ABSOLUTE_TIMEOUT_SECONDS, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(key, bytes) or len(key) < MIN_SIGNING_KEY_BYTES:
            raise ValueError(f"the session signing key must be at least {MIN_SIGNING_KEY_BYTES} bytes")
        super().__init__(idle_timeout=idle_timeout, absolute_timeout=absolute_timeout)
        self.cookie_max_age = int(idle_timeout)
        self._signing_key = key
        self._clock = clock
        self._revoked: OrderedDict[str, None] = OrderedDict()

    def _mac(self, signed: str) -> str:
        return _b64(hmac.new(self._signing_key, signed.encode("ascii"), hashlib.sha256).digest())

    def _sign(self, claims: PrincipalClaims, csrf: str, issued: float, seen: float) -> str:
        payload = {"iss": claims.issuer, "sub": claims.subject, "name": claims.display_name,
                   "groups": sorted(claims.groups), "at": claims.authenticated_at.isoformat(),
                   "method": claims.method, "csrf": csrf, "iat": issued, "seen": seen,
                   "nonce": secrets.token_urlsafe(16)}
        signed = f"{_SIGNED_VERSION}.{_b64(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())}"
        return f"{signed}.{self._mac(signed)}"

    def create(self, claims: PrincipalClaims) -> tuple[str, Session]:
        now = self._clock()
        csrf = secrets.token_urlsafe(_TOKEN_BYTES)
        token = self._sign(claims, csrf, now, now)
        return token, Session(self._key(token), claims, csrf, now, now)

    def get(self, token: str | None) -> Session | None:
        if not token or len(token) > MAX_SIGNED_TOKEN or token.count(".") != 2:
            return None
        signed, _, mac = token.rpartition(".")
        if not signed.startswith(_SIGNED_VERSION + ".") or not hmac.compare_digest(self._mac(signed), mac):
            return None
        key = self._key(token)
        with self._lock:
            if key in self._revoked:
                return None
        try:
            payload = json.loads(_unb64(signed.split(".", 1)[1]))
            issued, seen = float(payload["iat"]), float(payload["seen"])
            claims = PrincipalClaims(
                issuer=str(payload["iss"]), subject=str(payload["sub"]), display_name=str(payload["name"]),
                groups=frozenset(str(g) for g in payload["groups"]),
                authenticated_at=datetime.fromisoformat(payload["at"]), method=str(payload["method"]))
            csrf = str(payload["csrf"])
        except (ValueError, KeyError, TypeError):
            return None
        now = self._clock()
        if not (issued - 300 <= now <= issued + self._absolute and seen - 300 <= now <= seen + self._idle):
            return None
        return Session(key, claims, csrf, issued, seen)  # last_seen: when this token was issued or renewed

    def renew(self, session: Session) -> str | None:
        now = self._clock()
        if now - session.last_seen < RENEW_AFTER_SECONDS:
            return None
        return self._sign(session.claims, session.csrf_token, session.created, now)

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._revoked[self._key(token)] = None
                while len(self._revoked) > MAX_REVOKED:
                    self._revoked.popitem(last=False)
