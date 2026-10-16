"""The demo application as the Cloudflare Worker runs it (docs/deployment/cloudflare-demo.md).

``HostedDemo`` is the real demo application (``build_demo_application``) over an in-memory,
read-only copy of the validated demo store (``open_demo_image``). The Worker builds it at
import time, so Cloudflare's deploy-time memory snapshot already holds it opened, validated
by ``validate_demo_store``, and with the directory snapshot loaded: no request pays for that.

The store is read-only (owner decision for the public demo), so the demo's read-only route
policy applies (``app.runtime.api.NON_PERSISTING``), and SQLite refuses any write that got
past it. D1 holds the canonical copy of the same store. Each request first proves that D1
still holds exactly this store (``check_d1``); otherwise the Worker answers 503 and serves
nothing. Before the first request of an isolate, the Worker's own environment must give the
same settings this application was built with (``check_environment``): that is where
OGWA's demo profile refuses live-integration settings and production credentials, and where
sessions become signed cookies, since consecutive requests reach different isolates.

Nothing here imports a Cloudflare module; ``cloudflare/worker/src/entry.py`` adapts the
Worker's request to ``handle`` and its response back.
"""

import io
import json
import logging
import time
import zlib
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from app.api.errors import ApiError
from app.api.http import Response
from app.api.local import OffsetClock
from app.api.sessions import MIN_SIGNING_KEY_BYTES, SignedSessionManager
from app.cloudflare.identity import StoreIdentity, read_identity, read_schema_digest, schema_digest
from app.core.config import Settings, load_settings
from app.core.errors import ConfigError, OgwaSafetyError
from app.domain.ids import IdKind, new_id
from app.runtime.api import RUNTIME_HEADER, VISITOR_METHOD, VISITOR_SUBJECT, DemoApplication, build_demo_application
from app.runtime.datasets import resolve_dataset
from app.runtime.demo_store import open_demo_image
from app.store.store import utc_now

UNAVAILABLE = "The demo store is unavailable, so nothing is served. Quote the request id when reporting it."
# The Worker secret that signs session cookies (``SignedSessionManager``): 64 hex digits. Not an
# OGWA_* setting, because it configures the host, not OGWA; its value is never logged.
SESSION_KEY_NAME = "HOSTED_SESSION_KEY"
SCHEMA_RECHECK_SECONDS = 60


class VisitorSessions(SignedSessionManager):
    """The public demo's sessions, which are only ever the anonymous visitor's (``app.runtime.api``). A cookie
    this key signed for any other principal, before the demo became anonymous, is refused like a forged one."""

    def get(self, token: str | None):
        session = super().get(token)
        if session is None or (session.claims.subject, session.claims.method) != (VISITOR_SUBJECT, VISITOR_METHOD):
            return None
        return session


class NoAssets:
    """The Worker's ``OgwaWebApp`` has no UI files: Workers Static Assets serve them before the
    Worker runs, so any other non-API path reaching the Worker is a 404, as it is locally."""

    paths: frozenset[str] = frozenset()

    def get(self, path: str) -> None:
        return None


class DemoClock:
    """The demo clock of ``python -m app.api serve`` in demo: real time elapsed from the newest
    audit event. It starts at an isolate's first request (``begin``), not at import time, whose
    monotonic origin would belong to the deploy-time snapshot rather than to the isolate."""

    def __init__(self) -> None:
        self.start_at = None
        self._clock: OffsetClock | None = None

    def begin(self) -> None:
        if self._clock is None:
            self._clock = OffsetClock(self.start_at or utc_now())

    def __call__(self):
        return self._clock() if self._clock is not None else utc_now()


def wsgi_environ(method: str, url: str, headers: Iterable[tuple[str, str]], body: bytes) -> dict[str, Any]:
    """A WSGI environ (PEP 3333) for one request, as ``wsgiref`` would build it locally."""
    parts = urlsplit(url)
    https = parts.scheme == "https"
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method.upper(), "SCRIPT_NAME": "",
        "PATH_INFO": unquote(parts.path or "/", "latin-1"), "QUERY_STRING": parts.query,
        "SERVER_NAME": parts.hostname or "", "SERVER_PORT": str(parts.port or (443 if https else 80)),
        "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.version": (1, 0), "wsgi.url_scheme": parts.scheme or "https",
        "wsgi.input": io.BytesIO(body), "wsgi.errors": io.StringIO(), "wsgi.multithread": False,
        "wsgi.multiprocess": False, "wsgi.run_once": False,
    }
    for name, value in headers:
        key = name.upper().replace("-", "_")
        if key not in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            key = "HTTP_" + key
        environ[key] = f"{environ[key]},{value}" if key in environ else value
    return environ


def _differences(expected: StoreIdentity, actual: StoreIdentity) -> list[str]:
    a, b = expected.to_json(), actual.to_json()
    return sorted(k for k in a if a[k] != b[k])


def read_gzip_image(path: Path) -> bytearray:
    """A gzip file's content, decompressed straight into a buffer of its recorded size.

    Workers Free gives an isolate 128 MB, and Cloudflare snapshots the WebAssembly memory at
    its high-water mark. Decompressing into a growing buffer reallocates and peaks at about
    twice the store's size; this peaks at the store's size plus one read chunk."""
    with path.open("rb") as f:
        f.seek(-4, io.SEEK_END)
        size = int.from_bytes(f.read(4), "little")  # gzip ISIZE: the uncompressed size, mod 2**32
        f.seek(0)
        buffer = bytearray(size)
        view, filled = memoryview(buffer), 0
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip framing
        while not decompressor.eof:
            data = decompressor.unconsumed_tail or f.read(1 << 20)
            if not data:
                raise ValueError(f"{path.name} ends before its gzip stream does")
            chunk = decompressor.decompress(data, 1 << 20)
            if filled + len(chunk) > size:
                raise ValueError(f"{path.name} holds more than its recorded size")
            view[filled:filled + len(chunk)] = chunk
            filled += len(chunk)
        if filled != size or decompressor.unused_data or f.read(1):
            raise ValueError(f"{path.name} is not one gzip stream of its recorded size")
    return buffer


class HostedDemo:
    """The hosted demo application. ``load_image`` returns the demo store's bytes;
    ``environment``: the OGWA settings it is built with."""

    def __init__(self, load_image: Callable[[], bytes | bytearray], environment: Mapping[str, str], *,
                 expected: Mapping[str, Any] | None = None, logger: logging.Logger | None = None) -> None:
        self.log = logger or logging.getLogger("ogwa.hosted")
        self.settings = load_settings(environment)
        dataset = resolve_dataset(self.settings.demo_dataset)
        self.clock = DemoClock()
        expected = expected or {}
        opened = open_demo_image(self.settings, dataset, load_image, clock=self.clock,
                                 expected_audit_head=expected.get("audit_head"))
        self.app: DemoApplication = build_demo_application(self.settings, clock=self.clock, dataset=dataset,
                                                           opened=opened, assets=NoAssets())
        store = self.app.store
        if not store.read_only:  # pragma: no cover - open_demo_image opens read-only
            raise OgwaSafetyError("the hosted demo store must be read-only")
        newest = store.audit_events_page(limit=1)
        self.clock.start_at = newest[0].occurred_at if newest else None
        self.identity = read_identity(store.connection)
        self.schema = read_schema_digest(store.connection)
        if "identity" in expected and StoreIdentity.from_row(expected["identity"]) != self.identity:
            raise OgwaSafetyError("the demo store image is not the store this Worker was built for")
        if "schema" in expected and expected["schema"] != self.schema:
            raise OgwaSafetyError("the demo store image's schema is not the schema this Worker was built for")
        self.app.api.directory.preload()
        self.environment_ok: bool | None = None
        self.schema_ok: bool | None = None
        self._schema_checked_at: float | None = None

    # --- per-isolate and per-request checks -------------------------------------------------

    def check_environment(self, worker_environment: Mapping[str, str]) -> bool:
        """The Worker's own variables and secrets, read through OGWA's settings: they must give the
        settings this application was built with. ``load_settings`` refuses, among others, every
        live-integration setting and production credential variable in demo.

        Sessions must outlive the isolate that created them (each request may reach another), so
        they are signed cookies under the ``HOSTED_SESSION_KEY`` secret; without it, nothing is served.
        They are the anonymous visitor's only (``VisitorSessions``)."""
        try:
            actual = load_settings(worker_environment)
        except (ConfigError, OgwaSafetyError) as exc:
            self.log.error("hosted.environment_refused", extra={"ogwa": {"reason": str(exc)}})
            self.environment_ok = False
            return False
        same = _settings_key(actual) == _settings_key(self.settings)
        if not same:
            self.log.error("hosted.environment_mismatch", extra={"ogwa": {
                "built": _settings_key(self.settings), "worker": _settings_key(actual)}})
            self.environment_ok = False
            return False
        try:
            key = bytes.fromhex(worker_environment.get(SESSION_KEY_NAME, ""))
            self.app.api.sessions = VisitorSessions(key)
        except ValueError:
            self.log.error("hosted.session_key_unusable", extra={"ogwa": {
                "secret": SESSION_KEY_NAME, "need": f"{2 * MIN_SIGNING_KEY_BYTES} or more hex digits"}})
            self.environment_ok = False
            return False
        self.environment_ok = True
        return True

    def schema_check_due(self) -> bool:
        """Once per isolate; after a failure, again at most once a minute (a bootstrap may finish)."""
        if self.schema_ok is None:
            return True
        return not self.schema_ok and time.monotonic() - (self._schema_checked_at or 0.0) >= SCHEMA_RECHECK_SECONDS

    def check_schema(self, d1_schema_rows: Iterable[Mapping] | None) -> bool:
        """D1's schema objects (``SCHEMA_SQL``) must be exactly this store's: a partial or foreign
        import is refused."""
        actual = None if d1_schema_rows is None else schema_digest(d1_schema_rows)
        self._schema_checked_at = time.monotonic()
        self.schema_ok = actual == self.schema
        if not self.schema_ok:
            self.log.error("hosted.d1_schema_mismatch", extra={"ogwa": {
                "expected": self.schema, "d1": actual or "unavailable",
                "hint": "complete the D1 bootstrap (docs/deployment/cloudflare-demo.md)"}})
        return self.schema_ok

    def check_d1(self, d1_identity_row: Mapping | None) -> bool:
        """D1 must hold exactly the served store (``IDENTITY_SQL``). Checked on every request."""
        if d1_identity_row is None:
            self.log.error("hosted.d1_unavailable", extra={"ogwa": {"reason": "no identity row"}})
            return False
        try:
            actual = StoreIdentity.from_row(d1_identity_row)
        except (KeyError, TypeError) as exc:
            self.log.error("hosted.d1_identity_unreadable", extra={"ogwa": {"reason": type(exc).__name__}})
            return False
        if actual != self.identity:
            self.log.error("hosted.d1_identity_mismatch", extra={"ogwa": {
                "fields": _differences(self.identity, actual), "expected_head": self.identity.audit_head,
                "d1_head": actual.audit_head}})
            return False
        return True

    # --- requests ---------------------------------------------------------------------------

    def unavailable(self) -> tuple[int, list[tuple[str, str]], bytes]:
        request_id = new_id(IdKind.REQUEST)
        self.log.warning("hosted.unavailable", extra={"ogwa": {"request_id": request_id, "status": 503}})
        response = Response(503, ApiError(503, "DEMO_STORE_UNAVAILABLE", UNAVAILABLE).body(request_id),
                            [(RUNTIME_HEADER, self.settings.runtime_mode.value)])
        status, headers, payload = response.encode(request_id)
        return int(status.split(" ", 1)[0]), headers, payload

    def handle(self, method: str, url: str, headers: Iterable[tuple[str, str]],
               body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        """Run one request through the demo application, the WSGI way."""
        self.clock.begin()
        parts = urlsplit(url)
        # The Origin check of a POST accepts this Worker's own origin, whatever host serves it.
        self.app.api.allowed_origins = frozenset({f"{parts.scheme}://{parts.netloc}"})
        result: dict[str, Any] = {}

        def start_response(status, response_headers, exc_info=None):
            result["status"], result["headers"] = status, list(response_headers)

        chunks = self.app.web_app(wsgi_environ(method, url, headers, body), start_response)
        try:
            payload = b"".join(chunks)
        finally:
            close = getattr(chunks, "close", None)
            if close is not None:
                close()
        return int(result["status"].split(" ", 1)[0]), result["headers"], payload


def _settings_key(settings: Settings) -> dict[str, str]:
    return {"runtime_mode": settings.runtime_mode.value, "execution_mode": settings.mode.value,
            "demo_dataset": settings.demo_dataset, "log_level": settings.log_level}


def manifest_json(hosted_identity: StoreIdentity, schema: str, environment: Mapping[str, str]) -> str:
    """The build manifest the Worker checks its image against (``expected``)."""
    return json.dumps({"identity": hosted_identity.to_json(), "audit_head": hosted_identity.audit_head,
                       "schema": schema, "environment": dict(environment)}, indent=2, sort_keys=True) + "\n"
