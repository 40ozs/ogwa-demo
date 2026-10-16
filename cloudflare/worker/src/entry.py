"""Cloudflare Worker entry: the hosted OGWA demo (docs/deployment/cloudflare-demo.md).

The only Cloudflare-specific code. ``python -m app.cloudflare build`` stages the rest of this
directory: ``app/`` and ``config/`` (copies of the repository's), the validated demo store
image, and the build manifest. Everything below runs in the Worker; all of OGWA's logic is in
``app.cloudflare.hosted``, which the repository's tests drive directly.

At import time (captured by Cloudflare's deploy-time memory snapshot) the demo store image is
opened read-only and validated, and the demo application is built. Per request:

1. once per isolate: the Worker's variables and secrets must give the built settings, and
   D1's schema must be the store's complete schema (a partial bootstrap is refused);
2. every request: D1 must hold exactly the served store (one query, ``IDENTITY_SQL``);
3. the request runs through the demo application, the WSGI way.

Any failure answers 503 and serves nothing. UI files are Workers Static Assets and never
reach this code.
"""

import json
import logging
from pathlib import Path

from workers import Response, WorkerEntrypoint

from app.api.http import MAX_BODY_BYTES
from app.cloudflare.hosted import HostedDemo, read_gzip_image
from app.cloudflare.identity import IDENTITY_SQL, SCHEMA_SQL
from app.core.logging_setup import configure_logging

_HERE = Path(__file__).parent
configure_logging("INFO")
LOG = logging.getLogger("ogwa.hosted")
MANIFEST = json.loads((_HERE / "hosted-build.json").read_text(encoding="utf-8"))
HOSTED = HostedDemo(lambda: read_gzip_image(_HERE / "ogwa-demo.sqlite3.gz"), MANIFEST["environment"],
                    expected=MANIFEST, logger=LOG)


def _worker_environment(env) -> dict[str, str]:
    """The Worker's variables and secrets (string bindings), by name."""
    from js import Object

    raw = getattr(env, "_env", env)
    values = {}
    for name in Object.keys(raw):
        value = getattr(raw, name)
        if isinstance(value, str):
            values[str(name)] = value
    return values


def _response(status: int, headers: list[tuple[str, str]], body: bytes) -> Response:
    from js import Headers

    js_headers = Headers.new()
    for name, value in headers:
        js_headers.append(name, value)  # append, not set: Set-Cookie may repeat
    return Response(body, status=status, headers=js_headers)


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        try:
            if HOSTED.environment_ok is None:
                HOSTED.check_environment(_worker_environment(self.env))
            if HOSTED.environment_ok and HOSTED.schema_check_due():
                schema = await self.env.DB.prepare(SCHEMA_SQL).all()
                HOSTED.check_schema(schema["results"])
            if not (HOSTED.environment_ok and HOSTED.schema_ok):
                return _response(*HOSTED.unavailable())
            identity = await self.env.DB.prepare(IDENTITY_SQL).first()
            if not HOSTED.check_d1(identity):
                return _response(*HOSTED.unavailable())
            headers = list(request.headers.items())
            length = request.headers.get("content-length")
            body = b""
            if request.method == "POST" and length and length.isdigit() and int(length) <= MAX_BODY_BYTES:
                body = await request.bytes()
            return _response(*HOSTED.handle(request.method, request.url, headers, body))
        except Exception:
            LOG.error("hosted.request_failed", exc_info=True)
            return _response(*HOSTED.unavailable())
