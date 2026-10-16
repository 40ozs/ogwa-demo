"""Serve the operator UI and the operator API from one origin.

The UI is a set of static files (HTML, CSS, JavaScript modules) with no third-party code
and no build step. It talks only to ``/api/v1`` on its own origin, so the API's session
cookie (``__Host-``, ``SameSite=Strict``), CSRF token, and Origin check apply unchanged.
The browser never holds an Okta, AAP, or AD credential: it holds only the opaque session
cookie (HttpOnly, so scripts cannot read it) and the per-session CSRF token, in memory.

``OgwaWebApp`` is a WSGI callable:

- ``/api/v1`` and everything below it go to the API, untouched.
- ``GET``/``HEAD`` of ``/`` and of a known file under ``/ui/`` return that file. The set of
  files is fixed when the application is built; nothing else on disk can be reached, and
  there is no directory listing.
- Everything else is ``404``; any other method on a UI path is ``405``.

UI responses carry their own strict Content-Security-Policy: scripts, styles, and
images from this origin only, ``fetch`` to this origin only, no inline script or style,
no framing, no form submission, and Trusted Types enforced, so an HTML-injection sink
(``innerHTML`` and the like) throws instead of rendering. The UI code builds its DOM
with ``textContent`` and ``createElement`` only; ``tests/test_ui_static.py`` pins that.
"""

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from app.api.app import API_PREFIX

STATIC_ROOT = Path(__file__).resolve().parent / "static"
UI_PREFIX = "/ui/"
INDEX_FILE = "index.html"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}
UI_CSP = "; ".join((
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
))
UI_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", UI_CSP),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()"),
)


class StaticAssets:
    """The UI's files, read once. Maps a request path to (content type, bytes)."""

    def __init__(self, root: Path = STATIC_ROOT) -> None:
        files: dict[str, tuple[str, bytes]] = {}
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            content_type = CONTENT_TYPES.get(path.suffix)
            if content_type is None:
                raise ValueError(f"unexpected file type in the UI: {path.relative_to(root).as_posix()}")
            files[UI_PREFIX + path.relative_to(root).as_posix()] = (content_type, path.read_bytes())
        index = files.get(UI_PREFIX + INDEX_FILE)
        if index is None:
            raise ValueError("the UI has no index.html")
        files["/"] = index
        self._files = files

    @property
    def paths(self) -> frozenset[str]:
        return frozenset(self._files)

    def get(self, path: str) -> tuple[str, bytes] | None:
        return self._files.get(path)


def _is_api(path: str) -> bool:
    return path == API_PREFIX or path.startswith(API_PREFIX + "/")


class OgwaWebApp:
    """The UI's static files and the API, on one origin."""

    def __init__(self, api: Callable[[dict[str, Any], Callable], Iterable[bytes]],
                 assets: StaticAssets | None = None) -> None:
        self.api = api
        self.assets = assets or StaticAssets()

    def __call__(self, environ: dict[str, Any], start_response) -> Iterable[bytes]:
        path = str(environ.get("PATH_INFO") or "/")
        if _is_api(path):
            return self.api(environ, start_response)
        method = str(environ.get("REQUEST_METHOD", "")).upper()
        asset = self.assets.get(path)
        if asset is None:
            return self._plain(start_response, "404 Not Found", b"Not found.\n")
        if method not in ("GET", "HEAD"):
            return self._plain(start_response, "405 Method Not Allowed", b"Method not allowed.\n",
                               [("Allow", "GET, HEAD")])
        content_type, body = asset
        start_response("200 OK", [("Content-Type", content_type), ("Content-Length", str(len(body))), *UI_HEADERS])
        return [b"" if method == "HEAD" else body]

    @staticmethod
    def _plain(start_response, status: str, body: bytes, extra: list[tuple[str, str]] | None = None) -> list[bytes]:
        start_response(status, [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body))),
                                *UI_HEADERS, *(extra or [])])
        return [body]
