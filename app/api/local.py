"""Building and serving the API for local synthetic use (D50).

Mapping review runs against the synthetic AD directory over the store's own recorded AD
evidence (owner decision after P08). No production AD adapter exists.

The server binds 127.0.0.1 only; there is no option to bind anything else. ``wsgiref`` is
single-threaded, which also keeps the store's one SQLite connection on one thread. A
production deployment needs a reviewed WSGI server, TLS, and a real identity adapter;
none of those exist in this build.
"""

import logging
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from app.api.app import OgwaApi
from app.api.authz import load_role_bindings
from app.api.identity import SyntheticIdentityAdapter, load_synthetic_directory
from app.api.services import MappingReviewGateway
from app.api.sessions import SessionManager
from app.demo.synthetic_directory import SyntheticMappingGateway
from app.remediation.aap import TemplateMetadata
from app.domain.quarantine import QuarantineOus
from app.remediation.allowlist import RemediationAllowlist, load_allowlist
from app.remediation.quarantine import SYNTHETIC_QUARANTINE_OUS_PATH, load_quarantine_ous
from app.store.store import Store

REPO_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_IDP_PATH = REPO_ROOT / "config" / "synthetic-idp.json"
SYNTHETIC_ROLE_BINDINGS_PATH = REPO_ROOT / "config" / "role-bindings.synthetic.json"
SYNTHETIC_REMEDIATION_ALLOWLIST_PATH = REPO_ROOT / "config" / "remediation-allowlist.synthetic.json"
LOOPBACK_HOST = "127.0.0.1"


def local_origins(port: int) -> tuple[str, ...]:
    return (f"http://{LOOPBACK_HOST}:{port}", f"http://localhost:{port}")


def build_local_api(store: Store, *, clock: Callable[[], datetime], port: int | None = None,
                    sessions: SessionManager | None = None,
                    mapping_gateway: MappingReviewGateway | None = None, synthetic_directory: bool = True,
                    logger: logging.Logger | None = None, remediation_allowlist: RemediationAllowlist | None = None,
                    remediation_templates: Mapping[int, TemplateMetadata] | None = None,
                    quarantine_ous: QuarantineOus | None = None, routes=None) -> OgwaApi:
    """The API over a SYNTHETIC store with the synthetic identity adapter and role bindings.

    Mapping review uses ``mapping_gateway`` if one is given; otherwise, unless
    ``synthetic_directory`` is False, the synthetic AD directory over the store's own AD
    evidence. Both refuse anything but LOCAL_SYNTHETIC with a SYNTHETIC store.

    Remediation dry runs use ``remediation_allowlist`` if one is given, otherwise
    config/remediation-allowlist.synthetic.json (P10). The AD stages use ``quarantine_ous`` if
    one is given, otherwise config/quarantine-ous.synthetic.json (D136).

    ``routes`` replaces the route table; the demo runtime passes the same routes with its
    labels and mutation policy applied (``app.runtime.api.demo_routes``).
    """
    identity = SyntheticIdentityAdapter(load_synthetic_directory(SYNTHETIC_IDP_PATH), mode=store.mode,
                                        environment=store.marker.environment)
    bindings = load_role_bindings(SYNTHETIC_ROLE_BINDINGS_PATH, environment=store.marker.environment)
    if mapping_gateway is None and synthetic_directory:
        mapping_gateway = SyntheticMappingGateway(store, clock=clock)
    if remediation_allowlist is None:
        remediation_allowlist = load_allowlist(SYNTHETIC_REMEDIATION_ALLOWLIST_PATH,
                                               environment=store.marker.environment)
    if quarantine_ous is None:
        quarantine_ous = load_quarantine_ous(SYNTHETIC_QUARANTINE_OUS_PATH, environment=store.marker.environment)
    return OgwaApi(store=store, identity=identity, bindings=bindings, clock=clock, mode=store.mode,
                   sessions=sessions, mapping_gateway=mapping_gateway,
                   allowed_origins=local_origins(port) if port else (), logger=logger,
                   remediation_allowlist=remediation_allowlist, remediation_templates=remediation_templates,
                   quarantine_ous=quarantine_ous, routes=routes)


class OffsetClock:
    """Real elapsed time from a fixed starting instant. Lets the synthetic demo world, whose
    evidence is dated around its own "now", be explored with fresh-enough evidence."""

    def __init__(self, start: datetime, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._start = start
        self._origin = monotonic()
        self._monotonic = monotonic

    def __call__(self) -> datetime:
        return self._start + timedelta(seconds=self._monotonic() - self._origin)


class _QuietHandler(WSGIRequestHandler):
    # The API writes its own structured, redacted log line per request; the default
    # handler would print raw request lines (with query strings) to stderr.
    def log_message(self, format: str, *args) -> None:
        return


def make_local_server(app: Callable, port: int) -> WSGIServer:
    """Serve ``app`` (the API, or the UI and API together, ``app.ui.server.OgwaWebApp``) on loopback."""
    if not (port == 0 or 1024 <= port <= 65535):
        raise ValueError("port must be 0 or 1024-65535")
    return make_server(LOOPBACK_HOST, port, app, handler_class=_QuietHandler)
