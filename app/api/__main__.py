"""``python -m app.api serve``: run the operator API and UI locally over a SYNTHETIC store.

    serve [--port 8765] [--demo-clock]

Binds 127.0.0.1 only. Requires LOCAL_SYNTHETIC mode (the default) and a SYNTHETIC store at
OGWA_DATABASE_URL (see ``python -m app.store``). ``--demo-clock`` starts the API clock just
after the store's newest audit event, so the synthetic demo world's evidence is fresh.
Contacts no external system. Exit codes: 0 stopped, 2 refused.

With ``OGWA_RUNTIME_MODE=demo`` the same UI and API serve the demo store instead
(``app.runtime.api``, docs/demo-mode.md): the store must already hold the configured demo
dataset (``python -m app.runtime reset-demo``), and the demo clock is always on.
"""

import argparse
import logging
import sys

from app.api.local import OffsetClock, build_local_api, make_local_server
from app.core.errors import OgwaSafetyError
from app.core.logging_setup import configure_logging
from app.core.modes import ExecutionMode
from app.core.startup import bootstrap
from app.store.environment import DatabaseEnvironment
from app.store.store import Store, utc_now
from app.ui.server import OgwaWebApp

DEFAULT_PORT = 8765


class _ClockHolder:
    def __init__(self) -> None:
        self.source = utc_now

    def __call__(self):
        return self.source()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.api")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="serve the API on 127.0.0.1")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--demo-clock", action="store_true")
    args = parser.parse_args(argv)

    configure_logging("INFO")
    log = logging.getLogger("ogwa.api")
    try:
        context = bootstrap()
        if context.settings.is_demo:
            return _serve_demo(context, args.port, log)
        if context.settings.mode is not ExecutionMode.LOCAL_SYNTHETIC:
            raise OgwaSafetyError("the API serves only in LOCAL_SYNTHETIC mode in this build (D50)")
        clock = _ClockHolder()  # one clock for the store and the API, so their timestamps agree
        store = Store.open(context.settings.database, mode=context.settings.mode, clock=clock)
        if store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
            store.close()
            raise OgwaSafetyError("the API serves only a SYNTHETIC store in this build (D50)")
        if args.demo_clock:
            newest = store.audit_events_page(limit=1)
            clock.source = OffsetClock(newest[0].occurred_at if newest else utc_now())
        api = build_local_api(store, clock=clock, port=args.port)
        server = make_local_server(OgwaWebApp(api), args.port)  # the operator UI (P09) and the API, one origin
    except (OgwaSafetyError, ValueError, OSError) as exc:
        log.error("OGWA API refused to start: %s", exc)
        return 2
    configure_logging(context.settings.log_level)
    host, port = server.server_address[:2]
    log.info("OGWA operator UI and API listening on http://%s:%s (LOCAL_SYNTHETIC, synthetic sign-in only)", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()
    return 0


def _serve_demo(context, port: int, log: logging.Logger) -> int:
    """The demo runtime: the real UI and API over the validated demo store, synthetic providers only."""
    from app.runtime.api import build_demo_application

    try:
        clock = _ClockHolder()
        demo = build_demo_application(context.settings, clock=clock, port=port)
        newest = demo.store.audit_events_page(limit=1)
        clock.source = OffsetClock(newest[0].occurred_at if newest else utc_now())
        server = make_local_server(demo.web_app, port)
    except (OgwaSafetyError, ValueError, OSError) as exc:
        if "demo" in locals():
            demo.close()
        log.error("OGWA demo refused to start: %s", exc)
        return 2
    configure_logging(context.settings.log_level)
    host, bound = server.server_address[:2]
    log.info("OGWA DEMO ENVIRONMENT listening on http://%s:%s (dataset %s, synthetic data, no live integrations)",
             host, bound, demo.dataset.key)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        demo.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
