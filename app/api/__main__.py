"""``python -m app.api serve``: serve the demo's operator UI and API.

    serve [--port 8765] [--host 127.0.0.1|0.0.0.0]

Serves the real UI and API over the demo store (``app.runtime.api``, docs/demo-mode.md). The
store must already hold the configured demo dataset (``python -m app.runtime reset-demo``).
The API clock starts just after the store's newest audit event, so the synthetic world's
evidence is fresh. Contacts no external system.

The server binds 127.0.0.1 by default. ``--host 0.0.0.0`` is for a container, whose port is
published to the host's loopback (compose.yaml); the browser must still reach it as
``http://localhost:<port>`` or ``http://127.0.0.1:<port>`` (the API's Origin check). SIGTERM
stops the server cleanly. Exit codes: 0 stopped, 2 refused.
"""

import argparse
import logging
import signal
import sys

from app.api.local import BIND_HOSTS, LOOPBACK_HOST, OffsetClock, make_local_server
from app.core.errors import OgwaSafetyError
from app.core.logging_setup import configure_logging
from app.core.startup import bootstrap
from app.store.store import utc_now

DEFAULT_PORT = 8765


class _ClockHolder:
    def __init__(self) -> None:
        self.source = utc_now

    def __call__(self):
        return self.source()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.api")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="serve the demo UI and API")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--host", choices=BIND_HOSTS, default=LOOPBACK_HOST)
    args = parser.parse_args(argv)

    configure_logging("INFO")
    log = logging.getLogger("ogwa.api")
    from app.runtime.api import build_demo_application

    demo = None
    try:
        context = bootstrap()
        clock = _ClockHolder()  # one clock for the store and the API, so their timestamps agree
        demo = build_demo_application(context.settings, clock=clock, port=args.port)
        newest = demo.store.audit_events_page(limit=1)
        clock.source = OffsetClock(newest[0].occurred_at if newest else utc_now())
        server = make_local_server(demo.web_app, args.port, host=args.host)
    except (OgwaSafetyError, ValueError, OSError) as exc:
        if demo is not None:
            demo.close()
        log.error("OGWA demo refused to start: %s", exc)
        return 2
    configure_logging(context.settings.log_level)
    host, bound = server.server_address[:2]
    log.info("OGWA DEMO ENVIRONMENT listening on http://%s:%s (dataset %s, synthetic data, no live integrations)",
             host, bound, demo.dataset.key)
    signal.signal(signal.SIGTERM, signal.default_int_handler)  # docker stop: leave through the finally below
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
