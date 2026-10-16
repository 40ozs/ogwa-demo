"""``python -m app``: validate configuration and print the startup banner.

Starts no service and contacts no external system. ``python -m app.api serve`` serves the demo.
"""

import logging

from app.core.errors import ConfigError
from app.core.logging_setup import configure_logging
from app.core.startup import bootstrap


def main() -> int:
    configure_logging("INFO")
    log = logging.getLogger("ogwa.startup")
    try:
        context = bootstrap()
    except ConfigError as exc:
        log.error("OGWA startup refused: %s", exc)
        return 2
    configure_logging(context.settings.log_level)
    log.info("Configuration valid: no services started, no external systems contacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
