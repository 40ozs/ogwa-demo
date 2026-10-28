"""``python -m app``: validate configuration and print the startup banner.

The P01 build starts no services and contacts no external systems.
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
    log.info("Bootstrap build: no services started, no external systems contacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
