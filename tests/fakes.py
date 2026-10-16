"""Test doubles and synthetic fixtures. Nothing here contacts a real system."""

import contextlib
import io
import logging

from app.core.logging_setup import RedactingJsonFormatter


@contextlib.contextmanager
def captured_logs(name: str = "ogwa"):
    logger = logging.getLogger(name)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingJsonFormatter())
    saved = (logger.level, logger.propagate)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield stream
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]
