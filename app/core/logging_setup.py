"""Structured (JSON lines) logging with redaction applied to every record."""

import json
import logging
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, TextIO

from app.core.redaction import REDACTED, SENSITIVE_KEY, redact_text
from app.core.secret import Secret

ROOT_LOGGER = "ogwa"

# Values that report presence without revealing content; safe under sensitive keys.
_PRESENCE_SENTINELS = frozenset({"<set>", "<unset>"})

_HANDLER_MARKER = "_ogwa_handler"


def redact_field(key: str, value: Any) -> Any:
    if isinstance(value, Secret):
        return REDACTED
    if SENSITIVE_KEY.search(key) and not (isinstance(value, str) and value in _PRESENCE_SENTINELS):
        return REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))


class RedactingJsonFormatter(logging.Formatter):
    """Formats records as one JSON object per line.

    Structured fields are passed as ``extra={"ogwa": {...}}`` and emitted under ``fields``.
    The message, every field, and any exception text are redacted.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        fields = getattr(record, "ogwa", None)
        if isinstance(fields, Mapping):
            payload["fields"] = {str(k): redact_field(str(k), v) for k, v in fields.items()}
        if record.exc_info:
            payload["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=lambda v: redact_text(str(v)))


class _RedactingStreamHandler(logging.StreamHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        # The stdlib fallback prints the raw message and arguments; report only the failure type.
        if logging.raiseExceptions and sys.stderr:
            try:
                sys.stderr.write(f"--- OGWA logging error: {type(sys.exc_info()[1]).__name__}; record withheld ---\n")
            except OSError:
                pass


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> logging.Logger:
    logger = logging.getLogger(ROOT_LOGGER)
    for existing in list(logger.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            logger.removeHandler(existing)
    handler = _RedactingStreamHandler(stream or sys.stderr)
    handler.setFormatter(RedactingJsonFormatter())
    setattr(handler, _HANDLER_MARKER, True)
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
