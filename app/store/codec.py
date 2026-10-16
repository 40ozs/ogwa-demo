"""Column encodings shared by SQLite and PostgreSQL.

Timestamps are fixed-width UTC text (``YYYY-MM-DDTHH:MM:SS.ffffffZ``), so lexical order
is time order on both engines and the CHECK constraints can validate the shape. Booleans
are 0/1 integers. Short lists are canonical JSON text.
"""

import json
from datetime import datetime, timezone

from app.domain.ids import check_utc
from app.store.errors import StoreIntegrityError

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    return check_utc(value, "timestamp").astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_ts(text: str | None) -> datetime | None:
    if text is None:
        return None
    try:
        return datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise StoreIntegrityError(f"stored timestamp {text!r} is malformed") from None


def flag(value: bool) -> int:
    if not isinstance(value, bool):
        raise TypeError("expected a bool")
    return int(value)


def unflag(value: object) -> bool:
    if value not in (0, 1) or isinstance(value, bool):
        raise StoreIntegrityError(f"stored flag {value!r} is not 0 or 1")
    return bool(value)


def json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_json(text: str) -> object:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        raise StoreIntegrityError("stored JSON is malformed") from None


def str_tuple(text: str) -> tuple[str, ...]:
    value = parse_json(text)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise StoreIntegrityError("stored list is not a list of strings")
    return tuple(value)
