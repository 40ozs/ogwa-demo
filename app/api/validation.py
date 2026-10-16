"""Input validation: strict bodies, strict queries, and bounded pagination.

Unknown body keys and unknown query parameters are refused, not ignored, so a misspelt
or smuggled field (for example ``"force": true``) can never be silently dropped and
mistaken for success.
"""

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeVar

from app.api.errors import bad_request, not_found, validation
from app.domain.evidence import DIGEST_PREFIX
from app.domain.ids import IdKind

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_OFFSET = 100_000
MAX_REASON_LENGTH = 1000
_ID_RE = re.compile(r"^(?P<kind>[a-z]+)_[0-9a-f]{32}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CURSOR_RE = re.compile(r"^o:(\d{1,6})$")

E = TypeVar("E", bound=StrEnum)


def path_id(value: str, kind: IdKind, what: str) -> str:
    """An internal id from the path. Anything malformed is simply not found."""
    m = _ID_RE.match(value or "")
    if m is None or m["kind"] != kind.value:
        raise not_found(what)
    return value


class Body:
    """Typed, bounded access to a JSON request body. Construction refuses unknown keys."""

    def __init__(self, body: Mapping[str, Any] | None, *, allowed: Iterable[str]) -> None:
        self._body = dict(body or {})
        unknown = sorted(set(self._body) - set(allowed))
        if unknown:
            raise validation(f"Unknown field(s): {', '.join(k[:40] for k in unknown[:10])}.")

    def raw(self, name: str) -> Any:
        return self._body.get(name)

    def text(self, name: str, *, max_length: int = MAX_REASON_LENGTH, required: bool = True) -> str | None:
        value = self._body.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str) or not value.strip():
            raise validation(f"{name} must be a non-empty string.")
        if len(value) > max_length:
            raise validation(f"{name} must be at most {max_length} characters.")
        return value

    def enum(self, name: str, enum_type: type[E], *, required: bool = True) -> E | None:
        value = self._body.get(name)
        if value is None and not required:
            return None
        allowed = tuple(enum_type)
        if not isinstance(value, str) or value not in {c.value for c in allowed}:
            raise validation(f"{name} must be one of: {', '.join(c.value for c in allowed)}.")
        return enum_type(value)

    def internal_id(self, name: str, kind: IdKind, *, required: bool = True) -> str | None:
        value = self._body.get(name)
        if value is None and not required:
            return None
        m = _ID_RE.match(value) if isinstance(value, str) else None
        if m is None or m["kind"] != kind.value:
            raise validation(f"{name} must be an OGWA {kind.name.lower()} id ({kind.value}_<32 hex>).")
        return value

    def digest(self, name: str, *, required: bool = True) -> str | None:
        value = self._body.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str) or not _DIGEST_RE.match(value):
            raise validation(f"{name} must be a {DIGEST_PREFIX}<64 hex> digest.")
        return value

    def boolean(self, name: str, *, required: bool = True) -> bool | None:
        value = self._body.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, bool):
            raise validation(f"{name} must be true or false.")
        return value

    def integer(self, name: str, *, minimum: int, maximum: int, required: bool = True) -> int | None:
        value = self._body.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise validation(f"{name} must be a whole number from {minimum} to {maximum}.")
        return value


def check_query(query: Mapping[str, str], allowed: Iterable[str]) -> None:
    unknown = sorted(set(query) - set(allowed))
    if unknown:
        raise bad_request(f"Unknown query parameter(s): {', '.join(k[:40] for k in unknown[:10])}.")


@dataclass(frozen=True)
class Page:
    limit: int
    offset: int

    def envelope(self, items: list, *, more: bool, total: int | None = None) -> dict[str, Any]:
        """``offset``, ``previousCursor``, and ``total`` (``null`` when not counted) are additive:
        they let a table say "51–100 of 298" and step back a page."""
        next_cursor = encode_cursor(self.offset + self.limit) if more else None
        previous = encode_cursor(max(0, self.offset - self.limit)) if self.offset else None
        return {"items": items, "page": {"limit": self.limit, "nextCursor": next_cursor, "previousCursor": previous,
                                         "offset": self.offset, "total": total}}

    def slice(self, items: list) -> dict[str, Any]:
        """The envelope for one page of a list that is already complete in memory."""
        return self.envelope(items[self.offset: self.offset + self.limit],
                             more=len(items) > self.offset + self.limit, total=len(items))


SORT_QUERY = frozenset({"sort", "order"})


@dataclass(frozen=True)
class Sort:
    key: str
    descending: bool


def sort_from(query: Mapping[str, str], allowed: Iterable[str]) -> Sort | None:
    """``sort=<field>&order=asc|desc`` from the query; ``None`` keeps the listing's own order."""
    key, order = query.get("sort"), query.get("order")
    if order is not None and order not in ("asc", "desc"):
        raise bad_request("order must be asc or desc.")
    if key is None:
        return None
    allowed = sorted(allowed)
    if key not in allowed:
        raise bad_request(f"sort must be one of: {', '.join(allowed)}.")
    return Sort(key, order == "desc")


def sorted_by(items: list, sort: Sort | None, keys: Mapping[str, Any]) -> list:
    """A stable sort: ties keep the listing's own order, and a missing value (``None``) sorts
    last in both directions, so an unknown date never poses as the oldest or the newest."""
    if sort is None:
        return items
    key = keys[sort.key]
    present = [x for x in items if key(x) is not None]
    missing = [x for x in items if key(x) is None]
    return sorted(present, key=key, reverse=sort.descending) + missing


def page_from(query: Mapping[str, str]) -> Page:
    raw_limit = query.get("limit")
    if raw_limit is None:
        limit = DEFAULT_PAGE_SIZE
    elif raw_limit.isascii() and raw_limit.isdigit() and 1 <= int(raw_limit) <= MAX_PAGE_SIZE:
        limit = int(raw_limit)
    else:
        raise bad_request(f"limit must be a whole number from 1 to {MAX_PAGE_SIZE}.")
    return Page(limit, decode_cursor(query.get("cursor")))


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"o:{offset}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii") if len(cursor) <= 24 else ""
    except (binascii.Error, UnicodeDecodeError, ValueError):
        text = ""
    m = _CURSOR_RE.match(text)
    if m is None or int(m[1]) > MAX_OFFSET:
        raise bad_request("cursor is not valid; use the nextCursor value from a previous page.")
    return int(m[1])
