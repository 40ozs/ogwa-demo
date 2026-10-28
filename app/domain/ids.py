"""Stable internal identifiers and shared field validation.

OGWA keys every entity by an ID it mints itself. External identifiers (Okta object IDs,
AD objectGUID, SID, distinguished name) are stored as attributes, never as primary keys:
names and DNs change, SIDs and names can collide across domains, and Okta IDs belong to
one tenant.
"""

import hashlib
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from enum import StrEnum

from app.domain.errors import InvalidRecord


class IdKind(StrEnum):
    OKTA_APPLICATION = "oapp"
    OKTA_GROUP = "ogrp"
    ASSIGNMENT = "asgn"
    USAGE_OBSERVATION = "use"
    AD_GROUP = "adg"
    IDENTITY_MAPPING = "map"
    DEPENDENCY_EVIDENCE = "dep"
    CANDIDATE = "cand"
    DECISION = "dec"
    APPROVAL = "apr"
    EXECUTION_JOB = "job"
    AUDIT_EVENT = "aud"
    OBSERVATION = "obs"  # one stored observation of an evidence record (P03 store)
    COLLECTOR_RUN = "run"
    REQUEST = "req"  # correlation id shared by every audit event of one operation
    MAPPING_REVIEW = "mrev"  # one human review event of an Okta-to-AD mapping (P06 registry)
    POLICY_VERSION = "pver"  # one approved version of the candidate-classification policy (P07)
    SYNTHETIC_DIRECTORY = "sdir"  # the synthetic directory snapshot of a demo dataset (0012)


_ID_RE = re.compile(r"^(?P<kind>[a-z]+)_(?P<hex>[0-9a-f]{32})$")
_EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")
_MAX_TEXT = 2000


# Set only inside ``deterministic_ids``; None means random ids.
_ID_SOURCE: ContextVar["_DeterministicIds | None"] = ContextVar("ogwa_id_source", default=None)


class _DeterministicIds:
    def __init__(self, namespace: str) -> None:
        self._namespace = namespace
        self._counters: dict[IdKind, int] = {}

    def next(self, kind: IdKind) -> str:
        n = self._counters[kind] = self._counters.get(kind, 0) + 1
        digest = hashlib.sha256(f"{self._namespace}:{kind.value}:{n}".encode()).hexdigest()
        return f"{kind.value}_{digest[:32]}"


def new_id(kind: IdKind) -> str:
    source = _ID_SOURCE.get()
    return source.next(kind) if source is not None else f"{kind.value}_{uuid.uuid4().hex}"


@contextmanager
def deterministic_ids(namespace: str) -> Iterator[None]:
    """Within this block, ``new_id`` returns reproducible ids derived from ``namespace``.

    For synthetic seeding and tests only: the same sequence of calls yields the same ids.
    """
    check_text(namespace, "namespace", max_length=100)
    token = _ID_SOURCE.set(_DeterministicIds(namespace))
    try:
        yield
    finally:
        _ID_SOURCE.reset(token)


def check_id(value: object, kind: IdKind, field: str) -> str:
    if not isinstance(value, str) or (m := _ID_RE.match(value)) is None or m["kind"] != kind.value:
        raise InvalidRecord(f"{field} must be an internal {kind.name} id ({kind.value}_<32 hex>)")
    return value


def check_ids(values: object, kind: IdKind, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise InvalidRecord(f"{field} must be a tuple")
    if not values and not allow_empty:
        raise InvalidRecord(f"{field} must not be empty")
    if len(set(values)) != len(values):
        raise InvalidRecord(f"{field} contains duplicates")
    for value in values:
        check_id(value, kind, field)
    return values


def check_external_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not _EXTERNAL_ID_RE.match(value):
        raise InvalidRecord(f"{field} must be 1-64 alphanumeric characters")
    return value


def check_text(value: object, field: str, *, max_length: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidRecord(f"{field} must be a non-empty string")
    if len(value) > max_length:
        raise InvalidRecord(f"{field} must be at most {max_length} characters")
    return value


def check_utc(value: object, field: str) -> datetime:
    """Require a timezone-aware datetime. Naive datetimes are ambiguous and rejected."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidRecord(f"{field} must be a timezone-aware datetime")
    return value


def check_enum(value: object, enum_type: type, field: str):
    if not isinstance(value, enum_type):
        raise InvalidRecord(f"{field} must be a {enum_type.__name__}")
    return value
