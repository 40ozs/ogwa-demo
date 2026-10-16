"""A directory snapshot as the store holds it: typed records with a content digest.

The digest covers every record's kind, id, sort key, references, and canonical JSON body, in
(kind, id) order, so two snapshots are equal exactly when their digests are. The store
records the digest in the audit chain when it loads a snapshot, and ``verify`` recomputes it.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.domain.errors import InvalidRecord

RECORD_KINDS = ("COMPANY", "DEPARTMENT", "PERSON", "EMPLOYMENT_EVENT", "APPLICATION", "GROUP", "NESTING",
                "MEMBERSHIP", "ASSIGNMENT", "FINDING", "SCENARIO")
MAX_BODY = 20000


def canonical(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class SnapshotRecord:
    kind: str
    id: str
    sort_key: str
    ref_a: str | None
    ref_b: str | None
    body: str  # canonical JSON object

    def __post_init__(self) -> None:
        if self.kind not in RECORD_KINDS:
            raise InvalidRecord(f"unknown snapshot record kind {self.kind!r}")
        for name in ("id", "sort_key"):
            value = getattr(self, name)
            if not isinstance(value, str) or not 1 <= len(value) <= (200 if name == "id" else 300):
                raise InvalidRecord(f"snapshot record {name} must be 1-200 characters")
        for name in ("ref_a", "ref_b"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 200):
                raise InvalidRecord(f"snapshot record {name} must be 1-200 characters or empty")
        if not isinstance(self.body, str) or not self.body.startswith("{") or len(self.body) > MAX_BODY:
            raise InvalidRecord("snapshot record body must be a JSON object of at most 20000 characters")

    @classmethod
    def of(cls, kind: str, id: str, sort_key: str, body: dict[str, Any], ref_a: str | None = None,
           ref_b: str | None = None) -> "SnapshotRecord":
        return cls(kind, id, sort_key, ref_a, ref_b, canonical(body))

    def line(self) -> str:
        return "\t".join((self.kind, self.id, self.sort_key, self.ref_a or "", self.ref_b or "", self.body))


@dataclass(frozen=True)
class DirectorySnapshot:
    dataset: str
    seed: str
    company: str
    as_of: datetime
    records: tuple[SnapshotRecord, ...]

    def __post_init__(self) -> None:
        keys = [(r.kind, r.id) for r in self.records]
        if len(set(keys)) != len(keys):
            raise InvalidRecord("snapshot records must be unique by kind and id")

    @property
    def digest(self) -> str:
        return content_digest(self.records)


def content_digest(records) -> str:
    h = hashlib.sha256()
    for record in sorted(records, key=lambda r: (r.kind, r.id)):
        h.update(record.line().encode("utf-8"))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()
