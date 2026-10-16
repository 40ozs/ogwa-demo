"""The identity of a demo store, read the same way from SQLite and from D1.

``IDENTITY_SQL`` is one statement with a scalar subquery per field, so the Worker can compare
the store it serves with the D1 database in a single D1 query per request (a handful of rows
read, all by key). The fields are the store's own identity evidence: the environment marker,
the schema version, the audit head, and the synthetic directory snapshot (migration 0012),
whose digest the seed's audit event vouches for. Two stores with the same identity hold the
same audit chain, and the chain covers every audited write.

``SCHEMA_SQL`` lists the store's schema objects with their SQL, which D1 keeps verbatim. Its
digest tells a complete D1 import from a partial one (docs/deployment/cloudflare-demo.md:
the import runs in phases).
"""

import hashlib
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields

IDENTITY_SQL = (
    "SELECT"
    " (SELECT environment FROM store_metadata WHERE singleton = 1) AS environment,"
    " (SELECT store_instance_id FROM store_metadata WHERE singleton = 1) AS store_instance_id,"
    " (SELECT max(version) FROM schema_migrations) AS schema_version,"
    " (SELECT sequence FROM audit_events ORDER BY sequence DESC LIMIT 1) AS audit_sequence,"
    " (SELECT digest FROM audit_events ORDER BY sequence DESC LIMIT 1) AS audit_head,"
    " (SELECT dataset FROM synthetic_directory_snapshots WHERE singleton = 1) AS dataset,"
    " (SELECT seed FROM synthetic_directory_snapshots WHERE singleton = 1) AS seed,"
    " (SELECT company FROM synthetic_directory_snapshots WHERE singleton = 1) AS company,"
    " (SELECT content_digest FROM synthetic_directory_snapshots WHERE singleton = 1) AS directory_digest,"
    " (SELECT record_count FROM synthetic_directory_snapshots WHERE singleton = 1) AS directory_records"
)

# D1 reserves the _cf_ prefix, and wrangler keeps its own d1_migrations table; neither is
# part of an OGWA store. SQLite's internal objects (sqlite_*) have no SQL of their own.
SCHEMA_SQL = (
    "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL"
    " AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\'"
    " AND name <> 'd1_migrations' ORDER BY type, name"
)


_INTEGER_FIELDS = frozenset({"schema_version", "audit_sequence", "directory_records"})


@dataclass(frozen=True)
class StoreIdentity:
    environment: str | None
    store_instance_id: str | None
    schema_version: int | None
    audit_sequence: int | None
    audit_head: str | None
    dataset: str | None
    seed: str | None
    company: str | None
    directory_digest: str | None
    directory_records: int | None

    @classmethod
    def from_row(cls, row: Mapping) -> "StoreIdentity":
        values = {}
        for f in fields(cls):
            value = row[f.name]
            # D1 returns numbers as JavaScript numbers; a whole float is the same integer.
            if f.name in _INTEGER_FIELDS and isinstance(value, float) and value.is_integer():
                value = int(value)
            values[f.name] = value
        return cls(**values)

    def to_json(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


def read_identity(conn: sqlite3.Connection) -> StoreIdentity:
    row = conn.execute(IDENTITY_SQL).fetchone()
    return StoreIdentity.from_row({key: row[key] for key in row.keys()})


def schema_digest(rows: Iterable[Mapping]) -> str:
    """A digest of a store's schema objects (``SCHEMA_SQL`` rows), in any order."""
    lines = sorted("\x1f".join((r["type"], r["name"], r["tbl_name"], r["sql"])) for r in rows)
    return "sha256:" + hashlib.sha256("\x1e".join(lines).encode("utf-8")).hexdigest()


def read_schema_digest(conn: sqlite3.Connection) -> str:
    return schema_digest(conn.execute(SCHEMA_SQL).fetchall())
