"""0012 — the synthetic directory snapshot (the Null Meridian demo dataset).

A SYNTHETIC store can hold one directory snapshot: the people, departments, groups, nesting,
memberships, application profiles, assignments, governance findings, and portfolio
scenarios of a generated demo company. OGWA's evidence tables cannot express people or
group nesting, and the snapshot is reference data for the demo views, not lifecycle
evidence: no lifecycle decision reads it.

- ``synthetic_directory_snapshots``: at most one row (``singleton``), naming the dataset,
  its seed, its "as of" time, the record count, and the SHA-256 digest of every record.
- ``synthetic_directory_records``: one row per record, keyed by kind and id, with two
  indexed references and a bounded JSON body.

The rows and the seed's ``SYNTHETIC_SEED_LOADED`` audit event are written in one
transaction; the event carries the digest, and ``verify`` recomputes it. SQLite triggers
refuse ``UPDATE`` and ``DELETE`` on both tables and refuse any insert into a store whose
environment marker is not ``SYNTHETIC``, so real data can never sit beside the snapshot.

Only SQLite is implemented; like 0002–0011, this migration refuses to run on PostgreSQL.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

from app.store.migrations.v0001_core_schema import count, digest, enum, internal_id, table, text, ts

VERSION = 12
NAME = "synthetic_directory"

# Frozen with this migration; a test compares it with the domain list.
RECORD_KINDS = ("COMPANY", "DEPARTMENT", "PERSON", "EMPLOYMENT_EVENT", "APPLICATION", "GROUP", "NESTING",
                "MEMBERSHIP", "ASSIGNMENT", "FINDING", "SCENARIO")

STATEMENTS: list[str] = [
    table(
        "synthetic_directory_snapshots",
        internal_id("id", "sdir", pk=True),
        "singleton INTEGER NOT NULL UNIQUE CHECK (singleton = 1)",
        text("dataset", 100),
        text("seed", 100),
        text("company", 200),
        ts("as_of"),
        count("record_count"),
        digest("content_digest"),
        ts("loaded_at"),
        text("correlation_id", 100),
    ),
    table(
        "synthetic_directory_records",
        internal_id("snapshot_id", "sdir") + " REFERENCES synthetic_directory_snapshots (id)",
        enum("kind", RECORD_KINDS),
        text("id", 200),
        text("sort_key", 300),
        text("ref_a", 200, null=True),
        text("ref_b", 200, null=True),
        "body TEXT NOT NULL CHECK (length(body) BETWEEN 2 AND 20000 AND substr(body, 1, 1) = '{')",
        "PRIMARY KEY (kind, id)",
    ),
    "CREATE INDEX ix_synthetic_directory_sort ON synthetic_directory_records (kind, sort_key)",
    "CREATE INDEX ix_synthetic_directory_ref_a ON synthetic_directory_records (kind, ref_a)",
    "CREATE INDEX ix_synthetic_directory_ref_b ON synthetic_directory_records (kind, ref_b)",
]


def _refuse(name: str, timing: str, table_name: str, message: str, when: str | None = None) -> str:
    assert "'" not in message, "trigger messages are embedded in single-quoted SQL"
    condition = f"\nWHEN {when}" if when else ""
    return (
        f"CREATE TRIGGER {name} {timing} ON {table_name}{condition}\n"
        f"BEGIN\n    SELECT RAISE(ABORT, '{message}');\nEND"
    )


_NOT_SYNTHETIC = "coalesce((SELECT environment FROM store_metadata WHERE singleton = 1), '') <> 'SYNTHETIC'"

_SQLITE: list[str] = []
for _table in ("synthetic_directory_snapshots", "synthetic_directory_records"):
    _SQLITE += [
        _refuse(f"trg_{_table}_no_update", "BEFORE UPDATE", _table, f"{_table} is append-only"),
        _refuse(f"trg_{_table}_no_delete", "BEFORE DELETE", _table, f"{_table} is append-only"),
        _refuse(f"trg_{_table}_synthetic_only", "BEFORE INSERT", _table,
                "a synthetic directory snapshot belongs only in a SYNTHETIC store", _NOT_SYNTHETIC),
    ]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
