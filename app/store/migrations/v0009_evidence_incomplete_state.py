"""0009 — the EVIDENCE_INCOMPLETE lifecycle state (owner decision after P09).

EVIDENCE_INCOMPLETE means required evidence was never fully or properly obtained;
STALE_EVIDENCE means once-complete evidence outlived its freshness window. Until now both
were stored as STALE_EVIDENCE. The allowed lifecycle states are inline CHECKs in v0001 on
``candidates`` (``state``, ``blocked_from``) and ``decisions`` (``from_state``,
``to_state``), which SQLite cannot alter, so both tables are rebuilt in this migration's
transaction, as 0006 rebuilt ``identity_mapping_observations``:

1. defer foreign-key checks to commit (``candidate_assignments``, ``approvals``,
   ``execution_jobs``, and ``decisions`` reference ``candidates``);
2. copy every row of both tables into plain backup tables;
3. drop ``decisions``, then ``candidates`` (dropping fires no triggers, and takes each
   table's own triggers and indexes with it; each child row now counts as a deferred
   violation), and create both again under the same names from v0001's DDL, with only
   the state lists extended;
4. re-insert every row verbatim, ``candidates`` first, while their triggers are absent:
   ``trg_candidates_start_discovered`` and ``trg_decisions_follow_candidate`` exist to
   refuse exactly such inserts of history. Then drop the backups;
5. recreate v0001's three indexes and v0002's seven triggers on these tables, byte for byte.

A rename is deliberately not used: SQLite does not clear deferred violations when a table is
renamed into place, only when parent rows are inserted. At commit every child row
references an existing parent, so the deferred check passes; otherwise the whole migration
rolls back. Candidate histories are verified from the decisions on load, and no stored
digest depends on storage, so a migrated store verifies as before.

Only SQLite is implemented. Like 0002–0008, this migration refuses to run on PostgreSQL.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

import re

from app.store.migrations import v0001_core_schema, v0002_append_only_guards
from app.store.migrations.v0001_core_schema import LIFECYCLE_STATES as V0001_LIFECYCLE_STATES
from app.store.migrations.v0001_core_schema import enum

VERSION = 9
NAME = "evidence_incomplete_state"

# Frozen with this migration; a test compares them with the domain enum.
LIFECYCLE_STATES = (*V0001_LIFECYCLE_STATES, "EVIDENCE_INCOMPLETE")

_TABLES = ("candidates", "decisions")  # parent first
_COLUMNS = {"candidates": (("state", False), ("blocked_from", True)),
            "decisions": (("from_state", False), ("to_state", False))}
_ORDER = {"candidates": "id", "decisions": "candidate_id, sequence"}


def _one(statements: list[str], prefix: str) -> str:
    found = [s for s in statements if s.startswith(prefix)]
    assert len(found) == 1, f"expected exactly one statement starting with {prefix!r}"
    return found[0]


def _rebuilt_table(name: str) -> str:
    ddl = _one(v0001_core_schema.STATEMENTS, f"CREATE TABLE {name} (")
    for column, nullable in _COLUMNS[name]:
        old, new = enum(column, V0001_LIFECYCLE_STATES, null=nullable), enum(column, LIFECYCLE_STATES, null=nullable)
        assert ddl.count(old) == 1, f"{name}.{column}"
        ddl = ddl.replace(old, new, 1)
    return ddl


def _on(table: str, statement: str) -> bool:
    first_line = statement.split("\n", 1)[0]
    return re.search(rf" ON {table}$", first_line) is not None


_INDEXES = [s for s in v0001_core_schema.STATEMENTS
            if s.startswith(("CREATE INDEX ", "CREATE UNIQUE INDEX ")) and any(f" ON {t} " in s for t in _TABLES)]
_TRIGGERS = [s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
             if s.startswith("CREATE TRIGGER ") and any(_on(t, s) for t in _TABLES)]
assert len(_INDEXES) == 3, _INDEXES
assert len(_TRIGGERS) == 7, [s.split()[2] for s in _TRIGGERS]

STATEMENTS: list[str] = []


def _backup(table: str) -> str:
    return f"ogwa_v0009_{table}_backup"


_SQLITE = [
    "PRAGMA defer_foreign_keys = ON",
    *(f"CREATE TABLE {_backup(t)} AS SELECT * FROM {t}" for t in _TABLES),
    *(f"DROP TABLE {t}" for t in reversed(_TABLES)),  # the child first
    *(statement for t in _TABLES for statement in (
        _rebuilt_table(t),
        f"INSERT INTO {t} SELECT * FROM {_backup(t)} ORDER BY {_ORDER[t]}",
        f"DROP TABLE {_backup(t)}",
    )),
    *_INDEXES,
    *_TRIGGERS,
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
