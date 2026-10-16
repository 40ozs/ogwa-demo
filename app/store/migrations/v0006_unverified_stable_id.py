"""0006 — the UNVERIFIED_STABLE_ID mapping confidence (owner decision D56).

A directory-source objectSid that resolves to one AD group, while the mechanism is not yet
verified (D37), is recorded as ``UNVERIFIED_STABLE_ID``: non-exact, and distinct from
``NAME_ONLY``. The allowed confidences are an inline CHECK in v0001, which SQLite cannot
alter, so ``identity_mapping_observations`` is rebuilt in this migration's transaction:

1. defer foreign-key checks to commit (``identity_mapping_candidates`` references the table);
2. copy every row into a plain backup table;
3. drop the table (dropping fires no triggers; each candidate row now counts as a deferred
   violation) and create it again under the same name from v0001's DDL, with only the
   confidence list extended;
4. re-insert every row verbatim (each re-inserted parent clears its children's violations)
   and drop the backup;
5. recreate v0001's index and v0002's two append-only triggers, byte for byte.

A rename is deliberately not used: SQLite does not clear deferred violations when a table is
renamed into place, only when parent rows are inserted. At commit every candidate row
references an existing observation, so the deferred check passes; otherwise the whole
migration rolls back. Stored observation digests do not depend on storage, so every
observation still verifies.

``mapping_reviews`` (0003) is unchanged: no review method yields this confidence.

Only SQLite is implemented. Like 0002–0005, this migration refuses to run on PostgreSQL.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

from app.store.migrations import v0001_core_schema, v0002_append_only_guards
from app.store.migrations.v0001_core_schema import CONFIDENCES as V0001_CONFIDENCES
from app.store.migrations.v0001_core_schema import enum

VERSION = 6
NAME = "unverified_stable_id"

# Frozen with this migration; a test compares them with the domain enum.
CONFIDENCES = (*V0001_CONFIDENCES, "UNVERIFIED_STABLE_ID")

_TABLE = "identity_mapping_observations"


def _one(statements: list[str], prefix: str) -> str:
    found = [s for s in statements if s.startswith(prefix)]
    assert len(found) == 1, f"expected exactly one statement starting with {prefix!r}"
    return found[0]


def _rebuilt_table() -> str:
    original = _one(v0001_core_schema.STATEMENTS, f"CREATE TABLE {_TABLE} (")
    old_check, new_check = enum("confidence", V0001_CONFIDENCES), enum("confidence", CONFIDENCES)
    assert original.count(old_check) == 1
    return original.replace(old_check, new_check, 1)


_INDEXES = [s for s in v0001_core_schema.STATEMENTS if s.startswith("CREATE INDEX ") and f" ON {_TABLE} " in s]
_TRIGGERS = [
    _one(v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"], f"CREATE TRIGGER {name} ")
    for name in (f"trg_{_TABLE}_no_update", f"trg_{_TABLE}_no_delete")
]
assert len(_INDEXES) == 1

STATEMENTS: list[str] = []

_BACKUP = "ogwa_v0006_backup"

_SQLITE = [
    "PRAGMA defer_foreign_keys = ON",
    f"CREATE TABLE {_BACKUP} AS SELECT * FROM {_TABLE}",
    f"DROP TABLE {_TABLE}",
    _rebuilt_table(),
    f"INSERT INTO {_TABLE} SELECT * FROM {_BACKUP} ORDER BY observation_id",
    f"DROP TABLE {_BACKUP}",
    *_INDEXES,
    *_TRIGGERS,
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
