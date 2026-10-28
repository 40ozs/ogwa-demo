"""0007 — a dedicated audit action for refused governed requests.

Owner decision after P08: an authenticated, well-formed attempt to change governed state
that policy or authorization refuses is recorded in the hash-chained audit trail as
``GOVERNED_REQUEST_REFUSED``. Unauthenticated, malformed, and generic authorization
failures stay in the API's security log.

The allowed audit actions are an inline CHECK, which SQLite cannot alter, so the table is
rebuilt exactly as 0005 rebuilt it:

1. create ``audit_events_v7``: v0001's DDL with only the action list extended;
2. copy every row verbatim (same ids, sequences, contents, and digests);
3. drop the old table and rename the new one;
4. recreate v0001's indexes and v0002's three audit guard triggers, byte for byte.

Nothing references ``audit_events`` by foreign key, and the hash chain covers each event's
content, not its storage, so the chain verifies unchanged.

Only SQLite is implemented; like 0002–0006, this migration refuses to run on PostgreSQL.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

from app.store.migrations import v0001_core_schema, v0002_append_only_guards
from app.store.migrations.v0001_core_schema import AUDIT_ACTIONS as V0001_AUDIT_ACTIONS
from app.store.migrations.v0001_core_schema import enum
from app.store.migrations.v0005_review_audit_actions import AUDIT_ACTIONS as V0005_AUDIT_ACTIONS

VERSION = 7
NAME = "governed_refusals"

# Frozen with this migration; a test compares it with the domain enum.
AUDIT_ACTIONS = (*V0005_AUDIT_ACTIONS, "GOVERNED_REQUEST_REFUSED")


def _one(statements: list[str], prefix: str) -> str:
    found = [s for s in statements if s.startswith(prefix)]
    assert len(found) == 1, f"expected exactly one statement starting with {prefix!r}"
    return found[0]


def _rebuilt_audit_table() -> str:
    original = _one(v0001_core_schema.STATEMENTS, "CREATE TABLE audit_events (")
    old_check, new_check = enum("action", V0001_AUDIT_ACTIONS), enum("action", AUDIT_ACTIONS)
    assert original.count(old_check) == 1
    return original.replace("CREATE TABLE audit_events (", "CREATE TABLE audit_events_v7 (", 1).replace(old_check, new_check, 1)


_COLUMNS = ("id, sequence, occurred_at, actor_kind, actor_id, action, subject_id, details, previous_digest, digest, "
            "execution_mode, result, correlation_id, before_ref, after_ref")

_AUDIT_INDEXES = [s for s in v0001_core_schema.STATEMENTS if s.startswith("CREATE INDEX ix_audit_")]
_AUDIT_TRIGGERS = [
    _one(v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"], f"CREATE TRIGGER {name} ")
    for name in ("trg_audit_events_no_update", "trg_audit_events_no_delete", "trg_audit_chain")
]
assert len(_AUDIT_INDEXES) == 2

STATEMENTS: list[str] = []

_SQLITE = [
    _rebuilt_audit_table(),
    f"INSERT INTO audit_events_v7 ({_COLUMNS}) SELECT {_COLUMNS} FROM audit_events ORDER BY sequence",
    "DROP TABLE audit_events",
    "ALTER TABLE audit_events_v7 RENAME TO audit_events",
    *_AUDIT_INDEXES,
    *_AUDIT_TRIGGERS,
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
