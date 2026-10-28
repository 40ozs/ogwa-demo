"""0005 — dedicated audit actions for mapping and policy reviews; policy reviewer roles.

Owner decisions after P07:

- D41: mapping reviews and policy reviews get their own audit actions
  (``MAPPING_REVIEW_RECORDED``, ``POLICY_REVIEW_RECORDED``) instead of ``APPROVAL_RECORDED``
  with a ``kind`` detail. Historical events are preserved unchanged.
- D33: Identity/Automation proposes a policy change; a different Security/IAM reviewer
  approves it. Each policy version records both roles.

The allowed audit actions are an inline CHECK in v0001, which SQLite cannot alter. The
table is therefore rebuilt in this migration's transaction:

1. create ``audit_events_v5``: v0001's DDL with only the action list extended;
2. copy every row verbatim (same ids, sequences, contents, and digests);
3. drop the old table (dropping fires no triggers) and rename the new one;
4. recreate v0001's indexes and v0002's three audit guard triggers, byte for byte.

Nothing references ``audit_events`` by foreign key. The hash chain covers each event's
content, not its storage, so it verifies unchanged; tests compare every row before and
after.

Only SQLite is implemented. Like 0002–0004, this migration refuses to run on PostgreSQL
(fail closed); there, adding a value is an ``ALTER TABLE ... DROP/ADD CONSTRAINT``.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

from app.store.migrations import v0001_core_schema, v0002_append_only_guards
from app.store.migrations.v0001_core_schema import AUDIT_ACTIONS as V0001_AUDIT_ACTIONS
from app.store.migrations.v0001_core_schema import enum

VERSION = 5
NAME = "review_audit_actions"

# Frozen with this migration; a test compares them with the domain enums.
AUDIT_ACTIONS = (*V0001_AUDIT_ACTIONS, "MAPPING_REVIEW_RECORDED", "POLICY_REVIEW_RECORDED")
PROPOSER_ROLES = ("IDENTITY_AUTOMATION",)
APPROVER_ROLES = ("SECURITY_IAM",)
POLICY_ROLES = (*PROPOSER_ROLES, *APPROVER_ROLES)


def _one(statements: list[str], prefix: str) -> str:
    found = [s for s in statements if s.startswith(prefix)]
    assert len(found) == 1, f"expected exactly one statement starting with {prefix!r}"
    return found[0]


def _rebuilt_audit_table() -> str:
    original = _one(v0001_core_schema.STATEMENTS, "CREATE TABLE audit_events (")
    old_check, new_check = enum("action", V0001_AUDIT_ACTIONS), enum("action", AUDIT_ACTIONS)
    assert original.count(old_check) == 1
    return original.replace("CREATE TABLE audit_events (", "CREATE TABLE audit_events_v5 (", 1).replace(old_check, new_check, 1)


_COLUMNS = ("id, sequence, occurred_at, actor_kind, actor_id, action, subject_id, details, previous_digest, digest, "
            "execution_mode, result, correlation_id, before_ref, after_ref")

_AUDIT_INDEXES = [s for s in v0001_core_schema.STATEMENTS if s.startswith("CREATE INDEX ix_audit_")]
_AUDIT_TRIGGERS = [
    _one(v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"], f"CREATE TRIGGER {name} ")
    for name in ("trg_audit_events_no_update", "trg_audit_events_no_delete", "trg_audit_chain")
]
assert len(_AUDIT_INDEXES) == 2


def _refuse(name: str, timing: str, table: str, message: str, when: str) -> str:
    assert "'" not in message, "trigger messages are embedded in single-quoted SQL"
    return f"CREATE TRIGGER {name} {timing} ON {table}\nWHEN {when}\nBEGIN\n    SELECT RAISE(ABORT, '{message}');\nEND"


# Everything is engine-specific: the rebuild and the triggers are SQLite only.
STATEMENTS: list[str] = []

_SQLITE = [
    _rebuilt_audit_table(),
    f"INSERT INTO audit_events_v5 ({_COLUMNS}) SELECT {_COLUMNS} FROM audit_events ORDER BY sequence",
    "DROP TABLE audit_events",
    "ALTER TABLE audit_events_v5 RENAME TO audit_events",
    *_AUDIT_INDEXES,
    *_AUDIT_TRIGGERS,
    # D33: who proposed and who approved each policy version, by role. Nullable only because
    # SQLite cannot add a NOT NULL column without a default; the trigger requires both.
    "ALTER TABLE policy_versions ADD COLUMN proposed_by_role TEXT "
    f"CHECK (proposed_by_role IS NULL OR proposed_by_role IN ({', '.join(repr(r) for r in PROPOSER_ROLES)}))",
    "ALTER TABLE policy_versions ADD COLUMN approved_by_role TEXT "
    f"CHECK (approved_by_role IS NULL OR approved_by_role IN ({', '.join(repr(r) for r in APPROVER_ROLES)}))",
    _refuse("trg_policy_versions_roles", "BEFORE INSERT", "policy_versions",
            "a policy version needs an Identity/Automation proposer and a Security/IAM approver",
            "NEW.proposed_by_role IS NULL OR NEW.approved_by_role IS NULL"),
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
