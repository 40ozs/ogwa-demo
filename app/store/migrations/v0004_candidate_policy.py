"""0004 — candidate-classification policy (P07).

1. ``dependency_findings.code``: what a finding is (direct members, primary-group
   references, parent groups, member groups, nested principals, other Okta assignments),
   so those facts stay separate once stored (owner decision D20). NULL for findings
   recorded before this migration and for findings that carry no code.
2. ``policy_versions``: one append-only chain of approved policy configurations. Each row
   holds the canonical policy document and its digest, the proposer, and a different
   approver. The database refuses an update, a delete, a row that does not extend the
   chain, a non-human actor, and self-approval.

Only SQLite has the guard triggers; like 0002 and 0003, this migration refuses to run on
PostgreSQL until equivalent guards exist (fail closed).

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

from app.store.migrations.v0001_core_schema import _in, actor, digest, internal_id, table, text, ts

VERSION = 4
NAME = "candidate_policy"

# Frozen with this migration; a test compares them with the domain enum.
FINDING_CODES = (
    "AD_DIRECT_MEMBERS", "AD_PRIMARY_GROUP_REFERENCES", "AD_PARENT_GROUP", "AD_MEMBER_GROUPS",
    "AD_NESTED_PRINCIPALS", "AD_NESTING_CYCLE", "OKTA_OTHER_APP_ASSIGNMENT",
)

STATEMENTS: list[str] = [
    f"ALTER TABLE dependency_findings ADD COLUMN code TEXT CHECK (code IS NULL OR {_in('code', FINDING_CODES)})",
    table(
        "policy_versions",
        internal_id("id", "pver", pk=True),
        "sequence INTEGER NOT NULL UNIQUE CHECK (sequence >= 0)",
        internal_id("supersedes", "pver", null=True) + " REFERENCES policy_versions (id)",
        digest("policy_digest"),
        text("document", 100000),
        *actor("proposed_by", human_only=True),
        *actor("approved_by", human_only=True),
        ts("decided_at"),
        text("reason", 2000),
        ts("recorded_at"),
        text("correlation_id", 100),
        "CHECK ((sequence = 0) = (supersedes IS NULL))",
        "CHECK (approved_by_id <> proposed_by_id)",
    ),
]


def _refuse(name: str, timing: str, message: str, when: str | None = None) -> str:
    assert "'" not in message, "trigger messages are embedded in single-quoted SQL"
    condition = f"\nWHEN {when}" if when else ""
    return (
        f"CREATE TRIGGER {name} {timing} ON policy_versions{condition}\n"
        f"BEGIN\n    SELECT RAISE(ABORT, '{message}');\nEND"
    )


_SQLITE = [
    _refuse("trg_policy_versions_no_update", "BEFORE UPDATE", "policy_versions is append-only"),
    _refuse("trg_policy_versions_no_delete", "BEFORE DELETE", "policy_versions is append-only"),
    _refuse(
        "trg_policy_versions_chain", "BEFORE INSERT", "a policy version must extend the policy chain",
        "NEW.sequence <> (SELECT count(*) FROM policy_versions) "
        "OR NEW.supersedes IS NOT (SELECT id FROM policy_versions ORDER BY sequence DESC LIMIT 1) "
        "OR NEW.decided_at < coalesce((SELECT max(decided_at) FROM policy_versions), NEW.decided_at) "
        "OR NEW.policy_digest = (SELECT policy_digest FROM policy_versions ORDER BY sequence DESC LIMIT 1)",
    ),
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
