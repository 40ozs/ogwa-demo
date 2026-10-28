"""0011 — the AD quarantine and AD deletion stages (P10B, owner decisions D143–D155).

P02–P10 had one AD stage: an ``AD_RETIREMENT`` approval given in ``REVALIDATION_REQUIRED``
led to ``RETIREMENT_DRY_RUN`` and then ``RETIRED``. The owner separated it into two governed
stages: an AD quarantine, then, after a 30-day post-quarantine hold, an AD deletion that
needs its own proposal and a new, independent approval (D128–D130, D138–D147). This
migration makes room for them:

- seven lifecycle states: ``QUARANTINE_APPROVED``, ``QUARANTINE_DRY_RUN``,
  ``QUARANTINE_HOLD``, ``DELETION_REVALIDATION_REQUIRED``, ``DELETION_PROPOSED``,
  ``DELETION_APPROVED``, ``DELETION_DRY_RUN``;
- two approval stages and two job kinds: ``AD_QUARANTINE`` and ``AD_DELETION``;
- four nullable candidate columns, projections of the decisions like
  ``okta_unassign_approver``: the quarantine approver, when the post-quarantine hold ends,
  and who proposed the deletion and when.

**Legacy rows are kept verbatim (D148).** ``AD_RETIREMENT`` stays an allowed stage and job
kind, and ``RETIREMENT_DRY_RUN`` an allowed state, so every recorded approval, job, and
decision still loads and verifies. New triggers refuse any *new* ``AD_RETIREMENT`` approval
or job and any new decision of the legacy stage; the rows already stored are untouched.

**Defence in depth for D144.** A candidate with a post-quarantine hold can never stand in, or
be blocked from, a state before the quarantine: a CHECK on ``candidates`` refuses it.

The allowed values are inline CHECKs, which SQLite cannot alter, so the four tables are
rebuilt in this migration's transaction, as 0009 rebuilt two of them:

1. defer foreign-key checks to commit (``candidate_assignments``, ``execution_job_targets``,
   and ``execution_job_status_events`` reference rebuilt tables and are not rebuilt);
2. copy every row of the four tables into plain backup tables;
3. drop ``decisions``, ``execution_jobs``, ``approvals``, then ``candidates`` (children
   first; dropping fires no triggers, and takes each table's triggers and indexes with it);
4. create each again under the same name, parents first, and re-insert every row verbatim
   while the triggers are absent. ``candidates`` is v0001's definition with the state lists
   extended and the four columns and their CHECKs appended; it is written out in full
   below. The other three are v0001's DDL with only their value lists extended. The new
   candidate columns start NULL for every existing row: no stored candidate has reached a
   P10B state. Then the backups are dropped;
5. recreate v0001's five indexes and v0002's eleven triggers on these tables. Ten are byte
   for byte; ``trg_candidates_start_discovered`` also requires the four new columns to be
   NULL. Then add the three triggers that refuse new legacy records.

At commit every child row references an existing parent again, so the deferred check passes;
otherwise the whole migration rolls back. No stored digest depends on storage, and audit
events are not touched, so the audit chain, and every external anchor of its head, verify
unchanged.

Only SQLite is implemented; like 0002–0010, this migration refuses to run on PostgreSQL.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

import re

from app.store.migrations import v0001_core_schema, v0002_append_only_guards
from app.store.migrations.v0001_core_schema import APPROVAL_STAGES as V0001_APPROVAL_STAGES
from app.store.migrations.v0001_core_schema import JOB_KINDS as V0001_JOB_KINDS
from app.store.migrations.v0001_core_schema import LIFECYCLE_STATES as V0001_LIFECYCLE_STATES
from app.store.migrations.v0001_core_schema import actor, count, enum, internal_id, table, ts
from app.store.migrations.v0009_evidence_incomplete_state import LIFECYCLE_STATES as V0009_LIFECYCLE_STATES

VERSION = 11
NAME = "ad_quarantine_deletion_stages"

# Frozen with this migration; a test compares them with the domain enums.
LIFECYCLE_STATES = (*V0009_LIFECYCLE_STATES, "QUARANTINE_APPROVED", "QUARANTINE_DRY_RUN", "QUARANTINE_HOLD",
                    "DELETION_REVALIDATION_REQUIRED", "DELETION_PROPOSED", "DELETION_APPROVED", "DELETION_DRY_RUN")
APPROVAL_STAGES = (*V0001_APPROVAL_STAGES, "AD_QUARANTINE", "AD_DELETION")
JOB_KINDS = (*V0001_JOB_KINDS, "AD_QUARANTINE", "AD_DELETION")
# Values kept only so stored history loads (D148). No new row may use them.
LEGACY_APPROVAL_STAGE = "AD_RETIREMENT"
LEGACY_JOB_KIND = "AD_RETIREMENT"
LEGACY_STATE = "RETIREMENT_DRY_RUN"
# The states a candidate never stands in, or is blocked from, once quarantined (D144).
PRE_QUARANTINE_STATES = ("DISCOVERED", "CANDIDATE", "NEEDS_REVIEW", "APPROVED", "OKTA_UNASSIGN_DRY_RUN", "HOLD",
                         "REVALIDATION_REQUIRED", "QUARANTINE_APPROVED", "QUARANTINE_DRY_RUN", "RETIREMENT_DRY_RUN")

_TABLES = ("candidates", "approvals", "execution_jobs", "decisions")  # parents first
_ORDER = {"candidates": "id", "approvals": "id", "execution_jobs": "id", "decisions": "candidate_id, sequence"}
# The candidate columns before this migration, in v0001's order.
_CANDIDATE_COLUMNS = (
    "id", "group_id", "proposed_by_kind", "proposed_by_id", "created_at", "reason_codes", "state", "epoch",
    "hold_until", "blocked_from", "okta_unassign_approver_kind", "okta_unassign_approver_id", "updated_at",
    "decision_count",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(repr(v) for v in values)


_CANDIDATES = table(
    "candidates",
    internal_id("id", "cand", pk=True),
    internal_id("group_id", "ogrp") + " REFERENCES okta_groups (id)",
    *actor("proposed_by"),
    ts("created_at"),
    "reason_codes TEXT NOT NULL",
    enum("state", LIFECYCLE_STATES),
    count("epoch"),
    ts("hold_until", null=True),
    enum("blocked_from", LIFECYCLE_STATES, null=True),
    *actor("okta_unassign_approver", null=True, human_only=True),
    ts("updated_at"),
    count("decision_count"),
    "CHECK (updated_at >= created_at)",
    # P10B: projections of the decisions, NULL until reached.
    *actor("quarantine_approver", null=True, human_only=True),
    ts("quarantine_hold_until", null=True),
    *actor("deletion_proposer", null=True, human_only=True),
    ts("deletion_proposed_at", null=True),
    "CHECK ((deletion_proposer_kind IS NULL) = (deletion_proposed_at IS NULL))",
    "CHECK (quarantine_hold_until IS NULL OR quarantine_approver_kind IS NOT NULL)",
    "CHECK (deletion_proposed_at IS NULL OR quarantine_hold_until IS NOT NULL)",
    f"CHECK (quarantine_hold_until IS NULL OR (state NOT IN ({_quoted(PRE_QUARANTINE_STATES)}) "
    f"AND (blocked_from IS NULL OR blocked_from NOT IN ({_quoted(PRE_QUARANTINE_STATES)}))))",
)


def _one(statements: list[str], prefix: str) -> str:
    found = [s for s in statements if s.startswith(prefix)]
    assert len(found) == 1, f"expected exactly one statement starting with {prefix!r}"
    return found[0]


def _extended(name: str, replacements: tuple[tuple[str, tuple[str, ...], tuple[str, ...], bool], ...]) -> str:
    ddl = _one(v0001_core_schema.STATEMENTS, f"CREATE TABLE {name} (")
    for column, old_values, new_values, nullable in replacements:
        old, new = enum(column, old_values, null=nullable), enum(column, new_values, null=nullable)
        assert ddl.count(old) == 1, f"{name}.{column}"
        ddl = ddl.replace(old, new, 1)
    return ddl


_DDL = {
    "candidates": _CANDIDATES,
    "approvals": _extended("approvals", (("stage", V0001_APPROVAL_STAGES, APPROVAL_STAGES, False),)),
    "execution_jobs": _extended("execution_jobs", (("kind", V0001_JOB_KINDS, JOB_KINDS, False),)),
    "decisions": _extended("decisions", (("from_state", V0001_LIFECYCLE_STATES, LIFECYCLE_STATES, False),
                                         ("to_state", V0001_LIFECYCLE_STATES, LIFECYCLE_STATES, False))),
}


def _on(table_name: str, statement: str) -> bool:
    first_line = statement.split("\n", 1)[0]
    return re.search(rf" ON {table_name}$", first_line) is not None


_INDEXES = [s for s in v0001_core_schema.STATEMENTS
            if s.startswith(("CREATE INDEX ", "CREATE UNIQUE INDEX ")) and any(f" ON {t} " in s for t in _TABLES)]
assert len(_INDEXES) == 5, _INDEXES

_START = "CREATE TRIGGER trg_candidates_start_discovered "
_V0002_TRIGGERS = [s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                   if s.startswith("CREATE TRIGGER ") and any(_on(t, s) for t in _TABLES)]
assert len(_V0002_TRIGGERS) == 11, [s.split()[2] for s in _V0002_TRIGGERS]
_START_CONDITION = "OR NEW.okta_unassign_approver_kind IS NOT NULL"
_TRIGGERS = []
for _statement in _V0002_TRIGGERS:
    if _statement.startswith(_START):
        assert _statement.count(_START_CONDITION) == 1
        _statement = _statement.replace(_START_CONDITION, _START_CONDITION + (
            " OR NEW.quarantine_approver_kind IS NOT NULL OR NEW.quarantine_hold_until IS NOT NULL"
            " OR NEW.deletion_proposer_kind IS NOT NULL OR NEW.deletion_proposed_at IS NOT NULL"), 1)
    _TRIGGERS.append(_statement)


def _refuse(name: str, table_name: str, message: str, when: str) -> str:
    assert "'" not in message, "trigger messages are embedded in single-quoted SQL"
    return (f"CREATE TRIGGER {name} BEFORE INSERT ON {table_name}\nWHEN {when}\n"
            f"BEGIN\n    SELECT RAISE(ABORT, '{message}');\nEND")


_LEGACY_TRIGGERS = [
    _refuse("trg_approvals_no_legacy_stage", "approvals",
            "AD_RETIREMENT is a legacy approval stage; new approvals use AD_QUARANTINE or AD_DELETION (D148)",
            f"NEW.stage = '{LEGACY_APPROVAL_STAGE}'"),
    _refuse("trg_execution_jobs_no_legacy_kind", "execution_jobs",
            "AD_RETIREMENT is a legacy job kind; new jobs use AD_QUARANTINE or AD_DELETION (D148)",
            f"NEW.kind = '{LEGACY_JOB_KIND}'"),
    _refuse("trg_decisions_no_legacy_step", "decisions",
            "the legacy single AD stage is history only; quarantine and deletion are separate stages (D148)",
            f"NEW.to_state = '{LEGACY_STATE}' OR (NEW.from_state = '{LEGACY_STATE}' AND NEW.to_state = 'RETIRED')"),
]


def _backup(table_name: str) -> str:
    return f"ogwa_v0011_{table_name}_backup"


def _restore(table_name: str) -> str:
    if table_name == "candidates":
        columns = ", ".join(_CANDIDATE_COLUMNS)
        return (f"INSERT INTO candidates ({columns}) SELECT {columns} FROM {_backup(table_name)} "
                f"ORDER BY {_ORDER[table_name]}")
    return f"INSERT INTO {table_name} SELECT * FROM {_backup(table_name)} ORDER BY {_ORDER[table_name]}"


STATEMENTS: list[str] = []

_SQLITE = [
    "PRAGMA defer_foreign_keys = ON",
    *(f"CREATE TABLE {_backup(t)} AS SELECT * FROM {t}" for t in _TABLES),
    *(f"DROP TABLE {t}" for t in reversed(_TABLES)),  # children first
    *(statement for t in _TABLES for statement in (_DDL[t], _restore(t), f"DROP TABLE {_backup(t)}")),
    *_INDEXES,
    *_TRIGGERS,
    *_LEGACY_TRIGGERS,
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
