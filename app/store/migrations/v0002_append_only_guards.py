"""0002 — database-level guards: append-only tables and lifecycle/audit chaining.

The application already writes append-only. These triggers make the database refuse
UPDATE and DELETE on history tables too, so a bug or an ad-hoc SQL session cannot
silently rewrite evidence, decisions, approvals, job history, or the audit log.

Only SQLite is implemented. PostgreSQL needs equivalent trigger functions plus
REVOKE UPDATE, DELETE for the application role; until they are written this migration
refuses to run there (fail closed). See docs/architecture/persistence.md.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

VERSION = 2
NAME = "append_only_guards"

APPEND_ONLY_TABLES = (
    "schema_migrations",
    "store_metadata",
    "collector_runs",
    "collector_run_outcomes",
    "okta_applications",
    "okta_application_observations",
    "okta_groups",
    "okta_group_observations",
    "app_group_assignments",
    "assignment_observations",
    "usage_scopes",
    "usage_observations",
    "ad_groups",
    "ad_group_observations",
    "identity_mappings",
    "identity_mapping_observations",
    "identity_mapping_candidates",
    "dependency_checks",
    "dependency_observations",
    "dependency_findings",
    "candidate_assignments",
    "approvals",
    "execution_jobs",
    "execution_job_targets",
    "execution_job_status_events",
    "decisions",
    "audit_events",
)

_FINISHED = "('SUCCEEDED', 'FAILED', 'REFUSED')"


def _refuse(name: str, timing: str, table: str, message: str, when: str | None = None) -> str:
    assert "'" not in message, "trigger messages are embedded in single-quoted SQL"
    condition = f"\nWHEN {when}" if when else ""
    return (
        f"CREATE TRIGGER {name} {timing} ON {table}{condition}\n"
        f"BEGIN\n    SELECT RAISE(ABORT, '{message}');\nEND"
    )


_SQLITE: list[str] = []
for _table in APPEND_ONLY_TABLES:
    _SQLITE.append(_refuse(f"trg_{_table}_no_update", "BEFORE UPDATE", _table, f"{_table} is append-only"))
    _SQLITE.append(_refuse(f"trg_{_table}_no_delete", "BEFORE DELETE", _table, f"{_table} is append-only"))

_SQLITE += [
    _refuse("trg_candidates_no_delete", "BEFORE DELETE", "candidates", "candidates are never deleted"),
    _refuse(
        "trg_candidates_identity_immutable",
        "BEFORE UPDATE OF id, group_id, proposed_by_kind, proposed_by_id, created_at, reason_codes",
        "candidates",
        "candidate identity columns are immutable",
    ),
    _refuse(
        "trg_candidates_start_discovered", "BEFORE INSERT", "candidates", "a new candidate must start in DISCOVERED",
        "NEW.state <> 'DISCOVERED' OR NEW.epoch <> 0 OR NEW.decision_count <> 0 OR NEW.blocked_from IS NOT NULL "
        "OR NEW.hold_until IS NOT NULL OR NEW.okta_unassign_approver_kind IS NOT NULL",
    ),
    _refuse(
        "trg_candidates_follow_decisions", "BEFORE UPDATE", "candidates",
        "candidate state may change only together with a new decision",
        "NEW.decision_count <> OLD.decision_count + 1 "
        "OR NEW.decision_count <> (SELECT count(*) FROM decisions WHERE candidate_id = NEW.id) "
        "OR NEW.state IS NOT (SELECT to_state FROM decisions WHERE candidate_id = NEW.id ORDER BY sequence DESC LIMIT 1) "
        "OR NEW.epoch IS NOT (SELECT epoch FROM decisions WHERE candidate_id = NEW.id ORDER BY sequence DESC LIMIT 1)",
    ),
    _refuse(
        "trg_decisions_follow_candidate", "BEFORE INSERT", "decisions",
        "a decision must continue from the current candidate state",
        "NEW.sequence IS NOT (SELECT decision_count FROM candidates WHERE id = NEW.candidate_id) "
        "OR NEW.from_state IS NOT (SELECT state FROM candidates WHERE id = NEW.candidate_id)",
    ),
    _refuse(
        "trg_audit_chain", "BEFORE INSERT", "audit_events", "audit events must extend the chain head",
        "NEW.sequence <> (SELECT coalesce(max(sequence) + 1, 0) FROM audit_events) "
        "OR (NEW.sequence > 0 AND NEW.previous_digest IS NOT "
        "(SELECT digest FROM audit_events WHERE sequence = NEW.sequence - 1))",
    ),
    _refuse(
        "trg_job_status_sequence", "BEFORE INSERT", "execution_job_status_events",
        "job status events are sequential and stop once the job has finished",
        "NEW.sequence <> (SELECT count(*) FROM execution_job_status_events WHERE job_id = NEW.job_id) "
        f"OR EXISTS (SELECT 1 FROM execution_job_status_events WHERE job_id = NEW.job_id AND status IN {_FINISHED})",
    ),
]

STATEMENTS: list[str] = []
# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
