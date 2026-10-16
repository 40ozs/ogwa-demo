"""0001 — core schema: environment marker, evidence, lifecycle, approvals, jobs, audit.

Portable DDL only (types TEXT and INTEGER, standard CHECK/UNIQUE/FOREIGN KEY constraints,
partial unique indexes), valid on SQLite and PostgreSQL. Allowed enum values are frozen
literals here, not imported from the domain, so this migration never changes once
applied. A domain enum that gains a value needs a new migration; a test detects drift.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

VERSION = 1
NAME = "core_schema"

EVIDENCE_SOURCES = ("OKTA_API", "OKTA_SYSTEM_LOG", "AD_VIA_AAP", "CONFIGURED_MAPPING", "OPERATOR_ATTESTATION", "SYNTHETIC")
RESULT_STATUSES = ("COMPLETE", "PARTIAL", "FAILED")
ACTOR_KINDS = ("HUMAN", "SYSTEM")
# PRODUCTION_MUTATION is deliberately absent: the database itself refuses it.
STORE_MODES = ("LOCAL_SYNTHETIC", "READ_ONLY_PRODUCTION", "DRY_RUN_MUTATION")
JOB_MODES = ("LOCAL_SYNTHETIC", "DRY_RUN_MUTATION")
ENVIRONMENTS = ("SYNTHETIC", "DEVELOPMENT", "PRODUCTION")
APP_STATUSES = ("ACTIVE", "INACTIVE")
GROUP_TYPES = ("OKTA_GROUP", "APP_GROUP", "BUILT_IN")
CONFIDENCES = (
    "EXACT_STABLE_ID", "EXACT_DIRECTORY_SOURCE", "EXACT_CONFIGURED_MAPPING", "NAME_ONLY", "AMBIGUOUS", "NOT_FOUND",
)
DEPENDENCY_KINDS = (
    "OKTA_OTHER_APP_ASSIGNMENT", "OKTA_POLICY_REFERENCE", "AD_GROUP_MEMBERS", "AD_NESTED_MEMBERSHIP",
    "AD_ACL_REFERENCE", "GPO_REFERENCE", "AAP_REFERENCE", "APPLICATION_CONFIGURATION", "OTHER",
)
LIFECYCLE_STATES = (
    "DISCOVERED", "CANDIDATE", "NEEDS_REVIEW", "APPROVED", "OKTA_UNASSIGN_DRY_RUN", "HOLD", "REVALIDATION_REQUIRED",
    "RETIREMENT_DRY_RUN", "RETIRED", "EXCLUDED", "REJECTED", "BLOCKED", "MAPPING_AMBIGUOUS", "DEPENDENCY_BLOCKED",
    "PROTECTED", "STALE_EVIDENCE",
)
TERMINAL_STATES = ("RETIRED", "EXCLUDED", "REJECTED", "PROTECTED")
APPROVAL_STAGES = ("OKTA_UNASSIGN", "AD_RETIREMENT")
APPROVAL_DECISIONS = ("APPROVE", "REJECT")
JOB_KINDS = ("OKTA_UNASSIGN", "AD_RETIREMENT")
JOB_STATUSES = ("PLANNED", "RUNNING", "SUCCEEDED", "FAILED", "REFUSED")
FINISHED_JOB_STATUSES = ("SUCCEEDED", "FAILED", "REFUSED")
COLLECTOR_ERROR_CODES = (
    "TIMEOUT", "RATE_LIMITED", "HTTP_ERROR", "AUTHENTICATION_FAILED", "PAGING_INTERRUPTED", "DOMAIN_UNREACHABLE", "OTHER",
)
AUDIT_ACTIONS = (
    "TRANSITION_APPLIED", "TRANSITION_REFUSED", "APPROVAL_RECORDED", "EXECUTION_JOB_RECORDED", "EVIDENCE_RECORDED",
    "CANDIDATE_CREATED", "EXECUTION_JOB_STATUS_RECORDED", "COLLECTOR_RUN_STARTED", "COLLECTOR_RUN_FINISHED",
    "STORE_INITIALIZED", "SYNTHETIC_SEED_LOADED",
)
AUDIT_RESULTS = ("SUCCEEDED", "REFUSED", "FAILED")


# --- column helpers (frozen with this migration) -------------------------------------


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def enum(column: str, values: tuple[str, ...], *, null: bool = False) -> str:
    check = f"{column} IS NULL OR {_in(column, values)}" if null else _in(column, values)
    return f"{column} TEXT{'' if null else ' NOT NULL'} CHECK ({check})"


def ts(column: str, *, null: bool = False) -> str:
    shape = f"length({column}) = 27 AND substr({column}, 11, 1) = 'T' AND substr({column}, 27, 1) = 'Z'"
    check = f"{column} IS NULL OR ({shape})" if null else shape
    return f"{column} TEXT{'' if null else ' NOT NULL'} CHECK ({check})"


def flag(column: str) -> str:
    return f"{column} INTEGER NOT NULL CHECK ({column} IN (0, 1))"


def count(column: str, *, null: bool = False) -> str:
    check = f"{column} IS NULL OR {column} >= 0" if null else f"{column} >= 0"
    return f"{column} INTEGER{'' if null else ' NOT NULL'} CHECK ({check})"


def internal_id(column: str, prefix: str, *, null: bool = False, pk: bool = False) -> str:
    shape = f"length({column}) = {len(prefix) + 33} AND substr({column}, 1, {len(prefix) + 1}) = '{prefix}_'"
    check = f"{column} IS NULL OR ({shape})" if null else shape
    tail = " PRIMARY KEY" if pk else ("" if null else " NOT NULL")
    return f"{column} TEXT{tail} CHECK ({check})"


def text(column: str, max_length: int, *, null: bool = False) -> str:
    shape = f"length({column}) BETWEEN 1 AND {max_length}"
    check = f"{column} IS NULL OR ({shape})" if null else shape
    return f"{column} TEXT{'' if null else ' NOT NULL'} CHECK ({check})"


def digest(column: str, *, null: bool = False) -> str:
    shape = f"length({column}) = 71 AND substr({column}, 1, 7) = 'sha256:'"
    check = f"{column} IS NULL OR ({shape})" if null else shape
    return f"{column} TEXT{'' if null else ' NOT NULL'} CHECK ({check})"


def actor(prefix: str, *, null: bool = False, human_only: bool = False) -> list[str]:
    kinds = ("HUMAN",) if human_only else ACTOR_KINDS
    cols = [enum(f"{prefix}_kind", kinds, null=null), text(f"{prefix}_id", 200, null=null)]
    if null:
        cols.append(f"CHECK (({prefix}_kind IS NULL AND {prefix}_id IS NULL) OR ({prefix}_kind IS NOT NULL AND {prefix}_id IS NOT NULL))")
    return cols


def provenance() -> list[str]:
    return [
        enum("source", EVIDENCE_SOURCES),
        ts("observed_at"),
        text("scope", 500),
        text("collector_version", 100),
        enum("result_status", RESULT_STATUSES),
        internal_id("collector_run_id", "run", null=True) + " REFERENCES collector_runs (id)",
        digest("digest"),
        ts("recorded_at"),
    ]


def table(name: str, *elements: str) -> str:
    # Table constraints go after every column definition (SQLite requires it).
    constraints = tuple(e for e in elements if e.startswith(("CHECK ", "UNIQUE ", "PRIMARY KEY ")))
    columns = tuple(e for e in elements if e not in constraints)
    body = ",\n    ".join(columns + constraints)
    return f"CREATE TABLE {name} (\n    {body}\n)"


def observation_table(name: str, entity_column: str, entity_prefix: str, entity_table: str, *columns: str) -> list[str]:
    return [
        table(
            name,
            internal_id("observation_id", "obs", pk=True),
            internal_id(entity_column, entity_prefix) + f" REFERENCES {entity_table} (id)",
            *columns,
            *provenance(),
            f"UNIQUE ({entity_column}, observed_at)",
        ),
    ]


# --- schema ---------------------------------------------------------------------------

STATEMENTS: list[str] = [
    # Environment marker: exactly one row, written once at initialization.
    table(
        "store_metadata",
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1)",
        enum("environment", ENVIRONMENTS),
        text("store_instance_id", 100),
        ts("created_at"),
        *actor("created_by"),
    ),
    # Collector runs and their single outcome.
    table(
        "collector_runs",
        internal_id("id", "run", pk=True),
        text("collector", 100),
        text("collector_version", 100),
        enum("source", EVIDENCE_SOURCES),
        enum("execution_mode", STORE_MODES),
        text("scope", 500),
        ts("started_at"),
        *actor("started_by"),
        ts("recorded_at"),
    ),
    table(
        "collector_run_outcomes",
        internal_id("run_id", "run", pk=True) + " REFERENCES collector_runs (id)",
        ts("finished_at"),
        enum("status", RESULT_STATUSES),
        count("records_observed"),
        enum("error_code", COLLECTOR_ERROR_CODES, null=True),
        text("error_summary", 300, null=True),
        ts("recorded_at"),
        "CHECK ((status = 'COMPLETE' AND error_code IS NULL) OR (status <> 'COMPLETE' AND error_code IS NOT NULL))",
    ),
    # Okta applications.
    table(
        "okta_applications",
        internal_id("id", "oapp", pk=True),
        text("okta_app_id", 64) + " UNIQUE",
        ts("recorded_at"),
    ),
    *observation_table(
        "okta_application_observations", "application_id", "oapp", "okta_applications",
        text("label", 200),
        enum("status", APP_STATUSES),
        text("sign_on_mode", 100),
    ),
    # Okta groups.
    table(
        "okta_groups",
        internal_id("id", "ogrp", pk=True),
        text("okta_group_id", 64) + " UNIQUE",
        ts("recorded_at"),
    ),
    *observation_table(
        "okta_group_observations", "group_id", "ogrp", "okta_groups",
        text("name", 300),
        enum("group_type", GROUP_TYPES),
        text("source_directory_id", 64, null=True),
        text("directory_external_id", 100, null=True),
        text("directory_qualified_name", 300, null=True),
        "CHECK (group_type = 'APP_GROUP' OR (source_directory_id IS NULL AND directory_external_id IS NULL "
        "AND directory_qualified_name IS NULL))",
    ),
    # Application-group assignments: one anchor per (application, group) pair.
    table(
        "app_group_assignments",
        internal_id("id", "asgn", pk=True),
        internal_id("application_id", "oapp") + " REFERENCES okta_applications (id)",
        internal_id("group_id", "ogrp") + " REFERENCES okta_groups (id)",
        ts("recorded_at"),
        "UNIQUE (application_id, group_id)",
    ),
    *observation_table(
        "assignment_observations", "assignment_id", "asgn", "app_group_assignments",
        flag("present"),
    ),
    # Usage: one anchor per (application, group scope); '*' is application-wide.
    table(
        "usage_scopes",
        internal_id("id", "use", pk=True),
        internal_id("application_id", "oapp") + " REFERENCES okta_applications (id)",
        internal_id("group_id", "ogrp", null=True) + " REFERENCES okta_groups (id)",
        text("scope_key", 40),
        ts("recorded_at"),
        "UNIQUE (application_id, scope_key)",
        "CHECK ((group_id IS NULL AND scope_key = '*') OR (group_id IS NOT NULL AND scope_key = group_id))",
    ),
    *observation_table(
        "usage_observations", "usage_id", "use", "usage_scopes",
        ts("window_start"),
        ts("window_end"),
        count("event_count"),
        count("distinct_user_count"),
        ts("last_activity_at", null=True),
        "CHECK (window_end > window_start)",
        "CHECK (window_end <= observed_at)",
        "CHECK (distinct_user_count <= event_count)",
        "CHECK (last_activity_at IS NULL OR last_activity_at <= window_end)",
    ),
    # AD groups, anchored by objectGUID.
    table(
        "ad_groups",
        internal_id("id", "adg", pk=True),
        "object_guid TEXT NOT NULL UNIQUE CHECK (length(object_guid) = 36 AND object_guid = lower(object_guid))",
        ts("recorded_at"),
    ),
    *observation_table(
        "ad_group_observations", "ad_group_id", "adg", "ad_groups",
        text("domain", 255),
        flag("group_exists"),
        text("sid", 200, null=True),
        text("distinguished_name", 1000, null=True),
        text("sam_account_name", 256, null=True),
        flag("admin_count"),
        flag("protected_from_accidental_deletion"),
        flag("is_critical_system_object"),
        count("member_count", null=True),
        "CHECK (group_exists = 0 OR (sid IS NOT NULL AND distinguished_name IS NOT NULL AND sam_account_name IS NOT NULL))",
    ),
    # Identity mappings: one anchor per Okta group.
    table(
        "identity_mappings",
        internal_id("id", "map", pk=True),
        internal_id("group_id", "ogrp") + " UNIQUE REFERENCES okta_groups (id)",
        ts("recorded_at"),
    ),
    *observation_table(
        "identity_mapping_observations", "mapping_id", "map", "identity_mappings",
        enum("confidence", CONFIDENCES),
        internal_id("ad_group_id", "adg", null=True) + " REFERENCES ad_groups (id)",
        text("reason", 2000),
        "matched_attributes TEXT NOT NULL",
        text("configuration_ref", 300, null=True),
        "CHECK ((confidence IN ('AMBIGUOUS', 'NOT_FOUND') AND ad_group_id IS NULL) "
        "OR (confidence NOT IN ('AMBIGUOUS', 'NOT_FOUND') AND ad_group_id IS NOT NULL))",
        "CHECK ((confidence = 'EXACT_CONFIGURED_MAPPING') = (configuration_ref IS NOT NULL))",
    ),
    table(
        "identity_mapping_candidates",
        internal_id("observation_id", "obs") + " REFERENCES identity_mapping_observations (observation_id)",
        count("ordinal"),
        internal_id("ad_group_id", "adg") + " REFERENCES ad_groups (id)",
        "PRIMARY KEY (observation_id, ordinal)",
        "UNIQUE (observation_id, ad_group_id)",
    ),
    # Dependency checks: one anchor per (subject, kind).
    table(
        "dependency_checks",
        internal_id("id", "dep", pk=True),
        "subject_id TEXT NOT NULL",
        internal_id("subject_group_id", "ogrp", null=True) + " REFERENCES okta_groups (id)",
        internal_id("subject_ad_group_id", "adg", null=True) + " REFERENCES ad_groups (id)",
        enum("kind", DEPENDENCY_KINDS),
        ts("recorded_at"),
        "UNIQUE (subject_id, kind)",
        "CHECK ((subject_group_id IS NOT NULL AND subject_ad_group_id IS NULL AND subject_id = subject_group_id) "
        "OR (subject_group_id IS NULL AND subject_ad_group_id IS NOT NULL AND subject_id = subject_ad_group_id))",
    ),
    *observation_table("dependency_observations", "check_id", "dep", "dependency_checks"),
    table(
        "dependency_findings",
        internal_id("observation_id", "obs") + " REFERENCES dependency_observations (observation_id)",
        count("ordinal"),
        text("description", 500),
        flag("blocking"),
        text("reference", 500, null=True),
        "PRIMARY KEY (observation_id, ordinal)",
    ),
    # Lifecycle candidates. Identity columns are immutable; the state columns are a
    # projection of the append-only decisions table and may change only in step with it.
    table(
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
    ),
    "CREATE UNIQUE INDEX ux_candidates_one_open_per_group ON candidates (group_id) WHERE "
    + " AND ".join(f"state <> '{s}'" for s in TERMINAL_STATES),
    table(
        "candidate_assignments",
        internal_id("candidate_id", "cand") + " REFERENCES candidates (id)",
        internal_id("assignment_id", "asgn") + " REFERENCES app_group_assignments (id)",
        "PRIMARY KEY (candidate_id, assignment_id)",
    ),
    # Approvals: decisions by named humans, never edited. A change of mind is a new record.
    table(
        "approvals",
        internal_id("id", "apr", pk=True),
        internal_id("candidate_id", "cand") + " REFERENCES candidates (id)",
        enum("stage", APPROVAL_STAGES),
        enum("decision", APPROVAL_DECISIONS),
        *actor("operator", human_only=True),
        ts("decided_at"),
        text("reason", 2000),
        digest("evidence_fingerprint"),
        count("candidate_epoch"),
        ts("expires_at"),
        ts("recorded_at"),
        text("correlation_id", 100),
        "CHECK (expires_at > decided_at)",
    ),
    # Execution jobs: the immutable request, its targets, and an append-only status history.
    table(
        "execution_jobs",
        internal_id("id", "job", pk=True),
        internal_id("candidate_id", "cand") + " REFERENCES candidates (id)",
        enum("kind", JOB_KINDS),
        enum("execution_mode", JOB_MODES),
        flag("dry_run"),
        *actor("requested_by"),
        ts("requested_at"),
        internal_id("approval_id", "apr") + " REFERENCES approvals (id)",
        digest("evidence_fingerprint"),
        ts("recorded_at"),
        "CHECK (execution_mode <> 'DRY_RUN_MUTATION' OR dry_run = 1)",
    ),
    table(
        "execution_job_targets",
        internal_id("job_id", "job") + " REFERENCES execution_jobs (id)",
        "target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 36 AND 37)",
        "PRIMARY KEY (job_id, target_id)",
    ),
    table(
        "execution_job_status_events",
        internal_id("job_id", "job") + " REFERENCES execution_jobs (id)",
        count("sequence"),
        enum("status", JOB_STATUSES),
        flag("executed"),
        flag("targets_synthetic"),
        ts("finished_at", null=True),
        text("external_ref", 200, null=True),
        text("detail", 300, null=True),
        ts("recorded_at"),
        text("correlation_id", 100),
        "PRIMARY KEY (job_id, sequence)",
        "CHECK (executed = 0 OR (status = 'SUCCEEDED' AND targets_synthetic = 1))",
        f"CHECK (({_in('status', FINISHED_JOB_STATUSES)} AND finished_at IS NOT NULL) "
        f"OR (status NOT IN ('SUCCEEDED', 'FAILED', 'REFUSED') AND finished_at IS NULL))",
    ),
    # Lifecycle decisions: one row per applied transition, never edited.
    table(
        "decisions",
        internal_id("id", "dec", pk=True),
        internal_id("candidate_id", "cand") + " REFERENCES candidates (id)",
        count("sequence"),
        enum("from_state", LIFECYCLE_STATES),
        enum("to_state", LIFECYCLE_STATES),
        *actor("actor"),
        ts("decided_at"),
        text("reason", 2000),
        digest("evidence_fingerprint"),
        count("epoch"),
        internal_id("approval_id", "apr", null=True) + " REFERENCES approvals (id)",
        internal_id("execution_job_id", "job", null=True) + " REFERENCES execution_jobs (id)",
        ts("recorded_at"),
        text("correlation_id", 100),
        "UNIQUE (candidate_id, sequence)",
        "CHECK (from_state <> to_state)",
    ),
    # The audit log: a single hash chain over every write.
    table(
        "audit_events",
        internal_id("id", "aud", pk=True),
        count("sequence") + " UNIQUE",
        ts("occurred_at"),
        *actor("actor"),
        enum("action", AUDIT_ACTIONS),
        text("subject_id", 100),
        "details TEXT NOT NULL",
        digest("previous_digest", null=True),
        digest("digest") + " UNIQUE",
        enum("execution_mode", STORE_MODES, null=True),
        enum("result", AUDIT_RESULTS, null=True),
        text("correlation_id", 100, null=True),
        text("before_ref", 200, null=True),
        text("after_ref", 200, null=True),
        "CHECK ((sequence = 0 AND previous_digest IS NULL) OR (sequence > 0 AND previous_digest IS NOT NULL))",
    ),
    # Lookup indexes.
    "CREATE INDEX ix_candidates_state ON candidates (state)",
    "CREATE INDEX ix_decisions_candidate ON decisions (candidate_id, sequence)",
    "CREATE INDEX ix_approvals_candidate ON approvals (candidate_id)",
    "CREATE INDEX ix_jobs_candidate ON execution_jobs (candidate_id)",
    "CREATE INDEX ix_audit_subject ON audit_events (subject_id)",
    "CREATE INDEX ix_audit_correlation ON audit_events (correlation_id)",
    "CREATE INDEX ix_assignments_group ON app_group_assignments (group_id)",
    "CREATE INDEX ix_mapping_obs_ad_group ON identity_mapping_observations (ad_group_id)",
]

# Engine-specific statements. Nothing is needed beyond the portable DDL.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": [], "postgresql": []}
