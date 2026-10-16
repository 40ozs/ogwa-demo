"""Ordered schema migrations. Each module defines VERSION, NAME, STATEMENTS (portable DDL)
and DIALECT_STATEMENTS (engine-specific DDL keyed by dialect).

Applied migrations are frozen: their checksum is recorded and re-verified on every open.
"""

import hashlib
from types import ModuleType

from app.store.errors import MigrationError
from app.store.migrations import (
    v0001_core_schema,
    v0002_append_only_guards,
    v0003_mapping_registry,
    v0004_candidate_policy,
    v0005_review_audit_actions,
    v0006_unverified_stable_id,
    v0007_governed_refusals,
    v0008_okta_directory_sid,
    v0009_evidence_incomplete_state,
    v0010_remediation_dry_runs,
    v0011_ad_quarantine_deletion_stages,
    v0012_synthetic_directory,
)

MIGRATIONS: tuple[ModuleType, ...] = (
    v0001_core_schema,
    v0002_append_only_guards,
    v0003_mapping_registry,
    v0004_candidate_policy,
    v0005_review_audit_actions,
    v0006_unverified_stable_id,
    v0007_governed_refusals,
    v0008_okta_directory_sid,
    v0009_evidence_incomplete_state,
    v0010_remediation_dry_runs,
    v0011_ad_quarantine_deletion_stages,
    v0012_synthetic_directory,
)
LATEST_VERSION = MIGRATIONS[-1].VERSION


def statements_for(migration: ModuleType, dialect: str) -> list[str]:
    if dialect not in migration.DIALECT_STATEMENTS:
        raise MigrationError(
            f"migration {migration.VERSION} ({migration.NAME}) has no {dialect} implementation; "
            "refusing to create a schema without its guards"
        )
    return [*migration.STATEMENTS, *migration.DIALECT_STATEMENTS[dialect]]


def checksum(migration: ModuleType, dialect: str) -> str:
    text = "\n;\n".join(statements_for(migration, dialect))
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check_order() -> None:
    versions = [m.VERSION for m in MIGRATIONS]
    if versions != list(range(1, len(MIGRATIONS) + 1)):
        raise MigrationError(f"migration versions must be 1..n without gaps, got {versions}")


_check_order()
