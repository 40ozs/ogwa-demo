import ast
import re
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from app.core.modes import ExecutionMode
from app.domain.actors import ActorKind
from app.domain.approval import ApprovalDecision, ApprovalStage
from app.domain.audit import AuditAction, AuditResult
from app.domain.candidate_policy import PolicyRole
from app.domain.collection import CollectorErrorCode
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.execution import FINISHED_STATUSES, JOB_MODES, JobKind, JobStatus
from app.domain.lifecycle import TERMINAL_STATES, LifecycleState
from app.domain.model import DependencyKind, FindingCode, MappingConfidence, OktaAppStatus, OktaGroupType
from app.store.db import DIALECT_SQLITE, connect
from app.store.environment import DatabaseEnvironment
from app.store.errors import MigrationError, StoreError
from app.store.migrations import (
    LATEST_VERSION,
    MIGRATIONS,
    checksum,
    statements_for,
    v0001_core_schema,
    v0002_append_only_guards,
    v0004_candidate_policy,
    v0005_review_audit_actions,
    v0006_unverified_stable_id,
    v0007_governed_refusals,
    v0009_evidence_incomplete_state,
    v0010_remediation_dry_runs,
    v0011_ad_quarantine_deletion_stages,
)
from app.store.migrator import applied_migrations, current_version, upgrade, verify_applied
from app.store.store import Store
from tests.store_fixtures import file_target, memory_target, new_store

REPO_ROOT = Path(__file__).resolve().parents[1]
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

# Applied migrations must never change. Changing one of these values means a migration
# was edited after it shipped: add a new migration instead.
PINNED_CHECKSUMS = {
    1: "sha256:77056647d59003ae66609ed9144cd2d2d2da43e06613f51673e6e5f346dceee4",
    2: "sha256:2cf2fc5ae3fd7b8ee03345ae1e9033960ec0d3a1821309a691a09256ca6594a7",
    3: "sha256:2a76c72163ebfa3557adb54c70fe343ee4c4079ebeb77c924dd8fbcff57f00b0",
    4: "sha256:18dfb643f140e3ec48f9a48e95f6f8cfdbceb6af670e442eb09f1eb4fb8396bf",
    5: "sha256:5d455e6205608094169f18547971826063647b8650191b653e65bd79f9bad1c9",
    6: "sha256:6982f12b98555f1da6bddce90fe5d07d9b86032dd72af1e0ab9f3086e6b7300b",
    7: "sha256:9960ff4e1d5bb86f8a06181f0c1507720d64ab086bec6c91bccb2843dba295a9",
    8: "sha256:113c10892ef4dbcfcf3dca91aac9f5c00fd3e21d21efa2cd1ae407e2e2efd291",
    9: "sha256:0bc10a821e87a1da50f57e17c91299bdc24c8208f0b6db0d1012780af2488a45",
    10: "sha256:03efd5c106b626ba0d57c20525f446dbabd6dd30e0bb041645fe300ece128699",
    11: "sha256:2d612dfe0aada50df9f9194db2c63b60b8d730d2fe49e6a4f86a489f3f1ddb16",
    12: "sha256:938355e8a16bbf274852c16517b46d3151334b3b467547f78a14cc10a45ba5c7",
}

# The original list of things that must be persisted, and the table that holds each.
PERSISTED_CONCEPTS = {
    "applications": "okta_applications",
    "groups": "okta_groups",
    "app-group assignments": "app_group_assignments",
    "usage observations": "usage_observations",
    "AD group observations": "ad_group_observations",
    "identity mappings": "identity_mapping_observations",
    "dependency evidence": "dependency_observations",
    "candidates": "candidates",
    "decisions": "decisions",
    "approvals": "approvals",
    "execution jobs": "execution_jobs",
    "audit events": "audit_events",
    "collector runs": "collector_runs",
    "identity mapping reviews": "mapping_reviews",
    "candidate policy versions": "policy_versions",
    "synthetic directory snapshot (0012)": "synthetic_directory_records",
}


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _triggers(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}


class MigrationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(memory_target())

    def tearDown(self):
        self.conn.close()

    def test_upgrade_from_empty_creates_every_persisted_concept(self):
        self.assertEqual(upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        tables = _tables(self.conn)
        for concept, table in PERSISTED_CONCEPTS.items():
            with self.subTest(concept=concept):
                self.assertIn(table, tables)
        self.assertEqual(current_version(self.conn), LATEST_VERSION)

    def test_upgrade_is_idempotent(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        self.assertEqual(upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK), [])
        self.assertEqual([m.version for m in applied_migrations(self.conn)], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])

    def test_stepwise_upgrade_applies_each_version_once(self):
        self.assertEqual(upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=1), [1])
        self.assertEqual(_triggers(self.conn), set())
        self.assertEqual(upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK), [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        self.assertIn("trg_audit_events_no_update", _triggers(self.conn))

    def test_applied_checksums_are_recorded(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        recorded = {m.version: m.checksum for m in applied_migrations(self.conn)}
        self.assertEqual(recorded, PINNED_CHECKSUMS)

    def test_downgrade_is_refused(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        with self.assertRaisesRegex(MigrationError, "downgrade"):
            upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=1)

    def test_failed_migration_leaves_previous_version(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=1)
        broken = [*v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"][:3], "CREATE TABLE broken ("]
        with mock.patch.dict(v0002_append_only_guards.DIALECT_STATEMENTS, {"sqlite": broken}):
            with self.assertRaises(sqlite3.Error):
                upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        self.assertEqual(current_version(self.conn), 1)
        self.assertEqual(_triggers(self.conn), set())  # the partial migration was rolled back

    def test_edited_migration_is_detected(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        edited = [*v0001_core_schema.STATEMENTS, "CREATE INDEX ix_extra ON candidates (epoch)"]
        with mock.patch.object(v0001_core_schema, "STATEMENTS", edited):
            with self.assertRaisesRegex(MigrationError, "changed after it was applied"):
                verify_applied(self.conn, DIALECT_SQLITE)

    def test_tampered_bookkeeping_is_detected(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=1)  # before the append-only guards exist
        self.conn.execute("UPDATE schema_migrations SET checksum = ?", ("sha256:" + "0" * 64,))
        with self.assertRaisesRegex(MigrationError, "changed after it was applied"):
            verify_applied(self.conn, DIALECT_SQLITE)

    def test_database_newer_than_build_is_refused(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK, target=1)
        self.conn.execute("INSERT INTO schema_migrations VALUES (2, 'future', ?, '2026-01-01T00:00:00.000000Z')",
                          ("sha256:" + "1" * 64,))
        self.conn.execute("INSERT INTO schema_migrations VALUES (3, 'future', ?, '2026-01-01T00:00:00.000000Z')",
                          ("sha256:" + "1" * 64,))
        with self.assertRaises(MigrationError):
            verify_applied(self.conn, DIALECT_SQLITE)

    def test_bookkeeping_becomes_append_only(self):
        upgrade(self.conn, DIALECT_SQLITE, clock=CLOCK)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute("DELETE FROM schema_migrations WHERE version = 2")


class MigrationContentTests(unittest.TestCase):
    def test_checksums_are_pinned(self):
        self.assertEqual({m.VERSION: checksum(m, DIALECT_SQLITE) for m in MIGRATIONS}, PINNED_CHECKSUMS)

    def test_postgresql_without_guards_fails_closed(self):
        self.assertTrue(statements_for(v0001_core_schema, "postgresql"))
        with self.assertRaisesRegex(MigrationError, "no postgresql implementation"):
            statements_for(v0002_append_only_guards, "postgresql")

    def test_portable_ddl_uses_only_shared_sql(self):
        forbidden = re.compile(
            r"AUTOINCREMENT|INSERT OR|OR REPLACE|WITHOUT ROWID|PRAGMA|`|\b(BLOB|REAL|DATETIME|BOOLEAN|NUMERIC)\b|RAISE\s*\(",
            re.IGNORECASE,
        )
        for migration in MIGRATIONS:
            for statement in migration.STATEMENTS:
                with self.subTest(migration=migration.VERSION, statement=statement[:60]):
                    self.assertIsNone(forbidden.search(statement))
                    types = set(re.findall(r"^\s+(?!CHECK|UNIQUE|PRIMARY)\w+ (\w+)\b", statement, re.MULTILINE))
                    self.assertLessEqual(types, {"TEXT", "INTEGER"})

    def test_frozen_enum_literals_match_the_domain(self):
        m = v0001_core_schema
        permitted_modes = {mode.value for mode in ExecutionMode} - {ExecutionMode.PRODUCTION_MUTATION.value}
        pairs = {
            "EVIDENCE_SOURCES": (m.EVIDENCE_SOURCES, EvidenceSource),
            "RESULT_STATUSES": (m.RESULT_STATUSES, ResultStatus),
            "ACTOR_KINDS": (m.ACTOR_KINDS, ActorKind),
            "ENVIRONMENTS": (m.ENVIRONMENTS, DatabaseEnvironment),
            "APP_STATUSES": (m.APP_STATUSES, OktaAppStatus),
            "GROUP_TYPES": (m.GROUP_TYPES, OktaGroupType),
            "DEPENDENCY_KINDS": (m.DEPENDENCY_KINDS, DependencyKind),
            "APPROVAL_DECISIONS": (m.APPROVAL_DECISIONS, ApprovalDecision),
            "JOB_STATUSES": (m.JOB_STATUSES, JobStatus),
            "COLLECTOR_ERROR_CODES": (m.COLLECTOR_ERROR_CODES, CollectorErrorCode),
            "AUDIT_RESULTS": (m.AUDIT_RESULTS, AuditResult),
        }
        for name, (literal, enum_type) in pairs.items():
            with self.subTest(name=name):
                self.assertEqual(set(literal), {e.value for e in enum_type})
        self.assertEqual(set(m.TERMINAL_STATES), {s.value for s in TERMINAL_STATES})
        self.assertEqual(set(m.FINISHED_JOB_STATUSES), {s.value for s in FINISHED_STATUSES})
        self.assertEqual(set(m.JOB_MODES), {mode.value for mode in JOB_MODES})
        self.assertEqual(set(m.STORE_MODES), permitted_modes)
        self.assertEqual(set(v0004_candidate_policy.FINDING_CODES), {c.value for c in FindingCode})
        # Audit actions: 0005 extends the v0001 list (D41), 0007 extends 0005's, and
        # 0010 extends 0007's; every historical value stays allowed, and the latest list
        # equals the domain.
        self.assertEqual(set(v0010_remediation_dry_runs.AUDIT_ACTIONS), {a.value for a in AuditAction})
        self.assertLess(set(m.AUDIT_ACTIONS), set(v0005_review_audit_actions.AUDIT_ACTIONS))
        self.assertLess(set(v0005_review_audit_actions.AUDIT_ACTIONS), set(v0007_governed_refusals.AUDIT_ACTIONS))
        self.assertLess(set(v0007_governed_refusals.AUDIT_ACTIONS), set(v0010_remediation_dry_runs.AUDIT_ACTIONS))
        self.assertEqual(v0010_remediation_dry_runs.AUDIT_ACTIONS[: len(v0007_governed_refusals.AUDIT_ACTIONS)],
                         v0007_governed_refusals.AUDIT_ACTIONS)
        self.assertEqual(set(v0005_review_audit_actions.POLICY_ROLES), {r.value for r in PolicyRole})
        # Confidences: 0006 extends the v0001 list (D56); every earlier value stays allowed.
        self.assertEqual(set(v0006_unverified_stable_id.CONFIDENCES), {c.value for c in MappingConfidence})
        self.assertLess(set(m.CONFIDENCES), set(v0006_unverified_stable_id.CONFIDENCES))
        # Lifecycle states: 0009 extends the v0001 list, and
        # 0011 extends 0009's (the AD quarantine and deletion stages).
        v0011 = v0011_ad_quarantine_deletion_stages
        self.assertEqual(set(v0011.LIFECYCLE_STATES), {s.value for s in LifecycleState})
        self.assertLess(set(m.LIFECYCLE_STATES), set(v0009_evidence_incomplete_state.LIFECYCLE_STATES))
        self.assertLess(set(v0009_evidence_incomplete_state.LIFECYCLE_STATES), set(v0011.LIFECYCLE_STATES))
        # Approval stages and job kinds: 0011 extends v0001's, and keeps AD_RETIREMENT for the
        # legacy rows (D148).
        self.assertEqual(set(v0011.APPROVAL_STAGES), {s.value for s in ApprovalStage})
        self.assertEqual(set(v0011.JOB_KINDS), {k.value for k in JobKind})
        self.assertLess(set(m.APPROVAL_STAGES), set(v0011.APPROVAL_STAGES))
        self.assertLess(set(m.JOB_KINDS), set(v0011.JOB_KINDS))
        # Synthetic directory record kinds (0012).
        from app.governance.snapshot import RECORD_KINDS
        from app.store.migrations import v0012_synthetic_directory

        self.assertEqual(v0012_synthetic_directory.RECORD_KINDS, RECORD_KINDS)

    def test_every_append_only_table_exists(self):
        conn = connect(memory_target())
        upgrade(conn, DIALECT_SQLITE, clock=CLOCK)
        self.assertLessEqual(set(v0002_append_only_guards.APPEND_ONLY_TABLES), _tables(conn))
        conn.close()


class OpenAndConnectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "store.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def test_connect_never_creates_a_missing_database(self):
        with self.assertRaisesRegex(StoreError, "initialize it first"):
            connect(file_target(self.path))
        self.assertFalse(self.path.exists())

    def test_foreign_keys_are_enforced(self):
        conn = connect(memory_target())
        self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        conn.close()

    def test_open_refuses_a_store_with_pending_migrations(self):
        conn = connect(file_target(self.path), create=True)
        upgrade(conn, DIALECT_SQLITE, clock=CLOCK, target=1)
        conn.close()
        with self.assertRaisesRegex(MigrationError, "run the upgrade command"):
            Store.open(file_target(self.path), mode=ExecutionMode.LOCAL_SYNTHETIC)

    def test_open_refuses_an_unmarked_database(self):
        conn = connect(file_target(self.path), create=True)
        upgrade(conn, DIALECT_SQLITE, clock=CLOCK)
        conn.close()
        with self.assertRaisesRegex(StoreError, "environment marker"):
            Store.open(file_target(self.path), mode=ExecutionMode.LOCAL_SYNTHETIC)

    def test_initialize_refuses_an_existing_file(self):
        self.path.write_text("not a database", encoding="utf-8")
        with self.assertRaisesRegex(StoreError, "already exists"):
            new_store(file_target(self.path))
        self.assertEqual(self.path.read_text(encoding="utf-8"), "not a database")

    def test_reopen_after_initialize(self):
        new_store(file_target(self.path)).close()
        with Store.open(file_target(self.path), mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            self.assertIs(store.marker.environment, DatabaseEnvironment.SYNTHETIC)
            self.assertEqual(len(store.audit_events()), 1)


class StoreIsolationTests(unittest.TestCase):
    """The store and the demo generator never reach the network or mutation code."""

    FORBIDDEN = {
        "socket", "http", "http.client", "urllib.request", "subprocess", "requests", "httpx",
        "app.core.safety",
    }

    def test_store_and_demo_import_nothing_forbidden(self):
        for package in ("store", "demo"):
            for path in (REPO_ROOT / "app" / package).rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                imported = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.update(a.name for a in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.add(node.module)
                with self.subTest(path=path.relative_to(REPO_ROOT).as_posix()):
                    self.assertEqual(imported & self.FORBIDDEN, set())


if __name__ == "__main__":
    unittest.main()
