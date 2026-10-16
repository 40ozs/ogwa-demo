"""Migration 0006 (D56): the UNVERIFIED_STABLE_ID confidence, with stored mappings preserved.

The synthetic demo world is seeded into a schema-5 store (the build is held at 5 for the
seed), then upgraded. Every identity-mapping observation and every candidate row that
references one by foreign key must be unchanged, and the store must verify.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.core.modes import ExecutionMode
from app.demo.synthetic_world import create_seeded_store
from app.domain.errors import InvalidRecord
from app.domain.model import IdentityMapping, MappingConfidence
from app.store.db import DIALECT_SQLITE, connect
from app.store.errors import StoreConflict
from app.store.migrations import v0002_append_only_guards
from app.store.migrator import upgrade
from app.store.store import Store
from tests.domain_fixtures import SYSTEM, T0, ad_group, mapping, okta_group
from tests.store_fixtures import build_held_at, file_target, new_store

TABLES = ("identity_mapping_observations", "identity_mapping_candidates", "audit_events")


def dump(conn: sqlite3.Connection, table: str) -> list[tuple]:
    columns = ", ".join(r[1] for r in conn.execute(f"PRAGMA table_info({table})"))
    return [tuple(r) for r in conn.execute(f"SELECT {columns} FROM {table} ORDER BY {columns}")]


def held_at_schema_5():
    return build_held_at(5)


def unverified_mapping():
    return mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID, matched_attributes=("objectSid", "samAccountName"),
                   reason="directory-source objectSid resolves to one AD group; mechanism unverified (D37)")


class UnverifiedIdentifierMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = file_target(Path(self.tmp.name) / "seeded.sqlite3")
        with held_at_schema_5():
            store, _ = create_seeded_store(self.target)
            store.close()

    def tearDown(self):
        self.tmp.cleanup()

    def _conn(self):
        return connect(self.target)

    def test_seeded_world_has_mappings_with_candidate_rows(self):
        conn = self._conn()
        try:
            self.assertGreaterEqual(len(dump(conn, "identity_mapping_candidates")), 2)
        finally:
            conn.close()

    def test_rows_and_foreign_keys_are_preserved(self):
        conn = self._conn()
        try:
            before = {t: dump(conn, t) for t in TABLES}
            self.assertEqual(upgrade(conn, DIALECT_SQLITE, clock=lambda: T0, target=6), [6])  # 0006 alone
            self.assertEqual({t: dump(conn, t) for t in TABLES}, before)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIsNone(conn.execute(
                "SELECT name FROM sqlite_master WHERE name = 'ogwa_v0006_backup'").fetchone())
        finally:
            conn.close()
        # Verify the store exactly as 0006 left it (the build is held at 6; 0007 is tested separately).
        with build_held_at(6), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            report = store.verify_integrity()
        self.assertEqual(report.schema_version, 6)

    def test_guards_survive_the_rebuild(self):
        conn = self._conn()
        try:
            upgrade(conn, DIALECT_SQLITE, clock=lambda: T0)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("UPDATE identity_mapping_observations SET reason = 'edited'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                conn.execute("DELETE FROM identity_mapping_observations")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "FOREIGN KEY"):
                conn.execute("INSERT INTO identity_mapping_candidates (observation_id, ordinal, ad_group_id) "
                             "SELECT 'obs_' || hex(randomblob(16)), 0, ad_group_id FROM identity_mapping_candidates LIMIT 1")
            triggers = {name: sql for name, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'identity_mapping_observations'")}
            expected = {s.split()[2]: s for s in v0002_append_only_guards.DIALECT_STATEMENTS["sqlite"]
                        if s.split()[2].startswith("trg_identity_mapping_observations_")}
            self.assertEqual(triggers, expected)
            self.assertIsNotNone(conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'ix_mapping_obs_ad_group'").fetchone())
        finally:
            conn.close()


class UnverifiedConfidenceRecordTests(unittest.TestCase):
    def test_record_rules(self):
        m = unverified_mapping()
        self.assertFalse(m.is_exact)
        with self.assertRaisesRegex(InvalidRecord, "objectGUID or objectSid"):
            mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID, matched_attributes=("samAccountName",))
        with self.assertRaises(InvalidRecord):
            mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID, matched_attributes=("objectSid",),
                    ad_group_id=None)
        with self.assertRaises(InvalidRecord):
            mapping(T0, confidence=MappingConfidence.UNVERIFIED_STABLE_ID, matched_attributes=("objectSid",),
                    configuration_ref="config/x.json#1")


class UnverifiedConfidenceStorageTests(unittest.TestCase):
    def _record(self, store):
        store.record_evidence(okta_group(T0), actor=SYSTEM)
        store.record_evidence(ad_group(T0), actor=SYSTEM)
        store.record_evidence(unverified_mapping(), actor=SYSTEM)

    def test_refused_before_0006(self):
        with held_at_schema_5():
            store = new_store()
            try:
                with self.assertRaisesRegex(StoreConflict, "CHECK"):
                    self._record(store)
            finally:
                store.close()

    def test_stored_and_read_back_after_0006(self):
        store = new_store()
        try:
            self._record(store)
            loaded = store.latest(IdentityMapping, unverified_mapping().id)
            self.assertEqual(loaded, unverified_mapping())
            self.assertFalse(loaded.is_exact)
            store.verify_integrity()
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
