"""Migration 0008 (owner decision): Okta's directory objectSid as unverified source metadata.

The synthetic world is seeded with the build held at schema 7 (no Okta SIDs, which only 0008
can hold) and then upgraded. Every existing row must keep its values, the chain must
verify, and the new column must accept only an APP_GROUP SID. The value is part of the
Okta group observation, so it carries that observation's provenance and freshness.
"""

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from app.core.modes import ExecutionMode
from app.demo.synthetic_world import create_seeded_store
from app.domain.errors import InvalidRecord
from app.domain.evidence import stable_digest
from app.domain.model import OktaGroup, OktaGroupType
from app.store.db import DIALECT_SQLITE, connect
from app.store.migrations import v0008_okta_directory_sid
from app.store.migrator import upgrade
from app.store.store import Store
from tests.api_fixtures import AUTOMATION, World
from tests.domain_fixtures import SYSTEM, T0, okta_group
from tests.store_fixtures import build_held_at, file_target

COLUMN = v0008_okta_directory_sid.COLUMN
SID = "S-1-5-21-1000000001-1000000002-1000000003-5010"


def dump(conn: sqlite3.Connection) -> dict[str, list[tuple]]:
    out = {}
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"):
        columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})") if r[1] != COLUMN]
        order = ", ".join(columns)
        out[table] = [tuple(r) for r in conn.execute(f"SELECT {order} FROM {table} ORDER BY {order}")]
    return out


class OktaDirectorySidMigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = file_target(Path(tmp.name) / "seeded.sqlite3")
        with build_held_at(7):
            store, self.summary = create_seeded_store(self.target)
            store.close()

    def upgraded(self) -> sqlite3.Connection:
        conn = connect(self.target)
        self.addCleanup(conn.close)
        self.assertEqual(upgrade(conn, DIALECT_SQLITE, clock=lambda: self.summary.as_of, target=8), [8])  # 0008 alone
        return conn

    def test_rows_are_unchanged_and_the_chain_verifies(self):
        conn = connect(self.target)
        before = dump(conn)
        conn.close()
        conn = self.upgraded()
        after = dump(conn)
        self.assertEqual(len(after["schema_migrations"]), len(before["schema_migrations"]) + 1)
        self.assertEqual({t: rows for t, rows in after.items() if t != "schema_migrations"},
                         {t: rows for t, rows in before.items() if t != "schema_migrations"})
        self.assertEqual(conn.execute(f"SELECT count(*) FROM okta_group_observations WHERE {COLUMN} IS NOT NULL")
                         .fetchone()[0], 0)
        conn.close()
        # Verify the store exactly as 0008 left it (the build is held at 8; 0009 is tested separately).
        with build_held_at(8), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            report = store.verify_integrity(expected_audit_head=self.summary.audit_head)
        self.assertEqual((report.schema_version, report.audit_head), (8, self.summary.audit_head))

    def _copy_observation(self, conn, **overrides):
        columns = [r[1] for r in conn.execute("PRAGMA table_info(okta_group_observations)")]
        row = dict(conn.execute("SELECT * FROM okta_group_observations WHERE group_type = 'APP_GROUP' LIMIT 1")
                   .fetchone())
        row.update(observation_id="obs_" + "f" * 32, **overrides)
        conn.execute(f"INSERT INTO okta_group_observations ({', '.join(columns)}) "
                     f"VALUES ({', '.join('?' for _ in columns)})", [row[c] for c in columns])

    def test_the_column_accepts_only_an_app_group_sid(self):
        conn = self.upgraded()
        conn.row_factory = sqlite3.Row
        bad = {
            "malformed": {COLUMN: "not-a-sid"},
            "lowercase": {COLUMN: SID.lower()},
            "embedded space": {COLUMN: SID.replace("-5010", "- 5010")},
            "not an APP_GROUP": {COLUMN: SID, "group_type": "OKTA_GROUP", "source_directory_id": None,
                                 "directory_external_id": None, "directory_qualified_name": None},
        }
        for name, overrides in bad.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK"):
                    self._copy_observation(conn, **overrides)
        # A well-formed APP_GROUP SID is accepted (a later observation of the same group).
        self._copy_observation(conn, observed_at="2026-03-02T13:00:00.000000Z", **{COLUMN: SID})
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute(f"UPDATE okta_group_observations SET {COLUMN} = ?", (SID,))
        conn.rollback()

    def test_a_held_build_cannot_drop_a_sid_silently(self):
        with build_held_at(7), Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            group = replace(okta_group(T0), directory_object_sid_unverified=SID)
            with self.assertRaises(AssertionError):
                store.record_evidence(group, actor=SYSTEM)


class OktaGroupSidRecordTests(unittest.TestCase):
    def test_it_is_validated_as_a_sid_on_an_app_group_only(self):
        app_group = okta_group(T0)
        self.assertIs(app_group.group_type, OktaGroupType.APP_GROUP)
        for bad in ("not-a-sid", "S-1-", "s-1-5-21-1", "S-1-5-21-" + "1" * 200):
            with self.subTest(sid=bad):
                with self.assertRaises(InvalidRecord):
                    replace(app_group, directory_object_sid_unverified=bad)
        with self.assertRaises(InvalidRecord):
            replace(app_group, group_type=OktaGroupType.OKTA_GROUP, source_directory_id=None,
                    directory_external_id=None, directory_qualified_name=None, directory_object_sid_unverified=SID)

    def test_without_a_sid_the_digest_is_what_it_was_before_0008(self):
        group = okta_group(T0)
        self.assertIsNone(group.directory_object_sid_unverified)
        before = {"okta_group_id": group.okta_group_id, "group_type": group.group_type,
                  "source_directory_id": group.source_directory_id, "directory_external_id": group.directory_external_id,
                  "directory_qualified_name": group.directory_qualified_name}
        self.assertEqual(group.material(), before)
        self.assertEqual(group.digest, stable_digest({"kind": group.KIND.value, "id": group.id, "material": before}))
        self.assertNotEqual(replace(group, directory_object_sid_unverified=SID).digest, group.digest)


class StoredSidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def group_of(self, key):
        return self.world.store.load_candidate(self.world.candidate(key)).okta_group_id

    def test_it_round_trips_with_its_observation_provenance(self):
        group = self.world.store.latest(OktaGroup, self.group_of("S01"))
        self.assertEqual(group.directory_object_sid_unverified, SID)
        self.assertEqual(group.provenance.scope, "synthetic:okta:group:00gSYNTHGRP01")
        self.assertTrue(group.provenance.decision_grade)
        self.assertIsNone(self.world.store.latest(OktaGroup, self.group_of("S08")).directory_object_sid_unverified)

    def test_the_api_labels_it_unverified(self):
        body = self.world.client(AUTOMATION).get(f"/api/v1/groups/{self.group_of('S01')}").json
        self.assertEqual(body["group"]["directoryObjectSidUnverified"], SID)
        self.assertNotIn("directoryObjectSid", body["group"])
        self.assertEqual(body["mapping"]["confidence"], "EXACT_CONFIGURED_MAPPING")  # from the configured pairing


if __name__ == "__main__":
    unittest.main()
