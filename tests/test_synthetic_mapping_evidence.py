"""Owner decision: the demo's identity mappings come from the engine.

Every IdentityMapping in the synthetic world is what the correlation engine proves over the
synthetic AD directory with ``config/correlation.synthetic.json``. Nothing is seeded as
already exact; a group the configuration does not name can only reach the name search; and
no production verification gate (D30, D37) is opened for the demo.

Synthetic only: in-memory seeded stores and the store-backed synthetic directory.
"""

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.correlation import model as correlation_model
from app.correlation.engine import correlate
from app.correlation.evidence import mapping_id_for
from app.correlation.model import CorrelationConfig, CorrelationOutcome
from app.demo import synthetic_world
from app.demo.synthetic_directory import (
    SYNTHETIC_CORRELATION_PATH,
    StoreADGroupIds,
    StoreSyntheticDirectory,
    correlate_stored_group,
    load_synthetic_correlation_config,
    okta_group_identity,
)
from app.demo.synthetic_world import create_seeded_store
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.model import IdentityMapping, MappingConfidence, OktaGroup
from app.integrations.okta import normalize
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreError
from tests.api_fixtures import AUTOMATION, World
from tests.store_fixtures import memory_target, new_store

V = "/api/v1"
CONFIG = load_synthetic_correlation_config()


def stored_mappings(store) -> list[IdentityMapping]:
    rows = store.connection.execute("SELECT id FROM identity_mappings ORDER BY id").fetchall()
    return [store.latest(IdentityMapping, r["id"]) for r in rows]


class EngineProducedMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()
        cls.store = cls.world.store

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def okta_id(self, mapping: IdentityMapping) -> str:
        return self.store.latest(OktaGroup, mapping.okta_group_id).okta_group_id

    def test_every_stored_mapping_is_what_the_engine_proves_now(self):
        mappings = stored_mappings(self.store)
        self.assertEqual(len(mappings), 15)  # every scenario but S13, whose AD read timed out
        for stored in mappings:
            with self.subTest(okta_group=self.okta_id(stored)):
                _, fresh = correlate_stored_group(self.store, stored.okta_group_id, config=CONFIG,
                                                  clock=lambda: stored.provenance.observed_at)
                self.assertEqual(stored.id, mapping_id_for(stored.okta_group_id))
                self.assertEqual(fresh.material(), stored.material())
                self.assertEqual(fresh.reason, stored.reason)
                self.assertIs(stored.provenance.source, EvidenceSource.SYNTHETIC)
                self.assertEqual(stored.provenance.collector_version, correlation_model.CORRELATION_VERSION)

    def test_exact_only_where_the_configuration_names_the_pair(self):
        configured = {m.okta_group_id: m for m in CONFIG.configured_mappings}
        exact = []
        for stored in stored_mappings(self.store):
            okta_id = self.okta_id(stored)
            with self.subTest(okta_group=okta_id):
                if stored.is_exact:
                    exact.append(okta_id)
                    self.assertIs(stored.confidence, MappingConfidence.EXACT_CONFIGURED_MAPPING)
                    self.assertEqual(stored.configuration_ref, configured[okta_id].configuration_ref)
                    self.assertEqual(set(stored.matched_attributes), {"objectGUID", "objectSid"})
                    self.assertIs(stored.provenance.result_status, ResultStatus.COMPLETE)
                else:
                    self.assertNotIn(stored.confidence, (MappingConfidence.EXACT_STABLE_ID,
                                                         MappingConfidence.EXACT_DIRECTORY_SOURCE))
        self.assertEqual(len(exact), 12)
        self.assertNotIn("00gSYNTHGRP10", exact)  # configured, but its objectGUID resolves nowhere

    def test_the_api_inspection_agrees_with_the_lifecycle_evidence(self):
        automation = self.world.client(AUTOMATION)
        expected = {"S01": ("RESOLVED", "EXACT_CONFIGURED_MAPPING"), "S07": ("RESOLVED", "EXACT_CONFIGURED_MAPPING"),
                    "S08": ("REVIEW_REQUIRED", "NAME_ONLY"), "S09": ("AMBIGUOUS", "AMBIGUOUS"),
                    "S10": ("STALE", "NOT_FOUND")}
        for key, (outcome, confidence) in expected.items():
            with self.subTest(scenario=key):
                candidate = self.store.load_candidate(self.world.candidate(key))
                stored = self.store.evidence_bundle(candidate).mapping
                inspection = automation.post(f"{V}/mappings/{candidate.okta_group_id}/inspection", {}).json
                self.assertEqual(inspection["outcome"], outcome)
                self.assertEqual((stored.confidence.value, inspection["confidence"]), (confidence, confidence))


class VerificationGateTests(unittest.TestCase):
    """The demo establishes exactness only through the configured path; the gates stay closed."""

    def setUp(self):
        self.store, self.summary = create_seeded_store(memory_target())
        self.addCleanup(self.store.close)
        self.s01 = next(s for s in self.summary.scenarios if s.key == "S01")
        self.group = self.store.load_candidate(self.s01.candidate_id).okta_group_id

    def test_the_gates_are_closed(self):
        self.assertFalse(correlation_model.DIRECTORY_SOURCE_SID_VERIFIED)
        self.assertFalse(normalize.OBJECT_GUID_DECODING_VERIFIED)

    def test_the_stored_okta_sid_alone_stays_review_required(self):
        # D37: Okta's stored objectSid (0008) resolves to the right group, but is not a basis.
        group = self.store.latest(OktaGroup, self.group)
        self.assertEqual(group.directory_object_sid_unverified, CONFIG.configured(group.okta_group_id).ad_sid)
        unconfigured = CorrelationConfig(directory_sources=CONFIG.directory_sources)
        result, mapping = correlate_stored_group(self.store, self.group, config=unconfigured,
                                                 clock=lambda: synthetic_world.AS_OF)
        self.assertIs(result.outcome, CorrelationOutcome.UNVERIFIED_IDENTIFIER)
        self.assertIs(mapping.confidence, MappingConfidence.UNVERIFIED_STABLE_ID)
        self.assertFalse(mapping.is_exact)

    def test_the_stored_okta_sid_corroborates_the_configured_pairing(self):
        result, mapping = correlate_stored_group(self.store, self.group, config=CONFIG,
                                                 clock=lambda: synthetic_world.AS_OF)
        self.assertEqual({c.basis for c in result.claims}, {"configured", "directory-source"})
        self.assertIs(mapping.confidence, MappingConfidence.EXACT_CONFIGURED_MAPPING)

    def test_an_okta_sid_naming_another_group_stops_the_pairing(self):
        group = self.store.latest(OktaGroup, self.group)
        other = replace(group, directory_object_sid_unverified=CONFIG.configured("00gSYNTHGRP03").ad_sid)
        result = correlate(okta_group_identity(other),
                           directory=StoreSyntheticDirectory(self.store, clock=lambda: synthetic_world.AS_OF),
                           config=CONFIG, clock=lambda: synthetic_world.AS_OF)
        self.assertIs(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertFalse(result.is_exact)

    def test_the_okta_derived_guid_is_never_used(self):
        group = self.store.latest(OktaGroup, self.group)
        self.assertIsNotNone(group.directory_external_id)
        self.assertIsNone(okta_group_identity(group).directory_object_guid)

    def test_without_a_pairing_or_an_okta_sid_a_group_is_only_name_matched(self):
        group = self.store.latest(OktaGroup, self.group)
        config = replace(CONFIG, configured_mappings=tuple(m for m in CONFIG.configured_mappings
                                                           if m.okta_group_id != group.okta_group_id))
        bare = replace(group, directory_object_sid_unverified=None)
        result = correlate(okta_group_identity(bare),
                           directory=StoreSyntheticDirectory(self.store, clock=lambda: synthetic_world.AS_OF),
                           config=config, clock=lambda: synthetic_world.AS_OF)
        self.assertIs(result.outcome, CorrelationOutcome.REVIEW_REQUIRED)
        self.assertIs(result.confidence, MappingConfidence.NAME_ONLY)

    def test_a_configured_pairing_must_agree_on_both_identifiers(self):
        okta_id = self.store.latest(OktaGroup, self.group).okta_group_id
        other_sid = CONFIG.configured("00gSYNTHGRP03").ad_sid
        config = replace(CONFIG, configured_mappings=tuple(
            replace(m, ad_sid=other_sid) if m.okta_group_id == okta_id else m for m in CONFIG.configured_mappings))
        result, mapping = correlate_stored_group(self.store, self.group, config=config, clock=lambda: synthetic_world.AS_OF)
        self.assertIs(result.outcome, CorrelationOutcome.STALE)
        self.assertFalse(mapping.is_exact)
        self.assertIs(mapping.provenance.result_status, ResultStatus.FAILED)


class SeedGuardTests(unittest.TestCase):
    def test_seeding_stops_if_the_engine_cannot_prove_a_scenario(self):
        config = replace(CONFIG, configured_mappings=tuple(m for m in CONFIG.configured_mappings
                                                           if m.okta_group_id != "00gSYNTHGRP01"))
        with mock.patch.object(synthetic_world, "load_synthetic_correlation_config", return_value=config):
            with self.assertRaisesRegex(StoreError, "expected S01 to correlate as EXACT_CONFIGURED_MAPPING; "
                                                    "the engine proved UNVERIFIED_STABLE_ID"):
                create_seeded_store(memory_target())

    def test_only_a_synthetic_store_can_be_correlated_this_way(self):
        stores = [new_store(environment=DatabaseEnvironment.PRODUCTION, mode=ExecutionMode.READ_ONLY_PRODUCTION),
                  new_store(environment=DatabaseEnvironment.DEVELOPMENT, mode=ExecutionMode.LOCAL_SYNTHETIC)]
        for store in stores:
            self.addCleanup(store.close)
            with self.subTest(environment=store.marker.environment):
                with self.assertRaises(ConfigError):
                    StoreADGroupIds(store)
                with self.assertRaises(ConfigError):
                    correlate_stored_group(store, "ogrp_" + "0" * 32, config=CONFIG, clock=lambda: synthetic_world.AS_OF)

    def test_unknown_ad_group_ids_are_refused(self):
        store, _ = create_seeded_store(memory_target())
        self.addCleanup(store.close)
        with self.assertRaises(StoreError):
            StoreADGroupIds(store).ad_group("5e1f0c3a-0000-4000-8000-ffffffffffff")


class ConfigLoaderTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.data = json.loads(SYNTHETIC_CORRELATION_PATH.read_text(encoding="utf-8"))

    def load(self, data) -> CorrelationConfig:
        path = self.dir / "c.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_synthetic_correlation_config(path)

    def test_the_repository_configuration_loads(self):
        config = self.load(self.data)
        self.assertEqual([s.domain for s in config.directory_sources], ["corp.synthetic.example"])
        self.assertEqual(len(config.configured_mappings), 13)  # S15 and S16: the AD stages

    def test_anything_not_synthetic_is_refused(self):
        def mapping_with(**changes):
            data = json.loads(json.dumps(self.data))
            data["correlation"]["configuredMappings"][0].update(changes)
            return data

        def source_with(**changes):
            data = json.loads(json.dumps(self.data))
            data["correlation"]["directorySources"][0].update(changes)
            return data

        bad = {
            "wrong format": {**self.data, "format": "ogwa-correlation/1"},
            "extra top-level key": {**self.data, "note": "x"},
            "unknown correlation key": {**self.data, "correlation": {**self.data["correlation"], "trustSids": True}},
            "real-looking Okta group": mapping_with(oktaGroupId="00g1a2b3c4d5e6f7g8h9"),
            "non-synthetic domain": mapping_with(domain="corp.example.com"),
            "unscoped pairing": {**mapping_with(), "correlation": {**self.data["correlation"], "configuredMappings": [
                {k: v for k, v in self.data["correlation"]["configuredMappings"][0].items() if k != "domain"}]}},
            "objectGUID without objectSid": {**self.data, "correlation": {**self.data["correlation"], "configuredMappings": [
                {k: v for k, v in self.data["correlation"]["configuredMappings"][0].items() if k != "adSid"}]}},
            "foreign configurationRef": mapping_with(configurationRef="config/mappings.json#S01"),
            "malformed GUID": mapping_with(adObjectGuid="not-a-guid"),
            "real-looking directory source": source_with(oktaAppId="0oa1a2b3c4d5e6f7g8h9"),
            "non-synthetic source domain": source_with(domain="corp.example.com"),
        }
        for name, data in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(ConfigError):
                    self.load(data)
        with self.assertRaises(ConfigError):
            load_synthetic_correlation_config(self.dir / "missing.json")


if __name__ == "__main__":
    unittest.main()
