"""The provider boundary (Demo Mode): the demo's providers are chosen once, and all are synthetic."""

import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.core.errors import ConfigError
from app.demo.synthetic_directory import SyntheticMappingGateway
from app.demo.synthetic_world import create_seeded_store
from app.domain.remediation import RemediationOperation
from app.remediation.allowlist import AdapterKind, AllowlistEntry, RemediationAllowlist
from app.runtime.datasets import resolve_dataset
from app.runtime.providers import DemoModeBlocked, IntegrationProviders, SyntheticOktaProvider, select_providers
from app.store.environment import DatabaseEnvironment
from tests.api_fixtures import TickClock
from tests.store_fixtures import memory_target

DATASET = "classic"


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_seeded_store(memory_target())
        cls.dataset = resolve_dataset(DATASET)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_the_demo_selects_only_synthetic_providers(self):
        providers = select_providers(store=self.store, dataset=self.dataset, clock=TickClock())
        self.assertEqual({f.name for f in dataclasses.fields(IntegrationProviders)},
                         {"okta", "ad_directory", "remediation_allowlist"})
        self.assertIsInstance(providers.okta, SyntheticOktaProvider)
        self.assertIsInstance(providers.ad_directory, SyntheticMappingGateway)
        self.assertEqual(providers.data_source, "synthetic")
        self.assertTrue(all(e.adapter is AdapterKind.SYNTHETIC for e in providers.remediation_allowlist.entries))

    def test_providers_need_the_opened_store_its_dataset_and_a_clock(self):
        for kwargs in ({"store": None, "dataset": self.dataset, "clock": TickClock()},
                       {"store": self.store, "dataset": None, "clock": TickClock()},
                       {"store": self.store, "dataset": self.dataset, "clock": None}):
            with self.subTest(missing=[k for k, v in kwargs.items() if v is None]), self.assertRaises(ConfigError):
                select_providers(**kwargs)

    def test_the_demo_refuses_an_allowlist_naming_a_live_adapter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlist.json"
            path.write_text(json.dumps({"format": "ogwa-remediation-allowlist/v2", "environment": "SYNTHETIC",
                                        "operations": {"OKTA_GROUP_UNASSIGN": {"adapter": "SYNTHETIC"}}}))
            select_providers(store=self.store, dataset=self.dataset, clock=TickClock(),
                             demo_allowlist_path=path)  # synthetic only: accepted
        live = RemediationAllowlist(DatabaseEnvironment.SYNTHETIC, (AllowlistEntry(
            RemediationOperation.OKTA_GROUP_UNASSIGN, AdapterKind.AAP, None),))
        with mock.patch("app.runtime.providers.load_allowlist", return_value=live), self.assertRaises(DemoModeBlocked):
            select_providers(store=self.store, dataset=self.dataset, clock=TickClock())


class SyntheticOktaProviderReadTests(unittest.TestCase):
    """The synthetic provider reads the dataset's canonical records through the shared read model."""

    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_seeded_store(memory_target())
        cls.provider = SyntheticOktaProvider(cls.store, resolve_dataset(DATASET))

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_known_synthetic_group_and_application_can_be_read(self):
        s07 = self.store.load_candidate(next(s.candidate_id for s in self.summary.scenarios if s.key == "S07"))
        group = self.provider.group(s07.okta_group_id)
        self.assertIsNotNone(group)
        self.assertIn(group.id, {g.id for g in self.provider.groups()})
        assignments = self.provider.assignments_of_group(group.id)
        self.assertTrue(assignments)
        application = self.provider.application(assignments[0].application_id)
        self.assertIsNotNone(application)
        self.assertIn(application.id, {a.id for a in self.provider.applications()})
        self.assertIn(group.id, {a.okta_group_id for a in self.provider.assignments_of_application(application.id)})


if __name__ == "__main__":
    unittest.main()
