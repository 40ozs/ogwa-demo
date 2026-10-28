"""The provider boundary (Demo Mode): the runtime mode selects real or synthetic providers, once."""

import unittest
from unittest import mock

from app.core.config import load_settings
from app.demo.synthetic_directory import SyntheticMappingGateway
from app.integrations.aap.client import AapReadOnlyClient
from app.integrations.okta.client import OktaReadOnlyClient
from app.remediation.allowlist import AdapterKind
from app.runtime.datasets import resolve_dataset
from app.runtime.providers import (
    DemoModeBlocked,
    DisabledAapProvider,
    RealAapProvider,
    RealOktaProvider,
    SyntheticOktaProvider,
    select_providers,
)
from app.core.errors import OgwaSafetyError
from app.core.runtime_mode import RuntimeMode
from app.demo.synthetic_world import create_seeded_store
from tests.api_fixtures import TickClock
from tests.store_fixtures import memory_target

DATASET = "classic"
DEMO_ENV = {"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": DATASET}


def _spies():
    """Constructor spies on every client that can reach a live system."""
    return (mock.patch.object(OktaReadOnlyClient, "__init__", side_effect=AssertionError("Okta client built")),
            mock.patch.object(AapReadOnlyClient, "__init__", side_effect=AssertionError("AAP client built")))


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_seeded_store(memory_target())
        cls.dataset = resolve_dataset(DATASET)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_production_selects_the_real_providers_without_contacting_anything(self):
        okta_spy, aap_spy = _spies()
        with okta_spy as okta_init, aap_spy as aap_init:
            providers = select_providers(load_settings({}), store=self.store)
        self.assertIs(providers.runtime_mode, RuntimeMode.PRODUCTION)
        self.assertIsInstance(providers.okta, RealOktaProvider)
        self.assertIsInstance(providers.aap, RealAapProvider)
        self.assertEqual(providers.data_source, "okta-management-api")
        okta_init.assert_not_called()
        aap_init.assert_not_called()

    def test_demo_selects_only_synthetic_providers(self):
        okta_spy, aap_spy = _spies()
        with okta_spy as okta_init, aap_spy as aap_init:
            providers = select_providers(load_settings(DEMO_ENV), store=self.store, dataset=self.dataset,
                                         clock=TickClock())
        self.assertIs(providers.runtime_mode, RuntimeMode.DEMO)
        self.assertIsInstance(providers.okta, SyntheticOktaProvider)
        self.assertIsInstance(providers.aap, DisabledAapProvider)
        self.assertIsInstance(providers.ad_directory, SyntheticMappingGateway)
        self.assertEqual(providers.data_source, "synthetic")
        self.assertTrue(all(e.adapter is AdapterKind.SYNTHETIC for e in providers.remediation_allowlist.entries))
        self.assertEqual(dict(providers.remediation_templates), {})
        okta_init.assert_not_called()
        aap_init.assert_not_called()

    def test_real_providers_refuse_to_exist_in_demo(self):
        settings = load_settings(DEMO_ENV)
        with self.assertRaises(DemoModeBlocked):
            RealOktaProvider(self.store, settings)
        with self.assertRaises(DemoModeBlocked):
            RealAapProvider(settings)

    def test_demo_has_no_collector_and_no_aap(self):
        providers = select_providers(load_settings(DEMO_ENV), store=self.store, dataset=self.dataset,
                                     clock=TickClock())
        with self.assertRaises(DemoModeBlocked):
            providers.okta.collector_session(credentials=object())
        with self.assertRaises(DemoModeBlocked):
            providers.aap.discovery_client()

    def test_production_collector_sessions_are_built_only_on_request(self):
        settings = load_settings({"OGWA_EXECUTION_MODE": "READ_ONLY_PRODUCTION",
                                  "OGWA_OKTA_ORG_URL": "https://synthetic-org.okta.example"})
        providers = select_providers(settings, store=None)
        with mock.patch.object(OktaReadOnlyClient, "from_settings", return_value="client") as built:
            self.assertEqual(providers.okta.collector_session(credentials="synthetic-credential"), "client")
        built.assert_called_once()
        with mock.patch.object(AapReadOnlyClient, "from_settings", return_value="aap") as aap_built:
            self.assertEqual(providers.aap.discovery_client(), "aap")
        aap_built.assert_called_once()

    def test_no_okta_collection_in_local_synthetic_production(self):
        with self.assertRaises(OgwaSafetyError):
            select_providers(load_settings({}), store=self.store).okta.collector_session(credentials=object())

    def test_demo_refuses_an_allowlist_naming_a_live_adapter(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlist.json"
            path.write_text(json.dumps({"format": "ogwa-remediation-allowlist/v2", "environment": "SYNTHETIC",
                                        "operations": {"OKTA_GROUP_UNASSIGN": {"adapter": "SYNTHETIC"}}}))
            select_providers(load_settings(DEMO_ENV), store=self.store, dataset=self.dataset, clock=TickClock(),
                             demo_allowlist_path=path)  # synthetic only: accepted
        from app.remediation.allowlist import AllowlistEntry, RemediationAllowlist
        from app.domain.remediation import RemediationOperation
        from app.store.environment import DatabaseEnvironment

        live = RemediationAllowlist(DatabaseEnvironment.SYNTHETIC, (AllowlistEntry(
            RemediationOperation.OKTA_GROUP_UNASSIGN, AdapterKind.AAP, None),))
        with mock.patch("app.runtime.providers.load_allowlist", return_value=live), self.assertRaises(DemoModeBlocked):
            select_providers(load_settings(DEMO_ENV), store=self.store, dataset=self.dataset, clock=TickClock())


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
