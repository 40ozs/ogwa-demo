"""The provider boundary: the one place the runtime mode selects integration providers.

OGWA's shared logic (inventory read model, correlation engine, candidate classification,
lifecycle, governance, API, UI) reads only from the store. Live systems reach the store
only through collectors and integration adapters, and those are chosen here, once:

| Role | ``production`` | ``demo`` |
| --- | --- | --- |
| Okta | ``RealOktaProvider``: store reads, plus a GET-only ``OktaReadOnlyClient`` collector session built on request, with an approved credential | ``SyntheticOktaProvider``: store reads of the seeded synthetic dataset; no collector exists |
| AD directory (mapping review) | none in this build (the read-only PowerShell worker runs under AAP, P05) | ``SyntheticMappingGateway`` over the store's synthetic AD evidence |
| AAP | ``RealAapProvider``: a GET-only ``AapReadOnlyClient`` built on request, from ``OGWA_AAP_URL``/``OGWA_AAP_TOKEN`` | ``DisabledAapProvider``: refuses; no AAP client is ever built |
| Remediation | the deployment's allowlist (SYNTHETIC or AAP adapters, dry run only) | the synthetic allowlist, SYNTHETIC adapter only: SIMULATED answers |

In demo the real providers are never constructed (they refuse to be), so no Okta or AAP
client and no HTTP client exists in a demo process. This module imports the client classes
only inside the production methods that build them; a demo build never imports the AAP
client module (the Okta client module is imported indirectly by existing domain code, but
never instantiated). Business logic never checks the runtime mode itself; it receives what
this module selected.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from app.api.readmodel import ReadModel
from app.api.validation import Page
from app.core.config import Settings
from app.core.errors import ConfigError, OgwaSafetyError
from app.core.modes import ExecutionMode
from app.core.runtime_mode import RuntimeMode
from app.domain.model import ApplicationGroupAssignment, OktaApplication, OktaGroup
from app.remediation.allowlist import AdapterKind, RemediationAllowlist, load_allowlist
from app.runtime.datasets import DemoDataset
from app.store.environment import DatabaseEnvironment
from app.store.store import Store

MAX_LIST = 1000


class DemoModeBlocked(OgwaSafetyError):
    """An operation that needs a live system was asked for in the demo runtime."""


# --- Okta --------------------------------------------------------------------------------


class _StoreInventory:
    """Okta inventory as recorded in the store: the read surface the shared logic uses."""

    name: ClassVar[str] = "ABSTRACT"
    data_source: ClassVar[str] = "unknown"
    synthetic: ClassVar[bool] = False

    def __init__(self, store: Store | None) -> None:
        self._store = store
        self._model = ReadModel(store) if store is not None else None  # one per provider: it registers SQL functions

    def _read(self) -> ReadModel:
        if self._model is None:
            raise OgwaSafetyError(f"the {self.name} Okta provider has no store to read")
        return self._model

    def applications(self, *, limit: int = MAX_LIST, offset: int = 0) -> list[OktaApplication]:
        return self._read().page_of("applications", Page(limit=limit, offset=offset))[0]

    def groups(self, *, limit: int = MAX_LIST, offset: int = 0) -> list[OktaGroup]:
        return self._read().page_of("groups", Page(limit=limit, offset=offset))[0]

    def application(self, application_id: str) -> OktaApplication | None:
        return self._read_store().latest(OktaApplication, application_id)

    def group(self, group_id: str) -> OktaGroup | None:
        return self._read_store().latest(OktaGroup, group_id)

    def assignments_of_application(self, application_id: str) -> list[ApplicationGroupAssignment]:
        return self._read().assignments_of_application(application_id)

    def assignments_of_group(self, okta_group_ref: str) -> list[ApplicationGroupAssignment]:
        return self._read().assignments_of_group(okta_group_ref)

    def _read_store(self) -> Store:
        self._read()
        return self._store  # type: ignore[return-value]


class RealOktaProvider(_StoreInventory):
    """Production: collected evidence in the store, and a read-only collector session on request.

    Nothing is contacted when the provider is built. ``collector_session`` builds the
    GET-only client (``app.integrations.okta``) with an approved credential provider; it
    refuses in LOCAL_SYNTHETIC, where no live Okta host is permitted."""

    name = "RealOktaProvider"
    data_source = "okta-management-api"
    synthetic = False

    def __init__(self, store: Store | None, settings: Settings) -> None:
        super().__init__(store)
        if settings.is_demo:
            raise DemoModeBlocked("the real Okta provider cannot be built in the demo runtime")
        self._settings = settings

    def collector_session(self, *, credentials: Any, **kwargs: Any):
        if self._settings.is_demo:  # pragma: no cover - the constructor already refuses
            raise DemoModeBlocked("no Okta collector runs in the demo runtime")
        if self._settings.mode is ExecutionMode.LOCAL_SYNTHETIC:
            raise OgwaSafetyError("Okta collection does not run in LOCAL_SYNTHETIC mode")
        from app.integrations.okta.client import OktaReadOnlyClient  # imported only for a production session

        return OktaReadOnlyClient.from_settings(self._settings, credentials=credentials, **kwargs)


class SyntheticOktaProvider(_StoreInventory):
    """Demo: the seeded synthetic dataset, read through the same read model as production."""

    name = "SyntheticOktaProvider"
    data_source = "synthetic"
    synthetic = True

    def __init__(self, store: Store, dataset: DemoDataset) -> None:
        if store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
            raise DemoModeBlocked("the synthetic Okta provider reads a SYNTHETIC store only")
        super().__init__(store)
        self.dataset = dataset

    def collector_session(self, **_: Any):
        raise DemoModeBlocked("the demo runtime has no Okta tenant: its Okta evidence is the synthetic dataset "
                              f"{self.dataset.key}, loaded by that dataset's seed")


# --- AAP ---------------------------------------------------------------------------------


class RealAapProvider:
    name = "RealAapProvider"

    def __init__(self, settings: Settings) -> None:
        if settings.is_demo:
            raise DemoModeBlocked("the real AAP provider cannot be built in the demo runtime")
        self._settings = settings

    def discovery_client(self, **kwargs: Any):
        from app.integrations.aap.client import AapReadOnlyClient  # imported only for a production session

        return AapReadOnlyClient.from_settings(self._settings, **kwargs)


class DisabledAapProvider:
    name = "DisabledAapProvider"

    def discovery_client(self, **_: Any):
        raise DemoModeBlocked("the demo runtime has no AAP controller; AAP discovery and job launches are disabled")


# --- selection ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntegrationProviders:
    runtime_mode: RuntimeMode
    okta: _StoreInventory
    aap: RealAapProvider | DisabledAapProvider
    # Mapping review's AD lookups (``app.api.services.MappingReviewGateway``), or None.
    ad_directory: Any = None
    remediation_allowlist: RemediationAllowlist | None = None
    remediation_templates: Mapping[int, Any] = field(default_factory=dict)

    @property
    def data_source(self) -> str:
        return self.okta.data_source


def select_providers(settings: Settings, *, store: Store | None, dataset: DemoDataset | None = None,
                     clock: Callable[[], datetime] | None = None,
                     demo_allowlist_path=None) -> IntegrationProviders:
    """The providers for ``settings.runtime_mode``. The only place that choice is made."""
    if settings.runtime_mode is RuntimeMode.DEMO:
        return _demo_providers(settings, store=store, dataset=dataset, clock=clock, allowlist_path=demo_allowlist_path)
    return IntegrationProviders(RuntimeMode.PRODUCTION, okta=RealOktaProvider(store, settings),
                                aap=RealAapProvider(settings))


def _demo_providers(settings: Settings, *, store: Store | None, dataset: DemoDataset | None,
                    clock: Callable[[], datetime] | None, allowlist_path) -> IntegrationProviders:
    from app.api.local import SYNTHETIC_REMEDIATION_ALLOWLIST_PATH
    from app.demo.synthetic_directory import SyntheticMappingGateway

    if settings.mode is not ExecutionMode.LOCAL_SYNTHETIC:  # pragma: no cover - load_settings refuses this
        raise DemoModeBlocked("the demo runtime runs only in LOCAL_SYNTHETIC mode")
    if store is None or dataset is None or clock is None:
        raise ConfigError("the demo providers need the opened demo store, its dataset, and a clock")
    if store.mode is not ExecutionMode.LOCAL_SYNTHETIC or store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
        raise DemoModeBlocked("the demo runtime serves only a SYNTHETIC store opened in LOCAL_SYNTHETIC mode")
    allowlist = load_allowlist(allowlist_path or SYNTHETIC_REMEDIATION_ALLOWLIST_PATH,
                               environment=DatabaseEnvironment.SYNTHETIC)
    live = sorted(e.operation.value for e in allowlist.entries if e.adapter is not AdapterKind.SYNTHETIC)
    if live:
        raise DemoModeBlocked(f"the demo remediation allowlist may name only the SYNTHETIC adapter; {', '.join(live)} "
                              "name another")
    return IntegrationProviders(
        RuntimeMode.DEMO, okta=SyntheticOktaProvider(store, dataset), aap=DisabledAapProvider(),
        ad_directory=SyntheticMappingGateway(store, clock=clock), remediation_allowlist=allowlist,
        remediation_templates={})
