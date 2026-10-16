"""The provider boundary: the one place the demo's integration providers are chosen.

OGWA's shared logic (inventory read model, correlation engine, candidate classification,
lifecycle, governance, API, UI) reads only from the store. The providers that stand where
live systems would are chosen here, once, and every one of them is synthetic:

| Role | Provider |
| --- | --- |
| Okta | ``SyntheticOktaProvider``: store reads of the seeded synthetic dataset |
| AD directory (mapping review) | ``SyntheticMappingGateway`` over the store's synthetic AD evidence |
| Remediation | the synthetic allowlist, SYNTHETIC adapter only: SIMULATED answers |

This build includes no Okta, AD, or AAP client and no outbound HTTP client, so there is no
live provider to select. Business logic never checks the runtime itself; it receives what
this module selected.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from app.api.readmodel import ReadModel
from app.api.validation import Page
from app.core.errors import ConfigError, OgwaSafetyError
from app.core.modes import ExecutionMode
from app.domain.model import ApplicationGroupAssignment, OktaApplication, OktaGroup
from app.remediation.allowlist import AdapterKind, RemediationAllowlist, load_allowlist
from app.runtime.datasets import DemoDataset
from app.store.environment import DatabaseEnvironment
from app.store.store import Store

MAX_LIST = 1000


class DemoModeBlocked(OgwaSafetyError):
    """A provider configuration that would reach beyond the synthetic demo was refused."""


class SyntheticOktaProvider:
    """Okta inventory as the seeded synthetic dataset records it, read through the shared read model."""

    name: ClassVar[str] = "SyntheticOktaProvider"
    data_source: ClassVar[str] = "synthetic"
    synthetic: ClassVar[bool] = True

    def __init__(self, store: Store, dataset: DemoDataset) -> None:
        if store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
            raise DemoModeBlocked("the synthetic Okta provider reads a SYNTHETIC store only")
        self._store = store
        self._model = ReadModel(store)  # one per provider: it registers SQL functions
        self.dataset = dataset

    def applications(self, *, limit: int = MAX_LIST, offset: int = 0) -> list[OktaApplication]:
        return self._model.page_of("applications", Page(limit=limit, offset=offset))[0]

    def groups(self, *, limit: int = MAX_LIST, offset: int = 0) -> list[OktaGroup]:
        return self._model.page_of("groups", Page(limit=limit, offset=offset))[0]

    def application(self, application_id: str) -> OktaApplication | None:
        return self._store.latest(OktaApplication, application_id)

    def group(self, group_id: str) -> OktaGroup | None:
        return self._store.latest(OktaGroup, group_id)

    def assignments_of_application(self, application_id: str) -> list[ApplicationGroupAssignment]:
        return self._model.assignments_of_application(application_id)

    def assignments_of_group(self, okta_group_ref: str) -> list[ApplicationGroupAssignment]:
        return self._model.assignments_of_group(okta_group_ref)


@dataclass(frozen=True)
class IntegrationProviders:
    okta: SyntheticOktaProvider
    # Mapping review's AD lookups (``app.api.services.MappingReviewGateway``).
    ad_directory: Any
    remediation_allowlist: RemediationAllowlist

    @property
    def data_source(self) -> str:
        return self.okta.data_source


def select_providers(*, store: Store | None, dataset: DemoDataset | None, clock: Callable[[], datetime] | None,
                     demo_allowlist_path=None) -> IntegrationProviders:
    """The demo's providers over the opened demo store. The only place they are chosen."""
    from app.api.local import SYNTHETIC_REMEDIATION_ALLOWLIST_PATH
    from app.demo.synthetic_directory import SyntheticMappingGateway

    if store is None or dataset is None or clock is None:
        raise ConfigError("the demo providers need the opened demo store, its dataset, and a clock")
    if store.mode is not ExecutionMode.LOCAL_SYNTHETIC or store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
        raise DemoModeBlocked("the demo serves only a SYNTHETIC store opened in LOCAL_SYNTHETIC mode")
    allowlist = load_allowlist(demo_allowlist_path or SYNTHETIC_REMEDIATION_ALLOWLIST_PATH,
                               environment=DatabaseEnvironment.SYNTHETIC)
    live = sorted(e.operation.value for e in allowlist.entries if e.adapter is not AdapterKind.SYNTHETIC)
    if live:
        raise DemoModeBlocked(f"the demo remediation allowlist may name only the SYNTHETIC adapter; {', '.join(live)} "
                              "name another")
    return IntegrationProviders(okta=SyntheticOktaProvider(store, dataset),
                                ad_directory=SyntheticMappingGateway(store, clock=clock), remediation_allowlist=allowlist)
