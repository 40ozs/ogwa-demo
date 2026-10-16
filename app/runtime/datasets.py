"""Demo datasets: Demo Mode's thin adapter over the synthetic dataset registry.

Demo Mode generates no data and keeps no dataset registry of its own. The one registry is
``app.demo.datasets``, owned by the synthetic-data implementation: for each dataset it names
the seed namespace, lifecycle policy, correlation configuration, and seed function. This
module only:

- resolves the operator's ``OGWA_DEMO_DATASET`` selector through ``app.demo.datasets.dataset``;
- reads the dataset's canonical metadata from the implementation itself (for Null Meridian,
  ``app.demo.null_meridian.profile``), never from a copy here;
- hands Demo Mode the implementation's own seed function.

| Selector (``OGWA_DEMO_DATASET``) | Seed namespace (audit identity) | Seed function |
| --- | --- | --- |
| ``null-meridian`` (default) | ``null-meridian-v1`` | ``app.demo.null_meridian.world.create_null_meridian_store`` |
| ``classic`` | ``ogwa-synthetic-demo-v1`` | ``app.demo.synthetic_world.create_seeded_store`` |

The selector chooses a dataset. The seed namespace is what the seed records in the store's
single ``SYNTHETIC_SEED_LOADED`` audit event, and what ``app.runtime.demo_store`` checks; it
is never renamed. A selector that is unknown, or whose implementation is missing from this
build, is *unavailable*: selecting it fails closed with the reason, and nothing falls back
to another dataset.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

from app.core.database_url import DatabaseTarget
from app.core.errors import ConfigError
from app.demo import datasets as registry

NULL_MERIDIAN_KEY = "null-meridian"
NULL_MERIDIAN_MODULE = "app.demo.null_meridian"
CLASSIC_KEY = "classic"
CLASSIC_MODULE = "app.demo.synthetic_world"


class DatasetUnavailable(ConfigError):
    """The selected demo dataset cannot be used by this build."""


@dataclass(frozen=True)
class DatasetMetadata:
    """Non-sensitive facts about a synthetic organization, as its implementation states them.

    ``key`` is the operator-facing selector; ``seed`` is the canonical seed namespace."""

    key: str
    company_name: str
    primary_domain: str
    snapshot_date: date
    seed: str
    synthetic: bool = True

    def to_json(self) -> dict[str, Any]:
        return {"key": self.key, "companyName": self.company_name, "primaryDomain": self.primary_domain,
                "snapshotDate": self.snapshot_date.isoformat(), "seed": self.seed, "synthetic": self.synthetic}


# (target, *, clock=None) -> (Store, SeedSummary with .namespace and .audit_head)
SeedFunction = Callable[..., tuple[Any, Any]]


@dataclass(frozen=True)
class DemoDataset:
    metadata: DatasetMetadata
    module: str
    seed_store: SeedFunction
    entry: registry.DemoDataset  # the registry's own record of this dataset

    @property
    def key(self) -> str:
        return self.metadata.key

    @property
    def seed_namespace(self) -> str:
        """The namespace the implementation records in its SYNTHETIC_SEED_LOADED audit event."""
        return self.metadata.seed

    def create_seeded_store(self, target: DatabaseTarget, *, clock=None) -> tuple[Any, Any]:
        return self.seed_store(target, clock=clock)


# --- bindings to the synthetic implementations -------------------------------------------


def _null_meridian(entry: registry.DemoDataset) -> DemoDataset:
    from app.demo.null_meridian import profile, world

    if entry.create is not world.create_null_meridian_store:
        raise DatasetUnavailable(f"the dataset registry does not bind {NULL_MERIDIAN_KEY} to "
                                 "app.demo.null_meridian.world.create_null_meridian_store")
    metadata = DatasetMetadata(key=profile.DATASET_KEY, company_name=profile.COMPANY,
                               primary_domain=profile.PRIMARY_DOMAIN, snapshot_date=profile.SNAPSHOT_DATE,
                               seed=profile.SEED)
    return DemoDataset(metadata, NULL_MERIDIAN_MODULE, world.create_null_meridian_store, entry)


def _classic(entry: registry.DemoDataset) -> DemoDataset:
    from app.demo import synthetic_world as world

    if entry.create is not world.create_seeded_store:
        raise DatasetUnavailable(f"the dataset registry does not bind {CLASSIC_KEY} to {CLASSIC_MODULE}")
    metadata = DatasetMetadata(key=entry.key, company_name=world.COMPANY, primary_domain=world.CORP.dns,
                               snapshot_date=world.AS_OF.date(), seed=world.SEED_NAMESPACE)
    return DemoDataset(metadata, CLASSIC_MODULE, world.create_seeded_store, entry)


_ADAPTERS: dict[str, tuple[str, Callable[[registry.DemoDataset], DemoDataset]]] = {
    NULL_MERIDIAN_KEY: (NULL_MERIDIAN_MODULE, _null_meridian),
    CLASSIC_KEY: (CLASSIC_MODULE, _classic),
}


def registered_keys() -> tuple[str, ...]:
    return registry.DATASET_KEYS


def resolve_dataset(key: str) -> DemoDataset:
    """The dataset selected by ``key``, or DatasetUnavailable. Never another dataset instead."""
    if key not in registry.DATASET_KEYS:
        raise DatasetUnavailable(f"unknown demo dataset {key[:64]!r}; choose one of "
                                 f"{', '.join(registry.DATASET_KEYS)}{_namespace_hint(key)}")
    if key not in _ADAPTERS:
        raise DatasetUnavailable(f"demo dataset {key!r} is registered, but Demo Mode has no adapter for its metadata "
                                 "(app.runtime.datasets)")
    module, adapt = _ADAPTERS[key]
    try:
        dataset = adapt(registry.dataset(key))
    except ModuleNotFoundError as exc:
        if exc.name is None or not (exc.name == module or exc.name.startswith(module + ".")
                                    or module.startswith(exc.name + ".")):
            raise  # the implementation exists but one of its own imports is broken: report that, not "missing"
        raise DatasetUnavailable(f"demo dataset {key} is provided by {module}, which is not in this build; "
                                 "Demo Mode does not substitute another dataset (docs/demo-mode.md)") from None
    if dataset.key != key or dataset.seed_namespace != dataset.entry.namespace:
        raise DatasetUnavailable(f"demo dataset {key!r} resolved to {dataset.key!r} with seed namespace "
                                 f"{dataset.seed_namespace!r}; the registry states {dataset.entry.namespace!r}")
    return dataset


def _namespace_hint(key: str) -> str:
    """A seed namespace given where a selector belongs: say which selector names it."""
    for candidate in registry.DATASET_KEYS:
        try:
            if registry.dataset(candidate).namespace == key:
                return f" ({key} is the seed namespace of the dataset selected as {candidate})"
        except Exception:  # noqa: BLE001 - a hint only; resolution itself reports unavailability
            continue
    return ""


def dataset_status() -> dict[str, str]:
    """Each registered dataset and whether this build can use it (for status output)."""
    status = {}
    for key in registry.DATASET_KEYS:
        try:
            dataset = resolve_dataset(key)
            status[key] = f"available (seed {dataset.seed_namespace}, {dataset.metadata.company_name})"
        except DatasetUnavailable as exc:
            status[key] = f"unavailable: {exc}"
    return status
