"""The synthetic demo datasets a local store can be seeded with, and which one a store holds.

- ``null-meridian`` (the default demo): the fictional 1,800-person company Null Meridian
  (``app.demo.null_meridian``), with its directory snapshot, application estate, and
  portfolio scenarios.
- ``classic``: the sixteen-scenario lifecycle harness (``app.demo.synthetic_world``), which
  covers every lifecycle condition and backs most of the test suite.

The dataset is chosen when the store is (re)seeded, by deployment configuration or the
operator's ``reset-demo --dataset`` flag. Nothing at runtime switches it, and no browser or
API route can: a running server only reads which dataset its store holds.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.domain.policy import LifecyclePolicy

REPO_ROOT = Path(__file__).resolve().parents[2]


def _no_releases() -> tuple:
    return ()


def _no_walkthrough(public: bool = False) -> None:
    return None


@dataclass(frozen=True)
class DemoDataset:
    key: str
    title: str
    namespace: str
    as_of: datetime
    policy: LifecyclePolicy
    correlation_path: Path
    create: Callable  # (target, *, clock=None) -> (Store, SeedSummary)
    # The dataset's named synthetic policy releases, oldest first: () when it has none.
    releases: Callable[[], tuple] = _no_releases
    # The dataset's guided reviewer walkthrough: None when it has none. public=True words it for the public demo.
    walkthrough: Callable[..., dict | None] = _no_walkthrough


def _classic() -> DemoDataset:
    from app.demo import synthetic_world as w

    return DemoDataset("classic", "Synthetic Widgets Ltd (16 lifecycle scenarios)", w.SEED_NAMESPACE, w.AS_OF, w.POLICY,
                       REPO_ROOT / "config" / "correlation.synthetic.json", w.create_seeded_store)


def _null_meridian() -> DemoDataset:
    from app.demo.null_meridian import policy, profile, walkthrough, world

    return DemoDataset(profile.DATASET_KEY, "Null Meridian (1,800 employees, 10 years of identity history)",
                       profile.SEED, profile.AS_OF, world.POLICY, REPO_ROOT / "config" / "correlation.null-meridian.json",
                       world.create_null_meridian_store, policy.releases, walkthrough.walkthrough)


DATASET_KEYS = ("null-meridian", "classic")
DEFAULT_DATASET = "null-meridian"


def dataset(key: str) -> DemoDataset:
    if key == "classic":
        return _classic()
    if key == "null-meridian":
        return _null_meridian()
    raise ValueError(f"unknown demo dataset {key!r}; choose one of {', '.join(DATASET_KEYS)}")


def dataset_of(store) -> DemoDataset:
    """The dataset a SYNTHETIC store was seeded with: Null Meridian when it holds that directory
    snapshot, the classic world otherwise."""
    info = store.synthetic_directory()
    return dataset(info.dataset) if info is not None else _classic()
