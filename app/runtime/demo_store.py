"""Demo persistence: open, validate, and reset the demo store.

The demo store is its own SQLite file (``var/ogwa-demo.sqlite3`` by default), never the
production default store (``app.core.config`` refuses that path in demo). It holds exactly
one synthetic dataset, written by that dataset's own seed through the dataset registry
(``app.demo.datasets``, reached through ``app.runtime.datasets``).

**Opening** (``open_demo_store``) refuses unless:

1. the runtime mode is ``demo`` (positively confirmed, not inferred);
2. the file exists: a missing demo store is a startup failure, never a new empty store;
3. it is an OGWA store marked ``SYNTHETIC`` (read read-only first);
4. the whole store passes ``verify_integrity`` (migrations, audit chain, evidence digests,
   candidate histories, mapping reviews, policy versions, and the synthetic directory
   snapshot's digest, migration 0012);
5. every piece of dataset identity evidence agrees with the configured dataset
   (``validate_demo_store``):

   - exactly one ``SYNTHETIC_SEED_LOADED`` audit event, naming the dataset's seed namespace
     (``null-meridian-v1`` for Null Meridian);
   - the dataset the registry reads from the store (``app.demo.datasets.dataset_of``): a
     Null Meridian store must hold the Null Meridian directory snapshot, and a classic store
     must hold none;
   - when a snapshot is present, its dataset, seed, and company match the configured
     dataset, and the seed event names the same directory dataset and digest.

**Reset** (``reset_demo_store``) is the Demo Mode guard around the one guarded reset,
``app.store.reset.reset_synthetic_store``: it refuses unless the runtime mode is ``demo``
and the store is not the production default, requires an existing file to be marked
``SYNTHETIC`` (a DEVELOPMENT store is refused here, though the developer reset accepts it),
then lets the guarded reset delete the file and run the dataset's own seed, and finally
validates the result as ``open_demo_store`` would, pinning the audit head the seed reported.
A production store (marked ``PRODUCTION``) is never opened for writing or deleted.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.core.database_url import DatabaseTarget, parse_database_url
from app.core.errors import OgwaSafetyError
from app.core.modes import ExecutionMode
from app.demo.datasets import dataset_of
from app.domain.audit import AuditAction
from app.runtime.datasets import DemoDataset
from app.store.db import connect, connect_image
from app.store.environment import DatabaseEnvironment, read_marker
from app.store.errors import StoreError, StoreIntegrityError
from app.store.reset import DEFAULT_ALLOWED_ROOT, ResetRefused, check_reset_allowed, reset_synthetic_store
from app.store.store import IntegrityReport, Store, utc_now


class DemoPersistenceUnavailable(OgwaSafetyError):
    """The demo store is missing, foreign, or does not hold the configured dataset."""


@dataclass(frozen=True)
class DemoStoreReport:
    dataset: str
    seed_namespace: str
    seed_audit_sequence: int
    seed_audit_digest: str
    integrity: IntegrityReport
    directory_dataset: str | None = None  # the 0012 snapshot's dataset, if the store holds one
    directory_records: int = 0


@dataclass(frozen=True)
class DemoResetResult:
    path: Path
    replaced_existing: bool
    dataset: str
    audit_head: str
    report: DemoStoreReport
    summary: Any = None  # the seed's own SeedSummary: namespace, scenarios, audit head


def _require_demo(settings: Settings, action: str) -> None:
    if not settings.is_demo:
        raise ResetRefused(f"{action} runs only with OGWA_RUNTIME_MODE=demo, not {settings.runtime_mode.value}")
    if settings.mode is not ExecutionMode.LOCAL_SYNTHETIC:  # pragma: no cover - load_settings refuses this
        raise ResetRefused(f"{action} runs only in LOCAL_SYNTHETIC mode")
    if settings.database.path is None or settings.database.path == parse_database_url(None).path:
        raise ResetRefused(f"{action} refuses the production default store")


def validate_demo_store(store: Store, dataset: DemoDataset, *,
                        expected_audit_head: str | None = None) -> DemoStoreReport:
    """Check that ``store`` is an intact SYNTHETIC store holding ``dataset``. Raises if not."""
    if store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
        raise DemoPersistenceUnavailable(f"the demo store is marked {store.marker.environment.value}, not SYNTHETIC")
    try:
        integrity = store.verify_integrity(expected_audit_head=expected_audit_head)
    except StoreIntegrityError as exc:
        raise DemoPersistenceUnavailable(f"the demo store failed verification: {exc}") from None
    seeds = [e for e in store.audit_events() if e.action is AuditAction.SYNTHETIC_SEED_LOADED]
    if len(seeds) != 1:
        raise DemoPersistenceUnavailable(f"the demo store holds {len(seeds)} synthetic seeds; exactly one is required")
    seed = dict(seeds[0].details)
    namespace = seed.get("namespace")
    if namespace != dataset.seed_namespace:
        raise DemoPersistenceUnavailable(f"the demo store holds seed namespace {str(namespace)[:64]!r}, not the "
                                         f"configured dataset {dataset.key!r} ({dataset.seed_namespace}); reset it "
                                         "with python -m app.runtime reset-demo")
    try:
        held = dataset_of(store).key
    except ValueError as exc:
        raise DemoPersistenceUnavailable(f"the demo store holds an unregistered synthetic dataset ({exc})") from None
    if held != dataset.key:
        raise DemoPersistenceUnavailable(f"the demo store holds dataset {held!r}, not the configured {dataset.key!r}; "
                                         "reset it with python -m app.runtime reset-demo")
    snapshot = store.synthetic_directory()
    if snapshot is not None:
        problems = [name for name, ok in (
            ("snapshot seed", snapshot.seed == dataset.seed_namespace),
            ("snapshot company", snapshot.company == dataset.metadata.company_name),
            ("seed event dataset", seed.get("directory_dataset") == snapshot.dataset),
            ("seed event digest", seed.get("directory_digest") == snapshot.content_digest),
            # Audit details are stored as text.
            ("seed event record count", str(seed.get("directory_records")) == str(snapshot.record_count)),
        ) if not ok]
        if problems:
            raise DemoPersistenceUnavailable("the demo store's dataset identity evidence disagrees "
                                             f"({', '.join(problems)}) with dataset {dataset.key!r}")
    return DemoStoreReport(dataset.key, dataset.seed_namespace, seeds[0].sequence, seeds[0].digest, integrity,
                           snapshot.dataset if snapshot else None, integrity.directory_records_checked)


def open_demo_store(settings: Settings, dataset: DemoDataset, *, clock: Callable[[], datetime],
                    expected_audit_head: str | None = None) -> tuple[Store, DemoStoreReport]:
    _require_demo(settings, "the demo store")
    path = settings.database.path
    if path is None or not path.is_file():
        raise DemoPersistenceUnavailable(f"no demo store at {path}; create it with "
                                         "OGWA_RUNTIME_MODE=demo python -m app.runtime reset-demo --confirm-synthetic-reset")
    _require_synthetic_marker(settings.database)
    store = Store.open(settings.database, mode=ExecutionMode.LOCAL_SYNTHETIC, clock=clock)
    try:
        return store, validate_demo_store(store, dataset, expected_audit_head=expected_audit_head)
    except BaseException:
        store.close()
        raise


def open_demo_image(settings: Settings, dataset: DemoDataset, load: Callable[[], bytes | bytearray], *,
                    clock: Callable[[], datetime], expected_audit_head: str | None = None) -> tuple[Store, DemoStoreReport]:
    """``open_demo_store`` for the bytes of a demo store file, opened in memory and read-only.

    For a host with no persistent filesystem (docs/deployment/cloudflare-demo.md). The same
    checks apply: the demo runtime, a SYNTHETIC marker, and ``validate_demo_store``. ``load``
    returns the bytes; nothing keeps them once SQLite holds its copy, so a host with little
    memory never holds the store twice while it is validated."""
    _require_demo(settings, "the demo store")
    try:
        conn = connect_image(load())
    except (StoreError, sqlite3.Error) as exc:
        raise DemoPersistenceUnavailable(f"the demo store image could not be opened ({exc})") from None
    try:
        _check_synthetic_marker(conn)
        store = Store._from_connection(conn, mode=ExecutionMode.LOCAL_SYNTHETIC, clock=clock)
        return store, validate_demo_store(store, dataset, expected_audit_head=expected_audit_head)
    except BaseException:
        conn.close()
        raise


def _require_synthetic_marker(target: DatabaseTarget) -> None:
    """Read the marker read-only first, so a non-synthetic file is never opened for writing."""
    try:
        conn = connect(target, read_only=True)
    except (StoreError, sqlite3.Error) as exc:
        raise DemoPersistenceUnavailable(f"the demo store could not be opened ({exc})") from None
    try:
        _check_synthetic_marker(conn)
    finally:
        conn.close()


def _check_synthetic_marker(conn: sqlite3.Connection) -> None:
    try:
        marker = read_marker(conn)
    except (StoreError, sqlite3.Error) as exc:
        raise DemoPersistenceUnavailable(f"the demo store is not a readable OGWA store ({exc})") from None
    if marker is None:
        raise DemoPersistenceUnavailable("the demo store file has no OGWA environment marker")
    if marker.environment is not DatabaseEnvironment.SYNTHETIC:
        raise DemoPersistenceUnavailable(f"the demo store is marked {marker.environment.value}; Demo Mode opens only "
                                         "a SYNTHETIC store")


def reset_demo_store(settings: Settings, dataset: DemoDataset, *, confirmed: bool,
                     allowed_root: Path = DEFAULT_ALLOWED_ROOT, clock=None) -> DemoResetResult:
    """Delete the demo store and re-create it from the dataset's own deterministic seed."""
    _require_demo(settings, "the demo reset")
    target = settings.database
    existed = check_reset_allowed(target, mode=settings.mode, allowed_root=allowed_root, confirmed=confirmed)
    if existed:
        try:
            _require_synthetic_marker(target)
        except DemoPersistenceUnavailable as exc:
            raise ResetRefused(f"the demo reset refuses this file: {exc}") from None
    # The one guarded reset: it re-applies check_reset_allowed, then seeds through the registry.
    result = reset_synthetic_store(target, mode=settings.mode, confirmed=confirmed, allowed_root=allowed_root,
                                   clock=clock, dataset=dataset.key)
    if result.summary.namespace != dataset.seed_namespace:
        raise DemoPersistenceUnavailable(f"the {dataset.key} seed reported namespace {result.summary.namespace!r}, "
                                         f"not {dataset.seed_namespace!r}")
    # Validation only reads; it never draws on the caller's (seed) clock.
    with Store.open(target, mode=ExecutionMode.LOCAL_SYNTHETIC, clock=utc_now) as store:
        report = validate_demo_store(store, dataset, expected_audit_head=result.summary.audit_head)
    return DemoResetResult(result.path, result.replaced_existing, dataset.key, result.summary.audit_head, report,
                           result.summary)
