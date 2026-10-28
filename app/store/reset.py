"""Guarded reset of a local synthetic store.

The reset deletes a database file and recreates it with the synthetic demo world. It
refuses unless every one of these holds:

1. the execution mode is LOCAL_SYNTHETIC;
2. the target is a local SQLite file (not in-memory, not a network database);
3. the file lies inside the allowed root (``<project>/var`` for the CLI);
4. if the file exists, it is an OGWA store marked SYNTHETIC or DEVELOPMENT;
5. the existing store holds no evidence or collector run from a non-synthetic source;
6. the caller explicitly confirmed the reset.

Checks 4 and 5 open the existing file read-only. A file that cannot be read as an OGWA
store is never deleted.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from app.core.database_url import PROJECT_ROOT, DatabaseTarget
from app.core.modes import ExecutionMode
from app.demo.datasets import dataset as demo_dataset
from app.demo.synthetic_world import SeedSummary
from app.store.db import connect
from app.store.environment import RESETTABLE_ENVIRONMENTS, read_marker
from app.store.errors import StoreError
from app.store.evidence_tables import SPECS

DEFAULT_ALLOWED_ROOT = PROJECT_ROOT / "var"
_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


class ResetRefused(StoreError):
    """The reset guard refused to touch the database."""


@dataclass(frozen=True)
class ResetResult:
    path: Path
    replaced_existing: bool
    summary: SeedSummary
    dataset: str = "classic"


def check_reset_allowed(target: DatabaseTarget, *, mode: ExecutionMode, allowed_root: Path, confirmed: bool) -> bool:
    """Raise ResetRefused unless a reset is allowed. Returns whether a database file exists."""
    if mode is not ExecutionMode.LOCAL_SYNTHETIC:
        raise ResetRefused(f"reset runs only in LOCAL_SYNTHETIC mode, not {mode.value}")
    if target.backend != "sqlite" or target.path is None:
        raise ResetRefused("reset applies only to a local SQLite database file")
    path, root = target.path.resolve(), allowed_root.resolve()
    if not path.is_relative_to(root) or path == root:
        raise ResetRefused(f"reset refuses {path}: it is outside the allowed root {root}")
    if not confirmed:
        raise ResetRefused("reset needs explicit confirmation")
    if not path.exists():
        return False
    if not path.is_file():
        raise ResetRefused(f"{path} is not a file")
    try:
        conn = connect(target, read_only=True)
    except (StoreError, sqlite3.Error) as exc:
        raise ResetRefused(f"{path} could not be opened as an OGWA store ({exc}); not deleting it") from None
    try:
        try:
            marker = read_marker(conn)
        except (StoreError, sqlite3.Error) as exc:
            raise ResetRefused(f"{path} is not a readable OGWA store ({exc}); not deleting it") from None
        if marker is None:
            raise ResetRefused(f"{path} has no OGWA environment marker; not deleting it")
        if marker.environment not in RESETTABLE_ENVIRONMENTS:
            raise ResetRefused(f"{path} is marked {marker.environment.value}; only SYNTHETIC or DEVELOPMENT stores can be reset")
        real = _non_synthetic_rows(conn)
        if real:
            raise ResetRefused(f"{path} holds {real} non-synthetic evidence or collector records; not deleting it")
    finally:
        conn.close()
    return True


def _non_synthetic_rows(conn: sqlite3.Connection) -> int:
    tables = ["collector_runs", *(spec.observation_table for spec in SPECS)]
    return sum(conn.execute(f"SELECT count(*) FROM {t} WHERE source <> 'SYNTHETIC'").fetchone()[0] for t in tables)


def reset_synthetic_store(target: DatabaseTarget, *, mode: ExecutionMode, confirmed: bool,
                          allowed_root: Path = DEFAULT_ALLOWED_ROOT, clock=None, dataset: str = "classic") -> ResetResult:
    """``dataset``: ``classic`` (the 16-scenario lifecycle harness), ``genesee-press`` or ``null-meridian``."""
    create = demo_dataset(dataset).create  # an unknown dataset is refused before anything is touched
    existed = check_reset_allowed(target, mode=mode, allowed_root=allowed_root, confirmed=confirmed)
    path = target.path.resolve()
    if existed:
        path.unlink()
    for suffix in _SIDECAR_SUFFIXES:
        sidecar = path.with_name(path.name + suffix)
        if sidecar.is_file():
            sidecar.unlink()
    store, summary = create(target, clock=clock)
    store.close()
    return ResetResult(path, existed, summary, dataset)
