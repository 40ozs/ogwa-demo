"""The database environment marker and what it permits.

Every store is marked once, at initialization, as SYNTHETIC, DEVELOPMENT, or PRODUCTION.
The marker cannot be changed afterwards (the row is append-only). It decides which
execution modes may open the store and which evidence sources may be written to it, so
synthetic demo data and real discovery data are never mixed, and the reset command can
recognise a database it is allowed to destroy.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.evidence import EvidenceSource
from app.store import codec
from app.store.errors import EnvironmentRefused, StoreIntegrityError


class DatabaseEnvironment(StrEnum):
    SYNTHETIC = "SYNTHETIC"  # demo and test data only; may be reset
    DEVELOPMENT = "DEVELOPMENT"  # a developer's scratch store; may be reset if it holds no real evidence
    PRODUCTION = "PRODUCTION"  # real discovery data; never reset by OGWA


RESETTABLE_ENVIRONMENTS = frozenset({DatabaseEnvironment.SYNTHETIC, DatabaseEnvironment.DEVELOPMENT})

MODES_PERMITTED: dict[DatabaseEnvironment, frozenset[ExecutionMode]] = {
    DatabaseEnvironment.SYNTHETIC: frozenset({ExecutionMode.LOCAL_SYNTHETIC}),
    DatabaseEnvironment.DEVELOPMENT: frozenset(
        {ExecutionMode.LOCAL_SYNTHETIC, ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION}
    ),
    DatabaseEnvironment.PRODUCTION: frozenset({ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION}),
}


@dataclass(frozen=True)
class StoreMarker:
    environment: DatabaseEnvironment
    store_instance_id: str
    created_at: datetime
    created_by: Actor


def read_marker(conn: sqlite3.Connection) -> StoreMarker | None:
    """The marker, or None when the database has no OGWA metadata (not an OGWA store)."""
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'store_metadata'").fetchone()
    if not exists:
        return None
    rows = conn.execute(
        "SELECT environment, store_instance_id, created_at, created_by_kind, created_by_id FROM store_metadata"
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise StoreIntegrityError("store_metadata must hold exactly one row")
    row = rows[0]
    try:
        environment = DatabaseEnvironment(row["environment"])
        created_by = Actor(ActorKind(row["created_by_kind"]), row["created_by_id"])
    except ValueError:
        raise StoreIntegrityError("store_metadata holds an unknown environment or actor") from None
    return StoreMarker(environment, row["store_instance_id"], codec.parse_ts(row["created_at"]), created_by)


def write_marker(conn: sqlite3.Connection, marker: StoreMarker) -> None:
    conn.execute(
        "INSERT INTO store_metadata (singleton, environment, store_instance_id, created_at, created_by_kind, created_by_id) "
        "VALUES (1, ?, ?, ?, ?, ?)",
        (
            marker.environment.value,
            marker.store_instance_id,
            codec.ts(marker.created_at),
            marker.created_by.kind.value,
            marker.created_by.id,
        ),
    )


def check_mode_permitted(environment: DatabaseEnvironment, mode: ExecutionMode) -> None:
    if mode not in MODES_PERMITTED[environment]:
        allowed = ", ".join(sorted(m.value for m in MODES_PERMITTED[environment]))
        raise EnvironmentRefused(
            f"a {environment.value} store cannot be used in {mode.value} mode (allowed: {allowed})"
        )


def check_source_permitted(environment: DatabaseEnvironment, mode: ExecutionMode, source: EvidenceSource) -> None:
    """Synthetic evidence only in synthetic contexts, real evidence never in them."""
    if source is EvidenceSource.SYNTHETIC:
        if environment is DatabaseEnvironment.PRODUCTION:
            raise EnvironmentRefused("synthetic evidence cannot be written to a PRODUCTION store")
    else:
        if environment is DatabaseEnvironment.SYNTHETIC:
            raise EnvironmentRefused(f"{source.value} evidence cannot be written to a SYNTHETIC store")
        if mode is ExecutionMode.LOCAL_SYNTHETIC:
            raise EnvironmentRefused(f"{source.value} evidence cannot be recorded in LOCAL_SYNTHETIC mode")
