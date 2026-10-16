"""Applies and verifies schema migrations.

Forward-only: there is no downgrade, because the store holds append-only history that a
downgrade would have to destroy. Each migration runs in its own transaction together
with its bookkeeping row, so a failure leaves the schema at the previous version.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from app.store import codec
from app.store.db import transaction
from app.store.errors import MigrationError
from app.store.migrations import LATEST_VERSION, MIGRATIONS, checksum, statements_for

_BOOKKEEPING = (
    "CREATE TABLE IF NOT EXISTS schema_migrations (\n"
    "    version INTEGER PRIMARY KEY CHECK (version > 0),\n"
    "    name TEXT NOT NULL,\n"
    "    checksum TEXT NOT NULL CHECK (length(checksum) = 71),\n"
    "    applied_at TEXT NOT NULL CHECK (length(applied_at) = 27)\n"
    ")"
)


@dataclass(frozen=True)
class AppliedMigration:
    version: int
    name: str
    checksum: str
    applied_at: datetime


def applied_migrations(conn: sqlite3.Connection) -> list[AppliedMigration]:
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'").fetchone()
    if not exists:
        return []
    rows = conn.execute("SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version").fetchall()
    return [AppliedMigration(r["version"], r["name"], r["checksum"], codec.parse_ts(r["applied_at"])) for r in rows]


def current_version(conn: sqlite3.Connection) -> int:
    applied = applied_migrations(conn)
    return applied[-1].version if applied else 0


def verify_applied(conn: sqlite3.Connection, dialect: str) -> int:
    """Check every applied migration is known, contiguous, and unchanged. Returns the version."""
    applied = applied_migrations(conn)
    known = {m.VERSION: m for m in MIGRATIONS}
    for expected_version, record in enumerate(applied, start=1):
        if record.version != expected_version:
            raise MigrationError(f"applied migrations have a gap before version {record.version}")
        migration = known.get(record.version)
        if migration is None:
            raise MigrationError(
                f"database is at schema version {record.version}, newer than this build ({LATEST_VERSION}); "
                "refusing to use it"
            )
        if record.name != migration.NAME or record.checksum != checksum(migration, dialect):
            raise MigrationError(f"migration {record.version} ({record.name}) was changed after it was applied")
    return applied[-1].version if applied else 0


def upgrade(conn: sqlite3.Connection, dialect: str, *, clock: Callable[[], datetime], target: int | None = None) -> list[int]:
    """Apply pending migrations up to ``target`` (default: latest). Returns the versions applied."""
    target = LATEST_VERSION if target is None else target
    if not 0 <= target <= LATEST_VERSION:
        raise MigrationError(f"target version must be between 0 and {LATEST_VERSION}")
    conn.execute(_BOOKKEEPING)
    current = verify_applied(conn, dialect)
    if target < current:
        raise MigrationError("downgrades are not supported; the store keeps append-only history")
    done = []
    for migration in MIGRATIONS[current:target]:
        statements = statements_for(migration, dialect)
        with transaction(conn):
            for statement in statements:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                (migration.VERSION, migration.NAME, checksum(migration, dialect), codec.ts(clock())),
            )
        done.append(migration.VERSION)
    return done
