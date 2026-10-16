"""Connections and transactions.

Connections run in autocommit mode and every write goes through ``transaction``, which
issues ``BEGIN IMMEDIATE`` so concurrent writers serialize instead of racing on audit
sequence numbers. Foreign keys are switched on and verified for every connection.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from app.core.database_url import DatabaseTarget
from app.store.errors import StoreError

DIALECT_SQLITE = "sqlite"


def connect(target: DatabaseTarget, *, create: bool = False, read_only: bool = False) -> sqlite3.Connection:
    """Open the database. Without ``create``, a missing file is an error, never a new empty store."""
    if target.backend != DIALECT_SQLITE:
        raise StoreError(f"unsupported database backend {target.backend!r}")
    if target.path is None:
        if read_only:
            raise StoreError("an in-memory database cannot be opened read-only")
        conn = sqlite3.connect(":memory:", isolation_level=None)
    else:
        if not create and not target.path.is_file():
            raise StoreError(f"no database at {target.path}; initialize it first")
        if create:
            target.path.parent.mkdir(parents=True, exist_ok=True)
        mode = "ro" if read_only else ("rwc" if create else "rw")
        conn = sqlite3.connect(f"{target.path.as_uri()}?mode={mode}", uri=True, isolation_level=None)
    return _configure(conn)


def connect_image(image: bytes) -> sqlite3.Connection:
    """Open an in-memory copy of a store file's bytes, read-only.

    For a host without a persistent filesystem (the Cloudflare Worker, docs/deployment/
    cloudflare-demo.md). ``query_only`` makes SQLite refuse every write, so the copy can
    never drift from the store it was taken from."""
    conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    try:
        conn.deserialize(image)
        conn.execute("PRAGMA query_only = ON")
    except BaseException:
        conn.close()
        raise
    return _configure(conn)


def _configure(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        conn.close()
        raise StoreError("SQLite foreign key enforcement could not be enabled")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    if conn.in_transaction:
        raise StoreError("nested transactions are not supported")
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        # A failed COMMIT (SQLITE_BUSY, a deferred constraint) leaves the transaction open;
        # some errors end it already, so roll back only what is still open.
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
