"""Durable lifecycle, evidence, and audit store.

Standard-library ``sqlite3`` with hand-written DDL kept to the SQL subset SQLite and
PostgreSQL share, plus a versioned, checksummed migration runner. SQLAlchemy and Alembic
were the preferred stack, but no approved package source is configured (decision D5),
so the owner chose this approach. See docs/architecture/persistence.md.

Nothing in this package contacts a network service. Evidence records are append-only,
lifecycle state changes only through ``app.domain.lifecycle.apply_transition``, and every
write appends to a hash-chained audit log.
"""
