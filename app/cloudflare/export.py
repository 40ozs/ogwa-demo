"""A demo store as SQL for D1, in import phases that respect D1 Free's daily write quota.

The export reproduces the store exactly: every schema object with the SQL SQLite recorded
when the canonical migrations created it (so D1 holds the same schema, not a re-derived
one), and every row, in the original's storage order. Nothing is added, renamed, or dropped.

D1 counts "rows written" per row plus one per index entry, including the index entries a
``CREATE INDEX`` writes for existing rows, and D1 Free allows 100,000 a day
(docs/deployment/cloudflare-demo.md). The Null Meridian demo store needs about 174,000, so
the import is planned in phases, each under ``budget``, to be run on different UTC days:

1. tables, then rows (parents before children), then indexes, then triggers, in that
   order, so no trigger fires during the import and the stored rows are taken as they are;
2. rows are packed in chunks, and an index whose entries do not fit today's remaining budget
   starts the next phase.

Every statement is a single INSERT, CREATE, or PRAGMA, well under D1's 100 KB statement limit.
"""

import sqlite3
from dataclasses import dataclass

D1_FREE_ROWS_WRITTEN_PER_DAY = 100_000
DEFAULT_BUDGET = 95_000  # leaves room for the checks run against D1 on the same day
D1_MAX_STATEMENT_BYTES = 100_000
ROWS_PER_CHUNK = 5_000
_PREAMBLE = "PRAGMA defer_foreign_keys = true"


class ExportError(Exception):
    """The store cannot be exported within D1's limits."""


@dataclass(frozen=True)
class Phase:
    number: int
    statements: tuple[str, ...]
    rows_written: int  # D1's count, estimated: rows, plus index entries, plus schema rows

    def sql(self) -> str:
        return "".join(f"{s};\n" for s in self.statements)


@dataclass(frozen=True)
class _Item:
    cost: int
    statements: tuple[str, ...]


def literal(value: object) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):  # pragma: no cover - SQLite never returns bool
        raise ExportError("a stored value is a bool")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ExportError("a stored REAL is not finite")
        return repr(value)
    if isinstance(value, bytes):
        return "X'" + value.hex() + "'"
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    raise ExportError(f"unexpected stored value of type {type(value).__name__}")


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _schema(conn: sqlite3.Connection, kind: str) -> list[tuple[str, str, str]]:
    return [(r[0], r[1], r[2]) for r in conn.execute(
        "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = ? AND sql IS NOT NULL "
        "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY rowid", (kind,))]


def _parents_first(conn: sqlite3.Connection, tables: list[str]) -> list[str]:
    """Tables ordered so every table comes after the tables its foreign keys reference."""
    known = set(tables)
    parents = {t: {r[2] for r in conn.execute(f"PRAGMA foreign_key_list({_quote(t)})")} & known - {t} for t in tables}
    ordered: list[str] = []
    while len(ordered) < len(tables):
        ready = [t for t in tables if t not in ordered and parents[t] <= set(ordered)]
        if not ready:
            raise ExportError("the store's foreign keys form a cycle")
        ordered.append(ready[0])
    return ordered


def _items(conn: sqlite3.Connection) -> list[_Item]:
    tables = _schema(conn, "table")
    names = [name for name, _, _ in tables]
    items = [_Item(1, (sql,)) for _, _, sql in tables]
    for table in _parents_first(conn, names):
        auto = sum(1 for r in conn.execute(f"PRAGMA index_list({_quote(table)})") if r[3] != "c")
        columns = [r[1] for r in conn.execute(f"PRAGMA table_info({_quote(table)})")]
        insert = f"INSERT INTO {_quote(table)} ({', '.join(_quote(c) for c in columns)}) VALUES "
        # In rowid order, so the copy's rows are stored in the original's order.
        rows = conn.execute(f"SELECT {', '.join(_quote(c) for c in columns)} FROM {_quote(table)} "
                            "ORDER BY rowid").fetchall()
        for start in range(0, len(rows), ROWS_PER_CHUNK):
            chunk = rows[start:start + ROWS_PER_CHUNK]
            statements = tuple(insert + "(" + ", ".join(literal(v) for v in row) + ")" for row in chunk)
            items.append(_Item(len(chunk) * (1 + auto), statements))
    counts = {name: conn.execute(f"SELECT count(*) FROM {_quote(name)}").fetchone()[0] for name in names}
    items += [_Item(counts[table] + 1, (sql,)) for _, table, sql in _schema(conn, "index")]
    items += [_Item(1, (sql,)) for kind in ("trigger", "view") for _, _, sql in _schema(conn, kind)]
    return items


def plan_phases(conn: sqlite3.Connection, *, budget: int = DEFAULT_BUDGET) -> list[Phase]:
    """The store as D1 import phases, in order. Deterministic for a given store."""
    if not 0 < budget <= D1_FREE_ROWS_WRITTEN_PER_DAY:
        raise ExportError(f"the phase budget must be 1-{D1_FREE_ROWS_WRITTEN_PER_DAY} rows written")
    phases: list[Phase] = []
    statements: list[str] = []
    cost = 0
    for item in _items(conn):
        if item.cost > budget:
            raise ExportError(f"one step writes {item.cost} rows, more than the phase budget {budget}")
        if cost + item.cost > budget:
            phases.append(Phase(len(phases) + 1, (_PREAMBLE, *statements), cost))
            statements, cost = [], 0
        statements += item.statements
        cost += item.cost
    if statements:
        phases.append(Phase(len(phases) + 1, (_PREAMBLE, *statements), cost))
    for phase in phases:
        longest = max(len(s.encode("utf-8")) for s in phase.statements)
        if longest > D1_MAX_STATEMENT_BYTES:
            raise ExportError(f"phase {phase.number} has a {longest}-byte statement; D1 accepts {D1_MAX_STATEMENT_BYTES}")
    return phases
