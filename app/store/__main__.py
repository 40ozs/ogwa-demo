"""``python -m app.store``: inspect the demo store.

    status                          schema version, environment marker, counts, audit head
    verify [--expected-audit-head]  re-verify migrations, audit chain, evidence digests, histories

The database comes from OGWA_DATABASE_URL (default: the demo store, var/ogwa-demo.sqlite3).
The demo store is created and reset by ``python -m app.runtime reset-demo``. Nothing here
contacts a network service. Exit codes: 0 success, 1 verification failure, 2 refused.
"""

import argparse
import sqlite3
import sys

from app.core.config import load_settings
from app.core.errors import OgwaSafetyError
from app.store.db import connect
from app.store.environment import read_marker
from app.store.errors import StoreIntegrityError
from app.store.migrations import LATEST_VERSION
from app.store.migrator import current_version
from app.store.store import Store


def _status(settings) -> int:
    target = settings.database
    if target.path is not None and not target.path.exists():
        print(f"No database at {target.location}.")
        return 0
    conn = connect(target, read_only=True)
    try:
        marker = read_marker(conn)
        print(f"schema_version: {current_version(conn)} (build expects {LATEST_VERSION})")
        print(f"environment:    {marker.environment.value if marker else '<unmarked>'}")
        if marker is None:
            return 0
        head = conn.execute("SELECT sequence, digest FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
        print(f"audit_events:   {head['sequence'] + 1 if head else 0}")
        print(f"audit_head:     {head['digest'] if head else '-'}")
        snapshot = conn.execute("SELECT dataset, seed, record_count FROM synthetic_directory_snapshots").fetchone()
        print(f"demo_dataset:   {snapshot['dataset'] + ' (seed ' + snapshot['seed'] + ', ' + str(snapshot['record_count'])
                                  + ' directory records)' if snapshot else 'classic (no directory snapshot)'}")
        for row in conn.execute("SELECT state, count(*) AS n FROM candidates GROUP BY state ORDER BY state"):
            print(f"candidates[{row['state']}]: {row['n']}")
    finally:
        conn.close()
    return 0


def _verify(settings, expected_head: str | None) -> int:
    with Store.open(settings.database, mode=settings.mode) as store:
        try:
            report = store.verify_integrity(expected_audit_head=expected_head)
        except StoreIntegrityError as exc:
            print(f"INTEGRITY FAILURE: {exc}", file=sys.stderr)
            return 1
    print(f"OK: schema {report.schema_version}, {report.environment.value}, {report.audit_events} audit events, "
          f"{report.observations_checked} observations, {report.candidates_checked} candidates verified"
          + (f", {report.directory_records_checked} synthetic directory records" if report.directory_records_checked else ""))
    print(f"audit_head: {report.audit_head}  (record this value outside the database to anchor the chain)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.store", description="Inspect the demo store.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    verify = commands.add_parser("verify")
    verify.add_argument("--expected-audit-head")
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
        print(f"OGWA store | execution_mode={settings.mode.value} | database={settings.database.location}")
        if args.command == "status":
            return _status(settings)
        return _verify(settings, args.expected_audit_head)
    except StoreIntegrityError as exc:
        print(f"INTEGRITY FAILURE: {exc}", file=sys.stderr)
        return 1
    except (OgwaSafetyError, sqlite3.Error) as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
