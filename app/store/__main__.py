"""``python -m app.store``: manage the local OGWA store.

    status                          schema version, environment marker, counts, audit head
    init --environment ENV          create a new, marked store (SYNTHETIC, DEVELOPMENT, PRODUCTION)
    upgrade                         apply pending migrations to an existing store
    verify [--expected-audit-head]  re-verify migrations, audit chain, evidence digests, histories
    reset-demo --confirm-synthetic-reset [--dataset genesee-press|null-meridian|classic]
                                    delete and re-seed a SYNTHETIC/DEVELOPMENT store under var/
                                    (default dataset: genesee-press, the shared world's demo company)

The database comes from OGWA_DATABASE_URL and the mode from OGWA_EXECUTION_MODE. Nothing
here contacts a network service. Exit codes: 0 success, 1 verification failure, 2 refused.

``reset-demo`` here is the developer reset of the standard runtime's local synthetic store.
Under ``OGWA_RUNTIME_MODE=demo`` it refuses: the demo store has one reset command,
``python -m app.runtime reset-demo``, which takes its dataset from ``OGWA_DEMO_DATASET`` and
validates the result. Both run the same guarded reset (``app.store.reset``) and the same
dataset registry (``app.demo.datasets``).
"""

import argparse
import getpass
import sqlite3
import sys

from app.core.config import load_settings
from app.core.errors import OgwaSafetyError
from app.demo.datasets import DATASET_KEYS, DEFAULT_DATASET
from app.domain.actors import Actor, ActorKind
from app.store.db import DIALECT_SQLITE, connect
from app.store.environment import DatabaseEnvironment, check_mode_permitted, read_marker
from app.store.errors import StoreIntegrityError
from app.store.migrations import LATEST_VERSION
from app.store.migrator import current_version, upgrade
from app.store import reset as reset_module
from app.store.store import Store, utc_now


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


def _init(settings, environment: str) -> int:
    actor = Actor(ActorKind.HUMAN, f"local:{getpass.getuser()}")
    store = Store.initialize(settings.database, environment=DatabaseEnvironment(environment), mode=settings.mode, actor=actor)
    store.close()
    print(f"Initialized a {environment} store at {settings.database.location} (schema {LATEST_VERSION}).")
    return 0


def _upgrade(settings) -> int:
    conn = connect(settings.database)
    try:
        marker = read_marker(conn)
        if marker is None:
            print("Refused: not an initialized OGWA store; use init.", file=sys.stderr)
            return 2
        check_mode_permitted(marker.environment, settings.mode)
        applied = upgrade(conn, DIALECT_SQLITE, clock=utc_now)
    finally:
        conn.close()
    print(f"Applied migrations: {applied or 'none (already current)'}")
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


def _reset(settings, confirmed: bool, dataset: str) -> int:
    result = reset_module.reset_synthetic_store(settings.database, mode=settings.mode, confirmed=confirmed,
                                                allowed_root=reset_module.DEFAULT_ALLOWED_ROOT, dataset=dataset)
    print(f"{'Replaced' if result.replaced_existing else 'Created'} synthetic store at {result.path} "
          f"(dataset {result.dataset}, seed {result.summary.namespace})")
    for scenario in result.summary.scenarios:
        state = scenario.final_state.value if scenario.final_state else "-"
        print(f"  {scenario.key}  {state:<22} {scenario.title}")
    print(f"audit_head: {result.summary.audit_head}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.store", description="Manage the local OGWA store.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    init = commands.add_parser("init")
    init.add_argument("--environment", required=True, choices=[e.value for e in DatabaseEnvironment])
    commands.add_parser("upgrade")
    verify = commands.add_parser("verify")
    verify.add_argument("--expected-audit-head")
    reset = commands.add_parser("reset-demo")
    reset.add_argument("--confirm-synthetic-reset", action="store_true")
    reset.add_argument("--dataset", choices=DATASET_KEYS, default=DEFAULT_DATASET)
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
        print(f"OGWA store | execution_mode={settings.mode.value} | database={settings.database.location}")
        if args.command == "status":
            return _status(settings)
        if args.command == "init":
            return _init(settings, args.environment)
        if args.command == "upgrade":
            return _upgrade(settings)
        if args.command == "verify":
            return _verify(settings, args.expected_audit_head)
        if settings.is_demo:
            print("Refused: under OGWA_RUNTIME_MODE=demo the demo store is reset with "
                  "python -m app.runtime reset-demo --confirm-synthetic-reset (dataset from OGWA_DEMO_DATASET).",
                  file=sys.stderr)
            return 2
        return _reset(settings, args.confirm_synthetic_reset, args.dataset)
    except StoreIntegrityError as exc:
        print(f"INTEGRITY FAILURE: {exc}", file=sys.stderr)
        return 1
    except (OgwaSafetyError, sqlite3.Error) as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
