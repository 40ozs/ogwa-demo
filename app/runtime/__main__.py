"""``python -m app.runtime``: Demo Mode operator commands.

    status                                  runtime mode, demo dataset, dataset availability, demo store
    reset-demo --confirm-synthetic-reset    re-create the demo store from the dataset's own seed
    verify [--expected-audit-head HEAD]     validate the demo store against the configured dataset

The dataset is the configured ``OGWA_DEMO_DATASET`` selector (default ``null-meridian``),
resolved through the dataset registry ``app.demo.datasets``; there is no ``--dataset`` flag,
so the store and the server always agree on it. This is the one reset command for the demo
store.

The sequence is: reset the demo store (the guarded reset runs the dataset's own seed),
validate the canonical dataset, then start OGWA (``python -m app.api serve``). Nothing here
contacts a network service. Exit codes: 0 success, 1 validation failure, 2 refused.
"""

import argparse
import sqlite3
import sys

from app.core.config import load_settings
from app.core.errors import OgwaSafetyError
from app.runtime.datasets import dataset_status, resolve_dataset
from app.runtime.demo_store import DemoPersistenceUnavailable, open_demo_store, reset_demo_store
from app.store import reset as reset_module
from app.store.store import utc_now


def _status(settings) -> int:
    print(f"runtime_mode:  {settings.runtime_mode.value}")
    print(f"demo_dataset:  {settings.demo_dataset}")
    for key, state in dataset_status().items():
        print(f"dataset[{key}]: {state}")
    path = settings.database.path
    print(f"demo_store:    {'present' if path is not None and path.is_file() else 'missing'}")
    return 0


def _reset(settings, confirmed: bool) -> int:
    dataset = resolve_dataset(settings.demo_dataset)
    result = reset_demo_store(settings, dataset, confirmed=confirmed, allowed_root=reset_module.DEFAULT_ALLOWED_ROOT)
    report = result.report
    print(f"{'Replaced' if result.replaced_existing else 'Created'} the demo store for dataset {result.dataset} "
          f"({dataset.metadata.company_name}, {dataset.metadata.primary_domain}, snapshot "
          f"{dataset.metadata.snapshot_date.isoformat()}) at {result.path}")
    _print_report(report)
    for scenario in result.summary.scenarios:
        state = scenario.final_state.value if scenario.final_state else "-"
        print(f"  {scenario.key}  {state:<22} {scenario.title}")
    print(f"audit_head: {result.audit_head}")
    return 0


def _print_report(report) -> None:
    integrity = report.integrity
    print(f"validated: schema {integrity.schema_version}, {integrity.environment.value}, {integrity.audit_events} "
          f"audit events, {integrity.observations_checked} observations, {integrity.candidates_checked} candidates"
          + (f", {report.directory_records} synthetic directory records" if report.directory_records else ""))
    print(f"seed_namespace: {report.seed_namespace} (SYNTHETIC_SEED_LOADED #{report.seed_audit_sequence})")
    print(f"directory_dataset: {report.directory_dataset or '-'}")


def _verify(settings, expected_head: str | None) -> int:
    dataset = resolve_dataset(settings.demo_dataset)
    try:
        store, report = open_demo_store(settings, dataset, clock=utc_now, expected_audit_head=expected_head)
    except DemoPersistenceUnavailable as exc:
        print(f"DEMO STORE INVALID: {exc}", file=sys.stderr)
        return 1
    store.close()
    _print_report(report)
    print(f"OK: dataset {report.dataset}, audit_head {report.integrity.audit_head}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.runtime", description="Demo Mode operator commands.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    reset = commands.add_parser("reset-demo")
    reset.add_argument("--confirm-synthetic-reset", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--expected-audit-head")
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
        if args.command == "status":
            return _status(settings)
        print(f"OGWA demo | dataset={settings.demo_dataset}")
        if args.command == "reset-demo":
            return _reset(settings, args.confirm_synthetic_reset)
        return _verify(settings, args.expected_audit_head)
    except (OgwaSafetyError, sqlite3.Error) as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
