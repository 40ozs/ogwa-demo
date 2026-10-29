"""``python -m app.cloudflare``: build and verify the Cloudflare-hosted demo (docs/deployment/cloudflare-demo.md).

    build [--worker DIR] [--out DIR] [--budget N]   seed, validate, stage the Worker, plan the D1 import
    next-phase --d1-schema FILE                    which D1 import phase is due (wrangler --json output)
    verify-export EXPORT [--out DIR]               validate a `wrangler d1 export` of the hosted D1
    sql identity|schema                            the SQL the operator runs against D1 with wrangler

``build`` runs the demo runtime's own reset (``reset_demo_store``: the guarded reset and the
dataset's deterministic seed) into ``<out>/var``, builds the hosted application from that
store exactly as the Worker will (``HostedDemo``, which runs ``validate_demo_store``), and
writes: the Worker's sources, store image, and build manifest under ``<worker>/src``; the UI
files and their headers under ``<worker>/public``; and the D1 import phases under ``<out>/d1``.
The runtime settings come from the Worker's own ``vars`` in ``<worker>/wrangler.jsonc``, so
the store, the Worker, and D1 always agree on the dataset.

``verify-export`` loads a SQL export of the hosted D1 into a throw-away SQLite store and runs
``python -m app.runtime verify``'s validation on it, pinned to the build's audit head; then it
checks the store's identity and schema against the build manifest. Nothing here contacts
Cloudflare or any other system: wrangler does, run by the operator
(``scripts/cloudflare-demo.ps1``). Exit codes: 0 success, 1 validation failure, 2 refused,
3 (next-phase) the import is complete.
"""

import argparse
import gzip
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from app.cloudflare.export import DEFAULT_BUDGET, ExportError, plan_phases
from app.cloudflare.hosted import HostedDemo, manifest_json
from app.cloudflare.identity import IDENTITY_SQL, SCHEMA_SQL, StoreIdentity, read_identity, read_schema_digest
from app.core.config import load_settings
from app.core.database_url import PROJECT_ROOT
from app.core.errors import OgwaSafetyError
from app.demo.genesee_press.projection import LOCK_PATH, VENDOR_ROOT
from app.runtime.datasets import resolve_dataset
from app.runtime.demo_store import DemoPersistenceUnavailable, open_demo_store, reset_demo_store
from app.store.store import utc_now
from app.ui.server import STATIC_ROOT, UI_HEADERS, UI_PREFIX

DEFAULT_WORKER = PROJECT_ROOT / "cloudflare" / "worker"
DEFAULT_OUT = PROJECT_ROOT / "cloudflare" / "build"
IMAGE_NAME = "ogwa-demo.sqlite3.gz"
MANIFEST_NAME = "hosted-build.json"
STORE_NAME = "ogwa-demo.sqlite3"


def read_wrangler_config(worker: Path) -> dict:
    """``wrangler.jsonc``, which OGWA keeps free of comments, so it is plain JSON."""
    return json.loads((worker / "wrangler.jsonc").read_text(encoding="utf-8"))


def worker_environment(worker: Path) -> dict[str, str]:
    """The OGWA settings the Worker runs with: its ``vars`` named ``OGWA_*``."""
    variables = read_wrangler_config(worker).get("vars", {})
    return {k: v for k, v in variables.items() if k.upper().startswith("OGWA_")}


def headers_file(runtime_mode: str) -> str:
    """Workers Static Assets ``_headers``: the local server's UI headers, for every UI file."""
    lines = [f"  {name}: {value}" for name, value in (*UI_HEADERS, ("X-OGWA-Runtime-Mode", runtime_mode))]
    return "".join(f"{path}\n" + "\n".join(lines) + "\n" for path in ("/", "/index.html", UI_PREFIX + "*"))


def _stage_tree(source: Path, target: Path, pattern: str) -> int:
    if target.exists():
        shutil.rmtree(target)
    count = 0
    for path in sorted(source.rglob(pattern)):
        if "__pycache__" in path.parts or path.name.startswith(".") or not path.is_file():
            continue
        dest = target / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        count += 1
    return count


def _build(worker: Path, out: Path, budget: int) -> int:
    environment = worker_environment(worker)
    var = out / "var"
    var.mkdir(parents=True, exist_ok=True)
    store_path = var / STORE_NAME
    settings = load_settings({**environment, "OGWA_DATABASE_URL": f"sqlite:///{store_path.as_posix()}"})
    if not settings.is_demo:
        print("Refused: the Worker's vars must select OGWA_RUNTIME_MODE=demo.", file=sys.stderr)
        return 2
    dataset = resolve_dataset(settings.demo_dataset or "")
    reset = reset_demo_store(settings, dataset, confirmed=True, allowed_root=var)
    image = store_path.read_bytes()
    hosted = HostedDemo(lambda: image, environment, expected={"audit_head": reset.audit_head})
    print(f"Seeded and validated dataset {reset.dataset} ({dataset.metadata.company_name}): "
          f"{reset.report.integrity.audit_events} audit events, {reset.report.directory_records} directory records")
    print(f"audit_head: {hosted.identity.audit_head}")

    conn = sqlite3.connect(f"file:{store_path.as_posix()}?mode=ro", uri=True)
    try:
        phases = plan_phases(conn, budget=budget)
    finally:
        conn.close()
    d1 = out / "d1"
    if d1.exists():
        shutil.rmtree(d1)
    d1.mkdir(parents=True)
    plan = []
    for phase in phases:
        sql = phase.sql().encode("utf-8")
        (d1 / f"phase-{phase.number}.sql").write_bytes(sql)
        plan.append({"phase": phase.number, "file": f"phase-{phase.number}.sql", "statements": len(phase.statements),
                     "estimatedRowsWritten": phase.rows_written, "sha256": hashlib.sha256(sql).hexdigest(),
                     "objects": _objects(phase.statements)})
        print(f"D1 phase {phase.number}: {len(phase.statements)} statements, ~{phase.rows_written} rows written")
    (d1 / "plan.json").write_text(json.dumps({"budget": budget, "phases": plan}, indent=2) + "\n", encoding="utf-8")

    src = worker / "src"
    modules = _stage_tree(PROJECT_ROOT / "app", src / "app", "*.py")
    _stage_tree(PROJECT_ROOT / "config", src / "config", "*.json")
    # Pyodide sees only bundled files, and the Genesee Press profile reads these three at import.
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    folder = VENDOR_ROOT / lock["snapshot"] / "projections" / "ogwa"
    shutil.rmtree(src / "vendor", ignore_errors=True)
    for path in (LOCK_PATH, folder / "projection.json", folder / "organization.jsonl"):
        dest = src / path.relative_to(PROJECT_ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    (src / IMAGE_NAME).write_bytes(gzip.compress(image, compresslevel=9, mtime=0))
    manifest = manifest_json(hosted.identity, hosted.schema, environment)
    (src / MANIFEST_NAME).write_text(manifest, encoding="utf-8")
    (out / MANIFEST_NAME).write_text(manifest, encoding="utf-8")
    public = worker / "public"
    _stage_tree(STATIC_ROOT, public / UI_PREFIX.strip("/"), "*")
    shutil.copyfile(STATIC_ROOT / "index.html", public / "index.html")
    (public / "_headers").write_text(headers_file(settings.runtime_mode.value), encoding="utf-8")
    print(f"Staged the Worker in {worker}: {modules} Python modules, the store image, and the UI in public/")
    return 0


def _objects(statements) -> list[str]:
    """The schema objects a phase creates, as ``type:name``."""
    found = []
    for statement in statements:  # SQLite's normalized schema SQL: "CREATE [UNIQUE] <TYPE> <name> ..."
        words = statement.split(None, 4)
        if words[:2] == ["CREATE", "UNIQUE"]:
            words = [words[0], *words[2:]]
        if len(words) > 2 and words[0] == "CREATE" and words[1] in ("TABLE", "INDEX", "TRIGGER", "VIEW"):
            found.append(f"{words[1].lower()}:{words[2].strip(chr(34))}")
    return found


def _d1_rows(path: Path) -> list[dict]:
    """The result rows of ``wrangler d1 execute --json``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data if isinstance(data, list) else [data]
    if len(results) != 1 or not results[0].get("success", False):
        raise ValueError("expected one successful wrangler d1 result")
    return list(results[0].get("results") or [])


def _next_phase(out: Path, schema_file: Path) -> int:
    plan = json.loads((out / "d1" / "plan.json").read_text(encoding="utf-8"))["phases"]
    present = {f"{r['type']}:{r['name']}" for r in _d1_rows(schema_file)}
    done: set[str] = set()
    for phase in plan:
        if present == done:
            print(f"next: phase {phase['phase']} ({out / 'd1' / phase['file']}), ~{phase['estimatedRowsWritten']} rows "
                  "written; run each phase on a different UTC day")
            return 0
        done |= set(phase["objects"])
    if present == done:
        print("complete: D1 holds every phase")
        return 3
    print(f"Refused: D1 holds {len(present)} schema objects that match no completed phase; it is not this "
          "build's import", file=sys.stderr)
    return 2


def _verify_export(export: Path, out: Path) -> int:
    from app.runtime.__main__ import _print_report

    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="ogwa-d1-export-") as tmp:
        path = Path(tmp) / "var" / STORE_NAME
        path.parent.mkdir()
        conn = sqlite3.connect(path, isolation_level=None)
        try:
            conn.executescript(export.read_text(encoding="utf-8"))
            identity, schema = read_identity(_rows(conn)), read_schema_digest(_rows(conn))
        finally:
            conn.close()
        settings = load_settings({**manifest["environment"], "OGWA_DATABASE_URL": f"sqlite:///{path.as_posix()}"})
        try:
            store, report = open_demo_store(settings, resolve_dataset(settings.demo_dataset or ""), clock=utc_now,
                                            expected_audit_head=manifest["audit_head"])
        except DemoPersistenceUnavailable as exc:
            print(f"DEMO STORE INVALID: {exc}", file=sys.stderr)
            return 1
        store.close()
    _print_report(report)
    problems = []
    if identity != StoreIdentity.from_row(manifest["identity"]):
        problems.append("identity differs from the build manifest")
    if schema != manifest["schema"]:
        problems.append("schema differs from the build manifest")
    if problems:
        print(f"HOSTED STORE MISMATCH: {'; '.join(problems)}", file=sys.stderr)
        return 1
    print(f"OK: dataset {report.dataset}, audit_head {report.integrity.audit_head}, schema {schema}")
    return 0


def _rows(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    return conn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cloudflare", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--worker", type=Path, default=DEFAULT_WORKER)
    build.add_argument("--out", type=Path, default=DEFAULT_OUT)
    build.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    nxt = commands.add_parser("next-phase")
    nxt.add_argument("--d1-schema", type=Path, required=True)
    nxt.add_argument("--out", type=Path, default=DEFAULT_OUT)
    verify = commands.add_parser("verify-export")
    verify.add_argument("export", type=Path)
    verify.add_argument("--out", type=Path, default=DEFAULT_OUT)
    sql = commands.add_parser("sql")
    sql.add_argument("which", choices=("identity", "schema"))
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            return _build(args.worker.resolve(), args.out.resolve(), args.budget)
        if args.command == "next-phase":
            return _next_phase(args.out.resolve(), args.d1_schema)
        if args.command == "verify-export":
            return _verify_export(args.export, args.out.resolve())
        print(IDENTITY_SQL if args.which == "identity" else SCHEMA_SQL)
        return 0
    except (OgwaSafetyError, ExportError, ValueError, OSError, sqlite3.Error) as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
