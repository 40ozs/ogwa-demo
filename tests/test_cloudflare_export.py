"""The D1 export of the demo store and the operator CLI, ``python -m app.cloudflare``.

The export must reproduce the demo store exactly (every row, in storage order, and the
schema SQL the canonical migrations created), in phases that each fit D1 Free's daily write
quota. ``build`` must seed through the demo reset and stage what the Worker runs;
``next-phase`` must refuse a D1 database that is not this build's import; and
``verify-export`` must run the demo runtime's own validation on an export of the hosted D1.
"""

import contextlib
import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.cloudflare import __main__ as cli
from app.cloudflare.export import (
    D1_FREE_ROWS_WRITTEN_PER_DAY,
    D1_MAX_STATEMENT_BYTES,
    DEFAULT_BUDGET,
    ExportError,
    literal,
    plan_phases,
)
from app.cloudflare.hosted import HostedDemo, read_gzip_image
from app.cloudflare.identity import SCHEMA_SQL, read_identity, read_schema_digest
from tests.test_null_meridian_seed import GOLDEN_AUDIT_HEAD

REPO = Path(__file__).resolve().parents[1]
_TMP: tempfile.TemporaryDirectory | None = None
OUT = WORKER = Path()


def setUpModule():
    """One real build into a throw-away worker directory (the demo reset runs once)."""
    global _TMP, OUT, WORKER
    _TMP = tempfile.TemporaryDirectory(prefix="ogwa-cf-build-")
    root = Path(_TMP.name)
    OUT, WORKER = root / "build", root / "worker"
    (WORKER / "src").mkdir(parents=True)
    shutil.copyfile(REPO / "cloudflare" / "worker" / "wrangler.jsonc", WORKER / "wrangler.jsonc")
    code, _, err = run("build", "--worker", str(WORKER), "--out", str(OUT))
    assert code == 0, err


def tearDownModule():
    _TMP.cleanup()


def run(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


def store() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{(OUT / 'var' / 'ogwa-demo.sqlite3').as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def tables(conn: sqlite3.Connection) -> dict[str, list[tuple]]:
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                                        "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {n: [tuple(r) for r in conn.execute(f'SELECT rowid, * FROM "{n}" ORDER BY rowid')] for n in names}


def d1_result(rows: list[dict]) -> str:
    """What ``wrangler d1 execute --json`` prints for one query."""
    return json.dumps([{"results": rows, "success": True, "meta": {}}])


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = store()
        cls.phases = plan_phases(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_the_phases_reproduce_the_store_exactly(self):
        copy = sqlite3.connect(":memory:")
        copy.row_factory = sqlite3.Row
        for phase in self.phases:
            copy.executescript("BEGIN;\n" + phase.sql() + "COMMIT;")
        self.assertEqual(tables(copy), tables(self.conn), "every row, in storage order")
        self.assertEqual(read_schema_digest(copy), read_schema_digest(self.conn), "the canonical schema SQL")
        self.assertEqual(read_identity(copy), read_identity(self.conn))
        hosted = HostedDemo(copy.serialize, cli.worker_environment(WORKER), expected={"audit_head": GOLDEN_AUDIT_HEAD})
        self.addCleanup(hosted.app.close)
        copy.close()
        self.assertEqual(hosted.identity.audit_head, GOLDEN_AUDIT_HEAD, "and passes validate_demo_store")

    def test_each_phase_fits_d1_free_and_the_store_needs_more_than_one(self):
        self.assertGreater(sum(p.rows_written for p in self.phases), D1_FREE_ROWS_WRITTEN_PER_DAY,
                           "the whole import exceeds one day's free writes")
        self.assertGreaterEqual(len(self.phases), 2)
        for phase in self.phases:
            with self.subTest(phase=phase.number):
                self.assertLessEqual(phase.rows_written, DEFAULT_BUDGET)
                self.assertEqual(phase.statements[0], "PRAGMA defer_foreign_keys = true")
                self.assertLessEqual(max(len(s.encode()) for s in phase.statements), D1_MAX_STATEMENT_BYTES)
                self.assertFalse(any(s.upper().startswith(("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT"))
                                     for s in phase.statements), "D1 refuses transaction statements")

    def test_rows_go_in_before_any_trigger_exists_and_parents_before_children(self):
        statements = [s for p in self.phases for s in p.statements]
        first_trigger = next(i for i, s in enumerate(statements) if s.startswith("CREATE TRIGGER"))
        last_insert = max(i for i, s in enumerate(statements) if s.startswith("INSERT"))
        self.assertLess(last_insert, first_trigger)
        first_insert = {}
        for i, s in enumerate(statements):
            if s.startswith("INSERT INTO"):
                first_insert.setdefault(s.split()[2].strip('"'), i)
        for child in first_insert:
            for fk in self.conn.execute(f'PRAGMA foreign_key_list("{child}")'):
                if fk[2] in first_insert and fk[2] != child:
                    self.assertLess(first_insert[fk[2]], first_insert[child], f"{fk[2]} before {child}")

    def test_the_plan_is_deterministic_and_respects_the_budget(self):
        self.assertEqual(plan_phases(self.conn), self.phases)
        small = plan_phases(self.conn, budget=60_000)
        self.assertGreater(len(small), len(self.phases))
        self.assertTrue(all(p.rows_written <= 60_000 for p in small))
        with self.assertRaisesRegex(ExportError, "more than the phase budget"):
            plan_phases(self.conn, budget=1_000)  # one index of the directory records needs more
        with self.assertRaises(ExportError):
            plan_phases(self.conn, budget=D1_FREE_ROWS_WRITTEN_PER_DAY + 1)

    def test_literals(self):
        self.assertEqual([literal(v) for v in (None, 7, 1.5, "it's", b"\x00\xff")],
                         ["NULL", "7", "1.5", "'it''s'", "X'00ff'"])
        for bad in (float("nan"), float("inf"), object()):
            with self.assertRaises(ExportError):
                literal(bad)


class BuildTests(unittest.TestCase):
    def test_the_build_stages_what_the_worker_runs(self):
        src = WORKER / "src"
        manifest = json.loads((src / cli.MANIFEST_NAME).read_text())
        self.assertEqual(manifest["audit_head"], GOLDEN_AUDIT_HEAD)
        self.assertEqual(manifest["environment"], {"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": "null-meridian"})
        self.assertEqual((OUT / cli.MANIFEST_NAME).read_text(), (src / cli.MANIFEST_NAME).read_text())
        self.assertTrue((src / "app" / "cloudflare" / "hosted.py").is_file())
        self.assertFalse(any(p.suffix not in (".py",) for p in (src / "app").rglob("*") if p.is_file()))
        self.assertFalse(list((src / "app").rglob("__pycache__")))
        self.assertTrue((src / "config" / "synthetic-idp.json").is_file())
        public = WORKER / "public"
        self.assertEqual((public / "index.html").read_bytes(), (REPO / "app/ui/static/index.html").read_bytes())
        self.assertTrue((public / "ui" / "js" / "main.js").is_file())
        headers = (public / "_headers").read_text()
        self.assertIn("Content-Security-Policy: default-src 'none'", headers)
        self.assertIn("X-OGWA-Runtime-Mode: demo", headers)
        plan = json.loads((OUT / "d1" / "plan.json").read_text())
        self.assertEqual([p["phase"] for p in plan["phases"]], list(range(1, len(plan["phases"]) + 1)))

    def test_the_image_is_the_validated_store(self):
        image = read_gzip_image(WORKER / "src" / cli.IMAGE_NAME)
        self.assertEqual(image, (OUT / "var" / "ogwa-demo.sqlite3").read_bytes())
        manifest = json.loads((WORKER / "src" / cli.MANIFEST_NAME).read_text())
        hosted = HostedDemo(lambda: image, manifest["environment"], expected=manifest)  # as the Worker, at import
        hosted.app.close()

    def test_a_worker_whose_vars_select_production_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            worker = Path(tmp) / "worker"
            worker.mkdir()
            config = json.loads((WORKER / "wrangler.jsonc").read_text())
            config["vars"] = {"OGWA_RUNTIME_MODE": "production", "OGWA_DEMO_DATASET": "null-meridian"}
            (worker / "wrangler.jsonc").write_text(json.dumps(config))
            code, _, err = run("build", "--worker", str(worker), "--out", str(Path(tmp) / "out"))
        self.assertEqual(code, 2, err)
        self.assertIn("Demo Mode only", err)


class NextPhaseTests(unittest.TestCase):
    def schema_rows(self, upto: int) -> list[dict]:
        copy = sqlite3.connect(":memory:")
        copy.row_factory = sqlite3.Row
        for number in range(1, upto + 1):
            copy.executescript("BEGIN;\n" + (OUT / "d1" / f"phase-{number}.sql").read_text() + "COMMIT;")
        return [dict(r) for r in copy.execute(SCHEMA_SQL)]

    def next_phase(self, rows: list[dict]) -> tuple[int, str, str]:
        path = OUT / "schema.json"
        path.write_text(d1_result(rows))
        return run("next-phase", "--d1-schema", str(path), "--out", str(OUT))

    def test_the_phases_run_in_order_and_then_the_import_is_complete(self):
        phases = len(json.loads((OUT / "d1" / "plan.json").read_text())["phases"])
        for done in range(phases):
            with self.subTest(done=done):
                code, out, _ = self.next_phase(self.schema_rows(done))
                self.assertEqual(code, 0)
                self.assertIn(f"next: phase {done + 1} ", out)
        code, out, _ = self.next_phase(self.schema_rows(phases))
        self.assertEqual((code, out.strip()), (3, "complete: D1 holds every phase"))

    def test_a_foreign_or_partial_database_is_refused(self):
        rows = self.schema_rows(1)
        for altered in (rows[:-1], [*rows, {"type": "table", "name": "other", "tbl_name": "other", "sql": "x"}],
                        [{"type": "table", "name": "other", "tbl_name": "other", "sql": "x"}]):
            with self.subTest(objects=len(altered)):
                code, _, err = self.next_phase(altered)
                self.assertEqual(code, 2)
                self.assertIn("is not this build's import", err)

    def test_wrangler_output_must_be_one_successful_result(self):
        path = OUT / "schema.json"
        path.write_text(json.dumps([{"results": [], "success": False}]))
        self.assertEqual(run("next-phase", "--d1-schema", str(path), "--out", str(OUT))[0], 2)


class VerifyExportTests(unittest.TestCase):
    def export(self, statements: str) -> Path:
        path = OUT / "export.sql"
        path.write_text(statements)
        return path

    def phases_sql(self) -> str:
        plan = json.loads((OUT / "d1" / "plan.json").read_text())["phases"]
        return "".join((OUT / "d1" / p["file"]).read_text() for p in plan)

    def test_an_export_of_the_complete_import_verifies(self):
        code, out, err = run("verify-export", str(self.export(self.phases_sql())), "--out", str(OUT))
        self.assertEqual(code, 0, err)
        self.assertIn(f"OK: dataset null-meridian, audit_head {GOLDEN_AUDIT_HEAD}", out)
        self.assertIn("seed_namespace: null-meridian-v1", out)

    def test_a_tampered_or_partial_export_fails(self):
        sql = self.phases_sql()
        tampered = sql.replace("'Null Meridian'", "'Null Meridiam'", 1)
        self.assertNotEqual(tampered, sql)
        code, _, err = run("verify-export", str(self.export(tampered)), "--out", str(OUT))
        self.assertEqual(code, 1, err)
        first = (OUT / "d1" / "phase-1.sql").read_text()
        code, _, err = run("verify-export", str(self.export(first)), "--out", str(OUT))
        self.assertEqual(code, 1)
        self.assertIn("schema differs", err)

    def test_the_cli_prints_the_sql_the_operator_runs(self):
        self.assertEqual(run("sql", "schema")[1].strip(), SCHEMA_SQL)
        self.assertIn("FROM audit_events ORDER BY sequence DESC LIMIT 1", run("sql", "identity")[1])
