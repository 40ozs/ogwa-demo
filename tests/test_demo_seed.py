"""The synthetic demo world, its reproducibility, and the guarded reset command."""

import contextlib
import io
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.core.modes import ExecutionMode
from app.demo import synthetic_world as world
from app.demo.synthetic_world import (
    AS_OF,
    POLICY,
    REVIEWER_1,
    Condition,
    SeedClock,
    create_seeded_store,
    seed_synthetic_world,
    seeded_id,
)
from app.domain.audit import AuditAction
from app.domain.collection import CollectorErrorCode
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.execution import JobStatus
from app.domain.ids import IdKind
from app.domain.lifecycle import LifecycleState
from app.domain.model import EXACT_CONFIDENCES, ADGroup, DependencyCoverage
from app.store import __main__ as cli
from app.store import reset as reset_module
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreError
from app.store.reset import ResetRefused, reset_synthetic_store
from app.store.store import Store
from tests.domain_fixtures import T0, application, prov
from tests.store_fixtures import file_target, memory_target, new_store, table_dump

S = LifecycleState
EXPECTED_FINAL_STATES = {
    "S01": S.HOLD, "S02": S.DISCOVERED, "S03": S.DEPENDENCY_BLOCKED, "S04": S.DEPENDENCY_BLOCKED,
    "S05": S.DEPENDENCY_BLOCKED, "S06": S.PROTECTED, "S07": S.NEEDS_REVIEW, "S08": S.NEEDS_REVIEW,
    "S09": S.MAPPING_AMBIGUOUS, "S10": S.BLOCKED, "S11": S.STALE_EVIDENCE, "S12": S.REVALIDATION_REQUIRED,
    "S13": S.DISCOVERED, "S14": S.APPROVED, "S15": S.QUARANTINE_HOLD, "S16": S.DELETION_PROPOSED,
}
# Why each expected refusal happened, as recorded in the audit log.
EXPECTED_REFUSALS = {
    "S02": "sign-ins in the window",
    "S08": "mapping confidence NAME_ONLY is not exact",
    "S12": "dependency coverage is PARTIAL",
    "S13": "is not decision-grade",
    "S14": "dry run status is FAILED",
}


class SeededWorldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_seeded_store(memory_target())
        cls.by_key = {s.key: s for s in cls.summary.scenarios}

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_every_required_condition_is_expressed(self):
        covered = {c for s in self.summary.scenarios for c in s.conditions}
        self.assertEqual(covered, set(Condition))
        self.assertEqual(len(Condition), 16)  # the P03 list, and two P10B AD-stage conditions

    def test_each_scenario_reaches_its_expected_state(self):
        for key, state in EXPECTED_FINAL_STATES.items():
            with self.subTest(scenario=key):
                scenario = self.by_key[key]
                self.assertIs(scenario.final_state, state)
                self.assertIs(self.store.load_candidate(scenario.candidate_id).state, state)

    def test_refusals_are_audited_with_their_reasons(self):
        refusals = [e for e in self.store.audit_events() if e.action is AuditAction.TRANSITION_REFUSED]
        self.assertEqual(len(refusals), len(EXPECTED_REFUSALS))
        for key, reason in EXPECTED_REFUSALS.items():
            with self.subTest(scenario=key):
                cid = self.by_key[key].candidate_id
                problems = [dict(e.details)["problems"] for e in refusals if e.subject_id == cid]
                self.assertEqual(len(problems), 1)
                self.assertIn(reason, problems[0])

    def test_s01_completed_the_okta_path_with_a_successful_dry_run(self):
        candidate = self.store.load_candidate(self.by_key["S01"].candidate_id)
        self.assertEqual(candidate.okta_unassign_approver, REVIEWER_1)
        self.assertGreater(candidate.hold_until, AS_OF)
        app = self.store.evidence_bundle(candidate).applications[0]
        self.assertEqual(app.status.value, "INACTIVE")
        history = self.store.job_status_history(seeded_id(IdKind.EXECUTION_JOB, "S01-okta"))
        self.assertEqual([h.status for h in history], [JobStatus.PLANNED, JobStatus.RUNNING, JobStatus.SUCCEEDED])

    def test_s14_dry_run_failure_is_recorded(self):
        job = self.store.load_execution_job(seeded_id(IdKind.EXECUTION_JOB, "S14-okta"))
        self.assertIs(job.status, JobStatus.FAILED)
        self.assertFalse(job.executed)
        last = self.store.job_status_history(job.id)[-1]
        self.assertTrue(last.external_ref.startswith("aap-synthetic-job-"))
        self.assertIn("unreachable", last.detail)

    def test_s13_collector_failures_are_recorded(self):
        outcomes = {
            key: self.store.collector_run_outcome(seeded_id(IdKind.COLLECTOR_RUN, key))
            for key in ("S13-usage-rate-limited", "S13-ad-timeout")
        }
        self.assertEqual((outcomes["S13-usage-rate-limited"].status, outcomes["S13-usage-rate-limited"].error_code),
                         (ResultStatus.PARTIAL, CollectorErrorCode.RATE_LIMITED))
        self.assertEqual((outcomes["S13-ad-timeout"].status, outcomes["S13-ad-timeout"].error_code),
                         (ResultStatus.FAILED, CollectorErrorCode.TIMEOUT))
        evidence = self.store.evidence_bundle(self.store.load_candidate(self.by_key["S13"].candidate_id))
        self.assertIs(evidence.usage[0].provenance.result_status, ResultStatus.PARTIAL)
        self.assertIsNone(evidence.ad_group)

    def test_dependency_coverage_partial_and_unknown(self):
        required = POLICY.required_dependency_kinds
        coverage = {
            key: self.store.evidence_bundle(self.store.load_candidate(self.by_key[key].candidate_id)).dependency_coverage(required)
            for key in ("S01", "S07", "S12")
        }
        self.assertEqual(coverage, {"S01": DependencyCoverage.COMPLETE, "S07": DependencyCoverage.UNKNOWN,
                                    "S12": DependencyCoverage.PARTIAL})

    def mapping_of(self, key):
        return self.store.evidence_bundle(self.store.load_candidate(self.by_key[key].candidate_id)).mapping

    def test_mapping_variants(self):
        # Every mapping is what the correlation engine proved (owner decision after the P08 addendum).
        for key in ("S01", "S07"):
            with self.subTest(scenario=key):
                exact = self.mapping_of(key)
                self.assertEqual(exact.confidence.value, "EXACT_CONFIGURED_MAPPING")
                self.assertEqual(set(exact.matched_attributes), {"objectGUID", "objectSid"})
                self.assertEqual(exact.configuration_ref, f"config/correlation.synthetic.json#{key}")
        name_only = self.mapping_of("S08")
        self.assertEqual((name_only.confidence.value, name_only.matched_attributes), ("NAME_ONLY", ("samAccountName",)))
        ambiguous = self.mapping_of("S09")
        self.assertEqual(ambiguous.confidence.value, "AMBIGUOUS")
        domains = {self.store.latest(ADGroup, i).domain for i in ambiguous.candidate_ad_group_ids}
        self.assertEqual(domains, {"corp.synthetic.example", "emea.synthetic.example"})
        self.assertEqual({c.value for c in EXACT_CONFIDENCES} & {self.mapping_of(k).confidence.value
                                                                for k in self.by_key if self.mapping_of(k)},
                         {"EXACT_CONFIGURED_MAPPING"})

    def test_missing_and_nested_ad_groups(self):
        bundle = self.store.evidence_bundle(self.store.load_candidate(self.by_key["S10"].candidate_id))
        self.assertEqual(bundle.mapping.confidence.value, "NOT_FOUND")  # the configured objectGUID resolves nowhere
        self.assertIn("MAPPING_UNRESOLVABLE", bundle.mapping.reason)
        self.assertIsNone(bundle.ad_group)
        self.assertFalse(self.store.latest(ADGroup, seeded_id(IdKind.AD_GROUP, "S10")).exists)
        parent = self.store.latest(ADGroup, seeded_id(IdKind.AD_GROUP, "S05-parent"))
        self.assertEqual(parent.sam_account_name, "SYNTH-ROLE-FINANCE-ALL")

    def test_every_name_is_obviously_fictional(self):
        conn = self.store.connection
        for (name,) in conn.execute("SELECT name FROM okta_group_observations"):
            self.assertTrue(name.startswith("SYNTH-"), name)
        for (label,) in conn.execute("SELECT label FROM okta_application_observations"):
            self.assertTrue(label.startswith("SYNTH "), label)
        for (domain,) in conn.execute("SELECT DISTINCT domain FROM ad_group_observations"):
            self.assertTrue(domain.endswith(".synthetic.example"), domain)
        for table in ("okta_application_observations", "okta_group_observations", "ad_group_observations", "collector_runs"):
            sources = {r[0] for r in conn.execute(f"SELECT DISTINCT source FROM {table}")}
            self.assertEqual(sources, {EvidenceSource.SYNTHETIC.value}, table)

    def test_seeded_store_verifies(self):
        report = self.store.verify_integrity(expected_audit_head=self.summary.audit_head)
        self.assertEqual(report.candidates_checked, 16)
        self.assertIs(self.store.audit_events()[-1].action, AuditAction.SYNTHETIC_SEED_LOADED)


class ReproducibilityTests(unittest.TestCase):
    def test_seeding_twice_gives_identical_databases(self):
        first, a = create_seeded_store(memory_target())
        second, b = create_seeded_store(memory_target())
        try:
            self.assertEqual(a, b)
            self.assertEqual(table_dump(first), table_dump(second))
        finally:
            first.close()
            second.close()

    def test_seed_refuses_a_non_empty_or_non_synthetic_store(self):
        store, _ = create_seeded_store(memory_target())
        with store, self.assertRaisesRegex(StoreError, "empty store"):
            seed_synthetic_world(store)
        with new_store(environment=DatabaseEnvironment.DEVELOPMENT) as development:
            with self.assertRaisesRegex(StoreError, "SYNTHETIC store"):
                seed_synthetic_world(development)


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "var"
        self.root.mkdir()
        self.target = file_target(self.root / "demo.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def reset(self, target=None, **kw):
        kw.setdefault("mode", ExecutionMode.LOCAL_SYNTHETIC)
        kw.setdefault("confirmed", True)
        return reset_synthetic_store(target or self.target, allowed_root=self.root, **kw)

    def assertUntouched(self, path: Path, before: bytes):
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), before)

    def test_creates_then_replaces_reproducibly(self):
        first = self.reset()
        self.assertFalse(first.replaced_existing)
        second = self.reset()
        self.assertTrue(second.replaced_existing)
        self.assertEqual(first.summary.audit_head, second.summary.audit_head)
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            self.assertEqual(len(store.candidate_ids()), 16)

    def test_refuses_outside_local_synthetic_mode(self):
        for mode in (ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.DRY_RUN_MUTATION, ExecutionMode.PRODUCTION_MUTATION):
            with self.subTest(mode=mode), self.assertRaisesRegex(ResetRefused, "LOCAL_SYNTHETIC"):
                self.reset(mode=mode)
        self.assertFalse(self.target.path.exists())

    def test_refuses_without_confirmation(self):
        with self.assertRaisesRegex(ResetRefused, "confirmation"):
            self.reset(confirmed=False)

    def test_refuses_paths_outside_the_allowed_root_and_in_memory(self):
        outside = file_target(Path(self.tmp.name) / "elsewhere.sqlite3")
        with self.assertRaisesRegex(ResetRefused, "outside the allowed root"):
            self.reset(outside)
        sneaky = file_target(self.root / ".." / "elsewhere.sqlite3")
        with self.assertRaisesRegex(ResetRefused, "outside the allowed root"):
            self.reset(sneaky)
        with self.assertRaisesRegex(ResetRefused, "database file"):
            self.reset(memory_target())

    def test_refuses_a_production_store(self):
        new_store(self.target, environment=DatabaseEnvironment.PRODUCTION, mode=ExecutionMode.READ_ONLY_PRODUCTION).close()
        before = self.target.path.read_bytes()
        with self.assertRaisesRegex(ResetRefused, "marked PRODUCTION"):
            self.reset()
        self.assertUntouched(self.target.path, before)

    def test_refuses_a_development_store_holding_real_evidence(self):
        with new_store(self.target, environment=DatabaseEnvironment.DEVELOPMENT, mode=ExecutionMode.READ_ONLY_PRODUCTION) as store:
            store.record_evidence(application(T0, provenance=prov(T0, source=EvidenceSource.OKTA_API)),
                                  actor=world.COLLECTOR)
        before = self.target.path.read_bytes()
        with self.assertRaisesRegex(ResetRefused, "non-synthetic"):
            self.reset()
        self.assertUntouched(self.target.path, before)

    def test_resets_a_development_store_holding_only_synthetic_evidence(self):
        with new_store(self.target, environment=DatabaseEnvironment.DEVELOPMENT) as store:
            store.record_evidence(application(T0), actor=world.COLLECTOR)
        self.assertTrue(self.reset().replaced_existing)
        with Store.open(self.target, mode=ExecutionMode.LOCAL_SYNTHETIC) as store:
            self.assertIs(store.marker.environment, DatabaseEnvironment.SYNTHETIC)

    def test_never_deletes_files_it_cannot_identify(self):
        foreign = sqlite3.connect(self.target.path)
        foreign.execute("CREATE TABLE important (x INTEGER)")
        foreign.commit()
        foreign.close()
        before = self.target.path.read_bytes()
        with self.assertRaisesRegex(ResetRefused, "no OGWA environment marker"):
            self.reset()
        self.assertUntouched(self.target.path, before)
        self.target.path.write_text("plain text, not a database", encoding="utf-8")
        with self.assertRaisesRegex(ResetRefused, "not deleting"):
            self.reset()
        self.assertUntouched(self.target.path, b"plain text, not a database")


class StoreCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "var"
        self.root.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, url=None, mode="LOCAL_SYNTHETIC"):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        env["OGWA_EXECUTION_MODE"] = mode
        env["OGWA_DATABASE_URL"] = url or f"sqlite:///{(self.root / 'demo.sqlite3').as_posix()}"
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(reset_module, "DEFAULT_ALLOWED_ROOT", self.root), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_reset_demo_requires_confirmation(self):
        code, _, err = self.run_cli("reset-demo")
        self.assertEqual(code, 2)
        self.assertIn("confirmation", err)

    def test_reset_demo_refuses_outside_var(self):
        url = f"sqlite:///{(Path(self.tmp.name) / 'outside.sqlite3').as_posix()}"
        code, _, err = self.run_cli("reset-demo", "--confirm-synthetic-reset", url=url)
        self.assertEqual(code, 2)
        self.assertIn("outside the allowed root", err)

    def test_reset_demo_refuses_in_read_only_production_mode(self):
        code, _, err = self.run_cli("reset-demo", "--confirm-synthetic-reset", mode="READ_ONLY_PRODUCTION")
        self.assertEqual(code, 2)
        self.assertIn("LOCAL_SYNTHETIC", err)

    def test_reset_status_and_verify(self):
        # The classic 16-scenario world, by name; the CLI's default is Null Meridian (tests/test_null_meridian_seed.py).
        code, out, _ = self.run_cli("reset-demo", "--confirm-synthetic-reset", "--dataset", "classic")
        self.assertEqual(code, 0, out)
        self.assertIn("S14", out)
        head = out.strip().splitlines()[-1].split()[-1]
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("environment:    SYNTHETIC", out)
        code, out, _ = self.run_cli("verify", "--expected-audit-head", head)
        self.assertEqual(code, 0, out)
        code, _, err = self.run_cli("verify", "--expected-audit-head", "sha256:" + "0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("INTEGRITY FAILURE", err)

    def test_postgresql_url_is_refused(self):
        code, _, err = self.run_cli("status", url="postgresql://db.synthetic.example/ogwa")
        self.assertEqual(code, 2)
        self.assertIn("PostgreSQL", err)

    def test_init_production_is_refused_in_synthetic_mode(self):
        code, _, err = self.run_cli("init", "--environment", "PRODUCTION")
        self.assertEqual(code, 2)
        self.assertIn("cannot be used in LOCAL_SYNTHETIC", err)
        self.assertFalse((self.root / "demo.sqlite3").exists())


class SeedClockTests(unittest.TestCase):
    def test_clock_is_deterministic_and_after_as_of(self):
        a, b = SeedClock(), SeedClock()
        readings = [a() for _ in range(3)]
        self.assertEqual(readings, [b() for _ in range(3)])
        self.assertTrue(all(r > AS_OF for r in readings))
        self.assertLess(readings[0], readings[1])


if __name__ == "__main__":
    unittest.main()
