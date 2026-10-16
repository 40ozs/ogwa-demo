"""Domain additions made for the store: deterministic ids, audit context fields, collector runs."""

import unittest
from dataclasses import replace

from app.core.errors import ProductionMutationNotPermitted
from app.core.modes import ExecutionMode
from app.domain.audit import AuditAction, AuditResult, AuditTrail, verify_chain
from app.domain.collection import CollectorErrorCode, CollectorRun, CollectorRunOutcome
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.ids import IdKind, check_id, deterministic_ids, new_id
from tests.domain_fixtures import HOUR, SYSTEM, T0, fixed_id


class DeterministicIdTests(unittest.TestCase):
    def test_same_namespace_gives_same_sequence(self):
        with deterministic_ids("synthetic-test"):
            first = [new_id(IdKind.CANDIDATE), new_id(IdKind.DECISION), new_id(IdKind.CANDIDATE)]
        with deterministic_ids("synthetic-test"):
            second = [new_id(IdKind.CANDIDATE), new_id(IdKind.DECISION), new_id(IdKind.CANDIDATE)]
        self.assertEqual(first, second)
        self.assertEqual(len(set(first)), 3)
        check_id(first[0], IdKind.CANDIDATE, "id")

    def test_namespaces_differ_and_ids_are_random_outside_the_block(self):
        with deterministic_ids("synthetic-a"):
            a = new_id(IdKind.CANDIDATE)
        with deterministic_ids("synthetic-b"):
            b = new_id(IdKind.CANDIDATE)
        self.assertNotEqual(a, b)
        self.assertNotEqual(new_id(IdKind.CANDIDATE), new_id(IdKind.CANDIDATE))


class AuditContextTests(unittest.TestCase):
    def test_context_fields_are_recorded_and_covered_by_the_digest(self):
        trail = AuditTrail()
        event = trail.append(actor=SYSTEM, action=AuditAction.EVIDENCE_RECORDED, subject_id="s", occurred_at=T0,
                             execution_mode=ExecutionMode.LOCAL_SYNTHETIC, result=AuditResult.SUCCEEDED,
                             correlation_id="req_synthetic-1", before_ref="observation:a", after_ref="observation:b")
        verify_chain(trail.events, expected_head=event.digest)
        for change in ({"result": AuditResult.FAILED}, {"after_ref": "observation:c"}, {"correlation_id": "req_other"}):
            with self.subTest(change=change):
                self.assertNotEqual(replace(event, **change).digest, event.digest)

    def test_invalid_context_is_rejected(self):
        trail = AuditTrail()
        for bad in ({"correlation_id": "has spaces"}, {"correlation_id": "x" * 101}, {"before_ref": ""},
                    {"after_ref": "y" * 201}, {"result": "OK"}, {"execution_mode": "LOCAL_SYNTHETIC"}):
            with self.subTest(bad=bad), self.assertRaises(InvalidRecord):
                trail.append(actor=SYSTEM, action=AuditAction.EVIDENCE_RECORDED, subject_id="s", occurred_at=T0, **bad)

    def test_refs_are_redacted(self):
        event = AuditTrail().append(actor=SYSTEM, action=AuditAction.EVIDENCE_RECORDED, subject_id="s", occurred_at=T0,
                                    before_ref="ref token=synthetic-secret-value-9")
        self.assertNotIn("synthetic-secret-value-9", event.before_ref)


class CollectorRunTests(unittest.TestCase):
    def run_record(self, **kw):
        fields = dict(id=fixed_id(IdKind.COLLECTOR_RUN, 1), collector="okta-usage", collector_version="synthetic-1.0",
                      source=EvidenceSource.SYNTHETIC, mode=ExecutionMode.LOCAL_SYNTHETIC, scope="synthetic:scope",
                      started_at=T0, started_by=SYSTEM)
        fields.update(kw)
        return CollectorRun(**fields)

    def test_production_mutation_runs_cannot_exist(self):
        with self.assertRaises(ProductionMutationNotPermitted):
            self.run_record(mode=ExecutionMode.PRODUCTION_MUTATION)

    def test_outcome_error_code_matches_status(self):
        run_id = fixed_id(IdKind.COLLECTOR_RUN, 1)
        CollectorRunOutcome(run_id, T0 + HOUR, ResultStatus.COMPLETE, 10)
        CollectorRunOutcome(run_id, T0 + HOUR, ResultStatus.PARTIAL, 3, CollectorErrorCode.RATE_LIMITED, "HTTP 429")
        for status, code in ((ResultStatus.COMPLETE, CollectorErrorCode.TIMEOUT), (ResultStatus.FAILED, None)):
            with self.subTest(status=status), self.assertRaises(InvalidRecord):
                CollectorRunOutcome(run_id, T0 + HOUR, status, 0, code)

    def test_outcome_summary_must_not_carry_credentials(self):
        with self.assertRaisesRegex(InvalidRecord, "credential"):
            CollectorRunOutcome(fixed_id(IdKind.COLLECTOR_RUN, 1), T0 + HOUR, ResultStatus.FAILED, 0,
                                CollectorErrorCode.AUTHENTICATION_FAILED, "401 with Authorization: SSWS synthetic0123")


if __name__ == "__main__":
    unittest.main()
