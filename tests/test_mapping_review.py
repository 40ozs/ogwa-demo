"""Mapping review: the registry record, the operator service contract, and store persistence.

Synthetic only (D22). The service is exercised against the synthetic forest; the store
tests use in-memory SYNTHETIC stores.
"""

import sqlite3
import unittest
from datetime import timedelta

from app.correlation import (
    CorrelationOutcome,
    DriftKind,
    InMemoryMappingRegistry,
    MappingReviewService,
    ReviewAction,
    ReviewRefused,
    StoreMappingRegistry,
    mapping_evidence,
)
from app.domain.audit import AuditAction
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.ids import IdKind, new_id
from app.domain.mapping_review import (
    MappingMethod,
    MappingReview,
    ReviewStatus,
    current_approval,
    pending_selection,
    rejected_guids,
    review_append_problems,
)
from app.domain.model import ADGroup, IdentityMapping, MappingConfidence, OktaGroup, OktaGroupType
from app.integrations.ad.contract import LookupKind
from app.integrations.ad.records import ADStableIds
from app.store.db import DIALECT_SQLITE
from app.store.errors import StoreConflict
from app.store.migrations import statements_for, v0003_mapping_registry
from app.store.migrations.v0003_mapping_registry import MAPPING_METHODS, REVIEW_STATUSES
from tests.correlation_fixtures import (
    sid_verified,
    CORP,
    EMEA,
    OPERATOR_1,
    OPERATOR_2,
    SYSTEM,
    T,
    Clock,
    SyntheticDirectory,
    ad_group,
    config,
    okta_ad_group,
    okta_native_group,
    ref,
)
from tests.store_fixtures import MutableClock, new_store

PAYROLL = ad_group(4101, "SYNTH-App-Payroll-Users")
FIN_CORP = ad_group(4102, "SYNTH-App-Finance")
FIN_EMEA = ad_group(5102, "SYNTH-App-Finance", EMEA)
HR = ad_group(4105, "SYNTH-App-HR")
IDS = ADStableIds(CORP)


def review(n: int = 1, *, status=ReviewStatus.APPROVED, method=MappingMethod.OPERATOR_SELECTED, ad=HR,
           sequence=0, supersedes=None, by=OPERATOR_1, at=T, **kw) -> MappingReview:
    from app.domain.mapping_review import METHOD_CONFIDENCE
    fields = dict(
        id=new_id(IdKind.MAPPING_REVIEW), okta_group_ref=ref(n), okta_group_id=f"00gSYNTH{n:04d}",
        okta_group_name="SYNTH-Okta", sequence=sequence, supersedes=supersedes, ad_object_guid=ad.object_guid,
        ad_sid=ad.object_sid, ad_distinguished_name=ad.distinguished_name, ad_sam_account_name=ad.sam_account_name,
        ad_domain=ad.domain, method=method, confidence=METHOD_CONFIDENCE[method], review_status=status,
        verified_at=at, evidence_fingerprint="sha256:" + "b" * 64, decided_by=by, decided_at=at,
        reason="synthetic review",
        configuration_ref="config/synthetic.json#1" if method is MappingMethod.CONFIGURED else None,
    )
    fields.update(kw)
    return MappingReview(**fields)


# --- the record ---------------------------------------------------------------------------


class MappingReviewRecordTests(unittest.TestCase):
    def test_valid_review(self):
        r = review()
        self.assertTrue(r.registry_ref.startswith("ogwa-mapping-registry:mrev_"))
        self.assertTrue(r.same_identity(HR.object_guid, HR.object_sid))

    def test_invariants(self):
        bad = {
            "name match approved": dict(method=MappingMethod.NAME_MATCH),
            "system reviewer": dict(by=SYSTEM),
            "proposed directory pairing": dict(status=ReviewStatus.PROPOSED, method=MappingMethod.DIRECTORY_SOURCE_SID),
            "confidence not from method": dict(confidence=MappingConfidence.EXACT_STABLE_ID),
            "configured without ref": dict(method=MappingMethod.CONFIGURED, configuration_ref=None),
            "ref on another method": dict(configuration_ref="config/x.json#1"),
            "first review superseding": dict(supersedes=new_id(IdKind.MAPPING_REVIEW)),
            "later review superseding nothing": dict(sequence=1),
            "uppercase guid": dict(ad_object_guid=HR.object_guid.upper()),
            "not a SID": dict(ad_sid="S-1-x"),
            "uppercase domain": dict(ad_domain=CORP.upper()),
            "verified after decided": dict(verified_at=T + timedelta(seconds=1)),
            "bad fingerprint": dict(evidence_fingerprint="sha256:short"),
            "external okta ref": dict(okta_group_ref="00gSYNTH0001"),
        }
        for name, changes in bad.items():
            with self.subTest(name), self.assertRaises(InvalidRecord):
                review(**changes)

    def test_chain_rules(self):
        first = review(status=ReviewStatus.PROPOSED)
        good = review(status=ReviewStatus.APPROVED, sequence=1, supersedes=first.id, by=OPERATOR_2)
        self.assertEqual(review_append_problems((first,), good), [])
        problems = {
            "wrong sequence": review(sequence=2, supersedes=first.id, by=OPERATOR_2),
            "wrong parent": review(sequence=1, supersedes=new_id(IdKind.MAPPING_REVIEW), by=OPERATOR_2),
            "backdated": review(sequence=1, supersedes=first.id, by=OPERATOR_2, at=T - timedelta(seconds=1)),
            "self approval": review(sequence=1, supersedes=first.id, by=OPERATOR_1),
            "approving another object": review(sequence=1, supersedes=first.id, by=OPERATOR_2, ad=PAYROLL),
            "other group": review(2, sequence=1, supersedes=first.id, by=OPERATOR_2),
        }
        for name, candidate in problems.items():
            with self.subTest(name):
                self.assertTrue(review_append_problems((first,), candidate))
        self.assertTrue(review_append_problems((), review(status=ReviewStatus.APPROVED)))  # nothing pending

    def test_history_projections(self):
        a = review(status=ReviewStatus.PROPOSED)
        b = review(sequence=1, supersedes=a.id, by=OPERATOR_2)
        c = review(status=ReviewStatus.REJECTED, method=MappingMethod.NAME_MATCH, ad=PAYROLL, sequence=2, supersedes=b.id)
        d = review(status=ReviewStatus.REJECTED, sequence=3, supersedes=c.id)
        self.assertEqual(pending_selection((a,)), a)
        self.assertIsNone(pending_selection((a, b)))
        self.assertEqual(current_approval((a, b, c)), b)  # rejecting another object leaves the approval
        self.assertIsNone(current_approval((a, b, c, d)))
        self.assertEqual(rejected_guids((a, b, c, d)), {PAYROLL.object_guid, HR.object_guid})


# --- the service -----------------------------------------------------------------------------


class ServiceCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.directory = SyntheticDirectory([PAYROLL, FIN_CORP, FIN_EMEA, HR], clock=self.clock)
        self.registry = InMemoryMappingRegistry()
        self.service = MappingReviewService(directory=self.directory, config=config(), registry=self.registry,
                                            clock=self.clock)

    def tick(self):
        self.clock.advance(timedelta(minutes=1))


class ReviewServiceTests(ServiceCase):
    @sid_verified
    def test_exact_correlation_can_be_approved_once(self):
        okta = okta_ad_group(1, PAYROLL)
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.result.outcome, CorrelationOutcome.RESOLVED)
        self.assertIn(ReviewAction.APPROVE, inspection.allowed_actions)
        self.assertEqual(inspection.approvable_guid, PAYROLL.object_guid)
        self.tick()
        recorded = self.service.approve(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid,
                                        expected_fingerprint=inspection.evidence_fingerprint, reason="matches the SID")
        self.assertEqual((recorded.review_status, recorded.method, recorded.confidence),
                         (ReviewStatus.APPROVED, MappingMethod.DIRECTORY_SOURCE_SID, MappingConfidence.EXACT_STABLE_ID))
        self.assertEqual((recorded.ad_object_guid, recorded.ad_sid, recorded.ad_distinguished_name),
                         (PAYROLL.object_guid, PAYROLL.object_sid, PAYROLL.distinguished_name))
        self.assertEqual(recorded.evidence_fingerprint, inspection.evidence_fingerprint)
        self.assertLessEqual(recorded.verified_at, recorded.decided_at)
        again = self.service.inspect(okta)
        self.assertEqual(again.result.approval, recorded)
        self.assertNotIn(ReviewAction.APPROVE, again.allowed_actions)  # nothing new to acknowledge
        with self.assertRaises(ReviewRefused):
            self.service.approve(okta, operator=OPERATOR_2, object_guid=PAYROLL.object_guid,
                                 expected_fingerprint=again.evidence_fingerprint, reason="again")

    def test_approval_requires_the_evidence_the_operator_saw(self):
        okta = okta_ad_group(1, PAYROLL)
        seen = self.service.inspect(okta).evidence_fingerprint
        self.directory.replace(PAYROLL.object_guid,
                               distinguished_name="CN=SYNTH-App-Payroll-Users,OU=Moved,DC=corp,DC=synthetic,DC=example")
        with self.assertRaisesRegex(ReviewRefused, "changed"):
            self.service.approve(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid,
                                 expected_fingerprint=seen, reason="stale screen")
        self.assertEqual(self.registry.history(ref(1)), ())

    def test_only_humans_review(self):
        okta = okta_ad_group(1, PAYROLL)
        fp = self.service.inspect(okta).evidence_fingerprint
        for call in (
            lambda: self.service.approve(okta, operator=SYSTEM, object_guid=PAYROLL.object_guid, expected_fingerprint=fp, reason="x"),
            lambda: self.service.reject(okta, operator=SYSTEM, object_guid=PAYROLL.object_guid, expected_fingerprint=fp, reason="x"),
            lambda: self.service.search(okta, operator=SYSTEM, by=LookupKind.NAME, value="x"),
        ):
            with self.assertRaisesRegex(ReviewRefused, "human"):
                call()

    def test_name_only_cannot_be_approved(self):
        okta = okta_native_group(2, "SYNTH-App-HR")
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.result.outcome, CorrelationOutcome.REVIEW_REQUIRED)
        self.assertNotIn(ReviewAction.APPROVE, inspection.allowed_actions)
        with self.assertRaisesRegex(ReviewRefused, "NAME_ONLY"):
            self.service.approve(okta, operator=OPERATOR_1, object_guid=HR.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="looks right")
        self.assertEqual(self.registry.history(ref(2)), ())

    def test_operator_selection_needs_a_second_operator(self):
        okta = okta_native_group(3, "SYNTH-App-HR")
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-HR")
        proposal = self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid,
                                       reason="owner confirmed by ticket SYNTH-1")
        self.assertEqual((proposal.review_status, proposal.method), (ReviewStatus.PROPOSED, MappingMethod.OPERATOR_SELECTED))
        self.tick()
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.result.outcome, CorrelationOutcome.REVIEW_REQUIRED)  # not exact until approved
        self.assertEqual(inspection.approvable_guid, HR.object_guid)
        with self.assertRaisesRegex(ReviewRefused, "cannot also approve"):
            self.service.approve(okta, operator=OPERATOR_1, object_guid=HR.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="self")
        approval = self.service.approve(okta, operator=OPERATOR_2, object_guid=HR.object_guid,
                                        expected_fingerprint=inspection.evidence_fingerprint, reason="second pair of eyes")
        self.assertEqual((approval.review_status, approval.confidence),
                         (ReviewStatus.APPROVED, MappingConfidence.EXACT_CONFIGURED_MAPPING))
        result = self.service.inspect(okta).result
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        mapping = mapping_evidence(result, source=EvidenceSource.SYNTHETIC, ids=IDS).mapping
        self.assertEqual(mapping.configuration_ref, approval.registry_ref)
        self.assertTrue(mapping.is_exact)

    def test_selection_resolves_an_ambiguous_name(self):
        okta = okta_native_group(4, "SYNTH-App-Finance")
        self.assertEqual(self.service.inspect(okta).result.outcome, CorrelationOutcome.AMBIGUOUS)
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-Finance")
        self.assertEqual(len(search.lookup.candidates), 2)
        self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=FIN_EMEA.object_guid, reason="EMEA")
        self.tick()
        fp = self.service.inspect(okta).evidence_fingerprint
        self.service.approve(okta, operator=OPERATOR_2, object_guid=FIN_EMEA.object_guid, expected_fingerprint=fp,
                             reason="confirmed")
        result = self.service.inspect(okta).result
        self.assertEqual((result.outcome, result.target), (CorrelationOutcome.RESOLVED, FIN_EMEA))

    def test_selection_refusals(self):
        okta = okta_native_group(5, "SYNTH-App-HR")
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-HR")
        with self.assertRaisesRegex(ReviewRefused, "not among"):
            self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=PAYROLL.object_guid, reason="x")
        with self.assertRaisesRegex(ReviewRefused, "different Okta group"):
            self.service.select(okta_native_group(6, "x"), operator=OPERATOR_1, search=search,
                                object_guid=HR.object_guid, reason="x")
        self.directory.replace(HR.object_guid, object_sid=f"{HR.object_sid}0")
        with self.assertRaisesRegex(ReviewRefused, "changed"):
            self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid, reason="x")
        self.directory.remove(HR.object_guid)
        with self.assertRaisesRegex(ReviewRefused, "re-verified"):
            self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid, reason="x")
        self.clock.advance(timedelta(minutes=31))
        with self.assertRaisesRegex(ReviewRefused, "too old"):
            self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid, reason="x")
        with self.assertRaisesRegex(ReviewRefused, "cannot search"):
            self.service.search(okta, operator=OPERATOR_1, by="anr", value="x")
        self.assertEqual(self.registry.history(ref(5)), ())

    def test_search_is_one_bounded_lookup(self):
        okta = okta_native_group(7, "x")
        self.service.search(okta, operator=OPERATOR_1, by=LookupKind.SAM_ACCOUNT_NAME, value="SYNTH-App-Finance")
        self.assertEqual(self.directory.calls, [(LookupKind.SAM_ACCOUNT_NAME, "SYNTH-App-Finance", None)])

    @sid_verified
    def test_rejecting_the_exact_proposal_stops_auto_resolution(self):
        okta = okta_ad_group(8, PAYROLL)
        fp = self.service.inspect(okta).evidence_fingerprint
        rejection = self.service.reject(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid,
                                        expected_fingerprint=fp, reason="wrong integration")
        self.assertEqual((rejection.review_status, rejection.method),
                         (ReviewStatus.REJECTED, MappingMethod.DIRECTORY_SOURCE_SID))
        result = self.service.inspect(okta).result
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.REJECTED_PAIRING, {d.kind for d in result.drift})

    @sid_verified
    def test_rejecting_an_approval_withdraws_it(self):
        okta = okta_ad_group(9, PAYROLL)
        fp = self.service.inspect(okta).evidence_fingerprint
        self.service.approve(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid, expected_fingerprint=fp, reason="ok")
        self.tick()
        fp = self.service.inspect(okta).evidence_fingerprint
        self.service.reject(okta, operator=OPERATOR_2, object_guid=PAYROLL.object_guid, expected_fingerprint=fp,
                            reason="withdrawn")
        self.assertIsNone(current_approval(self.registry.history(ref(9))))

    def test_only_pairings_on_screen_can_be_rejected(self):
        okta = okta_native_group(10, "SYNTH-App-HR")
        fp = self.service.inspect(okta).evidence_fingerprint
        with self.assertRaisesRegex(ReviewRefused, "shown"):
            self.service.reject(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid, expected_fingerprint=fp,
                                reason="x")
        rejected = self.service.reject(okta, operator=OPERATOR_1, object_guid=HR.object_guid, expected_fingerprint=fp,
                                       reason="not the counterpart")
        self.assertEqual(rejected.method, MappingMethod.NAME_MATCH)

    @sid_verified
    def test_pending_selection_contradicting_the_directory_source_is_not_approvable(self):
        okta = okta_ad_group(11, PAYROLL)
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-HR")
        self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid, reason="x")
        self.tick()
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.approvable_guid, PAYROLL.object_guid)  # the resolved pairing, not the selection
        with self.assertRaises(ReviewRefused):
            self.service.approve(okta, operator=OPERATOR_2, object_guid=HR.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="x")

    @sid_verified
    def test_conflicts_and_stale_mappings_are_not_approvable(self):
        okta = okta_ad_group(12, PAYROLL)
        fp = self.service.inspect(okta).evidence_fingerprint
        self.service.approve(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid, expected_fingerprint=fp, reason="ok")
        self.directory.remove(PAYROLL.object_guid)
        self.tick()
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.result.outcome, CorrelationOutcome.STALE)
        self.assertNotIn(ReviewAction.APPROVE, inspection.allowed_actions)
        with self.assertRaisesRegex(ReviewRefused, "STALE"):
            self.service.approve(okta, operator=OPERATOR_2, object_guid=PAYROLL.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="x")
        # The approval is surfaced, not repaired: it stays recorded, and can be withdrawn by a human.
        self.assertEqual(len(self.registry.history(ref(12))), 1)
        self.assertIn(ReviewAction.REJECT, inspection.allowed_actions)
        self.service.reject(okta, operator=OPERATOR_2, object_guid=PAYROLL.object_guid,
                            expected_fingerprint=inspection.evidence_fingerprint, reason="AD group deleted")

    def test_drift_is_acknowledged_only_by_a_new_approval(self):
        okta = okta_native_group(13, "SYNTH-Okta-HR")
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.OBJECT_GUID, value=HR.object_guid)
        self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid, reason="x")
        self.tick()
        fp = self.service.inspect(okta).evidence_fingerprint
        first = self.service.approve(okta, operator=OPERATOR_2, object_guid=HR.object_guid, expected_fingerprint=fp,
                                     reason="ok")
        self.directory.replace(HR.object_guid, sam_account_name="SYNTH-App-HR2",
                               distinguished_name="CN=SYNTH-App-HR2,OU=Groups,DC=corp,DC=synthetic,DC=example")
        self.tick()
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual({d.kind for d in inspection.result.drift}, {DriftKind.AD_GROUP_RENAMED, DriftKind.AD_GROUP_MOVED})
        self.assertEqual(self.registry.history(ref(13))[-1], first)  # not silently repaired
        self.assertIn(ReviewAction.APPROVE, inspection.allowed_actions)
        ack = self.service.approve(okta, operator=OPERATOR_1, object_guid=HR.object_guid,
                                   expected_fingerprint=inspection.evidence_fingerprint, reason="rename acknowledged")
        self.assertEqual((ack.ad_sam_account_name, ack.supersedes), ("SYNTH-App-HR2", first.id))
        self.assertFalse(self.service.inspect(okta).result.drift)


# --- the store ---------------------------------------------------------------------------


def _okta_group_record(n: int, name: str, at) -> OktaGroup:
    prov = Provenance(source=EvidenceSource.SYNTHETIC, observed_at=at, scope="synthetic:okta",
                      collector_version="synthetic-1.0", result_status=ResultStatus.COMPLETE)
    return OktaGroup(id=ref(n), okta_group_id=f"00gSYNTH{n:04d}", name=name, group_type=OktaGroupType.OKTA_GROUP,
                     provenance=prov)


class StoreRegistryTests(unittest.TestCase):
    def setUp(self):
        self.store_clock = MutableClock(T + timedelta(days=1))
        self.store = new_store(clock=self.store_clock)
        self.addCleanup(self.store.close)
        self.store.record_evidence(_okta_group_record(1, "SYNTH-Okta-HR", T), actor=SYSTEM)
        self.clock = Clock(T + timedelta(hours=1))
        self.directory = SyntheticDirectory([HR, PAYROLL], clock=self.clock)
        self.service = MappingReviewService(directory=self.directory, config=config(),
                                            registry=StoreMappingRegistry(self.store), clock=self.clock)
        self.okta = okta_native_group(1, "SYNTH-Okta-HR")

    def select_and_approve(self):
        search = self.service.search(self.okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-HR")
        proposal = self.service.select(self.okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid,
                                       reason="selected")
        self.clock.advance(timedelta(minutes=1))
        fp = self.service.inspect(self.okta).evidence_fingerprint
        approval = self.service.approve(self.okta, operator=OPERATOR_2, object_guid=HR.object_guid,
                                        expected_fingerprint=fp, reason="approved")
        return proposal, approval

    def test_reviews_persist_with_audit_and_integrity(self):
        proposal, approval = self.select_and_approve()
        self.assertEqual(self.store.mapping_reviews(ref(1)), [proposal, approval])
        events = [e for e in self.store.audit_events() if e.action is AuditAction.MAPPING_REVIEW_RECORDED]  # D41
        self.assertEqual([dict(e.details)["review_status"] for e in events], ["PROPOSED", "APPROVED"])
        self.assertFalse([e for e in self.store.audit_events() if e.action is AuditAction.APPROVAL_RECORDED])
        self.assertEqual([e.actor for e in events], [OPERATOR_1, OPERATOR_2])
        self.assertEqual(events[1].before_ref, f"mapping_review:{proposal.id}")
        self.store.verify_integrity()
        result = self.service.inspect(self.okta).result
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)

    def test_rows_are_append_only(self):
        self.select_and_approve()
        conn = self.store.connection
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute("UPDATE mapping_reviews SET review_status = 'REJECTED'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            conn.execute("DELETE FROM mapping_reviews")

    def test_database_refuses_out_of_chain_and_self_approved_rows(self):
        proposal, approval = self.select_and_approve()
        conn = self.store.connection
        row = dict(conn.execute("SELECT * FROM mapping_reviews WHERE id = ?", (approval.id,)).fetchone())

        def insert(**changes):
            values = dict(row, id=new_id(IdKind.MAPPING_REVIEW))
            values.update(changes)
            cols = ", ".join(values)
            conn.execute(f"INSERT INTO mapping_reviews ({cols}) VALUES ({', '.join('?' for _ in values)})",
                         tuple(values.values()))
            return values["id"]

        with self.assertRaisesRegex(sqlite3.IntegrityError, "extend"):
            insert(sequence=2, supersedes=proposal.id)  # forks the chain
        with self.assertRaisesRegex(sqlite3.IntegrityError, "different approver"):
            # an operator-selected approval of an object nobody selected
            insert(sequence=2, supersedes=approval.id, ad_object_guid=PAYROLL.object_guid, ad_sid=PAYROLL.object_sid)
        reack = insert(sequence=2, supersedes=approval.id)  # re-acknowledging the same approved identity is allowed
        with self.assertRaises(sqlite3.IntegrityError):
            insert(sequence=2, supersedes=approval.id, method="NAME_MATCH", confidence="NAME_ONLY")
        with self.assertRaises(sqlite3.IntegrityError):
            insert(sequence=3, supersedes=reack, decided_by_kind="SYSTEM")
        self.assertEqual(len(self.store.mapping_reviews(ref(1))), 3)

    def test_database_refuses_self_approval_of_a_selection(self):
        search = self.service.search(self.okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-HR")
        proposal = self.service.select(self.okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid,
                                       reason="selected")
        conn = self.store.connection
        values = dict(conn.execute("SELECT * FROM mapping_reviews WHERE id = ?", (proposal.id,)).fetchone())
        values.update(id=new_id(IdKind.MAPPING_REVIEW), sequence=1, supersedes=proposal.id, review_status="APPROVED")
        sql = f"INSERT INTO mapping_reviews ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})"
        with self.assertRaisesRegex(sqlite3.IntegrityError, "different approver"):
            conn.execute(sql, tuple(values.values()))
        values.update(decided_by_id=OPERATOR_2.id)
        conn.execute(sql, tuple(values.values()))  # the same row from a second operator is accepted

    def test_store_refuses_reviews_of_unrecorded_groups_and_broken_chains(self):
        with self.assertRaisesRegex(StoreConflict, "not been recorded"):
            self.store.record_mapping_review(review(2, status=ReviewStatus.REJECTED, at=T))
        with self.assertRaisesRegex(StoreConflict, "different Okta group id"):
            self.store.record_mapping_review(review(1, status=ReviewStatus.REJECTED, okta_group_id="00gSYNTH9999"))
        with self.assertRaisesRegex(StoreConflict, "pending selection"):
            self.store.record_mapping_review(review(1, status=ReviewStatus.APPROVED))
        with self.assertRaisesRegex(StoreConflict, "future"):
            self.store.record_mapping_review(review(1, status=ReviewStatus.REJECTED, at=T + timedelta(days=30)))

    def test_emitted_mapping_needs_the_ad_group_recorded_first(self):
        self.select_and_approve()
        result = self.service.inspect(self.okta).result
        evidence = mapping_evidence(result, source=EvidenceSource.SYNTHETIC, ids=IDS)
        with self.assertRaises(StoreConflict):
            self.store.record_evidence(evidence.mapping, actor=SYSTEM)
        prov = Provenance(source=EvidenceSource.SYNTHETIC, observed_at=T + timedelta(hours=1), scope="synthetic:ad",
                          collector_version="synthetic-1.0", result_status=ResultStatus.COMPLETE)
        for guid in evidence.required_ad_object_guids:
            self.store.record_evidence(ADGroup(id=IDS.ad_group(guid), object_guid=guid, domain=CORP, exists=True,
                                               provenance=prov, sid=HR.object_sid,
                                               distinguished_name=HR.distinguished_name,
                                               sam_account_name=HR.sam_account_name), actor=SYSTEM)
        self.store.record_evidence(evidence.mapping, actor=SYSTEM)
        stored = self.store.latest(IdentityMapping, evidence.mapping.id)
        self.assertEqual(stored, evidence.mapping)
        self.assertTrue(stored.is_exact)


class MigrationContentTests(unittest.TestCase):
    def test_frozen_literals_match_the_domain(self):
        self.assertEqual(set(MAPPING_METHODS), {m.value for m in MappingMethod})
        self.assertEqual(set(REVIEW_STATUSES), {s.value for s in ReviewStatus})

    def test_postgresql_without_guards_fails_closed(self):
        from app.store.errors import MigrationError
        self.assertTrue(statements_for(v0003_mapping_registry, DIALECT_SQLITE))
        with self.assertRaisesRegex(MigrationError, "no postgresql implementation"):
            statements_for(v0003_mapping_registry, "postgresql")


# --- owner decision D37: directory-source SID is not exact while unverified -------------------------


class DirectorySourceSidGateServiceTests(ServiceCase):
    def test_directory_source_match_cannot_be_approved_directly(self):
        okta = okta_ad_group(1, PAYROLL)
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.result.outcome, CorrelationOutcome.UNVERIFIED_IDENTIFIER)  # D56
        self.assertNotIn(ReviewAction.APPROVE, inspection.allowed_actions)
        with self.assertRaisesRegex(ReviewRefused, "unverified directory-source identifier"):
            self.service.approve(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="matches the SID")
        self.assertEqual(self.registry.history(ref(1)), ())

    def test_selection_and_second_operator_make_it_exact(self):
        okta = okta_ad_group(2, PAYROLL)
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.SAM_ACCOUNT_NAME,
                                     value=PAYROLL.sam_account_name)
        self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=PAYROLL.object_guid,
                            reason="owner confirmed by ticket SYNTH-2")
        self.tick()
        inspection = self.service.inspect(okta)
        self.assertEqual(inspection.approvable_guid, PAYROLL.object_guid)
        with self.assertRaisesRegex(ReviewRefused, "cannot also approve"):
            self.service.approve(okta, operator=OPERATOR_1, object_guid=PAYROLL.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="self")
        approval = self.service.approve(okta, operator=OPERATOR_2, object_guid=PAYROLL.object_guid,
                                        expected_fingerprint=inspection.evidence_fingerprint, reason="second pair of eyes")
        self.assertEqual((approval.method, approval.confidence),
                         (MappingMethod.OPERATOR_SELECTED, MappingConfidence.EXACT_CONFIGURED_MAPPING))
        result = self.service.inspect(okta).result
        self.assertEqual((result.outcome, result.method), (CorrelationOutcome.RESOLVED, MappingMethod.OPERATOR_SELECTED))

    def test_selection_contradicting_the_directory_source_is_not_approvable(self):
        okta = okta_ad_group(3, PAYROLL)
        search = self.service.search(okta, operator=OPERATOR_1, by=LookupKind.NAME, value="SYNTH-App-HR")
        self.service.select(okta, operator=OPERATOR_1, search=search, object_guid=HR.object_guid, reason="x")
        self.tick()
        inspection = self.service.inspect(okta)
        self.assertIsNone(inspection.approvable_guid)
        with self.assertRaises(ReviewRefused):
            self.service.approve(okta, operator=OPERATOR_2, object_guid=HR.object_guid,
                                 expected_fingerprint=inspection.evidence_fingerprint, reason="x")


if __name__ == "__main__":
    unittest.main()
