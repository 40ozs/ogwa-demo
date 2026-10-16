"""Identity correlation: the case matrix. Synthetic forest only (D22); no directory is contacted.

Matrix: exact, name-only, ambiguous, stale, not-found, partial-forest, Okta metadata,
fingerprint, the AD report adapter, and static safety checks.
"""

import ast
import json
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from app.correlation import (
    ADIdentityLookup,
    BoundedLookups,
    CorrelationConfig,
    CorrelationOutcome,
    DriftKind,
    LookupStatus,
    OktaGroupIdentity,
    OktaSourceState,
    ReportBackedDirectory,
    correlate,
    identity_lookup_from_report,
    mapping_evidence,
    mapping_id_for,
)
from app.correlation import model as correlation_model
from app.correlation.model import ADIdentity, DirectorySource
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.ids import IdKind, new_id
from app.domain.mapping_review import MappingMethod, MappingReview, ReviewStatus
from app.domain.model import MappingConfidence, OktaGroupType
from app.integrations.ad.contract import ADReadRequest, LookupKind, parse_group_report
from app.integrations.ad.records import ADStableIds
from app.integrations.okta import normalize
from app.integrations.okta.models import GroupType, OktaGroupRecord
from tests.correlation_fixtures import (
    sid_verified,
    APAC,
    CORP,
    CORP_SOURCE,
    EMEA,
    EMEA_SOURCE,
    OPERATOR_1,
    OTHER_SOURCE,
    T,
    Clock,
    LimitedDirectory,
    SyntheticDirectory,
    ad_group,
    config,
    configured,
    okta_ad_group,
    okta_native_group,
    ref,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "ad"
IDS = ADStableIds(CORP)

PAYROLL = ad_group(4101, "SYNTH-App-Payroll-Users")
FIN_CORP = ad_group(4102, "SYNTH-App-Finance")
FIN_EMEA = ad_group(5102, "SYNTH-App-Finance", EMEA)
CLAIMS = ad_group(4103, "SYNTH-App-Claims")
CLAIMS_APAC = ad_group(6103, "SYNTH-App-Claims", APAC)
HR = ad_group(4105, "SYNTH-App-HR")
OTHER = ad_group(4199, "SYNTH-Unrelated")


def approved(n: int, ad: ADIdentity, *, method=MappingMethod.OPERATOR_SELECTED, okta_name: str | None = None,
             configuration_ref: str | None = None, sequence: int = 0, supersedes: str | None = None,
             status=ReviewStatus.APPROVED) -> MappingReview:
    from app.domain.mapping_review import METHOD_CONFIDENCE
    if method is MappingMethod.CONFIGURED and configuration_ref is None:
        configuration_ref = f"config/synthetic-mappings.json#group-{n}"
    return MappingReview(
        id=new_id(IdKind.MAPPING_REVIEW), okta_group_ref=ref(n), okta_group_id=f"00gSYNTH{n:04d}",
        okta_group_name=okta_name or ad.sam_account_name, sequence=sequence, supersedes=supersedes,
        ad_object_guid=ad.object_guid, ad_sid=ad.object_sid, ad_distinguished_name=ad.distinguished_name,
        ad_sam_account_name=ad.sam_account_name, ad_domain=ad.domain, method=method,
        confidence=METHOD_CONFIDENCE[method], review_status=status, verified_at=T - timedelta(days=1),
        evidence_fingerprint="sha256:" + "a" * 64, decided_by=OPERATOR_1, decided_at=T - timedelta(days=1),
        reason="synthetic approval", configuration_ref=configuration_ref,
    )


class CorrelationCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.directory = SyntheticDirectory([PAYROLL, FIN_CORP, FIN_EMEA, CLAIMS, HR, OTHER], clock=self.clock)

    def run_case(self, okta, cfg=None, history=(), directory=None):
        return correlate(okta, directory=directory or self.directory, config=cfg or config(), clock=self.clock,
                         history=history)

    def emitted(self, result, source=EvidenceSource.AD_VIA_AAP):
        return mapping_evidence(result, source=source, ids=IDS)

    def kinds(self, result):
        return {d.kind for d in result.drift}

    def assert_not_exact(self, result):
        self.assertNotEqual(result.outcome, CorrelationOutcome.RESOLVED)
        mapping = self.emitted(result).mapping
        self.assertFalse(mapping.is_exact and mapping.provenance.decision_grade,
                         "a non-resolved correlation must never emit decision-grade exact evidence")
        return mapping


# --- exact --------------------------------------------------------------------------------


class ExactCorrelationTests(CorrelationCase):
    @sid_verified
    def test_directory_source_sid_resolves_exactly(self):
        result = self.run_case(okta_ad_group(1, PAYROLL))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.method, MappingMethod.DIRECTORY_SOURCE_SID)
        self.assertEqual(result.confidence, MappingConfidence.EXACT_STABLE_ID)
        self.assertEqual(result.target, PAYROLL)
        self.assertEqual(result.okta_source, OktaSourceState.VERIFIABLE)
        self.assertEqual(set(result.matched_attributes), {"objectSid", "samAccountName", "distinguishedName"})
        self.assertEqual(self.directory.calls, [(LookupKind.OBJECT_SID, PAYROLL.object_sid, CORP)])
        evidence = self.emitted(result)
        mapping = evidence.mapping
        self.assertTrue(mapping.is_exact)
        self.assertEqual(mapping.provenance.result_status, ResultStatus.COMPLETE)
        self.assertEqual(mapping.ad_group_id, IDS.ad_group(PAYROLL.object_guid))
        self.assertEqual(mapping.okta_group_id, ref(1))
        self.assertEqual(mapping.id, mapping_id_for(ref(1)))
        self.assertEqual(evidence.required_ad_object_guids, (PAYROLL.object_guid,))

    @sid_verified
    def test_sid_lookup_is_scoped_to_the_source_domain(self):
        hr_emea = ad_group(5105, "SYNTH-App-HR", EMEA)
        self.directory.add(hr_emea)
        result = self.run_case(okta_ad_group(2, hr_emea, source=EMEA_SOURCE))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(self.directory.calls, [(LookupKind.OBJECT_SID, hr_emea.object_sid, EMEA)])

    @sid_verified
    def test_okta_dn_lagging_a_move_is_informational_when_sam_corroborates(self):
        okta = okta_ad_group(1, PAYROLL, dn="CN=SYNTH-App-Payroll-Users,OU=Old,DC=corp,DC=synthetic,DC=example")
        result = self.run_case(okta)
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(self.kinds(result), {DriftKind.OKTA_DIRECTORY_METADATA_STALE})
        self.assertFalse(result.blocking_drift)
        self.assertNotIn("distinguishedName", result.matched_attributes)

    def test_configured_mapping_resolves_and_cites_its_configuration(self):
        okta = okta_native_group(3, "SYNTH-Payroll-Okta-Name")  # Okta-mastered: no directory metadata
        result = self.run_case(okta, config(configured(3, PAYROLL)))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.method, MappingMethod.CONFIGURED)
        self.assertEqual(result.confidence, MappingConfidence.EXACT_CONFIGURED_MAPPING)
        self.assertEqual(result.configuration_ref, "config/synthetic-mappings.json#group-3")
        mapping = self.emitted(result).mapping
        self.assertEqual(mapping.provenance.source, EvidenceSource.CONFIGURED_MAPPING)
        self.assertEqual(mapping.configuration_ref, "config/synthetic-mappings.json#group-3")
        self.assertEqual(self.emitted(result, EvidenceSource.SYNTHETIC).mapping.provenance.source, EvidenceSource.SYNTHETIC)

    def test_configured_mapping_without_domain_searches_the_forest_by_guid(self):
        result = self.run_case(okta_native_group(3, "x"), config(configured(3, PAYROLL, domain=False, sid=False)))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.matched_attributes, ("objectGUID",))
        self.assertEqual(self.directory.calls, [(LookupKind.OBJECT_GUID, PAYROLL.object_guid, None)])

    def test_configured_and_directory_source_must_agree_and_configured_is_the_basis(self):
        result = self.run_case(okta_ad_group(4, PAYROLL), config(configured(4, PAYROLL)))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.method, MappingMethod.CONFIGURED)
        self.assertEqual({c.basis for c in result.claims}, {"configured", "directory-source"})

    def test_approved_operator_selection_resolves_by_its_stable_ids(self):
        okta = okta_native_group(5, "SYNTH-HR-Okta")
        review = approved(5, HR, okta_name="SYNTH-HR-Okta")
        result = self.run_case(okta, history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.method, MappingMethod.OPERATOR_SELECTED)
        self.assertEqual(result.confidence, MappingConfidence.EXACT_CONFIGURED_MAPPING)
        self.assertEqual(result.configuration_ref, review.registry_ref)
        self.assertEqual(result.approval, review)
        self.assertEqual(set(result.matched_attributes), {"objectGUID", "objectSid"})
        self.assertEqual(self.directory.calls, [(LookupKind.OBJECT_GUID, HR.object_guid, CORP)])
        mapping = self.emitted(result).mapping
        self.assertEqual(mapping.configuration_ref, review.registry_ref)
        self.assertEqual(mapping.provenance.source, EvidenceSource.CONFIGURED_MAPPING)

    @sid_verified
    def test_approval_and_directory_source_agreeing_uses_the_directory_basis(self):
        review = approved(1, PAYROLL, method=MappingMethod.DIRECTORY_SOURCE_SID)
        result = self.run_case(okta_ad_group(1, PAYROLL), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.method, MappingMethod.DIRECTORY_SOURCE_SID)
        self.assertFalse(result.drift)

    def test_okta_derived_guid_cannot_be_used_while_decoding_is_unverified(self):
        self.assertFalse(normalize.OBJECT_GUID_DECODING_VERIFIED)
        with self.assertRaisesRegex(InvalidRecord, "D30"):
            replace(okta_ad_group(1, PAYROLL), directory_object_guid=PAYROLL.object_guid)
        record = OktaGroupRecord(
            okta_group_id="00gSYNTH0001", name="SYNTH-App-Payroll-Users", group_type=GroupType.APP_GROUP,
            last_updated=None, last_membership_updated=None, source_app_id=CORP_SOURCE,
            directory_external_id="synthetic", directory_object_guid_unverified=PAYROLL.object_guid,
            directory_object_sid=PAYROLL.object_sid, sam_account_name=PAYROLL.sam_account_name,
        )
        identity = OktaGroupIdentity.from_record(record, okta_group_ref=ref(1), observed_at=T, complete=True)
        self.assertIsNone(identity.directory_object_guid)
        self.assertEqual(identity.directory_object_sid, PAYROLL.object_sid)


# --- name only ----------------------------------------------------------------------------


class NameOnlyTests(CorrelationCase):
    def test_unique_name_without_stable_id_is_name_only(self):
        result = self.run_case(okta_ad_group(10, CLAIMS, sid=None))
        self.assertEqual(result.outcome, CorrelationOutcome.REVIEW_REQUIRED)
        self.assertEqual(result.confidence, MappingConfidence.NAME_ONLY)
        self.assertEqual(result.method, MappingMethod.NAME_MATCH)
        self.assertEqual(result.okta_source, OktaSourceState.ABSENT)
        self.assertEqual(self.directory.calls, [(LookupKind.SAM_ACCOUNT_NAME, "SYNTH-App-Claims", None)])
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.NAME_ONLY)
        self.assertEqual(mapping.matched_attributes, ("samAccountName",))
        self.assertEqual(mapping.provenance.result_status, ResultStatus.COMPLETE)

    def test_okta_mastered_group_with_a_matching_ad_name_is_name_only(self):
        result = self.run_case(okta_native_group(11, "SYNTH-App-HR"))
        self.assertEqual(result.outcome, CorrelationOutcome.REVIEW_REQUIRED)
        self.assertEqual(result.okta_source, OktaSourceState.NOT_DIRECTORY)
        self.assertEqual(self.directory.calls, [(LookupKind.NAME, "SYNTH-App-HR", None)])
        self.assertEqual(self.assert_not_exact(result).matched_attributes, ("name",))

    def test_group_from_a_non_ad_source_is_name_only(self):
        okta = okta_ad_group(12, HR, source=OTHER_SOURCE)
        result = self.run_case(okta)
        self.assertEqual(result.okta_source, OktaSourceState.UNCONFIGURED_SOURCE)
        self.assertEqual(result.outcome, CorrelationOutcome.REVIEW_REQUIRED)
        self.assert_not_exact(result)

    def test_sid_without_any_corroborating_name_is_not_a_stable_basis(self):
        okta = okta_ad_group(13, HR, sam=None, dn=None, qualified=None)
        result = self.run_case(okta)
        self.assertEqual(result.okta_source, OktaSourceState.ABSENT)
        self.assertEqual(result.outcome, CorrelationOutcome.REVIEW_REQUIRED)
        self.assertNotIn((LookupKind.OBJECT_SID, HR.object_sid, CORP), self.directory.calls)

    def test_rejected_name_candidate_is_not_offered_again(self):
        rejected = approved(10, CLAIMS, method=MappingMethod.NAME_MATCH, status=ReviewStatus.REJECTED)
        result = self.run_case(okta_ad_group(10, CLAIMS, sid=None), history=(rejected,))
        self.assertEqual(result.outcome, CorrelationOutcome.NOT_FOUND)
        self.assertEqual(result.previously_rejected, (CLAIMS.object_guid,))
        self.assertEqual(self.emitted(result).mapping.confidence, MappingConfidence.NOT_FOUND)


# --- ambiguous ----------------------------------------------------------------------------


class AmbiguousTests(CorrelationCase):
    def test_duplicate_names_across_domains_are_ambiguous(self):
        result = self.run_case(okta_ad_group(20, FIN_CORP, sid=None))
        self.assertEqual(result.outcome, CorrelationOutcome.AMBIGUOUS)
        self.assertIn(DriftKind.DUPLICATE_CANDIDATES, self.kinds(result))
        self.assertEqual({c.object_guid for c in result.candidates}, {FIN_CORP.object_guid, FIN_EMEA.object_guid})
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.AMBIGUOUS)
        self.assertEqual(set(mapping.candidate_ad_group_ids),
                         {IDS.ad_group(FIN_CORP.object_guid), IDS.ad_group(FIN_EMEA.object_guid)})
        self.assertEqual(mapping.provenance.result_status, ResultStatus.COMPLETE)

    def test_duplicates_with_an_unreachable_domain_are_ambiguous_but_partial(self):
        self.directory.add(CLAIMS_APAC, ad_group(5103, "SYNTH-App-Claims", EMEA))
        self.directory.unreachable = {APAC}
        result = self.run_case(okta_ad_group(21, CLAIMS, sid=None))
        self.assertEqual(result.outcome, CorrelationOutcome.AMBIGUOUS)
        self.assertEqual(self.emitted(result).mapping.provenance.result_status, ResultStatus.PARTIAL)

    def test_truncated_candidate_list_is_partial(self):
        groups = [ad_group(7000 + i, "SYNTH-Common", d) for i, d in enumerate((CORP, EMEA, APAC))]
        directory = LimitedDirectory(groups, clock=self.clock, limit=2)
        result = self.run_case(okta_native_group(22, "SYNTH-Common"), directory=directory)
        self.assertEqual(result.outcome, CorrelationOutcome.AMBIGUOUS)
        self.assertIn("truncated", next(d.detail for d in result.drift if d.kind is DriftKind.DUPLICATE_CANDIDATES))
        self.assertEqual(self.emitted(result).mapping.provenance.result_status, ResultStatus.PARTIAL)

    def test_configured_and_directory_source_disagreeing_is_a_conflict(self):
        result = self.run_case(okta_ad_group(23, PAYROLL), config(configured(23, HR)))
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.SOURCE_CONFLICT, self.kinds(result))
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.AMBIGUOUS)
        self.assertEqual(mapping.provenance.result_status, ResultStatus.FAILED)

    def test_rejected_pairing_is_never_auto_resolved(self):
        rejection = approved(24, PAYROLL, method=MappingMethod.DIRECTORY_SOURCE_SID, status=ReviewStatus.REJECTED)
        result = self.run_case(okta_ad_group(24, PAYROLL), history=(rejection,))
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.REJECTED_PAIRING, self.kinds(result))
        self.assert_not_exact(result)


# --- stale --------------------------------------------------------------------------------


class StaleMappingTests(CorrelationCase):
    def test_deleted_ad_group_makes_an_approval_unresolvable(self):
        review = approved(30, HR)
        self.directory.remove(HR.object_guid)
        result = self.run_case(okta_native_group(30, "SYNTH-App-HR"), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.STALE)
        self.assertIn(DriftKind.MAPPING_UNRESOLVABLE, self.kinds(result))
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.NOT_FOUND)
        self.assertEqual(mapping.provenance.result_status, ResultStatus.COMPLETE)

    def test_guid_with_a_different_sid_is_a_mismatch(self):
        review = approved(31, HR)
        self.directory.replace(HR.object_guid, object_sid=f"{HR.object_sid[:-4]}9999")
        result = self.run_case(okta_native_group(31, "SYNTH-App-HR"), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.STALE)
        self.assertIn(DriftKind.AD_SID_MISMATCH, self.kinds(result))
        self.assertEqual(self.assert_not_exact(result).provenance.result_status, ResultStatus.FAILED)

    def test_mapped_sid_now_pointing_at_another_object_is_detected(self):
        review = approved(32, HR)
        self.directory.remove(HR.object_guid)
        impostor = replace(OTHER, object_guid="5e7e7000-0000-4000-8000-000000009999", object_sid=HR.object_sid)
        self.directory.remove(OTHER.object_guid)
        self.directory.add(impostor)
        result = self.run_case(okta_native_group(32, "SYNTH-App-HR"), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.STALE)
        self.assertIn(DriftKind.IDENTITY_REASSIGNED, self.kinds(result))
        self.assertIsNone(result.target)
        self.assert_not_exact(result)

    def test_group_moved_to_another_domain_is_stale(self):
        review = approved(33, HR)
        moved = replace(HR, domain=EMEA, object_sid=f"{ad_group(1, 'x', EMEA).object_sid[:-2]}-5333",
                        distinguished_name="CN=SYNTH-App-HR,OU=Groups,DC=emea,DC=corp,DC=synthetic,DC=example")
        self.directory.remove(HR.object_guid)
        self.directory.add(moved)
        result = self.run_case(okta_native_group(33, "SYNTH-App-HR"), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.STALE)
        self.assertIn(DriftKind.AD_GROUP_CHANGED_DOMAIN, self.kinds(result))
        self.assertIn((LookupKind.OBJECT_GUID, HR.object_guid, None), self.directory.calls)
        self.assert_not_exact(result)

    def test_configured_guid_that_no_longer_resolves_is_stale(self):
        self.directory.remove(PAYROLL.object_guid)
        result = self.run_case(okta_native_group(34, "x"), config(configured(34, PAYROLL)))
        self.assertEqual(result.outcome, CorrelationOutcome.STALE)
        self.assert_not_exact(result)

    def test_okta_sid_that_does_not_resolve_is_stale(self):
        self.directory.remove(PAYROLL.object_guid)
        result = self.run_case(okta_ad_group(35, PAYROLL))
        self.assertEqual(result.outcome, CorrelationOutcome.STALE)
        self.assertIn(DriftKind.MAPPING_UNRESOLVABLE, self.kinds(result))

    def test_ad_rename_and_move_are_surfaced_not_repaired(self):
        review = approved(36, HR)
        history = (review,)
        self.directory.replace(HR.object_guid, sam_account_name="SYNTH-App-HR-Renamed",
                               distinguished_name="CN=SYNTH-App-HR-Renamed,OU=Archive,DC=corp,DC=synthetic,DC=example")
        result = self.run_case(okta_native_group(36, "SYNTH-App-HR"), history=history)
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)  # same GUID and SID: same object
        self.assertEqual(self.kinds(result), {DriftKind.AD_GROUP_RENAMED, DriftKind.AD_GROUP_MOVED})
        self.assertFalse(result.blocking_drift)
        self.assertEqual(result.approval.ad_sam_account_name, "SYNTH-App-HR")  # the stored record is untouched
        self.assertEqual(result.target.sam_account_name, "SYNTH-App-HR-Renamed")

    def test_okta_rename_is_surfaced(self):
        result = self.run_case(okta_native_group(37, "SYNTH-HR-New-Name"), history=(approved(37, HR, okta_name="SYNTH-HR"),))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(self.kinds(result), {DriftKind.OKTA_GROUP_RENAMED})

    def test_directory_approval_without_okta_metadata_is_a_conflict(self):
        review = approved(38, PAYROLL, method=MappingMethod.DIRECTORY_SOURCE_SID)
        result = self.run_case(okta_ad_group(38, PAYROLL, sid=None), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.OKTA_SOURCE_CHANGED, self.kinds(result))
        self.assert_not_exact(result)

    def test_approved_configuration_that_was_removed_is_a_conflict(self):
        review = approved(39, PAYROLL, method=MappingMethod.CONFIGURED)
        result = self.run_case(okta_native_group(39, "x"), config(), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.CONFIGURATION_REMOVED, self.kinds(result))

    def test_prior_approval_conflicting_with_current_okta_identity_is_a_conflict(self):
        review = approved(40, HR)  # approved HR earlier ...
        result = self.run_case(okta_ad_group(40, PAYROLL), history=(review,))  # ... Okta now carries PAYROLL's SID
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.SOURCE_CONFLICT, self.kinds(result))
        self.assertEqual({c.object_guid for c in result.candidates}, {HR.object_guid, PAYROLL.object_guid})
        self.assertEqual(self.assert_not_exact(result).confidence, MappingConfidence.AMBIGUOUS)

    def test_withdrawn_approval_no_longer_resolves(self):
        first = approved(41, HR)
        withdrawn = approved(41, HR, status=ReviewStatus.REJECTED, sequence=1, supersedes=first.id)
        result = self.run_case(okta_native_group(41, "SYNTH-Okta-Only-Name"), history=(first, withdrawn))
        self.assertIsNone(result.approval)
        self.assertEqual(result.outcome, CorrelationOutcome.NOT_FOUND)


# --- not found ----------------------------------------------------------------------------


class NotFoundTests(CorrelationCase):
    def test_no_ad_group_anywhere(self):
        result = self.run_case(okta_native_group(50, "SYNTH-Okta-Only"))
        self.assertEqual(result.outcome, CorrelationOutcome.NOT_FOUND)
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.NOT_FOUND)
        self.assertEqual(mapping.provenance.result_status, ResultStatus.COMPLETE)
        self.assertEqual(mapping.candidate_ad_group_ids, ())

    def test_built_in_group_is_not_looked_up(self):
        result = self.run_case(okta_native_group(51, "Everyone", group_type=OktaGroupType.BUILT_IN))
        self.assertEqual(result.outcome, CorrelationOutcome.NOT_FOUND)
        self.assertEqual(result.okta_source, OktaSourceState.BUILT_IN)
        self.assertEqual(self.directory.calls, [])


# --- partial forest and failures -------------------------------------------------------------


class PartialForestTests(CorrelationCase):
    def test_single_name_match_with_an_unreachable_domain_is_incomplete(self):
        self.directory.unreachable = {APAC}
        result = self.run_case(okta_ad_group(60, CLAIMS, sid=None))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
        self.assertTrue(any(APAC in r for r in result.reasons))
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.NOT_FOUND)
        self.assertEqual(mapping.provenance.result_status, ResultStatus.PARTIAL)

    def test_no_name_match_with_an_unreachable_domain_is_not_not_found(self):
        self.directory.unreachable = {EMEA}
        result = self.run_case(okta_native_group(61, "SYNTH-Okta-Only"))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
        self.assertEqual(self.emitted(result).mapping.provenance.result_status, ResultStatus.PARTIAL)

    def test_unreachable_source_domain_blocks_sid_resolution(self):
        self.directory.unreachable = {CORP}
        result = self.run_case(okta_ad_group(62, PAYROLL))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
        self.assert_not_exact(result)

    def test_vanished_group_with_unsearchable_domains_is_incomplete_not_stale(self):
        review = approved(63, HR)
        self.directory.remove(HR.object_guid)
        self.directory.unreachable = {APAC}
        result = self.run_case(okta_native_group(63, "SYNTH-App-HR"), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
        self.assertNotIn(DriftKind.MAPPING_UNRESOLVABLE, self.kinds(result))

    def test_failed_domain_is_incomplete(self):
        self.directory.failing = {CORP}
        result = self.run_case(okta_ad_group(64, PAYROLL))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)

    def test_incomplete_okta_observation_never_resolves(self):
        result = self.run_case(okta_ad_group(65, PAYROLL, complete=False))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
        self.assertEqual(self.emitted(result).mapping.provenance.result_status, ResultStatus.PARTIAL)

    def test_lookup_budget_is_enforced(self):
        result = self.run_case(okta_ad_group(66, PAYROLL), config(configured(66, PAYROLL), max_lookups=1))
        self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
        self.assertEqual(len(self.directory.calls), 1)
        self.assertTrue(any("budget" in r for r in result.reasons))

    def test_raising_or_misanswering_directory_is_a_failed_lookup(self):
        class Raising:
            def lookup(self, by, value, domain):
                raise RuntimeError("synthetic transport failure")

        class Misanswering:
            def lookup(self, by, value, domain):
                return ADIdentityLookup(by=LookupKind.OBJECT_SID, value=OTHER.object_sid, domain=CORP,
                                        status=LookupStatus.RESOLVED, observed_at=T, candidates=(OTHER,))

        for directory in (Raising(), Misanswering()):
            with self.subTest(directory=type(directory).__name__):
                result = self.run_case(okta_ad_group(67, PAYROLL), directory=directory)
                self.assertEqual(result.outcome, CorrelationOutcome.INCOMPLETE)
                self.assertEqual(result.lookups[0].status, LookupStatus.FAILED)

    def test_bounded_lookups_cache_and_cap(self):
        bounded = BoundedLookups(self.directory, max_lookups=2, clock=self.clock)
        first = bounded.lookup(LookupKind.OBJECT_GUID, PAYROLL.object_guid, CORP)
        self.assertIs(bounded.lookup(LookupKind.OBJECT_GUID, PAYROLL.object_guid.upper(), CORP), first)
        bounded.lookup(LookupKind.OBJECT_GUID, HR.object_guid, CORP)
        refused = bounded.lookup(LookupKind.OBJECT_GUID, OTHER.object_guid, CORP)
        self.assertEqual(refused.status, LookupStatus.FAILED)
        self.assertEqual((bounded.performed, bounded.refused, len(self.directory.calls)), (2, 1, 2))


# --- Okta metadata --------------------------------------------------------------------------


class OktaMetadataTests(CorrelationCase):
    def assert_inconsistent(self, okta, fragment):
        result = self.run_case(okta)
        self.assertEqual(result.okta_source, OktaSourceState.INCONSISTENT)
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertTrue(any(fragment in d.detail for d in result.drift if d.kind is DriftKind.OKTA_METADATA_INCONSISTENT),
                        [d.detail for d in result.drift])
        self.assert_not_exact(result)

    def test_dn_outside_the_source_domain(self):
        self.assert_inconsistent(okta_ad_group(70, PAYROLL, source=EMEA_SOURCE, qualified=None), "DN is in")

    def test_qualified_name_disagrees_with_sam(self):
        self.assert_inconsistent(okta_ad_group(71, PAYROLL, qualified="SYNTHCORP\\SYNTH-Other"), "disagree")

    def test_qualified_name_in_another_netbios_domain(self):
        self.assert_inconsistent(okta_ad_group(72, PAYROLL, qualified="SYNTHEMEA\\SYNTH-App-Payroll-Users"), "domain")

    def test_malformed_qualified_name(self):
        self.assert_inconsistent(okta_ad_group(73, PAYROLL, qualified="no-backslash"), "DOMAIN\\name")

    def test_identifier_without_source_integration(self):
        self.assert_inconsistent(okta_ad_group(74, PAYROLL, source=None), "no source integration")

    def test_builtin_sid(self):
        self.assert_inconsistent(okta_ad_group(75, PAYROLL, sid="S-1-5-32-544"), "builtin")

    def test_sid_resolving_to_an_object_with_other_names(self):
        okta = okta_ad_group(76, PAYROLL, sid=HR.object_sid)  # Okta's names say PAYROLL, its SID says HR
        result = self.run_case(okta)
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)
        self.assertIn(DriftKind.OKTA_METADATA_INCONSISTENT, self.kinds(result))
        self.assert_not_exact(result)

    def test_inconsistent_metadata_blocks_even_a_configured_mapping(self):
        okta = okta_ad_group(77, PAYROLL, qualified="SYNTHCORP\\SYNTH-Other")
        result = self.run_case(okta, config(configured(77, PAYROLL)))
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)


# --- fingerprint ----------------------------------------------------------------------------


class FingerprintTests(CorrelationCase):
    def test_reobserving_identical_facts_keeps_the_fingerprint(self):
        first = self.run_case(okta_ad_group(80, PAYROLL)).evidence_fingerprint
        self.clock.advance(timedelta(hours=3))
        okta = okta_ad_group(80, PAYROLL, observed_at=T + timedelta(hours=3))
        self.assertEqual(self.run_case(okta).evidence_fingerprint, first)

    def test_material_changes_change_the_fingerprint(self):
        base = self.run_case(okta_ad_group(81, PAYROLL)).evidence_fingerprint
        renamed_okta = self.run_case(okta_ad_group(81, PAYROLL, name="SYNTH-Renamed")).evidence_fingerprint
        self.directory.replace(PAYROLL.object_guid,
                               distinguished_name="CN=SYNTH-App-Payroll-Users,OU=Moved,DC=corp,DC=synthetic,DC=example")
        moved_ad = self.run_case(okta_ad_group(81, PAYROLL)).evidence_fingerprint
        self.assertEqual(len({base, renamed_okta, moved_ad}), 3)


# --- evidence emission ----------------------------------------------------------------------


class EmissionTests(CorrelationCase):
    def test_every_outcome_supersedes_with_the_same_mapping_id(self):
        okta = okta_ad_group(90, PAYROLL)
        resolved = self.emitted(self.run_case(okta)).mapping
        self.directory.unreachable = {CORP}
        incomplete = self.emitted(self.run_case(okta)).mapping
        self.assertEqual(resolved.id, incomplete.id)
        self.assertNotEqual(resolved.digest, incomplete.digest)

    def test_evidence_is_as_old_as_its_oldest_input(self):
        okta = okta_ad_group(91, PAYROLL, observed_at=T - timedelta(days=2))
        mapping = self.emitted(self.run_case(okta)).mapping
        self.assertEqual(mapping.provenance.observed_at, T - timedelta(days=2))

    def test_only_real_or_synthetic_sources(self):
        with self.assertRaises(ValueError):
            mapping_evidence(self.run_case(okta_ad_group(92, PAYROLL)), source=EvidenceSource.OKTA_API, ids=IDS)

    def test_reason_is_bounded(self):
        many = [ad_group(8000 + i, "SYNTH-Common", (CORP, EMEA, APAC)[i % 3]) for i in range(12)]
        directory = SyntheticDirectory(many, clock=self.clock)
        mapping = self.emitted(self.run_case(okta_native_group(93, "SYNTH-Common"), directory=directory)).mapping
        self.assertLessEqual(len(mapping.reason), 2000)


# --- configuration ----------------------------------------------------------------------------


class ConfigurationTests(unittest.TestCase):
    def test_strict_json_shape(self):
        cfg = CorrelationConfig.from_mapping({
            "directorySources": [{"oktaAppId": CORP_SOURCE, "domain": CORP, "netbiosName": "SYNTHCORP"}],
            "configuredMappings": [{"oktaGroupId": "00gSYNTH0001", "adObjectGuid": PAYROLL.object_guid,
                                    "configurationRef": "config/synthetic.json#1"}],
            "maxLookups": 6,
        })
        self.assertEqual(cfg.source(CORP_SOURCE).domain, CORP)
        self.assertEqual(cfg.configured("00gSYNTH0001").ad_object_guid, PAYROLL.object_guid)
        self.assertEqual(cfg.max_lookups, 6)

    def test_refusals(self):
        entry = {"oktaGroupId": "00gSYNTH0001", "adObjectGuid": PAYROLL.object_guid, "configurationRef": "c#1"}
        bad = {
            "unknown key": {"surprise": 1},
            "unknown entry key": {"configuredMappings": [dict(entry, extra=1)]},
            "missing ref": {"configuredMappings": [{"oktaGroupId": "00gSYNTH0001", "adObjectGuid": PAYROLL.object_guid}]},
            "duplicate group": {"configuredMappings": [entry, entry]},
            "uppercase guid": {"configuredMappings": [dict(entry, adObjectGuid=PAYROLL.object_guid.upper())]},
            "bad domain": {"directorySources": [{"oktaAppId": CORP_SOURCE, "domain": "Not A Domain"}]},
            "duplicate source": {"directorySources": [{"oktaAppId": CORP_SOURCE, "domain": CORP}] * 2},
            "budget too high": {"maxLookups": 100},
            "candidates too high": {"maxCandidates": 26},
        }
        for name, data in bad.items():
            with self.subTest(name), self.assertRaises(InvalidRecord):
                CorrelationConfig.from_mapping(data)
        with self.assertRaises(InvalidRecord):
            DirectorySource(okta_app_id="has spaces", domain=CORP)


# --- AD report adapter -----------------------------------------------------------------------


def _fixture(name: str) -> str:
    return (FIXTURES / f"{name}.json").read_text(encoding="utf-8")


class ReportAdapterTests(unittest.TestCase):
    def test_golden_reports_map_to_identity_lookups(self):
        cases = {
            "unique-group": (LookupStatus.RESOLVED, True, 1),
            "ambiguous-name": (LookupStatus.AMBIGUOUS, True, None),
            "not-found": (LookupStatus.NOT_FOUND, True, 0),
            "unreachable-domain": (LookupStatus.INCOMPLETE, False, 1),
            # The worker calls this Resolved (objectGUID is forest-unique); correlation is stricter.
            "resolved-with-unreachable-parent-domain": (LookupStatus.RESOLVED, False, 1),
        }
        for name, (status, complete, count) in cases.items():
            with self.subTest(name):
                lookup = identity_lookup_from_report(parse_group_report(_fixture(name)))
                self.assertEqual(lookup.status, status)
                self.assertEqual(lookup.complete, complete)
                if count is not None:
                    self.assertEqual(len(lookup.candidates), count)

    def test_report_backed_directory_sends_identity_only_requests(self):
        sent = []

        def worker(request_json):
            sent.append(json.loads(request_json))
            return _fixture("unique-group")

        directory = ReportBackedDirectory(worker, clock=Clock(), max_candidates=7)
        lookup = directory.lookup(LookupKind.OBJECT_GUID, "5e7e7000-0000-4000-8000-000000104101", None)
        self.assertEqual(lookup.status, LookupStatus.RESOLVED)
        request = ADReadRequest.from_payload(sent[0])
        self.assertFalse(any((request.include_direct_members, request.include_nested_members,
                              request.include_primary_group_references, request.include_member_of)))
        self.assertEqual(request.limits["maxAmbiguousCandidates"], 7)

    def test_unusable_answers_are_failed_lookups(self):
        clock = Clock()
        guid = "5e7e7000-0000-4000-8000-000000104101"
        cases = {
            "answers another lookup": lambda _: _fixture("not-found"),
            "not json": lambda _: "{",
            "transport error": lambda _: (_ for _ in ()).throw(OSError("synthetic")),
        }
        for name, worker in cases.items():
            with self.subTest(name):
                lookup = ReportBackedDirectory(worker, clock=clock).lookup(LookupKind.OBJECT_GUID, guid, None)
                self.assertEqual(lookup.status, LookupStatus.FAILED)
        called = []
        lookup = ReportBackedDirectory(lambda r: called.append(r) or "", clock=clock).lookup(
            LookupKind.NAME, "bad\x00name", None)
        self.assertEqual((lookup.status, called), (LookupStatus.FAILED, []))

    def test_correlation_over_worker_reports(self):
        clock = Clock()
        directory = ReportBackedDirectory(lambda _: _fixture("unique-group"), clock=clock)
        target = ADIdentity(object_guid="5e7e7000-0000-4000-8000-000000104101",
                            object_sid="S-1-5-21-1000000001-1000000002-1000000003-4101",
                            distinguished_name="CN=SYNTH-App-Payroll-Users,OU=Groups,DC=corp,DC=synthetic,DC=example",
                            sam_account_name="SYNTH-App-Payroll-Users", domain=CORP)
        result = correlate(okta_native_group(95, "x"), directory=directory,
                           config=config(configured(95, target, sid=False, domain=False)), clock=clock)
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.target, target)


# --- static safety ----------------------------------------------------------------------------


class CorrelationSafetyTests(unittest.TestCase):
    FORBIDDEN_MODULES = ("urllib", "http", "socket", "subprocess", "requests", "ssl")

    def test_correlation_package_has_no_network_or_process_access(self):
        for path in sorted((REPO_ROOT / "app" / "correlation").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    with self.subTest(file=path.name, module=name):
                        self.assertFalse(any(name == m or name.startswith(m + ".") for m in self.FORBIDDEN_MODULES))

    def test_correlation_never_reports_an_exact_result_from_a_name(self):
        clock = Clock()
        groups = [ad_group(9000 + i, f"SYNTH-N{i}") for i in range(5)]
        directory = SyntheticDirectory(groups, clock=clock)
        for i, group in enumerate(groups):
            for okta in (okta_native_group(100 + i, group.sam_account_name), okta_ad_group(200 + i, group, sid=None)):
                result = correlate(okta, directory=directory, config=config(), clock=clock)
                self.assertNotIn(result.confidence, {MappingConfidence.EXACT_STABLE_ID,
                                                     MappingConfidence.EXACT_CONFIGURED_MAPPING,
                                                     MappingConfidence.EXACT_DIRECTORY_SOURCE})

    def test_history_of_another_group_is_refused(self):
        clock = Clock()
        with self.assertRaises(InvalidRecord):
            correlate(okta_native_group(1, "x"), directory=SyntheticDirectory(clock=clock), config=config(),
                      clock=clock, history=(approved(2, HR),))


# --- owner decision D37: directory-source SID is not exact while unverified -------------------------


class DirectorySourceSidGateTests(CorrelationCase):
    def test_gate_is_off_until_p11(self):
        # Pinned like OBJECT_GUID_DECODING_VERIFIED: changing it is a reviewed source change.
        self.assertFalse(correlation_model.DIRECTORY_SOURCE_SID_VERIFIED)

    def test_directory_source_sid_alone_is_unverified_and_not_exact(self):
        # D56: reported as an unverified stable identifier, never as a name match.
        result = self.run_case(okta_ad_group(1, PAYROLL))
        self.assertEqual(result.outcome, CorrelationOutcome.UNVERIFIED_IDENTIFIER)
        self.assertEqual(result.confidence, MappingConfidence.UNVERIFIED_STABLE_ID)
        self.assertEqual(result.method, MappingMethod.DIRECTORY_SOURCE_SID)
        self.assertEqual(result.target, PAYROLL)
        self.assertEqual(set(result.matched_attributes), {"objectSid", "samAccountName", "distinguishedName"})
        self.assertTrue(result.reasons[0].startswith("UNVERIFIED_IDENTIFIER"))
        self.assertIn("D37", result.reasons[0])
        mapping = self.assert_not_exact(result)
        self.assertEqual(mapping.confidence, MappingConfidence.UNVERIFIED_STABLE_ID)
        self.assertNotEqual(mapping.confidence, MappingConfidence.NAME_ONLY)
        self.assertEqual(mapping.provenance.result_status, ResultStatus.COMPLETE)
        self.assertEqual(mapping.ad_group_id, IDS.ad_group(PAYROLL.object_guid))

    def test_operator_selected_approval_stays_exact_with_directory_corroboration(self):
        # D38: an operator selection approved by a different operator is exact; the
        # directory-source SID agrees but is not the basis.
        result = self.run_case(okta_ad_group(1, PAYROLL), history=(approved(1, PAYROLL),))
        self.assertEqual(result.outcome, CorrelationOutcome.RESOLVED)
        self.assertEqual(result.method, MappingMethod.OPERATOR_SELECTED)
        self.assertEqual(result.confidence, MappingConfidence.EXACT_CONFIGURED_MAPPING)
        self.assertEqual({c.basis for c in result.claims}, {"directory-source", "approved-review"})

    def test_configured_mapping_stays_exact_with_directory_corroboration(self):
        result = self.run_case(okta_ad_group(4, PAYROLL), config(configured(4, PAYROLL)))
        self.assertEqual((result.outcome, result.method), (CorrelationOutcome.RESOLVED, MappingMethod.CONFIGURED))

    def test_an_earlier_directory_source_approval_is_not_a_basis(self):
        review = approved(1, PAYROLL, method=MappingMethod.DIRECTORY_SOURCE_SID)
        result = self.run_case(okta_ad_group(1, PAYROLL), history=(review,))
        self.assertEqual(result.outcome, CorrelationOutcome.UNVERIFIED_IDENTIFIER)
        self.assert_not_exact(result)
        alone = self.run_case(okta_native_group(1, "SYNTH-Payroll-Okta"), history=(review,))
        self.assert_not_exact(alone)

    def test_disagreement_is_still_a_conflict(self):
        result = self.run_case(okta_ad_group(4, PAYROLL), config(configured(4, HR)))
        self.assertEqual(result.outcome, CorrelationOutcome.CONFLICT)


if __name__ == "__main__":
    unittest.main()
