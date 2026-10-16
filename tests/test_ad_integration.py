"""The AD report contract: parsing, emptiness, protection, and domain evidence.

Every report here is a golden fixture in tests/fixtures/ad: a synthetic AD reader report in
the contract's strict JSON form. This build includes no AD reader, and nothing here contacts
a directory.
"""

import copy
import dataclasses
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from app.core.modes import ExecutionMode
from app.domain.collection import CollectorErrorCode
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.model import DependencyCoverage, DependencyKind, assess_dependency_coverage
from app.integrations.ad import (
    ADProtectionPolicy,
    ADReadRequest,
    ADStableIds,
    ContractError,
    DomainProtectionPolicy,
    EmptinessVerdict,
    Fact,
    LookupKind,
    ProtectionStatus,
    ResolutionStatus,
    SectionStatus,
    ad_evidence,
    assess_emptiness,
    assess_protection,
    collector_result,
    evidence_source_for_mode,
    parse_group_report,
)
from app.integrations.ad import contract, records

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "ad"

CORP = "corp.synthetic.example"
EMEA = "emea.corp.synthetic.example"
APAC = "apac.corp.synthetic.example"
AD_KINDS = frozenset({DependencyKind.AD_GROUP_MEMBERS, DependencyKind.AD_NESTED_MEMBERSHIP})
SCENARIOS = (
    "unique-group",
    "ambiguous-name",
    "not-found",
    "unreachable-domain",
    "nested-group",
    "primary-group-dependency",
    "protected-group",
    "normal-empty-group",
    "resolved-with-unreachable-parent-domain",
)


def payload(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def report(name: str, mutate=None):
    data = payload(name)
    if mutate is not None:
        mutate(data)
    return parse_group_report(json.dumps(data))


def policy(**overrides) -> ADProtectionPolicy:
    governed = {CORP: DomainProtectionPolicy(retirement_allowed=True), EMEA: DomainProtectionPolicy(retirement_allowed=True)}
    return ADProtectionPolicy(governed_domains=overrides.pop("governed_domains", governed), **overrides)


def evidence(name: str, mutate=None, *, protection_policy=None):
    r = report(name, mutate)
    return r, ad_evidence(r, policy=protection_policy or policy(), source=EvidenceSource.SYNTHETIC, ids=ADStableIds(CORP))


class ContractConstantTests(unittest.TestCase):
    def test_every_scenario_has_a_golden_fixture_and_nothing_else_is_there(self):
        self.assertEqual(sorted(p.stem for p in FIXTURES.glob("*.json")), sorted(SCENARIOS))


class ReportParsingTests(unittest.TestCase):
    def test_every_fixture_parses(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                r = report(name)
                self.assertEqual(r.observed_at, datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc))
                self.assertEqual(r.forest_name, CORP)

    def _assert_refused(self, mutate, fragment=""):
        with self.assertRaises(ContractError) as caught:
            report("unique-group", mutate)
        self.assertIn(fragment, str(caught.exception))

    def test_unknown_or_missing_keys_are_refused_at_every_level(self):
        self._assert_refused(lambda d: d.update(extra=1), "unexpected keys")
        self._assert_refused(lambda d: d.pop("memberOf"), "missing keys")
        self._assert_refused(lambda d: d["group"].update(isEmpty=True), "unexpected keys")
        self._assert_refused(lambda d: d["directMembers"]["byClass"].update(printer=1), "unexpected keys")
        self._assert_refused(lambda d: d["resolution"]["candidates"][0].pop("domain"), "missing keys")

    def test_a_report_that_is_not_read_only_is_refused(self):
        self._assert_refused(lambda d: d["worker"].update(readOnly=False), "readOnly")
        self._assert_refused(lambda d: d["worker"].pop("readOnly"), "missing keys")

    def test_other_schemas_workers_and_versions_are_refused(self):
        self._assert_refused(lambda d: d.update(schema="ogwa.ad.group-report/v2"), "schema")
        self._assert_refused(lambda d: d["worker"].update(name="Other.Reader"), "worker.name")
        self._assert_refused(lambda d: d["worker"].update(version="9.9.9"), "unsupported worker version")

    def test_identifiers_must_be_well_formed(self):
        self._assert_refused(lambda d: d["group"].update(objectGUID=d["group"]["objectGUID"].upper()), "canonical")
        self._assert_refused(lambda d: d["group"].update(objectSid="S-1-5-21-x"), "SID")
        self._assert_refused(lambda d: d["group"].update(rid=4102), "does not match")
        self._assert_refused(lambda d: d["group"].update(builtinDomain=True), "builtinDomain")
        self._assert_refused(lambda d: d["group"].update(domain="CORP.synthetic.example"), "lowercase")

    def test_types_and_values_must_match(self):
        self._assert_refused(lambda d: d["directMembers"].update(count=-1), "non-negative")
        self._assert_refused(lambda d: d["directMembers"].update(count="2"), "non-negative")
        self._assert_refused(lambda d: d["directMembers"].update(status="Done"), "unknown value")
        self._assert_refused(lambda d: d["group"].update(isCriticalSystemObject=0), "true or false")
        self._assert_refused(lambda d: d["group"].update(groupScope="Local"), "groupScope")
        self._assert_refused(lambda d: d.update(observedAt="2026-10-04 12:00"), "timestamp")
        self._assert_refused(lambda d: d["protection"].update(indicators=["Trusted"]), "unknown indicator")
        self._assert_refused(lambda d: d["resolution"].update(error="x" * 301), "300")

    def test_resolution_and_group_must_agree(self):
        self._assert_refused(lambda d: d.update(group=None), "must include the group")
        with self.assertRaises(ContractError):
            report("not-found", lambda d: d.update(group=payload("unique-group")["group"]))

    def test_request_echo_must_be_normalized(self):
        self._assert_refused(lambda d: d["request"]["lookup"].update(value=d["request"]["lookup"]["value"].upper()), "normalized")

    def test_contacted_and_reachable_must_agree(self):
        self._assert_refused(lambda d: d["domains"][0].update(reachable=None), "reachable")

    def test_malformed_and_oversized_reports_are_refused(self):
        for text in ("", "{", "[]", "null"):
            with self.subTest(text=text), self.assertRaises(ContractError):
                parse_group_report(text)
        with self.assertRaises(ContractError):
            parse_group_report(" " * (contract.MAX_REPORT_CHARACTERS + 1))

    def test_an_invalid_request_report_needs_no_request_echo(self):
        def invalid(d):
            d["request"] = None
            d["resolution"].update(status="InvalidRequest", error="lookup.value is not a GUID")
            d["group"] = None

        r = report("not-found", invalid)
        self.assertIs(r.resolution.status, ResolutionStatus.INVALID_REQUEST)
        self.assertIsNone(r.request)


class RequestTests(unittest.TestCase):
    def test_defaults_and_payload(self):
        request = ADReadRequest(by=LookupKind.OBJECT_GUID, value="{5E7E7000-0000-4000-8000-000000104110}")
        data = request.to_payload()
        self.assertEqual(data["lookup"], {"by": "objectGUID", "value": "5e7e7000-0000-4000-8000-000000104110", "domain": None})
        self.assertEqual(data["include"], {"directMembers": True, "nestedMembers": True, "primaryGroupReferences": True, "memberOf": True})
        self.assertEqual(data["limits"], {k: v.default for k, v in contract.LIMITS.items()})
        self.assertEqual(ADReadRequest.from_payload(json.loads(request.to_json())), request)

    def test_the_fixture_request_echo_round_trips(self):
        echo = payload("nested-group")["request"]
        self.assertEqual(ADReadRequest.from_payload(echo).to_payload(), echo)

    def test_invalid_requests_are_refused(self):
        cases = {
            "bad GUID": dict(by="objectGUID", value="nope"),
            "bad SID": dict(by="objectSid", value="S-1-5-21-x"),
            "bad DN": dict(by="distinguishedName", value="CN=x,OU=y"),
            "unknown kind": dict(by="mail", value="x"),
            "control char": dict(by="name", value="a\tb"),
            "padded": dict(by="name", value=" a"),
            "too long": dict(by="name", value="a" * 1025),
            "bad domain": dict(by="name", value="a", domain="not a domain"),
            "limit too high": dict(by="name", value="a", limits={"maxDirectMembers": 5001}),
            "limit zero": dict(by="name", value="a", limits={"maxNestedGroups": 0}),
            "bool limit": dict(by="name", value="a", limits={"maxNestedGroups": True}),
            "unknown limit": dict(by="name", value="a", limits={"maxEverything": 1}),
            "nested without direct": dict(by="name", value="a", include_direct_members=False),
        }
        for label, kwargs in cases.items():
            with self.subTest(label), self.assertRaises(ContractError):
                ADReadRequest(**kwargs)

    def test_domain_is_lowercased(self):
        self.assertEqual(ADReadRequest(by="name", value="a", domain="CORP.Synthetic.Example").domain, CORP)


class ScenarioTests(unittest.TestCase):
    """The eight required scenarios, plus a resolved group whose parent search was partial."""

    def test_unique_group(self):
        r, e = evidence("unique-group")
        self.assertIs(r.resolution.status, ResolutionStatus.RESOLVED)
        self.assertIs(r.resolution.matched_by, LookupKind.OBJECT_GUID)
        self.assertEqual(
            (e.emptiness.no_direct_members, e.emptiness.no_nested_members, e.emptiness.no_primary_group_references),
            (Fact.NO, Fact.YES, Fact.YES),
        )
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.NOT_EMPTY)
        self.assertIs(e.protection.status, ProtectionStatus.NOT_PROTECTED)
        self.assertEqual(e.ad_group.member_count, 2)
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.COMPLETE)
        members = _dependency(e, DependencyKind.AD_GROUP_MEMBERS)
        self.assertEqual([f.description for f in members.blocking_findings], ["2 direct member value(s) (2 user)"])

    def test_ambiguous_name(self):
        r, e = evidence("ambiguous-name")
        self.assertIs(r.resolution.status, ResolutionStatus.AMBIGUOUS)
        self.assertEqual(sorted(c.domain for c in r.resolution.candidates), [CORP, EMEA])
        self.assertEqual(len({c.object_guid for c in r.resolution.candidates}), 2)
        self.assertIsNone(e.ad_group)
        self.assertEqual(e.dependencies, ())
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.UNDETERMINED)
        self.assertTrue(e.protection.blocks_retirement)

    def test_not_found(self):
        r, e = evidence("not-found")
        self.assertIs(r.resolution.status, ResolutionStatus.NOT_FOUND)
        self.assertEqual(r.resolution.searched_domains, (APAC, CORP, EMEA))
        self.assertFalse(e.ad_group.exists)
        self.assertEqual(e.ad_group.object_guid, r.request.value)
        self.assertEqual(e.ad_group.id, ADStableIds(CORP).ad_group(r.request.value))
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.COMPLETE)

    def test_not_found_with_an_unsearched_domain_records_no_group(self):
        _, e = evidence("not-found", lambda d: d["resolution"].update(unsearchedDomains=[APAC]))
        self.assertIsNone(e.ad_group)

    def test_not_found_by_name_records_no_group(self):
        def by_name(d):
            d["request"]["lookup"].update(by="name", value="SYNTH-Nothing")
            d["resolution"]["matchedBy"] = "name"

        _, e = evidence("not-found", by_name)
        self.assertIsNone(e.ad_group)

    def test_unreachable_domain(self):
        r, e = evidence("unreachable-domain")
        self.assertIs(r.resolution.status, ResolutionStatus.INCONCLUSIVE)
        self.assertEqual(r.resolution.unsearched_domains, (APAC,))
        self.assertEqual(len(r.resolution.candidates), 1)
        self.assertIsNone(r.group)
        self.assertIsNone(e.ad_group)
        result = collector_result(r, e)
        self.assertIs(result.status, ResultStatus.PARTIAL)
        self.assertIs(result.error_code, CollectorErrorCode.DOMAIN_UNREACHABLE)

    def test_nested_group(self):
        r, e = evidence("nested-group")
        self.assertIs(e.emptiness.no_nested_members, Fact.NO)
        self.assertEqual(r.nested_members.principal_count, 2)
        self.assertTrue(r.nested_members.cycle_detected)
        nesting = _dependency(e, DependencyKind.AD_NESTED_MEMBERSHIP)
        blocking = sorted(f.description for f in nesting.blocking_findings)
        self.assertEqual(
            blocking,
            [
                "2 principal(s) reachable through member groups",
                "contains 1 member group(s)",
                f"member of group SYNTH-Nested-Grandchild ({EMEA})",
                f"member of group SYNTH-Resource-Access ({EMEA})",
            ],
        )
        self.assertIn("group nesting contains a cycle", [f.description for f in nesting.findings if not f.blocking])

    def test_primary_group_dependency(self):
        # The member attribute is empty, so a "no members" boolean would call this group
        # empty. It is not: two objects use it as their primary group.
        r, e = evidence("primary-group-dependency")
        self.assertIs(r.resolution.matched_by, LookupKind.OBJECT_SID)
        self.assertEqual(r.direct_members.count, 0)
        self.assertEqual(
            (e.emptiness.no_direct_members, e.emptiness.no_nested_members, e.emptiness.no_primary_group_references),
            (Fact.YES, Fact.YES, Fact.NO),
        )
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.NOT_EMPTY)
        self.assertEqual(e.ad_group.member_count, 0)
        members = _dependency(e, DependencyKind.AD_GROUP_MEMBERS)
        self.assertEqual(
            [f.description for f in members.blocking_findings],
            ["2 object(s) use this group as their primary group (primaryGroupID 4108)"],
        )

    def test_protected_group(self):
        r, e = evidence("protected-group")
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.EMPTY)  # empty, and still protected
        self.assertIs(e.protection.status, ProtectionStatus.PROTECTED)
        self.assertTrue(e.protection.blocks_retirement)
        self.assertIn("adminCount is set (AdminSDHolder-protected)", e.protection.reasons)
        self.assertIn("member of well-known group S-1-5-21-1000000001-1000000002-1000000003-512", e.protection.reasons)
        self.assertTrue(e.ad_group.admin_count)  # the domain record carries the protection
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.COMPLETE)

    def test_normal_empty_group(self):
        r, e = evidence("normal-empty-group")
        self.assertIs(r.resolution.matched_by, LookupKind.DISTINGUISHED_NAME)
        self.assertEqual(
            (e.emptiness.no_direct_members, e.emptiness.no_nested_members, e.emptiness.no_primary_group_references),
            (Fact.YES, Fact.YES, Fact.YES),
        )
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.EMPTY)
        self.assertEqual(e.emptiness.definition, "ogwa-ad-empty/v1")
        self.assertIs(e.protection.status, ProtectionStatus.NOT_PROTECTED)
        self.assertFalse(e.protection.blocks_retirement)
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.COMPLETE)
        self.assertEqual([d.blocking_findings for d in e.dependencies], [(), ()])
        self.assertIs(assess_dependency_coverage(e.dependencies, AD_KINDS), DependencyCoverage.COMPLETE)
        self.assertIs(collector_result(r, e).status, ResultStatus.COMPLETE)

    def test_resolved_group_with_an_unreachable_parent_domain(self):
        r, e = evidence("resolved-with-unreachable-parent-domain")
        self.assertIs(r.resolution.status, ResolutionStatus.RESOLVED)  # objectGUID is forest-unique
        self.assertIs(r.member_of.status, SectionStatus.PARTIAL)
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.EMPTY)
        self.assertIs(e.protection.status, ProtectionStatus.UNDETERMINED)
        self.assertTrue(e.protection.blocks_retirement)
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.PARTIAL)
        self.assertIs(_dependency(e, DependencyKind.AD_NESTED_MEMBERSHIP).provenance.result_status, ResultStatus.PARTIAL)
        self.assertIs(assess_dependency_coverage(e.dependencies, AD_KINDS), DependencyCoverage.PARTIAL)
        result = collector_result(r, e)
        self.assertEqual((result.status, result.error_code), (ResultStatus.PARTIAL, CollectorErrorCode.DOMAIN_UNREACHABLE))


class EmptinessTests(unittest.TestCase):
    def test_a_positive_count_is_a_fact_even_when_the_read_was_truncated(self):
        def truncated(d):
            d["directMembers"]["status"] = "Truncated"

        self.assertIs(assess_emptiness(report("unique-group", truncated)).no_direct_members, Fact.NO)

    def test_zero_proves_absence_only_when_complete(self):
        for status in ("Truncated", "Partial"):
            def change(d, status=status):
                d["nestedMembers"]["status"] = status

            with self.subTest(status=status):
                a = assess_emptiness(report("normal-empty-group", change))
                self.assertIs(a.no_nested_members, Fact.UNKNOWN)
                self.assertIs(a.verdict, EmptinessVerdict.UNDETERMINED)

    def test_failed_or_unrequested_sections_are_unknown(self):
        def failed(d):
            d["primaryGroupReferences"].update(status="Failed", count=None)

        def not_requested(d):
            d["directMembers"].update(status="NotRequested", count=None)

        self.assertIs(assess_emptiness(report("normal-empty-group", failed)).no_primary_group_references, Fact.UNKNOWN)
        self.assertIs(assess_emptiness(report("normal-empty-group", not_requested)).no_direct_members, Fact.UNKNOWN)

    def test_any_no_wins_over_unknown(self):
        def mixed(d):
            d["nestedMembers"].update(status="Failed", principalCount=None)

        self.assertIs(assess_emptiness(report("unique-group", mixed)).verdict, EmptinessVerdict.NOT_EMPTY)

    def test_every_fact_is_explained(self):
        a = assess_emptiness(report("primary-group-dependency"))
        self.assertEqual([s.split("=")[0] for s in a.evidence], ["NoDirectMembers", "NoNestedMembers", "NoPrimaryGroupReferences"])


class ProtectionTests(unittest.TestCase):
    def test_an_ungoverned_domain_is_undetermined(self):
        r = report("normal-empty-group")
        a = assess_protection(r, policy(governed_domains={EMEA: DomainProtectionPolicy(retirement_allowed=True)}))
        self.assertIs(a.status, ProtectionStatus.UNDETERMINED)
        self.assertIn(f"domain {CORP} has no OGWA protection policy", a.gaps)

    def test_unreadable_protected_from_accidental_deletion_is_undetermined(self):
        def unreadable(d):
            d["group"]["protectedFromAccidentalDeletion"] = None
            d["protection"].update(status="Undetermined", error="ProtectedFromAccidentalDeletion could not be read")

        _, e = evidence("normal-empty-group", unreadable)
        self.assertIs(e.protection.status, ProtectionStatus.UNDETERMINED)
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.PARTIAL)
        self.assertFalse(e.ad_group.protected_from_accidental_deletion)  # recorded False, but not decision-grade
        self.assertTrue(e.not_decision_grade)

    def test_configuration_can_add_protection(self):
        r = report("normal-empty-group")
        guid, sid = r.group.object_guid, r.group.object_sid
        cases = {
            "guid denylist": policy(protected_object_guids=frozenset({guid.upper()})),
            "sid denylist": policy(protected_sids=frozenset({sid})),
            "name list": policy(protected_names=frozenset({"synth-legacy-empty"})),
            "protected container": policy(
                governed_domains={CORP: DomainProtectionPolicy(True, ("OU=Groups,DC=corp,DC=synthetic,DC=example",))}
            ),
            "domain policy": policy(governed_domains={CORP: DomainProtectionPolicy(retirement_allowed=False)}),
        }
        for label, p in cases.items():
            with self.subTest(label):
                e = ad_evidence(r, policy=p, source=EvidenceSource.SYNTHETIC, ids=ADStableIds(CORP))
                self.assertIs(e.protection.status, ProtectionStatus.PROTECTED)
                # The ADGroup record cannot carry these reasons, so it must not be decision-grade.
                self.assertIs(e.ad_group.provenance.result_status, ResultStatus.PARTIAL)

    def test_privileged_names_cannot_be_configured_away(self):
        def dns_admins(d):
            d["group"].update(samAccountName="DnsAdmins", name="DnsAdmins")

        self.assertIs(assess_protection(report("normal-empty-group", dns_admins), policy()).status, ProtectionStatus.PROTECTED)
        self.assertIn("dnsadmins", policy(protected_names=frozenset()).effective_protected_names)

    def test_well_known_sids_are_protected(self):
        def builtin(d):
            g = d["group"]
            g.update(objectSid="S-1-5-32-548", domainSid="S-1-5-32", rid=548, builtinDomain=True)

        a = assess_protection(report("normal-empty-group", builtin), policy())
        self.assertIs(a.status, ProtectionStatus.PROTECTED)
        self.assertIn("well-known SID (RID 548)", a.reasons)

    def test_worker_indicators_are_never_dropped(self):
        def extra(d):
            d["protection"]["indicators"] = ["CriticalSystemObject"]

        a = assess_protection(report("normal-empty-group", extra), policy())
        self.assertIs(a.status, ProtectionStatus.PROTECTED)
        self.assertIn("worker indicator CriticalSystemObject", a.reasons)

    def test_policy_configuration_is_strict(self):
        good = {"governedDomains": {CORP: {"retirementAllowed": True, "protectedDnSuffixes": ["OU=Tier0,DC=corp,DC=synthetic,DC=example"]}}}
        self.assertIn(CORP, ADProtectionPolicy.from_mapping(good).governed_domains)
        bad = (
            {},
            {"governedDomains": {}, "allowAll": True},
            {"governedDomains": {CORP: {"retirementAllowed": "yes"}}},
            {"governedDomains": {CORP: {"retirementAllowed": True, "skip": 1}}},
            {"governedDomains": {CORP: {"retirementAllowed": True, "protectedDnSuffixes": ["OU=x"]}}},
            {"governedDomains": {}, "protectedObjectGuids": ["not-a-guid"]},
            {"governedDomains": {}, "protectedSids": ["S-1-x"]},
        )
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ContractError):
                ADProtectionPolicy.from_mapping(data)


class RecordTests(unittest.TestCase):
    def test_only_ad_sources_are_accepted(self):
        r = report("unique-group")
        for source in (EvidenceSource.OKTA_API, EvidenceSource.OPERATOR_ATTESTATION, EvidenceSource.CONFIGURED_MAPPING):
            with self.subTest(source=source), self.assertRaises(ValueError):
                ad_evidence(r, policy=policy(), source=source, ids=ADStableIds(CORP))

    def test_evidence_source_follows_the_mode(self):
        self.assertIs(evidence_source_for_mode(ExecutionMode.LOCAL_SYNTHETIC), EvidenceSource.SYNTHETIC)
        self.assertIs(evidence_source_for_mode(ExecutionMode.READ_ONLY_PRODUCTION), EvidenceSource.AD_VIA_AAP)

    def test_ids_are_stable_across_renames_and_moves(self):
        def renamed(d):
            g = d["group"]
            g.update(distinguishedName="CN=SYNTH-Renamed,OU=Archive,DC=corp,DC=synthetic,DC=example", samAccountName="SYNTH-Renamed", name="SYNTH-Renamed")

        _, before = evidence("unique-group")
        _, after = evidence("unique-group", renamed)
        self.assertEqual(before.ad_group.id, after.ad_group.id)
        self.assertEqual([d.id for d in before.dependencies], [d.id for d in after.dependencies])
        self.assertNotEqual(before.ad_group.digest, after.ad_group.digest)  # but the change is material

    def test_member_count_is_unknown_when_the_member_read_failed(self):
        def failed(d):
            d["directMembers"].update(status="Failed", count=None)

        _, e = evidence("unique-group", failed)
        self.assertIsNone(e.ad_group.member_count)
        self.assertIs(_dependency(e, DependencyKind.AD_GROUP_MEMBERS).provenance.result_status, ResultStatus.PARTIAL)

    def test_unrequested_sections_produce_no_dependency_record(self):
        def nothing_requested(d):
            d["request"]["include"] = dict.fromkeys(contract.INCLUDE_KEYS, False)
            for section in ("directMembers", "nestedMembers", "primaryGroupReferences", "memberOf"):
                d[section]["status"] = "NotRequested"

        _, e = evidence("normal-empty-group", nothing_requested)
        self.assertEqual(e.dependencies, ())
        self.assertIs(assess_dependency_coverage(e.dependencies, AD_KINDS), DependencyCoverage.UNKNOWN)

    def test_parent_findings_are_capped(self):
        def many_parents(d):
            parent = d["memberOf"]["parents"][0]
            d["memberOf"]["parents"] = [
                dict(copy.deepcopy(parent), objectGUID=f"5e7e7000-0000-4000-8000-{i:012d}", distinguishedName=f"CN=P{i},DC=corp,DC=synthetic,DC=example")
                for i in range(25)
            ]
            d["memberOf"]["count"] = 25

        _, e = evidence("protected-group", many_parents)
        descriptions = [f.description for f in _dependency(e, DependencyKind.AD_NESTED_MEMBERSHIP).findings]
        self.assertEqual(len(descriptions), 21)
        self.assertIn("member of 5 more group(s)", descriptions)


class OwnerDecisionTests(unittest.TestCase):
    """D19 (unverified live behaviors never give COMPLETE) and D21 (unknown protection is final)."""

    def _real(self, name, mutate=None, protection_policy=None):
        r = report(name, mutate)
        return ad_evidence(r, policy=protection_policy or policy(), source=EvidenceSource.AD_VIA_AAP, ids=ADStableIds(CORP))

    def test_no_live_behavior_is_verified_before_p11(self):
        self.assertEqual(records.VERIFIED_LIVE_BEHAVIORS, frozenset())

    def test_real_evidence_is_never_complete_while_behaviors_are_unverified(self):
        e = self._real("normal-empty-group")
        self.assertIs(e.protection.status, ProtectionStatus.UNDETERMINED)
        self.assertTrue(e.protection.blocks_retirement)
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.PARTIAL)
        self.assertIs(_dependency(e, DependencyKind.AD_NESTED_MEMBERSHIP).provenance.result_status, ResultStatus.PARTIAL)
        self.assertEqual(
            set(e.unverified_live_behaviors),
            {records.LiveBehavior.DELETION_PROTECTION_READABILITY, records.LiveBehavior.CROSS_DOMAIN_PARENT_LOOKUP},
        )
        self.assertTrue(any("D19" in g for g in e.protection.gaps))
        # Small direct membership does not depend on large-group behavior.
        self.assertIs(_dependency(e, DependencyKind.AD_GROUP_MEMBERS).provenance.result_status, ResultStatus.COMPLETE)
        # The emptiness facts themselves stay separate and unchanged (D20).
        self.assertIs(e.emptiness.verdict, EmptinessVerdict.EMPTY)

    def test_large_groups_are_not_complete_from_real_sources(self):
        def large(d):
            d["directMembers"]["count"] = records.LARGE_GROUP_THRESHOLD

        real = self._real("unique-group", large)
        self.assertIn(records.LiveBehavior.LARGE_GROUP_COMPLETENESS, real.unverified_live_behaviors)
        self.assertIs(_dependency(real, DependencyKind.AD_GROUP_MEMBERS).provenance.result_status, ResultStatus.PARTIAL)
        self.assertTrue(any(g.startswith("member_count:") for g in real.not_decision_grade))
        _, synthetic = evidence("unique-group", large)
        self.assertIs(_dependency(synthetic, DependencyKind.AD_GROUP_MEMBERS).provenance.result_status, ResultStatus.COMPLETE)

    def test_large_nested_membership_is_not_complete_from_real_sources(self):
        def large(d):
            d["nestedMembers"]["principalCount"] = records.LARGE_GROUP_THRESHOLD

        e = self._real("nested-group", large, policy(governed_domains={CORP: DomainProtectionPolicy(True)}))
        self.assertIn(records.LiveBehavior.LARGE_GROUP_COMPLETENESS, e.unverified_live_behaviors)

    def test_protected_groups_stay_protected(self):
        e = self._real("protected-group")
        self.assertIs(e.protection.status, ProtectionStatus.PROTECTED)

    def test_the_gate_is_the_only_difference_once_p11_verifies(self):
        with mock.patch.object(records, "VERIFIED_LIVE_BEHAVIORS", frozenset(records.LiveBehavior)):
            e = self._real("normal-empty-group")
        self.assertIs(e.protection.status, ProtectionStatus.NOT_PROTECTED)
        self.assertIs(e.ad_group.provenance.result_status, ResultStatus.COMPLETE)
        self.assertEqual(e.unverified_live_behaviors, ())

    def test_unknown_protection_cannot_be_configured_away(self):
        def unreadable(d):
            d["group"]["protectedFromAccidentalDeletion"] = None

        r = report("normal-empty-group", unreadable)
        everything_allowed = {d: DomainProtectionPolicy(retirement_allowed=True) for d in (CORP, EMEA, APAC)}
        for p in (policy(), policy(governed_domains=everything_allowed), ADProtectionPolicy(governed_domains=everything_allowed)):
            for source in (EvidenceSource.SYNTHETIC, EvidenceSource.AD_VIA_AAP):
                with mock.patch.object(records, "VERIFIED_LIVE_BEHAVIORS", frozenset(records.LiveBehavior)):
                    e = ad_evidence(r, policy=p, source=source, ids=ADStableIds(CORP))
                with self.subTest(source=source):
                    self.assertIs(e.protection.status, ProtectionStatus.UNDETERMINED)
                    self.assertIs(e.ad_group.provenance.result_status, ResultStatus.PARTIAL)
        # The policy has no field that could override an unknown result.
        fields = {f.name for f in dataclasses.fields(ADProtectionPolicy)}
        self.assertEqual(fields, {"governed_domains", "protected_object_guids", "protected_sids", "protected_names", "effective_protected_names"})


def _dependency(e, kind):
    (match,) = [d for d in e.dependencies if d.kind is kind]
    return match


if __name__ == "__main__":
    unittest.main()
