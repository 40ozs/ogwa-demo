"""The Null Meridian dataset generator: the canonical company, its history, and its naming eras.

Pure generation only (no store): see tests/test_null_meridian_seed.py for the store, reset,
correlation, and API.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
from collections import Counter
from datetime import date
from pathlib import Path

from app.demo.null_meridian import dataset as dataset_module
from app.demo.null_meridian import profile
from app.demo.null_meridian.dataset import build_dataset
from app.demo.null_meridian.manifest import CORRELATION_PATH, MANIFEST_PATH, generated_files
from app.governance.naming import MODERN_APP_RE, MODERN_SHARE_RE, check_name, legacy_style

REPO_ROOT = Path(__file__).resolve().parents[1]
DS = build_dataset()
ACTIVE = [p for p in DS.people if p.status == "ACTIVE"]
FORMER = [p for p in DS.people if p.status == "TERMINATED"]
APP_SLUGS = frozenset(a.slug for a in DS.applications)
DEPT_SLUGS = frozenset(d.slug for d in DS.departments)


def fingerprint(ds) -> str:
    """A digest of every generated record, for comparing runs."""
    parts = [ds.counts(), [p.to_dict() for p in ds.people], [e.to_dict() for e in ds.events],
             [a.to_dict() for a in ds.applications], [g.to_dict() for g in ds.groups], ds.nesting, ds.memberships,
             [a.to_dict() for a in ds.assignments], [f.to_dict() for f in ds.findings]]
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


class CompanyProfileTests(unittest.TestCase):
    def test_canonical_profile(self):
        self.assertEqual((profile.COMPANY, profile.PRIMARY_DOMAIN, profile.SEED), ("Null Meridian", "nullmeridian.info",
                                                                                  "null-meridian-v1"))
        self.assertEqual((profile.FOUNDED, profile.OKTA_ADOPTED, profile.MODERN_NAMING_ADOPTED, profile.SNAPSHOT_DATE),
                         (date(2016, 10, 1), date(2021, 10, 1), date(2023, 10, 1), date(2026, 10, 1)))
        self.assertEqual(profile.SNAPSHOT_DATE.year - profile.FOUNDED.year, 10)
        self.assertEqual(DS.profile()["activeEmployees"], 1800)

    def test_exactly_1800_active_employees_and_a_former_population(self):
        self.assertEqual(len(ACTIVE), 1800)
        self.assertEqual(sum(d.size for d in DS.departments), 1800)
        self.assertEqual(Counter(p.department for p in ACTIVE), {d.slug: d.size for d in DS.departments})
        self.assertGreater(len(FORMER), 500)
        self.assertTrue(all(p.termination_date and p.termination_date < profile.SNAPSHOT_DATE for p in FORMER))
        self.assertTrue(all(p.termination_date is None for p in ACTIVE))

    def test_department_sizes_vary_as_required(self):
        size = {d.slug: d.size for d in DS.departments}
        large = sorted(size, key=size.get, reverse=True)[:4]
        self.assertEqual(set(large), {"engineering", "sales", "customer-success", "operations"})
        for small in ("security", "legal", "finance", "executive", "it"):
            self.assertLess(size[small], 100, small)
        self.assertEqual(set(size), {"engineering", "product", "data", "it", "security", "finance", "people", "legal",
                                     "sales", "marketing", "customer-success", "operations", "design", "executive"})

    def test_hierarchy_has_every_level_and_valid_managers(self):
        levels = Counter(p.level for p in ACTIVE)
        for level in ("executive", "vp", "director", "manager", "ic"):
            self.assertGreater(levels[level], 0, level)
        ids = {p.id for p in ACTIVE}
        ceo = [p for p in ACTIVE if p.manager_id is None]
        self.assertEqual([p.title for p in ceo], ["Chief Executive Officer"])
        self.assertTrue(all(p.manager_id in ids for p in ACTIVE if p.manager_id))
        # No management cycles: every chain reaches the CEO.
        by_id = {p.id: p for p in ACTIVE}
        for p in ACTIVE:
            seen, node = set(), p
            while node.manager_id:
                self.assertNotIn(node.id, seen)
                seen.add(node.id)
                node = by_id[node.manager_id]
            self.assertEqual(node.id, ceo[0].id)

    def test_history_spans_ten_years_with_promotions_transfers_and_recent_hires(self):
        hires = Counter(p.hire_date.year for p in ACTIVE)
        self.assertEqual(min(hires), 2016)
        self.assertGreaterEqual(hires[2026], 50)  # recent hires
        self.assertGreaterEqual(sum(n for y, n in hires.items() if y <= 2018), 50)  # long tenure
        kinds = Counter(e.kind for e in DS.events)
        for kind in ("HIRED", "PROMOTED", "TITLE_CHANGED", "TRANSFERRED", "OKTA_ACTIVATED", "TERMINATED",
                     "OKTA_DEACTIVATED"):
            self.assertGreater(kinds[kind], 10, kind)
        self.assertEqual(kinds["HIRED"], len(DS.people))
        for e in DS.events:
            self.assertTrue(profile.FOUNDED <= e.on < profile.SNAPSHOT_DATE, e)

    def test_okta_was_introduced_on_2021_10_01(self):
        self.assertTrue(all(e.on >= profile.OKTA_ADOPTED for e in DS.events if e.kind.startswith("OKTA_")))
        self.assertTrue(all(p.okta_activated is None or p.okta_activated >= profile.OKTA_ADOPTED for p in DS.people))
        left_before = [p for p in FORMER if p.termination_date < profile.OKTA_ADOPTED]
        self.assertTrue(left_before and all(p.okta_status == "NONE" for p in left_before))
        self.assertTrue(all(a.okta_integrated >= profile.OKTA_ADOPTED for a in DS.applications))
        pre_okta = [g for g in DS.groups if g.source == "OKTA" and g.created_at.date() < profile.OKTA_ADOPTED]
        self.assertEqual(pre_okta, [])
        self.assertTrue(any(a.adopted < profile.OKTA_ADOPTED for a in DS.applications))


class IdentityTests(unittest.TestCase):
    def test_emails_are_first_last_at_nullmeridian_info_with_collision_suffixes(self):
        emails = [p.email for p in DS.people]
        self.assertEqual(len(set(emails)), len(emails))
        pattern = re.compile(r"^[a-z]+\.[a-z]+[0-9]*@nullmeridian\.info$")
        for p in DS.people:
            self.assertRegex(p.email, pattern)
            self.assertEqual(p.upn, p.email)
            self.assertTrue(p.email.startswith(f"{re.sub('[^a-z]', '', p.first_name.lower())}."), p.email)
        self.assertGreater(sum(1 for e in emails if re.search(r"[0-9]@", e)), 10, "collisions are suffixed")
        self.assertEqual(len({p.sam_account_name.casefold() for p in DS.people}), len(DS.people))

    def test_identifiers_are_stable_uuidv5(self):
        import uuid
        for p in DS.people[:200]:
            u = uuid.UUID(p.uuid)
            self.assertEqual(u.version, 5)
            self.assertEqual(p.id, f"psn_{u.hex}")
        for g in DS.groups:
            self.assertEqual(uuid.UUID(g.uuid).version, 5)
            if g.ad_object_guid:
                self.assertEqual(uuid.UUID(g.ad_object_guid).version, 5)
                self.assertTrue(g.ad_sid.startswith(profile.AD_DOMAIN_SID + "-"))
            if g.okta_group_id:
                self.assertTrue(g.okta_group_id.startswith("00gSYNTHNM"), g.okta_group_id)
        self.assertTrue(all(a.okta_app_id.startswith("0oaSYNTHNM") for a in DS.applications))

    def test_only_fictional_domains_appear(self):
        """No production or third-party domain: every DNS-like name is nullmeridian.info or a reserved one."""
        text = "\n".join(path.read_text(encoding="utf-8") for path in generated_files(DS))
        domains = set(re.findall(r"@([A-Za-z0-9.-]+)", text))
        self.assertEqual(domains, {"nullmeridian.info"})
        dcs = set(re.findall(r"(DC=[^\"]+?)\"", text))
        self.assertEqual(dcs, {"DC=corp,DC=nullmeridian,DC=info"})
        for match in re.findall(r"\b[a-z0-9-]+\.(?:com|net|org|io|local|corp|internal)\b", text, re.I):
            self.fail(f"unexpected domain-like name {match}")


class DeterminismTests(unittest.TestCase):
    def test_rebuilding_gives_identical_output(self):
        dataset_module.build_dataset.cache_clear()
        try:
            again = dataset_module.build_dataset()
        finally:
            dataset_module.build_dataset.cache_clear()
        self.assertEqual(fingerprint(again), fingerprint(DS))

    def test_output_does_not_depend_on_hash_randomization(self):
        code = ("import hashlib,json,sys; sys.path.insert(0, '.'); from tests.test_null_meridian_dataset import fingerprint;"
                "from app.demo.null_meridian.dataset import build_dataset; print(fingerprint(build_dataset()))")
        results = set()
        for seed in ("1", "4242"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            out = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, env=env, capture_output=True, text=True,
                                 check=True)
            results.add(out.stdout.strip().splitlines()[-1])
        self.assertEqual(results, {fingerprint(DS)})

    def test_committed_manifest_and_correlation_configuration_are_current(self):
        for path, text in generated_files(DS).items():
            with self.subTest(file=path.name):
                self.assertEqual(path.read_text(encoding="utf-8"), text,
                                 "regenerate with: python -m app.demo.null_meridian write")
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["profile"]["seed"], "null-meridian-v1")
        self.assertEqual(len(manifest["users"]["rows"]), len(DS.people))
        self.assertEqual(sum(1 for r in manifest["users"]["rows"] if r[12] == "ACTIVE"), 1800)
        self.assertEqual(len(manifest["groups"]["rows"]), len(DS.groups))
        self.assertTrue(CORRELATION_PATH.is_file())


class NamingTests(unittest.TestCase):
    def test_modern_names_conform_to_the_grammar(self):
        modern = [g for g in DS.groups if g.name.startswith(("sg-okta-", "sg-share-"))]
        self.assertGreater(len(modern), 100)
        for g in modern:
            check = check_name(g.name, applications=APP_SLUGS, departments=DEPT_SLUGS)
            with self.subTest(group=g.name):
                self.assertTrue(check.conforms, check.problem)
                if g.name.startswith("sg-okta-"):
                    m = MODERN_APP_RE.match(g.name)
                    self.assertEqual((m["slug"], m["tier"]), (g.application, g.tier))
                else:
                    m = MODERN_SHARE_RE.match(g.name)
                    self.assertEqual(m["slug"], g.department)

    def test_grammar_rejects_malformed_names(self):
        for bad in ("sg-okta-crm", "sg-okta-crm-superuser", "SG-OKTA-CRM-USER", "sg-okta-nosuchapp-user",
                    "sg-share-finance-rw", "sg-share-nosuchdept-write", "sg_okta_crm_user", "sg-okta--user"):
            with self.subTest(name=bad):
                self.assertFalse(check_name(bad, applications=APP_SLUGS, departments=DEPT_SLUGS).conforms)

    def test_modern_names_never_predate_the_standard(self):
        for g in DS.groups:
            if g.name.lower().startswith(("sg-okta-", "sg-share-")):
                self.assertGreaterEqual(g.created_at.date(), profile.MODERN_NAMING_ADOPTED, g.name)

    def test_groups_created_since_the_standard_predominantly_follow_it(self):
        recent = [g for g in DS.groups if g.created_at.date() >= profile.MODERN_NAMING_ADOPTED and g.kind != "BUILT_IN"]
        conforming = [g for g in recent if check_name(g.name, applications=APP_SLUGS, departments=DEPT_SLUGS).conforms]
        self.assertGreaterEqual(len(conforming) / len(recent), 0.95)
        flagged = {f.subject_id for f in DS.findings if f.code == "NONSTANDARD_NAME_RECENT"}
        self.assertEqual({g.id for g in recent if g not in conforming}, flagged)
        self.assertTrue(flagged, "a few deliberate exceptions exist")

    def test_older_groups_show_several_eras_of_convention(self):
        old = [g for g in DS.groups if g.created_at.date() < profile.MODERN_NAMING_ADOPTED and g.kind != "BUILT_IN"]
        styles = Counter(legacy_style(g.name) for g in old)
        self.assertGreaterEqual(len([s for s in styles if s != "other"]), 10, styles)
        eras = Counter(g.era for g in old)
        self.assertEqual(set(eras), {"legacy-ad", "app-specific", "transitional-okta"})
        examples = {g.name for g in old}
        for name in ("GG_Dept_Sales", "Finance-RW", "Sales-RW", "FS-Data-R", "Share_Engineering_Modify", "NM-SALESENG-USERS",
                     "GG_Finance_RW", "Git_Dev", "CRM-Sales", "Okta_CRM_Users", "OKTA-Git-Admins", "APP-Chat-Users"):
            self.assertIn(name, examples)

    def test_group_dates_match_their_naming_era(self):
        for g in DS.groups:
            era = profile.era_for(g.created_at.date())
            self.assertEqual(g.era, era.key, g.name)
            self.assertLessEqual(g.created_at, g.modified_at, g.name)
            self.assertGreaterEqual(g.created_at.date(), profile.FOUNDED)
        transitional = [g for g in DS.groups if g.name.startswith(("Okta_", "OKTA-", "okta-"))]
        self.assertTrue(all(g.created_at.date() >= profile.OKTA_ADOPTED for g in transitional))
        old_modified = [g for g in DS.groups if g.era == "legacy-ad" and g.modified_at.year <= 2023]
        self.assertGreater(len(old_modified), 20, "legacy groups are not all recently modified")


class EstateTests(unittest.TestCase):
    def test_application_estate(self):
        active = [a for a in DS.applications if a.status == "ACTIVE"]
        self.assertTrue(60 <= len(active) <= 80, len(active))
        self.assertTrue({"SAML_2_0", "OPENID_CONNECT", "BROWSER_PLUGIN", "BOOKMARK"} <= {a.sign_on_mode for a in DS.applications})
        self.assertEqual({a.provisioning for a in DS.applications}, {"SCIM", "MANUAL", "NONE"})
        self.assertEqual({a.assignment_model for a in DS.applications}, {"GROUP", "DIRECT", "MIXED"})
        self.assertGreaterEqual(len({a.category for a in DS.applications}), 15)
        self.assertTrue(any(len(a.tiers) >= 4 for a in DS.applications))
        self.assertTrue(any(a.status == "INACTIVE" for a in DS.applications))

    def test_hierarchy_scales_poorly_but_is_acyclic(self):
        index = DS.index
        depths = Counter(index.depth(g.key) for g in DS.groups)
        self.assertGreaterEqual(max(depths), 4)
        self.assertGreaterEqual(len([d for d in depths if d > 0]), 3, "inconsistent nesting depth")
        crm_routes = index.route_counts("crm")
        self.assertGreaterEqual(max(crm_routes.values()), 3, "someone reaches CRM by three routes")
        broad = [g for g in DS.groups if g.kind == "ALL_STAFF"][0]
        self.assertGreater(len(index.effective(broad.key)), 1700)
        self.assertGreater(len(index.parents(broad.key)), 5, "the broad group is nested into many app groups")

    def test_governance_findings_reflect_moderate_debt(self):
        group_health = Counter(DS.analysis.group_severity.values())
        app_health = Counter(DS.analysis.application_severity.values())
        total = group_health + app_health
        n = sum(total.values())
        self.assertTrue(0.70 <= total["CLEAN"] / n <= 0.80, total)
        self.assertTrue(0.15 <= total["QUESTIONABLE"] / n <= 0.20, total)
        self.assertTrue(0.05 <= total["ACTIONABLE"] / n <= 0.10, total)
        codes = Counter(f.code for f in DS.findings)
        for code in ("EMPTY_GROUP_ASSIGNED", "DEPRECATED_GROUP_STILL_ASSIGNED", "TERMINATED_MEMBERS_RETAINED",
                     "ADMIN_TIER_UNEXPECTED_MEMBER", "BROAD_PRIVILEGED_NESTING", "STALE_DEPRECATED_GROUP",
                     "DUPLICATE_ENTITLEMENT", "NONSTANDARD_NAME_RECENT", "DEEP_NESTING", "UNNECESSARY_INTERMEDIATE",
                     "OWNER_MISSING", "UNUSED_GROUP", "MAPPING_REVIEW_NEEDED", "DUPLICATE_NAME", "LEGACY_NAMING",
                     "DIRECT_ASSIGNMENTS_BYPASS_GROUPS", "DIRECT_ASSIGNMENT_ONLY", "REDUNDANT_ACCESS_PATHS",
                     "INACTIVE_APP_STILL_ASSIGNED", "PUSH_TARGET_MISSING", "ASSIGNED_TO_INACTIVE_APP"):
            self.assertGreater(codes[code], 0, code)

    def test_correlation_cases_cover_every_required_kind(self):
        cases = Counter(g.correlation_case for g in DS.groups if g.correlation_case)
        for case in ("EXACT", "NORMALIZED_EXACT", "LEGACY_NAME_EXACT", "NAME_ONLY", "MULTIPLE_MATCHES", "NO_MATCH",
                     "LEGACY_AD_TO_MODERN_OKTA", "UNVERIFIED_STABLE_ID", "CONFIGURED_TARGET_DELETED"):
            self.assertGreaterEqual(cases[case], 2 if case != "CONFIGURED_TARGET_DELETED" else 1, case)
        pairs = [g for g in DS.groups if g.replaced_by]
        self.assertGreater(len(pairs), 20, "deprecated groups paired with their replacements")

    def test_portfolio_scenarios_name_existing_objects(self):
        keys = {g.key for g in DS.groups}
        self.assertEqual([s.number for s in DS.scenarios], list(range(1, 11)))
        for s in DS.scenarios:
            self.assertTrue(set(s.group_keys) <= keys, s.key)
            self.assertTrue(set(s.application_slugs) <= APP_SLUGS, s.key)
        self.assertEqual(len(DS.index.effective("app:status-page:modern:admin")), 0)
        self.assertEqual(DS.index.depth("app:warehouse:modern:readonly"), 4)


if __name__ == "__main__":
    unittest.main()
