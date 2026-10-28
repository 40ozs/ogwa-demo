"""The Genesee Press demo dataset (SYNTH-OGWA-01): the vendored shared-world projection, the dataset
OGWA builds from it, the seed, and its parity with the legacy Null Meridian dataset.

Golden values here are the Genesee Press equivalents of ``tests/test_null_meridian_seed.py``'s.
Any change to the vendored projection, the overlay, the seed or the store's write path moves the
audit head; update it (and ``docs/demo/genesee-press.md``) only for an intended change.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from app.demo.datasets import DATASET_KEYS, DEFAULT_DATASET, dataset, dataset_of
from app.demo.genesee_press import profile
from app.demo.genesee_press.audit_sample import DEFAULT_PATH as SAMPLE_PATH
from app.demo.genesee_press.audit_sample import build_audit_sample
from app.demo.genesee_press.dataset import RNG, build_dataset
from app.demo.genesee_press.manifest import generated_files
from app.demo.genesee_press.overlay import OVERLAY_PATH, build_overlay, render
from app.demo.genesee_press.projection import ProjectionError, load, vendored
from app.demo.genesee_press.world import candidates, create_genesee_press_store
from app.demo.null_meridian import audit_sample
from app.demo.null_meridian.dataset import build_dataset as legacy_dataset
from app.demo.null_meridian.world import CANDIDATES as LEGACY_CANDIDATES
from app.governance.naming import check_name
from tests.store_fixtures import memory_target

REPO_ROOT = Path(__file__).resolve().parents[1]
# Re-pinned by SYNTH-CROSSAPP-01 for the shared-directory correction only (synthetic-enterprise dataset 2.1.0,
# ogwa@0.3.1; docs/operations/audit-anchors.md): the 12 OGWA team groups that duplicated an ADG group by letter
# case are that group (D-XA-01), and groups ADG models carry ADG's SID/objectGUID (D-XA-02). 1,629 -> 1,617
# events, 32,337 -> 31,921 directory records (-12 groups, -383 memberships, -21 findings). SYNTH-OGWA-01 head:
# sha256:83cfda606c7a05916a4f5f0bb184bbec7f4fa95a8ffd0d3c01707f031f77aa17.
GOLDEN_AUDIT_HEAD = "sha256:f11f0a99ec5aff7e40b9aeda7dc2a8e60df29bc273a745060b8d480ed1d4b39f"
GOLDEN_AUDIT_EVENTS = 1617
GOLDEN_DIRECTORY_RECORDS = 31921
# The same five outcomes, with the same counts, as the legacy dataset (tests/test_null_meridian_seed.py).
GOLDEN_CONFIDENCES = {"EXACT_CONFIGURED_MAPPING": 201, "NOT_FOUND": 45, "UNVERIFIED_STABLE_ID": 42, "NAME_ONLY": 7,
                      "AMBIGUOUS": 3}
# synthetic-enterprise universe/scenarios/gp-ogwa-lifecycle-candidates.json (expectations.ogwa), as candidate ->
# (canonical group, canonical application, state).
SCENARIO_EXPECTATIONS = {
    "GP-C01": ("grp_3GKZJQJ1VC3W", "app_N77XR1SNPYSN", "NEEDS_REVIEW"),
    "GP-C02": ("grp_DCAEQP349BPK", "app_5CTNDX4SKVMW", "NEEDS_REVIEW"),
    "GP-C03": ("grp_482QNK9D0Z0H", "app_G505R6A4GC58", "DEPENDENCY_BLOCKED"),
    "GP-C04": ("grp_GS17T3W7FART", "app_WTXDA81KGHCJ", "MAPPING_AMBIGUOUS"),
    "GP-C05": ("grp_MQR951D55VP1", "app_GGZ7WJBQPXKC", "DEPENDENCY_BLOCKED"),
    "GP-C06": ("grp_AQ0V7HQRVZAB", "app_XR82NP8T3V1F", "NEEDS_REVIEW"),
    "GP-C07": ("grp_457MN72JPEKN", "app_W9F7606VBEF3", "BLOCKED"),
    "GP-C08": ("grp_DEWX9921RCJD", "app_W9F7606VBEF3", "HOLD"),
    "GP-C09": ("grp_C0FTDPE2PVQV", "app_GEN2EAWCD44K", "PROTECTED"),
    "GP-C10": ("grp_6FFD8EFKH6VG", "app_G3TZ6EG3WA37", "NEEDS_REVIEW"),
    "GP-C11": ("grp_QKG6FYSXYS42", "app_44ZMT5CPCABN", "APPROVED"),
}
# Former organization values that must not appear in any demo-facing Genesee Press output.
OLD_TOKENS = ("Null Meridian", "nullmeridian", "NMCORP", "SYNTHNM", "Meridian HQ", "NM-LIFECYCLE")
OLD_PATTERNS = (re.compile(r"\bNM-?C\d\d\b"), re.compile(r"(?<![A-Za-z0-9])(sg|SG)-"), re.compile(r"\bNM\d{5}\b"))


def old_values(text: str) -> list[str]:
    return [t for t in OLD_TOKENS if t in text] + [p.pattern for p in OLD_PATTERNS if p.search(text)]


class VendoredProjectionTests(unittest.TestCase):
    def test_the_lock_pins_the_vendored_projection(self):
        lock = json.loads((REPO_ROOT / "SYNTHETIC_ENTERPRISE.lock").read_text())
        self.assertEqual((lock["repository"], lock["snapshot"], lock["projection"], lock["contract_version"],
                          lock["dataset"]),
                         ("40ozs/synthetic-enterprise", "standard-baseline", "ogwa@0.3.1", "0.2.0",
                          "synthetic-enterprise-world@2.1.0"))
        self.assertRegex(lock["commit"], r"^[0-9a-f]{40}$")
        source = vendored().source
        self.assertEqual((source["commit"], source["manifestSha256"]), (lock["commit"], lock["manifest_sha256"]))
        files = sorted(p.relative_to(REPO_ROOT / "vendor").as_posix() for p in (REPO_ROOT / "vendor").rglob("*") if p.is_file())
        self.assertEqual(files, ["synthetic-enterprise/standard-baseline/manifest.json"] + [
            f"synthetic-enterprise/standard-baseline/projections/ogwa/{n}" for n in sorted(
                ("applications.jsonl", "assignments.jsonl", "employment_events.jsonl", "groups.jsonl", "memberships.jsonl",
                 "org_units.jsonl", "organization.jsonl", "people.jsonl", "projection.json"))])

    def test_a_changed_vendored_file_is_refused(self):
        source = REPO_ROOT / "vendor" / "synthetic-enterprise"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "vendor"
            shutil.copytree(source, root)
            lock = Path(tmp) / "SYNTHETIC_ENTERPRISE.lock"
            shutil.copy(REPO_ROOT / "SYNTHETIC_ENTERPRISE.lock", lock)
            self.assertEqual(load(lock, root).source, vendored().source)
            people = root / "standard-baseline" / "projections" / "ogwa" / "people.jsonl"
            people.write_text(people.read_text().replace("Genesee HQ", "Genesee Hq", 1))
            with self.assertRaisesRegex(ProjectionError, "people.jsonl does not match its digest"):
                load(lock, root)
            shutil.copy(source / "standard-baseline" / "projections" / "ogwa" / "people.jsonl", people)
            data = json.loads(lock.read_text())
            data["projection"] = "ogwa@0.2.0"
            lock.write_text(json.dumps(data))
            with self.assertRaisesRegex(ProjectionError, "the lock pins ogwa@0.2.0"):
                load(lock, root)

    def test_the_runtime_never_reaches_synthetic_enterprise(self):
        for path in sorted((REPO_ROOT / "app").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("github.com/40ozs/synthetic-enterprise", text, path)
            self.assertNotIn("raw.githubusercontent", text, path)


class GeneseePressDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = build_dataset()
        cls.projection = vendored()

    def test_the_profile_is_the_shared_world_s(self):
        org = self.projection.organization
        self.assertEqual((profile.COMPANY, profile.PRIMARY_DOMAIN, profile.AD_DNS_DOMAIN, profile.AD_NETBIOS),
                         (org["name"], org["primary_domain"], "corp.geneseepress.example", "GPCORP"))
        self.assertEqual((profile.COMPANY, profile.PRIMARY_DOMAIN), ("Genesee Press", "geneseepress.example"))
        self.assertEqual((profile.OKTA_AD_SOURCE_ID, profile.OKTA_EVERYONE_ID), ("0oaSYNTHGPADDIR", "00gSYNTHGPEVERYONE"))
        self.assertEqual(profile.AS_OF.isoformat(), "2026-10-01T12:00:00+00:00")
        p = self.ds.profile()
        self.assertEqual((p["dataset"], p["seed"], p["company"], p["activeEmployees"]),
                         ("genesee-press", "genesee-press-v1", "Genesee Press", 1800))
        self.assertEqual(p["source"]["commit"], self.projection.lock["commit"])

    def test_every_shared_world_record_is_present(self):
        records = {name: self.projection.records(name) for name in self.projection.files}
        self.assertEqual(len(self.ds.people), len(records["people.jsonl"]))
        self.assertEqual(len(self.ds.groups), len(records["groups.jsonl"]))
        self.assertEqual(len(self.ds.applications), len(records["applications.jsonl"]))
        self.assertEqual(len(self.ds.assignments), len(records["assignments.jsonl"]))
        self.assertEqual({p.id for p in self.ds.people}, {RNG.record_id("psn", p["canonical_id"]) for p in records["people.jsonl"]})
        self.assertEqual({a.id for a in self.ds.assignments}, {a["legacy_assignment_id"] for a in records["assignments.jsonl"]})
        self.assertEqual({a.okta_app_id for a in self.ds.applications}, {a["okta_app_id"] for a in records["applications.jsonl"]})
        counts = self.ds.counts()
        self.assertEqual((counts["activeEmployees"], counts["formerEmployees"], counts["departments"]), (1800, 640, 14))
        self.assertEqual((counts["applications"], counts["activeApplications"], counts["groups"]), (81, 76, 560))  # 572 before D-XA-01
        self.assertEqual((counts["oktaVisibleGroups"], counts["groupAssignments"], counts["directUserAssignments"]),
                         (298, 186, 61))

    def test_canonical_people_and_employee_numbers(self):
        self.assertTrue(all(re.fullmatch(r"GP-\d{5}", p.employee_number) for p in self.ds.people))
        self.assertTrue(all(p.email.endswith("@geneseepress.example") and p.upn == p.email for p in self.ds.people))
        by_number = {p.employee_number: p for p in self.ds.people}
        source = {p["employee_number"]: p for p in self.projection.records("people.jsonl")}
        for number, person in by_number.items():
            self.assertEqual((person.display_name, person.sam_account_name), (source[number]["display_name"],
                                                                              source[number]["sam_account_name"]))
        # Legacy employee numbers appear only in the projection's legacy field, never on an OGWA record.
        self.assertTrue(all(n.startswith("NM") for p in source.values() for n in p["legacy_employee_numbers"]))

    def test_owners_and_assignees_are_remapped_to_canonical_people(self):
        people = {p["canonical_id"]: p for p in self.projection.records("people.jsonl")}
        person_of = {RNG.record_id("psn", cid): p for cid, p in people.items()}
        legacy = legacy_dataset()
        legacy_numbers = {p.id: p.employee_number for p in legacy.people}
        legacy_groups = {g.key: g for g in legacy.groups}
        groups = {g.key: g for g in self.ds.groups}
        # The legacy candidate owners (formerly NM00693, NM01218, NM02282, NM01439, NM02128) are the canonical
        # people their personas were mapped to (synthetic-enterprise D-NM-04, D-NM-14).
        for key in ("app:status-page:modern:admin", "app:fpa-planning:transitional:user", "app:print-release:legacy:user",
                    "app:old-wiki:legacy:user", "app:legacy-cloud:legacy:admin"):
            with self.subTest(group=key):
                owner = person_of[groups[key].owner_id]
                self.assertIn(legacy_numbers[legacy_groups[key].owner_id], owner["legacy_employee_numbers"])
        for app in self.ds.applications:
            old = next(a for a in legacy.applications if a.slug == app.slug)
            self.assertIn(legacy_numbers[old.owner_id], person_of[app.owner_id]["legacy_employee_numbers"])
        crm = [a for a in self.ds.assignments if a.application == "crm" and a.person_id]
        self.assertEqual(len(crm), 23)
        self.assertTrue(all(a.person_id in person_of for a in crm))

    def test_group_names_follow_the_sec_standard(self):
        self.assertFalse([g.name for g in self.ds.groups if re.match(r"(?i)^(sg|dg)[-_]", g.name)])
        modern = [g for g in self.ds.groups if g.name.startswith(("sec-okta-", "sec-share-"))]
        self.assertEqual(len(modern), self.ds.counts()["modernNamedGroups"])
        self.assertEqual(len(modern), 198)
        apps = frozenset(a.slug for a in self.ds.applications)
        depts = frozenset(d.slug for d in self.ds.departments)
        self.assertTrue(check_name("sec-okta-crm-user", applications=apps, departments=depts, prefix="sec").conforms)
        self.assertFalse(check_name("sec-okta-crm-user", applications=apps, departments=depts).conforms)
        self.assertEqual(check_name("di-systems-administrators", applications=apps, departments=depts, prefix="sec").style,
                         "di-<name>")
        # Department abbreviations that only begin with the same letters are not the prefix (ADR-0010).
        self.assertIn("Sec-GRC", {g.name for g in self.ds.groups})
        okta_names = {g.okta_name for g in self.ds.groups if g.okta_name}
        self.assertTrue({"SEC-OKTA-VPN-USER", "SEC-OKTA-MDM-ADMIN"} <= okta_names)

    def test_correlation_expectations_match_the_legacy_dataset(self):
        legacy = {g.key: g.correlation_case for g in legacy_dataset().groups if g.okta_visible}
        current = {g.key: g.correlation_case for g in self.ds.groups if g.okta_visible}
        self.assertEqual(current, legacy)

    def test_candidate_groups_are_the_scenario_s(self):
        groups = {g["canonical_id"]: g for g in self.projection.records("groups.jsonl")}
        apps = {a["canonical_id"]: a for a in self.projection.records("applications.jsonl")}
        specs = {c.key: c for c in candidates()}
        self.assertEqual(sorted(specs), sorted(SCENARIO_EXPECTATIONS))
        for key, (group, app, state) in SCENARIO_EXPECTATIONS.items():
            with self.subTest(candidate=key):
                self.assertEqual(specs[key].group_key, groups[group]["legacy_group_key"])
                self.assertEqual(specs[key].application, apps[app]["legacy_slug"])
                self.assertEqual(specs[key].expected.value, state)
        self.assertEqual([c.key.replace("NM-C", "GP-C") for c in LEGACY_CANDIDATES], list(specs))
        # GP-C10's imperfect evidence is the scenario's observation pair.
        observations = {(o["behaviour"], tuple(o["scope"])) for o in self.projection.header["observations"]}
        self.assertEqual(observations, {("timeout", ("grp_6FFD8EFKH6VG",)), ("partial", ("grp_6FFD8EFKH6VG",))})

    def test_portfolio_scenarios_keep_their_stories(self):
        scenarios = {s.key: s for s in self.ds.scenarios}
        self.assertEqual([s.number for s in self.ds.scenarios], list(range(1, 11)))
        self.assertEqual(scenarios["empty-assigned"].candidate_key, "GP-C02")
        self.assertIn("sec-okta-status-page-admin", scenarios["empty-assigned"].summary)
        index = self.ds.index
        self.assertEqual(len(index.effective("app:status-page:modern:admin")), 0)
        self.assertEqual(index.depth("app:warehouse:modern:readonly"), 4)
        # All-Staff nests the department groups; in the shared world their members are the canonical people
        # (ADG's department groups are canonical where both apps had one), 1,598 of them (legacy: 1,798). 1,624 before
        # SYNTH-CROSSAPP-01: OGWA's eng-*/Fin-/Mkt-/Ops-/Sec- team groups under All-Staff are ADG's team groups since
        # D-XA-01, with ADG's members.
        self.assertEqual(len(index.effective("all-staff")), 1598)

    def test_no_former_organization_value_in_demo_facing_output(self):
        for path, text in generated_files(self.ds).items():
            self.assertEqual(old_values(text.replace('"legacy', "")), [], path.name)
        for name in ("config/genesee-press/ogwa-overlay.json", "config/policies/genesee-press/GP-LIFECYCLE-004-1.1.0.json",
                     "config/policies/genesee-press/GP-LIFECYCLE-004-1.2.0.json"):
            text = (REPO_ROOT / name).read_text()
            self.assertEqual(old_values(text.replace("legacy Null Meridian generator", "")), [], name)
        self.assertEqual(old_values(SAMPLE_PATH.read_text()), [])

    def test_committed_files_are_current(self):
        for path, text in generated_files(self.ds).items():
            self.assertEqual(path.read_text(encoding="utf-8"), text, path.name)
        self.assertEqual(OVERLAY_PATH.read_text(encoding="utf-8"), render(build_overlay(legacy_dataset(), self.projection)))

    def test_output_does_not_depend_on_hash_randomization(self):
        code = ("from app.demo.genesee_press.dataset import build_dataset; import hashlib, json; "
                "print(hashlib.sha256(json.dumps(build_dataset().counts(), sort_keys=True).encode()).hexdigest(), "
                "hashlib.sha256(''.join(f.id for f in build_dataset().findings).encode()).hexdigest())")
        outputs = {subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=True,
                                  env={**os.environ, "PYTHONHASHSEED": seed}).stdout for seed in ("1", "2")}
        self.assertEqual(len(outputs), 1)


class SeededGeneseePressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.summary = create_genesee_press_store(memory_target())
        cls.by_key = {s.key: s for s in cls.summary.scenarios}

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_golden_audit_head(self):
        self.assertEqual(self.summary.audit_head, GOLDEN_AUDIT_HEAD)
        self.assertEqual(self.summary.namespace, "genesee-press-v1")
        self.assertEqual(self.store.audit_head()[0] + 1, GOLDEN_AUDIT_EVENTS)

    def test_candidates_reach_the_scenario_s_states(self):
        self.assertEqual(sorted(self.by_key), sorted(SCENARIO_EXPECTATIONS))
        for key, (_, _, state) in SCENARIO_EXPECTATIONS.items():
            with self.subTest(candidate=key):
                self.assertEqual(self.store.load_candidate(self.by_key[key].candidate_id).state.value, state)

    def test_golden_correlation_outcomes(self):
        latest = self.store.connection.execute(
            "SELECT o.confidence FROM identity_mapping_observations o WHERE o.observed_at = (SELECT max(p.observed_at) "
            "FROM identity_mapping_observations p WHERE p.mapping_id = o.mapping_id)").fetchall()
        self.assertEqual(dict(Counter(r[0] for r in latest)), GOLDEN_CONFIDENCES)

    def test_every_record_is_synthetic_and_genesee_press(self):
        conn = self.store.connection
        self.assertEqual({r[0] for r in conn.execute("SELECT DISTINCT domain FROM ad_group_observations")},
                         {"corp.geneseepress.example"})
        self.assertTrue(all(r[0].startswith("00gSYNTHGP") for r in conn.execute("SELECT okta_group_id FROM okta_groups")))
        self.assertTrue(all(r[0].startswith("0oaSYNTHGP") for r in conn.execute("SELECT okta_app_id FROM okta_applications")))
        info = self.store.synthetic_directory()
        self.assertEqual((info.dataset, info.seed, info.company, info.record_count),
                         ("genesee-press", "genesee-press-v1", "Genesee Press", GOLDEN_DIRECTORY_RECORDS))
        self.assertEqual(self.store.verify_integrity(expected_audit_head=self.summary.audit_head).directory_records_checked,
                         GOLDEN_DIRECTORY_RECORDS)
        text = "\n".join(r[0] for r in conn.execute("SELECT body FROM synthetic_directory_records"))
        self.assertEqual(old_values(text), [])

    def test_seeding_twice_gives_the_same_head(self):
        store, summary = create_genesee_press_store(memory_target())
        try:
            self.assertEqual(summary.audit_head, self.summary.audit_head)
        finally:
            store.close()

    def test_registry_defaults_to_genesee_press(self):
        self.assertEqual((DEFAULT_DATASET, DATASET_KEYS), ("genesee-press", ("genesee-press", "null-meridian", "classic")))
        entry = dataset("genesee-press")
        self.assertEqual((entry.namespace, entry.correlation_path.name), ("genesee-press-v1", "correlation.genesee-press.json"))
        self.assertEqual(dataset_of(self.store).key, "genesee-press")
        guide = entry.walkthrough(public=True)
        self.assertEqual([p["candidateKey"] for p in guide["parts"]], ["GP-C10", "GP-C11"])
        self.assertEqual(old_values(json.dumps(guide)), [])

    def test_the_committed_audit_sample_is_what_this_build_generates(self):
        self.assertEqual(SAMPLE_PATH.read_text(encoding="utf-8"), audit_sample.render(build_audit_sample()))


class HostedGeneseePressTests(unittest.TestCase):
    """The public hosted demo (Cloudflare Worker) over a Genesee Press image, as ``wrangler.jsonc`` selects it.
    The full hosted contract is ``tests/test_cloudflare_hosted.py`` (dataset-independent, run on Null Meridian)."""

    @classmethod
    def setUpClass(cls):
        from app.cloudflare.hosted import HostedDemo
        from tests.test_cloudflare_hosted import demo_image

        cls.tmp = tempfile.TemporaryDirectory(prefix="ogwa-gp-hosted-")
        environment = json.loads((REPO_ROOT / "cloudflare" / "worker" / "wrangler.jsonc").read_text())["vars"]
        cls.assert_environment = environment
        image = demo_image(Path(cls.tmp.name), environment["OGWA_DEMO_DATASET"])
        cls.hosted = HostedDemo(lambda: image, environment, expected={"audit_head": GOLDEN_AUDIT_HEAD})

    @classmethod
    def tearDownClass(cls):
        cls.hosted.app.close()
        cls.tmp.cleanup()

    def test_the_worker_serves_genesee_press(self):
        from tests.test_cloudflare_hosted import V, Client

        self.assertEqual(self.assert_environment, {"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": "genesee-press"})
        client = Client(self.hosted)
        status, _, health = client.request("GET", f"{V}/health")
        self.assertEqual((status, health["organization"], health["dataset"]["seed"], health["dataset"]["primaryDomain"]),
                         (200, "Genesee Press", "genesee-press-v1", "geneseepress.example"))
        client.visit()
        self.assertEqual(client.request("GET", f"{V}/directory")[2]["counts"], build_dataset().counts())
        people = client.request("GET", f"{V}/people?q=GP-00001")[2]["items"]
        self.assertEqual(len(people), 1)

    def test_a_visitor_drills_gp_c11_only_and_nothing_is_recorded(self):
        from app.runtime.api import DRILL_SCOPE_MESSAGE
        from tests.test_cloudflare_hosted import V, Client

        visitor = Client(self.hosted)
        visitor.visit()
        head = visitor.audit_head()
        c11, c10 = visitor.scenario("GP-C11"), visitor.scenario("GP-C10")
        self.assertEqual(visitor.request("GET", f"{V}/session")[2]["principal"]["publicDrillCandidates"], [c11])
        detail = visitor.request("GET", f"{V}/candidates/{c11}")[2]
        approval = visitor.request("GET", f"{V}/candidates/{c11}/approvals")[2]["items"][0]["id"]
        body = {"operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": detail["candidate"]["assignmentIds"][0]},
                "approvalId": approval, "expectedEvidenceFingerprint": detail["evidenceFingerprint"],
                "mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"}
        status, _, answer = visitor.request("POST", f"{V}/candidates/{c11}/remediation-drills", body)
        self.assertEqual((status, answer["drill"]["finalState"], answer["drill"]["recorded"]),
                         (200, "POST_ACTION_VERIFIED", False))
        self.assertEqual((answer["chain"]["policyId"], answer["chain"]["policyVersion"]), ("GP-LIFECYCLE-004", "1.2.0"))
        d10 = visitor.request("GET", f"{V}/candidates/{c10}")[2]
        status, _, refused = visitor.request("POST", f"{V}/candidates/{c10}/remediation-drills", {
            **body, "target": {"assignmentId": d10["candidate"]["assignmentIds"][0]},
            "expectedEvidenceFingerprint": d10["evidenceFingerprint"]})
        self.assertEqual((status, refused["error"]["code"], refused["error"]["message"]),
                         (403, "PUBLIC_DRILL_SCOPE", DRILL_SCOPE_MESSAGE))
        self.assertEqual(d10["evidenceAssessment"]["decision"]["code"], "CONFLICTING_EVIDENCE")
        self.assertEqual(visitor.audit_head(), head)


if __name__ == "__main__":
    unittest.main()
