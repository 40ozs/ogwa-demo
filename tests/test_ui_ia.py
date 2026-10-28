"""OGWA-UI-IA-01 on the API side: sorted and counted listings, and the identity resolver.

Everything runs over real seeded worlds (Null Meridian, and the classic world for evidence
without a directory snapshot). The UI's presentation of these answers is covered by
tests/ui/present.test.mjs and the browser gate.
"""

import unittest
from dataclasses import replace
from datetime import timedelta

from app.demo.synthetic_world import COLLECTOR
from app.domain.model import ADGroup, OktaGroup
from tests.api_fixtures import ADMIN, VIEWER, World

V = "/api/v1"


def every_page(client, path: str, limit: int = 200) -> list[dict]:
    items, cursor = [], None
    sep = "&" if "?" in path else "?"
    while True:
        body = client.get(f"{V}{path}{sep}limit={limit}" + (f"&cursor={cursor}" if cursor else "")).json
        items += body["items"]
        cursor = body["page"]["nextCursor"]
        if not cursor:
            return items


class SortedListingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")
        cls.client = cls.world.client(VIEWER)
        cls.admin = cls.world.client(ADMIN)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def get(self, path, client=None):
        return (client or self.client).get(V + path)

    def test_every_listing_counts_its_rows_and_steps_both_ways(self):
        for path, client in (("/people", None), ("/directory-groups", None), ("/governance-findings", None),
                             ("/applications", None), ("/groups", None), ("/mappings", None),
                             ("/dependency-findings", None), ("/candidates", None), ("/approvals", None),
                             ("/execution-jobs", None), ("/collector-runs", None), ("/audit-events", self.admin)):
            with self.subTest(listing=path):
                first = self.get(f"{path}?limit=2", client).json["page"]
                self.assertEqual((first["offset"], first["previousCursor"]), (0, None))
                self.assertIsInstance(first["total"], int)
                if first["nextCursor"]:
                    second = self.get(f"{path}?limit=2&cursor={first['nextCursor']}", client).json["page"]
                    self.assertEqual(second["offset"], 2)
                    back = self.get(f"{path}?limit=2&cursor={second['previousCursor']}", client).json["page"]
                    self.assertEqual(back["offset"], 0)

    def test_sorting_holds_across_pages_in_both_directions(self):
        everyone = every_page(self.client, "/people?sort=displayName")
        self.assertEqual(len(everyone), 2809)
        names = [p["displayName"].casefold() for p in everyone]
        self.assertEqual(names, sorted(names))
        backwards = [p["displayName"].casefold() for p in every_page(self.client, "/people?sort=displayName&order=desc")]
        self.assertEqual(backwards, sorted(names, reverse=True))
        # Ties keep the listing's own order (hire order) in both directions: a stable sort.
        hired = every_page(self.client, "/people")
        rank = {p["id"]: i for i, p in enumerate(hired)}
        for ordered in (everyone, every_page(self.client, "/people?sort=displayName&order=desc")):
            for a, b in zip(ordered, ordered[1:]):
                if a["displayName"] == b["displayName"]:
                    self.assertLess(rank[a["id"]], rank[b["id"]])

    def test_a_missing_deactivation_date_sorts_last_either_way(self):
        for order in ("asc", "desc"):
            with self.subTest(order=order):
                people = every_page(self.client, f"/people?sort=terminationDate&order={order}")
                dates = [p["terminationDate"] for p in people]
                known = [d for d in dates if d]
                self.assertEqual(dates[len(known):], [None] * (len(dates) - len(known)))
                self.assertEqual(known, sorted(known, reverse=order == "desc"))

    def test_final_partial_page_empty_listing_and_a_page_past_the_end(self):
        last = self.get("/people?limit=200&cursor=bzoyODAw").json  # offset 2800 of 2809
        self.assertEqual((len(last["items"]), last["page"]["nextCursor"], last["page"]["total"]), (9, None, 2809))
        empty = self.get("/people?q=nobody-is-called-this").json
        self.assertEqual((empty["items"], empty["page"]["total"], empty["page"]["nextCursor"]), ([], 0, None))
        past = self.get("/directory-groups?cursor=bzo1MDAw").json  # offset 5000 of 401
        self.assertEqual((past["items"], past["page"]["offset"], past["page"]["total"]), ([], 5000, 401))

    def test_sort_and_order_are_validated(self):
        for path in ("/people?sort=salary", "/people?sort=displayName&order=up", "/groups?sort=digest",
                     "/audit-events?sort=action"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path, self.admin).status, 400)

    def test_store_listings_sort_by_what_the_ui_shows(self):
        groups = [g["name"].casefold() for g in every_page(self.client, "/groups?sort=name")]
        self.assertEqual(groups, sorted(groups))
        mappings = every_page(self.client, "/mappings?sort=adGroup")
        names = self.get("/identities?ids=" + ",".join(m["adGroupId"] for m in mappings[:40] if m["adGroupId"])).json["items"]
        shown = [names[m["adGroupId"]]["name"].casefold() for m in mappings[:40] if m["adGroupId"]]
        self.assertEqual(shown, sorted(shown))
        self.assertTrue(all(m["adGroupId"] is None for m in mappings[len([m for m in mappings if m["adGroupId"]]):]),
                        "mappings without an AD group sort last")

    def test_the_audit_trail_sorts_only_by_sequence(self):
        newest = self.get("/audit-events?limit=3", self.admin).json["items"]
        oldest = self.get("/audit-events?limit=3&sort=sequence&order=asc", self.admin).json["items"]
        self.assertGreater(newest[0]["sequence"], newest[1]["sequence"])
        self.assertEqual([e["sequence"] for e in oldest], [0, 1, 2])

    def test_a_group_is_found_by_any_of_its_stable_identifiers(self):
        archived = next(g for g in every_page(self.client, "/directory-groups?q=finance-rw") if g["status"] == "DEPRECATED")
        detail = self.get(f"/directory-groups/{archived['id']}").json["group"]
        for q in (detail["adSid"], detail["adObjectGuid"], detail["adEvidenceId"], detail["adSamAccountName"]):
            with self.subTest(q=q):
                found = self.get(f"/directory-groups?q={q}").json["items"]
                self.assertEqual([g["id"] for g in found], [archived["id"]])
                self.assertEqual(found[0]["name"], "Finance-RW", "a SID search still shows the common name")

    def test_deactivations_summary(self):
        body = self.get("/directory").json
        stats = body["deactivations"]
        self.assertEqual(sum(stats["byYear"].values()), body["counts"]["formerEmployees"])
        recent = [p for p in every_page(self.client, "/people?status=TERMINATED")
                  if p["terminationDate"] and p["terminationDate"] > "2026-07-03"]
        self.assertEqual(stats["last90Days"], len(recent))
        self.assertEqual(stats["asOf"], "2026-10-01")

    def test_dashboard_summarizes_dependency_findings(self):
        summary = self.get("/dashboard").json["dependencyFindings"]
        # OGWA-DEMO-01: NM-C10 adds five checks (three complete, one FAILED, one PARTIAL), and NM-C09's
        # membership read now reports the members its AD group object lists (the fourth finding).
        # OGWA-DEMO-03: NM-C11 adds eight complete checks with no finding (re-collected, not added again).
        self.assertEqual(summary, {"checks": 71, "checksWithFindings": 4, "findings": 4, "blocking": 4})


class IdentityResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")
        cls.client = cls.world.client(VIEWER)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def resolve(self, *ids):
        result = self.client.get(f"{V}/identities?ids={','.join(ids)}")
        self.assertEqual(result.status, 200, result.json)
        return result.json["items"]

    def group(self, dgrp: str) -> dict:
        return self.client.get(f"{V}/directory-groups/{dgrp}").json["group"]

    def test_a_sid_and_an_ad_evidence_id_resolve_to_the_common_name_and_the_canonical_page(self):
        all_staff = self.client.get(f"{V}/directory-groups?q=all-staff").json["items"][0]
        detail = self.group(all_staff["id"])
        by_sid, by_ad = self.resolve(detail["adSid"], detail["adEvidenceId"]).values()
        for entry in (by_sid, by_ad):
            self.assertEqual((entry["kind"], entry["name"], entry["route"], entry["routeId"]),
                             ("AD_GROUP", "All-Staff", "directory-groups", all_staff["id"]))
            self.assertEqual(entry["qualifier"], detail["adDistinguishedName"], "the raw identity stays available")

    def test_groups_that_share_a_name_never_resolve_to_each_other(self):
        named = [g for g in self.client.get(f"{V}/directory-groups?q=finance-rw").json["items"] if g["name"] == "Finance-RW"]
        ad = [g for g in named if g["source"] == "AD"]
        self.assertEqual((len(named), len(ad)), (3, 2), "two AD groups and an Okta group are all named Finance-RW")
        evidence = [self.group(g["id"])["adEvidenceId"] for g in ad]
        resolved = self.resolve(*evidence)
        for g, ref in zip(ad, evidence):
            entry = resolved[ref]
            self.assertEqual(entry["routeId"], g["id"], "each AD evidence id opens its own group")
            self.assertTrue(entry["ambiguous"])
        self.assertNotEqual(resolved[evidence[0]]["qualifier"], resolved[evidence[1]]["qualifier"])
        self.assertTrue(all(g["ambiguous"] for g in named))

    def test_unresolved_and_unsupported_ids_are_reported_never_hidden(self):
        missing, job = "adg_" + "0" * 32, "job_" + "0" * 32
        out = self.resolve(missing, job, "S-1-5-21-1-2-3-999999")
        self.assertEqual(out[missing], {"kind": "AD_GROUP", "resolved": False})
        self.assertEqual(out[job], {"kind": None, "resolved": False})
        self.assertFalse(out["S-1-5-21-1-2-3-999999"]["resolved"])

    def test_names_are_never_lookup_keys(self):
        for bad in ("All-Staff", "adg_XYZ", "x" * 40, ",".join(f"adg_{i:032x}" for i in range(51))):
            with self.subTest(ids=bad[:30]):
                self.assertEqual(self.client.get(f"{V}/identities?ids={bad}").status, 400)
        # Null Meridian records its policy versions (OGWA-DEMO-02), so no unrecorded-policy notice is added.
        self.assertEqual(self.client.get(f"{V}/identities").json, {"items": {}})

    def test_an_okta_group_shows_its_ad_counterpart_only_from_an_exact_mapping(self):
        mappings = self.client.get(f"{V}/mappings?limit=200").json["items"]
        exact = next(m for m in mappings if m["isExact"] and m["adGroupId"])
        loose = next(m for m in mappings if not m["isExact"] and m["adGroupId"])
        out = self.resolve(exact["oktaGroupId"], loose["oktaGroupId"])
        self.assertEqual(out[exact["oktaGroupId"]]["mappedAdGroup"]["id"], exact["adGroupId"])
        self.assertEqual(out[exact["oktaGroupId"]]["route"], "groups")
        self.assertNotIn("mappedAdGroup", out[loose["oktaGroupId"]], "a name-only or unverified mapping names no AD group")

    def test_access_chains_link_to_the_groups_they_name_in_order(self):
        person = self.client.get(f"{V}/people?department=finance&status=ACTIVE&limit=1").json["items"][0]
        access = self.client.get(f"{V}/people/{person['id']}").json["access"]
        chains = [r["chain"] for a in access for r in a["routes"] if not r["direct"]]
        self.assertTrue(chains)
        nodes = {n["id"]: n for chain in chains for n in chain}
        resolved = {}
        ids = list(nodes)
        for i in range(0, len(ids), 50):
            resolved.update(self.resolve(*ids[i:i + 50]))
        for ref, node in nodes.items():
            self.assertEqual((resolved[ref]["name"], resolved[ref]["routeId"]), (node["name"], ref))
            self.assertIn("qualifier", node, "chain nodes carry the qualifier for shared names")

    def test_people_and_candidates_resolve(self):
        person = self.client.get(f"{V}/people?status=TERMINATED&limit=1").json["items"][0]
        candidate = self.client.get(f"{V}/candidates?limit=1").json["items"][0]
        out = self.resolve(person["id"], candidate["id"])
        self.assertEqual((out[person["id"]]["name"], out[person["id"]]["status"]), (person["displayName"], "TERMINATED"))
        okta = self.world.store.latest(OktaGroup, candidate["oktaGroupId"])
        self.assertEqual((out[candidate["id"]]["name"], out[candidate["id"]]["route"]), (okta.name, "candidates"))


class RenamedGroupTests(unittest.TestCase):
    """Without a directory snapshot, a name comes from the AD evidence's latest observation."""

    def test_a_renamed_ad_group_still_resolves_by_its_stable_id(self):
        world = World()
        try:
            client = world.client(VIEWER)
            ad_id = next(m["adGroupId"] for m in client.get(f"{V}/mappings?limit=200").json["items"] if m["adGroupId"])
            before = client.get(f"{V}/identities?ids={ad_id}").json["items"][ad_id]
            self.assertEqual((before["kind"], before["route"], before["ambiguous"]), ("AD_GROUP", None, None))
            ad = world.store.latest(ADGroup, ad_id)
            world.store.record_evidence(replace(ad, sam_account_name="Renamed-Group", provenance=replace(
                ad.provenance, observed_at=ad.provenance.observed_at + timedelta(hours=1))), actor=COLLECTOR)
            after = client.get(f"{V}/identities?ids={ad_id}").json["items"][ad_id]
            self.assertEqual(after["name"], "Renamed-Group")
            self.assertEqual(after["qualifier"], ad.distinguished_name)
        finally:
            world.close()


if __name__ == "__main__":
    unittest.main()
