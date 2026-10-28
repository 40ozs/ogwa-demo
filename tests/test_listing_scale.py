"""OGWA-UI-IA-02: store-backed listings are filtered, sorted, and paged in one query, so a sorted
page loads only its own records, on the demo worlds and on a synthetic tenant ten times larger.

The expected order is computed here from the served items and the names ``GET /identities``
gives: by the value the UI shows, a missing value last in both directions, and ties in the
listing's own order, which ends in the stable id.
"""

import unittest
from collections import Counter
from unittest import mock

from app.api.readmodel import PAGED
from app.api.resolve import ID_RE
from app.api.validation import encode_cursor
from app.domain.model import MappingConfidence
from app.store.store import Store
from tests.api_fixtures import ADMIN, VIEWER, World
from tests.scale_fixtures import ScaleTenant
from tests.test_ui_ia import V, every_page

RANK = {c.value: i for i, c in enumerate(MappingConfidence)}
LISTINGS = {"/applications": "applications", "/groups": "groups", "/mappings": "mappings",
            "/dependency-findings": "dependencies", "/candidates": "candidates", "/approvals": "approvals",
            "/execution-jobs": "jobs", "/collector-runs": "collectors"}


def text(value):
    return value.casefold() if value else None


def expected(items, key, descending: bool) -> list[str]:
    present = [x for x in items if key(x) is not None]  # sorted() is stable, also in reverse
    return [x["id"] for x in sorted(present, key=key, reverse=descending) + [x for x in items if key(x) is None]]


def sort_keys(names: dict[str, str | None]) -> dict[str, dict]:
    """Each listing's sortable fields, as keys over the served item."""
    seen = {"observedAt": lambda r: r["provenance"]["observedAt"], "result": lambda r: r["provenance"]["resultStatus"]}
    name = lambda field: lambda r: text(names.get(r[field]))  # noqa: E731
    outcome = lambda field: lambda r: r["outcome"][field] if r["outcome"] else None  # noqa: E731
    return {
        "/applications": {**seen, "label": lambda a: text(a["label"]), "status": lambda a: a["status"],
                          "signOnMode": lambda a: a["signOnMode"]},
        "/groups": {**seen, "name": lambda g: text(g["name"]), "groupType": lambda g: g["groupType"],
                    "directoryQualifiedName": lambda g: text(g["directoryQualifiedName"])},
        "/mappings": {**seen, "confidence": lambda m: RANK[m["confidence"]], "oktaGroup": name("oktaGroupId"),
                      "adGroup": name("adGroupId")},
        "/dependency-findings": {**seen, "dependencyKind": lambda d: d["dependencyKind"], "subject": name("subjectId"),
                                 "findings": lambda d: (sum(f["blocking"] for f in d["findings"]), len(d["findings"]))},
        "/candidates": {"oktaGroup": name("oktaGroupId"), "state": lambda c: c["state"],
                        "holdUntil": lambda c: c["holdUntil"], "updatedAt": lambda c: c["updatedAt"],
                        "createdAt": lambda c: c["createdAt"]},
        "/approvals": {"stage": lambda a: a["stage"], "decision": lambda a: a["decision"],
                       "decidedAt": lambda a: a["decidedAt"], "expiresAt": lambda a: a["expiresAt"],
                       "candidate": name("candidateId")},
        "/execution-jobs": {"kind": lambda j: j["kind"], "status": lambda j: j["status"],
                            "requestedAt": lambda j: j["requestedAt"], "candidate": name("candidateId")},
        "/collector-runs": {"collector": lambda r: r["collector"], "startedAt": lambda r: r["startedAt"],
                            "outcome": outcome("status"), "records": outcome("recordsObserved")},
    }


class Contract:
    """Every sortable field of every store-backed listing, in both directions, across all pages."""

    client = None

    def names(self, items: list[dict]) -> dict[str, str | None]:
        ids = sorted({x[f] for x in items for f in ("oktaGroupId", "adGroupId", "subjectId", "candidateId")
                      if ID_RE.match(x.get(f) or "")})  # /groups' oktaGroupId is Okta's own id
        found = {}
        for i in range(0, len(ids), 40):  # as the UI batches them: the query is capped at 2,048 characters
            found.update(self.client.get(f"{V}/identities?ids={','.join(ids[i:i + 40])}").json["items"])
        return {ref: entry.get("name") for ref, entry in found.items()}

    def check(self, path: str, limit: int = 200) -> None:
        base = path.split("?")[0]
        own = every_page(self.client, path, limit)
        keys = sort_keys(self.names(own))[base]
        self.assertEqual(set(keys), set(PAGED[LISTINGS[base]][2]), "a sortable field without a reference order")
        sep = "&" if "?" in path else "?"
        for field, key in keys.items():
            for order in ("asc", "desc"):
                with self.subTest(path=path, sort=field, order=order):
                    served = every_page(self.client, f"{path}{sep}sort={field}&order={order}", limit)
                    self.assertEqual([x["id"] for x in served], expected(own, key, order == "desc"))


class DemoWorldOrderTests(Contract, unittest.TestCase):
    """The classic world has approvals, jobs, and collector runs; Null Meridian has the directory
    snapshot, whose common names (not sAMAccountNames) are what AD groups sort by."""

    def test_every_sortable_field_on_both_demo_worlds(self):
        for dataset in ("classic", "null-meridian"):
            world = World(dataset=dataset)
            try:
                self.client = world.client(VIEWER)
                for path in LISTINGS:
                    self.check(path, limit=7)  # several pages even on the small worlds
            finally:
                world.close()

    def test_a_filter_applies_before_sorting_and_paging(self):
        world = World()
        try:
            self.client = world.client(VIEWER)
            self.check("/candidates?state=DEPENDENCY_BLOCKED", limit=2)
            first = self.client.get(f"{V}/candidates?state=DEPENDENCY_BLOCKED&sort=oktaGroup&order=desc&limit=2").json
            self.assertEqual((len(first["items"]), first["page"]["total"]), (2, 3))
            everyone = every_page(self.client, "/candidates?state=DEPENDENCY_BLOCKED&sort=oktaGroup&order=desc", 2)
            self.assertEqual({c["state"] for c in everyone}, {"DEPENDENCY_BLOCKED"})
            # A filter that left the list shorter than the page asked for: an empty page, never an error.
            past = self.client.get(f"{V}/candidates?state=DEPENDENCY_BLOCKED&sort=oktaGroup&limit=2"
                                   f"&cursor={encode_cursor(4)}").json
            self.assertEqual((past["items"], past["page"]["total"], past["page"]["nextCursor"]), ([], 3, None))
            self.assertEqual(past["page"]["previousCursor"], encode_cursor(2))
        finally:
            world.close()


class LargeTenantTests(Contract, unittest.TestCase):
    """3,000 Okta groups, AD groups, and mappings: ten times the demo."""

    @classmethod
    def setUpClass(cls):
        cls.tenant = ScaleTenant(groups=3000)
        cls.client = cls.tenant.client()

    @classmethod
    def tearDownClass(cls):
        cls.tenant.close()

    def get(self, path: str) -> dict:
        result = self.client.get(V + path)
        self.assertEqual(result.status, 200, result.json)
        return result.json

    def test_every_sortable_field_across_every_page(self):
        for path in ("/applications", "/groups", "/mappings", "/dependency-findings", "/candidates"):
            self.check(path)

    def test_a_sorted_page_loads_only_its_own_records(self):
        loads = Counter()

        def counting(name, real):
            def load(store, *args, **kwargs):
                loads[name] += 1
                return real(store, *args, **kwargs)
            return load

        with mock.patch.object(Store, "latest", counting("latest", Store.latest)), \
                mock.patch.object(Store, "load_candidate", counting("candidate", Store.load_candidate)):
            for path in ("/groups?sort=name&order=desc", "/mappings?sort=adGroup", "/mappings?sort=oktaGroup",
                         "/mappings?sort=confidence", "/dependency-findings?sort=subject",
                         "/candidates?sort=oktaGroup&order=desc", "/applications?sort=label"):
                with self.subTest(path=path):
                    loads.clear()
                    body = self.get(f"{path}&limit=25&cursor={encode_cursor(25)}")
                    self.assertEqual(len(body["items"]), 25)
                    self.assertEqual(sum(loads.values()), 25, "only the page's own records are loaded")
            loads.clear()
            self.assertEqual(self.get("/dashboard")["dependencyFindings"],
                             {"checks": 600, "checksWithFindings": 200, "findings": 200, "blocking": 200})
            self.assertEqual(loads["latest"], 0, "the dashboard counts dependency findings without loading them")

    def test_ties_break_by_stable_id_in_both_directions(self):
        for order in ("asc", "desc"):
            groups = every_page(self.client, f"/groups?sort=name&order={order}")
            ties = [(a, b) for a, b in zip(groups, groups[1:]) if a["name"] == b["name"]]
            self.assertEqual(len(ties), 2000, "every name is shared by three groups")
            self.assertTrue(all(a["id"] < b["id"] for a, b in ties))

    def test_missing_values_sort_last_either_way(self):
        for order in ("asc", "desc"):
            mappings = every_page(self.client, f"/mappings?sort=adGroup&order={order}")
            unmapped = [m["adGroupId"] is None for m in mappings]
            self.assertEqual(unmapped, sorted(unmapped), "mappings without an AD group come last")
            self.assertEqual(sum(unmapped), 300)

    def test_first_last_single_empty_and_out_of_range_pages(self):
        everyone = expected(every_page(self.client, "/groups"), lambda g: text(g["name"]), False)
        first = self.get("/groups?sort=name&limit=7")
        self.assertEqual([g["id"] for g in first["items"]], everyone[:7])
        self.assertEqual((first["page"]["offset"], first["page"]["previousCursor"]), (0, None))
        last = self.get(f"/groups?sort=name&limit=7&cursor={encode_cursor(2996)}")  # 3000 = 428 * 7 + 4
        self.assertEqual([g["id"] for g in last["items"]], everyone[-4:])
        self.assertEqual((last["page"]["nextCursor"], last["page"]["total"]), (None, 3000))
        single = self.get("/applications?sort=label&order=desc&limit=100")
        self.assertEqual((len(single["items"]), single["page"]["nextCursor"], single["page"]["previousCursor"]),
                         (60, None, None))
        for path in ("/approvals?sort=candidate", "/execution-jobs?sort=status", "/collector-runs?sort=outcome"):
            with self.subTest(empty=path):
                empty = self.get(path)
                self.assertEqual((empty["items"], empty["page"]["total"], empty["page"]["nextCursor"]), ([], 0, None))
        past = self.get(f"/mappings?sort=adGroup&cursor={encode_cursor(5000)}")
        self.assertEqual((past["items"], past["page"]["offset"], past["page"]["total"]), ([], 5000, 3000))


class AuditTrailOrderTests(unittest.TestCase):
    """The audit trail stays in its chain's sequence order: no other sort, and no gap or repeat
    between pages (OGWA-UI-IA-02 keeps this as the one deliberate exception)."""

    def test_sequence_order_is_continuous_across_pages(self):
        world = World(dataset="null-meridian")
        try:
            admin = world.client(ADMIN)
            total = admin.get(f"{V}/audit-events?limit=1").json["page"]["total"]
            for path, step in (("/audit-events", -1), ("/audit-events?sort=sequence&order=asc", 1)):
                with self.subTest(path=path):
                    sequences = [e["sequence"] for e in every_page(admin, path)]
                    self.assertEqual(len(sequences), total)
                    self.assertTrue(all(b - a == step for a, b in zip(sequences, sequences[1:])))
            candidate = world.candidate("NM-C08")
            events = every_page(admin, f"/candidates/{candidate}/audit-events", limit=2)
            sequences = [e["sequence"] for e in events]
            self.assertGreater(len(sequences), 2)
            self.assertEqual(sequences, sorted(sequences, reverse=True), "a candidate's trail is newest first")
            self.assertEqual(admin.get(f"{V}/audit-events?sort=occurredAt").status, 400)
        finally:
            world.close()


if __name__ == "__main__":
    unittest.main()
