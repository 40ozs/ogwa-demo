"""OGWA-REVIEW-QUEUE-API-01: the server-side Review queue, the current evidence verdict per row,
approval usability in listings, and the directory group -> lifecycle candidate link.

The queue's order is checked against the UI's own ``review.js queueOrder`` (run under Node over
the served rows), its status table against ``review.js STATUS_OF``, its paging over a synthetic
tenant of more than 1,000 candidates, and its reads against the store's audit head. Approval
usability is checked against what the server then does with the approval. The directory link is
checked against the identity mappings, never against names.
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import unittest
from datetime import timedelta
from pathlib import Path

from app.api.readmodel import PAGED, REVIEW_STATUS, REVIEW_STATUSES, review_filter, review_status
from app.api.validation import encode_cursor
from app.api.review_queue import AGREES, DIFFERS, NOT_APPLICABLE, UNAVAILABLE, agreement
from app.domain.lifecycle import LifecycleState
from tests.api_fixtures import AUTOMATION, EXECUTOR, NO_ROLE, SECURITY, SECURITY_2, VIEWER, World
from tests.scale_fixtures import ScaleTenant
from tests.test_ui_ia import every_page

REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEW_JS = REPO_ROOT / "app" / "ui" / "static" / "js" / "review.js"
NODE = shutil.which("node")
V = "/api/v1"
Q = f"{V}/review-queue"


def ui_queue_order(items: list[dict], now: str | None) -> list[str]:
    """The ids of ``items`` in the order the UI's own review.js queueOrder puts them."""
    script = ("import { queueOrder } from " + json.dumps(REVIEW_JS.as_uri()) + ";\n"
              "let raw = ''; process.stdin.on('data', (d) => { raw += d; }).on('end', () => {\n"
              "  const { items, now } = JSON.parse(raw);\n"
              "  process.stdout.write(JSON.stringify([...items].sort(queueOrder(now)).map((c) => c.id)));\n"
              "});\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("OGWA_")}
    env["NODE_OPTIONS"] = ""
    result = subprocess.run([NODE, "--input-type=module", "-e", script], input=json.dumps({"items": items, "now": now}),
                            capture_output=True, text=True, encoding="utf-8", timeout=120, env=env, cwd=REPO_ROOT)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def audit_state(store) -> tuple:
    return store.audit_head(), store.connection.total_changes


class ReviewStatusTable(unittest.TestCase):
    def test_the_server_table_is_the_ui_table(self):
        block = re.search(r"const STATUS_OF = Object\.freeze\(\{(.*?)\}\);", REVIEW_JS.read_text(encoding="utf-8"),
                          re.S).group(1)
        ui = dict(re.findall(r"\b([A-Z_]+): \"([a-z-]+)\"", block))
        self.assertEqual({s.value: k for s, k in REVIEW_STATUS.items()}, ui)
        self.assertEqual(set(REVIEW_STATUS), set(LifecycleState), "every lifecycle state has one review status")

    def test_conservative_readings(self):
        self.assertEqual(review_status("PROTECTED"), "closed")
        self.assertEqual(review_status("DELETION_REVALIDATION_REQUIRED"), "needs-review")
        self.assertEqual(review_status("SOMETHING_NEW"), "blocked")
        self.assertNotIn("ready", " ".join(REVIEW_STATUSES))

    def test_sql_filter_and_order_treat_an_unknown_state_as_blocked(self):
        # The store refuses unknown states, so the SQL is run on a scratch table of the same shape.
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE candidates (id TEXT, group_id TEXT, state TEXT, hold_until TEXT, "
                     "quarantine_hold_until TEXT, updated_at TEXT, created_at TEXT)")
        rows = [("c1", "WAITING_X", "HOLD", "2026-01-03", None, "2026-01-01"), ("c2", "N", "NEEDS_REVIEW", None, None, "2026-01-02"),
                ("c3", "U", "SOMETHING_NEW", None, None, "2026-01-01"), ("c4", "B", "BLOCKED", None, None, "2026-01-02"),
                ("c5", "C", "EXCLUDED", None, None, "2026-01-01"), ("c6", "W", "DISCOVERED", None, None, "2026-01-01"),
                ("c7", "Q", "QUARANTINE_HOLD", None, "2026-01-02", "2026-01-05")]
        conn.executemany("INSERT INTO candidates VALUES (?, ?, ?, ?, ?, ?, '2026-01-01')", rows)
        conn.create_function("snapshot_ad_name", 1, lambda ref: None)

        def ids(statuses):
            where, params = review_filter(statuses)
            return [r["id"] for r in conn.execute(f"SELECT a.id FROM candidates a {where} ORDER BY {PAGED['queue'][1]}", params)]

        self.assertEqual(ids(("blocked",)), ["c3", "c4"])
        self.assertEqual(ids(("waiting",)), ["c7", "c1", "c6"], "the nearest hold end first, then the longest wait")
        self.assertEqual(ids(("closed",)), ["c5"])
        self.assertEqual(ids(REVIEW_STATUSES), ["c2", "c3", "c4", "c7", "c1", "c6", "c5"])
        self.assertNotIn("c3", ids(("needs-review", "waiting", "in-progress", "retired", "closed")))


class QueueOnTheClassicWorld(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world = World()
        cls.client = cls.world.client(SECURITY)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def test_rows_counts_and_filters(self):
        body = self.client.get(f"{Q}?status=all&limit=50").json
        states = self.client.get(f"{V}/dashboard").json["candidatesByState"]
        expected = dict.fromkeys(REVIEW_STATUSES, 0)
        for state, n in states.items():
            expected[review_status(state)] += n
        self.assertEqual({k: body["counts"][k] for k in REVIEW_STATUSES}, expected)
        self.assertEqual(body["counts"]["all"], sum(states.values()))
        self.assertEqual(body["page"]["total"], body["counts"]["all"])
        for key in (*REVIEW_STATUSES, "open"):
            rows = every_page(self.client, f"/review-queue?status={key}", 50)
            self.assertEqual(len(rows), body["counts"][key], key)
            wanted = ("needs-review", "blocked", "waiting", "in-progress") if key == "open" else (key,)
            self.assertTrue(all(r["reviewStatus"] in wanted and review_status(r["state"]) == r["reviewStatus"]
                                for r in rows), key)
        self.assertEqual(self.client.get(Q).json["status"], "open")

    def test_order_is_the_uis_queue_order(self):
        body = self.client.get(f"{Q}?status=all&limit=50").json
        served = [r["id"] for r in body["items"]]
        self.assertEqual(served, ui_queue_order(body["items"], body["generatedAt"]))
        self.assertIn("HOLD", [r["state"] for r in body["items"]], "the world has a deadline to order by")

    def test_server_sorts_and_paging_validation(self):
        for field in PAGED["queue"][2]:
            for order in ("asc", "desc"):
                self.assertEqual(self.client.get(f"{Q}?status=all&sort={field}&order={order}").status, 200, field)
        self.assertEqual(self.client.get(Q).json["page"]["limit"], 25)
        for bad in ("status=ready", "status=", "limit=51", "limit=0", "sort=state", "cursor=nope", "q=x"):
            self.assertEqual(self.client.get(f"{Q}?{bad}").status, 400, bad)
        past = self.client.get(f"{Q}?status=all&cursor={encode_cursor(10_000)}").json  # past the end
        self.assertEqual((past["items"], past["page"]["nextCursor"]), ([], None))

    def test_holds_ending_soon_are_counted_on_the_server_clock(self):
        body = self.client.get(f"{Q}?status=all&limit=50").json
        now = self.world.clock.now  # the server read it just before; a later tick changes nothing here
        due = [r for r in body["items"] if (r["holdUntil"] if r["state"] == "HOLD" else
                                            r["quarantineHoldUntil"] if r["state"] == "QUARANTINE_HOLD" else None)]
        self.assertGreaterEqual(len(due), 2)
        self.world.clock.advance(timedelta(days=60))  # every hold is now past
        self.assertEqual(self.client.get(Q).json["holdsEndingWithin7Days"], len(due))
        self.world.clock.now = now

    def test_reading_the_queue_changes_nothing(self):
        before = audit_state(self.world.store)
        states = {r["id"]: r["state"] for r in every_page(self.client, f"/review-queue?status=all", 7)}
        self.client.get(f"{Q}?status=blocked&sort=deadline&order=desc")
        self.assertEqual(audit_state(self.world.store), before)
        self.assertEqual({c: self.world.store.load_candidate(c).state.value for c in states}, states)
        self.assertEqual(self.client.post(Q, {}).status, 405)

    def test_authorization(self):
        self.assertEqual(self.world.client().get(Q).status, 401)
        no_role = self.world.client(NO_ROLE)
        for query in ("", "?status=all", "?status=closed&limit=50", "?sort=deadline&order=desc"):
            self.assertEqual(no_role.get(Q + query).status, 403, query)  # no filter or sort gets round READ_INVENTORY
        for subject in (VIEWER, AUTOMATION, EXECUTOR):
            self.assertEqual(self.world.client(subject).get(f"{Q}?status=all").status, 200, subject)
        # The listing names candidates only, and only the store's.
        rows = every_page(self.client, f"/review-queue?status=all", 50)
        stored = {r["id"] for r in self.world.store.connection.execute("SELECT id FROM candidates")}
        self.assertEqual({r["id"] for r in rows}, stored)
        self.assertTrue(all(r["id"].startswith("cand_") for r in rows))


class EvidenceVerdict(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.client = self.world.client(SECURITY)

    def tearDown(self):
        self.world.close()

    def rows(self):
        return {r["id"]: r for r in every_page(self.client, f"/review-queue?status=all", 50)}

    def test_the_verdict_is_the_candidate_pages(self):
        for cid, row in self.rows().items():
            detail = self.client.get(f"{V}/candidates/{cid}").json
            v, cls = row["evidenceVerdict"], detail["classification"]
            self.assertEqual(v["classification"], cls and cls["classification"], cid)
            self.assertEqual(v["suggestedState"], cls and cls["lifecycleDiversion"], cid)
            self.assertEqual(v["decision"]["code"], detail["evidenceAssessment"]["decision"]["code"], cid)
            self.assertEqual((v["isApproval"], v["autoRemediationEligible"]), (False, False))
            self.assertEqual(row["state"], detail["candidate"]["state"], "the verdict never rewrites the state")

    def test_agreement_disagreement_and_terminal(self):
        rows = self.rows()
        by = lambda key: rows[self.world.candidate(key)]["evidenceVerdict"]  # noqa: E731
        # S03: recorded DEPENDENCY_BLOCKED, and the classifier still parks it there.
        self.assertEqual((by("S03")["agreement"], by("S03")["suggestedState"]), (AGREES, "DEPENDENCY_BLOCKED"))
        # S11: recorded STALE_EVIDENCE; the evidence is still stale.
        self.assertEqual((by("S11")["agreement"], by("S11")["classification"]), (AGREES, "STALE_EVIDENCE"))
        # S06: protected is terminal, so nothing is compared.
        self.assertEqual(by("S06")["agreement"], NOT_APPLICABLE)
        differs = [r for r in rows.values() if r["evidenceVerdict"]["agreement"] == DIFFERS]
        self.assertTrue(any(r["state"] == "NEEDS_REVIEW" and r["evidenceVerdict"]["classification"] == "EVIDENCE_INCOMPLETE"
                            for r in differs), "recorded NEEDS_REVIEW while the evidence is now incomplete")
        for r in differs:  # a disagreement never reads as the more permissive side
            self.assertNotEqual(r["evidenceVerdict"]["decision"]["code"], "ELIGIBLE_FOR_HUMAN_APPROVAL", r["state"])

    def test_evidence_that_went_stale_shows_against_the_recorded_state(self):
        cid = self.world.candidate("S07")
        before = self.rows()[cid]
        self.world.clock.advance(timedelta(days=120))
        after = self.rows()[cid]
        self.assertEqual(after["state"], before["state"], "the recorded state stands")
        self.assertEqual(after["evidenceVerdict"]["suggestedState"], "STALE_EVIDENCE")
        self.assertEqual(after["evidenceVerdict"]["agreement"], DIFFERS)
        self.assertIn("EVIDENCE_STALE", after["evidenceVerdict"]["blockingReasons"])

    def test_unavailable_and_unknown(self):
        self.assertEqual(agreement(LifecycleState.NEEDS_REVIEW, None), UNAVAILABLE)
        self.assertEqual(agreement(LifecycleState.MAPPING_AMBIGUOUS, {"lifecycleDiversion": None}), DIFFERS)
        self.assertEqual(agreement(LifecycleState.NEEDS_REVIEW, {"lifecycleDiversion": None}), AGREES)
        self.assertEqual(agreement(LifecycleState.REJECTED, None), NOT_APPLICABLE)

    def test_a_verdict_authorizes_nothing(self):
        rows = self.rows()
        eligible = [r for r in rows.values() if r["evidenceVerdict"]["decision"]["eligibleForHumanApproval"]]
        self.assertTrue(eligible, "the classic world has a candidate eligible for a human's approval")
        cid = eligible[0]["id"]
        fp = self.world.fingerprint(self.client, cid)
        # Eligible is not approved: the proposer is still refused, and nothing moved.
        stage = {"NEEDS_REVIEW": "OKTA_UNASSIGN", "REVALIDATION_REQUIRED": "AD_QUARANTINE",
                 "DELETION_PROPOSED": "AD_DELETION"}[eligible[0]["state"]]
        refused = self.world.client(AUTOMATION).post(f"{V}/candidates/{cid}/approvals", {
            "stage": stage, "decision": "APPROVE", "reason": "verdict is not approval", "expectedEvidenceFingerprint": fp})
        self.assertEqual(refused.status, 403)
        self.assertEqual(self.rows()[cid]["state"], eligible[0]["state"])


class ApprovalUsability(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.client = self.world.client(SECURITY)

    def tearDown(self):
        self.world.close()

    def approvals(self, cid=None):
        path = f"{V}/candidates/{cid}/approvals" if cid else f"{V}/approvals?limit=200"
        return self.client.get(path).json["items"]

    def test_listings_agree_and_carry_the_rules_own_words(self):
        listed = {a["id"]: a["usability"] for a in self.approvals()}
        self.assertTrue(listed)
        for cid in {a["candidateId"] for a in self.approvals()}:
            for a in self.approvals(cid):
                self.assertEqual(a["usability"], listed[a["id"]])
        for u in listed.values():
            self.assertEqual(u["usable"], u["status"] == "USABLE")
            self.assertEqual(u["usable"], not u["problems"])
        statuses = {u["status"] for u in listed.values()}
        self.assertTrue({"USABLE", "EXPIRED", "STAGE_NOT_CURRENT"} <= statuses, statuses)

    def test_usable_means_the_dry_run_accepts_it_and_unusable_means_it_refuses(self):
        cid = self.world.candidate("S14")  # APPROVED (Okta stage) with its approval
        approvals = self.approvals(cid)
        usable = [a for a in approvals if a["usability"]["usable"]]
        self.assertEqual(len(usable), 1)
        fp = self.world.fingerprint(self.client, cid)
        body = {"kind": "OKTA_UNASSIGN", "approvalId": usable[0]["id"], "expectedEvidenceFingerprint": fp,
                "dryRun": True, "executionMode": "DRY_RUN_MUTATION"}
        before = audit_state(self.world.store)
        self.client.get(f"{V}/approvals")
        self.assertEqual(audit_state(self.world.store), before, "reading usability changes nothing")
        # Usable is not authorization: a person without the planning permission is still refused.
        for subject in (VIEWER, SECURITY):
            refused = self.world.client(subject).post(f"{V}/candidates/{cid}/execution-jobs", body)
            self.assertEqual(refused.status, 403, subject)
        # Valid means the approval rules pass, not that the step is ready: the dry run has its own guard
        # (evidence under 24 hours old), and refuses for that, never for the approval.
        stale = self.world.client(EXECUTOR).post(f"{V}/candidates/{cid}/execution-jobs", body)
        self.assertEqual(stale.json["error"]["code"], "EVIDENCE_RULES_NOT_MET")
        self.world.refresh_evidence(cid)
        self.assertTrue(next(a for a in self.approvals(cid) if a["id"] == usable[0]["id"])["usability"]["usable"])
        self.assertEqual(self.world.client(EXECUTOR).post(f"{V}/candidates/{cid}/execution-jobs", body).status, 201)
        # Once it expires the listing says so, and the planner refuses it for that reason.
        self.world.clock.advance(timedelta(days=30))
        u = next(a for a in self.approvals(cid) if a["id"] == usable[0]["id"])["usability"]
        self.assertEqual((u["status"], u["usable"]), ("EXPIRED", False))
        fp = self.world.fingerprint(self.client, cid)
        refused = self.world.client(EXECUTOR).post(f"{V}/candidates/{cid}/execution-jobs",
                                                    {**body, "expectedEvidenceFingerprint": fp})
        self.assertEqual(refused.json["error"]["code"], "APPROVAL_INVALID")
        self.assertTrue(any("expired" in p for p in refused.json["error"]["problems"]))

    def test_a_new_epoch_supersedes_and_a_rejection_is_not_an_approval(self):
        cid = self.world.candidate("S14")
        approval = next(a for a in self.approvals(cid) if a["usability"]["usable"])
        # Hold (BLOCKED) and re-enter: the candidate's epoch moves on, so the approval no longer counts.
        automation = self.world.client(AUTOMATION)
        self.assertEqual(automation.post(f"{V}/candidates/{cid}/transitions",
                                         {"target": "BLOCKED", "reason": "usability test hold"}).status, 201)
        fp = self.world.fingerprint(self.client, cid)
        reentry = automation.post(f"{V}/candidates/{cid}/transitions", {
            "target": "CANDIDATE", "reason": "usability test re-entry", "expectedEvidenceFingerprint": fp})
        self.assertEqual(reentry.status, 201, reentry.json)
        u = next(a for a in self.approvals(cid) if a["id"] == approval["id"])["usability"]
        self.assertEqual((u["status"], u["usable"]), ("EPOCH_SUPERSEDED", False))
        self.assertTrue(any("epoch" in p for p in u["problems"]))
        # A rejection.
        s07 = self.world.candidate("S07")
        fp = self.world.fingerprint(self.client, s07)
        self.assertEqual(self.world.client(SECURITY_2).post(f"{V}/candidates/{s07}/approvals", {
            "stage": "OKTA_UNASSIGN", "decision": "REJECT", "reason": "not now", "expectedEvidenceFingerprint": fp}).status, 201)
        rejected = [a for a in self.approvals(s07) if a["decision"] == "REJECT"]
        self.assertEqual({a["usability"]["status"] for a in rejected}, {"NOT_AN_APPROVAL"})


class DirectoryGroupCandidates(unittest.TestCase):
    """The AD group page's candidates come only from an exact identity mapping to its stable id."""

    @classmethod
    def setUpClass(cls):
        cls.world = World(dataset="null-meridian")
        cls.client = cls.world.client(SECURITY)
        cls.groups = every_page(cls.client, "/directory-groups", 200)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def detail(self, g):
        return self.client.get(f"{V}/directory-groups/{g['id']}").json

    def named(self, name, source):
        return [g for g in self.groups if g["name"] == name and g["source"] == source]

    def test_every_link_is_an_exact_mapping_to_this_groups_stable_id(self):
        linked = 0
        for g in self.groups:
            if g["source"] != "AD":
                continue
            for c in self.detail(g)["lifecycleCandidates"]:
                linked += 1
                m = self.client.get(f"{V}/mappings/{c['oktaGroupId']}").json["mapping"]
                self.assertTrue(m["isExact"], g["name"])
                self.assertEqual((m["adGroupId"], m["id"], c["relationship"]),
                                 (g["adEvidenceId"], c["mappingId"], "EXACT_IDENTITY_MAPPING"))
                self.assertIn(c["candidateId"], self.client.get(f"{V}/groups/{c['oktaGroupId']}").json["candidateIds"])
        self.assertGreaterEqual(linked, 5)

    def test_an_unproven_mapping_never_links_even_where_the_snapshot_points(self):
        for name in ("KB-Admins", "WikiV1-Users"):  # UNVERIFIED_STABLE_ID and NAME_ONLY in the dataset
            (g,) = self.named(name, "AD")
            self.assertTrue(g["oktaEvidenceId"], "the snapshot names an Okta counterpart")
            self.assertTrue(self.client.get(f"{V}/groups/{g['oktaEvidenceId']}").json["candidateIds"],
                            "and that Okta group has a candidate")
            self.assertEqual(self.detail(g)["lifecycleCandidates"], [], name)

    def test_shared_names_never_cross_link(self):
        ad = self.named("Finance-RW", "AD")
        (okta,) = self.named("Finance-RW", "OKTA")
        self.assertEqual(len(ad), 2)
        own = self.detail(okta)["lifecycleCandidates"]
        self.assertTrue(own)
        self.assertEqual({c["relationship"] for c in own}, {"OKTA_GROUP"})
        self.assertEqual({c["oktaGroupId"] for c in own}, {okta["oktaEvidenceId"]})
        for g in ad:
            theirs = {c["candidateId"] for c in self.detail(g)["lifecycleCandidates"]}
            self.assertFalse(theirs & {c["candidateId"] for c in own}, g["id"])

    def test_a_group_with_no_candidate_says_none(self):
        quiet = next(g for g in self.groups if g["source"] == "AD" and not g.get("oktaEvidenceId"))
        self.assertEqual(self.detail(quiet)["lifecycleCandidates"], [])


class QueueAtScale(unittest.TestCase):
    """More than the old 1,000-row ceiling, with ties in priority, waiting time, and name."""

    @classmethod
    def setUpClass(cls):
        cls.tenant = ScaleTenant(groups=4400)  # 1,100 candidates
        cls.client = cls.tenant.client(SECURITY)
        automation = cls.tenant.client(AUTOMATION)
        ids = [r["id"] for r in cls.tenant.store.connection.execute("SELECT id FROM candidates ORDER BY id")]
        targets = ("BLOCKED", "EXCLUDED", "MAPPING_AMBIGUOUS", "REJECTED", "PROTECTED")
        for i, cid in enumerate(ids[::3]):
            result = automation.post(f"{V}/candidates/{cid}/transitions", {"target": targets[i % len(targets)],
                                                                          "reason": "scale fixture diversion"})
            assert result.status == 201, result.json
        cls.total = len(ids)

    @classmethod
    def tearDownClass(cls):
        cls.tenant.close()

    def test_every_page_in_priority_order_without_gaps_or_repeats(self):
        self.assertGreater(self.total, 1000)
        before = audit_state(self.tenant.store)
        pages, path = [], f"{Q}?status=all&limit=50"
        while path:
            body = self.client.get(path).json
            pages.append(body)
            cursor = body["page"]["nextCursor"]
            path = f"{Q}?status=all&limit=50&cursor={cursor}" if cursor else None
        rows = [r for p in pages for r in p["items"]]
        ids = [r["id"] for r in rows]
        self.assertEqual(len(ids), self.total)
        self.assertEqual(len(set(ids)), self.total, "no row repeats across pages")
        self.assertEqual(set(ids), {r["id"] for r in self.tenant.store.connection.execute("SELECT id FROM candidates")})
        self.assertEqual({p["page"]["total"] for p in pages}, {self.total})
        self.assertEqual([len(p["items"]) for p in pages[:-1]], [50] * (len(pages) - 1))
        self.assertEqual(len(pages[-1]["items"]), self.total % 50 or 50, "the final page is partial")
        self.assertEqual(ids, ui_queue_order(rows, pages[0]["generatedAt"]))
        self.assertTrue(all(r["evidenceVerdict"]["decision"]["code"] for r in rows))
        self.assertEqual(audit_state(self.tenant.store), before)
        # Ties: many rows share a status and a last change; only the stable id orders them.
        same = [r for r in rows if r["reviewStatus"] == "waiting"]
        self.assertGreater(len(same) - len({r["updatedAt"] for r in same}), 500)

    def test_filters_are_applied_before_paging(self):
        counts = self.client.get(Q).json["counts"]
        self.assertEqual(counts["all"], self.total)
        for key in ("blocked", "closed", "waiting"):
            body = self.client.get(f"{Q}?status={key}&limit=50").json
            self.assertEqual(body["page"]["total"], counts[key], key)
            rows = every_page(self.client, f"/review-queue?status={key}", 50)
            self.assertEqual(len(rows), counts[key], key)
            self.assertEqual({r["reviewStatus"] for r in rows}, {key})
        self.assertEqual(counts["open"] + counts["closed"] + counts["retired"], self.total)

    def test_a_middle_page_is_the_same_slice_of_the_whole(self):
        whole = [r["id"] for r in every_page(self.client, f"/review-queue?status=open", 50)]
        first = self.client.get(f"{Q}?status=open&limit=40").json
        second = self.client.get(f"{Q}?status=open&limit=40&cursor={first['page']['nextCursor']}").json
        self.assertEqual([r["id"] for r in second["items"]], whole[40:80])
        self.assertEqual(second["page"]["previousCursor"], encode_cursor(0))


if __name__ == "__main__":
    unittest.main()
