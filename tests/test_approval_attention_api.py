"""OGWA-APPROVAL-ATTENTION-01: approvals that need a person's attention, from the server's own
approval usability.

``expiringSoon`` marks a **usable** approval that expires within ``EXPIRING_SOON_WITHIN`` (a
presentation threshold, never a rule), and ``GET /approvals?usability=`` filters by the server's
own judgement before paging, with counts over every approval. Checked here: valid and not near
expiry, valid and expiring soon, the window's boundary, expired, superseded, an expiring approval
whose step still has its own checks to pass (and fails them), counts and filters over every
approval, deterministic order, malformed requests, authorization, and that reading changes nothing.
"""

import unittest
from datetime import timedelta

from app.api.review_queue import EXPIRING_SOON_WITHIN, ApprovalUsability
from tests.api_fixtures import AUTOMATION, EXECUTOR, NO_ROLE, SECURITY, VIEWER, World
from tests.test_review_queue_api import audit_state

V = "/api/v1"
FILTERS = ("all", "valid", "expiring-soon", "expired")


class ApprovalAttention(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.client = self.world.client(SECURITY)
        self.cid = self.world.candidate("S14")  # APPROVED (Okta stage) with its one usable approval

    def tearDown(self):
        self.world.close()

    def listing(self, usability="all", **query):
        params = "&".join(f"{k}={v}" for k, v in {"usability": usability, "limit": 50, **query}.items())
        response = self.client.get(f"{V}/approvals?{params}")
        self.assertEqual(response.status, 200, response.json)
        return response.json

    def ids(self, usability, **query):
        return [a["id"] for a in self.listing(usability, **query)["items"]]

    def s14_approval(self):
        return next(a for a in self.client.get(f"{V}/candidates/{self.cid}/approvals").json["items"]
                    if a["usability"]["usable"])

    def to_hours_before_expiry(self, hours: float, aid: str | None = None):
        """Move the server's clock to ``hours`` before the S14 approval (or ``aid``) expires."""
        expires = self.world.store.load_approval(aid or self.s14_approval()["id"]).expires_at
        self.world.clock.advance(expires - timedelta(hours=hours) - self.world.clock.now)

    # --- each reading ------------------------------------------------------------------------

    def test_valid_and_not_near_expiry_is_valid_and_not_expiring_soon(self):
        a = self.s14_approval()
        self.assertEqual(a["usability"], {"status": "USABLE", "usable": True, "problems": [], "expiringSoon": False})
        data = self.listing()
        self.assertEqual((data["counts"]["valid"], data["counts"]["expiringSoon"]), (1, 0))
        self.assertEqual(self.ids("valid"), [a["id"]])
        self.assertEqual(self.ids("expiring-soon"), [])
        self.assertEqual(data["expiringSoonWithinHours"], 48)
        self.assertEqual(EXPIRING_SOON_WITHIN, timedelta(hours=48))

    def test_valid_and_expiring_soon_is_counted_filtered_and_still_only_valid(self):
        self.to_hours_before_expiry(30)
        a = self.s14_approval()
        self.assertEqual(a["usability"], {"status": "USABLE", "usable": True, "problems": [], "expiringSoon": True})
        data = self.listing("expiring-soon")
        self.assertEqual([x["id"] for x in data["items"]], [a["id"]])
        self.assertEqual(data["page"]["total"], 1)
        self.assertEqual(data["counts"]["expiringSoon"], 1)
        self.assertEqual(data["items"][0]["usability"], a["usability"], "the listing and the candidate's agree")
        self.assertEqual(self.ids("valid"), [a["id"]], "expiring soon is still valid until it expires")

    def test_the_window_boundary(self):
        approval = self.world.store.load_approval(self.s14_approval()["id"])
        ref = self.world.store.recorded_policies(approval_ids=(approval.id,)).get(f"approval:{approval.id}")

        def at(delta):
            return ApprovalUsability(self.world.api, approval.expires_at - delta).of(approval, ref)

        self.assertEqual((at(EXPIRING_SOON_WITHIN + timedelta(seconds=1))["usable"],
                          at(EXPIRING_SOON_WITHIN + timedelta(seconds=1))["expiringSoon"]), (True, False))
        self.assertEqual((at(EXPIRING_SOON_WITHIN)["usable"], at(EXPIRING_SOON_WITHIN)["expiringSoon"]), (True, True))
        self.assertEqual((at(timedelta(seconds=1))["usable"], at(timedelta(seconds=1))["expiringSoon"]), (True, True))
        # At its expiry it has expired: not valid, so not "expiring soon" either.
        self.assertEqual((at(timedelta(0))["status"], at(timedelta(0))["expiringSoon"]), ("EXPIRED", False))

    def test_expired_is_neither_valid_nor_expiring_soon(self):
        aid = self.s14_approval()["id"]
        self.world.clock.advance(timedelta(days=30))
        a = next(x for x in self.client.get(f"{V}/candidates/{self.cid}/approvals").json["items"] if x["id"] == aid)
        self.assertEqual((a["usability"]["status"], a["usability"]["usable"], a["usability"]["expiringSoon"]),
                         ("EXPIRED", False, False))
        self.assertIn(aid, self.ids("expired"))
        self.assertNotIn(aid, self.ids("valid") + self.ids("expiring-soon"))
        data = self.listing("expired")
        self.assertTrue(all(x["expired"] and x["decision"] == "APPROVE" for x in data["items"]))
        self.assertEqual(data["page"]["total"], data["counts"]["expired"])

    def test_superseded_inside_the_window_is_not_expiring_soon(self):
        aid = self.s14_approval()["id"]
        automation = self.world.client(AUTOMATION)
        self.assertEqual(automation.post(f"{V}/candidates/{self.cid}/transitions",
                                         {"target": "BLOCKED", "reason": "attention test hold"}).status, 201)
        fp = self.world.fingerprint(self.client, self.cid)
        self.assertEqual(automation.post(f"{V}/candidates/{self.cid}/transitions", {
            "target": "CANDIDATE", "reason": "attention test re-entry", "expectedEvidenceFingerprint": fp}).status, 201)
        self.to_hours_before_expiry(30, aid)
        u = next(x for x in self.client.get(f"{V}/candidates/{self.cid}/approvals").json["items"] if x["id"] == aid)["usability"]
        self.assertEqual((u["status"], u["usable"], u["expiringSoon"]), ("EPOCH_SUPERSEDED", False, False))
        data = self.listing()
        self.assertEqual((data["counts"]["valid"], data["counts"]["expiringSoon"]), (0, 0))
        self.assertNotIn(aid, self.ids("expiring-soon"))

    def test_an_expiring_approval_is_not_executable_its_step_has_its_own_checks(self):
        """Regression: "valid and expiring soon" never makes a step ready. The dry run still needs
        evidence under 24 hours old, and refuses for that; a person without the permission is refused."""
        self.to_hours_before_expiry(30)  # five days on: the evidence is now older than 24 hours
        a = self.s14_approval()
        self.assertTrue(a["usability"]["usable"] and a["usability"]["expiringSoon"])
        before = audit_state(self.world.store)
        for which in FILTERS:
            self.listing(which)
        self.assertEqual(audit_state(self.world.store), before, "reading attention changes nothing")
        fp = self.world.fingerprint(self.client, self.cid)
        body = {"kind": "OKTA_UNASSIGN", "approvalId": a["id"], "expectedEvidenceFingerprint": fp,
                "dryRun": True, "executionMode": "DRY_RUN_MUTATION"}
        for subject in (VIEWER, SECURITY):
            self.assertEqual(self.world.client(subject).post(f"{V}/candidates/{self.cid}/execution-jobs", body).status, 403)
        refused = self.world.client(EXECUTOR).post(f"{V}/candidates/{self.cid}/execution-jobs", body)
        self.assertEqual(refused.json["error"]["code"], "EVIDENCE_RULES_NOT_MET")

    # --- counts, filters, order ----------------------------------------------------------------

    def test_counts_cover_every_approval_whatever_the_page_or_filter(self):
        self.to_hours_before_expiry(30)
        full = self.listing()
        self.assertEqual(full["counts"]["all"], full["page"]["total"])
        for which in FILTERS:
            for limit in (1, 50):
                with self.subTest(which=which, limit=limit):
                    data = self.listing(which, limit=limit)
                    self.assertEqual(data["counts"], full["counts"])
                    self.assertEqual(data["usability"], which)
                    self.assertEqual(data["page"]["total"], full["counts"][{"expiring-soon": "expiringSoon"}.get(which, which)])

    def test_filters_page_and_keep_a_deterministic_order(self):
        expired = self.listing("expired", sort="expiresAt", order="asc")["items"]
        self.assertGreaterEqual(len(expired), 3)
        # Ties (two approvals expire at the same instant) fall to the listing's order: newest decision, then id.
        expected = sorted(sorted(sorted(expired, key=lambda a: a["id"]), key=lambda a: a["decidedAt"], reverse=True),
                          key=lambda a: a["expiresAt"])
        self.assertEqual([a["id"] for a in expired], [a["id"] for a in expected])
        self.assertTrue(any(x["expiresAt"] == y["expiresAt"] for x, y in zip(expired, expired[1:])), "the fixture has a tie")
        first = self.listing("expired", limit=2, sort="expiresAt", order="asc")
        second = self.listing("expired", limit=2, sort="expiresAt", order="asc", cursor=first["page"]["nextCursor"])
        self.assertEqual([a["id"] for a in first["items"] + second["items"]], [a["id"] for a in expected[:4]])
        # The judged filters page their own list the same way, past the end included.
        valid = self.listing("valid", limit=1)
        self.assertEqual((len(valid["items"]), valid["page"]["nextCursor"]), (1, None))
        past = self.listing("valid", limit=1, cursor=first["page"]["nextCursor"])
        self.assertEqual((past["items"], past["page"]["total"]), ([], 1))

    def test_malformed_and_unauthorized_requests(self):
        bad = self.client.get(f"{V}/approvals?usability=ready")
        self.assertEqual((bad.status, bad.json["error"]["code"]), (400, "MALFORMED_REQUEST"))
        self.assertEqual(self.world.client(None).get(f"{V}/approvals?usability=expiring-soon").status, 401)
        self.assertEqual(self.world.client(NO_ROLE).get(f"{V}/approvals?usability=expiring-soon").status, 403)
        self.assertEqual(self.client.post(f"{V}/approvals?usability=expiring-soon", {}).status, 405)


if __name__ == "__main__":
    unittest.main()
