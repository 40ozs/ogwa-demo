"""OGWA-DEMO-02: versioned synthetic policy releases, and the exact policy every decision records.

- The release format (``ogwa-policy-release/v1``): strict, stable, and pinned for both fixtures.
- ``PolicyRef``: what a decision records, and its stable serialization.
- Null Meridian: NM-LIFECYCLE-004 v1.1.0 and v1.2.0 recorded through the store's real policy chain;
  every seeded decision names v1.1.0, the live demo judges by v1.2.0, and a newer version never
  rewrites what an older decision recorded.
- The store refuses a decision judged by anything but the policy in force.

Synthetic data only; nothing here contacts any system.
"""

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest import mock

from app.api.services import PolicyInForce, policy_in_force
from app.demo.null_meridian import policy as nm_policy
from app.demo.null_meridian.world import POLICY as NM_POLICY
from app.domain.actors import Actor, ActorKind
from app.domain.candidate_policy import CandidatePolicy
from app.domain.errors import InvalidRecord
from app.domain.evidence import FreshnessPolicy
from app.domain.lifecycle import LifecycleState, TransitionRequest
from app.domain.policy_release import (
    DEMO_SOURCE,
    POLICY_DETAIL_KEYS,
    RECORDED_SOURCE,
    PolicyRef,
    PolicyRelease,
    release_for_digest,
    release_history_problems,
    strip_policy_details,
)
from app.store.errors import StoreConflict
from tests.api_fixtures import SECURITY, SECURITY_2, World

V = "/api/v1"
# Goldens: the identity of each synthetic release. A change to a release file moves them; a
# released version must never change, so a new version gets a new file instead.
GOLDEN_RELEASES = {
    "1.1.0": ("sha256:695d65f302fd8d538b9d18aa774d620acae07d5c1ffec86c2f077b2b31af1e38",
              "sha256:d7e0e2c1b5926c332f75134e7fbcfde834b6d9de996503b80f026f3631eb91ed"),
    "1.2.0": ("sha256:45f3a32a72ba835141de97cf47c50f41009759ae52c62f208a8194459a6b10a7",
              "sha256:4ee7c5223e19b898752050954b350ad437aa6ad506871045549734eef201b3e5"),
}
REVIEWER = Actor(ActorKind.HUMAN, "synthetic.reviewer.two")


def releases():
    return nm_policy.releases()


def release(version: str) -> PolicyRelease:
    return next(r for r in releases() if r.version == version)


def newer_release(**rules) -> PolicyRelease:
    """A test-only 1.3.0 that no file publishes: the review window shortened to 600 h."""
    current = nm_policy.current_release()
    lifecycle = replace(current.rules.lifecycle, freshness=replace(current.rules.lifecycle.freshness,
                                                                   review=timedelta(hours=600)))
    return replace(current, version="1.3.0", supersedes="1.2.0", changes=("Test-only: review window 600 h.",),
                   effective_from=datetime(2026, 10, 1, 12, 30, tzinfo=timezone.utc),
                   rules=replace(current.rules, lifecycle=lifecycle, **rules))


class ReleaseFormatTests(unittest.TestCase):
    def test_both_releases_have_a_stable_identity(self):
        self.assertEqual([r.version for r in releases()], ["1.1.0", "1.2.0"])
        for r in releases():
            with self.subTest(version=r.version):
                self.assertEqual(r.policy_id, "NM-LIFECYCLE-004")
                self.assertEqual(r.name, f"NM-LIFECYCLE-004 v{r.version}")
                self.assertEqual((r.release_digest, r.policy_digest), GOLDEN_RELEASES[r.version])
                self.assertTrue(r.synthetic)
                self.assertEqual(r.rules.to_document()["format"], "ogwa-candidate-policy/v1")
        self.assertEqual(release_history_problems(releases()), [])

    def test_the_reviewer_file_is_exactly_the_release(self):
        """The readable file is generated from the release, so its text cannot drift from what runs."""
        for r in releases():
            with self.subTest(version=r.version):
                text = nm_policy.release_path(r.version).read_text(encoding="utf-8")
                self.assertEqual(text, r.readable_json())
                self.assertEqual(PolicyRelease.from_json(text), r)
                self.assertEqual(PolicyRelease.from_json(r.canonical_json()), r)
                self.assertEqual(json.loads(text), r.to_document())

    def test_serialization_is_stable(self):
        r = release("1.2.0")
        self.assertEqual(list(r.to_document()), ["format", "policyId", "version", "title", "purpose", "effectiveFrom",
                                                 "supersedes", "changes", "synthetic", "policy"])
        self.assertEqual(r.to_document()["effectiveFrom"], "2026-09-28T09:00:00Z")
        self.assertEqual(r.summary(), {
            "policyId": "NM-LIFECYCLE-004", "version": "1.2.0", "name": "NM-LIFECYCLE-004 v1.2.0",
            "title": r.title, "effectiveFrom": "2026-09-28T09:00:00Z", "supersedes": "1.1.0",
            "changes": list(r.changes), "synthetic": True, "releaseDigest": GOLDEN_RELEASES["1.2.0"][0],
            "policyDigest": GOLDEN_RELEASES["1.2.0"][1]})

    def test_v1_2_0_is_the_policy_the_demo_always_ran(self):
        """Naming the policy changed no classification: v1.2.0's rules are the demo's own."""
        self.assertEqual(release("1.2.0").rules.lifecycle, NM_POLICY)
        self.assertEqual(release("1.2.0").policy_digest, CandidatePolicy(lifecycle=NM_POLICY).digest)

    def test_the_version_change_is_distinguishable_and_named(self):
        old, new = release("1.1.0"), release("1.2.0")
        self.assertNotEqual(old.policy_digest, new.policy_digest)
        self.assertNotEqual(old.release_digest, new.release_digest)
        a, b = old.rules.to_document(), new.rules.to_document()
        changed = {k for k in a if a[k] != b[k]}
        self.assertEqual(changed, {"freshness"})
        self.assertEqual({k for k in a["freshness"] if a["freshness"][k] != b["freshness"][k]}, {"approvalHours"})
        self.assertEqual((a["freshness"]["approvalHours"], b["freshness"]["approvalHours"]), (336, 168))
        self.assertIn("336 h", new.changes[0])
        self.assertIn("168 h", new.changes[0])
        self.assertIs(release_for_digest(releases(), old.policy_digest), old)
        self.assertIsNone(release_for_digest(releases(), "sha256:" + "0" * 64), "never the nearest or the latest")

    def test_the_format_is_strict(self):
        good = release("1.2.0").to_document()
        cases = {
            "unknown key": {**good, "owner": "x"},
            "missing key": {k: v for k, v in good.items() if k != "purpose"},
            "wrong format": {**good, "format": "ogwa-policy-release/v2"},
            "short version": {**good, "version": "1.2"},
            "leading zero": {**good, "version": "01.2.0"},
            "prefixed version": {**good, "version": "v1.2.0"},
            "lower-case id": {**good, "policyId": "nm-lifecycle-004"},
            "id without a hyphen": {**good, "policyId": "NMLIFECYCLE004"},
            "supersedes a higher version": {**good, "supersedes": "1.3.0"},
            "supersedes itself": {**good, "supersedes": "1.2.0"},
            "supersedes without saying what changed": {**good, "changes": []},
            "local time": {**good, "effectiveFrom": "2026-09-28T09:00:00+02:00"},
            "date only": {**good, "effectiveFrom": "2026-09-28"},
            "synthetic as text": {**good, "synthetic": "true"},
            "a weakened floor": {**good, "policy": {**good["policy"], "usage": {**good["policy"]["usage"],
                                                                                "retirementWindowDays": 7}}},
        }
        for label, doc in cases.items():
            with self.subTest(label):
                with self.assertRaises(InvalidRecord):
                    PolicyRelease.from_document(doc)
        text = release("1.2.0").canonical_json()
        for label, bad in (("duplicate key", text.replace('"version":"1.2.0"', '"version":"1.2.0","version":"1.2.0"')),
                           ("NaN", text.replace('"retirementMaxSignIns":0', '"retirementMaxSignIns":NaN')),
                           ("not JSON", text[:-1])):
            with self.subTest(label):
                with self.assertRaises(InvalidRecord):
                    PolicyRelease.from_json(bad)

    def test_a_release_chain_is_one_policy_in_order(self):
        old, new = releases()
        self.assertTrue(release_history_problems((new, old)))
        self.assertTrue(release_history_problems((old, replace(new, supersedes="1.0.0"))))
        self.assertTrue(release_history_problems((old, replace(new, effective_from=old.effective_from))))
        self.assertTrue(release_history_problems((old, replace(new, rules=old.rules))), "a bump must change the rules")
        self.assertTrue(release_history_problems((old, replace(new, policy_id="NM-LIFECYCLE-005"))))
        self.assertTrue(release_history_problems((new,)), "the first release supersedes nothing")
        self.assertEqual(release_history_problems((old, new, newer_release())), [])
        self.assertTrue(release_history_problems(()))


class ReviewerDocumentTests(unittest.TestCase):
    """docs/demo/policies/NM-LIFECYCLE-004.md states the conditions the explanation shows."""

    def test_the_document_matches_the_rules_and_the_releases(self):
        from pathlib import Path

        from app.classification.explanation import RULES

        doc = (Path(__file__).resolve().parents[1] / "docs" / "demo" / "policies" / "NM-LIFECYCLE-004.md").read_text(
            encoding="utf-8")
        rules = release("1.2.0").rules
        for rule in RULES:
            with self.subTest(rule=rule.key):
                self.assertIn(f"`{rule.proof.value}` | {rule.rule(rules)} |", doc)
        for version, (release_digest, policy_digest) in GOLDEN_RELEASES.items():
            with self.subTest(version=version):
                self.assertIn(f"NM-LIFECYCLE-004-{version}.json", doc)
                self.assertIn(f"`{release_digest[:15]}…{release_digest[-4:]}`", doc)
                self.assertIn(f"`{policy_digest[:15]}…{policy_digest[-4:]}`", doc)
        self.assertIn("Synthetic", doc)


class PolicyRefTests(unittest.TestCase):
    def ref(self, **overrides):
        r = release("1.2.0")
        return PolicyRef.of(policy_digest=r.policy_digest, source=RECORDED_SOURCE,
                            version_id="pver_" + "a" * 32, sequence=1, release=r, **overrides)

    def test_serialization_is_stable(self):
        ref = self.ref()
        self.assertEqual(ref.to_dict(), {
            "policyId": "NM-LIFECYCLE-004", "version": "1.2.0", "name": "NM-LIFECYCLE-004 v1.2.0",
            "releaseDigest": GOLDEN_RELEASES["1.2.0"][0], "policyDigest": GOLDEN_RELEASES["1.2.0"][1],
            "source": "RECORDED_VERSION", "recorded": True, "versionId": "pver_" + "a" * 32, "versionSequence": 1})
        details = ref.audit_details()
        self.assertEqual(tuple(details), POLICY_DETAIL_KEYS)
        self.assertEqual(details["policy_release"], "1.2.0")
        self.assertEqual(PolicyRef.from_audit_details(tuple(sorted(details.items()))), ref)

    def test_an_unnamed_or_unrecorded_policy_is_said_so(self):
        unrecorded = PolicyRef.of(policy_digest=GOLDEN_RELEASES["1.2.0"][1], source=DEMO_SOURCE)
        self.assertEqual((unrecorded.name, unrecorded.recorded, unrecorded.version_id), (None, False, None))
        self.assertEqual(unrecorded.audit_details()["policy_id"], "-")
        self.assertEqual(PolicyRef.from_audit_details(tuple(unrecorded.audit_details().items())), unrecorded)
        self.assertIsNone(PolicyRef.from_audit_details((("decision_id", "x"),)), "no keys: none recorded")

    def test_inconsistent_references_are_refused(self):
        digest = GOLDEN_RELEASES["1.2.0"][1]
        for label, build in (
                ("recorded without a version", lambda: PolicyRef(digest, RECORDED_SOURCE)),
                ("unrecorded with a version", lambda: PolicyRef(digest, DEMO_SOURCE, "pver_" + "a" * 32, 0)),
                ("half a release identity", lambda: PolicyRef(digest, DEMO_SOURCE, policy_id="NM-LIFECYCLE-004")),
                ("an unknown source", lambda: PolicyRef(digest, "LATEST")),
                ("a release of other rules", lambda: PolicyRef.of(policy_digest=digest, source=DEMO_SOURCE,
                                                                  release=release("1.1.0")))):
            with self.subTest(label):
                with self.assertRaises(InvalidRecord):
                    build()
        partial = tuple((k, v) for k, v in self.ref().audit_details().items() if k != "policy_release")
        with self.assertRaises(InvalidRecord):
            PolicyRef.from_audit_details(partial)
        self.assertEqual(strip_policy_details((("decision_id", "x"), *self.ref().audit_details().items())),
                         (("decision_id", "x"),))


class NullMeridianPolicyHistoryTests(unittest.TestCase):
    """The recorded history, through the real store, API, and lifecycle."""

    def setUp(self):
        self.world = World(dataset="null-meridian")
        self.store = self.world.store
        self.client = self.world.client(SECURITY)

    def tearDown(self):
        self.world.close()

    def decisions(self, key):
        return self.client.get(f"{V}/candidates/{self.world.candidate(key)}/decisions").json["items"]

    def divert(self, key, client=None):
        return (client or self.client).post(f"{V}/candidates/{self.world.candidate(key)}/transitions",
                                            {"target": "BLOCKED", "reason": "synthetic reviewer holds it"})

    def test_the_store_records_both_versions_through_the_real_chain(self):
        versions = self.store.policy_versions()
        self.assertEqual([(v.sequence, v.decided_at) for v in versions],
                         [(0, release("1.1.0").effective_from), (1, release("1.2.0").effective_from)])
        self.assertEqual([v.policy_digest for v in versions], [GOLDEN_RELEASES[v][1] for v in ("1.1.0", "1.2.0")])
        self.assertEqual({(v.proposed_by, v.approved_by) for v in versions},
                         {(nm_policy.POLICY_AUTHOR, nm_policy.POLICY_APPROVER)})
        reviews = [e for e in self.store.audit_events() if e.action.value == "POLICY_REVIEW_RECORDED"]
        self.assertEqual([e.after_ref for e in reviews], [f"policy_version:{v.id}" for v in versions])
        in_force = policy_in_force(self.store)
        self.assertEqual((in_force.recorded, in_force.version_sequence, in_force.release.name),
                         (True, 1, "NM-LIFECYCLE-004 v1.2.0"))
        self.store.verify_integrity()

    def test_every_seeded_decision_records_the_version_that_judged_it(self):
        v110 = self.store.policy_versions()[0]
        seen = 0
        for key in ("NM-C01", "NM-C06", "NM-C07", "NM-C08", "NM-C10"):
            refs = self.store.recorded_policies(self.world.candidate(key))
            decisions = self.store.decisions(self.world.candidate(key))
            self.assertEqual(set(refs) >= {f"decision:{d.id}" for d in decisions}, True, key)
            for ref in refs.values():
                self.assertEqual((ref.policy_id, ref.version, ref.version_id, ref.sequence),
                                 ("NM-LIFECYCLE-004", "1.1.0", v110.id, 0), key)
                seen += 1
        self.assertGreater(seen, 10)
        self.assertTrue(all(d["policy"]["name"] == "NM-LIFECYCLE-004 v1.1.0" for d in self.decisions("NM-C08")))
        approvals = self.client.get(f"{V}/candidates/{self.world.candidate('NM-C08')}/approvals").json["items"]
        self.assertEqual([(a["stage"], a["policy"]["version"]) for a in approvals], [("OKTA_UNASSIGN", "1.1.0")])
        listing = self.client.get(f"{V}/approvals?limit=50").json["items"]
        # OGWA-DEMO-04: the triage approvals (2026-09-24/25) record 1.1.0; NM-C11's snapshot-day
        # approval (2026-10-01, after 1.2.0 took effect on 2026-09-28) records 1.2.0.
        nm_c11 = self.world.candidate("NM-C11")
        self.assertEqual(sorted((a["candidateId"] == nm_c11, a["policy"]["version"]) for a in listing),
                         [(False, "1.1.0")] * (len(listing) - 1) + [(True, "1.2.0")])
        for a in listing:
            in_force = [r for r in nm_policy.releases()
                        if r.effective_from <= datetime.fromisoformat(a["decidedAt"].replace("Z", "+00:00"))][-1]
            self.assertEqual(a["policy"]["version"], in_force.version, a["id"])

    def test_a_new_decision_records_the_policy_in_force_and_history_is_unchanged(self):
        before = self.decisions("NM-C01")
        result = self.divert("NM-C01")
        self.assertEqual(result.status, 201, result.json)
        self.assertEqual(result.json["decision"]["policy"]["name"], "NM-LIFECYCLE-004 v1.2.0")
        self.assertEqual(result.json["decision"]["policy"]["publishedRelease"], "MATCHES_RECORDED")
        after = self.decisions("NM-C01")
        self.assertEqual(after[:-1], before, "earlier decisions read exactly as before")
        self.assertEqual([d["policy"]["version"] for d in after], ["1.1.0", "1.1.0", "1.2.0"])

    def test_a_newer_version_never_rewrites_what_an_older_decision_recorded(self):
        self.assertEqual(self.divert("NM-C01").status, 201)
        history = {k: self.decisions(k) for k in ("NM-C01", "NM-C08", "NM-C10")}
        newer = newer_release()
        self.store.record_policy_version(nm_policy.policy_version(
            newer, id="pver_" + "c" * 32, previous=self.store.active_policy_version()))
        # 1.3.0 is recorded but no file publishes it: the policy in force has no release identity.
        detail = self.client.get(f"{V}/candidates/{self.world.candidate('NM-C10')}").json
        self.assertEqual((detail["policy"]["versionSequence"], detail["policy"]["name"]), (2, None))
        self.assertEqual(detail["decisionExplanation"]["policy"]["policyDigest"], newer.policy_digest)
        self.assertIsNone(detail["decisionExplanation"]["policy"]["name"], "never guessed from the nearest release")
        for key, items in history.items():
            self.assertEqual(self.decisions(key), items, key)
        # Once 1.3.0 is published too, the live decision names it; history still does not move.
        with mock.patch.object(nm_policy, "releases", return_value=(*releases(), newer)):
            detail = self.client.get(f"{V}/candidates/{self.world.candidate('NM-C10')}").json
            self.assertEqual(detail["decisionExplanation"]["policy"]["name"], "NM-LIFECYCLE-004 v1.3.0")
            for key, items in history.items():
                self.assertEqual(self.decisions(key), items, key)
        self.store.verify_integrity()

    def test_an_edited_release_file_shows_as_a_difference_not_as_the_recorded_policy(self):
        edited = replace(release("1.1.0"), title="Edited after the fact")
        with mock.patch.object(nm_policy, "releases", return_value=(edited, release("1.2.0"))):
            items = self.decisions("NM-C08")
        self.assertTrue(all(d["policy"]["publishedRelease"] == "DIFFERS_FROM_RECORDED" for d in items))
        self.assertTrue(all(d["policy"]["releaseDigest"] == GOLDEN_RELEASES["1.1.0"][0] for d in items),
                        "the recorded identity is shown, not the edited one")


class PolicyInForceGuardTests(unittest.TestCase):
    """No decision can be recorded as judged by a policy that is not the one in force."""

    def setUp(self):
        self.world = World(dataset="null-meridian")
        self.store = self.world.store
        self.cid = self.world.candidate("NM-C01")
        self.v110, self.v120 = self.store.policy_versions()

    def tearDown(self):
        self.world.close()

    def in_force(self, version, release_=None):
        return PolicyInForce(version.policy, RECORDED_SOURCE, version.id, version.sequence, release_)

    def request(self):
        candidate = self.store.load_candidate(self.cid)
        return TransitionRequest(target=LifecycleState.BLOCKED, actor=REVIEWER, reason="synthetic hold",
                                 now=self.world.clock(), evidence=self.store.evidence_bundle(candidate))

    def unchanged(self):
        return self.store.audit_head(), len(self.store.decisions(self.cid))

    def test_a_superseded_version_is_refused_and_nothing_is_recorded(self):
        before = self.unchanged()
        stale = self.in_force(self.v110, release("1.1.0"))
        for label, call in (
                ("transition", lambda: self.store.transition(self.cid, self.request(), stale.policy.lifecycle,
                                                             policy_ref=stale.ref)),
                ("transition with current rules", lambda: self.store.transition(
                    self.cid, self.request(), self.v120.policy.lifecycle, policy_ref=stale.ref)),
                ("unrecorded demo policy", lambda: self.store.transition(
                    self.cid, self.request(), self.v120.policy.lifecycle,
                    policy_ref=PolicyRef.of(policy_digest=self.v120.policy_digest, source=DEMO_SOURCE)))):
            with self.subTest(label):
                with self.assertRaises(StoreConflict):
                    call()
                self.assertEqual(self.unchanged(), before)

    def test_rules_other_than_the_version_s_own_are_refused(self):
        current = self.in_force(self.v120, release("1.2.0"))
        loose = replace(current.policy.lifecycle, freshness=FreshnessPolicy(approval=timedelta(days=14)))
        before = self.unchanged()
        with self.assertRaises(StoreConflict):
            self.store.transition(self.cid, self.request(), loose, policy_ref=current.ref)
        self.assertEqual(self.unchanged(), before)
        self.store.transition(self.cid, self.request(), current.policy.lifecycle, policy_ref=current.ref)
        self.assertEqual(self.store.recorded_policies(self.cid)[f"decision:{self.store.decisions(self.cid)[-1].id}"],
                         current.ref)

    def test_a_policy_recorded_while_a_request_was_judged_makes_the_api_refuse(self):
        """The server read 1.1.0 (as if 1.2.0 were recorded between the read and the write)."""
        client = self.world.client(SECURITY_2)
        before = self.unchanged()
        with mock.patch("app.api.services.policy_in_force", return_value=self.in_force(self.v110, release("1.1.0"))):
            result = client.post(f"{V}/candidates/{self.cid}/transitions", {"target": "BLOCKED", "reason": "hold"})
        self.assertEqual((result.status, result.code), (409, "CONFLICT"), result.json)
        self.assertEqual(len(self.store.decisions(self.cid)), before[1], "no decision recorded")
        # The only new event is the API's own audited refusal, naming why.
        new_events = self.store.audit_events()[before[0][0] + 1:]
        self.assertEqual([(e.result.value, dict(e.details)["code"], dict(e.details)["message"]) for e in new_events],
                         [("REFUSED", "CONFLICT", "the decision names a policy version that is not the version in force")])


if __name__ == "__main__":
    unittest.main()
