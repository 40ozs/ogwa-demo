"""The Null Meridian directory views in a real headless browser (opt-in, like the other browser tests).

Serves an in-memory Null Meridian world on loopback and walks every directory view a
reviewer would: the company overview, the portfolio scenarios, findings, people, a person's
access paths, directory groups, and the inventory pages that link into them. Each must render
accessibly, request nothing but its own origin, and offer no mutating control.

Null Meridian content throughout (scenario titles, NM-C08/NM-C10, nullmeridian.info), so with
``UI_BROWSER_TARGET`` it runs only against a target serving Null Meridian; on Genesee Press, see
test_genesee_press_ui (every view, the data-quality candidate) and test_ui_ia.
"""

import json
import unittest

from tests.browser.harness import Browser, SyntheticServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

# OGWA-UI-REVIEW-01: the sections a candidate page opens with, before its evidence.
REVIEW_FIRST = ["Lifecycle", "What blocks this candidate", "Next step", "Evidence readiness"]
VIEWS = ("#/directory", "#/scenarios", "#/findings", "#/findings?severity=ACTIONABLE", "#/people",
         "#/people?department=data&status=ACTIVE", "#/people?status=TERMINATED", "#/directory-groups",
         "#/directory-groups?health=ACTIONABLE", "#/directory-groups?era=legacy-ad", "#/applications", "#/groups",
         "#/candidates", "#/")
NOT_RENDERED = ("Something went wrong", "Not found", "Not permitted", "Loading")


@unittest.skipIf(skip_reason(), skip_reason() or "")
class NullMeridianViewTests(BrowserCase):
    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.server = SyntheticServer(refresh=(), dataset="null-meridian").start_and_wait()
        try:
            cls.browser = Browser(browser_path())
        except Exception:
            cls.server.stop()
            raise

    signed_in = False

    def setUp(self):
        if not type(self).signed_in:
            self.sign_in("synthetic.viewer.one")
            type(self).signed_in = True

    def follow_first(self, listing: str, selector: str = "main table a") -> str:
        self.nav(listing)
        href = self.browser.evaluate(f"document.querySelector({json.dumps(selector)}).getAttribute('href')")
        self.nav(href)
        return href

    def check_page(self, where: str) -> None:
        b = self.browser
        self.assertNotIn(b.title(), NOT_RENDERED, b.text("#view") if b.title() != "Loading" else where)
        self.assert_accessible(where)
        self.assert_no_dangerous_control(where)

    def test_a_every_directory_view_renders(self):
        for hash_path in VIEWS:
            with self.subTest(view=hash_path):
                self.nav(hash_path)
                self.check_page(hash_path)
        self.nav("#/directory", expect_title="Company Directory")
        self.browser.evaluate("document.querySelector('details.profile').open = true")
        text = self.browser.text()
        self.assertIn("Null Meridian is fictional.", text)
        self.assertIn("nullmeridian.info", text)
        self.assertIn("Active employees\n1800", text)
        self.browser.screenshot("nm-01-directory")
        self.assert_clean()

    def test_b_details_reached_by_links(self):
        b = self.browser
        for listing in ("#/people", "#/directory-groups", "#/directory-groups?health=ACTIONABLE", "#/findings",
                        "#/findings?tab=governance", "#/applications", "#/groups"):
            with self.subTest(detail_from=listing):
                href = self.follow_first(listing, "main :is(#tab-panel, #view > div) table a")
                self.check_page(href)
        self.nav("#/people?department=data")
        self.follow_first("#/people?department=data")
        self.assertIn("Application access and how it is granted", b.text())
        b.screenshot("nm-02-person")
        self.assert_clean()

    def test_c_scenarios_link_to_candidates_and_groups(self):
        b = self.browser
        self.nav("#/scenarios", expect_title="Portfolio scenarios")
        text = b.text()
        for title in ("A healthy modern application", "A legacy application with transitional groups",
                      "An empty group still linked to an application", "Direct assignments bypassing group governance",
                      "Duplicate and overlapping access paths", "Ambiguous legacy-to-modern group correlation",
                      "A clean remediation candidate", "A hierarchy that works but has become unnecessarily deep",
                      "Conflicting and incomplete evidence: no safe decision"):
            self.assertIn(title, text)
        b.screenshot("nm-03-scenarios")
        candidate = b.evaluate("document.querySelector('main a[href^=\"#/candidates/\"]').getAttribute('href')")
        self.nav(candidate, prefix="Candidate: ")
        self.check_page(candidate)
        self.nav("#/directory-groups?q=sg-okta-warehouse-readonly")
        self.follow_first("#/directory-groups?q=sg-okta-warehouse-readonly", "#tab-panel table a")
        self.assertIn("DEEP_NESTING", b.text())
        b.screenshot("nm-04-deep-group")
        self.assert_clean()

    def test_d_phone_width_has_no_page_level_horizontal_scroll(self):
        b = self.browser
        b.viewport(375, 812, mobile=True)
        try:
            for hash_path in ("#/directory", "#/scenarios", "#/people", "#/findings", "#/directory-groups"):
                with self.subTest(view=hash_path):
                    self.nav(hash_path)
                    overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    self.assertLessEqual(overflow, 0, f"{hash_path} scrolls sideways at 375px")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")

    def test_e_conflicting_evidence_is_explained_not_acted_on(self):
        """OGWA-DEMO-01: NM-C10's page answers the reviewer's six questions and offers no way to act."""
        b = self.browser
        candidate = f"#/candidates/{self.server.scenarios['NM-C10']}"
        self.nav(candidate, prefix="Candidate: ")
        self.check_page(candidate)
        text = b.text()
        for expected in ("Is this safe to act on?", "No action: sources disagree", "1. Proposed governance issue",
                         "2. Sources that support it", "3. Sources that disagree, conflict, or are unavailable",
                         "4. Identity mapping", "5. What OGWA can safely decide now", "6. Evidence needed to proceed",
                         "Probable, not proven", "Rules would refuse", "Evidence by source",
                         # Every evidence state, each in its own words.
                         "Confirmed", "Source says none", "Not collected", "Source unavailable", "Partial read",
                         "Identity not established", "Conflicting"):
            self.assertIn(expected, text)
        self.assertNotIn("Eligible for a named human", text)
        self.assertNotIn("Rules would accept", text)
        # OGWA-UI-REVIEW-01: the operator's reading (lifecycle, what blocks it, the next step, evidence readiness)
        # comes first; the assessment is the first evidence section after it.
        sections = b.evaluate("[...document.querySelectorAll('#view section h2')].map(h => h.textContent).slice(0, 5)")
        self.assertEqual(sections, REVIEW_FIRST + ["Is this safe to act on?"])
        b.screenshot("nm-05-conflicting-evidence")
        b.viewport(375, 812, mobile=True)
        try:
            self.nav(candidate, prefix="Candidate: ")
            overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            self.assertLessEqual(overflow, 0, "the candidate page scrolls sideways at 375px")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")
        self.assert_clean()

    def test_f_the_decision_names_the_policy_version_that_produced_it(self):
        """OGWA-DEMO-02: the candidate page says which policy version ran, why, and what judged its history."""
        b = self.browser
        for key, decision, forced in (("NM-C10", "No action: sources disagree", "Yes"),
                                      ("NM-C08", "No action: no approval is open in this state", "No")):
            candidate = f"#/candidates/{self.server.scenarios[key]}"
            self.nav(candidate, prefix="Candidate: ")
            self.check_page(candidate)
            text = b.text()
            for expected in ("Why this decision", "Policy version that ran", "NM-LIFECYCLE-004 v1.2.0",
                             "In force now", "Decision it produced", decision,
                             "Did ambiguous or missing evidence force manual review?", forced,
                             "What would need to change for a different outcome",
                             "Conditions, as the policy version that ran states them", "Rule under this version",
                             "AD counterpart established exactly", "Judged by policy"):
                self.assertIn(expected, text, key)
            if key == "NM-C10":
                self.assertIn("Not proven", text)
                self.assertIn("Not judged", text)
            else:
                # Its history was judged by v1.1.0; the page says so instead of relabelling it.
                self.assertIn("NM-LIFECYCLE-004 v1.1.0", text)
                self.assertIn("Superseded", text)
                self.assertIn("Not applicable", text)
        sections = b.evaluate("[...document.querySelectorAll('#view section h2')].map(h => h.textContent).slice(0, 6)")
        self.assertEqual(sections, REVIEW_FIRST + ["Is this safe to act on?", "Why this decision"])
        b.screenshot("nm-06-policy-version")
        b.viewport(375, 812, mobile=True)
        try:
            self.nav(f"#/candidates/{self.server.scenarios['NM-C10']}", prefix="Candidate: ")
            overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            self.assertLessEqual(overflow, 0, "the candidate page scrolls sideways at 375px")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")
        self.assert_clean()

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
