"""OGWA-UI-REVIEW-01 in a real headless browser, over the classic synthetic world (opt-in, UI_BROWSER_TESTS=1).

The operator review workflow: the Review queue (review statuses read from lifecycle states,
filters by keyboard with focus kept, waiting never shown as blocked, nothing shown as ready), the
candidate page's lifecycle stepper and its text equivalent, the next step, evidence readiness,
Impact & Blockers ("none found" apart from "not established"), Decisions apart from holds, Plans &
simulations wording, the dashboard's attention links, and find by id.
"""

import json
import re
import unittest

from tests.browser.harness import Browser, SyntheticServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

STATUSES = {"Needs review", "Blocked", "Waiting", "In progress (dry run only)", "Retired (observed)", "Closed"}


@unittest.skipIf(skip_reason(), skip_reason() or "")
class ReviewWorkflowTests(BrowserCase):
    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.server = SyntheticServer().start_and_wait()
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

    def history(self, step: str) -> None:
        b = self.browser
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate(f"history.{step}()")
        b.wait_for("!document.getElementById('view').dataset.old && "
                   "document.getElementById('page-title').textContent !== 'Loading'", message=step)

    def statuses(self) -> list[str]:
        """The review status of every row in the queue table (the badge before the lifecycle line)."""
        return self.browser.evaluate("[...document.querySelectorAll('main table tbody tr')]"
                                     ".map(r => r.children[1].querySelector('.badge').textContent)")

    # --- the Review queue -------------------------------------------------------------------

    def test_a_the_queue_reads_lifecycle_states_and_filters_by_keyboard(self):
        b = self.browser
        self.nav("#/review", expect_title="Review queue")
        self.assertEqual(b.text("main nav.status-filters a[aria-current=true]").split(" (")[0], "Open")
        statuses = self.statuses()
        self.assertTrue(statuses)
        self.assertLessEqual(set(statuses), {"Needs review", "Blocked", "Waiting", "In progress (dry run only)"})
        order = ["Needs review", "Blocked", "Waiting", "In progress (dry run only)"]
        self.assertEqual(statuses, sorted(statuses, key=order.index), "decisions first, then blocked, then waiting")
        # Every row keeps its lifecycle state, so the review status is never the only fact shown.
        lifecycle = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.children[1].innerText)")
        self.assertTrue(all("Lifecycle:" in x for x in lifecycle), lifecycle)
        self.assert_accessible("review queue")
        # A filter link keeps focus after the queue re-renders, and Back returns to the open queue.
        b.focus("main nav.status-filters a[data-focus-key='status:blocked']")
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.key("Enter")
        b.wait_for("!document.getElementById('view').dataset.old", message="filtered queue")
        self.assertEqual(b.evaluate("document.activeElement.dataset.focusKey"), "status:blocked")
        self.assertEqual(b.evaluate("document.activeElement.getAttribute('aria-current')"), "true")
        self.assertEqual(set(self.statuses()), {"Blocked"})
        text = b.text("main table")
        for expected in ("Blocked: dependency", "Blocked: evidence stale", "Blocked: identity not proven", "Held by an operator",
                         "Blocking dependency resolved", "Only clears when fresh, complete evidence is recorded"):
            self.assertIn(expected, text)
        b.screenshot("review-01-blocked")
        self.history("back")
        self.assertEqual(b.text("main nav.status-filters a[aria-current=true]").split(" (")[0], "Open")

    def test_b_waiting_is_not_blocked_and_nothing_is_ready(self):
        b = self.browser
        self.nav("#/review?status=waiting", expect_title="Review queue")
        self.assertEqual(set(self.statuses()), {"Waiting"})
        rows = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.innerText)")
        holds = [r for r in rows if "hold period" in r]
        self.assertEqual(len(holds), 2, "the post-unassignment and post-quarantine holds")
        for row in holds:
            self.assertRegex(row, r"(remaining|Ended .* ago)", "a hold's end is worded on the server's clock")
            self.assertIn("until 20", row, "and its absolute time is kept")
            self.assertNotRegex(row, r"\bBlocked\b")
        self.nav("#/review?status=all", expect_title="Review queue")
        self.assertLessEqual(set(self.statuses()), STATUSES)
        self.assertNotRegex(b.text("#view"), r"\bReady\b")
        approved = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.innerText)"
                              ".filter(t => t.includes('Approved for a future Okta step'))")
        self.assertTrue(approved and all("In progress (dry run only)" in r and "It executes nothing." in r for r in approved))

    # --- the candidate page ---------------------------------------------------------------

    def test_c_the_lifecycle_stepper_has_a_text_equivalent(self):
        b = self.browser
        stepper = "document.querySelector('ol.stepper')"
        for key, current, status in (("S16", "Deletion review", "Current"), ("S01", "Hold", "Current, waiting"),
                                     ("S03", "Discovery", "Blocked"), ("S06", "Discovery", "Stopped here")):
            with self.subTest(candidate=key):
                self.candidate(key)
                self.assertEqual(b.evaluate(f"{stepper}.getAttribute('aria-label')"), "Lifecycle stages")
                items = b.evaluate(f"[...{stepper}.children].map(li => li.innerText.replace(/\\n/g, ' | '))")
                self.assertEqual(len(items), 10)
                at = b.evaluate(f"[...{stepper}.querySelectorAll('[aria-current=step]')].map(li => li.querySelector('.step-label').textContent)")
                self.assertEqual(at, [current])
                here = b.evaluate(f"{stepper}.querySelector('[aria-current=step] .step-status').textContent")
                self.assertEqual(here, status)
                # Status is written out on every stage; the mark is hidden from assistive technology.
                self.assertTrue(b.evaluate(f"[...{stepper}.querySelectorAll('.step-mark')].every(m => m.getAttribute('aria-hidden') === 'true')"))
                self.assertTrue(b.evaluate(f"[...{stepper}.children].every(li => li.querySelector('.step-status').textContent.trim())"))
                self.assertTrue(b.text(".stepper-summary").startswith("Stage "))
                after = b.evaluate(f"""(() => {{ const li = [...{stepper}.children];
                    return li.slice(li.findIndex(x => x.getAttribute('aria-current') === 'step') + 1).map(x => x.dataset.status); }})()""")
                self.assertNotIn("done", after, "no stage after the candidate is shown as reached")
                self.assert_accessible(f"candidate {key}")
        self.candidate("S03")
        self.assertIn("Blocking dependency resolved", b.text("#view"))
        self.assertRegex(b.text("#view"), r"\d+ of \d+ required sources complete and current")
        sections = b.evaluate("[...document.querySelectorAll('#view section h2')].map(h => h.textContent).slice(0, 5)")
        self.assertEqual(sections, ["Lifecycle", "What blocks this candidate", "Next step", "Evidence readiness",
                                    "Is this safe to act on?"])
        b.screenshot("review-02-stepper-blocked")

    # --- Impact & Blockers ----------------------------------------------------------------

    def test_d_impact_and_blockers_tell_none_found_from_not_established(self):
        b = self.browser
        self.nav("#/findings", expect_title="Findings")
        self.assertEqual(b.evaluate("document.querySelector('[role=tab][aria-selected=true]').textContent"), "Impact & Blockers")
        checks = b.evaluate("fetch('/api/v1/dependency-findings?limit=200', {credentials: 'same-origin'}).then(r => r.json())"
                            ".then(j => j.page.nextCursor ? null : j.items)")
        self.assertIsNotNone(checks, "every check fits in one API page")
        gaps = sum(1 for d in checks if not d["findings"] and not (d["provenance"]["resultStatus"] == "COMPLETE" and d["provenance"]["decisionGrade"]))
        blocking = sum(1 for d in checks if any(f["blocking"] for f in d["findings"]))
        self.nav("#/findings?tab=dependency&sort=findings&order=desc")
        first_page = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.children[1].innerText)")
        self.assertTrue(any(x.startswith("Directory constraint") or x.startswith("Known dependency") or x.startswith("External reference")
                            for x in first_page))
        self.assertTrue(blocking and any("Blocks lifecycle progress" in x for x in first_page))
        # Over every page: a coverage gap always says OGWA could not tell, and never "None found".
        seen_gaps = 0
        self.nav("#/findings?tab=dependency")
        while True:
            cells = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.children[1].innerText)")
            for cell in cells:
                if cell.startswith("Coverage gap"):
                    seen_gaps += 1
                    self.assertIn("could not determine whether a dependency exists", cell)
                    self.assertNotIn("None found", cell)
                if cell.startswith("None found"):
                    self.assertIn("complete, decision-grade check", cell)
            if not b.evaluate("[...document.querySelectorAll('nav.pager a')].some(a => a.textContent === 'Next page')"):
                break
            self.click_link("Next page")
        self.assertEqual(seen_gaps, gaps)
        self.assert_accessible("impact and blockers")

    def click_link(self, text: str) -> None:
        b = self.browser
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate(f"[...document.querySelectorAll('main a')].find(a => a.textContent === {json.dumps(text)}).click()")
        b.wait_for("!document.getElementById('view').dataset.old", message=text)

    # --- Decisions, plans, dashboard, find -------------------------------------------------

    def test_e_decisions_are_recorded_decisions_only(self):
        b = self.browser
        self.sign_in("synthetic.securityiam.one")
        self.candidate("S08")
        self.press_button("Decline approval: Okta unassignment")
        b.type("Synthetic: usage window under review.")
        self.press_button("Record rejection")
        b.wait_for("document.body.innerText.includes('Rejection recorded')", message="rejection flash")
        self.nav("#/decisions", expect_title="Decisions")
        rows = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.innerText)")
        rejected = [r for r in rows if "Rejected" in r]
        self.assertEqual(len(rejected), 1)
        self.assertIn("Synthetic: usage window under review.", rejected[0])
        self.assertTrue(any(re.search(r"Expired \d+ (days|hours?) ago", r) for r in rows), "expired approvals say how long ago")
        self.assertTrue(any(re.search(r"\d+ (days|hours?) remaining", r) for r in rows))
        self.assertTrue(all("Approved for future action" in r or "Rejected" in r for r in rows))
        self.assertIn("it is not execution", b.text("#view"))
        self.assertNotIn("hold period", b.text("main table"), "holds are not decisions")
        self.assert_accessible("decisions")
        self.assert_no_dangerous_control("decisions")
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate("[...document.querySelectorAll('main tbody tr')].find(r => r.innerText.includes('Rejected')).querySelector('a').click()")
        b.wait_for("!document.getElementById('view').dataset.old && document.getElementById('page-title').textContent.startsWith('Candidate: ')",
                   message="candidate from its decision")
        self.sign_in("synthetic.viewer.one")

    def test_f_plans_and_simulations_never_imply_execution(self):
        b = self.browser
        self.nav("#/jobs", expect_title="Plans & simulations")
        text = b.text("#view")
        self.assertIn("Dry-run planning only.", text)
        self.assertIn("Synthetic drills", text)
        statuses = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.children[3].querySelector('.badge').textContent)")
        self.assertTrue(statuses)
        self.assertTrue(all(s.endswith("nothing executed") for s in statuses), statuses)
        self.assertNotIn("Succeeded", b.text("main table"), "a finished plan is never worded as a success")
        self.assertEqual(set(b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.children[4].innerText)")), {"No"})
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate("document.querySelector('main table tbody th a').click()")
        b.wait_for("!document.getElementById('view').dataset.old && document.getElementById('page-title').textContent.startsWith('Dry-run plan ')",
                   message="plan detail")
        self.assertIn("nothing executed", b.text("#view"))

    def test_g_the_dashboard_starts_with_what_needs_attention(self):
        b = self.browser
        self.nav("#/", expect_title="Dashboard")
        self.assertEqual(b.evaluate("document.querySelector('#view section h2').textContent"), "Needs attention")
        links = b.evaluate("[...document.querySelectorAll('ul.attention a')].map(a => [a.textContent, a.getAttribute('href')])")
        # "1 candidate …" and "4 candidates …" name the same link.
        hrefs = {re.sub(r"^[\d,]+ (candidates?)? ?", lambda m: "candidates " if m.group(1) else "", t): h for t, h in links}
        # Holds near their end are counted on the server's clock: the same count, worked out here from the API.
        soon = b.evaluate("""Promise.all([fetch('/api/v1/dashboard', {credentials: 'same-origin'}).then(r => r.json()),
            fetch('/api/v1/candidates?limit=200', {credentials: 'same-origin'}).then(r => r.json())]).then(([d, c]) =>
            c.items.map(x => x.state === 'HOLD' ? x.holdUntil : x.state === 'QUARANTINE_HOLD' ? x.quarantineHoldUntil : null)
              .filter(Boolean).filter(t => Date.parse(t) - Date.parse(d.generatedAt) <= 7 * 86400000).length)""")
        if soon:
            self.assertEqual(hrefs["holds ended or ending within 7 days"], "#/review?status=waiting")
        else:
            self.assertNotIn("holds ended or ending within 7 days", hrefs)
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate("document.querySelector('ul.attention a[href=\"#/review?status=needs-review\"]').click()")
        b.wait_for("!document.getElementById('view').dataset.old && document.getElementById('page-title').textContent === 'Review queue'",
                   message="filtered queue from the dashboard")
        self.assertEqual(set(self.statuses()), {"Needs review"})
        self.assertEqual(len(self.statuses()), int(links[0][0].split(" ")[0]), "the dashboard's count is the queue's")

    def test_h_find_by_id_opens_the_object_and_never_matches_names_locally(self):
        b = self.browser
        self.nav("#/", expect_title="Dashboard")
        cid = self.server.scenarios["S12"]
        b.focus("form[role=search] input")
        b.type(cid)
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.key("Enter")
        b.wait_for("!document.getElementById('view').dataset.old && document.getElementById('page-title').textContent.startsWith('Candidate: ')",
                   message="candidate by id")
        self.assertEqual(b.evaluate("location.hash"), f"#/candidates/{cid}")
        self.nav("#/", expect_title="Dashboard")
        b.focus("form[role=search] input")
        b.type("finance")
        b.key("Enter")
        b.wait_for("document.querySelector('form[role=search] + div p')", message="no id match")
        self.assertIn('No object has the id "finance".', b.text("#view"))
        self.assertEqual(b.evaluate("location.hash"), "#/", "a name is never resolved in the browser")

    def test_i_phone_width_has_no_sideways_scroll(self):
        b = self.browser
        b.viewport(375, 812, mobile=True)
        try:
            for page in ("#/review", "#/review?status=all", "#/decisions", "#/jobs", f"#/candidates/{self.server.scenarios['S16']}"):
                with self.subTest(page=page):
                    self.nav(page)
                    overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    self.assertLessEqual(overflow, 0, f"{page} scrolls sideways at 375px")
            b.screenshot("review-03-phone")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")
            b.viewport(1280, 900)

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
