"""The synthetic remediation drill in a real headless browser (OGWA-DEMO-03; opt-in like the others).

Serves an in-memory Null Meridian world on loopback and, as an executor, drills NM-C11's
approved Okta unassignment from its candidate page: a dry run, the timeout / verification /
retry / verification scenario, and a verification failure. Dry run and execution must be
impossible to confuse in a screenshot; the page must stay accessible, keyboard-operable, free
of sideways scroll at phone width, and request nothing but its own origin.

OGWA-DEMO-04: the result's mode banner (DRY RUN — NO STATE CHANGED vs SYNTHETIC EXECUTION, "No
external provider or persistent environment was modified.") is above everything else and never
shared; the "Authorized by" chain names the policy version, decision, approval, and operation id;
and the guided walkthrough leads from the dashboard to both of its candidates.
"""

import json
import unittest

from tests.browser.harness import Browser, SyntheticServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

SECTION = "Remediation: dry run or synthetic drill"
TIMEOUT_RETRY = ["EXECUTION REQUESTED — SYNTHETIC DEMO", "OUTCOME UNKNOWN — VERIFYING",
                 "VERIFYING — READING SYNTHETIC PROVIDER STATE", "RETRY PERMITTED — VERIFIED NOT APPLIED",
                 "EXECUTION REQUESTED — SYNTHETIC DEMO", "EXECUTED — SYNTHETIC DEMO", "POST-ACTION VERIFIED"]
WIDTHS = (320, 360, 375, 390, 414, 640, 768, 1280, 1440, 1920)


@unittest.skipIf(skip_reason(), skip_reason() or "")
class RemediationDrillUiTests(BrowserCase):
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

    signed_in_as = None

    def as_user(self, subject: str) -> None:
        if type(self).signed_in_as != subject:
            # The public demo has no sign-in: its anonymous visitor (a viewer) may drill NM-C11, as an executor may.
            self.sign_in("synthetic.viewer.one" if self.on_public_demo() else subject)
            type(self).signed_in_as = subject
        self.nav(f"#/candidates/{self.server.scenarios['NM-C11']}", prefix="Candidate: ")

    def on_public_demo(self) -> bool:
        self.browser.goto(self.server.origin + "/#/")
        self.browser.wait_for("document.getElementById('page-title').textContent !== 'Loading'", message="the console")
        return self.public_demo()

    def section_text(self) -> str:
        return self.browser.evaluate(f"""(() => {{ const s = [...document.querySelectorAll('section')]
            .find(x => x.querySelector('h2') && x.querySelector('h2').textContent === {json.dumps(SECTION)});
            return s ? s.innerText : null; }})()""")

    def mode_banner(self) -> list[str]:
        return self.browser.evaluate("""(() => { const m = document.querySelector('.drill-result .drill-mode-banner');
            return m ? [m.dataset.mode, m.dataset.tone, m.querySelector('.drill-mode').textContent] : null; })()""")

    def step_labels(self) -> list[str]:
        return self.browser.evaluate("[...document.querySelectorAll('.drill-steps .state-label')].map(e => e.textContent)")

    def run_drill(self, scenario: str | None = None) -> str:
        """Choose the mode with the keyboard, then press Run drill with Enter, and wait for the answer."""
        b = self.browser
        b.focus(".drill-form input[type=radio]:checked")
        if scenario is not None:
            if b.evaluate("document.querySelector('.drill-form input[type=radio]:checked').value") == "DRY_RUN":
                b.key("ArrowRight")  # the radio group's own keyboard behaviour selects the next mode
            self.assertFalse(b.evaluate("document.querySelector('.drill-form select[aria-describedby]').disabled"))
            b.evaluate(f"""(() => {{ const s = document.querySelector('.drill-form select[aria-describedby]');
                s.value = {json.dumps(scenario)}; s.dispatchEvent(new Event('change')); }})()""")
        elif b.evaluate("document.querySelector('.drill-form input[type=radio]:checked').value") != "DRY_RUN":
            b.key("ArrowLeft")
        b.evaluate("document.querySelector('.drill-result').replaceChildren()")
        self.press_button("Run drill")
        b.wait_for("document.querySelector('.drill-result .drill-outcome, .drill-result .form-error')",
                   message="the drill's answer")
        return b.text(".drill-result")

    def test_a_dry_run_says_no_state_changed(self):
        self.as_user("synthetic.executor.one")
        self.assertIn("A drill changes only a synthetic provider fixture, and records nothing.", self.section_text())
        self.assertTrue(self.browser.evaluate("document.querySelector('.drill-form select[aria-describedby]').disabled"),
                        "a dry run takes no fault scenario")
        text = self.run_drill()
        self.assertIn("DRY RUN — NO STATE CHANGED", text)
        self.assertIn("Nothing was submitted", text)
        self.assertIn("Unchanged", text)
        self.assertNotIn("EXECUTED", text)
        self.assertIn("Nothing was submitted to the synthetic provider.", text, "an empty ledger says so")
        self.assertEqual(self.mode_banner(), ["DRY_RUN", "neutral", "DRY RUN — NO STATE CHANGED"])
        self.assertNotIn("SYNTHETIC EXECUTION", text, "a dry run never carries the execution banner")
        self.assertIn("Not reached: nothing was executed", text)
        self.assertEqual(self.browser.active()["tag"], "h3", "focus moves to the result")
        self.assert_accessible("dry-run drill")
        self.assert_no_dangerous_control("dry-run drill")
        self.browser.screenshot("nm-06-drill-dry-run")

    def test_b_a_timeout_is_verified_then_retried_once_then_verified(self):
        self.as_user("synthetic.executor.one")
        text = self.run_drill("TIMEOUT_NOT_APPLIED")
        self.assertEqual(self.step_labels(), TIMEOUT_RETRY)
        self.assertNotIn("DRY RUN", text)
        self.assertIn("Executed against the synthetic provider fixture only (2 submissions, 1 change applied", text)
        self.assertEqual(self.browser.evaluate("document.querySelector('.drill-banner').dataset.tone"), "info")
        self.assertIn("+30 s", text, "the timeout is visible on the synthetic clock")
        self.assertEqual(self.mode_banner(), ["SYNTHETIC_EXECUTION", "caution", "SYNTHETIC EXECUTION"])
        self.assertIn("No external provider or persistent environment was modified.", text)
        self.assertTrue(self.browser.evaluate("""(() => { const m = document.querySelector('.drill-mode-banner'),
            o = document.querySelector('.drill-banner');
            return !!(m.compareDocumentPosition(o) & Node.DOCUMENT_POSITION_FOLLOWING); })()"""),
            "the mode banner comes before the outcome")
        for fact in ("Authorized by", "NM-LIFECYCLE-004 v1.2.0, recorded version 2", "NEEDS_REVIEW → APPROVED",
                     "Judged by the version in force", "Confirmed: the target is in its planned after-state",
                     "POST-ACTION VERIFIED", "No: a drill records nothing"):
            self.assertIn(fact, text)
        self.assertEqual(self.browser.evaluate(
            "[...document.querySelectorAll('.drill-result table tbody tr')].length > 0"), True)
        self.assert_accessible("timeout drill")
        self.browser.screenshot("nm-07-drill-timeout-verify-retry")
        # The drill recorded nothing: the candidate is still approved, with no dry-run job.
        self.nav(f"#/candidates/{self.server.scenarios['NM-C11']}", prefix="Candidate: ")
        self.assertIn("No dry run has been planned.", self.browser.text())

    def test_c_a_verification_failure_is_never_shown_as_success(self):
        self.as_user("synthetic.executor.one")
        text = self.run_drill("ACKNOWLEDGED_NOT_APPLIED")
        self.assertIn("VERIFICATION FAILED — NOT A SUCCESS", text)
        self.assertIn("Not a success.", text)
        self.assertEqual(self.browser.evaluate("document.querySelector('.drill-banner').dataset.tone"), "blocked")
        self.assertNotIn("VERIFIED\n", text)
        self.browser.screenshot("nm-08-drill-verification-failed")

    def test_d_an_unverifiable_outcome_stays_unknown(self):
        self.as_user("synthetic.executor.one")
        text = self.run_drill("TIMEOUT_UNVERIFIABLE")
        self.assertIn("RETRY NOT PERMITTED — NEEDS A PERSON", text)
        self.assertIn("read failed, read failed", text)
        self.assertNotIn("EXECUTED — SYNTHETIC DEMO", text)

    def test_e_no_width_scrolls_sideways(self):
        # 320 px is also 1280 px at 400% zoom, and 640 px is 1280 px at 200%.
        b = self.browser
        self.as_user("synthetic.executor.one")
        overflow = "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        try:
            b.viewport(320, 640, mobile=True)
            self.nav(f"#/candidates/{self.server.scenarios['NM-C11']}", prefix="Candidate: ")
            self.run_drill("TIMEOUT_NOT_APPLIED")
            b.screenshot("nm-09-drill-320")
            for width in WIDTHS:  # the drill's steps carry its 36-character operation id
                with self.subTest(page="NM-C11 after a drill", width=width):
                    b.viewport(width, 800, mobile=width < 1024)
                    self.assertLessEqual(b.evaluate(overflow), 0, f"the drill result scrolls sideways at {width}px")
            for page in ("#/scenarios", f"#/candidates/{self.server.scenarios['NM-C10']}"):
                for width in WIDTHS:
                    with self.subTest(page=page, width=width):
                        b.viewport(width, 800, mobile=width < 1024)
                        self.nav(page)
                        self.assertLessEqual(b.evaluate(overflow), 0, f"{page} scrolls sideways at {width}px")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")

    def test_f_a_viewer_sees_the_drill_but_cannot_run_it(self):
        if self.on_public_demo():
            self.skipTest("the public demo's visitor may drill NM-C11, its only approved candidate; "
                          "test_hosted_demo_ui and test_cloudflare_hosted prove it reaches no other")
        self.as_user("synthetic.viewer.one")
        text = self.section_text()
        self.assertIn("needs the dry-run planning permission", text)
        self.assertNotIn("Run drill", self.browser.buttons())

    def test_g_the_walkthrough_leads_from_the_dashboard_to_both_candidates(self):
        b = self.browser
        self.as_user("synthetic.viewer.one")
        self.nav("#/", expect_title="Dashboard")
        self.assertIn("Start the five-minute reviewer walkthrough", b.text())
        self.nav("#/scenarios", expect_title="Portfolio scenarios")
        text = b.text()
        for phrase in ("Reviewer walkthrough (about five minutes)", "All data is synthetic",
                       "No external provider is contacted", "discarded after each answer",
                       "Failure injection is deterministic", "Part 1 — Data quality", "Part 2 — Controlled remediation"):
            self.assertIn(phrase, text)
        links = b.evaluate("[...document.querySelectorAll('.walkthrough-part a')].map(a => [a.textContent, a.getAttribute('href')])")
        self.assertEqual(links, [["Open NM-C10", f"#/candidates/{self.server.scenarios['NM-C10']}"],
                                 ["Open NM-C11", f"#/candidates/{self.server.scenarios['NM-C11']}"]])
        self.assert_accessible("walkthrough")
        b.screenshot("nm-10-walkthrough")
        type(self).signed_in_as = None

    def test_h_a_failed_drill_keeps_focus_on_run_drill_and_says_why(self):
        b = self.browser
        self.as_user("synthetic.executor.one")
        b.focus(".drill-form input[type=radio]:checked")
        b.hold("*/remediation-drills")
        try:
            self.press_button("Run drill")
            b.release(b.held(), fail=True)
            b.wait_for("document.querySelector('.drill-result [role=alert]')", message="the failure")
        finally:
            b.hold(None)
        self.assertEqual(b.active()["text"], "Run drill", "focus stays on the control that failed, next to the reason")
        self.assertIn("could not be reached", b.text(".drill-result"))
        self.assertNotIn("VERIFIED", b.text(".drill-result"), "a failure is never shown as a result")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
