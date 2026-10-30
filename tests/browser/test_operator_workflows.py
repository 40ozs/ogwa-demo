"""End-to-end operator workflows in a real headless browser, over a synthetic world.

Opt-in: set UI_BROWSER_TESTS=1 (scripts/browser-check.ps1 does). Otherwise every test here
is skipped, so the default suite never starts a browser. See tests/browser/harness.py for
the isolation rules (in-memory synthetic store, throw-away profile, no name resolution
except 127.0.0.1). Synthetic principals and synthetic data only.
"""

import json
import re
import unittest

from tests.browser.harness import A11Y_AUDIT, Browser, SyntheticServer, browser_path, enabled

TONES = {"blocked", "caution", "info", "neutral", "terminal"}
FORBIDDEN_CONTROL = re.compile(r"^(delete|unassign|execute|remove|retire|disable)\b", re.I)
# Records every state the page heading and the content were in together, as a reader could meet them.
PAGE_STATES = """window.__ogwaStates = new Set(); new MutationObserver(() => window.__ogwaStates.add(
  document.getElementById('page-title').textContent + (document.getElementById('view').dataset.old ? ' / old content' : ' / new content')))
  .observe(document.getElementById('main'), { childList: true, characterData: true, subtree: true });"""
# Laptop screens, and the same screens zoomed (CSS pixels): 1280 at 125% and 150%, 1440 at 125%.
LAPTOPS = ((1280, 800), (1366, 768), (1440, 900), (1920, 1080), (1024, 640), (853, 533), (1152, 720))
IN_VIEW = """(() => { const r = document.activeElement.getBoundingClientRect();
  return r.top >= 0 && r.bottom <= innerHeight && r.left >= 0 && r.right <= innerWidth; })()"""


def skip_reason() -> str | None:
    if not enabled():
        return "browser tests are opt-in: set UI_BROWSER_TESTS=1 (scripts/browser-check.ps1)"
    if browser_path() is None:
        return "no Chrome or Edge executable found (set UI_BROWSER)"
    return None


class BrowserCase(unittest.TestCase):
    server: SyntheticServer
    browser: Browser

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

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.server.stop()

    # --- helpers --------------------------------------------------------------------------

    def nav(self, hash_path: str, expect_title: str | None = None, prefix: str | None = None) -> None:
        b = self.browser
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        # Setting the current hash again fires no hashchange, so re-render explicitly then.
        b.evaluate(f"""location.hash === {json.dumps(hash_path)}
            ? window.dispatchEvent(new HashChangeEvent('hashchange')) : (location.hash = {json.dumps(hash_path)})""")
        b.wait_for("!document.getElementById('view').dataset.old && "
                   "document.getElementById('page-title').textContent !== 'Loading'", message=f"render of {hash_path}")
        if expect_title:
            self.assertEqual(b.title(), expect_title)
        if prefix:
            self.assertTrue(b.title().startswith(prefix), b.title())

    def candidate(self, key: str) -> None:
        self.nav(f"#/candidates/{self.server.scenarios[key]}", prefix="Candidate: ")

    def public_demo(self) -> bool:
        """Whether the server is the anonymous public demo (OGWA-DEMO-HOSTED-ANON-01): it has no sign-in, and
        every visitor is the same synthetic viewer. Asked of GET /health once the page is on the origin."""
        return bool(self.browser.evaluate("fetch('/api/v1/health').then(r => r.json()).then(j => j.publicDemo === true)"))

    def sign_in(self, subject: str) -> None:
        b = self.browser
        b.goto(self.server.origin + "/#/")
        b.wait_for("['Sign in', 'Dashboard'].includes(document.getElementById('page-title').textContent)",
                   message="sign-in or dashboard")
        if self.public_demo():
            if subject != "synthetic.viewer.one":
                self.skipTest(f"the public demo has no sign-in, so no {subject}: every visitor is its anonymous viewer")
            b.wait_title("Dashboard")
            return
        if b.title() == "Dashboard":  # still signed in from an earlier test: the cookie survives a reload
            self.sign_out()
        b.focus("input[name=subject]")
        b.type(subject)
        b.key("Enter")
        b.wait_title("Dashboard")

    def sign_out(self) -> None:
        b = self.browser
        b.evaluate("[...document.querySelectorAll('#account button')].find(x => x.textContent === 'Sign out').click()")
        b.wait_title("Sign in")

    def press_button(self, label: str) -> None:
        self.browser.focus_button(label)
        self.browser.key("Enter")

    def assert_accessible(self, where: str) -> None:
        self.assertEqual(self.browser.evaluate(A11Y_AUDIT), [], where)

    def assert_no_dangerous_control(self, where: str) -> None:
        for label in self.browser.buttons():
            self.assertIsNone(FORBIDDEN_CONTROL.search(label), f"{where}: {label}")
        tones = set(self.browser.evaluate("[...document.querySelectorAll('[data-tone]')].map(e => e.dataset.tone)"))
        self.assertLessEqual(tones, TONES, where)

    def banner_text(self) -> str:
        return self.browser.evaluate("""(() => { const s = [...document.querySelectorAll('section')]
            .find(x => x.querySelector('h2') && x.querySelector('h2').textContent === 'What blocks this candidate');
            return s ? s.innerText : ''; })()""")

    def assert_clean(self) -> None:
        origin = self.server.origin + "/"
        foreign = [u for u in self.browser.requested_urls() if not (u.startswith(origin) or u == "about:blank")]
        self.assertEqual(foreign, [], "the page requested something other than its own origin")
        self.assertEqual(self.browser.problems(), [], "console errors, exceptions, or CSP violations")


@unittest.skipIf(skip_reason(), skip_reason() or "")
class ReadOnlyReviewTests(BrowserCase):
    """A viewer reviews evidence. Nothing here records anything."""

    def test_a_keyboard_sign_in_and_safety_labels(self):
        b = self.browser
        b.goto(self.server.origin + "/")
        b.wait_title("Sign in")
        self.assertEqual(b.active()["tag"], "input", "the subject field has focus on arrival")
        # Start sequential navigation from the top of the document, as on a fresh page.
        b.evaluate("document.body.tabIndex = -1; document.body.focus(); document.body.removeAttribute('tabindex')")
        b.key("Tab")
        self.assertIn("skip-link", b.active()["cls"])
        b.key("Enter")
        self.assertEqual(b.active()["id"], "main")
        self.assertEqual(b.title(), "Sign in", "the skip link does not navigate")
        b.focus("input[name=subject]")
        b.type("synthetic.viewer.one")
        b.key("Enter")
        b.wait_title("Dashboard")
        self.assertEqual(b.active()["id"], "page-title", "focus moves to the new page's heading")
        self.assertIn("DEMO POLICY — UNRECORDED", b.text("#policy-notice"))
        self.assertEqual(b.text("#environment"), "SYNTHETIC store · LOCAL_SYNTHETIC")
        self.assertIn("This build cannot change Okta or Active Directory", b.text(".safety-strip"))
        # The page's CSP is in force in the real browser: Trusted Types make an HTML sink throw,
        # another origin's image and an inline style are refused. (Probed in a separate tab, so
        # its violations stay out of this one's.)
        self.assertEqual(b.csp_probe(self.server.origin + "/"),
                         {"innerHTML": "TypeError", "violations": ["img-src", "style-src-attr"]})
        self.assertIn("This store has no company directory snapshot", b.text(), "the dashboard says what it cannot show")
        b.evaluate("document.querySelector('details.system-details').open = true")
        self.assertIn("Production changes allowed by this build\nNo", b.text())
        b.screenshot("01-dashboard")

    def test_b_every_view_renders_accessibly_without_a_mutating_control(self):
        b = self.browser
        if b.title() == "Sign in":
            self.sign_in("synthetic.viewer.one")
        # The old addresses (#/approvals, #/applications, #/groups, #/dependencies) arrive on their new pages.
        views = ["#/", "#/review", "#/review?status=all", "#/decisions", "#/candidates", "#/candidates?state=NEEDS_REVIEW",
                 "#/approvals", "#/applications", "#/groups", "#/inventory/groups", "#/mappings", "#/dependencies",
                 "#/collectors", "#/jobs", "#/audit"]
        for hash_path in views:
            with self.subTest(view=hash_path):
                self.nav(hash_path)
                self.assertNotIn(b.title(), ("Something went wrong", "Not found", "Not permitted", "Loading"),
                                 b.text("#view") if b.title() != "Loading" else "")
                self.assert_accessible(hash_path)
                self.assert_no_dangerous_control(hash_path)
        # Details reached by following links, as an operator would.
        for listing, selector in (("#/applications", "main table a"), ("#/groups", "main table a"),
                                  ("#/mappings", "main table a"), ("#/jobs", "main table a"),
                                  ("#/review", "main table a"), ("#/decisions", "main table a")):
            with self.subTest(detail_from=listing):
                self.nav(listing)
                href = b.evaluate(f"document.querySelector({json.dumps(selector)}).getAttribute('href')")
                self.nav(href)
                self.assertNotIn(b.title(), ("Something went wrong", "Not found", "Not permitted"))
                self.assert_accessible(href)
                self.assert_no_dangerous_control(href)
        self.nav("#/audit")
        self.assertIn("Your role cannot read the audit trail.", b.text())

    def test_c_candidate_detail_explains_the_decision(self):
        b = self.browser
        if b.title() == "Sign in":
            self.sign_in("synthetic.viewer.one")
        expected = {
            "S08": ["Name-only match — automatic retirement blocked."],
            "S09": ["Mapping ambiguous — automatic retirement blocked."],
            "S10": ["Mapped AD group not found — automatic retirement blocked."],
            "S13": ["No mapping evidence — automatic retirement blocked.", "Evidence incomplete — a collection did not finish.",
                    "Okta reports a directory SID"],
            "S11": ["Evidence stale — revalidation required."],
            "S12": ["Dependency coverage incomplete — AD deletion blocked."],
            "S06": ["Protected group — OGWA never retires it."],
            "S04": ["AD group has members — AD deletion blocked."],
            "S05": ["Nested group dependency — AD deletion blocked."],
            "S03": ["Group is assigned to another application — retirement blocked."],
        }
        confidence = {}
        for key, phrases in expected.items():
            with self.subTest(scenario=key):
                self.candidate(key)
                banners = self.banner_text()
                for phrase in phrases:
                    self.assertIn(phrase, banners)
                page = b.text()
                for field in ("Okta application", "Usage window", "Last observed sign-in", "Assigned Okta group",
                              "Mapping confidence", "Direct members", "Nested members and member groups",
                              "AD parent groups", "primaryGroupID references", "Other Okta assignments",
                              "Protected status", "Dependency coverage", "Classification reasons",
                              "Evidence timestamps", "Decision history", "DEMO POLICY — UNRECORDED"):
                    self.assertIn(field, page)
                self.assertIn("No decision is open to you", page, "a viewer is offered no action")
                self.assertEqual(b.evaluate("document.querySelectorAll('.action-list button').length"), 0)
                self.assert_accessible(key)
                self.assert_no_dangerous_control(key)
                confidence[key] = b.evaluate("""(() => { const dt = [...document.querySelectorAll('dt')]
                    .find(x => x.textContent === 'Mapping confidence'); return dt.nextElementSibling.querySelector('.badge').textContent; })()""")
                b.screenshot(f"02-candidate-{key}")
        # D98: the four non-exact paths look different, not merely read differently.
        self.assertEqual([confidence[k] for k in ("S08", "S09", "S10", "S13")],
                         ["Name-only match", "Ambiguous", "AD group not found", "No mapping evidence"])
        # D97: S13's missing evidence and S07's unchecked dependencies are never called stale.
        for key in ("S13", "S07"):
            self.candidate(key)
            self.assertNotRegex(self.banner_text().lower(), r"\bstale\b", key)
        self.assertIn("AD membership not checked — AD deletion blocked.", self.banner_text())

    def test_d_phone_width_has_no_page_level_horizontal_scroll(self):
        b = self.browser
        if b.title() == "Sign in":
            self.sign_in("synthetic.viewer.one")
        b.viewport(375, 812, mobile=True)
        try:
            for hash_path in ("#/", "#/review", "#/candidates", f"#/candidates/{self.server.scenarios['S12']}",
                              f"#/candidates/{self.server.scenarios['S16']}", "#/collectors", "#/jobs", "#/decisions"):
                with self.subTest(view=hash_path):
                    self.nav(hash_path)
                    overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    self.assertLessEqual(overflow, 0, f"{hash_path} scrolls sideways at 375px")
            b.screenshot("03-phone-candidate")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")

    def test_e_focus_is_visible_and_reduced_motion_is_honoured(self):
        b = self.browser
        if b.title() == "Sign in":
            self.sign_in("synthetic.viewer.one")
        self.nav("#/candidates")
        b.focus("#page-title")
        b.key("Tab")
        style = b.evaluate("(() => { const s = getComputedStyle(document.activeElement); "
                           "return [document.activeElement.tagName, s.outlineStyle, s.outlineWidth]; })()")
        self.assertEqual(style[1:], ["solid", "3px"], style)
        transition = "getComputedStyle(document.querySelector('.nav-list a')).transitionDuration"
        self.assertNotEqual(b.evaluate(transition), "0s")
        b.media([{"name": "prefers-reduced-motion", "value": "reduce"}])
        try:
            self.assertEqual(b.evaluate(transition), "0s")
        finally:
            b.media([])
        background = "getComputedStyle(document.body).backgroundColor"
        for scheme, colour in (("light", "rgb(246, 245, 241)"), ("dark", "rgb(21, 23, 26)")):
            b.media([{"name": "prefers-color-scheme", "value": scheme}])
            try:
                self.assertEqual(b.evaluate(background), colour, scheme)
                self.nav(f"#/candidates/{self.server.scenarios['S09']}")
                b.screenshot(f"07-{scheme}-S09")
            finally:
                b.media([])

    def test_f_a_slow_page_never_names_itself_over_the_old_content(self):
        b = self.browser
        b.goto(self.server.origin + "/#/")
        b.wait_for("['Sign in', 'Dashboard'].includes(document.getElementById('page-title').textContent)",
                   message="sign-in or dashboard")
        if b.title() == "Dashboard":
            self.sign_out()
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate(PAGE_STATES)
        b.hold("*/api/v1/dashboard*")
        try:
            b.focus("input[name=subject]")
            b.type("synthetic.viewer.one")
            b.key("Enter")
            b.release(b.held())  # the header's environment line
            data = b.held()  # the dashboard's own data: the page is loading, slowly
            self.assertEqual(b.title(), "Loading")
            self.assertEqual(b.evaluate("document.getElementById('main').getAttribute('aria-busy')"), "true")
            self.assertTrue(b.evaluate("!!document.getElementById('view').dataset.old"), "the old content is still shown")
            b.release(data)
        finally:
            b.hold(None)
        b.wait_title("Dashboard")
        self.assertEqual(b.active()["id"], "page-title")
        self.assertIsNone(b.evaluate("document.getElementById('main').getAttribute('aria-busy')"))
        self.assertEqual(b.evaluate("[...window.__ogwaStates].sort()"),
                         ["Dashboard / new content", "Loading / old content"],
                         "the heading only ever named the page that was on screen")

    def test_g_a_slow_page_leaves_focus_where_the_reader_moved_it_and_a_failed_one_explains(self):
        b = self.browser
        self.sign_in("synthetic.viewer.one")
        b.hold("*/api/v1/candidates*")
        try:
            b.focus("#primary-nav a[href='#/review']")
            b.key("Enter")
            data = b.held()
            b.key("Tab")  # while the page loads, the reader moves on
            moved = b.active()
            self.assertEqual(moved["text"], "Findings")
            b.release(data)
            b.wait_title("Review queue")
            self.assertEqual(b.active(), moved, "the late render did not take focus back")
            b.wait_for("document.getElementById('announcer').textContent === 'Review queue'",
                       message="the new page is announced instead")
            # A page whose data fails: focus goes to the heading, which says so, with the explanation below it.
            self.nav("#/collectors", expect_title="Collection health")
            b.focus("#primary-nav a[href='#/review']")
            b.key("Enter")
            b.release(b.held(), fail=True)
            b.wait_title("Something went wrong")
        finally:
            b.hold(None)
        self.assertEqual(b.active()["id"], "page-title")
        self.assertIn("could not be reached", b.text("#view [role=alert]"))

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


@unittest.skipIf(skip_reason(), skip_reason() or "")
class DecisionWorkflowTests(BrowserCase):
    """Reviewers record decisions. Every one is explicit, re-checked, audited, and changes nothing outside OGWA."""

    def test_a_approval_is_explicit_and_changes_nothing(self):
        b = self.browser
        self.sign_in("synthetic.securityiam.one")
        self.candidate("S07")
        self.press_button("Approve for future action: Okta unassignment")
        self.assertEqual(b.active()["tag"], "textarea", "focus moves into the opened form")
        page = b.text()
        self.assertIn("Approval alone does not mutate production.", page)
        self.assert_accessible("approval form")
        # The validity limit is the server's policy value, not one written into the browser code.
        server_max = b.evaluate("fetch('/api/v1/policy', {credentials: 'same-origin'}).then(r => r.json())"
                                ".then(j => j.inForce.approvalMaxValidHours)")
        self.assertIsInstance(server_max, int)
        self.assertEqual(b.evaluate("document.querySelector('form.action-form input[type=number]').max"), str(server_max))
        self.assertIn(f"1 to {server_max}, the policy's maximum.", b.text("form.action-form"))
        self.press_button("Record approval")
        b.wait_for("document.querySelector('[role=alert]')", message="validation message")
        self.assertIn("Give a reason.", b.text("[role=alert]"))
        self.assertEqual(b.active()["tag"], "textarea", "focus returns to the field to fix")
        b.type("Synthetic review: application inactive, exact configured mapping.")
        b.key("Tab")  # validity hours
        b.key("Tab")  # acknowledgement
        self.assertEqual(b.evaluate("document.activeElement.type"), "checkbox")
        self.press_button("Record approval")
        self.assertIn("Confirm that you understand approval changes nothing.", b.text("[role=alert]"))
        b.focus("form.action-form input[type=checkbox]")
        b.key(" ")
        self.press_button("Record approval")
        b.wait_for("document.body.innerText.includes('Approval recorded for Okta unassignment')", message="approval flash")
        page = b.text()
        self.assertIn("Nothing in Okta or Active Directory changed.", page)
        self.assertIn("Approved for a future Okta step", page)
        self.assertIn("Synthetic review: application inactive, exact configured mapping.", page)
        self.assertEqual(b.active()["id"], "page-title")
        b.screenshot("04-approved")

    def test_b_name_only_approval_is_refused_explained_and_audited(self):
        b = self.browser
        self.candidate("S08")
        self.press_button("Approve for future action: Okta unassignment")
        b.type("Synthetic attempt on a name-only mapping.")
        b.focus("form.action-form input[type=checkbox]")
        b.key(" ")
        self.press_button("Record approval")
        b.wait_for("document.querySelector('form [role=alert]')", message="refusal")
        refusal = b.text("form [role=alert]")
        self.assertIn("The lifecycle rules refuse this step on the current evidence", refusal)
        self.assertRegex(refusal, r"recorded in the audit trail as aud_[0-9a-f]{32}")
        self.assertRegex(refusal, r"Request id: req_[0-9a-f]{32}")
        self.assertIn("Needs review", b.text(".detail-main"))
        b.screenshot("05-refused")

    def test_c_audit_history_shows_the_refusal(self):
        b = self.browser
        self.nav("#/audit", expect_title="Audit history")
        page = b.text()
        self.assertIn("Governed request refused", page)
        self.assertIn("Approval recorded", page)
        self.assert_accessible("audit")

    def test_d_executor_plans_and_records_a_dry_run_and_nothing_executes(self):
        b = self.browser
        self.sign_in("synthetic.executor.one")
        self.candidate("S07")
        self.press_button("Run dry-run: Okta unassignment")
        self.assertIn("A dry run plans; it never executes.", b.text())
        self.assertEqual(b.evaluate("document.querySelectorAll('form.action-form select option').length"), 1)
        self.press_button("Plan dry run")
        b.wait_for("document.body.innerText.includes('Dry run planned')", message="dry-run flash")
        self.assertIn("none was executed", b.text())
        self.press_button("Record the dry-run step")
        self.assertEqual(b.active()["tag"], "select", "focus starts on the job to record")
        b.focus("form.action-form textarea")
        b.type("Synthetic: recording the planned dry run.")
        self.press_button("Record dry-run step")
        b.wait_for("document.body.innerText.includes('Recorded: Okta dry run recorded')", message="record flash")
        self.assertIn("Okta dry run recorded", b.text(".detail-main"))
        self.nav("#/jobs", expect_title="Plans & simulations")
        page = b.text()
        self.assertIn("Dry-run planning only.", page)
        self.assertNotRegex(page, r"\tYes\t", "no job shows Executed: Yes")
        self.assert_no_dangerous_control("jobs")
        b.screenshot("06-jobs")

    def test_da_an_opened_form_is_on_screen_at_laptop_sizes(self):
        b = self.browser
        self.sign_in("synthetic.automation.one")
        self.candidate("S12")
        try:
            for width, height in LAPTOPS:
                with self.subTest(width=width, height=height):
                    b.viewport(width, height)
                    b.evaluate("window.scrollTo(0, 1500)")
                    self.press_button("Hold (block for review)")
                    self.assertEqual(b.active()["tag"], "textarea")
                    self.assertTrue(b.evaluate(IN_VIEW), "the focused reason field is on screen")
                    b.key("Tab")
                    self.assertEqual(b.active()["text"], "Hold candidate")
                    self.assertTrue(b.evaluate(IN_VIEW), "the submit button is on screen")
                    b.screenshot(f"08-form-open-{width}x{height}")
                    b.key("Escape")
                    self.assertEqual(b.active()["text"], "Hold (block for review)", "focus returns to the opener")
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")

    def test_db_a_failed_decision_keeps_focus_on_its_submit_button_and_records_nothing(self):
        b = self.browser
        self.sign_in("synthetic.automation.one")
        self.candidate("S12")
        self.press_button("Hold (block for review)")
        b.type("Synthetic hold: the connection drops.")
        b.hold("*/transitions")
        try:
            self.press_button("Hold candidate")
            b.release(b.held(), fail=True)
            b.wait_for("document.querySelector('form.action-form [role=alert]')", message="the failure")
        finally:
            b.hold(None)
        self.assertEqual(b.active()["text"], "Hold candidate", "focus stays on the control that failed")
        self.assertIn("could not be reached", b.text("form.action-form [role=alert]"))
        self.candidate("S12")
        self.assertIn("Hold (block for review)", b.buttons(), "nothing was recorded")

    def test_e_hold_by_keyboard_and_escape_restores_focus(self):
        b = self.browser
        self.sign_in("synthetic.automation.one")
        self.candidate("S12")
        self.press_button("Hold (block for review)")
        self.assertEqual(b.active()["tag"], "textarea")
        b.key("Escape")
        self.assertEqual(b.evaluate("document.querySelectorAll('form.action-form').length"), 0)
        self.assertEqual(b.active()["text"], "Hold (block for review)", "focus returns to the button that opened the form")
        b.key("Enter")
        b.type("Synthetic hold: nesting has not been checked.")
        b.key("Tab")
        self.assertEqual(b.active()["text"], "Hold candidate")
        b.key("Enter")
        b.wait_for("document.body.innerText.includes('Recorded: Revalidation required → Held by an operator')",
                   message="hold flash")
        # OGWA-UI-REVIEW-01: a held candidate waits in the Review queue as blocked, never among the decisions.
        self.nav("#/review?status=blocked", expect_title="Review queue")
        held = b.text("main table")
        self.assertIn("Held by an operator", held)
        self.assertIn("Hold to be lifted", held)
        self.nav("#/decisions", expect_title="Decisions")
        self.assertNotIn("Held by an operator", b.text("#view"))

    def test_f_exclusion_needs_an_explicit_confirmation(self):
        b = self.browser
        self.candidate("S02")
        self.press_button("Exclude")
        self.assertIn("Exclusion is terminal.", b.text())
        b.type("Synthetic: application is still in use.")
        self.press_button("Exclude candidate")
        self.assertIn("Confirm that you understand this is terminal.", b.text("[role=alert]"))
        self.assertEqual(b.evaluate("document.activeElement.type"), "checkbox")
        b.key(" ")
        self.press_button("Exclude candidate")
        b.wait_for("document.body.innerText.includes('Recorded: Discovered → Excluded')", message="exclude flash")
        self.assertIn("Excluded", b.text(".detail-main"))

    def test_g_a_refused_revalidation_is_explained(self):
        b = self.browser
        self.candidate("S01")
        self.press_button("Request revalidation")
        b.type("Synthetic: asking to revalidate during the hold period.")
        self.press_button("Submit revalidation request")
        b.wait_for("document.querySelector('form [role=alert]')", message="refusal")
        refusal = b.text("form [role=alert]")
        self.assertIn("The lifecycle refused this step. The refusal was recorded in the audit trail.", refusal)
        self.assertGreater(b.evaluate("document.querySelectorAll('form [role=alert] li').length"), 0, "problems are listed")
        self.assertIn("Post-unassignment hold period", b.text(".detail-main"))

    def test_gb_an_ad_deletion_is_approved_by_an_independent_person(self):
        """P10B: the post-quarantine hold offers no approval; a proposed deletion offers one to a
        person who approved no earlier stage and did not propose it (D139, D143)."""
        b = self.browser
        self.sign_in("synthetic.securityiam.one")
        self.candidate("S15")
        main = b.text(".detail-main")
        self.assertIn("Post-quarantine hold period", main)
        self.assertIn("OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example", main)
        self.assertNotIn("Approve for future action", b.text())
        self.candidate("S16")
        self.assertIn("Deletion proposed", b.text(".detail-main"))
        self.press_button("Approve for future action: AD deletion")
        self.assertEqual(b.active()["tag"], "textarea", "focus moves into the opened form")
        self.assert_accessible("deletion approval form")
        b.type("Synthetic deletion review: quarantined 30 days, fresh evidence is clean.")
        b.focus("form.action-form input[type=checkbox]")
        b.key(" ")
        self.press_button("Record approval")
        b.wait_for("document.body.innerText.includes('Approval recorded for AD deletion')", message="approval flash")
        self.assertIn("Nothing in Okta or Active Directory changed.", b.text())
        self.assertIn("Approved for a future AD deletion", b.text(".detail-main"))
        self.assert_no_dangerous_control("S16 approved")
        b.screenshot("08-deletion-approved")

    def test_gc_the_executor_plans_the_deletion_dry_run_and_nothing_executes(self):
        b = self.browser
        self.sign_in("synthetic.executor.one")
        self.candidate("S16")
        self.press_button("Run dry-run: AD deletion")
        self.assertIn("A dry run plans; it never executes.", b.text())
        self.press_button("Plan dry run")
        b.wait_for("document.body.innerText.includes('Dry run planned')", message="dry-run flash")
        self.assertIn("none was executed", b.text())
        self.press_button("Record the dry-run step")
        b.focus("form.action-form textarea")
        b.type("Synthetic: recording the planned deletion dry run.")
        self.press_button("Record dry-run step")
        b.wait_for("document.body.innerText.includes('Recorded: AD deletion dry run recorded')", message="record flash")
        self.assertIn("AD deletion dry run recorded", b.text(".detail-main"))
        self.nav("#/jobs", expect_title="Plans & simulations")
        self.assertNotRegex(b.text(), r"\tYes\t", "no job shows Executed: Yes")
        self.assert_no_dangerous_control("jobs after the deletion dry run")

    def test_h_sign_out_ends_the_session(self):
        b = self.browser
        self.sign_out()
        self.assertTrue(b.evaluate("document.getElementById('primary-nav').hidden"))
        b.evaluate("location.hash = '#/candidates'")
        b.wait_title("Sign in")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
