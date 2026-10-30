"""The public hosted demo (the Cloudflare Worker) in a real headless browser.

Opt-in, like the other browser tests (UI_BROWSER_TESTS=1). The server is
``tests.browser.harness.HostedDemoServer``: the Worker's own application (``HostedDemo``) on
loopback over the dataset the Worker is configured with (Genesee Press), or, with ``UI_BROWSER_TARGET``,
the Worker itself (``wrangler dev`` or the deployed workers.dev URL), whatever dataset it serves. The two
walkthrough candidates are addressed by their walkthrough part ("data-quality": GP-C10 on Genesee Press;
"controlled-remediation", the public drill: GP-C11), resolved from the target's own API
(docs/deployment/hosted-demo-fixtures.md).

OGWA-DEMO-HOSTED-ANON-01: the public demo has no sign-in. Each test starts where a reviewer starts,
with no session (cookies cleared) at the public URL or a link into it, and fails if a sign-in form
ever appears:

- A. a fresh visitor lands on the dashboard, with the demo indicator, and reaches every view;
- B. a direct link to a reviewer page opens that page, not the dashboard;
- C. nothing offers a synthetic principal to sign in as;
- D. an approval or a hold a visitor attempts is refused as read-only, and nothing changes;
- E. the public drill's grant reaches neither the data-quality candidate nor any other, borrowed or forged;
- F. the visitor runs the public drill candidate's whole recovery drill without choosing an identity;
- G. a lost or expired session, a hard reload, and a new browser are usable at once, on unchanged data;
- I. a second tab's drill still runs, once, after another tab replaced the shared session;
- J. a session lost while the first page loads comes back without a reload; a refused cookie ends in an explanation;
- K. a drill pressed after the session lapsed runs, once, instead of vanishing;
- the static UI carries the local server's security headers (CSP, framing, referrer);
- no other write leaves the page: the refused attempts of D and E and the drills are the only ones (assert_clean).
"""

import json
import unittest

from tests.browser import test_remediation_drill_ui as drill_ui
from tests.browser.cdp import CdpError
from tests.browser.harness import Browser, HostedDemoServer, Tab, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

READ_ONLY = "This public demo is read-only"
# The walkthrough candidates are judged by the dataset's LIFECYCLE-004 v1.2.0 (GP- on Genesee Press, NM- on Null Meridian).
POLICY = r"\b[A-Z]+-LIFECYCLE-004 v1\.2\.0"
FIXTURES = ("Synthetic subject", "synthetic.viewer.one", "synthetic.securityiam.one", "synthetic.automation.one",
            "synthetic.executor.one", "synthetic.admin.one", "config/synthetic-idp.json")
# Runs before the page's own scripts: records whether a sign-in form was ever in the document.
SIGN_IN_WATCH = """window.__ogwaSignInSeen = false;
new MutationObserver(() => { if (document.querySelector('form.signin, input[name=subject]')) window.__ogwaSignInSeen = true; })
  .observe(document, { childList: true, subtree: true });"""
POST = """(async (requests) => {
  const session = await (await fetch('/api/v1/session', { credentials: 'same-origin' })).json();
  const out = [];
  for (const [path, body] of requests) {
    const r = await fetch('/api/v1' + path, { method: 'POST', credentials: 'same-origin', body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json', 'X-OGWA-CSRF': session.csrfToken } });
    const j = await r.json();
    out.push([r.status, j.error ? j.error.code : null, j.error ? j.error.message : null, 'drill' in j]);
  }
  return out; })"""


@unittest.skipIf(skip_reason(), skip_reason() or "")
class HostedDemoUiTests(BrowserCase):
    server: HostedDemoServer
    canonical: tuple | None = None
    deliberate_writes = ("/approvals", "/transitions", "/remediation-drills")  # refused (D, E) or a drill (records nothing)

    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.server = HostedDemoServer().start_and_wait()
        try:
            cls.browser = Browser(browser_path())
            cls.browser.send("Page.addScriptToEvaluateOnNewDocument", {"source": SIGN_IN_WATCH})
        except Exception:
            cls.server.stop()
            raise

    run_drill = drill_ui.RemediationDrillUiTests.run_drill
    step_labels = drill_ui.RemediationDrillUiTests.step_labels
    mode_banner = drill_ui.RemediationDrillUiTests.mode_banner

    # --- helpers --------------------------------------------------------------------------

    def visit(self, hash_path: str = "#/", browser: Browser | None = None) -> None:
        """A visitor with no session opens ``hash_path``: the console must open it, with no sign-in."""
        b = browser or self.browser
        b.send("Network.clearBrowserCookies")
        b.goto("about:blank")
        b.wait_for("location.href === 'about:blank'", message="a blank page")
        b.goto(f"{self.server.origin}/{hash_path}")
        b.wait_for("document.getElementById('page-title') && "
                   "!['Loading', 'Sign in'].includes(document.getElementById('page-title').textContent)"
                   " || window.__ogwaSignInSeen", message="the console")
        self.assert_never_signed_in(b)

    def assert_never_signed_in(self, b: Browser | None = None) -> None:
        b = b or self.browser
        self.assertIs(b.evaluate("window.__ogwaSignInSeen"), False, "a sign-in form appeared")
        self.assertNotEqual(b.title(), "Sign in")
        self.assertEqual(b.evaluate("document.cookie"), "", "the session cookie is HttpOnly")

    def scenario(self, part: str) -> str:
        """The candidate id of a walkthrough part, from the server's own GET /demo-scenarios."""
        return self.part(part)[1]

    def state(self, b: Browser | None = None) -> tuple:
        """What any visitor can see of the canonical data: the dashboard's audit count and head, and both walkthrough
        candidates' state, decisions, approvals, and jobs."""
        return tuple(json.dumps(x, sort_keys=True) for x in (b or self.browser).evaluate("""(async () => {
            const get = async (p) => (await fetch('/api/v1' + p, {credentials: 'same-origin'})).json();
            const parts = (await get('/demo-scenarios')).walkthrough.parts;
            const store = (await get('/dashboard')).store;
            const out = [[store.auditEvents, store.auditHead]];
            for (const id of parts.map(p => p.candidateId)) {
              out.push([(await get(`/candidates/${id}`)).candidate.state, (await get(`/candidates/${id}/decisions`)).items,
                        (await get(`/candidates/${id}/approvals`)).items, (await get(`/candidates/${id}/execution-jobs`)).items]);
            }
            return out; })()"""))

    def assert_canonical(self, b: Browser | None = None) -> None:
        if type(self).canonical is None:
            type(self).canonical = self.state()  # this run's first look, when test_a did not run first
        self.assertEqual(self.state(b), type(self).canonical, "the canonical synthetic data changed")

    def post(self, requests: list) -> list:
        return self.browser.evaluate(f"{POST}({json.dumps(requests)})")

    def drill_answers(self) -> dict:
        """This tab's drill requests so far: request id → HTTP status, in order."""
        b = self.browser
        return {e["params"]["requestId"]: e["params"]["response"]["status"] for e in b.cdp.events
                if e.get("sessionId") == b.session and e.get("method") == "Network.responseReceived"
                and e["params"]["response"]["url"].endswith("/remediation-drills")}

    def assert_one_timeout_drill(self, text: str) -> None:
        """The public drill candidate's timeout drill ran once, in full: one operation id, verified before its one retry."""
        self.assertEqual(self.step_labels(), drill_ui.TIMEOUT_RETRY)
        self.assertIn("Executed against the synthetic provider fixture only (2 submissions, 1 change applied", text)
        operations = self.browser.evaluate("[...document.querySelector('.drill-result').innerText"
                                           ".matchAll(/rop_[0-9a-f]{32}/g)].map(m => m[0])")
        self.assertEqual(len(set(operations)), 1, "one operation id")
        self.assertIn("No: a drill records nothing", text)

    # --- A. anonymous landing -------------------------------------------------------------------------------------

    def test_a_a_fresh_visitor_lands_on_the_dashboard_without_signing_in(self):
        b = self.browser
        self.visit("")
        b.wait_title("Dashboard")
        self.assert_canonical()
        b.wait_for("!document.getElementById('demo-indicator').hidden", message="the demo indicator")
        self.assertEqual((b.text("#demo-label"), b.text("#demo-sublabel")),
                         ("DEMO ENVIRONMENT", "Public synthetic demo · no live integrations"))
        self.assertIn("without signing in", b.evaluate("document.getElementById('demo-detail').textContent"))
        self.assertEqual(b.text("#account"), "Public demo visitor (read-only, no sign-in)")
        self.assertNotIn("Sign out", b.buttons())
        self.assertEqual(b.text("#environment"), "SYNTHETIC store · LOCAL_SYNTHETIC")
        b.screenshot("hosted-01-anonymous-dashboard")
        nav = b.evaluate("[...document.querySelectorAll('#primary-nav a')].map(a => a.getAttribute('href'))")
        self.assertGreaterEqual(len(nav), 10)
        for hash_path in nav:
            with self.subTest(view=hash_path):
                self.nav(hash_path)
                self.assertNotIn(b.title(), ("Something went wrong", "Not found", "Not permitted", "Loading", "Sign in"))
                self.assert_accessible(hash_path)
                self.assert_no_dangerous_control(hash_path)
        self.nav("#/audit", expect_title="Audit history")
        self.assertIn("The public demo does not show the audit trail.", b.text())
        self.nav("#/directory", expect_title="Company Directory")
        b.evaluate("document.querySelector('details.profile').open = true")
        active = b.evaluate("fetch('/api/v1/directory', {credentials: 'same-origin'}).then(r => r.json())"
                            ".then(j => j.counts.activeEmployees)")
        self.assertIn(f"Active employees\n{active}", b.text(), "the profile shows the API's own count")
        self.assert_never_signed_in()

    # --- B. direct links ------------------------------------------------------------------------------------------

    def test_b_a_direct_link_opens_its_page_after_the_anonymous_session_starts(self):
        b = self.browser
        self.visit("#/")
        links = {f"#/candidates/{self.scenario('data-quality')}": "Candidate: ",
                 f"#/candidates/{self.scenario('controlled-remediation')}": "Candidate: ", "#/scenarios": "Portfolio scenarios", "#/directory": "Company Directory",
                 "#/findings?tab=governance": "Findings", "#/inventory/groups?tab=okta": "Groups",
                 "#/review": "Review queue", "#/decisions": "Decisions"}
        for link, title in links.items():
            with self.subTest(link=link):
                self.visit(link)
                b.wait_title_prefix(title)
                self.assertEqual(b.evaluate("location.hash"), link, "the requested page, not the dashboard")
        b.screenshot("hosted-02-direct-link")

    # --- C. no identity selection ---------------------------------------------------------------------------------

    def test_c_nothing_offers_a_synthetic_principal_to_sign_in_as(self):
        b = self.browser
        self.visit("#/")
        pages = ["#/", "#/scenarios", f"#/candidates/{self.scenario('data-quality')}",
                 f"#/candidates/{self.scenario('controlled-remediation')}", "#/approvals", "#/audit"]
        for page in pages:
            with self.subTest(page=page):
                self.visit(page)
                b.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
                text = b.evaluate("document.body.innerText")
                for fixture in FIXTURES:
                    self.assertNotIn(fixture, text)
                for label in ("Sign in", "Sign out", "Switch user"):
                    self.assertNotIn(label, b.buttons())
                self.assertIsNone(b.evaluate("document.querySelector('input[name=subject], select[name=role], "
                                             "select[name=subject]')"))
        source = b.evaluate("fetch('/', {credentials: 'same-origin'}).then(r => r.text())")
        for fixture in FIXTURES:
            self.assertNotIn(fixture, source)

    # --- D. normal writes stay refused ----------------------------------------------------------------------------

    def test_d_an_approval_or_a_hold_is_refused_as_read_only_and_nothing_changes(self):
        b = self.browser
        self.visit("#/")
        c10 = self.scenario("data-quality")
        self.visit(f"#/candidates/{c10}")
        b.wait_title_prefix("Candidate: ")
        panel = b.text(".actions-panel")
        self.assertIn("This public demo is read-only.", panel)
        self.assertIn("Approvals, holds, and every other decision are refused", panel)
        for label in b.buttons():
            self.assertFalse(label.startswith(("Approve", "Hold", "Decline", "Exclude", "Reject")), label)
        b.screenshot("hosted-03-read-only-actions")
        before = self.state()
        answers = self.post([
            (f"/candidates/{c10}/approvals", {"stage": "OKTA_UNASSIGN", "decision": "APPROVE",
                                              "reason": "Hosted demo visitor: trying an approval.", "validHours": 24,
                                              "acknowledged": True}),
            (f"/candidates/{c10}/transitions", {"to": "BLOCKED", "reason": "Hosted demo visitor: trying a hold."}),
        ])
        for status, code, message, drilled in answers:
            self.assertEqual((status, code, drilled), (403, "DEMO_READ_ONLY", False))
            self.assertIn(READ_ONLY, message)
        self.nav(b.evaluate("location.hash"))
        self.assertIn("Needs review", b.text(".detail-main"))
        self.assertEqual(self.state(), before, "nothing was recorded")
        self.assert_canonical()

    # --- E. authorization isolation of the data-quality candidate -------------------------------------------------

    def test_e_the_public_drill_grant_cannot_be_borrowed_or_forged_for_another_candidate(self):
        b = self.browser
        self.visit("#/")
        c10, c11 = self.scenario("data-quality"), self.scenario("controlled-remediation")
        self.visit(f"#/candidates/{c10}")
        b.wait_title_prefix("Candidate: ")
        self.assertNotIn("Run drill", b.buttons())
        text = b.text()
        for fact in ("No action: sources disagree", "Probable, not proven", "Not proven", "Source unavailable"):
            self.assertIn(fact, text)
        self.assertRegex(text, POLICY, "the decision names the policy version in force")
        detail = b.evaluate(f"fetch('/api/v1/candidates/{c10}', {{credentials: 'same-origin'}}).then(r => r.json())")
        approval = b.evaluate(f"""fetch('/api/v1/candidates/{c11}/approvals', {{credentials: 'same-origin'}})
            .then(r => r.json()).then(j => j.items[0].id)""")
        before = self.state()
        requests = []
        for approval_id in (approval, "apr_" + "0" * 32):  # borrowed from the drill candidate, and forged
            for mode in ({"mode": "DRY_RUN"}, {"mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"}):
                requests.append((f"/candidates/{c10}/remediation-drills", {
                    "operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": detail["candidate"]["assignmentIds"][0]},
                    "approvalId": approval_id, "expectedEvidenceFingerprint": detail["evidenceFingerprint"], **mode}))
        for status, code, _, drilled in self.post(requests):
            self.assertEqual((status, code, drilled), (403, "PUBLIC_DRILL_SCOPE", False))
        self.assertEqual(self.state(), before, "nothing ran and nothing was recorded")
        self.assert_canonical()

    # --- F. the public drill --------------------------------------------------------------------------------------

    def test_f_the_visitor_runs_the_public_recovery_drill_without_choosing_an_identity(self):
        b = self.browser
        self.visit("#/")
        c11 = self.scenario("controlled-remediation")
        self.visit(f"#/candidates/{c11}")
        b.wait_title_prefix("Candidate: ")
        text = self.run_drill()
        self.assertIn("DRY RUN — NO STATE CHANGED", text)
        self.assertEqual(self.mode_banner(), ["DRY_RUN", "neutral", "DRY RUN — NO STATE CHANGED"])
        text = self.run_drill("TIMEOUT_NOT_APPLIED")
        self.assertEqual(self.step_labels(), drill_ui.TIMEOUT_RETRY)
        self.assertEqual(self.mode_banner(), ["SYNTHETIC_EXECUTION", "caution", "SYNTHETIC EXECUTION"])
        self.assertIn("Executed against the synthetic provider fixture only (2 submissions, 1 change applied", text)
        operations = b.evaluate("[...document.querySelector('.drill-result').innerText.matchAll(/rop_[0-9a-f]{32}/g)]"
                                ".map(m => m[0])")
        self.assertGreaterEqual(len(operations), 2)
        self.assertEqual(len(set(operations)), 1, "the retry carries the same operation id")
        for fact in ("POST-ACTION VERIFIED", "No: a drill records nothing"):
            self.assertIn(fact, text)
        self.assertRegex(text, POLICY + ", recorded version 2")
        self.assert_accessible("public drill")
        b.screenshot("hosted-04-public-drill")
        self.nav(f"#/candidates/{c11}", prefix="Candidate: ")
        self.assertIn("Approved", b.text(".detail-main"))
        self.assertIn("No dry run has been planned.", b.text())
        self.assert_canonical()
        self.assert_never_signed_in()

    # --- G. session reset -----------------------------------------------------------------------------------------

    def test_g_a_lost_or_expired_session_a_reload_and_a_new_browser_are_usable_at_once(self):
        b = self.browser
        self.visit("#/")
        self.visit(f"#/candidates/{self.scenario('controlled-remediation')}")
        b.wait_title_prefix("Candidate: ")
        # The session is lost mid-visit (cookies cleared), then expires (a cookie no server accepts).
        b.send("Network.clearBrowserCookies")
        self.nav("#/scenarios", expect_title="Portfolio scenarios")
        b.send("Network.setCookie", {"name": "__Host-ogwa-session", "value": "v1.expired.x", "url": self.server.origin + "/",
                                     "secure": True, "httpOnly": True, "sameSite": "Strict"})
        self.nav("#/directory", expect_title="Company Directory")
        self.assert_never_signed_in()
        b.send("Page.reload", {"ignoreCache": True})
        b.wait_title("Company Directory")
        self.assert_never_signed_in()
        self.assert_canonical()
        other = Browser(browser_path())
        try:
            other.send("Page.addScriptToEvaluateOnNewDocument", {"source": SIGN_IN_WATCH})
            self.visit("#/", browser=other)
            other.wait_title("Dashboard")
            self.assert_canonical(other)
            self.assertEqual(other.problems(), [])
        finally:
            other.close()

    # --- I. a second tab ------------------------------------------------------------------------------------------

    def test_i_a_second_tabs_drill_runs_once_after_another_tab_replaced_the_session(self):
        b = self.browser
        self.visit("#/")
        c11 = self.scenario("controlled-remediation")
        other = Tab(b)
        try:
            # The session ends (as after 15 idle minutes); another tab starts the next one, with a new CSRF token.
            self.visit(f"#/candidates/{c11}")
            b.wait_title_prefix("Candidate: ")
            b.send("Network.clearBrowserCookies")
            other.goto(f"{self.server.origin}/#/scenarios")
            other.wait_title("Portfolio scenarios")
            before = self.drill_answers()
            text = self.run_drill("TIMEOUT_NOT_APPLIED")
            self.assertEqual([s for r, s in self.drill_answers().items() if r not in before], [403, 200],
                             "refused before it ran (stale CSRF token), then sent once more")
            self.assert_one_timeout_drill(text)
            # Both tabs open at once, before either has a session: whichever cookie the browser keeps, the drill runs.
            b.send("Network.clearBrowserCookies")
            b.goto(f"{self.server.origin}/#/candidates/{c11}")
            other.goto(f"{self.server.origin}/#/scenarios")
            b.wait_title_prefix("Candidate: ")
            other.wait_title("Portfolio scenarios")
            before = self.drill_answers()
            text = self.run_drill("TIMEOUT_NOT_APPLIED")
            self.assertEqual([s for r, s in self.drill_answers().items() if r not in before][-1], 200)
            self.assertEqual([s for r, s in self.drill_answers().items() if r not in before].count(200), 1)
            self.assert_one_timeout_drill(text)
            self.assertEqual(other.problems(), [])
        finally:
            other.close()
        self.assert_never_signed_in()
        self.assert_canonical()

    # --- J. a session lost during the first load ------------------------------------------------------------------

    def test_j_a_session_lost_while_the_first_page_loads_comes_back_without_a_reload(self):
        b = self.browser
        for trial in range(3):
            with self.subTest(trial=trial):
                b.send("Network.clearBrowserCookies")
                b.goto("about:blank")
                b.wait_for("location.href === 'about:blank'", message="a blank page")
                b.hold("*/api/v1/candidates*")
                try:
                    b.goto(f"{self.server.origin}/#/candidates")
                    data = b.held()  # the session has started; the first page's data is on its way
                    b.send("Network.clearBrowserCookies")  # ... and the cookie is lost before it arrives
                    b.send("Fetch.continueRequest", {"requestId": data["requestId"], "headers": [
                        {"name": k, "value": v} for k, v in data["request"]["headers"].items() if k.lower() != "cookie"]})
                    b.release(b.held())  # the same page, asked for again with the new session
                finally:
                    b.hold(None)
                b.wait_title("Lifecycle candidates")
                self.assertEqual(b.evaluate("location.hash"), "#/candidates", "the requested page, not the dashboard")
                self.assertFalse(b.evaluate("document.getElementById('primary-nav').hidden"))
                self.assert_never_signed_in()
        # Lost again later in the same visit: still no reload needed.
        b.send("Network.clearBrowserCookies")
        self.nav("#/scenarios", expect_title="Portfolio scenarios")
        self.assert_canonical()

    def test_ja_a_browser_that_refuses_the_cookie_gets_an_explanation_not_a_loop(self):
        b = self.browser
        b.send("Network.clearBrowserCookies")
        b.goto("about:blank")
        b.wait_for("location.href === 'about:blank'", message="a blank page")
        b.hold("*/api/v1/session", stage="Response")
        sessions = 0
        try:
            b.goto(f"{self.server.origin}/#/scenarios")
            while True:  # each new session's cookie is gone before the page reads the answer: a refused cookie
                try:
                    answer = b.held(timeout=5)
                except CdpError:
                    break  # the page has stopped asking
                sessions += 1
                self.assertLessEqual(sessions, 2, "the page keeps asking for a session")
                b.send("Network.clearBrowserCookies")
                b.release(answer)
        finally:
            b.hold(None)
        b.wait_title("Service unavailable")
        self.assertIn("Allow cookies for this site, then reload the page.", b.text())
        self.assert_never_signed_in()
        b.send("Network.clearBrowserCookies")

    # --- K. a drill pressed after the session lapsed --------------------------------------------------------------

    def test_k_a_drill_pressed_after_the_session_lapsed_runs_once(self):
        b = self.browser
        self.visit("#/")
        c11 = self.scenario("controlled-remediation")
        self.visit(f"#/candidates/{c11}")
        b.wait_title_prefix("Candidate: ")
        for lapse in ("lost", "expired"):
            with self.subTest(lapse=lapse):
                if lapse == "lost":
                    b.send("Network.clearBrowserCookies")
                else:  # a cookie no server accepts any more
                    b.send("Network.setCookie", {"name": "__Host-ogwa-session", "value": "v1.expired.x",
                                                 "url": self.server.origin + "/", "secure": True, "httpOnly": True,
                                                 "sameSite": "Strict"})
                before = self.drill_answers()
                text = self.run_drill("TIMEOUT_NOT_APPLIED")
                self.assertEqual([s for r, s in self.drill_answers().items() if r not in before], [401, 200],
                                 "refused before it ran (no session), then sent once more")
                self.assert_one_timeout_drill(text)
                self.assertEqual(b.evaluate("location.hash"), f"#/candidates/{c11}")
        self.assert_never_signed_in()
        self.assert_canonical()

    # --- static files ---------------------------------------------------------------------------------------------

    def test_h_the_ui_files_carry_the_security_headers(self):
        headers = self.browser.evaluate("""fetch('/', {credentials: 'same-origin'}).then(r =>
            Object.fromEntries([...r.headers.entries()]))""")
        self.assertIn("require-trusted-types-for 'script'", headers.get("content-security-policy", ""))
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("referrer-policy"), "no-referrer")
        self.assertEqual(headers.get("x-ogwa-runtime-mode"), "demo")
        self.assertEqual(self.browser.csp_probe(self.server.origin + "/"),
                         {"innerHTML": "TypeError", "violations": ["img-src", "style-src-attr"]})

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()
