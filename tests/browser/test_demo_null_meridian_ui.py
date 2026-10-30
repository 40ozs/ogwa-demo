"""The integrated demo in a real headless browser: Demo Mode's indicator over the Null Meridian views.

Opt-in, like the other browser tests (UI_BROWSER_TESTS=1). The server is the demo runtime
started as an operator starts it (``tests.browser.harness.DemoServer``: the demo reset, then
``OGWA_RUNTIME_MODE=demo python -m app.api serve``) over its default dataset, Null Meridian.

The walk proves both feature sets survive together: the "DEMO ENVIRONMENT · Synthetic data"
indicator shows before and after sign-in and names the dataset, every Null Meridian view
renders accessibly with no dangerous control, and the indicator never covers the navigation,
at desktop or phone width.
"""

import json
import unittest

from tests.browser.harness import Browser, DemoServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

NM_VIEWS = {"#/inventory/groups": "Groups", "#/scenarios": "Portfolio scenarios", "#/findings": "Findings",
            "#/people": "People", "#/inventory/applications": "Applications", "#/review": "Review queue"}
NOT_RENDERED = ("Something went wrong", "Not found", "Not permitted", "Loading")

INDICATOR_STATE = """(() => {
  const d = document.getElementById('demo-indicator');
  const r = d.getBoundingClientRect();
  return {hidden: d.hidden, open: d.open, width: r.width, height: r.height,
          label: document.getElementById('demo-label').textContent,
          sublabel: document.getElementById('demo-sublabel').textContent,
          detail: document.getElementById('demo-detail').innerText};
})()"""

# Every navigation link is the element actually hit at its own centre, and the indicator's
# box does not intersect the navigation's box.
NAV_UNOBSTRUCTED = """(() => {
  const nav = document.getElementById('primary-nav');
  const d = document.getElementById('demo-indicator').getBoundingClientRect();
  const n = nav.getBoundingClientRect();
  const overlap = !(d.right <= n.left || n.right <= d.left || d.bottom <= n.top || n.bottom <= d.top);
  const covered = [];
  for (const a of nav.querySelectorAll('a')) {
    a.scrollIntoView({block: 'nearest', inline: 'nearest'});
    const r = a.getBoundingClientRect();
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (!hit || !(hit === a || a.contains(hit))) covered.push(a.getAttribute('href'));
  }
  window.scrollTo(0, 0);
  return {overlap, covered, links: nav.querySelectorAll('a').length};
})()"""


@unittest.skipIf(skip_reason(), skip_reason() or "")
class DemoNullMeridianUiTests(BrowserCase):
    server: DemoServer

    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.server = DemoServer().start_and_wait()
        try:
            cls.browser = Browser(browser_path())
        except Exception:
            cls.server.stop()
            raise

    def indicator(self) -> dict:
        return self.browser.evaluate(INDICATOR_STATE)

    def assert_indicator_visible(self, where: str) -> None:
        state = self.indicator()
        self.assertFalse(state["hidden"], where)
        self.assertGreater(state["width"] * state["height"], 0, where)
        sublabel = "Public synthetic demo · no live integrations" if self.public_demo() else "Synthetic data"
        self.assertEqual((state["label"], state["sublabel"]), ("DEMO ENVIRONMENT", sublabel), where)

    def test_a_the_indicator_shows_before_sign_in_and_names_the_dataset(self):
        b = self.browser
        b.goto(self.server.origin + "/#/")
        b.wait_for("['Sign in', 'Dashboard'].includes(document.getElementById('page-title').textContent)",
                   message="sign-in, or the public demo's dashboard")
        b.wait_for("!document.getElementById('demo-indicator').hidden", message="the demo indicator")
        self.assert_indicator_visible("sign-in")
        b.evaluate("document.querySelector('#demo-indicator summary').click()")
        b.wait_for("document.getElementById('demo-indicator').open", message="the expanded indicator")
        detail = self.indicator()["detail"]
        self.assertIn("deterministic synthetic data for Null Meridian. No production Okta tenant is connected.", detail)
        self.assertIn("The OGWA application is real; the organization and its identities are fictional.", detail)
        self.assertIn("Domain nullmeridian.info, snapshot 2026-10-01, seed null-meridian-v1.", detail)
        header = b.evaluate("fetch('/api/v1/health').then(r => r.headers.get('X-OGWA-Runtime-Mode'))")
        self.assertEqual(header, "demo")
        b.screenshot("demo-nm-01-sign-in-indicator")
        b.evaluate("document.querySelector('#demo-indicator summary').click()")
        self.assert_accessible("sign-in")

    def test_b_the_sign_in_shell_and_every_null_meridian_view(self):
        b = self.browser
        self.sign_in("synthetic.viewer.one")
        self.assert_indicator_visible("dashboard")
        self.assertEqual(b.text("#environment"), "SYNTHETIC store · LOCAL_SYNTHETIC")
        self.assertIn("This build cannot change Okta or Active Directory", b.text(".safety-strip"))
        nav = b.evaluate("[...document.querySelectorAll('#primary-nav a')].map(a => a.getAttribute('href'))")
        self.assertLessEqual(set(NM_VIEWS), set(nav), "every Null Meridian view is in the navigation")
        for hash_path in nav:
            with self.subTest(view=hash_path):
                # Navigate by clicking the real link, as a reviewer would (from another page, so the
                # click always changes the location).
                self.nav("#/audit" if hash_path == "#/" else "#/")
                b.evaluate("document.getElementById('view').dataset.old = '1'")
                b.evaluate(f"document.querySelector('#primary-nav a[href={json.dumps(hash_path)}]').click()")
                b.wait_for("!document.getElementById('view').dataset.old && "
                           "document.getElementById('page-title').textContent !== 'Loading'", message=hash_path)
                self.assertNotIn(b.title(), NOT_RENDERED, f"{hash_path}: {b.text('#view')[:300]}")
                if hash_path in NM_VIEWS:
                    self.assertEqual(b.title(), NM_VIEWS[hash_path])
                current = b.evaluate("document.querySelector('#primary-nav a[aria-current=page]')"
                                     "?.getAttribute('href')")
                self.assertEqual(current, hash_path)
                self.assert_accessible(hash_path)
                self.assert_no_dangerous_control(hash_path)
                self.assert_indicator_visible(hash_path)
        self.nav("#/directory", expect_title="Company Directory")
        self.assertIn("Null Meridian is fictional.", b.text())
        b.evaluate("document.querySelector('details.profile').open = true")
        self.assertIn("Active employees\n1800", b.text())
        b.screenshot("demo-nm-02-directory")
        self.nav("#/scenarios", expect_title="Portfolio scenarios")
        b.screenshot("demo-nm-03-scenarios")
        self.nav("#/findings?tab=governance", expect_title="Findings")
        b.screenshot("demo-nm-04-findings")

    def test_c_person_access_paths_and_directory_group_detail(self):
        b = self.browser
        self.nav("#/people?q=nm00001", expect_title="People")
        person = b.evaluate("document.querySelector('main table a').getAttribute('href')")
        self.nav(person)
        self.assertIn("Application access and how it is granted", b.text())
        self.assertIn("Ian Gupta", b.text())
        self.assert_accessible(person)
        self.assert_indicator_visible(person)
        b.screenshot("demo-nm-05-person-access-paths")
        self.nav("#/directory-groups?q=sg-okta-warehouse-readonly", expect_title="Groups")
        group = b.evaluate("document.querySelector('#tab-panel table a').getAttribute('href')")
        self.nav(group)
        self.assertIn("DEEP_NESTING", b.text())
        self.assert_accessible(group)
        b.screenshot("demo-nm-06-directory-group")

    def test_d_the_indicator_never_covers_the_navigation(self):
        b = self.browser
        for width, height, mobile in ((1280, 900, False), (375, 812, True)):
            with self.subTest(width=width):
                b.viewport(width, height, mobile=mobile)
                try:
                    for opened in (False, True):
                        b.evaluate(f"document.getElementById('demo-indicator').open = {json.dumps(opened)}")
                        self.nav("#/directory", expect_title="Company Directory")
                        if mobile:  # a phone shows the navigation once its menu is expanded
                            b.evaluate("document.body.classList.contains('nav-collapsed') && "
                                       "document.getElementById('nav-toggle').click()")
                        result = b.evaluate(NAV_UNOBSTRUCTED)
                        self.assertGreaterEqual(result["links"], len(NM_VIEWS))
                        self.assertFalse(result["overlap"], f"the indicator overlaps the navigation (open={opened})")
                        self.assertEqual(result["covered"], [], f"navigation links covered (open={opened})")
                        overflow = b.evaluate("document.documentElement.scrollWidth - "
                                              "document.documentElement.clientWidth")
                        self.assertLessEqual(overflow, 0, f"{width}px scrolls sideways (open={opened})")
                    if mobile:
                        b.screenshot("demo-nm-07-phone")
                finally:
                    b.evaluate("document.getElementById('demo-indicator').open = false")
                    b.send("Emulation.clearDeviceMetricsOverride")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
