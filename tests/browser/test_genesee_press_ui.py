"""The default demo, Genesee Press (SYNTH-OGWA-01), in a real headless browser.

Opt-in (UI_BROWSER_TESTS=1). The server is the demo runtime over the Genesee Press dataset, read
from the vendored synthetic-enterprise projection. The walk checks what a reviewer sees first:
the indicator names Genesee Press and its reserved domain, the dashboard's walkthrough entry names
GP-C10 and GP-C11, the walkthrough and both candidates render accessibly, and no page shows a
former Null Meridian value.
"""

import re
import unittest

from tests.browser.harness import Browser, DemoServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

OLD = re.compile(r"Null Meridian|nullmeridian|NMCORP|SYNTHNM|\bNM-C\d\d\b|NM-LIFECYCLE|\bsg-okta-")


@unittest.skipIf(skip_reason(), skip_reason() or "")
class GeneseePressUiTests(BrowserCase):
    server: DemoServer

    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.server = DemoServer("genesee-press").start_and_wait()
        try:
            cls.browser = Browser(browser_path())
        except Exception:
            cls.server.stop()
            raise

    def page_text(self) -> str:
        return self.browser.evaluate("document.body.innerText")

    def test_a_the_indicator_names_genesee_press(self):
        b = self.browser
        b.goto(self.server.origin + "/#/")
        b.wait_for("!document.getElementById('demo-indicator').hidden", message="the demo indicator")
        b.evaluate("document.querySelector('#demo-indicator summary').click()")
        b.wait_for("document.getElementById('demo-indicator').open", message="the expanded indicator")
        detail = b.evaluate("document.getElementById('demo-detail').innerText")
        self.assertIn("deterministic synthetic data for Genesee Press.", detail)
        self.assertIn("Domain geneseepress.example, snapshot 2026-10-01, seed genesee-press-v1.", detail)
        b.screenshot("demo-gp-01-indicator")

    def test_b_the_dashboard_walkthrough_and_candidates(self):
        b = self.browser
        self.sign_in("synthetic.viewer.one")
        b.wait_for("document.querySelector('.walkthrough-entry')", message="the walkthrough entry")
        entry = b.text(".walkthrough-entry")
        self.assertIn("evidence quality on GP-C10, then a verified synthetic remediation on GP-C11", entry)
        self.assertIsNone(OLD.search(self.page_text()))
        b.screenshot("demo-gp-02-dashboard")
        self.nav("#/scenarios")
        text = self.page_text()
        for expected in ("GP-C10", "GP-C11", "Genesee Press", "GP-LIFECYCLE-004 v1.2.0"):
            self.assertIn(expected, text)
        self.assertIsNone(OLD.search(text))
        self.assert_accessible("#/scenarios")
        b.screenshot("demo-gp-03-scenarios")
        self.nav("#/directory")
        text = self.page_text()
        self.assertIn("Genesee Press", text)
        self.assertIsNone(OLD.search(text))
        self.assert_accessible("#/directory")
        b.screenshot("demo-gp-04-directory")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
