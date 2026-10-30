"""OGWA-UI-IA-01 in a real headless browser, over Null Meridian (opt-in, UI_BROWSER_TESTS=1).

The docked side navigation (grouped into Inventory, Review, and Operations since
OGWA-UI-REVIEW-01), the tabbed pages (Groups, Applications, Findings), shared table
sorting and paging, identity links (common names first, AD groups opening their canonical page,
Back returning to the investigation), "Deactivated" wording, and the dashboard. With
UI_BROWSER_TARGET it runs against an already-serving demo, such as the deployed Worker.
"""

import json
import re
import unittest

from tests.browser.harness import Browser, SyntheticServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

RAW_ID = re.compile(r"^(adg|ogrp|oapp|dgrp)_[0-9a-f]{32}$")
NAV = ("#/", "#/scenarios", "#/people", "#/inventory/groups", "#/inventory/applications", "#/mappings", "#/review",
       "#/findings", "#/decisions", "#/jobs", "#/collectors", "#/audit")
NAV_GROUPS = [["Inventory", ["People", "Groups", "Applications", "Identity mappings"]],
              ["Review", ["Review queue", "Findings", "Decisions"]],
              ["Operations", ["Plans & simulations", "Collection health", "Audit"]]]


@unittest.skipIf(skip_reason(), skip_reason() or "")
class InformationArchitectureTests(BrowserCase):
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

    # --- helpers ----------------------------------------------------------------------------

    def click(self, selector: str, title: str | None = None) -> None:
        """Click an element that navigates, and wait for the new render."""
        b = self.browser
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate(f"document.querySelector({json.dumps(selector)}).click()")
        b.wait_for("!document.getElementById('view').dataset.old && "
                   "document.getElementById('page-title').textContent !== 'Loading'", message=selector)
        if title:
            self.assertEqual(b.title(), title)

    def history(self, step: str) -> None:
        b = self.browser
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.evaluate(f"history.{step}()")
        b.wait_for("!document.getElementById('view').dataset.old && "
                   "document.getElementById('page-title').textContent !== 'Loading'", message=step)

    def selected_tab(self) -> str:
        return self.browser.evaluate("document.querySelector('[role=tab][aria-selected=true]').textContent")

    def rows(self, column: int, scope: str = "main") -> list[str]:
        return self.browser.evaluate(f"""[...document.querySelectorAll({json.dumps(scope + ' tbody tr')})]
            .map(r => r.children[{column}].innerText.split('\\n')[0].trim())""")

    # --- navigation ---------------------------------------------------------------------------

    def test_a_side_navigation_expands_collapses_and_marks_the_section(self):
        b = self.browser
        self.nav("#/")
        hrefs = b.evaluate("[...document.querySelectorAll('#primary-nav a')].map(a => a.getAttribute('href'))")
        self.assertEqual(tuple(hrefs), NAV, "one entry per destination; the superseded entries are gone")
        for gone in ("#/directory-groups", "#/applications", "#/groups", "#/dependencies", "#/directory", "#/okta",
                     "#/candidates", "#/approvals"):
            self.assertNotIn(gone, hrefs)
        # OGWA-UI-REVIEW-01: each group is a list named by its visible label.
        groups = b.evaluate("""[...document.querySelectorAll('#primary-nav ul[aria-labelledby]')].map(u =>
            [document.getElementById(u.getAttribute('aria-labelledby')).textContent, [...u.querySelectorAll('a')].map(a => a.textContent.trim())])""")
        self.assertEqual(groups, NAV_GROUPS)
        labels = b.evaluate("[...document.querySelectorAll('#primary-nav a')].map(a => [a.dataset.label, a.textContent.trim()])")
        self.assertTrue(all(label == text for label, text in labels), labels)
        toggle = "document.getElementById('nav-toggle')"
        self.assertEqual(b.evaluate(f"{toggle}.getAttribute('aria-expanded')"), "true")
        wide = b.evaluate("document.getElementById('primary-nav').getBoundingClientRect().width")
        b.evaluate(f"{toggle}.click()")
        self.assertEqual(b.evaluate(f"{toggle}.getAttribute('aria-expanded')"), "false")
        narrow = b.evaluate("document.getElementById('primary-nav').getBoundingClientRect().width")
        self.assertLess(narrow, wide / 2, "collapsed shows icons only")
        for selector in ("#primary-nav .nav-label", "#primary-nav .nav-group-label"):
            self.assertEqual(b.evaluate(f"getComputedStyle(document.querySelector({json.dumps(selector)})).width"), "1px",
                             "labels are hidden visually but stay the links' and groups' accessible names")
        self.assertEqual(b.evaluate("document.querySelector('#primary-nav a[href=\"#/inventory/groups\"]').textContent.trim()"), "Groups")
        b.screenshot("ia-01-collapsed")
        self.assert_accessible("collapsed navigation")
        # Navigating keeps the choice, and detail pages light up their section.
        self.click("#primary-nav a[href='#/inventory/applications']", "Applications")
        self.assertTrue(b.evaluate("document.body.classList.contains('nav-collapsed')"))
        self.click("#tab-panel table a", None)
        self.assertTrue(b.title().startswith("Application: "))
        current = "document.querySelector('#primary-nav a[aria-current=page]').getAttribute('href')"
        self.assertEqual(b.evaluate(current), "#/inventory/applications")
        self.nav("#/inventory/groups?tab=okta")
        self.click("#tab-panel table a")
        self.assertTrue(b.title().startswith("Okta group: "), b.title())
        self.assertEqual(b.evaluate(current), "#/inventory/groups")
        self.nav("#/inventory/groups")
        self.click("#tab-panel table a")
        self.assertTrue(b.title().startswith("AD group: "), b.title())
        self.assertEqual(b.evaluate(current), "#/inventory/groups")
        for page, section in (("#/candidates", "#/review"), ("#/directory", "#/people")):
            self.nav(page)
            self.assertEqual(b.evaluate(current), section, page)
        b.evaluate(f"{toggle}.click()")
        self.assertEqual(b.evaluate(f"{toggle}.getAttribute('aria-expanded')"), "true")

    def test_b_old_addresses_arrive_on_their_tab(self):
        b = self.browser
        for old, title, tab in (("#/directory-groups?health=ACTIONABLE", "Groups", "Directory groups"),
                                ("#/directory?tab=groups&era=modern", "Groups", "Directory groups"),
                                ("#/directory?tab=applications", "Applications", "Directory applications"),
                                ("#/applications?sort=label&order=desc", "Applications", "Okta applications"),
                                ("#/groups", "Groups", "Okta groups"), ("#/okta?tab=groups", "Groups", "Okta groups"),
                                ("#/okta", "Applications", "Okta applications"),
                                ("#/dependencies", "Findings", "Impact & Blockers"),
                                ("#/findings?severity=ACTIONABLE", "Findings", "Governance"),
                                ("#/approvals", "Review queue", None),
                                ("#/approvals?sort=decidedAt&order=asc", "Decisions", None)):
            with self.subTest(old=old):
                self.nav(old, expect_title=title)
                if tab:
                    self.assertEqual(self.selected_tab(), tab)
                kept = [kv for kv in (old.split("?")[1].split("&") if "?" in old else []) if not kv.startswith("tab=")]
                for kv in kept:
                    self.assertIn(kv, b.evaluate("location.hash"), "filters survive the move")
                self.history("back")
                self.assertNotEqual(b.evaluate("location.hash"), old,
                                    "the old address was replaced, so Back does not bounce through it")

    # --- tabs ---------------------------------------------------------------------------------

    def test_c_tabs_switch_without_a_reload_and_follow_history(self):
        b = self.browser
        for page, tabs in (("#/inventory/groups", ("Directory groups", "Okta groups")),
                           ("#/inventory/applications", ("Directory applications", "Okta applications")),
                           ("#/findings", ("Impact & Blockers", "Governance"))):
            with self.subTest(page=page):
                self.nav(page)
                b.evaluate("window.__sameDocument = 'yes'")
                self.assertEqual(b.evaluate("[...document.querySelectorAll('[role=tab]')].map(t => t.textContent)"), list(tabs))
                self.assertEqual(self.selected_tab(), tabs[0])
                # Keyboard: arrows move focus between tabs; Enter opens one, and focus stays on it.
                b.focus("[role=tab][aria-selected=true]")
                b.key("ArrowRight")
                self.assertEqual(b.evaluate("document.activeElement.textContent"), tabs[1])
                self.assertEqual(self.selected_tab(), tabs[0], "moving focus does not open the tab")
                b.evaluate("document.getElementById('view').dataset.old = '1'")
                b.key("Enter")
                b.wait_for("!document.getElementById('view').dataset.old", message="tab render")
                self.assertEqual(self.selected_tab(), tabs[1])
                self.assertEqual(b.evaluate("document.activeElement.getAttribute('role')"), "tab")
                self.assertEqual(b.evaluate("document.activeElement.textContent"), tabs[1])
                b.key("End")
                b.key("Home")
                self.assertEqual(b.evaluate("document.activeElement.textContent"), tabs[0])
                self.assertIn("tab=", b.evaluate("location.hash"))
                self.assert_accessible(f"{page} tab {tabs[1]}")
                self.history("back")
                self.assertEqual(self.selected_tab(), tabs[0])
                self.history("forward")
                self.assertEqual(self.selected_tab(), tabs[1])
                self.assertEqual(b.evaluate("window.__sameDocument"), "yes", "switching tabs never reloads the document")
        self.nav("#/findings?tab=governance", expect_title="Findings")
        self.assertEqual(self.selected_tab(), "Governance", "a tab can be linked to directly")

    # --- tables -------------------------------------------------------------------------------

    def test_d_server_sorting_and_paging(self):
        b = self.browser
        self.nav("#/people")
        self.assertEqual(b.evaluate("document.querySelector('th[aria-sort]').textContent.replace(/[▲▼↕]/g, '')"),
                         "Employee no.", "the default order is shown as a sort")
        self.click("th button.sort:first-child")  # Name
        self.assertIn("sort=displayName&order=asc", b.evaluate("location.hash"))
        self.assertEqual(b.evaluate("document.activeElement.className"), "sort", "focus stays on the header")
        page1 = self.rows(0)
        self.assertEqual(page1, sorted(page1, key=str.casefold))
        self.assertEqual(b.text(".pager-status"), "Rows 1–50 of 2809")
        self.click("nav.pager a:last-child")  # Next page
        self.assertEqual(b.text(".pager-status"), "Rows 51–100 of 2809")
        page2 = self.rows(0)
        self.assertLessEqual(page1[-1].casefold(), page2[0].casefold(), "sorted across pages, not within one")
        self.click("nav.pager a:first-child")  # Previous page
        self.assertEqual(self.rows(0), page1)
        self.click("th[aria-sort] button.sort")
        self.assertEqual(b.evaluate("document.querySelector('th[aria-sort]').getAttribute('aria-sort')"), "descending")
        names = self.rows(0)
        self.assertEqual(names, sorted(names, key=str.casefold, reverse=True))
        # The final, partial page of a listing, and an empty one.
        self.nav("#/inventory/groups?tab=directory&cursor=bzo0MDA")
        self.assertEqual(b.text(".pager-status"), "Rows 401–401 of 401")
        self.assertEqual(b.evaluate("[...document.querySelectorAll('nav.pager a')].map(a => a.textContent)"), ["Previous page"])
        self.nav("#/people?q=nobody-is-called-this")
        self.assertIn("Nobody matches these filters.", b.text())
        self.nav("#/inventory/groups?tab=directory&cursor=bzo1MDAw")
        self.assertIn("This page is past the end of the list.", b.text())

    def test_e_local_sorting_and_paging(self):
        b = self.browser
        self.nav("#/inventory/applications?tab=directory")
        self.assertEqual(b.text("#tab-panel .pager-status"), "Rows 1–25 of 81")
        sort = "[...document.querySelectorAll('#tab-panel th button.sort')].find(x => x.textContent.startsWith('People with access'))"
        b.evaluate(f"{sort}.click()")
        b.evaluate(f"{sort}.click()")
        self.assertEqual(b.evaluate(f"{sort}.closest('th').getAttribute('aria-sort')"), "descending")
        counts = [int(x) for x in self.rows(7, "#tab-panel")]
        self.assertEqual(counts, sorted(counts, reverse=True))
        nxt = "[...document.querySelectorAll('#tab-panel nav.pager button')].find(x => x.textContent === 'Next page')"
        for _ in range(3):
            b.evaluate(f"{nxt}.click()")
        self.assertEqual(b.text("#tab-panel .pager-status"), "Rows 76–81 of 81")
        self.assertEqual(b.evaluate(f"{nxt}.getAttribute('aria-disabled')"), "true")
        last = [int(x) for x in self.rows(7, "#tab-panel")]
        self.assertLessEqual(last[0], counts[-1], "local sorting also holds across pages")

    # --- identities ---------------------------------------------------------------------------

    def test_f_mappings_and_findings_show_names_and_open_the_ad_group(self):
        b = self.browser
        self.nav("#/mappings?sort=adGroup&order=asc", expect_title="Identity mappings")
        cells = b.evaluate("[...document.querySelectorAll('main tbody tr')].flatMap(r => [...r.children].map(c => c.innerText.trim()))")
        self.assertFalse([c for c in cells if RAW_ID.match(c)], "no raw id is a primary label")
        link = b.evaluate("document.querySelector('main tbody td:nth-child(4) a')")
        self.assertIsNotNone(link)
        name = b.evaluate("document.querySelector('main tbody td:nth-child(4) a').textContent")
        href = b.evaluate("document.querySelector('main tbody td:nth-child(4) a').getAttribute('href')")
        self.assertRegex(href, r"^#/directory-groups/dgrp_[0-9a-f]{32}$")
        self.assertRegex(b.evaluate("document.querySelector('main tbody td:nth-child(4) a').title"), r"adg_[0-9a-f]{32}",
                         "the raw id stays available")
        self.click("main tbody td:nth-child(4) a", f"AD group: {name}")
        self.assertRegex(b.text(), r"objectSid\nS-1-5-21-")
        self.assert_accessible("AD group page")
        self.history("back")
        self.assertEqual(b.title(), "Identity mappings")
        self.assertIn("sort=adGroup", b.evaluate("location.hash"), "Back returns to the same investigation")
        self.nav("#/findings?tab=dependency&sort=findings&order=desc")
        subject = b.evaluate("document.querySelector('main tbody th').innerText")
        self.assertFalse(RAW_ID.match(subject.strip()), subject)
        self.click("main tbody th a")
        self.assertTrue(b.title().startswith("AD group: "), b.title())

    def test_g_access_paths_link_each_group_to_its_page(self):
        b = self.browser
        self.nav("#/people?department=finance&status=ACTIVE")
        self.click("main tbody th a")
        person = b.title()
        chain = "document.querySelector('ol.chain')"
        steps = b.evaluate(f"[...{chain}.querySelectorAll('li')].map(li => li.innerText.trim())")
        self.assertGreater(len(steps), 1)
        self.assertFalse(b.evaluate(f"[...{chain}.querySelectorAll('a')].some(a => a.textContent.includes('›'))"),
                         "separators are never part of a link")
        self.assertTrue(b.evaluate(f"{chain}.getAttribute('aria-label').startsWith('Route to ')"))
        target = b.evaluate(f"{chain}.querySelectorAll('a')[1].getAttribute('href')")
        name = b.evaluate(f"{chain}.querySelectorAll('a')[1].textContent")
        self.click("ol.chain li:nth-child(2) a")
        self.assertIn(name, b.title())
        self.assertIn(target.split("/")[-1], b.text(), "the page shows the id it was opened by")
        self.history("back")
        self.assertEqual(b.title(), person)

    def test_h_shared_names_are_told_apart_and_sids_find_groups(self):
        b = self.browser
        self.nav("#/inventory/groups?tab=directory&q=finance-rw&source=AD")
        qualifiers = b.evaluate("[...document.querySelectorAll('#tab-panel tbody .ref-qualifier')].map(q => q.textContent)")
        self.assertEqual(len(qualifiers), 2)
        self.assertNotEqual(qualifiers[0], qualifiers[1])
        sid = b.evaluate("""fetch('/api/v1/directory-groups?q=all-staff', {credentials: 'same-origin'}).then(r => r.json())
            .then(j => fetch('/api/v1/directory-groups/' + j.items[0].id, {credentials: 'same-origin'})).then(r => r.json())
            .then(j => j.group.adSid)""")
        self.nav(f"#/inventory/groups?tab=directory&q={sid}")
        self.assertEqual(self.rows(0, "#tab-panel"), ["All-Staff"])

    # --- wording, dashboard, widths -------------------------------------------------------------

    def test_i_employees_are_active_or_deactivated(self):
        b = self.browser
        self.nav("#/people?status=TERMINATED")
        headers = b.evaluate("[...document.querySelectorAll('main thead th')].map(t => t.textContent.replace(/[▲▼↕]/g, ''))")
        self.assertEqual(headers[-2:], ["Status", "Deactivation date"])
        self.assertEqual(set(self.rows(6)), {"Deactivated"})
        self.assertTrue(all(re.match(r"^\d{4}-\d{2}-\d{2}$", d) for d in self.rows(7)))
        self.nav("#/people?status=ACTIVE")
        self.assertEqual((set(self.rows(6)), set(self.rows(7))), ({"Active"}, {"—"}))
        no_old_words = """(() => { const m = document.querySelector('main').cloneNode(true);
            m.querySelectorAll('.mono, details:not([open])').forEach(x => x.remove());
            return (m.textContent.match(/\\b(former|terminated)\\b/gi) || []); })()"""
        for page in ("#/people?status=TERMINATED", "#/", "#/findings?tab=governance&severity=ACTIONABLE"):
            with self.subTest(page=page):
                self.nav(page)
                self.assertEqual(b.evaluate(no_old_words), [], page)
        self.nav("#/people?status=TERMINATED")
        self.click("main tbody th a")
        self.assertEqual(b.evaluate(no_old_words), [])
        self.assertRegex(b.text(), r"Status\nDeactivated\nDeactivation date\n\d{4}-\d{2}-\d{2}")

    def test_j_dashboard_figures_charts_and_links(self):
        b = self.browser
        self.nav("#/", expect_title="Dashboard")
        # OGWA-UI-REVIEW-01: what needs attention comes first, key figures after it.
        sections = b.evaluate("[...document.querySelectorAll('#view section h2')].map(h => h.textContent)")
        self.assertEqual(sections[:4], ["Needs attention", "Review queue", "Find", "Key figures"])
        figures = b.evaluate("[...document.querySelectorAll('.kpi')].map(k => k.querySelector('.kpi-label').textContent)")
        self.assertEqual(figures, ["Active employees", "Deactivated employees", "Departments", "AD groups", "Okta groups",
                                   "Okta applications", "Open findings", "Actionable or blocking"])
        self.assertIn("1,800\nActive employees", b.text())
        self.assertTrue(b.evaluate("document.querySelector('svg.columns[role=img]').getAttribute('aria-label').includes('Deactivations per year')"))
        self.assertEqual(b.evaluate("document.querySelectorAll('.chart-table table').length"), 1, "the chart has a table")
        bars = b.evaluate("[...document.querySelectorAll('.bars')[0].querySelectorAll('.bar-row')].map(r => r.innerText.replace(/\\n/g, ' '))")
        self.assertEqual([x.rsplit(" ", 1)[0] for x in bars], ["Actionable", "Worth a look", "Context"])
        self.assert_accessible("dashboard")
        b.screenshot("ia-02-dashboard")
        self.click(".bars .bar-row", "Findings")
        self.assertEqual(self.selected_tab(), "Governance")
        self.assertEqual(b.text("p.filters strong"), "Actionable")
        self.nav("#/")
        self.click(".kpi[href*='status=TERMINATED']", "People")
        self.assertEqual(b.evaluate("document.querySelector('th[aria-sort]').textContent.replace(/[▲▼↕]/g, '')"), "Deactivation date")

    def test_k_narrow_widths_adapt(self):
        b = self.browser
        for width, height, mobile in ((768, 1024, True), (375, 812, True)):
            with self.subTest(width=width):
                b.viewport(width, height, mobile=mobile)
                try:
                    self.nav("#/")
                    self.assertTrue(b.evaluate("document.body.classList.contains('nav-collapsed')"))
                    self.assertEqual(b.evaluate("getComputedStyle(document.getElementById('nav-list')).display"), "none")
                    self.assertEqual(b.text("#nav-toggle"), "Expand menu")
                    b.evaluate("document.getElementById('nav-toggle').click()")
                    self.assertNotEqual(b.evaluate("getComputedStyle(document.getElementById('nav-list')).display"), "none")
                    self.click("#primary-nav a[href='#/findings']", "Findings")
                    self.assertTrue(b.evaluate("document.body.classList.contains('nav-collapsed')"), "the menu closes after use")
                    for page in ("#/", "#/inventory/groups", "#/inventory/groups?tab=okta", "#/findings?tab=governance",
                                 "#/findings?tab=dependency", "#/mappings", "#/review", "#/review?status=all", "#/decisions",
                                 "#/jobs"):
                        self.nav(page)
                        overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                        self.assertLessEqual(overflow, 0, f"{page} scrolls sideways at {width}px")
                    self.nav("#/people?department=finance&status=ACTIVE")
                    self.click("main tbody th a")
                    overflow = b.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    self.assertLessEqual(overflow, 0, f"access paths scroll sideways at {width}px")
                    b.screenshot(f"ia-03-{width}")
                finally:
                    b.send("Emulation.clearDeviceMetricsOverride")
                    b.viewport(1280, 900)
                    self.nav("#/")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
