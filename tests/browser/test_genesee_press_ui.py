"""The default demo, Genesee Press (SYNTH-OGWA-01), in a real headless browser.

Opt-in (UI_BROWSER_TESTS=1). The server is the demo runtime over the Genesee Press dataset, read
from the vendored synthetic-enterprise projection; with ``UI_BROWSER_TARGET`` it is the hosted
demo (the Worker), and the module skips unless that serves Genesee Press. The walk checks what a
reviewer sees first: the indicator names Genesee Press and its reserved domain, the dashboard's
walkthrough entry names GP-C10 and GP-C11, the walkthrough and both candidates render accessibly,
and no page shows a former Null Meridian value.

OGWA-REVIEW-QUEUE-API-01 folded the OGWA-UI-REVIEW-02 hosted UI probe in here, so the hosted gate
alone covers it: every page at 1280, 768 and 320 px; the Review queue's statuses read from the
API's lifecycle states (and never "Ready"); one candidate page per lifecycle state; holds,
Impact & Blockers, governance rules, Decisions, Plans; the dashboard; and Find. Counts are
derived from the API at run time, never from a fixture; the fixture expectations this module
does rely on are listed in docs/deployment/hosted-demo-fixtures.md. On the hosted demo, nothing
here writes (``assert_clean``).

OGWA-REVIEW-QUEUE-API-01 (tests j-m): the queue served by GET /review-queue (server paging,
filters, counts, order), "Evidence now" beside every row's lifecycle state, approval usability on
Decisions, and an AD group page that opens its lifecycle candidate directly.

OGWA-APPROVAL-ATTENTION-01 (test n): the dashboard's "approvals expiring soon" item appears exactly when
the server counts one (otherwise the zero state), and the Decisions filters carry the server's counts,
whatever the dataset's clock; nothing is worded ready or executable.
"""

import json
import re
import unittest

from tests.browser import test_demo_null_meridian_ui as nm_ui
from tests.browser.harness import Browser, DemoServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

OLD = re.compile(r"Null Meridian|nullmeridian|NMCORP|SYNTHNM|\bNM-C\d\d\b|NM-LIFECYCLE|\bsg-okta-")
# The review status of each lifecycle state (OGWA-UI-REVIEW-02 brief §4), independent of js/review.js;
# labels are matched by prefix ("In progress (dry run only)"). An unknown state reads Blocked.
STATUS = {
    "Needs review": {"NEEDS_REVIEW", "REVALIDATION_REQUIRED", "DELETION_REVALIDATION_REQUIRED", "DELETION_PROPOSED"},
    "Blocked": {"BLOCKED", "MAPPING_AMBIGUOUS", "DEPENDENCY_BLOCKED", "STALE_EVIDENCE", "EVIDENCE_INCOMPLETE",
                "RETIREMENT_DRY_RUN"},
    "Waiting": {"DISCOVERED", "CANDIDATE", "HOLD", "QUARANTINE_HOLD"},
    "In progress": {"APPROVED", "OKTA_UNASSIGN_DRY_RUN", "QUARANTINE_APPROVED", "QUARANTINE_DRY_RUN", "DELETION_APPROVED",
                    "DELETION_DRY_RUN"},
    "Retired": {"RETIRED"},
    "Closed": {"EXCLUDED", "REJECTED", "PROTECTED"},
}
OPEN = ("Needs review", "Blocked", "Waiting", "In progress")
PAGES = ("#/", "#/scenarios", "#/people", "#/inventory/groups", "#/inventory/groups?tab=directory",
         "#/inventory/applications", "#/inventory/applications?tab=directory", "#/mappings", "#/review",
         "#/review?status=all", "#/findings?tab=dependency", "#/findings?tab=governance", "#/decisions", "#/jobs",
         "#/collectors", "#/audit")
NOT_RENDERED = ("Something went wrong", "Not found", "Not permitted", "Loading")
REVIEW_FIRST = ["Lifecycle", "What blocks this candidate", "Next step", "Evidence readiness"]
OVERFLOW = "document.documentElement.scrollWidth - document.documentElement.clientWidth"
# The cells of the column headed `header`, in the tables whose caption starts with `caption`.
COLUMN = """((caption, header) => [...document.querySelectorAll('main table')]
  .filter(t => (t.caption ? t.caption.textContent : '').startsWith(caption))
  .flatMap(t => { const i = [...t.querySelectorAll('thead th')].findIndex(th => th.textContent.replace(/[▲▼↕]/g, '').trim() === header);
    return i < 0 ? [] : [...t.querySelectorAll('tbody tr')].map(r => r.children[i].innerText.trim()); }))"""
CODE = re.compile(r"^[A-Z][A-Z0-9_]+$")


def status_of(state: str) -> str:
    return next((k for k, v in STATUS.items() if state in v), "Blocked")


def label_key(label: str) -> str:
    return next((k for k in (*STATUS, "Open", "All") if label.startswith(k)), label)


@unittest.skipIf(skip_reason(), skip_reason() or "")
class GeneseePressUiTests(BrowserCase):
    server: DemoServer
    signed_in = False

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

    # --- helpers ----------------------------------------------------------------------------

    def page_text(self) -> str:
        return self.browser.evaluate("document.body.innerText")

    def viewer(self) -> None:
        if not type(self).signed_in:
            self.sign_in("synthetic.viewer.one")
            type(self).signed_in = True

    def api(self, path: str):
        return self.browser.evaluate(f"fetch('/api/v1{path}', {{credentials: 'same-origin'}}).then(r => r.json())")

    def candidates(self) -> list[dict]:
        items, cursor = [], None
        while True:
            page = self.api("/candidates?limit=200" + (f"&cursor={cursor}" if cursor else ""))
            items += page["items"]
            cursor = page["page"].get("nextCursor")
            if not cursor:
                return items

    def column(self, caption: str, header: str) -> list[str]:
        return self.browser.evaluate(f"{COLUMN}({json.dumps(caption)}, {json.dumps(header)})")

    def caption_total(self, label: str) -> int:
        caption = self.browser.evaluate("document.querySelector('main table caption').textContent")
        found = re.match(rf"{re.escape(label)}: (\d+) candidates?$", caption)
        self.assertIsNotNone(found, caption)
        return int(found.group(1))

    def press_and_render(self, selector: str) -> None:
        b = self.browser
        b.focus(selector)
        b.evaluate("document.getElementById('view').dataset.old = '1'")
        b.key("Enter")
        b.wait_for("!document.getElementById('view').dataset.old && "
                   "document.getElementById('page-title').textContent !== 'Loading'", message=selector)

    # --- what a reviewer sees first -----------------------------------------------------------

    def test_a_the_indicator_names_genesee_press(self):
        b = self.browser
        b.goto(self.server.origin + "/#/")
        b.wait_for("!document.getElementById('demo-indicator').hidden", message="the demo indicator")
        b.evaluate("document.querySelector('#demo-indicator summary').click()")
        b.wait_for("document.getElementById('demo-indicator').open", message="the expanded indicator")
        detail = b.evaluate("document.getElementById('demo-detail').innerText")
        self.assertIn("deterministic synthetic data for Genesee Press.", detail)
        self.assertIn("Domain geneseepress.example, snapshot 2026-10-01, seed genesee-press-v1.", detail)
        b.evaluate("document.querySelector('#demo-indicator summary').click()")
        b.screenshot("demo-gp-01-indicator")

    def test_b_the_dashboard_walkthrough_and_candidates(self):
        b = self.browser
        self.sign_in("synthetic.viewer.one")
        type(self).signed_in = True
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

    # --- every page ---------------------------------------------------------------------------

    def test_c_every_page_renders_at_1280_768_and_320_px(self):
        b = self.browser
        self.viewer()
        try:
            for width in (1280, 768, 320):
                b.viewport(width, 900, mobile=width < 768)
                for page in PAGES:
                    with self.subTest(width=width, page=page):
                        self.nav(page)
                        self.assertNotIn(b.title(), NOT_RENDERED, page)
                        self.assertLessEqual(b.evaluate(OVERFLOW), 0, f"{page} scrolls sideways at {width}px")
                        if width == 1280:
                            self.assert_accessible(page)
                            self.assert_no_dangerous_control(page)
        finally:
            b.send("Emulation.clearDeviceMetricsOverride")

    # --- the Review queue ---------------------------------------------------------------------

    def test_d_the_review_queue_reads_the_apis_lifecycle_states(self):
        b = self.browser
        self.viewer()
        states = {c["id"]: c["state"] for c in self.candidates()}
        expected = {k: sum(status_of(s) == k for s in states.values()) for k in STATUS}
        self.nav("#/review?status=all", expect_title="Review queue")
        self.assertEqual(self.caption_total("All"), len(states))
        filters = [re.fullmatch(r"(.+) \((\d+)\)", f).groups()
                   for f in b.evaluate("[...document.querySelectorAll('.status-filters a')].map(a => a.textContent)")]
        self.assertEqual({label_key(label): int(n) for label, n in filters},
                         {"Open": sum(expected[k] for k in OPEN), **expected, "All": len(states)},
                         "the filters count the API's candidates by review status")
        cells = self.column("All:", "Review status")
        self.assertTrue(cells and all("Lifecycle:" in c for c in cells), "every row keeps its lifecycle state")
        if len(cells) == len(states):  # the whole queue on one page
            shown = [label_key(c.split("\n")[0]) for c in cells]
            self.assertEqual({k: shown.count(k) for k in STATUS}, expected)
        self.assertNotRegex(b.text("main"), r"\bReady\b")
        self.assert_accessible("review queue")
        for key, label in (("needs-review", "Needs review"), ("blocked", "Blocked"), ("waiting", "Waiting")):
            with self.subTest(filter=label):
                self.press_and_render(f'.status-filters a[data-focus-key="status:{key}"]')
                self.assertEqual(b.evaluate("document.activeElement.dataset.focusKey"), f"status:{key}",
                                 "focus stays on the filter")
                self.assertEqual(self.caption_total(label), expected[label])
                self.assertTrue(all(c.startswith(label) for c in self.column(f"{label}:", "Review status")))
        # A hold is waiting work: in the Waiting queue, named on its page, never among the decisions.
        holds = [cid for cid, s in states.items() if s in ("HOLD", "QUARANTINE_HOLD")]
        self.nav("#/review?status=waiting")
        links = b.evaluate("[...document.querySelectorAll('main table a')].map(a => a.getAttribute('href'))")
        for cid in holds:
            self.assertIn(f"#/candidates/{cid}", links)
            self.nav(f"#/candidates/{cid}", prefix="Candidate: ")
            self.assertIn("hold", b.text("main").lower())
        self.nav("#/decisions", expect_title="Decisions")
        self.assertFalse([d for d in self.column("Approvals and rejections", "Decision") if "hold" in d.lower()])

    # --- candidate pages ----------------------------------------------------------------------

    def test_e_one_candidate_per_lifecycle_state_reads_review_status_first(self):
        b = self.browser
        self.viewer()
        first = {}
        for c in self.candidates():
            first.setdefault(c["state"], c["id"])
        for state, cid in sorted(first.items()):
            with self.subTest(state=state):
                self.nav(f"#/candidates/{cid}", prefix="Candidate: ")
                headline = b.text(".review-headline")
                self.assertTrue(headline.startswith(status_of(state)), headline)
                self.assertNotRegex(headline, r"\bReady\b")
                self.assertTrue(b.evaluate("""(() => { const p = document.querySelector('.review-headline'),
                    h = document.querySelector('main h2'); return !!(p.compareDocumentPosition(h) & Node.DOCUMENT_POSITION_FOLLOWING); })()"""),
                    "the review status comes before every section")
                heads = b.evaluate("[...document.querySelectorAll('main h2')].map(h => h.textContent.trim())")
                self.assertEqual([h for h in heads if h in REVIEW_FIRST], REVIEW_FIRST)
                for forensic in ("Decision summary", "Evidence timestamps", "Decision history"):
                    self.assertIn(forensic, heads)
                steps = b.evaluate("""[...document.querySelectorAll('ol.stepper li')].map(li => [li.querySelector('.step-label')
                    .textContent, li.querySelector('.step-status').textContent, li.dataset.status])""")
                self.assertEqual(len(steps), 10)
                self.assertTrue(all(label and words for label, words, _ in steps), "every stage in words")
                self.assertTrue(all(words == "Not yet eligible" for _, words, s in steps if s == "future"))
                self.assert_accessible(f"candidate {state}")

    def test_f_the_data_quality_candidate_is_explained_not_acted_on(self):
        """The Genesee Press counterpart of test_null_meridian_views' NM-C10 checks (the walkthrough's part 1)."""
        b = self.browser
        self.viewer()
        key, cid = self.part("data-quality")
        self.nav(f"#/candidates/{cid}", prefix="Candidate: ")
        text = b.text()
        for expected in ("Is this safe to act on?", "No action: sources disagree", "1. Proposed governance issue",
                         "2. Sources that support it", "3. Sources that disagree, conflict, or are unavailable",
                         "4. Identity mapping", "5. What OGWA can safely decide now", "6. Evidence needed to proceed",
                         "Probable, not proven", "Not collected", "Source unavailable", "Why this decision",
                         "Policy version that ran", "GP-LIFECYCLE-004 v1.2.0",
                         "Did ambiguous or missing evidence force manual review?"):
            self.assertIn(expected, text, key)
        for never in ("Eligible for a named human", "Rules would accept"):
            self.assertNotIn(never, text)
        self.assertNotIn("Run drill", b.buttons())
        self.assert_accessible(key)

    # --- findings, decisions, plans -------------------------------------------------------------

    def test_g_findings_groups_decisions_and_plans_say_what_they_mean(self):
        b = self.browser
        self.viewer()
        self.nav("#/findings?tab=dependency", expect_title="Findings")
        text = b.text("main table")
        self.assertTrue("Not established" in text or "None found" in text, "Impact & Blockers words, not blanks")
        self.nav("#/findings?tab=governance", expect_title="Findings")
        rules = [c.split("\n") for c in self.column("", "Rule")]
        self.assertTrue(rules)
        self.assertTrue(all(not CODE.match(r[0]) and len(r) > 1 and CODE.match(r[-1]) for r in rules),
                        f"the plain rule name first, its code beneath: {rules[:2]}")
        group = b.evaluate("document.querySelector('main a[href^=\"#/directory-groups/\"]').getAttribute('href')")
        self.nav(group, prefix="AD group: ")
        findings = [c.split("\n")[0] for c in self.column("", "Finding")]
        self.assertTrue(findings and not any(CODE.match(f) for f in findings), findings[:3])
        # An Okta group page shows each of its candidates' review status.
        self.nav(f"#/groups/{self.candidates()[0]['oktaGroupId']}", prefix="Okta group: ")
        rows = b.evaluate("""[...document.querySelectorAll('main table')].filter(t => t.caption.textContent.startsWith('Lifecycle candidates'))
            .flatMap(t => [...t.querySelectorAll('tbody tr')].map(r => [...r.children].map(c => c.innerText.trim().split('\\n')[0])))""")
        self.assertTrue(rows and all(any(label_key(cell) in STATUS for cell in row) for row in rows), rows[:1])
        # Decisions are recorded approvals and rejections, with expiry in words.
        self.nav("#/decisions", expect_title="Decisions")
        self.assertLessEqual(set(self.column("Approvals and rejections", "Decision")),
                             {"Approved for future action", "Rejected"})
        expiry = [e.split("\n")[0] for e in self.column("Approvals and rejections", "Expires")]
        self.assertTrue(all(re.search(r"(ago|remaining)$", e) or e == "Expired" for e in expiry
                            if e and not e.startswith("20")), expiry[:4])
        self.nav("#/jobs", expect_title="Plans & simulations")
        self.assertNotIn("Succeeded", b.text("main"))

    # --- dashboard and Find ---------------------------------------------------------------------

    def test_h_the_dashboard_starts_with_what_needs_attention(self):
        b = self.browser
        self.viewer()
        self.nav("#/", expect_title="Dashboard")
        heads = b.evaluate("[...document.querySelectorAll('main h2')].map(h => h.textContent.trim())")
        self.assertEqual(heads[0], "Needs attention")
        rows = b.evaluate("""(() => { const t = [...document.querySelectorAll('main table')]
            .find(t => /queue/i.test(t.caption ? t.caption.textContent : '')); return t ? t.querySelectorAll('tbody tr').length : -1; })()""")
        self.assertTrue(0 < rows <= 5, f"the head of the review queue: {rows} rows")
        self.assertIs(b.evaluate("document.querySelector('details.system-details').open"), False)
        self.assertGreater(b.evaluate("document.querySelectorAll('main svg').length"), 0, "charts render")
        links = b.evaluate("""[...[...document.querySelectorAll('main section')].find(s => s.querySelector('h2')
            ?.textContent.trim() === 'Needs attention').querySelectorAll('a')].map(a => a.getAttribute('href'))""")
        self.assertTrue(links)
        for href in links[:4]:
            with self.subTest(link=href):
                self.nav(href)
                self.assertNotIn(b.title(), NOT_RENDERED)

    def test_i_find_resolves_ids_on_the_server_and_never_names_locally(self):
        b = self.browser
        self.viewer()
        cid = self.candidates()[0]["id"]
        for query, opens in ((cid, True), ("Morgan", False)):
            with self.subTest(query=query):
                self.nav("#/", expect_title="Dashboard")
                before = len(b.requested_urls())
                b.focus("form[role=search] input")
                b.type(query)
                if opens:
                    self.press_and_render("form[role=search] input")
                    self.assertTrue(b.title().startswith("Candidate: "), b.title())
                else:
                    b.key("Enter")
                    b.wait_for("document.querySelector('[aria-live=polite] p')", message="the find answer")
                    self.assertIn("No object has the id", b.text("[aria-live=polite]"))
                api = [u for u in b.requested_urls()[before:] if "/api/v1/" in u]
                # An id is resolved by GET /identities first (then its page loads); a name asks the server nothing else.
                self.assertTrue(api[:1] and "/api/v1/identities?" in api[0] if opens else
                                all("/api/v1/identities?" in u for u in api), api[:3])
        for href, title in (("#/people?q=Morgan", "People"), ("#/inventory/groups?tab=directory&q=Finance", "Groups")):
            with self.subTest(search=href):
                before = len(b.requested_urls())
                self.nav(href, expect_title=title)
                self.assertTrue(any("q=" in u for u in b.requested_urls()[before:] if "/api/v1/" in u), "searched on the server")

    test_j_the_indicator_never_covers_the_navigation = nm_ui.DemoNullMeridianUiTests.test_d_the_indicator_never_covers_the_navigation

    # --- OGWA-REVIEW-QUEUE-API-01 --------------------------------------------------------------

    def test_j_the_queue_is_paged_filtered_and_counted_on_the_server(self):
        self.viewer()
        whole = self.api("/review-queue?status=all&limit=50")
        total = whole["page"]["total"]
        self.assertEqual(total, len(self.candidates()))
        self.assertEqual(whole["counts"]["all"], total)
        # Small pages: contiguous, no repeats, the same rows in the same order as one big page.
        ids, cursor = [], None
        while True:
            page = self.api("/review-queue?status=all&limit=4" + (f"&cursor={cursor}" if cursor else ""))
            self.assertEqual(page["page"]["total"], total)
            ids += [r["id"] for r in page["items"]]
            cursor = page["page"]["nextCursor"]
            if not cursor:
                break
        self.assertEqual(ids, [r["id"] for r in whole["items"]])
        for key in ("needs-review", "blocked", "waiting", "in-progress", "closed"):
            rows = self.api(f"/review-queue?status={key}&limit=50")
            self.assertEqual(rows["page"]["total"], whole["counts"][key], key)
            self.assertEqual({r["reviewStatus"] for r in rows["items"]} - {key}, set(), key)
        self.assertNotIn("ready", json.dumps(whole["counts"]).lower())
        self.nav("#/review?status=all", expect_title="Review queue")
        self.assertEqual(self.caption_total("All"), total)
        self.assertIn(f"of {total}", self.browser.text("main .pager"))
        shown = self.browser.evaluate("[...document.querySelectorAll('main table tbody th a')].map(a => a.getAttribute('href').split('/').pop())")
        self.assertEqual(shown, [r["id"] for r in whole["items"]][:25], "the browser keeps the server's priority order")

    def test_k_evidence_now_sits_beside_every_rows_lifecycle_state(self):
        self.viewer()
        self.nav("#/review?status=all", expect_title="Review queue")
        rows = self.browser.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => [r.children[1].innerText, r.children[2].innerText])")
        served = self.api("/review-queue?status=all&limit=25")["items"]
        self.assertEqual(len(rows), len(served))
        for (status, evidence), row in zip(rows, served):
            self.assertIn("Lifecycle:", status)
            self.assertIn(row["evidenceVerdict"]["decision"]["label"], evidence)
            self.assertRegex(evidence, r"Matches the recorded state|Differs from the recorded state|Terminal|Not classified")
            self.assertEqual(("Differs from the recorded state" in evidence), row["evidenceVerdict"]["agreement"] == "DIFFERS")
        self.assertNotRegex(self.page_text(), r"\bReady\b")

    def test_l_decisions_say_whether_each_approval_passes_the_approval_rules(self):
        self.viewer()
        self.nav("#/decisions", expect_title="Decisions")
        cells = self.column("Approvals and rejections", "Approval rules now")
        served = self.api("/approvals?limit=50")["items"]
        self.assertEqual(len(cells), len(served))
        self.assertTrue(all(c.strip() for c in cells), "every approval row answers")
        for cell, a in zip(cells, served):
            self.assertEqual(cell.startswith("Valid for its stage"), a["usability"]["usable"])
        self.assertNotRegex(self.page_text(), r"\b(Usable now|Ready)\b")

    def test_m_an_ad_group_opens_its_lifecycle_candidate_directly(self):
        self.viewer()
        linked = None
        for c in self.candidates():
            mapping = self.api(f"/mappings/{c['oktaGroupId']}")["mapping"]
            if mapping and mapping["isExact"] and mapping["adGroupId"]:
                found = [g for g in self.api(f"/directory-groups?q={mapping['adGroupId']}")["items"] if g["source"] == "AD"]
                if found:
                    linked = (found[0], c)
                    break
        self.assertIsNotNone(linked, "the dataset has an exactly mapped AD group with a candidate")
        group, cand = linked
        self.nav(f"#/directory-groups/{group['id']}", prefix="AD group: ")
        hrefs = self.browser.evaluate("[...document.querySelectorAll('main section')].filter(s => s.querySelector('h2') && "
                                      "s.querySelector('h2').textContent === 'Lifecycle candidates')"
                                      ".flatMap(s => [...s.querySelectorAll('tbody th a')].map(a => a.getAttribute('href')))")
        self.assertIn(f"#/candidates/{cand['id']}", hrefs)
        self.assertIn("Exact identity mapping", self.page_text())

    def test_n_approvals_expiring_soon_match_the_server(self):
        self.viewer()
        b = self.browser
        served = self.api("/approvals?usability=expiring-soon&limit=50")
        soon, hours = served["counts"]["expiringSoon"], served["expiringSoonWithinHours"]
        self.nav("#/", expect_title="Dashboard")
        links = b.evaluate("[...document.querySelectorAll('ul.attention a')].map(a => [a.textContent, a.getAttribute('href')])")
        expiring = [text for text, href in links if href == "#/decisions?usability=expiring-soon"]
        if soon:
            self.assertEqual(len(expiring), 1)
            self.assertTrue(expiring[0].startswith(f"{soon} approval"), expiring)
        else:
            self.assertEqual(expiring, [], "the zero state: no item")
        self.nav("#/decisions?usability=expiring-soon", expect_title="Decisions")
        labels = dict(re.findall(r"^(.+) \((\d+)\)$", b.text("main nav.status-filters"), re.M))
        self.assertEqual({k: int(v) for k, v in labels.items()},
                         {"All": served["counts"]["all"], "Valid for its stage": served["counts"]["valid"],
                          "Expiring soon": soon, "Expired": served["counts"]["expired"]})
        rows = b.evaluate("[...document.querySelectorAll('main table tbody tr')].map(r => r.innerText)")
        self.assertEqual(len(rows), len(served["items"]))
        if not soon:
            self.assertIn(f"No valid approval expires within {hours} hours.", self.page_text())
        self.assertNotRegex(self.page_text(), r"\b(Ready|Executable|Approved to delete)\b")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
