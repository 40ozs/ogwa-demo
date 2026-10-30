"""OGWA-UI-IA-02: the candidate page's tables in a real headless browser (opt-in, UI_BROWSER_TESTS=1).

Each data table on the candidate page sorts with the shared table: the active column and its
direction are shown (``aria-sort`` and an arrow), a new sort starts again at the first page,
ties keep the table's own order, and nothing reloads. Columns of prose, ids, or actions do not
sort, and the decision history and the audit trail keep their recorded order. Null Meridian
runs locally; with ``UI_BROWSER_TARGET`` the same checks run against the target's dataset (they
need only a DEPENDENCY_BLOCKED and a HOLD candidate). The classic world, whose stale-evidence
candidate has more classification reasons than one page holds, runs locally only.
"""

import json
import unittest

from tests.browser.harness import Browser, SyntheticServer, browser_path
from tests.browser.test_operator_workflows import BrowserCase, skip_reason

# Every table of the candidate page: whether each column sorts.
SORTABLE = {
    # OGWA-DEMO-01: the evidence assessment's per-source table; its free-text observation is not sortable.
    "Evidence by source, with its state": {"Source": True, "System": True, "What it says": False, "State": True,
                                           "Freshness": True, "Bearing": True, "Required": True, "Observed": True},
    "Classification reasons": {"Effect": True, "Reason": True, "Detail": False, "Subject": True},
    "Dependency coverage by kind": {"Kind": True, "Required": True, "Status": True, "Production collector": True},
    "Dependency findings": {"Kind": True, "Effect": True, "Finding": False, "Code": True, "Reference": True,
                            "Observed": True},
    "Evidence records": {"Record": True, "Observed": True, "Age": True, "Freshness (classifier)": True,
                         "Result": True, "Source": True},
    # OGWA-DEMO-02: the decision explanation's conditions keep the classifier's order; only the status sorts.
    "Conditions, as the policy version that ran states them": {"Condition": False, "Rule under this version": False,
                                                               "Status": True, "Why": False},
    "Lifecycle decisions, oldest first": {"When": False, "From": False, "To": False, "By": False,
                                          "Judged by policy": False, "Reason": False, "Approval / job": False},
    "Approvals and rejections": {"Stage": True, "Decision": True, "Approval rules now": True, "By": True, "Decided": True, "Expires": True,
                                 "Epoch": True, "Judged by policy": True, "Reason": False},
    "Dry-run plans": {"Plan": False, "Kind": True, "Status": True, "Executed": True, "Mode": True, "Requested": True},
    "Audit events for this candidate, newest first": {"Sequence": False, "Action": False, "When": False,
                                                      "Actor": False, "Result": False, "Request": False},
}


def table(caption: str) -> str:
    return f"[...document.querySelectorAll('table')].find(t => t.caption.textContent === {json.dumps(caption)})"


def headers(b: Browser, caption: str) -> dict[str, bool]:
    return dict(b.evaluate(f"""[...{table(caption)}.querySelectorAll('thead th')]
        .map(th => [th.textContent.replace(/[▲▼↕]/g, '').trim(), !!th.querySelector('button.sort')])"""))


def column(b: Browser, caption: str, index: int) -> list[str]:
    return b.evaluate(f"""[...{table(caption)}.querySelectorAll('tbody tr')]
        .map(r => r.children[{index}].innerText.split('\\n')[0].trim())""")


def sort(b: Browser, caption: str, label: str) -> None:
    """Click a sort header; the table re-renders in place and keeps focus on that header."""
    b.evaluate(f"""[...{table(caption)}.querySelectorAll('th button.sort')]
        .find(x => x.textContent.replace(/[▲▼↕]/g, '').trim() === {json.dumps(label)}).click()""")


def sorted_by(b: Browser, caption: str) -> list[list[str]]:
    return b.evaluate(f"""[...{table(caption)}.querySelectorAll('th[aria-sort]')]
        .map(th => [th.textContent.replace(/[▲▼↕]/g, '').trim(), th.getAttribute('aria-sort'),
                    th.querySelector('.sort-indicator').textContent])""")


def pager(b: Browser, caption: str, button: str | None = None) -> str:
    nav = f"document.querySelector('nav[aria-label=' + {json.dumps(json.dumps(caption + ': pages'))} + ']')"
    if button:
        b.evaluate(f"[...{nav}.querySelectorAll('button')].find(x => x.textContent === {json.dumps(button)}).click()")
    return b.evaluate(f"{nav}.querySelector('.pager-status').textContent")


AUDIT_TABLE = "Audit events for this candidate, newest first"


@unittest.skipIf(skip_reason(), skip_reason() or "")
class DemoCandidateTablesTests(BrowserCase):
    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.server = SyntheticServer(refresh=(), dataset="null-meridian", any_dataset=True).start_and_wait()
        try:
            cls.browser = Browser(browser_path())
        except Exception:
            cls.server.stop()
            raise

    signed_in = False
    audit_visible = True

    def setUp(self):
        if not type(self).signed_in:
            self.browser.goto(self.server.origin + "/#/")
            self.browser.wait_for("document.getElementById('page-title').textContent !== 'Loading'", message="console")
            # The public demo's anonymous visitor is a viewer, who cannot read the audit trail.
            type(self).audit_visible = not self.public_demo()
            self.sign_in("synthetic.admin.one" if self.audit_visible else "synthetic.viewer.one")  # nothing here writes
            type(self).signed_in = True

    def open_candidate(self, state: str) -> None:
        """The first candidate in a state, by Okta group name (the deployed demo has no scenario ids)."""
        self.nav(f"#/candidates?state={state}&sort=oktaGroup&order=asc", expect_title="Lifecycle candidates")
        self.browser.evaluate("document.getElementById('view').dataset.old = '1'")
        self.browser.evaluate("document.querySelector('main tbody tr a').click()")
        self.browser.wait_for("!document.getElementById('view').dataset.old && "
                              "document.getElementById('page-title').textContent.startsWith('Candidate: ')",
                              message="candidate page")

    def test_a_every_table_sorts_only_its_meaningful_columns(self):
        b, seen = self.browser, set()
        for state in ("DEPENDENCY_BLOCKED", "HOLD"):  # findings on one, approvals and jobs on the other
            self.open_candidate(state)
            for caption in self.browser.evaluate("[...document.querySelectorAll('main table caption')].map(c => c.textContent)"):
                with self.subTest(state=state, table=caption):
                    self.assertIn(caption, SORTABLE, "a new candidate-page table needs a sorting decision")
                    self.assertEqual(headers(b, caption), SORTABLE[caption])
                    seen.add(caption)
        expected = set(SORTABLE) - (set() if self.audit_visible else {AUDIT_TABLE})
        self.assertEqual(seen, expected, "every candidate-page table was checked")

    def test_b_ascending_descending_state_focus_and_no_reload(self):
        b = self.browser
        self.open_candidate("HOLD")
        b.evaluate("window.__candidateTablesMarker = 1")
        hash_before = b.evaluate("location.hash")
        self.assertEqual(sorted_by(b, "Evidence records"), [], "no column claims to be sorted before a sort")
        sort(b, "Evidence records", "Observed")
        self.assertEqual(sorted_by(b, "Evidence records"), [["Observed", "ascending", "▲"]])
        self.assertEqual(b.evaluate("document.activeElement.className"), "sort", "focus stays on the header")
        observed = column(b, "Evidence records", 1)
        self.assertEqual(observed, sorted(observed))
        sort(b, "Evidence records", "Observed")
        self.assertEqual(sorted_by(b, "Evidence records"), [["Observed", "descending", "▼"]])
        self.assertEqual(column(b, "Evidence records", 1), sorted(observed, reverse=True))
        sort(b, "Approvals and rejections", "Stage")
        self.assertEqual(sorted_by(b, "Approvals and rejections"), [["Stage", "ascending", "▲"]])
        self.assertEqual(sorted_by(b, "Evidence records"), [["Observed", "descending", "▼"]], "tables sort independently")
        self.assertEqual(b.evaluate("window.__candidateTablesMarker"), 1, "sorting never reloads the page")
        self.assertEqual(b.evaluate("location.hash"), hash_before)
        self.assert_accessible("candidate page, sorted")

    def test_c_ties_keep_the_tables_own_order(self):
        b = self.browser
        self.open_candidate("DEPENDENCY_BLOCKED")
        caption = "Classification reasons"
        own = list(zip(column(b, caption, 0), column(b, caption, 1)))  # (Effect, Reason), blocking first
        self.assertGreater(len({e for e, _ in own}), 1)
        for order, descending in (("ascending", False), ("descending", True)):
            sort(b, caption, "Effect")
            self.assertEqual(sorted_by(b, caption)[0][1], order)
            shown = list(zip(column(b, caption, 0), column(b, caption, 1)))
            self.assertEqual(shown, sorted(own, key=lambda r: r[0] == "Blocks", reverse=descending))

    def test_d_the_decision_history_and_audit_trail_keep_their_order(self):
        b = self.browser
        self.open_candidate("HOLD")
        if self.audit_visible:
            sequences = [int(s) for s in column(b, AUDIT_TABLE, 0)]
            self.assertGreater(len(sequences), 1)
            self.assertEqual(sequences, sorted(sequences, reverse=True))
        when = column(b, "Lifecycle decisions, oldest first", 0)
        self.assertEqual(when, sorted(when))

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


@unittest.skipIf(skip_reason(), skip_reason() or "")
class PagedCandidateTableTests(BrowserCase):
    """The classic world's stale-evidence candidate (S11) has 26 classification reasons."""

    signed_in = False

    def setUp(self):
        if not type(self).signed_in:
            self.sign_in("synthetic.viewer.one")
            type(self).signed_in = True

    def test_sorting_after_changing_pages_starts_again_at_the_first_page(self):
        b, caption = self.browser, "Classification reasons"
        self.candidate("S11")
        self.assertEqual(pager(b, caption), "Rows 1–25 of 26")
        self.assertEqual(pager(b, caption, "Next page"), "Rows 26–26 of 26")
        sort(b, caption, "Reason")
        self.assertEqual(pager(b, caption), "Rows 1–25 of 26", "a new sort returns to the first page")
        first = column(b, caption, 1)
        self.assertEqual(first, sorted(first, key=str.casefold))
        self.assertEqual(pager(b, caption, "Next page"), "Rows 26–26 of 26")
        self.assertLessEqual(first[-1].casefold(), column(b, caption, 1)[0].casefold(), "sorted across pages")
        sort(b, caption, "Reason")
        self.assertEqual(pager(b, caption), "Rows 1–25 of 26")
        self.assertEqual(sorted_by(b, caption), [["Reason", "descending", "▼"]])
        backwards = column(b, caption, 1)
        self.assertEqual(backwards, sorted(backwards, key=str.casefold, reverse=True))
        previous = "[...document.querySelectorAll('nav.pager button')].find(b => b.textContent === 'Previous page')"
        self.assertEqual(b.evaluate(f"{previous}.getAttribute('aria-disabled')"), "true")
        self.assert_accessible("candidate page, paged and sorted")

    def test_z_nothing_left_the_origin_and_nothing_failed(self):
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
