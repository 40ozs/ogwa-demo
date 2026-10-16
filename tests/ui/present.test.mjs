// Unit tests for the presentation rules (app/ui/static/js/present.js). Run by
// tests/test_ui_present.py, which writes what the real API returns over Null Meridian
// (UI_PRESENT_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  activeTab, ariaSort, clampPage, collectIds, employeeTerms, eventLabel, hashFor, nextSort, pageWindow, personStatus,
  refView, snapshotEntry, sortRows, tabKeyTarget,
} from "../../app/ui/static/js/present.js";

const fixturePath = process.env.UI_PRESENT_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_PRESENT_FIXTURES is not set (run tests/test_ui_present.py)" };

// --- employee status ------------------------------------------------------------------------

test("an active person is Active with no deactivation date", withFixtures, () => {
  const s = personStatus(fx.active);
  assert.deepEqual([s.label, s.active, s.deactivationDate], ["Active", true, null]);
});

test("a deactivated person is Deactivated, with the date in its own field", withFixtures, () => {
  assert.equal(fx.deactivated.status, "TERMINATED", "the API contract is unchanged");
  const s = personStatus(fx.deactivated);
  assert.equal(s.label, "Deactivated");
  assert.equal(s.deactivationDate, fx.deactivated.terminationDate);
  assert.match(s.deactivationDate, /^\d{4}-\d{2}-\d{2}$/);
});

test("a missing deactivation date is never invented", () => {
  assert.equal(personStatus({ status: "TERMINATED", terminationDate: null }).deactivationDate, null);
});

test("no user-facing label says Former or Terminated", () => {
  for (const words of [personStatus({ status: "TERMINATED" }).label, eventLabel("TERMINATED"),
    employeeTerms("3 former employee(s) still direct members"), employeeTerms("Former employees remain; terminated employee left")]) {
    assert.doesNotMatch(words, /\bformer\b|\bterminated\b/i, words);
  }
  assert.equal(employeeTerms("Disabled accounts of former employees are still direct members."),
    "Disabled accounts of deactivated employees are still direct members.");
  assert.equal(eventLabel("OKTA_DEACTIVATED"), "Okta deactivated", "Okta's own terms are kept");
  assert.equal(employeeTerms("adminCount still set from a former protected-group membership"),
    "adminCount still set from a former protected-group membership", "only employee wording changes");
});

// --- sorting and paging ---------------------------------------------------------------------

test("sort headers cycle ascending then descending, and say so", () => {
  let s = nextSort(null, "name");
  assert.deepEqual(s, { key: "name", dir: "asc" });
  assert.equal(ariaSort(s, "name"), "ascending");
  s = nextSort(s, "name");
  assert.equal(ariaSort(s, "name"), "descending");
  assert.equal(ariaSort(s, "other"), null);
  assert.deepEqual(nextSort(s, "other"), { key: "other", dir: "asc" });
});

test("local sorting is stable and puts empty values last both ways", () => {
  const rows = [{ n: "b", i: 1 }, { n: null, i: 2 }, { n: "A", i: 3 }, { n: "b", i: 4 }, { n: "", i: 5 }];
  assert.deepEqual(sortRows(rows, (r) => r.n, "asc").map((r) => r.i), [3, 1, 4, 2, 5]);
  assert.deepEqual(sortRows(rows, (r) => r.n, "desc").map((r) => r.i), [1, 4, 3, 2, 5]);
  assert.deepEqual(sortRows([{ v: 10 }, { v: 9 }], (r) => r.v, "asc").map((r) => r.v), [9, 10], "numbers sort as numbers");
});

test("page windows: first, middle, final partial, empty, and past the end", () => {
  assert.deepEqual(pick(pageWindow({ offset: 0, count: 50, total: 298 })), ["1–50 of 298", false, true, false]);
  assert.deepEqual(pick(pageWindow({ offset: 50, count: 50, total: 298 })), ["51–100 of 298", true, true, false]);
  assert.deepEqual(pick(pageWindow({ offset: 250, count: 48, total: 298 })), ["251–298 of 298", true, false, false]);
  assert.deepEqual(pick(pageWindow({ offset: 0, count: 0, total: 0 })), ["0 of 0", false, false, false]);
  assert.deepEqual(pick(pageWindow({ offset: 5000, count: 0, total: 401 })), ["0 of 401", true, false, true]);
  assert.equal(pageWindow({ offset: 0, count: 50, total: null, hasNext: true }).hasNext, true, "an uncounted listing trusts its cursor");
  assert.equal(clampPage(9, 30, 25), 1, "a page that no longer exists becomes the last one");
  assert.equal(clampPage(-1, 0, 25), 0);
});

function pick(w) {
  return [w.label, w.hasPrevious, w.hasNext, w.pastEnd];
}

// --- tabs and addresses ---------------------------------------------------------------------

test("tabs come from the address, and unknown tabs fall back", () => {
  const tabs = ["dependency", "governance"];
  assert.equal(activeTab({ tab: "governance" }, tabs), "governance");
  assert.equal(activeTab({ tab: "nope" }, tabs), "dependency");
  assert.equal(activeTab({}, tabs, "governance"), "governance");
});

test("arrow keys wrap between tabs; Home and End jump; other keys are ignored", () => {
  assert.equal(tabKeyTarget("ArrowRight", 2, 3), 0);
  assert.equal(tabKeyTarget("ArrowLeft", 0, 3), 2);
  assert.equal(tabKeyTarget("Home", 2, 3), 0);
  assert.equal(tabKeyTarget("End", 0, 3), 2);
  assert.equal(tabKeyTarget("Enter", 0, 3), null);
});

test("addresses keep the current query and drop emptied keys", () => {
  assert.equal(hashFor("/directory", { tab: "groups", cursor: "x", q: "fin" }, { sort: "name", order: "asc", cursor: null }),
    "#/directory?tab=groups&q=fin&sort=name&order=asc");
  assert.equal(hashFor("/findings", {}, { tab: "governance" }), "#/findings?tab=governance");
  assert.equal(hashFor("/okta", {}, {}), "#/okta");
});

// --- identities -----------------------------------------------------------------------------

test("an AD group SID shows its common name and opens its canonical page", withFixtures, () => {
  const v = refView(fx.identities[fx.allStaff.adSid], fx.allStaff.adSid);
  assert.equal(v.text, "All-Staff");
  assert.equal(v.href, `#/directory-groups/${fx.allStaff.id}`);
  assert.equal(v.qualifier, null, "a unique name needs no qualifier");
  assert.match(v.title, new RegExp(fx.allStaff.adSid), "the raw SID stays available");
  assert.notEqual(v.text, fx.allStaff.adSid, "the SID is never the primary label");
});

test("two AD groups that share a name each link to themselves and are told apart", withFixtures, () => {
  const [a, b] = fx.financeRw;
  const va = refView(fx.identities[a.adEvidenceId], a.adEvidenceId);
  const vb = refView(fx.identities[b.adEvidenceId], b.adEvidenceId);
  assert.equal(va.text, "Finance-RW");
  assert.equal(vb.text, "Finance-RW");
  assert.equal(va.href, `#/directory-groups/${a.id}`);
  assert.equal(vb.href, `#/directory-groups/${b.id}`);
  assert.equal(va.qualifier, a.adDistinguishedName);
  assert.equal(vb.qualifier, b.adDistinguishedName);
  assert.notEqual(va.qualifier, vb.qualifier);
});

test("an unresolved id is shown as itself and flagged, never hidden", withFixtures, () => {
  const v = refView(fx.identities[fx.unknown], fx.unknown);
  assert.deepEqual([v.text, v.href, v.unresolved], [fx.unknown, null, true]);
  assert.equal(refView(undefined, "job_1").unresolved, true);
});

test("access path nodes keep their order and link to the groups they name", withFixtures, () => {
  const views = fx.route.chain.map((node) => refView(snapshotEntry(node), node.id));
  assert.deepEqual(views.map((v) => v.text), fx.route.chain.map((n) => n.name));
  assert.deepEqual(views.map((v) => v.href), fx.route.chain.map((n) => `#/directory-groups/${n.id}`));
  assert.equal(snapshotEntry(null), null);
});

test("ids are collected once per view", () => {
  assert.deepEqual(collectIds([{ a: "x", b: "y" }, { a: "x", b: null }, { a: ["z"] }], "a", "b"), ["x", "y", "z"]);
});
