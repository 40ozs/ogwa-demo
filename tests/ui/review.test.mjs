// Unit tests for the operator review reading (app/ui/static/js/review.js, OGWA-UI-REVIEW-01).
// Run by tests/test_ui_review.py, which writes what the real API returns over the classic
// synthetic world (UI_REVIEW_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  APPROVAL_FILTERS, approvalUsability, evidenceReadiness, impactOf, lifecycleStages, nextStep, OPEN_STATUSES, planStatus, queueOrder,
  REVIEW_STATUS, reviewStatus, ruleLabel, STAGES, stageLabel, statesOf, statusCounts, verdictReading,
} from "../../app/ui/static/js/review.js";

const fixturePath = process.env.UI_REVIEW_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_REVIEW_FIXTURES is not set (run tests/test_ui_review.py)" };
const now = () => fx.dashboard.generatedAt;
const sc = (key) => fx.scenarios[key];
const stagesOf = (key) => lifecycleStages(sc(key).candidate, sc(key).decisions, now());
const byKey = (life) => Object.fromEntries(life.stages.map((s) => [s.key, s]));

// --- review status --------------------------------------------------------------------------

test("every lifecycle state has exactly one review status", withFixtures, () => {
  const seen = new Set();
  for (const key of Object.keys(REVIEW_STATUS)) for (const s of statesOf(key)) { assert.ok(!seen.has(s), s); seen.add(s); }
  assert.deepEqual([...seen].sort(), [...fx.states].sort());
});

test("decisions, revalidation and a deletion proposal need review; holds wait and are not blocked", () => {
  for (const s of ["NEEDS_REVIEW", "REVALIDATION_REQUIRED", "DELETION_REVALIDATION_REQUIRED", "DELETION_PROPOSED"]) {
    assert.equal(reviewStatus(s).key, "needs-review", s);
  }
  for (const s of ["HOLD", "QUARANTINE_HOLD"]) {
    assert.equal(reviewStatus(s).key, "waiting", s);
    assert.notEqual(reviewStatus(s).tone, "blocked", s);
  }
});

test("blocked states stay blocked, and an unknown state reads as blocked", () => {
  for (const s of ["BLOCKED", "MAPPING_AMBIGUOUS", "DEPENDENCY_BLOCKED", "STALE_EVIDENCE", "EVIDENCE_INCOMPLETE",
    "RETIREMENT_DRY_RUN", "SOMETHING_NEW"]) {
    assert.deepEqual([reviewStatus(s).key, reviewStatus(s).tone], ["blocked", "blocked"], s);
  }
});

test("no review status presents anything as ready, safe, or done", () => {
  for (const [key, status] of Object.entries(REVIEW_STATUS)) {
    assert.doesNotMatch(`${status.label} ${status.text}`, /\bready\b|\bsafe\b|\bsuccess|\bclear\b/i, key);
  }
  // Approved states are in progress, and say it is dry run only.
  for (const s of ["APPROVED", "QUARANTINE_APPROVED", "DELETION_APPROVED"]) {
    assert.match(reviewStatus(s).label, /dry run only/, s);
  }
  assert.deepEqual(OPEN_STATUSES, ["needs-review", "blocked", "waiting", "in-progress"]);
});

test("status counts add up the dashboard's per-state counts", withFixtures, () => {
  const counts = statusCounts(fx.dashboard.candidatesByState);
  const total = Object.values(fx.dashboard.candidatesByState).reduce((a, b) => a + b, 0);
  assert.equal(Object.values(counts).reduce((a, b) => a + b, 0), total);
  assert.equal(counts.closed, 2, "S06 protected and S08 excluded");
  assert.equal(counts["needs-review"], 3, "S07, S12, S16");
  assert.equal(statusCounts({ BRAND_NEW: 2 }).blocked, 2);
});

// --- the lifecycle stepper --------------------------------------------------------------------

test("initial review: discovery completed, review current, everything after not yet eligible", withFixtures, () => {
  const life = stagesOf("S07");
  assert.deepEqual(life.stages.map((s) => s.status),
    ["done", "current", "future", "future", "future", "future", "future", "future", "future", "future"]);
  assert.equal(life.stages[2].statusText, "Not yet eligible");
  assert.match(life.summary, /^Stage 2 of 10: Review, current \(Needs review\)\.$/);
});

test("approved: the Okta unassignment stage is current, and nothing after it is reached", withFixtures, () => {
  const s = byKey(stagesOf("S14"));
  assert.deepEqual([s.review.status, s.okta.status, s.hold.status], ["done", "current", "future"]);
  assert.match(s.okta.note, /Approved for a future Okta step/);
});

test("a hold is current and waiting, with its end read on the server's clock", withFixtures, () => {
  for (const [key, stage, field] of [["S01", "hold", "holdUntil"], ["S15", "quarantine-hold", "quarantineHoldUntil"]]) {
    const s = byKey(stagesOf(key))[stage];
    assert.equal(s.status, "waiting", key);
    assert.equal(s.until, sc(key).candidate[field], key);
    assert.match(s.note, /(remaining|Ended .* ago)$/, key);
    // Without the server's clock there is no relative wording: the browser's clock is never used.
    assert.doesNotMatch(byKey(lifecycleStages(sc(key).candidate, [], null))[stage].note, /remaining|ago/, key);
  }
});

test("revalidation, post-quarantine stages and a deletion proposal sit at their own stage", withFixtures, () => {
  assert.equal(byKey(stagesOf("S12")).revalidation.status, "current");
  const s16 = byKey(stagesOf("S16"));
  assert.deepEqual([s16.quarantine.status, s16["quarantine-hold"].status, s16["deletion-review"].status, s16.deletion.status],
    ["done", "done", "current", "future"]);
  const dryRun = lifecycleStages({ state: "QUARANTINE_DRY_RUN", blockedFrom: null }, [], null);
  assert.equal(byKey(dryRun).quarantine.status, "current");
});

test("a blocked candidate is blocked at the stage it was blocked from", withFixtures, () => {
  for (const [key, stage, label] of [["S03", "discovery", "Blocked: dependency"], ["S11", "discovery", "Blocked: evidence stale"],
    ["S09", "discovery", "Blocked: identity not proven"], ["S10", "review", "Held by an operator"]]) {
    const life = stagesOf(key);
    const s = byKey(life)[stage];
    assert.deepEqual([s.status, s.statusText, s.note], ["blocked", "Blocked", label], key);
    const after = life.stages.slice(life.stages.indexOf(s) + 1);
    assert.ok(after.every((x) => x.status === "future"), key);
  }
  const incomplete = lifecycleStages({ state: "EVIDENCE_INCOMPLETE", blockedFrom: "REVALIDATION_REQUIRED" }, [], null);
  assert.equal(byKey(incomplete).revalidation.note, "Blocked: evidence incomplete");
  assert.deepEqual(byKey(incomplete).hold.status, "done");
});

test("protected and excluded candidates stop at the furthest stage their history reached", withFixtures, () => {
  const excluded = byKey(stagesOf(fx.excluded));
  assert.deepEqual([excluded.discovery.status, excluded.review.status, excluded.okta.status],
    ["done", "closed", "not-reached"]);
  assert.equal(excluded.review.note, "Excluded");
  const prot = stagesOf("S06");
  assert.equal(prot.stages.filter((s) => s.status === "closed").length, 1);
  assert.ok(prot.stages.every((s) => s.status !== "future"), "a terminal candidate has no eligible future");
});

test("a retired candidate shows every stage completed, ending in Retired (observed)", () => {
  const life = lifecycleStages({ state: "RETIRED", blockedFrom: null }, [], null);
  assert.ok(life.stages.every((s) => s.status === "done"));
  assert.equal(life.stages.at(-1).note, "Retired (observed)");
});

test("every stage says its status in words, and exactly one is marked as where the candidate is", withFixtures, () => {
  for (const key of Object.keys(fx.scenarios)) {
    const life = stagesOf(key);
    assert.equal(life.stages.length, STAGES.length, key);
    assert.ok(life.stages.every((s) => s.statusText && s.label), key);
    assert.equal(life.stages.filter((s) => s.note).length, 1, key);
    assert.ok(life.summary.startsWith("Stage "), key);
  }
});

// --- next step --------------------------------------------------------------------------------

test("only states with an open human decision say so, and terminal states have no next step", withFixtures, () => {
  for (const key of Object.keys(fx.scenarios)) {
    const c = sc(key).candidate;
    assert.equal(nextStep(c, now()).decision, reviewStatus(c.state).key === "needs-review", key);
  }
  for (const s of ["RETIRED", "EXCLUDED", "REJECTED", "PROTECTED"]) assert.match(nextStep({ state: s }, null).text, /^None\./, s);
  assert.match(nextStep({ state: "STALE_EVIDENCE" }, null).text, /^Only clears when/);
  assert.match(nextStep({ state: "OKTA_UNASSIGN_DRY_RUN" }, null).text, /^Nothing in OGWA/);
});

test("a hold's deadline is the candidate's own field, never the browser's clock", withFixtures, () => {
  const c = sc("S01").candidate;
  const d = nextStep(c, now()).deadline;
  assert.equal(d.at, c.holdUntil);
  assert.ok(d.label);
  assert.equal(nextStep(c, null).deadline.label, null);
  assert.equal(nextStep(sc("S07").candidate, now()).deadline, null);
});

test("the queue puts decisions first, then blocked, then holds by their deadline", withFixtures, () => {
  const order = [...fx.candidates].sort(queueOrder(now())).map((c) => reviewStatus(c.state).key);
  const rank = order.map((k) => Object.keys(REVIEW_STATUS).indexOf(k));
  assert.deepEqual(rank, [...rank].sort((a, b) => a - b));
  assert.equal(order[0], "needs-review");
  const holds = [{ id: "a", state: "HOLD", holdUntil: "2026-03-09T00:00:00+00:00", updatedAt: "2026-01-01T00:00:00+00:00" },
    { id: "b", state: "QUARANTINE_HOLD", quarantineHoldUntil: "2026-03-05T00:00:00+00:00", updatedAt: "2026-02-01T00:00:00+00:00" }];
  assert.deepEqual(holds.sort(queueOrder(now())).map((c) => c.id), ["b", "a"]);
  assert.equal(stageLabel({ state: "DEPENDENCY_BLOCKED", blockedFrom: "DISCOVERED" }), "Discovery");
  assert.equal(stageLabel({ state: "EXCLUDED", blockedFrom: null }), null);
});

// --- evidence readiness -----------------------------------------------------------------------

test("evidence readiness counts the server's required sources that are complete and current", withFixtures, () => {
  for (const key of ["S07", "S11", "S12"]) {
    const a = sc(key).assessment;
    const r = evidenceReadiness(a);
    const required = a.items.filter((i) => i.required);
    assert.equal(r.required, required.length, key);
    assert.equal(r.usable, required.filter((i) => ["CONFIRMED", "REPORTS_NONE"].includes(i.state) && i.freshness === "CURRENT").length, key);
    assert.equal(r.problems.length, r.required - r.usable, key);
  }
  assert.ok(evidenceReadiness(sc("S11").assessment).problems.length > 0, "stale evidence is not usable");
  assert.equal(evidenceReadiness(null), null);
});

// --- impact and blockers ------------------------------------------------------------------------

test("a known blocking dependency blocks, and says which kind of dependency it is", withFixtures, () => {
  const blocking = fx.dependencyChecks.filter((d) => d.findings.some((f) => f.blocking));
  assert.ok(blocking.length, "the classic world has blocking dependency findings");
  for (const d of blocking) {
    const i = impactOf(d);
    assert.deepEqual([i.blocks, i.tone], [true, "blocked"], d.id);
    assert.match(i.effect, /^Blocks lifecycle progress/);
    assert.notEqual(i.category, "none-found");
  }
  assert.equal(impactOf({ dependencyKind: "AD_GROUP_MEMBERS", findings: [{ blocking: true }],
    provenance: { resultStatus: "COMPLETE", decisionGrade: true } }).category, "directory-constraint");
  assert.equal(impactOf({ dependencyKind: "GPO_REFERENCE", findings: [{ blocking: true }],
    provenance: { resultStatus: "COMPLETE", decisionGrade: true } }).category, "external-reference");
  assert.equal(impactOf({ dependencyKind: "OKTA_OTHER_APP_ASSIGNMENT", findings: [{ blocking: true }],
    provenance: { resultStatus: "COMPLETE", decisionGrade: true } }).category, "known-dependency");
});

test("an informational finding does not block on its own", () => {
  const i = impactOf({ dependencyKind: "OTHER", findings: [{ blocking: false }], provenance: { resultStatus: "COMPLETE", decisionGrade: true } });
  assert.deepEqual([i.blocks, i.tone, i.effect], [false, "neutral", "Informational: does not block on its own"]);
});

test("'none found' needs a complete, decision-grade check; anything less is not established", withFixtures, () => {
  const complete = impactOf({ dependencyKind: "AD_ACL_REFERENCE", findings: [], provenance: { resultStatus: "COMPLETE", decisionGrade: true } });
  assert.deepEqual([complete.category, complete.established], ["none-found", true]);
  for (const provenance of [{ resultStatus: "PARTIAL", decisionGrade: false }, { resultStatus: "FAILED", decisionGrade: false },
    { resultStatus: "COMPLETE", decisionGrade: false }, {}]) {
    const i = impactOf({ dependencyKind: "AD_ACL_REFERENCE", findings: [], provenance });
    assert.deepEqual([i.category, i.established, i.blocks], ["coverage-gap", false, false], JSON.stringify(provenance));
    assert.match(i.effect, /could not determine whether a dependency exists/);
    assert.doesNotMatch(i.effect, /none found/i);
  }
  // What an incomplete check did find still counts, and says more may exist.
  const partial = impactOf({ dependencyKind: "AD_NESTED_MEMBERSHIP", findings: [{ blocking: true }], provenance: { resultStatus: "PARTIAL", decisionGrade: false } });
  assert.deepEqual([partial.blocks, partial.incompleteNote], [true, "The check did not complete: more may exist."]);
  for (const d of fx.dependencyChecks) {
    const i = impactOf(d);
    if (i.category === "none-found") assert.ok(d.provenance.resultStatus === "COMPLETE" && d.provenance.decisionGrade, d.id);
  }
});

// --- governance and plans -----------------------------------------------------------------------

test("governance rules are named in plain words; the code stays the identifier", () => {
  assert.equal(ruleLabel("TERMINATED_MEMBERS_RETAINED"), "Deactivated members still retain access");
  assert.equal(ruleLabel("SOMETHING_NEW"), "SOMETHING_NEW");
});

test("a plan's status never suggests anything was executed", () => {
  for (const status of ["SUCCEEDED", "FAILED", "PLANNED", "RUNNING"]) {
    const s = planStatus({ status, dryRun: true, executed: false });
    assert.match(s.label, /nothing executed$/, status);
    assert.doesNotMatch(s.label, /succe|complete|done|applied/i, status);
  }
  assert.equal(planStatus({ status: "SUCCEEDED", dryRun: true, executed: true }).tone, "blocked");
  assert.equal(planStatus({ status: "SUCCEEDED", dryRun: false, executed: false }).tone, "blocked");
});

// --- OGWA-REVIEW-QUEUE-API-01: the server-side queue's verdict and approval usability ------------

test("the server's queue rows are in the UI's queue order, with the UI's review status", withFixtures, () => {
  const rows = fx.queue.items;
  assert.deepEqual(rows.map((c) => c.id), [...rows].sort(queueOrder(fx.queue.generatedAt)).map((c) => c.id));
  for (const c of rows) assert.equal(c.reviewStatus, reviewStatus(c.state).key, c.state);
  assert.deepEqual(Object.fromEntries(Object.keys(REVIEW_STATUS).map((k) => [k, fx.queue.counts[k]])),
    statusCounts(fx.dashboard.candidatesByState));
});

test("every row's evidence verdict is worded beside the recorded state, and a disagreement is shown", withFixtures, () => {
  const readings = fx.queue.items.map((c) => [c, verdictReading(c.evidenceVerdict, c.state)]);
  for (const [c, v] of readings) {
    assert.ok(v.label && v.agreement.text, c.id);
    assert.doesNotMatch(`${v.label} ${v.agreement.text}`, /\bready\b|\bsafe to\b/i);
  }
  const differs = readings.filter(([, v]) => v.agreement.key === "DIFFERS");
  assert.ok(differs.length >= 2, "the classic world has recorded states the evidence no longer supports");
  for (const [c, v] of differs) {
    assert.equal(v.agreement.tone, "caution");
    assert.match(v.agreement.text, /^Differs from the recorded state/);
    if (c.evidenceVerdict.suggestedState) assert.ok(v.agreement.text.includes("points to"), c.id);
  }
  const terminal = readings.find(([c]) => c.state === "PROTECTED")[1];
  assert.equal(terminal.agreement.key, "NOT_APPLICABLE");
  assert.ok(readings.some(([, v]) => v.blockers.length && v.blockers.every((b) => typeof b === "string" && b.length)));
});

test("a missing or unrecognized verdict is never read as agreement", () => {
  assert.equal(verdictReading(null, "NEEDS_REVIEW").agreement.key, "UNAVAILABLE");
  assert.equal(verdictReading(null, "NEEDS_REVIEW").tone, "blocked");
  const odd = verdictReading({ decision: { code: "SOMETHING_NEW", label: "?" }, agreement: "MAYBE", blockingReasons: [] }, "HOLD");
  assert.equal(odd.agreement.key, "UNKNOWN");
  assert.equal(odd.agreement.tone, "blocked");
  assert.equal(odd.tone, "blocked", "an unknown decision is a non-action");
  const differs = verdictReading({ decision: { code: "INSUFFICIENT_EVIDENCE", label: "No action" }, agreement: "DIFFERS",
    suggestedState: null, blockingReasons: ["EVIDENCE_STALE", "SOMETHING_NEW"] }, "MAPPING_AMBIGUOUS");
  assert.match(differs.agreement.text, /no longer suggests/);
  assert.deepEqual(differs.blockers, ["Evidence stale — revalidation required.", "something new — blocked."]);
});

test("only the server's USABLE reads as a valid approval, and valid is never ready", withFixtures, () => {
  const words = fx.approvals.map((a) => [a, approvalUsability(a.usability)]);
  for (const [a, u] of words) {
    assert.equal(u.usable, a.usability.status === "USABLE" && a.usability.usable === true, a.id);
    assert.doesNotMatch(u.label, /\bready\b|usable now/i);
    if (u.usable) assert.match(u.note, /own checks/);
    else assert.equal(u.note, null);
  }
  assert.ok(words.some(([, u]) => u.usable) && words.some(([, u]) => u.label === "Expired"));
});

test("a missing, contradictory, or unknown usability answer is not usable", () => {
  assert.equal(approvalUsability(undefined).usable, false);
  assert.equal(approvalUsability({ status: "USABLE", usable: false, problems: ["x"] }).usable, false);
  assert.equal(approvalUsability({ status: "SOMETHING_NEW", usable: true, problems: [] }).usable, false);
  assert.equal(approvalUsability({ status: "SOMETHING_NEW", usable: false, problems: [] }).label, "Not usable");
  assert.equal(approvalUsability({ status: "EPOCH_SUPERSEDED", usable: false, problems: ["e"] }).label,
    "Superseded: the candidate re-entered review");
});

// --- OGWA-APPROVAL-ATTENTION-01 -------------------------------------------------------------------

const NEVER = /\b(ready|executable|approved to delete)\b|ready to execute/i;

test("expiring soon is the server's flag, and only on a valid approval", () => {
  const soon = approvalUsability({ status: "USABLE", usable: true, problems: [], expiringSoon: true });
  assert.equal(soon.expiringSoon, true);
  assert.equal(soon.label, "Valid for its stage");
  assert.match(soon.note, /own checks/, "an expiring approval still says its step has its own checks");
  assert.equal(approvalUsability({ status: "USABLE", usable: true, problems: [] }).expiringSoon, false, "no flag, no warning");
  for (const u of [{ status: "EXPIRED", usable: false, problems: ["x"], expiringSoon: true },
    { status: "EPOCH_SUPERSEDED", usable: false, problems: ["e"], expiringSoon: true },
    { status: "USABLE", usable: false, problems: ["x"], expiringSoon: true }, undefined]) {
    assert.equal(approvalUsability(u).expiringSoon, false, JSON.stringify(u));
  }
});

test("no approval reading or filter is worded ready or executable", withFixtures, () => {
  for (const a of fx.approvals) {
    for (const expiringSoon of [false, true]) {
      const u = approvalUsability({ ...a.usability, expiringSoon });
      assert.doesNotMatch(`${u.label} ${u.note || ""}`, NEVER, a.id);
    }
  }
  assert.deepEqual(APPROVAL_FILTERS.map((f) => f.key), ["all", "valid", "expiring-soon", "expired"]);
  for (const f of APPROVAL_FILTERS) assert.doesNotMatch(f.label, NEVER);
});
