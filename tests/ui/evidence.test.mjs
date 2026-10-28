// Unit tests for the evidence-assessment wording (app/ui/static/js/evidence.js), OGWA-DEMO-01.
// Run by tests/test_ui_evidence.py, which first writes fixtures produced by the real API over
// both freshly seeded synthetic worlds (UI_EVIDENCE_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { membershipFacts } from "../../app/ui/static/js/assess.js";
import {
  decisionText, EVIDENCE_STATE_TEXT, otherAssignmentsFact, pendingStepText, requiredText, reviewerAnswers, stateText,
} from "../../app/ui/static/js/evidence.js";

const fixturePath = process.env.UI_EVIDENCE_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_EVIDENCE_FIXTURES is not set (run tests/test_ui_evidence.py)" };

const nm = (key) => fx.nullMeridian[key].evidenceAssessment;
const classic = (key) => fx.classic[key].evidenceAssessment;
const every = () => [...Object.values(fx.classic), ...Object.values(fx.nullMeridian)].map((d) => d.evidenceAssessment);
const MISSING = ["NOT_COLLECTED", "SOURCE_UNAVAILABLE", "PARTIAL", "NOT_COUNTED_SOURCE"];

// --- the states stay distinct ---------------------------------------------------------------------

test("every evidence state has its own label, and nothing missing is called none", () => {
  const labels = Object.values(EVIDENCE_STATE_TEXT).map((t) => t.label);
  assert.equal(new Set(labels).size, labels.length);
  for (const state of MISSING) {
    assert.doesNotMatch(stateText(state).label, /none/i, state);
    assert.notEqual(stateText(state).tone, "info", state);
  }
  assert.match(stateText("REPORTS_NONE").label, /none/i);
  assert.match(stateText("NOT_COLLECTED").meaning, /not none/i);
  assert.equal(stateText("SOMETHING_NEW").tone, "blocked", "an unknown state is never reassuring");
});

test("NM-C10 shows every kind of imperfect evidence, each with its own state", withFixtures, () => {
  const a = nm("NM-C10");
  const byState = {};
  for (const item of a.items) (byState[item.state] ||= []).push(item.label);
  for (const state of ["CONFIRMED", "REPORTS_NONE", "NOT_COLLECTED", "SOURCE_UNAVAILABLE", "PARTIAL", "AMBIGUOUS", "CONFLICTING"]) {
    assert.ok(byState[state] && byState[state].length, `NM-C10 has a ${state} source`);
  }
  // Not collected and "the source says none" are different rows with different labels.
  const none = a.items.filter((i) => i.state === "REPORTS_NONE").map((i) => stateText(i.state).label);
  const unread = a.items.filter((i) => i.state === "NOT_COLLECTED").map((i) => stateText(i.state).label);
  assert.ok(none.every((l) => l === "Source says none"));
  assert.ok(unread.every((l) => l === "Not collected"));
  // The conflicting items keep what each read said underneath.
  const conflicting = a.items.filter((i) => i.state === "CONFLICTING");
  assert.deepEqual(conflicting.map((i) => i.key).sort(), ["ad-group", "dependency:AD_GROUP_MEMBERS"]);
  assert.deepEqual(conflicting.map((i) => i.baseState).sort(), ["CONFIRMED", "REPORTS_NONE"]);
});

// --- the six reviewer questions ---------------------------------------------------------------------

test("NM-C10 answers the six reviewer questions with a non-action decision", withFixtures, () => {
  const r = reviewerAnswers(nm("NM-C10"));
  assert.match(r.issue, /KB-Admins/);
  assert.ok(r.supporting.some((i) => i.key.startsWith("usage:")), "zero sign-ins supports the proposal");
  assert.ok(r.supporting.every((i) => !MISSING.includes(i.state) && i.state !== "CONFLICTING"));
  const against = new Set(r.against.map((i) => i.state));
  for (const state of ["CONFLICTING", "SOURCE_UNAVAILABLE", "NOT_COLLECTED", "PARTIAL", "AMBIGUOUS"]) assert.ok(against.has(state), state);
  assert.equal(r.identity.state, "PROBABLE");
  assert.equal(r.identity.label, "Probable, not proven");
  assert.equal(r.identity.tone, "blocked");
  assert.equal(r.decision.code, "CONFLICTING_EVIDENCE");
  assert.equal(r.decision.tone, "blocked");
  assert.equal(r.decision.eligible, false);
  assert.deepEqual(r.constraints.map((c) => c.decision).slice(0, 4),
    ["CONFLICTING_EVIDENCE", "AMBIGUOUS_IDENTITY", "BLOCKED_ON_REQUIRED_SOURCE", "INSUFFICIENT_EVIDENCE"]);
  assert.equal(r.pending.status, "Rules would refuse");
  assert.equal(r.conflicts.length, 1);
  const needed = r.needed.join("\n");
  assert.match(needed, /Resolve the conflict/);
  assert.match(needed, /Re-run AD nesting/);
  assert.match(needed, /Complete AD ACL references/);
  assert.match(needed, /Collect GPO references/);
  assert.match(needed, /different operator approves it/);
});

test("without an assessment nothing is shown as safe", () => {
  assert.equal(reviewerAnswers(null), null);
  assert.equal(reviewerAnswers({}), null);
  const unknown = decisionText({ code: "SOMETHING_NEW", label: "x" });
  assert.equal(unknown.tone, "blocked");
  assert.equal(unknown.eligible, false);
  assert.equal(decisionText(null).eligible, false);
  // An eligible code without the server's eligibility flag is not eligible.
  assert.equal(decisionText({ code: "ELIGIBLE_FOR_HUMAN_APPROVAL", label: "x" }).eligible, false);
});

// --- the decision across both worlds ------------------------------------------------------------------

test("no assessment anywhere is an approval or makes anything automatically remediable", withFixtures, () => {
  for (const a of every()) {
    assert.equal(a.isApproval, false);
    assert.equal(a.decision.autoRemediationEligible, false);
    const eligible = a.decision.code === "ELIGIBLE_FOR_HUMAN_APPROVAL";
    assert.equal(a.decision.eligibleForHumanApproval, eligible);
    assert.equal(decisionText(a.decision).eligible, eligible);
    if (eligible) {
      assert.deepEqual(a.constraints, []);
      assert.ok(a.pendingStep.open && a.pendingStep.evaluated && a.pendingStep.accepts);
      for (const item of a.items.filter((i) => i.required)) assert.ok(item.decisionGrade, `${a.candidateId} ${item.key}`);
    }
  }
});

test("missing, failed, partial, ambiguous, or conflicting required evidence never shows as eligible", withFixtures, () => {
  for (const a of every()) {
    const weak = a.items.some((i) => i.required && [...MISSING, "AMBIGUOUS", "CONFLICTING"].includes(i.state));
    if (weak) assert.notEqual(a.decision.code, "ELIGIBLE_FOR_HUMAN_APPROVAL", a.candidateId);
    // A source that was not read, failed, stopped part-way, was only attested, or names no
    // established identity never counts as supporting the proposal.
    for (const item of a.items.filter((i) => [...MISSING, "AMBIGUOUS"].includes(i.state))) {
      assert.notEqual(item.stance, "SUPPORTS", `${a.candidateId} ${item.key} ${item.state}`);
    }
  }
});

test("the eligible paths say they are not approvals", withFixtures, () => {
  const fresh = reviewerAnswers(nm("NM-C01-refreshed"));
  assert.equal(fresh.decision.code, "ELIGIBLE_FOR_HUMAN_APPROVAL");
  assert.equal(fresh.decision.tone, "info");
  assert.match(fresh.decision.label, /not an approval/);
  assert.equal(fresh.pending.status, "Rules would accept");
  assert.match(fresh.pending.text, /nothing is executed/);
  assert.match(fresh.notes.join(" "), /never an approval/);
  assert.equal(classic("S16").decision.code, "ELIGIBLE_FOR_HUMAN_APPROVAL");
  // The same candidate with week-old evidence: the lifecycle refuses the approval.
  assert.equal(nm("NM-C01").decision.code, "LIFECYCLE_RULES_NOT_MET");
  assert.match(reviewerAnswers(nm("NM-C01")).needed.join(" "), /stale for APPROVAL/);
});

test("S07: the Okta step's rules would accept, but OGWA does not call the evidence sufficient", withFixtures, () => {
  const r = reviewerAnswers(classic("S07"));
  assert.equal(r.decision.code, "INSUFFICIENT_EVIDENCE");
  assert.equal(r.pending.status, "Rules would accept");
  assert.match(r.notes.join(" "), /would still accept a named human's approval/);
  assert.ok(classic("S07").items.filter((i) => i.kind === "dependency").every((i) => i.state === "NOT_COLLECTED" || i.state === "REPORTS_NONE"));
});

test("terminal and stopped candidates are worded as such", withFixtures, () => {
  assert.equal(reviewerAnswers(nm("NM-C09")).decision.code, "TERMINAL");
  assert.equal(reviewerAnswers(nm("NM-C09")).pending.status, "None");
  assert.equal(reviewerAnswers(nm("NM-C05")).decision.code, "NO_ACTION_BLOCKED");
  assert.equal(reviewerAnswers(nm("NM-C04")).identity.state, "AMBIGUOUS");
  assert.equal(reviewerAnswers(nm("NM-C07")).identity.state, "NOT_FOUND");
  assert.equal(reviewerAnswers(classic("S13")).identity.state, "NOT_ESTABLISHED");
  assert.equal(pendingStepText(null).status, "None");
  assert.equal(pendingStepText({ stage: "AD_QUARANTINE", open: false }).status, "Not open");
});

test("required is worded with the lifecycle stages that read the item", withFixtures, () => {
  const items = Object.fromEntries(nm("NM-C10").items.map((i) => [i.key, i]));
  assert.match(requiredText(items["mapping"]), /Okta unassignment, AD quarantine, AD deletion/);
  assert.match(requiredText(items["dependency:AD_NESTED_MEMBERSHIP"]), /AD quarantine, AD deletion/);
  assert.doesNotMatch(requiredText(items["dependency:AD_NESTED_MEMBERSHIP"]), /Okta unassignment/);
  assert.equal(requiredText({ required: false, neededFor: [] }), "Not required");
});

// --- regressions: missing never displayed as none ----------------------------------------------------

test("other Okta assignments are never 'none' without a classification (regression)", () => {
  assert.deepEqual(otherAssignmentsFact(0, null), { value: "Unknown: no classification", tone: "blocked" });
  assert.equal(otherAssignmentsFact(0, { reasonCodes: ["OTHER_ASSIGNMENTS_UNKNOWN"] }).value, "Not checked");
  assert.equal(otherAssignmentsFact(0, { reasonCodes: ["SINGLE_OKTA_ASSIGNMENT"] }).value, "None (complete check)");
  assert.equal(otherAssignmentsFact(2, null).tone, "blocked");
});

test("an unread AD member count is unknown, never a number (regression)", () => {
  const ad = { id: "adg_x", exists: true, memberCount: null };
  const facts = membershipFacts({ adGroup: ad, dependencies: [] });
  assert.equal(facts.direct.basis, "unavailable");
  assert.match(facts.direct.value, /^Unknown/);
  assert.doesNotMatch(facts.direct.value, /null|undefined|^0/);
  assert.equal(membershipFacts({ adGroup: { ...ad, memberCount: 0 }, dependencies: [] }).direct.value, "0 (AD member attribute)");
});
