// Unit tests for the policy-version wording (app/ui/static/js/policy.js), OGWA-DEMO-02.
// Run by tests/test_ui_policy.py, which first writes fixtures produced by the real API over a
// freshly seeded Null Meridian store (UI_POLICY_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  CONDITION_STATUS_TEXT, conditionRank, conditionStatusText, evidenceLabels, explanationAnswers, policyAgainstInForce, policyName,
} from "../../app/ui/static/js/policy.js";

const fixturePath = process.env.UI_POLICY_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_POLICY_FIXTURES is not set (run tests/test_ui_policy.py)" };
const nm = (key) => fx.nullMeridian[key];

test("every condition status has its own label, and an unknown one is never satisfied", () => {
  const labels = Object.values(CONDITION_STATUS_TEXT).map((t) => t.label);
  assert.equal(new Set(labels).size, labels.length);
  const unknown = conditionStatusText("PROBABLY_FINE");
  assert.equal(unknown.tone, "blocked");
  assert.match(unknown.label, /Unrecognized/);
  assert.notEqual(conditionStatusText("NOT_PROVEN").tone, "neutral", "not proven is never reassuring");
});

test("a decision that recorded no policy says so, and is never shown as the current one", () => {
  const none = policyName(null);
  assert.equal(none.known, false);
  assert.match(none.text, /Not recorded/);
  assert.doesNotMatch(none.text, /none/i);
  assert.equal(policyAgainstInForce(null, { policyDigest: "sha256:x" }).current, null);
});

test("explanationAnswers needs an explanation and counts unknown statuses", () => {
  assert.equal(explanationAnswers(null), null);
  assert.equal(explanationAnswers({}), null);
  const odd = explanationAnswers({ conditions: [{ key: "X", status: "MAYBE", evidence: [] }], manualReview: {} });
  assert.equal(odd.unrecognized.length, 1);
  assert.equal(odd.satisfied.length, 0);
});

test("every Null Meridian decision names NM-LIFECYCLE-004 v1.2.0 and agrees with the assessment", withFixtures, () => {
  for (const [key, detail] of Object.entries(fx.nullMeridian)) {
    const e = explanationAnswers(detail.decisionExplanation);
    assert.ok(e, key);
    assert.equal(e.policy.text, "NM-LIFECYCLE-004 v1.2.0", key);
    assert.equal(e.policy.tone, "info", key);
    assert.match(e.policy.detail, /Recorded version 2/, key);
    assert.equal(e.decision.code, detail.evidenceAssessment.decision.code, key);
    assert.equal(policyAgainstInForce(detail.decisionExplanation.policy, detail.policy).current, true, key);
    assert.equal(e.unrecognized.length, 0, key);
  }
});

test("NM-C10: ambiguous and missing evidence forces manual review", withFixtures, () => {
  const e = explanationAnswers(nm("NM-C10").decisionExplanation);
  assert.equal(e.forced.answer, "Yes");
  assert.equal(e.forced.tone, "blocked");
  assert.deepEqual(e.forced.because.map((c) => c.decision).slice(0, 2), ["CONFLICTING_EVIDENCE", "AMBIGUOUS_IDENTITY"]);
  assert.ok(e.notProven.some((c) => c.key === "EXACT_MAPPING"));
  assert.ok(e.change.length > 0);
});

test("NM-C01: complete evidence, refused only by the next step's rules", withFixtures, () => {
  const e = explanationAnswers(nm("NM-C01").decisionExplanation);
  assert.equal(e.forced.answer, "No");
  assert.deepEqual(e.notSatisfied.map((c) => c.key), ["NEXT_STEP_RULES"]);
  assert.equal(e.notProven.length, 0);
  assert.match(e.notSatisfied[0].rule, /168 h/);
});

test("NM-C08's history keeps v1.1.0 and is marked superseded, never relabelled", withFixtures, () => {
  const inForce = nm("NM-C08").policy;
  assert.ok(fx.decisionsNM_C08.length >= 5);
  for (const record of [...fx.decisionsNM_C08, ...fx.approvalsNM_C08]) {
    assert.equal(policyName(record.policy).text, "NM-LIFECYCLE-004 v1.1.0");
    const against = policyAgainstInForce(record.policy, inForce);
    assert.equal(against.current, false);
    assert.match(against.text, /Superseded: judged by NM-LIFECYCLE-004 v1\.1\.0; NM-LIFECYCLE-004 v1\.2\.0 is in force now/);
  }
});

test("an edited release shows as a difference", withFixtures, () => {
  const ref = { ...fx.decisionsNM_C08[0].policy, publishedRelease: "DIFFERS_FROM_RECORDED" };
  const name = policyName(ref);
  assert.equal(name.tone, "caution");
  assert.match(name.detail, /differs from what was recorded/);
});

test("the policy view lists both releases and the versions that record them", withFixtures, () => {
  assert.deepEqual(fx.policy.releases.map((r) => r.name), ["NM-LIFECYCLE-004 v1.1.0", "NM-LIFECYCLE-004 v1.2.0"]);
  assert.deepEqual(fx.policy.versions.map((v) => v.release && v.release.version), ["1.1.0", "1.2.0"]);
  assert.equal(fx.policy.inForce.name, "NM-LIFECYCLE-004 v1.2.0");
  assert.equal(fx.policy.editableViaApi, false);
});

test("the classic world's unrecorded policy is labelled, unnamed, and its seeded history says not recorded", withFixtures, () => {
  const e = explanationAnswers(fx.classic.detail.decisionExplanation);
  assert.match(e.policy.text, /Unrecorded demo policy \(no release identity\)/);
  assert.equal(e.policy.tone, "caution");
  assert.ok(fx.classic.decisions.length > 0);
  for (const d of fx.classic.decisions) assert.equal(policyName(d.policy).known, false);
});

test("evidence keys are shown with the assessment's labels", withFixtures, () => {
  const detail = nm("NM-C10");
  const mapping = detail.decisionExplanation.conditions.find((c) => c.key === "EXACT_MAPPING");
  const labels = evidenceLabels(mapping.evidence, detail.evidenceAssessment.items);
  assert.ok(labels.includes("Identity mapping (Okta group to AD group)"));
  assert.deepEqual(evidenceLabels(["unknown:key"], []), ["unknown:key"]);
});

test("sorting by status puts what stops the decision first, and an unknown status before all", () => {
  const order = ["SATISFIED", "NOT_APPLICABLE", "MAYBE", "NOT_PROVEN", "NOT_SATISFIED"]
    .sort((a, b) => conditionRank(a) - conditionRank(b));
  assert.deepEqual(order, ["MAYBE", "NOT_SATISFIED", "NOT_PROVEN", "SATISFIED", "NOT_APPLICABLE"]);
});
