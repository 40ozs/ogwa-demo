// Unit tests for the remediation-drill wording (app/ui/static/js/drill.js), OGWA-DEMO-03.
// Run by tests/test_ui_drill.py, which first writes fixtures produced by the real API over
// freshly seeded synthetic worlds (UI_DRILL_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  attemptRows, bindingText, chainFacts, DRILL_STAGES, drillOutcome, elapsedText, isVerified, ledgerRows, MODE_HEADLINE,
  MODE_TEXT, modeBanner, stageFor, STEP_TONE, stepFacts, stepTone,
} from "../../app/ui/static/js/drill.js";

const fixturePath = process.env.UI_DRILL_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_DRILL_FIXTURES is not set (run tests/test_ui_drill.py)" };
const every = () => [...Object.values(fx.nmC11), ...Object.values(fx.classicDelete)];
const clone = (x) => JSON.parse(JSON.stringify(x));

// --- the states and their tones --------------------------------------------------------------------

test("every server state has a tone, and an unknown state is blocked", withFixtures, () => {
  assert.deepEqual(Object.keys(STEP_TONE).sort(), Object.keys(fx.catalog.labels).sort());
  assert.equal(stepTone("SOMETHING_NEW"), "blocked");
  assert.equal(stepTone("POST_ACTION_VERIFIED"), "info", "the best tone is info: there is no reassuring tone");
  for (const [state, tone] of Object.entries(STEP_TONE)) {
    assert.ok(["blocked", "caution", "info", "neutral"].includes(tone), state);
    if (state !== "POST_ACTION_VERIFIED") assert.notEqual(tone, "info", `${state} is never shown as done`);
  }
  assert.equal(STEP_TONE.EXECUTED, "caution", "executed but not verified is not done");
});

test("the drill stage follows the candidate's state, and nothing else offers a drill", () => {
  assert.equal(stageFor("APPROVED").operation, "OKTA_GROUP_UNASSIGN");
  assert.equal(stageFor("QUARANTINE_DRY_RUN").targetField, "adGroupId");
  assert.equal(stageFor("DELETION_APPROVED").stage, "AD_DELETION");
  for (const state of ["NEEDS_REVIEW", "HOLD", "PROTECTED", "BLOCKED", "RETIRED", "SOMETHING_NEW"]) {
    assert.equal(stageFor(state), null, state);
  }
  assert.equal(Object.keys(DRILL_STAGES).length, 6);
  assert.match(MODE_TEXT.DRY_RUN.help, /no state changes/i);
  assert.doesNotMatch(MODE_TEXT.SYNTHETIC_EXECUTION.help, /no state changes/i);
});

// --- dry run vs execution ---------------------------------------------------------------------------

test("a dry run and an execution can never look alike", withFixtures, () => {
  const labels = fx.catalog.labels;
  assert.equal(labels.DRY_RUN, "DRY RUN — NO STATE CHANGED");
  assert.equal(labels.EXECUTED, "EXECUTED — SYNTHETIC DEMO");
  for (const drill of every()) {
    const o = drillOutcome(drill);
    if (drill.mode === "DRY_RUN") {
      assert.equal(o.headline, "DRY RUN — NO STATE CHANGED");
      assert.equal(o.tone, "neutral");
      assert.equal(o.verified, false);
      assert.match(o.detail, /Nothing was submitted/);
    } else {
      assert.doesNotMatch(o.headline, /DRY RUN|NO STATE CHANGED/, drill.scenario.key);
      for (const step of drill.steps) assert.doesNotMatch(step.label, /DRY RUN|NO STATE CHANGED/);
    }
  }
});

test("each scenario's real outcome is worded by its final state", withFixtures, () => {
  for (const [key, drill] of Object.entries(fx.nmC11)) {
    const o = drillOutcome(drill);
    if (key === "DRY_RUN") continue;
    const expected = fx.catalog.items.find((s) => s.key === key).expectedFinalState;
    assert.equal(drill.finalState, expected, key);
    assert.equal(o.headline, fx.catalog.labels[expected], key);
    assert.equal(o.verified, expected === "POST_ACTION_VERIFIED", key);
    assert.equal(o.tone, expected === "POST_ACTION_VERIFIED" ? "info" : "blocked", key);
  }
  assert.match(drillOutcome(fx.nmC11.TIMEOUT_NOT_APPLIED).detail, /2 submissions, 1 change applied inside the fixture/);
  assert.match(drillOutcome(fx.nmC11.TIMEOUT_AFTER_APPLY).detail, /1 submission, 1 change applied/);
  assert.match(drillOutcome(fx.nmC11.ACKNOWLEDGED_NOT_APPLIED).detail, /^Not a success/);
  assert.match(drillOutcome(fx.nmC11.TIMEOUT_UNVERIFIABLE).detail, /not retried/);
});

// --- success needs verification ------------------------------------------------------------------

test("only a verified drill whose record agrees counts as verified", withFixtures, () => {
  const verified = fx.nmC11.TIMEOUT_NOT_APPLIED;
  assert.equal(isVerified(verified), true);
  const claimed = clone(fx.nmC11.ACKNOWLEDGED_NOT_APPLIED);
  claimed.succeeded = true;
  assert.equal(isVerified(claimed), false);
  assert.equal(drillOutcome(claimed).tone, "blocked");
  assert.equal(drillOutcome(claimed).headline, "Inconsistent drill result");
  const unexecuted = clone(verified);
  unexecuted.steps = unexecuted.steps.filter((s) => s.state !== "EXECUTED");
  assert.equal(isVerified(unexecuted), false, "a verification without an execution is not a verified change");
  const mismatched = clone(verified);
  mismatched.finalState = "VERIFICATION_FAILED";
  assert.equal(drillOutcome(mismatched).tone, "blocked");
});

test("a dry run that reports a change is shown as inconsistent", withFixtures, () => {
  const dry = clone(fx.nmC11.DRY_RUN);
  dry.provider.mutationsApplied = 1;
  assert.equal(drillOutcome(dry).headline, "Inconsistent drill result");
  const dry2 = clone(fx.nmC11.DRY_RUN);
  dry2.provider.stateChanged = true;
  assert.equal(drillOutcome(dry2).tone, "blocked");
});

test("an empty or unknown result is never reassuring", () => {
  for (const drill of [null, {}, { steps: [] }]) assert.equal(drillOutcome(drill).tone, "blocked");
  const odd = { mode: "SYNTHETIC_EXECUTION", finalState: "PAUSED", steps: [{ state: "PAUSED", label: "PAUSED" }],
    modeBanner: { headline: "SYNTHETIC EXECUTION", detail: "x" } };
  assert.equal(drillOutcome(odd).tone, "blocked");
  assert.match(drillOutcome(odd).headline, /Unknown drill state/);
});

// --- the steps ------------------------------------------------------------------------------------

test("an unknown outcome shows the timeout and the reads that decided it", withFixtures, () => {
  const steps = fx.nmC11.TIMEOUT_NOT_APPLIED.steps;
  const unknown = Object.fromEntries(stepFacts(steps[1]));
  assert.match(unknown["Provider answer"], /no answer \(timeout\)/);
  const verifying = Object.fromEntries(stepFacts(steps[2]));
  assert.match(verifying["Target observed"], /not applied/);
  const unreadable = Object.fromEntries(stepFacts(fx.nmC11.TIMEOUT_UNVERIFIABLE.steps[2]));
  assert.equal(unreadable.Reads, "read failed, read failed");
  assert.match(unreadable["Target observed"], /still unknown/);
  assert.equal(elapsedText(steps[1].at, steps[0].at), "+30 s", "the timeout takes 30 s on the synthetic clock");
});

test("the fixture's ledger shows one applied change and no duplicate", withFixtures, () => {
  const rows = ledgerRows(fx.nmC11.TIMEOUT_NOT_APPLIED);
  assert.deepEqual(rows.map((r) => r.applied), ["Not applied", "Applied"]);
  assert.equal(new Set(rows.map((r) => r.actor)).size, 1, "both submissions carry the same operation id");
  assert.deepEqual(ledgerRows(fx.nmC11.TIMEOUT_AFTER_APPLY).map((r) => r.applied), ["Applied"]);
  assert.deepEqual(ledgerRows(fx.nmC11.DRY_RUN), []);
});

test("an AD deletion drill reads the same way", withFixtures, () => {
  const o = drillOutcome(fx.classicDelete.TIMEOUT_NOT_APPLIED);
  assert.equal(o.headline, "POST-ACTION VERIFIED");
  assert.equal(o.verified, true);
  assert.equal(fx.classicDelete.TIMEOUT_NOT_APPLIED.plannedTransition.after.exists, false);
  assert.equal(drillOutcome(fx.classicDelete.DRY_RUN).headline, "DRY RUN — NO STATE CHANGED");
});

// --- OGWA-DEMO-04: the mode banner, the authorization chain, the attempts ----------------------------

test("every drill carries a mode banner that matches its mode, and the two can never be confused", withFixtures, () => {
  for (const drill of every()) {
    const b = modeBanner(drill);
    assert.equal(b.mode, drill.mode);
    assert.equal(b.headline, MODE_HEADLINE[drill.mode]);
    if (drill.mode === "DRY_RUN") {
      assert.equal(b.headline, "DRY RUN — NO STATE CHANGED");
      assert.equal(b.tone, "neutral");
    } else {
      assert.equal(b.headline, "SYNTHETIC EXECUTION");
      assert.match(b.detail, /^No external provider or persistent environment was modified\./);
      assert.doesNotMatch(b.headline + b.detail, /DRY RUN|NO STATE CHANGED/);
      assert.equal(b.tone, "caution", "a synthetic execution is never shown in the dry run's neutral tone");
    }
  }
});

test("a missing or mismatched mode banner is blocked and makes the result inconsistent", withFixtures, () => {
  const run = clone(fx.nmC11.TIMEOUT_NOT_APPLIED);
  delete run.modeBanner;
  assert.equal(modeBanner(run).tone, "blocked");
  assert.equal(drillOutcome(run).headline, "Inconsistent drill result");
  const swapped = clone(fx.nmC11.TIMEOUT_NOT_APPLIED);
  swapped.modeBanner = clone(fx.nmC11.DRY_RUN.modeBanner);
  assert.equal(modeBanner(swapped).headline, "Unknown drill mode");
  assert.equal(drillOutcome(swapped).tone, "blocked");
  assert.equal(isVerified(swapped), true, "the steps still verify; only the banner is wrong");
});

test("verified needs the server's confirmed post-action read, not just the final state", withFixtures, () => {
  const run = clone(fx.nmC11.TIMEOUT_NOT_APPLIED);
  assert.equal(run.postActionVerification.result, "CONFIRMED");
  assert.equal(isVerified(run), true);
  for (const result of ["FAILED", "NOT_REACHED", "SOMETHING_NEW", undefined]) {
    const forged = clone(run);
    forged.postActionVerification = { ...forged.postActionVerification, result };
    assert.equal(isVerified(forged), false, String(result));
    assert.equal(drillOutcome(forged).tone, "blocked", String(result));
  }
  assert.equal(fx.nmC11.ACKNOWLEDGED_NOT_APPLIED.postActionVerification.result, "FAILED");
  assert.equal(fx.nmC11.DRY_RUN.postActionVerification.result, "NOT_REACHED");
});

test("the chain names the policy, the decision, the approval, and the operation", withFixtures, () => {
  const r = fx.nmC11Responses.TIMEOUT_NOT_APPLIED;
  const rows = Object.fromEntries(chainFacts(r.chain, r.authorization));
  assert.match(rows["Policy in force (the gates' rules)"], /^NM-LIFECYCLE-004 v1\.2\.0, recorded version 2$/);
  assert.match(rows["Lifecycle decision"], /^dec_[0-9a-f]{32}: NEEDS_REVIEW → APPROVED \(audit event #\d+\), recorded under NM-LIFECYCLE-004 v1\.2\.0$/);
  assert.match(rows["Approval (control)"], /^apr_[0-9a-f]{32}: OKTA_UNASSIGN, by synthetic\.reviewer\.one/);
  assert.equal(rows["Decision's policy"], "Judged by the version in force");
  assert.equal(rows["Approval's policy"], "Judged by the version in force");
  assert.equal(rows["Operation id (every attempt)"], r.drill.operationId);
  assert.match(rows["Post-action verification"], /^Confirmed/);
  assert.equal(rows["Final state"], "POST-ACTION VERIFIED");
  assert.equal(rows.Recorded, "No: a drill records nothing");
  assert.equal(chainFacts(null, r.authorization), null, "no chain is said, not invented");
  const dry = Object.fromEntries(chainFacts(fx.nmC11Responses.DRY_RUN.chain, fx.nmC11Responses.DRY_RUN.authorization));
  assert.equal(dry["Execution mode"], "Dry run");
  assert.match(dry["Post-action verification"], /^Not reached/);
});

test("a binding other than the version in force is never worded as acceptable", () => {
  assert.equal(bindingText("IN_FORCE").tone, "info");
  for (const b of ["SUPERSEDED", "NOT_RECORDED", "SOMETHING_NEW", undefined]) assert.equal(bindingText(b).tone, "blocked", String(b));
});

test("each attempt shows its answer, its verification read, and what followed", withFixtures, () => {
  const rows = attemptRows(fx.nmC11Responses.TIMEOUT_NOT_APPLIED.chain);
  assert.deepEqual(rows.map((r) => [r.attempt, r.answer, r.next]),
    [[1, "no answer (timeout)", "RETRY_PERMITTED"], [2, "says applied", "EXECUTED"]]);
  assert.match(rows[0].verification, /not applied/);
  assert.deepEqual(attemptRows(fx.nmC11Responses.DRY_RUN.chain), [], "a dry run submits nothing");
});
