// Unit tests for the UI's plain-language assessment (app/ui/static/js/assess.js).
// Run by tests/test_ui_assess.py, which first writes fixtures produced by the real API over
// a freshly seeded synthetic world (UI_ASSESS_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  actionPlan, candidateBanners, errorText, evidenceCondition, futureDatedSubjects, mappingInfo, membershipFacts,
  protectionInfo, staleSubjects, stateInfo, STATE_INFO, TONES, UI_TRANSITIONS, usageSummary,
} from "../../app/ui/static/js/assess.js";

const fixturePath = process.env.UI_ASSESS_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_ASSESS_FIXTURES is not set (run tests/test_ui_assess.py)" };

const scenario = (key) => fx.scenarios[key];
const banners = (key, who = "SECURITY") => candidateBanners(scenario(key).detail[who], scenario(key).evidence);
const headlines = (key) => banners(key).map((b) => b.headline);

// --- D98: name-only, ambiguous, not-found, and missing stay distinct ------------------------------

test("S08, S09, S10 and S13 have distinct mapping descriptions (D98)", withFixtures, () => {
  const infos = ["S08", "S09", "S10", "S13"].map((k) => mappingInfo(scenario(k).evidence.mapping, scenario(k).evidence.oktaGroup));
  assert.deepEqual(infos.map((i) => i.key), ["NAME_ONLY", "AMBIGUOUS", "NOT_FOUND", "MISSING"]);
  assert.equal(new Set(infos.map((i) => i.headline)).size, 4);
  for (const info of infos) {
    assert.equal(info.tone, "blocked");
    assert.equal(info.blocksAutomation, true);
    assert.match(info.headline, /automatic retirement blocked/);
  }
});

test("the dangerous-state wording appears where it applies", withFixtures, () => {
  assert.ok(headlines("S09").includes("Mapping ambiguous — automatic retirement blocked."));
  assert.ok(headlines("S12").includes("Dependency coverage incomplete — AD deletion blocked."));
  assert.ok(headlines("S11").includes("Evidence stale — revalidation required."));
  assert.ok(headlines("S08").includes("Name-only match — automatic retirement blocked."));
  assert.ok(headlines("S10").includes("Mapped AD group not found — automatic retirement blocked."));
});

// --- D97: unavailable, unverified, and unchecked are not "stale" -----------------------------------

test("S13: unverified SID and incomplete collection, never called stale (D97)", withFixtures, () => {
  const s13 = banners("S13");
  const text = s13.map((b) => `${b.headline} ${b.detail || ""}`).join("\n");
  assert.ok(s13.some((b) => b.headline === "Evidence incomplete — a collection did not finish."));
  assert.ok(s13.some((b) => b.headline === "No mapping evidence — automatic retirement blocked."));
  assert.match(text, /directory SID/);
  assert.match(text, /unverified/);
  assert.doesNotMatch(text, /stale/i);
  const condition = evidenceCondition(scenario("S13").detail.SECURITY.classification);
  assert.deepEqual([condition.stale, condition.unavailable], [false, true]);
});

test("S07: incomplete coverage is not called stale, and its diversion is EVIDENCE_INCOMPLETE", withFixtures, () => {
  // Owner decision: incomplete and stale are different lifecycle states (migration 0009).
  assert.equal(scenario("S07").detail.SECURITY.classification.lifecycleDiversion, "EVIDENCE_INCOMPLETE");
  assert.equal(scenario("S11").detail.SECURITY.classification.lifecycleDiversion, "STALE_EVIDENCE");
  assert.match(stateInfo("EVIDENCE_INCOMPLETE").label, /incomplete/);
  assert.doesNotMatch(`${stateInfo("EVIDENCE_INCOMPLETE").label} ${stateInfo("EVIDENCE_INCOMPLETE").text}`, /stale/i);
  assert.match(stateInfo("STALE_EVIDENCE").label, /stale/);
  const text = headlines("S07").join("\n");
  assert.doesNotMatch(text, /stale/i);
  assert.match(text, /AD membership not checked/);
  assert.match(text, /AD nesting not checked/);
  assert.match(text, /Dependency coverage incomplete/);
  const condition = evidenceCondition(scenario("S07").detail.SECURITY.classification);
  assert.deepEqual([condition.stale, condition.unchecked], [false, true]);
});

test("S11: genuinely stale evidence is called stale, once, with its record count", withFixtures, () => {
  const stale = banners("S11").filter((b) => b.headline === "Evidence stale — revalidation required.");
  assert.equal(stale.length, 1);
  assert.ok(stale[0].count > 1);
  assert.equal(evidenceCondition(scenario("S11").detail.SECURITY.classification).stale, true);
});

test("no wording promises that re-collection fixes a condition", withFixtures, () => {
  for (const key of Object.keys(fx.scenarios)) {
    for (const b of banners(key)) {
      const text = `${b.headline} ${b.detail || ""}`;
      assert.doesNotMatch(text, /re-?collect\w*\s+(will|would|to)\s+(fix|clear|resolve)/i, `${key}: ${text}`);
      assert.doesNotMatch(text, /(will|would) (fix|clear|resolve)/i, `${key}: ${text}`);
    }
  }
});

// --- tones -------------------------------------------------------------------------------------

test("no reassuring tone exists, and an exact mapping is a fact, not a verdict", withFixtures, () => {
  assert.deepEqual([...TONES], ["blocked", "caution", "info", "neutral", "terminal"]);
  for (const key of Object.keys(fx.scenarios)) {
    for (const b of banners(key)) assert.ok(TONES.includes(b.tone), `${key}: ${b.tone}`);
  }
  for (const info of Object.values(STATE_INFO)) assert.ok(TONES.includes(info.tone));
  const exact = mappingInfo(scenario("S14").evidence.mapping, scenario("S14").evidence.oktaGroup);
  assert.equal(exact.tone, "info");
  assert.match(exact.detail, /says nothing about whether changing it is safe/);
});

test("S14 (nothing blocking) shows no blocked or caution banner", withFixtures, () => {
  for (const b of banners("S14")) assert.equal(b.tone, "neutral", b.headline);
});

test("S06: the protected group leads with its protection", withFixtures, () => {
  const s06 = banners("S06");
  assert.equal(s06[0].headline, "Protected group — OGWA never retires it.");
  assert.equal(protectionInfo(scenario("S06").evidence.adGroup, scenario("S06").detail.SECURITY.classification).label, "Protected");
  assert.equal(stateInfo("PROTECTED").tone, "blocked");
});

test("banners are ordered most severe first", withFixtures, () => {
  const order = { blocked: 0, caution: 1, info: 2, neutral: 3, terminal: 4 };
  for (const key of Object.keys(fx.scenarios)) {
    const tones = banners(key).map((b) => order[b.tone]);
    assert.deepEqual(tones, [...tones].sort((a, b) => a - b), key);
  }
});

// --- membership, usage --------------------------------------------------------------------------

test("membership facts say 'not checked' unless a complete check exists", withFixtures, () => {
  const s04 = membershipFacts(scenario("S04").evidence);
  assert.equal(s04.direct.count, 14);
  assert.equal(s04.directFindings.basis, "finding");
  assert.equal(s04.primaryGroup.basis, "checked");
  const s05 = membershipFacts(scenario("S05").evidence);
  assert.equal(s05.parents.basis, "finding");
  assert.match(s05.parents.value, /SYNTH-ROLE-FINANCE-ALL/);
  const s07 = membershipFacts(scenario("S07").evidence);
  assert.deepEqual([s07.primaryGroup.value, s07.parents.value], ["Not checked", "Not checked"]);
  const s12 = membershipFacts(scenario("S12").evidence);
  assert.equal(s12.primaryGroup.value, "None observed (complete check)");
  assert.equal(s12.parents.value, "Not checked");
  const s09 = membershipFacts(scenario("S09").evidence);
  assert.equal(s09.direct.basis, "unavailable");
});

test("partial usage collection is never read as zero usage", withFixtures, () => {
  const s13 = usageSummary(scenario("S13").evidence.usage);
  assert.equal(s13.partial, true);
  assert.equal(s13.last, "Unknown: usage collection incomplete");
  assert.equal(usageSummary([]).tone, "blocked");
});

// --- actions --------------------------------------------------------------------------------------

test("the server marks evidence conditions as never an operator action", withFixtures, () => {
  for (const key of Object.keys(fx.scenarios)) {
    for (const who of Object.keys(scenario(key).detail)) {
      for (const t of scenario(key).detail[who].allowedActions.transitions) {
        if (["STALE_EVIDENCE", "EVIDENCE_INCOMPLETE"].includes(t.target)) {
          assert.deepEqual([t.operatorAction, t.permitted], [false, false], `${key}/${who}: ${t.target}`);
        }
      }
    }
  }
});

test("the approval limit is the server's, not the browser's", withFixtures, () => {
  for (const key of Object.keys(fx.scenarios)) {
    assert.equal(scenario(key).detail.SECURITY.policy.approvalMaxValidHours, 168, key);
  }
});

test("a viewer is offered nothing, anywhere", withFixtures, () => {
  for (const key of Object.keys(fx.scenarios)) {
    const s = scenario(key);
    const plan = actionPlan(s.detail.VIEWER, s.approvals, s.jobs);
    assert.deepEqual(plan, { approvals: [], transitions: [], dryRun: null, recordDryRun: null }, key);
  }
});

test("only the defined actions are ever offered", withFixtures, () => {
  const allowedTargets = new Set(Object.keys(UI_TRANSITIONS));
  for (const key of Object.keys(fx.scenarios)) {
    const s = scenario(key);
    for (const who of Object.keys(s.detail)) {
      const plan = actionPlan(s.detail[who], s.approvals, s.jobs);
      for (const t of plan.transitions) {
        assert.ok(allowedTargets.has(t.target), `${key}/${who}: ${t.target}`);
        assert.notEqual(t.action, "recordDryRun");
      }
    }
  }
  // The specific diversions the API allows (DEPENDENCY_BLOCKED, MAPPING_AMBIGUOUS, PROTECTED,
  // STALE_EVIDENCE) are API-only.
  for (const target of ["DEPENDENCY_BLOCKED", "MAPPING_AMBIGUOUS", "PROTECTED", "STALE_EVIDENCE", "EVIDENCE_INCOMPLETE",
    "RETIRED", "HOLD"]) {
    assert.equal(UI_TRANSITIONS[target], undefined, target);
  }
});

test("Security/IAM sees approval for S07; Identity Automation does not", withFixtures, () => {
  const s = scenario("S07");
  const security = actionPlan(s.detail.SECURITY, s.approvals, s.jobs);
  assert.deepEqual(security.approvals.map((a) => [a.stage, a.permitted]), [["OKTA_UNASSIGN", true]]);
  assert.deepEqual(security.transitions.map((t) => t.action).sort(), ["exclude", "hold", "reject"]);
  const automation = actionPlan(s.detail.AUTOMATION, s.approvals, s.jobs);
  assert.deepEqual(automation.approvals, []);
  assert.deepEqual(automation.transitions.map((t) => t.action).sort(), ["exclude", "hold", "reject"]);
});

test("the executor can plan S14's dry run against its unexpired approval", withFixtures, () => {
  const s = scenario("S14");
  const plan = actionPlan(s.detail.EXECUTOR, s.approvals, s.jobs);
  assert.equal(plan.dryRun.kind, "OKTA_UNASSIGN");
  assert.equal(plan.dryRun.approvals.length, 1);
  assert.equal(plan.recordDryRun, null); // its only job failed
  assert.deepEqual(plan.transitions, []);
});

test("S01 in its hold period: revalidation is requested with the evidence fingerprint", withFixtures, () => {
  const s = scenario("S01");
  const plan = actionPlan(s.detail.AUTOMATION, s.approvals, s.jobs);
  const revalidate = plan.transitions.find((t) => t.action === "revalidate");
  assert.ok(revalidate);
  assert.equal(revalidate.target, "REVALIDATION_REQUIRED");
  assert.equal(revalidate.needsFingerprint, true);
});

// --- The AD quarantine and deletion stages ----------------------------------------------------

test("S16: only Security/IAM is offered the AD deletion approval, and nobody a dry run yet", withFixtures, () => {
  const s = scenario("S16");
  assert.equal(s.detail.SECURITY.candidate.state, "DELETION_PROPOSED");
  const security = actionPlan(s.detail.SECURITY, s.approvals, s.jobs);
  assert.deepEqual(security.approvals.map((a) => [a.stage, a.permitted]), [["AD_DELETION", true]]);
  assert.equal(security.dryRun, null);
  assert.deepEqual(actionPlan(s.detail.AUTOMATION, s.approvals, s.jobs).approvals, []);
  assert.equal(actionPlan(s.detail.EXECUTOR, s.approvals, s.jobs).dryRun, null);
  assert.equal(stateInfo("DELETION_PROPOSED").label, "Deletion proposed");
});

test("S15 in its post-quarantine hold: no approval and no dry run; only revalidation is requested", withFixtures, () => {
  const s = scenario("S15");
  assert.equal(s.detail.SECURITY.candidate.state, "QUARANTINE_HOLD");
  assert.ok(s.detail.SECURITY.candidate.quarantineHoldUntil);
  assert.deepEqual(actionPlan(s.detail.SECURITY, s.approvals, s.jobs).approvals, []);
  assert.equal(actionPlan(s.detail.EXECUTOR, s.approvals, s.jobs).dryRun, null);
  const revalidate = actionPlan(s.detail.AUTOMATION, s.approvals, s.jobs).transitions.find((t) => t.action === "revalidate");
  assert.equal(revalidate.target, "DELETION_REVALIDATION_REQUIRED");
  assert.equal(s.detail.SECURITY.quarantine.inQuarantine, true);
  assert.match(stateInfo("QUARANTINE_HOLD").text, /never authorizes deletion/);
});

test("a deletion proposal is its own action, never a dry run or an approval", () => {
  const detail = {
    candidate: { id: "cand_x", state: "DELETION_REVALIDATION_REQUIRED", epoch: 1 },
    allowedActions: { transitions: [{ target: "DELETION_PROPOSED", category: "forward", operatorAction: true,
      permission: "LIFECYCLE_ADVANCE", permitted: true, requiresEvidenceFingerprint: true }], approvals: [], planDryRun: false },
  };
  const plan = actionPlan(detail, [], []);
  assert.deepEqual(plan.transitions.map((t) => [t.action, t.target, t.needsFingerprint]),
    [["proposeDeletion", "DELETION_PROPOSED", true]]);
  assert.equal(plan.dryRun, null);
});

test("only the deletion stage's own approval backs a deletion dry run (D146)", () => {
  const detail = {
    candidate: { id: "cand_x", state: "DELETION_APPROVED", epoch: 1 },
    allowedActions: { transitions: [], approvals: [], planDryRun: true },
  };
  const approvals = [
    { id: "apr_q", stage: "AD_QUARANTINE", decision: "APPROVE", expired: false, candidateEpoch: 1 },
    { id: "apr_o", stage: "OKTA_UNASSIGN", decision: "APPROVE", expired: false, candidateEpoch: 1 },
    { id: "apr_r", stage: "AD_RETIREMENT", decision: "APPROVE", expired: false, candidateEpoch: 1 },
    { id: "apr_old", stage: "AD_DELETION", decision: "APPROVE", expired: false, candidateEpoch: 0 },
    { id: "apr_d", stage: "AD_DELETION", decision: "APPROVE", expired: false, candidateEpoch: 1 },
  ];
  const plan = actionPlan(detail, approvals, []);
  assert.equal(plan.dryRun.kind, "AD_DELETION");
  assert.deepEqual(plan.dryRun.approvals.map((a) => a.id), ["apr_d"]);
  assert.equal(errorText("LEGACY_AD_RETIREMENT").includes("history only"), true);
});

// --- pure units -----------------------------------------------------------------------------------

test("future-dated evidence is worded as invalid, never fresh or stale", () => {
  const classification = {
    classification: "EVIDENCE_INCOMPLETE", adDeletionProhibited: true, lifecycleDiversion: "EVIDENCE_INCOMPLETE",
    reasons: [{ code: "EVIDENCE_FUTURE_DATED", blocks: true, subject: "adg_x", detail: "AD_GROUP adg_x: observed_at is in the future" }],
  };
  const out = candidateBanners({ classification }, { mapping: { confidence: "EXACT_CONFIGURED_MAPPING", isExact: true, matchedAttributes: [] } });
  const future = out.find((b) => b.codes.includes("EVIDENCE_FUTURE_DATED"));
  assert.equal(future.headline, "Future-dated evidence — invalid, decisions blocked.");
  assert.equal(future.tone, "blocked");
  assert.match(future.detail, /neither fresh nor stale/);
  assert.doesNotMatch(out.map((b) => b.headline).join(" "), /\bstale\b/i);
  assert.deepEqual([evidenceCondition(classification).futureDated, evidenceCondition(classification).stale], [true, false]);
  assert.deepEqual([...futureDatedSubjects(classification)], ["adg_x"]);
  assert.equal(staleSubjects(classification).size, 0);
});

test("unknown states and codes fail closed", () => {
  assert.equal(stateInfo("SOMETHING_NEW").tone, "caution");
  const unknown = mappingInfo({ confidence: "SOMETHING_NEW", isExact: false, candidateAdGroupIds: [] }, null);
  assert.equal(unknown.blocksAutomation, true);
  const forged = mappingInfo({ confidence: "SOMETHING_NEW", isExact: true, matchedAttributes: [] }, null);
  assert.equal(forged.blocksAutomation, true, "isExact alone, with an unknown confidence, proves nothing");
  const noClassification = candidateBanners({ classification: null }, {});
  assert.ok(noClassification.some((b) => /every action is blocked/.test(b.headline)));
  assert.equal(errorText("SOMETHING_NEW", "fallback"), "fallback");
});

test("approvals from another epoch, expired, or rejected never back a dry run", () => {
  const detail = {
    candidate: { id: "cand_x", state: "APPROVED", epoch: 2 },
    allowedActions: { transitions: [], approvals: [], planDryRun: true },
  };
  const approvals = [
    { id: "apr_a", stage: "OKTA_UNASSIGN", decision: "APPROVE", expired: false, candidateEpoch: 1 },
    { id: "apr_b", stage: "OKTA_UNASSIGN", decision: "APPROVE", expired: true, candidateEpoch: 2 },
    { id: "apr_c", stage: "OKTA_UNASSIGN", decision: "REJECT", expired: false, candidateEpoch: 2 },
    { id: "apr_d", stage: "AD_RETIREMENT", decision: "APPROVE", expired: false, candidateEpoch: 2 },
    { id: "apr_e", stage: "OKTA_UNASSIGN", decision: "APPROVE", expired: false, candidateEpoch: 2 },
  ];
  assert.deepEqual(actionPlan(detail, approvals, []).dryRun.approvals.map((a) => a.id), ["apr_e"]);
});
