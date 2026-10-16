// Plain-language reading of a synthetic remediation drill (POST /candidates/{id}/remediation-drills;
// app/remediation/drill.py). Pure functions, no DOM: tests/ui/drill.test.mjs.
//
// Rules this module keeps:
// - It never decides anything. Every state, label, reason, read, and answer comes from the
//   server; this module only chooses a tone and words the outcome.
// - A dry run and an execution can never look alike: the dry run's headline says no state
//   changed, and nothing an execution says does.
// - Only one outcome counts as done: POST_ACTION_VERIFIED with succeeded: true. Anything else,
//   including an executed but unverified change, is never given the best tone, and an unknown
//   state or a response that contradicts itself is treated as blocked.
// - There is no reassuring tone. The best outcome is "info", and it still says it changed only
//   a synthetic provider fixture.
// - The mode banner is the server's and is shown above everything else: DRY RUN —
//   NO STATE CHANGED, or SYNTHETIC EXECUTION with "No external provider or persistent environment
//   was modified." A banner that does not match the drill's mode makes the result inconsistent.
// - The authorization chain is the server's: each link shows the policy it
//   recorded, and only IN_FORCE (or, with no recorded version at all, UNRECORDED_POLICY) is
//   worded as binding; anything else, or nothing, is blocked.

// Which drill a candidate's state allows: the operation, the approval stage that authorizes
// it, and the one target field. Mirrors app/domain/remediation.py OPERATIONS; the server
// re-checks everything.
export const DRILL_STAGES = Object.freeze({
  APPROVED: { operation: "OKTA_GROUP_UNASSIGN", stage: "OKTA_UNASSIGN", targetField: "assignmentId" },
  OKTA_UNASSIGN_DRY_RUN: { operation: "OKTA_GROUP_UNASSIGN", stage: "OKTA_UNASSIGN", targetField: "assignmentId" },
  QUARANTINE_APPROVED: { operation: "AD_GROUP_QUARANTINE", stage: "AD_QUARANTINE", targetField: "adGroupId" },
  QUARANTINE_DRY_RUN: { operation: "AD_GROUP_QUARANTINE", stage: "AD_QUARANTINE", targetField: "adGroupId" },
  DELETION_APPROVED: { operation: "AD_GROUP_DELETE", stage: "AD_DELETION", targetField: "adGroupId" },
  DELETION_DRY_RUN: { operation: "AD_GROUP_DELETE", stage: "AD_DELETION", targetField: "adGroupId" },
});

export const OPERATION_TEXT = Object.freeze({
  OKTA_GROUP_UNASSIGN: "the Okta group's assignment to one application",
  AD_GROUP_QUARANTINE: "moving the AD group into its quarantine OU",
  AD_GROUP_DELETE: "the quarantined AD group's deletion",
});

export const MODE_TEXT = Object.freeze({
  DRY_RUN: { label: "Dry run", help: "Plans against the synthetic provider's current state. Submits nothing; no state changes." },
  SYNTHETIC_EXECUTION: { label: "Synthetic execution drill",
    help: "Submits the change to an in-memory synthetic provider fixture under a scripted fault scenario, then verifies it. Nothing is recorded, and nothing outside the fixture changes." },
});

// The tone of each step. Every state is listed; anything else is blocked.
export const STEP_TONE = Object.freeze({
  DRY_RUN: "neutral",
  BLOCKED: "blocked",
  EXECUTION_REQUESTED: "caution",
  OUTCOME_UNKNOWN: "caution",
  VERIFYING: "caution",
  RETRY_PERMITTED: "caution",
  RETRY_NOT_PERMITTED: "blocked",
  EXECUTED: "caution",
  POST_ACTION_VERIFIED: "info",
  VERIFICATION_FAILED: "blocked",
});

export const OBSERVATION_TEXT = Object.freeze({
  NOT_APPLIED: "still in the planned before-state (not applied)",
  APPLIED: "in the planned after-state (applied)",
  DIVERGED: "in neither planned state (changed by something else)",
  UNREADABLE: "could not be read (still unknown)",
});

export const ANSWER_TEXT = Object.freeze({
  APPLIED: "says applied",
  TIMEOUT: "no answer (timeout)",
  REFUSED: "refused",
});

export function stageFor(state) {
  return DRILL_STAGES[state] || null;
}

export function stepTone(state) {
  return STEP_TONE[state] || "blocked";
}

/** True only when the server says the drill ended verified, and its record agrees. */
export function isVerified(drill) {
  if (!drill || drill.succeeded !== true || drill.finalState !== "POST_ACTION_VERIFIED") return false;
  if (!drill.postActionVerification || drill.postActionVerification.result !== "CONFIRMED") return false;
  const steps = drill.steps || [];
  const last = steps[steps.length - 1];
  return Boolean(last && last.state === "POST_ACTION_VERIFIED" && steps.some((s) => s.state === "EXECUTED"));
}

// The mode banners' headlines, as the server words them (app/remediation/drill.py MODE_BANNERS).
export const MODE_HEADLINE = Object.freeze({ DRY_RUN: "DRY RUN — NO STATE CHANGED", SYNTHETIC_EXECUTION: "SYNTHETIC EXECUTION" });

function bannerMatchesMode(drill) {
  const b = drill && drill.modeBanner;
  return Boolean(b && MODE_HEADLINE[drill.mode] && b.headline === MODE_HEADLINE[drill.mode]);
}

function inconsistent(drill) {
  const steps = (drill && drill.steps) || [];
  const last = steps[steps.length - 1];
  if (!last || last.state !== drill.finalState) return true;
  if (drill.succeeded === true && !isVerified(drill)) return true;
  if (!bannerMatchesMode(drill)) return true;
  if (drill.mode === "DRY_RUN" && (steps.some((s) => s.state !== "DRY_RUN" && s.state !== "BLOCKED")
    || (drill.provider && (drill.provider.stateChanged || drill.provider.mutationsApplied)))) return true;
  return false;
}

/**
 * The drill's mode in one persistent banner: { headline, detail, tone, mode }. Always the
 * server's words; a missing or mismatched banner is blocked, never guessed.
 */
export function modeBanner(drill) {
  if (!bannerMatchesMode(drill)) {
    return { headline: "Unknown drill mode", tone: "blocked", mode: null,
      detail: "The response does not say whether this was a dry run or a synthetic execution. Treat it as neither." };
  }
  return { headline: drill.modeBanner.headline, detail: drill.modeBanner.detail, mode: drill.mode,
    tone: drill.mode === "DRY_RUN" ? "neutral" : "caution" };
}

export const BINDING_TEXT = Object.freeze({
  IN_FORCE: { label: "Judged by the version in force", tone: "info" },
  UNRECORDED_POLICY: { label: "No policy version recorded (unrecorded demo policy)", tone: "caution" },
  SUPERSEDED: { label: "Judged by a superseded version", tone: "blocked" },
  NOT_RECORDED: { label: "Recorded no policy", tone: "blocked" },
});

export function bindingText(binding) {
  return BINDING_TEXT[binding] || { label: `Unrecognized (${String(binding)})`, tone: "blocked" };
}

/**
 * "Authorized by": the chain from the policy to the operation, as [label, text] pairs, each
 * link by its recorded identifier. Returns null without a chain, so the caller can say so.
 */
export function chainFacts(chain, authorization) {
  if (!chain || !authorization) return null;
  const policy = chain.policyId ? `${chain.policyId} v${chain.policyVersion}` : "No named policy release";
  const seq = (n) => (Number.isInteger(n) ? ` (audit event #${n})` : " (no audit event found)");
  const a = authorization.approval || {};
  const d = authorization.decision;
  const recorded = (link) => (link && link.policy && link.policy.name) || (link && link.policy ? "an unnamed recorded policy" : "no policy");
  return [
    ["Policy in force (the gates' rules)", `${policy}${Number.isInteger(chain.policySequence) ? `, recorded version ${chain.policySequence + 1}` : ""}`],
    ["Lifecycle decision", d ? `${d.id}: ${d.from} → ${d.to}${seq(chain.decisionAuditSequence)}, recorded under ${recorded(d)}` : "No lifecycle decision applied this approval"],
    ["Decision's policy", d ? bindingText(d.binding).label : "—"],
    ["Approval (control)", `${a.id}: ${a.stage}, by ${a.operator ? a.operator.id : "unknown"}${seq(chain.approvalAuditSequence)}, recorded under ${recorded(a)}`],
    ["Approval's policy", bindingText(a.binding).label],
    ["Operation id (every attempt)", chain.operationId || "—"],
    ["Execution mode", chain.executionMode === "DRY_RUN" ? "Dry run" : `Synthetic execution (${chain.scenario || "no scenario"})`],
    ["Post-action verification", POST_ACTION_TEXT[chain.postActionVerification] || `Unrecognized (${chain.postActionVerification})`],
    ["Final state", chain.finalLabel || chain.finalState],
    ["Recorded", chain.recorded ? "Yes" : "No: a drill records nothing"],
  ];
}

export const POST_ACTION_TEXT = Object.freeze({
  CONFIRMED: "Confirmed: the target is in its planned after-state and nothing else in scope changed",
  FAILED: "Failed: not a success",
  NOT_REACHED: "Not reached: nothing was executed, so there was nothing to verify",
});

/** One row per submission: what the provider said, what a read then showed, what followed. */
export function attemptRows(chain) {
  return ((chain && chain.attempts) || []).map((t) => ({
    attempt: t.attempt, at: t.submittedAt,
    answer: t.answer ? (ANSWER_TEXT[t.answer] || t.answer) : "—",
    verification: t.verification ? (OBSERVATION_TEXT[t.verification] || t.verification) : "Not needed",
    next: t.next || "—",
  }));
}

/**
 * The outcome of a drill in one banner: { headline, tone, detail, verified }.
 * The headline is the server's label for the final state, except that a response which
 * contradicts itself is shown as blocked.
 */
export function drillOutcome(drill) {
  if (!drill || !Array.isArray(drill.steps) || !drill.steps.length) {
    return { headline: "No drill result", tone: "blocked", verified: false,
      detail: "The server returned no steps. Treat the change as not made and not verified." };
  }
  if (inconsistent(drill)) {
    return { headline: "Inconsistent drill result", tone: "blocked", verified: false,
      detail: "The response contradicts itself. Treat the change as not made and not verified." };
  }
  const p = drill.provider || {};
  const subs = drill.submissions || 0;
  const tries = `${subs} submission${subs === 1 ? "" : "s"}`;
  const applied = `${p.mutationsApplied || 0} change${p.mutationsApplied === 1 ? "" : "s"} applied inside the fixture`;
  const last = drill.steps[drill.steps.length - 1];
  const headline = last.label || drill.finalLabel || drill.finalState;
  switch (drill.finalState) {
    case "DRY_RUN":
      return { headline, tone: "neutral", verified: false,
        detail: "Planned only. Nothing was submitted, and the synthetic provider's state is identical before and after (same digest)." };
    case "POST_ACTION_VERIFIED":
      return { headline, tone: "info", verified: isVerified(drill),
        detail: `Executed against the synthetic provider fixture only (${tries}, ${applied}) and confirmed by a post-action read. Nothing was recorded; the lifecycle, Okta, and Active Directory are unchanged.` };
    case "VERIFICATION_FAILED":
      return { headline, tone: "blocked", verified: false,
        detail: `Not a success. The post-action read did not find the planned state (${tries}, ${applied}).` };
    case "RETRY_NOT_PERMITTED":
      return { headline, tone: "blocked", verified: false,
        detail: `Not done and not retried (${tries}, ${applied}). A person must reconcile the target before anything else happens.` };
    case "BLOCKED":
      return { headline, tone: "blocked", verified: false,
        detail: `Stopped before submitting (${tries}, ${applied}).` };
    default:
      return { headline: `Unknown drill state ${drill.finalState}`, tone: "blocked", verified: false,
        detail: "Treat the change as not made and not verified." };
  }
}

function readsText(reads) {
  if (!reads || !reads.length) return null;
  const words = reads.map((r) => (r.succeeded ? "read" : "read failed"));
  return words.join(", ");
}

/** The facts worth showing for one step, as [label, text] pairs; empty values are left out. */
export function stepFacts(step) {
  const rows = [];
  if (step.attempt) rows.push(["Attempt", String(step.attempt)]);
  if (step.answer) rows.push(["Provider answer", `${ANSWER_TEXT[step.answer] || step.answer}${step.answerDetail ? ` — ${step.answerDetail}` : ""}`]);
  if (step.observation) rows.push(["Target observed", OBSERVATION_TEXT[step.observation] || step.observation]);
  const reads = readsText(step.reads);
  if (reads) rows.push(["Reads", reads]);
  for (const p of step.problems || []) rows.push(["Gate", p]);
  for (const d of step.differences || []) rows.push(["Difference", d]);
  return rows;
}

/** One line per fixture ledger entry: what really happened inside the fixture. */
export function ledgerRows(drill) {
  const entries = (drill && drill.provider && drill.provider.ledger) || [];
  return entries.map((e) => ({
    seq: e.seq, at: e.at, actor: e.actor === "outside-this-run" ? "Someone outside this run" : e.actor,
    fault: e.fault || "—", applied: e.applied ? "Applied" : "Not applied", answer: e.answer ? (ANSWER_TEXT[e.answer] || e.answer) : "—",
  }));
}

/** "+30 s": how long after the drill's first step a step happened, on the fixture's synthetic clock. */
export function elapsedText(at, start) {
  const a = Date.parse(at);
  const s = Date.parse(start);
  if (Number.isNaN(a) || Number.isNaN(s)) return "—";
  return `+${Math.round((a - s) / 1000)} s`;
}
