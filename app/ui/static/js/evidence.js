// Plain-language reading of the server's evidence assessment (GET /candidates/{id} →
// evidenceAssessment; app/classification/assessment.py). Pure functions, no DOM:
// tests/ui/evidence.test.mjs.
//
// Rules this module keeps:
// - It never judges evidence. Every state, conflict, and decision comes from the server;
//   this module only words them and groups them by the six questions a reviewer asks.
// - The evidence states stay distinct: "not collected", "source unavailable", "partial",
//   "source says none", "identity not established", "conflicting", and "confirmed" each have
//   their own label, and nothing missing is ever worded as "none".
// - There is no reassuring tone. The best outcome, eligible for a named human's approval, is
//   "info" and says it is not an approval. Anything unproven is "caution" or "blocked".

export const EVIDENCE_STATE_TEXT = Object.freeze({
  CONFIRMED: { label: "Confirmed", tone: "info", meaning: "A complete read that found something." },
  REPORTS_NONE: { label: "Source says none", tone: "neutral",
    meaning: "A complete read that found nothing: evidence of absence, unlike a read that never happened." },
  NOT_COLLECTED: { label: "Not collected", tone: "blocked",
    meaning: "No observation is recorded. Unknown, not none." },
  SOURCE_UNAVAILABLE: { label: "Source unavailable", tone: "blocked",
    meaning: "The read was attempted and failed. Nothing is assumed in its place." },
  PARTIAL: { label: "Partial read", tone: "caution",
    meaning: "The read stopped part-way. What it found counts; what it did not find proves nothing." },
  NOT_COUNTED_SOURCE: { label: "Attested only", tone: "caution",
    meaning: "Checked only by a source that can block but never proves absence (D13)." },
  AMBIGUOUS: { label: "Identity not established", tone: "blocked",
    meaning: "Which AD group this is has not been proven exactly." },
  CONFLICTING: { label: "Conflicting", tone: "blocked",
    meaning: "This observation disagrees with another one about the same fact. OGWA does not choose a side." },
});

export const FRESHNESS_TEXT = Object.freeze({
  CURRENT: { label: "Current", tone: "neutral" },
  STALE: { label: "Stale", tone: "blocked" },
  FUTURE_DATED: { label: "Future-dated (invalid)", tone: "blocked" },
  NOT_ASSESSED: { label: "Not assessed", tone: "caution" },
});

export const STANCE_TEXT = Object.freeze({
  SUPPORTS: { label: "Supports the proposal", tone: "neutral" },
  DISAGREES: { label: "Reason not to act", tone: "blocked" },
  UNKNOWN: { label: "Cannot tell", tone: "caution" },
});

export const IDENTITY_TEXT = Object.freeze({
  CONFIRMED: { label: "Confirmed (exact)", tone: "info" },
  PROBABLE: { label: "Probable, not proven", tone: "blocked" },
  AMBIGUOUS: { label: "Ambiguous", tone: "blocked" },
  NOT_FOUND: { label: "No AD counterpart found", tone: "blocked" },
  NOT_ESTABLISHED: { label: "No mapping evidence", tone: "blocked" },
  UNAVAILABLE: { label: "Correlation did not finish", tone: "blocked" },
});

export const DECISION_TEXT = Object.freeze({
  TERMINAL: { tone: "terminal" },
  NO_ACTION_BLOCKED: { tone: "blocked" },
  CONFLICTING_EVIDENCE: { tone: "blocked" },
  AMBIGUOUS_IDENTITY: { tone: "blocked" },
  BLOCKED_ON_REQUIRED_SOURCE: { tone: "blocked" },
  INSUFFICIENT_EVIDENCE: { tone: "blocked" },
  NO_APPROVAL_OPEN: { tone: "caution" },
  MANUAL_REVIEW_REQUIRED: { tone: "caution" },
  LIFECYCLE_RULES_NOT_MET: { tone: "blocked" },
  ELIGIBLE_FOR_HUMAN_APPROVAL: { tone: "info" },
});

const STAGE_LABEL = Object.freeze({ OKTA_UNASSIGN: "Okta unassignment", AD_QUARANTINE: "AD quarantine",
  AD_DELETION: "AD deletion" });

// States that answer "which sources disagree or are unavailable" even without a stance.
const PROBLEM_STATES = new Set(["NOT_COLLECTED", "SOURCE_UNAVAILABLE", "PARTIAL", "NOT_COUNTED_SOURCE", "AMBIGUOUS",
  "CONFLICTING"]);

export function stateText(state) {
  return EVIDENCE_STATE_TEXT[state] || { label: String(state), tone: "blocked", meaning: "Unrecognized state: treat as unknown." };
}

export function freshnessText(freshness) {
  return FRESHNESS_TEXT[freshness] || { label: String(freshness), tone: "caution" };
}

export function stanceText(stance) {
  return STANCE_TEXT[stance] || { label: String(stance), tone: "caution" };
}

export function identityText(state) {
  return IDENTITY_TEXT[state] || { label: String(state), tone: "blocked" };
}

/** The decision, worded: {code, label, tone, eligible}. An unknown code is treated as a non-action. */
export function decisionText(decision) {
  const code = decision && decision.code;
  const known = DECISION_TEXT[code];
  return {
    code: code || "UNKNOWN",
    label: (decision && decision.label) || "No decision available",
    tone: known ? known.tone : "blocked",
    eligible: Boolean(known && code === "ELIGIBLE_FOR_HUMAN_APPROVAL" && decision.eligibleForHumanApproval === true),
  };
}

/** The next lifecycle step and the lifecycle guard's answer, in one sentence. */
export function pendingStepText(pending) {
  if (!pending || !pending.stage) {
    return { status: "None", tone: "terminal", text: "Nothing further is decided for this candidate." };
  }
  const stage = STAGE_LABEL[pending.stage] || pending.stage;
  if (!pending.open) return { status: "Not open", tone: "caution", text: `${stage} approval: not open in the candidate's current state.` };
  if (!pending.evaluated) {
    return { status: "Not evaluated", tone: "blocked",
      text: `${stage} approval: the lifecycle rules could not be evaluated. ${(pending.problems || []).join(" ")}`.trim() };
  }
  if (pending.accepts) {
    return { status: "Rules would accept", tone: "caution",
      text: `${stage} approval: the lifecycle's rules would accept a named human's approval on this evidence. That records a decision only; nothing is executed.` };
  }
  return { status: "Rules would refuse", tone: "blocked", text: `${stage} approval: the lifecycle would refuse it on this evidence.` };
}

/**
 * The assessment grouped by the six reviewer questions. Returns null without an assessment,
 * so the caller can say so rather than show an empty, reassuring panel.
 */
export function reviewerAnswers(assessment) {
  if (!assessment || !Array.isArray(assessment.items)) return null;
  const items = assessment.items;
  const supporting = items.filter((i) => i.stance === "SUPPORTS" && !PROBLEM_STATES.has(i.state));
  const against = items.filter((i) => i.stance === "DISAGREES" || PROBLEM_STATES.has(i.state));
  return {
    issue: (assessment.issue && assessment.issue.summary) || "Unknown",
    supporting,
    against,
    identity: { ...identityText(assessment.identity && assessment.identity.state),
      state: assessment.identity && assessment.identity.state,
      confidence: assessment.identity && assessment.identity.confidence,
      detail: (assessment.identity && assessment.identity.detail) || "" },
    decision: decisionText(assessment.decision),
    constraints: assessment.constraints || [],
    pending: pendingStepText(assessment.pendingStep),
    needed: assessment.needed || [],
    conflicts: assessment.conflicts || [],
    notes: assessment.notes || [],
  };
}

/** "Required" worded with the lifecycle stages whose rules read the item. */
export function requiredText(item) {
  const stages = (item.neededFor || []).map((s) => STAGE_LABEL[s] || s);
  if (!item.required) return "Not required";
  return stages.length ? `Required (read by: ${stages.join(", ")})` : "Required (retirement conditions)";
}

/**
 * Other Okta assignments of the candidate's group, worded for the decision summary. "None" is
 * said only when the server's classification proves it; without a classification it is unknown.
 */
export function otherAssignmentsFact(otherCount, classification) {
  if (otherCount > 0) return { value: `${otherCount} other application(s)`, tone: "blocked" };
  if (!classification) return { value: "Unknown: no classification", tone: "blocked" };
  const codes = new Set((classification.reasonCodes || []));
  if (codes.has("OTHER_ASSIGNMENTS_UNKNOWN")) return { value: "Not checked", tone: "blocked" };
  if (codes.has("SINGLE_OKTA_ASSIGNMENT")) return { value: "None (complete check)", tone: "neutral" };
  return { value: "None observed", tone: "caution" };
}
