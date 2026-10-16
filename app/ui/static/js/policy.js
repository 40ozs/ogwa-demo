// Plain-language reading of which policy produced a decision: the policy reference a
// decision recorded, and the server's decision explanation (GET /candidates/{id} →
// decisionExplanation; app/classification/explanation.py). Pure functions, no DOM:
// tests/ui/policy.test.mjs.
//
// Rules this module keeps:
// - It never judges anything. Every status is the server's; this module only words it.
// - A decision shows the policy it recorded, never the policy in force now. A decision that
//   recorded none says so, and one judged by a superseded version says that too.
// - An unknown status is worded as unknown and toned as blocked, never as satisfied.

export const CONDITION_STATUS_TEXT = Object.freeze({
  SATISFIED: { label: "Satisfied", tone: "neutral", meaning: "The classifier recorded the proof." },
  NOT_SATISFIED: { label: "Not satisfied", tone: "blocked", meaning: "A recorded fact contradicts the condition." },
  NOT_PROVEN: { label: "Not proven", tone: "caution",
    meaning: "Neither proven nor contradicted: the evidence is missing, partial, failed, ambiguous, or was not judged." },
  NOT_APPLICABLE: { label: "Not applicable", tone: "neutral", meaning: "The condition does not apply at this stage." },
});

// Sort order for a condition's status: what stops the decision first, an unknown status before all.
const STATUS_RANK = Object.freeze({ NOT_SATISFIED: 1, NOT_PROVEN: 2, SATISFIED: 3, NOT_APPLICABLE: 4 });

export function conditionRank(status) {
  return STATUS_RANK[status] || 0;
}

export function conditionStatusText(status) {
  return CONDITION_STATUS_TEXT[status] || { label: `Unrecognized (${String(status)})`, tone: "blocked",
    meaning: "Unrecognized status: treat the condition as not met." };
}

/** A policy reference worded: {text, detail, tone, known}. */
export function policyName(ref) {
  if (!ref) {
    return { text: "Not recorded with this decision", detail: "It was recorded before decisions named their policy.",
      tone: "caution", known: false };
  }
  const where = ref.recorded && Number.isInteger(ref.versionSequence)
    ? `Recorded version ${ref.versionSequence + 1}` : "Unrecorded demo policy";
  const published = ref.publishedRelease === "DIFFERS_FROM_RECORDED"
    ? " The release now published under this version differs from what was recorded."
    : ref.publishedRelease === "NOT_PUBLISHED" ? " No release is published under this version any more." : "";
  return { text: ref.name || `${where} (no release identity)`, detail: `${where}; rules ${ref.policyDigest}.${published}`,
    tone: ref.recorded && !published ? "info" : "caution", known: true };
}

/**
 * Whether a recorded decision was judged by the policy in force now. Compared by the rules'
 * digest; a different digest is a superseded policy, worded with both names.
 */
export function policyAgainstInForce(ref, inForce) {
  if (!ref) return { current: null, text: "Unknown: the decision recorded no policy." };
  if (!inForce || !inForce.policyDigest) return { current: null, text: "No policy is in force now to compare with." };
  if (ref.policyDigest === inForce.policyDigest) return { current: true, text: "The policy in force now." };
  const now = inForce.name || inForce.label || "a different policy";
  return { current: false, text: `Superseded: judged by ${policyName(ref).text}; ${now} is in force now.` };
}

/**
 * The explanation grouped by the reviewer's questions. Returns null without one, so the caller
 * can say so instead of showing an empty, reassuring panel.
 */
export function explanationAnswers(explanation) {
  if (!explanation || !Array.isArray(explanation.conditions)) return null;
  const conditions = explanation.conditions.map((c) => ({ ...c, statusText: conditionStatusText(c.status) }));
  const by = (status) => conditions.filter((c) => c.status === status);
  const review = explanation.manualReview || {};
  const because = Array.isArray(review.because) ? review.because : [];
  const forced = review.forcedByEvidence === true || because.length > 0;
  return {
    policy: explanation.policy ? policyName(explanation.policy)
      : { text: "No policy is in force", detail: "Nothing is judged without a policy (D52).", tone: "blocked", known: false },
    decision: explanation.decision || { code: "UNKNOWN", label: "No decision available" },
    conditions,
    satisfied: by("SATISFIED"),
    notSatisfied: by("NOT_SATISFIED"),
    notProven: by("NOT_PROVEN"),
    notApplicable: by("NOT_APPLICABLE"),
    unrecognized: conditions.filter((c) => !CONDITION_STATUS_TEXT[c.status]),
    forced: forced
      ? { answer: "Yes", tone: "blocked", because,
        text: "Ambiguous, conflicting, unreadable, or missing required evidence stops this decision by itself." }
      : { answer: "No", tone: "neutral", because: [],
        text: "The evidence the decision needs is decision-grade; what stops it, if anything, is a rule or a fact." },
    change: Array.isArray(explanation.whatWouldChange) ? explanation.whatWouldChange : [],
  };
}

/** Evidence item keys as the assessment labels them; a key the assessment does not hold stays as is. */
export function evidenceLabels(keys, items) {
  const labels = new Map((items || []).map((i) => [i.key, i.label]));
  return [...new Set((keys || []).map((k) => labels.get(k) || k))];
}
