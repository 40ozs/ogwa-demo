// The operator review reading of the lifecycle (OGWA-UI-REVIEW-01): one review status per
// lifecycle state, the lifecycle as a row of stages, the next step and who takes it, the impact
// of a dependency check, governance rules in plain words, and how a dry-run plan is worded.
// Pure functions, no DOM: tests/ui/review.test.mjs.
//
// Rules this module keeps:
// - The lifecycle state stays the fact. A review status is a grouping for the operator, never a
//   state and never an authorization; every view shows the lifecycle state beside it.
// - No status is "ready": every step forward needs a named human's decision or an observation
//   of a change made outside OGWA, and the server checks it again when it is asked for.
// - A state this module does not know is read as blocked.
// - Stages ahead of the candidate are never shown as reached or guaranteed: "Not yet eligible".
// - "OGWA could not tell" is never worded as "none found" (an unchecked kind is not clear).
import { reasonHeadline, stateInfo } from "./assess.js";
import { decisionText } from "./evidence.js";
import { deadlineText } from "./present.js";

// --- review status ------------------------------------------------------------------------

// Order is the Review queue's: what needs a person first.
export const REVIEW_STATUS = Object.freeze({
  "needs-review": { label: "Needs review", tone: "caution",
    text: "A person's decision is open: an approval, a revalidation, or a deletion proposal." },
  blocked: { label: "Blocked", tone: "blocked",
    text: "Stopped. Nothing moves forward until the blocking condition clears and the re-entry checks pass." },
  waiting: { label: "Waiting", tone: "neutral",
    text: "Waiting on time (a hold) or on discovery and classification. No decision is open yet." },
  "in-progress": { label: "In progress (dry run only)", tone: "caution",
    text: "An approval is recorded. OGWA only plans dry runs; any real change happens outside OGWA and counts only when read-only discovery observes it." },
  retired: { label: "Retired (observed)", tone: "terminal", text: "Read-only discovery observed the AD group deleted." },
  closed: { label: "Closed", tone: "terminal", text: "Excluded, rejected, or protected. Terminal for this candidate." },
});

// The open statuses: the Review queue's default view.
export const OPEN_STATUSES = Object.freeze(["needs-review", "blocked", "waiting", "in-progress"]);

const STATUS_OF = Object.freeze({
  NEEDS_REVIEW: "needs-review", REVALIDATION_REQUIRED: "needs-review", DELETION_REVALIDATION_REQUIRED: "needs-review",
  DELETION_PROPOSED: "needs-review",
  BLOCKED: "blocked", MAPPING_AMBIGUOUS: "blocked", DEPENDENCY_BLOCKED: "blocked", STALE_EVIDENCE: "blocked",
  EVIDENCE_INCOMPLETE: "blocked",
  // Legacy single AD stage (D148): nothing may continue from it except a diversion.
  RETIREMENT_DRY_RUN: "blocked",
  DISCOVERED: "waiting", CANDIDATE: "waiting", HOLD: "waiting", QUARANTINE_HOLD: "waiting",
  APPROVED: "in-progress", OKTA_UNASSIGN_DRY_RUN: "in-progress", QUARANTINE_APPROVED: "in-progress",
  QUARANTINE_DRY_RUN: "in-progress", DELETION_APPROVED: "in-progress", DELETION_DRY_RUN: "in-progress",
  RETIRED: "retired",
  EXCLUDED: "closed", REJECTED: "closed", PROTECTED: "closed",
});

/** The review status of a lifecycle state: {key, label, tone, text}. An unknown state is blocked. */
export function reviewStatus(state) {
  const key = STATUS_OF[state] || "blocked";
  return { key, ...REVIEW_STATUS[key] };
}

/** The lifecycle states a review status groups, in the lifecycle's order. */
export function statesOf(key) {
  return Object.keys(STATUS_OF).filter((state) => STATUS_OF[state] === key);
}

/** Candidates per review status from GET /dashboard's candidatesByState (unknown states count as blocked). */
export function statusCounts(byState) {
  const out = Object.fromEntries(Object.keys(REVIEW_STATUS).map((k) => [k, 0]));
  for (const [state, n] of Object.entries(byState || {})) out[reviewStatus(state).key] += n || 0;
  return out;
}

// --- next step ----------------------------------------------------------------------------

const STEP = Object.freeze({
  DISCOVERED: { required: "Classification", who: "Discovery (system)",
    text: "Classification on fresh, complete evidence decides whether this becomes a candidate." },
  CANDIDATE: { required: "Put up for review", who: "Discovery or a person (API only)",
    text: "Goes to review once an identity mapping is recorded." },
  NEEDS_REVIEW: { required: "Okta unassignment approval", who: "A Security IAM reviewer who did not propose it", decision: true,
    text: "Decide the Okta unassignment approval, or hold, exclude, or reject the candidate." },
  APPROVED: { required: "Dry run of the Okta unassignment", who: "An executor",
    text: "Plan a dry run under the approval. It executes nothing." },
  OKTA_UNASSIGN_DRY_RUN: { required: "Unassignment observed", who: "Read-only discovery",
    text: "Nothing in OGWA. Any removal happens outside OGWA; the hold starts only when discovery observes it." },
  HOLD: { required: "Hold to end", who: "Time", deadline: "holdUntil",
    text: "Wait for the hold to end. Its end opens revalidation and authorizes nothing." },
  REVALIDATION_REQUIRED: { required: "AD quarantine approval", who: "A second Security IAM reviewer, not the Okta-stage approver", decision: true,
    text: "Decide the AD quarantine approval on fresh evidence, or hold, exclude, or reject the candidate." },
  QUARANTINE_APPROVED: { required: "Dry run of the AD quarantine", who: "An executor",
    text: "Plan a dry run under the approval. It executes nothing." },
  QUARANTINE_DRY_RUN: { required: "Quarantine observed", who: "Read-only discovery",
    text: "Nothing in OGWA. Any move happens outside OGWA; the post-quarantine hold starts only when discovery observes it." },
  QUARANTINE_HOLD: { required: "Post-quarantine hold to end", who: "Time", deadline: "quarantineHoldUntil",
    text: "Wait for the 30-day hold to end. Its end opens revalidation and never authorizes deletion." },
  DELETION_REVALIDATION_REQUIRED: { required: "Deletion proposal", who: "An identity automation operator", decision: true,
    text: "Propose AD deletion on evidence collected after the hold, or hold, exclude, or reject the candidate." },
  DELETION_PROPOSED: { required: "AD deletion approval", who: "A reviewer who did not propose it or approve an earlier stage", decision: true,
    text: "Decide the AD deletion approval, or hold, exclude, or reject the candidate." },
  DELETION_APPROVED: { required: "Dry run of the AD deletion", who: "An executor",
    text: "Plan a dry run under the approval. It executes nothing." },
  DELETION_DRY_RUN: { required: "Deletion observed", who: "Read-only discovery",
    text: "Nothing in OGWA. Any deletion happens outside OGWA; the candidate retires only when discovery observes it." },
  RETIREMENT_DRY_RUN: { required: "Hold, exclusion, or rejection", who: "A person",
    text: "The legacy single AD stage is history only. Nothing may continue from it except a hold, exclusion, or rejection." },
  BLOCKED: { required: "Hold to be lifted", who: "A person",
    text: "A person lifts the hold; the candidate must then pass the re-entry checks." },
  MAPPING_AMBIGUOUS: { required: "Identity mapping proven", who: "Identity mapping review",
    text: "Prove the Okta group's AD counterpart exactly. Re-entry is checked by the lifecycle rules." },
  DEPENDENCY_BLOCKED: { required: "Blocking dependency resolved", who: "A person, outside OGWA",
    text: "Resolve the blocking dependency findings. Re-entry needs none left and is checked by the lifecycle rules." },
  STALE_EVIDENCE: { required: "Fresh evidence", who: "Collection, then classification",
    text: "Only clears when fresh, complete evidence is recorded; any other condition still applies." },
  EVIDENCE_INCOMPLETE: { required: "Complete evidence", who: "Collection, then classification",
    text: "Only clears when a complete, decision-grade collection is recorded; any other condition still applies." },
  RETIRED: { required: "None", who: "—", text: "None. Terminal." },
  EXCLUDED: { required: "None", who: "—", text: "None. Terminal: new evidence would create a new candidate." },
  REJECTED: { required: "None", who: "—", text: "None. Terminal: new evidence would create a new candidate." },
  PROTECTED: { required: "None", who: "—", text: "None. OGWA never retires a protected group." },
});

/**
 * What has to happen next for a candidate and who does it, from its lifecycle state:
 * {required, who, text, decision, deadline: {at, label, past} | null}. `nowIso` is the server's
 * clock; without it a deadline has no relative wording.
 */
export function nextStep(candidate, nowIso) {
  const step = STEP[candidate.state] || { required: "Unrecognized state", who: "—", text: "Unrecognized lifecycle state: treat as blocked." };
  const at = step.deadline ? candidate[step.deadline] : null;
  const rel = at ? deadlineText(at, nowIso, "Ended") : null;
  return {
    required: step.required, who: step.who, text: step.text, decision: Boolean(step.decision),
    deadline: at ? { at, label: rel ? rel.text : null, past: rel ? rel.past : null } : null,
  };
}

// --- the lifecycle as stages ----------------------------------------------------------------

export const STAGES = Object.freeze([
  { key: "discovery", label: "Discovery", states: ["DISCOVERED", "CANDIDATE"] },
  { key: "review", label: "Review", states: ["NEEDS_REVIEW"] },
  { key: "okta", label: "Okta unassignment", states: ["APPROVED", "OKTA_UNASSIGN_DRY_RUN"] },
  { key: "hold", label: "Hold", states: ["HOLD"] },
  { key: "revalidation", label: "Revalidation", states: ["REVALIDATION_REQUIRED", "RETIREMENT_DRY_RUN"] },
  { key: "quarantine", label: "AD quarantine", states: ["QUARANTINE_APPROVED", "QUARANTINE_DRY_RUN"] },
  { key: "quarantine-hold", label: "Post-quarantine hold", states: ["QUARANTINE_HOLD"] },
  { key: "deletion-review", label: "Deletion review", states: ["DELETION_REVALIDATION_REQUIRED", "DELETION_PROPOSED"] },
  { key: "deletion", label: "AD deletion", states: ["DELETION_APPROVED", "DELETION_DRY_RUN"] },
  { key: "retired", label: "Retired", states: ["RETIRED"] },
]);

export const STAGE_STATUS = Object.freeze({
  done: "Completed", current: "Current", waiting: "Current, waiting", blocked: "Blocked",
  closed: "Stopped here", future: "Not yet eligible", "not-reached": "Not reached",
});

const stageIndex = (state) => STAGES.findIndex((s) => s.states.includes(state));
const HOLD_UNTIL = { HOLD: "holdUntil", QUARANTINE_HOLD: "quarantineHoldUntil" };

/**
 * The candidate's lifecycle as a row of stages, for reading, never for deciding (the state
 * machine is authoritative): [{key, label, status, statusText, note}] and a one-line summary.
 * A blocked candidate is blocked at the stage it was blocked from; a closed one (excluded,
 * rejected, protected) stops at the furthest stage its recorded decisions reached. `decisions`
 * is GET /candidates/{id}/decisions; `nowIso` the server's clock, for a hold's remaining time.
 */
export function lifecycleStages(candidate, decisions, nowIso) {
  const state = candidate.state;
  const info = stateInfo(state);
  const status = reviewStatus(state).key;
  let at = stageIndex(state);
  let mode = "progress";
  if (state === "RETIRED") mode = "retired";
  else if (status === "closed") {
    mode = "closed";
    at = 0;
    for (const d of decisions || []) for (const s of [d.from, d.to]) at = Math.max(at, stageIndex(s));
  } else if (status === "blocked" && at < 0) {
    mode = "blocked";
    at = Math.max(0, stageIndex(candidate.blockedFrom));
  } else if (at < 0) {
    mode = "blocked"; // unknown state
    at = 0;
  }
  const here = mode === "retired" ? STAGES.length - 1 : at;
  const stages = STAGES.map((stage, i) => {
    let s;
    let note = null;
    let until = null;
    if (mode === "retired") s = "done";
    else if (i < at) s = "done";
    else if (i > at) s = mode === "closed" ? "not-reached" : "future";
    else if (mode === "closed" || mode === "blocked" || state === "RETIREMENT_DRY_RUN") s = mode === "closed" ? "closed" : "blocked";
    else s = HOLD_UNTIL[state] ? "waiting" : "current";
    if (i === here) {
      note = info.label;
      until = s === "waiting" ? candidate[HOLD_UNTIL[state]] || null : null;
      const rel = until ? deadlineText(until, nowIso, "Ended") : null;
      if (rel) note = `${info.label}, ${rel.text}`;
    }
    return { key: stage.key, label: stage.label, status: s, statusText: STAGE_STATUS[s], note, until };
  });
  const cur = stages[here];
  return { stages, summary: `Stage ${here + 1} of ${STAGES.length}: ${cur.label}, ${cur.statusText.toLowerCase()} (${cur.note}).` };
}

/** The stage a candidate is at (a blocked one: the stage it was blocked from), or null when closed or unknown. */
export function stageLabel(candidate) {
  const i = stageIndex(candidate.state);
  const at = i >= 0 ? i : stageIndex(candidate.blockedFrom);
  return at >= 0 ? STAGES[at].label : null;
}

const RANK = Object.keys(REVIEW_STATUS);

/**
 * The Review queue's order: by review status (decisions first), then the nearest deadline, then
 * the longest wait (oldest last change). `nowIso` is the server's clock.
 */
export function queueOrder(nowIso) {
  const deadline = (c) => nextStep(c, nowIso).deadline;
  return (a, b) => {
    const rank = RANK.indexOf(reviewStatus(a.state).key) - RANK.indexOf(reviewStatus(b.state).key);
    if (rank) return rank;
    const da = deadline(a);
    const db = deadline(b);
    if (da && db && da.at !== db.at) return da.at < db.at ? -1 : 1;
    if (Boolean(da) !== Boolean(db)) return da ? -1 : 1;
    return a.updatedAt < b.updatedAt ? -1 : a.updatedAt > b.updatedAt ? 1 : (a.id < b.id ? -1 : 1);
  };
}

// --- the current evidence verdict (OGWA-REVIEW-QUEUE-API-01) ------------------------------------

/**
 * A queue row's evidence verdict (GET /review-queue `evidenceVerdict`) in words, beside the
 * recorded state, never instead of it: {label, tone, agreement: {key, tone, text}, blockers}.
 * `label` is the assessment's decision ("what OGWA can safely conclude now"); `agreement` says
 * whether the classifier's current suggestion matches the recorded state. A disagreement is
 * shown, never resolved: the state stands until the lifecycle records a transition. Anything
 * missing or unknown reads as not assessed or unrecognized, never as agreement.
 */
export function verdictReading(verdict, state) {
  if (!verdict) {
    return { label: "Not assessed", tone: "blocked", blockers: [],
      agreement: { key: "UNAVAILABLE", tone: "blocked", text: "No evidence verdict was returned." } };
  }
  const decision = decisionText(verdict.decision);
  const suggested = verdict.suggestedState ? stateInfo(verdict.suggestedState).label : null;
  const AGREEMENT = {
    AGREES: { tone: "neutral", text: "Matches the recorded state." },
    DIFFERS: { tone: "caution", text: suggested
      ? `Differs from the recorded state: the evidence now points to “${suggested}”.`
      : `Differs from the recorded state: the classifier no longer suggests “${stateInfo(state).label}”.` },
    NOT_APPLICABLE: { tone: "terminal", text: "Terminal: nothing further is decided." },
    UNAVAILABLE: { tone: "blocked", text: "Not classified: no policy in force, or no assignment evidence." },
  };
  const known = AGREEMENT[verdict.agreement];
  return {
    label: decision.label, tone: decision.tone,
    agreement: known ? { key: verdict.agreement, ...known }
      : { key: "UNKNOWN", tone: "blocked", text: "Unrecognized comparison with the recorded state." },
    blockers: (verdict.blockingReasons || []).map(reasonHeadline),
  };
}

// --- approval usability (OGWA-REVIEW-QUEUE-API-01) ------------------------------------------------

const USABILITY = Object.freeze({
  USABLE: { label: "Valid for its stage", tone: "caution" },
  EXPIRED: { label: "Expired", tone: "neutral" },
  EPOCH_SUPERSEDED: { label: "Superseded: the candidate re-entered review", tone: "neutral" },
  STAGE_NOT_CURRENT: { label: "Not usable in the candidate's current state", tone: "neutral" },
  EVIDENCE_CHANGED: { label: "Not usable: evidence changed since", tone: "neutral" },
  POLICY_NOT_IN_FORCE: { label: "Not usable: judged by a policy not in force", tone: "neutral" },
  NO_POLICY: { label: "Not usable: no policy in force", tone: "blocked" },
  NOT_AN_APPROVAL: { label: "Rejection: authorizes nothing", tone: "neutral" },
  LEGACY: { label: "Legacy: authorizes nothing", tone: "neutral" },
  NOT_USABLE: { label: "Not usable", tone: "blocked" },
});

// A valid approval is not a ready step: the step it backs has its own checks.
export const USABLE_NOTE = "The step it backs has its own checks (for a dry run, evidence under 24 hours old); the server applies them when it is requested.";

/**
 * Whether a recorded approval still passes the lifecycle's approval rules, as the server judged it
 * (`usability` on GET /approvals and GET /candidates/{id}/approvals): {usable, expiringSoon, label,
 * tone, problems, note}. Only the server's `usable: true` with status USABLE reads as valid; a missing
 * or unknown answer is not usable. Valid is never "ready": `note` says the step is checked too.
 * `expiringSoon` (OGWA-APPROVAL-ATTENTION-01) is the server's flag, and only on a valid approval:
 * nothing here works out validity or nearness from dates.
 */
export function approvalUsability(u) {
  const usable = Boolean(u && u.usable === true && u.status === "USABLE");
  const known = u && USABILITY[u.status];
  const words = usable ? USABILITY.USABLE : known && u.status !== "USABLE" ? known : USABILITY.NOT_USABLE;
  return { usable, expiringSoon: usable && u.expiringSoon === true, ...words, problems: (u && u.problems) || [],
    note: usable ? USABLE_NOTE : null };
}

// The Decisions filters (OGWA-APPROVAL-ATTENTION-01): GET /approvals `usability`, applied by the server
// over every approval before paging; `count` names the response's `counts` field.
export const APPROVAL_FILTERS = Object.freeze([
  { key: "all", label: "All", count: "all" },
  { key: "valid", label: "Valid for its stage", count: "valid" },
  { key: "expiring-soon", label: "Expiring soon", count: "expiringSoon" },
  { key: "expired", label: "Expired", count: "expired" },
]);

// --- evidence readiness -------------------------------------------------------------------------

const USABLE = new Set(["CONFIRMED", "REPORTS_NONE"]);

/**
 * How many of the sources the server marks required are complete and current, from the
 * server's evidence assessment: {required, usable, problems: [label]}; null without one. It
 * counts the server's states and judges nothing itself.
 */
export function evidenceReadiness(assessment) {
  if (!assessment || !Array.isArray(assessment.items)) return null;
  const required = assessment.items.filter((i) => i.required);
  const problems = required.filter((i) => !(USABLE.has(i.state) && i.freshness === "CURRENT"));
  return { required: required.length, usable: required.length - problems.length, problems: problems.map((i) => i.label) };
}

// --- impact of a dependency check ---------------------------------------------------------------

const DIRECTORY_KINDS = new Set(["AD_GROUP_MEMBERS", "AD_NESTED_MEMBERSHIP"]);
const REFERENCE_KINDS = new Set(["AD_ACL_REFERENCE", "GPO_REFERENCE", "AAP_REFERENCE", "APPLICATION_CONFIGURATION",
  "OKTA_POLICY_REFERENCE"]);

export const IMPACT_CATEGORY = Object.freeze({
  "known-dependency": "Known dependency",
  "directory-constraint": "Directory constraint",
  "external-reference": "External reference",
  "coverage-gap": "Coverage gap",
  "none-found": "None found",
});

/**
 * What one dependency check (GET /dependency-findings item) means for the lifecycle:
 * {category, categoryLabel, effect, tone, blocks, established}. A check that is not complete
 * and decision-grade never establishes absence: with nothing found it is a coverage gap
 * ("OGWA could not determine whether a dependency exists"); what it did find still counts.
 */
export function impactOf(check) {
  const p = check.provenance || {};
  const established = p.resultStatus === "COMPLETE" && p.decisionGrade === true;
  const found = check.findings || [];
  const blocks = found.some((f) => f.blocking);
  let category;
  if (!found.length) category = established ? "none-found" : "coverage-gap";
  else if (DIRECTORY_KINDS.has(check.dependencyKind)) category = "directory-constraint";
  else if (REFERENCE_KINDS.has(check.dependencyKind)) category = "external-reference";
  else category = "known-dependency";
  let effect;
  let tone;
  if (blocks) { effect = "Blocks lifecycle progress for this group"; tone = "blocked"; }
  else if (found.length) { effect = "Informational: does not block on its own"; tone = "neutral"; }
  else if (established) { effect = "None found (complete, decision-grade check)"; tone = "neutral"; }
  else { effect = "Not established: OGWA could not determine whether a dependency exists"; tone = "caution"; }
  return {
    category, categoryLabel: IMPACT_CATEGORY[category], effect, tone, blocks, established,
    // Something found by an incomplete check counts, but it is not the whole picture.
    incompleteNote: found.length && !established ? "The check did not complete: more may exist." : null,
  };
}

// --- governance rules -----------------------------------------------------------------------------

// Plain words first; the rule code (app/governance/analysis.py RULES) is kept as the identifier.
export const RULE_LABEL = Object.freeze({
  EMPTY_GROUP_ASSIGNED: "Assigned group gives nobody access",
  ASSIGNED_TO_INACTIVE_APP: "Group still assigned to an inactive application",
  DEPRECATED_GROUP_STILL_ASSIGNED: "Deprecated group still assigned",
  TERMINATED_MEMBERS_RETAINED: "Deactivated members still retain access",
  ADMIN_TIER_UNEXPECTED_MEMBER: "Unexpected member in an administrator tier",
  PUSH_TARGET_MISSING: "Pushed AD group no longer exists",
  BROAD_PRIVILEGED_NESTING: "A whole department inherits a privileged tier",
  STALE_DEPRECATED_GROUP: "Deprecated group left behind",
  DUPLICATE_ENTITLEMENT: "Several groups grant the same access",
  NONSTANDARD_NAME_RECENT: "Recent group breaks the naming standard",
  DEEP_NESTING: "Access passes through deep nesting",
  UNNECESSARY_INTERMEDIATE: "Group only passes access through",
  OWNER_MISSING: "No recorded owner",
  OWNER_DEPARTED: "Owner has left the company",
  UNUSED_GROUP: "Group appears unused",
  MAPPING_REVIEW_NEEDED: "AD counterpart not established",
  DUPLICATE_NAME: "Name shared with another group",
  LEGACY_NAMING: "Pre-standard name",
  LEGACY_NAMED_ASSIGNMENT: "Access granted under a pre-standard name",
  DIRECT_ASSIGNMENTS_BYPASS_GROUPS: "Individual assignments bypass groups",
  DIRECT_ASSIGNMENT_ONLY: "Every assignment is to an individual",
  REDUNDANT_ACCESS_PATHS: "People reach the application several ways",
  INACTIVE_APP_STILL_ASSIGNED: "Inactive application still has assignments",
  LOW_USAGE: "Almost no sign-ins in 90 days",
  NOT_STANDARDIZED: "No standard groups for this application yet",
});

/** A governance rule's plain-language label; an unknown code is shown as itself. */
export function ruleLabel(code) {
  return RULE_LABEL[code] || String(code);
}

// --- plans and simulations ------------------------------------------------------------------------

/**
 * A recorded job's status in words that never suggest a change was made: a dry run that
 * finished says nothing was executed. A job recorded as executed is shown as blocked, because
 * this build cannot execute.
 */
export function planStatus(job) {
  if (job.executed) return { label: "Recorded as executed: this build cannot execute", tone: "blocked" };
  if (!job.dryRun) return { label: "Not a dry run: treat as invalid", tone: "blocked" };
  if (job.status === "SUCCEEDED") return { label: "Plan finished, nothing executed", tone: "neutral" };
  if (job.status === "FAILED") return { label: "Plan failed, nothing executed", tone: "blocked" };
  const words = String(job.status).replace(/_/g, " ").toLowerCase();
  return { label: `${words.charAt(0).toUpperCase()}${words.slice(1)}, nothing executed`, tone: "neutral" };
}
