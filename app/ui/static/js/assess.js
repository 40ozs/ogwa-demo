// Plain-language reading of API evidence. Pure functions, no DOM: tests/ui/assess.test.mjs.
//
// Rules this module keeps:
// - It never judges evidence itself. Freshness, coverage, and blocking come from the
//   server's classification (made under the policy in force); this module only words them.
// - There is no reassuring tone. Facts are "info" at best; anything unproven is "caution"
//   or "blocked". An exact mapping is a fact, not a safety verdict.
// - "Unavailable" and "stale" are different conditions (owner decision D97). A directory
//   SID that Okta reports is unverified metadata; it never establishes a mapping (D37).
//   Nothing here says that re-collecting evidence will clear a condition unless that is
//   the only thing the condition is about, and even then it says "only clears when".
// - Name-only, ambiguous, not-found, and missing mappings stay distinct (D98).

export const TONES = Object.freeze(["blocked", "caution", "info", "neutral", "terminal"]);

// --- lifecycle states ---------------------------------------------------------------------

export const STATE_INFO = Object.freeze({
  DISCOVERED: { label: "Discovered", tone: "neutral", text: "Observed by discovery. Not a candidate yet." },
  CANDIDATE: { label: "Candidate", tone: "info", text: "Evidence suggests a review. A candidate is not an authorization." },
  NEEDS_REVIEW: { label: "Needs review", tone: "info", text: "Waiting for a reviewer's decision." },
  APPROVED: { label: "Approved for a future Okta step", tone: "caution",
    text: "The Okta unassignment is approved for a future, separately executed step. Nothing has been changed." },
  OKTA_UNASSIGN_DRY_RUN: { label: "Okta dry run recorded", tone: "caution",
    text: "A dry run of the Okta unassignment was recorded. OGWA changed nothing." },
  HOLD: { label: "Post-unassignment hold period", tone: "caution",
    text: "Discovery observed the Okta unassignment. The AD quarantine waits for the hold period to end and for evidence to be revalidated." },
  REVALIDATION_REQUIRED: { label: "Revalidation required", tone: "caution",
    text: "Evidence must be revalidated before anyone may approve an AD quarantine." },
  // The AD stages: quarantine, a 30-day hold, then a separately proposed and approved deletion.
  QUARANTINE_APPROVED: { label: "Approved for a future AD quarantine", tone: "caution",
    text: "The AD quarantine is approved for a future, separately executed step. It authorizes no deletion. Nothing has been changed." },
  QUARANTINE_DRY_RUN: { label: "AD quarantine dry run recorded", tone: "caution",
    text: "A dry run of moving the AD group into its quarantine OU was recorded. OGWA changed nothing." },
  QUARANTINE_HOLD: { label: "Post-quarantine hold period", tone: "caution",
    text: "Discovery observed the AD group in its quarantine OU. A 30-day hold runs; its end only opens revalidation and never authorizes deletion." },
  DELETION_REVALIDATION_REQUIRED: { label: "Revalidation required before deletion", tone: "caution",
    text: "Evidence collected after the post-quarantine hold must be complete and fresh before anyone may propose a deletion." },
  DELETION_PROPOSED: { label: "Deletion proposed", tone: "caution",
    text: "A person proposed deleting the quarantined AD group. Someone else must approve it: not the proposer, the quarantine approver, or the Okta approver." },
  DELETION_APPROVED: { label: "Approved for a future AD deletion", tone: "caution",
    text: "The AD deletion is approved for a future, separately executed step. Nothing has been changed." },
  DELETION_DRY_RUN: { label: "AD deletion dry run recorded", tone: "caution",
    text: "A dry run of deleting the AD group was recorded. OGWA changed nothing." },
  RETIREMENT_DRY_RUN: { label: "Legacy AD retirement dry run", tone: "caution",
    text: "Recorded under the legacy single AD stage, which is history only. Nothing may continue from it except a hold, exclusion, or rejection." },
  RETIRED: { label: "Retired (observed)", tone: "terminal", text: "Read-only discovery observed the AD group deleted. Terminal." },
  EXCLUDED: { label: "Excluded", tone: "terminal", text: "Excluded by an operator. Terminal: new evidence would create a new candidate." },
  REJECTED: { label: "Rejected", tone: "terminal", text: "Rejected by an operator. Terminal: new evidence would create a new candidate." },
  BLOCKED: { label: "Held by an operator", tone: "blocked",
    text: "Blocked by an operator. Lifting the block needs a person and passes the re-entry checks." },
  MAPPING_AMBIGUOUS: { label: "Blocked: identity not proven", tone: "blocked",
    text: "Blocked until the Okta group's AD counterpart is proven." },
  DEPENDENCY_BLOCKED: { label: "Blocked: dependency", tone: "blocked", text: "Blocked by a dependency finding." },
  PROTECTED: { label: "Protected", tone: "blocked", text: "A protected group. OGWA never retires it. Terminal." },
  // The two evidence conditions are recorded by discovery and classification, never by an
  // operator, and they are different facts (owner decisions).
  STALE_EVIDENCE: { label: "Blocked: evidence stale", tone: "blocked",
    text: "Evidence that was once complete has outlived its freshness window. Fresh evidence is needed before any decision; other conditions below may still apply." },
  EVIDENCE_INCOMPLETE: { label: "Blocked: evidence incomplete", tone: "blocked",
    text: "Required evidence was never fully or properly obtained. The reasons below say what is missing." },
});

export function stateInfo(state) {
  return STATE_INFO[state] || { label: String(state), tone: "caution", text: "Unrecognized state: treat as blocked." };
}

// --- identity mapping (D37, D97, D98) -------------------------------------------------------

const EXACT = Object.freeze({
  EXACT_STABLE_ID: "Exact: stable identifier",
  EXACT_DIRECTORY_SOURCE: "Exact: directory source",
  EXACT_CONFIGURED_MAPPING: "Exact: configured mapping",
});

/**
 * How the Okta group maps to AD, worded for a reviewer.
 * Returns {key, label, tone, headline, detail, blocksAutomation}.
 */
export function mappingInfo(mapping, oktaGroup) {
  const sid = oktaGroup && oktaGroup.directoryObjectSidUnverified;
  const sidNote = sid
    ? "Okta reports a directory SID for this group. It is unverified source metadata: it can corroborate a mapping but never establish one (D37)."
    : null;
  if (!mapping) {
    return {
      key: "MISSING", label: "No mapping evidence", tone: "blocked", blocksAutomation: true,
      headline: "No mapping evidence — automatic retirement blocked.",
      detail: join("No identity-mapping observation is recorded, so which AD group this is remains unknown.", sidNote),
    };
  }
  if (mapping.isExact && EXACT[mapping.confidence]) {
    const basis = mapping.matchedAttributes && mapping.matchedAttributes.length
      ? `Matched on ${mapping.matchedAttributes.join(" and ")}.` : null;
    const ref = mapping.configurationRef ? `Configuration: ${mapping.configurationRef}.` : null;
    return {
      key: mapping.confidence, label: EXACT[mapping.confidence], tone: "info", blocksAutomation: false,
      headline: `${EXACT[mapping.confidence]}.`,
      detail: join(basis, ref, "An exact mapping identifies the AD group. It says nothing about whether changing it is safe."),
    };
  }
  switch (mapping.confidence) {
    case "NAME_ONLY":
      return {
        key: "NAME_ONLY", label: "Name-only match", tone: "blocked", blocksAutomation: true,
        headline: "Name-only match — automatic retirement blocked.",
        detail: join("Only the names match. A matching name never proves which AD group this is; a person must establish the mapping.", sidNote),
      };
    case "AMBIGUOUS": {
      const n = (mapping.candidateAdGroupIds || []).length;
      return {
        key: "AMBIGUOUS", label: "Ambiguous", tone: "blocked", blocksAutomation: true,
        headline: "Mapping ambiguous — automatic retirement blocked.",
        detail: join(`${n || "Several"} AD groups could be the counterpart. Until a reviewed decision picks one, none is assumed.`, sidNote),
      };
    }
    case "NOT_FOUND":
      return {
        key: "NOT_FOUND", label: "AD group not found", tone: "blocked", blocksAutomation: true,
        headline: "Mapped AD group not found — automatic retirement blocked.",
        detail: join("No AD group with the expected identity was found. It may have been removed or renamed, or the identity may be wrong.", sidNote),
      };
    case "UNVERIFIED_STABLE_ID":
      return {
        key: "UNVERIFIED_STABLE_ID", label: "Directory SID observed, unverified", tone: "blocked", blocksAutomation: true,
        headline: "Directory SID observed but unverified — automatic retirement blocked.",
        detail: "Okta's directory SID resolves to one AD group, but that source is not yet verified against real AD (D37). It corroborates; it cannot establish the mapping.",
      };
    default:
      return {
        key: String(mapping.confidence), label: "Not exact", tone: "blocked", blocksAutomation: true,
        headline: "Mapping not exact — automatic retirement blocked.",
        detail: join(`Recorded confidence: ${mapping.confidence}.`, sidNote),
      };
  }
}

// --- classification reasons -------------------------------------------------------------------

// Blocking reason codes, worded. Codes that are not listed fall back to the server's detail.
// `gate` names what the condition stops.
const REASON_TEXT = Object.freeze({
  EVIDENCE_STALE: { tone: "blocked", headline: "Evidence stale — revalidation required.",
    detail: "Some evidence is older than the policy allows for this step. Fresh evidence must be collected before a decision; any other condition listed here still applies." },
  EVIDENCE_NOT_DECISION_GRADE: { tone: "blocked", headline: "Evidence incomplete — a collection did not finish.",
    detail: "At least one collector returned a partial or failed result, so the evidence cannot support a decision. This condition only clears when a complete, decision-grade collection is recorded." },
  // Owner decision: future-dated evidence is never fresh and never
  // stale; it is incomplete/invalid evidence with its own reason.
  EVIDENCE_FUTURE_DATED: { tone: "blocked", headline: "Future-dated evidence — invalid, decisions blocked.",
    detail: "A record's timestamp is ahead of the server clock (beyond the allowed clock skew). It is neither fresh nor stale: it is treated as invalid, incomplete evidence until the timestamp is explained." },
  EVIDENCE_INCONSISTENT: { tone: "blocked", headline: "Evidence inconsistent — blocked.", detail: null },
  REQUIRED_CONDITION_UNPROVEN: { tone: "blocked", headline: "A required condition is unproven — retirement blocked.", detail: null },
  AD_GROUP_NOT_OBSERVED: { tone: "blocked", headline: "AD evidence unavailable — AD deletion blocked.",
    detail: "There is no observation of the AD group at all. This is missing evidence, not old evidence." },
  AD_GROUP_NOT_FOUND: { tone: "blocked", headline: "AD group not found — AD deletion blocked.", detail: null },
  AD_MEMBERSHIP_UNKNOWN: { tone: "blocked", headline: "AD membership not checked — AD deletion blocked.",
    detail: "No complete membership check is recorded, so whether the group has members is unknown." },
  AD_NESTING_UNKNOWN: { tone: "blocked", headline: "AD nesting not checked — AD deletion blocked.",
    detail: "No complete nesting check is recorded, so parent groups and nested members are unknown." },
  DEPENDENCY_COVERAGE_INCOMPLETE: { tone: "blocked", headline: "Dependency coverage incomplete — AD deletion blocked.",
    detail: "Not every required dependency kind has a decision-grade check. Unchecked is not the same as clear." },
  OTHER_ASSIGNMENTS_UNKNOWN: { tone: "blocked", headline: "Other Okta assignments not checked — retirement blocked.",
    detail: "Whether this group is assigned to other applications is unknown." },
  SHARED_OKTA_ASSIGNMENT: { tone: "blocked", headline: "Group is assigned to another application — retirement blocked.", detail: null },
  AD_DIRECT_MEMBERS: { tone: "blocked", headline: "AD group has members — AD deletion blocked.", detail: null },
  AD_MEMBERSHIP_FINDING: { tone: "blocked", headline: "AD group has members — AD deletion blocked.", detail: null },
  AD_PRIMARY_GROUP_REFERENCES: { tone: "blocked", headline: "Objects use this as their primary group — AD deletion blocked.", detail: null },
  AD_PARENT_GROUP: { tone: "blocked", headline: "Nested in another group — AD deletion blocked.", detail: null },
  AD_MEMBER_GROUPS: { tone: "blocked", headline: "Contains other groups — AD deletion blocked.", detail: null },
  AD_NESTED_PRINCIPALS: { tone: "blocked", headline: "Principals reach access through nesting — AD deletion blocked.", detail: null },
  AD_NESTING_FINDING: { tone: "blocked", headline: "Nested group dependency — AD deletion blocked.", detail: null },
  DEPENDENCY_FINDING: { tone: "blocked", headline: "Blocking dependency finding.", detail: null },
  PROTECTED_GROUP: { tone: "blocked", headline: "Protected group — OGWA never retires it.", detail: null },
  PROTECTION_UNDETERMINED: { tone: "blocked", headline: "Protection status unknown — treated as protected.",
    detail: "Unknown protection cannot be overridden (D21)." },
  USAGE_ABOVE_RETIREMENT_THRESHOLD: { tone: "blocked", headline: "Application still in use — not a retirement candidate.", detail: null },
  IN_USE: { tone: "blocked", headline: "Application in use.", detail: null },
  USAGE_WINDOW_TOO_SHORT: { tone: "blocked", headline: "Usage window too short to support retirement.", detail: null },
  USAGE_WINDOW_REVIEW_ONLY: { tone: "caution", headline: "Usage window supports review only, not retirement.", detail: null },
  USAGE_NOT_OBSERVED: { tone: "blocked", headline: "Usage not observed — retirement blocked.",
    detail: "No usage observation is recorded. Missing usage is not zero usage." },
  APPLICATION_NOT_OBSERVED: { tone: "blocked", headline: "Application not observed — blocked.", detail: null },
  OKTA_GROUP_NOT_OBSERVED: { tone: "blocked", headline: "Okta group not observed — blocked.", detail: null },
  ASSIGNMENT_NOT_OBSERVED: { tone: "blocked", headline: "Okta assignment not observed — blocked.", detail: null },
  ASSIGNMENT_ABSENT: { tone: "caution", headline: "Okta assignment no longer observed.",
    detail: "Expected after an observed unassignment; otherwise a reason to re-check the evidence." },
  NOT_AD_SOURCED: { tone: "blocked", headline: "Not an AD-sourced group — AD retirement does not apply.", detail: null },
  OKTA_ONLY_GROUP: { tone: "blocked", headline: "Okta-only group — AD retirement does not apply.", detail: null },
});

// Mapping reason codes are worded by mappingInfo(), so the banner says it once.
const MAPPING_CODES = new Set(["MAPPING_MISSING", "MAPPING_NAME_ONLY", "MAPPING_AMBIGUOUS", "MAPPING_NOT_FOUND",
  "MAPPING_UNVERIFIED_IDENTIFIER", "MAPPING_NOT_EXACT"]);

const TONE_ORDER = { blocked: 0, caution: 1, info: 2, neutral: 3, terminal: 4 };

/**
 * The conditions a reviewer must see first, most severe first, each said once.
 * detail = GET /candidates/{id}; evidence = GET /candidates/{id}/evidence.
 * Returns [{tone, headline, detail, codes, count}].
 */
export function candidateBanners(detail, evidence) {
  const out = [];
  const byHeadline = new Map();
  const add = (tone, headline, text, code) => {
    const existing = byHeadline.get(headline);
    if (existing) {
      existing.count += 1;
      if (code && !existing.codes.includes(code)) existing.codes.push(code);
      return;
    }
    const item = { tone, headline, detail: text, codes: code ? [code] : [], count: 1 };
    byHeadline.set(headline, item);
    out.push(item);
  };
  const classification = detail && detail.classification;
  const ev = evidence || {};
  const mapping = mappingInfo(ev.mapping || null, ev.oktaGroup || null);
  if (mapping.blocksAutomation) add(mapping.tone, mapping.headline, mapping.detail, `MAPPING:${mapping.key}`);

  if (!classification) {
    add("blocked", "No classification available — every action is blocked.",
      "The server could not classify this candidate (no policy in force, or no assignment evidence).", null);
  } else {
    for (const reason of classification.reasons || []) {
      if (!reason.blocks || MAPPING_CODES.has(reason.code)) continue;
      const known = REASON_TEXT[reason.code];
      if (known) add(known.tone, known.headline, known.detail || reason.detail, reason.code);
      else add("blocked", `${reason.code.replace(/_/g, " ").toLowerCase()} — blocked.`, reason.detail, reason.code);
    }
    if (classification.adDeletionProhibited) {
      add("caution", "AD deletion is not permitted on this evidence.",
        "The classifier found at least one unproven or blocking condition for AD retirement.", "AD_DELETION_PROHIBITED");
    }
  }
  if (ev.oktaGroup && ev.oktaGroup.directoryObjectSidUnverified && !mapping.blocksAutomation) {
    add("neutral", "Okta reports a directory SID (unverified).",
      "Unverified source metadata. The mapping above rests on other evidence; the SID never establishes it (D37).", "SID_UNVERIFIED");
  }
  // Stable sort: most severe first, keeping the server's order within a tone.
  return out
    .map((item, index) => ({ item, index }))
    .sort((a, b) => (TONE_ORDER[a.item.tone] - TONE_ORDER[b.item.tone]) || (a.index - b.index))
    .map(({ item }) => item);
}

/** Reason codes that mean "missing" (unavailable) versus "old" (stale): D97. */
export function evidenceCondition(classification) {
  const codes = new Set(((classification && classification.reasons) || []).filter((r) => r.blocks).map((r) => r.code));
  return {
    stale: codes.has("EVIDENCE_STALE"),
    futureDated: codes.has("EVIDENCE_FUTURE_DATED"),
    unavailable: ["AD_GROUP_NOT_OBSERVED", "EVIDENCE_NOT_DECISION_GRADE", "USAGE_NOT_OBSERVED", "APPLICATION_NOT_OBSERVED",
      "OKTA_GROUP_NOT_OBSERVED", "ASSIGNMENT_NOT_OBSERVED", "MAPPING_MISSING"].some((c) => codes.has(c)),
    unchecked: ["AD_MEMBERSHIP_UNKNOWN", "AD_NESTING_UNKNOWN", "OTHER_ASSIGNMENTS_UNKNOWN", "DEPENDENCY_COVERAGE_INCOMPLETE"]
      .some((c) => codes.has(c)),
  };
}

/** Subjects (evidence ids) that the classifier called stale. */
export function staleSubjects(classification) {
  return subjectsWith(classification, "EVIDENCE_STALE");
}

/** Subjects (evidence ids) that the classifier found dated in the future: invalid, not stale. */
export function futureDatedSubjects(classification) {
  return subjectsWith(classification, "EVIDENCE_FUTURE_DATED");
}

function subjectsWith(classification, code) {
  return new Set(((classification && classification.reasons) || [])
    .filter((r) => r.code === code && r.subject).map((r) => r.subject));
}

// --- dependencies ------------------------------------------------------------------------------

export const KIND_LABEL = Object.freeze({
  OKTA_OTHER_APP_ASSIGNMENT: "Other Okta application assignments",
  OKTA_POLICY_REFERENCE: "Okta policy and group-rule references",
  AD_GROUP_MEMBERS: "AD members and primaryGroupID",
  AD_NESTED_MEMBERSHIP: "AD nesting (parents and member groups)",
  AD_ACL_REFERENCE: "AD ACL references",
  GPO_REFERENCE: "GPO references",
  AAP_REFERENCE: "AAP references",
  APPLICATION_CONFIGURATION: "Application configuration",
  OTHER: "Other",
});

export const COVERAGE_TEXT = Object.freeze({
  COVERED: { label: "Checked (decision-grade)", tone: "info" },
  NOT_COUNTED_SOURCE: { label: "Checked, but by a source that does not count", tone: "caution" },
  NOT_DECISION_GRADE: { label: "Checked, not decision-grade", tone: "caution" },
  NOT_CHECKED: { label: "Not checked", tone: "blocked" },
});

export function coverageText(status) {
  return COVERAGE_TEXT[status] || { label: String(status), tone: "caution" };
}

export function overallCoverageText(overall) {
  return {
    COMPLETE: { label: "Complete: every required kind checked", tone: "info" },
    PARTIAL: { label: "Partial: some required kinds unchecked", tone: "blocked" },
    UNKNOWN: { label: "Unknown: no required kind checked", tone: "blocked" },
  }[overall] || { label: String(overall || "Unavailable"), tone: "blocked" };
}

function decisionGradeChecks(dependencies, kind) {
  return (dependencies || []).filter((d) => d.dependencyKind === kind
    && d.provenance && d.provenance.decisionGrade && d.provenance.resultStatus === "COMPLETE");
}

function findingsOf(dependencies, kind, codes, uncoded) {
  const out = [];
  for (const d of dependencies || []) {
    if (d.dependencyKind !== kind) continue;
    for (const f of d.findings || []) {
      if (codes.includes(f.code) || (uncoded && f.code === null)) out.push(f);
    }
  }
  return out;
}

/**
 * Membership facts for the candidate detail, each {value, basis}: the AD group's direct
 * member count, primaryGroupID references, parent groups, and nested membership. "None
 * observed" is only said after a complete, decision-grade check; otherwise "not checked".
 */
export function membershipFacts(evidence) {
  const ev = evidence || {};
  const deps = ev.dependencies || [];
  const ad = ev.adGroup;
  const membersChecked = decisionGradeChecks(deps, "AD_GROUP_MEMBERS").length > 0;
  const nestingChecked = decisionGradeChecks(deps, "AD_NESTED_MEMBERSHIP").length > 0;
  const describe = (items, checked) => {
    if (items.length) return { value: items.map((f) => f.description).join("; "), basis: "finding", count: items.length };
    if (checked) return { value: "None observed (complete check)", basis: "checked", count: 0 };
    return { value: "Not checked", basis: "unchecked", count: null };
  };
  let direct;
  if (!ad) direct = { value: "Unknown: AD group not observed", basis: "unavailable", count: null };
  else if (ad.exists === false) direct = { value: "AD group does not exist", basis: "observed", count: null };
  // An unread member attribute is unknown, never zero.
  else if (ad.memberCount === null || ad.memberCount === undefined) direct = { value: "Unknown: the member attribute was not read", basis: "unavailable", count: null };
  else direct = { value: `${ad.memberCount} (AD member attribute)`, basis: "observed", count: ad.memberCount };
  return {
    direct,
    directFindings: describe(findingsOf(deps, "AD_GROUP_MEMBERS", ["AD_DIRECT_MEMBERS"], true), membersChecked),
    primaryGroup: describe(findingsOf(deps, "AD_GROUP_MEMBERS", ["AD_PRIMARY_GROUP_REFERENCES"], false), membersChecked),
    parents: describe(findingsOf(deps, "AD_NESTED_MEMBERSHIP", ["AD_PARENT_GROUP"], true), nestingChecked),
    memberGroups: describe(findingsOf(deps, "AD_NESTED_MEMBERSHIP", ["AD_MEMBER_GROUPS", "AD_NESTED_PRINCIPALS"], false), nestingChecked),
  };
}

/** The AD group's protection, worded. Never "not protected" unless the server's reasons say so. */
export function protectionInfo(adGroup, classification) {
  const codes = new Set(((classification && classification.reasons) || []).map((r) => r.code));
  if (codes.has("PROTECTED_GROUP")) return { label: "Protected", tone: "blocked" };
  if (codes.has("PROTECTION_UNDETERMINED")) return { label: "Unknown — treated as protected", tone: "blocked" };
  if (!adGroup) return { label: "Unknown: AD group not observed", tone: "blocked" };
  if (codes.has("NOT_PROTECTED")) return { label: "No protection marker observed", tone: "neutral" };
  return { label: "Not determined by the classifier", tone: "caution" };
}

// --- usage ------------------------------------------------------------------------------------

export function usageSummary(usage) {
  if (!usage || !usage.length) return { window: "No usage observation", last: "Unknown: usage not observed", tone: "blocked" };
  const u = usage[0];
  const partial = u.provenance && u.provenance.resultStatus !== "COMPLETE";
  return {
    window: `${u.windowStart} to ${u.windowEnd}`,
    windowStart: u.windowStart, windowEnd: u.windowEnd,
    events: u.eventCount, users: u.distinctUserCount,
    last: u.lastActivityAt ? u.lastActivityAt : (partial ? "Unknown: usage collection incomplete" : "None in the window"),
    lastAt: u.lastActivityAt,
    tone: partial ? "blocked" : "neutral",
    partial,
  };
}

// --- actions ----------------------------------------------------------------------------------

// The only lifecycle targets the UI offers, and what each is called (the action list).
// HOLD in the lifecycle is the post-unassignment period, not an operator action, so the
// operator's "Hold" is the generic BLOCKED diversion.
export const UI_TRANSITIONS = Object.freeze({
  BLOCKED: "hold",
  EXCLUDED: "exclude",
  REJECTED: "reject",
  REVALIDATION_REQUIRED: "revalidate",
  DELETION_REVALIDATION_REQUIRED: "revalidate",
  DELETION_PROPOSED: "proposeDeletion",
  OKTA_UNASSIGN_DRY_RUN: "recordDryRun",
  QUARANTINE_DRY_RUN: "recordDryRun",
  DELETION_DRY_RUN: "recordDryRun",
});

// Where each stage's dry run is planned (its approved state), and the state the dry run records.
const STAGE_FOR_STATE = Object.freeze({
  APPROVED: "OKTA_UNASSIGN", QUARANTINE_APPROVED: "AD_QUARANTINE", DELETION_APPROVED: "AD_DELETION",
});
const DRY_RUN_TARGET = Object.freeze({
  OKTA_UNASSIGN: "OKTA_UNASSIGN_DRY_RUN", AD_QUARANTINE: "QUARANTINE_DRY_RUN", AD_DELETION: "DELETION_DRY_RUN",
});

/** Approvals that could back a dry run of `stage` right now (the server re-checks everything). */
export function usableApprovals(approvals, candidate, stage) {
  return (approvals || []).filter((a) => a.stage === stage && a.decision === "APPROVE" && !a.expired
    && a.candidateEpoch === candidate.epoch);
}

/**
 * What the signed-in person can be offered on this candidate. Only these actions exist:
 * approve for future action / decline approval, hold, exclude, reject, request
 * revalidation, plan a dry run, and record a planned dry run. allowedActions is the
 * server's hint; the server checks everything again when the action is requested.
 */
export function actionPlan(detail, approvals, jobs) {
  const candidate = detail.candidate;
  const allowed = detail.allowedActions || { transitions: [], approvals: [], planDryRun: false };
  const plan = { approvals: [], transitions: [], dryRun: null, recordDryRun: null };
  for (const a of allowed.approvals || []) {
    const conflicts = a.separationOfDutiesConflicts || [];
    if (a.permitted || conflicts.length) plan.approvals.push({ stage: a.stage, permitted: a.permitted, conflicts });
  }
  for (const t of allowed.transitions || []) {
    const action = UI_TRANSITIONS[t.target];
    if (!action || !t.permitted || !t.operatorAction || action === "recordDryRun") continue;
    plan.transitions.push({ action, target: t.target, category: t.category, needsFingerprint: t.requiresEvidenceFingerprint });
  }
  const stage = STAGE_FOR_STATE[candidate.state];
  if (allowed.planDryRun && stage) {
    plan.dryRun = { kind: stage, approvals: usableApprovals(approvals, candidate, stage) };
  }
  const target = stage && DRY_RUN_TARGET[stage];
  const recordable = (allowed.transitions || []).find((t) => t.target === target && t.permitted && t.operatorAction);
  if (recordable) {
    const usable = new Set(usableApprovals(approvals, candidate, stage).map((a) => a.id));
    const succeeded = (jobs || []).filter((j) => j.kind === stage && j.status === "SUCCEEDED" && j.dryRun
      && !j.executed && usable.has(j.approvalId));
    if (succeeded.length) plan.recordDryRun = { target, jobs: succeeded };
  }
  return plan;
}

// --- errors -----------------------------------------------------------------------------------

const ERROR_TEXT = Object.freeze({
  EVIDENCE_CHANGED: "The evidence changed since you loaded this page. Nothing was recorded. Reload and review again.",
  EVIDENCE_RULES_NOT_MET: "The lifecycle rules refuse this step on the current evidence, so it cannot be recorded.",
  SEPARATION_OF_DUTIES: "Four-eyes rule: someone else must do this.",
  TRANSITION_REFUSED: "The lifecycle refused this step. The refusal was recorded in the audit trail.",
  APPROVAL_INVALID: "The approval does not authorize this dry run.",
  INVALID_STATE: "The candidate is not in a state where this can be recorded. Reload to see its current state.",
  PRODUCTION_MUTATION_REFUSED: "This build never changes production. The request was refused.",
  LEGACY_AD_RETIREMENT: "The legacy single AD stage is history only. AD quarantine and AD deletion are approved separately.",
  FORBIDDEN: "You do not have permission for this.",
  UNAUTHENTICATED: "Your session has ended. Sign in again.",
  VALIDATION_FAILED: "The form was not accepted.",
  NETWORK_ERROR: "The OGWA service could not be reached. Nothing was recorded.",
  CSRF_FAILED: "The request could not be verified. Reload the page and try again.",
});

export function errorText(code, fallback) {
  return ERROR_TEXT[code] || fallback || "The request failed.";
}

function join(...parts) {
  return parts.filter(Boolean).join(" ");
}
