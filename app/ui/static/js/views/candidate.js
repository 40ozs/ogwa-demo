import {
  anonymous, can, canDrill, checkedId, decideApproval, get, planDryRun, principal, runRemediationDrill, transition,
} from "../api.js";
import {
  actionPlan, candidateBanners, futureDatedSubjects, KIND_LABEL, mappingInfo, membershipFacts, overallCoverageText,
  protectionInfo, staleSubjects, stateInfo, usableApprovals, usageSummary,
} from "../assess.js";
import {
  attemptRows, chainFacts, drillOutcome, elapsedText, ledgerRows, MODE_TEXT, modeBanner, OPERATION_TEXT, stageFor,
  stepFacts, stepTone,
} from "../drill.js";
import { actorText, age, badge, banner, facts, fmtTime, h, humanize, mono, section, table, uid, yesNo } from "../dom.js";
import {
  freshnessText, otherAssignmentsFact, requiredText, reviewerAnswers, stanceText, stateText,
} from "../evidence.js";
import { conditionRank, evidenceLabels, explanationAnswers, policyAgainstInForce, policyName } from "../policy.js";
import { evidenceReadiness, lifecycleStages, nextStep, planStatus, reviewStatus } from "../review.js";
import { appLink, errorBox, groupLink, identity, jobLink, mappingLink, resolveRefs } from "./common.js";
import { coverageTable, resultBadge } from "./inventory.js";

const MAX_REASON = 1000;
const STAGE_LABEL = { OKTA_UNASSIGN: "Okta unassignment", AD_QUARANTINE: "AD quarantine", AD_DELETION: "AD deletion",
  AD_RETIREMENT: "AD retirement (legacy)" };

export async function candidate(ctx) {
  const id = checkedId(ctx.params.id);
  const [detail, evidence, deps, decisions, approvals, jobs] = await Promise.all([
    get(`/candidates/${id}`), get(`/candidates/${id}/evidence`), get(`/candidates/${id}/dependencies`),
    get(`/candidates/${id}/decisions`), get(`/candidates/${id}/approvals`), get(`/candidates/${id}/execution-jobs`),
  ]);
  const c = detail.candidate;
  const [group, audit, drillCatalog] = await Promise.all([
    get(`/groups/${checkedId(c.oktaGroupId)}`),
    can("READ_AUDIT") ? get(`/candidates/${id}/audit-events`, { limit: 50 }) : Promise.resolve(null),
    stageFor(c.state) ? get("/remediation-drill-scenarios") : Promise.resolve(null),
  ]);
  const okta = evidence.oktaGroup;
  // Names for every id this page shows: the AD group, other applications, and reason subjects.
  const refs = await resolveRefs([evidence.adGroup && evidence.adGroup.id,
    ...(group.assignments || []).map((a) => a.applicationId),
    ...((detail.classification && detail.classification.reasons) || []).map((r) => r.subject)]);
  ctx.setTitle(`Candidate: ${okta ? okta.name : c.oktaGroupId}`);

  const classification = detail.classification;
  const now = (classification && classification.classifiedAt) || null;
  const info = stateInfo(c.state);
  const fingerprintDrift = evidence.evidenceFingerprint !== detail.evidenceFingerprint;
  const banners = candidateBanners(detail, evidence);
  const plan = actionPlan(detail, approvals.items, jobs.items);
  const status = reviewStatus(c.state);

  // OGWA-UI-REVIEW-01: the operator's reading first (status, lifecycle, what blocks it, the next step, evidence
  // readiness), then the evidence and its provenance. Every line is read from the API; nothing is judged here.
  const main = h("div", { class: "detail-main" },
    ctx.flash ? h("div", { class: "banner", "data-tone": "info", role: "status" }, h("strong", null, ctx.flash)) : null,
    h("p", { class: "review-headline" }, badge(status.label, status.tone), " ", h("strong", null, info.label)),
    h("p", null, info.text),
    fingerprintDrift ? banner("blocked", "Evidence changed while this page loaded.", "Reload before recording anything.") : null,
    section("Lifecycle", stepper(lifecycleStages(c, decisions.items, now))),
    section("What blocks this candidate",
      banners.length ? h("ul", { class: "banner-list" }, banners.map((b) => h("li", null,
        h("div", { class: "banner", "data-tone": b.tone }, h("strong", null, b.headline),
          b.detail ? h("p", null, b.detail) : null,
          b.count > 1 ? h("p", null, `Applies to ${b.count} records.`) : null))))
        : banner("neutral", "The classifier found no blocking condition.",
          "This is not an authorization and not a safety verdict. Every action is checked again by the server."),
      classification ? h("p", { class: "muted" }, "Judged under ", classification.policy.name ? [h("strong", null, classification.policy.name), " "] : null,
        badge(classification.policy.label, classification.policy.recorded ? "info" : "caution"),
        ` at ${fmtTime(classification.classifiedAt)} (server clock).`) : null),
    nextStepSection(nextStep(c, now), plan),
    readinessSection(evidenceReadiness(detail.evidenceAssessment), classification),
    assessmentSection(detail.evidenceAssessment),
    explanationSection(detail.decisionExplanation, detail.evidenceAssessment),
    drillSection(detail, evidence, approvals.items, drillCatalog),
    section("Decision summary", summaryFacts(c, evidence, deps, group, classification, now, detail.quarantine, refs)),
    section("Classification reasons", reasonsTable(classification, refs)),
    section("Dependency coverage",
      deps.coverage ? h("p", null, "Overall: ", (() => { const t = overallCoverageText(deps.coverage.overall); return badge(t.label, t.tone); })()) : null,
      coverageTable(deps.coverage),
      h("h3", null, "Findings"),
      findingsTable(deps.findings)),
    section("Evidence timestamps", evidenceTable(evidence, classification, now)),
    section("Decision history", decisionsTable(decisions.items, detail.policy)),
    section("Approvals", approvalsTable(approvals.items, detail.policy)),
    section("Dry-run plans", jobsTable(jobs.items)),
    audit ? section("Audit trail", auditTable(audit.items)) : null,
  );

  ctx.view.append(h("div", { class: "detail-layout" }, main,
    h("aside", { "aria-labelledby": "actions-heading" },
      actionsPanel(ctx, detail, plan, fingerprintDrift))));
}

// --- the operator's reading (OGWA-UI-REVIEW-01) -------------------------------------------------

// A mark per stage status, hidden from assistive technology: the status is always written out too.
const STEP_MARK = { done: "✓", current: "●", waiting: "◷", blocked: "✕", closed: "■", future: "○", "not-reached": "–" };
const STEP_TONE = { done: "neutral", current: "caution", waiting: "caution", blocked: "blocked", closed: "terminal",
  future: "neutral", "not-reached": "neutral" };

/** The lifecycle as a list of stages: a reading of the state machine, which stays authoritative. */
function stepper(life) {
  return [h("p", { class: "stepper-summary" }, life.summary),
    h("ol", { class: "stepper", "aria-label": "Lifecycle stages" }, life.stages.map((s) => h("li", {
      class: "step", "data-status": s.status, "data-tone": STEP_TONE[s.status], "aria-current": s.note ? "step" : null },
    h("span", { class: "step-mark", "aria-hidden": "true" }, STEP_MARK[s.status]),
    h("span", { class: "step-label" }, s.label),
    h("span", { class: "step-status" }, s.statusText),
    s.note ? h("span", { class: "step-note" }, s.note) : null,
    s.until ? h("span", { class: "step-note" }, `until ${fmtTime(s.until)}`) : null))),
    h("p", { class: "muted" }, "Stages ahead are not guaranteed: each needs its own evidence checks and, where it records a change, a named person's approval.")];
}

function nextStepSection(step, plan) {
  const open = [
    ...plan.approvals.filter((a) => a.permitted).map((a) => `Approve or decline: ${STAGE_LABEL[a.stage] || a.stage}`),
    ...plan.transitions.map((t) => TRANSITION_FORMS[t.action].label),
    plan.dryRun ? `Run dry-run: ${STAGE_LABEL[plan.dryRun.kind]}` : null,
    plan.recordDryRun ? "Record the dry-run step" : null,
  ].filter(Boolean);
  return section("Next step",
    facts([
      ["Needs", h("strong", null, step.required)],
      ["What happens next", step.text],
      ["Who", step.who],
      ...(step.deadline ? [["Deadline", [step.deadline.label ? [badge(step.deadline.label, step.deadline.past ? "caution" : "neutral"), " "] : null,
        `until ${fmtTime(step.deadline.at)}`]]] : []),
    ], "Next step"),
    h("p", null, anonymous() ? "This public demo is read-only: nothing can be recorded here."
      : open.length ? `Open to you now, under Record a decision: ${open.join("; ")}. The server checks each one again.`
        : "No decision is open to you on this candidate in its current state."));
}

function readinessSection(readiness, classification) {
  if (!readiness) {
    return section("Evidence readiness", banner("blocked", "No evidence assessment is available.", "Treat every source as unknown."));
  }
  const all = readiness.required > 0 && readiness.usable === readiness.required;
  return section("Evidence readiness",
    // A sentence, so it wraps (a badge does not) and the page never scrolls sideways on a phone.
    h("p", null, h("strong", { class: "state-label", "data-tone": all ? "neutral" : readiness.required ? "blocked" : "caution" },
      readiness.required ? `${readiness.usable} of ${readiness.required} required sources complete and current` : "No source is marked required")),
    readiness.problems.length ? h("p", null, "Not complete and current: ", readiness.problems.join(", "), ".") : null,
    h("p", { class: "muted" }, classification ? `Evaluated at ${fmtTime(classification.classifiedAt)} on the server's clock, when this page loaded. ` : "",
      "Complete and current is not a safety verdict; each source's state and bearing are below."));
}

// --- synthetic remediation drill (OGWA-DEMO-03) ------------------------------------------------

const DRILL_TITLE = "Remediation: dry run or synthetic drill";

/**
 * A dry run or a synthetic execution drill of the stage's one remediation, against an
 * in-memory provider fixture the server builds from this candidate's synthetic evidence and
 * discards. It records nothing, so it does not reload the page: the candidate is unchanged.
 */
function drillSection(detail, evidence, approvals, catalog) {
  const c = detail.candidate;
  const stage = stageFor(c.state);
  if (!stage || !catalog) return null;
  const intro = banner("caution", "A drill changes only a synthetic provider fixture, and records nothing.", catalog.notice);
  if (!canDrill(c.id)) {
    return section(DRILL_TITLE, intro, h("p", { class: "muted" }, anonymous()
      ? "In this public demo, the drill runs only on the walkthrough's controlled-remediation candidate (Portfolio scenarios, part 2)."
      : "Running a drill needs the dry-run planning permission (the executor role), and the stage's approver cannot run it."));
  }
  const approved = usableApprovals(approvals, c, stage.stage);
  const targets = stage.targetField === "assignmentId" ? c.assignmentIds : (evidence.adGroup ? [evidence.adGroup.id] : []);
  if (!approved.length || !targets.length) {
    return section(DRILL_TITLE, intro, banner("caution", "No drill is possible yet.", approved.length
      ? "The candidate has no target for this operation."
      : `A drill starts from the same gates as a dry run, so it needs an unexpired ${STAGE_LABEL[stage.stage]} approval for this epoch. None exists.`));
  }
  const ids = { target: uid("drill-target"), approval: uid("drill-approval"), scenario: uid("drill-scenario"),
    help: uid("drill-help"), mode: uid("drill-mode") };
  const targetSelect = h("select", { id: ids.target, required: true }, targets.map((t) => h("option", { value: t }, t)));
  const approvalSelect = h("select", { id: ids.approval, required: true }, approved.map(approvalOption));
  const scenarioSelect = h("select", { id: ids.scenario, disabled: true, "aria-describedby": ids.help },
    catalog.items.map((x) => h("option", { value: x.key }, x.title)));
  const scenarioHelp = h("p", { class: "hint", id: ids.help }, catalog.items.length ? catalog.items[0].description : "");
  scenarioSelect.addEventListener("change", () => {
    const chosen = catalog.items.find((x) => x.key === scenarioSelect.value);
    scenarioHelp.textContent = chosen ? chosen.description : "";
  });
  const inputs = [];
  const modes = ["DRY_RUN", "SYNTHETIC_EXECUTION"].map((mode, i) => {
    const id = `${ids.mode}-${i}`;
    const input = h("input", { type: "radio", name: ids.mode, id, value: mode, checked: i === 0,
      "aria-describedby": `${id}-help` });
    input.addEventListener("change", () => { scenarioSelect.disabled = selectedMode() !== "SYNTHETIC_EXECUTION"; });
    inputs.push(input);
    return h("div", { class: "check" }, input, h("div", null, h("label", { for: id }, MODE_TEXT[mode].label),
      h("p", { class: "action-help", id: `${id}-help` }, MODE_TEXT[mode].help)));
  });
  const selectedMode = () => (inputs.find((i) => i.checked) || inputs[0]).value;
  const result = h("div", { class: "drill-result", "aria-live": "polite" });
  const run = h("button", { type: "submit" }, "Run drill");
  const form = h("form", { class: "drill-form", "aria-label": "Synthetic remediation drill", novalidate: true },
    facts([["Operation", [mono(stage.operation), ": ", OPERATION_TEXT[stage.operation]]],
      ["Approval stage", STAGE_LABEL[stage.stage]]], "The remediation this drill runs"),
    h("div", { class: "field" }, h("label", { for: ids.target }, "Target"), targetSelect),
    h("div", { class: "field" }, h("label", { for: ids.approval }, "Approval the drill starts from"), approvalSelect),
    h("fieldset", null, h("legend", null, "Mode"), modes),
    h("div", { class: "field" }, h("label", { for: ids.scenario }, "Fault scenario (synthetic execution only)"),
      scenarioHelp, scenarioSelect),
    h("div", { class: "form-buttons" }, run));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    run.disabled = true;
    result.replaceChildren(h("p", { class: "muted" }, "Waiting for the server's answer…"));
    try {
      const mode = selectedMode();
      const body = { operation: stage.operation, target: { [stage.targetField]: targetSelect.value },
        approvalId: approvalSelect.value, expectedEvidenceFingerprint: detail.evidenceFingerprint, mode };
      if (mode === "SYNTHETIC_EXECUTION") body.scenario = scenarioSelect.value;
      const data = await runRemediationDrill(c.id, body);
      result.replaceChildren(drillResult(data.drill, data));
    } catch (error) {
      result.replaceChildren(errorBox(error));
    } finally {
      run.disabled = false;
    }
    (result.querySelector("h3") || run).focus(); // a failure has no result heading: stay on Run drill, next to why
  });
  return section(DRILL_TITLE, intro, form, result);
}

function drillResult(drill, data) {
  const outcome = drillOutcome(drill);
  const mode = modeBanner(drill);
  const p = drill.provider || {};
  const start = drill.steps.length ? drill.steps[0].at : null;
  const title = drill.mode === "DRY_RUN" ? "Dry-run result"
    : `Synthetic execution drill: ${drill.scenario ? drill.scenario.title : "unnamed scenario"}`;
  const chain = chainFacts(data && data.chain, data && data.authorization);
  const attempts = attemptRows(data && data.chain);
  return h("div", { class: "drill-outcome", "data-mode": drill.mode },
    h("h3", { tabindex: "-1" }, title),
    // OGWA-DEMO-04: the mode, in the server's words, above everything else: a dry run and a
    // synthetic execution can never be mistaken for each other, or for a real change.
    h("div", { class: "banner drill-mode-banner", "data-tone": mode.tone, "data-mode": mode.mode || "UNKNOWN" },
      h("strong", { class: "drill-mode" }, mode.headline), h("p", null, mode.detail)),
    h("div", { class: "banner drill-banner", "data-tone": outcome.tone, role: "status" },
      h("strong", { class: "drill-state" }, outcome.headline), h("p", null, outcome.detail)),
    h("h4", null, "Authorized by"),
    chain ? facts(chain, "Authorization chain")
      : banner("blocked", "No authorization chain was returned.", "Treat this drill as unauthorized."),
    attempts.length ? table("Attempts", [
      { label: "Attempt", num: true, rowHeader: true, render: (r) => String(r.attempt) },
      { label: "Provider answer", render: (r) => r.answer },
      { label: "Verification read", render: (r) => r.verification },
      { label: "Then", render: (r) => mono(r.next) },
    ], attempts, "Nothing was submitted.") : null,
    facts([
      ["Planned change", drill.plannedTransition ? drill.plannedTransition.summary : "—"],
      ["Operation id (idempotency key)", mono(drill.operationId)],
      ["Submissions", `${drill.submissions} of at most ${drill.maxSubmissions}`],
      ["Synthetic provider state", p.stateChanged ? "Changed, inside the fixture only" : "Unchanged"],
      ["State digest before", mono(p.digestBefore)],
      ["State digest after", mono(p.digestAfter)],
      ["Recorded", drill.recorded ? "Yes" : "Nothing was recorded"],
    ], "Drill facts"),
    h("h4", null, "Steps"),
    h("ol", { class: "drill-steps" }, drill.steps.map((step) => {
      const rows = stepFacts(step);
      return h("li", { class: "drill-step" },
        h("p", { class: "drill-step-head" }, h("strong", { class: "state-label", "data-tone": stepTone(step.state) }, step.label),
          " ", h("span", { class: "muted" }, elapsedText(step.at, start))),
        h("p", null, step.detail),
        rows.length ? facts(rows, `Step ${step.seq}`) : null);
    })),
    h("h4", null, "What really happened inside the fixture"),
    h("p", { class: "muted" }, p.ledgerNote || ""),
    table("Synthetic provider ledger", [
      { label: "#", num: true, rowHeader: true, render: (r) => String(r.seq) },
      { label: "Submitted by", render: (r) => mono(r.actor) },
      { label: "Scripted fault", render: (r) => mono(r.fault) },
      { label: "Inside the fixture", render: (r) => r.applied },
      { label: "Answer", render: (r) => r.answer },
    ], ledgerRows(drill), "Nothing was submitted to the synthetic provider."));
}

// --- evidence assessment (OGWA-DEMO-01) --------------------------------------------------------

/**
 * "Is this safe to act on?": the server's evidence assessment, grouped by the six questions a
 * reviewer asks. Every state, conflict, and decision is the server's; nothing is judged here.
 */
function assessmentSection(assessment) {
  const a = reviewerAnswers(assessment);
  if (!a) {
    return section("Is this safe to act on?",
      banner("blocked", "No evidence assessment is available.", "Without one, treat every source as unknown and nothing as safe to act on."));
  }
  const itemLine = (i) => h("li", null, h("strong", null, i.label), ": ", i.observation, " ",
    badge(stateText(i.state).label, stateText(i.state).tone));
  const sources = (list, empty) => (list.length ? h("ul", { class: "plain-list" }, list.map(itemLine)) : h("span", { class: "muted" }, empty));
  return section("Is this safe to act on?",
    h("div", { class: "banner", "data-tone": a.decision.tone },
      h("strong", null, a.decision.label),
      a.constraints.length ? h("p", null, a.constraints[0].detail) : null,
      h("p", null, a.decision.eligible
        ? "Not an approval: a named human decides, and this build only plans dry runs."
        : "OGWA will not treat this candidate as safe to act on. Nothing is eligible for automatic action.")),
    facts([
      ["1. Proposed governance issue", a.issue],
      ["2. Sources that support it", sources(a.supporting, "None")],
      ["3. Sources that disagree, conflict, or are unavailable", sources(a.against, "None")],
      ["4. Identity mapping", [badge(a.identity.label, a.identity.tone), a.identity.confidence ? [" ", mono(a.identity.confidence)] : null,
        h("div", { class: "muted" }, a.identity.detail)]],
      // Decision labels are sentences, so they are text, not (non-wrapping) badges.
      ["5. What OGWA can safely decide now", [h("strong", null, a.decision.label),
        a.constraints.length > 1 ? [h("div", { class: "muted" }, "Also applies:"), h("ul", { class: "plain-list" },
          a.constraints.slice(1).map((c) => h("li", null, h("strong", null, c.label), ": ", c.detail)))] : null]],
      ["6. Evidence needed to proceed", a.needed.length ? h("ol", null, a.needed.map((n) => h("li", null, n)))
        : h("span", { class: "muted" }, "Nothing further: the evidence supports putting this to a named human.")],
      ["Next lifecycle step", [badge(a.pending.status, a.pending.tone), " ", a.pending.text]],
    ], "Evidence assessment"),
    a.conflicts.length ? h("div", null, h("h3", null, "Conflicts"), h("ul", { class: "banner-list" }, a.conflicts.map((c) =>
      h("li", null, banner("blocked", c.title || humanize(c.code), c.summary))))) : null,
    h("h3", null, "Evidence by source"),
    evidenceStatesTable(assessment.items),
    a.notes.map((n) => h("p", { class: "muted" }, n)));
}

// --- decision explanation (OGWA-DEMO-02) -------------------------------------------------------

/**
 * "Why this decision": which policy version produced it, each condition as that version states
 * it, whether evidence forced manual review, and what would change the outcome. The server's
 * explanation, worded; nothing is judged here.
 */
function explanationSection(explanation, assessment) {
  const e = explanationAnswers(explanation);
  const items = (assessment && assessment.items) || [];
  if (!e) {
    return section("Why this decision",
      banner("blocked", "No decision explanation is available.", "Treat the decision above as unexplained, not as safe."));
  }
  return section("Why this decision",
    facts([
      ["Policy version that ran", [h("strong", null, e.policy.text), " ", badge(e.policy.known ? "In force now" : "None", e.policy.tone),
        h("div", { class: "muted" }, e.policy.detail)]],
      ["Decision it produced", h("strong", null, e.decision.label)],
      ["Conditions", `${e.satisfied.length} satisfied, ${e.notSatisfied.length} not satisfied, ${e.notProven.length} not proven`
        + (e.notApplicable.length ? `, ${e.notApplicable.length} not applicable` : "")
        + (e.unrecognized.length ? `, ${e.unrecognized.length} unrecognized` : "")],
      ["Did ambiguous or missing evidence force manual review?", [badge(e.forced.answer, e.forced.tone), " ", e.forced.text,
        e.forced.because.length ? h("ul", { class: "plain-list" }, e.forced.because.map((c) => h("li", null, h("strong", null, c.label), ": ", c.detail))) : null]],
      ["What would need to change for a different outcome", e.change.length ? h("ol", null, e.change.map((n) => h("li", null, n)))
        : h("span", { class: "muted" }, "No evidence change would alter this outcome.")],
    ], "Decision explanation"),
    table("Conditions, as the policy version that ran states them", [
      { label: "Condition", rowHeader: true, render: (c) => c.label },
      { label: "Rule under this version", render: (c) => c.rule },
      // Only the status sorts (unmet first); the conditions otherwise keep the classifier's order.
      { label: "Status", render: (c) => badge(c.statusText.label, c.statusText.tone), sort: (c) => conditionRank(c.status) },
      { label: "Why", render: (c) => [c.detail, h("div", { class: "muted" }, "Evidence read: ",
        c.evidence.length ? evidenceLabels(c.evidence, items).join("; ") : "none recorded")] },
    ], e.conditions, "No condition was evaluated."));
}

function policyCell(ref, inForce) {
  const name = policyName(ref);
  const against = policyAgainstInForce(ref, inForce);
  return [name.known ? name.text : h("span", { class: "muted" }, name.text),
    against.current === false ? h("div", null, badge("Superseded", "caution")) : null];
}

function evidenceStatesTable(items) {
  const STATE_ORDER = ["CONFLICTING", "SOURCE_UNAVAILABLE", "NOT_COLLECTED", "AMBIGUOUS", "PARTIAL", "NOT_COUNTED_SOURCE",
    "REPORTS_NONE", "CONFIRMED"];
  return table("Evidence by source, with its state", [
    { label: "Source", rowHeader: true, render: (i) => i.label, sort: (i) => i.label },
    { label: "System", render: (i) => i.system, sort: (i) => i.system },
    { label: "What it says", render: (i) => i.observation },
    { label: "State", render: (i) => [badge(stateText(i.state).label, stateText(i.state).tone),
      i.state !== i.baseState ? h("div", { class: "muted" }, `Read: ${stateText(i.baseState).label}`) : null],
    sort: (i) => STATE_ORDER.indexOf(i.state) },
    { label: "Freshness", render: (i) => badge(freshnessText(i.freshness).label, freshnessText(i.freshness).tone), sort: (i) => i.freshness },
    { label: "Bearing", render: (i) => badge(stanceText(i.stance).label, stanceText(i.stance).tone), sort: (i) => i.stance },
    { label: "Required", render: (i) => requiredText(i), sort: (i) => Number(!i.required) },
    { label: "Observed", render: (i) => (i.observedAt ? fmtTime(i.observedAt) : "Never"), sort: (i) => i.observedAt || "" },
  ], items, "No evidence source is recorded for this candidate.");
}

// --- summary -----------------------------------------------------------------------------------

function summaryFacts(c, ev, deps, group, classification, now, quarantine, refs) {
  const mapping = mappingInfo(ev.mapping, ev.oktaGroup);
  const usage = usageSummary(ev.usage);
  const members = membershipFacts(ev);
  const protection = protectionInfo(ev.adGroup, classification);
  const coverage = deps.coverage ? overallCoverageText(deps.coverage.overall) : { label: "Unavailable", tone: "blocked" };
  const candidateApps = new Set(ev.assignments.map((a) => a.applicationId));
  const others = (group.assignments || []).filter((a) => a.present && !candidateApps.has(a.applicationId));
  const ad = ev.adGroup;
  const adLabel = ev.mapping && ev.mapping.isExact ? "Mapped AD group" : "AD group in evidence (not proven to be the counterpart)";

  return facts([
    ["Okta application", ev.applications.length ? h("ul", { class: "plain-list" }, ev.applications.map((a) =>
      h("li", null, appLink(a.id, a.label), " ", badge(humanize(a.status), a.status === "ACTIVE" ? "neutral" : "caution"))))
      : badge("No application observed", "blocked")],
    ["Usage window", usage.windowStart ? `${fmtTime(usage.windowStart)} to ${fmtTime(usage.windowEnd)}` : badge(usage.window, "blocked")],
    ["Sign-ins in window", usage.windowStart ? [`${usage.events} sign-in(s) by ${usage.users} user(s)`,
      usage.partial ? [" ", badge("Collection incomplete", "blocked")] : null] : "—"],
    ["Last observed sign-in", usage.lastAt ? `${fmtTime(usage.lastAt)} (${age(usage.lastAt, now)} ago)` : badge(usage.last, usage.tone)],
    ["Assigned Okta group", ev.oktaGroup ? [groupLink(ev.oktaGroup.id, ev.oktaGroup.name), ` (${humanize(ev.oktaGroup.groupType)})`]
      : badge("Not observed", "blocked")],
    ["Mapping confidence", [badge(mapping.label, mapping.tone), " ", mappingLink(c.oktaGroupId, "mapping evidence")]],
    [adLabel, ad ? h("div", null,
      h("div", null, identity(refs[ad.id], ad.id)),
      h("div", null, mono(ad.distinguishedName)),
      h("div", { class: "muted" }, "Domain ", mono(ad.domain), ", objectGUID ", mono(ad.objectGuid), ", objectSid ", mono(ad.sid)),
      ad.exists ? null : badge("Does not exist", "blocked"))
      : badge("AD evidence unavailable", "blocked")],
    ["Direct members", factText(members.direct)],
    ["Direct-member findings", factText(members.directFindings)],
    ["Nested members and member groups", factText(members.memberGroups)],
    ["AD parent groups", factText(members.parents)],
    ["primaryGroupID references", factText(members.primaryGroup)],
    ["Other Okta assignments", others.length ? h("ul", { class: "plain-list" }, others.map((a) => h("li", null, identity(refs[a.applicationId], a.applicationId))))
      : (() => { const f = otherAssignmentsFact(0, classification); return badge(f.value, f.tone); })()],
    ["Protected status", [badge(protection.label, protection.tone),
      ad ? h("div", { class: "muted" }, `adminCount ${yesNo(ad.adminCount)}; protected from accidental deletion ${yesNo(ad.protectedFromAccidentalDeletion)}; critical system object ${yesNo(ad.isCriticalSystemObject)}`) : null]],
    ["Dependency coverage", badge(coverage.label, coverage.tone)],
    ["Classification", classification ? [badge(humanize(classification.classification), "neutral"),
      classification.usageTier ? ` Usage tier: ${humanize(classification.usageTier)}.` : null] : badge("Unavailable", "blocked")],
    ["Classifier's suggested diversion", classification && classification.lifecycleDiversion
      ? [stateInfo(classification.lifecycleDiversion).label, h("div", { class: "muted" }, "Where the classifier would park this candidate. The reasons above say exactly why.")] : "None"],
    ["Proposed by", actorText(c.proposedBy)],
    ["Candidate id", mono(c.id)],
    ["Epoch", String(c.epoch)],
    ["Hold until", c.holdUntil ? fmtTime(c.holdUntil) : "—"],
    ["Quarantine OU", quarantineText(quarantine)],
    ["Quarantine approved by", c.quarantineApprover ? actorText(c.quarantineApprover) : "—"],
    ["Post-quarantine hold until", c.quarantineHoldUntil ? fmtTime(c.quarantineHoldUntil) : "—"],
    ["Deletion proposed by", c.deletionProposer ? [actorText(c.deletionProposer), ` at ${fmtTime(c.deletionProposedAt)}`] : "—"],
  ], "Decision summary");
}

/** Where the AD group stands against its domain's quarantine OU (read-only deployment configuration). */
function quarantineText(q) {
  if (!q) return "—";
  if (!q.quarantineOu) return badge(`No quarantine OU configured for ${q.domain}`, "blocked");
  const where = q.inQuarantine === true ? badge("Group is in the quarantine OU", "caution")
    : q.inQuarantine === false ? badge("Group is not in the quarantine OU", "neutral") : badge("Location unknown", "blocked");
  return [mono(q.quarantineOu), " ", where];
}

function factText(fact) {
  if (fact.basis === "unchecked" || fact.basis === "unavailable") return badge(fact.value, "blocked");
  if (fact.basis === "finding") return badge(fact.value, "blocked");
  return fact.value;
}

// --- tables ------------------------------------------------------------------------------------

function reasonsTable(classification, refs) {
  if (!classification) return banner("blocked", "No classification.", "Without a classification nothing can be decided.");
  return table("Classification reasons", [
    { label: "Effect", render: (r) => (r.blocks ? badge("Blocks", "blocked") : badge("Informational", "neutral")), sort: (r) => Number(r.blocks) },
    { label: "Reason", rowHeader: true, render: (r) => humanize(r.code), sort: (r) => humanize(r.code) },
    { label: "Detail", render: (r) => r.detail },
    { label: "Subject", render: (r) => (!r.subject ? "—" : refs[r.subject] && refs[r.subject].resolved ? identity(refs[r.subject], r.subject) : mono(r.subject)),
      sort: (r) => (refs[r.subject] && refs[r.subject].resolved ? refs[r.subject].name : r.subject) },
  ], [...classification.reasons].sort((a, b) => Number(b.blocks) - Number(a.blocks)));
}

function findingsTable(findings) {
  const rows = [];
  for (const d of findings) for (const f of d.findings) rows.push({ d, f });
  return table("Dependency findings", [
    { label: "Kind", rowHeader: true, render: (r) => KIND_LABEL[r.d.dependencyKind] || r.d.dependencyKind, sort: (r) => KIND_LABEL[r.d.dependencyKind] || r.d.dependencyKind },
    { label: "Effect", render: (r) => (r.f.blocking ? badge("Blocking", "blocked") : badge("Informational", "neutral")), sort: (r) => Number(r.f.blocking) },
    { label: "Finding", render: (r) => r.f.description },
    { label: "Code", render: (r) => (r.f.code ? mono(r.f.code) : "Uncoded"), sort: (r) => r.f.code },
    { label: "Reference", render: (r) => (r.f.reference ? mono(r.f.reference) : "—"), sort: (r) => r.f.reference },
    { label: "Observed", render: (r) => fmtTime(r.d.provenance.observedAt), sort: (r) => r.d.provenance.observedAt },
  ], rows, "No dependency findings are recorded. Check the coverage table: an unchecked kind is not clear.");
}

function evidenceTable(ev, classification, now) {
  const stale = staleSubjects(classification);
  const future = futureDatedSubjects(classification);
  const freshness = (r) => (future.has(r.id) ? badge("Future-dated (invalid)", "blocked")
    : stale.has(r.id) ? badge("Stale", "blocked") : "Not flagged");
  const flagged = (r) => (future.has(r.id) ? 2 : stale.has(r.id) ? 1 : 0);
  const rows = [
    ...(ev.oktaGroup ? [["Okta group", ev.oktaGroup]] : []),
    ...ev.applications.map((a) => ["Okta application", a]),
    ...ev.assignments.map((a) => ["Okta assignment", a]),
    ...ev.usage.map((u) => ["Okta usage", u]),
    ...(ev.mapping ? [["Identity mapping", ev.mapping]] : []),
    ...(ev.adGroup ? [["AD group", ev.adGroup]] : []),
    ...ev.dependencies.map((d) => [`Dependency: ${KIND_LABEL[d.dependencyKind] || d.dependencyKind}`, d]),
  ];
  const missing = [];
  if (!ev.oktaGroup) missing.push("Okta group");
  if (!ev.usage.length) missing.push("Okta usage");
  if (!ev.mapping) missing.push("Identity mapping");
  if (!ev.adGroup) missing.push("AD group");
  return [
    missing.length ? banner("blocked", `Not observed: ${missing.join(", ")}.`, "Missing evidence is unavailable, not old. Nothing is assumed in its place.") : null,
    table("Evidence records", [
      { label: "Record", rowHeader: true, render: ([kind]) => kind, sort: ([kind]) => kind },
      { label: "Observed", render: ([, r]) => fmtTime(r.provenance.observedAt), sort: ([, r]) => r.provenance.observedAt },
      { label: "Age", render: ([, r]) => age(r.provenance.observedAt, now), sort: ([, r]) => -Date.parse(r.provenance.observedAt) },
      { label: "Freshness (classifier)", render: ([, r]) => freshness(r), sort: ([, r]) => flagged(r) },
      { label: "Result", render: ([, r]) => resultBadge(r.provenance), sort: ([, r]) => r.provenance.resultStatus },
      { label: "Source", render: ([, r]) => mono(r.provenance.source), sort: ([, r]) => r.provenance.source },
    ], rows),
    h("p", { class: "muted" }, "Evidence fingerprint: ", mono(ev.evidenceFingerprint)),
  ];
}

// Like the audit trail, the decision history is an ordered chain (each decision starts where the
// last one ended), so it keeps its recorded order and is not sortable.
function decisionsTable(items, inForce) {
  return table("Lifecycle decisions, oldest first", [
    { label: "When", rowHeader: true, render: (d) => fmtTime(d.decidedAt) },
    { label: "From", render: (d) => stateInfo(d.from).label },
    { label: "To", render: (d) => stateInfo(d.to).label },
    { label: "By", render: (d) => actorText(d.actor) },
    { label: "Judged by policy", render: (d) => policyCell(d.policy, inForce) },
    { label: "Reason", render: (d) => d.reason },
    { label: "Approval / job", render: (d) => [d.approvalId ? mono(d.approvalId) : null, d.executionJobId ? [" ", jobLink(d.executionJobId)] : null] },
  ], items, "No lifecycle decision is recorded yet.");
}

function approvalsTable(items, inForce) {
  return table("Approvals and rejections", [
    { label: "Stage", rowHeader: true, render: (a) => STAGE_LABEL[a.stage] || a.stage, sort: (a) => STAGE_LABEL[a.stage] || a.stage },
    { label: "Decision", render: (a) => (a.decision === "APPROVE" ? badge("Approved for future action", "caution") : badge("Rejected", "neutral")), sort: (a) => a.decision },
    { label: "By", render: (a) => actorText(a.operator), sort: (a) => actorText(a.operator) },
    { label: "Decided", render: (a) => fmtTime(a.decidedAt), sort: (a) => a.decidedAt },
    { label: "Expires", render: (a) => [fmtTime(a.expiresAt), a.expired ? [" ", badge("Expired", "neutral")] : null], sort: (a) => a.expiresAt },
    { label: "Epoch", num: true, render: (a) => String(a.candidateEpoch), sort: (a) => a.candidateEpoch },
    { label: "Judged by policy", render: (a) => policyCell(a.policy, inForce), sort: (a) => policyName(a.policy).text },
    { label: "Reason", render: (a) => a.reason },
  ], items, "No approval or rejection is recorded.");
}

function jobsTable(items) {
  return table("Dry-run plans", [
    { label: "Plan", rowHeader: true, render: (j) => jobLink(j.id) },
    { label: "Kind", render: (j) => STAGE_LABEL[j.kind] || j.kind, sort: (j) => STAGE_LABEL[j.kind] || j.kind },
    { label: "Status", render: (j) => { const st = planStatus(j); return badge(st.label, st.tone); }, sort: (j) => planStatus(j).label },
    { label: "Executed", render: (j) => (j.executed ? badge("Yes", "blocked") : "No"), sort: (j) => Number(j.executed) },
    { label: "Mode", render: (j) => mono(j.executionMode), sort: (j) => j.executionMode },
    { label: "Requested", render: (j) => `${fmtTime(j.requestedAt)} by ${actorText(j.requestedBy)}`, sort: (j) => j.requestedAt },
  ], items, "No dry run has been planned.");
}

// The audit trail keeps the chain's sequence order (newest first): an event history, not a dataset.
function auditTable(items) {
  return table("Audit events for this candidate, newest first", [
    { label: "Sequence", num: true, render: (e) => String(e.sequence) },
    { label: "Action", rowHeader: true, render: (e) => humanize(e.action) },
    { label: "When", render: (e) => fmtTime(e.occurredAt) },
    { label: "Actor", render: (e) => actorText(e.actor) },
    { label: "Result", render: (e) => humanize(e.result) },
    { label: "Request", render: (e) => mono(e.correlationId) },
  ], items, "No audit events.");
}

// --- actions -----------------------------------------------------------------------------------

function actionsPanel(ctx, detail, plan, fingerprintDrift) {
  const c = detail.candidate;
  const fingerprint = detail.evidenceFingerprint;
  const formSlot = h("div", { class: "form-slot" });
  const items = [];
  let opener = null;

  const open = (button, buildForm) => {
    opener = button;
    formSlot.replaceChildren(buildForm(close));
    const first = formSlot.querySelector("textarea, select, input");
    if (first) first.focus();
  };
  const close = () => {
    formSlot.replaceChildren();
    if (opener) opener.focus();
  };
  const offer = (label, help, buildForm) => {
    const button = h("button", { type: "button" }, label);
    button.addEventListener("click", () => open(button, buildForm));
    items.push(h("li", null, button, help ? h("p", { class: "action-help" }, help) : null));
  };

  for (const a of plan.approvals) {
    const stage = STAGE_LABEL[a.stage] || a.stage;
    if (!a.permitted) {
      items.push(h("li", null, h("div", { class: "banner", "data-tone": "caution" },
        h("strong", null, `You cannot decide the ${stage} approval.`),
        h("ul", { class: "plain-list" }, a.conflicts.map((x) => h("li", null, x))))));
      continue;
    }
    offer(`Approve for future action: ${stage}`, "Records approval only. Changes nothing.",
      (done) => approvalForm(ctx, c, fingerprint, a.stage, "APPROVE", done, maxValidHours(detail)));
    offer(`Decline approval: ${stage}`, "Records a rejection of this approval stage.",
      (done) => approvalForm(ctx, c, fingerprint, a.stage, "REJECT", done, null));
  }
  for (const t of plan.transitions) {
    const spec = TRANSITION_FORMS[t.action];
    offer(spec.label, spec.help, (done) => transitionForm(ctx, c, fingerprint, t, spec, done));
  }
  if (plan.dryRun) {
    offer(`Run dry-run: ${STAGE_LABEL[plan.dryRun.kind]}`, "Plans what would change. Executes nothing.",
      (done) => dryRunForm(ctx, c, fingerprint, plan.dryRun, done));
  }
  if (plan.recordDryRun) {
    offer("Record the dry-run step", "Records a planned dry run in the lifecycle. Executes nothing.",
      (done) => recordDryRunForm(ctx, c, fingerprint, plan.recordDryRun, done));
  }

  const who = principal();
  return h("div", { class: "actions-panel" },
    h("h2", { id: "actions-heading" }, "Record a decision"),
    h("p", null, "Nothing here changes Okta or Active Directory. The server re-checks every decision against the evidence you are looking at and records it in the audit trail."),
    h("p", { class: "muted" }, "Evidence fingerprint: ", mono(fingerprint)),
    fingerprintDrift ? banner("blocked", "Reload first.", "The evidence changed while the page loaded.") : null,
    items.length && !fingerprintDrift ? h("ul", { class: "action-list" }, items)
      : anonymous() ? banner("neutral", "This public demo is read-only.",
        "Approvals, holds, and every other decision are refused, and nothing is recorded. Run OGWA locally to try them.")
      : h("p", null, fingerprintDrift ? "" : `No decision is open to you on this candidate in its current state (${stateInfo(c.state).label}).`),
    formSlot,
    who && !anonymous() ? h("p", { class: "muted" }, `Signed in as ${who.subject} (${who.roles.join(", ") || "no role"}).`) : null,
    h("p", { class: "muted" }, "There is no delete, unassign, or execute action in this console."));
}

const TRANSITION_FORMS = {
  hold: {
    label: "Hold (block for review)", help: "Stops progress until a person lifts the hold.", submit: "Hold candidate",
    notice: ["caution", "Holding moves the candidate to BLOCKED.",
      "Lifting the hold needs a person, and the candidate must pass the re-entry checks again. Nothing in Okta or AD changes."],
  },
  exclude: {
    label: "Exclude", help: "Terminal. Use for groups that must never be candidates.", submit: "Exclude candidate", confirm: true,
    notice: ["blocked", "Exclusion is terminal.",
      "The candidate leaves the lifecycle for good; new evidence would create a new candidate. Nothing in Okta or AD changes."],
  },
  reject: {
    label: "Reject candidate", help: "Terminal. The evidence does not justify further review.", submit: "Reject candidate", confirm: true,
    notice: ["blocked", "Rejection is terminal.",
      "The candidate leaves the lifecycle for good; new evidence would create a new candidate. Nothing in Okta or AD changes."],
  },
  revalidate: {
    label: "Request revalidation", help: "Moves the candidate to revalidation if the rules allow it.", submit: "Submit revalidation request",
    notice: ["caution", "Revalidation is checked by the lifecycle rules.",
      "The server refuses it unless every condition for revalidation holds on the current evidence (for example, the hold period has ended). A refusal is recorded in the audit trail."],
  },
  proposeDeletion: {
    label: "Propose AD deletion", help: "Records your proposal only. Someone else must approve it. Nothing is deleted.",
    submit: "Record deletion proposal",
    notice: ["caution", "A proposal changes nothing in Active Directory.",
      "The server checks fresh evidence collected after the post-quarantine hold. A different person, who approved neither the Okta unassignment nor the quarantine, must then approve the deletion; you cannot approve your own proposal."],
  },
};

// --- forms -------------------------------------------------------------------------------------

function reasonField(describedBy) {
  const id = uid("reason");
  const hint = uid("hint");
  const textarea = h("textarea", { id, name: "reason", required: true, maxlength: String(MAX_REASON),
    "aria-describedby": [hint, describedBy].filter(Boolean).join(" ") });
  return {
    node: h("div", { class: "field" }, h("label", { for: id }, "Reason (recorded in the audit trail)"),
      h("span", { class: "hint", id: hint }, `Required. At most ${MAX_REASON} characters. Do not paste credentials or personal data.`),
      textarea),
    value: () => textarea.value.trim(),
    el: textarea,
  };
}

function confirmBox(text) {
  const id = uid("confirm");
  const input = h("input", { type: "checkbox", id, required: true });
  return { node: h("div", { class: "check" }, input, h("label", { for: id }, text)), checked: () => input.checked, el: input };
}

function actionForm(title, noticeParts, fields, submitLabel, onSubmit, done) {
  const noticeId = uid("notice");
  const errorSlot = h("div", { "aria-live": "assertive" });
  const submit = h("button", { type: "submit", class: "primary" }, submitLabel);
  const cancel = h("button", { type: "button", on: { click: done } }, "Cancel");
  const form = h("form", { class: "action-form", novalidate: true },
    h("fieldset", null,
      h("legend", null, title),
      noticeParts ? h("div", { class: "banner", "data-tone": noticeParts[0], id: noticeId },
        h("strong", null, noticeParts[1]), h("p", null, noticeParts[2])) : null,
      fields(noticeId),
      errorSlot,
      h("div", { class: "form-buttons" }, submit, cancel)));
  form.addEventListener("keydown", (event) => { if (event.key === "Escape") { event.preventDefault(); done(); } });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorSlot.replaceChildren();
    const problem = form.validate ? form.validate() : null;
    if (problem) {
      errorSlot.append(h("div", { class: "banner", "data-tone": "blocked", role: "alert" }, h("strong", null, problem.message)));
      problem.focus.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = "Recording…";
    try {
      await onSubmit();
    } catch (error) {
      submit.disabled = false;
      submit.textContent = submitLabel;
      submit.focus(); // disabling it dropped focus; the error appears just above it
      const reload = error && error.code === "EVIDENCE_CHANGED"
        ? h("button", { type: "button", on: { click: () => ctx_reload() } }, "Reload this candidate") : null;
      errorSlot.append(errorBox(error, reload));
    }
  });
  return form;
}

// The router's reload, set when a candidate page renders; used by the "Reload" button.
let ctx_reload = () => location.reload();

function guard(form, checks) {
  form.validate = () => {
    for (const [ok, message, focus] of checks) if (!ok()) return { message, focus };
    return null;
  };
  return form;
}

/** The longest approval validity the policy in force allows, from the server; null if it did not say. */
function maxValidHours(detail) {
  const value = detail && detail.policy ? detail.policy.approvalMaxValidHours : null;
  return Number.isInteger(value) && value >= 1 ? value : null;
}

function approvalForm(ctx, c, fingerprint, stage, decision, done, maxHours) {
  ctx_reload = () => ctx.reload();
  const stageLabel = STAGE_LABEL[stage] || stage;
  const approve = decision === "APPROVE";
  const reason = reasonField();
  const hoursId = uid("hours");
  // Without a server-supplied maximum the field is not offered, and the server applies the policy maximum.
  const offerHours = approve && maxHours !== null;
  const hours = h("input", { type: "number", id: hoursId, min: "1", max: offerHours ? String(maxHours) : null, step: "1",
    inputmode: "numeric" });
  const ack = confirmBox("I understand that this approval does not change Okta or Active Directory. It only records my decision for a future, separately executed step.");
  const form = actionForm(
    approve ? `Approve for future action: ${stageLabel}` : `Decline approval: ${stageLabel}`,
    approve
      ? ["caution", "Approval alone does not mutate production.",
        "It records that you approve a future, separately executed step, bound to this exact evidence. In this build, execution is dry-run planning only. The server refuses the approval if the lifecycle rules would refuse the step."]
      : ["neutral", "Records a rejection of this approval stage.", "The candidate's state does not change. Nothing in Okta or AD changes."],
    (noticeId) => {
      reason.el.setAttribute("aria-describedby", `${reason.el.getAttribute("aria-describedby")} ${noticeId}`);
      return [reason.node,
        offerHours ? h("div", { class: "field" }, h("label", { for: hoursId }, "Valid for (hours, optional)"),
          h("span", { class: "hint" }, `1 to ${maxHours}, the policy's maximum. Leave empty for the maximum.`), hours) : null,
        approve ? ack.node : null];
    },
    approve ? "Record approval" : "Record rejection",
    async () => {
      const body = { stage, decision, reason: reason.value(), expectedEvidenceFingerprint: fingerprint };
      if (offerHours && hours.value) body.validForHours = Number(hours.value);
      const result = await decideApproval(c.id, body);
      ctx.reload(approve
        ? `Approval recorded for ${stageLabel} (${result.approval.id}). Nothing in Okta or Active Directory changed.`
        : `Rejection recorded for ${stageLabel}. Nothing in Okta or Active Directory changed.`);
    }, done);
  return guard(form, [
    [() => reason.value().length > 0, "Give a reason.", reason.el],
    [() => !offerHours || !hours.value || (Number.isInteger(Number(hours.value)) && Number(hours.value) >= 1 && Number(hours.value) <= maxHours),
      `Hours must be a whole number from 1 to ${maxHours}.`, hours],
    [() => !approve || ack.checked(), "Confirm that you understand approval changes nothing.", ack.el],
  ]);
}

function transitionForm(ctx, c, fingerprint, t, spec, done) {
  ctx_reload = () => ctx.reload();
  const reason = reasonField();
  const confirm = spec.confirm ? confirmBox("I understand this is terminal for this candidate.") : null;
  const form = actionForm(spec.label, spec.notice,
    (noticeId) => {
      reason.el.setAttribute("aria-describedby", `${reason.el.getAttribute("aria-describedby")} ${noticeId}`);
      return [reason.node, confirm ? confirm.node : null];
    },
    spec.submit,
    async () => {
      const body = { target: t.target, reason: reason.value() };
      if (t.needsFingerprint) body.expectedEvidenceFingerprint = fingerprint;
      await transition(c.id, body);
      ctx.reload(`Recorded: ${stateInfo(c.state).label} → ${stateInfo(t.target).label}. Nothing in Okta or Active Directory changed.`);
    }, done);
  return guard(form, [
    [() => reason.value().length > 0, "Give a reason.", reason.el],
    [() => !confirm || confirm.checked(), "Confirm that you understand this is terminal.", confirm ? confirm.el : reason.el],
  ]);
}

function approvalOption(a) {
  return h("option", { value: a.id }, `${a.id} — approved by ${a.operator.id}, expires ${fmtTime(a.expiresAt)}`);
}

function dryRunForm(ctx, c, fingerprint, dry, done) {
  ctx_reload = () => ctx.reload();
  const stageLabel = STAGE_LABEL[dry.kind];
  if (!dry.approvals.length) {
    const back = h("button", { type: "button", on: { click: done } }, "Close");
    return h("div", { class: "action-form", role: "group", "aria-label": `Run dry-run: ${stageLabel}` },
      banner("caution", "No usable approval.", `A dry run needs an unexpired ${stageLabel} approval for this epoch. None exists.`), back);
  }
  const selectId = uid("approval");
  const select = h("select", { id: selectId, required: true }, dry.approvals.map(approvalOption));
  const result = h("div", { "aria-live": "polite" });
  const form = actionForm(`Run dry-run: ${stageLabel}`,
    ["caution", "A dry run plans; it never executes.",
      "OGWA records what would change as a dry-run job (executed: false). Nothing in Okta or AD changes. Real execution is not available in this build."],
    () => [h("div", { class: "field" }, h("label", { for: selectId }, "Approval this dry run relies on"), select), result],
    "Plan dry run",
    async () => {
      const data = await planDryRun(c.id, { kind: dry.kind, approvalId: select.value, expectedEvidenceFingerprint: fingerprint });
      ctx.reload(`Dry run planned (${data.job.id}): ${data.plannedActions.length} change(s) would be made; none was executed.`);
    }, done);
  return form;
}

function recordDryRunForm(ctx, c, fingerprint, rec, done) {
  ctx_reload = () => ctx.reload();
  const reason = reasonField();
  const selectId = uid("job");
  const select = h("select", { id: selectId, required: true },
    rec.jobs.map((j) => h("option", { value: j.id }, `${j.id} — planned by ${j.requestedBy.id}, ${fmtTime(j.requestedAt)}`)));
  const form = actionForm("Record the dry-run step",
    ["caution", "Records a planned dry run in the lifecycle.",
      "The candidate moves to the dry-run state. Nothing is executed and nothing in Okta or AD changes."],
    (noticeId) => {
      reason.el.setAttribute("aria-describedby", `${reason.el.getAttribute("aria-describedby")} ${noticeId}`);
      return [h("div", { class: "field" }, h("label", { for: selectId }, "Dry-run job"), select), reason.node];
    },
    "Record dry-run step",
    async () => {
      const job = rec.jobs.find((j) => j.id === select.value);
      await transition(c.id, { target: rec.target, reason: reason.value(), expectedEvidenceFingerprint: fingerprint,
        approvalId: job.approvalId, jobId: job.id });
      ctx.reload(`Recorded: ${stateInfo(rec.target).label}. Nothing in Okta or Active Directory changed.`);
    }, done);
  return guard(form, [[() => reason.value().length > 0, "Give a reason.", reason.el]]);
}
