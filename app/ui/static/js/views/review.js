// Review (OGWA-UI-REVIEW-01): the Review queue (everything waiting on a person, on time, or on
// evidence, in one place) and Decisions (the approvals and rejections people recorded). Holds
// are waiting work, so they are in the queue, never among the decisions.
// OGWA-REVIEW-QUEUE-API-01: the queue is filtered, ordered, counted, and paged on the server
// (GET /review-queue), and each row carries the classifier's current evidence verdict.
import { get } from "../api.js";
import { stateInfo } from "../assess.js";
import { actorText, badge, fmtTime, focusAfterRoute, h, link, table } from "../dom.js";
import { policyAgainstInForce, policyName } from "../policy.js";
import { collectIds, deadlineText, hashFor, span } from "../present.js";
import { approvalUsability, nextStep, REVIEW_STATUS, reviewStatus, stageLabel, verdictReading } from "../review.js";
import { candidateName } from "./candidates.js";
import { identity, lede, listing, pageParams, resolveRefs } from "./common.js";

const STAGE_LABEL = { OKTA_UNASSIGN: "Okta unassignment", AD_QUARANTINE: "AD quarantine", AD_DELETION: "AD deletion",
  AD_RETIREMENT: "AD retirement (legacy)" };

// A row costs the server one classification, so the queue's pages are smaller than other listings'.
const QUEUE_PAGE = 25;

/** A review status with the lifecycle state it reads, which stays the fact. */
export function reviewCell(state) {
  const status = reviewStatus(state);
  const info = stateInfo(state);
  return [badge(status.label, status.tone), h("div", { class: "muted" }, "Lifecycle: ", badge(info.label, info.tone))];
}

/** The current evidence verdict beside the recorded state: the decision, and whether they agree. */
export function verdictCell(c) {
  const v = verdictReading(c.evidenceVerdict, c.state);
  const more = v.blockers.length > 1 ? ` (+${v.blockers.length - 1} more)` : "";
  return [h("strong", { class: "state-label", "data-tone": v.tone }, v.label),
    h("div", { class: "state-label", "data-tone": v.agreement.tone }, v.agreement.text),
    v.blockers.length ? h("div", { class: "muted" }, `${v.blockers[0]}${more}`) : null];
}

/**
 * The queue's columns. With `server`, the sortable ones name GET /review-queue's `sort` fields;
 * without, the rows keep the server's priority order (the dashboard's head of the queue).
 */
function queueColumns(refs, now, server) {
  const step = (c) => nextStep(c, now);
  const sort = (key) => (server ? key : undefined);
  return [
    { label: "Candidate", rowHeader: true, render: (c) => candidateName(refs, c), sort: sort("oktaGroup") },
    { label: "Review status", render: (c) => reviewCell(c.state) },
    { label: "Evidence now", render: verdictCell },
    { label: "Stage", render: (c) => stageLabel(c) || "—" },
    { label: "Needs", render: (c) => step(c).required },
    { label: "Next step", render: (c) => [step(c).text, h("div", { class: "muted" }, `By: ${step(c).who}`)] },
    { label: "Waiting", render: (c) => waitingCell(c, now), sort: sort("updatedAt") },
    { label: "Deadline", render: (c) => deadlineCell(step(c).deadline), sort: sort("deadline") },
  ];
}

/** Rows of the queue as a table, in the server's order; `caption` names what is shown. */
export function queueTable(caption, rows, refs, now, emptyText) {
  return table(caption, queueColumns(refs, now, false), rows, emptyText);
}

function waitingCell(c, now) {
  const s = span(c.updatedAt, now);
  return [s ? (s.ms >= 0 ? s.text : "Changed after the server's clock") : "—", h("div", { class: "muted" }, `since ${fmtTime(c.updatedAt)}`)];
}

function deadlineCell(deadline) {
  if (!deadline) return "—";
  return [deadline.label ? badge(deadline.label, deadline.past ? "caution" : "neutral") : null,
    h("div", { class: "muted" }, `until ${fmtTime(deadline.at)}`)];
}

// --- the Review queue ------------------------------------------------------------------------

const FILTERS = [["open", "Open"], ...Object.entries(REVIEW_STATUS).map(([k, v]) => [k, v.label]), ["all", "All"]];

export async function reviewQueue(ctx) {
  ctx.setTitle("Review queue");
  const status = FILTERS.some(([k]) => k === ctx.query.status) ? ctx.query.status : "open";
  const data = await get("/review-queue", pageParams(ctx.query, { limit: QUEUE_PAGE, status }));
  const refs = await resolveRefs(collectIds(data.items, "oktaGroupId"));
  const counts = data.counts || {};
  const total = data.page.total;
  const current = FILTERS.find(([k]) => k === status)[1];

  ctx.view.append(
    lede("Everything that waits on a person, on time, or on evidence, in one place: what needs a decision first, then what is blocked and why, then holds by their deadline. A review status is a reading of the lifecycle state shown under it, and “Evidence now” is the classifier's current reading of the evidence, shown beside the recorded state, never instead of it. Neither authorizes anything, and the server checks every action again."),
    h("nav", { class: "filters status-filters", "aria-label": "Review status" },
      h("ul", null, FILTERS.map(([key, label]) => h("li", null, h("a", {
        href: hashFor("/review", {}, { status: key === "open" ? null : key }), "data-focus-key": `status:${key}`,
        "aria-current": key === status ? "true" : null, on: { click: () => { focusAfterRoute.key = `status:${key}`; } },
      }, `${label} (${counts[key] || 0})`))))),
    REVIEW_STATUS[status] ? h("p", null, REVIEW_STATUS[status].text) : null,
    listing("/review", ctx.query, data, `${current}: ${total} candidate${total === 1 ? "" : "s"}`,
      queueColumns(refs, data.generatedAt || null, true),
      status === "open" ? "Nothing is waiting: no candidate needs review, is blocked, waits, or is in progress." : "No candidate has this review status."),
    h("p", { class: "muted" }, "Counts cover every candidate; the list is in review priority unless a column is sorted. Times are read against the server's clock",
      data.generatedAt ? ` (${fmtTime(data.generatedAt)}).` : ", which did not answer, so only absolute times are shown.", " ",
      link("#/candidates", "Every candidate by lifecycle state")));
}

// --- Decisions -------------------------------------------------------------------------------

function policyCell(ref, inForce) {
  const name = policyName(ref);
  const against = policyAgainstInForce(ref, inForce);
  return [name.known ? name.text : h("span", { class: "muted" }, name.text),
    against.current === false ? h("div", null, badge("Superseded", "caution")) : null];
}

function expiryCell(a, now) {
  const rel = deadlineText(a.expiresAt, now, "Expired");
  // The server's `expired` is the fact; the words only add how long.
  const words = a.expired ? (rel && rel.past ? rel.text : "Expired") : (rel && !rel.past ? rel.text : null);
  return [words ? badge(words, a.expired ? "neutral" : "caution") : null, h("div", { class: "muted" }, fmtTime(a.expiresAt))];
}

/** Whether an approval can be used now, as the server judged it (never re-derived here). */
export function usabilityCell(a) {
  const u = approvalUsability(a.usability);
  return [h("strong", { class: "state-label", "data-tone": u.tone }, u.label),
    h("div", { class: "muted" }, u.usable ? u.note : u.problems[0] || null)];
}

export async function decisions(ctx) {
  ctx.setTitle("Decisions");
  const defaultSort = { key: "decidedAt", dir: "desc" };
  const [list, dash] = await Promise.all([get("/approvals", pageParams(ctx.query, null, defaultSort)), get("/dashboard")]);
  const now = dash.generatedAt || null;
  const refs = await resolveRefs(collectIds(list.items, "candidateId"));
  ctx.view.append(
    lede("The approvals and rejections people recorded. An approval records a decision for a future, separately executed step: it is not execution, and it changes nothing in Okta or Active Directory. An approval stops counting when it expires, its candidate re-enters review (a new epoch), the evidence it was given on changes, or the candidate is past its stage. “Approval rules now” is the server's answer under the lifecycle's own approval rules; valid is not ready, because the step it backs has its own checks, and the server applies them all again when it is requested."),
    h("p", null, "Holds are not decisions. Candidates waiting in a hold, or for a decision, are in the ", link("#/review", "Review queue"), "."),
    listing("/decisions", ctx.query, list, "Approvals and rejections", [
      { label: "Candidate", rowHeader: true, render: (a) => identity(refs[a.candidateId], a.candidateId), sort: "candidate" },
      { label: "Stage", render: (a) => STAGE_LABEL[a.stage] || a.stage, sort: "stage" },
      { label: "Decision", render: (a) => (a.decision === "APPROVE" ? badge("Approved for future action", "caution") : badge("Rejected", "neutral")), sort: "decision" },
      { label: "Approval rules now", render: usabilityCell },
      { label: "By", render: (a) => actorText(a.operator) },
      { label: "Decided", render: (a) => fmtTime(a.decidedAt), sort: "decidedAt" },
      { label: "Expires", render: (a) => expiryCell(a, now), sort: "expiresAt" },
      { label: "Judged by policy", render: (a) => policyCell(a.policy, dash.policy) },
      { label: "Reason", render: (a) => a.reason },
    ], "No approvals or rejections are recorded.", defaultSort));
}
