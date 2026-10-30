// Review (OGWA-UI-REVIEW-01): the Review queue (everything waiting on a person, on time, or on
// evidence, in one place) and Decisions (the approvals and rejections people recorded). Holds
// are waiting work, so they are in the queue, never among the decisions.
import { get } from "../api.js";
import { stateInfo } from "../assess.js";
import { actorText, badge, banner, fmtTime, focusAfterRoute, h, link, table } from "../dom.js";
import { policyAgainstInForce, policyName } from "../policy.js";
import { collectIds, deadlineText, hashFor, span } from "../present.js";
import {
  nextStep, OPEN_STATUSES, queueOrder, REVIEW_STATUS, reviewStatus, stageLabel, statusCounts,
} from "../review.js";
import { candidateName } from "./candidates.js";
import { identity, lede, listing, pageParams, resolveRefs } from "./common.js";

const STAGE_LABEL = { OKTA_UNASSIGN: "Okta unassignment", AD_QUARANTINE: "AD quarantine", AD_DELETION: "AD deletion",
  AD_RETIREMENT: "AD retirement (legacy)" };

// The API pages candidates 200 at a time; the queue reads at most this many and says so beyond it.
const MAX_ROWS = 1000;

/** A review status with the lifecycle state it reads, which stays the fact. */
export function reviewCell(state) {
  const status = reviewStatus(state);
  const info = stateInfo(state);
  return [badge(status.label, status.tone), h("div", { class: "muted" }, "Lifecycle: ", badge(info.label, info.tone))];
}

/**
 * Every candidate (paged through, up to MAX_ROWS), with the server's clock and the per-status
 * counts from GET /dashboard, which count every candidate even when the rows stop short.
 */
export async function loadQueue(dashboard) {
  const [dash, first] = await Promise.all([dashboard ? Promise.resolve(dashboard) : get("/dashboard"),
    get("/candidates", { limit: 200 })]);
  const items = [...first.items];
  let page = first.page;
  while (page.nextCursor && items.length < MAX_ROWS) {
    const next = await get("/candidates", { limit: 200, cursor: page.nextCursor });
    items.push(...next.items);
    page = next.page;
  }
  const now = dash.generatedAt || null;
  return { now, counts: statusCounts(dash.candidatesByState), items: items.sort(queueOrder(now)),
    truncated: Boolean(page.nextCursor), total: first.page.total };
}

/** The queue's rows as a table, in the queue's order; `caption` names what is shown. */
export function queueTable(caption, rows, refs, now, emptyText) {
  const step = (c) => nextStep(c, now);
  return table(caption, [
    { label: "Candidate", rowHeader: true, render: (c) => candidateName(refs, c), sort: (c) => (refs[c.oktaGroupId] || {}).name || c.oktaGroupId },
    { label: "Review status", render: (c) => reviewCell(c.state), sort: (c) => Object.keys(REVIEW_STATUS).indexOf(reviewStatus(c.state).key) },
    { label: "Stage", render: (c) => stageLabel(c) || "—", sort: (c) => stageLabel(c) },
    { label: "Needs", render: (c) => step(c).required },
    { label: "Next step", render: (c) => [step(c).text, h("div", { class: "muted" }, `By: ${step(c).who}`)] },
    { label: "Waiting", render: (c) => waitingCell(c, now), sort: (c) => c.updatedAt },
    { label: "Deadline", render: (c) => deadlineCell(step(c).deadline), sort: (c) => (step(c).deadline || {}).at },
  ], [...rows].sort(queueOrder(now)), emptyText);
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
  const queue = await loadQueue();
  const keys = status === "open" ? OPEN_STATUSES : status === "all" ? Object.keys(REVIEW_STATUS) : [status];
  const rows = queue.items.filter((c) => keys.includes(reviewStatus(c.state).key));
  const refs = await resolveRefs(collectIds(rows, "oktaGroupId"));
  const countOf = (k) => (k === "open" ? OPEN_STATUSES : k === "all" ? Object.keys(REVIEW_STATUS) : [k])
    .reduce((n, key) => n + (queue.counts[key] || 0), 0);
  const current = FILTERS.find(([k]) => k === status)[1];

  ctx.view.append(
    lede("Everything that waits on a person, on time, or on evidence, in one place: what needs a decision first, then what is blocked and why, then holds by their deadline. A review status is a reading of the lifecycle state shown under it; it authorizes nothing, and the server checks every action again."),
    h("nav", { class: "filters status-filters", "aria-label": "Review status" },
      h("ul", null, FILTERS.map(([key, label]) => h("li", null, h("a", {
        href: hashFor("/review", {}, { status: key === "open" ? null : key }), "data-focus-key": `status:${key}`,
        "aria-current": key === status ? "true" : null, on: { click: () => { focusAfterRoute.key = `status:${key}`; } },
      }, `${label} (${countOf(key)})`))))),
    queue.truncated ? banner("caution", `Only the first ${queue.items.length} of ${queue.total} candidates are listed.`,
      "The counts above include every candidate. Use the lifecycle state list to see the rest.") : null,
    REVIEW_STATUS[status] ? h("p", null, REVIEW_STATUS[status].text) : null,
    queueTable(`${current}: ${rows.length} candidate${rows.length === 1 ? "" : "s"}`, rows, refs, queue.now,
      status === "open" ? "Nothing is waiting: no candidate needs review, is blocked, waits, or is in progress." : "No candidate has this review status."),
    h("p", { class: "muted" }, "Times are read against the server's clock",
      queue.now ? ` (${fmtTime(queue.now)}).` : ", which did not answer, so only absolute times are shown.", " ",
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

export async function decisions(ctx) {
  ctx.setTitle("Decisions");
  const defaultSort = { key: "decidedAt", dir: "desc" };
  const [list, dash] = await Promise.all([get("/approvals", pageParams(ctx.query, null, defaultSort)), get("/dashboard")]);
  const now = dash.generatedAt || null;
  const refs = await resolveRefs(collectIds(list.items, "candidateId"));
  ctx.view.append(
    lede("The approvals and rejections people recorded. An approval records a decision for a future, separately executed step: it is not execution, and it changes nothing in Okta or Active Directory. An approval also stops counting when it expires or its candidate re-enters review (a new epoch); each candidate's page shows which of its approvals can still be used."),
    h("p", null, "Holds are not decisions. Candidates waiting in a hold, or for a decision, are in the ", link("#/review", "Review queue"), "."),
    listing("/decisions", ctx.query, list, "Approvals and rejections", [
      { label: "Candidate", rowHeader: true, render: (a) => identity(refs[a.candidateId], a.candidateId), sort: "candidate" },
      { label: "Stage", render: (a) => STAGE_LABEL[a.stage] || a.stage, sort: "stage" },
      { label: "Decision", render: (a) => (a.decision === "APPROVE" ? badge("Approved for future action", "caution") : badge("Rejected", "neutral")), sort: "decision" },
      { label: "By", render: (a) => actorText(a.operator) },
      { label: "Decided", render: (a) => fmtTime(a.decidedAt), sort: "decidedAt" },
      { label: "Expires", render: (a) => expiryCell(a, now), sort: "expiresAt" },
      { label: "Judged by policy", render: (a) => policyCell(a.policy, dash.policy) },
      { label: "Reason", render: (a) => a.reason },
    ], "No approvals or rejections are recorded.", defaultSort));
}
