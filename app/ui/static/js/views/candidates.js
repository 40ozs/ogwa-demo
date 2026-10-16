import { get } from "../api.js";
import { STATE_INFO, stateInfo } from "../assess.js";
import { badge, fmtTime, h, humanize, uid } from "../dom.js";
import { collectIds, hashFor } from "../present.js";
import { candidateLink, go, lede, listing, pageParams, resolveRefs } from "./common.js";

/** A candidate, named by its Okta group (resolved by id; the raw id when it cannot be). */
export function candidateName(refs, c) {
  const entry = refs[c.oktaGroupId];
  return candidateLink(c.id, entry && entry.resolved ? entry.name : c.oktaGroupId);
}

export async function candidates(ctx) {
  ctx.setTitle("Lifecycle candidates");
  const state = ctx.query.state && STATE_INFO[ctx.query.state] ? ctx.query.state : "";
  const query = state ? { ...ctx.query, state } : { ...ctx.query, state: null };
  const defaultSort = { key: "createdAt", dir: "asc" };
  const data = await get("/candidates", pageParams(ctx.query, state ? { state } : {}, defaultSort));
  const refs = await resolveRefs(collectIds(data.items, "oktaGroupId"));
  const selectId = uid("state");
  const select = h("select", { id: selectId, name: "state" },
    h("option", { value: "" }, "All states"),
    Object.entries(STATE_INFO).map(([value, info]) => h("option", { value, selected: value === state }, info.label)));
  const form = h("form", { class: "filters", "aria-label": "Filter candidates", on: { submit: (event) => {
    event.preventDefault();
    go(hashFor("/candidates", {}, { state: select.value }), null);
  } } },
  h("div", { class: "field" }, h("label", { for: selectId }, "Lifecycle state"), select),
  h("button", { type: "submit" }, "Show"));

  ctx.view.append(
    lede("The review queue, oldest first. A candidate is evidence for review, never authorization to change anything."),
    form,
    listing("/candidates", query, data, state ? `Candidates in state ${stateInfo(state).label}` : "All candidates", [
      { label: "Okta group", rowHeader: true, render: (c) => candidateName(refs, c), sort: "oktaGroup" },
      { label: "State", render: (c) => { const i = stateInfo(c.state); return badge(i.label, i.tone); }, sort: "state" },
      { label: "Why it was proposed", render: (c) => (c.reasonCodes.length ? c.reasonCodes.map(humanize).join("; ") : "—") },
      { label: "Blocked from", render: (c) => (c.blockedFrom ? stateInfo(c.blockedFrom).label : "—") },
      { label: "Hold until", render: (c) => fmtTime(c.holdUntil), sort: "holdUntil" },
      { label: "Proposed", render: (c) => fmtTime(c.createdAt), sort: "createdAt" },
      { label: "Updated", render: (c) => fmtTime(c.updatedAt), sort: "updatedAt" },
    ], state ? "No candidates are in this state." : "No candidates are recorded.", defaultSort));
}
