import { anonymous, can, checkedId, get } from "../api.js";
import { stateInfo } from "../assess.js";
import { actorText, badge, banner, facts, fmtTime, h, humanize, mono, section, table } from "../dom.js";
import { collectIds } from "../present.js";
import { identity, jobLink, lede, listing, pageParams, resolveRefs } from "./common.js";
import { candidateName } from "./candidates.js";

const STAGE_LABEL = { OKTA_UNASSIGN: "Okta unassignment", AD_QUARANTINE: "AD quarantine", AD_DELETION: "AD deletion",
  AD_RETIREMENT: "AD retirement (legacy)" };

// --- approvals and holds --------------------------------------------------------------------

export async function approvals(ctx) {
  ctx.setTitle("Approvals and holds");
  const defaultSort = { key: "decidedAt", dir: "desc" };
  const [list, review, revalidation, proposed, held, holdPeriod, quarantineHold] = await Promise.all([
    get("/approvals", pageParams(ctx.query, null, defaultSort)),
    get("/candidates", { state: "NEEDS_REVIEW", limit: 200 }),
    get("/candidates", { state: "REVALIDATION_REQUIRED", limit: 200 }),
    get("/candidates", { state: "DELETION_PROPOSED", limit: 200 }),
    get("/candidates", { state: "BLOCKED", limit: 200 }),
    get("/candidates", { state: "HOLD", limit: 200 }),
    get("/candidates", { state: "QUARANTINE_HOLD", limit: 200 }),
  ]);
  const queues = [review, revalidation, proposed, held, holdPeriod, quarantineHold].flatMap((q) => q.items);
  const refs = await resolveRefs([...collectIds(queues, "oktaGroupId"), ...collectIds(list.items, "candidateId")]);
  const holdUntil = (c) => (c.state === "QUARANTINE_HOLD" ? c.quarantineHoldUntil : c.holdUntil);
  const queue = (items, caption, empty) => table(caption, [
    { label: "Okta group", rowHeader: true, render: (c) => candidateName(refs, c), sort: (c) => (refs[c.oktaGroupId] || {}).name },
    { label: "State", render: (c) => { const i = stateInfo(c.state); return badge(i.label, i.tone); }, sort: (c) => stateInfo(c.state).label },
    { label: "Blocked from", render: (c) => (c.blockedFrom ? stateInfo(c.blockedFrom).label : "—") },
    { label: "Hold until", render: (c) => fmtTime(holdUntil(c)), sort: holdUntil },
    { label: "Updated", render: (c) => fmtTime(c.updatedAt), sort: (c) => c.updatedAt },
  ], items, empty);

  ctx.view.append(
    lede("Approvals record a decision for a future, separately executed step. An approval alone changes nothing in Okta or Active Directory."),
    section("Waiting for a decision",
      queue(review.items, "Okta unassignment: waiting in Needs review", "Nothing is waiting for an Okta unassignment decision."),
      queue(revalidation.items, "AD quarantine: waiting in Revalidation required", "Nothing is waiting for an AD quarantine decision."),
      queue(proposed.items, "AD deletion: waiting in Deletion proposed", "Nothing is waiting for an AD deletion decision.")),
    section("Holds",
      queue(held.items, "Held by an operator (BLOCKED)", "No candidate is held by an operator."),
      queue(holdPeriod.items, "In the post-unassignment hold period", "No candidate is in its hold period."),
      queue(quarantineHold.items, "In the post-quarantine hold period", "No candidate is in its post-quarantine hold.")),
    section("Recorded approvals and rejections",
      listing("/approvals", ctx.query, list, "Approvals and rejections", [
        { label: "Candidate", rowHeader: true, render: (a) => identity(refs[a.candidateId], a.candidateId), sort: "candidate" },
        { label: "Stage", render: (a) => STAGE_LABEL[a.stage] || a.stage, sort: "stage" },
        { label: "Decision", render: (a) => (a.decision === "APPROVE" ? badge("Approved for future action", "caution") : badge("Rejected", "neutral")), sort: "decision" },
        { label: "By", render: (a) => actorText(a.operator) },
        { label: "Decided", render: (a) => fmtTime(a.decidedAt), sort: "decidedAt" },
        { label: "Expires", render: (a) => [fmtTime(a.expiresAt), a.expired ? [" ", badge("Expired", "neutral")] : null], sort: "expiresAt" },
        { label: "Reason", render: (a) => a.reason },
      ], "No approvals or rejections are recorded.", defaultSort)));
}

// --- execution jobs -------------------------------------------------------------------------

const NO_EXECUTION = "Execution is not available in this build. Every job here is a dry-run plan or a recorded check-mode result; nothing was executed by OGWA.";

function jobStatus(j) {
  return badge(humanize(j.status), j.status === "FAILED" ? "blocked" : "neutral");
}

export async function jobs(ctx) {
  ctx.setTitle("Execution jobs");
  const defaultSort = { key: "requestedAt", dir: "desc" };
  const data = await get("/execution-jobs", pageParams(ctx.query, null, defaultSort));
  const refs = await resolveRefs(collectIds(data.items, "candidateId"));
  ctx.view.append(
    banner("caution", "Dry-run planning only.", NO_EXECUTION),
    listing("/jobs", ctx.query, data, "Execution jobs", [
      { label: "Job", rowHeader: true, render: (j) => jobLink(j.id) },
      { label: "Candidate", render: (j) => identity(refs[j.candidateId], j.candidateId), sort: "candidate" },
      { label: "Kind", render: (j) => STAGE_LABEL[j.kind] || j.kind, sort: "kind" },
      { label: "Status", render: jobStatus, sort: "status" },
      { label: "Executed", render: (j) => (j.executed ? badge("Yes", "blocked") : "No") },
      { label: "Mode", render: (j) => mono(j.executionMode) },
      { label: "Requested", render: (j) => `${fmtTime(j.requestedAt)} by ${actorText(j.requestedBy)}`, sort: "requestedAt" },
    ], "No execution jobs are recorded.", defaultSort));
}

export async function job(ctx) {
  const id = checkedId(ctx.params.id);
  const { job: j } = await get(`/execution-jobs/${id}`);
  const refs = await resolveRefs([j.candidateId]);
  ctx.setTitle(`Execution job ${j.id}`);
  ctx.view.append(
    banner("caution", "Dry-run planning only.", NO_EXECUTION),
    facts([
      ["Candidate", identity(refs[j.candidateId], j.candidateId)],
      ["Kind", STAGE_LABEL[j.kind] || j.kind],
      ["Status", jobStatus(j)],
      ["Executed", j.executed ? badge("Yes", "blocked") : "No"],
      ["Dry run", j.dryRun ? "Yes" : badge("No", "blocked")],
      ["Execution mode", mono(j.executionMode)],
      ["Approval", mono(j.approvalId)],
      ["Evidence fingerprint", mono(j.evidenceFingerprint)],
      ["Targets", j.targets.length ? h("ul", { class: "plain-list" }, j.targets.map((t) => h("li", null, mono(t)))) : "—"],
      ["Requested", `${fmtTime(j.requestedAt)} by ${actorText(j.requestedBy)}`],
      ["Finished", fmtTime(j.finishedAt)],
    ], "Execution job"),
    section("Status history",
      table("Status history", [
        { label: "Sequence", num: true, render: (e) => String(e.sequence) },
        { label: "Status", rowHeader: true, render: (e) => humanize(e.status) },
        { label: "Executed", render: (e) => (e.executed ? badge("Yes", "blocked") : "No") },
        { label: "Detail", render: (e) => e.detail },
        { label: "External reference", render: (e) => (e.externalRef ? mono(e.externalRef) : "—") },
        { label: "Recorded", render: (e) => fmtTime(e.recordedAt) },
      ], j.statusHistory)));
}

// --- audit history --------------------------------------------------------------------------

export async function audit(ctx) {
  ctx.setTitle("Audit history");
  if (!can("READ_AUDIT")) {
    ctx.view.append(anonymous()
      ? banner("neutral", "The public demo does not show the audit trail.", "The dashboard shows its event count and head, which no visitor can move. Run OGWA locally to read the trail.")
      : banner("neutral", "Your role cannot read the audit trail.", "Ask someone with audit access, such as an administrator."));
    return;
  }
  const params = pageParams(ctx.query, null, { key: "sequence", dir: "desc" });
  const subject = typeof ctx.query.subjectId === "string" && /^[A-Za-z0-9_.:\/-]{1,100}$/.test(ctx.query.subjectId) ? ctx.query.subjectId : "";
  if (subject) params.subjectId = subject;
  const data = await get("/audit-events", params);
  const refs = await resolveRefs(collectIds(data.items, "subjectId").concat(subject || []));
  const filterLink = (id, text) => h("a", { href: `#/audit?subjectId=${encodeURIComponent(id)}` }, text);
  // A subject that names an object shows its name (linked to the object) and a link to its events;
  // anything else (approvals, jobs, decisions) keeps its id.
  const subjectCell = (id) => (refs[id] && refs[id].resolved
    ? h("span", null, identity(refs[id], id), " ", filterLink(id, "Events")) : filterLink(id, id));
  ctx.view.append(
    lede("The hash-chained audit trail, in chain order. Each event was re-verified against its digest when it was read. Only the sequence is sortable: sorting the chain by anything else would re-verify every event."),
    subject ? h("p", null, "Showing events for ", refs[subject] && refs[subject].resolved ? identity(refs[subject], subject) : mono(subject), ". ",
      h("a", { href: "#/audit" }, "Show all events")) : null,
    listing("/audit", subject ? { ...ctx.query, subjectId: subject } : ctx.query, data, "Audit events", [
      { label: "Sequence", num: true, render: (e) => String(e.sequence), sort: "sequence" },
      { label: "Action", rowHeader: true, render: (e) => humanize(e.action) },
      { label: "When", render: (e) => fmtTime(e.occurredAt) },
      { label: "Actor", render: (e) => actorText(e.actor) },
      { label: "Subject", render: (e) => (e.subjectId ? subjectCell(e.subjectId) : "—") },
      { label: "Result", render: (e) => (e.result ? badge(humanize(e.result), e.result === "SUCCEEDED" ? "neutral" : "caution") : "—") },
      { label: "Details", render: (e) => detailsList(e.details) },
      { label: "Request", render: (e) => mono(e.correlationId) },
      { label: "Digest", render: (e) => mono(e.digest) },
    ], "No audit events.", { key: "sequence", dir: "desc" }));
}

function detailsList(details) {
  const entries = Object.entries(details || {});
  if (!entries.length) return "—";
  return h("ul", { class: "plain-list" }, entries.map(([k, v]) => h("li", null, mono(k), `: ${v}`)));
}
