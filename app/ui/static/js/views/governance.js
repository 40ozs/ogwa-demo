import { anonymous, can, checkedId, get } from "../api.js";
import { actorText, badge, banner, facts, fmtTime, h, humanize, link, mono, section, table } from "../dom.js";
import { collectIds } from "../present.js";
import { planStatus } from "../review.js";
import { identity, jobLink, lede, listing, pageParams, resolveRefs } from "./common.js";

const STAGE_LABEL = { OKTA_UNASSIGN: "Okta unassignment", AD_QUARANTINE: "AD quarantine", AD_DELETION: "AD deletion",
  AD_RETIREMENT: "AD retirement (legacy)" };

// --- plans and simulations (OGWA-UI-REVIEW-01: was "Execution jobs"; the routes are unchanged) ---

const NO_EXECUTION = "Execution is not available in this build. Every record here is a dry-run plan or a recorded check-mode result; OGWA executed nothing and changed nothing in Okta or Active Directory.";

function jobStatus(j) {
  const s = planStatus(j);
  return badge(s.label, s.tone);
}

export async function jobs(ctx) {
  ctx.setTitle("Plans & simulations");
  const defaultSort = { key: "requestedAt", dir: "desc" };
  const data = await get("/execution-jobs", pageParams(ctx.query, null, defaultSort));
  const refs = await resolveRefs(collectIds(data.items, "candidateId"));
  ctx.view.append(
    banner("caution", "Dry-run planning only.", NO_EXECUTION),
    section("Dry-run plans and recorded check-mode results",
      listing("/jobs", ctx.query, data, "Dry-run plans", [
        { label: "Plan", rowHeader: true, render: (j) => jobLink(j.id) },
        { label: "Candidate", render: (j) => identity(refs[j.candidateId], j.candidateId), sort: "candidate" },
        { label: "Stage", render: (j) => STAGE_LABEL[j.kind] || j.kind, sort: "kind" },
        { label: "Status", render: jobStatus, sort: "status" },
        { label: "Executed", render: (j) => (j.executed ? badge("Yes", "blocked") : "No") },
        { label: "Mode", render: (j) => mono(j.executionMode) },
        { label: "Requested", render: (j) => `${fmtTime(j.requestedAt)} by ${actorText(j.requestedBy)}`, sort: "requestedAt" },
      ], "No dry-run plan is recorded.", defaultSort)),
    section("Synthetic drills",
      h("p", null, "A synthetic drill runs one remediation against an in-memory provider fixture that the server builds and then discards. It changes no external provider or persistent environment, and it records nothing, so drills never appear in this list. Run one from a candidate at a remediation stage; the ",
        link("#/scenarios", "Portfolio scenarios"), " walkthrough shows one.")));
}

export async function job(ctx) {
  const id = checkedId(ctx.params.id);
  const { job: j } = await get(`/execution-jobs/${id}`);
  const refs = await resolveRefs([j.candidateId]);
  ctx.setTitle(`Dry-run plan ${j.id}`);
  ctx.view.append(
    banner("caution", "Dry-run planning only.", NO_EXECUTION),
    facts([
      ["Candidate", identity(refs[j.candidateId], j.candidateId)],
      ["Kind", STAGE_LABEL[j.kind] || j.kind],
      ["Status", jobStatus(j)],
      ["Recorded status", mono(j.status)],
      ["Executed", j.executed ? badge("Yes", "blocked") : "No"],
      ["Dry run", j.dryRun ? "Yes" : badge("No", "blocked")],
      ["Execution mode", mono(j.executionMode)],
      ["Approval", mono(j.approvalId)],
      ["Evidence fingerprint", mono(j.evidenceFingerprint)],
      ["Targets", j.targets.length ? h("ul", { class: "plain-list" }, j.targets.map((t) => h("li", null, mono(t)))) : "—"],
      ["Requested", `${fmtTime(j.requestedAt)} by ${actorText(j.requestedBy)}`],
      ["Finished", fmtTime(j.finishedAt)],
    ], "Dry-run plan"),
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
