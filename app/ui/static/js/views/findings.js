// Findings: dependency checks and governance findings, as two tabs of one page. The two
// datasets stay separate: each tab keeps its own columns, filters, and API.
import { get } from "../api.js";
import { KIND_LABEL } from "../assess.js";
import { badge, h, link, mono, section, table } from "../dom.js";
import { activeTab, collectIds, employeeTerms, hashFor } from "../present.js";
import { HEALTH_LABEL, filterLinks, healthBadge } from "./directory.js";
import { identity, lede, listing, pageParams, resolveRefs, tabs } from "./common.js";
import { provenanceCells } from "./inventory.js";

const FINDING_TABS = [{ id: "dependency", text: "Dependency" }, { id: "governance", text: "Governance" }];
const GOVERNANCE_FILTERS = ["severity", "code", "subjectKind"];

export async function findings(ctx) {
  ctx.setTitle("Findings");
  // Links from before the tabs (#/findings?severity=…) meant governance findings.
  const legacy = GOVERNANCE_FILTERS.some((name) => ctx.query[name]);
  const tab = activeTab(ctx.query, FINDING_TABS.map((t) => t.id), legacy ? "governance" : "dependency");
  const query = { ...ctx.query, tab };
  const panel = tab === "governance" ? await governanceTab(query) : await dependencyTab(query);
  ctx.view.append(tabs("/findings", "Findings", FINDING_TABS, tab, panel));
}

// --- dependency checks ----------------------------------------------------------------------

async function dependencyTab(query) {
  const data = await get("/dependency-findings", pageParams(query, null, { key: "dependencyKind", dir: "asc" }));
  const refs = await resolveRefs(collectIds(data.items, "subjectId"));
  return [
    lede("Each dependency check and what it found. A check that found nothing is only meaningful if it completed and is decision-grade; an unchecked kind is never clear."),
    listing("/findings", query, data, "Dependency checks", [
      { label: "Kind", rowHeader: true, render: (d) => KIND_LABEL[d.dependencyKind] || d.dependencyKind, sort: "dependencyKind" },
      { label: "Subject", render: (d) => identity(refs[d.subjectId], d.subjectId), sort: "subject" },
      { label: "Findings", sort: "findings", render: (d) => (d.findings.length
        ? h("ul", { class: "plain-list" }, d.findings.map((f) => h("li", null,
          f.blocking ? badge("Blocking", "blocked") : badge("Informational", "neutral"), " ", f.description,
          f.code ? [" ", mono(`(${f.code})`)] : null)))
        : (d.provenance.resultStatus === "COMPLETE" && d.provenance.decisionGrade ? "None found (complete check)" : badge("No result usable", "caution"))) },
      ...provenanceCells(),
    ], "No dependency checks are recorded.", { key: "dependencyKind", dir: "asc" }),
    h("p", { class: "muted" }, "Per-candidate coverage, including kinds that were never checked, is on each candidate's page."),
  ];
}

// --- governance findings --------------------------------------------------------------------

const SUBJECT_ROUTE = { GROUP: "directory-groups", APPLICATION: "applications", PERSON: "people" };

async function governanceTab(query) {
  const filters = {};
  for (const name of GOVERNANCE_FILTERS) if (query[name]) filters[name] = query[name];
  const defaultSort = { key: "severity", dir: "desc" };
  const data = await get("/governance-findings", pageParams(query, filters, defaultSort));
  // Two groups can share a name, so subjects are resolved by id for their qualifier.
  const refs = await resolveRefs(collectIds(data.items, "subjectId"));
  const counts = data.counts || {};
  const rows = [];
  for (const severity of ["ACTIONABLE", "QUESTIONABLE", "INFO"]) {
    for (const [code, n] of Object.entries(counts[severity] || {})) rows.push({ severity, code, n });
  }
  const subject = (f) => (refs[f.subjectId] ? identity(refs[f.subjectId], f.subjectId)
    : link(`#/${SUBJECT_ROUTE[f.subjectKind]}/${f.subjectId}`, f.subjectName));
  return [
    lede(data.note),
    filterLinks("/findings", query, "severity", ["ACTIONABLE", "QUESTIONABLE", "INFO"], HEALTH_LABEL),
    section("Findings by rule",
      table("How many findings each rule produced", [
        { label: "Rule", rowHeader: true, render: (r) => link(hashFor("/findings", {}, { tab: "governance", code: r.code }), r.code), sort: (r) => r.code },
        { label: "Severity", render: (r) => healthBadge(r.severity), sort: (r) => ["INFO", "QUESTIONABLE", "ACTIONABLE"].indexOf(r.severity) },
        { label: "Findings", num: true, render: (r) => String(r.n), sort: (r) => r.n },
      ], rows, "No findings: this store has no directory snapshot.")),
    section("Findings",
      listing("/findings", query, data, "Findings", [
        { label: "Subject", rowHeader: true, render: subject, sort: "subjectName" },
        { label: "Severity", render: (f) => healthBadge(f.severity), sort: "severity" },
        { label: "Rule", render: (f) => mono(f.code), sort: "code" },
        { label: "What was found", render: (f) => employeeTerms(f.summary) },
        { label: "Suggested review", render: (f) => employeeTerms(f.recommendation) },
      ], "No findings match these filters.", defaultSort)),
  ];
}
