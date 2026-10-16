import { checkedId, get } from "../api.js";
import { coverageText, KIND_LABEL, mappingInfo } from "../assess.js";
import { badge, banner, facts, fmtTime, h, humanize, mono, section, table, yesNo, actorText } from "../dom.js";
import { activeTab, collectIds, employeeTerms } from "../present.js";
import { appLink, groupLink, identity, lede, listing, mappingLink, pageParams, resolveRefs, tabs } from "./common.js";
import { directoryGroupLink, healthBadge, personLink } from "./directory.js";

/** Observed and Result columns of an evidence listing; sortable on the server. */
export function provenanceCells() {
  return [
    { label: "Observed", render: (r) => fmtTime(r.provenance.observedAt), sort: "observedAt" },
    { label: "Result", render: (r) => resultBadge(r.provenance), sort: "result" },
  ];
}

export function resultBadge(provenance) {
  if (!provenance) return badge("No observation", "blocked");
  if (provenance.resultStatus !== "COMPLETE") return badge(`${humanize(provenance.resultStatus)} result`, "blocked");
  if (!provenance.decisionGrade) return badge("Not decision-grade", "caution");
  return badge("Complete", "neutral");
}

export function provenanceFacts(p) {
  return facts([
    ["Source", mono(p.source)],
    ["Observed", fmtTime(p.observedAt)],
    ["Scope", mono(p.scope)],
    ["Result", resultBadge(p)],
    ["Decision-grade", yesNo(p.decisionGrade)],
    ["Collector version", mono(p.collectorVersion)],
  ], "Provenance");
}

function appStatusBadge(status) {
  return badge(humanize(status), status === "ACTIVE" ? "neutral" : "caution");
}

// --- Okta: applications and groups ---------------------------------------------------------

const OKTA_TABS = [{ id: "applications", text: "Applications" }, { id: "groups", text: "Groups" }];

export async function okta(ctx) {
  ctx.setTitle("Okta");
  const tab = activeTab(ctx.query, OKTA_TABS.map((t) => t.id));
  const query = { ...ctx.query, tab };
  const panel = tab === "groups" ? await oktaGroups(query) : await oktaApplications(query);
  ctx.view.append(tabs("/okta", "Okta", OKTA_TABS, tab, panel));
}

async function oktaApplications(query) {
  const defaultSort = { key: "label", dir: "asc" };
  const data = await get("/applications", pageParams(query, null, defaultSort));
  return [
    lede("Okta applications as last observed. Status and usage come from Okta's read-only APIs."),
    listing("/okta", query, data, "Okta applications", [
      { label: "Application", rowHeader: true, render: (a) => appLink(a.id, a.label), sort: "label" },
      { label: "Status", render: (a) => appStatusBadge(a.status), sort: "status" },
      { label: "Sign-on mode", render: (a) => a.signOnMode, sort: "signOnMode" },
      ...provenanceCells(),
    ], "No applications are recorded.", defaultSort),
  ];
}

async function oktaGroups(query) {
  const defaultSort = { key: "name", dir: "asc" };
  const data = await get("/groups", pageParams(query, null, defaultSort));
  const refs = await resolveRefs(collectIds(data.items, "id"));
  const mapped = (g) => {
    const ad = refs[g.id] && refs[g.id].mappedAdGroup;
    return ad ? identity(ad, ad.id) : "—";
  };
  return [
    lede("Okta groups as last observed. An AD group is shown only where an exact identity mapping names it. The directory SID that Okta reports is unverified metadata and never establishes a mapping."),
    listing("/okta", query, data, "Okta groups", [
      { label: "Okta group", rowHeader: true, render: (g) => identity(refs[g.id], g.id), sort: "name" },
      { label: "Type", render: (g) => humanize(g.groupType), sort: "groupType" },
      { label: "Mapped AD group (exact)", render: mapped },
      { label: "Directory name (Okta)", render: (g) => (g.directoryQualifiedName ? mono(g.directoryQualifiedName) : "—"), sort: "directoryQualifiedName" },
      { label: "Directory SID (unverified)", render: (g) => (g.directoryObjectSidUnverified ? mono(g.directoryObjectSidUnverified) : "—") },
      ...provenanceCells(),
    ], "No Okta groups are recorded.", defaultSort),
  ];
}

export async function application(ctx) {
  const id = checkedId(ctx.params.id);
  const data = await get(`/applications/${id}`);
  const app = data.application;
  const refs = await resolveRefs(collectIds(data.assignments, "oktaGroupId"));
  ctx.setTitle(`Application: ${app.label}`);
  ctx.view.append(
    facts([
      ["Label", app.label],
      ["Status", appStatusBadge(app.status)],
      ["Okta app id", mono(app.oktaAppId)],
      ["Sign-on mode", app.signOnMode],
      ["OGWA id", mono(app.id)],
      ["Digest", mono(app.digest)],
    ], "Application"),
    section("Provenance", provenanceFacts(app.provenance)),
    data.profile ? applicationProfile(data.profile) : null,
    section("Group assignments",
      table("Groups assigned to this application", [
        { label: "Okta group", rowHeader: true, render: (a) => identity(refs[a.oktaGroupId], a.oktaGroupId),
          sort: (a) => (refs[a.oktaGroupId] || {}).name },
        { label: "Assignment", render: (a) => (a.present ? "Present" : badge("No longer observed", "caution")), sort: (a) => (a.present ? 0 : 1) },
        { label: "Observed", render: (a) => fmtTime(a.provenance.observedAt), sort: (a) => a.provenance.observedAt },
        { label: "Result", render: (a) => resultBadge(a.provenance) },
      ], data.assignments, "No group assignments are recorded.")));
}

function applicationProfile(profile) {
  const a = profile.application;
  return section("In the company directory",
    facts([
      ["Category", a.category],
      ["Provisioning", a.provisioning],
      ["Adopted", a.adopted],
      ["Behind Okta since", a.oktaIntegrated],
      ["sg-okta-* groups since", a.standardized || "Not standardized"],
      ["Tiers", a.tiers.join(", ")],
      ["Assignment model", humanize(a.assignmentModel)],
      ["Owner", profile.owner ? personLink(profile.owner.id, profile.owner.displayName) : "None recorded"],
      ["People with access", String(a.entitledPeople)],
      ["Sign-ins in 90 days", `${a.usageEvents90d} by ${a.usageUsers90d} people`],
      ["Health", healthBadge(a.health)],
    ], "Application profile"),
    table("Groups granting access, every naming era", [
      { label: "Group", rowHeader: true, render: (r) => (r.group ? directoryGroupLink(r.group.id, r.group.name) : r.groupKey),
        sort: (r) => (r.group ? r.group.name : r.groupKey) },
      { label: "Tier", render: (r) => r.tier || "—", sort: (r) => r.tier },
      { label: "Since", render: (r) => r.created, sort: (r) => r.created },
      { label: "Present", render: (r) => (r.present ? "Yes" : badge("No longer assigned", "neutral")), sort: (r) => (r.present ? 0 : 1) },
      { label: "Group health", render: (r) => (r.group ? healthBadge(r.group.health) : "—") },
    ], profile.groupAssignments, "No group assignments."),
    table("Individual assignments (outside group governance)", [
      { label: "Person", rowHeader: true, render: (r) => (r.person ? personLink(r.person.id, r.person.displayName) : r.personId),
        sort: (r) => (r.person ? r.person.displayName : r.personId) },
      { label: "Tier", render: (r) => r.tier || "—", sort: (r) => r.tier },
      { label: "Since", render: (r) => r.created, sort: (r) => r.created },
    ], profile.directAssignments, "No individual assignments."),
    table("Governance findings on this application", [
      { label: "Severity", rowHeader: true, render: (f) => healthBadge(f.severity) },
      { label: "Finding", render: (f) => [mono(f.code), " ", employeeTerms(f.summary)] },
    ], profile.findings, "No findings."));
}

export function adGroupFacts(ad, entry) {
  if (!ad) return banner("blocked", "AD evidence unavailable.", "There is no observation of an AD group for this mapping.");
  return facts([
    ["AD group", entry ? identity(entry, ad.id) : "—"],
    ["sAMAccountName", mono(ad.samAccountName)],
    ["Distinguished name", mono(ad.distinguishedName)],
    ["Domain", mono(ad.domain)],
    ["objectGUID", mono(ad.objectGuid)],
    ["objectSid", mono(ad.sid)],
    ["Exists", ad.exists ? "Yes" : badge("No", "blocked")],
    ["Direct members (AD member attribute)", ad.memberCount === null || ad.memberCount === undefined ? "Unknown" : String(ad.memberCount)],
    ["adminCount", yesNo(ad.adminCount)],
    ["Protected from accidental deletion", yesNo(ad.protectedFromAccidentalDeletion)],
    ["Critical system object", yesNo(ad.isCriticalSystemObject)],
    ["Observed", `${fmtTime(ad.provenance.observedAt)} (${ad.provenance.source})`],
    ["Result", resultBadge(ad.provenance)],
  ], "AD group");
}

export async function group(ctx) {
  const id = checkedId(ctx.params.id);
  const data = await get(`/groups/${id}`);
  const g = data.group;
  const info = mappingInfo(data.mapping, g);
  const refs = await resolveRefs([...collectIds(data.assignments, "applicationId"), data.adGroup && data.adGroup.id]);
  ctx.setTitle(`Okta group: ${g.name}`);
  ctx.view.append(
    facts([
      ["Name", g.name],
      ["Type", humanize(g.groupType)],
      ["Okta group id", mono(g.oktaGroupId)],
      ["Directory name (Okta)", g.directoryQualifiedName ? mono(g.directoryQualifiedName) : "—"],
      ["Directory SID (unverified, D37)", g.directoryObjectSidUnverified ? mono(g.directoryObjectSidUnverified) : "None reported"],
      ["OGWA id", mono(g.id)],
      ["Company directory", data.directory ? [directoryGroupLink(data.directory.id, "Naming era, nesting, and members"), " ",
        healthBadge(data.directory.health)] : "Not in a directory snapshot"],
    ], "Okta group"),
    section("Identity mapping",
      banner(info.tone, info.headline, info.detail),
      h("p", null, mappingLink(g.id, "Mapping evidence and review history"))),
    section("Mapped AD group", data.mapping && data.mapping.adGroupId ? adGroupFacts(data.adGroup, data.adGroup && refs[data.adGroup.id])
      : h("p", { class: "muted" }, "No AD group is mapped exactly.")),
    section("Application assignments",
      table("Applications this group is assigned to", [
        { label: "Application", rowHeader: true, render: (a) => identity(refs[a.applicationId], a.applicationId),
          sort: (a) => (refs[a.applicationId] || {}).name },
        { label: "Assignment", render: (a) => (a.present ? "Present" : badge("No longer observed", "caution")), sort: (a) => (a.present ? 0 : 1) },
        { label: "Observed", render: (a) => fmtTime(a.provenance.observedAt), sort: (a) => a.provenance.observedAt },
        { label: "Result", render: (a) => resultBadge(a.provenance) },
      ], data.assignments, "No application assignments are recorded.")),
    section("Lifecycle candidates",
      data.candidateIds.length ? h("ul", { class: "plain-list" }, data.candidateIds.map((c) => h("li", null, h("a", { href: `#/candidates/${c}` }, `Candidate for ${g.name}`), " ", mono(c))))
        : h("p", { class: "muted" }, "No candidate exists for this group.")));
}

// --- identity mappings ----------------------------------------------------------------------

export async function mappings(ctx) {
  ctx.setTitle("Identity mappings");
  const defaultSort = { key: "oktaGroup", dir: "asc" };
  const data = await get("/mappings", pageParams(ctx.query, null, defaultSort));
  const refs = await resolveRefs(collectIds(data.items, "oktaGroupId", "adGroupId"));
  ctx.view.append(
    lede("How each Okta group corresponds to an AD group. Only an exact mapping identifies the AD group; name-only, ambiguous, and not-found mappings block every automatic step."),
    listing("/mappings", ctx.query, data, "Identity mappings", [
      { label: "Okta group", rowHeader: true, sort: "oktaGroup",
        render: (m) => (refs[m.oktaGroupId] && refs[m.oktaGroupId].resolved ? mappingLink(m.oktaGroupId, refs[m.oktaGroupId].name)
          : identity(refs[m.oktaGroupId], m.oktaGroupId)) },
      { label: "Confidence", render: (m) => { const i = mappingInfo(m, null); return badge(i.label, i.tone); }, sort: "confidence" },
      { label: "Matched on", render: (m) => (m.matchedAttributes.length ? m.matchedAttributes.join(", ") : "—") },
      { label: "AD group", render: (m) => (m.adGroupId ? identity(refs[m.adGroupId], m.adGroupId) : "—"), sort: "adGroup" },
      ...provenanceCells(),
    ], "No identity mappings are recorded.", defaultSort));
}

export async function mapping(ctx) {
  const id = checkedId(ctx.params.id);
  const data = await get(`/mappings/${id}`);
  const group = await get(`/groups/${id}`);
  const info = mappingInfo(data.mapping, group.group);
  const m = data.mapping;
  const registry = data.registry || { reviews: [] };
  const refs = await resolveRefs([data.adGroup && data.adGroup.id, ...collectIds(data.candidateAdGroups, "id")]);
  ctx.setTitle(`Identity mapping: ${group.group.name}`);
  ctx.view.append(
    banner(info.tone, info.headline, info.detail),
    m ? facts([
      ["Confidence", badge(info.label, info.tone)],
      ["Exact", m.isExact ? "Yes" : "No"],
      ["Reason (engine)", m.reason],
      ["Matched attributes", m.matchedAttributes.join(", ") || "—"],
      ["Configuration reference", m.configurationRef ? mono(m.configurationRef) : "—"],
      ["Observed", `${fmtTime(m.provenance.observedAt)} (${m.provenance.source})`],
      ["Result", resultBadge(m.provenance)],
      ["Okta group", groupLink(id, group.group.name)],
    ], "Mapping") : null,
    section("Mapped AD group", m && m.adGroupId ? adGroupFacts(data.adGroup, data.adGroup && refs[data.adGroup.id])
      : h("p", { class: "muted" }, "None.")),
    data.candidateAdGroups.length ? section("Possible counterparts (none is assumed)",
      table("AD groups that could be the counterpart", [
        { label: "AD group", rowHeader: true, render: (a) => identity(refs[a.id], a.id) },
        { label: "sAMAccountName", render: (a) => mono(a.samAccountName) },
        { label: "Domain", render: (a) => mono(a.domain) },
        { label: "Distinguished name", render: (a) => mono(a.distinguishedName) },
        { label: "objectGUID", render: (a) => mono(a.objectGuid) },
      ], data.candidateAdGroups)) : null,
    section("Review history",
      h("p", { class: "muted" }, "Mapping reviews are recorded through the API by two different people. This console shows them read-only."),
      table("Mapping reviews", [
        { label: "Status", rowHeader: true, render: (r) => humanize(r.reviewStatus) },
        { label: "Confidence", render: (r) => humanize(r.confidence) },
        { label: "AD group", render: (r) => mono(r.adDistinguishedName) },
        { label: "Decided by", render: (r) => actorText(r.decidedBy) },
        { label: "Decided", render: (r) => fmtTime(r.decidedAt), sort: (r) => r.decidedAt },
        { label: "Reason", render: (r) => r.reason },
      ], registry.reviews, "No mapping reviews are recorded.")));
}

export function coverageTable(coverage) {
  if (!coverage) return banner("blocked", "Dependency coverage unavailable.", "No policy is in force, so coverage cannot be judged.");
  return table("Dependency coverage by kind", [
    { label: "Kind", rowHeader: true, render: (k) => KIND_LABEL[k.kind] || k.kind, sort: (k) => KIND_LABEL[k.kind] || k.kind },
    { label: "Required", render: (k) => (k.required ? "Yes" : "No"), sort: (k) => Number(k.required) },
    { label: "Status", render: (k) => { const t = coverageText(k.status); return badge(t.label, k.required ? t.tone : "neutral"); },
      sort: (k) => coverageText(k.status).label },
    { label: "Production collector", render: (k) => (k.productionCollector
      ? [k.productionCollector, k.productionCollectorLiveVerified ? "" : " (not live-verified)"] : "None exists"),
      sort: (k) => k.productionCollector },
  ], coverage.kinds);
}

// --- collectors -----------------------------------------------------------------------------

export async function collectors(ctx) {
  ctx.setTitle("Collector health");
  const data = await get("/collector-runs", pageParams(ctx.query));
  const s = data.summary || {};
  ctx.view.append(
    lede("Every read-only collection run. A partial or failed run leaves evidence that cannot support a decision; it is shown, never hidden."),
    facts([
      ["Runs recorded", String(s.runs || 0)],
      ["Incomplete (partial or failed)", s.incomplete ? badge(String(s.incomplete), "blocked") : "0"],
      ["Unfinished", s.unfinished ? badge(String(s.unfinished), "caution") : "0"],
    ], "Collector summary"),
    listing("/collectors", ctx.query, data, "Collector runs, newest first", [
      { label: "Collector", rowHeader: true, render: (r) => r.collector, sort: "collector" },
      { label: "Started", render: (r) => fmtTime(r.startedAt), sort: "startedAt" },
      { label: "Outcome", render: (r) => (!r.outcome ? badge("Unfinished", "caution")
        : r.outcome.status === "COMPLETE" ? badge("Complete", "neutral") : badge(humanize(r.outcome.status), "blocked")), sort: "outcome" },
      { label: "Records", num: true, render: (r) => (r.outcome ? String(r.outcome.recordsObserved) : "—"), sort: "records" },
      { label: "Error", render: (r) => (r.outcome && r.outcome.errorCode
        ? [mono(r.outcome.errorCode), r.outcome.errorSummary ? ` ${r.outcome.errorSummary}` : ""] : "—") },
      { label: "Source", render: (r) => mono(r.source) },
      { label: "Scope", render: (r) => mono(r.scope) },
    ], "No collector runs are recorded."));
}
