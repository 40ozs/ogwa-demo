// The synthetic directory snapshot: the demo company (Company Directory: departments, groups,
// applications), its people, the canonical AD group page, and the portfolio scenarios.
// Read-only views.
import { checkedId, get } from "../api.js";
import { badge, banner, facts, fmtTime, h, humanize, link, mono, section, table, uid } from "../dom.js";
import { activeTab, employeeTerms, eventLabel, hashFor, PERSON_STATUS_LABEL, personStatus } from "../present.js";
import { appLink, candidateLink, chain, go, groupLink, groupRef, lede, listing, pageParams, tabs } from "./common.js";

const HEALTH_TONE = { ACTIONABLE: "blocked", QUESTIONABLE: "caution", CLEAN: "neutral", INFO: "info" };
export const HEALTH_LABEL = { ACTIONABLE: "Actionable", QUESTIONABLE: "Worth a look", CLEAN: "No findings", INFO: "Context" };
const HEALTH_RANK = { CLEAN: 0, INFO: 1, QUESTIONABLE: 2, ACTIONABLE: 3 };
const ERA_LABEL = { "legacy-ad": "2016–2019 legacy AD", "app-specific": "2019–2021 app-specific",
  "transitional-okta": "2021–2023 transitional Okta", modern: "2023– sg-* standard" };
const SOURCE_LABEL = { AD: "AD", OKTA: "Okta", BUILT_IN: "Built-in" };
const DIRECTORY_TABS = [{ id: "departments", text: "Departments" }, { id: "groups", text: "Groups" },
  { id: "applications", text: "Applications" }];

export function healthBadge(value) {
  return badge(HEALTH_LABEL[value] || humanize(value), HEALTH_TONE[value] || "neutral");
}

function eraText(era) {
  return ERA_LABEL[era] || era;
}

export function day(value) {
  return value ? String(value).slice(0, 10) : "—";
}

export function personLink(id, text) {
  return link(`#/people/${id}`, text || id);
}

export function directoryGroupLink(id, text) {
  return link(`#/directory-groups/${id}`, text || id);
}

function personRef(p) {
  if (!p) return "—";
  return [personLink(p.id, p.displayName), p.status === "ACTIVE" ? null : [" ", badge(personStatus(p).label, "caution")]];
}

export function filterLinks(route, query, name, values, labels) {
  const items = [["All", null], ...values.map((v) => [labels ? labels[v] || humanize(v) : humanize(v), v])];
  return h("p", { class: "filters" }, `${humanize(name)}: `, items.map(([text, value], i) => {
    const current = (query[name] || null) === value;
    return [i ? " · " : null, current ? h("strong", { "aria-current": "true" }, text)
      : link(hashFor(route, query, { [name]: value, cursor: null }), text)];
  }));
}

/** A search box over a listing's `q`; the result keeps the listing's other filters. */
function searchForm(route, query, label, hint) {
  const id = uid("search");
  const input = h("input", { type: "text", id, name: "q", value: query.q || "", maxlength: "100", autocomplete: "off" });
  return h("form", { class: "filters", role: "search", on: { submit: (event) => {
    event.preventDefault();
    go(hashFor(route, query, { q: input.value.trim(), cursor: null }), null);
  } } },
  h("div", { class: "field" }, h("label", { for: id }, label), hint ? h("span", { class: "hint" }, hint) : null, input),
  h("button", { type: "submit" }, "Search"));
}

function noSnapshot(data) {
  return banner("info", "No directory snapshot in this store.", data && data.note ? data.note
    : "Seed the Genesee Press dataset (python -m app.store reset-demo --dataset genesee-press --confirm-synthetic-reset).");
}

export function findingsTable(caption, items) {
  return table(caption, [
    { label: "Severity", rowHeader: true, render: (f) => healthBadge(f.severity), sort: (f) => -HEALTH_RANK[f.severity] },
    { label: "Finding", render: (f) => [mono(f.code), " ", employeeTerms(f.summary)], sort: (f) => f.code },
    { label: "Suggested review", render: (f) => employeeTerms(f.recommendation) },
  ], items || [], "No findings.");
}

// --- the company: Company Directory -------------------------------------------------------

export async function directory(ctx) {
  ctx.setTitle("Company Directory");
  const data = await get("/directory");
  if (!data.available) { ctx.view.append(noSnapshot(data)); return data; }
  const tab = activeTab(ctx.query, DIRECTORY_TABS.map((t) => t.id));
  const panel = tab === "groups" ? await groupsTab(ctx) : tab === "applications" ? applicationsTab(data) : departmentsTab(data);
  ctx.view.append(
    banner("caution", `${data.profile.company} is fictional.`, `Every person, group, application, and identifier here was generated from the seed ${data.profile.seed}. Nothing was read from a real tenant or directory.`),
    companyProfile(data),
    tabs("/directory", "Company Directory", DIRECTORY_TABS, tab, panel));
  return data;
}

function companyProfile(data) {
  const p = data.profile;
  const c = data.counts || {};
  const health = c.groupHealth || {};
  const total = (health.CLEAN || 0) + (health.QUESTIONABLE || 0) + (health.ACTIONABLE || 0);
  const pct = (n) => (total ? `${Math.round((100 * n) / total)}%` : "—");
  return h("details", { class: "profile" }, h("summary", null, "Company profile, estate, and group health"),
    h("div", { class: "cards" },
      h("div", { class: "card" }, h("h2", null, "Company"), facts([
        ["Primary domain", mono(p.primaryDomain)],
        ["Founded", p.founded],
        ["Okta adopted", p.oktaAdopted],
        ["sg-* naming standard since", p.modernNamingAdopted],
        ["Snapshot", p.snapshotDate],
        ["Active employees", String(c.activeEmployees)],
        ["Deactivated employees", String(c.formerEmployees)],
      ], "Company")),
      h("div", { class: "card" }, h("h2", null, "Estate"), facts([
        ["Applications (active)", `${c.applications} (${c.activeApplications})`],
        ["Groups (Okta sees)", `${c.groups} (${c.oktaVisibleGroups})`],
        ["Groups on the sg-* standard", String(c.modernNamedGroups)],
        ["Nesting edges", String(c.nestingEdges)],
        ["Direct memberships", String(c.directMemberships)],
        ["Individual app assignments", String(c.directUserAssignments)],
      ], "Estate")),
      h("div", { class: "card" }, h("h2", null, "Group health"), facts([
        ["No findings", `${health.CLEAN || 0} (${pct(health.CLEAN || 0)})`],
        ["Worth a look", `${health.QUESTIONABLE || 0} (${pct(health.QUESTIONABLE || 0)})`],
        ["Actionable", `${health.ACTIONABLE || 0} (${pct(health.ACTIONABLE || 0)})`],
      ], "Group health"), h("p", null, link("#/findings?tab=governance", "Governance findings")))),
    table("Groups by the era they were created in", [
      { label: "Era", rowHeader: true, render: ([era]) => link(hashFor("/directory", {}, { tab: "groups", era }), eraText(era)) },
      { label: "Groups", num: true, render: ([, n]) => String(n) },
    ], Object.entries(c.groupsByEra || {})));
}

function departmentsTab(data) {
  return table("Departments", [
    { label: "Department", rowHeader: true, render: (d) => link(`#/people?department=${d.slug}`, d.name), sort: (d) => d.name },
    { label: "Active people", num: true, render: (d) => String(d.size), sort: (d) => d.size },
    { label: "Formed", render: (d) => d.formed, sort: (d) => d.formed },
    { label: "Led by", render: (d) => d.leaderTitle, sort: (d) => d.leaderTitle },
  ], data.departments, "No departments.");
}

function applicationsTab(data) {
  return table("Application estate", [
    { label: "Application", rowHeader: true, render: (a) => appLink(a.id, a.label), sort: (a) => a.label },
    { label: "Category", render: (a) => a.category, sort: (a) => a.category },
    { label: "Status", render: (a) => humanize(a.status), sort: (a) => a.status },
    { label: "Sign-on", render: (a) => humanize(a.signOnMode), sort: (a) => a.signOnMode },
    { label: "Provisioning", render: (a) => a.provisioning, sort: (a) => a.provisioning },
    { label: "Assignment", render: (a) => humanize(a.assignmentModel), sort: (a) => a.assignmentModel },
    { label: "sg-okta-* since", render: (a) => a.standardized || "Not standardized", sort: (a) => a.standardized },
    { label: "People with access", num: true, render: (a) => String(a.entitledPeople), sort: (a) => a.entitledPeople },
    { label: "Health", render: (a) => healthBadge(a.health), sort: (a) => HEALTH_RANK[a.health] },
  ], data.applications, "No applications.");
}

const GROUP_DEFAULT_SORT = { key: "name", dir: "asc" };

async function groupsTab(ctx) {
  const filters = {};
  for (const name of ["era", "health", "source", "q"]) if (ctx.query[name]) filters[name] = ctx.query[name];
  const data = await get("/directory-groups", pageParams(ctx.query, filters, GROUP_DEFAULT_SORT));
  const route = "/directory";
  return [
    lede("Every AD and Okta group in the snapshot, including AD-only groups Okta never sees. Health is the most serious governance finding on the group."),
    searchForm(route, ctx.query, "Find a group", "By name, sAMAccountName, objectSid, objectGUID, or Okta group id"),
    filterLinks(route, ctx.query, "health", ["ACTIONABLE", "QUESTIONABLE", "CLEAN"], HEALTH_LABEL),
    filterLinks(route, ctx.query, "era", Object.keys(ERA_LABEL), ERA_LABEL),
    filterLinks(route, ctx.query, "source", ["AD", "OKTA", "BUILT_IN"], SOURCE_LABEL),
    listing(route, ctx.query, data, "Directory groups", [
      { label: "Group", rowHeader: true, render: groupRef, sort: "name" },
      { label: "Source", render: (g) => SOURCE_LABEL[g.source] || humanize(g.source), sort: "source" },
      { label: "Kind", render: (g) => humanize(g.kind), sort: "kind" },
      { label: "Era", render: (g) => eraText(g.era), sort: "era" },
      { label: "Created", render: (g) => day(g.createdAt), sort: "createdAt" },
      { label: "Status", render: (g) => humanize(g.status), sort: "status" },
      { label: "Effective members", num: true, render: (g) => String(g.effectiveMembers), sort: "effectiveMembers" },
      { label: "Nesting depth", num: true, render: (g) => String(g.nestingDepth), sort: "nestingDepth" },
      { label: "Health", render: (g) => healthBadge(g.health), sort: "health" },
    ], "No group matches these filters.", GROUP_DEFAULT_SORT),
  ];
}

// --- people -------------------------------------------------------------------------------------

const PEOPLE_DEFAULT_SORT = { key: "employeeNumber", dir: "asc" };

function statusCell(p) {
  const s = personStatus(p);
  return s.active ? s.label : badge(s.label, s.tone);
}

function deactivationCell(p) {
  const s = personStatus(p);
  if (s.active) return "—";
  return s.deactivationDate ? day(s.deactivationDate) : "Not recorded";
}

export async function people(ctx) {
  ctx.setTitle("People");
  const summary = await get("/directory");
  if (!summary.available) { ctx.view.append(noSnapshot(summary)); return; }
  const filters = {};
  for (const name of ["department", "status", "q"]) if (ctx.query[name]) filters[name] = ctx.query[name];
  const data = await get("/people", pageParams(ctx.query, filters, PEOPLE_DEFAULT_SORT));
  const department = Object.fromEntries(summary.departments.map((d) => [d.slug, d.name]));
  ctx.view.append(
    lede("Every synthetic person, active and deactivated. Deactivated employees never count toward the active headcount."),
    searchForm("/people", ctx.query, "Find a person", "By name, email, or employee number"),
    filterLinks("/people", ctx.query, "status", ["ACTIVE", "TERMINATED"], PERSON_STATUS_LABEL),
    filterLinks("/people", ctx.query, "department", summary.departments.map((d) => d.slug),
      Object.fromEntries(summary.departments.map((d) => [d.slug, d.name]))),
    listing("/people", ctx.query, data, "People", [
      { label: "Name", rowHeader: true, render: (p) => personLink(p.id, p.displayName), sort: "displayName" },
      { label: "Employee no.", render: (p) => mono(p.employeeNumber), sort: "employeeNumber" },
      { label: "Email", render: (p) => mono(p.email), sort: "email" },
      { label: "Department", render: (p) => department[p.department] || p.department, sort: "department" },
      { label: "Title", render: (p) => p.title, sort: "title" },
      { label: "Hired", render: (p) => day(p.hireDate), sort: "hireDate" },
      { label: "Status", render: statusCell, sort: "status" },
      { label: "Deactivation date", render: deactivationCell, sort: "terminationDate" },
    ], "Nobody matches these filters.", PEOPLE_DEFAULT_SORT));
}

export async function person(ctx) {
  const id = checkedId(ctx.params.id);
  const data = await get(`/people/${id}`);
  const p = data.person;
  ctx.setTitle(p.displayName);
  ctx.view.append(
    facts([
      ["Employee number", mono(p.employeeNumber)],
      ["Email and UPN", mono(p.email)],
      ["sAMAccountName", mono(p.samAccountName)],
      ["Department", p.department],
      ["Team", p.team || "—"],
      ["Title", p.title],
      ["Manager", personRef(data.manager)],
      ["Location", p.location],
      ["Hired", day(p.hireDate)],
      ["Status", statusCell(p)],
      ["Deactivation date", deactivationCell(p)],
      ["Okta account", humanize(p.oktaStatus)],
      ["AD account", humanize(p.adAccount)],
    ], "Person"),
    section("Employment and account history",
      table("History, oldest first", [
        { label: "Date", rowHeader: true, render: (e) => e.on, sort: (e) => e.on },
        { label: "Event", render: (e) => eventLabel(e.kind), sort: (e) => eventLabel(e.kind) },
        { label: "Department", render: (e) => e.department },
        { label: "Title", render: (e) => e.title },
        { label: "Detail", render: (e) => e.detail },
      ], data.history)),
    data.directReports.length ? section("Direct reports",
      h("ul", { class: "plain-list" }, data.directReports.map((r) => h("li", null, personRef(r), ` — ${r.title}`)))) : null,
    section("Direct group memberships",
      data.directGroups.length ? h("ul", { class: "plain-list" }, data.directGroups.map((g) => h("li", null, groupRef(g))))
        : h("p", { class: "muted" }, "No direct memberships.")),
    section("Application access and how it is granted",
      h("p", { class: "muted" }, "Each route is the assigned group first, then the nested groups down to one this person is a direct member of. More than one route to the same application means removing one route does not remove the access."),
      table("Applications this person reaches", [
        { label: "Application", rowHeader: true, render: (a) => (a.application.id ? appLink(a.application.id, a.application.label) : a.application.label),
          sort: (a) => a.application.label },
        { label: "Routes", num: true, render: (a) => (a.routeCount > 1 ? badge(String(a.routeCount), "caution") : String(a.routeCount)),
          sort: (a) => a.routeCount },
        { label: "How", render: (a) => h("ul", { class: "plain-list" }, a.routes.map((r) => h("li", null,
          r.direct ? badge("Individual assignment", "caution")
            : chain(r.chain.map(groupRef), `Route to ${a.application.label}`)))) },
      ], data.access, "This person reaches no application.")));
}

// --- the canonical group page ---------------------------------------------------------------

export async function directoryGroup(ctx) {
  const id = checkedId(ctx.params.id);
  const data = await get(`/directory-groups/${id}`);
  const g = data.group;
  const isAd = g.source === "AD";
  ctx.setTitle(`${isAd ? "AD group" : "Directory group"}: ${g.name}`);
  const sample = data.samplePath;
  ctx.view.append(
    g.ambiguous ? banner("info", `More than one group is named ${g.name}.`,
      "This page is the one identified below; links throughout OGWA go by its stable id, never by name.") : null,
    facts([
      ["Name", g.name],
      ["Name in Okta", g.oktaName && g.oktaName !== g.name ? mono(g.oktaName) : (g.oktaVisible ? "Same" : "Not visible to Okta")],
      ["Source", SOURCE_LABEL[g.source] || humanize(g.source)],
      ["Kind", humanize(g.kind)],
      ["Naming era", eraText(g.era)],
      ["Naming style", mono(g.namingStyle)],
      ["Created", fmtTime(g.createdAt)],
      ["Last modified", fmtTime(g.modifiedAt)],
      ["Status", humanize(g.status)],
      ["Owner", personRef(data.owner)],
      ["Effective members (active)", String(g.effectiveMembers)],
      ["Direct members", String(g.directMembers)],
      ["Nesting depth below", String(g.nestingDepth)],
      ["Correlation expected", g.correlationCase ? humanize(g.correlationCase) : "Not in Okta"],
      ["Okta group", g.oktaEvidenceId ? groupLink(g.oktaEvidenceId, "Okta group evidence and identity mapping") : "—"],
      ["Description", g.description],
      ["Health", healthBadge(g.health)],
    ], "Directory group"),
    isAd ? section("AD identity",
      h("p", { class: "muted" }, "The stable identifiers of this AD object. Its name is presentation only."),
      facts([
        ["sAMAccountName", mono(g.adSamAccountName)],
        ["Distinguished name", mono(g.adDistinguishedName)],
        ["objectSid", mono(g.adSid)],
        ["objectGUID", mono(g.adObjectGuid)],
        ["Exists in AD", g.adExists === false ? badge("No", "blocked") : "Yes"],
        ["OGWA AD evidence id", mono(g.adEvidenceId)],
        ["OGWA directory id", mono(g.id)],
      ], "AD identity")) : null,
    section("Governance findings", findingsTable("Findings on this group", data.findings)),
    section("Lineage",
      facts([
        ["Replaced by", groupRef(data.replacedBy)],
        ["Replaces", data.replaces.length ? h("ul", { class: "plain-list" }, data.replaces.map((r) => h("li", null, groupRef(r)))) : "—"],
        ["Pushed to (AD)", groupRef(data.pushTarget)],
      ], "Lineage")),
    section("Nesting",
      facts([
        ["Nested in (parent groups)", data.parents.length ? h("ul", { class: "plain-list" }, data.parents.map((r) => h("li", null, groupRef(r)))) : "—"],
        ["Contains groups", data.children.length ? h("ul", { class: "plain-list" }, data.children.map((r) => h("li", null, groupRef(r)))) : "—"],
      ], "Nesting"),
      sample ? h("div", null, h("p", null, "Example paths for ", personRef(sample.person), ":"),
        h("ul", { class: "plain-list" }, sample.chains.map((c) => h("li", null, chain(c.map(groupRef), `Path for ${sample.person.displayName}`)))))
        : null),
    section("Application assignments",
      table("Assignments of this group", [
        { label: "Application", rowHeader: true, render: (a) => a.applicationLabel || a.application, sort: (a) => a.applicationLabel || a.application },
        { label: "Tier", render: (a) => a.tier || "—", sort: (a) => a.tier },
        { label: "Since", render: (a) => a.created, sort: (a) => a.created },
        { label: "Present", render: (a) => (a.present ? "Yes" : badge("No longer assigned", "neutral")), sort: (a) => (a.present ? 1 : 0) },
      ], data.assignments, "Not assigned to any application.")),
    section("Direct members",
      table("Direct members", [
        { label: "Person", rowHeader: true, render: (p) => personRef(p), sort: (p) => p.displayName },
        { label: "Department", render: (p) => p.department, sort: (p) => p.department },
        { label: "Title", render: (p) => p.title, sort: (p) => p.title },
      ], data.directMembers, "No direct members."),
      data.directMembersTruncated ? h("p", { class: "muted" }, "Only the first 200 direct members are listed.") : null));
}

// --- scenarios ----------------------------------------------------------------------------------

export async function scenarios(ctx) {
  ctx.setTitle("Portfolio scenarios");
  const data = await get("/demo-scenarios");
  if (!data.items.length) { ctx.view.append(noSnapshot(null)); return; }
  ctx.view.append(
    walkthroughSection(data.walkthrough),
    lede(`${data.items.length} situations a reviewer can follow end to end in this synthetic company. Each links to the groups, applications, and lifecycle candidate involved.`),
    data.items.map((s) => section(`${s.number}. ${s.title}`,
      h("p", null, s.summary),
      h("p", { class: "muted" }, "Where to look: ", s.whatToLookAt),
      facts([
        ["Groups", s.groups.length ? h("ul", { class: "plain-list" }, s.groups.map((g) => h("li", null, groupRef(g), " ", healthBadge(g.health)))) : "—"],
        ["Applications", s.applications.length ? s.applications.map((a, i) => [i ? ", " : null, appLink(a.id, a.label)]) : "—"],
        ["Lifecycle candidate", s.candidateId ? candidateLink(s.candidateId, s.candidateKey) : "None"],
      ], s.title))));
}

// OGWA-DEMO-04: the guided reviewer walkthrough, the server's text. Its disclosures come first and
// are never folded away: all data is synthetic, nothing external is contacted, the drill's state is
// discarded, and its failures are scripted.
function walkthroughSection(guide) {
  if (!guide || !Array.isArray(guide.parts)) return null;
  return section(guide.title,
    h("p", { class: "lede" }, guide.summary),
    h("div", { class: "banner walkthrough-disclosures", "data-tone": "caution" },
      h("strong", null, "Before you start"),
      h("ul", { class: "plain-list" }, (guide.disclosures || []).map((d) => h("li", null, d)))),
    guide.parts.map((part) => h("div", { class: "walkthrough-part", "data-part": part.key },
      h("h3", null, part.title),
      h("p", null, part.candidateId ? candidateLink(part.candidateId, `Open ${part.candidateKey}`)
        : h("span", { class: "muted" }, `${part.candidateKey} is not in this store.`)),
      h("ol", { class: "walkthrough-steps" }, part.steps.map((step) => h("li", null, step.text,
        step.section ? h("span", { class: "muted" }, ` (section: ${step.section})`) : null))),
      h("p", null, h("strong", null, "Expected outcome: "), part.outcome))));
}
