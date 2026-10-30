// The dashboard answers "what needs attention now?" first (OGWA-UI-REVIEW-01): what waits for a
// decision, what is blocked, evidence and collection problems, holds near their end, and the
// head of the review queue. Then key figures and small charts. Each number links to the
// filtered Review queue or the list that explains it. The technical posture (policy, store,
// audit head) is kept, folded away under "System details".
import { get } from "../api.js";
import { stateInfo } from "../assess.js";
import { badge, facts, fmtTime, h, humanize, link, mono, section, svg, table, uid } from "../dom.js";
import { collectIds, hashFor, refView, span } from "../present.js";
import { nextStep, OPEN_STATUSES, reviewStatus } from "../review.js";
import { resolveRefs } from "./common.js";
import { loadQueue, queueTable } from "./review.js";

const STATE_ORDER = ["DISCOVERED", "CANDIDATE", "NEEDS_REVIEW", "APPROVED", "OKTA_UNASSIGN_DRY_RUN", "HOLD",
  "REVALIDATION_REQUIRED", "QUARANTINE_APPROVED", "QUARANTINE_DRY_RUN", "QUARANTINE_HOLD", "DELETION_REVALIDATION_REQUIRED",
  "DELETION_PROPOSED", "DELETION_APPROVED", "DELETION_DRY_RUN", "RETIREMENT_DRY_RUN", "BLOCKED", "MAPPING_AMBIGUOUS",
  "DEPENDENCY_BLOCKED", "STALE_EVIDENCE", "EVIDENCE_INCOMPLETE", "PROTECTED", "EXCLUDED", "REJECTED", "RETIRED"];

const EVIDENCE_LABEL = { applications: "Okta applications", oktaGroups: "Okta groups", adGroups: "AD groups",
  mappings: "Identity mappings", dependencyChecks: "Dependency checks" };

const count = (n) => Number(n || 0).toLocaleString("en-US");
const sum = (values) => values.reduce((a, b) => a + (b || 0), 0);

export async function dashboard(ctx) {
  ctx.setTitle("Dashboard");
  const [data, directory, governance] = await Promise.all([
    get("/dashboard"), get("/directory"), get("/governance-findings", { limit: 1 })]);
  const dir = directory.available ? directory : null;
  const bySeverity = Object.fromEntries(Object.entries(governance.counts || {}).map(([s, codes]) => [s, sum(Object.values(codes))]));
  const deps = data.dependencyFindings || {};
  const governanceTotal = sum(Object.values(bySeverity));
  const health = dir ? dir.counts.groupHealth || {} : {};
  const findingsLink = (severity) => hashFor("/findings", {}, { tab: "governance", severity });
  const groupsLink = (value) => hashFor("/inventory/groups", {}, { tab: "directory", health: value });
  const queue = await loadQueue(data);
  const preview = queue.items.filter((c) => OPEN_STATUSES.includes(reviewStatus(c.state).key)).slice(0, 5);
  const refs = await resolveRefs(collectIds(preview, "oktaGroupId"));

  ctx.view.append(
    // OGWA-DEMO-04: the demo's entry point. Only a store with the synthetic company directory has
    // the walkthrough's candidates.
    dir ? h("p", { class: "lede walkthrough-entry" }, "New to this demo? ",
      link("#/scenarios", "Start the five-minute reviewer walkthrough"),
      `: evidence quality on ${walkthroughKey(dir, 10)}, then a verified synthetic remediation on ${walkthroughKey(dir, 11)}. ` +
      "All data is synthetic.") : null,
    attention(data, queue, dir, bySeverity, deps),
    section("Review queue",
      queueTable("Next in the review queue", preview, refs, queue.now, "Nothing is waiting for review, blocked, or in progress."),
      h("p", null, link("#/review", "Open the review queue"))),
    findForm(),
    section("Key figures", keyFigures(data, dir, bySeverity, governanceTotal, deps)),
    h("div", { class: "chart-grid" },
      governanceTotal ? section("Governance findings by severity",
        barList("Governance findings by severity", [
          { label: "Actionable", value: bySeverity.ACTIONABLE, tone: "blocked", href: findingsLink("ACTIONABLE") },
          { label: "Worth a look", value: bySeverity.QUESTIONABLE, tone: "caution", href: findingsLink("QUESTIONABLE") },
          { label: "Context", value: bySeverity.INFO, tone: "info", href: findingsLink("INFO") },
        ])) : null,
      dir ? section("Group health",
        barList("Directory groups by their most serious finding", [
          { label: "Actionable", value: health.ACTIONABLE, tone: "blocked", href: groupsLink("ACTIONABLE") },
          { label: "Worth a look", value: health.QUESTIONABLE, tone: "caution", href: groupsLink("QUESTIONABLE") },
          { label: "No findings", value: health.CLEAN, tone: "neutral", href: groupsLink("CLEAN") },
        ])) : null,
      dir && dir.deactivations ? section("Deactivations per year", deactivationChart(dir.deactivations)) : null),
    dir ? null : h("p", { class: "muted" }, "This store has no company directory snapshot, so people, departments, and governance findings are not shown."),
    systemDetails(data));
  return data;
}

// --- key figures ------------------------------------------------------------------------------

// The walkthrough's two candidates (OGWA-DEMO-04) in the store's dataset: GP-C10 and GP-C11 for Genesee
// Press (the default demo), NM-C10 and NM-C11 for the legacy Null Meridian dataset.
function walkthroughKey(dir, n) {
  const prefix = dir.snapshot && dir.snapshot.dataset === "null-meridian" ? "NM-C" : "GP-C";
  return `${prefix}${n}`;
}

function keyFigures(data, dir, bySeverity, governanceTotal, deps) {
  const ev = data.evidence || {};
  const tiles = [];
  if (dir) {
    tiles.push(
      ["Active employees", dir.counts.activeEmployees, hashFor("/people", {}, { status: "ACTIVE" })],
      ["Deactivated employees", dir.counts.formerEmployees, hashFor("/people", {}, { status: "TERMINATED", sort: "terminationDate", order: "desc" })],
      ["Departments", dir.departments.length, "#/directory"]);
  }
  tiles.push(
    ["AD groups", ev.adGroups, dir ? hashFor("/inventory/groups", {}, { tab: "directory", source: "AD" }) : "#/mappings"],
    ["Okta groups", ev.oktaGroups, hashFor("/inventory/groups", {}, { tab: "okta" })],
    ["Okta applications", ev.applications, hashFor("/inventory/applications", {}, { tab: "okta" })],
    ["Open findings", governanceTotal + (deps.findings || 0), hashFor("/findings", {}, { tab: governanceTotal ? "governance" : "dependency" }),
      `${count(governanceTotal)} governance · ${count(deps.findings)} dependency`],
    ["Actionable or blocking", (bySeverity.ACTIONABLE || 0) + (deps.blocking || 0), hashFor("/findings", {}, { tab: "governance", severity: "ACTIONABLE" }),
      `${count(bySeverity.ACTIONABLE)} actionable · ${count(deps.blocking)} blocking`]);
  return h("ul", { class: "kpis", "aria-label": "Key figures" }, tiles.map(([label, value, href, detail]) => h("li", null,
    h("a", { class: "kpi", href }, h("span", { class: "kpi-value" }, count(value)), h("span", { class: "kpi-label" }, label),
      detail ? h("span", { class: "kpi-detail" }, detail) : null))));
}

// --- what deserves attention ------------------------------------------------------------------

const DAY = 86400000;
const review = (status) => hashFor("/review", {}, { status });
const cands = (n) => (n === 1 ? "candidate" : "candidates");

function attention(data, queue, dir, bySeverity, deps) {
  const byState = data.candidatesByState || {};
  const collectors = data.collectors || {};
  const recent = dir && dir.deactivations;
  // Holds that ended or end within 7 days, on the server's clock; none are counted without it.
  const holds = queue.now ? queue.items.filter((c) => {
    const d = nextStep(c, queue.now).deadline;
    const s = d && span(queue.now, d.at);
    return s && s.ms <= 7 * DAY;
  }).length : 0;
  const evidence = (byState.STALE_EVIDENCE || 0) + (byState.EVIDENCE_INCOMPLETE || 0);
  const items = [
    [queue.counts["needs-review"], "caution", "Decision", `${cands(queue.counts["needs-review"])} waiting for a person's decision`, review("needs-review")],
    [queue.counts.blocked, "blocked", "Blocked", `${cands(queue.counts.blocked)} blocked`, review("blocked")],
    [evidence, "blocked", "Evidence", `${cands(evidence)} blocked on stale or incomplete evidence`, review("blocked")],
    [(collectors.incomplete || 0) + (collectors.unfinished || 0), "blocked", "Collection", "collector runs incomplete or unfinished", "#/collectors"],
    [holds, "caution", "Hold", `holds ended or ending within 7 days${queue.truncated ? ` (among the first ${count(queue.items.length)} candidates)` : ""}`, review("waiting")],
    [queue.counts["in-progress"], "caution", "Dry run", `${cands(queue.counts["in-progress"])} approved for a future step (dry run only)`, review("in-progress")],
    [bySeverity.ACTIONABLE, "blocked", "Actionable", "actionable governance findings", hashFor("/findings", {}, { tab: "governance", severity: "ACTIONABLE" })],
    [deps.blocking, "blocked", "Blocking", "blocking dependency findings", hashFor("/findings", {}, { tab: "dependency", sort: "findings", order: "desc" })],
    [recent ? recent.last90Days : 0, "info", "Recent", `people deactivated in the 90 days to ${recent ? recent.asOf : ""}`,
      hashFor("/people", {}, { status: "TERMINATED", sort: "terminationDate", order: "desc" })],
  ].filter(([n]) => n);
  return section("Needs attention",
    items.length ? h("ul", { class: "attention" }, items.map(([n, tone, tag, text, href]) => h("li", null,
      badge(tag, tone), " ", link(href, `${count(n)} ${text}`))))
      : h("p", { class: "muted" }, "No waiting decision, blocked candidate, hold, actionable finding, or collector problem is recorded."));
}

// --- find ------------------------------------------------------------------------------------------

/**
 * Open one object by its stable id (GET /identities: OGWA ids and AD objectSids), or search people
 * and groups by name on the server. Nothing is matched by name in the browser.
 */
function findForm() {
  const id = uid("find");
  const hint = uid("find-hint");
  const input = h("input", { type: "text", id, maxlength: "100", autocomplete: "off", "aria-describedby": hint });
  const result = h("div", { "aria-live": "polite" });
  const form = h("form", { class: "filters", role: "search", "aria-label": "Find an object", on: { submit: async (event) => {
    event.preventDefault();
    const value = input.value.trim();
    if (!value) return;
    const view = refView((await resolveRefs([value]))[value], value);
    if (view.href) { location.hash = view.href; return; }
    result.replaceChildren(h("p", null, `No object has the id "${value}". Search by name on the server: `,
      link(hashFor("/people", {}, { q: value }), "People"), " · ",
      link(hashFor("/inventory/groups", {}, { tab: "directory", q: value }), "Directory groups")));
  } } },
  h("div", { class: "field" }, h("label", { for: id }, "Find by id"),
    h("span", { class: "hint", id: hint }, "An OGWA id (person, group, application, candidate) or an AD objectSid."), input),
  h("button", { type: "submit" }, "Open"));
  return section("Find", form, result);
}

// --- charts -------------------------------------------------------------------------------------

/** A bar's outline: square at the baseline, a 4-unit rounded data end. */
function barPath(width, height, radius) {
  const r = Math.min(radius, width, height / 2);
  return `M0,0H${width - r}A${r},${r} 0 0 1 ${width},${r}V${height - r}A${r},${r} 0 0 1 ${width - r},${height}H0Z`;
}

/**
 * Horizontal bars, one per class, each a link to the list it counts. Every bar carries its label
 * and value as text, so the tone's colour is never the only cue, and the list is its own text
 * equivalent.
 */
function barList(label, rows) {
  const max = Math.max(1, ...rows.map((r) => r.value || 0));
  return h("ul", { class: "bars", "aria-label": label }, rows.map((r) => {
    const width = Math.round((400 * (r.value || 0)) / max);
    return h("li", null, h("a", { class: "bar-row", href: r.href, title: `${r.label}: ${count(r.value)}. Open the list.` },
      h("span", { class: "bar-label" }, r.label),
      svg("svg", { class: "bar-track", viewBox: "0 0 400 14", preserveAspectRatio: "none", "aria-hidden": "true", focusable: "false" },
        width ? svg("path", { class: "bar-fill", "data-tone": r.tone, d: barPath(width, 14, 4) }) : null),
      h("span", { class: "bar-value" }, count(r.value))));
  }));
}

/** Deactivations per year: one series, so one colour and no legend; a table holds every value. */
function deactivationChart(deactivations) {
  const years = Object.keys(deactivations.byYear);
  if (!years.length) return h("p", { class: "muted" }, "No deactivations are recorded.");
  const values = years.map((y) => deactivations.byYear[y]);
  const max = Math.max(...values);
  const peak = values.indexOf(max);
  const width = 440;
  const base = 120;
  const slot = width / years.length;
  const bar = Math.min(24, slot - 6);
  const marks = years.map((year, i) => {
    const height = Math.max(1, Math.round((100 * values[i]) / max));
    const x = i * slot + (slot - bar) / 2;
    const r = Math.min(4, height, bar / 2);
    const top = base - height;
    return svg("g", null,
      svg("title", null, `${year}: ${count(values[i])} deactivated`),
      svg("path", { class: "column", d: `M${x},${base}V${top + r}A${r},${r} 0 0 1 ${x + r},${top}H${x + bar - r}A${r},${r} 0 0 1 ${x + bar},${top + r}V${base}Z` }),
      i === peak || i === years.length - 1
        ? svg("text", { class: "chart-value", x: x + bar / 2, y: top - 5, "text-anchor": "middle" }, count(values[i])) : null,
      svg("text", { class: "chart-axis", x: x + bar / 2, y: base + 16, "text-anchor": "middle" }, year));
  });
  return [
    svg("svg", { class: "columns", viewBox: `0 0 ${width} 140`, role: "img",
      "aria-label": `Deactivations per year, ${years[0]} to ${years[years.length - 1]}; the most, ${count(max)}, in ${years[peak]}. The table below lists every year.` },
    svg("line", { class: "chart-baseline", x1: 0, x2: width, y1: base, y2: base }), marks),
    h("details", { class: "chart-table" }, h("summary", null, "Show as a table"),
      table("Deactivations per year", [
        { label: "Year", rowHeader: true, render: (y) => y },
        { label: "Deactivated", num: true, render: (y) => count(deactivations.byYear[y]) },
      ], years)),
  ];
}

// --- the technical posture, folded away --------------------------------------------------------

function systemDetails(data) {
  const safety = data.safety || {};
  const counts = data.candidatesByState || {};
  const states = STATE_ORDER.filter((s) => counts[s]).concat(Object.keys(counts).filter((s) => !STATE_ORDER.includes(s)));
  const collectors = data.collectors || {};
  return h("details", { class: "profile system-details" },
    h("summary", null, "System details: safety posture, lifecycle candidates, evidence, policy, and store"),
    h("div", { class: "cards" },
      h("div", { class: "card" }, h("h2", null, "Safety posture"), facts([
        ["Execution mode", mono(safety.executionMode)],
        ["External changes", safety.externalMutation || "—"],
        ["Production changes allowed by this build", safety.productionMutationPermittedByBuild ? "Yes" : "No"],
        ["Execution routes", humanize(safety.executionRoutes)],
      ], "Safety posture")),
      h("div", { class: "card" }, h("h2", null, "Waiting for approval"), facts([
        ["Okta unassignment (needs review)", String((data.awaitingApproval || {}).OKTA_UNASSIGN || 0)],
        ["AD quarantine (revalidation required)", String((data.awaitingApproval || {}).AD_QUARANTINE || 0)],
        ["AD deletion (deletion proposed)", String((data.awaitingApproval || {}).AD_DELETION || 0)],
      ], "Waiting for approval"), h("p", null, link(hashFor("/review", {}, { status: "needs-review" }), "Review queue: needs review"))),
      h("div", { class: "card" }, h("h2", null, "Collection health"), facts([
        ["Runs recorded", String(collectors.runs || 0)],
        ["Incomplete", String(collectors.incomplete || 0)],
        ["Unfinished", String(collectors.unfinished || 0)],
      ], "Collection health"), h("p", null, link("#/collectors", "Collection health")))),
    section("Candidates by state",
      table("Candidates by lifecycle state", [
        { label: "State", rowHeader: true, render: (s) => link(`#/candidates?state=${encodeURIComponent(s)}`, stateInfo(s).label), sort: (s) => stateInfo(s).label },
        { label: "Meaning", render: (s) => stateInfo(s).text },
        { label: "Count", num: true, render: (s) => String(counts[s]), sort: (s) => counts[s] },
      ], states, "No candidates are recorded.")),
    section("Evidence held",
      facts(Object.entries(data.evidence || {}).map(([k, v]) => [EVIDENCE_LABEL[k] || humanize(k), String(v)]), "Evidence held")),
    section("Policy and store",
      facts([
        ["Policy in force", data.policy && data.policy.label ? [data.policy.name ? [h("strong", null, data.policy.name), " "] : null,
          badge(data.policy.label, data.policy.recorded ? "info" : "caution")]
          : badge(`Unavailable: ${(data.policy || {}).unavailable || "unknown"}`, "blocked")],
        ["Policy digest", mono((data.policy || {}).policyDigest)],
        ["Store environment", mono((data.store || {}).environment)],
        ["Audit events", String((data.store || {}).auditEvents ?? "—")],
        ["Audit head", mono((data.store || {}).auditHead)],
        ["Generated at (server clock)", fmtTime(data.generatedAt)],
      ], "Policy and store"),
      h("p", { class: "muted" }, "Compare the audit head with the recorded anchor in docs/operations/audit-anchors.md.")));
}
