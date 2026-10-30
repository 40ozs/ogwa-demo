// Pure presentation rules shared by the views (OGWA-UI-IA-01): employee status words, sorting
// and paging arithmetic, tab keys, hash addresses (and where old ones moved), time on the
// server's clock, and how a resolved identity is shown.
// No DOM here; tests/ui/present.test.mjs covers it under Node.

// --- employees ------------------------------------------------------------------------------

// The API keeps its contract (status TERMINATED, terminationDate). The UI says "Deactivated",
// never "Former" or "Terminated".
export const PERSON_STATUS_LABEL = Object.freeze({ ACTIVE: "Active", TERMINATED: "Deactivated" });
const EVENT_LABEL = Object.freeze({ TERMINATED: "Deactivated" });

export function personStatus(person) {
  const active = person.status === "ACTIVE";
  return {
    label: PERSON_STATUS_LABEL[person.status] || "Unknown",
    tone: active ? "neutral" : "caution",
    active,
    // A missing date stays missing: it is never inferred from anything else.
    deactivationDate: active ? null : (person.terminationDate || null),
  };
}

/**
 * Stored finding text (the governance rules' summaries) still says "former employee"; the words
 * shown say "deactivated employee". The stored record and the rule's code are unchanged.
 */
export function employeeTerms(text) {
  return typeof text === "string"
    ? text.replace(/\b(former|terminated) (employee)/gi, (_, w, e) => `${w[0] === w[0].toUpperCase() ? "D" : "d"}eactivated ${e}`)
    : text;
}

/** Words for an employment history event kind (HIRED, TERMINATED, OKTA_DEACTIVATED, ...). */
export function eventLabel(kind) {
  if (EVENT_LABEL[kind]) return EVENT_LABEL[kind];
  const text = String(kind).replace(/_/g, " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// --- sorting and paging -------------------------------------------------------------------

/** The sort after a column header is pressed: a new column starts ascending, the same one flips. */
export function nextSort(current, key) {
  if (current && current.key === key) return { key, dir: current.dir === "asc" ? "desc" : "asc" };
  return { key, dir: "asc" };
}

export function ariaSort(current, key) {
  if (!current || current.key !== key) return null;
  return current.dir === "desc" ? "descending" : "ascending";
}

function comparable(value) {
  return typeof value === "string" ? value.toLocaleLowerCase("en") : value;
}

/** A stable sort like the server's: ties keep their order, and empty values go last either way. */
export function sortRows(rows, valueOf, dir) {
  const present = [];
  const missing = [];
  rows.forEach((row, index) => {
    const value = valueOf(row);
    (value === null || value === undefined || value === "" ? missing : present).push({ row, index, value: comparable(value) });
  });
  const sign = dir === "desc" ? -1 : 1;
  present.sort((a, b) => (a.value < b.value ? -sign : a.value > b.value ? sign : a.index - b.index));
  return [...present, ...missing].map((x) => x.row);
}

/** Where a page sits in its listing: "51–100 of 298", and whether there is a page either side. */
export function pageWindow({ offset, count, total, hasNext }) {
  const from = count ? offset + 1 : 0;
  const to = offset + count;
  const known = typeof total === "number";
  return {
    from, to, total: known ? total : null,
    hasPrevious: offset > 0,
    hasNext: known ? to < total : Boolean(hasNext),
    // A cursor past the end (a stale link, or a filter that shrank the list) shows no rows.
    pastEnd: count === 0 && offset > 0,
    label: count ? `${from}–${to}${known ? ` of ${total}` : ""}` : (known ? `0 of ${total}` : "0"),
  };
}

/** A page number that still exists after the rows changed (0-based). */
export function clampPage(page, rowCount, pageSize) {
  const last = Math.max(0, Math.ceil(rowCount / pageSize) - 1);
  return Math.min(Math.max(0, page), last);
}

// --- tabs and addresses -------------------------------------------------------------------

export function activeTab(query, tabs, fallback) {
  return tabs.includes(query.tab) ? query.tab : fallback || tabs[0];
}

/** The tab index a key moves to (arrow keys wrap; Home and End jump), or null for other keys. */
export function tabKeyTarget(key, index, count) {
  if (key === "ArrowRight") return (index + 1) % count;
  if (key === "ArrowLeft") return (index - 1 + count) % count;
  if (key === "Home") return 0;
  if (key === "End") return count - 1;
  return null;
}

/** "#/route?a=1" from the current query with `changes` applied; null or "" removes a key. */
export function hashFor(route, query, changes) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...(query || {}), ...(changes || {}) })) {
    if (v !== null && v !== undefined && v !== "") params.set(k, String(v));
  }
  const q = params.toString();
  return `#${route}${q ? `?${q}` : ""}`;
}

/**
 * Where an address from before OGWA-UI-IA-01 or OGWA-UI-REVIEW-01 lives now, as [route, query],
 * or null when it has not moved. Filters, sorting, and the page are kept; only the page and its
 * tab change.
 */
export function movedRoute(path, query) {
  const q = { ...(query || {}) };
  switch (path) {
    case "/directory-groups": return ["/inventory/groups", { ...q, tab: "directory" }];
    case "/groups": return ["/inventory/groups", { ...q, tab: "okta" }];
    case "/applications": return ["/inventory/applications", { ...q, tab: "okta" }];
    case "/okta": return [q.tab === "groups" ? "/inventory/groups" : "/inventory/applications", { ...q, tab: "okta" }];
    case "/directory":
      return q.tab === "groups" || q.tab === "applications" ? [`/inventory/${q.tab}`, { ...q, tab: "directory" }] : null;
    case "/dependencies": return ["/findings", { ...q, tab: "dependency" }];
    // "Approvals and holds": its waiting work is now the Review queue, and its sorted or paged list of
    // recorded approvals and rejections is Decisions.
    case "/approvals": return q.sort || q.cursor ? ["/decisions", q] : ["/review", {}];
    default: return null;
  }
}

// --- time, always on the server's clock -----------------------------------------------------

const plural = (n, unit) => `${n} ${unit}${n === 1 ? "" : "s"}`;

/**
 * The time from `fromIso` to `toIso` in words ("3 days", "5 hours", "under an hour") and its
 * sign. Both instants come from the server (its clock is the demo clock in a demo); null when
 * either is missing, so the browser's clock is never used in its place.
 */
export function span(fromIso, toIso) {
  if (!fromIso || !toIso) return null;
  const ms = Date.parse(toIso) - Date.parse(fromIso);
  if (Number.isNaN(ms)) return null;
  const hours = Math.floor(Math.abs(ms) / 3600000);
  return { ms, text: hours < 1 ? "under an hour" : hours < 48 ? plural(hours, "hour") : plural(Math.floor(hours / 24), "day") };
}

/** A deadline against the server's clock: "2 days remaining" or "Ended 3 hours ago"; the caller shows the absolute time too. */
export function deadlineText(atIso, nowIso, endedWord) {
  const s = span(nowIso, atIso);
  if (!s) return null;
  return s.ms > 0 ? { past: false, text: `${s.text} remaining` } : { past: true, text: `${endedWord || "Ended"} ${s.text} ago` };
}

// --- identities ---------------------------------------------------------------------------

export const KIND_TEXT = Object.freeze({ AD_GROUP: "AD group", DIRECTORY_GROUP: "Directory group", OKTA_GROUP: "Okta group",
  OKTA_APPLICATION: "Okta application", PERSON: "Person", CANDIDATE: "Lifecycle candidate" });

/**
 * How one id is shown, from its GET /identities entry: the common name links to the object's
 * canonical page, and the raw id stays available (title). The qualifier (an AD distinguished
 * name, an Okta group id) is shown when the name is shared or might be. An id that did not
 * resolve is shown as itself and said to be unresolved, never hidden.
 */
export function refView(entry, id) {
  if (!entry || !entry.resolved || !entry.name) {
    return { text: id, href: null, qualifier: null, unresolved: true, title: id, kind: entry && entry.kind };
  }
  const extra = [id, entry.sid].filter(Boolean).join(" · ");
  return {
    text: entry.name,
    href: entry.route ? `#/${entry.route}/${entry.routeId}` : null,
    qualifier: entry.ambiguous === false ? null : (entry.qualifier || null),
    unresolved: false,
    title: extra,
    kind: entry.kind,
  };
}

/** A directory snapshot group reference (from the directory API) as a resolver entry. */
export function snapshotEntry(group) {
  if (!group) return null;
  return { kind: group.source === "AD" ? "AD_GROUP" : "DIRECTORY_GROUP", resolved: true, name: group.name,
    route: "directory-groups", routeId: group.id, qualifier: group.qualifier, ambiguous: group.ambiguous };
}

/** The distinct, non-empty values of `fields` across `rows`, for one GET /identities call. */
export function collectIds(rows, ...fields) {
  const out = new Set();
  for (const row of rows) {
    for (const field of fields) {
      const value = typeof field === "function" ? field(row) : row[field];
      for (const v of [].concat(value || [])) if (v) out.add(v);
    }
  }
  return [...out];
}
