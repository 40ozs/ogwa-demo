import { get } from "../api.js";
import { errorText } from "../assess.js";
import { badge, focusAfterRoute, h, link, table } from "../dom.js";
import { hashFor, nextSort, pageWindow, refView, snapshotEntry, tabKeyTarget } from "../present.js";

/** A refusal or failure, explained. role=alert so it is announced when it appears. */
export function errorBox(error, extra) {
  const problems = (error && error.problems) || [];
  return h("div", { class: "banner form-error", "data-tone": "blocked", role: "alert" },
    h("strong", null, errorText(error && error.code, error && error.message)),
    error && error.message && errorText(error.code, null) !== error.message ? h("p", null, error.message) : null,
    problems.length ? h("ul", { class: "plain-list" }, problems.map((p) => h("li", null, p))) : null,
    error && error.auditEventId ? h("p", null, "This refusal was recorded in the audit trail as ",
      h("span", { class: "mono" }, error.auditEventId), ".") : null,
    error && error.requestId ? h("p", { class: "muted" }, "Request id: ", h("span", { class: "mono" }, error.requestId)) : null,
    extra || null);
}

/** Navigate to `hash`, then give focus back to the control `focusKey` names. */
export function go(hash, focusKey) {
  focusAfterRoute.key = focusKey || null;
  location.hash = hash;
}

function pagerLink(text, hash, focusKey) {
  return h("a", { href: hash, "data-focus-key": focusKey, on: { click: () => { focusAfterRoute.key = focusKey; } } }, text);
}

/**
 * Pages of a cursor-paged listing: "Previous page", "Rows 51–100 of 298", "Next page" (cursors
 * are opaque). A cursor past the end (a stale link) offers the first page instead.
 */
export function pager(route, page, params) {
  if (!page) return null;
  const query = { ...(params || {}) };
  const win = pageWindow({ offset: page.offset || 0, count: page.count || 0, total: page.total,
    hasNext: Boolean(page.nextCursor) });
  if (win.pastEnd) {
    return h("nav", { class: "pager", "aria-label": "Pages" }, h("span", null, "This page is past the end of the list. "),
      pagerLink("First page", hashFor(route, query, { cursor: null }), "pager:first"));
  }
  if (!win.hasPrevious && !win.hasNext) {
    return win.total ? h("p", { class: "pager pager-status muted" }, `Rows ${win.label}`) : null;
  }
  return h("nav", { class: "pager", "aria-label": "Pages" },
    win.hasPrevious ? pagerLink("Previous page", hashFor(route, query, { cursor: page.previousCursor }), "pager:prev") : null,
    h("span", { class: "pager-status" }, `Rows ${win.label}`),
    win.hasNext ? pagerLink("Next page", hashFor(route, query, { cursor: page.nextCursor }), "pager:next") : null);
}

/** The listing's sort from the route query, or its default. */
export function sortFrom(query, fallback) {
  if (query.sort) return { key: query.sort, dir: query.order === "desc" ? "desc" : "asc" };
  return fallback || null;
}

/** The page and sort parameters a listing passes to the API (limit, cursor, sort, order). */
export function pageParams(query, extra, defaultSort) {
  const params = { limit: 50, ...(extra || {}) };
  if (query.cursor) params.cursor = query.cursor;
  const sort = sortFrom(query, defaultSort);
  if (sort) { params.sort = sort.key; params.order = sort.dir; }
  return params;
}

/**
 * A server-paged, server-sorted listing: a table whose sortable columns name the API's `sort`
 * field, then its pager. Sorting returns to the first page; filters and the tab are kept.
 */
export function listing(route, query, data, caption, columns, emptyText, defaultSort) {
  const sort = sortFrom(query, defaultSort);
  const onSort = (key) => {
    const next = nextSort(sort, key);
    go(hashFor(route, query, { sort: next.key, order: next.dir, cursor: null }), `${caption}:${key}`);
  };
  return [table(caption, columns, data.items, emptyText, { server: { sort, onSort } }),
    pager(route, { ...data.page, count: data.items.length }, query)];
}

/**
 * Tabs that are addresses (`?tab=`): switching is a hash change, so it never reloads the
 * document, and Back and Forward move between tabs. Arrow keys, Home, and End move between
 * tabs; Enter or Space opens one.
 */
export function tabs(route, label, items, active, ...panel) {
  const buttons = items.map(({ id, text }) => h("button", {
    type: "button", role: "tab", id: `tab-${id}`, "aria-selected": id === active ? "true" : "false",
    "aria-controls": "tab-panel", tabindex: id === active ? "0" : "-1", "data-focus-key": `tab-${id}`,
    on: { click: () => { if (id !== active) go(hashFor(route, {}, { tab: id }), `tab-${id}`); } },
  }, text));
  const list = h("div", { role: "tablist", "aria-label": label, class: "tabs", on: { keydown: (event) => {
    const index = buttons.indexOf(document.activeElement);
    const target = index < 0 ? null : tabKeyTarget(event.key, index, buttons.length);
    if (target === null) return;
    event.preventDefault();
    buttons[target].focus();
  } } }, buttons);
  return [list, h("div", { role: "tabpanel", id: "tab-panel", "aria-labelledby": `tab-${active}`, tabindex: "0",
    class: "tab-panel" }, panel)];
}

export function lede(text) {
  return h("p", { class: "lede" }, text);
}

// --- identities -----------------------------------------------------------------------------

// The ids GET /identities accepts: OGWA ids and AD domain objectSids.
const RESOLVABLE = /^(?:[a-z]{2,6}_[0-9a-f]{32}|S-1-5-21(?:-[0-9]{1,10}){4})$/;

/**
 * GET /identities for the ids a view shows: { id: entry }. Batches of 40 keep each query under
 * the API's 2,048-character limit (an id is ~40 characters once its comma is encoded).
 */
export async function resolveRefs(ids) {
  const unique = [...new Set(ids.filter((id) => RESOLVABLE.test(id || "")))];
  const batches = [];
  for (let i = 0; i < unique.length; i += 40) batches.push(unique.slice(i, i + 40));
  const results = await Promise.all(batches.map((batch) => get("/identities", { ids: batch.join(",") })));
  return Object.assign({}, ...results.map((r) => r.items));
}

/**
 * One identity, by its stable id: the common name, linked to its canonical page, with the raw
 * id as its tooltip; a qualifier line when the name is shared; the raw id when unresolved.
 */
export function identity(entry, id) {
  const v = refView(entry, id);
  if (v.unresolved) {
    return h("span", { class: "ref" }, h("span", { class: "mono" }, id), " ", badge("Not resolved", "neutral"));
  }
  const name = v.href ? h("a", { href: v.href, title: v.title }, v.text) : h("span", { title: v.title }, v.text);
  return h("span", { class: "ref" }, name, v.qualifier ? h("span", { class: "ref-qualifier mono" }, v.qualifier) : null);
}

/** A directory snapshot group (as the directory API returns it), shown like any identity. */
export function groupRef(group) {
  return group ? identity(snapshotEntry(group), group.id) : "—";
}

/**
 * An access path, in order: an ordered list, so a screen reader hears each step's position, and
 * the separators are drawn by CSS, never part of a link.
 */
export function chain(nodes, label) {
  return h("ol", { class: "chain", "aria-label": label || "Access path" }, nodes.map((n) => h("li", null, n)));
}

export function candidateLink(id, text) {
  return link(`#/candidates/${id}`, text || id);
}

export function groupLink(id, text) {
  return link(`#/groups/${id}`, text || id);
}

export function appLink(id, text) {
  return link(`#/applications/${id}`, text || id);
}

export function mappingLink(groupId, text) {
  return link(`#/mappings/${groupId}`, text || groupId);
}

export function jobLink(id, text) {
  return link(`#/jobs/${id}`, text || id);
}
