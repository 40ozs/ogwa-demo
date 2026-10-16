import { ariaSort, clampPage, nextSort, pageWindow, sortRows } from "./present.js";

// Safe DOM construction. Every string becomes a text node; there is no HTML-string path.
// The page's Content-Security-Policy also enforces Trusted Types, so an HTML sink such as
// innerHTML would throw even if one were added by mistake.

/**
 * h("p", {class: "x", on: {click: fn}}, "text", child, [more])
 * Attributes: class, id, for, hidden, disabled, required, checked, value, data-*, aria-*,
 * and other plain attributes. Event handlers go in `on`.
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "on") {
      for (const [event, handler] of Object.entries(value)) el.addEventListener(event, handler);
    } else if (name === "class") {
      el.className = value;
    } else if (name === "for") {
      el.htmlFor = value;
    } else if (name === "value") {
      el.value = value;
    } else if (name === "checked") {
      el.checked = Boolean(value);
    } else if (/^on/i.test(name)) {
      throw new Error("event handlers go in the `on` attribute");
    } else if (value === true) {
      el.setAttribute(name, "");
    } else {
      el.setAttribute(name, String(value));
    }
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

let uniqueCounter = 0;
export function uid(prefix) {
  uniqueCounter += 1;
  return `${prefix}-${uniqueCounter}`;
}

// --- formatting ---------------------------------------------------------------------------

export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toISOString().replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
}

/** Age of `iso` relative to the server's clock `nowIso`, in words ("3 days"). */
export function age(iso, nowIso) {
  if (!iso || !nowIso) return "";
  const ms = new Date(nowIso).getTime() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return "";
  if (ms < 0) return "in the future";
  const hours = ms / 3600000;
  if (hours < 1) return "under an hour";
  if (hours < 48) return `${Math.floor(hours)} hours`;
  return `${Math.floor(hours / 24)} days`;
}

export function actorText(actor) {
  if (!actor) return "—";
  const kind = { HUMAN: "person", SYSTEM: "system" }[actor.kind] || String(actor.kind).toLowerCase();
  return `${actor.id} (${kind})`;
}

export function humanize(code) {
  if (code === null || code === undefined) return "—";
  const text = String(code).replace(/_/g, " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function yesNo(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "Unknown";
}

// --- building blocks ----------------------------------------------------------------------

export function badge(text, tone) {
  return h("span", { class: "badge", "data-tone": tone || "neutral" }, text);
}

export function mono(text) {
  return h("span", { class: "mono" }, text === null || text === undefined ? "—" : String(text));
}

export function link(href, text) {
  return h("a", { href }, text);
}

/** A labelled definition list: rows are [term, value] pairs (value: string, Node, or array). */
export function facts(rows, label) {
  const dl = h("dl", { class: "facts", "aria-label": label || null });
  for (const [term, value] of rows) {
    if (value === undefined) continue;
    dl.append(h("dt", null, term), h("dd", null, value === null ? "—" : value));
  }
  return dl;
}

/**
 * Which control gets focus after the next re-render (a tab, a sort header, a pager control),
 * instead of the page heading. Set just before navigating; main.js consumes it.
 */
export const focusAfterRoute = { key: null };

const PAGE_SIZE = 25;

function sortHeader(column, sort, onSort, focusKey) {
  const state = ariaSort(sort, column.sortKey);
  return h("th", { scope: "col", class: column.num ? "num" : null, "aria-sort": state },
    h("button", { type: "button", class: "sort", "data-focus-key": focusKey, on: { click: () => onSort(column.sortKey) } },
      column.label,
      h("span", { class: "sort-indicator", "aria-hidden": "true" }, state === "ascending" ? "▲" : state === "descending" ? "▼" : "↕")));
}

function pagerButton(label, enabled, focusKey, go) {
  // aria-disabled rather than disabled: the control keeps focus when it reaches the last page.
  return h("button", { type: "button", "aria-disabled": enabled ? null : "true", "data-focus-key": focusKey,
    on: { click: () => { if (enabled) go(); } } }, label);
}

/**
 * A semantic table in a keyboard-scrollable region.
 * columns: [{label, render: row => string|Node, num?, rowHeader?, sort?}]
 *
 * `sort` makes a column sortable. A function (row => value) sorts the rows held here, and more
 * than 25 rows are paged here too. A string sorts on the server: `opts.server` is
 * {sort: {key, dir} | null, onSort(key)}, and the listing's pager is the caller's.
 */
export function table(caption, columns, rows, emptyText, opts) {
  if (!rows.length) {
    return h("p", { class: "muted" }, emptyText || `${caption}: none.`);
  }
  const captionId = uid("caption");
  const server = (opts && opts.server) || null;
  const cols = columns.map((c) => ({ ...c, sortKey: c.sort ? (typeof c.sort === "string" ? c.sort : c.label) : null }));
  const local = { sort: null, page: 0 };
  const paged = !server && rows.length > PAGE_SIZE;
  const holder = h("div", { class: "data-table" });
  // A server-sorted table is rebuilt by the route, so its focus keys must not depend on uid().
  const keyPrefix = server ? caption : captionId;

  function render(focusKey) {
    let view = rows;
    if (!server && local.sort) {
      const column = cols.find((c) => c.sortKey === local.sort.key);
      view = sortRows(rows, column.sort, local.sort.dir);
    }
    const page = paged ? clampPage(local.page, view.length, PAGE_SIZE) : 0;
    if (paged) view = view.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    const sort = server ? server.sort : local.sort;
    const onSort = server ? server.onSort : (key) => { local.sort = nextSort(local.sort, key); local.page = 0; render(`${keyPrefix}:${key}`); };
    const head = h("tr", null, cols.map((c) => (c.sortKey ? sortHeader(c, sort, onSort, `${keyPrefix}:${c.sortKey}`)
      : h("th", { scope: "col", class: c.num ? "num" : null }, c.label))));
    const body = view.map((row) => h("tr", null, cols.map((c) => {
      const value = c.render(row);
      const cell = c.rowHeader ? "th" : "td";
      return h(cell, { scope: c.rowHeader ? "row" : null, class: c.num ? "num" : null },
        value === null || value === undefined || value === "" ? "—" : value);
    })));
    const win = pageWindow({ offset: page * PAGE_SIZE, count: view.length, total: rows.length });
    holder.replaceChildren();
    append(holder, [
      h("div", { class: "table-wrap", role: "region", "aria-labelledby": captionId, tabindex: "0" },
        h("table", null, h("caption", { id: captionId }, caption), h("thead", null, head), h("tbody", null, body))),
      paged ? h("nav", { class: "pager", "aria-label": `${caption}: pages` },
        pagerButton("Previous page", win.hasPrevious, `${captionId}:prev`, () => { local.page = page - 1; render(`${captionId}:prev`); }),
        h("span", { class: "pager-status" }, `Rows ${win.label}`),
        pagerButton("Next page", win.hasNext, `${captionId}:next`, () => { local.page = page + 1; render(`${captionId}:next`); }))
        : null]);
    if (focusKey) {
      const target = holder.querySelector(`[data-focus-key="${focusKey}"]`);
      if (target) target.focus();
    }
  }
  render(null);
  return holder;
}

// --- inline SVG (charts and icons) --------------------------------------------------------

const SVG_NS = "http://www.w3.org/2000/svg";

/** svg("rect", {x: 0, width: 10}): an SVG element with plain attributes (no style). */
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (/^on|^style$/i.test(name)) throw new Error("no handlers or inline style on SVG");
    el.setAttribute(name, String(value));
  }
  append(el, children);
  return el;
}

export function banner(tone, headline, detail) {
  return h("div", { class: "banner", "data-tone": tone },
    h("strong", null, headline), detail ? h("p", null, detail) : null);
}

export function section(title, ...children) {
  const id = uid("section");
  return h("section", { "aria-labelledby": id }, h("h2", { id }, title), children);
}
