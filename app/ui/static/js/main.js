// The console shell: session, navigation, and focus management.
import * as api from "./api.js";
import { append, banner, focusAfterRoute, h } from "./dom.js";
import { candidate } from "./views/candidate.js";
import { candidates } from "./views/candidates.js";
import { demoIndicator } from "./runtime.js";
import { errorBox } from "./views/common.js";
import { dashboard } from "./views/dashboard.js";
import { directory, directoryGroup, people, person, scenarios } from "./views/directory.js";
import { findings } from "./views/findings.js";
import { approvals, audit, job, jobs } from "./views/governance.js";
import { application, collectors, group, mapping, mappings, okta } from "./views/inventory.js";
import { signin } from "./views/signin.js";

const ID = "(?<id>[a-z]+_[0-9a-f]{32})";

// [path, view, the navigation entry it belongs to]. Detail pages light up their section.
const ROUTES = [
  [/^\/$/, dashboard, "/"],
  [/^\/people$/, people, "/people"],
  [new RegExp(`^/people/${ID}$`), person, "/people"],
  [/^\/directory$/, directory, "/directory"],
  [new RegExp(`^/directory-groups/${ID}$`), directoryGroup, "/directory"],
  [/^\/okta$/, okta, "/okta"],
  [new RegExp(`^/applications/${ID}$`), application, "/okta"],
  [new RegExp(`^/groups/${ID}$`), group, "/okta"],
  [/^\/mappings$/, mappings, "/mappings"],
  [new RegExp(`^/mappings/${ID}$`), mapping, "/mappings"],
  [/^\/findings$/, findings, "/findings"],
  [/^\/candidates$/, candidates, "/candidates"],
  [new RegExp(`^/candidates/${ID}$`), candidate, "/candidates"],
  [/^\/approvals$/, approvals, "/approvals"],
  [/^\/scenarios$/, scenarios, "/scenarios"],
  [/^\/jobs$/, jobs, "/jobs"],
  [new RegExp(`^/jobs/${ID}$`), job, "/jobs"],
  [/^\/collectors$/, collectors, "/collectors"],
  [/^\/audit$/, audit, "/audit"],
];

// Pages that became tabs. Old links and bookmarks still arrive: the address is
// replaced, so Back does not bounce through it, and its filters are kept.
const MOVED = new Map([
  ["/directory-groups", ["/directory", "groups"]],
  ["/applications", ["/okta", "applications"]],
  ["/groups", ["/okta", "groups"]],
  ["/dependencies", ["/findings", "dependency"]],
]);

const el = {
  main: document.getElementById("main"),
  title: document.getElementById("page-title"),
  view: document.getElementById("view"),
  nav: document.getElementById("primary-nav"),
  navToggle: document.getElementById("nav-toggle"),
  account: document.getElementById("account"),
  env: document.getElementById("environment"),
  demo: document.getElementById("demo-indicator"),
  policy: document.getElementById("policy-notice"),
  announcer: document.getElementById("announcer"),
};

let renderSeq = 0;
let lastPolicy = null;
let publicDemo = false; // the anonymous public demo (GET /health): it never shows the sign-in form
// The session request made since a page last rendered; renders share it. The public demo answers it with
// a new anonymous session, so a lost or expired one comes back without a sign-in. A browser that refuses
// the cookie gets the error below after one more request rather than a loop, because no page renders in between.
let pendingSession = null;

function announce(text) {
  el.announcer.textContent = "";
  // A separate task so assistive technology notices the change.
  setTimeout(() => { el.announcer.textContent = text; }, 50);
}

function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const [pathPart, queryPart] = raw.split("?", 2);
  const query = Object.fromEntries(new URLSearchParams(queryPart || ""));
  return { path: pathPart || "/", query };
}

function setTitle(text) {
  el.title.textContent = text;
  document.title = `${text} — OGWA`;
}

function markNav(navPath) {
  for (const a of el.nav.querySelectorAll("a")) {
    if (a.getAttribute("href") === `#${navPath}`) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}

function showPolicy({ notice }) {
  if (notice === lastPolicy) return;
  lastPolicy = notice;
  el.policy.hidden = !notice;
  el.policy.textContent = notice ? `Policy: ${notice}. Classifications and lifecycle checks use a policy that has not been recorded or approved.` : "";
}

function renderAccount() {
  const who = api.principal();
  el.account.replaceChildren();
  el.nav.hidden = !who;
  if (!who) return;
  if (api.anonymous()) {
    el.account.append(h("p", null, "Public demo visitor ", h("span", { class: "muted" }, "(read-only, no sign-in)")));
    return;
  }
  const out = h("button", { type: "button", on: { click: async () => {
    try { await api.signOut(); } catch { /* the session is gone either way */ }
    renderAccount();
    location.hash = "#/";
    route();
  } } }, "Sign out");
  el.account.append(h("p", null, h("span", { class: "visually-hidden" }, "Signed in as "), who.displayName || who.subject,
    " ", h("span", { class: "muted" }, `(${who.roles.length ? who.roles.join(", ") : "no OGWA role"})`)), out);
}

async function loadEnvironment() {
  try {
    const data = await api.get("/dashboard");
    const env = (data.store || {}).environment;
    const mode = (data.safety || {}).executionMode;
    el.env.textContent = `${env || "UNKNOWN"} store · ${mode || "unknown mode"}`;
    el.env.setAttribute("data-tone", env === "SYNTHETIC" ? "caution" : "blocked");
  } catch {
    el.env.textContent = "Environment unknown";
    el.env.setAttribute("data-tone", "blocked");
  }
}

// The demo indicator comes from the public /health route, so it shows before sign-in too.
async function loadRuntime() {
  let indicator = null;
  try {
    indicator = demoIndicator(await api.get("/health"));
  } catch {
    indicator = null; // the standard runtime shows nothing; a failed check is not a demo
  }
  el.demo.hidden = !indicator;
  if (!indicator) return;
  publicDemo = indicator.public;
  document.getElementById("demo-label").textContent = indicator.label;
  document.getElementById("demo-sublabel").textContent = indicator.sublabel;
  document.getElementById("demo-detail").replaceChildren(...indicator.detail.map((text) => h("p", null, text)));
}

// The side navigation: docked and labelled, or icons only. The choice lasts while the page is
// open; nothing is written to browser storage (the UI stores nothing, see docs/architecture/ui.md).
const narrow = window.matchMedia("(max-width: 48rem)");
let navCollapsed = narrow.matches;

function applyNav() {
  document.body.classList.toggle("nav-collapsed", navCollapsed);
  el.navToggle.setAttribute("aria-expanded", navCollapsed ? "false" : "true");
  el.navToggle.querySelector(".nav-toggle-label").textContent = navCollapsed ? "Expand menu" : "Collapse menu";
}

el.navToggle.addEventListener("click", () => { navCollapsed = !navCollapsed; applyNav(); });
applyNav();

// Puts a page on screen in one step: its heading, its content, and focus, so the heading never names a page that
// is not shown. Focus moves (to `target`, else the heading) only if the reader left it where it was when the
// navigation began (`from`), or it was on the old content; a reader who moved it meanwhile keeps it there.
function show(view, title, from, target) {
  const active = document.activeElement;
  const ours = active === from || active === document.body || el.view.contains(active);
  setTitle(title);
  el.view.replaceWith(view);
  el.view = view;
  el.main.removeAttribute("aria-busy");
  if (ours) (target || el.title).focus();
}

async function route(flash) {
  const seq = ++renderSeq;
  const { path, query } = parseHash();
  const moved = MOVED.get(path);
  if (moved) {
    const params = new URLSearchParams(query);
    params.set("tab", moved[1]);
    location.replace(`#${moved[0]}?${params.toString()}`);
    return;
  }
  const from = document.activeElement;
  const view = h("div", { id: "view" });
  let title = "Loading";
  // Views append through the null-safe helper; a bare Element.append would print "null". A view's title is
  // applied with the view (show), not when the view starts fetching.
  const ctx = { query, params: {}, setTitle: (text) => { title = text; },
    view: { append: (...children) => append(view, children) }, flash: flash || null, reload: (message) => route(message) };
  el.main.setAttribute("aria-busy", "true");

  if (!api.principal()) {
    pendingSession = pendingSession || api.loadSession();
    await pendingSession.catch(() => null); // the sign-in form or the error below
    if (seq !== renderSeq) return;
    if (api.principal()) { renderAccount(); loadEnvironment(); }
  }
  if (!api.principal() && publicDemo) {
    view.append(banner("blocked", "The public demo could not start a session.",
      "Allow cookies for this site, then reload the page. No sign-in is needed."));
    show(view, "Service unavailable", from);
    return;
  }
  if (!api.principal()) {
    markNav("");
    const input = signin(ctx, async () => {
      renderAccount();
      await loadEnvironment();
      route();
    });
    show(view, title, from, input);
    announce("Sign in");
    return;
  }

  let match = null;
  for (const [re, render, navPath] of ROUTES) {
    const m = re.exec(path);
    if (m) { match = { render, navPath, params: m.groups || {} }; break; }
  }
  ctx.params = match ? match.params : {};
  setTitle("Loading");
  try {
    if (!match) {
      title = "Not found";
      view.append(h("p", null, "There is no such page. ", h("a", { href: "#/" }, "Go to the dashboard"), "."));
    } else {
      await match.render(ctx);
    }
  } catch (error) {
    if (error && error.status === 401) return; // handled by the unauthenticated listener
    view.replaceChildren();
    if (error && error.status === 404) title = "Not found";
    else if (error && error.status === 403) title = "Not permitted";
    else title = "Something went wrong";
    view.append(errorBox(error));
  }
  if (seq !== renderSeq) return; // a later navigation won
  pendingSession = null;
  markNav(match ? match.navPath : "");
  // A tab, sort header, or pager control that caused this render keeps focus; otherwise the heading.
  const key = focusAfterRoute.key;
  focusAfterRoute.key = null;
  const keep = key ? [...view.querySelectorAll("[data-focus-key]")].find((x) => x.getAttribute("data-focus-key") === key) : null;
  show(view, title, from, keep);
  if (narrow.matches && !navCollapsed) { navCollapsed = true; applyNav(); }
  announce(flash ? `${el.title.textContent}. ${flash}` : el.title.textContent);
}

api.on("unauthenticated", () => {
  renderAccount();
  route();
});
api.on("policy", showPolicy);

// The skip link moves focus to <main> without touching the hash router's location.
document.querySelector(".skip-link").addEventListener("click", (event) => {
  event.preventDefault();
  document.getElementById("main").focus();
});

function isRoute(hash) {
  return hash === "" || hash === "#" || hash.startsWith("#/");
}

async function start() {
  await loadRuntime();
  try {
    pendingSession = api.loadSession();
    await pendingSession;
  } catch (error) {
    show(h("div", { id: "view" }, errorBox(error)), "Service unavailable", document.body);
    return;
  } finally {
    pendingSession = null; // settled: a session lost while the first page renders is asked for again
  }
  renderAccount();
  if (api.principal()) await loadEnvironment();
  window.addEventListener("hashchange", () => { if (isRoute(location.hash)) route(); });
  route();
}

start();
