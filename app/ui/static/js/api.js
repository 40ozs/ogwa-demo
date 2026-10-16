// The UI's only connection to the outside: same-origin JSON calls to /api/v1.
//
// The browser holds no Okta, AAP, or AD credential. The session cookie is HttpOnly, so
// this code never sees it; the CSRF token is kept in memory only (never in localStorage
// or sessionStorage) and is re-read from GET /session after a reload, or when the server refuses it as stale.
//
// POSTs are limited to the paths in WRITE_PATHS. There is no call to the execute route.

const BASE = "/api/v1";
const ID_RE = /^[a-z]{2,6}_[0-9a-f]{32}$/;

// Every write the UI can make. tests/test_ui_static.py pins this list.
export const WRITE_PATHS = Object.freeze([
  "/session",
  "/session/logout",
  "/candidates/{candidateId}/transitions",
  "/candidates/{candidateId}/approvals",
  "/candidates/{candidateId}/execution-jobs",
  // A synthetic drill. It records nothing and changes only an in-memory
  // provider fixture that the server discards when it answers.
  "/candidates/{candidateId}/remediation-drills",
]);

const session = { csrf: null, principal: null };
// Refusals the server makes before any handler runs (app/api/app.py): the request did nothing.
const REFUSED_BEFORE_ANY_HANDLER = ["UNAUTHENTICATED", "CSRF_FAILED"];
const listeners = { unauthenticated: [], policy: [] };

export class ApiError extends Error {
  constructor(status, error) {
    super((error && error.message) || `Request failed (${status}).`);
    this.status = status;
    this.code = (error && error.code) || "UNEXPECTED_RESPONSE";
    this.problems = (error && error.problems) || [];
    this.requestId = (error && error.requestId) || null;
    this.auditEventId = (error && error.auditEventId) || null;
  }
}

export function on(event, handler) {
  listeners[event].push(handler);
}

function emit(event, value) {
  for (const handler of listeners[event]) handler(value);
}

/** An internal id, checked before it is put in a URL. */
export function checkedId(id) {
  if (typeof id !== "string" || !ID_RE.test(id)) throw new ApiError(404, { code: "NOT_FOUND", message: "No such record." });
  return id;
}

export function path(template, params) {
  return template.replace(/\{(\w+)\}/g, (_, name) => encodeURIComponent(checkedId(params[name])));
}

function query(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== null && value !== undefined && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request(method, route, body, resent = false) {
  const visitor = anonymous();
  const headers = { Accept: "application/json" };
  const init = { method, headers, credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" };
  if (method === "POST") {
    headers["Content-Type"] = "application/json";
    if (session.csrf) headers["X-OGWA-CSRF"] = session.csrf;
    init.body = JSON.stringify(body || {});
  }
  let response;
  try {
    response = await fetch(BASE + route, init);
  } catch {
    throw new ApiError(0, { code: "NETWORK_ERROR", message: "The OGWA service could not be reached." });
  }
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  emit("policy", { notice: data.policyNotice || null, header: response.headers.get("X-OGWA-Policy-Status") });
  if (!response.ok) {
    const error = new ApiError(response.status, data.error);
    // The public demo's visitor session can lapse, or another tab can replace it (and its CSRF token). Such a
    // POST did nothing, so it is sent once more with the visitor session GET /session hands out: once, and
    // never after any other answer, which may mean it ran.
    if (method === "POST" && visitor && !resent && REFUSED_BEFORE_ANY_HANDLER.includes(error.code) && await renewVisitor()) {
      return request(method, route, body, true);
    }
    if (response.status === 401) {
      const hadSession = session.principal !== null;
      session.csrf = null;
      session.principal = null;
      if (hadSession) emit("unauthenticated", error); // a session that ended, not a failed sign-in
    }
    throw error;
  }
  return data;
}

export function get(route, params) {
  return request("GET", route + query(params));
}

function post(template, params, body) {
  if (!WRITE_PATHS.includes(template)) throw new Error(`the UI does not write to ${template}`);
  return request("POST", path(template, params || {}), body);
}

// --- session ------------------------------------------------------------------------------

export function principal() {
  return session.principal;
}

export function can(permission) {
  return Boolean(session.principal && session.principal.permissions.includes(permission));
}

/** The public demo's anonymous visitor: no sign-in, and no sign-out (app/runtime/api.py). */
export function anonymous() {
  return Boolean(session.principal && session.principal.authenticationMethod === "anonymous-public-demo");
}

/** Whether this visitor may run a candidate's synthetic drill: an executor, or the public demo's one candidate. */
export function canDrill(candidateId) {
  return can("EXECUTION_PLAN_DRY_RUN")
    || Boolean(session.principal && (session.principal.publicDrillCandidates || []).includes(candidateId));
}

export async function loadSession() {
  try {
    const data = await get("/session");
    session.csrf = data.csrfToken;
    session.principal = data.principal;
    return data.principal;
  } catch (error) {
    if (error.status === 401) return null;
    throw error;
  }
}

/** A visitor session from GET /session, for the one resend above; false if none came back. */
async function renewVisitor() {
  try {
    await loadSession();
  } catch {
    return false;
  }
  return anonymous();
}

export async function signIn(subject) {
  const data = await post("/session", {}, { subject });
  session.csrf = data.csrfToken;
  session.principal = data.principal;
  return data.principal;
}

export async function signOut() {
  try {
    await post("/session/logout", {}, {});
  } finally {
    session.csrf = null;
    session.principal = null;
  }
}

// --- governed writes ----------------------------------------------------------------------

export function transition(candidateId, body) {
  return post("/candidates/{candidateId}/transitions", { candidateId }, body);
}

export function decideApproval(candidateId, body) {
  return post("/candidates/{candidateId}/approvals", { candidateId }, body);
}

export function runRemediationDrill(candidateId, body) {
  // The body names a mode (DRY_RUN or SYNTHETIC_EXECUTION) and, to execute, one scenario from
  // the server's catalog. It never carries an execution mode, a dry-run flag, or a fault.
  return post("/candidates/{candidateId}/remediation-drills", { candidateId }, body);
}

export function planDryRun(candidateId, body) {
  // dryRun and executionMode are fixed here: the UI cannot ask for anything but a plan.
  return post("/candidates/{candidateId}/execution-jobs", { candidateId },
    { ...body, dryRun: true, executionMode: "DRY_RUN_MUTATION" });
}
