// Unit tests for the API client's one resend (app/ui/static/js/api.js). Run by tests/test_ui_api.py.
// The server refuses a POST whose session has lapsed (401 UNAUTHENTICATED) or whose CSRF token another tab has
// replaced (403 CSRF_FAILED) before any handler runs (app/api/app.py), so nothing happened. Only then, and only
// for the public demo's anonymous visitor, is it sent once more with the visitor session GET /session hands out.
// No network: fetch is replaced. Synthetic data only.
import assert from "node:assert/strict";
import { test } from "node:test";

import * as api from "../../app/ui/static/js/api.js";

const C11 = `cand_${"1".repeat(32)}`;
const VISITOR = { subject: "public.visitor", authenticationMethod: "anonymous-public-demo", roles: ["VIEWER"],
  permissions: ["READ_INVENTORY"], publicDrillCandidates: [C11] };
const EXECUTOR = { subject: "synthetic.executor.one", authenticationMethod: "synthetic", roles: ["EXECUTOR"],
  permissions: ["READ_INVENTORY", "EXECUTION_PLAN_DRY_RUN"] };
const DRILL = `/candidates/${C11}/remediation-drills`;

let calls = [];
let ended = 0;
api.on("unauthenticated", () => { ended += 1; });

/** The answers to the next requests, in order: [status, body], or an Error for a request that never got one. */
function serve(...answers) {
  calls = [];
  ended = 0;
  globalThis.fetch = async (url, init) => {
    calls.push([init.method, url.replace("/api/v1", ""), init.headers["X-OGWA-CSRF"] || null]);
    const next = answers.shift();
    if (next === undefined) throw new Error(`unexpected request ${url}`);
    if (next instanceof Error) throw next;
    return { ok: next[0] < 400, status: next[0], json: async () => next[1], headers: { get: () => null } };
  };
}
const session = (principal, csrf) => [200, { principal, csrfToken: csrf }];
const refused = (status, code) => [status, { error: { code, message: code } }];
const drill = () => api.runRemediationDrill(C11, { mode: "DRY_RUN" });

async function as(principal) {
  serve(session(principal, "token-1"));
  await api.loadSession();
}

test("a visitor's drill refused for another tab's CSRF token is sent once more, with the current token", async () => {
  await as(VISITOR);
  serve(refused(403, "CSRF_FAILED"), session(VISITOR, "token-2"), [200, { drill: { mode: "DRY_RUN" } }]);
  assert.deepEqual(await drill(), { drill: { mode: "DRY_RUN" } });
  assert.deepEqual(calls, [["POST", DRILL, "token-1"], ["GET", "/session", null], ["POST", DRILL, "token-2"]]);
  assert.equal(ended, 0, "the page is not re-rendered: the reader keeps the drill's answer");
});

test("a visitor's drill pressed after the session lapsed is sent once more, in a new visitor session", async () => {
  await as(VISITOR);
  serve(refused(401, "UNAUTHENTICATED"), session(VISITOR, "token-2"), [200, { drill: { mode: "DRY_RUN" } }]);
  assert.deepEqual(await drill(), { drill: { mode: "DRY_RUN" } });
  assert.deepEqual(calls, [["POST", DRILL, "token-1"], ["GET", "/session", null], ["POST", DRILL, "token-2"]]);
  assert.equal(ended, 0);
});

test("it is sent once more at most", async () => {
  for (const code of ["CSRF_FAILED", "UNAUTHENTICATED"]) {
    await as(VISITOR);
    serve(refused(code === "CSRF_FAILED" ? 403 : 401, code), session(VISITOR, "token-2"), refused(403, "CSRF_FAILED"));
    await assert.rejects(drill(), { code: "CSRF_FAILED" });
    assert.equal(calls.filter(([method]) => method === "POST").length, 2, code);
  }
});

test("no other refusal, failure, or unknown outcome is ever sent again", async () => {
  const answers = [refused(403, "FORBIDDEN"), refused(403, "DEMO_READ_ONLY"), refused(403, "PUBLIC_DRILL_SCOPE"),
    refused(403, "ORIGIN_REFUSED"), refused(409, "EVIDENCE_CHANGED"), refused(401, "UNSUPPORTED_AUTHENTICATION"),
    [500, {}], [502, {}], new TypeError("Failed to fetch")];
  for (const answer of answers) {
    await as(VISITOR);
    serve(answer);
    await assert.rejects(drill());
    assert.deepEqual(calls, [["POST", DRILL, "token-1"]], String(answer));
  }
});

test("a signed-in principal's refused write is never sent again", async () => {
  await as(EXECUTOR);
  serve(refused(403, "CSRF_FAILED"));
  await assert.rejects(drill(), { code: "CSRF_FAILED" });
  assert.equal(calls.length, 1);
  await as(EXECUTOR);
  serve(refused(401, "UNAUTHENTICATED"));
  await assert.rejects(drill(), { status: 401 });
  assert.equal(calls.length, 1);
  assert.equal(ended, 1, "the session ended: the page shows the sign-in form");
});

test("without a visitor session again, nothing is sent again", async () => {
  await as(VISITOR);
  serve(refused(401, "UNAUTHENTICATED"), refused(401, "UNAUTHENTICATED"));  // the browser refuses the cookie
  await assert.rejects(drill(), { status: 401 });
  assert.deepEqual(calls, [["POST", DRILL, "token-1"], ["GET", "/session", null]]);
  assert.equal(ended, 1, "the session ended once: the page explains it");
  await as(VISITOR);
  serve(refused(403, "CSRF_FAILED"), session(EXECUTOR, "token-2"));  // GET /session names someone else
  await assert.rejects(drill(), { code: "CSRF_FAILED" });
  assert.equal(calls.length, 2);
  await as(VISITOR);
  serve(refused(403, "CSRF_FAILED"), [503, {}]);
  await assert.rejects(drill(), { code: "CSRF_FAILED" });
  assert.equal(calls.length, 2);
});

test("reads are never sent again here", async () => {
  await as(VISITOR);
  serve(refused(401, "UNAUTHENTICATED"));
  await assert.rejects(api.get("/dashboard"), { status: 401 });
  assert.equal(calls.length, 1);
  assert.equal(ended, 1, "the router starts a new visitor session and renders the page again");
});
