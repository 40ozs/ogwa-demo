# The hosted demo on Cloudflare

The public demo at <https://ogwa-demo.d-walkes.workers.dev> runs the real OGWA application, in
Demo Mode over the Null Meridian dataset, as a Cloudflare **Python Worker** with **Workers Static
Assets** and one **D1** database. It is **anonymous** (no sign-in) and **read-only**: every visitor
sees the same synthetic store, and nothing a visitor does changes it. It holds no integration
credential of any kind.

## What a reviewer should expect

- The page opens on the dashboard. There is no sign-in form: the header says **Public demo
  visitor (read-only, no sign-in)**, and the indicator says **DEMO ENVIRONMENT · Public synthetic
  demo · no live integrations**.
- Every view can be opened. **NM-C10** shows why OGWA refuses to act. **NM-C11**'s remediation
  drill runs: a dry run, then a synthetic execution through an unknown outcome, verification, a
  retry with the same operation id, and post-action verification. The drill records nothing.
- Approvals, holds and every other decision are refused (`403 DEMO_READ_ONLY`), so the candidate
  pages offer no decision forms.
- The audit trail and mapping inspection are not shown. The dashboard shows the audit event count
  (1,458) and head (`sha256:e8793f89…eb41`), which no visitor can move.

## Hosted and local

| | Hosted (this document) | Local (`docker compose up`, or `python -m app.api serve`) |
| --- | --- | --- |
| Entry | Anonymous: every visitor is the synthetic `public.visitor` (VIEWER) | Synthetic sign-in as any principal in `config/synthetic-idp.json` |
| Recording decisions | Refused (`DEMO_READ_ONLY`) | Holds and mapping reviews are recorded; an approval is refused by the evidence-freshness gate (`409 EVIDENCE_RULES_NOT_MET`) |
| Remediation drill | NM-C11 only | Any candidate an executor may drill |
| Audit trail, mapping inspection | Not available; the dashboard shows the audit head | Available to the roles that hold them |
| Store | D1 holds it; each isolate serves an in-memory, read-only copy | A SQLite file (`var/` or the Docker volume) |
| Reset | None needed: nothing changes | `reset-demo`, or `docker compose down -v` |

## Architecture

```text
browser ──► Workers Static Assets: /, /ui/*  (index.html, CSS, JS; _headers: CSP, X-Frame-Options, …)
   │
   └──────► Python Worker (cloudflare/worker/src/entry.py)          /api/v1/*, anything else
               │  at import time (Cloudflare's deploy-time snapshot):
               │    the validated demo store image → open_demo_image → validate_demo_store
               │    → build_demo_application (read-only, anonymous)
               │  per isolate: Worker vars/secrets → load_settings (the demo profile);
               │               D1 schema == the store's complete schema
               │  per request: D1 identity == the served store's identity (1 query)
               │               → HostedDemo.handle → the real OGWA WSGI application
               ▼
             D1: the canonical demo store, written only by the operator import
```

- **An in-memory copy, checked against D1.** OGWA's store is synchronous SQLite code that makes
  many small queries per view; a D1 round trip per query would be far too slow. The Worker builds a
  read-only copy of the validated store at import time, so Cloudflare's deploy-time snapshot holds
  it and no request pays for it. On every request it proves that D1 still holds exactly that store
  (marker, schema version, audit head, snapshot digest). An empty, partial, foreign or changed D1
  makes it answer 503 and serve nothing.
- **Signed sessions.** One browser's requests reach different Cloudflare locations and isolates,
  so in-process sessions are never found again. The session is a cookie signed with HMAC-SHA256
  under the `HOSTED_SESSION_KEY` secret (`SignedSessionManager`, `app/api/sessions.py`). Local
  OGWA keeps server-side sessions.

## Anonymous access

- `GET /api/v1/session` gives a visitor without a session a new one for the synthetic, anonymous
  `public.visitor` (method `anonymous-public-demo`). Its role comes from the role bindings like any
  other: VIEWER (`READ_INVENTORY`) and nothing else. Data routes need that cookie (401 without it).
- `POST /api/v1/session` answers `403 PUBLIC_DEMO_NO_SIGN_IN`: no visitor can choose a principal.
  The Worker accepts no cookie but the visitor's (`VisitorSessions`), so a cookie signed for any
  other principal is refused like a forged one.
- The visitor may run the synthetic drill on the walkthrough's controlled-remediation candidate
  (NM-C11, marked `publicDrill`) and on no other (`403 PUBLIC_DRILL_SCOPE`). For that one request,
  on that one candidate, it holds the executor's role; the session stays VIEWER. Every other drill
  check is unchanged: the approval must be this candidate's, and the evidence fresh.
- The cookie is `__Host-`, Secure, HttpOnly, SameSite=Strict, Max-Age=900. A session ends after
  15 minutes unused or 8 hours after it began; a response renews it at most once a minute. If it
  is lost or expires, the UI starts a new one and opens the requested page. A drill sent with a
  lapsed session, or with a CSRF token another tab has replaced, is refused before it runs
  (`401`, `403 CSRF_FAILED`); the UI then takes the new visitor session and sends it once more.

The code is `app/runtime/api.py` (the routes) and `app/cloudflare/hosted.py` (`VisitorSessions`).

## Why it is safe

- **Demo profile, applied twice.** `load_settings` refuses live-integration settings and
  production credential variables, first for the build's environment and then for the Worker's
  real variables and secrets, before an isolate's first request. A refused setting makes the
  Worker answer 503.
- **Synthetic providers only.** No network fallback exists, the Worker glue makes no outbound
  call, and the demo path starts no process (`tests/test_cloudflare_worker_config.py`,
  `tests/test_cloudflare_hosted.py`).
- **Read-only, twice.** The route policy refuses every persisting request, and SQLite refuses any
  write (`PRAGMA query_only`). A refused governed request is logged (`api.refusal_not_chained`),
  never appended to the audit chain.
- **No write path to D1.** There is no bootstrap or reset endpoint and no bootstrap secret; the
  Worker only reads D1's identity and schema.
- **One secret.** `HOSTED_SESSION_KEY` (64 or more hex digits, set with `wrangler secret put`).
- **Security headers.** The UI's `_headers` and the API send a CSP with Trusted Types,
  `X-Frame-Options` and a strict referrer policy.
- **Platform behavior.** `workers.dev` adds Cloudflare's `NEL` and `Report-To` headers to every
  response (network-error reports go to Cloudflare) and serves its own `robots.txt`. OGWA sets
  neither and cannot turn them off on `workers.dev`.

## What persists, and what does not

- **D1** holds the canonical store. Only the operator import writes it; visitors never do.
- **Each isolate** serves an in-memory, read-only copy, so nothing is written there either.
- **A session** exists only in the visitor's signed cookie. The Worker keeps no session state.
- **A drill** changes an in-memory provider fixture that is discarded after each answer.
- **Logs** go to Workers Logs: one redacted JSON line per API request, never a secret or cookie.

## The pieces

| Layer | Code | Role |
| --- | --- | --- |
| Worker glue | `cloudflare/worker/src/entry.py` | The only Cloudflare-specific code: reads the Worker env and D1, then hands the request to `HostedDemo` |
| Hosted application | `app/cloudflare/hosted.py` | `HostedDemo`: the store image, the D1, schema and environment checks, the WSGI adapter, `VisitorSessions`. Tested outside Cloudflare |
| Store identity | `app/cloudflare/identity.py` | `IDENTITY_SQL` and `SCHEMA_SQL`, one statement each, the same on SQLite and D1 |
| D1 export | `app/cloudflare/export.py` | The store as D1 SQL, in phases |
| Operator CLI and script | `python -m app.cloudflare`, `scripts/cloudflare-demo.ps1` | Build, import, verify, deploy |
| Shared with local | `app/runtime/*`, `app/api/*`, `app/store/*` | The same validation, routes, services and store as `python -m app.api serve` |

## Deploying your own copy

You need a Cloudflare account on **Workers Paid** (typical API requests use more CPU than Workers
Free allows), Python 3.11+, Node.js (for `npx wrangler`), `uv` (for `pywrangler`) and PowerShell 7.

1. **Create a D1 database:** `npx wrangler d1 create <name>`. The name and id in
   `cloudflare/worker/wrangler.jsonc` are the maintainer's: replace them with yours, and set the
   same name as `$database` in `scripts/cloudflare-demo.ps1` and in
   `tests/test_cloudflare_worker_config.py`.
2. **Set the session key:** `npx wrangler secret put HOSTED_SESSION_KEY` with 64 hex digits, for
   example from `python -c "import secrets; print(secrets.token_hex(32))"`.
3. **Build:** `pwsh scripts/cloudflare-demo.ps1 -Build`. It seeds the store with the demo's own
   guarded reset, builds `HostedDemo` from it exactly as the Worker will, writes the D1 import
   phases to `cloudflare/build/d1/`, and stages the Worker. Two builds give identical phase files.
4. **Import:** `pwsh scripts/cloudflare-demo.ps1 -Bootstrap -ConfirmSyntheticBootstrap`, once per
   phase. There are two, because D1 Free counts each index entry as a written row (100,000 a day);
   on Workers Paid both may run the same day. The script refuses a D1 database that is not this
   build's import. The Worker answers 503 until both phases are in.
5. **Verify:** `pwsh scripts/cloudflare-demo.ps1 -Verify` exports D1 and validates it with the
   demo runtime's own checks. D1 is unavailable while the export runs.
6. **Deploy:** `pwsh scripts/cloudflare-demo.ps1 -Deploy` (`pywrangler deploy`), after the gates
   below.

A dataset or schema change needs a **new** D1 database: the import compares schema objects, not
rows, so it would read the old database as complete, and the Worker would answer 503. Import the
new database while the old Worker still serves, then deploy; the old version and old database stay
a consistent rollback pair.

## Rollback

- **A previous Worker version:** `npx wrangler versions list --name ogwa-demo`, then
  `npx wrangler rollback <version-id> --name ogwa-demo`. A version carries its own bindings, and D1
  is not touched. Roll back only to a version built with anonymous entry: an older one brings back
  the hosted sign-in.
- **Take the demo offline:** set `"workers_dev": false` in `wrangler.jsonc` and deploy.
- **Deleting D1** is destructive and separate (`npx wrangler d1 delete <name>`). D1 Time Travel can
  restore a database to an earlier point.

## Validation

| Gate | Command |
| --- | --- |
| Unit tests, including the Cloudflare tests | `python -m unittest discover -s tests -t .` (`tests/test_cloudflare_*.py`) |
| Hosted smoke: anonymous entry, a viewer's permissions only, the read-only refusals, NM-C10 refusing NM-C11's drill grant, NM-C11's drill recording nothing, the walkthrough, and the audit head | `python scripts/hosted_smoke.py https://ogwa-demo.d-walkes.workers.dev` |
| Browser gate, local (includes the Worker's own application on loopback, `HostedDemoServer`) | `pwsh scripts/browser-check.ps1` |
| Browser gate against a Worker | `UI_BROWSER_TESTS=1 UI_BROWSER_TARGET=<origin> python -m unittest tests.browser.test_demo_null_meridian_ui tests.browser.test_null_meridian_views tests.browser.test_hosted_demo_ui tests.browser.test_ui_ia tests.browser.test_candidate_tables tests.browser.test_remediation_drill_ui -v` |
| Wrangler config | `npx wrangler deploy --dry-run` in `cloudflare/worker` |
| D1 | `pwsh scripts/cloudflare-demo.ps1 -Verify` |

`UI_BROWSER_TARGET` points the browser at a demo that is already serving; the browser can then
resolve that one host besides `127.0.0.1`, and nothing else. Tests that need a signed-in
principal skip there by design.

## Known limitations

- **Signed sessions cannot be revoked everywhere.** Signing out clears the browser's cookie, but a
  copy of the token made earlier still works in other isolates until it expires. The data is
  synthetic and read-only. Rotating `HOSTED_SESSION_KEY` ends every session.
- **D1 is checked by identity on each request, not row by row.** The identity covers the audit
  head, and so every audited write. A full check is the verify step.
- **Spend has no hard cap.** `limits.cpu_ms` (2,000 ms) bounds each request, not how many arrive.
  A budget alert in the Cloudflare dashboard is the owner's signal.
- **The demo clock starts per isolate,** just after the newest audit event, as a local server's
  does at start.
