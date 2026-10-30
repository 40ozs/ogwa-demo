# The Cloudflare-hosted demo (Workers Paid + D1)

The public OGWA demo runs the real application, in Demo Mode over the Genesee Press dataset, as a
Cloudflare **Python Worker** with **Workers Static Assets** and one **D1** database. It holds no
integration credential of any kind. It is **read-only** for visitors: the shared store never
changes (owner decision, OGWA-CLOUDFLARE-DEMO-01).

**Plan. Workers Paid is REQUIRED for the hosted OGWA demo.** Workers Free is not a supported
configuration and not a rollback target. On the deployed Worker, API requests use a median of 28 ms
of CPU, while Free allows 10 ms and terminates Workers that run over consistently. The owner
upgraded the account to Workers Paid on 2026-10-12. The demo depends on the plan's $5 a month, and
traffic beyond the included usage is billed. A `limits.cpu_ms` guardrail of 2,000 ms bounds each
request. See "Plan and limits".

| | |
| --- | --- |
| Worker | `ogwa-demo`, at `https://ogwa-demo.d-walkes.workers.dev`, on Workers Paid (required), CPU capped at 2,000 ms per request (`limits.cpu_ms`) |
| D1 database | `ogwa-demo-3`, region WNAM, binding `DB` (since SYNTH-HOSTED-CUTOVER-MAC-01; its id is in `wrangler.jsonc`). The earlier databases `ogwa-demo-2` (Null Meridian, bound to the rollback version) and `ogwa-demo` are kept unchanged as rollback assets |
| Deployment repository | `40ozs/ogwa-demo` `main`: the sanitized release exported from this repository. Build and deploy from a checkout of it, not from this repository (see "Genesee Press cutover") |
| Static assets | `cloudflare/worker/public/` (the UI), with `_headers` for the UI's security headers |
| Runtime variables | `OGWA_RUNTIME_MODE=demo`, `OGWA_DEMO_DATASET=genesee-press` (OGWA's own names, `vars` in `wrangler.jsonc`) |
| Secrets | `HOSTED_SESSION_KEY` only: the key that signs session cookies (64 hex digits, set with `wrangler secret put`, never stored elsewhere). No integration credential exists, and the Worker refuses to serve if one with a production name is added (below). |
| Dataset | selector `genesee-press`, seed namespace `genesee-press-v1`, company Genesee Press (synthetic-enterprise dataset 2.1.0), audit head `sha256:f11f0a99…d4b39f` (1,617 events), 11 lifecycle candidates, 31,921 directory records |
| Python | 3.14 (Pyodide 314.0.6), through `compatibility_date` 2026-10-01 and the `python_workers` flag |

## Architecture

```text
browser ──► Workers Static Assets: /, /ui/*  (index.html, CSS, JS; _headers: CSP, X-Frame-Options, …)
   │
   └──────► Python Worker (cloudflare/worker/src/entry.py)          /api/v1/*, anything else
               │  at import time (Cloudflare's deploy-time memory snapshot):
               │    the validated demo store image → open_demo_image → validate_demo_store
               │    → build_demo_application (read-only) → directory snapshot preloaded
               │  per isolate: Worker vars/secrets → load_settings (the demo profile),
               │               signed sessions from HOSTED_SESSION_KEY;
               │               D1 schema == the store's complete schema
               │  per request: D1 identity == the served store's identity (1 query)
               │               → HostedDemo.handle → the real OGWA WSGI application
               ▼
             D1 `ogwa-demo-3`: the canonical demo store, written only by the operator bootstrap
```

**Why sessions are signed cookies.** Consecutive requests from one browser reach different
Cloudflare locations and isolates: one visitor's requests were measured at ATL, SJC, BOS, and PDX
within seconds. OGWA's in-process sessions are therefore never found again. With them, 0 of 20
follow-up requests kept the session, and `wrangler dev`, with its single isolate, could not
show this. The Worker uses `SignedSessionManager` (`app/api/sessions.py`). The cookie carries
the principal's claims, its CSRF token, and its issue time, signed with HMAC-SHA256 under
`HOSTED_SESSION_KEY`. After the change, 20 of 20 requests kept the session. Local OGWA keeps its
server-side sessions.

**Why the Worker does not query D1 for each view.** OGWA's store is synchronous SQLite code
with many small queries per view (up to ~150 for some lists), and the demo's directory views
load all 31,268 snapshot records once per process. A D1 query is a network round trip, and
Workers Free, the original target, allows 50 D1 queries per invocation and 10 ms of CPU. Measured
in Pyodide (local `workerd`, arm64), rebuilding the store from D1 per isolate took ~0.8 s and
validating it another ~0.5 s. So the Worker serves an in-memory, read-only copy of the same
validated store. It builds the copy at import time, so the deploy-time snapshot holds it
and no request pays for it. On every request, it proves that D1 still holds exactly that
store. Steady-state requests measured 0–6 ms locally.

**Why D1.** D1 is the store of record: the complete canonical demo store (every table, row,
index, and trigger, with the schema SQL the canonical migrations created). The hosted verify
validates D1 itself with the demo runtime's own checks. The Worker answers only while D1
holds the store it serves: an empty, partial, foreign, or changed D1 makes it answer 503 and
serve nothing. A SQLite file inside the Worker would not persist. Nothing here stores a
database file in the Worker's filesystem.

**Why `GET /system/integrity` does not re-verify on each call** (OGWA-INTEGRITY-COST-03).
`Store.verify_integrity` (`app/store/store.py`) re-reads and re-hashes the whole store:

- the migrations;
- all 1,404 audit events and their chain;
- 1,355 evidence observations, each re-digested, with its anchor row read per observation;
- 9 candidate histories, and the mapping-review and policy-version chains;
- all 31,268 directory snapshot records, against their recorded digest.

The result depends only on the store, not on who asks. A full run takes ~200 ms in native
CPython, half of it the directory snapshot. In Pyodide on the Worker it took 0.6–2.6 s of CPU,
and the route used to run it on every call.

The hosted store cannot change. It is an in-memory image under `PRAGMA query_only`, and D1
changes only through operator imports. The Worker already runs the full `verify_integrity` once,
at import time, inside `validate_demo_store`, pinned to the build manifest's audit head. A
failure there fails the deploy. Cloudflare's deploy-time snapshot holds the resulting report, so
every isolate starts with it, and no request ever runs the first verification.

How the report is reused:

- **What is kept.** `verify_integrity` keeps its report when the store is read-only, tagged with
  the audit head (sequence and digest) and the connection's row-change count (`total_changes`) at
  the end of the run. A verification that fails raises an error and keeps nothing.
- **What the route serves.** The route calls `Store.verified_integrity`. That returns the kept
  report only while the store is still read-only and both tags are unchanged. Otherwise it runs
  the full verification again. A writable store, such as local `serve` or a production store, is
  verified in full on every call, as before.
- **A new import or a new build** means a new deployment: new isolates, a new `Store`, and a fresh
  verification at import. If D1 stops matching the served store, the per-request identity check
  refuses it with 503 before the application runs (`entry.py`). That holds whatever report was kept.
- **Operator verification.** The build, `verify-export`, and `python -m app.runtime verify` call
  `verify_integrity` itself, which always verifies in full and never reads the kept report.

The response is unchanged. Its `auditHead` is the head the report was verified at, which is also
the head D1 must hold.

### The pieces

| Layer | Code | Role |
| --- | --- | --- |
| Worker glue | `cloudflare/worker/src/entry.py` | The only Cloudflare-specific code. It reads the Worker env and D1, then hands the request to `HostedDemo`. |
| Hosted application | `app/cloudflare/hosted.py` | `HostedDemo`: `open_demo_image` + `build_demo_application`, the D1, schema, and environment checks, and the WSGI request adapter. Tested outside Cloudflare. |
| Store identity | `app/cloudflare/identity.py` | `IDENTITY_SQL` (marker, schema version, audit head, 0012 snapshot) and `SCHEMA_SQL`. One statement each, the same on SQLite and D1. |
| D1 export | `app/cloudflare/export.py` | The store as D1 SQL, in phases under the daily write budget. |
| Operator CLI | `python -m app.cloudflare` | `build`, `next-phase`, `verify-export`, `sql`. |
| Operator script | `scripts/cloudflare-demo.ps1` | `-Build`, `-Bootstrap -ConfirmSyntheticBootstrap`, `-Verify`, `-Deploy` (wrangler pinned to 4.147.0). |
| Existing code reused | `app/runtime/demo_store.py` (`open_demo_image`, `validate_demo_store`), `app/runtime/api.py` (`build_demo_application`, `demo_routes`), `app/api/*`, `app/store/*` | The same validation, routes, services, and store as `python -m app.api serve` in demo. |

**Local SQLite and hosted D1.** Locally, nothing changed. `python -m app.runtime reset-demo` and
`python -m app.api serve` use the demo store file under `var/` exactly as before, and every
test uses local SQLite. The hosted Worker never opens a file. `app.store.db.connect_image`
deserializes the store's bytes into memory with `PRAGMA query_only = ON`.

## Plan and limits

All limits and prices are from Cloudflare's documentation as checked on 2026-10-12
([limits](https://developers.cloudflare.com/workers/platform/limits/),
[pricing](https://developers.cloudflare.com/workers/platform/pricing/)). The demo uses three
products: the Worker (Workers Paid), Workers Static Assets, and one D1 database. An account audit
on 2026-10-12 found nothing else: no Containers, Durable Objects, KV, R2 (not enabled), Queues,
Vectorize, Workers AI binding, Access application, Hyperdrive, or custom domain. The only
plan-specific setting is `limits.cpu_ms`. `tests/test_cloudflare_worker_config.py` pins the
configuration to the reviewed keys and the CPU cap.

**Measured on the deployed Worker** (per-request `cpuTime` from `wrangler tail`, requests from many
Cloudflare locations, 2026-10-12):

| | |
| --- | --- |
| CPU, typical use | 131 API requests across 13 routes: median 28 ms, p90 97 ms, max 219 ms. `GET /people/{id}` had a median of 75 ms and `GET /health` 11 ms. 120 of 131 were over 10 ms. |
| CPU, every route | 217 requests, under the 5,000 ms cap then in place: every read route, mapping inspection, and the read-only refusals. Median 35 ms, p90 159 ms. Apart from the integrity check, the heaviest was mapping inspection (max 211 ms; 348 ms before the cap). |
| CPU, `GET /system/integrity` | Before OGWA-INTEGRITY-COST-03 it was the outlier, re-running the full store verification on each call: 694–2,623 ms over 45 calls (median ~1.3 s). A fresh baseline of 10 calls gave median 1,398 ms, p90 2,409 ms, max 2,498 ms. After the change (version `9b571578`): 31 calls, median 75 ms, p90 120 ms, max 131 ms. The first call after the deploy used 86 ms. |
| Outcome | every request `ok`. Cloudflare's analytics for 2026-10-12 show only `success` (and 2 `clientDisconnected`): no request has exceeded a CPU limit. |
| Memory | WASM memory at import measured at 93.8 MiB, in local `workerd` (the store image is unchanged since). Over 128 MiB, the deploy-time snapshot fails (below). |
| Latency | ~80–150 ms wall time for warm API requests. The first requests after a deploy (new isolates) took 1.4–2.8 s, and a cold isolate in a new location 1–2.5 s. |

**Workers Paid** costs $5 a month, the account minimum, and the demo depends on it. It includes
10 million requests and 30 million CPU-ms a month; at the measured median, the CPU allowance covers
about a million API requests. Requests for static assets are free and unlimited. Standard usage has
no duration charge. D1 is included up to 25 billion rows read, 50 million rows written, and 5 GB
stored a month, and the demo is far below each (below). Usage beyond the allowance is billed:

| Overage | Price |
| --- | --- |
| Worker requests | $0.30 per million |
| Worker CPU time | $0.02 per million CPU-ms |
| D1 rows read / rows written / storage | $0.001 per million / $1.00 per million / $0.75 per GB-month |
| Workers Logs, beyond 20 million events a month | $0.60 per million |

The Worker is public, so heavy or abusive traffic costs money. Nothing rate-limits it.

**Integrity check: CPU cost before and after.** These are estimates, not billing. They count CPU
at the overage price ($0.02 per million CPU-ms, confirmed on the pricing page on 2026-10-12). The
request charge ($0.30 per million) is the same before and after.

| Integrity calls | Before (median 1,398 ms, max 2,623 ms) | After (median 75 ms, max 131 ms) |
| --- | --- | --- |
| 1 | ~1,400 CPU-ms ≈ $0.000028 (max $0.000052) | ~75 CPU-ms ≈ $0.0000015 (max $0.0000026) |
| 100 | ~140,000 CPU-ms ≈ $0.0028 (max $0.0052) | ~7,500 CPU-ms ≈ $0.00015 (max $0.00026) |
| 1,000 | ~1.4 million CPU-ms ≈ $0.028 (max $0.052) | ~75,000 CPU-ms ≈ $0.0015 (max $0.0026) |

That is about 19× less CPU per call. The plan's 30 million included CPU-ms a month covered about
21,000 integrity calls before the change, and covers about 400,000 now.

**CPU guardrail: `limits.cpu_ms` = 2000** (`wrangler.jsonc`, version `6dd50d79`). Paid's default
is 30,000 ms per request, and its maximum 300,000 ms. A request over the cap is stopped: the client
gets error 1102, and the invocation's outcome is `exceededCpu`. The cap does not limit how many
requests arrive. It stops a runaway or pathological request at 2 s of CPU instead of 30 s.

How the value was chosen:

1. **5,000 ms** (OGWA-CLOUDFLARE-COST-GUARD-02), about 1.9× `GET /system/integrity`, which then
   used up to 2,623 ms.
2. **1,000 ms trial** (version `f6f2d259`), after OGWA-INTEGRITY-COST-03 brought integrity down to
   at most 148 ms. 450 requests were tailed, all `ok`:
   - mapping inspection (`POST /mappings/{id}/inspection`), 34 calls: median 244 ms, p90 374 ms,
     max **823 ms**, 82% of the cap, in a cold LHR isolate;
   - every other route: at most 237 ms.

   Inspection does ~700 small store reads per call. The first runs in a fresh isolate cost several
   times the warm figure, so a cold inspection could cross 1,000 ms and fail a legitimate request.
3. **2,000 ms** (owner decision), about 2.4× the worst inspection measured. On version `6dd50d79`,
   371 requests were tailed, all `ok`:
   - inspection, 34 calls: median 230 ms, p90 480 ms, max 623 ms (31% of the cap);
   - integrity, 31 calls: median 65 ms, max 147 ms;
   - every other route: at most 203 ms.

If `exceededCpu` ever appears for a legitimate route, raise the cap; do not weaken the route.
Making inspection cheaper would allow a lower cap. That is code work in the correlation path,
not a configuration change.

**Budget alert (owner action).** The deploy tooling's Cloudflare login has no billing or
notifications scope (the API answers 403), so no budget alert was read or created. Budget alerts
track the account's usage-based spend for the billing period. They send an email and never pause
anything. To create one: Manage Account → Billing → Billable Usage → **Create budget alert**, with
a name, a threshold in USD, and recipients. Recommended:

1. a first alert at a low threshold, for example $5 of usage-based spend: the $5 subscription is
   expected, so this catches the first overage;
2. a second, emergency alert at a higher threshold, for example $25.

Per-product usage notifications (requests, CPU) are under Notifications and are optional. No other
paid product was enabled for this.

Free limits, for reference only. Workers Free is not a supported configuration:

| Limit (Free) | Value | What this deployment does |
| --- | --- | --- |
| Worker requests | 100,000/day | Static assets do not count. Each API call is one request. |
| CPU per request | 10 ms, with "some built-in flexibility" for infrequent overruns ([limits](https://developers.cloudflare.com/workers/platform/limits/)) | **Not met**: median 28 ms (above). Heavy work happens at import time, in the snapshot, but a typical request still needs more than 10 ms in Pyodide. |
| Memory per isolate | 128 MB (all plans) | 93.8 MiB of WASM memory after import. The deploy-time snapshot must stay under 128 MiB, and the first deploy, at 129.3 MiB, was refused (10021). |
| Worker size | 64 MiB uncompressed | The store image is bundled gzipped (~4 MB). |
| D1 queries per invocation | 50 | 1 per request (identity). The schema check adds 1 once per isolate. |
| D1 rows read | 5,000,000/day | ~10 per request (identity), ~180 once per isolate (schema). |
| D1 rows written | 100,000/day, counting each index entry ([pricing](https://developers.cloudflare.com/d1/platform/pricing/)) | 0 at runtime (read-only). The bootstrap needs two days on Free (below). On Paid there is no daily cap, so both phases ran on 2026-10-12. |
| D1 storage | 500 MB per database, 5 GB total | 23.1 MB after the bootstrap (32 tables). |
| D1 statement size | 100 KB | The largest export statement is 2.7 KB. |
| Static assets | free and unlimited | The UI. |
| Workers Logs | 200,000 events/day, 3-day retention (from 2026-12-01: 0.5 GB/day, 7 days) | One line per API request. |

No deployment command asked for a plan change. The upgrade was the owner's decision, made in the dashboard.

## Bootstrap (operator only, never over HTTP)

The demo store is created by the demo runtime's own reset and imported into D1 by the
operator with wrangler. **There is no bootstrap or reset endpoint and no bootstrap secret.**
The Worker cannot write to D1 at all: it only reads the identity and schema.

1. **Build.** `pwsh scripts/cloudflare-demo.ps1 -Build` (`python -m app.cloudflare build`):
   - runs `reset_demo_store` (the guarded reset and the configured dataset's deterministic seed;
     Genesee Press since SYNTH-OGWA-01) into
     `cloudflare/build/var/`;
   - builds `HostedDemo` from that store exactly as the Worker will (`validate_demo_store`,
     pinned to the seed's audit head);
   - writes the D1 import phases to `cloudflare/build/d1/` (`phase-N.sql`, `plan.json`), and
     stages the Worker: `src/app`, `src/config`, the gzipped store image, the build manifest
     `hosted-build.json`, and `public/` with `_headers`.

   The build is deterministic: two builds produce byte-identical phase files.
2. **Create D1** (once): `npx wrangler d1 create ogwa-demo`, and record the id in
   `cloudflare/worker/wrangler.jsonc`.
3. **Import, one phase at a time.** Run `pwsh scripts/cloudflare-demo.ps1 -Bootstrap
   -ConfirmSyntheticBootstrap` once per phase. On Workers Paid, all phases may run the same day.
   The split was sized for D1 Free's daily write quota and does no harm. The Genesee Press build
   has **three** phases (rows written into `ogwa-demo-3`: 83,651, 63,844 and 32,000); the table
   below is the earlier two-phase Null Meridian build.

   D1 Free counts each index entry as a written row, and allows 100,000 a day. The complete Null
   Meridian store needs ~174,000, so the import is split:

   | Phase | Contents | Rows written (measured) |
   | --- | --- | --- |
   | 1 | every table, every row (parents first), and every index except the three on `synthetic_directory_records` | 79,906 |
   | 2 | the three directory-record indexes and every trigger | 93,885 |

   Before importing, the script reads D1's schema objects. `next-phase` then names the due
   phase, refuses a D1 that matches no completed phase ("not this build's import"), and says
   `complete` when done. Triggers are created after all rows, so none fires during the import.
   Until the last phase is in, a Worker bound to that D1 answers 503.
4. **Verify**: `pwsh scripts/cloudflare-demo.ps1 -Verify`.

**Disabling the bootstrap after use.** Nothing needs disabling. The bootstrap is an operator
command with wrangler access to the account, so it is never deployed and never public. The
deployed Worker has no write path to D1. The hosted store is `query_only`, and every persisting
route answers `DEMO_READ_ONLY`.

### Genesee Press cutover (SYNTH-HOSTED-CUTOVER-MAC-01, SYNTH-OGWA-HOSTED-RETRY-01; done 2026-10-29)

The hosted demo serves Genesee Press from D1 `ogwa-demo-3`. The build seeds audit head
`sha256:f11f0a99…d4b39f` (1,617 events, 11 lifecycle candidates, 31,921 directory records) in **three**
phases. Records of each step are in `40ozs/synthetic-enterprise` (`docs/demo/reports/`).

- **Deployment repository.** The Worker is built and deployed from a checkout of `40ozs/ogwa-demo`
  `main`, the sanitized release that synthetic-enterprise's exporter makes from a commit of this
  repository (its `demo-release.json` names that commit). Run `-Build`, `-Bootstrap`, `-Verify` and
  `-Deploy` there, not from this repository.
- **Import and verify before activation.** A new database is fully imported (`-Bootstrap
  -ConfirmSyntheticBootstrap` once per phase, until `next-phase` says `complete`) and passes `-Verify`
  before any Worker bound to it is deployed. Only then is `ogwa-demo` `main` advanced and `-Deploy`
  run, followed by `python scripts/hosted_smoke.py <url>` (61/61).
- **Rollback assets.** `ogwa-demo-2` (Null Meridian) and `ogwa-demo` stay untouched. The previous Worker
  version, bound to `ogwa-demo-2`, is the rollback (see "Rollback"). Deleting any of them is a separate
  owner decision.

## Hosted verify

`pwsh scripts/cloudflare-demo.ps1 -Verify` runs `wrangler d1 export ogwa-demo-3 --remote` and then
`python -m app.cloudflare verify-export`. The export is loaded into a throw-away SQLite store,
which then goes through `open_demo_store`, the same validation as `python -m app.runtime verify`:

- `validate_demo_store`: the SYNTHETIC marker, exactly one `SYNTHETIC_SEED_LOADED` with namespace
  `genesee-press-v1`, dataset `genesee-press`, company Genesee Press, and the 0012 snapshot's
  identity and digest;
- `verify_integrity`, pinned to the build's audit head.

It then checks D1's identity and schema digest against the build manifest. No integrity
algorithm is re-implemented, and nothing kept from an earlier run is reused: `verify_integrity`
always verifies in full.

D1 is unavailable while an export runs, and the Worker answers 503 meanwhile. The export reads
every row (~45,000 rows read), so run it when needed rather than on a schedule.

## Deploy

`pwsh scripts/cloudflare-demo.ps1 -Deploy` runs `uvx --from workers-py pywrangler deploy` in
`cloudflare/worker`, from the `40ozs/ogwa-demo` `main` checkout (see "Genesee Press cutover").
Merging this repository's `main` deploys nothing. `pywrangler` vendors only Cloudflare's runtime
SDK; OGWA has no Python dependency. Before deploying, confirm the gates in "Validation" below.

Local rehearsal: build, then import the phases into a local D1 and run `uv run pywrangler dev`
(`wrangler d1 execute ogwa-demo --local --persist-to DIR --file cloudflare/build/d1/phase-N.sql`,
then `pywrangler dev --persist-to DIR`). The browser suite runs against it with
`UI_BROWSER_TARGET=http://127.0.0.1:8787` (below).

## Public access and mutation posture

The Worker is public, with no Cloudflare Access. OGWA's own authorization applies unchanged:

- **No sign-in (OGWA-DEMO-HOSTED-ANON-01).** A visitor opens the URL, or any link into it, and
  is in the console. `GET /api/v1/session` gives a visitor without a session a new one for the
  synthetic, anonymous **public visitor** (`public.visitor`, method `anonymous-public-demo`). Its
  role comes from the role bindings like any other: VIEWER (`READ_INVENTORY`) and nothing else.
  `POST /api/v1/session` answers 403 `PUBLIC_DEMO_NO_SIGN_IN`, so no visitor can choose a
  principal, and the Worker accepts no cookie but the visitor's (`VisitorSessions`): one signed
  for another principal before this change is refused like a forged one. The UI never shows the
  sign-in form here; if a session is lost or expires, it starts a new one and opens the requested
  page. Data routes still need the cookie, so a client without one gets 401 until it calls
  `GET /session`. A drill sent with a lapsed session, or with a CSRF token another tab has
  replaced, is refused before it runs (`401`, `403 CSRF_FAILED`); the UI then takes the new
  visitor session and sends it once more.
- **The GP-C11 drill.** The visitor may run the synthetic remediation drill on the walkthrough's
  controlled-remediation candidate (GP-C11 in Genesee Press, NM-C11 in Null Meridian; marked
  `publicDrill`) and on no other: anything else is
  403 `PUBLIC_DRILL_SCOPE` before the drill service is reached. For that one request, on that one
  candidate, it holds the executor's role; the session keeps VIEWER. Every other drill check is
  unchanged (the approval must be this candidate's, the evidence fresh, the scenario from the
  catalog). The visitor cannot read the audit trail or `/system/*`; the dashboard shows the audit
  event count and head.
- **The session** is a signed cookie (`__Host-`, Secure, HttpOnly, SameSite=Strict, Max-Age=900):
  it cannot be forged or altered without `HOSTED_SESSION_KEY`. It expires after 15 minutes
  without use, or 8 hours after it began, whichever comes first. While the session is in use, a
  response renews the cookie at most once a minute: the same session and CSRF token, with a fresh
  15 minutes. A renewal never extends the 8 hours.
- **Read-only shared state.** In OGWA's own code, a demo over a read-only store refuses every
  `POST` that would record something with 403 `DEMO_READ_ONLY` (`app.runtime.api`):
  - transitions and approvals;
  - mapping selections, approvals, and rejections;
  - job plans and remediation dry runs.

  Any visitor gets that explanation, not a bare 403 for a role it lacks. What still runs records
  nothing (`NON_PERSISTING`): sign-out, the GP-C11 drill, and mapping inspection and AD search,
  which need a mapping role no visitor has. Execution stays refused (`DEMO_MODE_BLOCKED`).
- **Two layers, both fail-closed.** The route policy refuses persisting requests, and SQLite
  refuses any write (`query_only`).
- **Refusals are logged, not chained.** On a read-only store a refused governed request is
  logged as `api.refusal_not_chained`. It cannot be appended to the audit chain, by design:
  appending would change the shared store.
- **Visitors cannot change anything** in D1 or in the served store. No reset is ever needed,
  and nothing drifts.

## Production isolation

The Worker runs the demo profile: `load_settings` refuses live-integration settings and
production credential variables (`OGWA_OKTA_*`, `OGWA_AAP_*`, `OKTA_API_TOKEN`,
`LDAP_BIND_PASSWORD`, …). It is applied twice:

- to the build's environment, at import time;
- to the Worker's real variables and secrets, before the first request of each isolate. A
  mismatch or a refused setting makes the Worker answer 503.

The demo providers are synthetic: `SyntheticOktaProvider`, `DisabledAapProvider`, and the
synthetic AD mapping gateway. No network fallback exists, and the Worker glue makes no outbound
call (pinned by `tests/test_cloudflare_worker_config.py`). Python Workers cannot start
processes; the demo path never tries (`no_live_system` spies, `tests/test_cloudflare_hosted.py`).

## Logs

`observability.enabled` turns on Workers Logs. OGWA's JSON log lines are redacted, as locally,
and never include a secret or a cookie. Search them in the dashboard (Workers & Pages →
`ogwa-demo` → Logs) or follow them with `npx wrangler tail ogwa-demo`.

| Event | Meaning |
| --- | --- |
| `api.request` | one line per API request: route, status, principal, elapsed ms |
| `api.internal_error`, `api.integrity_failure` | an unexpected exception, or stored records failing verification (500) |
| `api.refusal_not_chained` | a refused governed request on the read-only store |
| `hosted.d1_identity_mismatch`, `hosted.d1_unavailable`, `hosted.d1_identity_unreadable` | D1 does not hold the served store (503) |
| `hosted.d1_schema_mismatch` | D1's schema is incomplete or foreign, for example during the bootstrap (503) |
| `hosted.environment_refused`, `hosted.environment_mismatch` | the Worker's variables or secrets fail the demo profile (503) |
| `hosted.session_key_unusable` | `HOSTED_SESSION_KEY` is missing or shorter than 64 hex digits (503); the log names the secret, never its value |
| `hosted.request_failed` | a D1 error or other exception in the Worker glue (503) |
| `hosted.unavailable` | a 503 answer, with its request id |

A failed import-time validation fails the deploy itself: `pywrangler deploy` reports the error.
A request stopped by the CPU cap writes no OGWA line. `wrangler tail` shows its outcome as
`exceededCpu`, and the analytics count it under a status other than `success`.
CPU per request is in the dashboard's metrics, and in Cloudflare's GraphQL analytics
(`workersInvocationsAdaptive`).

## Rollback

These steps keep D1 and all evidence intact:

- **Previous Worker version:** `npx wrangler versions list --name ogwa-demo`, then
  `npx wrangler rollback <version-id> --name ogwa-demo`. D1 is not touched by a rollback.
  To undo the Genesee Press cutover (live version `a4bd4702-d356-4459-904e-855145c3a2fc`, D1 `ogwa-demo-3`):
  `npx wrangler rollback c6c2036a-0e01-45b2-86b0-9b0e5882715d --name ogwa-demo`, the previous Null Meridian
  version on `ogwa-demo-2`, without sign-in.
  To undo OGWA-DEMO-DEPLOY-03: `npx wrangler rollback 25af5127-d3bd-4666-a297-93c5b18aa0d3 --name ogwa-demo`.
  A version carries its own bindings, so this restores the old Worker bound to the untouched `ogwa-demo`.
  To undo OGWA-DEMO-HOSTED-ANON-01 (live version `1b5f5691-1a68-4880-9229-e2e7c06c5cea`, same D1): `npx wrangler rollback dd5048d2-c551-414a-bbfa-fdc55309ce23 --name ogwa-demo`, which brings back the synthetic sign-in screen.
  `06949d69-…` is the version before the CPU cap and the session idle timeout
  (OGWA-CLOUDFLARE-COST-GUARD-02). Rolling back to it keeps current sessions. Rolling forward
  again signs out sessions it issued, once.
- **Raise or remove only the CPU cap:** change or delete `limits` in `wrangler.jsonc` and deploy.
  Without it, requests get Paid's default of 30 s. The previous cap was 5,000 ms (version `9b571578`).
- **Workers Free is not a rollback target.** On Free the demo exceeds the CPU limit.
- **Take the demo offline:** set `"workers_dev": false` in `wrangler.jsonc` and deploy, or
  turn off the workers.dev route in the dashboard. Static assets and the API stop being served.
  Re-enable by reverting.
- **Delete the Worker** (`npx wrangler delete --name ogwa-demo`): only on an owner decision. D1 stays.

**Deleting D1 is a separate, destructive action.** It needs an explicit owner decision:
`npx wrangler d1 delete ogwa-demo`. D1 Time Travel (30 days on Workers Paid) can restore a D1 database to
an earlier point (`npx wrangler d1 time-travel restore`).

## Future migrations

The D1 schema is never edited by hand and never derived separately. It is always the schema
the canonical migrations (`app/store/migrations/`) create, carried over verbatim.

When a migration is added, or the dataset changes:

1. Build again. The demo reset creates a store at the new schema version.
2. Create a new D1 database, or delete the old one on an owner decision.
3. Bootstrap the new phases (one per UTC day).
4. Verify, then deploy.

The Worker refuses to serve until D1 holds the new store. Because the demo store is
deterministic and visitors never change it, re-creating it loses nothing.

**A dataset change cannot be bootstrapped into the existing database** (OGWA-DEMO-DEPLOY-01).
`next-phase` compares schema objects, not rows. When only the data changed, as with OGWA-DEMO-04
(schema 12 and digest `e1cebad6…0213` unchanged; audit head `cc90d367…0ac6` → `e8793f89…eb41`),
it reads the old database as `complete`, and `-Bootstrap` prints "Nothing to import". A Worker
deployed onto that database answers 503 for every API request (`hosted.d1_identity_mismatch`),
and the old Worker does the same on a new store: both directions fail closed. So step 2 is not
optional. A new database, bootstrapped while the current Worker still serves the old one and
switched in by the deploy, avoids the outage and keeps a rollback consistent (old version, old
database). It needs its name in `wrangler.jsonc`, `scripts/cloudflare-demo.ps1`, and
`tests/test_cloudflare_worker_config.py`. Deleting and re-creating `ogwa-demo` keeps the name
and needs only the new id, but the demo is down from the deletion until the deploy.

`wrangler d1 migrations` is not used: replaying migration SQL against D1 would need a second
copy of the schema's history, and the store's own `schema_migrations` table already records
it, with checksums that `verify_applied` checks on every open.

## Validation

| Gate | Command |
| --- | --- |
| Unit tests, including the Cloudflare tests | `python -m unittest discover -s tests -t .` (`tests/test_cloudflare_*.py`) |
| Hosted smoke (61 checks over real HTTPS, all as the anonymous visitor: no sign-in, a viewer's permissions only, read-only refusals, a synthetic remediation drill on GP-C11 that must record nothing, its policy/decision/approval chain, verification before the retry under one operation id, the dry-run boundary, GP-C10 staying non-actionable and refusing GP-C11's drill grant, the public walkthrough, and the dashboard's audit head; OGWA-DEMO-HOSTED-ANON-01) | `python scripts/hosted_smoke.py https://ogwa-demo.d-walkes.workers.dev` |
| CPU per route | `npx wrangler tail ogwa-demo --format json` while the routes are exercised. Every outcome must be `ok`, and `cpuTime` must stay well under `limits.cpu_ms` |
| Browser gate, local | `pwsh scripts/browser-check.ps1`, which includes `tests.browser.test_hosted_demo_ui` over `HostedDemoServer`, the Worker's own application on loopback |
| Browser gate against the Worker | `UI_BROWSER_TESTS=1 UI_BROWSER_TARGET=<origin> python -m unittest tests.browser.test_demo_null_meridian_ui tests.browser.test_null_meridian_views tests.browser.test_hosted_demo_ui tests.browser.test_ui_ia tests.browser.test_candidate_tables tests.browser.test_remediation_drill_ui -v` (NM-C10, NM-C11's drill, and the walkthrough address candidates by this build's seeded ids, so a stale Worker fails them) |
| Wrangler config | `npx wrangler deploy --dry-run` in `cloudflare/worker` |
| Hosted D1 | `pwsh scripts/cloudflare-demo.ps1 -Verify` |

`UI_BROWSER_TARGET` points the browser at an already-serving demo. The browser can then resolve
that one host besides `127.0.0.1`, and nothing else. On macOS, also set `UI_BROWSER` to Chrome's
binary (`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`); otherwise every browser
test skips. `test_operator_workflows` exercises the
classic world and recorded decisions, which the hosted demo does not serve, so it skips there and
stays in the local gate.

## Known limitations

- **Signed sessions cannot be revoked everywhere.** Signing out deletes the browser's cookie, so
  the signed-out browser is signed out (and gets a new anonymous session on its next page), and the isolate that handled the sign-out refuses the
  token afterwards. A copy of the token made before sign-out still works in other isolates: 6 of
  6 tries were accepted on 2026-10-12. The copy works until it goes 15 minutes unused, or, if
  someone keeps using it, until 8 hours after sign-in. Global revocation would need shared
  server-side state (KV or a Durable Object), which this demo does not use. Data is synthetic and
  read-only, so the exposure is a visitor's own synthetic session. Rotating `HOSTED_SESSION_KEY`
  (`wrangler secret put`) signs everyone out.
- **The demo clock starts per isolate.** Each isolate starts its clock just after the newest
  audit event, as a local demo server does at start.
- **No approval can complete in Null Meridian.** The dataset's evidence is a week old at the demo
  clock, so the freshness gate refuses an approval, as OGWA-DEMO-INTEGRATION-01 recorded.
  The hosted demo refuses every recorded decision anyway (`DEMO_READ_ONLY`).
- **`GET /system/integrity` reports the import-time verification.** In the hosted demo it serves
  the full verification the Worker ran when it loaded the store, pinned to the build's audit head.
  It does not run a new one on each call (see "Architecture"). A fresh full check of D1 is the
  hosted verify. Since OGWA-DEMO-HOSTED-ANON-01 no visitor holds `READ_SYSTEM`, so the public demo
  never serves it; the tests reach it with a session they mint themselves.
- **Workers Paid is required:** $5 a month, plus usage-based overage. At a median of 28 ms of CPU
  per request, the demo cannot run on Workers Free. Spend has no hard cap. The CPU cap bounds each
  request, and a budget alert is the owner's signal (see "Plan and limits").
- **D1 is checked by identity on each request, not row by row.** The identity covers the audit
  head, and so every audited write, plus the marker and the snapshot digest. A full check is the
  hosted verify.
