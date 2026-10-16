# Demo Mode

Demo Mode is the only runtime of this build. It runs **the real OGWA application** (the
same UI, API, read model, correlation engine, candidate classification, lifecycle,
approvals, audit chain, governance views, and remediation dry runs) over a **deterministic
synthetic dataset**. The build includes no Okta, Active Directory, or AAP client and no
outbound HTTP client, so there is no live system for it to reach. The application is real.
The organization and its identities are fictional.

There is no separate demo application, API, or UI.

| | What it is | Where |
| --- | --- | --- |
| **Demo Mode** | The runtime and safety boundary: the runtime mode, the provider boundary, the isolated demo store, the demo mutation policy, the UI indicator | `app/runtime/`, this document |
| **Null Meridian** | The canonical synthetic dataset Demo Mode serves by default: a fictional 1,800-person company with ten years of identity history | `app/demo/null_meridian/`, [demo/null-meridian.md](demo/null-meridian.md) |

Demo Mode owns no data. Null Meridian owns no runtime policy. They meet in one place: the
dataset registry `app/demo/datasets.py`.

## Canonical commands

```sh
python -m app                                                       # validate configuration and print the startup banner
python -m app.runtime reset-demo --confirm-synthetic-reset          # create or reseed the demo store, validated
python -m app.runtime verify                                        # re-validate the demo store at any time
python -m app.runtime verify --expected-audit-head sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41
                                                                    # ...and pin it to the canonical seed (right after a reset)
python -m app.api serve                                             # start the demo: http://127.0.0.1:8765/
python -m app.runtime status                                        # runtime, selected dataset, availability, store presence
```

No environment variable is required. The dataset defaults to `null-meridian`.

Tests: `python -m unittest discover -s tests -t .` (the full suite), and
`UI_BROWSER_TESTS=1 python -m unittest tests.browser.test_operator_workflows
tests.browser.test_null_meridian_views tests.browser.test_demo_null_meridian_ui` (the opt-in
browser gate; `UI_BROWSER` names the browser executable if Chrome or Edge is not in a
standard place). The focused Demo Mode set is listed in "Validating isolation" below.

## Runtime mode

The runtime mode is always `demo`, and the [execution mode](security/execution-modes.md) is
always `LOCAL_SYNTHETIC`. `Settings` has no field that could hold another mode or a
credential. Configuration is read from the process environment only. No API route, UI
control, or request can change it.

`OGWA_RUNTIME_MODE` may be left unset or set to `demo`. Any other value refuses startup with
"This public build supports Demo Mode only. Live integrations are unavailable." It never
falls back to another mode.

Code: `app/core/runtime_mode.py` (the `RuntimeMode` enum and parser) and
`app/core/config.py` (validation).

### What `demo` requires and refuses (startup validation)

Every setting is optional:

| Setting | Accepted values |
| --- | --- |
| `OGWA_RUNTIME_MODE` | Unset or `demo`. |
| `OGWA_EXECUTION_MODE` | Unset or `LOCAL_SYNTHETIC`. `PRODUCTION_MUTATION` raises `ProductionMutationNotPermitted`; any other value refuses startup. |
| `OGWA_DEMO_DATASET` | A dataset **selector** from the registry: `null-meridian` (the default) or `classic`. An unknown selector is refused; a seed namespace given as a selector (`null-meridian-v1`) is refused with the selector that names it. |
| `OGWA_LOG_LEVEL` | `DEBUG`, `INFO` (the default), `WARNING`, or `ERROR`. |
| `OGWA_DATABASE_URL` | Defaults to `sqlite:///var/ogwa-demo.sqlite3`. It must name a file, not `:memory:`. |

Startup also refuses, with the same demo-only message:

- the live-integration keys `OGWA_OKTA_ORG_URL`, `OGWA_OKTA_API_TOKEN`, `OGWA_AAP_URL`,
  `OGWA_AAP_TOKEN`, and `OGWA_HTTP_*`: the build has no integration for them to configure;
- any other `OGWA_*` key, so a typo or an attempted override cannot change behaviour;
- credential variables of other Okta, AAP/AWX, and AD tooling (`OKTA_API_TOKEN`,
  `OKTA_CLIENT_TOKEN`, `OKTA_CLIENT_SECRET`, `OKTA_CLIENT_PRIVATEKEY`, `OKTA_PRIVATE_KEY`,
  `CONTROLLER_PASSWORD`, `CONTROLLER_OAUTH_TOKEN`, `TOWER_PASSWORD`, `TOWER_OAUTH_TOKEN`,
  `AAP_TOKEN`, `AD_BIND_PASSWORD`, `LDAP_BIND_PASSWORD`). OGWA never reads them; their
  presence means production credentials reached a demo process.

Errors name the variable, never its value. The demo store must also exist and hold exactly
the configured dataset ([below](#demo-persistence-and-store-identity)). No Okta token, AAP
token, or AD credential is needed or accepted.

## Provider boundary

OGWA's shared logic reads only from the store. `app/runtime/providers.py`
(`select_providers`) is the one place where the providers that stand in for live systems
are chosen, and every one of them is synthetic:

| Role | Provider |
| --- | --- |
| Okta | `SyntheticOktaProvider`: store reads of the seeded dataset |
| AD directory (mapping review) | `SyntheticMappingGateway`: a synthetic AD directory over the dataset's AD evidence |
| Remediation | The synthetic allowlist, restricted to the `SYNTHETIC` adapter. An allowlist naming any other adapter stops the build (`DemoModeBlocked`). |

`select_providers` also refuses a store that is not marked `SYNTHETIC` or not opened in
`LOCAL_SYNTHETIC`. There is no live provider to select. Business logic contains no
runtime-mode checks.

## Synthetic-data integration: the dataset registry

Demo Mode generates no data and keeps no registry of its own. The one registry is
`app/demo/datasets.py` (`dataset(key)`, `DATASET_KEYS`, `DEFAULT_DATASET`, `dataset_of(store)`),
owned by the synthetic-data implementation. It is shared by the guarded store reset, the
API's policy and correlation configuration, and Demo Mode. `app/runtime/datasets.py` is
Demo Mode's thin adapter over it:

```text
OGWA_DEMO_DATASET (selector)
   -> app.runtime.datasets.resolve_dataset        (Demo Mode's adapter: metadata, fail closed)
   -> app.demo.datasets.dataset(selector)         (the registry)
   -> the implementation's own seed and profile
```

| Selector (`OGWA_DEMO_DATASET`) | Seed namespace (audit identity) | Seed function | Canonical metadata read from |
| --- | --- | --- | --- |
| `null-meridian` (default) | `null-meridian-v1` | `app.demo.null_meridian.world.create_null_meridian_store` | `app.demo.null_meridian.profile` (`COMPANY`, `PRIMARY_DOMAIN`, `SNAPSHOT_DATE`, `SEED`, `DATASET_KEY`) |
| `classic` | `ogwa-synthetic-demo-v1` | `app.demo.synthetic_world.create_seeded_store` | `app.demo.synthetic_world` (`COMPANY`, `CORP.dns`, `AS_OF`, `SEED_NAMESPACE`) |

- **The selector** chooses a dataset. It is the registry's key, so the operator, the store
  CLI, the registry, and the 0012 directory snapshot all use the same word.
- **The seed namespace** is the dataset's canonical audit identity: what its seed records in
  the store's single `SYNTHETIC_SEED_LOADED` audit event (and, for Null Meridian, in the
  snapshot's `seed` column). It is never renamed. `/health` reports it as `dataset.seed`.
- `_null_meridian()` imports the seed function from `app.demo.null_meridian.world`, reads
  the metadata from `app.demo.null_meridian.profile`, and checks that the registry binds the
  same function and namespace. It holds no Null Meridian value and duplicates no generator
  logic.
- `classic` is the 16-scenario lifecycle world. It is selected only explicitly; the Demo Mode
  test suite uses it because it covers every lifecycle state.
- **No fallback.** A selector that is unknown, or whose implementation is not in the build,
  is `DatasetUnavailable`, naming the dependency. Nothing is ever served or seeded in its
  place: with Null Meridian missing, the demo refuses to start even if a classic store is at
  the configured path (`tests/test_null_meridian_demo.py`).

The Null Meridian generation rules, counts, correlation cases, governance findings, and
lifecycle candidates are specified in [demo/null-meridian.md](demo/null-meridian.md) and its
manifest. They are not repeated here, and Demo Mode does not restate them: its tests compare
what the demo serves with the dataset's own manifest, generator, and seed expectations.

## Demo persistence and store identity

The demo store is its own SQLite file (`var/ogwa-demo.sqlite3` by default), with OGWA's full
schema, migrations (including 0012, the synthetic directory snapshot), and store code.
`app/runtime/demo_store.py` handles it.

- **Opening** reads the environment marker read-only first, so a non-`SYNTHETIC` file is
  never opened for writing, then runs `verify_integrity` (migrations, audit chain, evidence
  digests, candidate histories, mapping reviews, policy versions, and the 0012 snapshot's
  content digest, which the seed's audit event must vouch for).
- A store is accepted for a dataset only when **every piece of identity evidence agrees**:

  | Evidence | Null Meridian (`null-meridian`) | Classic (`classic`) |
  | --- | --- | --- |
  | Environment marker | `SYNTHETIC` | `SYNTHETIC` |
  | `SYNTHETIC_SEED_LOADED` audit events | exactly one, namespace `null-meridian-v1` | exactly one, namespace `ogwa-synthetic-demo-v1` |
  | Dataset the registry reads from the store (`dataset_of`) | `null-meridian` (the 0012 snapshot is present) | `classic` (no snapshot) |
  | 0012 snapshot | dataset `null-meridian`, seed `null-meridian-v1`, company `Null Meridian` | none |
  | Seed event's directory fields | `directory_dataset`, `directory_digest`, `directory_records` equal the snapshot's | none |
  | Integrity verification | passes | passes |

  The two mechanisms reinforce each other: the audit chain vouches for the snapshot's
  digest, and the snapshot names the dataset the audit event's namespace belongs to.
  Dataset identity needs no migration of its own.
- A missing demo store is a startup failure, never a new empty store. An unmarked file, a
  `PRODUCTION` or `DEVELOPMENT` store, a store of the other dataset, a store whose seed
  namespace has no matching snapshot, and a tampered snapshot are all refused.

## Seed and reset

There is **one reset command for the demo store**:

```sh
python -m app.runtime reset-demo --confirm-synthetic-reset
```

It takes the dataset from `OGWA_DEMO_DATASET` (there is no `--dataset` flag, so the store
and the server always agree), and it is a guard around the one guarded reset,
`app.store.reset.reset_synthetic_store`:

1. it refuses any existing file not marked `SYNTHETIC`;
2. the guarded reset applies its own checks (`LOCAL_SYNTHETIC`, a file under `var/`, an
   existing file marked `SYNTHETIC` or `DEVELOPMENT` that holds no real evidence, explicit
   confirmation, a registered dataset), deletes the file, and runs the dataset's own seed
   from the registry: for Null Meridian, `create_null_meridian_store`;
3. it validates the result as opening does (the `SYNTHETIC_SEED_LOADED` event, its namespace,
   the snapshot, integrity), pinning the audit head the seed reported.

It is deterministic: every reset gives byte-identical tables and the dataset's pinned
canonical audit head, for Null Meridian
`sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41`
([operations/audit-anchors.md](operations/audit-anchors.md)).

## Mutation policy

OGWA has no route that changes Okta, AD, or AAP. Remediation is dry-run only, and the
execute route always refuses ([mutation-gates.md](security/mutation-gates.md)). The demo
classifies every `POST` route of the API. The table is
`app.runtime.api.DEMO_MUTATION_POLICY`. An unclassified `POST` route stops the demo build,
so a route added later cannot reach the demo unreviewed.

| Class | Routes | In the demo |
| --- | --- | --- |
| `SESSION` | `POST /session`, `POST /session/logout` | Synthetic sign-in and sign-out (the public demo has no sign-in: see below) |
| `LOCAL` | `POST /candidates/{id}/transitions`, `/candidates/{id}/approvals`, `/mappings/{id}/inspection`, `/mappings/{id}/searches`, `/mappings/{id}/selections`, `/mappings/{id}/approvals`, `/mappings/{id}/rejections` | Run normally against the demo store. A successful response carries `"demo": {"classification": "LOCAL", "notice": "Recorded in the demo store only — …", "externalSystemsContacted": false}`. |
| `SIMULATED` | `POST /candidates/{id}/execution-jobs` (dry-run plan), `POST /candidates/{id}/remediation-dry-runs` (the `SYNTHETIC` adapter answers `SIMULATED`), `POST /candidates/{id}/remediation-drills` (a dry run or synthetic execution against an in-memory provider fixture, which records nothing) | Run normally. A successful response carries `"demo": {"classification": "SIMULATED", "notice": "Simulation only — no Okta tenant was modified.", "externalSystemsContacted": false}`. |
| `BLOCKED` | `POST /execution-jobs/{jobId}/execute` | Answers 403 `DEMO_MODE_BLOCKED` ("Execution is blocked in the demo environment. …") before the lifecycle service is reached. The refusal is chained as `GOVERNED_REQUEST_REFUSED` in the demo store's audit log. |

**Read-only demos.** Over a read-only demo store (the public hosted demo,
[deployment/cloudflare-demo.md](deployment/cloudflare-demo.md)), `demo_routes(..., read_only=True)`
refuses every `POST` above that would record something with 403 `DEMO_READ_ONLY`, to any
visitor. Only `NON_PERSISTING` routes stay open: sign-out, mapping inspection, AD search, and the
remediation drill, which record nothing; their notice says "nothing was recorded". The
execute route keeps its own refusal. A refused governed request is logged
(`api.refusal_not_chained`), not chained: the store cannot change. `build_demo_application`
picks the read-only policy whenever the store is read-only (`Store.read_only`), so the two
cannot disagree.

**The public demo is anonymous.** A read-only demo has no sign-in: `GET /session` starts a
session for the synthetic, anonymous public visitor (`public.visitor`, VIEWER, from the role
bindings), and `POST /session` answers `PUBLIC_DEMO_NO_SIGN_IN`, so no visitor can choose a
principal. Every refusing route answers any visitor with its own explanation (`DEMO_READ_ONLY`,
`DEMO_MODE_BLOCKED`). The visitor may run the synthetic drill on NM-C11 only
(`PUBLIC_DRILL_SCOPE` elsewhere), holding the executor's role for that request alone.
`/health` says `publicDemo: true`, the indicator reads "Public synthetic demo · no live
integrations", and the walkthrough names no synthetic principal. The local demo keeps its
synthetic sign-in.

Enforcement is in the backend: the route table the demo API is built with, the providers,
and the remediation allowlist. The local demo changes no route's access rule (public,
session, permission) (`tests/test_demo_mode.py`, `DemoMutationPolicyTests`); the read-only
public demo changes only the ones above (`tests/test_cloudflare_hosted.py`,
`ReadOnlyRoutePolicyTests`).

Null Meridian's views use read routes only (`GET /directory`, `/people`, `/people/{personId}`,
`/directory-groups`, `/directory-groups/{directoryGroupId}`, `/governance-findings`,
`/demo-scenarios`). They read only the 0012 snapshot (a test pins that `app/api/directory.py`
only selects), reach the demo unwrapped, and keep their permission checks. The policy table
covers every `POST` route of the API exactly (`tests/test_null_meridian_demo.py`).
`/demo-scenarios` lists the dataset's portfolio scenarios; despite its name it neither reads
nor changes the runtime mode.

## UI indicator and runtime metadata

- `GET /api/v1/health` (public) answers `{"status": "ok", "runtimeMode": "demo",
  "dataSource": "synthetic", "organization": …, "dataset": {"key", "companyName",
  "primaryDomain", "snapshotDate", "seed", "synthetic": true}, "liveIntegrations": false,
  "publicDemo": false}` (`true` on the read-only public demo).
  It carries no path, host, or credential.
- `GET /api/v1/dashboard` also carries that block as `runtime`.
- Every response (API and UI files) carries `X-OGWA-Runtime-Mode: demo`.
- The UI shows a small persistent **DEMO ENVIRONMENT · Synthetic data** pill in the header,
  before and after sign-in. Expanding it explains: "This environment uses deterministic
  synthetic data for <organization>. No production Okta tenant is connected. The OGWA
  application is real; the organization and its identities are fictional." The
  organization comes from `/health`; the UI holds no dataset name (`js/runtime.js`). The
  pill stays hidden until `/health` reports the demo runtime.
- Expanded, the explanation takes its own row of the header and pushes the navigation down;
  it never overlays a navigation link, at desktop or phone width
  (`tests/browser/test_demo_null_meridian_ui.py`). Null Meridian's views (company directory,
  portfolio scenarios, governance findings, people, person access paths, directory groups)
  are in the same navigation as every other view.

## Running locally

```sh
python -m app.runtime reset-demo --confirm-synthetic-reset
python -m app.api serve
# open http://127.0.0.1:8765/ and sign in as any synthetic principal, e.g. synthetic.securityiam.one
```

`serve` binds 127.0.0.1 by default and takes `--port` (default 8765) and `--host`
(`127.0.0.1` or `0.0.0.0`, the latter for a container). The demo always starts its clock
just after the store's newest audit event, so the synthetic evidence is as fresh as the
dataset made it. Null Meridian's evidence is a collection taken a week before its snapshot,
so a step that needs fresher evidence (an approval) is refused by the real lifecycle gate
until the evidence is re-observed. `OGWA_DEMO_DATASET=classic` serves the 16-scenario
lifecycle world instead (reset it with the same command).

## Run it in Docker

`docker compose up --build` builds the image, seeds the demo store on first start, and
serves the demo at http://localhost:8765. See the README's
[Docker quick start](../README.md#quick-start-with-docker).

## Validating isolation

```sh
python -m unittest tests.test_runtime_mode tests.test_demo_providers tests.test_demo_mode \
  tests.test_ui_runtime tests.test_null_meridian_demo
UI_BROWSER_TESTS=1 python -m unittest tests.browser.test_demo_null_meridian_ui
```

These prove the following:

- only the demo runtime and the synthetic providers exist, and every attempt to select
  another runtime or execution mode fails startup;
- the demo needs no credential, and refuses live settings and foreign credential variables
  without echoing their values;
- building and using the demo (health, dashboard, every inventory listing, correlation
  inspection, AD search, an approval, a remediation dry run) makes no socket connection,
  starts no process, opens no URL, and imports no outbound network client;
- the demo store is isolated: a store with any marker but `SYNTHETIC` is refused and left
  byte-identical, and the reset refuses it;
- the demo layer changes no data: every inventory and candidate route serves the same JSON
  as the shared API without it, with no demo-only views;
- determinism is preserved: two resets match each other and the dataset's own seed;
- `DEMO ENVIRONMENT` appears for the demo's real `/health`;
- over Null Meridian: the canonical seed and audit head, identical state across resets,
  representative manifest records served through the real API, the real correlation
  engine's results for every Okta group, the governance findings and posture, the ten
  lifecycle candidates' states, and every store-identity refusal;
- in a real browser, the indicator and every Null Meridian view together.

## Public deployment

The public demo runs on Cloudflare Workers Paid (required) with D1. It is read-only for
visitors and holds no integration credential.
[deployment/cloudflare-demo.md](deployment/cloudflare-demo.md) covers the architecture,
bootstrap, verification, and rollback.
