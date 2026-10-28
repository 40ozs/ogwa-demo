# Demo Mode

Status: OGWA-DEMO-MODE-01, integrated with the Null Meridian dataset by
OGWA-DEMO-INTEGRATION-01. Demo Mode runs **the real OGWA application** (the same UI, API,
read model, correlation engine, candidate classification, lifecycle, approvals, audit chain,
governance views, and remediation dry runs) over a **deterministic synthetic dataset**, with
a hard runtime and provider boundary that keeps it away from every live system. The
application is real. The organization and its identities are fictional.

One codebase serves both runtimes. There is no separate demo application, API, or UI.

| | What it is | Where |
| --- | --- | --- |
| **Demo Mode** | The runtime and safety boundary: `OGWA_RUNTIME_MODE=demo`, the provider boundary, the isolated demo store, the demo mutation policy, the UI indicator | `app/runtime/`, this document |
| **Genesee Press** | The synthetic dataset Demo Mode serves by default (SYNTH-OGWA-01): the shared synthetic world's 1,800-person company, read from the vendored `synthetic-enterprise` projection | `app/demo/genesee_press/`, [demo/genesee-press.md](demo/genesee-press.md) |
| **Null Meridian** | The legacy synthetic dataset (OGWA's own generator), kept until Genesee Press parity is accepted; same seed path | `app/demo/null_meridian/`, [demo/null-meridian.md](demo/null-meridian.md) |

Demo Mode owns no data. Null Meridian owns no runtime policy. They meet in one place: the
dataset registry `app/demo/datasets.py`.

## Canonical commands

```sh
export OGWA_RUNTIME_MODE=demo                                       # select the demo runtime (dataset: genesee-press)
python -m app.runtime reset-demo --confirm-synthetic-reset          # reset/reseed the demo store, validated
python -m app.runtime verify                                        # re-validate the demo store at any time
python -m app.runtime verify --expected-audit-head sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41
                                                                    # ...and pin it to the canonical seed (right after a reset)
python -m app.api serve                                             # start the demo: http://127.0.0.1:8765/
python -m app.runtime status                                        # runtime, selected dataset, availability, store presence
```

Tests: `python -m unittest discover -s tests -t .` (the full suite), and
`UI_BROWSER_TESTS=1 python -m unittest tests.browser.test_operator_workflows
tests.browser.test_null_meridian_views tests.browser.test_demo_null_meridian_ui` (the opt-in
browser gate; `UI_BROWSER` names the browser executable if Chrome or Edge is not in a
standard place). The focused Demo Mode set is listed in "Validating isolation" below.

## Runtime mode

`OGWA_RUNTIME_MODE` selects the runtime. It is a deployment setting read from the process
environment only. No API route, UI control, or request can change it.

| Value | Meaning |
| --- | --- |
| `production` (default when unset) | The standard OGWA runtime. Every existing rule applies unchanged, including `OGWA_EXECUTION_MODE` and its own default (`LOCAL_SYNTHETIC`). |
| `demo` | The sealed demo profile described here. |
| anything else | Startup fails (`ConfigError`). It never falls back to another mode. |

The runtime mode is orthogonal to the [execution mode](security/execution-modes.md). The
execution mode decides whether external state may change; the runtime mode decides where
data comes from. A demo process is always `LOCAL_SYNTHETIC`. A `LOCAL_SYNTHETIC` process is
not necessarily a demo: developers keep using it under the standard runtime.

Code: `app/core/runtime_mode.py` (the `RuntimeMode` enum and parser) and
`app/core/config.py` (validation).

### What `demo` requires and refuses (startup validation)

| Setting | In `demo` |
| --- | --- |
| `OGWA_EXECUTION_MODE` | Must be unset or `LOCAL_SYNTHETIC`; anything else fails startup. |
| `OGWA_OKTA_ORG_URL`, `OGWA_OKTA_API_TOKEN`, `OGWA_AAP_URL`, `OGWA_AAP_TOKEN` | Must be unset. Any of them fails startup, and the error names the variable, never its value. |
| Other tools' credential variables (`OKTA_API_TOKEN`, `OKTA_CLIENT_TOKEN`, `OKTA_CLIENT_SECRET`, `OKTA_CLIENT_PRIVATEKEY`, `OKTA_PRIVATE_KEY`, `CONTROLLER_PASSWORD`, `CONTROLLER_OAUTH_TOKEN`, `TOWER_PASSWORD`, `TOWER_OAUTH_TOKEN`, `AAP_TOKEN`, `AD_BIND_PASSWORD`, `LDAP_BIND_PASSWORD`) | Must be absent from the process environment. OGWA never reads them, but their presence means production credentials reached a demo deployment. |
| `OGWA_DATABASE_URL` | Defaults to `sqlite:///var/ogwa-demo.sqlite3`. It must name a file (not `:memory:`) and must not be the production default store (`var/ogwa-local.sqlite3`). |
| `OGWA_DEMO_DATASET` | A dataset **selector** from the registry: `genesee-press` (the default), `null-meridian` (legacy) or `classic`. Outside `demo` it must be blank. An unknown selector fails startup; a seed namespace given as a selector (`null-meridian-v1`) is refused with the selector that names it. |
| The demo store | Must exist, be marked `SYNTHETIC`, hold exactly the configured dataset (every piece of identity evidence agreeing, below), and pass full verification. Otherwise startup fails. |

No Okta token, AAP token, or AD credential is needed or accepted.

## Provider boundary

OGWA's shared logic reads only from the store. Live systems reach the store only through
collectors and integration adapters. `app/runtime/providers.py` is the one place where the
runtime mode chooses them (`select_providers`):

| Role | `production` | `demo` |
| --- | --- | --- |
| Okta | `RealOktaProvider`: store reads, plus a GET-only `OktaReadOnlyClient` collector session built only on request, with an approved credential | `SyntheticOktaProvider`: store reads of the seeded dataset. `collector_session()` raises `DemoModeBlocked`. |
| AD directory (mapping review) | No production adapter in this build. The read-only PowerShell worker runs under AAP (P05). | `SyntheticMappingGateway` over the dataset's AD evidence |
| AAP | `RealAapProvider`: a GET-only `AapReadOnlyClient` built only on request | `DisabledAapProvider`: every call raises `DemoModeBlocked` |
| Remediation | The deployment's allowlist (dry run only) | The synthetic allowlist, restricted to the `SYNTHETIC` adapter. Any other adapter stops the build. |

`RealOktaProvider` and `RealAapProvider` raise `DemoModeBlocked` if constructed with demo
settings. In a demo process, no Okta client, AAP client, or HTTP client is ever
constructed, and the AAP client module is never imported. The Okta client module is
imported indirectly by existing domain code, but never instantiated.

Business logic contains no runtime-mode checks.

## Synthetic-data integration: the dataset registry

Demo Mode generates no data and keeps no registry of its own. The one registry is
`app/demo/datasets.py` (`dataset(key)`, `DATASET_KEYS`, `DEFAULT_DATASET`, `dataset_of(store)`),
owned by the synthetic-data implementation. It is shared by the developer reset
(`python -m app.store reset-demo`), the standard runtime's demo policy and correlation
configuration, and Demo Mode. `app/runtime/datasets.py` is Demo Mode's thin adapter over it:

```text
OGWA_DEMO_DATASET (selector)
   -> app.runtime.datasets.resolve_dataset        (Demo Mode's adapter: metadata, fail closed)
   -> app.demo.datasets.dataset(selector)         (the registry)
   -> the implementation's own seed and profile
```

| Selector (`OGWA_DEMO_DATASET`) | Seed namespace (audit identity) | Seed function | Canonical metadata read from |
| --- | --- | --- | --- |
| `genesee-press` (default) | `genesee-press-v1` | `app.demo.genesee_press.world.create_genesee_press_store` | `app.demo.genesee_press.profile` (reads the vendored projection: `COMPANY`, `PRIMARY_DOMAIN`, `SNAPSHOT_DATE`; `SEED`, `DATASET_KEY`) |
| `null-meridian` (legacy) | `null-meridian-v1` | `app.demo.null_meridian.world.create_null_meridian_store` | `app.demo.null_meridian.profile` (`COMPANY`, `PRIMARY_DOMAIN`, `SNAPSHOT_DATE`, `SEED`, `DATASET_KEY`) |
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
  test suite uses it because it covers every lifecycle state and can be compared route by
  route with the standard runtime.
- **No fallback.** A selector that is unknown, or whose implementation is not in the build,
  is `DatasetUnavailable`, naming the dependency. Nothing is ever served or seeded in its
  place: with Null Meridian missing, the demo refuses to start even if a classic store is at
  the configured path (`tests/test_null_meridian_demo.py`).

The Null Meridian generation rules, counts, correlation cases, governance findings, and
lifecycle candidates are specified in [demo/null-meridian.md](demo/null-meridian.md) and its
manifest. They are not repeated here, and Demo Mode does not restate them: its tests compare
what the demo serves with the dataset's own manifest, generator, and seed expectations.

## Demo persistence and store identity

The demo store is its own SQLite file (`var/ogwa-demo.sqlite3` by default), with the same
schema, migrations (including 0012, the synthetic directory snapshot), and store code as
every other OGWA store. `app/runtime/demo_store.py` handles it.

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
  digest, and the snapshot names the dataset the audit event's namespace belongs to. No new
  migration was added for dataset identity.
- A missing demo store is a startup failure, never a new empty store. An unmarked file, a
  `PRODUCTION` or `DEVELOPMENT` store, a store of the other dataset, a store whose seed
  namespace has no matching snapshot, and a tampered snapshot are all refused.

## Seed and reset

There is **one reset command for the demo store**:

```sh
OGWA_RUNTIME_MODE=demo python -m app.runtime reset-demo --confirm-synthetic-reset
```

It takes the dataset from `OGWA_DEMO_DATASET` (there is no `--dataset` flag, so the store
and the server always agree), and it is a guard around the one guarded reset,
`app.store.reset.reset_synthetic_store`, which the developer reset uses too:

1. it refuses unless `OGWA_RUNTIME_MODE=demo` (positively confirmed, never inferred);
2. it refuses the production default store, and any existing file not marked `SYNTHETIC`;
3. the guarded reset applies its own checks (`LOCAL_SYNTHETIC`, a file under `var/`, an
   existing file marked `SYNTHETIC` or `DEVELOPMENT` that holds no real evidence, explicit
   confirmation, a registered dataset), deletes the file, and runs the dataset's own seed
   from the registry: for Null Meridian, `create_null_meridian_store`;
4. it validates the result as opening does (the `SYNTHETIC_SEED_LOADED` event, its namespace,
   the snapshot, integrity), pinning the audit head the seed reported.

It is deterministic: every reset gives byte-identical tables and the dataset's pinned
canonical audit head, for Null Meridian
`sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41`
([operations/audit-anchors.md](operations/audit-anchors.md)).

`python -m app.store reset-demo [--dataset null-meridian|classic]` remains the developer
reset of the **standard** runtime's local synthetic store (default `var/ogwa-local.sqlite3`;
default dataset `null-meridian` too). Under `OGWA_RUNTIME_MODE=demo` it refuses and names
the command above, so no command can reseed the demo store with a dataset other than the
configured one.

## Mutation policy

OGWA has no route that changes Okta, AD, or AAP. Remediation is dry-run only, and the
execute route always refuses ([mutation-gates.md](security/mutation-gates.md)). The demo
classifies every `POST` route of the API. The table is
`app.runtime.api.DEMO_MUTATION_POLICY`. An unclassified `POST` route stops the demo build,
so a route added later cannot reach the demo unreviewed.

| Class | Routes | In demo |
| --- | --- | --- |
| Session | `POST /session`, `POST /session/logout` | Synthetic sign-in, unchanged (the public demo has none: see below) |
| A: demo-local | `POST /candidates/{id}/transitions`, `/candidates/{id}/approvals`, `/mappings/{id}/inspection`, `/mappings/{id}/searches`, `/mappings/{id}/selections`, `/mappings/{id}/approvals`, `/mappings/{id}/rejections` | Run normally against the demo store. A successful response carries `"demo": {"classification": "LOCAL", "notice": "Recorded in the demo store only — …", "externalSystemsContacted": false}`. |
| B: simulated | `POST /candidates/{id}/execution-jobs` (dry-run plan), `POST /candidates/{id}/remediation-dry-runs` (the `SYNTHETIC` adapter answers `SIMULATED`), `POST /candidates/{id}/remediation-drills` (OGWA-DEMO-03: a dry run or synthetic execution against an in-memory provider fixture, which records nothing) | Run normally. A successful response carries `"demo": {"classification": "SIMULATED", "notice": "Simulation only — no Okta tenant was modified.", "externalSystemsContacted": false}`. |
| C: blocked | `POST /execution-jobs/{jobId}/execute` | Answers 403 `DEMO_MODE_BLOCKED` ("Execution is blocked in the demo environment. …") before the lifecycle service is reached. The refusal is chained as `GOVERNED_REQUEST_REFUSED` in the demo store's audit log. |

**Read-only demos.** Over a read-only demo store (the public hosted demo,
[deployment/cloudflare-demo.md](deployment/cloudflare-demo.md)), `demo_routes(..., read_only=True)`
refuses every `POST` above that would record something with 403 `DEMO_READ_ONLY`. Only
`NON_PERSISTING` routes stay open: sign-in, sign-out, mapping inspection, AD search, and the
remediation drill (OGWA-DEMO-03), which record nothing; their notice says "nothing was recorded". The execute route keeps its own
refusal. A refused governed request is logged (`api.refusal_not_chained`), not chained: the
store cannot change. `build_demo_application` picks the read-only policy whenever the store is
read-only (`Store.read_only`), so the two cannot disagree.

**The public demo is anonymous** (OGWA-DEMO-HOSTED-ANON-01). A read-only demo has no sign-in:
`GET /session` starts a session for the synthetic, anonymous public visitor (VIEWER, from the
role bindings), `POST /session` answers `PUBLIC_DEMO_NO_SIGN_IN`, and every refusing route answers
any visitor with its own explanation (`DEMO_READ_ONLY`, `DEMO_MODE_BLOCKED`). The visitor may run
the synthetic drill on NM-C11 only (`PUBLIC_DRILL_SCOPE` elsewhere), holding the executor's role
for that request alone. `/health` says `publicDemo: true`, the indicator reads "Public synthetic
demo · no live integrations", and the walkthrough names no synthetic principal.

Enforcement is in the backend: the route table the demo API is built with, the providers,
and the remediation allowlist. Route access rules (public, session, permission) are
identical to the standard runtime's (`tests/test_demo_mode.py`, `DemoMutationPolicyTests`).

Null Meridian added only read routes (`GET /directory`, `/people`, `/people/{personId}`,
`/directory-groups`, `/directory-groups/{directoryGroupId}`, `/governance-findings`,
`/demo-scenarios`). They read only the 0012 snapshot (a test pins that `app/api/directory.py`
only selects), reach the demo unwrapped, and keep their permission checks. The policy table
still covers every `POST` route of the integrated API exactly (`tests/test_null_meridian_demo.py`).
`/demo-scenarios` lists the dataset's portfolio scenarios; despite its name it neither reads
nor changes the runtime mode.

## UI indicator and runtime metadata

- `GET /api/v1/health` (public) in demo answers `{"status": "ok", "runtimeMode": "demo",
  "dataSource": "synthetic", "organization": …, "dataset": {"key", "companyName",
  "primaryDomain", "snapshotDate", "seed", "synthetic": true}, "liveIntegrations": false}`.
  It carries no path, host, or credential. The standard runtime's `/health` is unchanged.
- `GET /api/v1/dashboard` in demo also carries that block as `runtime`.
- Every demo response (API and UI files) carries `X-OGWA-Runtime-Mode: demo`.
- The UI shows a small persistent **DEMO ENVIRONMENT · Synthetic data** pill in the header,
  before and after sign-in. Expanding it explains: "This environment uses deterministic
  synthetic data for <organization>. No production Okta tenant is connected. The OGWA
  application is real; the organization and its identities are fictional." The
  organization comes from `/health`; the UI holds no dataset name (`js/runtime.js`). In the
  standard runtime the pill stays hidden.
- Expanded, the explanation takes its own row of the header and pushes the navigation down;
  it never overlays a navigation link, at desktop or phone width
  (`tests/browser/test_demo_null_meridian_ui.py`). Null Meridian's views (company directory,
  portfolio scenarios, governance findings, people, person access paths, directory groups)
  are in the same navigation as every other view.

## Running locally

```sh
OGWA_RUNTIME_MODE=demo python -m app.runtime reset-demo --confirm-synthetic-reset
OGWA_RUNTIME_MODE=demo python -m app.api serve
# open http://127.0.0.1:8765/ and sign in as any synthetic principal, e.g. synthetic.securityiam.one
```

The demo always starts its clock just after the store's newest audit event, so the
synthetic evidence is as fresh as the dataset made it. Null Meridian's evidence is a
collection taken a week before its snapshot, so a step that needs fresher evidence (an
approval) is refused by the real lifecycle gate until the evidence is re-observed, exactly as
in production. `OGWA_DEMO_DATASET=classic` serves the 16-scenario lifecycle world instead
(reset it with the same command).

## Validating isolation

```sh
python -m unittest tests.test_runtime_mode tests.test_demo_providers tests.test_demo_mode \
  tests.test_ui_runtime tests.test_null_meridian_demo
UI_BROWSER_TESTS=1 python -m unittest tests.browser.test_demo_null_meridian_ui
```

These prove the following:

- `production` selects the real providers, `demo` the synthetic ones, and an unknown mode
  fails;
- demo needs no credential, and refuses live settings and foreign credential variables;
- building and using the demo (health, dashboard, every inventory listing, correlation
  inspection, AD search, an approval, a remediation dry run) makes no socket connection,
  starts no process, opens no URL, and constructs no Okta, AAP, or HTTP client;
- the demo store is isolated: a production store is refused and left byte-identical, and
  the reset refuses production;
- the demo serves the same JSON as the standard runtime for every inventory and candidate
  route over the same dataset, with no demo-only views;
- determinism is preserved: two resets match each other and the dataset's own seed;
- `DEMO ENVIRONMENT` appears for the demo's real `/health` and not for production's;
- over Null Meridian: the canonical seed and audit head, identical state across resets,
  representative manifest records served through the real API, the real correlation
  engine's results for every Okta group, the governance findings and posture, the ten
  lifecycle candidates' states, and every store-identity refusal;
- in a real browser, the indicator and every Null Meridian view together.

## Public deployment

The public demo runs on Cloudflare Workers Paid (required) with D1. It is read-only for visitors and holds
no credential. [deployment/cloudflare-demo.md](deployment/cloudflare-demo.md) covers the
architecture, bootstrap, verification, and rollback. Locally, `python -m app.api serve` still
binds `127.0.0.1` only.
