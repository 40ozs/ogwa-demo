# OGWA

Web application for identity and group lifecycle governance: correlating Okta
applications and their assigned groups, Okta usage, Active Directory group state, and
dependency evidence to support reviewed lifecycle decisions (candidate, review, hold,
approval, revalidation, retirement).

> **Status: P10.** Safety guardrails (P01), the pure domain model and lifecycle contract
> (P02), a durable lifecycle/audit store with a synthetic demo world (P03), a read-only
> Okta API client (P04, tested against mocks only; no approved credential yet), a
> read-only AD boundary (P05: a PowerShell worker plus its Python contract, tested against
> a synthetic directory only; no live AD read yet), and the Okta-to-AD identity correlation
> engine with its review service contract (P06, synthetic only), and the candidate
> classification and dependency policy engine (P07, synthetic only) exist. The operator
> API (P08) serves `LOCAL_SYNTHETIC` data with synthetic sign-in only, and the operator UI
> (P09) reviews it in the browser: evidence, explanations, and the P09 decisions, with no
> delete, unassign, or execute action. The remediation path (P10) exists **dry-run only**:
> one gated operation on one explicit target resolves to SIMULATED, WHATIF,
> VALIDATION_ONLY, or BLOCKED, never to a change. The AAP adapter can only validate, and
> the PowerShell remediation worker has no production adapter.

## Safety posture

- Default execution mode is `LOCAL_SYNTHETIC`. `PRODUCTION_MUTATION` is rejected at
  startup by this build and cannot be enabled through configuration.
- A lifecycle candidate is evidence for review, never authorization to delete.
- Remediation is dry-run only. No outcome, record, adapter, or worker mode can perform a
  change ([docs/security/mutation-gates.md](docs/security/mutation-gates.md)).
- Credentials never live in source, `.env.example`, tests, fixtures, logs, or reports.

See [docs/security/execution-modes.md](docs/security/execution-modes.md),
[docs/security/safety-invariants.md](docs/security/safety-invariants.md),
[docs/security/credentials.md](docs/security/credentials.md), and the binding
[owner decisions](docs/architecture/decisions.md). The domain and lifecycle are described
in [docs/architecture/domain-model.md](docs/architecture/domain-model.md) and
[docs/architecture/lifecycle-state-machine.md](docs/architecture/lifecycle-state-machine.md), and
the store in [docs/architecture/persistence.md](docs/architecture/persistence.md).

## Running

Requires Python 3.11+ (standard library only), PowerShell 7, and Node.js (only as the test
runner for the UI's JavaScript unit tests; no packages). The AD worker also runs on
Windows PowerShell 5.1; it needs the ActiveDirectory (RSAT) module only for live reads.

```powershell
python -m app                    # validate configuration, print the startup banner, exit
pwsh scripts/check.ps1           # compile + unit tests (incl. UI logic under Node) + PowerShell worker tests (synthetic only)

# Local store (OGWA_DATABASE_URL, default var/ogwa-local.sqlite3; var/ is git-ignored)
python -m app.store reset-demo --confirm-synthetic-reset   # (re)create the local synthetic store: Genesee Press (docs/demo/genesee-press.md)
python -m app.store reset-demo --confirm-synthetic-reset --dataset classic   # or the 16-scenario lifecycle world
python -m app.store status                                 # schema, environment marker, counts, audit head
python -m app.store verify                                 # re-verify migrations, audit chain, evidence, histories

# Operator UI and API: 127.0.0.1 only, LOCAL_SYNTHETIC + SYNTHETIC store only, synthetic sign-in
python -m app.api serve --demo-clock                       # open http://127.0.0.1:8765/ (docs/architecture/ui.md)
pwsh scripts/browser-check.ps1                             # UI browser gate (headless Chrome/Edge, synthetic): required before a pilot or release
```

`reset-demo` runs only in `LOCAL_SYNTHETIC` mode, only on a file under `var/`, and only on
a store marked `SYNTHETIC` or `DEVELOPMENT` that holds no real evidence.

### Demo Mode

`OGWA_RUNTIME_MODE=demo` runs the same application over a deterministic synthetic dataset
in its own store (`var/ogwa-demo.sqlite3`), with no live integration and no credential.
Unset, the runtime is `production`, the standard runtime, unchanged. Demo Mode is the
runtime and safety boundary ([docs/demo-mode.md](docs/demo-mode.md)); Genesee Press, the shared
synthetic world's company read from the vendored `synthetic-enterprise` projection, is the dataset it
serves by default ([docs/demo/genesee-press.md](docs/demo/genesee-press.md)). The legacy Null Meridian
dataset ([docs/demo/null-meridian.md](docs/demo/null-meridian.md)) stays selectable until cutover.
Reviewers start at **Portfolio scenarios**: a five-minute walkthrough of NM-C10 (no safe action
on conflicting evidence) and NM-C11 (a dry run, then a verified synthetic execution under
NM-LIFECYCLE-004 v1.2.0); the same chain is in the generated sample
[docs/demo/samples/ogwa-audit-sample.json](docs/demo/samples/ogwa-audit-sample.json).

```powershell
$env:OGWA_RUNTIME_MODE = "demo"                                 # dataset: genesee-press (seed namespace genesee-press-v1)
python -m app.runtime reset-demo --confirm-synthetic-reset      # reset/reseed and validate the demo store
python -m app.runtime verify                                    # re-validate it: dataset identity and integrity
python -m app.api serve                                         # the real UI and API, DEMO ENVIRONMENT
```

Under the demo runtime, `python -m app.store reset-demo` refuses: the demo store has one
reset command.

The public demo is hosted on Cloudflare Workers Paid (required) with D1, read-only for visitors
([docs/deployment/cloudflare-demo.md](docs/deployment/cloudflare-demo.md)):

```powershell
python -m app.cloudflare build                                   # seed, validate, stage the Worker, plan the D1 import
pwsh scripts/cloudflare-demo.ps1 -Bootstrap -ConfirmSyntheticBootstrap   # next D1 phase (one per UTC day)
pwsh scripts/cloudflare-demo.ps1 -Verify                         # export the hosted D1 and validate it
pwsh scripts/cloudflare-demo.ps1 -Deploy                         # deploy the Worker
```

## Layout

| Path | Purpose |
| --- | --- |
| `app/core/` | Execution mode, configuration, secrets, redaction, HTTP policy, mutation policy, startup |
| `app/domain/` | Pure domain model: entities, evidence and freshness, identity mapping, dependency coverage, approvals, execution jobs, collector runs, audit chain, lifecycle state machine |
| `app/store/` | SQLite store (PostgreSQL-compatible DDL), versioned migrations, append-only evidence and audit, environment marker, guarded reset, `python -m app.store` |
| `app/demo/` | Deterministic synthetic demo datasets: Genesee Press (`genesee_press/`, the default: the shared synthetic world's 1,800-person company from the vendored projection; see [docs/demo/genesee-press.md](docs/demo/genesee-press.md)), the legacy Null Meridian (`null_meridian/`, OGWA's own generator and the shared seed path; see [docs/demo/null-meridian.md](docs/demo/null-meridian.md)) and the classic 16-scenario lifecycle world |
| `app/governance/` | Directory-snapshot records, the sg-okta / sg-share naming standard, effective membership and access paths, and governance findings |
| `app/cloudflare/` | The Cloudflare-hosted demo: the Worker's application (`HostedDemo`), store identity, the D1 export, and `python -m app.cloudflare`; see [docs/deployment/cloudflare-demo.md](docs/deployment/cloudflare-demo.md) |
| `cloudflare/worker/` | The Cloudflare Python Worker: `wrangler.jsonc` and its entry module (the build stages the rest) |
| `app/runtime/` | Demo Mode: dataset adapter, the provider boundary, demo store and reset, demo API wiring, `python -m app.runtime`; see [docs/demo-mode.md](docs/demo-mode.md) |
| `app/integrations/okta/` | Read-only (GET-only) Okta client: apps, assignments, groups, members, bounded System Log usage; see [docs/architecture/okta-integration.md](docs/architecture/okta-integration.md) |
| `app/integrations/ad/` | AD worker contract (strict JSON), emptiness and protection assessment, conversion to domain evidence; see [docs/architecture/ad-integration.md](docs/architecture/ad-integration.md) |
| `app/correlation/` | Okta-to-AD identity correlation (stable ids first, `NAME_ONLY` never exact), drift detection, mapping evidence, and the operator review service contract; see [docs/architecture/identity-correlation.md](docs/architecture/identity-correlation.md) |
| `app/classification/` | Candidate classification and dependency policy, the evidence assessment (OGWA-DEMO-01), and the decision explanation under the exact policy version that produced it (OGWA-DEMO-02); see [docs/architecture/candidate-policy.md](docs/architecture/candidate-policy.md) and [docs/architecture/evidence-assessment.md](docs/architecture/evidence-assessment.md) |
| `app/api/` | Operator API (WSGI, standard library): roles and IdP-group-id bindings, sessions and CSRF, separation of duties, dry-run planning only; see [docs/architecture/api.md](docs/architecture/api.md) and [docs/security/authorization.md](docs/security/authorization.md) |
| `app/ui/` | Operator UI (P09): static, dependency-free ES modules served beside the API on one origin, strict CSP with Trusted Types; see [docs/architecture/ui.md](docs/architecture/ui.md) |
| `app/remediation/` | Remediation (P10), dry-run only: server-side allowlist, synthetic and AAP adapters (plan only), AAP template classification, the worker contract; see [docs/architecture/remediation.md](docs/architecture/remediation.md). The synthetic drill (OGWA-DEMO-03): execution states, uncertain outcomes, verification before a safe retry, and post-action verification against an in-memory provider fixture that records nothing; see [docs/architecture/remediation-execution.md](docs/architecture/remediation-execution.md) |
| `app/integrations/aap/` | Read-only (GET-only) AAP discovery of job-template and survey metadata (P10; not run live) |
| `config/` | Policy template (v1), the synthetic policy releases (`policies/genesee-press/` GP-LIFECYCLE-004 and the legacy `policies/null-meridian/`, OGWA-DEMO-02; see [docs/demo/policies/NM-LIFECYCLE-004.md](docs/demo/policies/NM-LIFECYCLE-004.md)), synthetic identity provider, role bindings, and remediation allowlist for local use |
| `worker/OGWA.ADReader/` | Read-only PowerShell AD worker (Get-* cmdlets only), to be run by a read-only AAP job |
| `worker/OGWA.Remediation/` | PowerShell remediation worker (P10): ShouldProcess, `-WhatIf`, `-Confirm`, `-ValidateOnly`, structured results; only an in-memory synthetic adapter |
| `tests/` | Unit tests; synthetic data only (`tests/powershell/` holds the worker tests, `tests/fixtures/ad/` and `tests/fixtures/remediation/` their golden documents, `tests/ui/` the UI's JavaScript unit tests, `tests/browser/` the opt-in browser tests) |
| `docs/architecture/` | Architecture overview and decisions |
| `docs/demo/` | The Genesee Press and Null Meridian datasets' descriptions and machine-readable manifests |
| `vendor/synthetic-enterprise/` | The shared synthetic world's OGWA projection, pinned by `SYNTHETIC_ENTERPRISE.lock` and verified before use; re-vendored, never edited by hand |
| `docs/security/` | Execution modes, credential handling, safety invariants |
| `docs/operations/` | Operator runbooks (Okta read-only, AD read-only) |
| `docs/agent-runs/` | Reports from each agent-run prompt |
| `scripts/` | Local developer tooling |
