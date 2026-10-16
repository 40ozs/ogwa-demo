# OGWA

**Can this identity and governance evidence be trusted enough to make a change? Which policy
supports that decision? And can you prove what happened afterward?**

OGWA is a web application for identity and group lifecycle governance. It correlates Okta
groups, application assignments and sign-in usage with Active Directory group state and
dependency evidence, such as file-share ACLs, GPOs and automation. It then decides, under a
versioned policy, whether a group can safely move through review, approval, removal and
retirement. It is written in standard-library Python, with a dependency-free JavaScript UI.

This repository is a **demo build**. It runs over **Null Meridian**, a fictional 1,800-person
company with ten years of synthetic identity history, and it cannot connect to a real identity
system ([Demo Mode](#demo-mode)).

## Live demo

**<https://ogwa-demo.d-walkes.workers.dev>**

- **No sign-in.** Every visitor is the same anonymous, read-only synthetic viewer, and the page
  opens on the dashboard.
- **NM-C11's remediation drill runs**, because it records nothing. It is the only drill a visitor
  can run.
- **Nothing is recorded.** Approvals, holds and other decisions get `403 DEMO_READ_ONLY`. The
  audit trail and mapping inspection are local-only; the dashboard shows the audit head.
- Run it locally (below) to sign in as the synthetic principals and record holds and reviews of
  your own. [docs/deployment/cloudflare-demo.md](docs/deployment/cloudflare-demo.md) compares the
  two.

## Why OGWA exists

Group cleanup looks easy: find the groups nobody uses and remove them. The hard part is that
the evidence is rarely clean. A directory read times out. A membership count was never
collected. Two sources disagree. A group's link to its Active Directory counterpart rests on a
name match rather than a stable identifier. A policy changes between the triage and the
approval. A change request times out, and nobody knows whether it was applied.

Acting on that evidence fails quietly. A "member count unknown" read as zero removes a group
that people still use. A probable name match retires the wrong directory object. A retried
request that had in fact succeeded applies a change twice. A later policy edit rewrites why an
old decision was made.

OGWA is the control layer for those cases. **Missing information is never permission to act**,
and **a change is not done until a read proves it**.

```text
synthetic source evidence → normalization / correlation → evidence quality → policy evaluation
  → decision → approval / authorization → dry run → synthetic execution → verification
  → safe retry → post-action verification → audit evidence
```

## Two demo scenarios

| | NM-C10: why OGWA refuses to act | NM-C11: how OGWA acts safely |
| --- | --- | --- |
| Evidence | Conflicting AD reads, a nesting read that failed, a partial ACL scan, checks never collected | Re-collected on the snapshot day, every required item current |
| Identity | Probable, not proven (an unverified SID) | Exact |
| Policy | NM-LIFECYCLE-004 v1.2.0: conditions **Not proven** | NM-LIFECYCLE-004 v1.2.0: decision and approval both judged by it |
| Outcome | Manual review. No approval can be recorded, no remediation is offered, and another candidate's approval cannot be borrowed | Dry run (no state changed), then a synthetic execution: **OUTCOME UNKNOWN**, verification, a retry with the same operation id, **POST-ACTION VERIFIED** |
| Lesson | Uncertainty is a control state, not a gap to fill with a default | Remediation is a verified state transition, not a button click |

## Quick start with Docker

You need Docker with Compose. Nothing else: no Python, Node, credentials or Cloudflare account.

```sh
git clone https://github.com/40ozs/ogwa-demo.git
cd ogwa-demo
docker compose up --build
```

Open <http://localhost:8765> and sign in as `synthetic.executor.one`.

- The first start seeds and validates the demo store (about 10 seconds). The container is
  healthy once the API answers over the validated store.
- The port is published on `127.0.0.1` only. Keep host port 8765: the API accepts browser
  requests from `http://localhost:8765` and `http://127.0.0.1:8765`.
- Holds and mapping reviews you record are kept in the `demo-store` volume across restarts. An
  approval is refused (`409 EVIDENCE_RULES_NOT_MET`): Null Meridian's evidence is older than the
  policy's 168-hour approval window, and the refusal is the lesson.
- Stopping the first start while it seeds is safe: the next start seeds again. If the container
  ever exits because the demo store cannot be read, `docker compose down -v` deletes it.

```sh
docker compose down                 # stop; the demo store is kept
docker compose down -v              # stop and delete the demo store
docker compose up --build           # after down -v: seeds a fresh store, identical to the first
```

To check the store against its published audit anchor:

```sh
docker compose exec ogwa python -m app.runtime verify \
  --expected-audit-head sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41
```

This passes on a fresh store. Anything you record afterwards extends the audit chain and moves
the head.

## Local development without Docker

You need **Python 3.11 or later**. OGWA uses the standard library only, so there is nothing to
`pip install`. The full test suite also needs **Node.js 18.15 or later**: seven of its modules run
the UI's JavaScript tests under Node, and they fail without it. Optional: **Chrome or Edge** for
the browser tests, and **PowerShell 7** for the scripts in `scripts/` and the PowerShell worker
tests.

```sh
git clone https://github.com/40ozs/ogwa-demo.git
cd ogwa-demo
python3 -m app.runtime reset-demo --confirm-synthetic-reset    # seed and validate var/ogwa-demo.sqlite3
python3 -m app.runtime verify \
  --expected-audit-head sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41
python3 -m app.api serve                                       # http://127.0.0.1:8765/
```

Use `python` or `py` instead of `python3` where that is how Python 3.11+ is installed. There is
no build step: the UI is static files served by the same process. To start again from the
seed, rerun `reset-demo`. `OGWA_DEMO_DATASET=classic` selects the smaller 16-scenario lifecycle
world instead of Null Meridian; [`.env.example`](.env.example) lists every setting.

### Tests

```sh
python3 -m unittest discover -s tests -t .              # the full suite: about 1,300 tests, a few minutes
python3 -m app.demo.null_meridian.audit_sample --check  # the committed audit sample equals this build's output
python3 -m unittest tests.test_ui_drill tests.test_ui_evidence tests.test_ui_policy   # UI logic under Node
UI_BROWSER_TESTS=1 python3 -m unittest discover -s tests/browser -t .                # headless Chrome or Edge
python3 scripts/docker_smoke.py                         # Docker acceptance, in its own Compose project
pwsh scripts/check.ps1                                  # optional: compile, full suite, PowerShell worker tests
```

The browser tests look for Chrome or Edge in the standard places on Windows, macOS and Linux;
`UI_BROWSER` names the executable if it is elsewhere. With `UI_BROWSER_TESTS=1` and no browser,
they fail rather than skip. `pwsh scripts/browser-check.ps1` also fails when anything is skipped.

`docker_smoke.py` runs in its own Compose project (`ogwa-docker-smoke`) and deletes only that
project's volume, so your demo store is untouched. It needs port 8765, so stop your demo first
(`docker compose stop`).

## Five-minute walkthrough

[docs/demo/walkthrough.md](docs/demo/walkthrough.md) walks NM-C10 and then NM-C11 in the UI.
The same steps are on the app's **Portfolio scenarios** page (dashboard, then "Start the
five-minute reviewer walkthrough").
[docs/demo/samples/ogwa-audit-sample.json](docs/demo/samples/ogwa-audit-sample.json) holds both
scenarios as the application's own API responses and audit events, generated and checked byte
for byte against the build.

## Architecture

The architecture is drawn in
[docs/architecture/overview.md](docs/architecture/overview.md#from-evidence-to-verified-action).
Each key design decision links to where it is specified, and to the invariants and tests that
enforce it.

| Decision | Specified in | Enforced by |
| --- | --- | --- |
| **Preserve uncertainty.** Not collected, unavailable, partial, conflicting and explicitly-none evidence mean different things and never merge. An unknown member count is never zero. | [evidence-assessment.md](docs/architecture/evidence-assessment.md) | [EA-1, EA-3, EA-4, EA-7](docs/security/safety-invariants.md#evidence-assessment-invariants) |
| **Decisions are version-bound.** Every decision, approval and refusal records the exact policy version that judged it. The store refuses a superseded version. | [NM-LIFECYCLE-004.md](docs/demo/policies/NM-LIFECYCLE-004.md), [candidate-policy.md](docs/architecture/candidate-policy.md) | [PV-4, PV-5](docs/security/safety-invariants.md#policy-version-invariants) |
| **Historical decisions stay historical.** A newer policy version never changes what an earlier decision shows. The demo seed is checked for chronology in both directions. | [NM-LIFECYCLE-004.md](docs/demo/policies/NM-LIFECYCLE-004.md#chronology) | [PV-6](docs/security/safety-invariants.md#policy-version-invariants), [DI-4](docs/security/safety-invariants.md#policy-and-remediation-integration-invariants) |
| **An unknown execution outcome is not success.** A timeout after submission produces `OUTCOME_UNKNOWN`, which leads only to verification. | [remediation-execution.md](docs/architecture/remediation-execution.md#the-state-machine) | [RX-2](docs/security/safety-invariants.md#remediation-execution-invariants) |
| **Verify before retry.** A retry needs a read proving the change was not applied. The gates and the policy binding are checked again, the operation id is unchanged, and there are at most 2 submissions. | [remediation-execution.md](docs/architecture/remediation-execution.md#idempotency-and-the-retry-invariant) | [RX-3, RX-4, RX-5](docs/security/safety-invariants.md#remediation-execution-invariants), [DI-2](docs/security/safety-invariants.md#policy-and-remediation-integration-invariants) |
| **Success requires verification.** `EXECUTED` is never final. Only a post-action read of the after-state, with nothing else in scope changed, gives `POST_ACTION_VERIFIED`. | [remediation-execution.md](docs/architecture/remediation-execution.md#the-state-machine) | [RX-6, RX-7](docs/security/safety-invariants.md#remediation-execution-invariants), [DI-6](docs/security/safety-invariants.md#policy-and-remediation-integration-invariants) |
| **Synthetic execution is isolated.** The drill changes only an in-memory fixture that is discarded after each answer. It writes no audit event, job or decision, and the governed path still never executes. | [remediation-execution.md](docs/architecture/remediation-execution.md#owner-review), [decisions.md](docs/architecture/decisions.md) (D8, D153) | [RX-8, RX-9](docs/security/safety-invariants.md#remediation-execution-invariants) |

| Path | Purpose |
| --- | --- |
| `app/core/` | Configuration (Demo Mode only), execution-mode vocabulary, secrets and redaction, mutation policy, startup |
| `app/domain/` | Pure domain model: entities, evidence and freshness, identity mapping, dependency coverage, approvals, execution jobs, audit chain, lifecycle state machine, policy releases, remediation execution states |
| `app/store/` | SQLite store (PostgreSQL-compatible DDL), versioned migrations, append-only evidence and audit, environment marker, guarded reset |
| `app/demo/` | Deterministic synthetic datasets: Null Meridian (`null_meridian/`) and the classic 16-scenario lifecycle world |
| `app/runtime/` | Demo Mode: dataset adapter, the synthetic provider boundary, the demo store and its reset, demo API wiring, `python -m app.runtime` |
| `app/integrations/` | The Okta record models and the AD lookup contract that correlation uses (`OktaGroupRecord`, `LookupKind`). Also the Okta JSON normalizers and the AD report parser and assessment from the production design, which the demo does not run: its data comes from the synthetic datasets. No client: nothing here contacts a system |
| `app/correlation/` | Okta-to-AD identity correlation (stable ids first, `NAME_ONLY` never exact), mapping evidence and review |
| `app/classification/` | Candidate classification, dependency policy, evidence assessment, and the decision explanation under the exact policy version that produced it |
| `app/governance/` | Directory-snapshot records, the sg-okta / sg-share naming standard, effective membership and access paths, governance findings |
| `app/api/` | Operator API (WSGI, standard library): roles and bindings, sessions and CSRF, separation of duties, dry-run planning, the drill's authorization chain |
| `app/ui/` | Operator UI: static, dependency-free ES modules served beside the API on one origin, strict CSP with Trusted Types |
| `app/remediation/` | Dry-run remediation (allowlist, adapters, worker contract) and the synthetic drill: execution states, uncertain outcomes, verification before a safe retry |
| `app/cloudflare/`, `cloudflare/worker/` | The hosted demo on Cloudflare Workers with D1 ([docs/deployment/cloudflare-demo.md](docs/deployment/cloudflare-demo.md)) |
| `worker/OGWA.Remediation/` | PowerShell remediation worker: `ShouldProcess`, `-WhatIf`, `-ValidateOnly`, structured results; an in-memory synthetic adapter only |
| `config/` | The synthetic policy releases, identity provider, role bindings, correlation configuration and remediation allowlist |
| `Dockerfile`, `compose.yaml` | The Docker runtime |
| `docs/` | Architecture, decisions, security invariants, the demo's dataset and walkthrough, the hosted deployment |

## Where to look

| Area | Start here |
| --- | --- |
| Evidence modeling | [`app/classification/assessment.py`](app/classification/assessment.py): `EvidenceState`, `assess`, `_conflicts`, `_constraints`. [`app/domain/evidence.py`](app/domain/evidence.py): `ResultStatus`, `Provenance`, freshness |
| Synthetic source evidence | [`app/demo/null_meridian/world.py`](app/demo/null_meridian/world.py) (`seed_null_meridian`: the Okta- and AD-shaped evidence the demo serves), [`app/demo/synthetic_world.py`](app/demo/synthetic_world.py) (the classic world), [`app/correlation/engine.py`](app/correlation/engine.py) (`correlate`) |
| Identity correlation | [`app/correlation/engine.py`](app/correlation/engine.py) (`correlate`: stable ids first, `NAME_ONLY` is never exact), [`app/correlation/review.py`](app/correlation/review.py) |
| Candidate classification | [`app/classification/classifier.py`](app/classification/classifier.py) (`classify`, `_membership`) |
| Policy design and versions | [`config/policies/null-meridian/`](config/policies/null-meridian/), [`app/domain/policy_release.py`](app/domain/policy_release.py) (`PolicyRelease`, `PolicyRef`, `release_history_problems`), [`app/demo/null_meridian/policy.py`](app/demo/null_meridian/policy.py) |
| Governance decision logic | [`app/domain/lifecycle.py`](app/domain/lifecycle.py) (closed transition table, guards, `apply_transition`), [`app/api/services.py`](app/api/services.py) (`policy_in_force`, `LifecycleService.classify_assess_explain`) |
| Decision explanation | [`app/classification/explanation.py`](app/classification/explanation.py) (`ConditionStatus`, `explain`) |
| Policy chronology | [`app/demo/null_meridian/world.py`](app/demo/null_meridian/world.py) (`policy_chronology_problems`, `seed_null_meridian`), [`app/store/store.py`](app/store/store.py) (`Store._check_policy_ref`) |
| Remediation state machine | [`app/domain/remediation_execution.py`](app/domain/remediation_execution.py) (`TRANSITIONS`, `operation_id`, `retry_decision`, `verify_trace`) |
| Retry, idempotency, verification | [`app/remediation/drill.py`](app/remediation/drill.py) (`ExecutionRun.request`, `.decide`, `.post_verify`, `run_drill`) |
| Synthetic provider fixture | [`app/remediation/synthetic_provider.py`](app/remediation/synthetic_provider.py) (`SCENARIOS`, `SyntheticProviderFixture.submit`) |
| Authorization binding | [`app/api/authorization.py`](app/api/authorization.py) (`binding`, `remediation_authorization`, `drill_chain`), [`app/api/remediation.py`](app/api/remediation.py) (`RemediationService.drill`) |
| Audit integrity | [`app/domain/audit.py`](app/domain/audit.py) (`next_event`, `verify_chain`), [`app/store/store.py`](app/store/store.py) (`verify_integrity`), [`app/demo/null_meridian/audit_sample.py`](app/demo/null_meridian/audit_sample.py) (sample generator) |
| API design | [`app/api/routes.py`](app/api/routes.py) (`ROUTES`), [`app/api/authz.py`](app/api/authz.py) (roles, permissions, role bindings), [docs/architecture/api.md](docs/architecture/api.md), [docs/security/authorization.md](docs/security/authorization.md) |
| UI | [`app/ui/static/js/views/candidate.js`](app/ui/static/js/views/candidate.js) ("Is this safe to act on?", "Why this decision", the drill, "Authorized by"), [`evidence.js`](app/ui/static/js/evidence.js), [`policy.js`](app/ui/static/js/policy.js), [`drill.js`](app/ui/static/js/drill.js) |
| Demo-only boundary | [`app/core/config.py`](app/core/config.py) (`load_settings`, `LIVE_INTEGRATION_KEYS`), [`app/runtime/providers.py`](app/runtime/providers.py) (`select_providers`), [`app/runtime/api.py`](app/runtime/api.py) (`DEMO_MUTATION_POLICY`) |
| Synthetic demo design | [`app/demo/null_meridian/`](app/demo/null_meridian/) (`world.py`: `_nm_c10`, `_nm_c11`; `walkthrough.py`), [docs/demo/null-meridian.md](docs/demo/null-meridian.md) |
| Testing | [`tests/`](tests/) (standard-library `unittest`), [`tests/ui/`](tests/ui/) (Node tests over real API output), [`tests/browser/`](tests/browser/) (opt-in headless-browser tests) |

## Representative tests

These tests back the claims above. Each one is named `module.Class.test` and runs on its own
with `python3 -m unittest tests.<name>`.

| Claim | Test |
| --- | --- |
| An unknown member count is not treated as zero | `test_evidence_assessment.UnknownMemberCountRegressionTests.test_an_unknown_member_count_proves_nothing` |
| Conflicting evidence stays conflicting (both reads kept, not resolved) | `test_evidence_assessment.ConflictTests.test_ad_object_lists_members_but_the_membership_read_found_none` |
| Missing required evidence never creates eligibility (60+ single degradations) | `test_evidence_assessment.NoEligibilityFromMissingDataTests.test_every_single_degradation_is_refused` |
| NM-C10 stays non-actionable | `test_evidence_assessment.NullMeridianScenarioTests.test_nm_c10_shows_every_state_and_refuses_every_decision` |
| A decision records the exact policy version that judged it | `test_policy_release.NullMeridianPolicyHistoryTests.test_every_seeded_decision_records_the_version_that_judged_it` |
| A later version never rewrites a historical decision | `test_policy_release.NullMeridianPolicyHistoryTests.test_a_newer_version_never_rewrites_what_an_older_decision_recorded` |
| Policy chronology is enforced (the wrong seed order is refused) | `test_ogwa_demo_integration.SeedChronologyTests.test_the_naive_merge_order_is_refused_by_the_seed` |
| Incomplete evidence is "not proven", never satisfied or failed | `test_decision_explanation.ExplanationAgreesWithTheDecisionTests.test_missing_evidence_is_never_satisfied_or_failed` |
| A dry run makes zero mutations | `test_remediation_drill_api.DryRunDrillTests.test_a_dry_run_changes_nothing_and_says_so` |
| An unknown outcome leads only to verification | `test_remediation_execution.TransitionTableTests.test_an_unknown_outcome_leads_only_to_verification` |
| A retry needs a read showing the change was not applied | `test_remediation_execution.RetryDecisionTests.test_only_a_read_showing_the_before_state_permits_a_retry` |
| An applied change whose answer was lost is not resubmitted | `test_remediation_execution.ExecutionRunTests.test_an_applied_change_whose_answer_was_lost_is_not_resubmitted` |
| A retry carries the same operation id and applies once | `test_remediation_execution.ExecutionRunTests.test_a_retry_carries_the_same_operation_id_and_applies_once` |
| Success requires post-action verification | `test_ogwa_demo_integration.PostActionPredicateTests.test_post_action_verified_needs_the_read_the_after_state_and_an_unchanged_scope` |
| A failed verification never becomes success | `test_remediation_drill_api.UncertainOutcomeTests.test_a_failed_post_action_verification_is_never_reported_as_success` |
| A drill is tied to the policy, decision and approval | `test_ogwa_demo_integration.PolicyToRemediationLinkTests.test_a_drill_names_the_policy_version_decision_and_approval_that_authorized_it` |
| A superseded authorization cannot execute | `test_ogwa_demo_integration.HistoricalBindingTests.test_an_approval_judged_by_a_superseded_version_authorizes_no_drill_and_builds_nothing` |
| NM-C10 cannot enter remediation by any route | `test_ogwa_demo_integration.NmC10NeverDrillsTests.test_no_route_takes_nm_c10_into_a_drill` |
| NM-C11 runs the intended synthetic drill | `test_remediation_drill_api.NullMeridianDrillTests.test_nm_c11_is_drillable_at_the_demo_clock_without_refreshing_anything` |
| A drill persists nothing and reaches no live system | `test_remediation_drill_api.RecordsNothingTests.test_no_drill_writes_to_the_store_or_reaches_a_live_system` |
| The audit sample is the application's own serialization | `test_ogwa_demo_integration.AuditSampleTests.test_the_committed_sample_is_exactly_what_this_build_generates` |
| No setting can switch the build into a live or production runtime | `test_runtime_mode.DemoOnlyEscapeTests.test_every_attempt_to_select_a_live_or_production_runtime_is_refused` |
| The build contains no outbound network client | `test_mutation_safety.NoOutboundClientTests.test_no_application_module_imports_an_outbound_network_or_process_module` |

The modules that hold most of these run in under a minute:

```sh
python3 -m unittest tests.test_evidence_assessment tests.test_policy_release tests.test_decision_explanation \
  tests.test_remediation_execution tests.test_remediation_drill_api tests.test_ogwa_demo_integration
```

[docs/security/safety-invariants.md](docs/security/safety-invariants.md) maps every invariant
to the tests that enforce it.

## Demo Mode

This repository is intentionally demo-only. [docs/demo-mode.md](docs/demo-mode.md) describes
the boundary in full.

- **Everything is synthetic.** All identities, organizations, policies, directory objects,
  applications, evidence, provider responses and audit events are generated.
- **No live integration is included.** The build has no Okta, Active Directory or AAP client and
  no outbound HTTP client. Okta- and AD-shaped records come only from the synthetic datasets.
- **No credentials are needed or accepted.** Startup refuses Okta, AAP and outbound-HTTP
  settings, unknown `OGWA_*` keys, and Okta/AAP/AD credential variables. Error messages name the
  variable, never its value.
- **It cannot be switched into production.** The runtime mode is always `demo` and the
  execution mode always `LOCAL_SYNTHETIC`; any other value of `OGWA_RUNTIME_MODE` or
  `OGWA_EXECUTION_MODE` refuses startup with *"This public build supports Demo Mode only. Live
  integrations are unavailable."* `GET /api/v1/health` always reports `liveIntegrations: false`.
- **Remediation drills change nothing outside the process.** A drill runs against a scripted
  in-memory provider fixture that is discarded after each answer. The governed remediation path
  is dry-run only, and the execute route is blocked (`DEMO_MODE_BLOCKED`).
- **The local demo records only into its own store.** Approvals and decisions go into the
  SQLite demo store (`var/ogwa-demo.sqlite3`, or the Docker volume), which a reset re-creates
  from the seed.

## Synthetic data

- **Null Meridian** is a fictional company. Every person, group, application and identifier is
  generated deterministically from the seed `null-meridian-v1` and fixed name lists.
  `nullmeridian.info` is the company's invented domain name; OGWA never resolves or contacts it.
  Okta-shaped ids carry `SYNTH`. See [docs/demo/null-meridian.md](docs/demo/null-meridian.md#synthetic-only-guarantee).
- **The seed is pinned.** A fresh store holds 1,458 audit events whose head (sequence 1457) is
  `sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41`.
- **The classic world** (`app/demo/synthetic_world.py`) and the test fixtures use invented
  `synthetic.*` principals and hosts under the reserved `.example` TLD.
- **Policies:** NM-LIFECYCLE-004 v1.1.0 and v1.2.0 were written for the demo.
- **Credentials:** none exist. The only secret the hosted demo holds is its session-signing
  key, which is set in Cloudflare and never committed.

This is enforced, not only stated: Demo Mode refuses to start with a live setting or credential
in the environment; the snapshot tables refuse rows in a store not marked `SYNTHETIC`;
[`tests/test_repository_hygiene.py`](tests/test_repository_hygiene.py) scans the tree for
credential-shaped strings; and the audit sample's sanitization is tested
(`AuditSampleTests.test_the_sample_is_sanitized`).

## Project status

OGWA is a demonstration: a working governance core over synthetic data, with the hosted demo
above and the Docker and native local runs described here. It is not a production tool and
includes no path to one. The design decisions are recorded in
[docs/architecture/decisions.md](docs/architecture/decisions.md).

## License

[MIT](LICENSE)
