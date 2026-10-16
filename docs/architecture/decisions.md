# Owner decisions

These are the project's design decisions, each with its consequence. They are numbered for
reference, and other documents and the code cite them by number.

## 2026-10-03 — foundation and guardrails

| # | Decision | Consequence |
| --- | --- | --- |
| D3 | Changes to the safety-critical files need review; CODEOWNERS and branch protection should enforce that wherever the repository is hosted. | The safety-critical files: `app/core/build.py`, `app/core/safety.py`, and the import checks in `tests/test_mutation_safety.py`. |
| D4 | The application uses only the Python standard library. | No third-party dependency is needed to run or test it. |
| D5 | Python dependencies, if any are added, are installed only into a project-local `.venv`, from an approved package source. No global installs. | Never `pip install` into the system or user interpreter. `.venv/` is git-ignored. |
| D6 | The intended Okta production authentication model is a dedicated least-privilege, read-only OAuth service application. | No credentials are created and no scopes requested; the minimum permissions are derived and documented first (D28). SSWS API tokens are not the intended model. Live Okta reads are not included in this build. |
| D8 | `PRODUCTION_MUTATION` is impossible in this build. The startup guardrails must not be weakened. | `BUILD_ALLOWS_PRODUCTION_MUTATION` stays `False`. Do not remove or relax the strict key check, the mutation-policy injection, or the import check in `tests/test_mutation_safety.py`: no application module may import an outbound network or process module, and the only approved server import (`APPROVED_SERVER_IMPORTERS`) is the demo's WSGI server. Relaxing a test counts as weakening a guardrail. |

## 2026-10-03 — domain model

| # | Decision | Consequence |
| --- | --- | --- |
| D10 | The configured protected list is owned by the AD/Identity platform owner and changed only with Security/IAM review. It is additive only: nothing in the policy can remove the built-in protections. | Enforced in `app/domain/policy.py` (`LifecyclePolicy` protected lists). |
| D11 | The AD retirement approver must be a different human from the person who approved the Okta unassignment. | Enforced in `app/domain/approval.py` (`approval_problems`) and `app/domain/lifecycle.py` (`okta_unassign_approver`). |
| D12 | Only AD-sourced groups may enter the AD-retirement workflow. Okta-only groups are classified for review only; their separate lifecycle is not yet defined. | Enforced in `app/domain/lifecycle.py` (`_ad_workflow_origin`) and `app/domain/policy.py` (`GroupOrigin.OKTA_ONLY`). |
| D13 | An `OPERATOR_ATTESTATION` is recorded, and its blocking findings still block, but it never covers a dependency kind: a manual statement cannot turn PARTIAL coverage into COMPLETE. | Enforced in `app/domain/model.py` (`COVERAGE_SOURCES`). |

## 2026-10-05 — AD read contract

| # | Decision | Consequence |
| --- | --- | --- |
| D18 | The first live AD read needs an explicitly approved read-only identity, a single approved test-group objectGUID, and an authoritative governed-domain list. | Without all three, no live read. The live AD reader is not included in this build. |
| D19 | Large-group completeness, cross-domain parent lookup, and deletion-protection readability are unverified against real AD. | Until they are recorded as verified, they cannot contribute to COMPLETE evidence. Enforced by `VERIFIED_LIVE_BEHAVIORS` (empty) in `app/integrations/ad/records.py`. |
| D20 | Direct membership, nested membership, and primaryGroupID references stay separate facts. | Never collapse them into one emptiness boolean. |
| D21 | Unknown protection status is fail-closed and cannot be overridden. | No configuration, flag, or attestation may turn UNDETERMINED into NOT_PROTECTED. |
| D22 | Identity correlation is synthetic/mock-only. | Correlation contacts no external system. |
| D23 | Okta-derived AD GUID decoding stays UNVERIFIED_DIRECTORY_METADATA until it is proven against a known AD-backed Okta group. | `OBJECT_GUID_DECODING_VERIFIED` stays `False`; a decoded GUID cannot support an exact mapping. |

## 2026-10-05 — Okta read client

| # | Decision | Consequence |
| --- | --- | --- |
| D25 | Any general Okta resource client is GET/HEAD-only. | Nothing in `app/integrations/okta/` may gain a POST or other unsafe method. The Okta client is not included in this build. |
| D26 | Future OAuth token acquisition uses a dedicated, narrowly constrained token client whose only POST target is the configured `/oauth2/v1/token` endpoint. Do not implement signing until an approved crypto or signing mechanism exists. | The token client is a separate module outside `app/integrations/okta/`. Any other host, path, method, or redirect is refused, tests prove the single target, and it is reviewed like the D3 files. No signing and no token client until the mechanism is approved (D5). |
| D27 | The 90-day lifecycle usage policy stays unchanged. Native Okta System Log retention may support a shorter low-usage review signal but cannot by itself satisfy a complete 90-day retirement requirement. | `LifecyclePolicy.min_usage_window` stays 90 days. Native-retention usage is at most `REVIEW_SIGNAL_ONLY`. A complete 90-day window needs a longer-retention source. |
| D28 | Plan for a Read-Only Administrator role on the Okta service app, with only `okta.apps.read`, `okta.groups.read`, and `okta.logs.read`. Ask the Okta administrator whether a narrower custom role can satisfy every required read. Never use Super Admin. | A grant with any other scope must be refused. The admin role is invisible to OGWA, so provisioning and review enforce it. Switch to a custom role only if it covers every required read, including the System Log. |
| D29 | Okta pagination combines repeated response header fields, so a `Link: rel="next"` header is never dropped. It follows only same-origin links, detects cycles, and ends within a request budget. | Cycle detection compares normalized URLs. The HTTP client is not included in this build. |
| D30 | Okta-derived AD objectGUID decoding stays unverified until it is proven that a **known AD-backed Okta group** decodes to exactly the objectGUID AD independently reports for that group. | `OBJECT_GUID_DECODING_VERIFIED` stays `False` (O-10) until that proof is recorded. Until then the decoded value never reaches domain evidence. Refines D23, which is unchanged. |

## 2026-10-05 — candidate policy and correlation

| # | Decision | Consequence |
| --- | --- | --- |
| D32 | Git holds the policy schema, the hard floors and ceilings, and the default template. The active production policy is an immutable, append-only version in the OGWA database. | Format and bounds: `app/domain/candidate_policy.py`; template: `config/candidate-policy.template.json` (no environment values). The policy in force is `Store.active_policy_version()` (`policy_versions`, migration 0004); it is never read from a file at run time. |
| D33 | Identity/Automation may propose a policy change; a different Security/IAM reviewer must approve it. | Each `PolicyVersion` records `proposer_role` `IDENTITY_AUTOMATION` and `approver_role` `SECURITY_IAM`, held by two different humans; the domain, the store, and the database (migration 0005) refuse anything else. The operator API must derive the role from verified group membership. |
| D34 | Hard safety floors and ceilings are code-controlled and cannot be weakened through runtime policy. | The document has no key for a floor or ceiling; out-of-bounds values and dropped mandatory dependency kinds are refused (`TemplateAndFloorTests`). Changing a floor is a reviewed source change. |
| D35 | Policy v1 is the template defaults, unchanged: the 90-day usage window (D27) and the current 5-sign-in low-usage semantics. | v1 = the template; its digest is pinned by a test. With no AD integration ids configured, v1 treats no group as AD-sourced (fail closed); environment values are added only through a reviewed later version. |
| D36 | An AD-backed group with members continues to block Okta assignment removal in this lifecycle. | No change: the lifecycle's pre-unassign guards and the classifier (`HAS_MEMBERS`) keep blocking. |
| D37 | A directory-source SID may count as exact only after the mechanism is validated against a known AD-backed Okta group. | `DIRECTORY_SOURCE_SID_VERIFIED` (`app/correlation/model.py`) stays `False`. Until then such a match is `REVIEW_REQUIRED` / `NAME_ONLY`; it may corroborate, never be the basis of, an exact mapping. |
| D38 | An operator-selected mapping approved by a different operator counts as exact. | `OPERATOR_SELECTED` → `EXACT_CONFIGURED_MAPPING`, unchanged. |
| D39 | A name-only match never counts as exact. | Unchanged (C-1, C-9). |
| D40 | A pure rename with unchanged SID and objectGUID remains informational. | Unchanged: surfaced as drift, re-acknowledged by a new approval. |
| D41 | Mapping reviews and policy reviews get dedicated audit actions through a new migration; historical events stay unchanged. | Migration 0005 adds `MAPPING_REVIEW_RECORDED` and `POLICY_REVIEW_RECORDED`. Events recorded earlier keep `APPROVAL_RECORDED` with their `kind` detail; their rows and digests are preserved byte for byte. |
| D43 | `EVIDENCE_INCOMPLETE` remains a distinct classification. | Unchanged. |

## 2026-10-05 — roles and identity

| # | Decision | Consequence |
| --- | --- | --- |
| D46 | OGWA defines the application roles `IDENTITY_AUTOMATION` and `SECURITY_IAM`. | Generalizes the policy-review roles of D33 to application roles of the operator API. |
| D47 | Production role bindings use stable IdP group IDs, never group display names. | A binding names an immutable group id; a display-name match grants nothing. |
| D48 | Role bindings are deployment-controlled configuration for now and cannot be edited by ordinary OGWA operators. | There is no operator-facing write path to role bindings. |
| D49 | A principal may hold both roles, but the same principal may never act as both proposer and approver of the same reviewed action. | Four-eyes is per action and per principal, independent of the roles held (as already enforced for mapping and policy reviews). |
| D50 | The operator API stays `LOCAL_SYNTHETIC`: no production Okta credentials, no SSO connection. | D6, D18, D28 unchanged. |
| D51 | Authentication and authorization are built on synthetic authenticated-principal claims behind an adapter boundary. No real JWT verification without an approved verification library or service. | The adapter is the only place a real identity provider will plug in. |
| D52 | Production policy v1 stays unrecorded until authenticated operator identities exist. | Refines D35: v1 is defined (the template) but not recorded in any production store. |
| D53 | Okta AD integration ids stay empty in v1. The real ids must be validated before a reviewed v2 may add them. | Every group is `NOT_AD_SOURCED` under v1 (fail closed). |
| D56 | Unverified directory-source SID evidence is not labelled "name only". It is exposed as a distinct unverified-identifier result, still non-exact. | Refines D37: a new `UNVERIFIED_STABLE_ID` confidence and `UNVERIFIED_IDENTIFIER` correlation outcome; migration 0006. |

## 2026-10-05 — operator API

| # | Decision | Consequence |
| --- | --- | --- |
| D58 | The operator API is the contract the UI is built on. | The UI reads and acts only through the API routes in [api.md](api.md). |
| D59 | Keep the roles `VIEWER`, `EXECUTOR`, and `ADMINISTRATOR` alongside D46's two. | Five application roles; the permission table is in [../security/authorization.md](../security/authorization.md). |
| D60 | `VIEWER` is strictly read-only. | `VIEWER` holds exactly `READ_INVENTORY` (pinned by test). |
| D61 | `EXECUTOR` may plan dry runs for already-approved stages only; it has no mapping, policy, or approval power. | `EXECUTOR` holds exactly `READ_INVENTORY` and `EXECUTION_PLAN_DRY_RUN`; planning needs a valid approval of that stage by someone else. |
| D62 | `ADMINISTRATOR` handles operational and configuration concerns only and has no lifecycle authority. | `ADMINISTRATOR` holds exactly `READ_INVENTORY`, `READ_AUDIT`, `READ_SYSTEM`. |
| D63 | No lifecycle permission is inherited implicitly from `ADMINISTRATOR`. | Code checks permissions, never role names; a test fails if any API module refers to a role outside the role table. |
| D64 | Unauthenticated, malformed, and generic authorization failures stay in the security log. | 401s, CSRF/Origin refusals, a route's static permission refusal (raised before the request is read), 400/404/422 stay out of the audit chain. |
| D65 | Authenticated, valid attempts at governed state changes that policy or authorization refuses are recorded in the hash-chained audit trail under a dedicated action. | Migration 0007 adds `GOVERNED_REQUEST_REFUSED`. A 403 or 409 on a governed route, after authentication, CSRF, the static permission, and body validation passed, is chained (refused lifecycle transitions keep `TRANSITION_REFUSED`, chained by the store). |
| D66 | The synthetic demo policy may stay unrecorded, but every API/UI surface labels it `DEMO POLICY — UNRECORDED`. | Every response carries `policyNotice` and `X-OGWA-Policy-Status: DEMO-UNRECORDED` while it is in force; every policy view carries `label`. |
| D68 | In `LOCAL_SYNTHETIC` only, wire the synthetic AD directory into the running API so mapping-review flows work end to end. No production AD adapter. | `app/demo/synthetic_directory.py` over the store's own recorded AD evidence; it refuses any other mode or store environment. |

## 2026-10-05 — audit boundary and synthetic mappings

| # | Decision | Consequence |
| --- | --- | --- |
| D72 | Confirm the audit boundary. A caller who lacks permission to use a route at all gets a normal authorization failure, in the security log only. An authenticated caller who is permitted to use the route, and whose well-formed governed request is then refused by lifecycle, policy, evidence, or separation-of-duties rules, gets a hash-chained `GOVERNED_REQUEST_REFUSED`. | Confirms D64 and D65. The execute route requires `EXECUTION_PLAN_DRY_RUN` or `EXECUTION_EXECUTE` statically, so a VIEWER's attempt stays in the security log, and only an executor's attempt (refused by the build) is chained. |
| D73 | Preserve that distinction; never hash-chain ordinary route-level authorization failures. | Pinned by the route-permission matrix test and the security-log test, which include the execute route. |
| D74 | Seeded exact mappings must match what the running correlation engine can prove. | See D75–D78. |
| D75 | Synthetic mapping evidence is produced through the correlation engine, never inserted as already-exact lifecycle evidence. | The seed records what `app.demo.synthetic_directory.correlate_stored_group` returns, and stops if the engine proves anything other than the scenario expects. |
| D76 | Prefer synthetic stable identifiers in the demo world, and let the synthetic-only correlation path establish the mapping. | `config/correlation.synthetic.json` names each exact pairing by objectGUID and objectSid; the engine must resolve both in the synthetic directory, giving `EXACT_CONFIGURED_MAPPING`. Okta's own copy of the objectSid is not stored (it would need a schema change). |
| D77 | Do not enable or weaken any production SID/GUID verification gate for demo purposes. | `DIRECTORY_SOURCE_SID_VERIFIED` and `OBJECT_GUID_DECODING_VERIFIED` stay `False`; a test shows a directory-source objectSid alone is still `UNVERIFIED_STABLE_ID` in the demo. |
| D78 | A synthetic mapping the engine cannot prove exact stays review-required; it is never seeded as exact. | A group the configuration does not name can only be name-matched. The demo has no `EXACT_STABLE_ID` or `EXACT_DIRECTORY_SOURCE` mapping. |

## 2026-10-05 — directory SID metadata

| # | Decision | Consequence |
| --- | --- | --- |
| D81 | `config/correlation.synthetic.json` is the source of stable identity for the synthetic demo world. | Confirms D76. |
| D82 | A synthetic exact mapping may be established when the normal correlation engine proves that the configured synthetic objectGUID and objectSid both resolve to the same synthetic AD group. | The `CONFIGURED` path, unchanged; a mismatched SID is `STALE`, an Okta SID naming another group is `CONFLICT`. |
| D83 | Do not require two-person human approval merely to create deterministic synthetic exact mappings; keep separate scenarios that demonstrate the human-review path. | S08 (`NAME_ONLY`, approval refused) and S09 (`AMBIGUOUS`, resolved through the two-person API flow) are kept. |
| D84 | Persist Okta's directory objectSid through a new schema migration. | Migration 0008. |
| D85 | Store it explicitly as unverified source metadata, not as exact mapping evidence. | Column and field `directory_object_sid_unverified`; API `directoryObjectSidUnverified`. |
| D86 | Preserve provenance and freshness with the existing evidence model. | It is a field of the Okta group observation, so it shares that observation's provenance and freshness rules; digests of observations without it are unchanged. |
| D87 | D37 remains authoritative: an Okta directory SID alone cannot establish an exact production mapping until that source is validated against a known AD-backed Okta group. | `DIRECTORY_SOURCE_SID_VERIFIED` stays `False`; alone it gives `UNVERIFIED_STABLE_ID`; it can only corroborate. |
| D88 | No production SID/GUID verification gate may be enabled or weakened for demo behavior. | Restates D77. |

## 2026-10-05 — audit anchor and UI evidence paths

| # | Decision | Consequence |
| --- | --- | --- |
| D94 | Record the synthetic store's audit head outside the database, in a durable, repo-tracked audit-anchor document. | [../operations/audit-anchors.md](../operations/audit-anchors.md). |
| D95 | The recorded anchor of the local synthetic store is `sha256:a3c53e52f912f99475162164fd05d67db32c3bfc8a68e0ae3e4e215d111ddd83`, 300 audit events, schema 8. | Verified with `python -m app.store verify --expected-audit-head` before it was recorded. Later migrations must preserve it (D150). |
| D96 | A copy of a store, such as a temporary backup, is not durable evidence of its audit head. | Only a head recorded in the audit-anchor document (D94) and checked with a reproducible command counts. |
| D97 | The UI distinguishes "directory SID observed but unverified / AD evidence unavailable" from genuinely stale evidence, and never says recollection will fix a condition unless that is true. | UI requirement. |
| D98 | S08, S09, S10, and S13 stay visibly distinct in the UI, so the name-only, ambiguous, not-found, and incomplete/unavailable evidence paths can all be demonstrated. | UI requirement. |

## 2026-10-05 — operator actions and evidence states

| # | Decision | Consequence |
| --- | --- | --- |
| D101 | The operator's Hold moves a candidate to `BLOCKED`. The lifecycle's `HOLD` remains exclusively the waiting period after the Okta unassignment. | Documented in [ui.md](ui.md). |
| D102 | Decline approval records an approval rejection and does not change the candidate's lifecycle state. | — |
| D103 | Reject candidate is a separate, terminal action and requires explicit confirmation. | — |
| D104 | Request revalidation moves a candidate to `REVALIDATION_REQUIRED`. Operators must never manually assign `STALE_EVIDENCE`. | The lifecycle allows `→ STALE_EVIDENCE` to system actors only; the API refuses it to everyone (`NOT_AN_OPERATOR_ACTION`, chained). The same rule applies to `EVIDENCE_INCOMPLETE` (D106, D114). |
| D105 | The UI does not offer submit-for-review, the detailed block-state actions, or a mapping-review UI. A mapping-review UI is required before a production pilot. | Open item before a pilot. |
| D106 | Correct the mismatch between incomplete and stale evidence. `EVIDENCE_INCOMPLETE` means required evidence was never fully or properly obtained; `STALE_EVIDENCE` means once-complete evidence exceeded its freshness window. Prefer an explicit `EVIDENCE_INCOMPLETE` lifecycle state if the migration is reasonably contained. | Lifecycle state `EVIDENCE_INCOMPLETE`, migration 0009 (rebuilds `candidates` and `decisions`; rows, digests, and the audit head unchanged), the classifier's `EVIDENCE_INCOMPLETE` diverts there, and `recommend_diversion` tells the two apart per record. Under these definitions a future-dated record forces `EVIDENCE_INCOMPLETE`, not `STALE_EVIDENCE` (D116). |
| D107 | Do not hard-code the 168-hour approval limit in the browser. Expose the applicable maximum through a read-only API/policy field and derive the UI's limit from the server. | Every policy view carries `approvalMaxValidHours`; the UI reads it and has no literal limit (pinned by a test). |
| D108 | The Node-based UI logic tests become part of the standard check. | `scripts/check.ps1` requires Node; `tests/test_ui_assess.py` fails, not skips, without it. |
| D109 | `scripts/browser-check.ps1` remains a separate suite but is a required pre-pilot and pre-release gate whenever the supported browser environment is available. | The script reports GATE PASSED (0), GATE FAILED (1, including any skipped test), or GATE NOT RUN (2, no supported browser). |
| D110 | Preserve the browser suite's external-host blocking and CSP assertions. | `tests/test_browser_gate_guards.py` (standard check) pins them; the suite also proves CSP enforcement in the real browser. |

## 2026-10-05 — system-derived evidence states

| # | Decision | Consequence |
| --- | --- | --- |
| D114 | Extends D104: `STALE_EVIDENCE` and `EVIDENCE_INCOMPLETE` are system-derived states and are never directly assignable by an operator. | The lifecycle allows both diversions to system actors only, and the API answers `NOT_AN_OPERATOR_ACTION`. |
| D115 | Operator actions may cause recollection or revalidation, or place a candidate on Hold, but operators cannot assert evidence-condition states. | The UI offers Request revalidation (`→ REVALIDATION_REQUIRED`) and Hold (`→ BLOCKED`). This build has no recollection trigger (no collector scheduling); one would request collection, never set a state. |
| D116 | Future-dated evidence is never fresh and never stale. Treat it as incomplete or invalid evidence and, where practical, expose a distinct reason such as `FUTURE_DATED_EVIDENCE`. | The classifier's existing distinct reason `EVIDENCE_FUTURE_DATED` is kept (not renamed). It forces `EVIDENCE_INCOMPLETE`, and a future-dated record is never also stale or current (tested). The UI says "Future-dated evidence — invalid" and marks the record "Future-dated (invalid)". A record within the policy's clock-skew tolerance is not future-dated (the domain freshness rule, unchanged). |

## 2026-10-05 — remediation and AAP

| # | Decision | Consequence |
| --- | --- | --- |
| D122 | Any production integration starts as a bounded, read-only gate. | No production mutation in that gate. D18's preconditions for the first live AD read still apply. The live integrations are not included in this build. |
| D123 | Provision a dedicated OGWA AAP service identity. Never use a personal or shared AAP token. | No OGWA AAP credential exists until the AAP owners provision one. This build accepts none: `OGWA_AAP_TOKEN` is refused at startup. |
| D124 | AAP System Auditor is acceptable for an initial read-only gate if the AAP owners approve it. It is the maximum acceptable initial privilege; prefer a narrower, OGWA-specific read-only role when feasible. | Discovery must accept the System Auditor flag and the read-only roles `Read`, `Auditor`, and `Member`, and nothing else. AAP discovery is not included in this build. |
| D125 | The OGWA AAP identity must not be able to launch, create, update, delete, or administer AAP objects. | Before listing anything, discovery must check the identity: a superuser is refused, and every direct and team role must be read-only. A listed template that the identity could start, edit, delete, copy, or schedule stops discovery. |
| D126 | Create no OGWA AAP template before or during a read-only gate. Discover existing AAP objects first. A dedicated what-if or validation template, if one is needed, comes later as a separately approved production change. | OGWA has no write path to AAP, and the synthetic allowlist names no template. |
| D128 | One AD approval may not authorize both quarantine and deletion. | The lifecycle's AD-stage approval (stored as `AD_RETIREMENT`) authorizes AD quarantine only. |
| D129 | AD quarantine and AD deletion are separate governed stages. | When decided, the lifecycle had no post-quarantine deletion stage, so nothing could authorize a deletion and the remediation operation `AD_GROUP_DELETE` was always `BLOCKED`. The deletion stage is modelled by D143–D155, with its own approval stage (D147). |
| D130 | Any future AD deletion requires a new approval bound to fresh post-quarantine, post-hold revalidation evidence. | A requirement on the deletion stage (D139, D143, D145). |
| D131 | Complete AD dependency coverage is not required merely to remove an Okta application assignment. It remains mandatory before AD retirement or deletion. | `OKTA_GROUP_UNASSIGN` does not require COMPLETE coverage; AD operations do. |
| D132 | Known AD members, or incomplete or unknown membership evidence, block every remediation operation, including Okta unassignment and AD quarantine and deletion. | For every operation, `NO_DEPENDENCY_BLOCKER` requires COMPLETE `AD_GROUP_MEMBERS` and `AD_NESTED_MEMBERSHIP` checks of the mapped AD group and a known direct member count of zero. |
| D133 | A dry-run request may return `BLOCKED` with reasons, but a blocked condition must never yield an executable plan. | A blocked request never reaches an adapter and carries no planned change; the worker's `Blocked` results plan nothing (R-17). |

## 2026-10-06 — AD quarantine and deletion rules

| # | Decision | Consequence |
| --- | --- | --- |
| D136 | Quarantine OU mappings belong in separate, deployment-controlled configuration, not in the candidate policy. Ordinary operators cannot edit them. | The candidate policy and its pinned v1 digest are unchanged (D32, D35). The mappings are in `config/quarantine-ous.synthetic.json`, which the server reads at start-up, and the lifecycle reads them to recognise a confirmed quarantine. No operator role, and no API route, can change configuration. |
| D137 | The AD deletion approver must differ from both the quarantine approver and the deletion proposer. | It adds to the existing rules: no stage can be approved by the candidate's proposer, and the AD-stage approver differs from the Okta-stage approver (D11). Whether the deletion approver must also differ from the Okta-stage approver is settled by D143. |
| D138 | The initial post-quarantine hold is 30 days, counted from the confirmed observation that the group is in its quarantine OU. | The hold starts from that observation, not from the quarantine approval or its dry run. Its length equals today's default Okta-stage `hold_period`, but it is a separate hold. |
| D139 | Completing the hold never authorizes deletion by itself. Fresh revalidation and a new, independent deletion approval are both mandatory. | Sharpens D130. The end of the hold only allows revalidation to begin. A deletion approval must be bound to that fresh revalidation evidence and meet D137. Nothing moves a candidate toward deletion merely because time has passed. |
| D140 | The lifecycle models AD quarantine, hold, revalidation, and deletion, in `LOCAL_SYNTHETIC` only. | Migration 0011 and D143–D155. |
| D141 | A production integration gate stays strictly read-only. | Confirms D122. It carries none of the AD-stage lifecycle work. |
| D142 | Do not enable any production deletion execution path. | The remediation worker's JSON boundary accepts only `WhatIf` and `ValidateOnly`. `BUILD_ALLOWS_PRODUCTION_MUTATION` stays `False` (D8). Deletion is modelled in `LOCAL_SYNTHETIC` only. |

## 2026-10-06 — AD quarantine and deletion lifecycle

| # | Decision | Consequence |
| --- | --- | --- |
| D143 | The deletion approver must differ from the deletion proposer, the quarantine approver, and the earlier Okta-unassignment approver. | Settles the point D137 left open. Enforced by the lifecycle guard of `DELETION_PROPOSED` → `DELETION_APPROVED`, by the API's approver checks (`SEPARATION_OF_DUTIES`, and the conflicts `allowedActions` shows), by the remediation gate `VALID_APPROVAL`, and when a candidate's history is loaded. |
| D144 | A candidate blocked after quarantine never returns to the pre-quarantine lifecycle. | From a post-quarantine block, re-entry at `CANDIDATE` or `REVALIDATION_REQUIRED` is refused. History replay rejects such a history. A CHECK on `candidates` (migration 0011) refuses a quarantined candidate in, or blocked from, a pre-quarantine state. |
| D145 | When a post-quarantine blocker is resolved, the candidate proceeds to `REVALIDATION_REQUIRED`, requires fresh complete evidence, and then requires a new deletion proposal and approval. | Read with D155: re-entry is at `DELETION_REVALIDATION_REQUIRED`, after the post-quarantine hold, on evidence collected after it. Re-entry starts a new epoch and clears the proposal, so the earlier deletion approval is void. |
| D146 | Previous Okta or quarantine approvals may never be reused to authorize deletion. | A deletion step accepts only an `AD_DELETION` approval of the current epoch, given after the proposal. The store refuses a job whose approval is of another stage. |
| D147 | Introduce `AD_QUARANTINE` and `AD_DELETION` as the governed approval stages. | Both are approval stages and job kinds (migration 0011). Each authorizes its own stage only. |
| D148 | Preserve existing `AD_RETIREMENT` rows as legacy historical records; do not rewrite historical approval or audit evidence. New approvals may not use `AD_RETIREMENT`. | Stored rows are kept verbatim and authorize nothing. The legacy single AD stage's two transitions stay in the table for history only, and are always refused. A new `AD_RETIREMENT` approval or job, or a new decision of the legacy stage, is refused by the API (`LEGACY_AD_RETIREMENT`), the store, and database triggers. |
| D149 | No unquarantine or restore operation. | None exists. A group observed outside its quarantine OU after the quarantine blocks the deletion stage; the candidate cannot go back. |
| D150 | Migration 0011 must preserve every existing row and the D95 audit chain, and is rehearsed on a copy before a store is upgraded. | `tests/test_ad_stages_migration.py` is that rehearsal's contract. The upgraded local synthetic store was verified with anchor D95 at schema 11. |
| D152 | The AD quarantine and deletion stages run only in `LOCAL_SYNTHETIC`. | The operator API serves `LOCAL_SYNTHETIC` only (D50). The stages are exercised on synthetic data: seed scenarios S15 and S16, and `config/quarantine-ous.synthetic.json`. |
| D153 | No production deletion, quarantine, or restoration execution path may be enabled. | `BUILD_ALLOWS_PRODUCTION_MUTATION` is `False`, no application module imports an outbound network or process module (D8), no role holds `EXECUTION_EXECUTE`, and the execute route refuses everyone. Every job is a dry run, and no remediation outcome is an execution. |
| D154 | A production integration gate remains strictly read-only. | Confirms D122 and D141. |
| D155 | After the quarantine, when its hold has ended or a post-quarantine blocker is resolved, the candidate is revalidated in a dedicated state, `DELETION_REVALIDATION_REQUIRED`. | D145's `REVALIDATION_REQUIRED` is read as this state. Each state has one meaning, and no transition leads from a post-quarantine state back to `REVALIDATION_REQUIRED` or earlier. |
