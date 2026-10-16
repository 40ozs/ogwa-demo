# Mutation gates

This document describes every gate between an operator's request and a change to Okta or
Active Directory. There are two kinds.

**Layers that make production mutation impossible in this build (D8).** Each one alone
is enough:

| # | Layer | Enforced in | Tests |
| --- | --- | --- | --- |
| 1 | The build forbids `PRODUCTION_MUTATION`. No configuration changes that | `BUILD_ALLOWS_PRODUCTION_MUTATION = False` (`app/core/build.py`), `assert_mode_permitted_by_build` | `test_execution_modes.py`; `test_every_layer_below_the_api_refuses_production_mutation_too` |
| 2 | Startup and settings refuse the mode | `app/core/config.py`, `startup.py` | `test_execution_modes.py` |
| 3 | The build has no outbound client: no application module imports a network, process, or HTTP-client module, and no live integration module or worker is in the build | `OUTBOUND_MODULES` (`tests/test_mutation_safety.py`) | `NoOutboundClientTests`; `DemoOnlyEscapeTests`; `test_the_remediation_package_cannot_reach_a_network_or_a_process` |
| 4 | Every remediation adapter's mutation policy is `DRY_RUN_MUTATION`, which can only plan; the operation it passes raises if called | `RemediationAdapter` (`app/remediation/adapters.py`) over `MutationCapableService` | `test_every_adapter_only_plans` |
| 5 | No adapter can reach a system. The synthetic adapter reads recorded evidence; the AAP adapter has no HTTP client | `adapters.py` | `test_no_socket_connection_or_process_is_used`; `test_the_adapter_holds_no_way_to_reach_aap` |
| 6 | No outcome or record can say "executed" | `RemediationOutcome` (four members), `RemediationResult.__post_init__`; `Store.record_remediation_dry_run`; `ExecutionJob` (X-1, X-2); database CHECKs (S-9) | `test_the_outcomes_are_exactly_the_four_non_executing_ones`; `test_a_result_can_never_claim_an_execution`; `test_the_store_cannot_record_an_execution_or_a_blocked_dry_run` |
| 7 | The API refuses any request for production mutation before anything else, and the execute route refuses everyone | `post_remediation_dry_run`, `RemediationService.dry_run`; `LifecycleService.execute` | `ProductionMutationSelectionTests`; `test_even_every_permission_cannot_turn_a_dry_run_into_an_execution` |
| 8 | The worker has no production adapter, and its JSON boundary has no mode that changes anything | `worker/OGWA.Remediation` (W-1 to W-9) | `Test-OgwaRemediation.ps1`; `test_remediation_worker_safety.py` |

**Synthetic drills change none of these layers.** A drill's synthetic
execution changes only an in-memory `SyntheticProviderFixture`, built from a candidate's
SYNTHETIC evidence and discarded after the answer. It is the one mutation-capable component
the application builds with a policy that can execute (`LOCAL_SYNTHETIC`, which executes
only against a synthetic target): the planner and the remediation adapters build
their own `DRY_RUN_MUTATION` policy, and no application module can import an outbound client
(layer 3; `test_only_the_fixture_may_hold_a_policy_that_can_execute`). A
drill's dry run gives the fixture `DRY_RUN_MUTATION`. It produces no `RemediationOutcome`, creates no job, uses no route of
layer 7, imports nothing layer 3 forbids, and records nothing. A drill starts with every
gate below, and evaluates them again before any retry. See
[../architecture/remediation-execution.md](../architecture/remediation-execution.md) (RX-1 to
RX-10).

**The hard gates.** They decide whether a dry run may even be simulated or validated.
A request that fails any of them is `BLOCKED`. One that passes them all still gets only
`SIMULATED`, `WHATIF`, or `VALIDATION_ONLY`.

## The hard gates

`evaluate_gates` (`app/domain/remediation.py`) is pure. It evaluates every gate, so a
refusal names every reason at once, and the API returns them all with
`409 REMEDIATION_BLOCKED`. The first eight are the required gates. The last two are
backstops that keep remediation at least as strict as the rest of OGWA.

| Gate | Passes only when | Tests (`test_remediation_gates.py` unless noted) |
| --- | --- | --- |
| `EXECUTION_MODE_PERMITS_DRY_RUN` | The process mode can plan a mutation (`LOCAL_SYNTHETIC`, the only mode this build runs, or `DRY_RUN_MUTATION`), and the request names no mode but `DRY_RUN_MUTATION`. `READ_ONLY_PRODUCTION` and anything unknown fail | `ExecutionModeGateTests` |
| `SINGLE_EXPLICIT_TARGET` | One target id of the operation's kind, inside the candidate's scope: one of its assignments, or exactly its mapped AD group. Its identity is resolved from recorded evidence, never from a name or a pattern | `SingleExplicitTargetTests`; API `test_a_request_names_exactly_one_explicit_target` |
| `EXACT_VERIFIED_MAPPING` | The mapping is for this Okta group and has an `EXACT_*` confidence from a COMPLETE observation, and the mapped AD group was observed, by objectGUID, to exist. `NAME_ONLY` and `UNVERIFIED_STABLE_ID` never pass (D37, D39, D56) | `MappingGateTests` |
| `FRESH_EVIDENCE` | Every record is COMPLETE, not future-dated beyond the skew tolerance (D116), and inside the EXECUTION window (at most 24 hours, E-3) | `FreshEvidenceTests`; API `StaleEvidenceTests` |
| `NOT_PROTECTED` | `protection_reasons` is empty: no built-in Okta group, configured protected list (D10), well-known SID or RID < 1000, adminCount, deletion protection, or critical system object. Protection must also be determinable: an incomplete AD record means unknown protection, which blocks (D21) | `ProtectionGateTests`; API `ProtectedGroupTests` |
| `VALID_APPROVAL` | An `APPROVE` for this operation's stage, candidate, and epoch. It is unexpired, within the policy's maximum lifetime, and not by the candidate's proposer. For AD quarantine (`AD_QUARANTINE`): given after the Okta hold by a different human from the Okta-stage approver (D11). For AD deletion (`AD_DELETION`): given after the post-quarantine hold and after the deletion was proposed, by a human who is not the proposer, the quarantine approver, or the Okta-stage approver (D143). No other stage's approval, and no legacy `AD_RETIREMENT` approval, counts (D146, D148) | `ApprovalGateTests`, `DeletionStageTests` |
| `APPROVAL_FINGERPRINT_MATCHES` | The approval was given on exactly the current evidence fingerprint | `FingerprintAndIdentityTests`; API `TargetIdentityTests`, `test_a_material_change_voids_the_approval` |
| `NO_DEPENDENCY_BLOCKER` | No blocking dependency finding. For **every** operation, the Okta unassignment included, membership evidence of the mapped AD group is complete and empty: COMPLETE `AD_GROUP_MEMBERS` and `AD_NESTED_MEMBERSHIP` checks, and a known direct member count of zero; a missing or incomplete check blocks (D132). For AD operations only, dependency coverage is COMPLETE (P-1, D131) | `DependencyGateTests`, `MembershipEvidenceTests` (gates and `test_post_p10_decisions.py`) |
| `SEPARATION_OF_DUTIES` | A named human requests it, and not the stage's approver (D49) | `SeparationAndLifecycleTests`; API `test_the_approver_cannot_request_the_dry_run_of_their_own_stage` |
| `LIFECYCLE_RULES` | The candidate is at the operation's stage: `APPROVED` or `OKTA_UNASSIGN_DRY_RUN` for the Okta unassignment, `QUARANTINE_APPROVED` or `QUARANTINE_DRY_RUN` for AD quarantine, `DELETION_APPROVED` or `DELETION_DRY_RUN` for AD deletion. The lifecycle's own rules for that stage hold: consistency, AD origin (D12), assignments present (Okta) or still absent (AD), usage, and the group outside (quarantine) or inside (deletion) its domain's quarantine OU, per the deployment's configuration (D136). When every other gate passes, the lifecycle's full guard for the stage's step is evaluated as well, with a hypothetical successful dry run that is never recorded | `SeparationAndLifecycleTests`, `DeletionStageTests` |

### What the five proofs rest on

| Proof | Why it holds | Tests |
| --- | --- | --- |
| A valid approval still cannot cause production mutation | Layers 1 to 8: every gate passing yields `SIMULATED` (synthetic) or `VALIDATION_ONLY` (AAP), recorded as such. The candidate does not move, no job is created, and no socket, process, or HTTP connection is used | `ValidApprovalCannotMutateProductionTests` |
| Direct attempts to select production mutation are rejected | `PRODUCTION_MUTATION` or `dryRun: false` is refused first, other modes are `422`, and fields such as `execute`, `outcome`, or `templateId` are unknown (`422`). The service, the gates, the mutation policy, the settings loader, and the worker boundary each refuse again | `ProductionMutationSelectionTests`; "the boundary has no mode that changes anything" in `tests/powershell/Test-OgwaRemediation.ps1` |
| Stale evidence invalidates approval | `FRESH_EVIDENCE` fails once evidence is older than 24 hours, even while the approval is unexpired. Re-observing the same facts restores freshness without a new approval; a material change also fails `APPROVAL_FINGERPRINT_MATCHES` | `StaleEvidenceTests`; `FreshEvidenceTests` |
| Changing target identity invalidates approval | The target's identity is part of the evidence. Any change to objectSid, DN, sAMAccountName, objectGUID, or domain changes the fingerprint, and a re-pointed mapping fails `SINGLE_EXPLICIT_TARGET` as well. The worker re-verifies the identity live (`TARGET_IDENTITY_CHANGED`) | `TargetIdentityTests`; `test_changing_the_target_identity_invalidates_the_approval`; worker `a changed identity blocks` |
| Protected groups cannot be overridden by normal operators | No request field, role, or permission overrides protection, and none exists. Granting every permission to every role still gets `NOT_PROTECTED`. The worker refuses protected groups even when the caller agrees. Unknown protection is never overridable (D21). Protection can only be added (D10), never removed | `ProtectedGroupTests`; worker `protected groups are Blocked whatever the caller agrees to` |

## AD quarantine and deletion are separate stages (D128–D130)

One AD approval may not authorize both quarantine and deletion (D128). The lifecycle models
the two stages (D143–D155; see
[../architecture/lifecycle-state-machine.md](../architecture/lifecycle-state-machine.md#the-ad-stages)),
in `LOCAL_SYNTHETIC` only (D152). What each path does now:

| Path | What happens | Tests |
| --- | --- | --- |
| The quarantine approval (`AD_QUARANTINE`) | Given in `REVALIDATION_REQUIRED` by a second human (D11). It authorizes `AD_GROUP_QUARANTINE`, and the lifecycle's quarantine dry run, only | `test_the_quarantine_approval_authorizes_quarantine_and_never_deletion`, `QuarantineApprovalGuardTests` |
| The deletion proposal | `DELETION_REVALIDATION_REQUIRED` → `DELETION_PROPOSED`, by a human with `LIFECYCLE_ADVANCE`, after the 30-day post-quarantine hold, on complete evidence collected after it, with the group in its quarantine OU (D130, D138, D145) | `DeletionProposalGuardTests` |
| The deletion approval (`AD_DELETION`) | Given in `DELETION_PROPOSED`, after the proposal, by a human who is not the proposer, the quarantine approver, or the Okta-stage approver (D143). Only this approval authorizes `AD_GROUP_DELETE` or the lifecycle's deletion dry run (D146) | `DeletionApprovalGuardTests`, `test_quarantine_hold_proposal_and_deletion_each_need_their_own_people` |
| The end of the post-quarantine hold | Opens revalidation, and nothing else: no approval, proposal, or dry run is reachable from `QUARANTINE_HOLD` (D139) | `test_the_end_of_the_hold_authorizes_nothing` |
| A block after quarantine | Re-enters only at `DELETION_REVALIDATION_REQUIRED`, never earlier (D144); the proposal is cleared and a new epoch voids the old approval (D145) | `PostQuarantineReentryTests`, `PostQuarantineBlockTests` |
| The legacy single AD stage (`AD_RETIREMENT`) | History only. Approving it, planning its job kind, or recording its steps is `409 LEGACY_AD_RETIREMENT`; the store and database triggers refuse new rows. Stored rows are kept verbatim and authorize nothing (D148) | `LegacyStageTests`, `test_the_legacy_single_ad_stage_can_be_neither_approved_planned_nor_recorded`, `test_nothing_new_may_use_the_legacy_stage` |
| A restore (unquarantine) | Does not exist (D149) | — |

Every one of these is a decision or a dry run. No production deletion, quarantine, or
restoration path exists (D153).

## A blocked condition never yields a plan (D133)

A dry-run request may come back `BLOCKED` with every reason, and nothing else:

- a request that fails any gate never reaches an adapter, so no change is even computed;
- the `409` body carries the gates and their problems, never a planned change or a launch
  payload;
- a `BLOCKED` `RemediationResult` or adapter answer with a planned change cannot be built;
- the worker's `Blocked` results always have an empty `plannedChanges`, and OGWA refuses one
  that does not;
- a refused lifecycle dry run creates no job and returns no `plannedActions`.

Tests: `BlockedNeverPlansTests`, `ResultRecordTests`, `test_a_tampered_result_is_refused`.

## The AAP identity (D123–D126)

This build includes no AAP discovery client and holds no AAP identity or token, so the
identity rules (D123–D125, in [../architecture/decisions.md](../architecture/decisions.md))
have nothing to apply to. OGWA has no write path to AAP at all and creates no AAP template
(D126): the AAP remediation adapter only checks a reviewed template's recorded metadata and
never launches it (`AapAdapterTests`, `test_the_adapter_holds_no_way_to_reach_aap`).

## Anti-footgun controls

| Control | How |
| --- | --- |
| No bulk execution API | One candidate in the path and one target object with one field. Lists, extra fields, and plural keys are `422`. There is no remediation collection route and no remediation execute route (`test_there_is_no_bulk_remediation_and_no_remediation_execute_route`) |
| At most one lifecycle target per request | The candidate is the path's only subject. Every governed write route names exactly one subject |
| No free-form PowerShell | The worker accepts no script, scriptblock, or command. It runs no dynamic code (no `Invoke-Expression`, no `&` on a variable) and imports no module. Its adapter is data, not code, and only the module's own functions act on it (W-3, W-4) |
| No browser-supplied AAP template id | The request has no such field (`422`). The template comes only from the server-side allowlist, pinned to a reviewed record |
| Server-side allowlist | `config/remediation-allowlist.*.json`, environment-bound and strict; an unlisted operation is `BLOCKED` |
| Operation-specific schemas | API: `target` has exactly `assignmentId` (Okta) or `adGroupId` (AD). Worker: each operation's target keys are fixed in `contract.json` and enforced on both sides |

## Recording

| Event | Where |
| --- | --- |
| A dry run answered `SIMULATED`, `WHATIF`, or `VALIDATION_ONLY` | Audit chain, `REMEDIATION_DRY_RUN_RECORDED` (migration 0010): actor, candidate, operation, outcome, adapter, target and identity digest, approval, fingerprint, planned changes, `executed: false` |
| A `BLOCKED` dry run, or any other `403`/`409` after validation | Audit chain, `GOVERNED_REQUEST_REFUSED` (0007), with `request.operation` and `request.target.<field>` |
| Unauthenticated, CSRF, a route's static permission, or a malformed body | API security log only (D64, D73) |

## Changing a gate

A gate may be made stricter in an ordinary reviewed change. Making one looser, removing
one, or relaxing its test weakens a guardrail and needs an owner decision (D8). The same
applies to anything in the "impossible in this build" table.
