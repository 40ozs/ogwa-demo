# Safety invariants

These invariants hold in the current build. Each one names where it is enforced and which
tests prove it. Weakening one, including relaxing its test, counts as weakening a
guardrail under owner decision D8 ([../architecture/decisions.md](../architecture/decisions.md)).

Execution modes and the mutation policy are described in
[execution-modes.md](execution-modes.md). The first table restates the build invariants the
rest depend on.

## Build invariants

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| I-1 | `PRODUCTION_MUTATION` cannot be enabled by configuration | `app/core/build.py`, `modes.py`, `config.py`, `startup.py`, `safety.py` | `test_execution_modes.py` |
| I-2 | Mutation-capable code needs an injected `MutationPolicy`; read-only modes deny or only plan | `app/core/safety.py` | `test_mutation_safety.py` |
| I-3 | The build has no outbound client: no application module imports a network, process, or HTTP-client module (the demo's WSGI server is the one approved server import), and no Okta, AAP, or HTTP client module or AD reader is in the build | `OUTBOUND_MODULES`, `APPROVED_SERVER_IMPORTERS` (`tests/test_mutation_safety.py`); `REMOVED_MODULES` (`tests/test_runtime_mode.py`) | `NoOutboundClientTests` (`tests/test_mutation_safety.py`), `DemoOnlyEscapeTests` (`tests/test_runtime_mode.py`) |

## Domain invariants

### Purity

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| D-1 | The domain package performs no I/O. It cannot import network, subprocess, filesystem, database, HTTP-client, or mutation-policy modules | Code review | `DomainPurityTests` |
| D-2 | Every rule takes `now` explicitly; nothing reads the clock | `app/domain/*` | Deterministic synthetic tests throughout |

### State machine

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| L-1 | State changes only through the closed `TRANSITIONS` table. Every other (source, target) pair is refused, even with full evidence, approval, and job | `apply_transition` | `test_every_unlisted_transition_is_refused_even_with_full_evidence` |
| L-2 | New candidates start in `DISCOVERED`, and nothing can return there | `LifecycleCandidate.discover`, table | `test_discover_always_starts_in_discovered`, `test_nothing_returns_to_discovered_and_gates_have_one_entrance` |
| L-3 | Progressing states move one step forward only. Approval, dry-run, hold, and retirement states each have exactly one entrance | Table | `test_progressing_states_only_move_one_step_forward`, entrance test |
| L-4 | Terminal states (`RETIRED`, `EXCLUDED`, `REJECTED`, `PROTECTED`) have no outgoing transitions | Table | `test_terminal_states_have_no_outgoing_transitions`, `test_retired_is_terminal` |
| L-5 | Moving to a safer state is always possible from any non-terminal state, with only a reason | Diversion rules | `test_every_diversion_needs_only_a_reason` |
| L-6 | Only humans approve, exclude, reject, or lift a generic block | `TransitionRule.actors`, `ApprovalRecord` | `test_human_only_transitions`, `test_system_cannot_exclude_or_reject`, `test_generic_block_is_lifted_only_by_a_human` |
| L-7 | Re-entry after a block increments the epoch, which voids all earlier approvals | `apply_transition`, `approval_problems` | `test_reentry_increments_epoch_and_voids_earlier_approvals` |
| L-8 | A candidate blocked after unassignment cannot restart the pre-unassignment path, and one blocked before cannot jump ahead | `_g_reenter_*` | `test_reentry_point_depends_on_where_the_block_happened` |
| L-9 | A stored state that the decision history cannot reproduce is detected | `verify_history` | `HistoryTests` |
| L-10 | Every refusal and every applied transition can be audited | `apply_and_audit` | `test_apply_and_audit_records_applied_and_refused_transitions` |

### Evidence

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| E-1 | Every observation records source, time, scope, collector version, result status, and a material digest | `Provenance`, `Evidence` | `ProvenanceAndDigestTests` |
| E-2 | Only `COMPLETE` results drive decisions | `freshness_problems`, guards | `test_incomplete_results_are_never_fresh_enough`, candidacy, hold, and retirement refusals |
| E-3 | Destructive-path steps (dry runs, recording a removal or deletion) require evidence no older than 24 hours. The ceiling cannot be raised | `FreshnessPolicy`, `FRESHNESS_CEILINGS` | `test_ceilings_and_ordering_cannot_be_loosened`, "stale for EXECUTION" refusals |
| E-4 | Future-dated evidence beyond clock-skew tolerance is rejected | `freshness_problems` | `test_future_dated_evidence_is_rejected_beyond_skew` |
| E-5 | A recorded removal or deletion must have been observed after the dry run finished | `_observed_after_job` | "observed before the dry run finished" refusals |
| E-6 | Naive (timezone-less) datetimes are rejected everywhere | `check_utc` | `test_naive_datetimes_are_rejected` |

### Identity mapping

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| M-1 | `NAME_ONLY` supports investigation only: it can reach `NEEDS_REVIEW`, never `APPROVED` | `_exact_mapping` | `test_inexact_mappings_may_still_be_investigated`, `test_inexact_mapping_cannot_be_approved` |
| M-2 | `AMBIGUOUS` and `NOT_FOUND` can never advance toward retirement | `_exact_mapping`, `_clearance` | Approval, retirement, and re-entry refusals |
| M-3 | A mapping record's form matches its confidence (stable-ID attributes for `EXACT_STABLE_ID`, two or more candidates for `AMBIGUOUS`, a config reference for `EXACT_CONFIGURED_MAPPING`, and so on) and always carries a reason | `IdentityMapping.__post_init__` | `IdentityMappingTests` |
| M-4 | AD groups are keyed by canonical objectGUID and resolved in their own domain. Name alone is never an AD identity | `ADGroup` | `test_ad_group_rules` |
| M-5 | External identifiers cannot stand in for internal IDs | `check_id` | `test_external_or_wrong_kind_ids_are_rejected_as_internal_ids` |
| M-7 | Okta's directory objectSid is stored only as `directory_object_sid_unverified` (0008): validated as a SID, `APP_GROUP` only (domain and database), part of the Okta group observation's provenance, absent from the digest when absent, and passed to correlation only as the D37-gated directory-source claim | `OktaGroup`, v0008 CHECK, `okta_group_identity` | `tests/test_okta_directory_sid_migration.py`, `test_the_stored_okta_sid_alone_stays_review_required` |
| M-6 | Demo identity mappings are what the correlation engine proves over the synthetic directory with the synthetic mapping configuration; none is seeded as exact, a group the configuration does not name is at best `NAME_ONLY`, and no verification gate is changed for the demo (D75–D78) | `correlate_stored_group`, `_World.correlate` | `tests/test_synthetic_mapping_evidence.py` |

### Dependencies and protection

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| P-1 | AD retirement requires dependency coverage `COMPLETE`. `PARTIAL` and `UNKNOWN` prohibit it | `_g_retirement_dry_run` | `test_incomplete_coverage_holds_at_review_and_prohibits_deletion` |
| P-2 | Coverage is derived from decision-grade checks, never asserted. A failed check does not count | `assess_dependency_coverage` | `DependencyCoverageTests` |
| P-3 | Policy cannot drop the mandatory dependency kinds | `LifecyclePolicy` | `test_policy_cannot_be_loosened` |
| P-4 | A blocking dependency finding stops every forward move | `_blocking_dependencies` | Blocking-dependency refusals in each guard |
| P-5 | Protected groups (Okta built-in, well-known SID or RID < 1000, `adminCount`, `ProtectedFromAccidentalDeletion`, critical system object, configured list) never progress | `protection_reasons`, guards | `test_protection_reasons`, protected refusals |

### Approvals

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| A-1 | An approval is a record bound to candidate, stage, epoch, evidence fingerprint, and expiry, made by a named human | `ApprovalRecord` | `ApprovalRecordTests` |
| A-2 | A material evidence change voids the approval. Re-observing identical facts does not | `evidence_fingerprint`, `approval_problems` | `test_approval_is_invalidated_by_material_evidence_change`, `test_re_observed_identical_evidence_keeps_the_approval_valid`, `test_fingerprint_*` |
| A-3 | Expired, future-dated, over-long, rejected, wrong-stage, or wrong-candidate approvals are refused | `approval_problems` | `test_each_invalidating_condition`, approval-gate refusals |
| A-4 | The candidate's proposer cannot approve it | `approval_problems` | `test_proposer_cannot_approve_their_own_candidate` |
| A-5 | AD retirement needs its own approval, given after the hold period. The Okta-unassign approval cannot authorize it | Stage and `not_before` checks | `test_earlier_approvals_never_authorize_a_deletion`, "before the hold period ended" |
| A-6 | Approval lifetime is capped (default 7 days, maximum 14) | `LifecyclePolicy`, `approval_problems` | `test_policy_cannot_be_loosened`, "lifetime exceeds" |

### Execution

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| X-1 | An `ExecutionJob` in `PRODUCTION_MUTATION` cannot be constructed | `ExecutionJob.__post_init__` with `assert_mode_permitted_by_build` | `test_production_mutation_jobs_cannot_exist_in_this_build` |
| X-2 | A job recording a real (non-synthetic) execution cannot be constructed | `ExecutionJob.__post_init__` | `test_real_execution_cannot_be_recorded` |
| X-3 | Forward guards accept only dry-run, succeeded, non-executed jobs that match the candidate, approval, fingerprint, and targets | `_dry_run_job` | `UnassignDryRunGuardTests`, `DeletionDryRunGuardTests` |

### Audit

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| U-1 | Audit events are hash-chained. Edits, removals, and reordering are detected, and the newest event is covered when its digest is anchored | `AuditTrail`, `verify_chain` | `test_tampering_is_detected` |
| U-2 | Audit details are redacted (value patterns and credential-like keys) | `clean_details` | `test_details_are_redacted` |

## Store invariants

See [../architecture/persistence.md](../architecture/persistence.md).

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| S-1 | Evidence, decisions, approvals, job status, collector outcomes, audit events, migrations, and the environment marker are append-only. The database refuses UPDATE and DELETE | Migration 0002 triggers; `Store` never updates them | `AppendOnlyTests.test_every_history_table_refuses_update_and_delete` |
| S-2 | Candidate state changes only together with a newly appended decision that continues from the current state. New candidates start in `DISCOVERED`. Identity columns are immutable and candidates are never deleted | `Store.transition`; triggers | `AppendOnlyTests` candidate tests |
| S-3 | Every load replays the decision history. A state written directly to the database is detected. Each decision, and every approval that is read, must match the audit event that recorded it, and an approval step must cite an approval of its stage given by the step's actor. So a forged or edited decision or approval either fails to load or changes the audit head that S-5 anchors | `Store.load_candidate` → `verify_history`; `Store._require_audited` | `TamperDetectionTests`, `ForgedApprovalTests` |
| S-4 | Every write commits atomically with exactly one audit event that records actor, action, target, time, execution mode, result, correlation id, and before/after references. Refused transitions are audited too | `Store._audit`, `Store.transition` | `AuditAppendTests`, `test_refused_transition_is_audited_and_changes_nothing`, `test_failed_write_leaves_no_trace` |
| S-5 | The audit log is one hash chain. Inserts must extend the head, every stored digest is re-verified, and the head can be anchored externally | Trigger `trg_audit_chain`, `verify_integrity` | `test_audit_events_must_extend_the_chain_head`, `test_edited_audit_event_is_detected`, `test_rewritten_newest_event_is_detected_with_an_anchor` |
| S-6 | Stored evidence that no longer matches its material digest is detected | `Store._build` | `test_edited_observation_is_detected` |
| S-7 | A transition may cite only recorded evidence, a recorded approval, and a job's latest recorded state | `Store.transition` | `test_transition_must_cite_recorded_evidence_approval_and_job`, `test_job_snapshot_must_be_the_latest_recorded_state` |
| S-8 | Caller-supplied times cannot run ahead of the store clock, so holds and approval windows cannot be skipped by post-dating | `Store._not_future` | `test_post_dated_transition_is_refused`, `test_future_observation_is_refused` |
| S-9 | The database refuses `PRODUCTION_MUTATION` in jobs, collector runs, and audit events, refuses `READ_ONLY_PRODUCTION` jobs, and refuses `executed` without SUCCEEDED and synthetic targets | Migration 0001 CHECK constraints | `CheckConstraintTests` |
| S-10 | Synthetic and real evidence never mix. A SYNTHETIC store opens only in `LOCAL_SYNTHETIC` and accepts only `SYNTHETIC` evidence. A PRODUCTION store never opens in `LOCAL_SYNTHETIC` and refuses synthetic evidence and jobs | `app/store/environment.py`, `Store` | `EnvironmentRuleTests` |
| S-11 | The reset deletes only a SQLite file under `var/`, only in `LOCAL_SYNTHETIC` mode, only with confirmation, and only if the file is an OGWA store marked SYNTHETIC/DEVELOPMENT with no non-synthetic evidence. It never deletes a file it cannot identify | `check_reset_allowed` | `ResetTests`, `StoreCliTests` |
| S-12 | Applied migrations cannot change silently, the database cannot be newer than the build, and there are no downgrades | `verify_applied`, `PINNED_CHECKSUMS` | `MigrationRunnerTests`, `test_checksums_are_pinned` |
| S-13 | The store and demo packages import no network, subprocess, HTTP-client, or mutation-policy module | Code review | `StoreIsolationTests` |
| S-14 | Job details, collector error summaries, and audit references are redacted. A collector summary containing credential-shaped text is rejected | `redact_text`, `CollectorRunOutcome` | `test_credentials_never_reach_the_audit_log`, `test_outcome_summary_must_not_carry_credentials` |

## Okta integration invariants

See [../architecture/okta-integration.md](../architecture/okta-integration.md). O-1 to O-9
and O-11 covered the read-only Okta HTTP client, its pacing, and its System Log usage and
evidence collection, which are not included in this build. The record models and
normalization (`app/integrations/okta/models.py`, `normalize.py`) remain.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| O-10 | An Okta-derived AD objectGUID never reaches correlation or domain evidence until its decoding is proven against a known AD-backed Okta group whose objectGUID is independently known from AD (D23, D30) | `OBJECT_GUID_DECODING_VERIFIED = False` (`normalize.py`), `OktaGroupIdentity` | `test_okta_derived_guid_cannot_be_used_while_decoding_is_unverified` |

## AD integration invariants

See [../architecture/ad-integration.md](../architecture/ad-integration.md). These invariants
cover the AD report contract parser, the emptiness and protection assessments, and the
conversion to domain evidence; the golden fixtures in `tests/fixtures/ad/` are synthetic
reports in the contract's form. AD-1 and AD-2 covered the PowerShell AD reader, which is not
included in this build.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| AD-3 | An AD read request is validated; unknown keys and out-of-range limits are refused | `ADReadRequest` | `RequestTests` |
| AD-4 | A group counts as resolved only when the report proves exactly one match: more than one match is `Ambiguous`, and an unsearched domain makes "not found" `Inconclusive`; neither, nor a "not found" by name, yields an AD group record | `ResolutionStatus`, `ad_evidence` | golden scenarios, `ScenarioTests` |
| AD-5 | Emptiness is three facts (direct, nested, primary-group). Zero proves absence only from a complete read; `EMPTY` needs all three YES | `assess_emptiness` | `EmptinessTests`, `test_primary_group_dependency` |
| AD-6 | Protection that cannot be determined (unreadable PFAD, unread parents, ungoverned domain, a report's `Undetermined`) is `UNDETERMINED` and blocks retirement. A report's indicators and the built-in privileged names can only add protection | `assess_protection` | `ProtectionTests` |
| AD-7 | The `ADGroup` record never looks less protected than the assessment: if it cannot express the protection, it is PARTIAL | `ad_evidence` | `test_configuration_can_add_protection` |
| AD-8 | AD evidence is COMPLETE only if every section behind it was read completely. `exists=False` comes only from an objectGUID lookup that searched every domain | `records.py` | `RecordTests`, `test_not_found_*` |
| AD-9 | The report contract is strict in both directions; a report not marked `readOnly: true`, or from another worker or version, is refused | `parse_group_report` | `ReportParsingTests` |
| AD-10 | `app/integrations/ad` imports no network, process, or mutation module and does no file I/O | Code review | `PythonBoundaryTests` |
| AD-11 | Live behaviors not yet verified against real AD (large-group completeness, cross-domain parent lookup, deletion-protection readability) never contribute to COMPLETE evidence from `AD_VIA_AAP`. `VERIFIED_LIVE_BEHAVIORS` is empty (D19) | `records.py` | `OwnerDecisionTests` |
| AD-12 | UNDETERMINED protection cannot be overridden by any policy, flag, or source; it always blocks retirement and keeps the `ADGroup` record PARTIAL (D21) | `assess_protection`, `ad_evidence` | `test_unknown_protection_cannot_be_configured_away` |

## Identity correlation invariants

See [../architecture/identity-correlation.md](../architecture/identity-correlation.md).
Tests are in `tests/test_identity_correlation.py` and `tests/test_mapping_review.py`.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| C-1 | A name match is never exact: the name fallback runs only without any claim and yields `NAME_ONLY`, `AMBIGUOUS`, or `NOT_FOUND` | `_from_name_search` | `NameOnlyTests`, `test_correlation_never_reports_an_exact_result_from_a_name` |
| C-2 | `RESOLVED` needs every claim (configured, directory source, approval) to name the same AD object by stable id, every lookup and the Okta observation complete, and no blocking drift | `_from_claims` | `AmbiguousTests`, `StaleMappingTests`, `PartialForestTests` |
| C-3 | A lookup is decision-grade only if every domain in scope was searched and nothing was truncated, even for objectGUID/SID hits | `ADIdentityLookup.complete` | `PartialForestTests`, `test_golden_reports_map_to_identity_lookups` |
| C-4 | A directory-source SID must be corroborated by Okta's own name or DN, in the integration's domain; inconsistent Okta metadata blocks even a configured mapping | `assess_okta_source`, `_corroborate` | `OktaMetadataTests` |
| C-5 | The Okta-derived objectGUID cannot enter correlation while `OBJECT_GUID_DECODING_VERIFIED` is `False` (D23, D30) | `OktaGroupIdentity` | `test_okta_derived_guid_cannot_be_used_while_decoding_is_unverified` |
| C-6 | Drift is surfaced, never repaired: stale, reassigned, moved-domain, and conflicting identities stop resolution; renames are reported and the stored review keeps the old values until a human approves again | `_check_guid`, `_renames`, append-only registry | `StaleMappingTests`, `test_drift_is_acknowledged_only_by_a_new_approval` |
| C-7 | Every correlation emits one mapping with the same id per Okta group, so an unresolved run supersedes an earlier exact mapping; only `RESOLVED` emits `EXACT_*` | `mapping_evidence` | `EmissionTests`, `assert_not_exact` in every non-resolved case |
| C-8 | Lookups per correlation are capped (default 10, ceiling 16) and de-duplicated; a directory error, a wrong answer, or a spent budget is a `FAILED` lookup, never an answer | `BoundedLookups`, `ReportBackedDirectory` | `test_lookup_budget_is_enforced`, `test_raising_or_misanswering_directory_is_a_failed_lookup`, `ReportAdapterTests` |
| C-9 | Only a named human reviews; every action re-evaluates and requires the evidence fingerprint the operator saw; `NAME_ONLY` cannot be approved | `MappingReviewService` | `ReviewServiceTests` |
| C-10 | An operator selection must come from a fresh bounded search, is re-verified by objectGUID, and must be approved by a different human (domain chain rule and database trigger) | `select`, `review_append_problems`, `trg_mapping_reviews_four_eyes` | `test_operator_selection_needs_a_second_operator`, `test_database_refuses_self_approval_of_a_selection` |
| C-11 | A rejected pairing is never auto-resolved again | `_from_claims`, `_from_name_search` | `test_rejected_pairing_is_never_auto_resolved`, `test_rejected_name_candidate_is_not_offered_again` |
| C-12 | `mapping_reviews` is append-only and chained per Okta group; the database refuses rewrites, forks, non-exact or name-only approvals, and non-human reviewers | migration 0003 | `StoreRegistryTests` |
| C-13 | `app/correlation` imports no network, process, HTTP-client, or Okta-client module | Code review | `test_correlation_package_has_no_network_or_process_access` |
| C-14 | A directory-source objectSid match is never the basis of an exact mapping until it is verified; it may only corroborate (D37). On its own it is `UNVERIFIED_IDENTIFIER` / `UNVERIFIED_STABLE_ID`, never labelled name-only and never exact (D56). `DIRECTORY_SOURCE_SID_VERIFIED` is pinned `False` | `_may_be_exact`, `app/correlation/model.py`, migration 0006 | `DirectorySourceSidGateTests`, `DirectorySourceSidGateServiceTests` |

## Candidate policy invariants

See [../architecture/candidate-policy.md](../architecture/candidate-policy.md) and
[../operations/dependency-coverage.md](../operations/dependency-coverage.md). Tests are in
`tests/test_candidate_classification.py` and `tests/test_candidate_policy.py`.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| P-1 | A classification is never an approval: the result has no approve, transition, or execute operation, and `to_dict()` states `isApproval: false` | `ClassificationResult` | `test_a_candidate_is_not_an_approval` |
| P-2 | `RETIREMENT_CANDIDATE` needs a positive proof of every required condition; a missing proof gives `EVIDENCE_INCOMPLETE` (`REQUIRED_CONDITION_UNPROVEN`), never promotion | `_decide`, `RETIREMENT_CANDIDATE_REQUIRES` | `test_missing_proof_is_never_promoted` |
| P-3 | Removing, degrading (PARTIAL/FAILED), aging, attesting, or contradicting any single safety condition prevents promotion | the classifier passes | `SingleMissingConditionTests` (matrix, every record removed/degraded/aged, 300 random combinations) |
| P-4 | Dependency coverage that is not exactly COMPLETE prohibits AD deletion and holds the result at review; coverage is the lifecycle's own `assess_dependency_coverage` | `classify`, `coverage_report` | `DependencyCoverageTests` |
| P-5 | Negative facts (no members, no parents, no other assignment, not protected) need a COMPLETE check from a counting source; an attestation never proves absence (D13); positive facts count even from partial reads | `_counts`, `_membership`, `_assignments` | `test_attestation_never_proves_a_negative`, the matrix |
| P-6 | Every blocking finding becomes a blocking reason, by its code or, without one, by its kind; nothing is dropped | `_findings` | `test_every_blocking_finding_is_reported` |
| P-7 | Direct members, primaryGroupID references, parent groups, member groups, and nested principals stay separate coded facts through evidence and storage (D20) | `FindingCode`, `ad_evidence`, migration 0004 | `FindingCodeTests`, `GoldenADReportTests` |
| P-8 | A `RETIREMENT_CANDIDATE` always satisfies the lifecycle's candidacy guard and the retirement evidence conditions (exact mapping, existing group, no protection, COMPLETE coverage, no blocking finding) | the classifier vs `apply_transition` | `LifecycleAgreementTests` |
| P-9 | No dependency kind is covered from production until a verified collector exists; `PRODUCTION_COLLECTORS` is pinned, and live AD evidence cannot promote while its behaviours are unverified (D19) | `coverage.py`, `records.py` | `test_no_dependency_domain_is_covered_from_production_yet`, `test_live_ad_evidence_cannot_promote_before_p11` |
| P-10 | Thresholds are configuration with floors and ceilings; the policy document is strict and complete; every result names its policy digest | `CandidatePolicy` | `PolicyBoundsTests`, `PolicyDocumentTests`, `test_thresholds_come_from_policy` |
| P-11 | A policy change is an append-only `PolicyVersion`, proposed by an Identity/Automation human and approved by a different Security/IAM human (D33), audited in the same transaction; the database refuses rewrites, forks, unchanged versions, self-approval, and non-human actors | `version_append_problems`, `Store.record_policy_version`, migration 0004 | `PolicyVersionTests`, `PolicyStoreTests` |
| P-12 | An explanation never contains a proof of absence next to evidence of presence | the classifier passes | `ExplanationConsistencyTests` |
| P-13 | `app/classification` imports no network, process, integration, store, or correlation module | Code review | `test_classification_imports_nothing_that_reads_or_writes_externally` |
| P-14 | The policy template in git is policy v1 and equals the code defaults; floors and ceilings are not configurable and cannot be weakened by any document (D32, D34, D35) | `CandidatePolicy`, `config/candidate-policy.template.json` | `TemplateAndFloorTests` |
| P-16 | Only an `EXACT_*` confidence yields `EXACT_MAPPING`; every other confidence, including any added later, forces `MAPPING_REQUIRED` | `_origin_mapping_and_membership` | `MappingConfidenceCoverageTests` |
| P-15 | Mapping and policy reviews have dedicated audit actions; events recorded before migration 0005 are preserved byte for byte and the chain still verifies (D41) | migration 0005, `Store` | `ReviewAuditMigrationTests`, `test_versions_persist_with_audit_and_integrity`, `test_reviews_persist_with_audit_and_integrity` |

## Operator API invariants

See [authorization.md](authorization.md) and [../architecture/api.md](../architecture/api.md).

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| API-1 | The API serves only in `LOCAL_SYNTHETIC` over a SYNTHETIC store with the synthetic identity adapter; no other adapter exists (D50, D51) | `OgwaApi.__init__`, `SyntheticIdentityAdapter`, `python -m app.api serve` | `test_api_refuses_every_mode_but_local_synthetic`, `test_synthetic_adapter_exists_only_for_local_synthetic_data`, `test_cli_refuses_modes_other_than_local_synthetic` |
| API-2 | Identity comes only from the session cookie. Identity headers are never read; an `Authorization` header is refused | `OgwaApi._handle` | `test_identity_headers_are_never_trusted`, `test_authorization_headers_are_refused_even_with_a_valid_session` |
| API-3 | Roles come only from bindings of stable IdP group ids for the adapter's issuer; display names and other issuers grant nothing; no route writes bindings (D47, D48) | `RoleBindings`, `parse_role_bindings` | `RoleBindingTests` |
| API-4 | Every route declares its access (public, session, or named permissions) at registration, and the permission check runs before the request body is read | `Route`, `OgwaApi._handle` | `test_routes_must_declare_access`, `RouteAccessMatrixTests` |
| API-5 | No role combines approving with planning execution, submitting with approving, or selecting with approving a mapping; `ADMINISTRATOR` holds no write permission; no role holds `EXECUTION_EXECUTE` | `ROLE_PERMISSIONS` | `RoleModelTests` |
| API-6 | Four-eyes per action (D49): the submitter or proposer never approves the stage, the Okta-stage approver never approves AD retirement (D11), and an approver never plans or records the dry run they approved | `LifecycleService.approver_conflicts`, `plan_dry_run`, `transition` | `SeparationOfDutiesTests` |
| API-7 | An approval or a dry-run plan is accepted only if the lifecycle guard of the step it authorizes passes; forward actions must name the current evidence fingerprint | `LifecycleService._guard`, `_require_fresh_view` | `test_approvers_cannot_bypass_evidence_rules`, `test_executors_cannot_execute_without_a_valid_approval`, `test_a_material_evidence_change_voids_the_approval_for_execution` |
| API-8 | `PRODUCTION_MUTATION` and non-dry-run requests are refused before any other check; the execute route refuses every principal; dry-run planning uses a `DRY_RUN_MUTATION` policy that can only plan | `plan_dry_run`, `execute`, `DryRunPlanner` | `ProductionMutationRefusalTests` |
| API-9 | Unsafe requests need the session's CSRF token and a same-origin (or absent) `Origin`; the session cookie is `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`; only token hashes are stored; sessions expire idle and absolutely | `OgwaApi._check_origin`, `SessionManager`, `session_cookie` | `AuthenticationTests` |
| API-10 | Error responses carry a stable code, a redacted message, and the request id, never exception text; bodies and queries are strict and bounded; listings are paginated with a ceiling | `ApiError`, `http.py`, `validation.py` | `ResponseContractTests` |
| API-11 | `app/api` imports no HTTP client, integration, process, or socket module, and its read model issues only `SELECT` | Code review | `test_api_imports_no_network_mutation_or_integration_module`, `test_read_model_only_selects` |
| API-12 | `VIEWER` is exactly read-only, `EXECUTOR` holds only dry-run planning, `ADMINISTRATOR` holds no lifecycle, review, approval, or execution permission, and no API code refers to a role name outside the role table (D60–D63) | `ROLE_PERMISSIONS` | `RoleDecisionTests` |
| API-13 | A 403/409 refusal of an authenticated, valid request on a governed route is chained as `GOVERNED_REQUEST_REFUSED` (once; lifecycle refusals stay `TRANSITION_REFUSED`), without free text; unauthenticated, CSRF/Origin, static-permission, malformed, and not-found failures are not chained; a failure to chain never changes the refusal (D64, D65) | `OgwaApi._chain_refusal`, `Store.record_governed_refusal`, migration 0007 | `GovernedRefusalAuditTests`, `GovernedRefusalMigrationTests` |
| API-14 | While the unrecorded demo policy is in force, every response carries `policyNotice: "DEMO POLICY — UNRECORDED"` and `X-OGWA-Policy-Status: DEMO-UNRECORDED`, and every policy view carries its `label` (D66) | `OgwaApi._label_policy`, `PolicyInForce` | `DemoPolicyLabelTests` |
| API-15 | The synthetic AD directory and mapping gateway exist only for a SYNTHETIC store in `LOCAL_SYNTHETIC`, read only the store, exclude deleted groups, never raise, and never pass the unverified Okta-derived objectGUID to correlation (D68, D23, D30) | `app/demo/synthetic_directory.py` | `SyntheticDirectoryTests` |
| API-16 | Only the execution function may use the execute route (static `EXECUTION_PLAN_DRY_RUN` or `EXECUTION_EXECUTE`); anyone else's attempt is an ordinary 403 kept out of the audit chain (D72, D73) | `ROUTES` (`EXECUTE_ROUTE`) | `test_every_route_enforces_its_permission_for_every_principal`, `test_generic_malformed_and_unauthenticated_failures_stay_in_the_security_log` |

## Remediation invariants

See [../architecture/remediation.md](../architecture/remediation.md) and
[mutation-gates.md](mutation-gates.md). Tests are in `tests/test_remediation_*.py` unless
noted.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| R-1 | A remediation resolves only to `SIMULATED`, `WHATIF`, `VALIDATION_ONLY`, or `BLOCKED`; no outcome, result, or record can say it executed | `RemediationOutcome`, `RemediationResult` | `OutcomeVocabularyTests`, `ResultRecordTests` |
| R-2 | A dry run is refused unless all ten gates pass, and every gate is always evaluated | `evaluate_gates`, `remediation_dry_run` | `HappyPathTests`, one class per gate, `test_every_gate_is_evaluated_so_every_reason_is_reported` |
| R-3 | Every adapter holds a `DRY_RUN_MUTATION` policy and only plans; no adapter can reach a system | `RemediationAdapter` | `test_every_adapter_only_plans`, `test_no_socket_connection_or_process_is_used`, `test_the_adapter_holds_no_way_to_reach_aap` |
| R-4 | The synthetic adapter serves a SYNTHETIC store only and refuses non-synthetic evidence | `adapter_for`, `SyntheticRemediationAdapter`, `parse_allowlist` | `test_it_refuses_evidence_that_is_not_synthetic`, `test_the_synthetic_adapter_is_refused_outside_a_synthetic_environment` |
| R-5 | The AAP adapter answers at most `VALIDATION_ONLY`, only for an observed template that classifies `KNOWN_READ_ONLY` against its reviewed record, and never launches | `AapRemediationAdapter` | `AapAdapterTests`, `test_the_aap_path_validates_a_reviewed_template_and_never_launches`, `test_an_aap_template_that_is_not_known_read_only_is_blocked` |
| R-6 | `PRODUCTION_MUTATION` or `dryRun: false` is refused before anything else; any other mode, and any field that could select execution, is `422` | `post_remediation_dry_run`, `RemediationService.dry_run` | `ProductionMutationSelectionTests` |
| R-7 | One candidate, one operation, one explicit target per request; no bulk route and no remediation execute route | `ROUTES`, `_remediation_target` | `AntiFootgunTests` |
| R-8 | The adapter and AAP template come only from the server-side, environment-bound allowlist, and each domain's quarantine OU only from the separate quarantine OU configuration (D136); an unlisted operation is `BLOCKED` | `app/remediation/allowlist.py`, `app/remediation/quarantine.py` | `AllowlistTests`, `test_quarantine_ous_are_explicit_ous_inside_their_domain` |
| R-9 | Stale, incomplete, or future-dated evidence blocks a dry run even while its approval is in force | `FRESH_EVIDENCE` | `StaleEvidenceTests`, `FreshEvidenceTests` |
| R-10 | A changed target identity, or a mapping re-pointed to another group, invalidates the approval | `APPROVAL_FINGERPRINT_MATCHES`, `SINGLE_EXPLICIT_TARGET` | `TargetIdentityTests`, `FingerprintAndIdentityTests` |
| R-11 | Protection blocks for every principal; no field, role, or permission overrides it, and unknown protection blocks too (D21) | `NOT_PROTECTED` | `ProtectedGroupTests`, `ProtectionGateTests` |
| R-12 | The approver of a stage cannot request its remediation dry run (D49) | `RemediationService.dry_run`, `SEPARATION_OF_DUTIES` | `test_the_approver_cannot_request_the_dry_run_of_their_own_stage`, `SeparationAndLifecycleTests` |
| R-13 | A remediation dry run never moves the lifecycle and never creates an `ExecutionJob` | `RemediationService` | `ValidApprovalCannotMutateProductionTests` |
| R-14 | A passing dry run is chained as `REMEDIATION_DRY_RUN_RECORDED` stating `executed: false`; a `BLOCKED` one is chained as `GOVERNED_REQUEST_REFUSED`; the store refuses to record a `BLOCKED` or executed result, a non-human actor, or another candidate's approval | `Store.record_remediation_dry_run`, `OgwaApi._chain_refusal` | `test_a_blocked_request_is_chained_with_its_operation_and_target_and_changes_nothing`, `RecordRulesTests` |
| R-15 | Migration 0010 keeps every audit row, digest, index, and guard byte for byte; an anchored head still verifies | migration 0010 | `RemediationAuditMigrationTests` |
| R-16 | `app/remediation` imports no HTTP client, socket, process, or integration module, and the build has no AAP client | Code review | `PackageBoundaryTests`, `test_no_live_integration_module_or_worker_is_in_the_build` |
| R-17 | A blocked condition never yields a plan: a request that fails a gate never reaches an adapter, and no `BLOCKED` result, answer, worker result, or `409` body carries a planned change (D133) | `remediation_dry_run`, `RemediationResult`, `AdapterAnswer`, `parse_worker_result` | `BlockedNeverPlansTests` |
| R-18 | AD quarantine and deletion are separate stages: `AD_GROUP_QUARANTINE` is authorized only by an `AD_QUARANTINE` approval and `AD_GROUP_DELETE` only by an `AD_DELETION` approval, each in its own stage's states (D128, D147). The deletion stage is modelled in Q-1 to Q-10 | `OPERATIONS`, `stage_approval_rules` | `DeletionStageTests` (gates and API) |
| R-19 | Known members, or missing or incomplete membership evidence (`AD_GROUP_MEMBERS`, `AD_NESTED_MEMBERSHIP`, the direct member count), block every remediation, the Okta unassignment included; complete coverage of the other kinds is required for AD operations only (D131, D132) | `NO_DEPENDENCY_BLOCKER` (`_membership`) | `MembershipEvidenceTests` (gates and API) |

## AD quarantine and deletion invariants

Owner decisions D143–D155. See
[../architecture/lifecycle-state-machine.md](../architecture/lifecycle-state-machine.md#the-ad-stages).
Tests are in `tests/test_lifecycle_ad_stages.py`, `tests/test_p10b_ad_stages_api.py`, and
`tests/test_ad_stages_migration.py` unless noted.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| Q-1 | Quarantine and deletion are separate governed stages, each with its own approval stage (`AD_QUARANTINE`, `AD_DELETION`), and each approval authorizes its own stage only (D128, D147) | `TRANSITIONS`, `stage_approval_rules`, `STAGES` | `QuarantineApprovalGuardTests`, `DeletionApprovalGuardTests`, `DeletionStageTests` |
| Q-2 | The deletion approver is not the deletion's proposer, the quarantine approver, the Okta-stage approver, or the candidate's proposer; the quarantine approver is not the Okta-stage approver (D11, D143) | the approval guards, `approver_conflicts`, `VALID_APPROVAL`, `verify_history` | `test_the_approver_must_differ_from_the_proposer_and_both_earlier_approvers`, `AdStageHistoryTests`, `test_quarantine_hold_proposal_and_deletion_each_need_their_own_people` |
| Q-3 | No earlier approval authorizes a deletion: only an `AD_DELETION` approval of the current epoch, given after the post-quarantine hold and after the proposal; a job references an approval of its own stage only (D146) | `approval_problems` (`given_after`, `not_before`), `Store._insert_job` | `test_earlier_approvals_never_authorize_a_deletion`, `test_an_approval_given_before_the_proposal_or_the_hold_end_is_not_this_proposals_approval` |
| Q-4 | The post-quarantine hold is 30 days from the confirmed quarantine observation, a constant outside the candidate policy; its end opens revalidation only (D138, D139) | `QUARANTINE_HOLD_PERIOD`, `_g_quarantine_hold_elapsed` | `QuarantineHoldTests` |
| Q-5 | A deletion is proposed, approved, and dry-run only on complete evidence collected after the hold: full dependency coverage, no members, not protected, the group still in its quarantine OU (D130, D131, D132) | `_post_quarantine` | `DeletionProposalGuardTests`, `DeletionDryRunGuardTests` |
| Q-6 | A quarantined candidate never returns before its quarantine; a post-quarantine block re-enters only at `DELETION_REVALIDATION_REQUIRED`, which clears the proposal and starts a new epoch (D144, D145, D155) | re-entry guards, `LifecycleCandidate` invariants, `verify_history`, a CHECK on `candidates` (0011) | `PostQuarantineReentryTests`, `PostQuarantineBlockTests`, `test_a_quarantined_candidate_cannot_stand_before_its_quarantine` |
| Q-7 | The quarantine OUs are deployment-controlled configuration outside the candidate policy; no route changes them; without them no AD-stage step passes (D136) | `QuarantineOus`, `load_quarantine_ous`, `quarantine_location_problems` | `QuarantineOuTests`, `QuarantineConfigurationTests` |
| Q-8 | Legacy `AD_RETIREMENT` rows are kept verbatim and authorize nothing; no new approval, job, or legacy-stage decision may be recorded (D148) | `LEGACY_*`, `legacy_ad_retirement`, `Store.record_approval`, `Store._insert_job`, triggers (0011) | `LegacyStageTests`, `test_nothing_new_may_use_the_legacy_stage`, `test_the_legacy_single_ad_stage_can_be_neither_approved_planned_nor_recorded` |
| Q-9 | There is no unquarantine or restore operation (D149), and every AD-stage job is a dry run; no production deletion, quarantine, or restoration path exists (D153) | `RemediationOperation`, `JobKind`, `ExecutionJob`, `DryRunPlanner` | `NoDeletionPathIsProductionTests`, `test_dry_run_planner_can_only_plan`, `test_a_valid_deletion_approval_only_simulates_the_deletion` |
| Q-10 | Migration 0011 keeps every row of the four rebuilt tables and every other table verbatim; an anchored audit head still verifies; the guards are recreated, plus three triggers refusing new legacy rows | migration 0011 | `AdStagesMigrationTests` |

## Evidence assessment invariants

See [../architecture/evidence-assessment.md](../architecture/evidence-assessment.md). Tests are in
`tests/test_evidence_assessment.py` and `tests/ui/evidence.test.mjs` (run by `tests/test_ui_evidence.py`).

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| EA-1 | Missing, failed, partial, attested-only, stale, future-dated, ambiguous, or conflicting required evidence never yields `ELIGIBLE_FOR_HUMAN_APPROVAL`, even if the guard were to accept | `_constraints` (and its decision-grade backstop) | `test_every_single_degradation_is_refused`, `test_even_if_the_guard_accepted_weak_evidence_is_never_eligible`, `test_random_combinations` |
| EA-2 | Eligible implies the classifier's `RETIREMENT_CANDIDATE` (after the unassignment: every `RETIREMENT_CANDIDATE_REQUIRES` proof, only `ASSIGNMENT_ABSENT` waived) and the real lifecycle guard accepting; it is never an approval and never automatic | `_constraints`, `LifecycleService.pending_step` | `test_eligible_implies_the_classifier_and_the_guard_agree`, `test_after_the_unassignment_only_the_expected_absence_is_waived`, `test_eligibility_agrees_with_the_real_approval_path` |
| EA-3 | Not collected, source unavailable, partial, attested only, says none, identity not established, conflicting, and confirmed stay distinct states, labels, and observations | `EvidenceState`, `evidence.js` | `DistinctStateTests`, `every evidence state has its own label` |
| EA-4 | Conflicts are shown, never resolved: both observations keep their own read (`baseState`), and a material conflict leads the decision unless a positive stopping fact or a terminal state comes first | `_conflicts`, `_constraints` | `ConflictTests`, `NM-C10 shows every kind of imperfect evidence` |
| EA-5 | The pending step's guard is evaluated with a hypothetical approval that is never recorded; reading an assessment writes nothing | `LifecycleService.pending_step` | `test_reading_the_assessment_writes_nothing`, `test_the_server_refuses_the_approval_and_records_nothing` |
| EA-6 | `app/classification/assessment.py` imports nothing that reads or writes outside OGWA's process | code review | `test_the_assessment_module_reads_and_writes_nothing_external` |
| EA-7 | An unknown AD member count is never zero: it proves no emptiness and holds the result at `EVIDENCE_INCOMPLETE` (`AD_MEMBERSHIP_UNKNOWN`), as D132 already did for the AD stages | `_membership` | `test_an_unknown_member_count_proves_nothing` |
| EA-8 | The NM-C10 scenario is deterministic and shows every state through the real seed, correlation engine, lifecycle guards, and API | `_nm_c10`, golden audit head | `test_the_scenario_is_deterministic`, `test_nm_c10_shows_every_state_and_refuses_every_decision`, `test_golden_audit_head` |

## Policy version invariants

See [../architecture/candidate-policy.md](../architecture/candidate-policy.md#named-releases-and-the-policy-each-decision-records),
[../architecture/evidence-assessment.md](../architecture/evidence-assessment.md#decision-explanation), and
[../demo/policies/NM-LIFECYCLE-004.md](../demo/policies/NM-LIFECYCLE-004.md). Tests are in
`tests/test_policy_release.py`, `tests/test_decision_explanation.py`, and `tests/ui/policy.test.mjs`
(run by `tests/test_ui_policy.py`).

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| PV-1 | A release is strict JSON with a stable policy id and an explicit semantic version, embedding an unchanged policy document (same parser, floors, ceilings); a chain is one id, increasing versions and effective times, each superseding the last, never repeating rules | `PolicyRelease`, `release_history_problems` | `ReleaseFormatTests` |
| PV-2 | A released version never changes: both synthetic releases' release and rules digests are pinned, and the reviewer file is exactly the release | goldens | `test_both_releases_have_a_stable_identity`, `test_the_reviewer_file_is_exactly_the_release` |
| PV-3 | A recorded version gets a release identity only from a release with exactly its rules, and only in a SYNTHETIC store; otherwise it has none, said as such, never the nearest or latest | `release_for_digest`, `policy_in_force`, `demo_releases` | `test_the_version_change_is_distinguishable_and_named`, `test_a_newer_version_never_rewrites_what_an_older_decision_recorded` |
| PV-4 | Every transition, refusal, and approval made through the API or the Null Meridian seed records the exact policy reference it was judged by, in its audit event (hash-chained, same transaction); the row's own details are still checked exactly (F08) | `Store.transition`, `Store.record_approval`, `_require_audited` | `test_every_seeded_decision_records_the_version_that_judged_it`, `test_a_new_decision_records_the_policy_in_force_and_history_is_unchanged` |
| PV-5 | No decision is recorded as judged by anything but the policy in force: a superseded version, other rules, or the unrecorded demo policy once a version is recorded is refused inside the write, and nothing is written | `Store._check_policy_ref` | `PolicyInForceGuardTests` |
| PV-6 | History is read back as recorded: a newer version never changes what an earlier decision shows; a record without a reference shows none; an edited release file shows `DIFFERS_FROM_RECORDED` | `Store.recorded_policies`, `policy_ref_json` | `test_a_newer_version_never_rewrites_what_an_older_decision_recorded`, `test_an_edited_release_file_shows_as_a_difference_not_as_the_recorded_policy`, `test_unrecorded_policy_is_labelled_and_unnamed` |
| PV-7 | The explanation never contradicts the decision: satisfied only with the classifier's proof, not satisfied only with a contradicting fact, otherwise not proven; an eligible decision has every condition satisfied; manual review is "forced by evidence" exactly when an evidence constraint applies; no condition is dropped | `explain` | `ExplanationAgreesWithTheDecisionTests`, `test_missing_evidence_is_never_satisfied_or_failed` |
| PV-8 | The classification, the assessment, and the explanation of one view name the same policy; the explanation module reads and writes nothing external | `classify_assess_explain`, `explain` | `test_every_surface_names_the_same_exact_policy_version`, `test_the_explanation_module_reads_and_writes_nothing_external` |

## Remediation execution invariants

The execution state machine and the synthetic drill
([../architecture/remediation-execution.md](../architecture/remediation-execution.md)). The
governed path's invariants above (R, X, W, D153) still apply.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| RX-1 | A dry run submits nothing and changes no state: its fixture holds a `DRY_RUN_MUTATION` policy, its ledger is empty, and its state digest is the same before and after | `run_drill`, `_dry_run`, `SyntheticProviderFixture` | `test_a_dry_run_changes_nothing_and_says_so`, `test_a_dry_run_never_submits_and_its_fixture_can_only_plan`, `test_a_plan_only_policy_applies_nothing_even_when_asked` |
| RX-2 | An unknown outcome leads only to verification: no resubmission, success, or retry decision without a read | `TRANSITIONS`, `ExecutionRun` (checks before touching the provider) | `test_an_unknown_outcome_leads_only_to_verification`, `test_a_timeout_never_leads_straight_to_a_resubmission` |
| RX-3 | A retry is permitted only by a read showing the before-state, with an attempt left (at most 2 submissions); an unreadable, diverged, or refused target is never retried | `retry_decision`, `verify_trace` | `test_only_a_read_showing_the_before_state_permits_a_retry`, `test_an_unreadable_outcome_is_never_retried_or_called_a_success`, `test_the_attempt_limit_holds`, `test_a_target_changed_elsewhere_outside_the_run_is_not_retried` |
| RX-4 | A retry is submitted only if the governed gates pass again at the retry's time and the precondition still holds | `ExecutionRun.request` (`recheck`) | `test_the_gates_are_evaluated_again_before_a_retry`, `test_the_gates_are_evaluated_again_before_the_retry` (API, real evidence ageing past 24 h) |
| RX-5 | No change is applied twice: every attempt carries the change's operation id; the provider refuses an applied id and a failed precondition without a change; an applied change whose answer was lost is never resubmitted | `operation_id`, `SyntheticProviderFixture.submit`, `retry_decision` | `test_an_applied_operation_id_is_never_applied_twice`, `test_a_submission_on_a_failed_precondition_changes_nothing`, `test_an_applied_change_whose_answer_was_lost_is_not_resubmitted`, `test_a_timeout_that_applied_the_change_is_never_resubmitted` |
| RX-6 | Success is only `POST_ACTION_VERIFIED`, reached only from `EXECUTED` through a post-action read in which the target is in its after-state and nothing else in scope changed | `TRANSITIONS`, `ExecutionRun.post_verify`, `scope_differences` | `test_success_follows_only_an_execution`, `test_an_unexpected_change_elsewhere_in_scope_fails_verification` |
| RX-7 | A verification failure (mismatch or unreadable) is never reported as success, by the API or the UI | `VERIFICATION_FAILED` (terminal), `drill.js` `drillOutcome`/`isVerified` | `test_a_failed_post_action_verification_is_never_reported_as_success`, `test_a_post_action_read_that_fails_is_never_a_success`, `only a verified drill whose record agrees counts as verified` |
| RX-8 | A request the governed path blocks builds no fixture and plans nothing (D133); a drill runs only in `LOCAL_SYNTHETIC`, over a SYNTHETIC store, on SYNTHETIC evidence, with the SYNTHETIC adapter | `run_drill`, `SyntheticProviderFixture.from_evidence` | `test_a_blocked_request_builds_no_provider`, `test_drills_run_only_in_local_synthetic`, `test_only_a_synthetic_or_plan_only_policy_is_accepted` |
| RX-9 | A drill writes nothing (no audit event, job, decision, or evidence), moves no lifecycle state, and contacts nothing; only the in-memory fixture changes, and only at the target | `RemediationService.drill`, `NON_PERSISTING` | `test_no_drill_writes_to_the_store_or_reaches_a_live_system`, `test_an_executed_drill_changes_only_the_synthetic_fixture`, `test_a_remediation_drill_runs_on_the_read_only_store_and_records_nothing` |
| RX-10 | Faults are a closed, deterministic catalog: a request cannot describe faults, nothing is random or reads the wall clock, and the same script gives the same run; dry run and execution never share a label | `SCENARIOS`, the synthetic clock, `STATE_LABELS` | `test_a_request_cannot_carry_its_own_faults_mode_or_adapter`, `test_nothing_in_the_execution_path_is_random_or_reads_the_wall_clock`, `test_the_same_script_gives_the_same_run`, `test_dry_run_and_execution_labels_cannot_be_confused` |

## Policy and remediation integration invariants

The policy binding (PV) joined to the remediation drill (RX)
([../architecture/remediation-execution.md](../architecture/remediation-execution.md#policy-binding-and-the-authorization-chain)).
Tests are in `tests/test_ogwa_demo_integration.py`, `tests/ui/drill.test.mjs` (run by
`tests/test_ui_drill.py`), and `tests/browser/test_remediation_drill_ui.py`. EA, PV, and RX above
still apply.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| DI-1 | A remediation dry run or drill names the exact policy version its gates were judged by, the lifecycle decision that applied its approval, and that approval, each by its recorded identifier and audit sequence, with the policy reference its own event recorded | `app/api/authorization.py` (`remediation_authorization`, `drill_chain`, `recorded_dry_run_chain`) | `test_a_drill_names_the_policy_version_decision_and_approval_that_authorized_it`, `test_the_chain_carries_mode_attempts_outcomes_verification_and_final_state` |
| DI-2 | While a policy version is recorded, a remediation rests only on an approval (and decision) judged by that version: anything else is `409 APPROVAL_POLICY_NOT_IN_FORCE` after the gates pass, before any fixture exists, and again before a retry | `RemediationAuthorization.problems`, `RemediationService.dry_run` / `.drill`, `run_drill(authorize=)` | `test_an_approval_judged_by_a_superseded_version_authorizes_no_drill_and_builds_nothing`, `test_the_binding_is_asked_again_before_a_retry`, `test_binding_is_exact_and_fails_closed` |
| DI-3 | A recorded governed dry run records the policy in force in its event, checked in the write (a superseded reference writes nothing), and is read back as recorded: a newer version never changes what it shows | `Store.record_remediation_dry_run(policy_ref=)`, `_check_policy_ref`, `remediation_record_json` | `test_a_recorded_dry_run_records_its_policy_and_shares_the_drills_operation_id`, `test_a_recorded_remediation_never_points_at_a_newer_policy_version`, `test_the_store_refuses_a_dry_run_record_judged_by_a_superseded_version` |
| DI-4 | The Null Meridian seed is chronological: every decision and approval records the release in force on its own date (1.1.0 for the triage, 1.2.0 for NM-C11's snapshot day); the seed stops otherwise | `seed_null_meridian`, `policy_chronology_problems` | `SeedChronologyTests` |
| DI-5 | NM-C11 is inside the 24-hour EXECUTION window at the demo's clock, and is blocked by `FRESH_EVIDENCE` once it is not; NM-C10 reaches no drill by any route (no approval, no borrowed approval, a forged approval blocked by the gates before a fixture exists) | the gates, `run_drill` | `test_fresh_at_the_demo_clock_and_blocked_once_the_execution_window_passes`, `test_no_route_takes_nm_c10_into_a_drill` |
| DI-6 | `POST_ACTION_VERIFIED` cannot be recorded in a trace without the post-action predicate (reason `MATCHES_EXPECTED_STATE`, target observed in its after-state, a successful read, no other change in scope); the UI counts a drill as verified only with the server's `CONFIRMED` post-action result | `verify_trace`, `post_action_predicate_problems`, `drill.js` `isVerified` | `test_post_action_verified_needs_the_read_the_after_state_and_an_unchanged_scope`, `test_every_verified_api_drill_carries_the_predicate`, `verified needs the server's confirmed post-action read` |
| DI-7 | Dry run and synthetic execution can never be confused: each drill carries the server's mode banner (DRY RUN — NO STATE CHANGED, neutral; SYNTHETIC EXECUTION, "No external provider or persistent environment was modified.", caution), shown above the outcome; a missing or mismatched banner is blocked | `MODE_BANNERS`, `drill.js` `modeBanner`, `views/candidate.js` | `DryRunVsExecutionWordingTests`, `every drill carries a mode banner…`, browser `test_a_…`, `test_b_…` |
| DI-8 | The reviewer audit sample is the application's own serialization, byte for byte, and synthetic: no cookie, CSRF token, credential, URL, IP address, or non-fictional domain | `app/demo/null_meridian/audit_sample.py` (`--check`) | `AuditSampleTests` |

## AAP template classification invariants

AAP-1 to AAP-4 and AAP-6 to AAP-8 covered AAP discovery, which is not included in this
build. AAP-5 holds for the job-template classification the plan-only AAP remediation
adapter uses. Tests are in `tests/test_remediation_adapters.py`.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| AAP-5 | `KNOWN_READ_ONLY` only for a check-mode job template with a fixed job type that matches a reviewed record field for field, including the project revision; never a workflow; `UNKNOWN` is treated like `MUTATION_CAPABLE` | `classify_template` (`app/remediation/aap.py`) | `AapAdapterTests` |

## Remediation worker invariants

See [../architecture/remediation.md](../architecture/remediation.md#the-powershell-worker-workerogwaremediation).
Behaviour: `tests/powershell/Test-OgwaRemediation.ps1` (PowerShell 7 and 5.1); static:
`tests/test_remediation_worker_safety.py`.

| # | Invariant | Enforced in | Tests |
| --- | --- | --- | --- |
| W-1 | The worker names no AD or Okta cmdlet, HTTP or directory API, file write, module import, dynamic code, or credential | `worker/OGWA.Remediation` | `RemediationWorkerStaticTests` |
| W-2 | Every state-changing command declares `SupportsShouldProcess` and `ConfirmImpact = 'High'`, and changes anything only after `ShouldProcess` agrees | the three commands | `test_state_changing_commands_ask_shouldprocess_before_any_change`, "every state-changing command supports ShouldProcess" |
| W-3 | The only adapter is the module's synthetic one (private token); with any other, every command is `Blocked` (`NO_PRODUCTION_ADAPTER`), even when confirmed | `Assert-OgwaSyntheticAdapter`, `Invoke-OgwaSyntheticChange` | "without the synthetic adapter every command is Blocked" |
| W-4 | The synthetic adapter refuses non-synthetic identities, and a synthetic change touches only its in-memory world | `New-OgwaSyntheticRemediationAdapter` | "the synthetic adapter refuses to describe anything that is not synthetic", "an agreed confirmation changes only the synthetic in-memory world" |
| W-5 | A target is one explicit identifier: a pattern is `WILDCARD_TARGET`, and a malformed identifier is refused before any lookup | `Test-OgwaTargetValues`, `Test-OgwaADTargetRequest` | "a pattern is never a target", "malformed identifiers are refused before any lookup" |
| W-6 | The live objectSid and DN must match what OGWA approved, or the result is `TARGET_IDENTITY_CHANGED` | `Resolve-OgwaADTarget` | "a changed identity blocks" |
| W-7 | Protection (and unknown protection), members, and parent groups always block | `Resolve-OgwaADTarget`, `Test-OgwaGroupIsEmpty` | "protected groups are Blocked whatever the caller agrees to", "members and parent groups block" |
| W-8 | The JSON boundary accepts only `WhatIf` and `ValidateOnly`, always passes `-WhatIf`, and so can never return `Simulated` | `Invoke-OgwaRemediation` | "the boundary has no mode that changes anything", `test_the_json_boundary_always_passes_whatif_and_never_skips_confirmation` |
| W-9 | Every result states `executed: false` and `productionMutation: false`; OGWA refuses a result that does not, that comes from another worker or version, or that answers another target | `Complete-OgwaRemediation`, `parse_worker_result` | `test_a_tampered_result_is_refused`, "every boundary result states executed false" |

## Limits of these guarantees

- Python cannot stop deliberate bypass. Someone with source access can call
  `dataclasses.replace` or construct a record directly. The invariants prevent accidental
  misuse. Deliberate bypass is caught by `verify_history` at load time, by the audit
  chain, and by code review (D3).
- `HOLD` and `RETIRED` record observed outcomes. They do not prove who made the change.
  Attribution evidence (Okta System Log, AD metadata) is an open item.
- The SQLite triggers stop accidental or ad-hoc rewrites, not someone with DDL rights.
  Such tampering is detected (S-3, S-5, S-6) but not prevented. Prevention on a server
  needs database roles (PostgreSQL `REVOKE`, a separate migration role).
- Audit-head anchoring is manual: `python -m app.store verify` prints the head, and the
  operator records it outside the database. A write-once external sink is future work.
