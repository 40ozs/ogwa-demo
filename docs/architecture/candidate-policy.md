# Candidate classification and dependency policy

Implemented in `app/classification/` (classifier, reasons, coverage) and `app/domain/candidate_policy.py`
(configuration and versions), with `app/domain/policy_release.py` (releases, `PolicyRef`). The policy registry is
persisted by store migration 0004. All tests use synthetic data. No external system is
contacted, and nothing here can change Okta, AD, or AAP.

Related: [domain-model.md](domain-model.md), [lifecycle-state-machine.md](lifecycle-state-machine.md),
[identity-correlation.md](identity-correlation.md), [ad-integration.md](ad-integration.md),
[../operations/dependency-coverage.md](../operations/dependency-coverage.md),
[../security/safety-invariants.md](../security/safety-invariants.md#candidate-policy-invariants).
Decisions D32–D43 ([decisions.md](decisions.md)) settle where the policy lives, who
may change it, and the audit actions.

## Purpose and limits

The classifier decides whether one Okta group / application relationship is:

- **not interesting** (`ACTIVE`);
- **worth a human look** (`LOW_USAGE_REVIEW`, `INACTIVE_REVIEW`);
- **stopped** by a positive fact (`PROTECTED`, `HAS_MEMBERS`, `NESTED_DEPENDENCY`,
  `SHARED_OKTA_ASSIGNMENT`, `DEPENDENCY_BLOCKED`);
- **stopped** by an evidence problem (`MAPPING_REQUIRED`, `STALE_EVIDENCE`, `EVIDENCE_INCOMPLETE`);
- or **eligible to be considered for retirement** (`RETIREMENT_CANDIDATE`).

**A `RETIREMENT_CANDIDATE` is not approval.** It is evidence for human review. Every later
step still goes through the lifecycle state machine: two different human approvers, the
hold period, dry runs, and fresh evidence at each step. `PRODUCTION_MUTATION` is still
impossible in this build (D8). The classifier has no method that approves, transitions,
schedules, or executes anything, and a test pins that.

## Inputs

```python
classify(bundle: EvidenceBundle, subject: CandidateSubject, policy: CandidatePolicy, now: datetime)
    -> ClassificationResult
```

- `EvidenceBundle` holds the records the lifecycle already uses: the Okta group,
  applications, assignments (including the group's assignments to *other* applications,
  when observed), usage, the identity mapping, the mapped AD group, and dependency evidence.
- `CandidateSubject` is the Okta group's internal id and the applications whose assignment
  is under review.
- `CandidatePolicy` is the versioned configuration (below).

The function is pure: no I/O, no clock, no randomness. The same inputs give the same
result. A static test pins that `app/classification` imports nothing from
`app.integrations`, `app.store`, `app.correlation`, or any network or process module.

## Signals

| Signal | Evidence | Reason codes |
| --- | --- | --- |
| Okta app status | `OktaApplication.status` | `APP_INACTIVE`, `APPLICATION_NOT_OBSERVED` |
| Usage observation window | `ApplicationUsageObservation.window` | `USAGE_WINDOW_COVERS_RETIREMENT`, `USAGE_WINDOW_REVIEW_ONLY` (D27), `USAGE_WINDOW_TOO_SHORT` |
| Login count | `event_count` | `NO_OBSERVED_USAGE`, `LOW_USAGE`, `IN_USE`, `USAGE_WITHIN_/ABOVE_RETIREMENT_THRESHOLD` |
| Unique users | `distinct_user_count` | optional ceiling on `LOW_USAGE` (`lowUsageMaxUniqueUsers`) |
| Last observed login | `last_activity_at` | `NO_RECENT_LOGIN` (heavy use that stopped) |
| Okta app-group assignment | `ApplicationGroupAssignment` | `ASSIGNMENT_PRESENT`, `ASSIGNMENT_ABSENT`, `ASSIGNMENT_NOT_OBSERVED` |
| AD mapping confidence | `IdentityMapping` | `EXACT_MAPPING`, `MAPPING_MISSING`, `MAPPING_NAME_ONLY`, `MAPPING_UNVERIFIED_IDENTIFIER` (D56), `MAPPING_AMBIGUOUS`, `MAPPING_NOT_FOUND`, `MAPPING_NOT_EXACT` (any other non-exact confidence: fail closed), `AD_GROUP_NOT_FOUND` |
| AD direct membership | `AD_GROUP_MEMBERS` finding `AD_DIRECT_MEMBERS`; `ADGroup.member_count` | `AD_DIRECT_MEMBERS` |
| primaryGroupID dependency | `AD_GROUP_MEMBERS` finding `AD_PRIMARY_GROUP_REFERENCES` | `AD_PRIMARY_GROUP_REFERENCES` |
| AD nested membership | `AD_NESTED_MEMBERSHIP` findings `AD_MEMBER_GROUPS`, `AD_NESTED_PRINCIPALS` | same codes |
| AD parent-group membership | `AD_NESTED_MEMBERSHIP` finding `AD_PARENT_GROUP` | `AD_PARENT_GROUP`, `AD_NO_PARENT_GROUPS` |
| Emptiness (all three membership facts) | complete membership and nesting checks with no findings | `AD_GROUP_EMPTY` (`ogwa-ad-empty/v1`) |
| Protected-group status | `protection_reasons()`; `ADGroup` completeness | `PROTECTED_GROUP`, `NOT_PROTECTED`, `PROTECTION_UNDETERMINED` (D21) |
| Other Okta app assignments | other present assignments; `OKTA_OTHER_APP_ASSIGNMENT` check | `SHARED_OKTA_ASSIGNMENT`, `SINGLE_OKTA_ASSIGNMENT`, `OTHER_ASSIGNMENTS_UNKNOWN` |
| Group origin | `group_origin()` (D12) | `AD_SOURCED_GROUP`, `OKTA_ONLY_GROUP`, `NOT_AD_SOURCED` |
| Dependency coverage | `assess_dependency_coverage()` | `DEPENDENCY_COVERAGE_COMPLETE`, `DEPENDENCY_COVERAGE_INCOMPLETE` |
| Other dependency findings | any blocking finding of another kind | `DEPENDENCY_FINDING` |
| Evidence freshness | every record's provenance | `EVIDENCE_CURRENT`, `EVIDENCE_STALE`, `EVIDENCE_FUTURE_DATED`, `EVIDENCE_NOT_DECISION_GRADE`, `EVIDENCE_INCONSISTENT` |

### Separate membership facts (D20)

Direct members, primaryGroupID references, parent groups, member groups, and principals
reached through member groups stay separate facts. `DependencyFinding.code` (`FindingCode`)
is optional; `ad_evidence` sets it on every finding it emits. The store persists it (migration 0004, `dependency_findings.code`). An
uncoded finding contributes nothing to the digest, so earlier records keep their digests.
A blocking finding without a code still blocks: it is classified by its dependency kind
(`AD_MEMBERSHIP_FINDING`, `AD_NESTING_FINDING`, `SHARED_OKTA_ASSIGNMENT`, or
`DEPENDENCY_FINDING`).

### Positive and negative facts

- **Positive facts count even from incomplete evidence.** A partial read that found members
  still found members, and a partial usage read with 50 sign-ins still shows use.
- **Negative facts need a COMPLETE check from a counting source** (`COVERAGE_SOURCES`:
  Okta API, System Log, AD via AAP, synthetic). "No members", "no parents", "no other
  assignment", and "not protected" are never inferred from a missing, partial, or attested
  check. An `OPERATOR_ATTESTATION` can block but never proves absence (D13).
- **An unknown AD member count is not zero** (EA-7). `ADGroup.member_count` of `null` (the
  member attribute was not read completely) adds `AD_MEMBERSHIP_UNKNOWN` and never proves
  `AD_GROUP_EMPTY`.
- Okta dependency kinds count only when recorded on the Okta group, and AD membership
  kinds only when recorded on the mapped AD group.

## Classification

Every proven reason is recorded with a code from a closed table (`REASON_EFFECTS`). Each
code has one fixed effect:

- it **forces** a classification;
- it **holds** the result at review (it blocks retirement without forcing a classification); or
- it is **supporting** evidence.

The classification is then:

1. the first forced classification in this order:
   `PROTECTED` › `ACTIVE` › `DEPENDENCY_BLOCKED` › `HAS_MEMBERS` › `NESTED_DEPENDENCY` ›
   `SHARED_OKTA_ASSIGNMENT` › `MAPPING_REQUIRED` › `STALE_EVIDENCE` › `EVIDENCE_INCOMPLETE`.
   Positive stopping facts come before evidence problems, so a group known to have members
   is `HAS_MEMBERS` even when other evidence is stale. All reasons are still listed.
2. Otherwise, if any reason holds the result at review, the usage tier gives the
   classification: `LOW_USAGE_REVIEW` if some use was observed, `INACTIVE_REVIEW` if the app
   is inactive or no use was observed.
3. Otherwise `RETIREMENT_CANDIDATE`, **but only if every required proof is present**:
   `AD_SOURCED_GROUP`, `EXACT_MAPPING`, `NOT_PROTECTED`, `AD_GROUP_EMPTY`,
   `AD_NO_PARENT_GROUPS`, `SINGLE_OKTA_ASSIGNMENT`, `DEPENDENCY_COVERAGE_COMPLETE`, and
   `EVIDENCE_CURRENT`. For each application, it also needs `ASSIGNMENT_PRESENT`,
   `USAGE_WITHIN_RETIREMENT_THRESHOLD`, and `USAGE_WINDOW_COVERS_RETIREMENT`. A missing
   proof gives `EVIDENCE_INCOMPLETE` with `REQUIRED_CONDITION_UNPROVEN`. Promotion requires
   proof of each condition, not merely the absence of a known blocker.

### Usage tiers

| Tier | Rule (defaults) |
| --- | --- |
| `ACTIVE` | more than `lowUsageMaxSignIns` (5) sign-ins, or more users than `lowUsageMaxUniqueUsers` if set, **and** a sign-in within `recentLoginWindowDays` (30) |
| `LOW` | 1–5 sign-ins, or heavy use with no recent sign-in (`NO_RECENT_LOGIN`) |
| `INACTIVE` | the app is `INACTIVE` in Okta, or 0 sign-ins in a decision-grade window |

The tiers are `Used`, `LowUsage` (5 sign-ins or fewer) and `NoRecentSignIns`.
An `INACTIVE` app is never `ACTIVE`, even with recent sign-ins. Its sign-ins still exceed
the retirement threshold, so it stays at `INACTIVE_REVIEW`.

For a retirement candidate, usage must be at or below `retirementMaxSignIns` (0) over a
window of at least `retirementWindowDays` (90, D27), exactly as the lifecycle's own
candidacy guard requires. A complete window shorter than 90 days, but at least
`reviewMinWindowDays` (30), is a **review signal only** (`USAGE_WINDOW_REVIEW_ONLY`). Okta's
native System Log retention can therefore produce `INACTIVE_REVIEW` but never a candidate.

### Output

`ClassificationResult` holds:

- `classification`;
- every `Reason` (`code`, `detail`, `subject`);
- `reason_codes` (distinct, in order; usable as `LifecycleCandidate.reason_codes`);
- `blockers`;
- `usage_tier`;
- a per-kind `coverage` report;
- `policy_digest` (which configuration produced it);
- `evidence_fingerprint` (the same digest the lifecycle uses for approvals);
- `ad_deletion_prohibited` (true unless the result is `RETIREMENT_CANDIDATE` with COMPLETE coverage);
- `lifecycle_diversion` (the blocked state a progressing candidate should move to);
- `explain()` (text) and `to_dict()` (JSON-ready, with `"isApproval": false`).

Example (synthetic):

```text
RETIREMENT_CANDIDATE
- EVIDENCE_CURRENT: every record is complete and observed within 30 days
- APP_INACTIVE: application 'Synthetic App' is INACTIVE in Okta
- NO_OBSERVED_USAGE: 0 sign-in(s), 0 user(s) in a 90-day application-wide window; last observed sign-in none in window
- USAGE_WITHIN_RETIREMENT_THRESHOLD: 0 sign-in(s), retirement threshold 0
- USAGE_WINDOW_COVERS_RETIREMENT: 90-day window covers the 90-day retirement window
- ASSIGNMENT_PRESENT: the group is assigned to the application
- SINGLE_OKTA_ASSIGNMENT: a complete check found no other application assignment
- AD_SOURCED_GROUP: imported through a configured AD integration
- EXACT_MAPPING: EXACT_STABLE_ID on objectGUID
- NOT_PROTECTED: no built-in, configured, or AD protection applies
- AD_GROUP_EMPTY: no direct members, no primaryGroupID references, no principals through member groups (ogwa-ad-empty/v1)
- AD_NO_PARENT_GROUPS: the AD group is not a member of any other group
- DEPENDENCY_COVERAGE_COMPLETE: every required dependency kind was checked completely
```

Reason codes are stable names. Threshold values appear in the detail text, not in the
code, so a policy change never renames a code. There is no `NO_OBSERVED_USAGE_90D`: that
condition is `NO_OBSERVED_USAGE` together with `USAGE_WINDOW_COVERS_RETIREMENT`.

### Lifecycle diversions

| Classification | Diversion for a progressing candidate |
| --- | --- |
| `PROTECTED` | `PROTECTED` |
| `MAPPING_REQUIRED` | `MAPPING_AMBIGUOUS` |
| `DEPENDENCY_BLOCKED`, `HAS_MEMBERS`, `NESTED_DEPENDENCY`, `SHARED_OKTA_ASSIGNMENT` | `DEPENDENCY_BLOCKED` |
| `STALE_EVIDENCE` | `STALE_EVIDENCE` |
| `EVIDENCE_INCOMPLETE` | `EVIDENCE_INCOMPLETE` (migration 0009) |
| `ACTIVE`, the review tiers, `RETIREMENT_CANDIDATE` | none. A human decides (`REJECTED` / `EXCLUDED` are human-only) |

The classifier never applies a diversion; the lifecycle's own guards do that.

`STALE_EVIDENCE` means once-complete evidence outlived its freshness window.
`EVIDENCE_INCOMPLETE` means required evidence was never fully or properly obtained:
missing, `PARTIAL`/`FAILED`, inconsistent, undetermined, or dated in the future. A
future-dated record forces `EVIDENCE_INCOMPLETE`. Future-dated evidence is never fresh and never stale; its
distinct reason is `EVIDENCE_FUTURE_DATED`, and such a record never also yields `EVIDENCE_STALE`
or `EVIDENCE_CURRENT` (D116). Neither state is ever assigned by an operator (D104, D114).

## The critical delete-safety rule

**If dependency coverage is not exactly `COMPLETE`, AD deletion stays prohibited.**

- Coverage is computed by the same `assess_dependency_coverage` the lifecycle's
  AD-stage guards use (the quarantine and deletion steps). A test checks that the two agree for every dropped kind.
- Incomplete coverage holds the result at `INACTIVE_REVIEW` / `LOW_USAGE_REVIEW` with
  `DEPENDENCY_COVERAGE_INCOMPLETE`, which names the uncovered kinds. It never lowers the
  required kinds: `LifecyclePolicy` refuses a configuration without the mandatory kinds,
  and the default requires every kind except `OTHER`.
- **No required dependency kind can be covered from production**
  (`PRODUCTION_COLLECTORS`, pinned by a test), so no production relationship can become a
  `RETIREMENT_CANDIDATE`. That is intended (fail closed). See
  [dependency-coverage.md](../operations/dependency-coverage.md).
- An end-to-end test reads the golden `normal-empty-group` AD report as `AD_VIA_AAP`
  evidence, as if read from real AD. The D19 gate makes the AD group record PARTIAL, so the classification is
  `EVIDENCE_INCOMPLETE` (`PROTECTION_UNDETERMINED`), never a candidate.

## Configuration

`CandidatePolicy` wraps the lifecycle's `LifecyclePolicy` (one source of truth for the
numbers both use) and adds the classifier's own thresholds. Every value has a floor or
ceiling the configuration cannot cross:

| Key | Default | Bounds |
| --- | --- | --- |
| `usage.lowUsageMaxSignIns` | 5 | `retirementMaxSignIns` … 1000 |
| `usage.lowUsageMaxUniqueUsers` | `null` (off) | 0 … `lowUsageMaxSignIns` |
| `usage.reviewMinWindowDays` | 30 | 7 … `retirementWindowDays` |
| `usage.recentLoginWindowDays` | 30 | 1 … `retirementWindowDays` |
| `usage.retirementWindowDays` | 90 (D27) | ≥ 30 (`LifecyclePolicy`) |
| `usage.retirementMaxSignIns` | 0 | 0 … 5 (`LifecyclePolicy`) |
| `freshness.*` | 720 h / 168 h / 24 h / 5 min | `FreshnessPolicy` ceilings (90 d / 14 d / 24 h / 15 min), tightening with risk |
| `lifecycle.holdPeriodDays`, `lifecycle.approvalMaxTtlHours` | 30 / 168 | ≥ 7 d; 1 h … 14 d |
| `requiredDependencyKinds` | every kind except `OTHER` | must include the four mandatory kinds |
| `protected.*`, `adDirectorySourceIds` | empty | additive lists; empty sources means nothing is AD-sourced (fail closed) |

The document (format `ogwa-candidate-policy/v1`) is strict JSON:

- every key is required and no other key is accepted;
- integers only, never booleans or floats;
- no duplicate keys, no `NaN`, no duplicate list entries;
- at most 100 000 characters.

Durations must be whole units. `canonical_json()` is the sorted, compact form, and
`digest` is its SHA-256.

## Where the policy lives (D32, D35)

- **Git** holds the format and its parser (`app/domain/candidate_policy.py`), the hard
  floors and ceilings (code constants and `LifecyclePolicy` / `FreshnessPolicy` checks), and
  the default template [`config/candidate-policy.template.json`](../../config/candidate-policy.template.json).
  The template contains no environment values: the AD integration and protected lists are
  empty.
- **The active production policy** is the latest `PolicyVersion` in the OGWA database
  (`Store.active_policy_version()`): immutable and append-only. It is never read from a
  file at run time.
- **Policy v1 is the template**, which equals the defaults above: the 90-day usage window
  (D27) and the 5-sign-in low-usage semantics. A test pins its digest
  (`sha256:911a0f0a…7307`), so a default cannot change silently. Because v1 configures no AD
  integration id, it treats no group as AD-sourced (fail closed). Environment values are
  added by a later version through the review below, never committed to git.
- **Floors and ceilings cannot be weakened by policy (D34).** The document has no key for
  them. Out-of-bounds values and dropped mandatory dependency kinds are refused
  (`TemplateAndFloorTests`), so changing a floor is a reviewed source change.

## Auditable changes

A configuration change is a `PolicyVersion`:

- the canonical document and its digest;
- `proposed_by`, acting as `IDENTITY_AUTOMATION`;
- `approved_by`, a **different human** acting as `SECURITY_IAM` (D33);
- `decided_at`, and a reason.

Versions form one chain (sequence, supersedes). A version is refused if it is unchanged,
back-dated, a fork, self-approved, or carries the wrong role. Each rule is enforced three
times: by the domain (`PolicyVersion`, `version_append_problems`), by the store, and by
SQLite triggers and CHECKs (migrations 0004 and 0005; `policy_versions` is append-only).
Roles are recorded as stated by the caller. The operator API must derive them from the
operator's verified group membership, never from free input.

Recording a version appends a `POLICY_REVIEW_RECORDED` audit event in the same transaction
(migration 0005, D41). The event carries the new and previous digests, the proposer, both
roles, and before/after references. `Store.active_policy_version()` returns the policy in
force, and `verify_integrity` re-checks the chain and every document's digest. Every
classification names the `policy_digest` it used, so any result can be traced to the
approved version.

Policy v1 stays unrecorded until the operator API provides authenticated proposers and
approvers (D52). The synthetic Null Meridian seed records its own two synthetic versions through
this same flow (below); the classic synthetic world still runs the unrecorded, labelled demo policy (D66).

## Named releases and the policy each decision records

A digest identifies rules exactly but means nothing to a reviewer. A **policy release**
(`app/domain/policy_release.py`, format `ogwa-policy-release/v1`) gives one policy document a
stable identity: `policyId` (never changes across versions), an explicit semantic `version`,
`effectiveFrom`, `supersedes`, `changes`, `title`, `purpose`, and `synthetic`, followed by the
`policy` document itself, unchanged. It is strict JSON like the policy document, so a release adds
identity and never a second way to state a rule. `release_digest` covers the whole release;
`policy_digest` is the rules' digest that every classification already names.

- A release chain is one policy id with strictly increasing versions and effective times, each
  release superseding the one before, and no two releases with the same rules
  (`release_history_problems`). A rules digest therefore names at most one release.
- A recorded `PolicyVersion` has a release identity only when a release carries exactly its rules
  (`release_for_digest`); otherwise every surface says it has none. No production release is held
  in git (D32), so only a SYNTHETIC store's demo dataset supplies releases (`demo_releases`).
- The Null Meridian releases are [NM-LIFECYCLE-004](../demo/policies/NM-LIFECYCLE-004.md) v1.1.0
  and v1.2.0 (`config/policies/null-meridian/`). The seed records v1.1.0 before triage and v1.2.0
  after it, through `Store.record_policy_version`, proposed and approved by two synthetic people;
  the snapshot day (NM-C11's approval) comes after v1.2.0 and records it, and the seed
  stops unless every decision and approval records the release in force on its own date
  (`policy_chronology_problems`).

**Every decision records the policy that judged it.** `Store.transition` and
`Store.record_approval` take a `PolicyRef` (the rules' digest, `RECORDED_VERSION` or
`UNRECORDED_SYNTHETIC_DEMO`, the version's id and sequence, and the release identity if any). Inside
the write transaction the store refuses (`StoreConflict`, nothing written) a reference that is not
the policy in force: a recorded reference must name the latest version by id, sequence, and digest,
and the lifecycle rules applied must be that version's own; an unrecorded reference is possible
only while no version is recorded. The reference is stored in the decision's (or approval's, or
refusal's) audit event, in the same transaction and hash chain; no schema change. F08 checks
the row's own details exactly, and the policy keys must be complete and valid.
`Store.recorded_policies` reads references back as recorded; a record made without one (the
classic seed, for example) shows none, never the policy in force now.

The API passes `PolicyInForce.ref` on every transition and approval, and serves each decision's and
approval's recorded `policy` with `publishedRelease` (`MATCHES_RECORDED`, `DIFFERS_FROM_RECORDED`,
`NOT_PUBLISHED`): a release file edited after the fact shows as a difference, never as the policy
that was recorded. Each decision is explained under the exact version that produced it
([evidence-assessment.md](evidence-assessment.md#decision-explanation)).

## Not in scope

No API or UI route edits the policy, classification results are not persisted, nothing
creates candidates automatically, and the Okta-only group lifecycle is undefined (D12).
