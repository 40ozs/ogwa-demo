# Domain model

Defined in `app/domain/`. Standard library only, with no I/O, network, or
clock reads: every rule takes `now` as an argument. Persistence, the web API, and
integrations live outside `app/domain/` and build on it.

Related: [lifecycle-state-machine.md](lifecycle-state-machine.md),
[../security/safety-invariants.md](../security/safety-invariants.md).

## Identity: internal IDs vs external identifiers

Every entity has an internal ID that OGWA mints: `<prefix>_<32 hex>`, for example
`cand_…` or `adg_…` (`app/domain/ids.py`). External identifiers are attributes and never
primary keys:

| Entity | Internal prefix | External identifiers held as attributes |
| --- | --- | --- |
| `OktaApplication` | `oapp` | `okta_app_id` |
| `OktaGroup` | `ogrp` | `okta_group_id`, `source_directory_id`, `directory_external_id`, `directory_qualified_name`, `directory_object_sid_unverified` (Okta's copy of the objectSid; unverified source metadata, migration 0008, D37) |
| `ApplicationGroupAssignment` | `asgn` | none (it is a pair of internal IDs) |
| `ApplicationUsageObservation` | `use` | none |
| `ADGroup` | `adg` | `object_guid`, `sid`, `distinguished_name`, `sam_account_name`, `domain` |
| `IdentityMapping` | `map` | none (it links internal IDs) |
| `DependencyEvidence` | `dep` | `findings[].reference` (free text) |
| `LifecycleCandidate` | `cand` | none |
| `LifecycleDecision` | `dec` | none |
| `ApprovalRecord` | `apr` | operator subject identifier |
| `ExecutionJob` | `job` | none |
| `AuditEvent` | `aud` | none |
| `CollectorRun` | `run` | none |
| Stored observation row | `obs` | none |
| Correlation id | `req` | none |
| `MappingReview` | `mrev` | the reviewed AD object's objectGUID, SID, DN, sAMAccountName |
| `PolicyVersion` | `pver` | none |

Why: names and DNs change, SIDs and names can repeat across domains, and Okta IDs only
mean something within one tenant. `check_id` rejects an external ID wherever an internal
one is expected.

**Observation IDs are stable per observed object or scope.** Observing the same
assignment, AD group, usage scope (application plus group scope), or dependency check
(subject plus kind) again produces a record with the **same** ID and a new provenance.
This keeps the evidence fingerprint unchanged when nothing material has changed. The
store keeps one anchor row per such ID and appends one observation row (`obs_…`)
per observation; see [persistence.md](persistence.md).

`deterministic_ids(namespace)` makes `new_id` reproducible inside a `with` block. Only the
synthetic seed and tests use it.

## Entities

All records are frozen dataclasses that validate their invariants on construction
(`InvalidRecord`). Timestamps must be timezone-aware.

### Observations (evidence)

Each observation carries a `Provenance` and exposes a `digest` of its material fields
(see [Evidence](#evidence-provenance-digests-freshness)).

| Entity | What it records | Key invariants |
| --- | --- | --- |
| `OktaApplication` | An Okta app: status, sign-on mode, label | `label` is display-only and excluded from the digest |
| `OktaGroup` | An Okta group: type `OKTA_GROUP` / `APP_GROUP` / `BUILT_IN`, plus directory attributes for imported groups | Directory attributes only on `APP_GROUP`. `BUILT_IN` groups are always protected |
| `ApplicationGroupAssignment` | Whether a group is assigned to an app at `observed_at` (`present`) | Stable ID per (app, group). `present=False` records an observed removal |
| `ApplicationUsageObservation` | Sign-in events and distinct users for an app over a window, either app-wide or attributed to one group | `window_end` ≤ `observed_at`; distinct users ≤ events; no `last_activity_at` inside the window when events = 0. The digest uses the window *length*, not its position |
| `ADGroup` | An AD group resolved **by objectGUID against its own domain**: SID, DN, sAMAccountName, `adminCount`, `ProtectedFromAccidentalDeletion`, `isCriticalSystemObject`, member count | Canonical lowercase GUID. `exists=True` requires a valid SID, DN, and sAMAccountName. `exists=False` records a complete lookup that found nothing |
| `IdentityMapping` | How an Okta group corresponds to an AD group, with confidence, matched attributes, and reason | See [Mapping confidence](#mapping-confidence) |
| `DependencyEvidence` | The result of checking **one dependency kind** for one subject (Okta or AD group), with findings | A COMPLETE check with no findings is positive evidence of absence |

### Lifecycle records

| Entity | What it records |
| --- | --- |
| `LifecycleCandidate` | An Okta group whose assignment to one or more apps appears unused, and (through the mapping) its AD group. Holds `state`, `epoch`, `hold_until`, `blocked_from`, and `proposed_by`, and the quarantine approver, the post-quarantine `quarantine_hold_until`, and the deletion's proposer and proposal time. Created only by `LifecycleCandidate.discover()` (always `DISCOVERED`) |
| `LifecycleDecision` | One applied transition: from/to state, actor, time, reason, evidence fingerprint, epoch, and the approval and job IDs used |
| `ApprovalRecord` | A human decision bound to candidate, stage, epoch, evidence fingerprint, and expiry. See [Approval model](#approval-model) |
| `ExecutionJob` | A planned or performed change. In this build it can only be a dry run or a synthetic-target execution. See [Execution jobs](#execution-jobs) |
| `AuditEvent` | An append-only, hash-chained event. See [Audit](#audit) |

Supporting types: `Actor` (`HUMAN` or `SYSTEM`, with a stable id), `EvidenceBundle` (the
current evidence for one candidate), and `LifecyclePolicy`.

### Candidate subject

A candidate is **group-centric**: one Okta group, the subset of its app assignments that
look unused (`assignment_ids`), and the AD group it maps to. Other active assignments of
the same group are recorded as `OKTA_OTHER_APP_ASSIGNMENT` dependencies, and they block
AD retirement. An app-centric view (all groups of one inactive app, as
the existing inactive-applications report produces) is a reporting projection over candidates, not a
separate lifecycle.

## Evidence: provenance, digests, freshness

Defined in `app/domain/evidence.py`.

### Provenance

Every decision-driving observation records:

| Field | Meaning |
| --- | --- |
| `source` | `OKTA_API`, `OKTA_SYSTEM_LOG`, `AD_VIA_AAP`, `CONFIGURED_MAPPING`, `OPERATOR_ATTESTATION`, `SYNTHETIC` |
| `observed_at` | When the observation was made (timezone-aware) |
| `scope` | What was queried, for example `okta:group:<id>:apps` |
| `collector_version` | The collector that produced it |
| `result_status` | `COMPLETE` (finished; result fully represented, even if empty), `PARTIAL` (truncated, paging interrupted, domain unreachable), `FAILED` |
| `digest` | On the record: SHA-256 over canonical JSON of the material fields (`stable_digest`) |

Only `COMPLETE` is decision-grade. `PARTIAL` and `FAILED` observations never satisfy a
guard. The one exception is dependency checks: an incomplete check is allowed in the
bundle but does not count toward coverage.

### Material fields

`digest` covers only fields whose change should invalidate an approval. Collection
timestamps, display labels, and explanatory reason text are excluded. As a result,
re-observing identical facts keeps the digest, while a new member, a new sign-in, or a
change in mapping confidence changes it.

### Freshness policy

`FreshnessPolicy` gives a maximum evidence age for each purpose:

| Purpose | Used for | Default | Hard ceiling |
| --- | --- | --- | --- |
| `REVIEW` | Becoming or remaining a candidate; human investigation | 30 days | 90 days |
| `APPROVAL` | A human approving the next step | 7 days | 14 days |
| `EXECUTION` | Dry runs, recording an observed change, any destructive step | 24 hours | 24 hours |

Rules: `execution ≤ approval ≤ review`. Clock-skew tolerance defaults to 5 minutes
(maximum 15). Evidence dated beyond the skew tolerance is rejected as future-dated. A
policy may tighten these values but never loosen them past the ceilings.

## Mapping confidence

`IdentityMapping.confidence` (`app/domain/model.py`):

| Confidence | Meaning | Record rules | Lifecycle use |
| --- | --- | --- | --- |
| `EXACT_STABLE_ID` | The Okta group carries the AD group's objectGUID or objectSid | Names one AD group; `matched_attributes` includes `objectGUID` or `objectSid` | Can reach approval and retirement |
| `EXACT_DIRECTORY_SOURCE` | Imported by a known AD integration and matches exactly one object in that integration's domain by directory attributes | Names one AD group; records matched attributes | Can reach approval and retirement |
| `EXACT_CONFIGURED_MAPPING` | A reviewed mapping configuration names the pair | Names one AD group; needs `configuration_ref`; source `CONFIGURED_MAPPING` | Can reach approval and retirement |
| `NAME_ONLY` | Names match, nothing stronger | Names one AD group; must not claim a stable-ID match | **Human investigation only**: may reach `NEEDS_REVIEW`, never `APPROVED` |
| `UNVERIFIED_STABLE_ID` (D56, migration 0006) | A stable identifier (the directory-source objectSid) resolves to one AD group, but the mechanism is unverified (D37) | Names one AD group; `matched_attributes` includes `objectGUID` or `objectSid`; no `configuration_ref` | **Human investigation only**, like `NAME_ONLY`; never `APPROVED` |
| `AMBIGUOUS` | More than one possible AD counterpart | No `ad_group_id`; at least two `candidate_ad_group_ids` | Never advances past review; `MAPPING_AMBIGUOUS` |
| `NOT_FOUND` | No AD counterpart | No `ad_group_id`, no candidates | Never advances past review; `MAPPING_AMBIGUOUS` |

Every mapping persists its `reason`, `matched_attributes`, and provenance. When a
mapping names an AD group, `ADGroup` itself is always keyed by objectGUID. So even an
exact mapping lands on a stable AD identity.

Mappings are produced by `app.correlation` (see
[identity-correlation.md](identity-correlation.md)): `EXACT_STABLE_ID` from a corroborated
directory-source objectSid, `EXACT_CONFIGURED_MAPPING` from the reviewed configuration or
from an operator selection approved by a second operator (citing
`ogwa-mapping-registry:<review id>`), and `NAME_ONLY` only from a name search. Human
review decisions about mappings are `MappingReview` records (`app/domain/mapping_review.py`).

## Dependency coverage

`DependencyKind` lists what can depend on a group: other Okta app assignments, Okta
policy references, AD members, nested membership, ACL references (shares, delegation),
GPO references, AAP references, app-side configuration, and other.

Coverage is **derived, never asserted** (`assess_dependency_coverage`):

| Coverage | Condition |
| --- | --- |
| `COMPLETE` | Every kind in `policy.required_dependency_kinds` has a decision-grade check |
| `PARTIAL` | Some required kinds have a decision-grade check |
| `UNKNOWN` | No required kind does |

By default every kind except `OTHER` is required. A policy cannot drop the mandatory
kinds (`OKTA_OTHER_APP_ASSIGNMENT`, `OKTA_POLICY_REFERENCE`, `AD_GROUP_MEMBERS`,
`AD_NESTED_MEMBERSHIP`). Kinds that cannot be collected automatically yet (for example
file-share ACLs) can be satisfied by an `OPERATOR_ATTESTATION` check from a named human.
Until they are, coverage stays `PARTIAL` and AD retirement stays impossible. That is
intended.

Any finding marked `blocking` stops progress regardless of coverage or staleness.

## Approval model

`ApprovalRecord` (`app/domain/approval.py`) records:

| Field | Purpose |
| --- | --- |
| `candidate_id`, `stage` | What is approved: `OKTA_UNASSIGN`, `AD_QUARANTINE`, or `AD_DELETION` (D147). `AD_RETIREMENT` is the legacy single AD stage: its stored rows are history and authorize nothing, and no new approval may use it (D148) |
| `decision` | `APPROVE` or `REJECT` |
| `operator` | A `HUMAN` actor; system actors cannot approve |
| `decided_at`, `expires_at` | Lifetime, capped by `policy.approval_max_ttl` (default 7 days, at most 14) |
| `reason` | Required text |
| `evidence_fingerprint` | Digest of the evidence bundle the operator reviewed |
| `candidate_epoch` | The candidate's epoch when approved |

`approval_problems()` refuses an approval that belongs to another candidate, is for
another stage, is a `REJECT`, comes from an earlier epoch, was given by the candidate's
proposer, exceeds the maximum lifetime, is future-dated or expired, predates the end of
the stage's hold, predates the stage's proposal (for `AD_DELETION`), was given by a person
the stage excludes (the Okta-stage approver for the AD stages, D11; the quarantine approver
and the deletion's proposer for the deletion, D143), is of the legacy `AD_RETIREMENT` stage,
or whose fingerprint differs from the current evidence. `stage_approval_rules()` in
`app/domain/lifecycle.py` supplies the hold, the proposal time, and the excluded people for
each stage.

**Evidence fingerprint** (`evidence_fingerprint`): SHA-256 over the sorted
`(kind, id, result_status, digest)` of every record in the bundle. Re-observing
identical facts keeps it. Any material change, a status change (for example COMPLETE to
PARTIAL), or adding or removing a record changes it, and that voids the approval.

## Execution jobs

`ExecutionJob` (`app/domain/execution.py`) records kind (`OKTA_UNASSIGN`, `AD_QUARANTINE`,
or `AD_DELETION`; the legacy `AD_RETIREMENT` only in stored history, D148), mode, dry-run
flag, status, approval (of the same stage as the kind), evidence fingerprint, targets
(internal IDs; exactly one AD group for an AD kind), and timing. Construction refuses:

- `PRODUCTION_MUTATION` (through `assert_mode_permitted_by_build`, the same check startup uses);
- `READ_ONLY_PRODUCTION`, which cannot plan mutations;
- a non-dry-run job in `DRY_RUN_MUTATION`;
- `executed=True` unless the mode is `LOCAL_SYNTHETIC` and the targets are synthetic
  (this mirrors `MutationCapableService._perform`).

So a record claiming a real production change cannot exist in this build.

## Audit

`AuditTrail` (`app/domain/audit.py`) is the in-memory form; `app.store` persists the same
chain. Each `AuditEvent` records actor, action, target (`subject_id`), time,
`execution_mode`, `result` (`SUCCEEDED`/`REFUSED`/`FAILED`), `correlation_id`,
and short `before_ref`/`after_ref` pointers to stored records. Its digest covers all of
that and the previous digest. `verify_chain` detects
edits, removals, and reordering. Pass `expected_head` (an externally anchored last
digest) to detect an edit to the newest event. Detail values go through the shared redaction (`app/core/redaction.py`),
and any detail whose key looks like a credential is replaced with `***`.
`apply_and_audit` records both applied and refused transitions.

## Policy

`LifecyclePolicy` (`app/domain/policy.py`), with defaults and limits:

| Setting | Default | Limit | Origin |
| --- | --- | --- | --- |
| `min_usage_window` | 90 days | ≥ 30 days | The Okta System Log retains about 90 days |
| `max_usage_events_for_candidate` | 0 (inactive) | 0–5 | The same report's low-usage threshold of 5; above 0 is a deliberate choice |
| `hold_period` | 30 days | ≥ 7 days | — |
| `approval_max_ttl` | 7 days | 1 hour – 14 days | — |
| `required_dependency_kinds` | all except `OTHER` | must include the mandatory kinds | — |
| `protected_okta_group_ids`, `protected_ad_object_guids`, `protected_ad_sids` | empty | frozensets | Configured protected list |

### Protection

`protection_reasons()` treats a candidate as protected if any of these holds:

- the Okta group is `BUILT_IN`;
- the Okta group is on the configured list;
- the AD SID is builtin (`S-1-5-32-*`) or has a domain RID below 1000. This covers
  Domain/Schema/Enterprise Admins, operators, and other well-known groups, and unlike a
  list of group names it does not depend on locale;
- `adminCount` is set;
- `ProtectedFromAccidentalDeletion` is set;
- `isCriticalSystemObject` is set;
- the AD group's GUID or SID is on the configured list.

Protection is terminal: the candidate moves to `PROTECTED` and never progresses.

## Open questions

- Where the authoritative configured protected list lives, and who owns it.
- ~~Whether the AD stage should require a second approver distinct from the
  `OKTA_UNASSIGN` approver.~~ Answered: yes (D11); and the AD deletion's approver differs
  from the quarantine approver and the deletion's proposer too (D143).
- Okta-mastered groups with no AD counterpart (`NOT_FOUND`) are out of scope for this
  lifecycle. They cannot pass approval. A separate Okta-only lifecycle may be needed.
- Who performed an observed unassignment or deletion, and when. HOLD and RETIRED are
  recorded from read-only observation. The Okta System Log
  (`group.application_assignment.remove`) and AD replication metadata could attribute the
  change; this build does not collect that evidence.
