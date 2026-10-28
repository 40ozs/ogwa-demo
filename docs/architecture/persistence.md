# Persistence, audit trail, and synthetic demo data

Status: P03. This describes `app/store/` and `app/demo/`.

## Stack decision

The P03 prompt preferred SQLAlchemy 2.x with Alembic. That would need new packages,
and decision D5 allows installs only into a project-local `.venv` from an
organization-approved package source. On this workstation:

- SQLAlchemy 2.0.49 is installed in the global interpreter but is not declared by the
  project;
- Alembic is not installed and there is no cached wheel;
- pip has no configured index, so it would fall back to public PyPI, which has not been
  shown to be org-approved.

On 2026-10-04 the owner chose to use the standard library for now:

| Concern | P03 implementation | Path to the preferred stack |
| --- | --- | --- |
| Database access | `sqlite3`, explicit SQL, one module per concern | Map the same tables with SQLAlchemy 2.x Core or ORM |
| Migrations | `app/store/migrator.py`: ordered, forward-only, per-migration transaction, checksums verified on every open | Turn each `vNNNN_*.py` into an Alembic revision with the same DDL, and stamp existing databases |
| Configuration | `OGWA_DATABASE_URL` in SQLAlchemy URL syntax (`sqlite:///…`) | Unchanged |
| PostgreSQL | DDL restricted to the SQL that SQLite and PostgreSQL share. PostgreSQL URLs are refused | Needs an approved driver and the PostgreSQL version of migration 0002 |

This choice is not yet in [decisions.md](decisions.md). The owner should record it there.

## Configuration

`OGWA_DATABASE_URL` (see `.env.example`):

- The default is `sqlite:///var/ogwa-local.sqlite3`. Relative paths resolve against the
  project root, and `var/` is git-ignored.
- `sqlite:///:memory:` is accepted for tests.
- PostgreSQL URLs, other schemes, query strings, and embedded credentials fail startup
  (`ConfigError`).
- A missing database file is never created implicitly. Only `init` and `reset-demo`
  create one.

## Schema

| Persisted concept | Anchor table (immutable identity) | History tables (append-only) |
| --- | --- | --- |
| Applications | `okta_applications` (`okta_app_id` unique) | `okta_application_observations` |
| Groups | `okta_groups` (`okta_group_id` unique) | `okta_group_observations` |
| App-group assignments | `app_group_assignments` (application, group unique) | `assignment_observations` |
| Usage observations | `usage_scopes` (application plus group scope, `*` = app-wide) | `usage_observations` |
| AD group observations | `ad_groups` (`object_guid` unique, canonical lowercase) | `ad_group_observations` |
| Identity mappings | `identity_mappings` (one per Okta group) | `identity_mapping_observations`, `identity_mapping_candidates` |
| Dependency evidence | `dependency_checks` (subject plus kind) | `dependency_observations`, `dependency_findings` |
| Candidates | `candidates` (identity immutable; state is a projection) | `candidate_assignments` |
| Decisions | — | `decisions` |
| Approvals | — | `approvals` |
| Execution jobs | `execution_jobs`, `execution_job_targets` | `execution_job_status_events` |
| Collector runs | `collector_runs` | `collector_run_outcomes` (exactly one per run) |
| Audit events | — | `audit_events` |
| Environment marker | `store_metadata` (one row, written once) | — |

The anchor/observation split follows the P02 identity model. A stable internal ID
identifies an object or scope. Re-observing it adds a row with a new provenance and
never overwrites the earlier one. "Latest" means the latest `observed_at`, so evidence
that arrives late cannot displace newer evidence. Each observation stores its material
digest, and the digest is recomputed and compared on every load.

**Portability rules** (`test_portable_ddl_uses_only_shared_sql`):

- Column types are `TEXT` and `INTEGER` only.
- Timestamps are fixed-width UTC text (`YYYY-MM-DDTHH:MM:SS.ffffffZ`) with a shape
  CHECK, so lexical order is time order.
- Booleans are `0`/`1` with a CHECK.
- Constraints are standard CHECK, UNIQUE, and FOREIGN KEY, plus one partial unique index.
- No `AUTOINCREMENT`, `INSERT OR …`, `PRAGMA`, or engine types in portable DDL.

**Constraints that encode safety rules**:

- `execution_jobs.execution_mode` allows only `LOCAL_SYNTHETIC` and `DRY_RUN_MUTATION`.
  `audit_events.execution_mode` and `collector_runs.execution_mode` exclude
  `PRODUCTION_MUTATION`.
- A status event may set `executed = 1` only when the status is `SUCCEEDED` and the
  targets are synthetic.
- Approvals are made by `HUMAN` actors only and must expire after they are decided.
- An unresolved mapping (`AMBIGUOUS`, `NOT_FOUND`) cannot name an AD group.
- A partial unique index allows at most one open (non-terminal) candidate per Okta
  group.
- Enum values are frozen literals inside the migration. A test fails if a domain enum
  drifts from them, so a new value needs a new migration.

## Migrations

`python -m app.store upgrade` applies pending migrations.

- Migrations are forward-only. A downgrade would destroy append-only history.
- Each migration runs in one transaction together with its bookkeeping row.
- Every applied migration's checksum is re-verified each time the store is opened. An
  edited migration, a gap, or a database newer than the build is refused.
- The checksums are pinned in `PINNED_CHECKSUMS` in `tests/test_store_migrations.py`.
  Never edit an applied migration; add a new one.

The migrations:

| Version | Content |
| --- | --- |
| 0001 `core_schema` | Every table, constraint, and index above (portable DDL) |
| 0002 `append_only_guards` | SQLite triggers: `UPDATE`/`DELETE` refused on every history and anchor table, including `schema_migrations` and `store_metadata`. Candidates are never deleted and their identity columns are immutable. New candidates start in `DISCOVERED`. A candidate's state, epoch, and decision count can change only in step with a newly appended decision, and the decision must continue from the candidate's current state. Audit inserts must extend the chain head. Job status events are sequential and stop once a job has finished |
| 0003 `mapping_registry` (P06) | `mapping_reviews`: one append-only chain of human mapping reviews per Okta group (PROPOSED, APPROVED, REJECTED). SQLite triggers refuse `UPDATE`/`DELETE`, a row that does not extend its group's chain, and an approval of an operator selection by the operator who selected it. CHECKs refuse non-exact or name-only approvals and non-human reviewers. No PostgreSQL implementation, so the runner refuses it there. See [identity-correlation.md](identity-correlation.md#persistence-mapping_reviews-migration-0003) |
| 0004 `candidate_policy` (P07) | `dependency_findings.code` (nullable, CHECKed against the frozen `FindingCode` list; an uncoded finding keeps its P03 digest). `policy_versions`: one append-only chain of approved candidate-policy documents with their digests; CHECKs require two different human actors, and SQLite triggers refuse `UPDATE`/`DELETE`, a row that does not extend the chain, a back-dated row, and an unchanged policy. No PostgreSQL implementation. See [candidate-policy.md](candidate-policy.md#auditable-changes) |
| 0005 `review_audit_actions` (D33, D41) | Rebuilds `audit_events` with the action list extended by `MAPPING_REVIEW_RECORDED` and `POLICY_REVIEW_RECORDED`. SQLite cannot alter a CHECK, so the migration creates the new table from v0001's DDL, copies every row verbatim, drops and renames, and recreates v0001's audit indexes and v0002's three audit triggers byte for byte. Earlier events, their digests, and the chain are unchanged. It also adds `policy_versions.proposed_by_role` (`IDENTITY_AUTOMATION`) and `approved_by_role` (`SECURITY_IAM`), required by a trigger. No PostgreSQL implementation |
| 0006 `unverified_stable_id` (D56) | Rebuilds `identity_mapping_observations` with the confidence list extended by `UNVERIFIED_STABLE_ID`. `identity_mapping_candidates` references the table, so foreign-key checks are deferred. Rows are stashed in a backup table, and the table is dropped, recreated under its own name, and refilled verbatim; a rename would leave SQLite's deferred-violation count uncleared, and the commit would fail. v0001's index and v0002's two triggers are recreated byte for byte. No PostgreSQL implementation |
| 0007 `governed_refusals` (D65) | Rebuilds `audit_events` exactly as 0005 did, with the action list extended by `GOVERNED_REQUEST_REFUSED`: a refused, authenticated, valid governed API request. Rows, digests, the chain, v0001's indexes, and v0002's three triggers are unchanged. `Store.record_governed_refusal` writes only the audit event, and only for a human actor. No PostgreSQL implementation |
| 0008 `okta_directory_sid` (D84–D87) | `okta_group_observations.directory_object_sid_unverified`: Okta's copy of the AD objectSid (`profile.objectSid`), stored as unverified source metadata, never as mapping evidence. `ADD COLUMN`, so existing rows keep their values (NULL here) and v0002's per-table triggers still apply; a CHECK allows a value only on an `APP_GROUP` row and only in SID shape. It is part of the Okta group observation, so it shares that observation's provenance and freshness. `OktaGroup.material()` includes it only when present, so earlier digests and evidence fingerprints are unchanged. No PostgreSQL implementation |
| 0009 `evidence_incomplete_state` (owner decisions after P09) | The `EVIDENCE_INCOMPLETE` lifecycle state. The state lists are inline CHECKs on `candidates` (`state`, `blocked_from`) and `decisions` (`from_state`, `to_state`), so both tables are rebuilt in the migration's transaction (deferred foreign keys; backup, drop, recreate under the same name, re-insert verbatim with their triggers absent, then v0001's three indexes and v0002's seven triggers byte for byte). Rows, digests, histories, and the audit chain are unchanged; no audit event is added, so an upgraded store keeps its head. No PostgreSQL implementation |
| 0010 `remediation_dry_runs` (P10) | Rebuilds `audit_events` exactly as 0005 and 0007 did, with the action list extended by `REMEDIATION_DRY_RUN_RECORDED`: a remediation dry run that passed every gate and resolved to `SIMULATED`, `WHATIF`, or `VALIDATION_ONLY`. The audit event is the record; no other table changes. `Store.record_remediation_dry_run` refuses a `BLOCKED` or executed result (a blocked dry run is `GOVERNED_REQUEST_REFUSED`), a non-human actor, and an approval of another candidate. Rows, digests, the chain, v0001's indexes, and v0002's three triggers are unchanged, so an upgraded store keeps its head. No PostgreSQL implementation. See [remediation.md](remediation.md) |

| 0011 `ad_quarantine_deletion_stages` (P10B, D143–D155) | The AD quarantine and deletion stages. Seven lifecycle states, the approval stages and job kinds `AD_QUARANTINE` and `AD_DELETION`, and four nullable candidate columns (`quarantine_approver_*`, `quarantine_hold_until`, `deletion_proposer_*`, `deletion_proposed_at`), projections of the decisions like `okta_unassign_approver`. The value lists are inline CHECKs, so `candidates`, `approvals`, `execution_jobs`, and `decisions` are rebuilt as 0009 rebuilt two of them (deferred foreign keys; backup, drop children first, recreate parents first, re-insert verbatim, then v0001's five indexes and v0002's eleven triggers). `trg_candidates_start_discovered` also requires the new columns to be NULL. New: a CHECK that a candidate with a post-quarantine hold never stands in, or is blocked from, a pre-quarantine state (D144), and three triggers refusing a new `AD_RETIREMENT` approval or job, or a new decision of the legacy stage (D148). Legacy rows stay, verbatim; the audit chain is not touched, so an upgraded store keeps its head. No PostgreSQL implementation |
| 0012 `synthetic_directory` (Null Meridian) | `synthetic_directory_snapshots` (at most one row: dataset, seed, as-of, record count, content digest) and `synthetic_directory_records` (kind, id, sort key, two indexed references, a bounded JSON body). A seed writes both in the transaction of its `SYNTHETIC_SEED_LOADED` audit event, which carries the digest; `verify` recomputes the digest and requires that event. SQLite triggers refuse `UPDATE`/`DELETE` on both tables and any insert into a store not marked `SYNTHETIC`. New tables only: no existing row, digest, or audit event changes, so an upgraded store keeps its head. A fresh seed by the schema-12 build records `schema_version` 12 in `STORE_INITIALIZED`, so its head differs from a schema-11 seed's. No PostgreSQL implementation. See [../demo/null-meridian.md](../demo/null-meridian.md) |

**PostgreSQL:** 0002 through 0012 have no PostgreSQL implementation, so the runner refuses to apply them
there (fail closed). Before deploying on PostgreSQL, write the equivalent trigger
functions, `REVOKE UPDATE, DELETE` on history tables from the application role, and add
`TIMESTAMPTZ` generated or shadow columns if wanted.

## Write path and lifecycle

All writes go through `app.store.store.Store`:

- Each write and its audit event commit in one `BEGIN IMMEDIATE` transaction. A failed
  write leaves neither behind.
- `transition()` loads the candidate, replays its decisions with `verify_history`, and
  checks the request:
  - every evidence record must already be recorded (matching id, `observed_at`, and
    digest);
  - the approval must be recorded;
  - the job must be its latest recorded state.
  It then calls the domain `apply_transition`, appends the decision, and updates the
  projection under an optimistic `decision_count` check. A refusal is audited
  (`TRANSITION_REFUSED`, result `REFUSED`) and re-raised. Nothing else changes.
- Caller-supplied times (`observed_at`, transition `now`, approval and job times) may not
  run more than 5 minutes ahead of the store clock. Post-dating a request therefore
  cannot end a hold early or keep an approval alive.
- Job status is appended, never replaced. The allowed progression is PLANNED → RUNNING →
  SUCCEEDED/FAILED/REFUSED (or PLANNED → finished), and a finished job is final. The
  request fields cannot change. AAP references and failure details are short and
  redacted.
- A collector run has exactly one outcome. An incomplete outcome requires an error code
  (`TIMEOUT`, `RATE_LIMITED`, …). Observations can join a run only while it is open, and
  only if they come from the same source.

## Audit design

Every write appends one event to a single SHA-256 hash chain (`audit_events`):

| Field | Content |
| --- | --- |
| `actor_kind`, `actor_id` | Human operator or OGWA component |
| `action` | `EVIDENCE_RECORDED`, `CANDIDATE_CREATED`, `TRANSITION_APPLIED`, `TRANSITION_REFUSED`, `APPROVAL_RECORDED`, `EXECUTION_JOB_RECORDED`, `EXECUTION_JOB_STATUS_RECORDED`, `COLLECTOR_RUN_STARTED`/`FINISHED`, `STORE_INITIALIZED`, `SYNTHETIC_SEED_LOADED` |
| `subject_id` | The target (candidate, evidence record, run, store) |
| `occurred_at` | Store clock. It is clamped so the chain never runs backwards when the wall clock steps back |
| `execution_mode` | The mode the store was opened in |
| `result` | `SUCCEEDED`, `REFUSED`, or `FAILED` |
| `correlation_id` | One per operation (`req_…`), also stored on decisions, approvals, and job status events |
| `before_ref`, `after_ref` | Pointers such as `candidate:<id>@NEEDS_REVIEW#e0`, `decision:<id>`, `observation:<id>`, or `job:<id>#2:FAILED`. Never content |
| `details` | Small redacted key/value pairs, each value capped at 1,000 characters. No API responses and no credentials (values and credential-like keys are redacted) |

**Verification:** `python -m app.store verify` (`Store.verify_integrity`) re-checks:

- migration checksums;
- every audit event's stored digest against its recomputed digest;
- chain links;
- every observation digest;
- every candidate's decision history.

**Anchoring:** the chain alone cannot detect a truncated tail. `verify` prints the head
digest; record it outside the database and pass `--expected-audit-head` later. A
write-once external sink for anchors is future work.

**Limits:** someone with DDL rights can drop triggers. Tampering is then detected (the
tamper tests do exactly this) but not prevented. Prevention on a server needs database
roles (PostgreSQL `REVOKE`) and a separate migration role.

## Environment marker and the reset command

`init --environment` writes `store_metadata` once. The marker decides which modes may
open the store and which evidence it accepts:

| Marker | Modes that may open it | Evidence accepted | Resettable |
| --- | --- | --- | --- |
| `SYNTHETIC` | `LOCAL_SYNTHETIC` | `SYNTHETIC` only | Yes |
| `DEVELOPMENT` | `LOCAL_SYNTHETIC`, `READ_ONLY_PRODUCTION`, `DRY_RUN_MUTATION` | Any. In `LOCAL_SYNTHETIC` mode, only `SYNTHETIC` | Only while it holds no non-synthetic evidence |
| `PRODUCTION` | `READ_ONLY_PRODUCTION`, `DRY_RUN_MUTATION` | Non-synthetic only | Never |

`python -m app.store reset-demo --confirm-synthetic-reset` deletes the database and
re-seeds it. It refuses unless all of these hold:

- the mode is `LOCAL_SYNTHETIC`;
- the target is a SQLite file inside `<project>/var/`;
- the confirmation flag is given;
- any existing file is an OGWA store marked `SYNTHETIC` or `DEVELOPMENT`;
- the store holds no non-synthetic evidence or collector run.

It reads the existing file read-only before deleting it. A file it cannot identify
(another SQLite database, plain text) is never deleted.

## Synthetic demo datasets

`python -m app.store reset-demo --confirm-synthetic-reset [--dataset null-meridian|classic]`
seeds one of two datasets (`app/demo/datasets.py`); the CLI's default is `null-meridian`, and
the Python API (`reset_synthetic_store`, `create_seeded_store`) defaults to `classic`, which
most tests use. The API reads which dataset a store holds from its snapshot (none: classic)
to choose the demo policy and the correlation configuration; nothing switches it at runtime.

- **Null Meridian** (`app/demo/null_meridian/`, described in
  [../demo/null-meridian.md](../demo/null-meridian.md)): a fictional 1,800-person company.
  Its applications, Okta groups, assignments, usage, and every AD group are recorded as
  `SYNTHETIC` evidence from one collection a week before its "now" (2026-10-01); each Okta
  group is correlated by the engine with `config/correlation.null-meridian.json`; nine
  lifecycle candidates walk the real guards; and the directory snapshot (0012) holds the
  people, history, nesting, memberships, findings, and scenarios.
- **Classic** (below): the sixteen-scenario lifecycle harness.

The same registry serves [Demo Mode](../demo-mode.md) (`OGWA_RUNTIME_MODE=demo`), whose own
store (`var/ogwa-demo.sqlite3`) is reset only by `python -m app.runtime reset-demo` with the
dataset from `OGWA_DEMO_DATASET`; under the demo runtime the store CLI's `reset-demo`
refuses. Demo Mode accepts a store only when its marker, its single `SYNTHETIC_SEED_LOADED`
event's namespace, the dataset `dataset_of` reads from the 0012 snapshot, the snapshot's
seed and company, and integrity verification all agree. No migration was added for that:
0012 and the seed's audit event are the identity evidence.

## Classic synthetic demo world

`app/demo/synthetic_world.py` is set at the fictional company "Synthetic Widgets Ltd":

- AD domains `corp.synthetic.example` and `emea.synthetic.example`;
- every group name starts with `SYNTH-` and every application label with `SYNTH `;
- invented GUIDs and SIDs.

The demo's "now" is `AS_OF = 2026-03-02T12:00Z`. Every write goes through the `Store`
API, so the seed exercises the same guards and audit trail as real use.

| Key | Scenario | Conditions | Final state | Why |
| --- | --- | --- | --- | --- |
| S01 | Inactive app, empty unshared group | 1, 7 | `HOLD` | Approval, successful AAP dry run, unassignment observed |
| S02 | Active low-use app | 2 | `DISCOVERED` | 3 sign-ins in 90 days > threshold 0; refusal audited |
| S03 | Group shared by two apps | 3 | `DEPENDENCY_BLOCKED` | Still assigned to an active app |
| S04 | Group with AD members | 4 | `DEPENDENCY_BLOCKED` | 14 members |
| S05 | Nested AD group | 5 | `DEPENDENCY_BLOCKED` | Member of a role group (also recorded) |
| S06 | Protected group | 6 | `PROTECTED` | `adminCount`, `ProtectedFromAccidentalDeletion` |
| S07 | Exact configured mapping, no dependency checks | 7, 12 | `NEEDS_REVIEW` | Coverage `UNKNOWN` |
| S08 | Name-only mapping (not in the mapping configuration) | 8 | `NEEDS_REVIEW` | A reviewer's approval is refused |
| S09 | Ambiguous mapping (same name in two domains) | 9 | `MAPPING_AMBIGUOUS` | The engine's name search fails closed |
| S10 | Mapped AD group missing | 10 | `BLOCKED` | The configured objectGUID resolves nowhere (`NOT_FOUND`); a reviewer blocked it |
| S11 | Stale evidence (120 days) | 11 | `STALE_EVIDENCE` | Older than the 30-day review limit |
| S12 | Partial dependency coverage after the hold | 12 | `REVALIDATION_REQUIRED` | The AD quarantine approval step is refused: coverage `PARTIAL`. (Before P10B, an `AD_RETIREMENT` approval and dry-run job; stores seeded then keep those legacy rows) |
| S13 | Collector rate-limited and timed out | 13 | `DISCOVERED` | Usage `PARTIAL` (429), AD lookup `TIMEOUT`; candidacy refused |
| S14 | AAP dry-run job failure | 14 | `APPROVED` | Job `FAILED`; the dry-run transition is refused |
| S15 | Quarantined; post-quarantine hold running (P10B) | 15 | `QUARANTINE_HOLD` | A second reviewer's quarantine approval, a successful dry run, the group observed in its quarantine OU; the 30-day hold runs |
| S16 | Deletion proposed after the post-quarantine hold (P10B) | 16 | `DELETION_PROPOSED` | Quarantined, held 30 days, revalidated on fresh evidence, proposed by a third reviewer; awaits an independent deletion approval (D143) |

Identity mappings are not seeded as already-exact evidence (D75). Each is what the
correlation engine proves over the AD groups seeded so far, with
`config/correlation.synthetic.json` as the demo's source of stable identity (D81). Every
AD-imported demo Okta group except S08 and S09 also carries Okta's objectSid as unverified
source metadata (0008); it corroborates the configured pairing and never replaces it (D87).
Results: S01–S07, S11, S12, and S14–S16 resolve to
`EXACT_CONFIGURED_MAPPING` on objectGUID and objectSid; S08 is `NAME_ONLY`, S09
`AMBIGUOUS`, and S10 `NOT_FOUND`; S13 has none (its AD read timed out). Seeding stops if the
engine proves anything else.

The world is deterministic. Ids come from `seeded_id`, `deterministic_ids`, and
`mapping_id_for`, times are fixed offsets of `AS_OF`, and the store clock is `SeedClock`. Seeding twice gives
identical tables and the same audit head; `ReproducibilityTests` and the reset tests
check this.
