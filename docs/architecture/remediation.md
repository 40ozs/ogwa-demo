# Remediation: the future execution path, dry-run only

Remediation is the narrow interface through which OGWA would change Okta or Active
Directory. This build implements that interface end to end and keeps it strictly
non-destructive. **This build performs no remediation.** Production mutation stays
impossible (D8), and nothing here relaxes a guardrail.

The gates are specified in [../security/mutation-gates.md](../security/mutation-gates.md).
The invariants are R-1 to R-19, AAP-5, and W-1 to W-9 in
[../security/safety-invariants.md](../security/safety-invariants.md).

## Shape

```text
Browser ──POST /candidates/{id}/remediation-dry-runs──▶ OGWA API (app/api/remediation.py)
             one operation, one target id, the approval,     │  1 production mutation refused first (D8)
             the evidence fingerprint the operator saw       │  2 permission EXECUTION_PLAN_DRY_RUN
                                                             │  3 fresh view, 4 separation of duties (D49)
                                                             ▼
                                             gates (app/domain/remediation.py, pure)
                                                             │  every gate evaluated; any failure → BLOCKED
                                                             ▼
                                  server-side allowlist (config/remediation-allowlist.*.json)
                                                             │  which adapter; AAP template
                                                             │  (quarantine OUs: config/quarantine-ous.*.json, D136)
                                                             ▼
                        adapter (app/remediation/adapters.py), DRY_RUN_MUTATION policy: plan only
                           ├─ SYNTHETIC ──▶ SIMULATED (computed from the synthetic world's evidence)
                           └─ AAP ───────▶ VALIDATION_ONLY (launch built and validated, never sent)
                                                             │
                                                             ▼
                       audit chain: REMEDIATION_DRY_RUN_RECORDED, or GOVERNED_REQUEST_REFUSED if BLOCKED

Future, not built:  AAP job (check mode) ──▶ worker/OGWA.Remediation -WhatIf ──▶ AD / Okta (read only)
```

The demo's provider boundary (`app/runtime/providers.py`) refuses an allowlist that names any
adapter other than `SYNTHETIC`, so every demo dry run goes through the synthetic adapter. The
plan-only AAP adapter and its template classification are present and tested, but unreachable
from the demo, and the build has no AAP client.

The PowerShell worker (`worker/OGWA.Remediation`) is the AAP-side half of the future
path. In this build it runs only in tests, against its in-memory synthetic adapter.

## Operations

| Operation | What it would change | Approval stage | Candidate states | Target (one) |
| --- | --- | --- | --- | --- |
| `OKTA_GROUP_UNASSIGN` | Remove one Okta group's assignment to one application | `OKTA_UNASSIGN` | `APPROVED`, `OKTA_UNASSIGN_DRY_RUN` | `{"assignmentId": "asgn_…"}` |
| `AD_GROUP_QUARANTINE` | Move one AD group into its domain's quarantine OU | `AD_QUARANTINE` (D147) | `QUARANTINE_APPROVED`, `QUARANTINE_DRY_RUN` | `{"adGroupId": "adg_…"}` |
| `AD_GROUP_DELETE` | Delete one quarantined AD group | `AD_DELETION` (D147) | `DELETION_APPROVED`, `DELETION_DRY_RUN` | `{"adGroupId": "adg_…"}` |

### AD quarantine and AD deletion are separate stages

Decisions D128–D130 and D143–D155; the lifecycle is in
[lifecycle-state-machine.md](lifecycle-state-machine.md#the-ad-stages).

- **One approval, one AD operation.** `AD_QUARANTINE` is approved in
  `REVALIDATION_REQUIRED`, after the Okta hold; `AD_DELETION` in `DELETION_PROPOSED`, after
  the quarantine was observed, its 30-day hold ended, fresh evidence was collected, and a
  person proposed the deletion. Each authorizes its own operation only. No Okta, quarantine,
  or legacy `AD_RETIREMENT` approval ever authorizes a deletion (D146, D148).
- **Independent people (D143).** The deletion approver is not the deletion's proposer, the
  quarantine approver, or the Okta-stage approver: `VALID_APPROVAL` fails otherwise. The
  approver of any stage may not request its dry run (D49).
- **Where the group must be.** A quarantine needs the group outside its domain's quarantine
  OU; a deletion needs it inside. `LIFECYCLE_RULES` checks both against the deployment's
  quarantine OU configuration (below); without one, no AD operation passes.
- **No restore (D149).** There is no unquarantine operation, in OGWA or in the worker.
- **Nothing executes (D153).** A deletion dry run that passes every gate is `SIMULATED` (or
  `VALIDATION_ONLY` through the AAP adapter), exactly like the other operations.

A target is named only by its OGWA id. OGWA resolves its explicit identity from recorded
evidence:

- an assignment: application and group ids, internal and Okta;
- an AD group: objectGUID, domain, objectSid, distinguishedName, sAMAccountName.

The identity is digested (`identityDigest`) and recorded with every dry run. A worker request
carries the identity, and the worker re-verifies it against the object it resolves.

## Outcomes

| Outcome | Meaning | Produced by |
| --- | --- | --- |
| `SIMULATED` | The change was computed against a synthetic model. Nothing was contacted | The synthetic adapter; the worker's synthetic adapter after an agreed `ShouldProcess` |
| `WHATIF` | The worker ran under `-WhatIf`; `ShouldProcess` declined the change | The PowerShell worker |
| `VALIDATION_ONLY` | The request, the target, and the adapter's contract were validated. Nothing was simulated, launched, or sent | The AAP adapter; the worker's `-ValidateOnly` |
| `BLOCKED` | A gate or the adapter refused | Anything |

There is no outcome for a performed change. `RemediationOutcome` has exactly these four
members, and a `RemediationResult` with `executed` or `productionMutation` set cannot be
built. The worker's results state both as `false`, and OGWA refuses a worker result that
says anything else.

**Synthetic drills.** What executing would mean (submission, an unknown
outcome, verification before a retry, a safe retry, post-action verification) is defined as
its own state machine and demonstrated by the synthetic drill
(`POST /candidates/{id}/remediation-drills`), against an in-memory provider fixture that is
discarded after each answer: [remediation-execution.md](remediation-execution.md). A drill
starts from this path's gates, allowlist, and synthetic adapter; it is not a
`RemediationOutcome`, creates no job, and records nothing. It leaves the dry-run path above as it is.

## The API

### `POST /api/v1/candidates/{candidateId}/remediation-dry-runs`

```json
{"operation": "AD_GROUP_DELETE", "target": {"adGroupId": "adg_…"}, "approvalId": "apr_…",
 "expectedEvidenceFingerprint": "sha256:…", "dryRun": true, "executionMode": "DRY_RUN_MUTATION"}
```

`dryRun` and `executionMode` are optional, and these are the only values they accept.
The body is strict: any other field (`force`, `templateId`, `script`, `override…`, a list
of targets) is `422`. The target object has exactly the one field its operation names.

The checks, in order (each fails closed):

1. `executionMode: "PRODUCTION_MUTATION"` or `dryRun: false` → `403
   PRODUCTION_MUTATION_REFUSED`, before anything else in the body is read. Any other mode
   → `422`.
2. Permission `EXECUTION_PLAN_DRY_RUN` (EXECUTOR, D61). The route's static permission
   refuses anyone else with an ordinary `403` that stays in the security log (D64, D73).
3. The candidate (`404`), the policy in force, and a fresh view (`409 EVIDENCE_CHANGED`).
4. The approval must belong to the candidate (`404`). Its approver may not request the dry
   run (`403 SEPARATION_OF_DUTIES`, D49).
5. The gates, the allowlist, and the adapter. Any failure is `409 REMEDIATION_BLOCKED`.
   The error carries `outcome: "BLOCKED"`, every gate with its own problems, and the
   adapter's reason, and never a planned change. A request that fails a gate never reaches
   an adapter (D133).

`201` returns the result: outcome, adapter, target and identity digest, every gate,
`plannedChanges`, and notes. `executed` and `productionMutation` are both `false`. It also
returns the audit event id.

Recording:

- A `201` dry run is chained as `REMEDIATION_DRY_RUN_RECORDED` (migration 0010). The event
  holds the operation, outcome, adapter, target and identity digest, approval,
  fingerprint, planned changes, and the literal `executed: false`.
- Every `403` or `409` after validation is chained as `GOVERNED_REQUEST_REFUSED`, with
  `request.operation` and `request.target.<field>`.

A remediation dry run never moves the lifecycle and never creates an `ExecutionJob`. Each
stage's lifecycle dry-run step still uses `POST …/execution-jobs`: `OKTA_UNASSIGN`,
`AD_QUARANTINE`, or `AD_DELETION`. The legacy `AD_RETIREMENT` kind is refused with
`LEGACY_AD_RETIREMENT` (D148).

### `GET /api/v1/candidates/{candidateId}/remediation-dry-runs`

`READ_INVENTORY`. Lists the candidate's recorded dry runs, oldest first, each checked
against its audit digest. It also says `executionAvailable: false`.

## The server-side allowlist

```json
{"format": "ogwa-remediation-allowlist/v2", "environment": "SYNTHETIC",
 "operations": {
   "OKTA_GROUP_UNASSIGN": {"adapter": "SYNTHETIC"},
   "AD_GROUP_QUARANTINE": {"adapter": "SYNTHETIC"},
   "AD_GROUP_DELETE": {"adapter": "SYNTHETIC"}}}
```

- It is deployment configuration. No route reads it back or changes it, and a request
  cannot name an adapter, a template, an OU, a script, or a host.
- An operation that is not listed is `BLOCKED`.
- The environment must equal the store's. The `SYNTHETIC` adapter is refused in any
  other environment.
- An AAP entry pins one job template: `jobTemplateId`, `jobTemplateName`, the survey
  `requestVariable` that carries the worker request, and the reviewed playbook, project,
  and project revision.
- Quarantine OUs have their own file (D136): v2 refuses `quarantineOus`, and a v1 file,
  which named them, is refused with a pointer to the new one.

### Quarantine OUs (D136)

```json
{"format": "ogwa-quarantine-ous/v1", "environment": "SYNTHETIC",
 "quarantineOus": {"corp.synthetic.example": "OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example",
                   "emea.synthetic.example": "OU=OGWA-Quarantine,DC=emea,DC=synthetic,DC=example"}}
```

- Separate, deployment-controlled configuration: not part of the candidate policy (whose
  pinned v1 digest is unchanged) and not part of the allowlist. The server reads it at
  start-up (`app/remediation/quarantine.py`); no route edits it, so no operator can change
  it. A change is a deployment change.
- Each key is a lowercase DNS domain; each value an explicit OU distinguished name inside
  that domain. Patterns, wildcards, and anything that is not an OU are refused.
- The lifecycle reads it to recognise a confirmed quarantine: the group observed as a
  direct child of its domain's OU. The adapters read it to say where a quarantine would
  move the group. The candidate detail shows the OU and whether the group is in it,
  read-only.
- The repository holds only `config/quarantine-ous.synthetic.json`.

The repository holds only `config/remediation-allowlist.synthetic.json`, which `serve` and
the tests load. It names no AAP template, because no OGWA template exists.

## Adapters

Every adapter is a `MutationCapableService` with a `DRY_RUN_MUTATION` mutation policy. That
policy can only answer `PLAN_ONLY`, and the operation passed to `_perform` raises if it is
ever called.

- **Synthetic** (`SYNTHETIC`):
  - computes the change from the recorded synthetic evidence, for example the moved DN for
    a quarantine;
  - refuses non-synthetic evidence;
  - answers `SIMULATED`.
- **AAP** (`AAP`): answers `VALIDATION_ONLY`. Unreachable from the demo (see [Shape](#shape)).
  - Takes the allowlisted template's observed metadata, keyed by template id; a template
    with none is `BLOCKED`.
  - Requires it to classify `KNOWN_READ_ONLY` against the template's reviewed record.
  - Requires a plain-text survey variable that can carry the request.
  - Builds the check-mode launch payload with a `WhatIf` worker request and records its
    digest.
  - It holds no HTTP client, so it cannot even read AAP (D8).
  - An unobserved, mutation-capable, unknown, or drifted template is `BLOCKED`.

## AAP template classification

The classifier (`app/remediation/aap.py`) is pure: it judges template metadata against a
reviewed record and contacts nothing. The read-only AAP discovery client that would supply
the metadata is not included in this build. It fails closed:

| Class | When |
| --- | --- |
| `MUTATION_CAPABLE` | `job_type: run`, or the job type can be changed at launch |
| `UNKNOWN` | Every workflow (any node type can run, and the node graph is not evaluated). Any template whose metadata is incomplete. Any check-mode template without a reviewed record, or drifted from it: name, playbook, project, project revision, survey variables, or launch-time variables, branch, inventory, or credentials |
| `KNOWN_READ_ONLY` | A check-mode job template with a fixed job type that matches its reviewed record field for field |

Check mode alone is never proof, because a task can opt out with `check_mode: false`. Only a
human review of the pinned playbook revision makes a template known read-only. `UNKNOWN` is
treated exactly like `MUTATION_CAPABLE`. **Nothing is ever launched.** `relevance` terms
(`ogwa`, `okta`, `ad group`, `quarantine`, …) only help a person find candidate templates.

## The PowerShell worker (`worker/OGWA.Remediation`)

| Command | Purpose |
| --- | --- |
| `Remove-OgwaOktaGroupAssignment -OktaAppId -OktaGroupId` | One assignment |
| `Move-OgwaADGroupToQuarantine -ObjectGuid -Domain -ExpectedSid -ExpectedDistinguishedName -QuarantineOu` | One group |
| `Remove-OgwaADGroup -ObjectGuid -Domain -ExpectedSid -ExpectedDistinguishedName` | One group |
| `Invoke-OgwaRemediation -RequestJson` | The JSON boundary: `ogwa.remediation.request/v1` in, `ogwa.remediation.result/v1` out |
| `New-OgwaSyntheticRemediationAdapter` | The only adapter: an in-memory synthetic world |

- **ShouldProcess.** Each state-changing command declares `SupportsShouldProcess`,
  `ConfirmImpact = 'High'`, and has the usual `-WhatIf` and `-Confirm`, plus
  `-ValidateOnly`. It takes no credential, no force switch, and no script.
- **Checks before `ShouldProcess`:**
  - the explicit target is validated: no patterns (`* ? % [ ]`), lowercase GUIDs, a DN
    inside the domain;
  - the adapter must be the module's own synthetic adapter (private token);
  - the target must be synthetic;
  - the group must resolve to exactly one object by objectGUID;
  - its objectSid and DN must match what OGWA approved (`TARGET_IDENTITY_CHANGED`);
  - protection blocks: adminCount, deletion protection, a critical system object, or a
    well-known SID; unknown protection also blocks;
  - members and parent groups block.
- **Outcomes.** `-ValidateOnly` gives `ValidationOnly`. `-WhatIf` gives `WhatIf`. An agreed
  confirmation changes the synthetic in-memory world only (`Simulated`). A declined one is
  `Blocked`. With any other adapter, every command is `Blocked` (`NO_PRODUCTION_ADAPTER`).
- **The JSON boundary.** It accepts only the modes `WhatIf` and `ValidateOnly`, and always
  passes `-WhatIf` too, so a request document can never cause a change.
- **The contract.** `contract.json` is shared with `app/remediation/worker.py`.
- **Tests.** `tests/powershell/Test-OgwaRemediation.ps1` runs on PowerShell 7 and 5.1. It
  writes golden request/result pairs to `tests/fixtures/remediation/`, which the Python
  tests parse.

Design rules the worker's commands keep:

- dry run by default;
- `ConfirmImpact = 'High'`;
- a built-in protected list (here, well-known SIDs and RIDs, which hold in any language);
- per-target structured results.

## What a future executing build would need (not authorized)

None of this is in this build, and nothing here makes it easier to switch on by accident:

1. A recorded decision authorizing production mutation, and a reviewed change of
   `BUILD_ALLOWS_PRODUCTION_MUTATION`.
2. The production quarantine OU configuration for each governed domain (D136), reviewed
   and deployed like any other configuration. (The AD deletion stage itself is modelled
   in `LOCAL_SYNTHETIC` only.)
3. The Okta, AD, and AAP clients this build does not include, and a reviewed production
   adapter for each operation:
   - in the worker, AD calls behind the same checks;
   - in OGWA, one reviewed module that launches AAP jobs.
4. Separate credentials:
   - a read-only AAP identity for discovery;
   - a launch-only identity for the reviewed remediation templates;
   - per-operation rollback (re-adding an assignment; moving a group back out of
     quarantine), which would need its own decision: there is no restore operation
     (D149).
5. An executed-outcome vocabulary, a migration, and tests that keep every gate in this
   document in front of it.

## Tests

| File | Covers |
| --- | --- |
| `tests/test_remediation_gates.py` | Each gate failing alone, at the domain level; the outcome vocabulary; result invariants |
| `tests/test_remediation_api.py` | Five safety properties end to end, and the anti-footgun controls |
| `tests/test_remediation_adapters.py` | The allowlist, both adapters (the AAP adapter over hand-built template metadata), and the worker contract against the golden fixtures |
| `tests/test_remediation_worker_safety.py` | Static checks of the worker (no cmdlets, no dynamic code, ShouldProcess order) |
| `tests/test_remediation_migration.py` | Migration 0010: rows, digests, guards, and the anchored head survive |
| `tests/test_post_p10_decisions.py` | D128–D133 at the API: the quarantine approval never authorizes deletion, the legacy stage refused, membership evidence, blocked requests never planned |
| `tests/test_lifecycle_ad_stages.py` | The AD stages in the lifecycle: every AD-stage guard, D143–D146, re-entry (D144, D145), the legacy stage (D148), and history checks |
| `tests/test_p10b_ad_stages_api.py` | The AD stages at the API: one candidate through quarantine, hold, proposal, independent approval, and deletion dry run; the quarantine OUs read-only |
| `tests/test_ad_stages_migration.py` | Migration 0011 on a store with legacy rows: every row, the anchored head, the guards, and the legacy triggers |
| `tests/powershell/Test-OgwaRemediation.ps1` | The worker's behaviour on PowerShell 7 and 5.1 |
| `tests/test_remediation_execution.py`, `tests/test_remediation_drill_api.py` | The execution state machine, the synthetic provider fixture, and the drill ([remediation-execution.md](remediation-execution.md)) |
