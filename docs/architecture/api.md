# Operator API

Status: P08, with the owner decisions after P08 (D58–D70) applied; P09 added three read-only
listings for the UI. The API runs **only in
`LOCAL_SYNTHETIC` mode over a SYNTHETIC store, with synthetic sign-in** (D50, D51). It is
the contract the UI will build on (D58). Authorization is described in
[../security/authorization.md](../security/authorization.md).

## Shape

```text
Browser ──(session cookie + CSRF header, JSON only)──▶ app/api (WSGI)
                                                         ├─ app/store        (read; audited writes)
                                                         ├─ app/domain       (lifecycle guards, approvals)
                                                         ├─ app/classification (read-only explanation)
                                                         └─ app/correlation  (mapping review, via a gateway)
```

- **Standard library only** (D4, D5). The application is a plain WSGI callable, so it can
  be tested in process and later hosted by any reviewed WSGI server.
- **No outbound calls.** `app/api` imports no HTTP client, no integration package, and no
  mutating client (`test_api_imports_no_network_mutation_or_integration_module`). Mapping
  review reaches an AD identity directory only through a gateway. In `LOCAL_SYNTHETIC` that
  is the synthetic directory over the store's own recorded AD evidence
  (`app/demo/synthetic_directory.py`, D68), which refuses any other mode or store. There is
  no production AD adapter.
- **Execution is dry-run planning only.** There is no executor. See
  [Mutation routes](#mutation-routes).

| Module | Responsibility |
| --- | --- |
| `app/api/app.py` | WSGI application: routing, request ids, authentication, Origin/CSRF checks, static permission check, structured errors |
| `app/api/routes.py` | The route table (`ROUTES`) and handlers |
| `app/api/services.py` | Transitions, approvals, dry-run planning, mapping reviews; separation of duties and evidence rules |
| `app/api/readmodel.py` | Bounded read-only queries (SELECT only) and JSON serializers |
| `app/api/authz.py` | Roles, permissions, role bindings, `Principal` |
| `app/api/identity.py` | Identity adapter boundary and the synthetic adapter |
| `app/api/sessions.py` | Server-side sessions and CSRF tokens |
| `app/api/http.py`, `validation.py`, `errors.py` | Strict JSON bodies and queries, pagination, error format, security headers |
| `app/api/local.py`, `__main__.py` | Local factory and the loopback-only `serve` command |
| `config/synthetic-idp.json`, `config/role-bindings.synthetic.json` | Synthetic principals and their role bindings |

## Running locally

```powershell
python -m app.store status             # the store must be SYNTHETIC and at the build's schema
python -m app.api serve --demo-clock   # http://127.0.0.1:8765, synthetic sign-in only
```

- `serve` also serves the operator UI (P09) on the same origin; see [ui.md](ui.md).
- `serve` binds `127.0.0.1` only; there is no host option. It refuses any mode other than
  `LOCAL_SYNTHETIC` and any store not marked SYNTHETIC.
- `--demo-clock` starts the API clock just after the store's newest audit event and lets it
  run in real time, so the demo world's evidence is fresh enough to work with.
- The server is `wsgiref`: single-threaded, plain HTTP, for local development only.
- Sessions are kept in memory, so restarting the server signs everyone out.

## Conventions

| Topic | Rule |
| --- | --- |
| Base path | `/api/v1`. Only `GET` and `POST` exist. |
| Media type | Request and response bodies are `application/json; charset=utf-8`. Any other request type gets `415`. |
| Bodies | At most 64 KiB, and a JSON **object**. Duplicate keys, `NaN`/`Infinity`, and **unknown fields** are refused (`400`/`422`), never ignored. |
| Queries | Each route lists its parameters. An unknown or repeated parameter gets `400`. |
| Ids | Internal ids only (`cand_…`, `ogrp_…`, `apr_…`, `job_…`). A malformed id in a path is `404`. |
| Times | ISO 8601 with offset (UTC). |
| Request id | Every response carries `X-Request-Id: req_<32 hex>`. Every audit event a request writes has it as its `correlationId`. |
| Security headers | `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`. |
| CORS | None. No `Access-Control-*` header is ever sent. |
| Policy notice | While the unrecorded synthetic demo policy is in force, **every** response body (errors included) carries `"policyNotice": "DEMO POLICY — UNRECORDED"` and the header `X-OGWA-Policy-Status: DEMO-UNRECORDED` (D66). Every policy view (`policy` objects) carries `label`, `recorded`, and `approvalMaxValidHours`
(the policy's longest approval validity in whole hours; the UI takes its limit from here, and
the server enforces the policy's own value). A UI must show the label wherever it shows a classification, an evidence judgement, or a lifecycle action. Once a policy version is recorded, the notice disappears and `label` reads `RECORDED POLICY VERSION n`. |

### Pagination

List endpoints accept `limit` (1–200, default 50) and `cursor`, and return:

```json
{"items": [...], "page": {"limit": 50, "nextCursor": "bzo1MA", "previousCursor": null, "offset": 0, "total": 298}}
```

`nextCursor` is opaque and is `null` on the last page. A cursor that the server did not
issue gets `400`, as does any page beyond 100,000 records. `previousCursor`, `offset`, and
`total` (the listing's row count after its filters) were added by OGWA-UI-IA-01; they are
additive, and a client that reads only `items` and `nextCursor` is unaffected.

**Sorting (OGWA-UI-IA-01).** Listings accept `sort=<field>&order=asc|desc`. Without `sort` a
listing keeps its own order. The sort is stable (ties keep the listing's order) and a missing
value sorts last in both directions. An unknown field or order is `400`. Fields:

| Listing | `sort` fields |
| --- | --- |
| `/people` | `displayName`, `employeeNumber`, `email`, `department`, `title`, `hireDate`, `status`, `terminationDate` |
| `/directory-groups` | `name`, `source`, `kind`, `era` (chronological), `createdAt`, `status`, `effectiveMembers`, `nestingDepth`, `health` (by seriousness) |
| `/governance-findings` | `severity` (by seriousness), `code`, `subjectName`, `subjectKind` |
| `/applications` | `label`, `status`, `signOnMode`, `observedAt`, `result` |
| `/groups` | `name`, `groupType`, `directoryQualifiedName`, `observedAt`, `result` |
| `/mappings` | `oktaGroup`, `adGroup` (by resolved name), `confidence` (strongest first), `observedAt`, `result` |
| `/dependency-findings` | `dependencyKind`, `subject` (by resolved name), `findings` (blocking, then all), `observedAt`, `result` |
| `/candidates` | `oktaGroup`, `state`, `holdUntil`, `createdAt`, `updatedAt` |
| `/review-queue` | `oktaGroup`, `updatedAt` (time waiting), `deadline` (a hold's end); without `sort`, review priority (below) |
| `/approvals` | `stage`, `decision`, `decidedAt`, `expiresAt`, `candidate` (also under a `usability=` filter; ties keep the listing's order: newest decision, then id) |
| `/execution-jobs` | `kind`, `status`, `requestedAt`, `candidate` |
| `/collector-runs` | `collector`, `startedAt`, `outcome`, `records` |
| `/audit-events` | `sequence` only: the chain is served in chain order, either way round |

**Filter, sort, then page, in one query (OGWA-UI-IA-02).** A store-backed listing (applications,
groups, mappings, dependency findings, candidates, approvals, execution jobs, collector runs)
filters, sorts, and pages in a single `SELECT … ORDER BY … LIMIT/OFFSET` (`ReadModel.page_ids`,
`PAGED` in `app/api/readmodel.py`), then loads only that page's records through the
digest-verifying loaders. Ties keep the listing's own order, which ends in the stable id, so a
page is deterministic and never ordered by a name alone. A column of ids sorts by the name it
resolves to, as `GET /identities` gives it; an AD group's name comes from the directory
snapshot, else its latest sAMAccountName. Text compares case-insensitively for ASCII letters
(SQLite's `NOCASE`). The response is unchanged.

The directory snapshot's listings (`/people`, `/directory-groups`, `/governance-findings`) are
served from the snapshot held in memory (loaded once per process): they filter, sort, and page
in memory, and shape only the page they return.

### Errors

```json
{"error": {"code": "SEPARATION_OF_DUTIES", "message": "Four-eyes rule: someone else must approve this (D49).",
           "requestId": "req_…", "problems": ["you submitted this candidate for OKTA_UNASSIGN approval"],
           "auditEventId": "aud_…"},
 "policyNotice": "DEMO POLICY — UNRECORDED"}
```

`auditEventId` is present when the refusal was recorded in the audit chain as
`GOVERNED_REQUEST_REFUSED` (see [Write endpoints](#write-endpoints)).

`code` is stable. `message` and `problems` are written for operators and pass through
redaction. A response never contains exception text, stack traces, file paths, or
credentials. Unexpected failures are logged server-side (redacted) and answered with
`INTERNAL_ERROR`; integrity failures are answered with `INTEGRITY_FAILURE`. Quote the
request id when reporting either.

| Status | Codes |
| --- | --- |
| 400 | `MALFORMED_REQUEST` |
| 401 | `UNAUTHENTICATED`, `AUTHENTICATION_FAILED`, `UNSUPPORTED_AUTHENTICATION` (an `Authorization` header was sent) |
| 403 | `FORBIDDEN`, `CSRF_FAILED`, `ORIGIN_REFUSED`, `SEPARATION_OF_DUTIES`, `NOT_AN_OPERATOR_ACTION`, `PRODUCTION_MUTATION_REFUSED`, `EXECUTION_MODE_NOT_AUTHORIZED` |
| 404 | `NOT_FOUND` |
| 405 | `METHOD_NOT_ALLOWED` (with `Allow`) |
| 409 | `EVIDENCE_CHANGED`, `EVIDENCE_RULES_NOT_MET`, `INVALID_STATE`, `APPROVAL_INVALID`, `TRANSITION_REFUSED`, `TRANSITION_NOT_PERMITTED`, `REVIEW_REFUSED`, `POLICY_NOT_RECORDED`, `LEGACY_AD_RETIREMENT`, `REMEDIATION_BLOCKED`, `APPROVAL_POLICY_NOT_IN_FORCE` (OGWA-DEMO-04), `CONFLICT` |
| 411, 413, 415 | `LENGTH_REQUIRED`, `PAYLOAD_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE` |
| 422 | `VALIDATION_FAILED` |
| 500 | `INTERNAL_ERROR`, `INTEGRITY_FAILURE` |
| 503 | `MAPPING_REVIEW_UNAVAILABLE` |

## Session

| Method and path | Access | Purpose |
| --- | --- | --- |
| `GET /health` | public | `{"status": "ok"}`. Under Demo Mode it also names the runtime and the dataset: `runtimeMode`, `dataSource`, `organization`, `dataset` (selector, company, domain, snapshot date, seed namespace), `liveIntegrations: false` ([../demo-mode.md](../demo-mode.md)) |
| `POST /session` | public | Synthetic sign-in: `{"subject": "synthetic.securityiam.one"}`. Sets the session cookie and returns the principal and `csrfToken` |
| `GET /session` | session | The principal (subject, roles, permissions) and the CSRF token |
| `POST /session/logout` | session | Ends the session and expires the cookie |

Every other `POST` needs the session's token in the `X-OGWA-CSRF` header.

## Read endpoints

All need `READ_INVENTORY` unless stated otherwise. Paged endpoints are marked *(paged)*.

| Method and path | Returns |
| --- | --- |
| `GET /dashboard` | Candidate counts by state, how many await each approval stage, collector run summary, evidence counts, the policy in force, the safety posture (`executionMode`, `productionMutationPermittedByBuild: false`, `executionRoutes: DRY_RUN_PLANNING_ONLY`), and the store's audit head, and (OGWA-UI-IA-01) a dependency findings summary: checks, checks with findings, findings, and blocking findings |
| `GET /applications` *(paged)*, `GET /applications/{applicationId}` | Okta applications (latest observation, provenance, digest); the detail view adds assignments |
| `GET /groups` *(paged)*, `GET /groups/{groupId}` | Okta groups; the detail view adds assignments, the identity mapping, the mapped AD group, and candidate ids |
| `GET /mappings` *(paged)*, `GET /mappings/{groupId}` | Identity-mapping evidence; the detail view adds the AD group or ambiguous candidates and the review registry (`currentApprovalId`, `pendingSelectionId`) |
| `GET /candidates` *(paged; `state=`)* | The candidate queue, oldest first, each loaded with history verification |
| `GET /review-queue` *(paged, 1–50 rows, default 25; `status=`)* | OGWA-REVIEW-QUEUE-API-01: the Review queue, filtered, ordered, counted, and paged on the server, each row with its review status and the current evidence verdict. See [Review queue](#review-queue-ogwa-review-queue-api-01) |
| `GET /candidates/{candidateId}` | The candidate (since P10B also `quarantineApprover`, `quarantineHoldUntil`, `deletionProposer`, `deletionProposedAt`), its `evidenceFingerprint`, its classification (`isApproval: false`), `quarantine` (the mapped AD group's domain, that domain's quarantine OU from deployment configuration, and whether the group is in it; read-only, D136), `allowedActions` for the signed-in principal, and (OGWA-DEMO-01) `evidenceAssessment`: each source's evidence state, conflicts, the identity mapping's state, the next approval step with the lifecycle guard's answer, the decision OGWA can safely make, and the evidence still needed (`isApproval: false`, `autoRemediationEligible: false`; see [evidence-assessment.md](evidence-assessment.md)). Since OGWA-DEMO-02 the assessment names the `policy` that produced its decision, and `decisionExplanation` explains it under that exact version: the policy, each condition as that version states it with its status and the evidence it read, whether evidence forced manual review, and what would change ([evidence-assessment.md](evidence-assessment.md#decision-explanation-ogwa-demo-02)) |
| `GET /candidates/{candidateId}/evidence` | The full evidence bundle with provenance and digests |
| `GET /candidates/{candidateId}/dependencies` | Dependency findings (with `FindingCode`, blocking flag) and the per-kind coverage report |
| `GET /candidates/{candidateId}/decisions` | Lifecycle decisions, oldest first; each with the `policy` it recorded (OGWA-DEMO-02: `policyId`, `version`, `name`, digests, recorded version, and `publishedRelease`), or `null` if it recorded none. Never the policy in force now. Approvals (per candidate and the `/approvals` listing) carry their `policy` the same way |
| `GET /candidates/{candidateId}/approvals` | Approvals and rejections, with `expired` and (OGWA-REVIEW-QUEUE-API-01) `usability`: see [Approval usability](#approval-usability-ogwa-review-queue-api-01) |
| `GET /candidates/{candidateId}/execution-jobs`, `GET /execution-jobs/{jobId}` | Jobs with their full status history |
| `GET /execution-jobs` *(paged)* | P09. Every job, newest first, with its status history, and `executionAvailable: false` |
| `GET /candidates/{candidateId}/remediation-dry-runs` | P10. The candidate's recorded remediation dry runs, oldest first, each checked against its audit digest: operation, outcome, adapter, target and identity digest, approval, fingerprint, `executed: false`; since OGWA-DEMO-04 also `policy` (the reference its event recorded, as recorded; `null` for a record made before) and `chain` (policy, decision, approval, operation id); plus `executionAvailable: false` |
| `GET /remediation-drill-scenarios` | OGWA-DEMO-03. The synthetic drill's closed fault-scenario catalog (key, title, description, scripted submissions, expected final state), its modes, every execution state's label, `maxSubmissions` (2), `maxVerificationReads` (2), and the drill notice |
| `GET /approvals` *(paged; `usability=`)* | P09. Every approval and rejection, newest first, with `expired` and (OGWA-REVIEW-QUEUE-API-01) `usability`; since OGWA-APPROVAL-ATTENTION-01 filtered by `usability` (`all`, `valid`, `expiring-soon`, `expired`) with `counts` over every approval: see [Approvals that need attention](#approvals-that-need-attention-ogwa-approval-attention-01) |
| `GET /dependency-findings` *(paged)* | P09. Every dependency check (latest observation) with its findings and provenance |
| `GET /collector-runs` *(paged)* | Collector runs, newest first, with outcome and error code; plus a summary |
| `GET /policy` | The policy in force (`RECORDED_VERSION`, or in a SYNTHETIC store only `UNRECORDED_SYNTHETIC_DEMO` with `label: "DEMO POLICY — UNRECORDED"`) and recorded versions. Since OGWA-DEMO-02 the policy in force carries `versionSequence`, `policyId`, `version`, `name`, and `release` (null when no release carries its rules); each version its `release`; and a SYNTHETIC store's demo dataset lists its synthetic `releases` (identity, purpose, and the full document). `editableViaApi: false` |
| `GET /audit-events` *(paged; `subjectId=`)* | **`READ_AUDIT`.** The audit chain, newest first, each event verified against its digest |
| `GET /candidates/{candidateId}/audit-events` *(paged)* | **`READ_AUDIT`.** One candidate's audit events |
| `GET /system/role-bindings` | **`READ_SYSTEM`.** The bindings in force, read-only (`editable: false`) |
| `GET /system/integrity` | **`READ_SYSTEM`.** Re-verifies migrations, the audit chain, every evidence digest, and every candidate history. A read-only store (the hosted demo's image) reports its last full verification while its audit head and contents are unchanged (`Store.verified_integrity`) |
| `GET /directory` | The synthetic directory snapshot (0012), if the store holds one: company profile, counts, departments, the application estate with health, and (OGWA-UI-IA-01) `deactivations`: per year, and in the 90 days to the snapshot date. `available: false` in a store without one (the classic world) |
| `GET /people` *(paged; `department=`, `status=ACTIVE\|TERMINATED`, `q=`)*, `GET /people/{personId}` | Synthetic people; the detail view adds manager, direct reports, employment and account history, direct groups, and every application the person reaches with each route (assigned group › nested groups › a group they are a direct member of, or an individual assignment) |
| `GET /directory-groups` *(paged; `era=`, `health=`, `source=`, `q=`: any name the group goes by, or exactly its OGWA id, AD evidence id, objectSid, objectGUID, or Okta group id)*, `GET /directory-groups/{directoryGroupId}` | Every AD and Okta group in the snapshot with era, naming style, dates, health, effective members, and nesting depth; the detail view adds owner, parents, children, lineage (replaced by / replaces / push target), assignments, direct members (first 200), findings, and an example membership path |
| `GET /governance-findings` *(paged; `severity=`, `code=`, `subjectKind=`)* | Governance findings (`app/governance/analysis.py`), most serious first, plus counts by severity and rule. Evidence for review; none authorizes a change |
| `GET /demo-scenarios` | The dataset's portfolio scenarios with their groups, applications, and lifecycle candidate; and `walkthrough` (OGWA-DEMO-04): the dataset's guided reviewer walkthrough (title, disclosures, two parts with their steps and resolved `candidateId`), or `null` for a dataset without one |
| `GET /identities?ids=a,b,…` | OGWA-UI-IA-01 (`app/api/resolve.py`): for up to 50 OGWA ids or AD domain objectSids, each one's kind, common name, canonical page (`route`, `routeId`), and a `qualifier` (an AD distinguished name or an Okta group id) with `ambiguous` (whether the snapshot has another group of that name; `null` when unknown). An Okta group with an exact mapping adds `mappedAdGroup`. An id that names nothing comes back `resolved: false`. Lookups go by stable id only: a name is never accepted (`400`), and a renamed group resolves to its new name under the same id |

`GET /directory-groups/{directoryGroupId}` adds `lifecycleCandidates` (OGWA-REVIEW-QUEUE-API-01): see
[Directory group → candidate](#directory-group--candidate-ogwa-review-queue-api-01).

`GET /applications/{applicationId}` adds `profile` (the snapshot's view of the application:
category, provisioning, owner, every group and individual assignment, findings) and
`GET /groups/{groupId}` adds `directory` (a link to the snapshot's group), both `null` without
a snapshot. These routes only read the snapshot (`app/api/directory.py`: SELECT only, a test
pins it); no route writes it.

`allowedActions` is a hint for the UI, not an authorization. The server checks everything
again when the action is requested.

```json
{"transitions": [{"target": "APPROVED", "category": "forward", "operatorAction": true,
                  "permission": "APPROVAL_DECIDE", "permitted": true, "requiresEvidenceFingerprint": true}],
 "approvals": [{"stage": "OKTA_UNASSIGN", "permitted": false,
                "separationOfDutiesConflicts": ["you submitted this candidate for OKTA_UNASSIGN approval"]}],
 "planDryRun": false}
```

## Review queue (OGWA-REVIEW-QUEUE-API-01)

`GET /review-queue` replaces the browser's old way of building the queue (reading up to 1,000
candidates through `GET /candidates` and sorting them itself). `GET /candidates` is unchanged.

**Query.** `status` = `open` (the default: needs review, blocked, waiting, in progress),
`needs-review`, `blocked`, `waiting`, `in-progress`, `retired`, `closed`, or `all`; `limit` 1–50
(default **25**: a row costs one classification, and the hosted Worker has a per-request CPU
limit); `cursor`; `sort` and `order` (above). Anything else is `400`. Filtering happens in the same
SQL statement as ordering and paging (`ReadModel.review_queue`, `PAGED["queue"]`), so filters
apply before paging and a page loads only its own candidates.

**Review status.** `readmodel.REVIEW_STATUS` groups lifecycle states exactly as the UI's
`review.js` (`tests/test_review_queue_api.py` pins the two tables together): needs review
(`NEEDS_REVIEW`, `REVALIDATION_REQUIRED`, `DELETION_REVALIDATION_REQUIRED`, `DELETION_PROPOSED`),
blocked (`BLOCKED`, `MAPPING_AMBIGUOUS`, `DEPENDENCY_BLOCKED`, `STALE_EVIDENCE`,
`EVIDENCE_INCOMPLETE`, `RETIREMENT_DRY_RUN`), waiting (`DISCOVERED`, `CANDIDATE`, `HOLD`,
`QUARANTINE_HOLD`), in progress (the six approved and dry-run states), retired (`RETIRED`), closed
(`EXCLUDED`, `REJECTED`, `PROTECTED`). A state the build does not know reads as **blocked**, in
the filter (`status=blocked` is "every state not grouped otherwise") and in the order. There is no
"ready" status.

**Order.** Without `sort`: review status (needs review, blocked, waiting, in progress, retired,
closed), then the nearest hold end (`holdUntil` in `HOLD`, `quarantineHoldUntil` in
`QUARANTINE_HOLD`; rows without one after), then the oldest last change (`updatedAt`), then the
stable candidate id. This is `review.js queueOrder`, which the tests run under Node over the served
rows. With `sort`, the field first and that order breaks ties. Ties never fall to a name.

**Response.** The standard envelope (`items`, `page` with `total` = the filtered count), plus
`status`, `counts` (per review status, `open`, and `all`, from one `GROUP BY` over **every**
candidate, never from the page), `holdsEndingWithin7Days` (holds that ended or end within 7 days of
`generatedAt`, counted in SQL over every candidate), `generatedAt` (the server's clock), and
`note`. Each item is `candidate_json` (as `GET /candidates`: ids, `state`, `epoch`, timestamps,
holds, approvers, `blockedFrom`, `reasonCodes`) plus:

| Field | Meaning |
| --- | --- |
| `reviewStatus` | The review status of the recorded state (above) |
| `evidenceVerdict.classification` | The classifier's current classification of the evidence, or `null` when it cannot run (no policy in force, or no assignment evidence) |
| `evidenceVerdict.suggestedState` | The lifecycle state the classifier would divert the candidate to now (`lifecycleDiversion`), or `null` |
| `evidenceVerdict.decision` | The evidence assessment's decision (`code`, `label`, `eligibleForHumanApproval`): what OGWA can safely conclude now. Never an approval |
| `evidenceVerdict.agreement` | `AGREES`, `DIFFERS` (the classifier would park the candidate elsewhere, or no longer finds the evidence condition its state records), `NOT_APPLICABLE` (terminal state), or `UNAVAILABLE` (no classification) |
| `evidenceVerdict.blockingReasons` | The classifier's blocking reason codes, distinct, in order |
| `evidenceVerdict.assessedAt`, `isApproval: false`, `autoRemediationEligible: false` | As on the candidate page |

The verdict is computed exactly as `GET /candidates/{id}` computes `classification` and
`evidenceAssessment` (`LifecycleService.classify_and_assess`); a test checks every row against the
candidate page. It is **informational**: it is never written back to the lifecycle, a `DIFFERS`
row keeps its recorded state until the lifecycle records a transition, and it authorizes nothing.
The forensic detail (reasons' text, evidence items, explanation) stays on the candidate page.

**Not offered, on purpose.** Filtering or sorting by the evidence verdict: the verdict is computed
per row, after paging, so a filter on it could not be applied before paging without classifying
every candidate on each request; the UI does not filter by it. Lifecycle state filtering stays on
`GET /candidates?state=` (the UI's "Every candidate by lifecycle state").

## Approval usability (OGWA-REVIEW-QUEUE-API-01)

`GET /approvals` and `GET /candidates/{id}/approvals` carry `usability: {status, usable,
problems}` on every row: whether the approval **passes the lifecycle's approval rules now**. It is
computed by `app/api/review_queue.py` `ApprovalUsability` with the rules the server itself
applies, not a second algorithm: `LifecycleService.stage_approval_problems` (the call a dry run's
planning makes: `stage_approval_rules` + `approval_problems`, with the candidate's **current**
evidence fingerprint and the policy in force), whether the candidate is in a state where that
stage's approval is used (`APPROVED`/`OKTA_UNASSIGN_DRY_RUN`, `QUARANTINE_APPROVED`/`QUARANTINE_DRY_RUN`,
`DELETION_APPROVED`/`DELETION_DRY_RUN`), and the remediation's policy binding
(`authorization.binding`). `problems` are the rules' own words; `usable` is `true` only when there
are none. `status` is the most telling one:

| `status` | When |
| --- | --- |
| `USABLE` | No rule fails. **Not "ready"**: the step it backs has its own guards (a dry run needs evidence under 24 hours old), which the server applies when it is requested |
| `EXPIRED` | Past `expiresAt` on the server's clock |
| `EPOCH_SUPERSEDED` | The candidate was blocked and re-entered review since (a new epoch) |
| `STAGE_NOT_CURRENT` | The candidate is not, or no longer, where this stage's approval is used |
| `POLICY_NOT_IN_FORCE` | Judged by a policy other than the version in force (remediation dry runs and drills refuse it) |
| `EVIDENCE_CHANGED` | The material evidence's fingerprint changed since the approval |
| `NO_POLICY` | No candidate policy is in force (D52) |
| `NOT_AN_APPROVAL`, `LEGACY` | A rejection; a legacy `AD_RETIREMENT` approval (D148) |
| `NOT_USABLE` | Any other rule (an excluded approver, a hold not yet ended, …) |

Usability is a reading: it changes nothing and authorizes nothing (tests: a usable approval is
still refused to a person without the planning permission; an expired one draws the planner's own
`APPROVAL_INVALID … expired`). The evidence fingerprint is read only for approvals that pass every
other rule, so the listing stays cheap.

## Approvals that need attention (OGWA-APPROVAL-ATTENTION-01)

`usability.expiringSoon` (on both approval listings) is `true` only for a `USABLE` approval whose
`expiresAt` is no later than **48 hours** after the server's clock (`EXPIRING_SOON_WITHIN` in
`app/api/review_queue.py`). The 48 hours are a **presentation threshold**, not an approval rule:
they change no approval's validity, and an expiring approval stays `USABLE` until its own expiry.
They are not the holds' 7 days on purpose: an approval is valid for at most the policy's
`approvalMaxTtlHours` (168 by default), so a 7-day window would mark every approval "expiring soon"
from the moment it was given. Like `USABLE`, `expiringSoon` says nothing about the step the
approval backs, which has its own checks (a dry run needs evidence under 24 hours old).

`GET /approvals` takes `usability`:

| `usability` | Rows | How |
| --- | --- | --- |
| `all` (default) | Every approval and rejection | SQL, paged as before |
| `valid` | Approvals the server judges `USABLE` | The server's own `ApprovalUsability` over every **unexpired** approval, then paged |
| `expiring-soon` | `USABLE` and `expiringSoon` | As `valid` |
| `expired` | Approvals (not rejections) past `expiresAt`: the server's own `expired` fact | SQL, paged |

Only an unexpired approval can be `USABLE`, and none is given for longer than 14 days
(`MAX_APPROVAL_HOURS`), so `valid` and `expiring-soon` judge a bounded set — the approvals of the
last two weeks at most — before paging, never one page. The response adds `usability` (the filter),
`counts` (`all`, `valid`, `expiringSoon`, `expired`: over every approval, whatever the filter or
page), `expiringSoonWithinHours` (48), `generatedAt` (the server's clock), and `note`. An unknown
`usability` is `400 MALFORMED_REQUEST`. `sort`/`order` apply under every filter; ties fall to the
listing's order (newest decision, then id), so pages never repeat or skip a row.

**Not offered, on purpose.** Filtering by `EPOCH_SUPERSEDED` or the other reasons an approval does
not count, and sorting by usability: telling them apart needs every approval ever recorded judged on
each request (the status is a headline over several rules, `EXPIRED` first). Each row names its
status, so they stay visible in every listing.

## Directory group → candidate (OGWA-REVIEW-QUEUE-API-01)

`GET /directory-groups/{id}` adds `lifecycleCandidates`: `[{candidateId, oktaGroupId, state,
reviewStatus, holdUntil, quarantineHoldUntil, relationship, mappingId, mappingConfidence}]`.

- An **AD** group's candidates come only through an **exact identity mapping** to its OGWA AD
  evidence id (`adEvidenceId`): the latest observation of each identity mapping whose
  `ad_group_id` is that id, re-read through the digest-verifying loader, kept only if `isExact`;
  then that mapping's Okta group's candidates (`relationship: EXACT_IDENTITY_MAPPING`, with the
  mapping's id and confidence). The snapshot's own Okta link (`oktaEvidenceId` on an AD group) is
  **not** a mapping and is not used: in both demo datasets `KB-Admins` (an unverified identifier)
  and `WikiV1-Users` (name only) have a snapshot link to an Okta group with a candidate, and their
  AD pages list none.
- An **Okta** directory group is the candidates' own subject: its `oktaEvidenceId`'s candidates
  (`relationship: OKTA_GROUP`).
- Nothing is matched by name. Groups that share a name (`Finance-RW`: two AD groups and an Okta
  group) never share candidates; the tests check every link against `GET /mappings/{oktaGroupId}`.

## Write endpoints

Every write goes through the store in its audited transaction. Refusals are recorded as
follows (D64, D65):

| Refusal | Where it is recorded |
| --- | --- |
| A lifecycle transition refused by its guard (`TRANSITION_REFUSED`) | Audit chain, `TRANSITION_REFUSED`, by the store |
| Any other 403 or 409 on a **governed route**, after authentication, CSRF, the route's static permission, and body validation passed: for example `SEPARATION_OF_DUTIES`, `EVIDENCE_RULES_NOT_MET`, `EVIDENCE_CHANGED`, `INVALID_STATE`, `APPROVAL_INVALID`, `PRODUCTION_MUTATION_REFUSED`, a per-transition `FORBIDDEN`, `NOT_AN_OPERATOR_ACTION`, `REVIEW_REFUSED` | Audit chain, `GOVERNED_REQUEST_REFUSED` (actor, subject, request id as correlation id, code, problems, and the request's structured fields; free-text reasons are not kept). The error carries `auditEventId` |
| Unauthenticated (401), CSRF or Origin refusals, a route's static permission refusal (the role cannot use the route at all; raised before the request is read), malformed or invalid input (400/411/413/415/422), unknown resources (404) | API security log only |

The governed routes are: `POST …/transitions`, `POST /candidates/{id}/approvals`,
`POST /candidates/{id}/execution-jobs`, `POST /execution-jobs/{id}/execute`,
`POST /candidates/{id}/remediation-dry-runs` (P10), and the mapping `selections`,
`approvals`, and `rejections`. Mapping `inspection` and `searches` change nothing and are
not governed; nor is `POST /candidates/{id}/remediation-drills` (OGWA-DEMO-03), which records
nothing and changes no governed state. If chaining a refusal fails, the refusal stands (nothing changed), and the
failure is logged.

### `POST /candidates/{candidateId}/transitions`

```json
{"target": "NEEDS_REVIEW", "reason": "…", "expectedEvidenceFingerprint": "sha256:…",
 "approvalId": "apr_…", "jobId": "job_…"}
```

- The permission depends on the step (see the authorization document): advancing and
  re-entry need `LIFECYCLE_ADVANCE`, moving to a safer state needs `LIFECYCLE_DIVERT`,
  `→ APPROVED`, `→ QUARANTINE_APPROVED`, and `→ DELETION_APPROVED` need `APPROVAL_DECIDE`,
  and `→ *_DRY_RUN` needs `EXECUTION_PLAN_DRY_RUN`. The deletion proposal,
  `DELETION_REVALIDATION_REQUIRED → DELETION_PROPOSED`, needs `LIFECYCLE_ADVANCE` and a human
  (P10B); the proposer is recorded and may not approve the deletion (D143).
- A forward or re-entry step needs `expectedEvidenceFingerprint`, which must equal the
  current fingerprint. Otherwise the answer is `EVIDENCE_CHANGED`. A move to a safer state
  needs only a reason (L-5).
- `OKTA_UNASSIGN_DRY_RUN → HOLD`, `QUARANTINE_DRY_RUN → QUARANTINE_HOLD`, and
  `DELETION_DRY_RUN → RETIRED` record that read-only discovery *observed* an approved change.
  They are never operator actions (`NOT_AN_OPERATOR_ACTION`).
- The legacy single AD stage's steps, `REVALIDATION_REQUIRED → RETIREMENT_DRY_RUN` and
  `RETIREMENT_DRY_RUN → RETIRED`, are refused with `409 LEGACY_AD_RETIREMENT` (D148, chained)
  and are not listed in `allowedActions`.
- `→ STALE_EVIDENCE` and `→ EVIDENCE_INCOMPLETE` record what the evidence says. The lifecycle
  allows them to system actors only, so they are never operator actions either
  (`NOT_AN_OPERATOR_ACTION`, chained as a governed refusal; owner decisions after P09). An
  operator who wants to stop a candidate holds it (`→ BLOCKED`). `allowedActions` lists these
  steps with `operatorAction: false` and `permission: null`.
- The lifecycle guard decides the rest (`TRANSITION_REFUSED`, with its problems).

### `POST /candidates/{candidateId}/approvals`

```json
{"stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "…",
 "expectedEvidenceFingerprint": "sha256:…", "validForHours": 48}
```

- Needs `APPROVAL_DECIDE`.
- `OKTA_UNASSIGN` is decided in `NEEDS_REVIEW`, `AD_QUARANTINE` in `REVALIDATION_REQUIRED`,
  and `AD_DELETION` in `DELETION_PROPOSED` (otherwise `INVALID_STATE`). `AD_RETIREMENT` is the
  legacy stage and is refused with `409 LEGACY_AD_RETIREMENT` (D148).
- The approval binds the candidate, the stage, the epoch, the **current** evidence
  fingerprint, and an expiry (by default the policy maximum, 7 days; never longer).
- The separation-of-duties rules apply (`SEPARATION_OF_DUTIES`).
- An `APPROVE` is first checked against the lifecycle guard of the step it would
  authorize. If the lifecycle would refuse that step, the approval is not recorded
  (`EVIDENCE_RULES_NOT_MET`). For example, a name-only mapping cannot be approved, and
  neither can an AD quarantine with partial dependency coverage.
- An `APPROVE` also moves the candidate, as the approver and in the same request, to the
  stage's approved state: `APPROVED`, `QUARANTINE_APPROVED`, or `DELETION_APPROVED`.

### `POST /candidates/{candidateId}/execution-jobs` (dry-run planning)

```json
{"kind": "OKTA_UNASSIGN", "approvalId": "apr_…", "expectedEvidenceFingerprint": "sha256:…",
 "dryRun": true, "executionMode": "DRY_RUN_MUTATION"}
```

The checks run in this order:

1. `dryRun: false` or `executionMode: "PRODUCTION_MUTATION"` → `PRODUCTION_MUTATION_REFUSED`,
   before anything else.
2. The `EXECUTION_PLAN_DRY_RUN` permission.
3. The process mode must be one that can record jobs (`EXECUTION_MODE_NOT_AUTHORIZED`).
4. The candidate state (`INVALID_STATE`).
5. A fresh view (`EVIDENCE_CHANGED`).
6. The planner must not be the approver (`SEPARATION_OF_DUTIES`).
7. The approval must be valid: right candidate, stage, epoch, APPROVE, unexpired, and its
   fingerprint equal to the current evidence. For the AD quarantine it must also be given
   after the hold, by someone other than the Okta-stage approver; for the AD deletion, after
   the post-quarantine hold and the proposal, by someone other than the proposer, the
   quarantine approver, and the Okta-stage approver (`APPROVAL_INVALID`).
8. The lifecycle guard of the dry-run step, including the 24-hour execution freshness
   ceiling (`EVIDENCE_RULES_NOT_MET`).

The job is recorded as `DRY_RUN_MUTATION`, `dryRun: true`, `executed: false`, and planned
then succeeded in one request. `plannedActions` lists what *would* change. The dry-run
step itself is then recorded with `POST …/transitions`, citing the approval and the job.

`kind` is `OKTA_UNASSIGN` (planned in `APPROVED`), `AD_QUARANTINE` (in
`QUARANTINE_APPROVED`), or `AD_DELETION` (in `DELETION_APPROVED`); `allowedActions.planDryRun`
is offered in those three states. Each kind takes its own stage's approval only (D146). The
legacy `AD_RETIREMENT` kind is refused with `409 LEGACY_AD_RETIREMENT` (D148).

### `POST /candidates/{candidateId}/remediation-dry-runs` (P10)

```json
{"operation": "AD_GROUP_DELETE", "target": {"adGroupId": "adg_…"}, "approvalId": "apr_…",
 "expectedEvidenceFingerprint": "sha256:…"}
```

One operation (`OKTA_GROUP_UNASSIGN`, `AD_GROUP_QUARANTINE`, `AD_GROUP_DELETE`) on one
explicit target. The target object has exactly `assignmentId` (Okta) or `adGroupId` (AD).
The body is strict, so a template id, a script, an override, or a list of targets is
`422`. `PRODUCTION_MUTATION` or `dryRun: false` is refused first; then come the
`EXECUTION_PLAN_DRY_RUN` permission, a fresh view, separation of duties, and the ten
remediation gates.

The answer is `201` with `SIMULATED` or `VALIDATION_ONLY` (`WHATIF` comes from the
PowerShell worker), always with `executed: false` and `productionMutation: false`. A
`BLOCKED` request is `409 REMEDIATION_BLOCKED`, listing every gate with its problems and
never a planned change (D133). Once the gates pass, the approval, and the decision that applied
it, must have been judged by the policy version in force (`409 APPROVAL_POLICY_NOT_IN_FORCE`,
chained as a refusal; OGWA-DEMO-04). The `201` also carries `authorization` and `record` (the
recorded dry run with its `policy` and `chain`); the event records the policy reference its gates
were judged by. `AD_GROUP_DELETE` needs an `AD_DELETION` approval in
`DELETION_APPROVED` or `DELETION_DRY_RUN` (P10B), and every operation needs complete, empty
membership evidence (D132). A dry
run never moves the lifecycle and never creates a job. See
[remediation.md](remediation.md) and
[../security/mutation-gates.md](../security/mutation-gates.md).

### `POST /candidates/{candidateId}/remediation-drills` (OGWA-DEMO-03)

```json
{"operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": "asgn_…"}, "approvalId": "apr_…",
 "expectedEvidenceFingerprint": "sha256:…", "mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"}
```

A dry run (`mode: DRY_RUN`, no scenario) or a synthetic execution (`SYNTHETIC_EXECUTION`, one
scenario from `GET /remediation-drill-scenarios`) of the same one-operation, one-target request
as a remediation dry run, against an in-memory provider fixture built from the candidate's
synthetic evidence and discarded after the answer.

- `executionMode: PRODUCTION_MUTATION` or `dryRun: false` is `403 PRODUCTION_MUTATION_REFUSED`
  before anything else is read; any other unknown field (`executionMode`, `dryRun`, `faults`,
  `adapter`, …), an unknown scenario, or a mode and scenario that do not fit is `422`.
- Then the `EXECUTION_PLAN_DRY_RUN` permission, a fresh view (`409 EVIDENCE_CHANGED`), the
  approval (`404`), separation of duties (`403 SEPARATION_OF_DUTIES`), and the governed
  `remediation_dry_run`: a blocked request is `409 REMEDIATION_BLOCKED` with every gate, and
  builds nothing. Outside `LOCAL_SYNTHETIC` with a SYNTHETIC store, evidence, and adapter it
  is `409 SYNTHETIC_DRILL_UNAVAILABLE`.
- `200` returns `drill`: the mode, scenario, operation, target, `operationId` (the
  idempotency key), `plannedTransition`, the governed plan and gates, every step (`state`,
  `label`, `at`, `reason`, `detail`, attempt, provider answer, observation, reads, gate
  problems, scope differences), `finalState`, `finalLabel`, `succeeded` (true only for
  `POST_ACTION_VERIFIED`), `submissions`, the fixture's state, digest, and ledger, and
  `syntheticOnly: true`, `productionMutation: false`, `externalSystemsContacted: false`,
  `recorded: false`, `lifecycleChanged: false`. Since OGWA-DEMO-04 the drill also carries
  `modeBanner` (DRY RUN — NO STATE CHANGED, or SYNTHETIC EXECUTION: "No external provider or
  persistent environment was modified."), `attempts`, and `postActionVerification` (`CONFIRMED`,
  `FAILED`, `NOT_REACHED`); the success label is POST-ACTION VERIFIED.
- Since OGWA-DEMO-04, once the gates pass, the approval and the decision that applied it must
  have been judged by the policy version in force (`409 APPROVAL_POLICY_NOT_IN_FORCE`; nothing is
  built), and the `200` also carries `authorization` (policy in force; the approval and the
  decision with their audit event ids, sequences, digests, recorded policy, and binding) and
  `chain` (policy id/version/digests, decision and approval ids with audit sequences, operation
  id, mode, scenario, attempts, post-action result, final state, `recorded: false`).

Nothing is recorded, so it is not a governed route: its refusals stay in the security log
(D64, D72). See [remediation-execution.md](remediation-execution.md).

### Mapping review (`/mappings/{groupId}/…`)

| Path | Permission | Body |
| --- | --- | --- |
| `POST …/inspection` | any mapping permission | `{}`. Re-runs correlation; returns the fingerprint, outcome, target, candidates, and allowed review actions |
| `POST …/searches` | `MAPPING_PROPOSE` | `{"by": "name", "value": "…", "domain": null}`. One bounded lookup; returns a `searchId` usable only by the same person |
| `POST …/selections` | `MAPPING_PROPOSE` | `{"searchId", "objectGuid", "reason"}`. Records a `PROPOSED` pairing |
| `POST …/approvals` | `MAPPING_APPROVE` | `{"objectGuid", "expectedEvidenceFingerprint", "reason"}`. The person who selected a pairing cannot approve it |
| `POST …/rejections` | `MAPPING_REJECT` | `{"objectGuid", "expectedEvidenceFingerprint", "reason"}` |

These need an AD identity directory. In `LOCAL_SYNTHETIC` the API uses the synthetic
directory over the store's own recorded AD groups (D68), so the whole flow works end to
end. For example, the demo's ambiguous S09 group: one person searches and selects the
EMEA group, a different Security/IAM person approves, and inspection then reports
`RESOLVED` / `EXACT_CONFIGURED_MAPPING`. Reviews are persisted in the store's mapping
registry (`MAPPING_REVIEW_RECORDED`). An API built without a gateway answers
`503 MAPPING_REVIEW_UNAVAILABLE`.

What the synthetic directory can prove is limited, on purpose:

- Stored Okta groups carry no verified stable identifier. Okta's rendering of the
  objectGUID stays unverified (D23, D30). Okta's objectSid is stored as unverified source
  metadata (0008) and shown as `directoryObjectSidUnverified`; it corroborates but never
  establishes a mapping (D37). So the engine can make a demo mapping exact only through
  the synthetic mapping configuration (`config/correlation.synthetic.json`, objectGUID and
  objectSid per pairing, D76, D81) or a two-person reviewed selection; a group with only
  Okta's SID is `UNVERIFIED_STABLE_ID`, and one with neither falls back to the bounded
  `samAccountName` search. Both stay review-required (D78).
- The demo's stored mapping evidence is itself what the engine proved, with the same
  configuration (D75). Until something changes, an inspection reproduces it.
- Inspection and reviews never rewrite stored `IdentityMapping` evidence. A new mapping
  observation is a collector's job (a re-correlation run), not an operator action. After
  S09 is approved, inspection reports `EXACT_CONFIGURED_MAPPING` while the lifecycle still
  reads the earlier `AMBIGUOUS` observation, until the evidence is re-collected.

## Mutation routes

`POST /execution-jobs/{jobId}/execute` is the shape a future remediation route will take.
Only the execution function may use it: its static permission is `EXECUTION_PLAN_DRY_RUN`
or `EXECUTION_EXECUTE`, so anyone else gets an ordinary `403 FORBIDDEN`, recorded in the
security log only (D72, D73). In this build it answers `403 PRODUCTION_MUTATION_REFUSED`
to everyone who may use it, whatever roles or permissions they hold, and that refusal is
chained. That holds even if a role were granted `EXECUTION_EXECUTE`, which none is. Enabling execution is a reviewed source change (see
[../security/execution-modes.md](../security/execution-modes.md)), never configuration.

P10's remediation dry runs do not change this. There is no remediation execute route, and
every remediation adapter can only plan. OGWA-DEMO-03's drills do not change it either: a
drill's synthetic execution changes only an in-memory provider fixture, records nothing, and
uses neither this route nor `ExecutionJob`.

## Not in P08

- **Policy-version writes.** No proposal or approval endpoint exists. D52 keeps v1
  unrecorded until real operator identities exist, and a two-step proposal needs a pending
  store the schema does not have.
- **Candidate creation.** Candidates come from discovery and classification (a collector
  pipeline), not from operators.
- **Production hosting.** That needs a reviewed WSGI server, TLS, a real identity adapter,
  and a shared session store.
- **A production AD directory for mapping review.** Only the synthetic directory exists
  (D68). The real one is the read-only AAP worker boundary.
