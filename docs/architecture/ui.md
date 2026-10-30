# Operator UI

Status: P09; restructured as an operator review workflow in OGWA-UI-REVIEW-01; server-side Review queue, evidence verdicts, approval usability, and the AD group → candidate link in OGWA-REVIEW-QUEUE-API-01. The UI is a restrained review console over the [operator API](api.md). It runs
only where the API runs: `LOCAL_SYNTHETIC`, a SYNTHETIC store, and synthetic sign-in. It has
no delete, unassign, or execute action.

## Shape

```text
Browser ── same origin ──▶ app/ui/server.py (OgwaWebApp, WSGI)
                             ├─ GET /, /ui/*   fixed set of static files (HTML, CSS, JS modules, SVG)
                             └─ /api/v1/*      the operator API, untouched (app/api)
```

- `python -m app.api serve --demo-clock` serves both on `http://127.0.0.1:8765`.
- **No third-party code and no build step.** Plain ES modules, standard library on the
  server (D4, D5). Nothing is fetched from anywhere but the page's own origin.
- **The browser holds no Okta, AAP, or AD credential.** It holds only the API's session
  cookie (`__Host-`, HttpOnly, so scripts cannot read it) and the per-session CSRF token,
  kept in memory. Nothing is written to `localStorage`, `sessionStorage`, or IndexedDB.
- Hash routing (`#/candidates/cand_…`), so the server serves exactly one HTML file.

| File | Responsibility |
| --- | --- |
| `app/ui/server.py` | Static files from a fixed allowlist, the UI's security headers, pass-through to the API |
| `app/ui/static/index.html` | Shell: skip link, header, policy notice, safety strip, docked side navigation, live region |
| `js/api.js` | The only network code: same-origin `fetch` to `/api/v1`, CSRF header, the five write paths. A public-demo visitor's POST refused before any handler ran (lapsed session, or a CSRF token another tab replaced) is sent once more with the new visitor session; nothing else is ever resent |
| `js/assess.js` | Pure functions that put the API's evidence into plain words (unit-tested under Node) |
| `js/dom.js` | Safe DOM construction (`createElement`/`textContent` only, `createElementNS` for SVG), formatting, the shared table (sorting, paging) |
| `js/present.js` | Pure presentation rules (OGWA-UI-IA-01): employee status words, sort and page arithmetic, tab keys, hash addresses and where old ones moved (`movedRoute`), time on the server's clock (`span`, `deadlineText`), how a resolved identity is shown (unit-tested under Node) |
| `js/review.js` | Pure operator review rules (OGWA-UI-REVIEW-01): the one mapping from lifecycle state to review status, the lifecycle stepper, the next step and who takes it, evidence readiness, the impact of a dependency check, governance rules in plain words, and dry-run plan wording (unit-tested under Node) |
| `js/main.js` | Session, routing, focus management, announcements |
| `js/views/*.js` | The views below |
| `css/ogwa.css` | Tokens, tones, light/dark, focus, reduced motion, responsive layout |

## Security headers (UI responses)

`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none';
require-trusted-types-for 'script'; trusted-types 'none'`, plus `nosniff`, `X-Frame-Options: DENY`,
`no-store`, `no-referrer`, CORP/COOP `same-origin`, and a restrictive `Permissions-Policy`.
Trusted Types are enforced with no policy, so an HTML-string sink such as `innerHTML` throws even
if one were added by mistake. API responses keep their own headers (`default-src 'none'`).

## Views

Since OGWA-UI-REVIEW-01 the navigation follows what an operator is doing rather than the domain
model: Dashboard and Portfolio scenarios, then **Inventory**, **Review**, and **Operations**.

| Group | View | Route | Source |
| --- | --- | --- | --- |
| — | Dashboard | `#/` | `GET /dashboard`, `GET /directory`, `GET /governance-findings` (counts), `GET /review-queue?limit=5` (the queue's head, its counts, and holds ending within 7 days) |
| — | Portfolio scenarios | `#/scenarios` | `GET /demo-scenarios`; opens with the dataset's five-minute reviewer walkthrough (OGWA-DEMO-04), linked from the dashboard when the synthetic directory is present |
| Inventory | People | `#/people[?department=&status=&q=]`, `#/people/{id}` | `GET /people`; the detail view shows history and every access route |
| Inventory | Company Directory (profile and departments; reached from People and the dashboard) | `#/directory` | `GET /directory` |
| Inventory | Groups | `#/inventory/groups?tab=directory\|okta` | Directory groups: `GET /directory-groups[?era=&health=&source=&q=]` (AD and Okta groups in the snapshot); Okta groups: `GET /groups` (+ `GET /identities` for the exactly mapped AD group). The sources stay separate tabs |
| Inventory | AD group (canonical group page), Okta group | `#/directory-groups/{id}`, `#/groups/{id}` | `GET /directory-groups/{id}` (with `lifecycleCandidates`: an AD group's through an exact identity mapping only); `GET /groups/{id}`, and each of its candidates (`GET /candidates/{id}`) with its review status and next step |
| Inventory | Applications | `#/inventory/applications?tab=directory\|okta`, `#/applications/{id}` | Directory applications: `GET /directory`; Okta applications: `GET /applications` |
| Inventory | Identity mappings | `#/mappings[/{groupId}]` | `GET /mappings` (read-only; review history shown, not editable) |
| Review | Review queue | `#/review[?status=needs-review\|blocked\|waiting\|in-progress\|retired\|closed\|all][&sort=&order=&cursor=]` | `GET /review-queue` (OGWA-REVIEW-QUEUE-API-01): 25 rows a page, filtered, ordered, counted, and paged on the server, with the server clock |
| Review | Every candidate by lifecycle state (linked from the queue) | `#/candidates[?state=]` | `GET /candidates` |
| Review | Candidate detail | `#/candidates/{id}` | candidate, evidence, dependencies, decisions, approvals, jobs, group; audit events with `READ_AUDIT` |
| Review | Findings: Impact & Blockers, Governance | `#/findings?tab=dependency\|governance[&severity=&code=]` | `GET /dependency-findings`, `GET /governance-findings` |
| Review | Decisions | `#/decisions` | `GET /approvals` (with each approval's `usability`), `GET /dashboard` (server clock, policy in force) |
| Operations | Plans & simulations | `#/jobs[/{id}]` | `GET /execution-jobs`, `GET /execution-jobs/{id}` |
| Operations | Collection health | `#/collectors` | `GET /collector-runs` |
| Operations | Audit | `#/audit[?subjectId=]` | `GET /audit-events` (`READ_AUDIT`) |

### Old addresses

Every earlier address still arrives (`present.movedRoute`). The address is replaced
(`location.replace`, so Back skips it) and its filters, sort, and page are kept:

| Old address | Now |
| --- | --- |
| `#/directory-groups[?…]`, `#/directory?tab=groups[&…]` | `#/inventory/groups?tab=directory[&…]` |
| `#/groups`, `#/okta?tab=groups` | `#/inventory/groups?tab=okta` |
| `#/applications`, `#/okta`, `#/okta?tab=applications` | `#/inventory/applications?tab=okta` |
| `#/directory?tab=applications` | `#/inventory/applications?tab=directory` |
| `#/dependencies[?…]` | `#/findings?tab=dependency[&…]` (the Impact & Blockers tab keeps its key) |
| `#/findings?severity=…` | the Governance tab |
| `#/approvals` ("Approvals and holds") | `#/review`; with a sort or cursor (the old decision list's), `#/decisions` with them |

Unchanged: `#/`, `#/people[/{id}]`, `#/directory` (departments), `#/directory-groups/{id}`,
`#/groups/{id}`, `#/applications/{id}`, `#/mappings[/{id}]`, `#/candidates[?state=]`,
`#/candidates/{id}`, `#/findings`, `#/scenarios`, `#/jobs[/{id}]`, `#/collectors`, `#/audit`.

The AD group page lists its **lifecycle candidates** (OGWA-REVIEW-QUEUE-API-01) with review status,
lifecycle state, next step, and "Linked by: Exact identity mapping" (a link to the mapping). The
server links them only through an exact identity mapping to the group's stable id; the page keeps
the snapshot's Okta group link as identity context and says plainly when no candidate is linked
("No lifecycle candidate is linked to this AD group by an exact identity mapping."). An Okta
directory group lists the candidates whose subject it is ("Its own Okta group").

The directory views are read-only and show the snapshot only when the store holds one (the
Null Meridian dataset); otherwise they say so. `tests/browser/test_null_meridian_views.py`
walks them in the browser gate.

Under Demo Mode ([../demo-mode.md](../demo-mode.md)) the header also shows the
"DEMO ENVIRONMENT · Synthetic data" indicator, from the public `/health`, before and after
sign-in. Expanded, its explanation takes its own header row and never covers the
navigation. `tests/browser/test_demo_null_meridian_ui.py` walks every view with it.

## Operator review (OGWA-UI-REVIEW-01)

The UI answers, in this order: what needs attention, what needs a decision from me, what is
blocked and why, where each candidate is in its lifecycle, what happens next, and what evidence
supports it. This is presentation only: the state machine, classification, evidence grades,
dependency coverage, approval rules and expiry, gates, remediation authorization, and the audit
chain are unchanged, and the server checks every action again.

### Review status: one reading of the lifecycle state

`review.reviewStatus(state)` is the only place a lifecycle state is grouped. Every view that
shows a review status shows the lifecycle state beside it (in the queue under "Lifecycle:", on
the candidate page in the headline), so the grouping is never the only fact.

| Review status | Lifecycle states | Why |
| --- | --- | --- |
| Needs review (caution) | `NEEDS_REVIEW`, `REVALIDATION_REQUIRED`, `DELETION_REVALIDATION_REQUIRED`, `DELETION_PROPOSED` | A named person's decision is open there: the Okta approval, the AD quarantine approval, the deletion proposal, the AD deletion approval |
| Blocked (blocked) | `BLOCKED`, `MAPPING_AMBIGUOUS`, `DEPENDENCY_BLOCKED`, `STALE_EVIDENCE`, `EVIDENCE_INCOMPLETE`, `RETIREMENT_DRY_RUN`, and any state the UI does not know | The state machine's blocked class; the legacy single AD stage can only be diverted (D148); an unknown state is treated as blocked |
| Waiting (neutral) | `DISCOVERED`, `CANDIDATE`, `HOLD`, `QUARANTINE_HOLD` | Waiting on classification or on time. No decision is open, and a hold is not a block |
| In progress (dry run only) (caution) | `APPROVED`, `OKTA_UNASSIGN_DRY_RUN`, `QUARANTINE_APPROVED`, `QUARANTINE_DRY_RUN`, `DELETION_APPROVED`, `DELETION_DRY_RUN` | An approval is recorded; OGWA plans dry runs only, and any change happens outside OGWA and counts only when read-only discovery observes it |
| Retired (observed) (terminal) | `RETIRED` | Discovery observed the group gone |
| Closed (terminal) | `EXCLUDED`, `REJECTED`, `PROTECTED` | Terminal states (`PROTECTED` is terminal in the state machine; its own state label stays "Protected", toned blocked) |

There is deliberately **no "Ready" status**: every step forward needs a named person's decision
or an observed external change, so nothing is ever presented as ready to proceed. A test pins it.

### Review queue

`#/review` replaces the "Approvals and holds" page as the place to find waiting work. It lists
every candidate in priority order: needs review, then blocked, then waiting, then in progress;
within a status, the nearest deadline and then the longest wait first. Since
OGWA-REVIEW-QUEUE-API-01 the **server** filters, orders, counts, and pages it
(`GET /review-queue`, [api.md](api.md#review-queue-ogwa-review-queue-api-01)): the browser shows
one page of 25 rows in the server's order, with the usual pager ("Rows 26–50 of 1,100") and
server-sorted Candidate, Waiting, and Deadline columns. The old 1,000-candidate ceiling is gone.
The server's order is `review.queueOrder`'s and its status table is `review.reviewStatus`'s
(tests run both under Node over the served rows). Columns: candidate, review status (with the
lifecycle state), **Evidence now**, stage, what it needs (the required decision or the blocker),
the next step and who takes it, how long it has waited (since its last change), and its deadline
(a hold's end). Filters are links (`?status=`) with the server's counts over every candidate; a
filter keeps focus after the page re-renders.

**Evidence now** (`review.verdictReading`) is the classifier's current reading of the evidence,
beside the recorded state, never instead of it: the evidence assessment's decision in the
server's words ("No action: identity not established"), then whether it matches the recorded
state ("Matches the recorded state.", "Differs from the recorded state: the evidence now points
to “Blocked: identity not proven”.", or for a terminal candidate "Terminal: nothing further is
decided."), then the first blocking reason as the candidate page words it. A disagreement is
shown, never resolved: the lifecycle state stands until the lifecycle records a transition, so a
candidate recorded as needing review whose evidence has gone stale reads "Needs review ·
Lifecycle: Needs review" and, beside it, "Differs … points to “Blocked: evidence stale”". A
missing or unknown verdict reads "Not assessed" or "Unrecognized comparison" (blocked tone), never
as agreement. The full forensic reading stays on the candidate page.

### Candidate detail: the operator's reading first

The page opens with, in order: the review status and the lifecycle state with its one-sentence
meaning; **Lifecycle**, a stepper; **What blocks this candidate** (the existing banners); **Next
step** (what it needs, what happens next, who, any deadline, and which actions are open to the
signed-in person, from the server's `allowedActions`); and **Evidence readiness** ("6 of 14
required sources complete and current": the server's required assessment items whose state is
Confirmed or Source says none and whose freshness is Current, with the others named). The
forensic sections follow unchanged: "Is this safe to act on?", "Why this decision", the drill,
the decision summary, reasons, coverage, evidence timestamps, decisions, approvals, dry-run
plans, and the audit trail.

The **stepper** (`review.lifecycleStages`) shows ten stages: Discovery, Review, Okta unassignment,
Hold, Revalidation, AD quarantine, Post-quarantine hold, Deletion review, AD deletion, Retired.
Each says its status in words: Completed, Current, Current, waiting (a hold, with its end on the
server's clock), Blocked (a blocked candidate, at the stage it was blocked from, naming the
lifecycle state), Stopped here (excluded, rejected, or protected: at the furthest stage its
recorded decisions reached), Not yet eligible (every later stage: never shown as reached or
guaranteed), and Not reached (after a terminal stop). The text equivalent is the list itself
(`ol aria-label="Lifecycle stages"`, the current stage `aria-current="step"`) plus a summary
sentence; the marks (✓ ● ◷ ✕ ■ ○ –) are `aria-hidden`, and colour is never the only cue. The
state machine stays authoritative: the stepper is a projection of the candidate's state,
`blockedFrom`, and decision history.

### Findings: Impact & Blockers

The dependency tab is now **Impact & Blockers** (its key stays `tab=dependency`, and
`#/dependencies` still arrives there). Each row leads with what is affected and its impact
(`review.impactOf`): the category (Known dependency, Directory constraint for AD membership and
nesting, External reference for ACL, GPO, AAP, application configuration, and Okta policy
references, Coverage gap, or None found) and its effect: "Blocks lifecycle progress for this
group", "Informational: does not block on its own", "None found (complete, decision-grade
check)", or "Not established: OGWA could not determine whether a dependency exists". A known
dependency and an undetermined one are never worded alike; something found by an incomplete
check still counts and says more may exist. The check's kind is kept as secondary evidence.

Governance findings lead with the rule in plain words (`review.RULE_LABEL`, for example
"Deactivated members still retain access") with the rule code beneath it. The codes are
unchanged and still filter (`?code=`).

### Decisions and holds

**Decisions** (`#/decisions`) lists the approvals and rejections people recorded: candidate,
stage, decision, **Approval rules now** (OGWA-REVIEW-QUEUE-API-01: the server's `usability`, worded
by `review.approvalUsability`: "Valid for its stage" with "The step it backs has its own checks
…", or why not: "Expired", "Superseded: the candidate re-entered review", "Not usable in the
candidate's current state", "Not usable: evidence changed since", "Rejection: authorizes
nothing"; never "ready"), by, decided, expiry (the server's `expired` flag, worded "Expired 3 days ago"
or "2 days remaining" with the absolute time beneath), the policy that judged it (marked
Superseded when it is not the one in force), and the reason. Holds are not decisions: they are
waiting work in the Review queue and on the candidate page. The candidate page's approvals table
has the same column, and the dry-run and drill forms offer only approvals the server judges valid
(`assess.usableApprovals` no longer re-derives validity from expiry and epoch in the browser).

### Plans & simulations

The visible name of `#/jobs` is **Plans & simulations**. A recorded job's status is worded so it
never suggests execution: "Plan finished, nothing executed", "Plan failed, nothing executed"; a
job recorded as executed, or not a dry run, is shown as blocked (this build cannot execute). The
raw status is kept on the plan's own page. Synthetic drills record nothing, so the page explains
where to run one instead of listing them.

### Dashboard

"Needs attention" comes first: candidates waiting for a person's decision, blocked, blocked on
stale or incomplete evidence, collector runs incomplete or unfinished, holds that ended or end
within 7 days (counted by the server over every candidate, on its clock), candidates approved for a future step, actionable
governance findings, blocking dependency findings, and recent deactivations. Each links to the
filtered Review queue or the list behind it. Then the head of the review queue (five rows),
**Find** (open an object by its OGWA id or AD objectSid through `GET /identities`; anything else
is offered as a server-side people or group search, never matched by name in the browser), key
figures, the charts, and System details.

### Time

Relative times ("6 days", "2 days remaining", "Expired 3 hours ago") are always computed from two
server instants: the record's and the server's clock (`GET /dashboard`'s `generatedAt`, or the
classification time on a candidate page). Without a server time only the absolute time is shown;
the browser's clock is never used. The absolute time is always shown too.

## Navigation, tabs, tables, identities (OGWA-UI-IA-01)

- **Docked side navigation.** Twelve destinations: Dashboard and Portfolio scenarios, then
  three named groups (Inventory, Review, Operations, since OGWA-UI-REVIEW-01), each group a list
  labelled by its heading (`ul aria-labelledby`), each destination an icon and a label. The toggle (`#nav-toggle`,
  `aria-expanded`) collapses it to icons; a collapsed link keeps its label as its accessible
  name and shows it as a tooltip on hover and keyboard focus. A detail page marks its section
  (an AD or Okta group marks Groups, an application Applications, a candidate Review queue).
  Collapsed, the group labels are hidden visually like the link labels. The choice lasts while the
  page is open: **it is not written to browser storage**, because the UI stores nothing
  (`tests/test_ui_static.py` pins that). Below 48rem the navigation is a menu above the page,
  closed by default and closed again after a link is followed.
- **Tabs are addresses** (`?tab=`): switching is a hash change, so the document never reloads,
  Back and Forward move between tabs, and a tab can be linked to. ARIA tabs: arrow keys, Home,
  and End move focus; Enter or Space opens a tab; focus stays on the tab after it opens.
- **One table.** `dom.table` is every table. A column with `sort` is sortable: a function sorts
  the rows held in the browser (and more than 25 rows are paged there); a string names the
  API's `sort` field, and `common.listing` pages and sorts on the server with `sort`, `order`,
  and the cursor in the address. The sorted header carries `aria-sort` and an arrow; sorting
  returns to the first page; a sort header, tab, or pager control keeps focus after the page
  re-renders (`focusAfterRoute`). Pagers say "Rows 51–100 of 298" and offer the previous and
  next page; a cursor past the end offers the first page. The candidate page's tables open in
  their meaningful order (blocking reasons first) and sort in the browser (OGWA-UI-IA-02) on every
  column with an order: not prose (a reason's detail, a finding's text), ids (a job), or actions.
  Two event histories keep their recorded order and do not sort: the audit trail (only by
  sequence, either way round on the audit page; sorting the chain by anything else would
  re-verify every event) and a candidate's decision history, a chain in which each decision
  starts where the last one ended.
- **Identities.** A stable id is shown by its common name, through one path: `GET /identities`
  (`app/api/resolve.py`) → `present.refView` → `common.identity`. The name links to the object's
  canonical page (an AD group: `#/directory-groups/{id}`, keyed by its stable directory id), the
  raw id is the link's tooltip, and a name that more than one group shares (Null Meridian has two
  AD groups called Finance-RW and an Okta group of that name) carries its distinguished name or
  Okta group id as a second line. An id that does not resolve is shown as itself with "Not
  resolved". Nothing is looked up by name. An Okta group's AD group is shown only from an exact
  identity mapping, never from the SID Okta reports (D37). Without a directory snapshot (the
  classic world), AD group names come from AD evidence and have no page to open.
- **Access paths** are ordered lists (`ol.chain`): each step a link, the "›" drawn by CSS
  outside the links, the list labelled with the application it reaches.
- **Employees are Active or Deactivated**, with the deactivation date in its own column; the
  API keeps `TERMINATED` and `terminationDate`. Stored governance finding text that says "former
  employee" is shown as "deactivated employee" (`present.employeeTerms`); the rule code
  `TERMINATED_MEMBERS_RETAINED` is an identifier and is unchanged.
- **Dashboard** (order since OGWA-UI-REVIEW-01, above): "Needs attention", the review queue's head, Find, key figures, findings by severity, group health, and
  deactivations per year (a table beside the chart); every figure and bar links to the list
  behind it. Chart fills are their own tokens (`--chart-*`), checked with the dataviz palette
  checks for both schemes; every bar carries its label and value as text. The safety posture,
  candidates by state, evidence, policy, and store are kept under "System details".

### Candidate detail

After the operator's reading above (OGWA-UI-REVIEW-01), the page answers "why can't this proceed?":

0. **Is this safe to act on?** (OGWA-DEMO-01): the server's evidence assessment, grouped by the
   six reviewer questions (issue, supporting sources, sources that disagree or are unavailable,
   identity mapping, what OGWA can safely decide, evidence needed), then the next lifecycle step,
   any conflicts, and every source's evidence state, freshness, bearing, and whether it is
   required (`evidence.js`; [evidence-assessment.md](evidence-assessment.md)).
   Then **Why this decision** (OGWA-DEMO-02): the policy version that ran, the decision it
   produced, each condition as that version states it (status, why, and the evidence it read),
   whether ambiguous or missing evidence forced manual review, and what would change the outcome
   (`policy.js`). An unknown status reads "Unrecognized" and is toned as blocked.
0a. **Remediation: dry run or synthetic drill** (OGWA-DEMO-03), only at a remediation stage
   (`APPROVED`, `QUARANTINE_APPROVED`, `DELETION_APPROVED`, and their dry-run states): the
   executor picks the target, the approval, a mode (radio group: *Dry run* or *Synthetic
   execution drill*), and, to execute, a fault scenario from the server's catalog (disabled for
   a dry run). The result names its final state in the server's words in a banner
   (DRY RUN — NO STATE CHANGED, POST-ACTION VERIFIED, VERIFICATION FAILED — NOT A SUCCESS, …), then lists
   every step with its own toned label and its time on the synthetic clock (`+30 s`), the
   operation id, the fixture's state digests, and the fixture's ledger. Focus moves to the
   result. Nothing is recorded, so the page does not reload. A reader without the dry-run
   planning permission sees why it cannot run one (`drill.js`;
   [remediation-execution.md](remediation-execution.md)).
   OGWA-DEMO-04: the result opens with the server's **mode banner**, above the outcome and
   heavier than it: DRY RUN — NO STATE CHANGED (neutral) or SYNTHETIC EXECUTION, "No external
   provider or persistent environment was modified." (caution); a missing or mismatched banner
   makes the result inconsistent (blocked). Then **Authorized by**: the policy in force, the
   lifecycle decision and the approval with their audit sequences and the policy each recorded
   (only "judged by the version in force" is worded as binding), the operation id, the mode, the
   post-action verification, and the final state; then an **Attempts** table (answer,
   verification read, what followed), kept in order.
1. **What blocks this candidate**: one plain-language banner per condition, most severe first,
   each said once, built from the server's classification reasons (`assess.candidateBanners`).
2. **Decision summary**: Okta app and status, usage window, last observed sign-in, the Okta
   group, mapping confidence, the AD group's identity (labelled "not proven" unless the mapping
   is exact), direct members, nested members and member groups, parent groups, primaryGroupID
   references, other Okta assignments, protection, dependency coverage, classification.
3. Classification reasons, dependency coverage per kind, findings, evidence timestamps (with the
   classifier's staleness per record), decision history, approvals, dry-run jobs, audit trail.
   Decision history and approvals show the policy each recorded ("Judged by policy"), marked
   Superseded when it is not the policy in force; a record without one says "Not recorded with
   this decision" (OGWA-DEMO-02).
4. **Record a decision** (aside): only the actions below, only when the server's
   `allowedActions` says the signed-in person may take them.

## Wording rules

- **No reassuring tone.** Tones are `blocked`, `caution`, `info`, `neutral`, `terminal`. There
  is no green and no "success" style; a test checks the palette's hues. An exact mapping is
  `info`: a fact, not a safety verdict. A recorded action is announced in `info`.
- **Plain language for dangerous states**, for example "Mapping ambiguous — automatic retirement
  blocked.", "Dependency coverage incomplete — AD deletion blocked.", "Evidence stale —
  revalidation required."
- **Unavailable is not stale (D97).** Missing evidence ("AD evidence unavailable", "Evidence
  incomplete — a collection did not finish") and unchecked dependencies ("AD membership not
  checked") are never called stale. Okta's directory SID is shown as unverified metadata that
  cannot establish a mapping (D37). Nothing says re-collection will fix a condition; where a
  condition is only about collection, the text says it "only clears when" a complete
  collection is recorded.
- **Future-dated evidence is invalid, not stale (D116):** "Future-dated evidence — invalid,
  decisions blocked.", and the evidence table marks the record "Future-dated (invalid)".
- **S08, S09, S10, S13 stay distinct (D98):** "Name-only match", "Ambiguous", "AD group not
  found", "No mapping evidence", each with its own explanation.
- **Banners come from reasons, not from `lifecycleDiversion`.** The UI shows the classifier's
  suggested diversion as such and words the reasons. Since the owner decisions after P09 the
  suggestion itself distinguishes the two evidence conditions: `EVIDENCE_INCOMPLETE` ("Blocked:
  evidence incomplete", required evidence never fully or properly obtained; S07, S12) and
  `STALE_EVIDENCE` ("Blocked: evidence stale", once-complete evidence past its window; S11).
- The policy label (`DEMO POLICY — UNRECORDED`, D66) is shown in the header on every page and
  next to every classification.

## Actions

| UI action | API call | Who (synthetic roles) |
| --- | --- | --- |
| Approve for future action | `POST …/approvals` `APPROVE` (stage from state) | SECURITY_IAM |
| Decline approval | `POST …/approvals` `REJECT` | SECURITY_IAM |
| Hold (block for review) | `POST …/transitions` → `BLOCKED` | IDENTITY_AUTOMATION, SECURITY_IAM |
| Exclude | `POST …/transitions` → `EXCLUDED` (terminal; confirmation required) | same |
| Reject candidate | `POST …/transitions` → `REJECTED` (terminal; confirmation required) | same |
| Request revalidation | `POST …/transitions` → `REVALIDATION_REQUIRED` or `DELETION_REVALIDATION_REQUIRED` (with fingerprint) | IDENTITY_AUTOMATION |
| Propose AD deletion (P10B) | `POST …/transitions` → `DELETION_PROPOSED` (with fingerprint). Records a proposal only; someone else must approve it (D143) | IDENTITY_AUTOMATION |
| Run dry-run | `POST …/execution-jobs` with `dryRun: true`, `DRY_RUN_MUTATION` fixed in `api.js`; the kind is the approved stage's (`OKTA_UNASSIGN`, `AD_QUARANTINE`, `AD_DELETION`) | EXECUTOR |
| Record the dry-run step | `POST …/transitions` → `*_DRY_RUN` citing approval and job | EXECUTOR |

- The lifecycle's `HOLD` is the post-unassignment period recorded by discovery, never an
  operator action. The operator's "Hold" is therefore the generic `BLOCKED` diversion
  (confirmed by the owner after P09).
- "Decline approval" records a rejection and leaves the lifecycle state unchanged; "Reject
  candidate" is a separate, terminal action behind an explicit confirmation (confirmed).
- Operators never assign `STALE_EVIDENCE` or `EVIDENCE_INCOMPLETE`: the lifecycle allows those
  diversions to system actors only, and the API refuses them (`NOT_AN_OPERATOR_ACTION`).
- The approval form's "valid for" limit is the policy's `approvalMaxValidHours`, read from the
  candidate's `policy`; nothing in the browser code fixes it. Without that field the form does
  not offer the choice, and the server applies the policy maximum.
- Every form needs a reason; forward steps and approvals send the evidence fingerprint the
  person was looking at, so a change in between is refused (`EVIDENCE_CHANGED`).
- The approval form says, before submission and in a required acknowledgement, that approval
  alone does not change Okta or Active Directory.
- Refusals are shown with the server's problems, the request id, and the audit event id when
  the refusal was chained.
- **Not in the UI (API only, by design of this package):** submitting for review, re-entry to
  CANDIDATE, the specific diversions (DEPENDENCY_BLOCKED, MAPPING_AMBIGUOUS, PROTECTED,
  STALE_EVIDENCE), and mapping review (inspection, search, selection, approval, rejection).
  The execute route is unreachable from the UI: `api.js` can POST to five paths only.

## Accessibility

Native elements throughout (links, buttons, forms with labels, `fieldset`/`legend`, tables with
captions and `scope`). A skip link; focus moves to the page heading on navigation and into a
form when it opens; Escape closes a form and returns focus to its button; validation errors are
announced and focus the field to fix. While a page loads, `<main>` is `aria-busy` and the heading
says "Loading"; the new heading, content and focus arrive together, and a reader who moved focus
meanwhile keeps it there. After a failed drill or decision, focus stays on the button that failed,
next to the announced error. The sticky decision panel scrolls within the screen, so an opened
form is never below it. A polite live region announces page changes. Focus is
always visible (3px outline). `prefers-reduced-motion` removes transitions; `forced-colors` keeps
borders; light and dark schemes both meet WCAG AA text contrast (tested). Below 40rem, fact
lists stack and wide tables scroll inside their own keyboard-focusable region.

## Tests

| Test | What it covers |
| --- | --- |
| `tests/test_ui_server.py` | Static allowlist, traversal and method refusal, UI headers and CSP, API pass-through, Origin check, the new read listings |
| `tests/test_ui_static.py` | No HTML sinks, storage, external URLs, or execute path; the six write paths (OGWA-DEMO-03 added the drill, which records nothing); the P09 action set; no green; contrast; focus and reduced motion; module imports resolve |
| `tests/test_ui_present.py` → `tests/ui/present.test.mjs` | `present.js` against the real API over Null Meridian: common names for SIDs and AD evidence ids, two groups of one name told apart, unresolved ids shown, access-path order, Active/Deactivated and the date, sort and page arithmetic, tab keys |
| `tests/test_ui_ia.py` | The API side: totals and both-way cursors on every listing, sorting across pages in both directions, stable ties, missing values last, final partial page, empty and past-the-end pages, validation; the resolver (SID and AD evidence id → name and canonical page, shared names, unresolved ids, names never accepted as keys, exact mappings only, renamed groups); SID search; the dashboard and deactivation summaries |
| `tests/test_ui_review.py` → `tests/ui/review.test.mjs` | OGWA-UI-REVIEW-01: `review.js` against the real API over the classic world (and one candidate excluded through the API): every lifecycle state has one review status (and the Python side pins it against `LifecycleState`), holds wait and are not blocked, no status is ready, the stepper for initial review, approval, both holds, revalidation, quarantine, deletion proposal, dependency, stale, incomplete, ambiguous, held, protected, excluded, and retired candidates, next steps, queue order, evidence readiness, impact categories (blocking, informational, none found only after a complete check, not established otherwise), every governance rule worded (pinned against `RULES`), and plan wording that never implies execution |
| `tests/test_ui_assess.py` → `tests/ui/assess.test.mjs` | `assess.js` against fixtures produced by the real API over a seeded synthetic world (D97, D98, tones, action plans, evidence conditions, the server's approval limit). Part of the standard check: `scripts/check.ps1` requires Node, and the test fails without it |
| `tests/test_browser_gate_guards.py` | Keeps the browser gate honest without a browser: the host-blocking flags, the clean-page and CSP assertions, and the gate's exit codes cannot be removed |
| `tests/test_listing_scale.py` | OGWA-UI-IA-02: every sortable field of every store-backed listing, both ways, across every page, against an order computed from the served items and resolved names, on both demo worlds and a synthetic tenant ten times larger (`tests/scale_fixtures.py`); a filter before paging; ties broken by stable id; missing values last; first, last, single, empty, and past-the-end pages; a sorted page loads only its own records; the audit trail's sequence continuity across pages |
| `tests/browser/test_candidate_tables.py` | Opt-in: which candidate-page columns sort (and that the decision history and audit trail do not), both directions with `aria-sort` and the arrow, focus kept, no reload, ties in the table's own order, a new sort after changing pages returning to the first page (the classic world's 26-reason candidate) |
| `tests/browser/test_ui_ia.py` | Opt-in: the side navigation (expanded, collapsed, kept after navigating, section marked on detail pages), old addresses, tabs (keyboard, no reload, Back/Forward, deep links), server and local sorting and paging, identity links from mappings, findings, and access paths to the right AD group and Back again, shared names, SID search, Deactivated wording, the dashboard's links, tablet and phone widths |
| `tests/test_ui_api.py` → `tests/ui/api.test.mjs` | `api.js`'s one resend: only a public-demo visitor's POST, only after `UNAUTHENTICATED` or `CSRF_FAILED`, only once; never a read, a signed-in principal's write, another refusal, a server error, or an unknown outcome |
| `tests/test_ui_drill.py` → `tests/ui/drill.test.mjs` | OGWA-DEMO-03: `drill.js` against real drill output (Null Meridian NM-C11 and a classic AD deletion, every scenario): dry run and execution never share wording, only a verified drill whose record agrees gets the best (info) tone, a self-contradicting or unknown result is blocked |
| `tests/browser/test_remediation_drill_ui.py` | Opt-in: NM-C11's drill by keyboard (dry run, timeout → verify → retry → verify, verification failure, unverifiable outcome), focus on the result (and on Run drill after a failed request), accessibility audit, no sideways scroll from 320 to 1920 px (NM-C11 after a drill, NM-C10, the walkthrough), a viewer cannot run it, nothing leaves the origin |
| `tests/test_review_queue_api.py` | OGWA-REVIEW-QUEUE-API-01, no browser: the server's status table equals `review.js`'s; the queue's SQL filter and order on an unknown state; counts, filters, and every status over the classic world; the served order equals `review.js queueOrder` (run under Node); sorts and paging validation; holds ending soon; reads change nothing (audit head and `total_changes`); authorization (401, 403 for a role without `READ_INVENTORY` whatever the filter); the verdict equals the candidate page's, agreement, disagreement, evidence gone stale, terminal and unavailable, and authorizes nothing; approval usability (usable, expired, new epoch, rejection, stage passed) against what the dry-run planner then does; the directory link only through exact mappings (`KB-Admins`, `WikiV1-Users`, the three `Finance-RW` groups); and a 1,100-candidate tenant: every page, no gap or repeat, final partial page, ties, filters before paging, a middle page |
| `tests/browser/test_genesee_press_ui.py` | Opt-in, the canonical hosted-gate module (OGWA-UI-REVIEW-02's probe folded in by OGWA-REVIEW-QUEUE-API-01): every page at 1280/768/320 px, the Review queue against the API (statuses, counts, no "Ready", keyboard filters), one candidate per lifecycle state, Decisions, Plans, dashboard, Find, and (tests j–m) server paging and filters of `GET /review-queue`, Evidence now beside every lifecycle state, approval usability on Decisions, and an AD group opening its candidate. Runs locally and against `UI_BROWSER_TARGET` ([../deployment/hosted-demo-fixtures.md](../deployment/hosted-demo-fixtures.md)) |
| `tests/browser/test_review_workflow.py` | Opt-in, OGWA-UI-REVIEW-01: the Review queue (statuses with their lifecycle states, priority order, a filter by keyboard keeping focus, Back), waiting apart from blocked, nothing ready, the stepper's text equivalent on four candidates, the candidate page's section order, Impact & Blockers against the API (every coverage gap says OGWA could not tell), a rejection recorded through the UI on Decisions with expiry wording, plans that never say executed or succeeded, the dashboard's attention links into the filtered queue, find by id, phone width; since OGWA-REVIEW-QUEUE-API-01 also Evidence now against the API, the server's order, counts, and sorts kept by the browser, the Decisions column, and (a Null Meridian class) the AD group → candidate link, Back, unproven mappings and shared names linking nothing |
| `tests/browser/test_operator_workflows.py` | Opt-in (`pwsh scripts/browser-check.ps1`): headless Chrome or Edge over DevTools, keyboard sign-in, every view, accessibility audit, phone width, focus visibility, reduced motion, light/dark, approval, refusal, dry run, hold, exclusion, refused revalidation, sign-out, slow and failed pages (heading, content and focus change together; a moved focus stays), opened forms on screen at laptop sizes and zoom, focus after a failed decision, no request leaves the origin, no console error or CSP violation |

The browser harness serves a fresh in-memory synthetic world (never `var/`), uses a throw-away
browser profile, and maps every host name except `127.0.0.1` to "not found". In a separate tab it
proves the page's CSP is enforced by the real browser: an HTML sink throws (Trusted Types), and
another origin's image and an inline style are refused (`img-src`, `style-src-attr`).

### The browser gate

`pwsh scripts/browser-check.ps1` stays separate from `check.ps1`, but it is a **required gate
before a pilot or a release wherever a supported browser is available** (owner decision after P09):

| Exit | Meaning |
| --- | --- |
| 0 `GATE PASSED` | Every browser test ran and passed |
| 1 `GATE FAILED` | A test failed or errored, or any test was skipped |
| 2 `GATE NOT RUN` | No supported browser (Chrome or Edge) was found; the gate is not satisfied |
