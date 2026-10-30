# Hosted demo fixture contract (Genesee Press)

What the hosted browser gate (the `UI_BROWSER_TARGET` run in [cloudflare-demo.md](cloudflare-demo.md),
"Validation") relies on in the data the Worker serves, and what it deliberately does not assert. The hosted
demo has served the **Genesee Press** synthetic dataset (`OGWA_DEMO_DATASET=genesee-press`, D1 `ogwa-demo-3`)
since 2026-10-29. All of it is synthetic.

The rule: the gate tests product behaviour. Where it needs a canonical object it finds it by a stable key at
run time; where it needs a number it reads the API's own figure. A fixture value is asserted only when the
value itself is the point (the dataset's identity, the walkthrough's lesson), and every such value is listed
below. A synthetic rebuild that keeps these expectations must not break the gate; one that breaks them must
update this page and the gate together.

## How the gate finds the canonical objects

`tests/browser/harness.py` `target_demo()` asks the target, as its anonymous visitor and with GETs only:

- `GET /api/v1/health`: `publicDemo` must be true; `dataset.key` names the dataset (`genesee-press`).
- `GET /api/v1/session`: the visitor's session cookie (nothing else is used).
- `GET /api/v1/demo-scenarios`: each portfolio scenario's `candidateId` by `candidateKey`, and the walkthrough's
  parts by `key`.

Modules address the two walkthrough candidates by **walkthrough part** (`BrowserCase.part`), never by a
hard-coded id or a dataset-specific key:

| Part key | Scenario key (Genesee Press) | What it is for |
| --- | --- | --- |
| `data-quality` | `GP-C10` | conflicting and incomplete evidence: no safe decision, nothing can be approved or drilled |
| `controlled-remediation` (`publicDrill: true`) | `GP-C11` | approved under the policy in force; the one candidate a public visitor may drill |

A module that asserts only product behaviour passes `any_dataset=True` to its server and runs against any
demo dataset; any other module skips, with the reason, unless the target serves its dataset.

## Stable expectations (asserted)

**Dataset identity** (`test_genesee_press_ui`): the demo indicator says "deterministic synthetic data for
Genesee Press." and "Domain geneseepress.example, snapshot 2026-10-01, seed genesee-press-v1."; the dashboard's
walkthrough entry names GP-C10 and GP-C11; the scenarios page names Genesee Press and GP-LIFECYCLE-004 v1.2.0;
no page shows a Null Meridian value (`Null Meridian`, `nullmeridian`, `NM-C..`, `NM-LIFECYCLE`, `sg-okta-`).

**The data-quality candidate (GP-C10)**: decision "No action: sources disagree"; mapping "Probable, not
proven"; at least one condition "Not proven"; evidence includes "Source unavailable" and "Not collected"; the
reviewer's six questions; "Why this decision" names the policy version that ran (GP-LIFECYCLE-004 v1.2.0);
never "Eligible for a named human" or "Rules would accept"; no "Run drill"; its review status reads "Needs
review"; an approval, a hold, or a drill on it is refused (403 `DEMO_READ_ONLY` / `PUBLIC_DRILL_SCOPE`).

**The controlled-remediation candidate (GP-C11)**: state APPROVED (review status "In progress …"), with an
approval; judged by `<prefix>-LIFECYCLE-004 v1.2.0, recorded version 2` (any dataset prefix in the
dataset-neutral modules), its decision history NEEDS_REVIEW → APPROVED. The synthetic drill's scripted
scenarios (`TIMEOUT_NOT_APPLIED`: 7 steps, "2 submissions, 1 change applied", one operation id, POST-ACTION
VERIFIED; `ACKNOWLEDGED_NOT_APPLIED`: VERIFICATION FAILED; `TIMEOUT_UNVERIFIABLE`: RETRY NOT PERMITTED) are
product behaviour, not data. After any drill the candidate is still Approved, "No dry run has been planned.",
and the dashboard's audit event count and head are unchanged (`test_hosted_demo_ui` `assert_canonical`).

**Lifecycle states present**: at least one `DEPENDENCY_BLOCKED` and one `HOLD` candidate, the HOLD one with an
approval or rejection, decision history, and (for a reader with audit access) audit events
(`test_candidate_tables`).

**Directory shape** (`test_ui_ia`): more than 100 people (two full pages), between 51 and 4,999 directory
groups, more than 25 directory applications, a Finance department with active people, people deactivated
with a date, a search for `finance-rw` (source AD) that finds exactly two groups told apart by their
qualifiers, an `All-Staff` group findable by its objectSid, identity mappings to AD groups, a governance
finding that links an AD group, and the dashboard's "Deactivations per year" chart.

**Review semantics** (`test_genesee_press_ui`): each lifecycle state reads as one review status by the
OGWA-UI-REVIEW-02 table (independent of `js/review.js`; an unknown state reads Blocked); the queue's filter
counts and the All caption equal that table applied to the states `GET /candidates` returns; every row keeps
"Lifecycle: …"; no "Ready" anywhere on the queue or a candidate headline; a hold is in the Waiting queue,
named on its page, and never among Decisions; Decisions lists only "Approved for future action" and
"Rejected", expiry in words.

**Links resolve**: every navigation entry, direct links into candidate, scenario, directory, findings, groups,
review, and decision pages, the dashboard's attention links, governance → AD group page, Okta group page →
its candidates, Find by id → the candidate (through `GET /identities` first).

**Read-only**: on the public demo nothing writes, except a module's deliberate writes (`deliberate_writes`):
`test_hosted_demo_ui`'s refused approval and hold and refused borrowed or forged drill grants (each asserted
refused, and the audit count and head asserted unchanged) and the synthetic drill, which records nothing.
`assert_clean` fails on any other POST, PUT, PATCH, or DELETE, in every hosted module.

## Deliberately not asserted

| Not asserted | Why |
| --- | --- |
| Candidate, group, application, person ids | they change on a synthetic rebuild; ids come from `GET /demo-scenarios` or are followed from links |
| Row counts: people (2,440), directory groups (560), directory applications (81), candidates (11) | incidental; the pager and filters are checked against the API's own `page.total` / counts |
| Per-status counts (Needs review 4, Blocked 4, Waiting 1, In progress 1, Closed 1) | derived at run time from the API's lifecycle states |
| Active employees (1,800) | read from `GET /directory` `counts.activeEmployees`, then looked for on the page |
| Number of decisions (3), "Superseded" badges (2), relative expiry values ("6 days remaining") | incidental, and expiry depends on the clock; only the allowed decision words and the expiry form are checked |
| Impact & Blockers counts ("Not established" 2, "None found" 88), governance rule cells (75), charts (7), dashboard queue rows (5) | incidental; only that the words are used, codes are secondary, charts render, and the queue head shows 1–5 rows |
| Audit event count and head values (1,617, `sha256:f11f0a99…`) | release evidence, checked by `scripts/hosted_smoke.py`; the gate asserts only that they do not change |
| Specific people (`GP-00001`, "Morgan") | "Morgan" is only a string that is not an id; no person is looked up by name |
| The >1,000-candidate queue warning | not reachable with this dataset; covered by unit tests |

## Assertion audit (OGWA-REVIEW-QUEUE-API-01)

Every dataset-specific assertion in the hosted-target modules, and the hosted UI probe of OGWA-UI-REVIEW-02,
classified as behaviour or fixture content.

| Module | Assertion (before) | Kind | Decision |
| --- | --- | --- | --- |
| harness | candidate ids from this build's Null Meridian seed under `UI_BROWSER_TARGET` | fixture | removed: read from the target's `GET /demo-scenarios` |
| harness | target assumed to serve Null Meridian; other modules skip | fixture | removed: dataset read from `GET /health`; skip only for dataset-specific modules |
| `test_hosted_demo_ui` | `scenarios.find(NM-C10 / NM-C11)` in links, pages, refusals, drills (8 tests) | fixture (key) | behaviour: walkthrough part `data-quality` / `controlled-remediation` |
| `test_hosted_demo_ui` | `state()` reads NM-C10 and NM-C11 | fixture (key) | behaviour: the walkthrough parts' candidates from the API |
| `test_hosted_demo_ui` | "Active employees\n1800" | fixture (count) | behaviour: equals `GET /directory` `counts.activeEmployees` |
| `test_hosted_demo_ui` | "NM-LIFECYCLE-004 v1.2.0" (E), "…, recorded version 2" (F) | fixture | updated: `[A-Z]+-LIFECYCLE-004 v1.2.0`; the exact GP name is pinned in `test_genesee_press_ui` |
| `test_hosted_demo_ui` | data-quality facts ("No action: sources disagree", "Probable, not proven", "Not proven", "Source unavailable"), "Needs review" after a refused write | fixture (canonical lesson) | kept: the walkthrough's stated lesson, same in both datasets |
| `test_hosted_demo_ui` | indicator and account wording, refusal codes, drill steps and banners, "No dry run has been planned.", headers, CSP | behaviour | kept |
| `test_remediation_drill_ui` | `scenarios['NM-C11']` / `['NM-C10']` (7 tests) | fixture (key) | behaviour: walkthrough parts |
| `test_remediation_drill_ui` | "NM-LIFECYCLE-004 v1.2.0, recorded version 2" | fixture | updated: `[A-Z]+-LIFECYCLE-004 v1.2.0, recorded version 2` |
| `test_remediation_drill_ui` | walkthrough links "Open NM-C10" / "Open NM-C11" with their ids | fixture | behaviour: "Open <part's key>" → that part's candidate |
| `test_remediation_drill_ui` | walkthrough title, disclosures, part titles | behaviour (product text) | kept |
| `test_remediation_drill_ui` | `test_f` (a viewer cannot drill) on the public demo | n/a | skipped with reason (the public visitor may drill; isolation is `test_hosted_demo_ui` E) |
| `test_ui_ia` | "Rows 1–50 of 2809", "Rows 51–100 of 2809" | fixture (count) | behaviour: `GET /people` `page.total` |
| `test_ui_ia` | cursor `bzo0MDA`, "Rows 401–401 of 401" | fixture (count) | behaviour: last page computed from `GET /directory-groups` `page.total` |
| `test_ui_ia` | "Rows 1–25 of 81", 3 × Next, "Rows 76–81 of 81" | fixture (count) | behaviour: from the `GET /directory` application count |
| `test_ui_ia` | "1,800\nActive employees" | fixture (count) | behaviour: `GET /directory` `counts.activeEmployees` |
| `test_ui_ia` | `department=finance`, `finance-rw` → 2 qualifiers, `all-staff` → "All-Staff" | fixture | kept, documented above (both datasets have them) |
| `test_ui_ia` | navigation, tabs, old addresses, KPI and bar labels, sorting, paging, wording | behaviour | kept |
| `test_candidate_tables` | a DEPENDENCY_BLOCKED and a HOLD candidate exist; class named Null Meridian | fixture (state) | kept, documented; class renamed `DemoCandidateTablesTests`, runs on any dataset |
| `test_candidate_tables` | `PagedCandidateTableTests` (classic S11) | fixture | skipped with reason on any hosted target (unchanged) |
| `test_demo_null_meridian_ui` | NM indicator text, "Null Meridian is fictional.", `nm00001` / Ian Gupta, `sg-okta-warehouse-readonly` DEEP_NESTING, 1800 | fixture (Null Meridian) | skipped with reason unless the target serves Null Meridian; Genesee coverage: `test_genesee_press_ui` a, b, j |
| `test_null_meridian_views` | NM scenario titles, NM-C08 / NM-C10, nullmeridian.info, NM-LIFECYCLE, 1800 | fixture (Null Meridian) | skipped with reason unless the target serves Null Meridian; Genesee coverage: `test_genesee_press_ui` c, f and `test_ui_ia` |
| `test_genesee_press_ui` | Genesee indicator, domain, seed, GP-C10/GP-C11, GP-LIFECYCLE-004 v1.2.0, no NM value | fixture (dataset identity) | kept: the point of the module; now runs on a Genesee target |
| probe → `test_genesee_press_ui` | 11 candidates; Needs review 4, Blocked 4, Waiting 1, In progress 1, Closed 1; Open 10, All 11 | fixture (count) | behaviour: derived from `GET /candidates` by the status table |
| probe → `test_genesee_press_ui` | queue rows, "Lifecycle:", no "Ready", keyboard filters keep focus, holds Waiting | behaviour | folded in (test_d) |
| probe → `test_genesee_press_ui` | every candidate page: status first, section order, 10-stage stepper, forensic sections, a11y | behaviour | folded in, one candidate per lifecycle state (test_e) |
| probe → `test_genesee_press_ui` | 16 pages at 1280 / 768 / 320 px, a11y at 1280 | behaviour | folded in (test_c) |
| probe → `test_genesee_press_ui` | Impact & Blockers 2 / 88, governance 75 cells, Decisions 3 rows, "6 days / 4 hours remaining", Superseded × 2, 7 charts, 5 queue rows | fixture (count) | removed as counts; the words and forms are asserted (test_g, test_h) |
| probe → `test_genesee_press_ui` | Find by id via `/identities`, name not matched locally, server-side `q=` searches | behaviour | folded in (test_i) |
| probe → `test_ui_ia` | grouped navigation, 375 px menu toggle | behaviour | already covered by `test_ui_ia` a and k, which now run on Genesee |
| probe | no write request | behaviour | folded into `assert_clean` for every hosted module |

## Checks for OGWA-REVIEW-QUEUE-API-01's features

`tests/browser/test_genesee_press_ui.py` tests j–m (deployed and passing against workers.dev, Worker
`75ef55ef`): `GET /review-queue` paged in small pages equals one large page, per-status totals equal its
`counts`, the UI's caption and pager agree with `page.total`, and the browser keeps the server's order;
"Evidence now" beside every row's "Lifecycle: …", agreeing with the row's `evidenceVerdict`; Decisions'
"Approval rules now" on every approval row, "Valid for its stage" exactly where `usability.usable`; an AD
group found through an exact identity mapping (from the API, never by name) opens its candidate. Each asserts
behaviour against the target's own API, not fixture counts.

## Checks for OGWA-APPROVAL-ATTENTION-01's features

`tests/browser/test_genesee_press_ui.py` test n: the dashboard's "approvals expiring soon" item is
present exactly when the target's `GET /approvals?usability=expiring-soon` counts one (and then starts
with that count), otherwise absent (the zero state); the Decisions filters' labels equal the response's
`counts`; the "Expiring soon" listing has the API's rows, or says "No valid approval expires within 48
hours."; nothing is worded Ready, Executable, or Approved to delete. Behaviour against the target's own
API, no fixture count.

**Fixture fact, not asserted:** the hosted Genesee Press store's clock is fixed at
`2026-10-01T14:20:50Z`, and its one valid approval (GP-C11's Okta approval) expires
`2026-10-08T07:00:00Z`, about 6.7 days later, so with the 48-hour window the hosted demo shows the zero
state. The expiring case is covered locally (`test_review_workflow.ApprovalAttentionTests`, a synthetic
world whose clock is moved on); D1 is never changed to manufacture one.
