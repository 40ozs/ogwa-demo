# Null Meridian: the canonical synthetic demo company

Null Meridian is OGWA's portfolio demo dataset: a fictional technology company with ten
years of identity history. It is part of OGWA's existing deterministic synthetic-data
architecture, seeded through the same `Store` API, lifecycle guards, correlation engine, and
audit chain as the classic 16-scenario world. It is not a separate application.

Machine-readable contract: [`null-meridian.manifest.json`](null-meridian.manifest.json)
(stable identifiers of every person, department, group, and application, group creation
dates, nesting, direct memberships, and assignments). Reviewed correlation configuration:
[`config/correlation.null-meridian.json`](../../config/correlation.null-meridian.json). Both
are generated from the seed and committed; `python -m app.demo.null_meridian check` (and a
unit test) fails if either drifts from the code.

## Synthetic-only guarantee

- Every person, name, group, application, and identifier is generated from the seed
  `null-meridian-v1`. Names are invented pairings from fixed lists
  (`app/demo/null_meridian/names.py`); nothing is derived from a tenant, a directory, an HR
  system, or production evidence.
- Application names are generic product categories ("CRM", "Team Chat"), never vendor names,
  so nothing implies the company is any vendor's customer.
- `nullmeridian.info` is the fictional company's own name. OGWA never resolves it, mails it,
  or contacts anything under it. Okta-shaped ids carry `SYNTH` (`00gSYNTHNM…`, `0oaSYNTHNM…`).
- Seeding needs no credential, runs only in `LOCAL_SYNTHETIC` mode into a `SYNTHETIC` store,
  and contacts no Okta tenant, AD domain, or AAP instance. The dataset modules import no
  network, integration, remediation, or process module (a test pins this), and a test runs
  the seed and the API with sockets, URL opening, and process creation patched to fail.
- The snapshot tables refuse inserts into any store not marked `SYNTHETIC` (migration 0012).

## Company profile

| Field | Value |
| --- | --- |
| Company | Null Meridian |
| Primary domain | `nullmeridian.info` (AD: `corp.nullmeridian.info`, NetBIOS `NMCORP`) |
| Founded | 2016-10-01 |
| Okta adopted | 2021-10-01 |
| sg-* naming standard | 2023-10-01 |
| Snapshot | 2026-10-01 (dataset "now": `2026-10-01T12:00Z`) |
| Company age | 10 years |
| Active employees | exactly 1,800 |
| Former employees | 1,009 (history only; never counted as active) |
| Technical debt | moderate |
| Seed | `null-meridian-v1` |

## Organization

| Department | Active | Formed | Notes |
| --- | ---: | --- | --- |
| Engineering | 480 | 2016-10 | 12 teams; department group nests team groups |
| Sales | 290 | 2017-04 | |
| Customer Success | 240 | 2018-01 | early members came from Sales |
| Operations | 210 | 2017-01 | |
| Marketing | 118 | 2017-06 | |
| Product | 105 | 2016-10 | |
| Data | 85 | 2020-01 | early members transferred from Engineering |
| Finance | 60 | 2017-03 | |
| Information Technology | 55 | 2018-06 | early members came from Operations |
| People / HR | 50 | 2017-09 | |
| Design | 45 | 2018-03 | |
| Security | 30 | 2020-06 | early members transferred from IT |
| Legal | 20 | 2019-02 | |
| Executive | 12 | 2016-10 | CEO, CTO, CPO (founders), CFO, CRO, GC, COO, CPeO, CMO, Chief of Staff, two EAs |

Each department has a leader (VP, Head of, Director, or CISO), directors in the large
departments, people managers (about one per eight), and individual contributors on title
ladders. Hire dates follow the growth curve (8 people in 2016 to 1,800 in 2026) with about
11% annual attrition; long-tenured and recent hires both appear. History records hires,
promotions, title changes, department transfers (including the moves when Data, Security,
IT, and Customer Success were formed), Okta activation in the 2021-10 to 2022-02 rollout
waves, terminations, and Okta deprovisioning.

Email and UPN are `firstname.lastname@nullmeridian.info`, allocated in hire order; a name
already used (by anyone, current or former) gets a numeric suffix (`jordan.lee2@…`).
sAMAccountNames follow the era: `flastname` before mid-2019, `first.last` after. Every
person, group, and application has a UUIDv5 under the seed's namespace.

## Naming eras

| Era | Dates | Conventions |
| --- | --- | --- |
| Legacy AD and shares | 2016-10 – 2019-06 | `GG_Dept_<Dept>`, `GG_App_<App>[_<Tier>]`, `<App>-Users`, `<App>_Dev`, `<Dept>-RW`, `<Dept>_Read`, `Share_<Dept>_Modify`, `GG_<Dept>_RW`, `All-Staff`, `Role_PeopleManagers` |
| Application-specific | 2019-07 – 2021-09 | `APP-<App>-Users`, `NM-<APP>-USERS`, `<App>_<Tier>`, `FS-<Dept>-R`, `Dept-<Dept>`, `eng-<team>` |
| Transitional Okta | 2021-10 – 2023-09 | `Okta_<App>_<Tier>` and `okta-<app>-<tier>s` (Okta-mastered), `OKTA-<App>-<Tier>` (AD), `okta-dept-<dept>` (Okta group rules) |
| Standard | 2023-10 – | `sg-okta-<application>-<tier>`, `sg-share-<department>-read-only|write` |

Creation dates always match the era (no `sg-*` group predates 2023-10-01; no Okta group
predates 2021-10-01), and old groups keep their old names and old modification dates.

### The standard (since 2023-10-01)

```
sg-okta-<application>-<tier>      tier: user standard power developer approver admin readonly billing
sg-share-<department>-<access>    access: read-only write
```

Slugs are lowercase words joined by hyphens (`sg-okta-status-page-admin`). A name conforms
only if it parses and its slug names a known application or department
(`app/governance/naming.py`). Applications have only the tiers they need. Of the groups
created since the standard, all but three conform; those three are flagged
`NONSTANDARD_NAME_RECENT`.

## How access grew (and scaled poorly)

When an application was standardized, its older groups were retired, nested inside the new
group (still the real source of members), kept but unassigned, or kept *and* still assigned.
The result, deliberately: department groups nested into application groups, team groups
nested into department groups, `All-Staff` nested into eighteen groups, Okta
assignment groups containing legacy AD groups, duplicate routes to the same entitlement,
unnecessary intermediates, inconsistent nesting depth (0 to 5 levels), groups without owners or
whose owner has left, and legacy groups still referenced by ACLs and a GPO. Nesting is
acyclic (the generator checks it). Model assumption: Okta flattens nested AD membership on
import, so an application assigned an AD group reaches everyone nested below it.

## Approximate object counts

| Object | Count |
| --- | ---: |
| Applications (active / inactive) | 81 (76 / 5) |
| Groups (AD / Okta-mastered / built-in) | 401 (350 / 50 / 1) |
| Groups Okta sees | 298 |
| Groups by era (legacy AD / app-specific / transitional / standard) | 122 / 55 / 61 / 163 |
| Nesting edges | 226 |
| Direct memberships | 19,462 |
| Assignments (group / individual) | 247 (186 / 61) |
| Employment and account events | 7,554 |
| Directory snapshot records in the store | 31,270 |

Exact, current values: `python -m app.demo.null_meridian summary` and the manifest's `counts`.

## Correlation cases

Each Okta-visible group is correlated by the real engine over the synthetic AD directory.
The dataset states the expected outcome and seeding stops if the engine proves anything else.

| Case | Engine result | Groups | Example |
| --- | --- | ---: | --- |
| Exact (configured, standard name) | `EXACT_CONFIGURED_MAPPING` | 123 | `sg-okta-crm-user` |
| Legacy-name exact | `EXACT_CONFIGURED_MAPPING` | 72 | `GG_App_Wiki` |
| Normalized exact (case differs between Okta and AD) | `EXACT_CONFIGURED_MAPPING` | 4 | `SG-OKTA-VPN-USER` / `sg-okta-vpn-user` |
| Old AD group mapped to a newer Okta group (Group Push) | `EXACT_CONFIGURED_MAPPING` | 2 | `sg-okta-payroll-user` → `GG_App_Payroll` |
| Directory-source SID only (not yet reviewed) | `UNVERIFIED_STABLE_ID` | 42 | `sg-okta-etl-developer` |
| Name-only | `NAME_ONLY` | 7 | `WikiV1-Users` |
| Multiple plausible matches | `AMBIGUOUS` | 3 | Okta `Finance-RW` vs two AD `Finance-RW` objects |
| No match (Okta-mastered, no AD counterpart) | `NOT_FOUND` | 43 | `Okta_CRM_Users` |
| Configured counterpart deleted | `NOT_FOUND` | 1 | `Okta_Fax_Users` |
| Built-in | `NOT_FOUND` | 1 | `Everyone` |

Deprecated groups paired with their replacement: every `replacedBy` link in the manifest
(for example `CRM-Sales` → `sg-okta-crm-user`, `Finance-RW` (archived) → `Finance-RW`).

## Governance findings

`app/governance/analysis.py` derives findings from the snapshot; each rule has one code,
one severity, and a recommendation. Counting groups and applications together, about 72%
have no finding beyond context, 19% are mildly questionable, and 8% clearly actionable
(a test holds these to 70–80 / 15–20 / 5–10).

## Lifecycle candidates

| Key | Group | Final state | Why |
| --- | --- | --- | --- |
| NM-C01 | `Timesheets_Users` | `NEEDS_REVIEW` | Clean remediation candidate: retired app, empty, exact, complete coverage |
| NM-C02 | `sg-okta-status-page-admin` | `NEEDS_REVIEW` | Empty group still assigned; no group-attributed use |
| NM-C03 | `CRM-Sales` | `DEPENDENCY_BLOCKED` | Deprecated but hundreds still reach CRM through it |
| NM-C04 | `Finance-RW` (Okta copy) | `MAPPING_AMBIGUOUS` | Two AD objects share the name |
| NM-C05 | `Print-Users` | `DEPENDENCY_BLOCKED` | Still in a file-share ACL and a GPO's filtering |
| NM-C06 | `WikiV1-Users` | `NEEDS_REVIEW` | Name-only mapping: the approval is refused and audited |
| NM-C07 | `Okta_Fax_Users` | `BLOCKED` | Its configured AD counterpart was deleted |
| NM-C08 | `GG_App_Fax` | `HOLD` | Approved, dry run succeeded, unassignment observed |
| NM-C09 | `CloudLegacy_Admins` | `PROTECTED` | adminCount and deletion protection still set |
| NM-C10 | `KB-Admins` | `NEEDS_REVIEW` | Conflicting and incomplete evidence: OGWA refuses every control decision (OGWA-DEMO-01) |
| NM-C11 | `OKTA-AdAnalytics-Users` | `APPROVED` | Empty, unused group of an application used through direct assignments; evidence re-collected on the snapshot day and the Okta unassignment approved: the remediation drill's candidate (OGWA-DEMO-03) |

Every candidate page opens with the **evidence assessment** (OGWA-DEMO-01,
[`app/classification/assessment.py`](../../app/classification/assessment.py)): each source's state,
the identity mapping's state, any conflict between sources, the decision OGWA can safely make, and
the evidence it would need to go further. See
[../agent-runs/OGWA-DEMO-01.md](../agent-runs/OGWA-DEMO-01.md).

### NM-C10: conflicting and incomplete evidence

`KB-Admins` (Knowledge Base administrators) has had no sign-in attributed to it in 90 days, so it
looks like an easy clean-up. Its evidence, all synthetic and all recorded through the normal store
API, says otherwise:

| Source | What it says | Evidence state |
| --- | --- | --- |
| Okta group, Knowledge Base application (ACTIVE), the assignment | They exist | `CONFIRMED` |
| Group-attributed System Log usage (90 days) | 0 sign-ins | `REPORTS_NONE` |
| Other Okta assignments; Okta policy references | None (complete checks) | `REPORTS_NONE` |
| Identity mapping | `UNVERIFIED_STABLE_ID`: Okta's directory SID resolves to one AD group, mechanism unverified (D37) | `AMBIGUOUS` (identity `PROBABLE`) |
| AD group object (14:00) vs AD membership read (16:00) | 2 member values vs none | `CONFLICTING` (both) |
| AD nesting read | Timed out (collector run `FAILED`, `TIMEOUT`) | `SOURCE_UNAVAILABLE` |
| AD ACL scan | Stopped after 3 of 7 shares (`PAGING_INTERRUPTED`) | `PARTIAL` |
| GPO, AAP, application-configuration checks | Never run; the group has no owner to attest them | `NOT_COLLECTED` |

The correlation engine proves the mapping, the lifecycle guards move the candidate to
`NEEDS_REVIEW`, and the evidence assessment's decision is `CONFLICTING_EVIDENCE`, with
`AMBIGUOUS_IDENTITY`, `BLOCKED_ON_REQUIRED_SOURCE`, and `INSUFFICIENT_EVIDENCE` also listed. An
Okta-stage approval is refused by the lifecycle (the mapping is not exact), and a test proves it.

### The policy each decision names (OGWA-DEMO-02)

Every candidate is judged by Null Meridian's synthetic lifecycle policy,
**[NM-LIFECYCLE-004](policies/NM-LIFECYCLE-004.md)**. The seed records two versions through the
store's real, append-only policy chain: **v1.1.0** (effective 2026-04-01; approval evidence up to
14 days old) before the candidates are triaged on 2026-09-24/25, so every triage decision and
approval records v1.1.0; then **v1.2.0** (effective 2026-09-28; 7 days), the policy in force for
the live demo. The snapshot day (2026-10-01) is seeded after v1.2.0 is recorded, so NM-C11's
approval and its `APPROVED` decision record v1.2.0 (OGWA-DEMO-04); the seed refuses any decision
or approval that does not record the release in force on its own date. The candidate page's "Why this decision" names v1.2.0, lists each condition as it
states it, and says whether evidence forced manual review; the decision and approval history
shows v1.1.0, marked Superseded. Under v1.2.0 NM-C01's week-old evidence is too old for an
approval (`LIFECYCLE_RULES_NOT_MET`); under v1.1.0 the same evidence would be eligible for a named
human's approval.

### NM-C11: a remediation drill

Null Meridian's inventory evidence is a collection taken a week before the snapshot, past the
remediation gates' 24-hour EXECUTION window at the demo's clock, so no other candidate can be
dry-run or drilled without collecting its evidence again. `OKTA-AdAnalytics-Users` is the access
group of Ad Analytics, whose users are all assigned directly: the group is empty, saw no sign-in in
90 days, and is mapped exactly (configured objectGUID and objectSid). It is reviewed like NM-C02;
then every record of its evidence is collected again at 06:00 on the snapshot day, facts unchanged
(the correlation engine proves the mapping again, D75), and `synthetic.reviewer.one` approves the
Okta unassignment at 07:00, judged under NM-LIFECYCLE-004 v1.2.0. Nothing is dry-run or executed
in the seed.

At the demo's clock every remediation gate can pass for an executor who did not approve it. On the
candidate page, **Remediation: dry run or synthetic drill** runs a dry run or a scripted synthetic
execution (a timeout, a verification read, one safe retry, a post-action read) against an in-memory
provider fixture, and records nothing: the candidate stays `APPROVED`. See
[../architecture/remediation-execution.md](../architecture/remediation-execution.md). A demo process
left running for more than about a day lets this evidence age past the 24-hour window, as it would
in production; a reset (or a fresh hosted isolate) starts the clock again.

## Portfolio scenarios

1. **Healthy modern application:** Observability Platform.
2. **Legacy application with transitional groups:** Expense Management.
3. **Empty group still linked to an application:** `sg-okta-status-page-admin` (NM-C02).
4. **Direct assignments bypassing group governance:** CRM (23 people) and Board Portal.
5. **Duplicate and overlapping access paths:** CRM user access through up to three groups plus an individual assignment.
6. **Ambiguous legacy-to-modern correlation:** Okta `Finance-RW` (NM-C04).
7. **Clean remediation candidate:** `Timesheets_Users` (NM-C01).
8. **Unnecessarily deep hierarchy:** `sg-okta-warehouse-readonly` › `OKTA-Warehouse-Readers` › `GG_Analytics_Users` › `Dept-Data` › data team groups.
9. **Conflicting and incomplete evidence:** `KB-Admins` (NM-C10): what OGWA can and cannot conclude when sources disagree, fail, or were never read.
10. **A remediation drill:** `OKTA-AdAnalytics-Users` (NM-C11): dry run versus synthetic execution, an uncertain outcome, verification before a retry, a safe retry, and post-action verification.

The console's **Portfolio scenarios** page links each to its groups, applications, and candidate.

### Reviewer walkthrough and audit sample (OGWA-DEMO-04)

The **Portfolio scenarios** page opens with a five-minute **reviewer walkthrough** (the dashboard
links to it): its disclosures first (all data synthetic; nothing external contacted; the drill's
fixture discarded after each answer; failure injection deterministic), then two parts.

1. **Data quality, NM-C10.** "Is this safe to act on?" reads "No action: sources disagree";
   the conflicting, unavailable, partial, and never-collected evidence; a "Probable, not proven"
   identity; "Why this decision" under NM-LIFECYCLE-004 v1.2.0, with the exact mapping and the AD
   conditions *not proven* (never satisfied or failed); manual review forced by evidence; no
   approval and so no remediation.
2. **Controlled remediation, NM-C11.** Fresh evidence; the triage under v1.1.0 and the
   snapshot-day approval and `APPROVED` decision under v1.2.0; a dry run (DRY RUN — NO STATE
   CHANGED); then a SYNTHETIC EXECUTION ("No external provider or persistent environment was
   modified.") under *Timeout, change not applied*: OUTCOME UNKNOWN — VERIFYING, verified not
   applied, RETRY PERMITTED, the retry with the same operation id, POST-ACTION VERIFIED; and,
   under **Authorized by**, the policy version, the decision, the approval, and the operation id.

The text lives with the dataset (`app/demo/null_meridian/walkthrough.py`) and is served with the
scenarios (`GET /demo-scenarios` → `walkthrough`). The same chain, as the API serializes it, is
in the generated, sanitized sample
[samples/ogwa-audit-sample.json](samples/ogwa-audit-sample.json)
(`python -m app.demo.null_meridian.audit_sample --write`; a test fails if it drifts by a byte).

## Running it

Null Meridian is the dataset; [Demo Mode](../demo-mode.md) is the runtime and safety boundary
that serves it. Null Meridian is Demo Mode's default dataset, selected as `null-meridian`
in the dataset registry (`app/demo/datasets.py`) and identified in every store by its seed
namespace `null-meridian-v1`.

**In Demo Mode (the canonical way to show it):**

```text
export OGWA_RUNTIME_MODE=demo                                      # Null Meridian is the default dataset
python -m app.runtime reset-demo --confirm-synthetic-reset         # reseed var/ogwa-demo.sqlite3, validated
python -m app.runtime verify                                       # re-validate (dataset identity + integrity)
python -m app.api serve                                            # http://127.0.0.1:8765/, DEMO ENVIRONMENT
```

**As a developer, under the standard runtime** (the local synthetic store,
`var/ogwa-local.sqlite3`; this command refuses under `OGWA_RUNTIME_MODE=demo`):

```text
python -m app.store reset-demo --confirm-synthetic-reset                       # Null Meridian (the default)
python -m app.store reset-demo --confirm-synthetic-reset --dataset classic     # the 16-scenario lifecycle world
python -m app.api serve --demo-clock                                           # http://127.0.0.1:8765/
```

**The dataset itself:**

```text
python -m app.demo.null_meridian check|write|summary                           # the committed manifest and configuration
```

Both resets run the same guarded reset (`app.store.reset.reset_synthetic_store`) and the
same seed (`app.demo.null_meridian.world.create_null_meridian_store`). The dataset is chosen
when the store is seeded (`OGWA_DEMO_DATASET` in Demo Mode, `--dataset` for the developer
reset). Nothing at runtime switches it, and no browser control or API route can switch a
running deployment between demo and production. A reset is deterministic: a fresh Null
Meridian store by this build always has audit head
`sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41` (a test pins it),
whichever command made it.
