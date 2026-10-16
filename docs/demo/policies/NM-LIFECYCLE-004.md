# NM-LIFECYCLE-004: Null Meridian group lifecycle (synthetic policy)

**Synthetic.** Null Meridian is a fictional company. This policy, its versions, the people who
proposed and approved them, and every identifier in it are generated demo data. It is not a
production policy and authorizes nothing: OGWA plans dry runs only (D8), and every lifecycle step
still needs named, different human approvers.

Release files: [`config/policies/null-meridian/`](../../../config/policies/null-meridian/)
(format `ogwa-policy-release/v1`). Code: `app/domain/policy_release.py` (format, chain checks,
`PolicyRef`), `app/demo/null_meridian/policy.py` (loading and recording), `app/classification/explanation.py`
(the explanation).

## What it decides

When an Okta application group and its Active Directory counterpart may be **put to a named human**
for retirement: no sign-in through the group in 90 days, an exact identity mapping, an empty and
unnested AD group, no other application assignment, complete dependency checks, and current
evidence. Everything short of that is a reason not to act, shown as such.

## Versions

| Version | Effective (UTC) | Supersedes | What changed | Rules digest | Release digest | Recorded in the demo store as |
| --- | --- | --- | --- | --- | --- | --- |
| [1.1.0](../../../config/policies/null-meridian/NM-LIFECYCLE-004-1.1.0.json) | 2026-04-01 09:00 | none | First version recorded in OGWA. Approval evidence may be up to **14 days (336 h)** old | `sha256:d7e0e2c1…91ed` | `sha256:695d65f3…1e38` | policy version 1 (sequence 0) |
| [1.2.0](../../../config/policies/null-meridian/NM-LIFECYCLE-004-1.2.0.json) | 2026-09-28 09:00 | 1.1.0 | Approval evidence window shortened to **7 days (168 h)** | `sha256:4ee7c522…b3e5` | `sha256:45f3a32a…10a7` | policy version 2 (sequence 1), **in force** |

Nothing else differs between the two versions (a test pins that). v1.2.0's rules are exactly the
policy the Null Meridian demo always ran, so naming it moved no classification.

Each file is strict JSON: identity (`policyId`, `version`, `title`, `purpose`, `effectiveFrom`,
`supersedes`, `changes`, `synthetic`) followed by `policy`, an unchanged `ogwa-candidate-policy/v1`
document: the same format, parser, floors, and ceilings as any OGWA policy
([../../architecture/candidate-policy.md](../../architecture/candidate-policy.md)). There is no
separate rule language: the conditions below are the classifier's own, and the file supplies
their numbers.

## Conditions (as v1.2.0 states them)

The explanation shows each of these for a candidate, with its status (`SATISFIED` only when the
classifier recorded the proof, `NOT_SATISFIED` only when it recorded a contradicting fact,
`NOT_PROVEN` otherwise, `NOT_APPLICABLE` when the stage makes it moot), why, and the evidence it read.

| Condition | Proof code | Rule under v1.2.0 |
| --- | --- | --- |
| Imported from the configured AD integration | `AD_SOURCED_GROUP` | The Okta group was imported through an AD integration this policy names (1 configured). None configured means no group qualifies (fail closed). |
| AD counterpart established exactly | `EXACT_MAPPING` | The Okta group maps to exactly one AD group by a stable identifier or a reviewed selection. Name-only and unverified-identifier matches never count (D37, D39). |
| Not a protected group | `NOT_PROTECTED` | No built-in, AD (adminCount, protection from accidental deletion), or configured protection applies (0 identifiers configured as protected). |
| AD group has no members | `AD_GROUP_EMPTY` | Complete reads find no direct members, no primaryGroupID references, and no principals through member groups. An unknown member count is never zero. |
| Not nested in another AD group | `AD_NO_PARENT_GROUPS` | A complete nesting read finds the AD group in no other group. |
| No other application assignment | `SINGLE_OKTA_ASSIGNMENT` | A complete Okta check finds the group assigned to no other application. |
| Every required dependency checked, none blocking | `DEPENDENCY_COVERAGE_COMPLETE` | Complete checks by a counting source for all 8 required kinds (AAP_REFERENCE, AD_ACL_REFERENCE, AD_GROUP_MEMBERS, AD_NESTED_MEMBERSHIP, APPLICATION_CONFIGURATION, GPO_REFERENCE, OKTA_OTHER_APP_ASSIGNMENT, OKTA_POLICY_REFERENCE), and no blocking finding. Anything less keeps AD deletion prohibited. |
| Core records complete and current | `EVIDENCE_CURRENT` | The Okta group, application, assignment, usage, identity mapping, and AD group records are complete reads observed within the review window (720 h) and not dated in the future. Dependency checks are judged by coverage, above. |
| Assigned to the application (per application) | `ASSIGNMENT_PRESENT` | The group's assignment to the application is observed: it is what the proposal removes. |
| No sign-in through the group (per application) | `USAGE_WITHIN_RETIREMENT_THRESHOLD` | At most 0 sign-in(s) in the usage window. |
| Usage window long enough (per application) | `USAGE_WINDOW_COVERS_RETIREMENT` | The usage window covers at least 90 days. A shorter complete window (at least 30 days) is a review signal only (D27). |
| Next approval accepted by the lifecycle rules | (the lifecycle guard) | Every record the step reads observed within the approval window (**168 h** under v1.2.0, **336 h** under v1.1.0), the mapping exact, the approval given by a different named person and valid at most 168 h; the lifecycle guard decides. |

Beyond these, the control decision itself refuses on conflicting sources, an
unestablished identity, an unreadable required source, or insufficient evidence; the explanation
says so under "Did ambiguous or missing evidence force manual review?".

## The main scenarios under it

| Candidate | Decision (v1.2.0) | Why, in the explanation |
| --- | --- | --- |
| NM-C10 `KB-Admins` | `CONFLICTING_EVIDENCE` | Manual review **forced by the evidence**: two AD reads disagree, the identity is only probable, the nesting read failed, coverage is partial. `EXACT_MAPPING` not proven; the AD-side conditions are "not judged" (the classifier reads them only through an exact mapping). What would change it: resolve the conflict, establish the AD counterpart exactly, collect the missing checks |
| NM-C01 `Timesheets_Users` | `LIFECYCLE_RULES_NOT_MET` | Every retirement condition satisfied; only the next step's rule fails: the evidence is older than 168 h. **Under v1.1.0 the same evidence would be `ELIGIBLE_FOR_HUMAN_APPROVAL`** (336 h). What would change it: re-collect the evidence |
| NM-C08 `GG_App_Fax` (in its hold) | `NO_APPROVAL_OPEN` | Its decision history (triage, approval, dry run, hold) was judged by and **records v1.1.0**, marked Superseded; the live decision names v1.2.0. Nothing rewrites the history |
| NM-C11 `OKTA-AdAnalytics-Users` | `NO_APPROVAL_OPEN` (approved) | Triaged on 2026-09-24 under **v1.1.0**; its evidence collected again and its Okta unassignment approved on the snapshot day (2026-10-01) under **v1.2.0**, which its approval and `APPROVED` decision record. A remediation dry run or synthetic drill rests on that approval only while v1.2.0 is in force (`APPROVAL_POLICY_NOT_IN_FORCE` otherwise), and names v1.2.0, the decision, and the approval in its chain |

## Where a reviewer sees it

- **API.** `GET /api/v1/policy`: the policy in force (`name`, `policyId`, `version`, digests,
  `release`), the recorded versions with their release identity, and both release documents.
  `GET /api/v1/candidates/{id}`: `decisionExplanation` (policy, decision, conditions, manual
  review, what would change) and `evidenceAssessment.policy`. `GET .../decisions` and
  `.../approvals`: each record's `policy`, exactly as recorded, with `publishedRelease`.
- **UI.** The candidate page: "Why this decision" right after "Is this safe to act on?", and a
  "Judged by policy" column in the decision and approval history.

## Chronology

The seed's dates (UTC): v1.1.0 takes effect 2026-04-01 09:00. The inventory is collected
2026-09-24 12:00, and NM-C01 to NM-C11 are triaged from 2026-09-24 16:00 to 2026-09-25 16:10.
v1.2.0 takes effect 2026-09-28 09:00. On the snapshot day, NM-C11's evidence is collected again
at 06:00, its Okta unassignment is approved at 07:00, and `APPROVED` is recorded at 07:05. The
snapshot (`AS_OF`) is 2026-10-01 12:00.

`seed_null_meridian` ([`app/demo/null_meridian/world.py`](../../../app/demo/null_meridian/world.py))
records them in that order:

1. the inventory and correlation;
2. v1.1.0;
3. the triage of every candidate (`candidates()`);
4. v1.2.0, after a guard that refuses a release taking effect before the last seeded decision;
5. the snapshot day (`snapshot_day()`): NM-C11's re-collection, approval and `APPROVED` decision,
   judged by and recording v1.2.0;
6. each candidate's final state (`record_results()`);
7. a two-sided check, `policy_chronology_problems`: every seeded decision and approval must record
   the release whose window (its `effectiveFrom` up to the next release's) holds the record's own
   date, and none may be dated after the snapshot. The seed raises otherwise.

The guard in step 4 looks in one direction only: no release may take effect before an earlier
decision. Step 7 also refuses a record dated after a release that it does not record. That is
what goes wrong if the snapshot day is seeded before v1.2.0 is recorded: the store accepts
NM-C11's approval and decision under v1.1.0, the latest version it knows, although v1.2.0 was in
force on their date. `SeedChronologyTests` in
[`tests/test_ogwa_demo_integration.py`](../../../tests/test_ogwa_demo_integration.py) reproduces
that order (`test_the_naive_merge_order_is_refused_by_the_seed`) and checks the seeded store in
both directions.

## Why a recorded decision cannot silently change meaning

1. Each released version is a file whose release and rules digests are pinned by tests; a new
   version is a new file, never an edit.
2. The store records versions append-only, two people, audited (D32, D33, migration 0004/0005);
   a version can neither be back-dated nor repeat the current rules.
3. Every decision and approval records the exact policy reference in its audit event (hash-chained,
   same transaction), and the store refuses a decision whose reference is not the version in force.
4. History is read back as recorded. If the file now published under a recorded version differed,
   the record would say `DIFFERS_FROM_RECORDED` instead of showing the new content.
