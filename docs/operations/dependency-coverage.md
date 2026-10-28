# Dependency coverage: what OGWA can and cannot check

Status: P07, 2026-10-05. This page lists which dependency domains OGWA actually covers.
It is the operator-facing companion to `PRODUCTION_COLLECTORS` in
`app/classification/coverage.py`. A test pins that table, so it and this page change
together, by review.

## The rule

> If dependency coverage is not exactly `COMPLETE`, AD deletion stays prohibited.

Coverage is `COMPLETE` only when **every required dependency kind** has a COMPLETE check
from a counting source (Okta API, Okta System Log, AD via AAP, or synthetic in tests). It
is computed by `assess_dependency_coverage`, the same function the lifecycle uses before
an AD retirement dry run. The classifier, the lifecycle guard, and this page all use one
definition.

The following never count toward coverage, but their blocking findings still block:

- a check that came back PARTIAL or FAILED;
- an operator attestation (D13);
- a check that was never run.

When coverage is incomplete, the classifier holds the relationship at `INACTIVE_REVIEW` or
`LOW_USAGE_REVIEW` with reason `DEPENDENCY_COVERAGE_INCOMPLETE`, which names the uncovered
kinds. It never lowers the bar to produce a candidate.

## Required kinds

The default policy requires every kind except `OTHER`. A policy may add `OTHER`. It can
never drop the four mandatory kinds (`OKTA_OTHER_APP_ASSIGNMENT`, `OKTA_POLICY_REFERENCE`,
`AD_GROUP_MEMBERS`, `AD_NESTED_MEMBERSHIP`); `LifecyclePolicy` refuses that.

## Coverage today, by domain

| Kind | What it means | OGWA collector | Covered from production today? |
| --- | --- | --- | --- |
| `AD_GROUP_MEMBERS` | Direct members and primaryGroupID references of the AD group | `OGWA.ADReader` worker (P05), run by a read-only AAP job | **No.** There is no AAP transport yet, and live results stay PARTIAL until P11 verifies the D19 behaviors (deletion-protection readability always; cross-domain parent lookup in multi-domain forests; completeness for groups of 1500+ members) |
| `AD_NESTED_MEMBERSHIP` | Parent groups, member groups, principals reached through nesting | same worker | **No**, for the same reasons |
| `OKTA_OTHER_APP_ASSIGNMENT` | The Okta group is assigned to other applications | none. P04 lists one application's groups, not one group's applications | **No.** A reverse listing (Okta's group "assigned apps" endpoint; confirm its scope against the D28 read-only set before use) or a complete per-app sweep is needed |
| `OKTA_POLICY_REFERENCE` | Sign-on, MFA, and password policies, group rules, and admin role assignments that name the group | none | **No.** Needs policy and group-rule reads; P04 requested no scope for them |
| `AD_ACL_REFERENCE` | File-share, OU-delegation, and other ACEs that name the group's SID | none | **No.** Needs an ACL inventory (file servers, AD delegation); out of OGWA's current reach |
| `GPO_REFERENCE` | Security filtering, Restricted Groups, Group Policy Preferences | none | **No.** Needs a read-only GPO report collector |
| `AAP_REFERENCE` | AAP inventories, RBAC teams, surveys, and credentials that name the group | none | **No.** Needs a read-only AAP API collector |
| `APPLICATION_CONFIGURATION` | Application-side configuration that names the group (local roles, SAML attribute mappings, ...) | none | **No.** Per-application; likely an owner attestation plus app-owner review, which never counts toward coverage (D13) |
| `OTHER` | Anything else | none | Not required by default |

**Result:** no production Okta group / application relationship can become a
`RETIREMENT_CANDIDATE` today. Every one stops at a review tier or earlier. This is the
intended fail-closed state, not a defect.

## What changes coverage

A kind becomes coverable from production only when **all** of the following hold:

1. A read-only collector exists that emits `DependencyEvidence` of that kind, with
   COMPLETE provenance only when the whole scope was read (E-2).
2. It runs under an approved least-privilege identity (D6, D18, D28), and its run report
   records which systems it contacted.
3. Its live behavior is verified against a known object and recorded in a run report.
   For the AD kinds, that means P11 adding entries to `VERIFIED_LIVE_BEHAVIORS` (D19).
4. `PRODUCTION_COLLECTORS` is updated by a reviewed change. Its test pins the current state.

Until every **required** kind meets those conditions, AD deletion stays prohibited,
whatever the classifier says about anything else.

## Reading a coverage report

`ClassificationResult.coverage.to_dict()` lists every kind with:

| Field | Meaning |
| --- | --- |
| `required` | whether the active policy requires it |
| `status` | `COVERED`, `NOT_DECISION_GRADE` (checked, but PARTIAL/FAILED), `NOT_COUNTED_SOURCE` (checked only by a source that never counts, such as an attestation), or `NOT_CHECKED` |
| `productionCollector` / `productionCollectorLiveVerified` | from the table above |

`overall` is `COMPLETE`, `PARTIAL` (some required kinds covered), or `UNKNOWN` (none).

## Operator guidance

- Treat `DEPENDENCY_COVERAGE_INCOMPLETE` as **hold**. Do not approve AD retirement on the
  strength of a manual check: an attestation is recorded and can block, but it cannot
  complete coverage.
- A blocking finding from any source, including an attestation, stops the candidate
  (`DEPENDENCY_BLOCKED`, `HAS_MEMBERS`, `NESTED_DEPENDENCY`, or `SHARED_OKTA_ASSIGNMENT`).
- Okta unassignment (the first lifecycle step) still requires the lifecycle's own guards,
  approvals, and dry run. The classifier's review tiers are prompts for human
  investigation, not approvals.
