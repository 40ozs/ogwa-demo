# Reviewer walkthrough (about five minutes)

Two synthetic candidates, two lessons. **NM-C10:** when the evidence is not good enough, OGWA
refuses to act and says why. **NM-C11:** when the evidence is good enough, an action is a
controlled, verified state transition, never a button click.

The app shows the same steps on its **Portfolio scenarios** page. Their source is
[`app/demo/null_meridian/walkthrough.py`](../../app/demo/null_meridian/walkthrough.py). This page
adds what each step proves and where the proof lives.

## Before you start

- **Open the demo.** Use the live demo at <https://ogwa-demo.d-walkes.workers.dev>, or run it
  locally with `docker compose up --build` and open <http://localhost:8765>. To run it without
  Docker, see [README: Local development without Docker](../../README.md#local-development-without-docker).
- **Who you are.** The live demo has no sign-in: every visitor is the same anonymous, read-only
  synthetic viewer. Locally, sign in as `synthetic.executor.one`, with no password. Sign-in is
  synthetic, and every principal is listed in [`config/synthetic-idp.json`](../../config/synthetic-idp.json).
- **Find the steps in the app.** On the dashboard, choose **Start the five-minute reviewer
  walkthrough** (`#/scenarios`).
- **All data is synthetic.** Null Meridian is a fictional company. No Okta tenant, Active
  Directory, AAP, or HR system is contacted, and the demo holds no integration credential.
- **The live demo is read-only.** A request that would record something gets
  `403 DEMO_READ_ONLY`. NM-C11's remediation drill still runs, because it records nothing. It
  works on an in-memory fixture that is discarded after each answer. Every step below works on
  the live demo except the one marked *local only*.

## Part 1: NM-C10, why OGWA refuses to act

NM-C10 (`KB-Admins`) holds conflicting and incomplete evidence. Its identity mapping is not
proven. OGWA therefore holds it for manual review and offers no remediation.

```text
conflicting / incomplete evidence → mapping not proven → conditions "Not proven" → manual review → no remediation
```

| # | Do this | You should see |
| --- | --- | --- |
| 1 | Open **NM-C10** from the walkthrough. | The candidate page, state `NEEDS_REVIEW`. |
| 2 | Read **Is this safe to act on?** | The decision is "No action: sources disagree" (`CONFLICTING_EVIDENCE`). |
| 3 | Under question 3, find the conflict. | The AD group object lists 2 member values, but the membership read found none. Both observations are shown as **Conflicting**, and neither is resolved in favour of the other. |
| 4 | Find the other evidence states. | The nesting read is **Source unavailable**, the ACL scan is a **Partial read**, and the AAP, GPO and application-configuration checks are **Not collected**. Sign-in usage is **Source says none**: a complete read that found nothing, which is a different state from "never read". |
| 5 | Under question 4, check the identity mapping. | **Probable, not proven.** An unverified directory SID corroborates the match but cannot establish it. |
| 6 | Open **Why this decision**. | The policy is **NM-LIFECYCLE-004 v1.2.0**, the exact version in force, with its rules digest. |
| 7 | Read the conditions table. | The exact-mapping, protection, emptiness, nesting and dependency conditions are **Not proven**. They are not marked satisfied, and they are not marked failed. |
| 8 | Read the manual-review answer. | "Did ambiguous or missing evidence force manual review?" is **Yes**. The answer lists what would change the outcome: resolve the conflict, establish the AD counterpart, and collect the missing checks. |
| 9 | Look for a remediation section. | **There is none.** The candidate has no approval, and the lifecycle refuses one while the mapping is not exact. |

**What this shows.** OGWA treats uncertainty as a control state of its own. It never turns
missing information into permission to act. Not collected, unavailable, partial, conflicting
and "says none" stay distinct all the way from evidence to decision.

**Behind the UI.** The page does not show the following refusals, but tests prove them:

- A named approver's approval is refused with `409 EVIDENCE_RULES_NOT_MET`, and nothing is recorded.
- A drill that cites NM-C11's approval for NM-C10 gets a `404` (on the live demo,
  `403 PUBLIC_DRILL_SCOPE` before that check).
- An approval forged and handed straight to the drill engine is blocked before any fixture exists.

The tests are `NullMeridianScenarioTests.test_nm_c10_shows_every_state_and_refuses_every_decision`
in [`tests/test_evidence_assessment.py`](../../tests/test_evidence_assessment.py) and
`NmC10NeverDrillsTests.test_no_route_takes_nm_c10_into_a_drill` in
[`tests/test_ogwa_demo_integration.py`](../../tests/test_ogwa_demo_integration.py).

## Part 2: NM-C11, how OGWA acts safely

NM-C11 (`OKTA-AdAnalytics-Users`) has fresh evidence and an exact mapping. Its approval and
decision were both judged by v1.2.0. It goes through a dry run, then a synthetic execution
with a scripted timeout.

```text
fresh evidence → NM-LIFECYCLE-004 v1.2.0 → decision + approval → DRY RUN (no mutation)
  → SYNTHETIC EXECUTION → OUTCOME UNKNOWN → verification → safe retry (same operation id)
  → POST-ACTION VERIFIED
```

| # | Do this | You should see |
| --- | --- | --- |
| 1 | Open **NM-C11** (locally, signed in as `synthetic.executor.one`). | State `APPROVED`. |
| 2 | Read **Is this safe to act on?** | Current, decision-grade evidence (re-collected on the snapshot day) and an exact mapping. |
| 3 | Read **Why this decision** and the decision history. | NM-LIFECYCLE-004 v1.2.0. The triage decisions show v1.1.0 (superseded). The snapshot-day approval and the `APPROVED` decision show v1.2.0. |
| 4 | In **Remediation: dry run or synthetic drill**, choose **Dry run** and run it. | The banner **DRY RUN — NO STATE CHANGED**. |
| 5 | Check the dry-run result. | The before and after state digests are identical, the ledger is empty, nothing was submitted, and the post-action check is "not reached". |
| 6 | Choose **Synthetic execution drill** with the scenario **Timeout, change not applied**, and run it. | The banner **SYNTHETIC EXECUTION**, with "No external provider or persistent environment was modified." |
| 7 | Read the first attempt. | **OUTCOME UNKNOWN — VERIFYING.** The submission timed out. Nothing is assumed, and nothing is resubmitted yet. |
| 8 | Read the verification step. | A read of the target shows the change was **not** applied. |
| 9 | Read the retry decision. | Only now does the result show **RETRY PERMITTED — VERIFIED NOT APPLIED**. The gates and the policy binding are checked again before the retry. |
| 10 | Compare the two attempts. | Both carry the **same operation id** (`rop_3cb0aff2…`). |
| 11 | Read the final state. | **POST-ACTION VERIFIED.** A post-action read found the target in its after-state and nothing else in scope changed. Executed alone never counts as success. |
| 12 | Open **Authorized by**. | The chain behind this run: the policy version, the decision and the approval with their audit sequences, both "Judged by the version in force", and the operation id. |
| 13 | Reload the page. | The candidate is still `APPROVED`, and the dashboard's audit event count and head have not moved. *Local only:* signed in as `synthetic.securityiam.one`, the candidate's audit trail shows no event from the drill. |

**What this shows.** OGWA treats remediation as a verified state transition, not a button
click. Three rules govern it:

- An unknown outcome leads only to verification.
- A retry needs a read proving the first attempt was not applied.
- Success needs a post-action read.

The synthetic provider state never persists.

**Behind the UI.** The drill's state machine is in
[`app/domain/remediation_execution.py`](../../app/domain/remediation_execution.py). The runner is
in [`app/remediation/drill.py`](../../app/remediation/drill.py), and the in-memory fixture with
its fault scripts is in
[`app/remediation/synthetic_provider.py`](../../app/remediation/synthetic_provider.py). The
policy, decision and approval binding is in
[`app/api/authorization.py`](../../app/api/authorization.py). The other fault scenarios show the
remaining paths:

- `TIMEOUT_AFTER_APPLY`: the change was applied, so it is not resubmitted.
- `TIMEOUT_UNVERIFIABLE` and `REPEATED_TIMEOUT`: the drill ends in "retry not permitted".
- `ACKNOWLEDGED_NOT_APPLIED`: the drill ends in **VERIFICATION FAILED — NOT A SUCCESS**.

[docs/architecture/remediation-execution.md](../architecture/remediation-execution.md) describes
all of them.

## Going deeper

- **A recorded example of both scenarios.** The
  [audit sample](samples/ogwa-audit-sample.json) is generated from the application's own API
  responses. It shows both scenarios, the policy versions, and the decision-chain audit events
  with their digests. `python -m app.demo.null_meridian.audit_sample --check` proves it matches
  the build byte for byte.
- **The invariants.** Each is listed in
  [docs/security/safety-invariants.md](../security/safety-invariants.md) with the tests that
  enforce it: EA-* for evidence, PV-* for policy versions, RX-* for remediation execution, and
  DI-* for the integration.
- **The hosted acceptance gates.** [docs/deployment/cloudflare-demo.md](../deployment/cloudflare-demo.md#validation)
  lists the gates a deployment of this demo must pass: the hosted smoke (NM-C10, the NM-C11 dry
  run and drill, and non-persistence), the browser gate against the Worker, and the D1 verify.
