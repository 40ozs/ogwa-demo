# Evidence assessment: evidence quality and the control decision it allows

Implemented in `app/classification/assessment.py` (pure), wired in
`app/api/services.py` (`LifecycleService.classify_and_assess`, `pending_step`), served as
`evidenceAssessment` on `GET /candidates/{candidateId}`, and rendered first on the candidate
page (`app/ui/static/js/evidence.js`, `views/candidate.js`). Synthetic data only; nothing here
reads or writes an external system.

Related: [candidate-policy.md](candidate-policy.md), [lifecycle-state-machine.md](lifecycle-state-machine.md),
[identity-correlation.md](identity-correlation.md), [../security/safety-invariants.md](../security/safety-invariants.md#evidence-assessment-invariants).

## What it answers

For one candidate: (1) the proposed governance issue; (2) which sources support it; (3) which
disagree, conflict, or are unavailable; (4) how sure the identity mapping is; (5) what OGWA can
safely decide now; (6) what evidence it would need to go further.

It **decides nothing the lifecycle does not**. The classifier says which retirement
conditions are proven; the lifecycle guard, evaluated exactly as an approval request's precheck
is (a hypothetical approval that is never recorded), says whether the next approval could be
recorded. The assessment puts both in front of a person, per source, and adds conflict detection.

## Evidence items

One item per source the proposal depends on: the Okta group, each application, the
candidate's assignment, usage, the identity mapping, the AD group, and every dependency kind
the policy requires (plus any other kind recorded). Each item carries its system, provenance
source, result status, observation time, what it says (`observation`), and:

| Field | Values |
| --- | --- |
| `state` | `CONFIRMED`, `REPORTS_NONE`, `NOT_COLLECTED`, `SOURCE_UNAVAILABLE`, `PARTIAL`, `NOT_COUNTED_SOURCE`, `AMBIGUOUS`, `CONFLICTING` (`baseState` keeps what the read itself said under a conflict) |
| `freshness` | `CURRENT`, `STALE`, `FUTURE_DATED`, `NOT_ASSESSED` (the classifier's review-window judgement) |
| `stance` | `SUPPORTS`, `DISAGREES`, `UNKNOWN`; from the classifier's reasons, or for dependency checks from the record (a blocking finding disagrees even from a partial read) |
| `required` | needed by the classifier's retirement conditions under the policy in force |
| `neededFor` | the lifecycle stages whose guards read it: every stage reads the Okta group, assignment, mapping, and AD group; only the Okta unassignment reads usage; only the AD stages require dependency coverage (D131, D132) |

The states never merge: "never collected" (`NOT_COLLECTED`), "the read failed"
(`SOURCE_UNAVAILABLE`), "the read stopped part-way" (`PARTIAL`), "only attested"
(`NOT_COUNTED_SOURCE`), "the source says none" (`REPORTS_NONE`), "identity not established"
(`AMBIGUOUS`), "two reads disagree" (`CONFLICTING`), and `CONFIRMED`.

## Conflicts

Detected generically, never resolved:

| Code | When |
| --- | --- |
| `AD_MEMBERSHIP_DISAGREES` | The AD group object lists member values and a complete, counting membership read found no direct member, or the object lists none (complete read) and the membership read found members. The AD report converter (`app/integrations/ad/`) derives both from the same section, so its own output never conflicts |
| `OTHER_ASSIGNMENT_DISAGREES` | A complete other-assignment check found none while the bundle holds another present assignment of the group |
| `EVIDENCE_INCONSISTENT` | Every classifier `EVIDENCE_INCONSISTENT` reason (a record about another subject) |

## The decision

Every constraint that applies is listed, most restrictive first; the first is the decision:

`TERMINAL` › `NO_ACTION_BLOCKED` › `CONFLICTING_EVIDENCE` › `AMBIGUOUS_IDENTITY` ›
`BLOCKED_ON_REQUIRED_SOURCE` › `INSUFFICIENT_EVIDENCE` › `NO_APPROVAL_OPEN` ›
`MANUAL_REVIEW_REQUIRED` › `LIFECYCLE_RULES_NOT_MET` › `ELIGIBLE_FOR_HUMAN_APPROVAL`.

`ELIGIBLE_FOR_HUMAN_APPROVAL` needs no constraint at all: the classifier's every retirement
condition proven (after the Okta unassignment, every proof in `RETIREMENT_CANDIDATE_REQUIRES`
explicitly, with only the expected `ASSIGNMENT_ABSENT` waived), no conflict, every required item
decision-grade, an open approval step, and the real guard accepting a named human's approval.
It is still not an approval: `isApproval` is `false` and `autoRemediationEligible` is always
`false` (this build only plans dry runs, D8).

When the assessment is stricter than the next step's guard (for example classic S07: the Okta
unassignment's guard does not read dependency coverage, so a human's approval would be accepted
while coverage is UNKNOWN), the assessment says so in `notes` rather than contradicting the
server: OGWA does not mark the proposal safe; the approver carries the judgement.

## Decision explanation

`app/classification/explanation.py` (pure, like the assessment) explains the decision under the
exact policy that produced it, served as `decisionExplanation` on `GET /candidates/{candidateId}`
and rendered as "Why this decision" right after the assessment. It answers:

1. **Which policy version ran?** The `PolicyRef` the server judged by (`policyId`, `version`,
   `name`, digests, recorded version and sequence). The assessment names the same reference
   (`evidenceAssessment.policy`), and the classification the same digest.
2. **Which conditions matched, and which were not satisfied?** One row per retirement condition
   of the classifier (`RETIREMENT_CANDIDATE_REQUIRES`, and per application
   `..._PER_APPLICATION`), plus the next lifecycle step. Each row states the rule with the numbers
   of the policy that ran, its status, why, and the evidence items it read.
3. **Did ambiguity or missing required evidence force manual review?** `manualReview.forcedByEvidence`
   is true exactly when a constraint is `CONFLICTING_EVIDENCE`, `AMBIGUOUS_IDENTITY`,
   `BLOCKED_ON_REQUIRED_SOURCE`, or `INSUFFICIENT_EVIDENCE`; `because` lists them.
4. **What would need to change?** The assessment's `needed`; when nothing in the evidence is
   missing, the deciding constraint ("Not an evidence question. …") or, when eligible, that the
   next step is a named human's decision.

It is a reading, never a second evaluator, so it cannot disagree with the decision:

| Status | Only when |
| --- | --- |
| `SATISFIED` | the classifier recorded the condition's proof (for the next step: the guard accepts) |
| `NOT_SATISFIED` | it recorded a fact that contradicts the condition (members, a parent group, another assignment, use above the threshold, stale evidence, a blocking finding, …) |
| `NOT_PROVEN` | neither: the evidence is missing, partial, failed, ambiguous, or the condition was not judged (the classifier reads AD-side facts only through an exact mapping, and says "Not judged" rather than nothing) |
| `NOT_APPLICABLE` | the stage makes it moot: the assignment's absence after the observed Okta unassignment; no approval open |

A condition is never dropped: with no application known, each per-application condition is
listed once, not proven. Over the assessment tests' whole degradation matrix (every single
weakened record) the explanation never shows a
condition satisfied without its proof or failed without a contradicting fact, and an eligible
decision has every condition satisfied (`tests/test_decision_explanation.py`, invariants PV-6, PV-7).
