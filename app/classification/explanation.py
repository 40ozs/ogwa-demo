"""Why a control decision came out as it did, under the exact policy that produced it (OGWA-DEMO-02).

``explain`` answers, for one candidate's evidence assessment:

1. Which policy version ran? The ``PolicyRef`` the server judged by: policy id, version, and digest.
2. Which conditions matched, and which were not satisfied? One row per retirement condition of the
   classifier and one for the next lifecycle step, each with the rule *as this policy states it*
   (its thresholds, windows, and required kinds) and the evidence items it read.
3. Did ambiguity or missing required evidence force manual review? Yes exactly when the decision's
   constraints include a conflict, an unestablished identity, an unreadable required source, or
   insufficient evidence; the answer lists them.
4. What would need to change for a different outcome? The assessment's own list of what is needed.

It is a reading, not a second evaluator. Every status comes from the classifier's recorded reasons
(``ClassificationResult.reasons``) or the lifecycle guard's answer (``PendingStep``), never from
re-judging the evidence, so the explanation can never disagree with the decision it explains. A
condition is ``SATISFIED`` only when the classifier recorded its proof; ``NOT_SATISFIED`` only
when it recorded a fact that contradicts it; anything else is ``NOT_PROVEN``. Missing evidence is
never shown as a satisfied or a failed condition.

Pure, like the assessment (EA-6): no I/O, no clock, no store.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable  # typing, not collections.abc: classification imports only the vetted set

from app.classification.assessment import (
    AD_STAGES,
    DECISION_LABEL,
    STAGE_LABEL,
    Decision,
    EvidenceAssessment,
    _guard_problems,
)
from app.classification.classifier import ClassificationResult
from app.classification.reasons import Reason, ReasonCode
from app.domain.candidate_policy import CandidatePolicy
from app.domain.policy_release import PolicyRef

R = ReasonCode


class ConditionStatus(StrEnum):
    SATISFIED = "SATISFIED"  # the classifier recorded the proof (or the guard accepts)
    NOT_SATISFIED = "NOT_SATISFIED"  # it recorded a fact that contradicts the condition
    NOT_PROVEN = "NOT_PROVEN"  # neither: missing, partial, failed, ambiguous, or not judged
    NOT_APPLICABLE = "NOT_APPLICABLE"  # the condition does not apply at this stage


# The constraints that mean the evidence itself, not a fact about the group, stops the decision.
EVIDENCE_DECISIONS = (Decision.CONFLICTING_EVIDENCE, Decision.AMBIGUOUS_IDENTITY, Decision.BLOCKED_ON_REQUIRED_SOURCE,
                      Decision.INSUFFICIENT_EVIDENCE)


def _hours(td) -> int:
    return int(td.total_seconds() // 3600)


@dataclass(frozen=True)
class _Rule:
    key: str
    label: str
    rule: Callable[[CandidatePolicy], str]
    proof: ReasonCode
    fails: frozenset[ReasonCode]  # recorded facts that contradict the condition
    unknown: frozenset[ReasonCode]  # recorded reasons that say it cannot be told
    evidence: tuple[str, ...]  # item keys (or "dependency:" prefix) the condition reads
    per_application: bool = False
    # The classifier judges this condition only once that proof is recorded (AD-side facts only
    # through an exact mapping of an AD-sourced group); without it the condition is not judged.
    after: ReasonCode | None = None

    @property
    def codes(self) -> frozenset[ReasonCode]:
        return self.fails | self.unknown | {self.proof}


RULES: tuple[_Rule, ...] = (
    _Rule("AD_SOURCED_GROUP", "Imported from the configured AD integration",
          lambda p: "The Okta group was imported through an AD integration this policy names "
                    f"({len(p.lifecycle.ad_directory_source_ids)} configured). None configured means no group "
                    "qualifies (fail closed).",
          R.AD_SOURCED_GROUP, frozenset({R.OKTA_ONLY_GROUP, R.NOT_AD_SOURCED}),
          frozenset({R.OKTA_GROUP_NOT_OBSERVED}), ("okta-group",)),
    _Rule("EXACT_MAPPING", "AD counterpart established exactly",
          lambda p: "The Okta group maps to exactly one AD group by a stable identifier or a reviewed selection. "
                    "Name-only and unverified-identifier matches never count (D37, D39).",
          R.EXACT_MAPPING, frozenset({R.MAPPING_NOT_FOUND, R.AD_GROUP_NOT_FOUND}),
          frozenset({R.MAPPING_MISSING, R.MAPPING_NAME_ONLY, R.MAPPING_AMBIGUOUS, R.MAPPING_UNVERIFIED_IDENTIFIER,
                     R.MAPPING_NOT_EXACT, R.AD_GROUP_NOT_OBSERVED}), ("mapping", "ad-group"), after=R.AD_SOURCED_GROUP),
    _Rule("NOT_PROTECTED", "Not a protected group",
          lambda p: "No built-in, AD (adminCount, protection from accidental deletion), or configured protection "
                    f"applies ({sum(len(s) for s in (p.lifecycle.protected_okta_group_ids, p.lifecycle.protected_ad_object_guids, p.lifecycle.protected_ad_sids))} "
                    "identifiers configured as protected).",
          R.NOT_PROTECTED, frozenset({R.PROTECTED_GROUP}), frozenset({R.PROTECTION_UNDETERMINED}), ("ad-group",),
          after=R.EXACT_MAPPING),
    _Rule("AD_GROUP_EMPTY", "AD group has no members",
          lambda p: "Complete reads find no direct members, no primaryGroupID references, and no principals through "
                    "member groups. An unknown member count is never zero.",
          R.AD_GROUP_EMPTY, frozenset({R.AD_DIRECT_MEMBERS, R.AD_PRIMARY_GROUP_REFERENCES, R.AD_MEMBERSHIP_FINDING,
                                       R.AD_MEMBER_GROUPS, R.AD_NESTED_PRINCIPALS}),
          frozenset({R.AD_MEMBERSHIP_UNKNOWN, R.AD_NESTING_UNKNOWN}),
          ("ad-group", "dependency:AD_GROUP_MEMBERS", "dependency:AD_NESTED_MEMBERSHIP"), after=R.EXACT_MAPPING),
    _Rule("AD_NO_PARENT_GROUPS", "Not nested in another AD group",
          lambda p: "A complete nesting read finds the AD group in no other group.",
          R.AD_NO_PARENT_GROUPS, frozenset({R.AD_PARENT_GROUP, R.AD_NESTING_FINDING}),
          frozenset({R.AD_NESTING_UNKNOWN}), ("dependency:AD_NESTED_MEMBERSHIP",), after=R.EXACT_MAPPING),
    _Rule("SINGLE_OKTA_ASSIGNMENT", "No other application assignment",
          lambda p: "A complete Okta check finds the group assigned to no other application.",
          R.SINGLE_OKTA_ASSIGNMENT, frozenset({R.SHARED_OKTA_ASSIGNMENT}), frozenset({R.OTHER_ASSIGNMENTS_UNKNOWN}),
          ("other-assignment:", "dependency:OKTA_OTHER_APP_ASSIGNMENT")),
    _Rule("DEPENDENCY_COVERAGE_COMPLETE", "Every required dependency checked, none blocking",
          lambda p: f"Complete checks by a counting source for all {len(p.lifecycle.required_dependency_kinds)} "
                    "required kinds (" + ", ".join(sorted(k.value for k in p.lifecycle.required_dependency_kinds))
                    + "), and no blocking finding. Anything less keeps AD deletion prohibited.",
          R.DEPENDENCY_COVERAGE_COMPLETE, frozenset({R.DEPENDENCY_FINDING}),
          frozenset({R.DEPENDENCY_COVERAGE_INCOMPLETE}), ("dependency:",)),
    _Rule("EVIDENCE_CURRENT", "Core records complete and current",
          lambda p: "The Okta group, application, assignment, usage, identity mapping, and AD group records are "
                    f"complete reads observed within the review window ({_hours(p.lifecycle.freshness.review)} h) "
                    "and not dated in the future. Dependency checks are judged by coverage, above.",
          R.EVIDENCE_CURRENT, frozenset({R.EVIDENCE_STALE}),
          frozenset({R.EVIDENCE_FUTURE_DATED, R.EVIDENCE_NOT_DECISION_GRADE, R.EVIDENCE_INCONSISTENT}), ()),
    _Rule("ASSIGNMENT_PRESENT", "Assigned to the application",
          lambda p: "The group's assignment to the application is observed: it is what the proposal removes.",
          R.ASSIGNMENT_PRESENT, frozenset({R.ASSIGNMENT_ABSENT}), frozenset({R.ASSIGNMENT_NOT_OBSERVED}),
          ("assignment:",), per_application=True),
    _Rule("USAGE_WITHIN_RETIREMENT_THRESHOLD", "No sign-in through the group",
          lambda p: f"At most {p.lifecycle.max_usage_events_for_candidate} sign-in(s) in the usage window.",
          R.USAGE_WITHIN_RETIREMENT_THRESHOLD, frozenset({R.USAGE_ABOVE_RETIREMENT_THRESHOLD, R.IN_USE}),
          frozenset({R.USAGE_NOT_OBSERVED, R.APPLICATION_NOT_OBSERVED}), ("usage:",), per_application=True),
    _Rule("USAGE_WINDOW_COVERS_RETIREMENT", "Usage window long enough",
          lambda p: f"The usage window covers at least {p.lifecycle.min_usage_window.days} days. A shorter complete "
                    f"window (at least {p.review_min_usage_window.days} days) is a review signal only (D27).",
          R.USAGE_WINDOW_COVERS_RETIREMENT, frozenset({R.USAGE_WINDOW_REVIEW_ONLY, R.USAGE_WINDOW_TOO_SHORT}),
          frozenset({R.USAGE_NOT_OBSERVED}), ("usage:",), per_application=True),
)
NEXT_STEP_KEY = "NEXT_STEP_RULES"


@dataclass(frozen=True)
class ConditionResult:
    key: str
    label: str
    rule: str  # the condition as the policy that ran states it
    status: ConditionStatus
    detail: str
    evidence: tuple[str, ...]  # assessment item keys the condition read
    application_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "rule": self.rule, "status": self.status.value,
                "detail": self.detail, "evidence": list(self.evidence), "applicationId": self.application_id}


@dataclass(frozen=True)
class DecisionExplanation:
    policy: PolicyRef | None
    decision: Decision
    conditions: tuple[ConditionResult, ...]
    review_forced_by_evidence: bool
    review_reasons: tuple[dict[str, Any], ...]  # the evidence constraints, as the assessment states them
    what_would_change: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in ConditionStatus}
        for c in self.conditions:
            counts[c.status.value] += 1
        return {
            "isApproval": False,
            "policy": self.policy.to_dict() if self.policy else None,
            "decision": {"code": self.decision.value, "label": DECISION_LABEL[self.decision]},
            "conditions": [c.to_dict() for c in self.conditions],
            "conditionCounts": counts,
            "manualReview": {"forcedByEvidence": self.review_forced_by_evidence, "because": list(self.review_reasons)},
            "whatWouldChange": list(self.what_would_change),
        }


def explain(assessment: EvidenceAssessment, classification: ClassificationResult | None,
            policy: CandidatePolicy | None, policy_ref: PolicyRef | None) -> DecisionExplanation:
    """Explain ``assessment``'s decision. ``policy`` and ``policy_ref`` are the policy it was judged by
    (both None when none is in force); ``classification`` is the one the assessment used."""
    if not isinstance(assessment, EvidenceAssessment):
        raise TypeError("assessment must be an EvidenceAssessment")
    if (policy is None) != (policy_ref is None):
        raise TypeError("policy and policy_ref are given together")
    if policy is not None and policy.digest != policy_ref.policy_digest:
        raise ValueError("policy_ref does not name this policy")
    if classification is not None and policy is not None and classification.policy_digest != policy.digest:
        raise ValueError("the classification was produced by a different policy")
    reasons = classification.reasons if classification is not None else ()
    # The applications under review: the classifier's subject and the assessment's items. A
    # condition is never dropped: with no application known, each per-application condition is
    # listed once, not proven.
    app_ids = tuple(dict.fromkeys(
        (classification.subject.application_ids if classification is not None else ())
        + tuple(k.split(":", 1)[1] for k in (i.key for i in assessment.items) if k.startswith("assignment:"))))
    after_unassignment = assessment.pending.stage in AD_STAGES
    conditions = []
    for rule in RULES:
        for app_id in ((app_ids or (None,)) if rule.per_application else (None,)):
            conditions.append(_condition(rule, assessment, classification, reasons, policy, app_id,
                                         after_unassignment))
    conditions.append(_next_step(assessment, policy))
    forced = tuple(c.to_dict() for c in assessment.constraints if c.decision in EVIDENCE_DECISIONS)
    if assessment.needed:
        change = assessment.needed
    elif assessment.eligible:
        change = ("Nothing in the evidence: the next step is a named human's decision. This is not an approval, and "
                  "any change to the evidence needs a new assessment.",)
    else:
        # Not an evidence question (terminal, no approval open, a person must judge): say what decides it.
        change = tuple(f"Not an evidence question. {c.detail}" for c in assessment.constraints[:1])
    return DecisionExplanation(policy=policy_ref, decision=assessment.decision, conditions=tuple(conditions),
                               review_forced_by_evidence=bool(forced), review_reasons=forced,
                               what_would_change=tuple(change))


def _condition(rule: _Rule, assessment: EvidenceAssessment, classification: ClassificationResult | None,
               reasons: tuple[Reason, ...], policy: CandidatePolicy | None, app_id: str | None,
               after_unassignment: bool) -> ConditionResult:
    mine = [r for r in reasons if r.code in rule.codes and (app_id is None or r.subject == app_id)]
    by_code = lambda codes: [r for r in mine if r.code in codes]  # noqa: E731
    text = rule.rule(policy) if policy is not None else "Not stated: no policy is in force (D52)."
    evidence = _evidence(rule, assessment, mine, app_id)
    if classification is None:
        status, detail = ConditionStatus.NOT_PROVEN, "Not judged: no classification is available."
    elif rule.per_application and app_id is None:
        status, detail = ConditionStatus.NOT_PROVEN, "No application assignment is recorded for this candidate."
    elif rule.key == "ASSIGNMENT_PRESENT" and after_unassignment:
        status, detail = (ConditionStatus.NOT_APPLICABLE,
                          "The Okta unassignment was observed; the assignment's absence is now the expected fact.")
    elif failed := by_code(rule.fails):
        status, detail = ConditionStatus.NOT_SATISFIED, "; ".join(r.detail for r in failed[:2])
    elif proved := by_code({rule.proof}):
        status, detail = ConditionStatus.SATISFIED, proved[0].detail
    elif rule.after is not None and not any(r.code is rule.after for r in reasons):
        status = ConditionStatus.NOT_PROVEN
        detail = (f"Not judged: the classifier reads this only after {rule.after.value} is proven, and it is not. "
                  "Nothing is assumed either way.")
    else:
        unknown = by_code(rule.unknown)
        status = ConditionStatus.NOT_PROVEN
        detail = "; ".join(r.detail for r in unknown[:2]) or "No proof was recorded."
    label = rule.label
    if app_id is not None:
        names = {i.key: i.label for i in assessment.items}
        app = names.get(f"application:{app_id}", "")
        label = f"{rule.label} ({app.split(': ', 1)[1]})" if ": " in app else rule.label
    return ConditionResult(rule.key, label, text, status, detail[:500], evidence, app_id)


def _evidence(rule: _Rule, assessment: EvidenceAssessment, mine: list[Reason], app_id: str | None) -> tuple[str, ...]:
    """The items the condition read: those carrying its reasons, then those it reads by kind."""
    codes = {r.code.value for r in mine}
    keys = [i.key for i in assessment.items if codes & set(i.reasons)]
    for i in assessment.items:
        for prefix in rule.evidence:
            if i.key == prefix or (prefix.endswith(":") and i.key.startswith(prefix)
                                   and (app_id is None or i.key == prefix + app_id)):
                keys.append(i.key)
    if rule.key == "EVIDENCE_CURRENT" and not keys:
        keys = [i.key for i in assessment.items if i.required and i.kind != "dependency"]
    if app_id is not None:
        keys = [k for k in keys if ":" not in k or k.endswith(app_id) or k.startswith("dependency:")]
    return tuple(dict.fromkeys(keys))


def _next_step(assessment: EvidenceAssessment, policy: CandidatePolicy | None) -> ConditionResult:
    pending = assessment.pending
    stage = STAGE_LABEL.get(pending.stage) if pending.stage else None
    label = f"{stage} approval accepted by the lifecycle rules" if stage else "Next lifecycle step"
    if policy is None:
        text = "Not stated: no policy is in force (D52)."
    else:
        lc = policy.lifecycle
        text = (f"Every record the step reads observed within the approval window "
                f"({_hours(lc.freshness.approval)} h), the mapping exact, the approval given by a different named "
                f"person and valid at most {_hours(lc.approval_max_ttl)} h; the lifecycle guard decides.")
    evidence = tuple(i.key for i in assessment.items if pending.stage in i.needed_for)
    if not pending.open:
        status = ConditionStatus.NOT_APPLICABLE
        detail = (f"No approval is open in {assessment.state.value}"
                  + (f"; the next one is the {stage}." if stage else ": nothing further is decided."))
    elif not pending.evaluated:
        status = ConditionStatus.NOT_PROVEN
        detail = "; ".join(pending.problems[:2]) or "The guard was not evaluated."
    elif pending.accepts:
        status, detail = ConditionStatus.SATISFIED, "The guard would accept a named human's approval on this evidence."
    else:
        status, detail = ConditionStatus.NOT_SATISFIED, "; ".join(_guard_problems(pending.problems)[:3])
    return ConditionResult(NEXT_STEP_KEY, label, text, status, detail[:500], evidence)


__all__ = ["EVIDENCE_DECISIONS", "NEXT_STEP_KEY", "RULES", "ConditionResult", "ConditionStatus",
           "DecisionExplanation", "explain"]
