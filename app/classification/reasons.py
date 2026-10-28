"""Classifications, reason codes, and what each reason code means.

Every reason code has one fixed meaning, recorded in ``REASON_EFFECTS``:

- ``outcome``: the classification the reason forces, if any (``PROTECTED``, ``ACTIVE``,
  a dependency block, a mapping or evidence problem);
- ``blocks``: whether it prevents ``RETIREMENT_CANDIDATE``. A blocking reason without an
  outcome keeps the result at the usage review tier (``LOW_USAGE_REVIEW`` or
  ``INACTIVE_REVIEW``);
- neither: supporting evidence. ``RETIREMENT_CANDIDATE_REQUIRES`` lists the supporting
  reasons that must all be present before a result can be ``RETIREMENT_CANDIDATE``.
  Promotion needs proof of every condition, not just the absence of a blocker.

A code's meaning never changes; a threshold's value appears in the reason's detail, so a
policy change does not rename a code.
"""

from dataclasses import dataclass
from enum import StrEnum

from app.domain.ids import check_text


class Classification(StrEnum):
    # The application is in use. Not interesting for lifecycle work.
    ACTIVE = "ACTIVE"
    # Some use, at or below the low-usage threshold. A human may look; nothing more.
    LOW_USAGE_REVIEW = "LOW_USAGE_REVIEW"
    # No observed use, or the application is inactive, but a retirement condition is
    # unproven (for example, dependency coverage is not COMPLETE). Review or hold.
    INACTIVE_REVIEW = "INACTIVE_REVIEW"
    # The Okta group has no exact AD mapping (missing, name-only, ambiguous, not found).
    MAPPING_REQUIRED = "MAPPING_REQUIRED"
    # The AD group has direct members or primaryGroupID references.
    HAS_MEMBERS = "HAS_MEMBERS"
    # The Okta group is assigned to another application as well.
    SHARED_OKTA_ASSIGNMENT = "SHARED_OKTA_ASSIGNMENT"
    # The AD group is nested in other groups, contains groups, or reaches principals through them.
    NESTED_DEPENDENCY = "NESTED_DEPENDENCY"
    # Built-in, configured, or AD-protected. Never progresses.
    PROTECTED = "PROTECTED"
    # A blocking dependency finding outside membership and Okta assignment (ACL, GPO, AAP, ...).
    DEPENDENCY_BLOCKED = "DEPENDENCY_BLOCKED"
    # Once-complete evidence has outlived its freshness window for review.
    STALE_EVIDENCE = "STALE_EVIDENCE"
    # Required evidence was never fully or properly obtained: missing, PARTIAL/FAILED,
    # dated in the future, inconsistent, or undetermined (owner decision after P09).
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    # Every retirement condition is proven, including COMPLETE dependency coverage.
    # Evidence for human review. NOT approval, NOT authorization to change anything.
    RETIREMENT_CANDIDATE = "RETIREMENT_CANDIDATE"


C = Classification

# The first forced outcome in this order wins. Positive facts that stop progress come
# before evidence problems: a group known to have members is HAS_MEMBERS even when other
# evidence is stale.
PRECEDENCE: tuple[Classification, ...] = (
    C.PROTECTED,
    C.ACTIVE,
    C.DEPENDENCY_BLOCKED,
    C.HAS_MEMBERS,
    C.NESTED_DEPENDENCY,
    C.SHARED_OKTA_ASSIGNMENT,
    C.MAPPING_REQUIRED,
    C.STALE_EVIDENCE,
    C.EVIDENCE_INCOMPLETE,
)


class UsageTier(StrEnum):
    ACTIVE = "ACTIVE"
    LOW = "LOW"
    INACTIVE = "INACTIVE"


class ReasonCode(StrEnum):
    # Usage and application
    APP_INACTIVE = "APP_INACTIVE"
    IN_USE = "IN_USE"
    LOW_USAGE = "LOW_USAGE"
    NO_OBSERVED_USAGE = "NO_OBSERVED_USAGE"
    NO_RECENT_LOGIN = "NO_RECENT_LOGIN"
    USAGE_WITHIN_RETIREMENT_THRESHOLD = "USAGE_WITHIN_RETIREMENT_THRESHOLD"
    USAGE_ABOVE_RETIREMENT_THRESHOLD = "USAGE_ABOVE_RETIREMENT_THRESHOLD"
    USAGE_WINDOW_COVERS_RETIREMENT = "USAGE_WINDOW_COVERS_RETIREMENT"
    USAGE_WINDOW_REVIEW_ONLY = "USAGE_WINDOW_REVIEW_ONLY"
    USAGE_WINDOW_TOO_SHORT = "USAGE_WINDOW_TOO_SHORT"
    USAGE_NOT_OBSERVED = "USAGE_NOT_OBSERVED"
    APPLICATION_NOT_OBSERVED = "APPLICATION_NOT_OBSERVED"
    # Okta assignment
    ASSIGNMENT_PRESENT = "ASSIGNMENT_PRESENT"
    ASSIGNMENT_ABSENT = "ASSIGNMENT_ABSENT"
    ASSIGNMENT_NOT_OBSERVED = "ASSIGNMENT_NOT_OBSERVED"
    SINGLE_OKTA_ASSIGNMENT = "SINGLE_OKTA_ASSIGNMENT"
    SHARED_OKTA_ASSIGNMENT = "SHARED_OKTA_ASSIGNMENT"
    OTHER_ASSIGNMENTS_UNKNOWN = "OTHER_ASSIGNMENTS_UNKNOWN"
    # Group origin and mapping
    OKTA_GROUP_NOT_OBSERVED = "OKTA_GROUP_NOT_OBSERVED"
    AD_SOURCED_GROUP = "AD_SOURCED_GROUP"
    OKTA_ONLY_GROUP = "OKTA_ONLY_GROUP"
    NOT_AD_SOURCED = "NOT_AD_SOURCED"
    EXACT_MAPPING = "EXACT_MAPPING"
    MAPPING_MISSING = "MAPPING_MISSING"
    MAPPING_NAME_ONLY = "MAPPING_NAME_ONLY"
    MAPPING_AMBIGUOUS = "MAPPING_AMBIGUOUS"
    MAPPING_NOT_FOUND = "MAPPING_NOT_FOUND"
    MAPPING_UNVERIFIED_IDENTIFIER = "MAPPING_UNVERIFIED_IDENTIFIER"  # D56
    MAPPING_NOT_EXACT = "MAPPING_NOT_EXACT"  # any other non-exact confidence (fail closed)
    AD_GROUP_NOT_OBSERVED = "AD_GROUP_NOT_OBSERVED"
    AD_GROUP_NOT_FOUND = "AD_GROUP_NOT_FOUND"
    # Protection
    PROTECTED_GROUP = "PROTECTED_GROUP"
    PROTECTION_UNDETERMINED = "PROTECTION_UNDETERMINED"
    NOT_PROTECTED = "NOT_PROTECTED"
    # AD membership (D20: separate facts)
    AD_GROUP_EMPTY = "AD_GROUP_EMPTY"
    AD_NO_PARENT_GROUPS = "AD_NO_PARENT_GROUPS"
    AD_DIRECT_MEMBERS = "AD_DIRECT_MEMBERS"
    AD_PRIMARY_GROUP_REFERENCES = "AD_PRIMARY_GROUP_REFERENCES"
    AD_MEMBERSHIP_FINDING = "AD_MEMBERSHIP_FINDING"  # uncoded membership finding
    AD_PARENT_GROUP = "AD_PARENT_GROUP"
    AD_MEMBER_GROUPS = "AD_MEMBER_GROUPS"
    AD_NESTED_PRINCIPALS = "AD_NESTED_PRINCIPALS"
    AD_NESTING_FINDING = "AD_NESTING_FINDING"  # uncoded nesting finding
    AD_NESTING_CYCLE = "AD_NESTING_CYCLE"
    AD_MEMBERSHIP_UNKNOWN = "AD_MEMBERSHIP_UNKNOWN"
    AD_NESTING_UNKNOWN = "AD_NESTING_UNKNOWN"
    # Other dependencies and coverage
    DEPENDENCY_FINDING = "DEPENDENCY_FINDING"
    DEPENDENCY_COVERAGE_COMPLETE = "DEPENDENCY_COVERAGE_COMPLETE"
    DEPENDENCY_COVERAGE_INCOMPLETE = "DEPENDENCY_COVERAGE_INCOMPLETE"
    # Evidence quality
    EVIDENCE_CURRENT = "EVIDENCE_CURRENT"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_FUTURE_DATED = "EVIDENCE_FUTURE_DATED"
    EVIDENCE_NOT_DECISION_GRADE = "EVIDENCE_NOT_DECISION_GRADE"
    EVIDENCE_INCONSISTENT = "EVIDENCE_INCONSISTENT"
    REQUIRED_CONDITION_UNPROVEN = "REQUIRED_CONDITION_UNPROVEN"


R = ReasonCode


@dataclass(frozen=True)
class ReasonEffect:
    outcome: Classification | None
    blocks: bool


_SUPPORTING = ReasonEffect(None, False)
_REVIEW_HOLD = ReasonEffect(None, True)


def _forces(outcome: Classification) -> ReasonEffect:
    return ReasonEffect(outcome, True)


REASON_EFFECTS: dict[ReasonCode, ReasonEffect] = {
    R.APP_INACTIVE: _SUPPORTING,
    R.IN_USE: _forces(C.ACTIVE),
    R.LOW_USAGE: _SUPPORTING,
    R.NO_OBSERVED_USAGE: _SUPPORTING,
    R.NO_RECENT_LOGIN: _SUPPORTING,
    R.USAGE_WITHIN_RETIREMENT_THRESHOLD: _SUPPORTING,
    R.USAGE_ABOVE_RETIREMENT_THRESHOLD: _REVIEW_HOLD,
    R.USAGE_WINDOW_COVERS_RETIREMENT: _SUPPORTING,
    R.USAGE_WINDOW_REVIEW_ONLY: _REVIEW_HOLD,
    R.USAGE_WINDOW_TOO_SHORT: _forces(C.EVIDENCE_INCOMPLETE),
    R.USAGE_NOT_OBSERVED: _forces(C.EVIDENCE_INCOMPLETE),
    R.APPLICATION_NOT_OBSERVED: _forces(C.EVIDENCE_INCOMPLETE),
    R.ASSIGNMENT_PRESENT: _SUPPORTING,
    R.ASSIGNMENT_ABSENT: _REVIEW_HOLD,
    R.ASSIGNMENT_NOT_OBSERVED: _forces(C.EVIDENCE_INCOMPLETE),
    R.SINGLE_OKTA_ASSIGNMENT: _SUPPORTING,
    R.SHARED_OKTA_ASSIGNMENT: _forces(C.SHARED_OKTA_ASSIGNMENT),
    R.OTHER_ASSIGNMENTS_UNKNOWN: _REVIEW_HOLD,
    R.OKTA_GROUP_NOT_OBSERVED: _forces(C.EVIDENCE_INCOMPLETE),
    R.AD_SOURCED_GROUP: _SUPPORTING,
    R.OKTA_ONLY_GROUP: _REVIEW_HOLD,
    R.NOT_AD_SOURCED: _REVIEW_HOLD,
    R.EXACT_MAPPING: _SUPPORTING,
    R.MAPPING_MISSING: _forces(C.MAPPING_REQUIRED),
    R.MAPPING_NAME_ONLY: _forces(C.MAPPING_REQUIRED),
    R.MAPPING_AMBIGUOUS: _forces(C.MAPPING_REQUIRED),
    R.MAPPING_NOT_FOUND: _forces(C.MAPPING_REQUIRED),
    R.MAPPING_UNVERIFIED_IDENTIFIER: _forces(C.MAPPING_REQUIRED),
    R.MAPPING_NOT_EXACT: _forces(C.MAPPING_REQUIRED),
    R.AD_GROUP_NOT_OBSERVED: _forces(C.EVIDENCE_INCOMPLETE),
    R.AD_GROUP_NOT_FOUND: _forces(C.MAPPING_REQUIRED),
    R.PROTECTED_GROUP: _forces(C.PROTECTED),
    R.PROTECTION_UNDETERMINED: _forces(C.EVIDENCE_INCOMPLETE),
    R.NOT_PROTECTED: _SUPPORTING,
    R.AD_GROUP_EMPTY: _SUPPORTING,
    R.AD_NO_PARENT_GROUPS: _SUPPORTING,
    R.AD_DIRECT_MEMBERS: _forces(C.HAS_MEMBERS),
    R.AD_PRIMARY_GROUP_REFERENCES: _forces(C.HAS_MEMBERS),
    R.AD_MEMBERSHIP_FINDING: _forces(C.HAS_MEMBERS),
    R.AD_PARENT_GROUP: _forces(C.NESTED_DEPENDENCY),
    R.AD_MEMBER_GROUPS: _forces(C.NESTED_DEPENDENCY),
    R.AD_NESTED_PRINCIPALS: _forces(C.NESTED_DEPENDENCY),
    R.AD_NESTING_FINDING: _forces(C.NESTED_DEPENDENCY),
    R.AD_NESTING_CYCLE: _SUPPORTING,
    R.AD_MEMBERSHIP_UNKNOWN: _forces(C.EVIDENCE_INCOMPLETE),
    R.AD_NESTING_UNKNOWN: _forces(C.EVIDENCE_INCOMPLETE),
    R.DEPENDENCY_FINDING: _forces(C.DEPENDENCY_BLOCKED),
    R.DEPENDENCY_COVERAGE_COMPLETE: _SUPPORTING,
    R.DEPENDENCY_COVERAGE_INCOMPLETE: _REVIEW_HOLD,
    R.EVIDENCE_CURRENT: _SUPPORTING,
    R.EVIDENCE_STALE: _forces(C.STALE_EVIDENCE),
    # A future-dated record was never properly obtained; it has not outlived any window, so
    # it is incomplete, not stale (owner decision after P09).
    R.EVIDENCE_FUTURE_DATED: _forces(C.EVIDENCE_INCOMPLETE),
    R.EVIDENCE_NOT_DECISION_GRADE: _forces(C.EVIDENCE_INCOMPLETE),
    R.EVIDENCE_INCONSISTENT: _forces(C.EVIDENCE_INCOMPLETE),
    R.REQUIRED_CONDITION_UNPROVEN: _forces(C.EVIDENCE_INCOMPLETE),
}

# Supporting reasons that must all be present (once for the candidate) ...
RETIREMENT_CANDIDATE_REQUIRES: frozenset[ReasonCode] = frozenset({
    R.AD_SOURCED_GROUP,
    R.EXACT_MAPPING,
    R.NOT_PROTECTED,
    R.AD_GROUP_EMPTY,
    R.AD_NO_PARENT_GROUPS,
    R.SINGLE_OKTA_ASSIGNMENT,
    R.DEPENDENCY_COVERAGE_COMPLETE,
    R.EVIDENCE_CURRENT,
})
# ... and once for every application in the subject.
RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION: frozenset[ReasonCode] = frozenset({
    R.ASSIGNMENT_PRESENT,
    R.USAGE_WITHIN_RETIREMENT_THRESHOLD,
    R.USAGE_WINDOW_COVERS_RETIREMENT,
})


@dataclass(frozen=True)
class Reason:
    code: ReasonCode
    detail: str  # concise human-readable evidence
    subject: str | None = None  # internal id of the record the reason is about, if any

    def __post_init__(self) -> None:
        if not isinstance(self.code, ReasonCode):
            raise TypeError("code must be a ReasonCode")
        check_text(self.detail, "detail", max_length=500)

    @property
    def effect(self) -> ReasonEffect:
        return REASON_EFFECTS[self.code]

    @property
    def outcome(self) -> Classification | None:
        return self.effect.outcome

    @property
    def blocks(self) -> bool:
        return self.effect.blocks

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code.value, "detail": self.detail, "subject": self.subject,
                "blocks": self.blocks, "outcome": self.outcome.value if self.outcome else None}
