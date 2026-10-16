"""Candidate classification and dependency policy. See docs/architecture/candidate-policy.md.

Pure functions over evidence the store already holds. Nothing here reads a network
service, changes an external system, or approves anything. A ``RETIREMENT_CANDIDATE`` is
evidence for human review, never authorization.
"""

from app.classification.classifier import (
    LIFECYCLE_DIVERSIONS,
    CandidateSubject,
    ClassificationResult,
    classify,
)
from app.classification.coverage import (
    PRODUCTION_COLLECTORS,
    CoverageReport,
    KindCoverage,
    KindStatus,
    coverage_report,
    production_coverage_gaps,
)
from app.classification.reasons import (
    PRECEDENCE,
    REASON_EFFECTS,
    RETIREMENT_CANDIDATE_REQUIRES,
    RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION,
    Classification,
    Reason,
    ReasonCode,
    UsageTier,
)

__all__ = [
    "LIFECYCLE_DIVERSIONS",
    "PRECEDENCE",
    "PRODUCTION_COLLECTORS",
    "REASON_EFFECTS",
    "RETIREMENT_CANDIDATE_REQUIRES",
    "RETIREMENT_CANDIDATE_REQUIRES_PER_APPLICATION",
    "CandidateSubject",
    "Classification",
    "ClassificationResult",
    "CoverageReport",
    "KindCoverage",
    "KindStatus",
    "Reason",
    "ReasonCode",
    "UsageTier",
    "classify",
    "coverage_report",
    "production_coverage_gaps",
]
