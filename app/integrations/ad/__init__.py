"""The Active Directory report contract. See docs/architecture/ad-integration.md.

OGWA never queries AD itself, and this build includes no AD reader. This package validates
AD reader reports in a strict JSON form and turns them into domain evidence; the demo's
reports and evidence are synthetic.

Public surface:

- ``ADReadRequest`` / ``parse_group_report``: the strict JSON contract;
- ``assess_emptiness``: the three explicit emptiness facts and the derived verdict;
- ``assess_protection`` with ``ADProtectionPolicy``: PROTECTED, NOT_PROTECTED, or
  UNDETERMINED (which blocks retirement);
- ``ad_evidence`` / ``collector_result``: conversion to domain evidence.
"""

from app.integrations.ad.assessment import (
    EMPTINESS_DEFINITION,
    ADProtectionPolicy,
    DomainProtectionPolicy,
    EmptinessAssessment,
    EmptinessVerdict,
    Fact,
    ProtectionAssessment,
    ProtectionStatus,
    assess_emptiness,
    assess_protection,
)
from app.integrations.ad.contract import (
    COLLECTOR_VERSION,
    ADGroupReport,
    ADReadRequest,
    ContractError,
    LookupKind,
    ResolutionStatus,
    SectionStatus,
    parse_group_report,
)
from app.integrations.ad.records import ADEvidence, ADStableIds, ad_evidence, collector_result, evidence_source_for_mode

__all__ = [
    "COLLECTOR_VERSION",
    "EMPTINESS_DEFINITION",
    "ADEvidence",
    "ADGroupReport",
    "ADProtectionPolicy",
    "ADReadRequest",
    "ADStableIds",
    "ContractError",
    "DomainProtectionPolicy",
    "EmptinessAssessment",
    "EmptinessVerdict",
    "Fact",
    "LookupKind",
    "ProtectionAssessment",
    "ProtectionStatus",
    "ResolutionStatus",
    "SectionStatus",
    "ad_evidence",
    "assess_emptiness",
    "assess_protection",
    "collector_result",
    "evidence_source_for_mode",
    "parse_group_report",
]
