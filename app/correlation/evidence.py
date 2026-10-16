"""Turn a correlation result into the ``IdentityMapping`` evidence the lifecycle reads.

Every correlation emits exactly one mapping record for its Okta group, with a stable id,
so a new run always supersedes the previous one in the store. A run that cannot resolve
never leaves an earlier exact mapping in force.

| Outcome | Confidence | Result status |
| --- | --- | --- |
| RESOLVED | EXACT_* from the method | COMPLETE |
| REVIEW_REQUIRED | NAME_ONLY | COMPLETE |
| UNVERIFIED_IDENTIFIER | UNVERIFIED_STABLE_ID (D56) | COMPLETE |
| AMBIGUOUS | AMBIGUOUS | COMPLETE if the search was complete, else PARTIAL |
| NOT_FOUND | NOT_FOUND | COMPLETE |
| STALE whose identity is simply gone | NOT_FOUND | COMPLETE |
| STALE otherwise, CONFLICT | AMBIGUOUS (two or more AD objects) or NOT_FOUND | FAILED |
| INCOMPLETE | AMBIGUOUS (two or more AD objects) or NOT_FOUND | PARTIAL |

Only EXACT_* with COMPLETE can move a candidate past review; the lifecycle guards already
enforce that (M-1, M-2, E-2).
"""

import hashlib
from dataclasses import dataclass
from typing import Protocol

from app.correlation.model import CORRELATION_VERSION, CorrelationOutcome, CorrelationResult, DriftKind
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.ids import IdKind, check_id
from app.domain.model import IdentityMapping, MappingConfidence

EVIDENCE_SOURCES = frozenset({EvidenceSource.AD_VIA_AAP, EvidenceSource.SYNTHETIC})
_MAX_REASON = 2000


class ADGroupIds(Protocol):
    """Resolves an AD objectGUID to the internal id of its ADGroup evidence.

    ``app.integrations.ad.records.ADStableIds`` derives the id for evidence read through
    the AD worker; the synthetic demo resolves it from the groups already in its store.
    """

    def ad_group(self, object_guid: str) -> str: ...


def mapping_id_for(okta_group_ref: str) -> str:
    """The stable IdentityMapping id of one Okta group."""
    check_id(okta_group_ref, IdKind.OKTA_GROUP, "okta_group_ref")
    digest = hashlib.sha256(f"ogwa-correlation|{okta_group_ref}".encode()).hexdigest()
    return f"{IdKind.IDENTITY_MAPPING.value}_{digest[:32]}"


@dataclass(frozen=True)
class MappingEvidence:
    mapping: IdentityMapping
    # AD groups the mapping references (ad_group_id or candidates). Their ADGroup evidence
    # must be recorded, from a full read-only AD read, before the mapping can be stored.
    required_ad_object_guids: tuple[str, ...]


def mapping_evidence(result: CorrelationResult, *, source: EvidenceSource, ids: ADGroupIds) -> MappingEvidence:
    """The IdentityMapping for ``result``. ``source`` is AD_VIA_AAP, or SYNTHETIC in LOCAL_SYNTHETIC."""
    if source not in EVIDENCE_SOURCES:
        raise ValueError(f"correlation evidence must come from {sorted(s.value for s in EVIDENCE_SOURCES)}")
    outcome = result.outcome
    guids: tuple[str, ...] = ()
    ad_group_id = None
    candidate_ids: tuple[str, ...] = ()
    matched: tuple[str, ...] = ()
    configuration_ref = None
    if outcome in (CorrelationOutcome.RESOLVED, CorrelationOutcome.REVIEW_REQUIRED, CorrelationOutcome.UNVERIFIED_IDENTIFIER):
        assert result.target is not None
        confidence = result.confidence
        guids = (result.target.object_guid,)
        ad_group_id = ids.ad_group(result.target.object_guid)
        matched = result.matched_attributes
        configuration_ref = result.configuration_ref if confidence is MappingConfidence.EXACT_CONFIGURED_MAPPING else None
        status = ResultStatus.COMPLETE
    else:
        guids = tuple(sorted({c.object_guid for c in result.candidates}))
        if len(guids) >= 2:
            confidence = MappingConfidence.AMBIGUOUS
            candidate_ids = tuple(ids.ad_group(g) for g in guids)
        else:
            confidence, guids = MappingConfidence.NOT_FOUND, ()
        status = _status(result)

    if confidence is MappingConfidence.EXACT_CONFIGURED_MAPPING and source is not EvidenceSource.SYNTHETIC:
        source = EvidenceSource.CONFIGURED_MAPPING  # required by IdentityMapping for this confidence
    provenance = Provenance(
        source=source, observed_at=_observed_at(result), scope=f"correlation:okta-group:{result.okta.okta_group_id}",
        collector_version=CORRELATION_VERSION, result_status=status,
    )
    mapping = IdentityMapping(
        id=mapping_id_for(result.okta.okta_group_ref), okta_group_id=result.okta.okta_group_ref,
        confidence=confidence, ad_group_id=ad_group_id, reason=_reason(result), provenance=provenance,
        matched_attributes=matched, candidate_ad_group_ids=candidate_ids, configuration_ref=configuration_ref,
    )
    return MappingEvidence(mapping, guids)


def _status(result: CorrelationResult) -> ResultStatus:
    outcome = result.outcome
    if outcome is CorrelationOutcome.NOT_FOUND:
        return ResultStatus.COMPLETE
    if outcome is CorrelationOutcome.AMBIGUOUS:
        complete = result.okta.complete and all(lk.complete for lk in result.lookups)
        return ResultStatus.COMPLETE if complete else ResultStatus.PARTIAL
    if outcome is CorrelationOutcome.INCOMPLETE:
        return ResultStatus.PARTIAL
    if outcome is CorrelationOutcome.STALE and {d.kind for d in result.blocking_drift} == {DriftKind.MAPPING_UNRESOLVABLE} \
            and all(lk.complete for lk in result.lookups) and result.okta.complete:
        return ResultStatus.COMPLETE  # the verified identity is gone; that is a complete fact
    return ResultStatus.FAILED


def _observed_at(result: CorrelationResult):
    # The evidence is as old as its oldest input.
    times = [result.okta.observed_at, *(lk.observed_at for lk in result.lookups)]
    return min(times)


def _reason(result: CorrelationResult) -> str:
    parts = [f"{result.outcome.value}"]
    parts += list(result.reasons)
    parts += [f"{d.kind.value}: {d.detail}" for d in result.drift]
    text = " | ".join(parts)
    return text[: _MAX_REASON - 1] + "…" if len(text) > _MAX_REASON else text
