"""Okta-to-AD identity correlation (P06). See docs/architecture/identity-correlation.md.

Read-only and pure: correlation asks a bounded ``ADIdentityDirectory`` for exact-match
lookups and decides; it never writes to Okta or AD. Public surface:

- ``correlate``: one Okta group to its AD counterpart, with outcome, drift, and fingerprint;
- ``mapping_evidence``: the ``IdentityMapping`` record the lifecycle reads;
- ``MappingReviewService``: inspect, search, select, approve, reject (service contract only);
- ``ReportBackedDirectory``: identity lookups over the P05 worker contract (synthetic only in P06).
"""

from app.correlation.directory import ADIdentityDirectory, BoundedLookups, ReportBackedDirectory, identity_lookup_from_report
from app.correlation.engine import assess_okta_source, correlate
from app.correlation.evidence import MappingEvidence, mapping_evidence, mapping_id_for
from app.correlation.model import (
    CORRELATION_VERSION,
    ADIdentity,
    ADIdentityLookup,
    ConfiguredMapping,
    CorrelationConfig,
    CorrelationOutcome,
    CorrelationResult,
    DirectorySource,
    DriftFinding,
    DriftKind,
    LookupStatus,
    OktaGroupIdentity,
    OktaSourceState,
)
from app.correlation.review import (
    InMemoryMappingRegistry,
    MappingInspection,
    MappingRegistry,
    MappingReviewService,
    ReviewAction,
    ReviewRefused,
    SearchResult,
    StoreMappingRegistry,
)

__all__ = [
    "CORRELATION_VERSION",
    "ADIdentity",
    "ADIdentityDirectory",
    "ADIdentityLookup",
    "BoundedLookups",
    "ConfiguredMapping",
    "CorrelationConfig",
    "CorrelationOutcome",
    "CorrelationResult",
    "DirectorySource",
    "DriftFinding",
    "DriftKind",
    "InMemoryMappingRegistry",
    "LookupStatus",
    "MappingEvidence",
    "MappingInspection",
    "MappingRegistry",
    "MappingReviewService",
    "OktaGroupIdentity",
    "OktaSourceState",
    "ReportBackedDirectory",
    "ReviewAction",
    "ReviewRefused",
    "SearchResult",
    "StoreMappingRegistry",
    "assess_okta_source",
    "correlate",
    "identity_lookup_from_report",
    "mapping_evidence",
    "mapping_id_for",
]
