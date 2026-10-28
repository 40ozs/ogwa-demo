"""Dependency coverage, per domain, and which domains OGWA can cover at all.

Overall coverage is ``assess_dependency_coverage``: the same function the lifecycle uses
before an AD retirement dry run, so the classifier and the lifecycle can never disagree.
This module adds the per-kind detail an operator needs: which kinds were checked, which
were checked only incompletely or only by an attestation (which never counts, D13), and
which were never checked.

``PRODUCTION_COLLECTORS`` records which kinds have an OGWA collector that could produce
counting evidence against real systems. It is documentation in code: a test pins it, and
docs/operations/dependency-coverage.md explains each entry. Today no required kind can be
covered from production, so no production group can become a RETIREMENT_CANDIDATE. That is
intended (fail closed).
"""

from dataclasses import dataclass
from enum import StrEnum

from app.domain.model import (
    COVERAGE_SOURCES,
    DependencyCoverage,
    DependencyEvidence,
    DependencyKind,
    assess_dependency_coverage,
)


class KindStatus(StrEnum):
    COVERED = "COVERED"  # a complete check from a counting source
    NOT_DECISION_GRADE = "NOT_DECISION_GRADE"  # checked, but the result is PARTIAL or FAILED
    NOT_COUNTED_SOURCE = "NOT_COUNTED_SOURCE"  # checked only by a source that never counts (e.g. attestation)
    NOT_CHECKED = "NOT_CHECKED"


@dataclass(frozen=True)
class ProductionCollector:
    name: str
    live_verified: bool  # False until P11 records the live behaviors it depends on (D19)
    note: str


_AD_READER = ProductionCollector(
    name="OGWA.ADReader worker (P05) through a read-only AAP job",
    live_verified=False,
    note="No AAP transport exists yet, and live AD results stay PARTIAL until P11 verifies the D19 behaviors.",
)

# None: OGWA has no collector for the kind. Its coverage can come only from synthetic data.
PRODUCTION_COLLECTORS: dict[DependencyKind, ProductionCollector | None] = {
    DependencyKind.AD_GROUP_MEMBERS: _AD_READER,
    DependencyKind.AD_NESTED_MEMBERSHIP: _AD_READER,
    DependencyKind.OKTA_OTHER_APP_ASSIGNMENT: None,
    DependencyKind.OKTA_POLICY_REFERENCE: None,
    DependencyKind.AD_ACL_REFERENCE: None,
    DependencyKind.GPO_REFERENCE: None,
    DependencyKind.AAP_REFERENCE: None,
    DependencyKind.APPLICATION_CONFIGURATION: None,
    DependencyKind.OTHER: None,
}


@dataclass(frozen=True)
class KindCoverage:
    kind: DependencyKind
    required: bool
    status: KindStatus
    production_collector: ProductionCollector | None

    def to_dict(self) -> dict[str, object]:
        collector = self.production_collector
        return {
            "kind": self.kind.value,
            "required": self.required,
            "status": self.status.value,
            "productionCollector": None if collector is None else collector.name,
            "productionCollectorLiveVerified": False if collector is None else collector.live_verified,
        }


@dataclass(frozen=True)
class CoverageReport:
    overall: DependencyCoverage
    kinds: tuple[KindCoverage, ...]

    @property
    def missing(self) -> tuple[DependencyKind, ...]:
        """Required kinds that are not covered."""
        return tuple(k.kind for k in self.kinds if k.required and k.status is not KindStatus.COVERED)

    @property
    def covered(self) -> tuple[DependencyKind, ...]:
        return tuple(k.kind for k in self.kinds if k.status is KindStatus.COVERED)

    def to_dict(self) -> dict[str, object]:
        return {"overall": self.overall.value, "kinds": [k.to_dict() for k in self.kinds]}


def _kind_status(records: list[DependencyEvidence]) -> KindStatus:
    if any(r.provenance.decision_grade and r.provenance.source in COVERAGE_SOURCES for r in records):
        return KindStatus.COVERED
    if any(r.provenance.decision_grade for r in records):
        return KindStatus.NOT_COUNTED_SOURCE
    if records:
        return KindStatus.NOT_DECISION_GRADE
    return KindStatus.NOT_CHECKED


def coverage_report(
    dependencies: tuple[DependencyEvidence, ...], required: frozenset[DependencyKind]
) -> CoverageReport:
    kinds = tuple(
        KindCoverage(
            kind=kind,
            required=kind in required,
            status=_kind_status([d for d in dependencies if d.kind is kind]),
            production_collector=PRODUCTION_COLLECTORS[kind],
        )
        for kind in DependencyKind
    )
    return CoverageReport(overall=assess_dependency_coverage(dependencies, required), kinds=kinds)


def production_coverage_gaps(required: frozenset[DependencyKind]) -> tuple[DependencyKind, ...]:
    """Required kinds that no live-verified OGWA collector can cover from production."""
    return tuple(
        sorted(
            (k for k in required if (c := PRODUCTION_COLLECTORS[k]) is None or not c.live_verified),
            key=lambda k: k.value,
        )
    )
