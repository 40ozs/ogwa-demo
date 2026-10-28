"""Synthetic P07 fixtures. Every name, id, SID, and GUID here is invented.

``world()`` is one synthetic Okta group G (AD-sourced) assigned to one synthetic
application A, mapped exactly to synthetic AD group X, with every required dependency kind
checked completely and nothing found: a RETIREMENT_CANDIDATE. Tests remove or change one
thing at a time and check that promotion stops.

Okta dependency kinds are checked on the Okta group, every other kind on the AD group.
"""

from dataclasses import replace

from app.classification import CandidateSubject, classify
from app.domain.candidate_policy import CandidatePolicy
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.ids import IdKind
from app.domain.model import (
    DependencyEvidence,
    DependencyFinding,
    DependencyKind,
    FindingCode,
)
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS, EvidenceBundle
from tests.domain_fixtures import (
    AD_ID,
    APP_ID,
    GROUP_ID,
    HOUR,
    POLICY,
    T0,
    ad_group,
    application,
    assignment,
    fixed_id,
    mapping,
    okta_group,
    prov,
    usage,
)

CPOLICY = CandidatePolicy(lifecycle=POLICY)
SUBJECT = CandidateSubject(GROUP_ID, (APP_ID,))
NOW = T0 + HOUR
OKTA_KINDS = frozenset({DependencyKind.OKTA_OTHER_APP_ASSIGNMENT, DependencyKind.OKTA_POLICY_REFERENCE})
APP_ID_2 = fixed_id(IdKind.OKTA_APPLICATION, 2)
ASSIGNMENT_ID_2 = fixed_id(IdKind.ASSIGNMENT, 2)
USAGE_ID_2 = fixed_id(IdKind.USAGE_OBSERVATION, 2)

DIRECT_MEMBERS = DependencyFinding("2 direct member value(s) (2 user)", True, code=FindingCode.AD_DIRECT_MEMBERS)
PRIMARY_GROUP = DependencyFinding("1 object(s) use this group as their primary group (primaryGroupID 4321)", True,
                                  code=FindingCode.AD_PRIMARY_GROUP_REFERENCES)
PARENT_GROUP = DependencyFinding("member of group SYNTH-PARENT (corp.synthetic.example)", True,
                                 "CN=SYNTH-PARENT,OU=Groups,DC=corp,DC=synthetic,DC=example", FindingCode.AD_PARENT_GROUP)
MEMBER_GROUPS = DependencyFinding("contains 1 member group(s)", True, code=FindingCode.AD_MEMBER_GROUPS)
NESTED_PRINCIPALS = DependencyFinding("3 principal(s) reachable through member groups", True,
                                      code=FindingCode.AD_NESTED_PRINCIPALS)
NESTING_CYCLE = DependencyFinding("group nesting contains a cycle", False, code=FindingCode.AD_NESTING_CYCLE)
OTHER_APP = DependencyFinding("assigned to synthetic application 0oaSYNTHAPP0099", True,
                              code=FindingCode.OKTA_OTHER_APP_ASSIGNMENT)
UNCODED = DependencyFinding("synthetic finding without a code", True)
GPO = DependencyFinding("security filtering of synthetic GPO SYNTH-GPO-1", True, "synthetic-gpo")


def dependency_id(kind: DependencyKind) -> str:
    return fixed_id(IdKind.DEPENDENCY_EVIDENCE, sorted(DependencyKind).index(kind) + 1)


def check(at, kind: DependencyKind, findings=(), status=ResultStatus.COMPLETE, source=EvidenceSource.SYNTHETIC,
          subject_id=None) -> DependencyEvidence:
    return DependencyEvidence(
        id=dependency_id(kind),
        subject_id=subject_id or (GROUP_ID if kind in OKTA_KINDS else AD_ID),
        kind=kind,
        findings=tuple(findings),
        provenance=prov(at, status, source),
    )


def checks(at, kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS) -> tuple[DependencyEvidence, ...]:
    return tuple(check(at, kind) for kind in sorted(kinds))


def world(at=T0, **overrides) -> EvidenceBundle:
    fields = dict(
        okta_group=okta_group(at),
        applications=(application(at),),
        assignments=(assignment(at),),
        usage=(usage(at),),
        mapping=mapping(at),
        ad_group=ad_group(at),
        dependencies=checks(at),
    )
    fields.update(overrides)
    return EvidenceBundle(**fields)


def with_check(bundle: EvidenceBundle, kind: DependencyKind, record: DependencyEvidence | None) -> EvidenceBundle:
    """Replace (or, with None, remove) the check of one kind."""
    others = tuple(d for d in bundle.dependencies if d.kind is not kind)
    return replace(bundle, dependencies=others + ((record,) if record is not None else ()))


def run(bundle: EvidenceBundle, policy: CandidatePolicy = CPOLICY, subject: CandidateSubject = SUBJECT, now=NOW):
    return classify(bundle, subject, policy, now)
