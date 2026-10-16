"""Synthetic domain fixtures. Every name, id, SID, and GUID here is invented.

The world: synthetic Okta group G is assigned to synthetic application A and maps
exactly (by objectGUID) to synthetic AD group X.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalRecord, ApprovalStage
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.execution import ExecutionJob, JobKind, JobStatus
from app.domain.ids import IdKind
from app.domain.lifecycle import LifecycleCandidate, LifecycleState, TransitionRequest, apply_transition
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    DependencyFinding,
    DependencyKind,
    IdentityMapping,
    MappingConfidence,
    OktaApplication,
    OktaAppStatus,
    OktaGroup,
    OktaGroupType,
)
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS, EvidenceBundle, LifecyclePolicy, evidence_fingerprint
from app.domain.quarantine import QuarantineOus

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

SYSTEM = Actor(ActorKind.SYSTEM, "collector/synthetic")
REVIEWER = Actor(ActorKind.HUMAN, "synthetic-reviewer-1")  # approves the Okta unassignment
SECOND_REVIEWER = Actor(ActorKind.HUMAN, "synthetic-reviewer-2")  # approves the AD quarantine
THIRD_REVIEWER = Actor(ActorKind.HUMAN, "synthetic-reviewer-3")  # proposes the AD deletion
FOURTH_REVIEWER = Actor(ActorKind.HUMAN, "synthetic-reviewer-4")  # approves the AD deletion

SYNTHETIC_AD_SOURCE_ID = "0oaSYNTHDIR0001"  # the synthetic Okta AD integration
POLICY = LifecyclePolicy(ad_directory_source_ids=frozenset({SYNTHETIC_AD_SOURCE_ID}))

SYNTHETIC_DOMAIN = "corp.synthetic.example"
SYNTHETIC_DOMAIN_SID = "S-1-5-21-1000000001-1000000002-1000000003"
SYNTHETIC_GUID = "5e1f0c3a-0000-4000-8000-000000000001"
QUARANTINE_OU = "OU=OGWA-Quarantine,DC=corp,DC=synthetic,DC=example"
QUARANTINE_OUS = QuarantineOus("SYNTHETIC", ((SYNTHETIC_DOMAIN, QUARANTINE_OU),))
GROUP_DN = "CN=SYNTH-GROUP-001,OU=Groups,DC=corp,DC=synthetic,DC=example"
QUARANTINED_DN = f"CN=SYNTH-GROUP-001,{QUARANTINE_OU}"


def fixed_id(kind: IdKind, n: int) -> str:
    return f"{kind.value}_{n:032x}"


GROUP_ID = fixed_id(IdKind.OKTA_GROUP, 1)
APP_ID = fixed_id(IdKind.OKTA_APPLICATION, 1)
ASSIGNMENT_ID = fixed_id(IdKind.ASSIGNMENT, 1)
USAGE_ID = fixed_id(IdKind.USAGE_OBSERVATION, 1)
AD_ID = fixed_id(IdKind.AD_GROUP, 1)
AD_ID_2 = fixed_id(IdKind.AD_GROUP, 2)
MAPPING_ID = fixed_id(IdKind.IDENTITY_MAPPING, 1)


def prov(at: datetime, status: ResultStatus = ResultStatus.COMPLETE, source: EvidenceSource = EvidenceSource.SYNTHETIC) -> Provenance:
    return Provenance(source=source, observed_at=at, scope="synthetic:scope", collector_version="synthetic-1.0", result_status=status)


def okta_group(at, **kw) -> OktaGroup:
    fields = dict(
        id=GROUP_ID,
        okta_group_id="00gSYNTHETIC0001",
        name="SYNTH-GROUP-001",
        group_type=OktaGroupType.APP_GROUP,
        provenance=prov(at),
        source_directory_id=SYNTHETIC_AD_SOURCE_ID,
        directory_external_id=SYNTHETIC_GUID,
        directory_qualified_name="SYNTH\\SYNTH-GROUP-001",
    )
    fields.update(kw)
    return OktaGroup(**fields)


def application(at, **kw) -> OktaApplication:
    fields = dict(id=APP_ID, okta_app_id="0oaSYNTHAPP0001", label="Synthetic App", status=OktaAppStatus.ACTIVE,
                  sign_on_mode="SAML_2_0", provenance=prov(at))
    fields.update(kw)
    return OktaApplication(**fields)


def assignment(at, present=True, status=ResultStatus.COMPLETE, **kw) -> ApplicationGroupAssignment:
    fields = dict(id=ASSIGNMENT_ID, application_id=APP_ID, okta_group_id=GROUP_ID, present=present, provenance=prov(at, status))
    fields.update(kw)
    return ApplicationGroupAssignment(**fields)


def usage(at, events=0, window_days=90, status=ResultStatus.COMPLETE, **kw) -> ApplicationUsageObservation:
    fields = dict(id=USAGE_ID, application_id=APP_ID, okta_group_id=None, window_start=at - timedelta(days=window_days),
                  window_end=at, event_count=events, distinct_user_count=min(events, 1), last_activity_at=None,
                  provenance=prov(at, status))
    if events:
        fields["last_activity_at"] = at - DAY
    fields.update(kw)
    return ApplicationUsageObservation(**fields)


def ad_group(at, exists=True, rid=4321, quarantined=False, **kw) -> ADGroup:
    fields = dict(id=AD_ID, object_guid=SYNTHETIC_GUID, domain=SYNTHETIC_DOMAIN, exists=exists, provenance=prov(at, source=EvidenceSource.SYNTHETIC),
                  sid=f"{SYNTHETIC_DOMAIN_SID}-{rid}", distinguished_name=QUARANTINED_DN if quarantined else GROUP_DN,
                  sam_account_name="SYNTH-GROUP-001", member_count=0)
    if not exists:
        fields.update(sid=None, distinguished_name=None, sam_account_name=None, member_count=None)
    fields.update(kw)
    return ADGroup(**fields)


def mapping(at, confidence=MappingConfidence.EXACT_STABLE_ID, **kw) -> IdentityMapping:
    fields = dict(id=MAPPING_ID, okta_group_id=GROUP_ID, confidence=confidence, ad_group_id=AD_ID,
                  reason="Okta group externalId equals the AD objectGUID", provenance=prov(at), matched_attributes=("objectGUID",))
    if confidence is MappingConfidence.NAME_ONLY:
        fields.update(matched_attributes=("sAMAccountName",), reason="names match")
    elif confidence is MappingConfidence.AMBIGUOUS:
        fields.update(ad_group_id=None, matched_attributes=("sAMAccountName",), candidate_ad_group_ids=(AD_ID, AD_ID_2),
                      reason="same name in two domains")
    elif confidence is MappingConfidence.NOT_FOUND:
        fields.update(ad_group_id=None, matched_attributes=(), reason="no AD object found")
    elif confidence is MappingConfidence.EXACT_DIRECTORY_SOURCE:
        fields.update(matched_attributes=("source_directory_id", "dn"))
    elif confidence is MappingConfidence.EXACT_CONFIGURED_MAPPING:
        fields.update(configuration_ref="mappings/synthetic.toml#1", provenance=prov(at, source=EvidenceSource.CONFIGURED_MAPPING))
    fields.update(kw)
    return IdentityMapping(**fields)


def dependency(at, kind: DependencyKind, n: int, findings=(), status=ResultStatus.COMPLETE, subject_id=None) -> DependencyEvidence:
    return DependencyEvidence(id=fixed_id(IdKind.DEPENDENCY_EVIDENCE, n), subject_id=subject_id or AD_ID, kind=kind,
                              findings=tuple(findings), provenance=prov(at, status))


def dependencies(at, kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS) -> tuple[DependencyEvidence, ...]:
    return tuple(dependency(at, kind, n) for n, kind in enumerate(sorted(kinds), start=1))


def blocking_finding() -> DependencyFinding:
    return DependencyFinding(description="referenced by a synthetic file-share ACL", blocking=True, reference="synthetic-share")


def bundle(at, *, present=True, ad_exists=True, confidence=MappingConfidence.EXACT_STABLE_ID, dep_kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS,
           usage_events=0, quarantined=False, **overrides) -> EvidenceBundle:
    unresolved = confidence in (MappingConfidence.AMBIGUOUS, MappingConfidence.NOT_FOUND)
    fields = dict(
        okta_group=okta_group(at),
        applications=(application(at),),
        assignments=(assignment(at, present=present),),
        usage=(usage(at, events=usage_events),),
        mapping=mapping(at, confidence=confidence),
        ad_group=None if unresolved else ad_group(at, exists=ad_exists, quarantined=quarantined),
        # Dependency checks here are about AD group X, which an unresolved mapping does not name.
        dependencies=() if unresolved else dependencies(at, dep_kinds),
    )
    fields.update(overrides)
    return EvidenceBundle(**fields)


STAGE_NUMBER = {ApprovalStage.OKTA_UNASSIGN: 1, ApprovalStage.AD_QUARANTINE: 2, ApprovalStage.AD_DELETION: 3,
                ApprovalStage.AD_RETIREMENT: 4}
KIND_NUMBER = {JobKind.OKTA_UNASSIGN: 1, JobKind.AD_QUARANTINE: 2, JobKind.AD_DELETION: 3, JobKind.AD_RETIREMENT: 4}


def approval(candidate, stage, decided_at, evidence, operator=REVIEWER, ttl=7 * DAY, **kw) -> ApprovalRecord:
    fields = dict(id=fixed_id(IdKind.APPROVAL, STAGE_NUMBER[stage]), candidate_id=candidate.id, stage=stage,
                  decision=ApprovalDecision.APPROVE, operator=operator, decided_at=decided_at, reason="synthetic review complete",
                  evidence_fingerprint=evidence_fingerprint(evidence), candidate_epoch=candidate.epoch, expires_at=decided_at + ttl)
    fields.update(kw)
    return ApprovalRecord(**fields)


def dry_run_job(candidate, kind, approval_record, evidence, requested_at, finished_at, **kw) -> ExecutionJob:
    targets = (ASSIGNMENT_ID,) if kind is JobKind.OKTA_UNASSIGN else (AD_ID,)
    fields = dict(id=fixed_id(IdKind.EXECUTION_JOB, KIND_NUMBER[kind]), candidate_id=candidate.id, kind=kind,
                  mode=ExecutionMode.DRY_RUN_MUTATION, dry_run=True, status=JobStatus.SUCCEEDED, requested_by=SYSTEM,
                  requested_at=requested_at, finished_at=finished_at, approval_id=approval_record.id,
                  evidence_fingerprint=evidence_fingerprint(evidence), targets=targets)
    fields.update(kw)
    return ExecutionJob(**fields)


def new_candidate(at=T0, proposed_by=SYSTEM) -> LifecycleCandidate:
    return LifecycleCandidate.discover(okta_group_id=GROUP_ID, assignment_ids=(ASSIGNMENT_ID,), proposed_by=proposed_by, now=at,
                                       reason_codes=("ZERO_USAGE_90D",))


class Journey:
    """Walks one synthetic candidate along the forward path, recording what was used.

    The Okta unassignment is approved by REVIEWER, the AD quarantine by SECOND_REVIEWER, and
    the deletion proposed by THIRD_REVIEWER and approved by FOURTH_REVIEWER (D11, D143)."""

    def __init__(self, policy: LifecyclePolicy = POLICY):
        self.policy = policy
        self.candidate = new_candidate()
        self.decisions = []
        self.pre = bundle(T0)  # evidence collected before unassignment
        self.unassign_approval = None
        self.unassign_job = None
        self.post = None  # evidence collected after the Okta hold
        self.quarantine_approval = None
        self.quarantine_job = None
        self.after_hold = None  # evidence collected after the post-quarantine hold
        self.deletion_approval = None
        self.deletion_job = None

    def step(self, target, at, actor=SYSTEM, evidence=None, approval_record=None, job=None, reason="synthetic step"):
        request = TransitionRequest(target=target, actor=actor, reason=reason, now=at, evidence=evidence or self.pre,
                                    approval=approval_record, job=job, quarantine_ous=QUARANTINE_OUS)
        result = apply_transition(self.candidate, request, self.policy)
        self.candidate = result.candidate
        self.decisions.append(result.decision)
        return result

    # Times along the happy path.
    T_CANDIDATE = T0 + HOUR
    T_REVIEW = T0 + 2 * HOUR
    T_APPROVE = T0 + 3 * HOUR
    T_UNASSIGN_DRY_RUN = T0 + 4 * HOUR
    T_UNASSIGNED_SEEN = T0 + DAY
    T_HOLD_ENDS = T_UNASSIGNED_SEEN + POLICY.hold_period
    T_QUARANTINE_APPROVE = T_HOLD_ENDS + HOUR
    T_QUARANTINE_DRY_RUN = T_HOLD_ENDS + 2 * HOUR
    T_QUARANTINE_SEEN = T_HOLD_ENDS + DAY
    T_QUARANTINE_HOLD_ENDS = T_QUARANTINE_SEEN + timedelta(days=30)
    T_DELETION_PROPOSED = T_QUARANTINE_HOLD_ENDS + HOUR
    T_DELETION_APPROVE = T_QUARANTINE_HOLD_ENDS + 2 * HOUR
    T_DELETION_DRY_RUN = T_QUARANTINE_HOLD_ENDS + 3 * HOUR
    T_RETIRED_SEEN = T_QUARANTINE_HOLD_ENDS + DAY

    PATH = (LifecycleState.CANDIDATE, LifecycleState.NEEDS_REVIEW, LifecycleState.APPROVED,
            LifecycleState.OKTA_UNASSIGN_DRY_RUN, LifecycleState.HOLD, LifecycleState.REVALIDATION_REQUIRED,
            LifecycleState.QUARANTINE_APPROVED, LifecycleState.QUARANTINE_DRY_RUN, LifecycleState.QUARANTINE_HOLD,
            LifecycleState.DELETION_REVALIDATION_REQUIRED, LifecycleState.DELETION_PROPOSED,
            LifecycleState.DELETION_APPROVED, LifecycleState.DELETION_DRY_RUN, LifecycleState.RETIRED)

    def to(self, state: LifecycleState) -> "Journey":
        for target in self.PATH[: self.PATH.index(state) + 1] if state in self.PATH else []:
            getattr(self, f"_to_{target.value.lower()}")()
        return self

    def _to_candidate(self):
        self.step(LifecycleState.CANDIDATE, self.T_CANDIDATE)

    def _to_needs_review(self):
        self.step(LifecycleState.NEEDS_REVIEW, self.T_REVIEW)

    def _to_approved(self):
        self.unassign_approval = approval(self.candidate, ApprovalStage.OKTA_UNASSIGN, self.T_APPROVE - timedelta(minutes=10), self.pre)
        self.step(LifecycleState.APPROVED, self.T_APPROVE, actor=REVIEWER, approval_record=self.unassign_approval)

    def _to_okta_unassign_dry_run(self):
        self.unassign_job = dry_run_job(self.candidate, JobKind.OKTA_UNASSIGN, self.unassign_approval, self.pre,
                                        self.T_APPROVE + timedelta(minutes=5), self.T_UNASSIGN_DRY_RUN - timedelta(minutes=5))
        self.step(LifecycleState.OKTA_UNASSIGN_DRY_RUN, self.T_UNASSIGN_DRY_RUN, approval_record=self.unassign_approval, job=self.unassign_job)

    def unassigned_evidence(self, at=None):
        at = at or self.T_UNASSIGNED_SEEN
        return replace(self.pre, assignments=(assignment(at, present=False),))

    def _to_hold(self):
        self.step(LifecycleState.HOLD, self.T_UNASSIGNED_SEEN, evidence=self.unassigned_evidence(),
                  approval_record=self.unassign_approval, job=self.unassign_job)

    def _to_revalidation_required(self):
        self.step(LifecycleState.REVALIDATION_REQUIRED, self.T_HOLD_ENDS, evidence=self.unassigned_evidence())

    def post_hold_evidence(self, at=None, **kw):
        kw.setdefault("present", False)
        return bundle(at or self.T_HOLD_ENDS, **kw)

    def _to_quarantine_approved(self):
        self.post = self.post_hold_evidence()
        self.quarantine_approval = approval(self.candidate, ApprovalStage.AD_QUARANTINE, self.T_QUARANTINE_APPROVE,
                                            self.post, operator=SECOND_REVIEWER)
        self.step(LifecycleState.QUARANTINE_APPROVED, self.T_QUARANTINE_APPROVE + timedelta(minutes=5),
                  actor=SECOND_REVIEWER, evidence=self.post, approval_record=self.quarantine_approval)

    def _to_quarantine_dry_run(self):
        self.quarantine_job = dry_run_job(self.candidate, JobKind.AD_QUARANTINE, self.quarantine_approval, self.post,
                                          self.T_QUARANTINE_APPROVE + timedelta(minutes=10),
                                          self.T_QUARANTINE_DRY_RUN - timedelta(minutes=5))
        self.step(LifecycleState.QUARANTINE_DRY_RUN, self.T_QUARANTINE_DRY_RUN, evidence=self.post,
                  approval_record=self.quarantine_approval, job=self.quarantine_job)

    def quarantined_evidence(self, at=None):
        at = at or self.T_QUARANTINE_SEEN
        return replace(self.post, ad_group=ad_group(at, quarantined=True))

    def _to_quarantine_hold(self):
        self.step(LifecycleState.QUARANTINE_HOLD, self.T_QUARANTINE_SEEN, evidence=self.quarantined_evidence(),
                  approval_record=self.quarantine_approval, job=self.quarantine_job)

    def _to_deletion_revalidation_required(self):
        self.step(LifecycleState.DELETION_REVALIDATION_REQUIRED, self.T_QUARANTINE_HOLD_ENDS,
                  evidence=self.quarantined_evidence())

    def post_quarantine_evidence(self, at=None, **kw):
        """Fresh, complete evidence collected after the post-quarantine hold, the group in quarantine."""
        kw.setdefault("present", False)
        kw.setdefault("quarantined", True)
        return bundle(at or self.T_QUARANTINE_HOLD_ENDS, **kw)

    def _to_deletion_proposed(self):
        self.after_hold = self.post_quarantine_evidence()
        self.step(LifecycleState.DELETION_PROPOSED, self.T_DELETION_PROPOSED, actor=THIRD_REVIEWER,
                  evidence=self.after_hold)

    def _to_deletion_approved(self):
        self.deletion_approval = approval(self.candidate, ApprovalStage.AD_DELETION, self.T_DELETION_APPROVE,
                                          self.after_hold, operator=FOURTH_REVIEWER)
        self.step(LifecycleState.DELETION_APPROVED, self.T_DELETION_APPROVE + timedelta(minutes=5),
                  actor=FOURTH_REVIEWER, evidence=self.after_hold, approval_record=self.deletion_approval)

    def _to_deletion_dry_run(self):
        self.deletion_job = dry_run_job(self.candidate, JobKind.AD_DELETION, self.deletion_approval, self.after_hold,
                                        self.T_DELETION_APPROVE + timedelta(minutes=10),
                                        self.T_DELETION_DRY_RUN - timedelta(minutes=5))
        self.step(LifecycleState.DELETION_DRY_RUN, self.T_DELETION_DRY_RUN, evidence=self.after_hold,
                  approval_record=self.deletion_approval, job=self.deletion_job)

    def retired_evidence(self, at=None):
        at = at or self.T_RETIRED_SEEN
        return replace(self.after_hold, ad_group=ad_group(at, exists=False))

    def _to_retired(self):
        self.step(LifecycleState.RETIRED, self.T_RETIRED_SEEN, evidence=self.retired_evidence(),
                  approval_record=self.deletion_approval, job=self.deletion_job)
