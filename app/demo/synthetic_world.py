"""Deterministic synthetic demo world for OGWA.

The fictional company "Synthetic Widgets Ltd" has an Okta org, two AD domains
(``corp.synthetic.example`` and ``emea.synthetic.example``, under the reserved
``.example`` TLD), and sixteen scenarios. Together they express every condition the
lifecycle has to handle (see ``Condition``). S15 and S16 reach the AD quarantine and
deletion stages through the same public API: a quarantine observed and its hold running,
and a deletion proposed after that hold and awaiting an independent approval. Every write goes through the public
``Store`` API, so seeding exercises the same validation, lifecycle guards, and audit
trail as real use.

Identity mappings are never written as already-exact evidence (owner decision). Each one is what the correlation engine proves over the synthetic AD
directory (the AD group evidence seeded so far) with the synthetic correlation
configuration, ``config/correlation.synthetic.json``; see
``app.demo.synthetic_directory.correlate_stored_group``. A scenario only states the
confidence it expects, and seeding stops if the engine proves something else.

Determinism: ids come from ``seeded_id``, ``deterministic_ids``, or ``mapping_id_for``, times
from fixed offsets of ``AS_OF``, and the store clock from ``SeedClock``. Seeding an empty
store twice gives byte-identical tables and the same audit head.
"""

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from app.core.database_url import DatabaseTarget
from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.domain.approval import ApprovalDecision, ApprovalRecord, ApprovalStage
from app.domain.collection import CollectorErrorCode, CollectorRun, CollectorRunOutcome
from app.domain.errors import TransitionRefused
from app.domain.evidence import EvidenceSource, Provenance, ResultStatus
from app.domain.execution import ExecutionJob, JobKind, JobStatus
from app.domain.ids import IdKind, deterministic_ids
from app.domain.lifecycle import LifecycleCandidate, LifecycleState, TransitionRequest, recommend_diversion
from app.demo.synthetic_directory import correlate_stored_group, load_synthetic_correlation_config
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    DependencyFinding,
    DependencyKind,
    MappingConfidence,
    OktaApplication,
    OktaAppStatus,
    OktaGroup,
    OktaGroupType,
)
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS, LifecyclePolicy, evidence_fingerprint
from app.remediation.quarantine import synthetic_quarantine_ous
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreError
from app.store.store import Store

SEED_NAMESPACE = "ogwa-synthetic-demo-v1"
AS_OF = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)  # the demo's "now"
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
MINUTE = timedelta(minutes=1)

COMPANY = "Synthetic Widgets Ltd (fictional)"
AD_SOURCE_ID = "0oaSYNTHADDIR01"  # the synthetic Okta AD integration
POLICY = LifecyclePolicy(ad_directory_source_ids=frozenset({AD_SOURCE_ID}))
COLLECTOR_VERSION = "synthetic-seed-1.0"


@dataclass(frozen=True)
class SyntheticDomain:
    dns: str
    netbios: str
    sid: str

    @property
    def dc(self) -> str:
        return ",".join(f"DC={part}" for part in self.dns.split("."))


CORP = SyntheticDomain("corp.synthetic.example", "SYNTHCORP", "S-1-5-21-1000000001-1000000002-1000000003")
EMEA = SyntheticDomain("emea.synthetic.example", "SYNTHEMEA", "S-1-5-21-2000000001-2000000002-2000000003")

SEEDER = Actor(ActorKind.SYSTEM, "ogwa/synthetic-seed")
COLLECTOR = Actor(ActorKind.SYSTEM, "collector/synthetic")
AAP_ADAPTER = Actor(ActorKind.SYSTEM, "adapter/aap-synthetic")
REVIEWER_1 = Actor(ActorKind.HUMAN, "synthetic.reviewer.one")
REVIEWER_2 = Actor(ActorKind.HUMAN, "synthetic.reviewer.two")
REVIEWER_3 = Actor(ActorKind.HUMAN, "synthetic.reviewer.three")  # proposes deletions (S16)
QUARANTINE_OU_NAME = "OGWA-Quarantine"  # config/quarantine-ous.synthetic.json


class Condition(StrEnum):
    """The conditions the demo world must express (the requirement list, in order)."""

    INACTIVE_APP_EMPTY_UNSHARED_GROUP = "inactive app + empty unshared group"
    ACTIVE_LOW_USE_APP = "active low-use app"
    SHARED_GROUP_MULTIPLE_APPS = "shared group across multiple apps"
    GROUP_WITH_AD_MEMBERS = "group with AD members"
    NESTED_AD_GROUP = "nested AD group"
    PROTECTED_GROUP = "protected group"
    EXACT_MAPPING = "exact mapping"
    NAME_ONLY_MAPPING = "name-only mapping"
    AMBIGUOUS_MAPPING = "ambiguous mapping"
    MISSING_GROUP = "missing group"
    STALE_EVIDENCE = "stale evidence"
    DEPENDENCY_COVERAGE_PARTIAL_OR_UNKNOWN = "dependency coverage partial/unknown"
    API_TIMEOUT_OR_RATE_LIMIT = "API timeout/rate-limit condition"
    AAP_DRY_RUN_FAILURE = "AAP dry-run job failure"
    # The AD quarantine and deletion stages.
    QUARANTINED_IN_HOLD = "AD group quarantined, post-quarantine hold running"
    DELETION_PROPOSED = "deletion proposed after the hold, awaiting an independent approval"


@dataclass(frozen=True)
class ScenarioResult:
    key: str
    title: str
    conditions: tuple[Condition, ...]
    candidate_id: str | None
    final_state: LifecycleState | None
    note: str


@dataclass(frozen=True)
class SeedSummary:
    namespace: str
    as_of: datetime
    scenarios: tuple[ScenarioResult, ...]
    audit_head: str


def seeded_id(kind: IdKind, label: str, namespace: str = SEED_NAMESPACE) -> str:
    return f"{kind.value}_{hashlib.sha256(f'{namespace}:{kind.value}:{label}'.encode()).hexdigest()[:32]}"


def synthetic_guid(n: int) -> str:
    return f"5e1f0c3a-0000-4000-8000-{n:012x}"


def synthetic_sid(domain: "SyntheticDomain", rid: int) -> str:
    return f"{domain.sid}-{rid}"


class SeedClock:
    """A deterministic store clock: starts after AS_OF and advances one second per reading."""

    def __init__(self, start: datetime = AS_OF + HOUR) -> None:
        self._next = start

    def __call__(self) -> datetime:
        value = self._next
        self._next += timedelta(seconds=1)
        return value


@dataclass(frozen=True)
class _Ids:
    app: str
    group: str
    assignment: str
    ad_group: str | None
    mapping: str


class _World:
    def __init__(self, store: Store, *, namespace: str = SEED_NAMESPACE, policy: LifecyclePolicy = POLICY,
                 correlation=None, ad_source_id: str = AD_SOURCE_ID) -> None:
        self.store = store
        self.namespace = namespace
        self.policy = policy
        # The policy reference decisions record. None (the classic world): decisions
        # record none, and the classic trail is unchanged.
        self.policy_ref = None
        self.ad_source_id = ad_source_id
        self.runs: dict[str, dict] = {}  # run id -> {"count": int, "last": datetime, "finished": bool}
        self.results: list[ScenarioResult] = []
        self.correlation = correlation if correlation is not None else load_synthetic_correlation_config()
        self.quarantine_ous = synthetic_quarantine_ous()
        self.directory = None  # a directory to correlate against; None: a fresh one per correlation

    def sid(self, kind: IdKind, label: str) -> str:
        """``seeded_id`` under this world's namespace."""
        return seeded_id(kind, label, self.namespace)

    # --- collector runs and observations -----------------------------------------------

    def run(self, collector: str, at: datetime, key: str | None = None) -> str:
        run_id = self.sid(IdKind.COLLECTOR_RUN, key or f"{collector}@{at.isoformat()}")
        if run_id not in self.runs:
            self.store.start_collector_run(CollectorRun(
                id=run_id, collector=collector, collector_version=COLLECTOR_VERSION, source=EvidenceSource.SYNTHETIC,
                mode=ExecutionMode.LOCAL_SYNTHETIC, scope=f"synthetic:{collector}", started_at=at - 5 * MINUTE,
                started_by=COLLECTOR,
            ))
            self.runs[run_id] = {"count": 0, "last": at - 5 * MINUTE, "finished": False}
        return run_id

    def finish_run(self, run_id: str, status: ResultStatus = ResultStatus.COMPLETE,
                   error: CollectorErrorCode | None = None, summary: str | None = None) -> None:
        state = self.runs[run_id]
        self.store.finish_collector_run(CollectorRunOutcome(
            run_id=run_id, finished_at=state["last"] + 2 * MINUTE, status=status, records_observed=state["count"],
            error_code=error, error_summary=summary,
        ), actor=COLLECTOR)
        state["finished"] = True

    def observe(self, record, collector: str, run_key: str | None = None):
        run_id = self.run(collector, record.provenance.observed_at, run_key)
        self.store.record_evidence(record, actor=COLLECTOR, collector_run_id=run_id)
        state = self.runs[run_id]
        state["count"] += 1
        state["last"] = max(state["last"], record.provenance.observed_at)
        return record

    @staticmethod
    def prov(at: datetime, scope: str, status: ResultStatus = ResultStatus.COMPLETE) -> Provenance:
        return Provenance(EvidenceSource.SYNTHETIC, at, scope, COLLECTOR_VERSION, status)

    def application(self, label: str, okta_app_id: str, name: str, status: OktaAppStatus, at: datetime) -> str:
        app_id = self.sid(IdKind.OKTA_APPLICATION, label)
        self.observe(OktaApplication(app_id, okta_app_id, name, status, "SAML_2_0",
                                     self.prov(at, f"synthetic:okta:app:{okta_app_id}")), "okta-apps")
        return app_id

    def okta_group(self, label: str, okta_group_id: str, name: str, at: datetime, *, domain: SyntheticDomain = CORP,
                   guid: str | None = None, sid: str | None = None,
                   group_type: OktaGroupType = OktaGroupType.APP_GROUP) -> str:
        """An Okta group; an APP_GROUP is imported by the synthetic AD integration.

        ``guid`` is Okta's rendering of the objectGUID (never used, D30) and ``sid`` Okta's
        copy of the objectSid, stored as unverified source metadata (0008, D37).
        """
        group_id = self.sid(IdKind.OKTA_GROUP, label)
        directory = {}
        if group_type is OktaGroupType.APP_GROUP:
            directory = dict(source_directory_id=self.ad_source_id, directory_external_id=guid,
                             directory_qualified_name=f"{domain.netbios}\\{name}",
                             directory_object_sid_unverified=sid)
        self.observe(OktaGroup(group_id, okta_group_id, name, group_type,
                               self.prov(at, f"synthetic:okta:group:{okta_group_id}"), **directory), "okta-apps")
        return group_id

    def assignment(self, label: str, app_id: str, group_id: str, at: datetime, present: bool = True) -> str:
        assignment_id = self.sid(IdKind.ASSIGNMENT, label)
        self.observe(ApplicationGroupAssignment(assignment_id, app_id, group_id, present,
                                                self.prov(at, f"synthetic:okta:app-groups:{label}")), "okta-apps")
        return assignment_id

    def usage(self, label: str, app_id: str, at: datetime, events: int = 0, users: int = 0,
              last_activity: datetime | None = None, status: ResultStatus = ResultStatus.COMPLETE,
              run_key: str | None = None) -> str:
        usage_id = self.sid(IdKind.USAGE_OBSERVATION, label)
        self.observe(ApplicationUsageObservation(
            usage_id, app_id, None, at - 90 * DAY, at, events, users, last_activity,
            self.prov(at, f"synthetic:okta:systemlog:app:{label}:90d", status),
        ), "okta-usage", run_key)
        return usage_id

    def ad_group(self, label: str, name: str, guid: str, rid: int, at: datetime, *, domain: SyntheticDomain = CORP,
                 exists: bool = True, members: int = 0, ou: str = "Groups", **flags) -> str:
        ad_id = self.sid(IdKind.AD_GROUP, label)
        attributes = dict(sid=synthetic_sid(domain, rid), distinguished_name=f"CN={name},OU={ou},{domain.dc}",
                          sam_account_name=name, member_count=members) if exists else {}
        self.observe(ADGroup(ad_id, guid, domain.dns, exists, self.prov(at, f"synthetic:ad:{domain.dns}:guid:{guid}"),
                             **attributes, **flags), "ad-groups")
        return ad_id

    def correlate(self, label: str, group_id: str, at: datetime, expect: MappingConfidence) -> str:
        """Record the mapping evidence the correlation engine proves for the group at ``at``.

        The engine's answer is never overridden. ``expect`` is the scenario's story; if the
        engine or the configuration proves something else, seeding stops.
        """
        result, mapping = correlate_stored_group(self.store, group_id, config=self.correlation, clock=lambda: at,
                                                 directory=self.directory)
        if mapping.confidence is not expect:
            raise StoreError(f"synthetic seed expected {label} to correlate as {expect.value}; "
                             f"the engine proved {mapping.confidence.value} ({result.outcome.value})")
        self.observe(mapping, "identity-mapping")
        return mapping.id

    def dependencies(self, label: str, group_id: str, ad_group_id: str | None, at: datetime,
                     kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS, findings: dict | None = None,
                     statuses: dict | None = None) -> None:
        findings, statuses = findings or {}, statuses or {}
        for kind in sorted(kinds):
            subject = group_id if kind.value.startswith("OKTA_") else ad_group_id
            if subject is None:
                continue
            self.observe(DependencyEvidence(
                self.sid(IdKind.DEPENDENCY_EVIDENCE, f"{label}:{kind.value}"), subject, kind,
                tuple(findings.get(kind, ())),
                self.prov(at, f"synthetic:deps:{label}:{kind.value}", statuses.get(kind, ResultStatus.COMPLETE)),
            ), "dependency-checks")

    def standard(self, n: int, at: datetime, *, app_name: str, app_status: OktaAppStatus, group_name: str,
                 events: int = 0, users: int = 0, members: int = 0,
                 mapping: MappingConfidence = MappingConfidence.EXACT_CONFIGURED_MAPPING,
                 dep_kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS, findings: dict | None = None, ad_exists: bool = True,
                 ad_flags: dict | None = None) -> _Ids:
        """One application, one group assigned to it, and its AD counterpart, correlated by the engine.

        ``mapping`` is the confidence the scenario expects the engine to prove.
        """
        s = f"S{n:02d}"
        guid, sid = synthetic_guid(n * 16), synthetic_sid(CORP, 5000 + n * 10)
        app = self.application(s, f"0oaSYNTHAPP{n:02d}", app_name, app_status, at)
        # A name-only scenario is one whose Okta record carries no directory identifier.
        name_only = mapping is MappingConfidence.NAME_ONLY
        group = self.okta_group(s, f"00gSYNTHGRP{n:02d}", group_name, at,
                                guid=None if name_only else guid, sid=None if name_only else sid)
        assignment = self.assignment(s, app, group, at)
        last = at - 20 * DAY if events else None
        self.usage(s, app, at, events, users, last)
        ad = self.ad_group(s, group_name, guid, 5000 + n * 10, at, exists=ad_exists, members=members, **(ad_flags or {}))
        mapping_id = self.correlate(s, group, at, mapping)
        self.dependencies(s, group, ad, at, dep_kinds, findings)
        return _Ids(app, group, assignment, ad, mapping_id)

    # --- lifecycle helpers -------------------------------------------------------------

    def candidate(self, ids: _Ids, at: datetime, *reason_codes: str) -> str:
        candidate = LifecycleCandidate.discover(okta_group_id=ids.group, assignment_ids=(ids.assignment,),
                                                proposed_by=COLLECTOR, now=at, reason_codes=reason_codes)
        self.store.create_candidate(candidate)
        return candidate.id

    def step(self, candidate_id: str, target: LifecycleState, at: datetime, *, actor: Actor = COLLECTOR,
             reason: str = "synthetic scenario step", approval=None, job=None, expect_refusal: bool = False) -> bool:
        candidate = self.store.load_candidate(candidate_id)
        request = TransitionRequest(target=target, actor=actor, reason=reason, now=at,
                                    evidence=self.store.evidence_bundle(candidate), approval=approval, job=job,
                                    quarantine_ous=self.quarantine_ous)
        try:
            self.store.transition(candidate_id, request, self.policy, policy_ref=self.policy_ref)
        except TransitionRefused as refused:
            if expect_refusal:
                return False
            raise StoreError(f"synthetic seed step unexpectedly refused: {refused}") from None
        if expect_refusal:
            raise StoreError(f"synthetic seed step to {target.value} was expected to be refused")
        return True

    def divert(self, candidate_id: str, at: datetime) -> LifecycleState:
        candidate = self.store.load_candidate(candidate_id)
        recommendation = recommend_diversion(candidate, self.store.evidence_bundle(candidate), at, self.policy)
        if recommendation is None:
            raise StoreError(f"synthetic seed expected a diversion for {candidate_id}")
        target, reason = recommendation
        self.step(candidate_id, target, at, reason=reason)
        return target

    def approve(self, candidate_id: str, label: str, stage: ApprovalStage, at: datetime, operator: Actor) -> ApprovalRecord:
        candidate = self.store.load_candidate(candidate_id)
        approval = ApprovalRecord(
            id=self.sid(IdKind.APPROVAL, label), candidate_id=candidate_id, stage=stage,
            decision=ApprovalDecision.APPROVE, operator=operator, decided_at=at,
            reason=f"synthetic review of {label} complete",
            evidence_fingerprint=evidence_fingerprint(self.store.evidence_bundle(candidate)),
            candidate_epoch=candidate.epoch, expires_at=at + 7 * DAY,
        )
        self.store.record_approval(approval, policy_ref=self.policy_ref)
        return approval

    def dry_run(self, candidate_id: str, label: str, kind: JobKind, approval: ApprovalRecord, requested_at: datetime,
                finished_at: datetime, targets: tuple[str, ...], final: JobStatus = JobStatus.SUCCEEDED,
                detail: str | None = None) -> ExecutionJob:
        candidate = self.store.load_candidate(candidate_id)
        planned = ExecutionJob(
            id=self.sid(IdKind.EXECUTION_JOB, label), candidate_id=candidate_id, kind=kind,
            mode=ExecutionMode.DRY_RUN_MUTATION, dry_run=True, status=JobStatus.PLANNED, requested_by=AAP_ADAPTER,
            requested_at=requested_at, approval_id=approval.id,
            evidence_fingerprint=evidence_fingerprint(self.store.evidence_bundle(candidate)), targets=targets,
        )
        external_ref = f"aap-synthetic-job-{label}"
        self.store.record_execution_job(planned)
        self.store.record_execution_job(replace(planned, status=JobStatus.RUNNING), external_ref=external_ref)
        finished = replace(planned, status=final, finished_at=finished_at)
        self.store.record_execution_job(finished, external_ref=external_ref, detail=detail)
        return finished

    def walk_to_hold(self, candidate_id: str, ids: _Ids, label: str, t: datetime) -> None:
        """CANDIDATE -> ... -> HOLD: approval, a successful dry run, then the unassignment observed."""
        self.step(candidate_id, LifecycleState.CANDIDATE, t + HOUR)
        self.step(candidate_id, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        approval = self.approve(candidate_id, f"{label}-okta", ApprovalStage.OKTA_UNASSIGN, t + 3 * HOUR, REVIEWER_1)
        self.step(candidate_id, LifecycleState.APPROVED, t + 3 * HOUR + 5 * MINUTE, actor=REVIEWER_1, approval=approval,
                  reason="synthetic reviewer approved the Okta unassignment")
        job = self.dry_run(candidate_id, f"{label}-okta", JobKind.OKTA_UNASSIGN, approval, t + 3 * HOUR + 10 * MINUTE,
                           t + 3 * HOUR + 40 * MINUTE, (ids.assignment,))
        self.step(candidate_id, LifecycleState.OKTA_UNASSIGN_DRY_RUN, t + 4 * HOUR, approval=approval, job=job)
        self.assignment(label, ids.app, ids.group, t + DAY, present=False)
        self.step(candidate_id, LifecycleState.HOLD, t + DAY + 10 * MINUTE, approval=approval, job=job,
                  reason="read-only discovery observed the assignment removed")

    def revalidate(self, n: int, ids: _Ids, at: datetime, *, app_name: str, group_name: str,
                   quarantined: bool = False, kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS, statuses: dict | None = None) -> None:
        """Re-observe a ``standard`` scenario's evidence at ``at``, after its Okta unassignment:
        the assignment absent, the AD group in its usual OU or in its domain's quarantine OU."""
        s = f"S{n:02d}"
        guid, rid = synthetic_guid(n * 16), 5000 + n * 10
        self.application(s, f"0oaSYNTHAPP{n:02d}", app_name, OktaAppStatus.INACTIVE, at)
        self.okta_group(s, f"00gSYNTHGRP{n:02d}", group_name, at, guid=guid, sid=synthetic_sid(CORP, rid))
        self.assignment(s, ids.app, ids.group, at, present=False)
        self.usage(s, ids.app, at)
        self.ad_group(s, group_name, guid, rid, at, ou=QUARANTINE_OU_NAME if quarantined else "Groups")
        self.correlate(s, ids.group, at, MappingConfidence.EXACT_CONFIGURED_MAPPING)
        self.dependencies(s, ids.group, ids.ad_group, at, kinds, statuses=statuses)

    def walk_to_quarantine_hold(self, candidate_id: str, ids: _Ids, n: int, q: datetime, *, app_name: str,
                                group_name: str) -> None:
        """REVALIDATION_REQUIRED -> ... -> QUARANTINE_HOLD: fresh evidence at ``q``, a second
        reviewer's quarantine approval, a successful dry run, then the group observed in its
        quarantine OU."""
        label = f"S{n:02d}"
        self.revalidate(n, ids, q, app_name=app_name, group_name=group_name)
        approval = self.approve(candidate_id, f"{label}-quarantine", ApprovalStage.AD_QUARANTINE, q + HOUR, REVIEWER_2)
        self.step(candidate_id, LifecycleState.QUARANTINE_APPROVED, q + HOUR + 5 * MINUTE, actor=REVIEWER_2,
                  approval=approval, reason="synthetic second reviewer approved the AD quarantine")
        job = self.dry_run(candidate_id, f"{label}-quarantine", JobKind.AD_QUARANTINE, approval,
                           q + HOUR + 10 * MINUTE, q + HOUR + 40 * MINUTE, (ids.ad_group,))
        self.step(candidate_id, LifecycleState.QUARANTINE_DRY_RUN, q + 2 * HOUR, approval=approval, job=job)
        self.ad_group(label, group_name, synthetic_guid(n * 16), 5000 + n * 10, q + DAY, ou=QUARANTINE_OU_NAME)
        self.step(candidate_id, LifecycleState.QUARANTINE_HOLD, q + DAY + 10 * MINUTE, approval=approval, job=job,
                  reason="read-only discovery observed the group in its quarantine OU")

    def result(self, key: str, title: str, conditions: tuple[Condition, ...], candidate_id: str | None, note: str) -> None:
        state = self.store.load_candidate(candidate_id).state if candidate_id else None
        self.results.append(ScenarioResult(key, title, conditions, candidate_id, state, note))


# --- scenarios ------------------------------------------------------------------------


def _s01(w: _World) -> None:
    t = AS_OF - 3 * DAY
    ids = w.standard(1, t, app_name="SYNTH Legacy Timesheets", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-TIMESHEETS-USERS")
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.walk_to_hold(cid, ids, "S01", t)
    w.result("S01", "Inactive app with an empty, unshared group", (
        Condition.INACTIVE_APP_EMPTY_UNSHARED_GROUP, Condition.EXACT_MAPPING,
    ), cid, "Walked the full Okta path: approval, successful dry run, unassignment observed; now in its hold period.")


def _s02(w: _World) -> None:
    t = AS_OF - DAY
    ids = w.standard(2, t, app_name="SYNTH Expense Archive", app_status=OktaAppStatus.ACTIVE,
                     group_name="SYNTH-APP-EXPENSE-ARCHIVE", events=3, users=2)
    cid = w.candidate(ids, t + 30 * MINUTE, "LOW_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR, expect_refusal=True)
    w.result("S02", "Active app with low use", (Condition.ACTIVE_LOW_USE_APP,), cid,
             "3 sign-ins by 2 users in 90 days exceeds the candidacy threshold (0); the refusal is audited.")


def _s03(w: _World) -> None:
    t = AS_OF - DAY
    other_app = w.application("S03B", "0oaSYNTHAPP03B", "SYNTH Reporting Portal", OktaAppStatus.ACTIVE, t)
    ids = w.standard(3, t, app_name="SYNTH Quarterly Reports (legacy)", app_status=OktaAppStatus.ACTIVE,
                     group_name="SYNTH-SHARED-REPORTING", findings={
                         DependencyKind.OKTA_OTHER_APP_ASSIGNMENT: (DependencyFinding(
                             "group is also assigned to SYNTH Reporting Portal", True, "okta:app:0oaSYNTHAPP03B"),),
                     })
    w.assignment("S03B", other_app, ids.group, t)
    w.usage("S03B", other_app, t, events=250, users=40, last_activity=t - DAY)
    cid = w.candidate(ids, t + 30 * MINUTE, "ZERO_USAGE_90D")
    w.divert(cid, t + HOUR)
    w.result("S03", "Group shared by two applications", (Condition.SHARED_GROUP_MULTIPLE_APPS,), cid,
             "Unused by one app but still assigned to an active one; blocked on the dependency.")


def _s04(w: _World) -> None:
    t = AS_OF - DAY
    ids = w.standard(4, t, app_name="SYNTH Travel Booking (retired)", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-TRAVEL-USERS", members=14, findings={
                         DependencyKind.AD_GROUP_MEMBERS: (DependencyFinding("14 direct members (synthetic users)", True),),
                     })
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.divert(cid, t + HOUR)
    w.result("S04", "Group that still has AD members", (Condition.GROUP_WITH_AD_MEMBERS,), cid,
             "The AD group has 14 members; blocked until membership is reviewed.")


def _s05(w: _World) -> None:
    t = AS_OF - DAY
    parent_guid = synthetic_guid(5 * 16 + 1)
    parent = w.ad_group("S05-parent", "SYNTH-ROLE-FINANCE-ALL", parent_guid, 5051, t, members=3)
    parent_dn = f"CN=SYNTH-ROLE-FINANCE-ALL,OU=Groups,{CORP.dc}"
    ids = w.standard(5, t, app_name="SYNTH Budget Planner", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-BUDGET-PLANNERS", findings={
                         DependencyKind.AD_NESTED_MEMBERSHIP: (DependencyFinding(
                             "member of SYNTH-ROLE-FINANCE-ALL", True, parent_dn),),
                     })
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.divert(cid, t + HOUR)
    w.result("S05", "Nested AD group", (Condition.NESTED_AD_GROUP,), cid,
             f"Nested in a role group ({parent}); retiring it would change effective access.")


def _s06(w: _World) -> None:
    t = AS_OF - DAY
    ids = w.standard(6, t, app_name="SYNTH Infrastructure Console", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-TIER0-OPERATORS",
                     ad_flags={"admin_count": True, "protected_from_accidental_deletion": True})
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.divert(cid, t + HOUR)
    w.result("S06", "Protected (privileged) group", (Condition.PROTECTED_GROUP,), cid,
             "adminCount and ProtectedFromAccidentalDeletion are set; PROTECTED is terminal.")


def _s07(w: _World) -> None:
    t = AS_OF - DAY
    ids = w.standard(7, t, app_name="SYNTH Visitor Badges", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-VISITOR-BADGES", dep_kinds=frozenset())
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR)
    w.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
    w.result("S07", "Exact configured mapping, no dependency checks yet", (
        Condition.EXACT_MAPPING, Condition.DEPENDENCY_COVERAGE_PARTIAL_OR_UNKNOWN,
    ), cid, "Awaiting review. No dependency kind has been checked, so coverage is UNKNOWN.")


def _s08(w: _World) -> None:
    t = AS_OF - 2 * DAY
    ids = w.standard(8, t, app_name="SYNTH Print Release", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-PRINT-RELEASE", mapping=MappingConfidence.NAME_ONLY)
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR)
    w.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
    approval = w.approve(cid, "S08-okta", ApprovalStage.OKTA_UNASSIGN, t + 3 * HOUR, REVIEWER_1)
    w.step(cid, LifecycleState.APPROVED, t + 3 * HOUR + 5 * MINUTE, actor=REVIEWER_1, approval=approval,
           reason="synthetic reviewer attempted approval", expect_refusal=True)
    w.result("S08", "Name-only mapping", (Condition.NAME_ONLY_MAPPING,), cid,
             "Not in the mapping configuration, so the engine can only match the name; a reviewer's "
             "approval is refused: NAME_ONLY correlation can never authorize a change.")


def _s09(w: _World) -> None:
    t = AS_OF - DAY
    name = "SYNTH-APP-WIKI-EDITORS"
    app = w.application("S09", "0oaSYNTHAPP09", "SYNTH Team Wiki (old)", OktaAppStatus.INACTIVE, t)
    group = w.okta_group("S09", "00gSYNTHGRP09", name, t, guid=None)
    assignment = w.assignment("S09", app, group, t)
    w.usage("S09", app, t)
    corp = w.ad_group("S09-corp", name, synthetic_guid(9 * 16), 5090, t)
    emea = w.ad_group("S09-emea", name, synthetic_guid(9 * 16 + 1), 5091, t, domain=EMEA)
    mapping = w.correlate("S09", group, t, MappingConfidence.AMBIGUOUS)
    w.dependencies("S09", group, None, t)
    cid = w.candidate(_Ids(app, group, assignment, None, mapping), t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.divert(cid, t + HOUR)
    w.result("S09", "Ambiguous mapping across two domains", (Condition.AMBIGUOUS_MAPPING,), cid,
             f"The same sAMAccountName exists in corp ({corp}) and emea ({emea}); the engine's name search "
             "fails closed to MAPPING_AMBIGUOUS.")


def _s10(w: _World) -> None:
    t = AS_OF - DAY
    ids = w.standard(10, t, app_name="SYNTH Canteen Menu", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-CANTEEN-MENU", ad_exists=False, dep_kinds=frozenset(),
                     mapping=MappingConfidence.NOT_FOUND)
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR)
    w.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
    w.step(cid, LifecycleState.BLOCKED, t + 3 * HOUR, actor=REVIEWER_1,
           reason="mapped AD group not found by objectGUID; find out who removed it before going further")
    w.result("S10", "Mapped AD group missing", (Condition.MISSING_GROUP,), cid,
             "The configured objectGUID no longer resolves anywhere in the forest, so the engine records "
             "NOT_FOUND (MAPPING_UNRESOLVABLE); a reviewer blocked the candidate.")


def _s11(w: _World) -> None:
    t = AS_OF - 120 * DAY
    ids = w.standard(11, t, app_name="SYNTH Holiday Planner", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-HOLIDAY-PLANNER")
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR)
    w.divert(cid, AS_OF - HOUR)
    w.result("S11", "Stale evidence", (Condition.STALE_EVIDENCE,), cid,
             "Evidence collected 120 days ago is too old for review (30 days); parked as STALE_EVIDENCE.")


def _s12(w: _World) -> None:
    t = AS_OF - 40 * DAY
    some_kinds = frozenset({DependencyKind.OKTA_OTHER_APP_ASSIGNMENT, DependencyKind.OKTA_POLICY_REFERENCE,
                            DependencyKind.AD_GROUP_MEMBERS})
    ids = w.standard(12, t, app_name="SYNTH Asset Register (v1)", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-ASSET-REGISTER", dep_kinds=some_kinds)
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.walk_to_hold(cid, ids, "S12", t)
    hold_until = w.store.load_candidate(cid).hold_until
    w.step(cid, LifecycleState.REVALIDATION_REQUIRED, hold_until + HOUR, reason="hold period ended")
    # Post-hold revalidation evidence: re-observed, but only some dependency kinds were checked
    # and the ACL check was interrupted.
    p = AS_OF - DAY
    guid = synthetic_guid(12 * 16)
    w.application("S12", "0oaSYNTHAPP12", "SYNTH Asset Register (v1)", OktaAppStatus.INACTIVE, p)
    w.okta_group("S12", "00gSYNTHGRP12", "SYNTH-APP-ASSET-REGISTER", p, guid=guid, sid=synthetic_sid(CORP, 5120))
    w.assignment("S12", ids.app, ids.group, p, present=False)
    w.usage("S12", ids.app, p)
    w.ad_group("S12", "SYNTH-APP-ASSET-REGISTER", guid, 5120, p)
    w.correlate("S12", ids.group, p, MappingConfidence.EXACT_CONFIGURED_MAPPING)
    w.dependencies("S12", ids.group, ids.ad_group, p, some_kinds | {DependencyKind.AD_ACL_REFERENCE},
                   statuses={DependencyKind.AD_ACL_REFERENCE: ResultStatus.PARTIAL})
    approval = w.approve(cid, "S12-quarantine", ApprovalStage.AD_QUARANTINE, p + HOUR, REVIEWER_2)
    w.step(cid, LifecycleState.QUARANTINE_APPROVED, p + HOUR + 5 * MINUTE, actor=REVIEWER_2, approval=approval,
           reason="synthetic second reviewer attempted the AD quarantine approval", expect_refusal=True)
    w.result("S12", "Partial dependency coverage at the AD stage", (Condition.DEPENDENCY_COVERAGE_PARTIAL_OR_UNKNOWN,),
             cid, "Hold ended and revalidation began, but the AD quarantine approval is refused: coverage is PARTIAL.")


def _s13(w: _World) -> None:
    t = AS_OF - 6 * HOUR
    s = "S13"
    app = w.application(s, "0oaSYNTHAPP13", "SYNTH Parking Permits", OktaAppStatus.ACTIVE, t)
    group = w.okta_group(s, "00gSYNTHGRP13", "SYNTH-APP-PARKING-PERMITS", t, guid=synthetic_guid(13 * 16),
                         sid=synthetic_sid(CORP, 5130))
    assignment = w.assignment(s, app, group, t)
    usage_run = w.run("okta-usage", t, key="S13-usage-rate-limited")
    w.usage(s, app, t, status=ResultStatus.PARTIAL, run_key="S13-usage-rate-limited")
    w.finish_run(usage_run, ResultStatus.PARTIAL, CollectorErrorCode.RATE_LIMITED,
                 "HTTP 429 from the synthetic System Log API; Retry-After 180s exceeds the 120s ceiling, paging stopped")
    ad_run = w.run("ad-groups", t, key="S13-ad-timeout")
    w.finish_run(ad_run, ResultStatus.FAILED, CollectorErrorCode.TIMEOUT,
                 "read timeout after 30s querying emea.synthetic.example through the synthetic AAP worker")
    cid = w.candidate(_Ids(app, group, assignment, None, ""), t + 30 * MINUTE, "ZERO_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR, expect_refusal=True)
    w.result("S13", "Collector timeout and rate limiting", (Condition.API_TIMEOUT_OR_RATE_LIMIT,), cid,
             "Usage collection was rate-limited (PARTIAL) and the AD lookup timed out; candidacy is refused.")


def _s14(w: _World) -> None:
    t = AS_OF - DAY
    ids = w.standard(14, t, app_name="SYNTH Survey Tool", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-SURVEY-TOOL")
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.step(cid, LifecycleState.CANDIDATE, t + HOUR)
    w.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
    approval = w.approve(cid, "S14-okta", ApprovalStage.OKTA_UNASSIGN, t + 3 * HOUR, REVIEWER_1)
    w.step(cid, LifecycleState.APPROVED, t + 3 * HOUR + 5 * MINUTE, actor=REVIEWER_1, approval=approval,
           reason="synthetic reviewer approved the Okta unassignment")
    job = w.dry_run(cid, "S14-okta", JobKind.OKTA_UNASSIGN, approval, t + 3 * HOUR + 10 * MINUTE,
                    t + 3 * HOUR + 25 * MINUTE, (ids.assignment,), final=JobStatus.FAILED,
                    detail="AAP check-mode job failed: synthetic inventory host unreachable")
    w.step(cid, LifecycleState.OKTA_UNASSIGN_DRY_RUN, t + 4 * HOUR, approval=approval, job=job, expect_refusal=True)
    w.result("S14", "AAP dry-run job failure", (Condition.AAP_DRY_RUN_FAILURE,), cid,
             "The dry run failed in AAP; the candidate stays APPROVED and the refusal is audited.")


def _s15(w: _World) -> None:
    t = AS_OF - 40 * DAY
    names = dict(app_name="SYNTH Room Booking (v1)", group_name="SYNTH-APP-ROOM-BOOKING")
    ids = w.standard(15, t, app_status=OktaAppStatus.INACTIVE, **names)
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.walk_to_hold(cid, ids, "S15", t)
    hold_until = w.store.load_candidate(cid).hold_until
    w.step(cid, LifecycleState.REVALIDATION_REQUIRED, hold_until + HOUR, reason="hold period ended")
    w.walk_to_quarantine_hold(cid, ids, 15, AS_OF - 3 * DAY, **names)
    w.result("S15", "Quarantined; post-quarantine hold running", (Condition.QUARANTINED_IN_HOLD,), cid,
             "A second reviewer approved the AD quarantine, its dry run succeeded, and discovery saw the group in "
             "its quarantine OU. The 30-day hold runs; its end authorizes nothing (D138, D139).")


def _s16(w: _World) -> None:
    t = AS_OF - 80 * DAY
    names = dict(app_name="SYNTH Fax Gateway", group_name="SYNTH-APP-FAX-GATEWAY")
    ids = w.standard(16, t, app_status=OktaAppStatus.INACTIVE, **names)
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.walk_to_hold(cid, ids, "S16", t)
    hold_until = w.store.load_candidate(cid).hold_until
    w.step(cid, LifecycleState.REVALIDATION_REQUIRED, hold_until + HOUR, reason="hold period ended")
    w.walk_to_quarantine_hold(cid, ids, 16, t + 33 * DAY, **names)
    quarantine_hold_until = w.store.load_candidate(cid).quarantine_hold_until
    w.step(cid, LifecycleState.DELETION_REVALIDATION_REQUIRED, quarantine_hold_until + HOUR,
           reason="post-quarantine hold ended; revalidation required")
    p = AS_OF - 6 * HOUR
    w.revalidate(16, ids, p, quarantined=True, **names)
    w.step(cid, LifecycleState.DELETION_PROPOSED, p + HOUR, actor=REVIEWER_3,
           reason="synthetic reviewer proposed the deletion on fresh post-hold evidence")
    w.result("S16", "Deletion proposed after the post-quarantine hold", (Condition.DELETION_PROPOSED,), cid,
             "Quarantined, held 30 days, revalidated on fresh evidence, and proposed for deletion by a third "
             "reviewer. It needs a new deletion approval from someone who approved neither earlier stage and did "
             "not propose it (D143).")


SCENARIOS = (_s01, _s02, _s03, _s04, _s05, _s06, _s07, _s08, _s09, _s10, _s11, _s12, _s13, _s14, _s15, _s16)


def seed_synthetic_world(store: Store) -> SeedSummary:
    """Load the synthetic world into an empty SYNTHETIC store."""
    if store.marker.environment is not DatabaseEnvironment.SYNTHETIC or store.mode is not ExecutionMode.LOCAL_SYNTHETIC:
        raise StoreError("the synthetic world can only be seeded into a SYNTHETIC store in LOCAL_SYNTHETIC mode")
    if store.candidate_ids() or store.connection.execute("SELECT count(*) FROM collector_runs").fetchone()[0]:
        raise StoreError("the synthetic world can only be seeded into an empty store")
    with deterministic_ids(f"{SEED_NAMESPACE}:seed"):
        world = _World(store)
        for scenario in SCENARIOS:
            scenario(world)
        for run_id, state in world.runs.items():
            if not state["finished"]:
                world.finish_run(run_id)
        store.record_synthetic_seed(actor=SEEDER, namespace=SEED_NAMESPACE, scenario_count=len(world.results),
                                    as_of=AS_OF)
    sequence, head = store.audit_head()
    return SeedSummary(SEED_NAMESPACE, AS_OF, tuple(world.results), head)


def create_seeded_store(target: DatabaseTarget, *, clock=None) -> tuple[Store, SeedSummary]:
    """Initialize a new SYNTHETIC store at ``target`` and seed it. Deterministic end to end."""
    clock = clock or SeedClock()
    with deterministic_ids(f"{SEED_NAMESPACE}:init"):
        store = Store.initialize(target, environment=DatabaseEnvironment.SYNTHETIC, mode=ExecutionMode.LOCAL_SYNTHETIC,
                                 actor=SEEDER, clock=clock)
    try:
        return store, seed_synthetic_world(store)
    except BaseException:
        store.close()
        raise
