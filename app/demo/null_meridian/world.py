"""Loads the Null Meridian dataset into a SYNTHETIC store, through the public ``Store`` API.

Seeding has three parts, all deterministic:

1. **Inventory evidence**, as a full read-only collection one week before the snapshot:
   every Okta application, every group Okta sees, every application assignment, 90 days
   of application usage, and every AD group (including AD-only and deleted ones). Then
   every Okta group is correlated by the real correlation engine over the synthetic AD
   directory with ``config/correlation.null-meridian.json``. The dataset only states the
   outcome it expects for each group; seeding stops if the engine proves anything else.
2. **Lifecycle candidates** for the portfolio scenarios (NM-C01 .. NM-C11), driven through
   the same lifecycle guards, approvals, dry runs, and audit trail as real use, in date order
   with the policy releases (OGWA-DEMO-04): NM-LIFECYCLE-004 v1.1.0 is recorded, the candidates
   are triaged (2026-09-24/25), v1.2.0 is recorded (effective 2026-09-28), and then the
   snapshot day (``snapshot_day``, 2026-10-01): NM-C11's evidence is collected again
   (``RECOLLECTED``) and its Okta unassignment approved under v1.2.0, so it is the one
   candidate fresh enough at the demo's clock for a remediation dry run or drill. Seeding
   stops unless every decision and approval records the release in force on its own date
   (``policy_chronology_problems``).
3. **The directory snapshot** (migration 0012): people, history, groups, nesting,
   memberships, assignments, findings, and scenarios, written with the seed's audit event.

Nothing here reaches Okta, AD, or AAP: every record is ``SYNTHETIC`` evidence made from the
generated dataset, and the store refuses anything else.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from app.core.database_url import DatabaseTarget
from app.core.modes import ExecutionMode
from app.demo.null_meridian import policy as nm_policy
from app.demo.null_meridian import rng
from app.demo.null_meridian.dataset import NullMeridianDataset
from app.demo.null_meridian.edition import Edition, null_meridian
from app.demo.null_meridian.profile import AS_OF
from app.demo.synthetic_directory import StoreSyntheticDirectory, load_synthetic_correlation_config
from app.demo.synthetic_world import (
    COLLECTOR,
    DAY,
    HOUR,
    MINUTE,
    REVIEWER_1,
    SEEDER,
    ScenarioResult,
    SeedClock,
    SeedSummary,
    _Ids,
    _World,
)
from app.domain.approval import ApprovalStage
from app.domain.collection import CollectorErrorCode
from app.domain.evidence import EvidenceKind, ResultStatus
from app.domain.ids import IdKind, deterministic_ids
from app.domain.lifecycle import LifecycleState
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    DependencyFinding,
    DependencyKind,
    FindingCode,
    MappingConfidence,
    OktaApplication,
    OktaAppStatus,
    OktaGroup,
    OktaGroupType,
)
from app.domain.policy import DEFAULT_REQUIRED_DEPENDENCY_KINDS
from app.domain.policy_release import RECORDED_SOURCE, PolicyRef
from app.governance.analysis import SEVERITY_RANK
from app.governance.snapshot import DirectorySnapshot, SnapshotRecord
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreError
from app.store.store import Store

# The lifecycle rules of the policy in force at the demo's clock: NM-LIFECYCLE-004 v1.2.0 (OGWA-DEMO-02).
POLICY = nm_policy.current_release().rules.lifecycle
COLLECTED = AS_OF - 7 * DAY  # the full read-only collection the inventory evidence comes from
# NM-C11's evidence is collected again on the snapshot day, so it is inside the 24-hour
# EXECUTION window when the demo's clock starts (just after the newest audit event).
RECOLLECTED = AS_OF - 6 * HOUR

# What the correlation engine must prove for each dataset correlation case.
EXPECTED_CONFIDENCE = {
    "EXACT": MappingConfidence.EXACT_CONFIGURED_MAPPING,
    "LEGACY_NAME_EXACT": MappingConfidence.EXACT_CONFIGURED_MAPPING,
    "NORMALIZED_EXACT": MappingConfidence.EXACT_CONFIGURED_MAPPING,
    "LEGACY_AD_TO_MODERN_OKTA": MappingConfidence.EXACT_CONFIGURED_MAPPING,
    "UNVERIFIED_STABLE_ID": MappingConfidence.UNVERIFIED_STABLE_ID,
    "NAME_ONLY": MappingConfidence.NAME_ONLY,
    "MULTIPLE_MATCHES": MappingConfidence.AMBIGUOUS,
    "NO_MATCH": MappingConfidence.NOT_FOUND,
    "CONFIGURED_TARGET_DELETED": MappingConfidence.NOT_FOUND,
    "BUILT_IN": MappingConfidence.NOT_FOUND,
}
GROUP_TYPE = {"APP_GROUP": OktaGroupType.APP_GROUP, "OKTA_GROUP": OktaGroupType.OKTA_GROUP,
              "BUILT_IN": OktaGroupType.BUILT_IN}


@dataclass(frozen=True)
class CandidateSpec:
    key: str
    title: str
    group_key: str
    application: str
    expected: LifecycleState
    note: str


CANDIDATES = (
    CandidateSpec("NM-C01", "Clean remediation candidate: retired application, empty group", "app:timesheets:legacy:user",
                  "timesheets", LifecycleState.NEEDS_REVIEW,
                  "Inactive app, empty unshared group, exact mapping, complete dependency checks: waiting for approval."),
    CandidateSpec("NM-C02", "Empty group still assigned to an active application", "app:status-page:modern:admin",
                  "status-page", LifecycleState.NEEDS_REVIEW,
                  "No members and no group-attributed sign-ins in 90 days; complete evidence, waiting for approval."),
    CandidateSpec("NM-C03", "Deprecated CRM group still assigned beside its replacement", "app:crm:legacy:user", "crm",
                  LifecycleState.DEPENDENCY_BLOCKED,
                  "Hundreds of people still reach CRM through it; blocked until they are moved to sg-okta-crm-user."),
    CandidateSpec("NM-C04", "Okta copy of a share group name: ambiguous in AD", "app:fpa-planning:transitional:user",
                  "fpa-planning", LifecycleState.MAPPING_AMBIGUOUS,
                  "Two AD objects are named Finance-RW; the name search fails closed."),
    CandidateSpec("NM-C05", "Legacy group still referenced by file-share ACLs and a GPO", "app:print-release:legacy:user",
                  "print-release", LifecycleState.DEPENDENCY_BLOCKED,
                  "The application is retired, but the group still appears in an ACL and a GPO's security filtering."),
    CandidateSpec("NM-C06", "Name-only correlation: approval refused", "app:old-wiki:legacy:user", "old-wiki",
                  LifecycleState.NEEDS_REVIEW,
                  "Okta's 2021 import never captured the objectSid; a name match can never authorize a change."),
    CandidateSpec("NM-C07", "Okta group pushed to a deleted AD group", "app:fax-gateway:transitional:user",
                  "fax-gateway", LifecycleState.BLOCKED,
                  "The configured counterpart no longer exists (NOT_FOUND); a reviewer blocked it pending investigation."),
    CandidateSpec("NM-C08", "Retired fax application: unassigned and in its hold period", "app:fax-gateway:legacy:user",
                  "fax-gateway", LifecycleState.HOLD,
                  "Approved, dry run succeeded, unassignment observed by read-only discovery; the 30-day hold runs."),
    CandidateSpec("NM-C09", "Protected administrator group of a retired cloud account", "app:legacy-cloud:legacy:admin",
                  "legacy-cloud", LifecycleState.PROTECTED,
                  "adminCount and protection from accidental deletion are still set; PROTECTED is terminal."),
    CandidateSpec("NM-C10", "Conflicting and incomplete evidence: no safe decision", "app:knowledge-base:legacy:admin",
                  "knowledge-base", LifecycleState.NEEDS_REVIEW,
                  "No sign-in through the group in 90 days, but the mapping is only probable, two AD reads disagree "
                  "on membership, the nesting read timed out, the ACL scan stopped part-way, and nobody owns the "
                  "group to attest the rest: OGWA refuses every control decision."),
    CandidateSpec("NM-C11", "Remediation drill: an approved removal of an empty group", "app:ad-analytics:transitional:user",
                  "ad-analytics", LifecycleState.APPROVED,
                  "Ad Analytics is used through direct assignments only; its access group is empty and saw no sign-in "
                  "in 90 days. Evidence re-collected on the snapshot day, the removal approved: an executor can dry-run "
                  "it, or drill it against a synthetic provider fixture."),
)


def candidates_for(edition: Edition) -> tuple[CandidateSpec, ...]:
    """The eleven candidates as ``edition`` labels and words them (NM-C01 .. for Null Meridian)."""
    return tuple(replace(c, key=edition.candidate_prefix + c.key[len("NM-C"):], title=edition.text(c.title),
                         note=edition.text(c.note)) for c in CANDIDATES)


class NullMeridianWorld(_World):
    def __init__(self, store: Store, ds: NullMeridianDataset, edition: Edition | None = None) -> None:
        edition = edition or null_meridian()
        super().__init__(store, namespace=edition.seed, policy=edition.policy.current_release().rules.lifecycle,
                         correlation=load_synthetic_correlation_config(edition.correlation_path),
                         ad_source_id=edition.okta_ad_source_id)
        self.edition = edition
        self.specs = candidates_for(edition)
        self.collected = edition.as_of - 7 * DAY
        self.recollected = edition.as_of - 6 * HOUR
        self.ds = ds
        self.groups = {g.key: g for g in ds.groups}
        self.apps = {a.slug: a for a in ds.applications}
        self.assignment_ids: dict[tuple[str, str], str] = {}  # (application id, Okta group id) -> assignment id
        self.mapping_ids: dict[str, str] = {}
        self.candidate_ids: dict[str, str] = {}

    @staticmethod
    def okta_ref(key: str, keyed=rng) -> str:
        return keyed.record_id("ogrp", key)

    @staticmethod
    def ad_ref(key: str, keyed=rng) -> str:
        return keyed.record_id("adg", key)

    def oref(self, key: str) -> str:
        return self.okta_ref(key, self.edition.rng)

    def aref(self, key: str) -> str:
        return self.ad_ref(key, self.edition.rng)

    def assignment(self, label: str, app_id: str, group_id: str, at: datetime, present: bool = True) -> str:
        # Re-observations of a dataset assignment keep its id (the store refuses a second identity).
        assignment_id = self.assignment_ids.get((app_id, group_id)) or self.sid(IdKind.ASSIGNMENT, label)
        self.observe(ApplicationGroupAssignment(assignment_id, app_id, group_id, present,
                                                self.prov(at, f"synthetic:okta:app-groups:{label}")), "okta-apps")
        return assignment_id

    # --- 1. inventory evidence ------------------------------------------------------------

    def inventory(self) -> None:
        at = self.collected
        for app in self.ds.applications:
            self.observe(OktaApplication(app.id, app.okta_app_id, app.label, OktaAppStatus(app.status), app.sign_on_mode,
                                         self.prov(at, f"synthetic:okta:app:{app.okta_app_id}")), "okta-apps")
        for g in self.ds.groups:
            if g.okta_visible:
                self.okta_group_evidence(g, at)
        held = {c.group_key for c in self.specs if c.expected is LifecycleState.HOLD}
        for a in self.ds.assignments:
            if a.group_key is None:
                continue  # individual assignments are in the directory snapshot, not group evidence
            app_id, group_id = self.apps[a.application].id, self.oref(a.group_key)
            self.assignment_ids[(app_id, group_id)] = a.id
            # A held candidate's assignment was present at collection; its removal is observed later.
            self.observe(ApplicationGroupAssignment(a.id, app_id, group_id, a.present or a.group_key in held,
                                                    self.prov(at, f"synthetic:okta:app-groups:{a.application}")),
                         "okta-apps")
        for app in self.ds.applications:
            self.usage_evidence(app, at + HOUR)
        for g in self.ds.groups:
            if g.source == "AD":
                self.ad_group_evidence(g, at + 2 * HOUR)
        self.directory = StoreSyntheticDirectory(self.store, clock=lambda: at).frozen()
        for g in self.ds.groups:
            if g.okta_visible:
                self.mapping_ids[g.key] = self.correlate(g.key, self.oref(g.key), at + 3 * HOUR,
                                                         EXPECTED_CONFIDENCE[g.correlation_case])
        self.directory = None

    def okta_group_evidence(self, g, at: datetime) -> None:
        directory = {}
        if g.okta_group_type == "APP_GROUP":
            directory = dict(source_directory_id=self.edition.okta_ad_source_id,
                             directory_external_id=g.ad_object_guid if g.okta_reports_sid else None,
                             directory_qualified_name=f"{self.edition.ad_netbios}\\{g.okta_name}",
                             directory_object_sid_unverified=g.ad_sid if g.okta_reports_sid else None)
        self.observe(OktaGroup(self.oref(g.key), g.okta_group_id, g.okta_name, GROUP_TYPE[g.okta_group_type],
                               self.prov(at, f"synthetic:okta:group:{g.okta_group_id}"), **directory), "okta-apps")

    def ad_group_evidence(self, g, at: datetime) -> None:
        attributes = {}
        if g.ad_exists:
            direct = len(self.ds.index.direct_members(g.key)) + len(self.ds.index.children(g.key))
            attributes = dict(sid=g.ad_sid, distinguished_name=g.ad_distinguished_name,
                              sam_account_name=g.ad_sam_account_name, member_count=direct, admin_count=g.admin_count,
                              protected_from_accidental_deletion=g.protected_from_deletion)
        domain = self.edition.ad_dns_domain
        self.observe(ADGroup(self.aref(g.key), g.ad_object_guid, domain, g.ad_exists,
                             self.prov(at, f"synthetic:ad:{domain}:guid:{g.ad_object_guid}"), **attributes),
                     "ad-groups")

    def usage_evidence(self, app, at: datetime, group_key: str | None = None, events: int | None = None) -> None:
        label = f"{app.slug}:{group_key or '*'}"
        events = app.usage_events_90d if events is None else events
        users = app.usage_users_90d if group_key is None else 0
        last = at - timedelta(hours=1 + self.edition.rng.below(70, "last", label)) if events else None
        self.observe(ApplicationUsageObservation(
            self.sid(IdKind.USAGE_OBSERVATION, label), app.id, self.oref(group_key) if group_key else None,
            at - 90 * DAY, at, events, users, last,
            self.prov(at, f"synthetic:okta:systemlog:app:{label}:90d")), "okta-usage")

    # --- policy versions ----------------------------------------------------------------------

    def record_policy(self, release) -> None:
        """Record ``release`` as the next policy version, as approved when it took effect, and judge
        every later seeded decision by it, as the API would."""
        previous = self.store.active_policy_version()
        version = self.edition.policy.policy_version(release, id=self.sid(IdKind.POLICY_VERSION, release.name),
                                                     previous=previous)
        self.store.record_policy_version(version)
        self.policy = version.policy.lifecycle
        self.policy_ref = PolicyRef.of(policy_digest=version.policy_digest, source=RECORDED_SOURCE,
                                       version_id=version.id, sequence=version.sequence, release=release)

    # --- 2. lifecycle candidates -----------------------------------------------------------

    def ids_for(self, spec: CandidateSpec) -> _Ids:
        g = self.groups[spec.group_key]
        app_id, group_id = self.apps[spec.application].id, self.oref(spec.group_key)
        ad = self.aref(spec.group_key) if g.source == "AD" and g.ad_exists else None
        if g.source == "OKTA" and g.push_target and self.groups[g.push_target].ad_exists:
            ad = self.aref(g.push_target)
        return _Ids(app_id, group_id, self.assignment_ids[(app_id, group_id)], ad, self.mapping_ids[spec.group_key])

    def candidates(self) -> None:
        """Every candidate as it was triaged, a week before the snapshot."""
        t = self.collected + 4 * HOUR
        for spec in self.specs:
            ids = self.ids_for(spec)
            self.candidate_ids[spec.key] = getattr(self, "_nm_c" + spec.key[-2:])(spec, ids, t)

    def snapshot_day(self) -> None:
        """OGWA-DEMO-03, on the snapshot day and after everything else, so the seed stays
        chronological (and anything recorded before it, such as a later policy release,
        governs it): NM-C11's evidence is collected again and its Okta unassignment approved."""
        spec = self.specs[10]
        cid, ids = self.candidate_ids[spec.key], self.ids_for(spec)
        self.recollect(cid, spec, ids, self.recollected)
        approval = self.approve(cid, f"{spec.key}-okta", ApprovalStage.OKTA_UNASSIGN, self.recollected + HOUR,
                                REVIEWER_1)
        self.step(cid, LifecycleState.APPROVED, self.recollected + HOUR + 5 * MINUTE, actor=REVIEWER_1, approval=approval,
                  reason="synthetic reviewer approved the Okta unassignment on re-collected evidence")

    def record_results(self) -> None:
        """Each candidate's final state, which must be the one its scenario states."""
        for spec in self.specs:
            cid = self.candidate_ids[spec.key]
            self.result(spec.key, spec.title, (), cid, spec.note)
            if self.store.load_candidate(cid).state is not spec.expected:
                raise StoreError(f"{spec.key} ended in {self.store.load_candidate(cid).state.value}, "
                                 f"not {spec.expected.value}")

    def deps(self, spec: CandidateSpec, ids: _Ids, at: datetime, findings: dict | None = None,
             kinds=DEFAULT_REQUIRED_DEPENDENCY_KINDS) -> None:
        self.dependencies(spec.key, ids.group, ids.ad_group, at, kinds, findings)

    def _nm_c01(self, spec, ids, t):
        self.deps(spec, ids, t)
        cid = self.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D", "EMPTY_GROUP")
        self.step(cid, LifecycleState.CANDIDATE, t + HOUR)
        self.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        return cid

    def _nm_c02(self, spec, ids, t):
        self.usage_evidence(self.apps[spec.application], t, spec.group_key, events=0)
        self.deps(spec, ids, t)
        cid = self.candidate(ids, t + 30 * MINUTE, "EMPTY_GROUP_ASSIGNED", "ZERO_GROUP_USAGE_90D")
        self.step(cid, LifecycleState.CANDIDATE, t + HOUR)
        self.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        return cid

    def _nm_c03(self, spec, ids, t):
        members = len(self.ds.index.effective(spec.group_key))
        replacement = self.groups[self.groups[spec.group_key].replaced_by].name
        self.deps(spec, ids, t, {DependencyKind.AD_GROUP_MEMBERS: (DependencyFinding(
            f"{members} people are effective members; {replacement} is assigned beside it", True),)})
        cid = self.candidate(ids, t + 30 * MINUTE, "DEPRECATED_GROUP_STILL_ASSIGNED")
        self.divert(cid, t + HOUR)
        return cid

    def _nm_c04(self, spec, ids, t):
        self.usage_evidence(self.apps[spec.application], t, spec.group_key, events=0)
        self.deps(spec, ids, t)
        cid = self.candidate(ids, t + 30 * MINUTE, "NONSTANDARD_NAME", "ZERO_GROUP_USAGE_90D")
        self.divert(cid, t + HOUR)
        return cid

    def _nm_c05(self, spec, ids, t):
        self.deps(spec, ids, t, {
            DependencyKind.AD_ACL_REFERENCE: (DependencyFinding(
                "Granted modify on the print-driver share (synthetic file server fs01)", True, "acl:fs01/print-drivers"),),
            DependencyKind.GPO_REFERENCE: (DependencyFinding(
                "Security filtering of the GPO 'Printers - Floor 2' (synthetic)", True, "gpo:printers-floor-2"),),
        })
        cid = self.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
        self.divert(cid, t + HOUR)
        return cid

    def _nm_c06(self, spec, ids, t):
        self.deps(spec, ids, t)
        cid = self.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
        self.step(cid, LifecycleState.CANDIDATE, t + HOUR)
        self.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        approval = self.approve(cid, f"{spec.key}-okta", ApprovalStage.OKTA_UNASSIGN, t + 3 * HOUR, REVIEWER_1)
        self.step(cid, LifecycleState.APPROVED, t + 3 * HOUR + 5 * MINUTE, actor=REVIEWER_1, approval=approval,
                  reason="synthetic reviewer attempted approval", expect_refusal=True)
        return cid

    def _nm_c07(self, spec, ids, t):
        cid = self.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
        self.step(cid, LifecycleState.CANDIDATE, t + HOUR)
        self.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        self.step(cid, LifecycleState.BLOCKED, t + 3 * HOUR, actor=REVIEWER_1,
                  reason="configured push target not found by objectGUID; find out who deleted it before going further")
        return cid

    def _nm_c08(self, spec, ids, t):
        self.deps(spec, ids, t)
        cid = self.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
        self.walk_to_hold(cid, ids, spec.key, t)
        return cid

    def direct_member_finding(self, group_key: str) -> DependencyFinding:
        """The membership read's direct-member finding, as the P05 converter words it: every
        member value, people and groups, the same values the AD group object counts."""
        people, groups = len(self.ds.index.direct_members(group_key)), len(self.ds.index.children(group_key))
        classes = ", ".join(f"{n} {name}" for name, n in (("user", people), ("group", groups)) if n)
        return DependencyFinding(f"{people + groups} direct member value(s) ({classes})", True,
                                 code=FindingCode.AD_DIRECT_MEMBERS)

    def _nm_c09(self, spec, ids, t):
        # The membership read agrees with the AD group object: both see the two administrators.
        self.deps(spec, ids, t, {DependencyKind.AD_GROUP_MEMBERS: (self.direct_member_finding(spec.group_key),)})
        cid = self.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
        self.divert(cid, t + HOUR)
        return cid

    def _nm_c10(self, spec, ids, t):
        """OGWA-DEMO-01: every kind of imperfect evidence on one candidate, none of it repaired.

        - Confirmed: the Okta group, the application (ACTIVE), and the assignment still exist.
        - Says none: no sign-in attributed to the group in 90 days; complete Okta checks find no
          other application assignment and no policy reference.
        - Probable identity: the correlation engine proves UNVERIFIED_STABLE_ID (Okta's
          directory objectSid only, D37); nothing here or in the demo changes that.
        - Conflicting: the AD group object read at 14:00 lists two member values; the
          membership read at 16:00 found none.
        - Source unavailable: the nesting read timed out (FAILED).
        - Partial: the file-server ACL scan stopped part-way.
        - Never collected: GPO, AAP, and application-configuration checks. The group has no
          recorded owner, so nobody could attest the application side.
        """
        K = DependencyKind
        self.usage_evidence(self.apps[spec.application], t, spec.group_key, events=0)
        self.deps(spec, ids, t, kinds=frozenset({K.OKTA_OTHER_APP_ASSIGNMENT, K.OKTA_POLICY_REFERENCE,
                                                 K.AD_GROUP_MEMBERS}))
        for kind, status, error, summary in (
                (K.AD_NESTED_MEMBERSHIP, ResultStatus.FAILED, CollectorErrorCode.TIMEOUT,
                 "read timeout after 30s expanding KB-Admins' nesting through the synthetic AAP worker"),
                (K.AD_ACL_REFERENCE, ResultStatus.PARTIAL, CollectorErrorCode.PAGING_INTERRUPTED,
                 "synthetic file-server ACL scan stopped after 3 of 7 shares; nothing found in what was read")):
            key = f"{spec.key}-{kind.value.lower()}"
            run_id = self.run("dependency-checks", t, key=key)
            self.observe(DependencyEvidence(self.sid(IdKind.DEPENDENCY_EVIDENCE, f"{spec.key}:{kind.value}"),
                                            ids.ad_group, kind, (),
                                            self.prov(t, f"synthetic:deps:{spec.key}:{kind.value}", status)),
                         "dependency-checks", key)
            self.finish_run(run_id, status, error, summary)
        cid = self.candidate(ids, t + 30 * MINUTE, "ZERO_GROUP_USAGE_90D")
        self.step(cid, LifecycleState.CANDIDATE, t + HOUR)
        self.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        return cid


    def _nm_c11(self, spec, ids, t):
        """OGWA-DEMO-03: the candidate a remediation drill runs on in the default demo.

        Triaged like NM-C02 a week before the snapshot. On the snapshot day
        (``snapshot_day``) every record of its evidence is collected again, unchanged (the
        mapping through the correlation engine again, D75), and a reviewer approves the Okta
        unassignment on that evidence. At the demo's clock the evidence is inside the 24-hour
        EXECUTION window and the approval is unexpired, so every remediation gate can pass
        for an executor who did not approve it (D49). Nothing dry-runs or executes anything."""
        self.usage_evidence(self.apps[spec.application], t, spec.group_key, events=0)
        self.deps(spec, ids, t)
        cid = self.candidate(ids, t + 30 * MINUTE, "EMPTY_GROUP_ASSIGNED", "ZERO_GROUP_USAGE_90D")
        self.step(cid, LifecycleState.CANDIDATE, t + HOUR)
        self.step(cid, LifecycleState.NEEDS_REVIEW, t + 2 * HOUR)
        return cid

    def recollect(self, candidate_id: str, spec: CandidateSpec, ids: _Ids, at: datetime) -> None:
        """Observe every record of the candidate's evidence again at ``at``, facts unchanged.
        The identity mapping is not copied: the correlation engine proves it again."""
        collectors = {EvidenceKind.OKTA_GROUP: "okta-apps", EvidenceKind.OKTA_APPLICATION: "okta-apps",
                      EvidenceKind.ASSIGNMENT: "okta-apps", EvidenceKind.USAGE: "okta-usage",
                      EvidenceKind.AD_GROUP: "ad-groups", EvidenceKind.DEPENDENCY: "dependency-checks"}
        bundle = self.store.evidence_bundle(self.store.load_candidate(candidate_id))
        for record in bundle.records():
            if record.KIND is not EvidenceKind.IDENTITY_MAPPING:
                self.observe(replace(record, provenance=replace(record.provenance, observed_at=at)),
                             collectors[record.KIND])
        self.correlate(spec.group_key, ids.group, at + 10 * MINUTE, EXPECTED_CONFIDENCE[
            self.groups[spec.group_key].correlation_case])


# --- 3. the directory snapshot ---------------------------------------------------------------


def directory_snapshot(ds: NullMeridianDataset, candidate_ids: dict[str, str],
                       edition: Edition | None = None) -> DirectorySnapshot:
    edition = edition or null_meridian()
    keyed = edition.rng
    index = ds.index
    health = ds.analysis.group_severity
    records = [SnapshotRecord.of("COMPANY", edition.key, edition.key, {**ds.profile(), "counts": ds.counts()})]
    records += [SnapshotRecord.of("DEPARTMENT", d.id, d.slug, {**d.to_dict(), "teams": [t.to_dict() for t in d.teams]},
                                  d.slug) for d in ds.departments]
    records += [SnapshotRecord.of("PERSON", p.id, p.employee_number, p.to_dict(), p.department, p.status)
                for p in ds.people]
    records += [SnapshotRecord.of("EMPLOYMENT_EVENT", e.id, f"{e.person_id}|{e.on.isoformat()}|{e.kind}", e.to_dict(),
                                  e.person_id, e.kind) for e in ds.events]
    for a in ds.applications:
        body = {**a.to_dict(), "health": ds.analysis.application_severity[a.slug],
                "entitledPeople": len(index.users_of(a.slug))}
        records.append(SnapshotRecord.of("APPLICATION", a.id, a.label.casefold(), body, a.slug, a.status))
    assigned: dict[str, list[str]] = {}
    for a in ds.assignments:
        if a.group_key and a.present:
            assigned.setdefault(a.group_key, []).append(a.application)
    for g in ds.groups:
        body = {**g.to_dict(), "health": health[g.key],
                "oktaEvidenceId": keyed.record_id("ogrp", g.key) if g.okta_visible else None,
                "adEvidenceId": keyed.record_id("adg", g.key) if g.source == "AD" else None,
                "effectiveMembers": len(index.effective(g.key)), "directMembers": len(index.direct_members(g.key)),
                "nestingDepth": index.depth(g.key), "parents": index.parents(g.key), "children": index.children(g.key),
                "assignedTo": sorted(set(assigned.get(g.key, ())))}
        records.append(SnapshotRecord.of("GROUP", g.id, f"{g.name.casefold()}|{g.key}", body,
                                         body["oktaEvidenceId"], g.key))
    records += [SnapshotRecord.of("NESTING", f"{p}>{c}", f"{p}>{c}", {}, p, c) for p, c in ds.nesting]
    records += [SnapshotRecord.of("MEMBERSHIP", f"{g}|{p}", f"{g}|{p}", {}, g, p) for g, p in ds.memberships]
    records += [SnapshotRecord.of("ASSIGNMENT", a.id, f"{a.application}|{a.group_key or a.person_id}", a.to_dict(),
                                  a.application, a.group_key or a.person_id) for a in ds.assignments]
    records += [SnapshotRecord.of("FINDING", f.id, f"{SEVERITY_RANK[f.severity]}|{f.code}|{f.subject_name.casefold()}",
                                  f.to_dict(), f.subject_id, f.severity) for f in ds.findings]
    records += [SnapshotRecord.of("SCENARIO", s.key, f"{s.number:02d}",
                                  {**s.to_dict(), "candidateId": candidate_ids.get(s.candidate_key)}, s.candidate_key)
                for s in ds.scenarios]
    return DirectorySnapshot(edition.key, edition.seed, edition.company, edition.as_of, tuple(records))


# --- policy chronology -------------------------------------------------------------------------


def policy_chronology_problems(store: Store, candidate_ids: tuple[str, ...], releases, as_of: datetime = AS_OF) -> list[str]:
    """Every seeded decision and approval must record the release in force when it was made
    (OGWA-DEMO-04): the one whose window, from its ``effectiveFrom`` up to the next release's,
    holds the record's ``decided_at``. The store already refuses a reference that is not the
    latest recorded version; this checks the seed's own dates against the releases' dates, in
    both directions, so no record names a version that took effect after it, or one that a
    newer version had already replaced. Returns the problems found (none: chronological)."""
    releases = tuple(releases)
    problems: list[str] = []

    def expected(at: datetime):
        in_force = [r for r in releases if r.effective_from <= at]
        return in_force[-1] if in_force else None

    for cid in candidate_ids:
        recorded = store.recorded_policies(cid)
        records = [(f"decision:{d.id}", d.decided_at) for d in store.decisions(cid)]
        records += [(f"approval:{a.id}", a.decided_at) for a in store.approvals_for(cid)]
        for key, at in records:
            ref, release = recorded.get(key), expected(at)
            if at > as_of:
                problems.append(f"{key} is dated {at.isoformat()}, after the snapshot")
            if ref is None:
                problems.append(f"{key} records no policy")
            elif release is None:
                problems.append(f"{key} is dated {at.isoformat()}, before any release took effect")
            elif (ref.policy_id, ref.version, ref.release_digest) != (
                    release.policy_id, release.version, release.release_digest):
                problems.append(f"{key} ({at.isoformat()}) records {ref.name}, but {release.name} was in force")
    return problems


# --- entry points ------------------------------------------------------------------------------


def seed_null_meridian(store: Store, edition: Edition | None = None) -> SeedSummary:
    """Load the edition's dataset (Null Meridian by default) into an empty SYNTHETIC store."""
    edition = edition or null_meridian()
    if store.marker.environment is not DatabaseEnvironment.SYNTHETIC or store.mode is not ExecutionMode.LOCAL_SYNTHETIC:
        raise StoreError(f"the {edition.company} dataset can only be seeded into a SYNTHETIC store in LOCAL_SYNTHETIC mode")
    if store.candidate_ids() or store.connection.execute("SELECT count(*) FROM collector_runs").fetchone()[0]:
        raise StoreError(f"the {edition.company} dataset can only be seeded into an empty store")
    ds = edition.dataset()
    first, *later = edition.policy.releases()
    with deterministic_ids(f"{edition.seed}:seed"):
        world = NullMeridianWorld(store, ds, edition)
        world.inventory()
        # The candidates were triaged on 2026-09-24/25, under 1.1.0; 1.2.0 took effect on 2026-09-28.
        world.record_policy(first)
        world.candidates()
        last_decision = max(d.decided_at for cid in world.candidate_ids.values() for d in store.decisions(cid))
        for release in later:
            if release.effective_from <= last_decision:
                raise StoreError(f"{release.name} takes effect before the last seeded decision ({last_decision})")
            world.record_policy(release)
        # The snapshot day (2026-10-01), after every release that took effect before it (OGWA-DEMO-04):
        # NM-C11's re-collection and approval are judged by, and record, the version in force then (1.2.0).
        world.snapshot_day()
        world.record_results()
        problems = policy_chronology_problems(store, tuple(world.candidate_ids.values()), (first, *later), edition.as_of)
        if problems:
            raise StoreError("the seeded policy chronology is wrong: " + "; ".join(problems))
        for run_id, state in world.runs.items():
            if not state["finished"]:
                world.finish_run(run_id, ResultStatus.COMPLETE)
        store.record_synthetic_seed(actor=SEEDER, namespace=edition.seed, scenario_count=len(world.results),
                                    as_of=edition.as_of, directory=directory_snapshot(ds, world.candidate_ids, edition))
    _, head = store.audit_head()
    return SeedSummary(edition.seed, edition.as_of, tuple(world.results), head)


def create_null_meridian_store(target: DatabaseTarget, *, clock=None, edition: Edition | None = None
                               ) -> tuple[Store, SeedSummary]:
    """Initialize a new SYNTHETIC store at ``target`` and load the edition's dataset (Null Meridian by default).
    Deterministic end to end."""
    edition = edition or null_meridian()
    clock = clock or SeedClock(edition.as_of + HOUR)
    with deterministic_ids(f"{edition.seed}:init"):
        store = Store.initialize(target, environment=DatabaseEnvironment.SYNTHETIC, mode=ExecutionMode.LOCAL_SYNTHETIC,
                                 actor=SEEDER, clock=clock)
    try:
        return store, seed_null_meridian(store, edition)
    except BaseException:
        store.close()
        raise


__all__ = ["CANDIDATES", "COLLECTED", "POLICY", "candidates_for", "ScenarioResult", "create_null_meridian_store", "seed_null_meridian",
           "COLLECTOR", "policy_chronology_problems"]
