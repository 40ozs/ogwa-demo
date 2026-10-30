"""Read-only views over the store, serialized for the API.

Listings select ids with bounded ``LIMIT``/``OFFSET`` queries (every statement here is a
``SELECT``; a test pins that) and then load each record through the store's public,
digest-verifying loaders, so a tampered row fails loudly instead of being served. A sorted
listing is filtered, sorted, and paged in that one query, so it loads only its own page.
Serialized records carry ids, statuses, and evidence metadata only: no API payloads and
no credentials ever reach the store, so none can reach a response.
"""

import json
from datetime import datetime
from functools import cached_property
from typing import Any

from app.api.validation import Page, Sort
from app.classification import coverage_report
from app.domain.actors import Actor
from app.domain.approval import ApprovalRecord
from app.domain.audit import AuditEvent
from app.domain.candidate_policy import PolicyVersion
from app.domain.policy_release import PolicyRef, PolicyRelease, release_for_digest
from app.domain.collection import CollectorRun, CollectorRunOutcome
from app.domain.evidence import Evidence, Provenance
from app.domain.execution import ExecutionJob
from app.domain.lifecycle import LifecycleCandidate, LifecycleDecision, LifecycleState
from app.domain.mapping_review import MappingReview, current_approval, pending_selection
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    IdentityMapping,
    MappingConfidence,
    OktaApplication,
    OktaGroup,
)
from app.domain.policy import EvidenceBundle, LifecyclePolicy, evidence_fingerprint
from app.store.codec import ts
from app.store.store import JobStatusEvent, Store

# Anchor tables an API listing may page through, and the evidence type stored in each.
LISTABLE = {
    "applications": ("okta_applications", OktaApplication),
    "groups": ("okta_groups", OktaGroup),
    "mappings": ("identity_mappings", IdentityMapping),
    "dependencies": ("dependency_checks", DependencyEvidence),  # P09: the dependency findings view
}


# --- paging in SQL (OGWA-UI-IA-02) -------------------------------------------------------------
#
# A listing's rows are ``a`` (an evidence anchor joined to its latest observation ``o``, as
# Store.latest picks it). ``order`` is the listing's own order and ends in the stable id: it is
# the order of an unsorted page, and it breaks every tie of a sort, so a page is deterministic
# and never ordered by a name alone. ``sorts`` maps each ``sort=`` field to the SQL values it
# sorts by: what the UI shows, with an id column sorting by the name it resolves to
# (app/api/resolve.py). A name only orders rows; it never identifies one.

def _rows(anchor: str, observations: str, column: str) -> str:
    return (f"{anchor} a JOIN {observations} o ON o.observation_id = (SELECT observation_id FROM {observations} "
            f"WHERE {column} = a.id ORDER BY observed_at DESC LIMIT 1)")


def _text(sql: str) -> str:
    # shortcut: NOCASE folds ASCII letters only (SQLite has no casefold); fine while names are ASCII.
    return f"NULLIF({sql}, '') COLLATE NOCASE"


def _okta_name(ref: str) -> str:
    return f"(SELECT name FROM okta_group_observations WHERE group_id = {ref} ORDER BY observed_at DESC LIMIT 1)"


def _ad_name(ref: str) -> str:
    """The directory snapshot's name for the AD group, else its latest sAMAccountName (as GET /identities)."""
    return (f"coalesce(snapshot_ad_name({ref}), (SELECT sam_account_name FROM ad_group_observations "
            f"WHERE ad_group_id = {ref} ORDER BY observed_at DESC LIMIT 1))")


_CANDIDATE_NAME = _text(_okta_name("(SELECT group_id FROM candidates WHERE id = a.candidate_id)"))


# --- the Review queue (OGWA-REVIEW-QUEUE-API-01) -----------------------------------------------
#
# One reading of the lifecycle state for review, the same table as the UI's review.js STATUS_OF
# (tests/test_review_queue_api.py pins the two together). It groups states for reading only:
# every row also carries its lifecycle state, which stays the fact. There is no "ready" status,
# and a state not listed here reads as blocked.

REVIEW_STATUSES = ("needs-review", "blocked", "waiting", "in-progress", "retired", "closed")  # the queue's order
OPEN_REVIEW_STATUSES = REVIEW_STATUSES[:4]
_LS = LifecycleState
REVIEW_STATUS: dict[LifecycleState, str] = {
    **dict.fromkeys((_LS.NEEDS_REVIEW, _LS.REVALIDATION_REQUIRED, _LS.DELETION_REVALIDATION_REQUIRED,
                     _LS.DELETION_PROPOSED), "needs-review"),
    # RETIREMENT_DRY_RUN: the legacy single AD stage (D148), from which only a diversion may follow.
    **dict.fromkeys((_LS.BLOCKED, _LS.MAPPING_AMBIGUOUS, _LS.DEPENDENCY_BLOCKED, _LS.STALE_EVIDENCE,
                     _LS.EVIDENCE_INCOMPLETE, _LS.RETIREMENT_DRY_RUN), "blocked"),
    **dict.fromkeys((_LS.DISCOVERED, _LS.CANDIDATE, _LS.HOLD, _LS.QUARANTINE_HOLD), "waiting"),
    **dict.fromkeys((_LS.APPROVED, _LS.OKTA_UNASSIGN_DRY_RUN, _LS.QUARANTINE_APPROVED, _LS.QUARANTINE_DRY_RUN,
                     _LS.DELETION_APPROVED, _LS.DELETION_DRY_RUN), "in-progress"),
    _LS.RETIRED: "retired",
    **dict.fromkeys((_LS.EXCLUDED, _LS.REJECTED, _LS.PROTECTED), "closed"),
}


def review_status(state: str) -> str:
    """The review status of a lifecycle state's value; a state this build does not know reads as blocked."""
    try:
        return REVIEW_STATUS[LifecycleState(state)]
    except (ValueError, KeyError):
        return "blocked"


def review_filter(statuses: tuple[str, ...]) -> tuple[str, tuple]:
    """``WHERE`` over ``candidates a`` for the rows whose review status is one of ``statuses``. Blocked
    is everything not grouped otherwise, so an unknown state is never filtered out of it."""
    if set(statuses) >= set(REVIEW_STATUSES):
        return "", ()
    keep = "blocked" in statuses
    states = tuple(s.value for s, k in REVIEW_STATUS.items() if (k in statuses) is not keep)
    return f"WHERE a.state {'NOT IN' if keep else 'IN'} ({', '.join('?' * len(states))})", states


_REVIEW_RANK = ("CASE a.state " + " ".join(f"WHEN '{s.value}' THEN {REVIEW_STATUSES.index(k)}"
                                           for s, k in REVIEW_STATUS.items())
                + f" ELSE {REVIEW_STATUSES.index('blocked')} END")
# A hold's end is the only deadline the lifecycle records (review.js nextStep: holdUntil, quarantineHoldUntil).
_DEADLINE = "CASE a.state WHEN 'HOLD' THEN a.hold_until WHEN 'QUARANTINE_HOLD' THEN a.quarantine_hold_until END"

_EVIDENCE_SORTS = {"observedAt": ("o.observed_at",), "result": ("o.result_status",)}
_FINDINGS = "(SELECT count(*) FROM dependency_findings WHERE observation_id = o.observation_id{})"

PAGED: dict[str, tuple[str, str, dict[str, tuple[str, ...]]]] = {
    "applications": (_rows("okta_applications", "okta_application_observations", "application_id"), "a.id", {
        **_EVIDENCE_SORTS, "label": (_text("o.label"),), "status": ("o.status",), "signOnMode": ("o.sign_on_mode",)}),
    "groups": (_rows("okta_groups", "okta_group_observations", "group_id"), "a.id", {
        **_EVIDENCE_SORTS, "name": (_text("o.name"),), "groupType": ("o.group_type",),
        "directoryQualifiedName": (_text("o.directory_qualified_name"),)}),
    "mappings": (_rows("identity_mappings", "identity_mapping_observations", "mapping_id"), "a.id", {
        **_EVIDENCE_SORTS,  # strongest confidence first, in MappingConfidence's order
        "confidence": ("CASE o.confidence " + " ".join(f"WHEN '{c.value}' THEN {i}" for i, c in
                                                        enumerate(MappingConfidence)) + " END",),
        "oktaGroup": (_text(_okta_name("a.group_id")),), "adGroup": (_text(_ad_name("o.ad_group_id")),)}),
    "dependencies": (_rows("dependency_checks", "dependency_observations", "check_id"), "a.id", {
        **_EVIDENCE_SORTS, "dependencyKind": ("a.kind",),
        "subject": (_text(f"CASE WHEN a.subject_group_id IS NOT NULL THEN {_okta_name('a.subject_group_id')} "
                          f"ELSE {_ad_name('a.subject_ad_group_id')} END"),),
        "findings": (_FINDINGS.format(" AND blocking = 1"), _FINDINGS.format(""))}),
    "candidates": ("candidates a", "a.created_at, a.id", {
        "oktaGroup": (_text(_okta_name("a.group_id")),), "state": ("a.state",), "holdUntil": ("a.hold_until",),
        "updatedAt": ("a.updated_at",), "createdAt": ("a.created_at",)}),
    # The Review queue's priority: review status (decisions first), the nearest hold end, the
    # longest wait (oldest last change), then the stable id. As review.js queueOrder.
    "queue": ("candidates a", f"{_REVIEW_RANK}, {_DEADLINE} NULLS LAST, a.updated_at, a.id", {
        "oktaGroup": (_text(_okta_name("a.group_id")),), "updatedAt": ("a.updated_at",), "deadline": (_DEADLINE,)}),
    "approvals": ("approvals a", "a.decided_at DESC, a.id", {
        "stage": ("a.stage",), "decision": ("a.decision",), "decidedAt": ("a.decided_at",),
        "expiresAt": ("a.expires_at",), "candidate": (_CANDIDATE_NAME,)}),
    "jobs": ("execution_jobs a", "a.requested_at DESC, a.id", {
        "kind": ("a.kind",), "requestedAt": ("a.requested_at",), "candidate": (_CANDIDATE_NAME,),
        "status": ("(SELECT status FROM execution_job_status_events WHERE job_id = a.id ORDER BY sequence DESC LIMIT 1)",)}),
    "collectors": ("collector_runs a LEFT JOIN collector_run_outcomes o ON o.run_id = a.id", "a.started_at DESC, a.id", {
        "collector": ("a.collector",), "startedAt": ("a.started_at",), "outcome": ("o.status",),
        "records": ("o.records_observed",)}),
}


def _order(listing: str, sort: Sort | None) -> str:
    """A listing's ORDER BY: the ``sort`` field first (a missing value last either way), then the listing's order."""
    _, order, sorts = PAGED[listing]
    if sort is None:
        return order
    direction = "DESC" if sort.descending else "ASC"
    return ", ".join(f"{value} {direction} NULLS LAST" for value in sorts[sort.key]) + ", " + order


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def actor_json(actor: Actor | None) -> dict[str, str] | None:
    return None if actor is None else {"kind": actor.kind.value, "id": actor.id}


def provenance_json(p: Provenance) -> dict[str, Any]:
    return {
        "source": p.source.value, "observedAt": iso(p.observed_at), "scope": p.scope,
        "collectorVersion": p.collector_version, "resultStatus": p.result_status.value,
        "decisionGrade": p.decision_grade,
    }


def _evidence(record: Evidence, fields: dict[str, Any]) -> dict[str, Any]:
    return {"id": record.id, "kind": record.KIND.value, **fields, "provenance": provenance_json(record.provenance),
            "digest": record.digest}


def application_json(a: OktaApplication) -> dict[str, Any]:
    return _evidence(a, {"oktaAppId": a.okta_app_id, "label": a.label, "status": a.status.value,
                         "signOnMode": a.sign_on_mode})


def okta_group_json(g: OktaGroup) -> dict[str, Any]:
    return _evidence(g, {"oktaGroupId": g.okta_group_id, "name": g.name, "groupType": g.group_type.value,
                         "sourceDirectoryId": g.source_directory_id,
                         "directoryQualifiedName": g.directory_qualified_name,
                         # Unverified source metadata (0008, D37): never presented as a mapping.
                         "directoryObjectSidUnverified": g.directory_object_sid_unverified})


def assignment_json(a: ApplicationGroupAssignment) -> dict[str, Any]:
    return _evidence(a, {"applicationId": a.application_id, "oktaGroupId": a.okta_group_id, "present": a.present})


def usage_json(u: ApplicationUsageObservation) -> dict[str, Any]:
    return _evidence(u, {"applicationId": u.application_id, "oktaGroupId": u.okta_group_id,
                         "windowStart": iso(u.window_start), "windowEnd": iso(u.window_end),
                         "eventCount": u.event_count, "distinctUserCount": u.distinct_user_count,
                         "lastActivityAt": iso(u.last_activity_at)})


def ad_group_json(g: ADGroup) -> dict[str, Any]:
    return _evidence(g, {"objectGuid": g.object_guid, "domain": g.domain, "exists": g.exists, "sid": g.sid,
                         "distinguishedName": g.distinguished_name, "samAccountName": g.sam_account_name,
                         "adminCount": g.admin_count,
                         "protectedFromAccidentalDeletion": g.protected_from_accidental_deletion,
                         "isCriticalSystemObject": g.is_critical_system_object, "memberCount": g.member_count})


def mapping_json(m: IdentityMapping) -> dict[str, Any]:
    return _evidence(m, {"oktaGroupId": m.okta_group_id, "confidence": m.confidence.value, "isExact": m.is_exact,
                         "adGroupId": m.ad_group_id, "reason": m.reason,
                         "matchedAttributes": list(m.matched_attributes),
                         "candidateAdGroupIds": list(m.candidate_ad_group_ids),
                         "configurationRef": m.configuration_ref})


def dependency_json(d: DependencyEvidence) -> dict[str, Any]:
    return _evidence(d, {"subjectId": d.subject_id, "dependencyKind": d.kind.value, "findings": [
        {"code": f.code.value if f.code else None, "description": f.description, "blocking": f.blocking,
         "reference": f.reference} for f in d.findings]})


def bundle_json(bundle: EvidenceBundle) -> dict[str, Any]:
    return {
        "evidenceFingerprint": evidence_fingerprint(bundle),
        "oktaGroup": okta_group_json(bundle.okta_group) if bundle.okta_group else None,
        "applications": [application_json(a) for a in bundle.applications],
        "assignments": [assignment_json(a) for a in bundle.assignments],
        "usage": [usage_json(u) for u in bundle.usage],
        "mapping": mapping_json(bundle.mapping) if bundle.mapping else None,
        "adGroup": ad_group_json(bundle.ad_group) if bundle.ad_group else None,
        "dependencies": [dependency_json(d) for d in bundle.dependencies],
    }


def dependencies_json(bundle: EvidenceBundle, policy: LifecyclePolicy | None) -> dict[str, Any]:
    body: dict[str, Any] = {"findings": [dependency_json(d) for d in bundle.dependencies], "coverage": None}
    if policy is not None:
        body["coverage"] = coverage_report(bundle.dependencies, policy.required_dependency_kinds).to_dict()
    return body


def candidate_json(c: LifecycleCandidate) -> dict[str, Any]:
    return {
        "id": c.id, "oktaGroupId": c.okta_group_id, "assignmentIds": list(c.assignment_ids), "state": c.state.value,
        "epoch": c.epoch, "proposedBy": actor_json(c.proposed_by), "createdAt": iso(c.created_at),
        "updatedAt": iso(c.updated_at), "holdUntil": iso(c.hold_until),
        "blockedFrom": c.blocked_from.value if c.blocked_from else None, "reasonCodes": list(c.reason_codes),
        "oktaUnassignApprover": actor_json(c.okta_unassign_approver),
        "quarantineApprover": actor_json(c.quarantine_approver),
        "quarantineHoldUntil": iso(c.quarantine_hold_until),
        "deletionProposer": actor_json(c.deletion_proposer), "deletionProposedAt": iso(c.deletion_proposed_at),
    }


def decision_json(d: LifecycleDecision) -> dict[str, Any]:
    return {
        "id": d.id, "candidateId": d.candidate_id, "from": d.from_state.value, "to": d.to_state.value,
        "actor": actor_json(d.actor), "decidedAt": iso(d.decided_at), "reason": d.reason,
        "evidenceFingerprint": d.evidence_fingerprint, "epoch": d.epoch, "approvalId": d.approval_id,
        "executionJobId": d.execution_job_id,
    }


def approval_json(a: ApprovalRecord, now: datetime) -> dict[str, Any]:
    return {
        "id": a.id, "candidateId": a.candidate_id, "stage": a.stage.value, "decision": a.decision.value,
        "operator": actor_json(a.operator), "decidedAt": iso(a.decided_at), "reason": a.reason,
        "evidenceFingerprint": a.evidence_fingerprint, "candidateEpoch": a.candidate_epoch,
        "expiresAt": iso(a.expires_at), "expired": now >= a.expires_at,
    }


def job_json(job: ExecutionJob, history: list[JobStatusEvent]) -> dict[str, Any]:
    return {
        "id": job.id, "candidateId": job.candidate_id, "kind": job.kind.value, "executionMode": job.mode.value,
        "dryRun": job.dry_run, "executed": job.executed, "status": job.status.value,
        "requestedBy": actor_json(job.requested_by), "requestedAt": iso(job.requested_at),
        "approvalId": job.approval_id, "evidenceFingerprint": job.evidence_fingerprint, "targets": list(job.targets),
        "targetsSynthetic": job.targets_synthetic, "finishedAt": iso(job.finished_at),
        "statusHistory": [{"sequence": e.sequence, "status": e.status.value, "executed": e.executed,
                           "finishedAt": iso(e.finished_at), "externalRef": e.external_ref, "detail": e.detail,
                           "recordedAt": iso(e.recorded_at)} for e in history],
    }


def collector_run_json(run: CollectorRun, outcome: CollectorRunOutcome | None) -> dict[str, Any]:
    return {
        "id": run.id, "collector": run.collector, "collectorVersion": run.collector_version,
        "source": run.source.value, "executionMode": run.mode.value, "scope": run.scope,
        "startedAt": iso(run.started_at), "startedBy": actor_json(run.started_by),
        "finished": outcome is not None,
        "outcome": None if outcome is None else {
            "finishedAt": iso(outcome.finished_at), "status": outcome.status.value,
            "recordsObserved": outcome.records_observed,
            "errorCode": outcome.error_code.value if outcome.error_code else None,
            "errorSummary": outcome.error_summary,
        },
    }


def audit_json(e: AuditEvent) -> dict[str, Any]:
    return {
        "id": e.id, "sequence": e.sequence, "occurredAt": iso(e.occurred_at), "actor": actor_json(e.actor),
        "action": e.action.value, "subjectId": e.subject_id, "details": {k: v for k, v in e.details},
        "executionMode": e.execution_mode.value if e.execution_mode else None,
        "result": e.result.value if e.result else None, "correlationId": e.correlation_id,
        "beforeRef": e.before_ref, "afterRef": e.after_ref, "digest": e.digest, "previousDigest": e.previous_digest,
    }


def mapping_review_json(r: MappingReview) -> dict[str, Any]:
    return {
        "id": r.id, "sequence": r.sequence, "supersedes": r.supersedes, "oktaGroupRef": r.okta_group_ref,
        "oktaGroupId": r.okta_group_id, "oktaGroupName": r.okta_group_name, "adObjectGuid": r.ad_object_guid,
        "adSid": r.ad_sid, "adDistinguishedName": r.ad_distinguished_name, "adDomain": r.ad_domain,
        "method": r.method.value, "confidence": r.confidence.value, "reviewStatus": r.review_status.value,
        "verifiedAt": iso(r.verified_at), "evidenceFingerprint": r.evidence_fingerprint,
        "decidedBy": actor_json(r.decided_by), "decidedAt": iso(r.decided_at), "reason": r.reason,
    }


def review_registry_json(history: tuple[MappingReview, ...]) -> dict[str, Any]:
    approval, pending = current_approval(history), pending_selection(history)
    return {
        "reviews": [mapping_review_json(r) for r in history],
        "currentApprovalId": approval.id if approval else None,
        "pendingSelectionId": pending.id if pending else None,
    }


def policy_version_json(v: PolicyVersion, releases: tuple[PolicyRelease, ...] = ()) -> dict[str, Any]:
    release = release_for_digest(releases, v.policy_digest)
    return {
        "id": v.id, "sequence": v.sequence, "supersedes": v.supersedes, "policyDigest": v.policy_digest,
        "proposedBy": actor_json(v.proposed_by), "proposerRole": v.proposer_role.value,
        "approvedBy": actor_json(v.approved_by), "approverRole": v.approver_role.value,
        "decidedAt": iso(v.decided_at), "reason": v.reason,
        "release": release.summary() if release else None,
    }


# How a recorded reference compares with the release now published under the same version.
PUBLISHED_MATCHES = "MATCHES_RECORDED"
PUBLISHED_DIFFERS = "DIFFERS_FROM_RECORDED"
NOT_PUBLISHED = "NOT_PUBLISHED"


def policy_ref_json(ref: PolicyRef | None, releases: tuple[PolicyRelease, ...] = ()) -> dict[str, Any] | None:
    """The policy a decision recorded, exactly as recorded (None: the record names none). Never the
    policy in force now. ``publishedRelease`` says whether the release now published under that
    version still has the recorded content, so an edited release file shows as a difference."""
    if ref is None:
        return None
    published = None
    if ref.policy_id is not None:
        current = next((r for r in releases if (r.policy_id, r.version) == (ref.policy_id, ref.version)), None)
        published = (NOT_PUBLISHED if current is None
                     else PUBLISHED_MATCHES if current.release_digest == ref.release_digest else PUBLISHED_DIFFERS)
    return {**ref.to_dict(), "publishedRelease": published}


class ReadModel:
    """Bounded, read-only queries. Every SQL statement here is a SELECT."""

    def __init__(self, store: Store) -> None:
        self._store = store
        self._conn = store.connection
        # The snapshot's names live in JSON bodies that SQLite cannot index: one dict lookup per row.
        self._conn.create_function("snapshot_ad_name", 1, lambda ref: self._snapshot_ad_names.get(ref),
                                   deterministic=True)

    @cached_property
    def _snapshot_ad_names(self) -> dict[str, str]:
        """The directory snapshot's AD group names by AD evidence id (none without a snapshot). Read
        once: like DirectoryView, this relies on the snapshot never changing once written (0012)."""
        bodies = [json.loads(r["body"]) for r in self._conn.execute(
            "SELECT body FROM synthetic_directory_records WHERE kind = 'GROUP'")]
        return {b["adEvidenceId"]: b["name"] for b in bodies if b.get("adEvidenceId")}

    def page_ids(self, listing: str, page: Page, sort: Sort | None = None, where: str = "",
                 params: tuple = ()) -> tuple[list[str], bool]:
        """One page of a listing's ids: filtered (``where``, this module's constants), sorted, then
        paged, in one query. A missing value sorts last either way; ties keep the listing's order."""
        rows = self._conn.execute(f"SELECT a.id FROM {PAGED[listing][0]} {where} ORDER BY {_order(listing, sort)} "
                                  "LIMIT ? OFFSET ?", (*params, page.limit + 1, page.offset)).fetchall()
        return [r["id"] for r in rows[: page.limit]], len(rows) > page.limit

    def all_ids(self, listing: str, sort: Sort | None, where: str, params: tuple) -> list[str]:
        """Every id ``where`` selects, in the listing's order, unpaged: only for a ``where`` that bounds
        the rows by itself (unexpired approvals, OGWA-APPROVAL-ATTENTION-01)."""
        rows = self._conn.execute(f"SELECT a.id FROM {PAGED[listing][0]} {where} ORDER BY {_order(listing, sort)}", params)
        return [r["id"] for r in rows]

    def page_of(self, listing: str, page: Page, sort: Sort | None = None) -> tuple[list[Evidence], bool]:
        ids, more = self.page_ids(listing, page, sort)
        records = [self._store.latest(LISTABLE[listing][1], i) for i in ids]
        return [r for r in records if r is not None], more

    def count(self, table: str, where: str = "", params: tuple = ()) -> int:
        """Rows in one of the listed tables (``table`` and ``where`` are this module's constants)."""
        return self._conn.execute(f"SELECT count(*) FROM {table} {where}", params).fetchone()[0]

    def candidates(self, page: Page, state: LifecycleState | None,
                   sort: Sort | None = None) -> tuple[list[LifecycleCandidate], bool]:
        where, params = ("WHERE a.state = ?", (state.value,)) if state is not None else ("", ())
        ids, more = self.page_ids("candidates", page, sort, where, params)
        return [self._store.load_candidate(i) for i in ids], more

    def state_counts(self) -> dict[str, int]:
        rows = self._conn.execute("SELECT state, count(*) AS n FROM candidates GROUP BY state ORDER BY state")
        return {r["state"]: r["n"] for r in rows}

    def review_queue(self, page: Page, statuses: tuple[str, ...],
                     sort: Sort | None = None) -> tuple[list[LifecycleCandidate], bool, int]:
        """One page of the Review queue: filtered by review status, in priority order (or ``sort``),
        then paged, in one query; with the filtered total. Only the page's candidates are loaded."""
        where, params = review_filter(statuses)
        ids, more = self.page_ids("queue", page, sort, where, params)
        return [self._store.load_candidate(i) for i in ids], more, self.count("candidates a", where, params)

    def review_counts(self) -> dict[str, int]:
        """Candidates per review status, over every candidate (one GROUP BY, whatever the page)."""
        counts = dict.fromkeys(REVIEW_STATUSES, 0)
        for state, n in self.state_counts().items():
            counts[review_status(state)] += n
        return counts

    def holds_ending_by(self, at: datetime) -> int:
        """Candidates in a hold that ended, or ends, no later than ``at``."""
        return self.count("candidates a", f"WHERE {_DEADLINE} <= ?", (ts(at),))

    def candidates_for_ad_group(self, ad_group_ref: str) -> list[tuple[str, IdentityMapping]]:
        """Candidates whose Okta group is mapped **exactly** to this AD group, by its OGWA AD evidence
        id, with the mapping that links them. Only the latest mapping observation counts, and it is
        re-read through the digest-verifying loader; a name never takes part."""
        rows = self._conn.execute(
            f"SELECT a.id FROM {PAGED['mappings'][0]} WHERE o.ad_group_id = ? ORDER BY a.id", (ad_group_ref,))
        out = []
        for row in rows.fetchall():
            m = self._store.latest(IdentityMapping, row["id"])
            if m is not None and m.is_exact and m.ad_group_id == ad_group_ref:
                out += [(cid, m) for cid in self.candidates_for_group(m.okta_group_id)]
        return out

    def collector_runs(self, page: Page, sort: Sort | None = None) -> tuple[list[dict[str, Any]], bool]:
        ids, more = self.page_ids("collectors", page, sort)
        return [collector_run_json(self._store.collector_run(i), self._store.collector_run_outcome(i)) for i in ids], more

    def collector_summary(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT count(*) AS total, "
            "sum(CASE WHEN o.run_id IS NULL THEN 1 ELSE 0 END) AS unfinished, "
            "sum(CASE WHEN o.status IS NOT NULL AND o.status <> 'COMPLETE' THEN 1 ELSE 0 END) AS incomplete "
            "FROM collector_runs r LEFT JOIN collector_run_outcomes o ON o.run_id = r.id"
        ).fetchone()
        return {"runs": row["total"] or 0, "unfinished": row["unfinished"] or 0, "incomplete": row["incomplete"] or 0}

    def evidence_counts(self) -> dict[str, int]:
        counts = {}
        for name, table in (("applications", "okta_applications"), ("oktaGroups", "okta_groups"),
                            ("adGroups", "ad_groups"), ("mappings", "identity_mappings"),
                            ("dependencyChecks", "dependency_checks")):
            counts[name] = self._conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        return counts

    def dependency_summary(self) -> dict[str, int]:
        """The dashboard's dependency figures, counted over each check's latest observation."""
        row = self._conn.execute(
            "SELECT count(*) AS checks, coalesce(sum(n > 0), 0) AS with_findings, coalesce(sum(n), 0) AS findings, "
            f"coalesce(sum(b), 0) AS blocking FROM (SELECT {_FINDINGS.format('')} AS n, "
            f"{_FINDINGS.format(' AND blocking = 1')} AS b FROM {PAGED['dependencies'][0]})").fetchone()
        return {"checks": row["checks"], "checksWithFindings": row["with_findings"], "findings": row["findings"],
                "blocking": row["blocking"]}

    def approvals(self, page: Page, sort: Sort | None = None, where: str = "",
                  params: tuple = ()) -> tuple[list[ApprovalRecord], bool]:
        """Every approval and rejection (or those ``where`` selects), newest first (P09: the approvals view)."""
        ids, more = self.page_ids("approvals", page, sort, where, params)
        return self.load_approvals(ids), more

    def load_approvals(self, ids: list[str]) -> list[ApprovalRecord]:
        records = [self._store.load_approval(i) for i in ids]
        return [r for r in records if r is not None]

    def execution_job_ids(self, page: Page, sort: Sort | None = None) -> tuple[list[str], bool]:
        """Every execution job id, newest first (P09: the execution jobs view)."""
        return self.page_ids("jobs", page, sort)

    def job_ids_for(self, candidate_id: str) -> list[str]:
        rows = self._conn.execute("SELECT id FROM execution_jobs WHERE candidate_id = ? ORDER BY requested_at, id",
                                  (candidate_id,))
        return [r["id"] for r in rows]

    def mapping_for_group(self, okta_group_ref: str) -> IdentityMapping | None:
        row = self._conn.execute("SELECT id FROM identity_mappings WHERE group_id = ?", (okta_group_ref,)).fetchone()
        return self._store.latest(IdentityMapping, row["id"]) if row else None

    def candidates_for_group(self, okta_group_ref: str) -> list[str]:
        rows = self._conn.execute("SELECT id FROM candidates WHERE group_id = ? ORDER BY created_at, id",
                                  (okta_group_ref,))
        return [r["id"] for r in rows]

    def assignments_of_application(self, application_id: str) -> list[ApplicationGroupAssignment]:
        rows = self._conn.execute(
            "SELECT id FROM app_group_assignments WHERE application_id = ? ORDER BY id LIMIT 500", (application_id,))
        return [a for a in (self._store.latest(ApplicationGroupAssignment, r["id"]) for r in rows) if a]

    def assignments_of_group(self, okta_group_ref: str) -> list[ApplicationGroupAssignment]:
        rows = self._conn.execute(
            "SELECT id FROM app_group_assignments WHERE group_id = ? ORDER BY id LIMIT 500", (okta_group_ref,))
        return [a for a in (self._store.latest(ApplicationGroupAssignment, r["id"]) for r in rows) if a]
