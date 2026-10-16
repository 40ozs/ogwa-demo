"""The API's routes. Each one declares its access at registration (see ``Route``).

``ROUTES`` is the whole surface. ``tests/test_api_authorization.py`` walks it for every
role, so a new route without an explicit access rule cannot be added unnoticed.
"""

from typing import Any

from app.api.app import Context, Route
from app.api.authz import Permission, Principal
from app.api import directory as directory_api
from app.api.errors import ApiError, not_found
from app.api.http import Response, expired_cookie, session_cookie
from app.api.identity import AuthenticationFailed
from app.api.readmodel import (
    LISTABLE,
    PAGED,
    ad_group_json,
    application_json,
    approval_json,
    assignment_json,
    audit_json,
    bundle_json,
    candidate_json,
    decision_json,
    dependencies_json,
    dependency_json,
    iso,
    job_json,
    mapping_json,
    mapping_review_json,
    okta_group_json,
    policy_ref_json,
    policy_version_json,
    review_registry_json,
)
from app.api.services import (
    LIFECYCLE_WRITE_PERMISSIONS,
    MAX_APPROVAL_HOURS,
    PLANNABLE_STATES,
    STAGES,
    demo_releases,
    is_operator_action,
    policy_in_force,
    production_mutation_refused,
    transition_permission,
)
from app.api.authorization import drill_chain
from app.api.remediation import remediation_record_json
from app.api.sessions import CSRF_HEADER, SESSION_COOKIE
from app.api.resolve import ID_RE as REF_ID_RE
from app.api.resolve import MAX_IDS, IdentityResolver
from app.api.validation import SORT_QUERY, Body, Sort, page_from, path_id, sort_from
from app.core.build import BUILD_ALLOWS_PRODUCTION_MUTATION
from app.core.modes import EXTERNAL_MUTATION_SUMMARY, ExecutionMode
from app.domain.approval import ApprovalDecision, ApprovalStage
from app.domain.execution import JobKind
from app.domain.ids import IdKind
from app.domain.lifecycle import TRANSITIONS, LifecycleCandidate, LifecycleState, allowed_targets
from app.domain.mapping_review import MappingReview
from app.domain.model import ADGroup, OktaApplication, OktaGroup
from app.domain.remediation import OPERATIONS, TARGET_ID_KINDS, RemediationOperation, TargetKind
from app.domain.remediation_execution import MAX_SUBMISSIONS, MAX_VERIFICATION_READS, STATE_LABELS
from app.remediation.drill import DRILL_NOTICE, DrillMode
from app.remediation.synthetic_provider import SCENARIOS
from app.governance.analysis import RULES as GOVERNANCE_RULES
from app.store.environment import DatabaseEnvironment

P = Permission
PAGE = frozenset({"limit", "cursor"})
LISTING = PAGE | SORT_QUERY


def _sort(ctx: Context, listing: str) -> Sort | None:
    """The listing's ``sort=``/``order=``; its fields are ReadModel's (app/api/readmodel.py PAGED)."""
    return sort_from(ctx.request.query, PAGED[listing][2])


def ok(body: dict[str, Any], status: int = 200, headers: list[tuple[str, str]] | None = None) -> Response:
    return Response(status, body, headers or [])


# --- public and session ----------------------------------------------------------------


def health(ctx: Context) -> Response:
    return ok({"status": "ok"})


def sign_in(ctx: Context) -> Response:
    api = ctx.api
    try:
        claims = api.identity.authenticate(ctx.request.body or {}, now=api.clock())
    except AuthenticationFailed as exc:
        raise ApiError(401, "AUTHENTICATION_FAILED", str(exc)) from None
    api.sessions.revoke(ctx.request.cookies.get(SESSION_COOKIE))  # never keep a pre-login session
    token, session = api.sessions.create(claims)
    principal = Principal(claims, api.bindings.roles_for(claims))
    return ok({"principal": principal.to_dict(), "csrfToken": session.csrf_token, "csrfHeader": CSRF_HEADER},
              201, [session_cookie(SESSION_COOKIE, token, api.sessions.cookie_max_age)])


def session_info(ctx: Context) -> Response:
    return ok({"principal": ctx.user.to_dict(), "csrfToken": ctx.session.csrf_token, "csrfHeader": CSRF_HEADER})


def sign_out(ctx: Context) -> Response:
    Body(ctx.request.body, allowed=())
    ctx.api.sessions.revoke(ctx.session_token)
    return ok({"signedOut": True}, headers=[expired_cookie(SESSION_COOKIE)])


# --- dashboard and inventory -----------------------------------------------------------


def dashboard(ctx: Context) -> Response:
    api = ctx.api
    counts = api.read.state_counts()
    try:
        policy = policy_in_force(api.store).to_dict()
    except ApiError as exc:
        policy = {"label": None, "recorded": False, "source": None, "unavailable": exc.code}
    head = api.store.audit_head()
    return ok({
        "candidatesByState": counts,
        "awaitingApproval": {stage.value: counts.get(entry.value, 0) for stage, (entry, _, _) in STAGES.items()},
        "collectors": api.read.collector_summary(),
        "evidence": api.read.evidence_counts(),
        "dependencyFindings": api.read.dependency_summary(),
        "policy": policy,
        "safety": {
            "executionMode": api.mode.value,
            "externalMutation": EXTERNAL_MUTATION_SUMMARY[api.mode],
            "productionMutationPermittedByBuild": BUILD_ALLOWS_PRODUCTION_MUTATION,
            "executionRoutes": "DRY_RUN_PLANNING_ONLY",
        },
        "store": {"environment": api.store.marker.environment.value,
                  "auditEvents": head[0] + 1 if head else 0, "auditHead": head[1] if head else None},
        "generatedAt": iso(api.clock()),
    })


def _listing(ctx: Context, listing: str, render) -> Response:
    page = page_from(ctx.request.query)
    records, more = ctx.api.read.page_of(listing, page, _sort(ctx, listing))
    return ok(page.envelope([render(r) for r in records], more=more, total=ctx.api.read.count(LISTABLE[listing][0])))


def applications(ctx: Context) -> Response:
    return _listing(ctx, "applications", application_json)


def application(ctx: Context) -> Response:
    app_id = path_id(ctx.request.path_params["applicationId"], IdKind.OKTA_APPLICATION, "application")
    record = ctx.api.store.latest(OktaApplication, app_id)
    if record is None:
        raise not_found("application")
    return ok({"application": application_json(record),
               "assignments": [assignment_json(a) for a in ctx.api.read.assignments_of_application(app_id)],
               # The synthetic directory snapshot's view of the application, if the store holds one.
               "profile": ctx.api.directory.application_profile(app_id)})


def groups(ctx: Context) -> Response:
    return _listing(ctx, "groups", okta_group_json)


def group(ctx: Context) -> Response:
    group_id = path_id(ctx.request.path_params["groupId"], IdKind.OKTA_GROUP, "Okta group")
    record = ctx.api.store.latest(OktaGroup, group_id)
    if record is None:
        raise not_found("Okta group")
    mapping = ctx.api.read.mapping_for_group(group_id)
    ad = ctx.api.store.latest(ADGroup, mapping.ad_group_id) if mapping and mapping.ad_group_id else None
    return ok({"group": okta_group_json(record),
               "assignments": [assignment_json(a) for a in ctx.api.read.assignments_of_group(group_id)],
               "mapping": mapping_json(mapping) if mapping else None,
               "adGroup": ad_group_json(ad) if ad else None,
               "candidateIds": ctx.api.read.candidates_for_group(group_id),
               "directory": ctx.api.directory.group_for_okta_ref(group_id)})


def mappings(ctx: Context) -> Response:
    return _listing(ctx, "mappings", mapping_json)


def mapping(ctx: Context) -> Response:
    group_id = path_id(ctx.request.path_params["groupId"], IdKind.OKTA_GROUP, "Okta group")
    if ctx.api.store.latest(OktaGroup, group_id) is None:
        raise not_found("Okta group")
    record = ctx.api.read.mapping_for_group(group_id)
    ad = ctx.api.store.latest(ADGroup, record.ad_group_id) if record and record.ad_group_id else None
    candidates = [a for a in (ctx.api.store.latest(ADGroup, i) for i in (record.candidate_ad_group_ids if record else ()))
                  if a]
    return ok({"oktaGroupId": group_id, "mapping": mapping_json(record) if record else None,
               "adGroup": ad_group_json(ad) if ad else None,
               "candidateAdGroups": [ad_group_json(a) for a in candidates],
               "registry": review_registry_json(tuple(ctx.api.store.mapping_reviews(group_id))),
               "reviewActionsAvailable": ctx.api.mappings.available})


# --- the synthetic directory snapshot (people, directory groups, findings) -------------


def directory_summary(ctx: Context) -> Response:
    return ok(ctx.api.directory.summary())


def people(ctx: Context) -> Response:
    page, q = page_from(ctx.request.query), ctx.request.query
    return ok(ctx.api.directory.people(page, department=directory_api.slug(q, "department"),
                                       status=directory_api.choice(q, "status", directory_api.PERSON_STATUSES),
                                       q=directory_api.search_text(q), sort=sort_from(q, directory_api.PEOPLE_SORT)))


def person(ctx: Context) -> Response:
    return ok(ctx.api.directory.person(ctx.request.path_params["personId"]))


def directory_groups(ctx: Context) -> Response:
    page, q = page_from(ctx.request.query), ctx.request.query
    return ok(ctx.api.directory.groups(page, era=directory_api.slug(q, "era"),
                                       health=directory_api.choice(q, "health", directory_api.HEALTH),
                                       source=directory_api.choice(q, "source", directory_api.GROUP_SOURCES),
                                       q=directory_api.search_text(q), sort=sort_from(q, directory_api.GROUP_SORT)))


def directory_group(ctx: Context) -> Response:
    return ok(ctx.api.directory.group(ctx.request.path_params["directoryGroupId"]))


def governance_findings(ctx: Context) -> Response:
    page, q = page_from(ctx.request.query), ctx.request.query
    listing, counts = ctx.api.directory.findings(
        page, severity=directory_api.choice(q, "severity", directory_api.SEVERITIES),
        code=directory_api.choice(q, "code", tuple(sorted(GOVERNANCE_RULES))),
        subject_kind=directory_api.choice(q, "subjectKind", ("GROUP", "APPLICATION", "PERSON")),
        sort=sort_from(q, directory_api.FINDING_SORT))
    return ok({**listing, "counts": counts,
               "note": "Findings are evidence for review. None of them authorizes a change."})


def demo_scenarios(ctx: Context) -> Response:
    """The portfolio scenarios and, for a dataset that has one, its guided reviewer walkthrough,
    each part's candidate key resolved to its candidate id from the scenarios."""
    items = ctx.api.directory.scenarios()
    return ok({"items": items, "walkthrough": _walkthrough(ctx, items)})


def _walkthrough(ctx: Context, items: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not items or ctx.api.store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
        return None
    from app.demo.datasets import dataset_of

    guide = dataset_of(ctx.api.store).walkthrough(public=ctx.api.store.read_only)  # a read-only store: the public demo
    if guide is None:
        return None
    ids = {s.get("candidateKey"): s.get("candidateId") for s in items if s.get("candidateKey")}
    return {**guide, "parts": [{**p, "candidateId": ids.get(p["candidateKey"])} for p in guide["parts"]]}


def identities(ctx: Context) -> Response:
    """Names and canonical pages for up to 50 stable ids (app/api/resolve.py)."""
    refs = list(dict.fromkeys(r for r in ctx.request.query.get("ids", "").split(",") if r))
    if len(refs) > MAX_IDS:
        raise ApiError(400, "MALFORMED_REQUEST", f"ids must list at most {MAX_IDS} comma-separated ids.")
    for ref in refs:
        if not (REF_ID_RE.match(ref) or directory_api.SID_RE.match(ref)):
            raise ApiError(400, "MALFORMED_REQUEST", "each id must be an OGWA id or an AD domain objectSid.")
    return ok({"items": IdentityResolver(ctx.api).resolve_many(refs)})


# --- candidates ------------------------------------------------------------------------


def _candidate(ctx: Context) -> LifecycleCandidate:
    candidate_id = path_id(ctx.request.path_params["candidateId"], IdKind.CANDIDATE, "candidate")
    return ctx.api.lifecycle.load(candidate_id)


def candidates(ctx: Context) -> Response:
    page = page_from(ctx.request.query)
    raw_state = ctx.request.query.get("state")
    state = None
    if raw_state is not None:
        if raw_state not in {s.value for s in LifecycleState}:
            raise ApiError(400, "MALFORMED_REQUEST", "state must be a lifecycle state name.")
        state = LifecycleState(raw_state)
    items, more = ctx.api.read.candidates(page, state, _sort(ctx, "candidates"))
    where, params = ("WHERE state = ?", (state.value,)) if state is not None else ("", ())
    return ok(page.envelope([candidate_json(c) for c in items], more=more,
                            total=ctx.api.read.count("candidates", where, params)))


def _allowed_actions(ctx: Context, candidate: LifecycleCandidate) -> dict[str, Any]:
    user, lifecycle = ctx.user, ctx.api.lifecycle
    transitions = []
    for target in sorted(allowed_targets(candidate.state)):
        key = (candidate.state, target)
        needed = transition_permission(*key)
        category = TRANSITIONS[key].category
        transitions.append({
            "target": target.value, "category": category,
            "operatorAction": is_operator_action(*key),
            "permission": needed.value if needed else None,
            "permitted": needed is not None and user.can(needed),
            "requiresEvidenceFingerprint": category != "diversion",
        })
    approvals = []
    for stage, (entry_state, _, _) in STAGES.items():
        if candidate.state is entry_state:
            conflicts = lifecycle.approver_conflicts(candidate, stage, user.actor)
            approvals.append({"stage": stage.value, "permitted": user.can(P.APPROVAL_DECIDE) and not conflicts,
                              "separationOfDutiesConflicts": conflicts})
    return {"transitions": transitions, "approvals": approvals,
            "planDryRun": user.can(P.EXECUTION_PLAN_DRY_RUN) and candidate.state in PLANNABLE_STATES}


def _quarantine_view(ctx: Context, bundle) -> dict[str, Any] | None:
    """Where the mapped AD group stands against its domain's quarantine OU (D136). Read-only:
    the OU comes from deployment configuration, which no route changes."""
    ad, ous = bundle.ad_group, ctx.api.lifecycle.quarantine_ous
    if ad is None or not ad.exists:
        return None
    return {"domain": ad.domain, "quarantineOu": ous.ou_for(ad.domain) if ous else None,
            "inQuarantine": ous.in_quarantine(ad) if ous else None}


def candidate(ctx: Context) -> Response:
    record = _candidate(ctx)
    bundle = ctx.api.store.evidence_bundle(record)
    view = bundle_json(bundle)
    try:
        in_force = policy_in_force(ctx.api.store).to_dict()
    except ApiError as exc:
        in_force = {"label": None, "recorded": False, "unavailable": exc.code}
    classification, assessment, explanation = ctx.api.lifecycle.classify_assess_explain(record, bundle)
    return ok({"candidate": candidate_json(record), "evidenceFingerprint": view["evidenceFingerprint"],
               "policy": in_force, "classification": classification, "evidenceAssessment": assessment,
               "decisionExplanation": explanation,
               "quarantine": _quarantine_view(ctx, bundle),
               "allowedActions": _allowed_actions(ctx, record),
               "note": "A candidate is evidence for review, never authorization to change anything."})


def candidate_evidence(ctx: Context) -> Response:
    record = _candidate(ctx)
    return ok({"candidateId": record.id, **bundle_json(ctx.api.store.evidence_bundle(record))})


def candidate_dependencies(ctx: Context) -> Response:
    record = _candidate(ctx)
    try:
        in_force = policy_in_force(ctx.api.store)
    except ApiError:
        in_force = None
    return ok({"candidateId": record.id, "policy": in_force.to_dict() if in_force else None,
               **dependencies_json(ctx.api.store.evidence_bundle(record), in_force.policy.lifecycle if in_force else None)})


def _judged_by(ctx: Context, refs: dict, ref: str) -> dict[str, Any] | None:
    """The policy a decision or approval recorded, as recorded; None if it recorded none."""
    return policy_ref_json(refs.get(ref), demo_releases(ctx.api.store))


def candidate_decisions(ctx: Context) -> Response:
    record = _candidate(ctx)
    refs = ctx.api.store.recorded_policies(record.id)
    return ok({"candidateId": record.id, "items": [
        {**decision_json(d), "policy": _judged_by(ctx, refs, f"decision:{d.id}")}
        for d in ctx.api.store.decisions(record.id)]})


def candidate_approvals(ctx: Context) -> Response:
    record = _candidate(ctx)
    now = ctx.api.clock()
    refs = ctx.api.store.recorded_policies(record.id)
    return ok({"candidateId": record.id, "items": [
        {**approval_json(a, now), "policy": _judged_by(ctx, refs, f"approval:{a.id}")}
        for a in ctx.api.store.approvals_for(record.id)]})


def candidate_jobs(ctx: Context) -> Response:
    record = _candidate(ctx)
    store = ctx.api.store
    return ok({"candidateId": record.id, "items": [
        job_json(store.load_execution_job(j), store.job_status_history(j)) for j in ctx.api.read.job_ids_for(record.id)]})


def candidate_audit(ctx: Context) -> Response:
    record = _candidate(ctx)
    page = page_from(ctx.request.query)
    events = ctx.api.store.audit_events_page(limit=page.limit + 1, offset=page.offset, subject_id=record.id)
    return ok(page.envelope([audit_json(e) for e in events[: page.limit]], more=len(events) > page.limit))


def dependency_findings(ctx: Context) -> Response:
    return _listing(ctx, "dependencies", dependency_json)


def approvals(ctx: Context) -> Response:
    page, now = page_from(ctx.request.query), ctx.api.clock()
    items, more = ctx.api.read.approvals(page, _sort(ctx, "approvals"))
    refs = ctx.api.store.recorded_policies(approval_ids=tuple(a.id for a in items))
    return ok(page.envelope([{**approval_json(a, now), "policy": _judged_by(ctx, refs, f"approval:{a.id}")}
                             for a in items], more=more, total=ctx.api.read.count("approvals")))


def execution_jobs(ctx: Context) -> Response:
    page, store = page_from(ctx.request.query), ctx.api.store
    ids, more = ctx.api.read.execution_job_ids(page, _sort(ctx, "jobs"))
    items = [job_json(store.load_execution_job(j), store.job_status_history(j)) for j in ids]
    return ok({**page.envelope(items, more=more, total=ctx.api.read.count("execution_jobs")), "executionAvailable": False})


def execution_job(ctx: Context) -> Response:
    job_id = path_id(ctx.request.path_params["jobId"], IdKind.EXECUTION_JOB, "execution job")
    job = ctx.api.store.load_execution_job(job_id)
    if job is None:
        raise not_found("execution job")
    return ok({"job": job_json(job, ctx.api.store.job_status_history(job_id))})


def collector_runs(ctx: Context) -> Response:
    page = page_from(ctx.request.query)
    items, more = ctx.api.read.collector_runs(page, _sort(ctx, "collectors"))
    return ok({**page.envelope(items, more=more, total=ctx.api.read.count("collector_runs")),
               "summary": ctx.api.read.collector_summary()})


def policy(ctx: Context) -> Response:
    try:
        in_force = policy_in_force(ctx.api.store).to_dict()
    except ApiError as exc:
        in_force = {"label": None, "recorded": False, "source": None, "unavailable": exc.code}
    releases = demo_releases(ctx.api.store)
    return ok({"inForce": in_force,
               "versions": [policy_version_json(v, releases) for v in ctx.api.store.policy_versions()],
               "releases": [{**r.summary(), "purpose": r.purpose, "document": r.to_document()} for r in releases],
               "editableViaApi": False})


def audit_events(ctx: Context) -> Response:
    page = page_from(ctx.request.query)
    subject = ctx.request.query.get("subjectId")
    if subject is not None and not 0 < len(subject) <= 100:
        raise ApiError(400, "MALFORMED_REQUEST", "subjectId must be 1-100 characters.")
    # The hash-chained trail is served in chain order, either way round; sorting it by any other
    # field would load and re-verify every event, so only the sequence is sortable.
    sort = sort_from(ctx.request.query, ("sequence",))
    events = ctx.api.store.audit_events_page(limit=page.limit + 1, offset=page.offset, subject_id=subject,
                                             oldest_first=bool(sort and not sort.descending))
    where, params = ("WHERE subject_id = ?", (subject,)) if subject is not None else ("", ())
    return ok(page.envelope([audit_json(e) for e in events[: page.limit]], more=len(events) > page.limit,
                            total=ctx.api.read.count("audit_events", where, params)))


def role_bindings(ctx: Context) -> Response:
    return ok(ctx.api.bindings.to_dict())


def system_integrity(ctx: Context) -> Response:
    report = ctx.api.store.verified_integrity()
    return ok({"schemaVersion": report.schema_version, "environment": report.environment.value,
               "auditEvents": report.audit_events, "auditHead": report.audit_head,
               "observationsChecked": report.observations_checked, "candidatesChecked": report.candidates_checked})


# --- lifecycle writes ------------------------------------------------------------------


def post_transition(ctx: Context) -> Response:
    record = _candidate(ctx)
    body = Body(ctx.request.body, allowed={"target", "reason", "expectedEvidenceFingerprint", "approvalId", "jobId"})
    result = ctx.api.lifecycle.transition(
        ctx.user, record.id, target=body.enum("target", LifecycleState), reason=body.text("reason"),
        expected_fingerprint=body.digest("expectedEvidenceFingerprint", required=False),
        approval_id=body.internal_id("approvalId", IdKind.APPROVAL, required=False),
        job_id=body.internal_id("jobId", IdKind.EXECUTION_JOB, required=False),
        request_id=ctx.request.request_id)
    decision = result["decision"]
    refs = ctx.api.store.recorded_policies(record.id)
    return ok({"candidate": candidate_json(result["candidate"]),
               "decision": {**decision_json(decision), "policy": _judged_by(ctx, refs, f"decision:{decision.id}")},
               "policy": result["policy"].to_dict()}, 201)


def post_approval(ctx: Context) -> Response:
    record = _candidate(ctx)
    body = Body(ctx.request.body, allowed={"stage", "decision", "reason", "expectedEvidenceFingerprint", "validForHours"})
    result = ctx.api.lifecycle.decide_approval(
        ctx.user, record.id, stage=body.enum("stage", ApprovalStage), decision=body.enum("decision", ApprovalDecision),
        reason=body.text("reason"), expected_fingerprint=body.digest("expectedEvidenceFingerprint"),
        valid_hours=body.integer("validForHours", minimum=1, maximum=MAX_APPROVAL_HOURS, required=False),
        request_id=ctx.request.request_id)
    decision, approval = result["decision"], result["approval"]
    refs = ctx.api.store.recorded_policies(record.id)
    return ok({"approval": {**approval_json(approval, ctx.api.clock()),
                            "policy": _judged_by(ctx, refs, f"approval:{approval.id}")},
               "candidate": candidate_json(result["candidate"]),
               "decision": {**decision_json(decision), "policy": _judged_by(ctx, refs, f"decision:{decision.id}")}
               if decision else None, "policy": result["policy"].to_dict()}, 201)


def post_execution_job(ctx: Context) -> Response:
    record = _candidate(ctx)
    body = Body(ctx.request.body, allowed={"kind", "approvalId", "expectedEvidenceFingerprint", "dryRun",
                                           "executionMode"})
    mode = body.raw("executionMode")
    if mode is not None and not isinstance(mode, str):
        raise ApiError(422, "VALIDATION_FAILED", "executionMode must be a string.")
    dry_run = body.boolean("dryRun", required=False)
    result = ctx.api.lifecycle.plan_dry_run(
        ctx.user, record.id, kind=body.enum("kind", JobKind),
        approval_id=body.internal_id("approvalId", IdKind.APPROVAL),
        expected_fingerprint=body.digest("expectedEvidenceFingerprint"),
        dry_run=True if dry_run is None else dry_run, requested_mode=mode, request_id=ctx.request.request_id)
    job = result["job"]
    return ok({"job": job_json(job, ctx.api.store.job_status_history(job.id)),
               "plannedActions": result["plannedActions"], "executed": False,
               "policy": result["policy"].to_dict()}, 201)


def post_execute(ctx: Context) -> Response:
    job_id = path_id(ctx.request.path_params["jobId"], IdKind.EXECUTION_JOB, "execution job")
    Body(ctx.request.body, allowed=())
    ctx.api.lifecycle.execute(ctx.user, job_id)
    raise AssertionError("unreachable")  # pragma: no cover - execute() always refuses in this build


# --- remediation dry runs --------------------------------------------------------

# Each operation's target is one object with exactly one field: the OGWA id of the one thing
# it would change. A list, a second field, or any other identifier is refused.
REMEDIATION_TARGET_FIELDS = {TargetKind.OKTA_ASSIGNMENT: "assignmentId", TargetKind.AD_GROUP: "adGroupId"}


def _remediation_target(raw: Any, operation: RemediationOperation) -> str:
    kind = OPERATIONS[operation].target_kind
    name = REMEDIATION_TARGET_FIELDS[kind]
    if not isinstance(raw, dict) or set(raw) != {name}:
        raise ApiError(422, "VALIDATION_FAILED", f"target must be one object with exactly one field, {name}: a "
                                                 f"remediation names a single explicit target, never a list or a "
                                                 f"pattern.")
    return Body(raw, allowed={name}).internal_id(name, TARGET_ID_KINDS[kind])


def post_remediation_dry_run(ctx: Context) -> Response:
    record = _candidate(ctx)
    body = Body(ctx.request.body, allowed={"operation", "target", "approvalId", "expectedEvidenceFingerprint", "dryRun",
                                           "executionMode"})
    mode = body.raw("executionMode")
    if mode is not None and not isinstance(mode, str):
        raise ApiError(422, "VALIDATION_FAILED", "executionMode must be a string.")
    dry_run = body.boolean("dryRun", required=False)
    if mode == ExecutionMode.PRODUCTION_MUTATION.value or dry_run is False:
        raise production_mutation_refused()  # before anything else is read (D8); the service checks again
    operation = body.enum("operation", RemediationOperation)
    result = ctx.api.remediation.dry_run(
        ctx.user, record.id, operation=operation, target_ref=_remediation_target(body.raw("target"), operation),
        approval_id=body.internal_id("approvalId", IdKind.APPROVAL),
        expected_fingerprint=body.digest("expectedEvidenceFingerprint"),
        dry_run=True if dry_run is None else dry_run, requested_mode=mode, request_id=ctx.request.request_id)
    event = result["event"]
    return ok({"remediation": result["result"].to_dict(), "auditEventId": event.id, "recordedAt": iso(event.occurred_at),
               "executed": False, "productionMutation": False, "policy": result["policy"].to_dict(),
               "authorization": result["authorization"].to_dict(ctx.api.store),
               "record": remediation_record_json(event, ctx.api.store)}, 201)


def candidate_remediation_dry_runs(ctx: Context) -> Response:
    record = _candidate(ctx)
    return ok({"candidateId": record.id,
               "items": [remediation_record_json(e, ctx.api.store) for e in ctx.api.remediation.recorded(record.id)],
               "executionAvailable": False})


# --- synthetic remediation drills -----------------------------------------

# A drill names its mode and, to execute, one scenario from the server's closed catalog. It
# cannot carry an execution mode, a dry-run flag, a fault, an adapter, or a template.
DRILL_FIELDS = {"operation", "target", "approvalId", "expectedEvidenceFingerprint", "mode", "scenario"}


def post_remediation_drill(ctx: Context) -> Response:
    record = _candidate(ctx)
    raw = ctx.request.body if isinstance(ctx.request.body, dict) else {}
    if raw.get("executionMode") == ExecutionMode.PRODUCTION_MUTATION.value or raw.get("dryRun") is False:
        raise production_mutation_refused()  # before anything else is read (D8)
    body = Body(ctx.request.body, allowed=DRILL_FIELDS)
    operation = body.enum("operation", RemediationOperation)
    mode = body.enum("mode", DrillMode)
    scenario = body.text("scenario", max_length=60, required=False)
    if scenario is not None and scenario not in SCENARIOS:
        raise ApiError(422, "VALIDATION_FAILED", f"scenario must be one of: {', '.join(SCENARIOS)}.")
    if (mode is DrillMode.DRY_RUN) != (scenario is None):
        raise ApiError(422, "VALIDATION_FAILED", "A SYNTHETIC_EXECUTION names one scenario; a DRY_RUN submits "
                                                 "nothing, so it names none.")
    result = ctx.api.remediation.drill(
        ctx.user, record.id, operation=operation, target_ref=_remediation_target(body.raw("target"), operation),
        approval_id=body.internal_id("approvalId", IdKind.APPROVAL),
        expected_fingerprint=body.digest("expectedEvidenceFingerprint"), mode=mode, scenario=scenario,
        request_id=ctx.request.request_id)
    authorization = result["authorization"]
    return ok({"drill": result["report"].to_dict(), "policy": result["policy"].to_dict(),
               "authorization": authorization.to_dict(ctx.api.store),
               "chain": drill_chain(authorization, result["report"])})


def remediation_drill_scenarios(ctx: Context) -> Response:
    return ok({"items": [s.to_dict() for s in SCENARIOS.values()], "modes": [m.value for m in DrillMode],
               "labels": {state.value: label for state, label in STATE_LABELS.items()},
               "maxSubmissions": MAX_SUBMISSIONS, "maxVerificationReads": MAX_VERIFICATION_READS,
               "notice": DRILL_NOTICE})


# --- mapping reviews -------------------------------------------------------------------


def _group_ref(ctx: Context) -> str:
    return path_id(ctx.request.path_params["groupId"], IdKind.OKTA_GROUP, "Okta group")


def _review(review: MappingReview) -> Response:
    return ok({"review": mapping_review_json(review)}, 201)


def post_mapping_inspection(ctx: Context) -> Response:
    Body(ctx.request.body, allowed=())
    inspection = ctx.api.mappings.inspect(ctx.user, _group_ref(ctx))
    result = inspection.result
    return ok({
        "evidenceFingerprint": inspection.evidence_fingerprint,
        "outcome": result.outcome.value, "confidence": result.confidence.value,
        "method": result.method.value if result.method else None,
        "target": _identity_json(result.target) if result.target else None,
        "candidates": [_identity_json(c) for c in result.candidates],
        "reasons": list(result.reasons),
        "allowedActions": sorted(a.value for a in inspection.allowed_actions),
        "approvableObjectGuid": inspection.approvable_guid,
        "registry": review_registry_json(inspection.history),
    })


def post_mapping_search(ctx: Context) -> Response:
    body = Body(ctx.request.body, allowed={"by", "value", "domain"})
    search_id, result = ctx.api.mappings.search(
        ctx.user, _group_ref(ctx), by=body.text("by", max_length=40), value=body.text("value", max_length=1000),
        domain=body.text("domain", max_length=255, required=False))
    lookup = result.lookup
    return ok({"searchId": search_id, "status": lookup.status.value, "observedAt": iso(lookup.observed_at),
               "candidates": [_identity_json(c) for c in lookup.candidates],
               "candidatesTruncated": lookup.candidates_truncated}, 201)


def _identity_json(identity) -> dict[str, Any]:
    return {"objectGuid": identity.object_guid, "objectSid": identity.object_sid,
            "distinguishedName": identity.distinguished_name, "samAccountName": identity.sam_account_name,
            "domain": identity.domain}


def post_mapping_selection(ctx: Context) -> Response:
    body = Body(ctx.request.body, allowed={"searchId", "objectGuid", "reason"})
    return _review(ctx.api.mappings.select(
        ctx.user, _group_ref(ctx), search_id=body.internal_id("searchId", IdKind.REQUEST),
        object_guid=body.text("objectGuid", max_length=36), reason=body.text("reason")))


def post_mapping_approval(ctx: Context) -> Response:
    body = Body(ctx.request.body, allowed={"objectGuid", "expectedEvidenceFingerprint", "reason"})
    return _review(ctx.api.mappings.approve(
        ctx.user, _group_ref(ctx), object_guid=body.text("objectGuid", max_length=36),
        expected_fingerprint=body.digest("expectedEvidenceFingerprint"), reason=body.text("reason")))


def post_mapping_rejection(ctx: Context) -> Response:
    body = Body(ctx.request.body, allowed={"objectGuid", "expectedEvidenceFingerprint", "reason"})
    return _review(ctx.api.mappings.reject(
        ctx.user, _group_ref(ctx), object_guid=body.text("objectGuid", max_length=36),
        expected_fingerprint=body.digest("expectedEvidenceFingerprint"), reason=body.text("reason")))


# --- the route table -------------------------------------------------------------------

V = "/api/v1"
READ = frozenset({P.READ_INVENTORY})
MAPPING_ANY = frozenset({P.MAPPING_PROPOSE, P.MAPPING_APPROVE, P.MAPPING_REJECT})
# Who may use the execute route at all: the execution function. Everyone else gets the
# ordinary route-level 403, which stays in the security log; an executor's attempt is a
# valid request that the build's production-mutation policy refuses, so it is chained.
EXECUTE_ROUTE = frozenset({P.EXECUTION_PLAN_DRY_RUN, P.EXECUTION_EXECUTE})


def _r(method: str, path: str, handler, access: str, any_of=frozenset(), query=frozenset(), *,
       governed: str | None = None) -> Route:
    return Route(method, V + path, handler, access, frozenset(any_of), frozenset(query), governed_subject=governed)


ROUTES: tuple[Route, ...] = (
    _r("GET", "/health", health, "public"),
    _r("POST", "/session", sign_in, "public"),
    _r("GET", "/session", session_info, "session"),
    _r("POST", "/session/logout", sign_out, "session"),

    _r("GET", "/dashboard", dashboard, "permission", READ),
    _r("GET", "/applications", applications, "permission", READ, LISTING),
    _r("GET", "/applications/{applicationId}", application, "permission", READ),
    _r("GET", "/groups", groups, "permission", READ, LISTING),
    _r("GET", "/groups/{groupId}", group, "permission", READ),
    _r("GET", "/mappings", mappings, "permission", READ, LISTING),
    _r("GET", "/mappings/{groupId}", mapping, "permission", READ),
    _r("GET", "/directory", directory_summary, "permission", READ),
    _r("GET", "/people", people, "permission", READ, LISTING | {"department", "status", "q"}),
    _r("GET", "/people/{personId}", person, "permission", READ),
    _r("GET", "/directory-groups", directory_groups, "permission", READ, LISTING | {"era", "health", "source", "q"}),
    _r("GET", "/directory-groups/{directoryGroupId}", directory_group, "permission", READ),
    _r("GET", "/governance-findings", governance_findings, "permission", READ, LISTING | {"severity", "code", "subjectKind"}),
    _r("GET", "/demo-scenarios", demo_scenarios, "permission", READ),
    _r("GET", "/identities", identities, "permission", READ, {"ids"}),
    _r("GET", "/candidates", candidates, "permission", READ, LISTING | {"state"}),
    _r("GET", "/candidates/{candidateId}", candidate, "permission", READ),
    _r("GET", "/candidates/{candidateId}/evidence", candidate_evidence, "permission", READ),
    _r("GET", "/candidates/{candidateId}/dependencies", candidate_dependencies, "permission", READ),
    _r("GET", "/candidates/{candidateId}/decisions", candidate_decisions, "permission", READ),
    _r("GET", "/candidates/{candidateId}/approvals", candidate_approvals, "permission", READ),
    _r("GET", "/candidates/{candidateId}/execution-jobs", candidate_jobs, "permission", READ),
    _r("GET", "/execution-jobs", execution_jobs, "permission", READ, LISTING),
    _r("GET", "/execution-jobs/{jobId}", execution_job, "permission", READ),
    _r("GET", "/approvals", approvals, "permission", READ, LISTING),
    _r("GET", "/dependency-findings", dependency_findings, "permission", READ, LISTING),
    _r("GET", "/collector-runs", collector_runs, "permission", READ, LISTING),
    _r("GET", "/policy", policy, "permission", READ),

    _r("GET", "/audit-events", audit_events, "permission", {P.READ_AUDIT}, LISTING | {"subjectId"}),
    _r("GET", "/candidates/{candidateId}/audit-events", candidate_audit, "permission", {P.READ_AUDIT}, PAGE),

    _r("GET", "/system/role-bindings", role_bindings, "permission", {P.READ_SYSTEM}),
    _r("GET", "/system/integrity", system_integrity, "permission", {P.READ_SYSTEM}),

    _r("POST", "/candidates/{candidateId}/transitions", post_transition, "permission", LIFECYCLE_WRITE_PERMISSIONS,
       governed="candidateId"),
    _r("POST", "/candidates/{candidateId}/approvals", post_approval, "permission", {P.APPROVAL_DECIDE},
       governed="candidateId"),
    _r("POST", "/candidates/{candidateId}/execution-jobs", post_execution_job, "permission",
       {P.EXECUTION_PLAN_DRY_RUN}, governed="candidateId"),
    _r("POST", "/execution-jobs/{jobId}/execute", post_execute, "permission", EXECUTE_ROUTE, governed="jobId"),
    # One operation on one explicit target of one candidate, dry run only.
    _r("GET", "/candidates/{candidateId}/remediation-dry-runs", candidate_remediation_dry_runs, "permission", READ),
    _r("POST", "/candidates/{candidateId}/remediation-dry-runs", post_remediation_dry_run, "permission",
       {P.EXECUTION_PLAN_DRY_RUN}, governed="candidateId"),
    # A synthetic drill against an in-memory provider fixture. It records
    # nothing and changes no governed state, so it is not a governed route (D64, D72).
    _r("GET", "/remediation-drill-scenarios", remediation_drill_scenarios, "permission", READ),
    _r("POST", "/candidates/{candidateId}/remediation-drills", post_remediation_drill, "permission",
       {P.EXECUTION_PLAN_DRY_RUN}),

    _r("POST", "/mappings/{groupId}/inspection", post_mapping_inspection, "permission", MAPPING_ANY),
    _r("POST", "/mappings/{groupId}/searches", post_mapping_search, "permission", {P.MAPPING_PROPOSE}),
    _r("POST", "/mappings/{groupId}/selections", post_mapping_selection, "permission", {P.MAPPING_PROPOSE},
       governed="groupId"),
    _r("POST", "/mappings/{groupId}/approvals", post_mapping_approval, "permission", {P.MAPPING_APPROVE},
       governed="groupId"),
    _r("POST", "/mappings/{groupId}/rejections", post_mapping_rejection, "permission", {P.MAPPING_REJECT},
       governed="groupId"),
)
