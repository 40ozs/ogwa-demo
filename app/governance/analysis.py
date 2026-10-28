"""Governance findings over a directory snapshot.

Each rule has one fixed code, one severity, and a plain-language recommendation:

- ``ACTIONABLE``: a concrete, low-ambiguity remediation exists (an empty group still
  assigned, a deprecated group still granting access, a disabled account left in a group).
- ``QUESTIONABLE``: worth a review, not obviously wrong (no owner, duplicate routes, deep or
  unnecessary nesting, a recent group outside the naming standard).
- ``INFO``: context only (pre-standard naming on an old group, an application not yet
  standardized). An object with only INFO findings counts as clean.

Findings are evidence for a person to review. None of them authorizes a change, and nothing
here writes anywhere.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from app.governance.index import DirectoryIndex
from app.governance.model import Application, Assignment, Finding, Group, Person
from app.governance.naming import check_name

ACTIONABLE, QUESTIONABLE, INFO = "ACTIONABLE", "QUESTIONABLE", "INFO"
SEVERITY_RANK = {ACTIONABLE: 0, QUESTIONABLE: 1, INFO: 2}
PRIVILEGED_TIERS = frozenset({"admin", "power", "approver", "billing"})
BROAD_KINDS = frozenset({"DEPARTMENT", "ALL_STAFF"})
DEEP_NESTING = 4

# code -> (severity, recommendation)
RULES: dict[str, tuple[str, str]] = {
    "EMPTY_GROUP_ASSIGNED": (ACTIONABLE, "Nobody gets access through this assignment. Confirm nothing references "
                                         "the group, then propose the Okta unassignment as a lifecycle candidate."),
    "ASSIGNED_TO_INACTIVE_APP": (ACTIONABLE, "The application is inactive. Propose the assignment as a lifecycle "
                                             "candidate; keep the group until its other dependencies are checked."),
    "DEPRECATED_GROUP_STILL_ASSIGNED": (ACTIONABLE, "The replacement group is assigned too. Move anyone who relies on "
                                                    "this route to the replacement, then remove the duplicate "
                                                    "assignment through a reviewed lifecycle candidate."),
    "TERMINATED_MEMBERS_RETAINED": (ACTIONABLE, "Disabled accounts of former employees are still direct members. "
                                                "Remove them in the AD offboarding clean-up."),
    "ADMIN_TIER_UNEXPECTED_MEMBER": (ACTIONABLE, "An administrator tier includes people outside the departments "
                                                 "that administer the application. Confirm with the application owner."),
    "PUSH_TARGET_MISSING": (ACTIONABLE, "The AD group this Okta group is pushed to no longer exists. Remove the stale "
                                        "push link and correlation entry, or recreate the target deliberately."),
    "BROAD_PRIVILEGED_NESTING": (ACTIONABLE, "A whole department (or everyone) inherits a privileged tier through "
                                             "nesting. Replace the nested department group with named people."),
    "STALE_DEPRECATED_GROUP": (QUESTIONABLE, "Superseded and no longer assigned. Check remaining references, then "
                                             "retire it."),
    "DUPLICATE_ENTITLEMENT": (QUESTIONABLE, "More than one group grants the same application tier. Keep one route."),
    "NONSTANDARD_NAME_RECENT": (QUESTIONABLE, "Created after the 2023-10-01 naming standard but does not follow it. "
                                              "Rename it or record why it is an exception."),
    "DEEP_NESTING": (QUESTIONABLE, "Access passes through four or more levels of nested groups. Flatten the chain so "
                                   "reviewers can see who has access."),
    "UNNECESSARY_INTERMEDIATE": (QUESTIONABLE, "A group with no members of its own that only passes one nested group "
                                               "on to one parent. Nest the child directly."),
    "OWNER_MISSING": (QUESTIONABLE, "The group grants application access but has no recorded owner. Assign one."),
    "OWNER_DEPARTED": (QUESTIONABLE, "The recorded owner has left the company. Assign a new owner."),
    "UNUSED_GROUP": (QUESTIONABLE, "Not assigned, not nested anywhere, and (nearly) empty. Confirm it is unused and "
                                   "retire it."),
    "MAPPING_REVIEW_NEEDED": (QUESTIONABLE, "The group is assigned to an application but its AD counterpart is not "
                                            "established exactly. Review the identity mapping."),
    "DUPLICATE_NAME": (QUESTIONABLE, "Another group has the same name. Name searches cannot tell them apart."),
    "LEGACY_NAMING": (INFO, "Created before the naming standard; no action needed while it is in use."),
    "LEGACY_NAMED_ASSIGNMENT": (INFO, "The application has not been standardized yet; its access still comes from "
                                      "pre-standard groups."),
    # Application-level rules.
    "DIRECT_ASSIGNMENTS_BYPASS_GROUPS": (ACTIONABLE, "People are assigned individually alongside group-based access. "
                                                     "Move them into the standard groups."),
    "DIRECT_ASSIGNMENT_ONLY": (QUESTIONABLE, "Every assignment is to an individual. Create sg-okta-* groups so access "
                                             "can be reviewed by group."),
    "REDUNDANT_ACCESS_PATHS": (QUESTIONABLE, "Some people reach the application through several assignments. Removing "
                                             "one route will not remove their access; review before cleaning up."),
    "INACTIVE_APP_STILL_ASSIGNED": (ACTIONABLE, "The application is inactive but still has assignments."),
    "LOW_USAGE": (QUESTIONABLE, "Almost no sign-ins in 90 days. Confirm the application is still needed."),
    "NOT_STANDARDIZED": (INFO, "No sg-okta-* groups exist for this application yet."),
}


@dataclass(frozen=True)
class Analysis:
    findings: tuple[Finding, ...]
    index: DirectoryIndex
    group_severity: dict[str, str]  # group key -> ACTIONABLE / QUESTIONABLE / CLEAN
    application_severity: dict[str, str]


def build_index(people: Iterable[Person], groups: Iterable[Group], nesting, memberships,
                assignments: Iterable[Assignment]) -> DirectoryIndex:
    people = list(people)
    return DirectoryIndex(
        group_kinds={g.key: g.kind for g in groups}, nesting=nesting, memberships=memberships,
        active_people=[p.id for p in people if p.status == "ACTIVE"],
        okta_people=[p.id for p in people if p.status == "ACTIVE" and p.okta_status == "ACTIVE"],
        assignments=[(a.application, a.group_key, a.person_id, a.tier) for a in assignments if a.present])


def analyze(*, people: tuple[Person, ...], groups: tuple[Group, ...], applications: tuple[Application, ...],
            nesting, memberships, assignments: tuple[Assignment, ...], standard_since: date,
            finding_id, standard_prefix: str = "sg") -> Analysis:
    """``finding_id(code, subject)`` mints a stable id for each finding. ``standard_prefix`` is the naming
    standard's prefix (``app.governance.naming``): ``sg`` (Null Meridian) or ``sec`` (Genesee Press)."""
    modern = f"{standard_prefix}-okta-"
    index = build_index(people, groups, nesting, memberships, assignments)
    by_key = {g.key: g for g in groups}
    by_person = {p.id: p for p in people}
    apps = {a.slug: a for a in applications}
    app_slugs = frozenset(apps)
    dept_slugs = frozenset(g.department for g in groups if g.department)
    present = [a for a in assignments if a.present]
    assigned_to: dict[str, list[str]] = {}
    for a in present:
        if a.group_key:
            assigned_to.setdefault(a.group_key, []).append(a.application)
    grants = set(assigned_to)
    for key in list(assigned_to):
        grants |= set(index.descendants(key))
    names: dict[str, list[str]] = {}
    for g in groups:
        names.setdefault(g.name.casefold(), []).append(g.key)
    modern_apps = {g.application for g in groups if g.application and g.name.startswith(modern)}

    findings: list[Finding] = []

    def add(code: str, kind: str, subject_id: str, subject_name: str, summary: str, **evidence) -> None:
        severity, recommendation = RULES[code]
        if standard_prefix != "sg":
            recommendation = recommendation.replace("sg-okta-", modern)
        findings.append(Finding(finding_id(code, subject_id), code, severity, kind, subject_id, subject_name, summary,
                                recommendation, {k: v for k, v in sorted(evidence.items())}))

    for g in sorted(groups, key=lambda x: x.key):
        if g.kind == "BUILT_IN":
            continue
        gid, name = g.id, g.name
        apps_here = sorted(set(assigned_to.get(g.key, ())))
        members = index.effective(g.key)
        for slug in apps_here:
            app = apps[slug]
            if app.status == "ACTIVE" and not members:
                add("EMPTY_GROUP_ASSIGNED", "GROUP", gid, name, f"Assigned to {app.label} with no effective members",
                    application=slug)
            if app.status != "ACTIVE":
                add("ASSIGNED_TO_INACTIVE_APP", "GROUP", gid, name, f"Still assigned to {app.label}, which is "
                    f"inactive since {app.retired.isoformat() if app.retired else 'an unknown date'}", application=slug)
            if g.status == "DEPRECATED":
                add("DEPRECATED_GROUP_STILL_ASSIGNED", "GROUP", gid, name,
                    f"Deprecated but still assigned to {app.label}", application=slug,
                    replacement=by_key[g.replaced_by].name if g.replaced_by in by_key else None)
        former = sorted(p for p in index.direct_members(g.key) if by_person[p].status != "ACTIVE")
        if former:
            add("TERMINATED_MEMBERS_RETAINED", "GROUP", gid, name,
                f"{len(former)} former employee(s) still direct members", people=former)
        if g.tier == "admin" and g.application in apps:
            allowed = set(apps[g.application].admin_departments) | {"it"}
            stray = sorted(p for p in members if by_person[p].department not in allowed)
            if stray:
                add("ADMIN_TIER_UNEXPECTED_MEMBER", "GROUP", gid, name,
                    f"{len(stray)} administrator(s) outside {', '.join(sorted(allowed))}", people=stray)
        if g.status == "DELETED_IN_AD":
            add("PUSH_TARGET_MISSING", "GROUP", gid, name, "Its pushed AD group was deleted; the link remains")
        if g.tier in PRIVILEGED_TIERS:
            broad = [by_key[d].name for d in index.descendants(g.key) if by_key[d].kind in BROAD_KINDS]
            if broad:
                add("BROAD_PRIVILEGED_NESTING", "GROUP", gid, name,
                    f"{g.tier} tier inherits {', '.join(sorted(broad))} ({len(members)} people)", nested=sorted(broad))
        if g.status == "DEPRECATED" and not apps_here and not index.parents(g.key):
            add("STALE_DEPRECATED_GROUP", "GROUP", gid, name, "Superseded, unassigned, still present",
                replacement=by_key[g.replaced_by].name if g.replaced_by in by_key else None,
                effective_members=len(members))
        if g.application and g.tier and g.key in assigned_to:
            rivals = sorted(o.name for o in groups if o.key != g.key and o.application == g.application
                            and o.tier == g.tier and o.key in assigned_to)
            if rivals and not g.name.startswith(modern):
                add("DUPLICATE_ENTITLEMENT", "GROUP", gid, name,
                    f"{g.application} {g.tier} is also granted by {', '.join(rivals)}", others=rivals)
        check = check_name(name, applications=app_slugs, departments=dept_slugs, prefix=standard_prefix)
        created = g.created_at.date()
        if created >= standard_since and not check.conforms:
            add("NONSTANDARD_NAME_RECENT", "GROUP", gid, name, f"Created {created.isoformat()}: {check.problem}",
                style=check.style)
        if created < standard_since and not check.conforms:
            add("LEGACY_NAMING", "GROUP", gid, name, f"{check.style} (created {created.isoformat()})",
                era=g.era, style=check.style)
            if g.key in assigned_to and g.application not in modern_apps:
                add("LEGACY_NAMED_ASSIGNMENT", "GROUP", gid, name, "Grants access under a pre-standard name",
                    application=g.application)
        depth = index.depth(g.key)
        if depth >= DEEP_NESTING and g.key in grants and not any(index.depth(p) > depth for p in index.parents(g.key)):
            chain = [g.name]
            node = g.key
            while index.children(node):
                node = max(index.children(node), key=lambda c: (index.depth(c), c))
                chain.append(by_key[node].name)
            add("DEEP_NESTING", "GROUP", gid, name, f"{depth} levels of nested groups: {' > '.join(chain)}",
                chain=chain, depth=depth)
        if (g.source == "AD" and not index.direct_members(g.key) and len(index.children(g.key)) == 1
                and len(index.parents(g.key)) == 1 and g.key not in assigned_to):
            child = by_key[index.children(g.key)[0]].name
            parent = by_key[index.parents(g.key)[0]].name
            add("UNNECESSARY_INTERMEDIATE", "GROUP", gid, name, f"Only passes {child} on to {parent}",
                child=child, parent=parent)
        if g.key in assigned_to and g.owner_id is None:
            add("OWNER_MISSING", "GROUP", gid, name, "Grants application access; no owner recorded")
        if g.owner_id and by_person[g.owner_id].status != "ACTIVE":
            owner = by_person[g.owner_id]
            add("OWNER_DEPARTED", "GROUP", gid, name,
                f"Owner {owner.display_name} left on {owner.termination_date.isoformat()}", owner=owner.id)
        if (g.okta_visible and not apps_here and not index.parents(g.key) and len(members) <= 2
                and g.status == "ACTIVE" and g.kind not in ("DEPARTMENT", "ALL_STAFF")):
            add("UNUSED_GROUP", "GROUP", gid, name, f"Unassigned, not nested, {len(members)} effective member(s)")
        if g.key in assigned_to and g.correlation_case in ("NAME_ONLY", "MULTIPLE_MATCHES", "UNVERIFIED_STABLE_ID"):
            add("MAPPING_REVIEW_NEEDED", "GROUP", gid, name, f"Correlation is {g.correlation_case}",
                correlation=g.correlation_case)
        # A push target shares its Okta group's name by design; that pair is one group in two systems.
        same = [k for k in names[g.name.casefold()] if by_key[k].replaced_by not in names[g.name.casefold()]
                or by_key[k].source != "AD" or by_key[by_key[k].replaced_by].source != "OKTA"]
        if len(same) > 1 and g.key in same:
            add("DUPLICATE_NAME", "GROUP", gid, name,
                f"{len(names[g.name.casefold()])} groups are named {g.name}",
                groups=sorted(by_key[k].id for k in names[g.name.casefold()]))

    for app in sorted(applications, key=lambda a: a.slug):
        groups_here = index.assigned_groups.get(app.slug, [])
        direct = index.direct_users.get(app.slug, set())
        if direct and groups_here:
            add("DIRECT_ASSIGNMENTS_BYPASS_GROUPS", "APPLICATION", app.id, app.label,
                f"{len(direct)} individual assignment(s) next to {len(groups_here)} group assignment(s)",
                people=sorted(direct))
        elif direct:
            add("DIRECT_ASSIGNMENT_ONLY", "APPLICATION", app.id, app.label,
                f"{len(direct)} individual assignment(s) and no group", people=sorted(direct))
        counts = index.route_counts(app.slug)
        multi = sorted(p for p, n in counts.items() if n >= 2)
        if multi:
            most = max(counts.values())
            add("REDUNDANT_ACCESS_PATHS", "APPLICATION", app.id, app.label,
                f"{len(multi)} people have more than one route (up to {most})",
                people_with_multiple_routes=len(multi), max_routes=most,
                examples=sorted(multi, key=lambda p: (-counts[p], p))[:5])
        if app.status != "ACTIVE" and (groups_here or direct):
            add("INACTIVE_APP_STILL_ASSIGNED", "APPLICATION", app.id, app.label,
                f"{len(groups_here)} group and {len(direct)} individual assignment(s) remain")
        if app.status == "ACTIVE" and app.usage_events_90d <= 5:
            add("LOW_USAGE", "APPLICATION", app.id, app.label, f"{app.usage_events_90d} sign-ins in 90 days")
        if app.status == "ACTIVE" and app.slug not in modern_apps:
            add("NOT_STANDARDIZED", "APPLICATION", app.id, app.label, f"No {modern}* groups yet")

    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.code, f.subject_name, f.subject_id))
    group_sev = {g.key: "CLEAN" for g in groups}
    by_gid = {g.id: g.key for g in groups}
    app_sev = {a.slug: "CLEAN" for a in applications}
    by_aid = {a.id: a.slug for a in applications}
    for f in findings:
        table, key = (group_sev, by_gid.get(f.subject_id)) if f.subject_kind == "GROUP" else (app_sev, by_aid.get(f.subject_id))
        if key is None or f.severity == INFO:
            continue
        if table[key] == "CLEAN" or SEVERITY_RANK[f.severity] < SEVERITY_RANK[table[key]]:
            table[key] = f.severity
    return Analysis(tuple(findings), index, group_sev, app_sev)
