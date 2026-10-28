"""Builds the whole Null Meridian dataset from the seed. Pure: no store, no I/O, no clock.

``build_dataset()`` is cached: the dataset is immutable and identical on every call.
"""

from collections import Counter
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any

from app.demo.null_meridian import rng
from app.demo.null_meridian.catalog import CATALOG
from app.demo.null_meridian.estate import build_estate
from app.demo.null_meridian.people import build_people, departments
from app.demo.null_meridian.profile import (
    ACTIVE_EMPLOYEES,
    AS_OF,
    COMPANY,
    DATASET_KEY,
    FOUNDED,
    MODERN_NAMING_ADOPTED,
    OKTA_ADOPTED,
    PRIMARY_DOMAIN,
    SEED,
    SNAPSHOT_DATE,
)
from app.governance.analysis import Analysis, analyze, build_index
from app.governance.index import DirectoryIndex
from app.governance.model import (
    Application,
    Assignment,
    Department,
    EmploymentEvent,
    Finding,
    Group,
    Person,
    Scenario,
)

SCENARIOS = (
    Scenario("healthy-modern", 1, "A healthy modern application",
             "Observability Platform arrived after the naming standard. Two sg-okta-* groups, an owner, a reviewed "
             "exact mapping for each, the Engineering department nested once, and named administrators.",
             "Group inventory: sg-okta-observability-user and -admin. No findings beyond the ordinary.",
             ("app:observability:modern:user", "app:observability:modern:admin"), ("observability",), None),
    Scenario("legacy-transitional", 2, "A legacy application with transitional groups",
             "Expense Management predates Okta. Its 2017 AD groups were imported in 2022, Okta_Expense_* groups were "
             "created during the migration, and both generations are still assigned. It was never standardized.",
             "Application detail for Expense Management: four assignments across two naming eras.",
             ("app:expense:legacy:user", "app:expense:legacy:admin", "app:expense:transitional:user",
              "app:expense:transitional:approver"), ("expense",), None),
    Scenario("empty-assigned", 3, "An empty group still linked to an application",
             "sg-okta-status-page-admin was created in the 2024 standardization of Status Page but never populated. "
             "It is still assigned. OGWA has it in NEEDS_REVIEW with complete evidence.",
             "Lifecycle candidate NM-C02 and the EMPTY_GROUP_ASSIGNED finding.",
             ("app:status-page:modern:admin",), ("status-page",), "NM-C02"),
    Scenario("direct-assignment", 4, "Direct assignments bypassing group governance",
             "CRM grants most access through groups, but 23 people were assigned individually over the years, and "
             "Board Portal has never had a group at all.",
             "DIRECT_ASSIGNMENTS_BYPASS_GROUPS on CRM and DIRECT_ASSIGNMENT_ONLY on Board Portal.",
             (), ("crm", "board-portal"), None),
    Scenario("overlapping-paths", 5, "Duplicate and overlapping access paths",
             "A CRM user can hold access through sg-okta-crm-user (with GG_Dept_Sales nested), the 2017 CRM-Sales "
             "group, the migration-era Okta_CRM_Users group, and an individual assignment, all at once. Removing any "
             "one of them changes nothing for that person.",
             "REDUNDANT_ACCESS_PATHS on CRM, then a person's access paths.",
             ("app:crm:modern:user", "app:crm:legacy:user", "app:crm:transitional:user"), ("crm",), "NM-C03"),
    Scenario("ambiguous-correlation", 6, "Ambiguous legacy-to-modern group correlation",
             "During the FP&A Planning rollout someone created an Okta group named Finance-RW, after the 2017 share "
             "group. AD holds two objects with that name: the share group and its archived 2017 predecessor. A name "
             "search cannot choose, so OGWA fails closed.",
             "Lifecycle candidate NM-C04 (MAPPING_AMBIGUOUS) and its identity mapping.",
             ("app:fpa-planning:transitional:user", "share:finance:legacy:0", "share:finance:archive"),
             ("fpa-planning",), "NM-C04"),
    Scenario("clean-candidate", 7, "A clean remediation candidate",
             "Legacy Timesheets was retired in March 2025. Its only group is empty, unshared, unnested, and mapped "
             "exactly by objectGUID and objectSid, and every dependency check is complete. It waits for approval.",
             "Lifecycle candidate NM-C01 in NEEDS_REVIEW: a RETIREMENT_CANDIDATE classification.",
             ("app:timesheets:legacy:user",), ("timesheets",), "NM-C01"),
    Scenario("deep-hierarchy", 8, "A hierarchy that works but has become unnecessarily deep",
             "Data Warehouse read access passes sg-okta-warehouse-readonly > OKTA-Warehouse-Readers > "
             "GG_Analytics_Users > Dept-Data > the data team groups. Every layer was a reasonable fix at the time.",
             "DEEP_NESTING and UNNECESSARY_INTERMEDIATE findings, and the membership paths of any analyst.",
             ("app:warehouse:modern:readonly", "app:warehouse:transitional:readonly", "app:warehouse:legacy:readonly"),
             ("warehouse",), None),
    Scenario("conflicting-evidence", 9, "Conflicting and incomplete evidence: no safe decision",
             "KB-Admins has had no sign-in in 90 days, so it looks like an easy clean-up. But its AD counterpart is "
             "only probable (an unverified directory SID), two AD reads disagree about its members, the nesting read "
             "timed out, the ACL scan stopped part-way, and with no owner on record nobody could attest the rest.",
             "Lifecycle candidate NM-C10: the evidence assessment shows each source's state and why OGWA can only "
             "refuse to act.",
             ("app:knowledge-base:legacy:admin",), ("knowledge-base",), "NM-C10"),
    Scenario("remediation-drill", 10, "A remediation drill: uncertain outcome, verification, and a safe retry",
             "Everyone who uses Ad Analytics is assigned to it directly; its access group OKTA-AdAnalytics-Users is "
             "empty and saw no sign-in in 90 days. Its evidence was collected again on the snapshot day and a "
             "reviewer approved removing the group's assignment. Nothing has been changed.",
             "Lifecycle candidate NM-C11 in APPROVED: as an executor, dry-run the removal, then drill it against a "
             "synthetic provider fixture (a timeout, a verification read, one safe retry, a post-action read). The "
             "drill records nothing and the candidate stays APPROVED.",
             ("app:ad-analytics:transitional:user",), ("ad-analytics",), "NM-C11"),
)


@dataclass(frozen=True)
class NullMeridianDataset:
    departments: tuple[Department, ...]
    people: tuple[Person, ...]
    events: tuple[EmploymentEvent, ...]
    applications: tuple[Application, ...]
    groups: tuple[Group, ...]
    nesting: tuple[tuple[str, str], ...]
    memberships: tuple[tuple[str, str], ...]
    assignments: tuple[Assignment, ...]
    findings: tuple[Finding, ...]
    scenarios: tuple[Scenario, ...]
    analysis: Analysis
    # Another dataset built into the same shape (app.demo.genesee_press) states its own profile and the
    # prefix of its naming standard; None and "sg" are Null Meridian's.
    company_profile: dict[str, Any] | None = None
    standard_prefix: str = "sg"

    @property
    def index(self) -> DirectoryIndex:
        return self.analysis.index

    def group(self, key: str) -> Group:
        return next(g for g in self.groups if g.key == key)

    def application(self, slug: str) -> Application:
        return next(a for a in self.applications if a.slug == slug)

    def profile(self) -> dict[str, Any]:
        if self.company_profile is not None:
            return dict(self.company_profile)
        return {
            "dataset": DATASET_KEY, "seed": SEED, "company": COMPANY, "primaryDomain": PRIMARY_DOMAIN,
            "founded": FOUNDED.isoformat(), "oktaAdopted": OKTA_ADOPTED.isoformat(),
            "modernNamingAdopted": MODERN_NAMING_ADOPTED.isoformat(), "snapshotDate": SNAPSHOT_DATE.isoformat(),
            "asOf": AS_OF.strftime("%Y-%m-%dT%H:%M:%SZ"), "activeEmployees": ACTIVE_EMPLOYEES,
            "techDebt": "moderate", "synthetic": True,
        }

    def counts(self) -> dict[str, Any]:
        groups = self.groups
        active = [p for p in self.people if p.status == "ACTIVE"]
        severity = Counter(self.analysis.group_severity.values())
        return {
            "activeEmployees": len(active),
            "formerEmployees": len(self.people) - len(active),
            "employmentEvents": len(self.events),
            "departments": len(self.departments),
            "applications": len(self.applications),
            "activeApplications": sum(1 for a in self.applications if a.status == "ACTIVE"),
            "groups": len(groups),
            "groupsBySource": dict(sorted(Counter(g.source for g in groups).items())),
            "oktaVisibleGroups": sum(1 for g in groups if g.okta_visible),
            "adGroups": sum(1 for g in groups if g.source == "AD"),
            "groupsByEra": dict(sorted(Counter(g.era for g in groups).items())),
            "modernNamedGroups": sum(1 for g in groups if g.name.startswith(
                (f"{self.standard_prefix}-okta-", f"{self.standard_prefix}-share-"))),
            "groupsByStatus": dict(sorted(Counter(g.status for g in groups).items())),
            "nestingEdges": len(self.nesting),
            "directMemberships": len(self.memberships),
            "assignments": len(self.assignments),
            "groupAssignments": sum(1 for a in self.assignments if a.group_key),
            "directUserAssignments": sum(1 for a in self.assignments if a.person_id),
            "correlationCases": dict(sorted(Counter(g.correlation_case for g in groups if g.correlation_case).items())),
            "findingsBySeverity": dict(sorted(Counter(f.severity for f in self.findings).items())),
            "findingsByCode": dict(sorted(Counter(f.code for f in self.findings).items())),
            "groupHealth": {k: severity.get(k, 0) for k in ("CLEAN", "QUESTIONABLE", "ACTIONABLE")},
        }


def _usage(applications: tuple[Application, ...], index: DirectoryIndex, keyed=rng) -> tuple[Application, ...]:
    specs = {s.slug: s for s in CATALOG}
    out = []
    for app in applications:
        spec = specs[app.slug]
        entitled = len(index.users_of(app.slug))
        if app.status != "ACTIVE" or spec.events_per_user == 0:
            out.append(replace(app, usage_events_90d=0, usage_users_90d=0))
            continue
        jitter = 0.9 + 0.2 * keyed.unit("usage", app.slug)
        users = min(entitled, round(entitled * spec.activity * jitter))
        events = max(users, round(users * spec.events_per_user * (0.85 + 0.3 * keyed.unit("events", app.slug))))
        out.append(replace(app, usage_users_90d=users, usage_events_90d=events))
    return tuple(out)


@lru_cache(maxsize=1)
def build_dataset() -> NullMeridianDataset:
    depts = departments()
    people, events = build_people(depts)
    estate = build_estate(depts, people)
    index = build_index(people, estate.groups, estate.nesting, estate.memberships, estate.assignments)
    applications = _usage(estate.applications, index)
    analysis = analyze(people=people, groups=estate.groups, applications=applications, nesting=estate.nesting,
                       memberships=estate.memberships, assignments=estate.assignments,
                       standard_since=MODERN_NAMING_ADOPTED,
                       finding_id=lambda code, subject: rng.record_id("fnd", code, subject))
    return NullMeridianDataset(depts, people, events, applications, estate.groups, estate.nesting, estate.memberships,
                               estate.assignments, analysis.findings, SCENARIOS, analysis)
