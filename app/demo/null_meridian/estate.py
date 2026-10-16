"""Null Meridian's groups, nesting, memberships, and application assignments.

The estate is built era by era, the way it accumulated:

1. 2016-2019, AD only: department, role, and share groups (``GG_Dept_Sales``,
   ``Finance-RW``), and the first application groups (``GG_App_Wiki``, ``Git_Dev``).
2. 2019-2021: application-specific groups in several styles (``APP-Chat-Users``,
   ``NM-CRM-USERS``), file-server migration groups (``FS-Finance-R``), ``Dept-Data``.
3. 2021-2023: Okta arrives. AD groups are imported and assigned as they are, or wrapped and
   replaced by transitional groups (``Okta_CRM_Users``, ``OKTA-Git-Admins``, ``okta-crm-users``).
4. 2023-2026: the standard. Applications standardized so far get ``sg-okta-<app>-<tier>``
   groups and departments get ``sg-share-<dept>-read-only|write``. What happened to the older
   groups varies by application: retired, nested, retained, or still assigned.

Nothing here is random: every choice is keyed on the dataset seed (``rng``).
"""

from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone

from app.demo.null_meridian import rng
from app.demo.null_meridian.catalog import CATALOG, AppSpec
from app.demo.null_meridian.profile import (
    AD_DNS_DOMAIN,
    AD_DOMAIN_SID,
    CORRELATION_CONFIG_REVIEWED,
    MODERN_NAMING_ADOPTED,
    OKTA_ADOPTED,
    OKTA_APP_PREFIX,
    OKTA_EVERYONE_ID,
    OKTA_GROUP_PREFIX,
    SNAPSHOT_DATE,
    era_for,
)
from app.governance.model import Application, Assignment, Department, Group, Person

DC = ",".join(f"DC={p}" for p in AD_DNS_DOMAIN.split("."))
# OUs the Okta AD agent imports. Teams, file shares, the archive, and push targets are not imported.
OU_LEGACY = "Security Groups"
OU_DEPARTMENTS = "Departments,OU=Security Groups"
OU_ARCHIVE = "Archive,OU=Security Groups"
OU_APPLICATIONS = "Application Groups"
OU_TEAMS = "Teams,OU=Groups"
OU_FILE_SHARES_LEGACY = "File Shares,OU=Groups,OU=Legacy"
OU_OKTA_TRANSITIONAL = "Okta,OU=Groups"
OU_MODERN_APPS = "Okta Assignment,OU=Groups,OU=Managed"
OU_MODERN_SHARES = "File Shares,OU=Groups,OU=Managed"
OU_PUSH = "Okta Push,OU=Groups,OU=Managed"
OU_PROJECTS = "Projects,OU=Groups"
IMPORTED_OUS = frozenset({OU_LEGACY, OU_DEPARTMENTS, OU_APPLICATIONS, OU_OKTA_TRANSITIONAL, OU_MODERN_APPS})

TIER_PLURAL = {"user": "Users", "admin": "Admins", "developer": "Developers", "readonly": "ReadOnly",
               "power": "PowerUsers", "approver": "Approvers", "standard": "Agents", "billing": "BillingOps"}
TIER_SHORT = {"user": "Users", "admin": "Admins", "developer": "Dev", "readonly": "RO", "power": "Power",
              "approver": "Approvers", "standard": "Std", "billing": "Billing"}
PRIVILEGED_TIERS = frozenset({"admin", "power", "approver", "billing"})

DEPT_TOKEN = {"engineering": "Engineering", "sales": "Sales", "customer-success": "CustomerSuccess",
              "operations": "Operations", "marketing": "Marketing", "product": "Product", "data": "Data",
              "finance": "Finance", "it": "IT", "people": "People", "design": "Design", "security": "Security",
              "legal": "Legal", "executive": "Executive"}
WORD_CASE = {"sdr": "SDR", "csm": "CSM", "pmo": "PMO", "fpa": "FPA", "iam": "IAM", "grc": "GRC", "qa": "QA", "sre": "SRE",
             "appsec": "AppSec", "secops": "SecOps", "revops": "RevOps", "bizops": "BizOps", "custops": "CustOps",
             "t1": "T1", "t2": "T2", "ux": "UX", "ops": "Ops"}
TEAM_PREFIX = {"sales": "Sales", "customer-success": "CS", "operations": "Ops", "marketing": "Mkt",
               "product": "Prod", "finance": "Fin", "it": "IT", "people": "HR", "design": "Design",
               "security": "Sec", "legal": "Legal"}

# Older group names that the estate spells out rather than derives (app, tier, phase).
NAME_OVERRIDES = {
    ("crm", "user", "legacy"): ("CRM-Sales", "<App>-<Dept>", "AD"),
    ("crm", "admin", "legacy"): ("CRM_Admins", "<App>_<Tier>", "AD"),
    ("crm", "user", "transitional"): ("Okta_CRM_Users", "Okta_<App>_<Tier>", "OKTA"),
    ("git", "developer", "legacy"): ("Git_Dev", "<App>_<Tier>", "AD"),
    ("git", "admin", "transitional"): ("OKTA-Git-Admins", "OKTA-<App>-<Tier>", "AD"),
    ("git", "developer", "transitional"): ("OKTA-Git-Developers", "OKTA-<App>-<Tier>", "AD"),
    ("chat", "user", "transitional"): ("APP-Chat-Users", "APP-<App>-<Tier>", "AD"),
    ("warehouse", "readonly", "legacy"): ("GG_Analytics_Users", "GG_<Area>_<Tier>", "AD"),
    ("warehouse", "readonly", "transitional"): ("OKTA-Warehouse-Readers", "OKTA-<App>-<Tier>", "AD"),
    ("fpa-planning", "user", "transitional"): ("Finance-RW", "reused share-group name", "OKTA"),
    ("fax-gateway", "user", "transitional"): ("Okta_Fax_Users", "Okta_<App>_<Tier>", "OKTA"),
    ("expense", "user", "transitional"): ("Okta_Expense_Users", "Okta_<App>_<Tier>", "OKTA"),
    ("expense", "approver", "transitional"): ("Okta_Expense_Approvers", "Okta_<App>_<Tier>", "OKTA"),
}

# Legacy file-share groups: department -> (name, access, created). The first write group of
# a migrated department is nested in its sg-share-*-write group; the others are deprecated.
SHARE_LEGACY = {
    "product": (("Product-RW", "write", date(2016, 11, 14)), ("Product_Read", "read", date(2016, 11, 14))),
    "engineering": (("Share_Engineering_Modify", "write", date(2017, 1, 23)),
                    ("Share_Engineering_Read", "read", date(2017, 1, 23)),
                    ("FS-Engineering-RW", "write", date(2019, 8, 26))),
    "operations": (("Ops-RW", "write", date(2017, 2, 6)), ("Ops_Read", "read", date(2017, 2, 6)),
                   ("FS-Ops-R", "read", date(2019, 9, 9))),
    "executive": (("GG_Exec_RW", "write", date(2017, 3, 6)),),
    "finance": (("Finance-RW", "write", date(2017, 4, 10)), ("Finance_Read", "read", date(2017, 4, 10)),
                ("GG_Finance_RW", "write", date(2018, 6, 18)), ("FS-Finance-R", "read", date(2019, 8, 26))),
    "sales": (("Sales-RW", "write", date(2017, 5, 15)), ("Sales_Read", "read", date(2017, 5, 15))),
    "marketing": (("Share_Marketing_Modify", "write", date(2017, 7, 17)),
                  ("Share_Marketing_Read", "read", date(2017, 7, 17))),
    "people": (("GG_HR_RW", "write", date(2017, 10, 2)), ("GG_HR_R", "read", date(2017, 10, 2)),
               ("FS-HR-RW", "write", date(2019, 8, 26))),
    "customer-success": (("CS-RW", "write", date(2018, 2, 5)), ("CS_Read", "read", date(2018, 2, 5))),
    "design": (("Share_Design_Modify", "write", date(2018, 4, 2)),),
    "it": (("GG_IT_RW", "write", date(2018, 7, 2)), ("GG_IT_R", "read", date(2018, 7, 2))),
    "legal": (("Legal-RW", "write", date(2019, 3, 4)), ("Legal_Read", "read", date(2019, 3, 4))),
    "data": (("FS-Data-RW", "write", date(2020, 2, 3)), ("FS-Data-R", "read", date(2020, 2, 3))),
    "security": (("FS-Security-RW", "write", date(2020, 7, 6)),),
}
SHARE_MODERN = {
    "engineering": date(2023, 11, 13), "security": date(2023, 12, 4), "finance": date(2024, 2, 5),
    "people": date(2024, 3, 18), "legal": date(2024, 4, 22), "sales": date(2024, 6, 3),
    "marketing": date(2024, 9, 16), "operations": date(2025, 1, 20), "product": date(2025, 3, 10),
    "design": date(2025, 5, 19), "customer-success": date(2025, 8, 11), "it": date(2025, 9, 8),
}

SITE_GROUPS = (
    ("site:hq", "GG_Site_HQ", "Meridian HQ", date(2017, 1, 9)),
    ("site:east", "GG_Site_East", "East Hub", date(2018, 9, 17)),
    ("site:north", "Site-North", "North Hub", date(2020, 2, 24)),
    ("site:remote-americas", "Site-Remote-Americas", "Remote (Americas)", date(2020, 4, 6)),
    ("site:remote-emea", "Site-Remote-EMEA", "Remote (EMEA)", date(2020, 4, 6)),
)
# Groups the lifecycle scenarios walk through approval and dry run: they must correlate exactly.
MUST_BE_EXACT = frozenset({"app:timesheets:legacy:user", "app:fax-gateway:legacy:user", "app:legacy-cloud:legacy:admin",
                           "app:status-page:modern:admin", "app:crm:legacy:user", "app:wiki:legacy:user",
                           "app:print-release:legacy:user"})
ARCHIVED_SHARES = (
    ("finance", "Finance-RW", "Finance-RW-2018", date(2017, 3, 20), date(2018, 6, 18)),
    ("sales", "Sales-RW", "Sales-RW-2017", date(2017, 4, 24), date(2017, 11, 6)),
    ("legal", "Legal-RW", "Legal-RW-old", date(2019, 2, 25), date(2020, 3, 2)),
)
# key, name, application, tier, department, created, description
OKTA_NAME_COPIES = (
    ("copy:sales-rw", "Sales-RW", "file-sync", "user", "sales", date(2022, 5, 16),
     "Sales team folder in Cloud File Sync; named after the AD share group it was meant to mirror"),
    ("copy:legal-rw", "Legal-RW", "contracts", "user", "legal", date(2022, 10, 3),
     "Contract Lifecycle access for Legal; named after the AD share group"),
)

# Groups that are neither application nor share groups: key, name, kind, created, ou or OKTA, members, note.
MISC_GROUPS = (
    ("misc:vpn-contractors", "VPN-Contractors", "ROLE", date(2018, 3, 19), OU_LEGACY, 0, "Contractor VPN access (no contractors since 2021)"),
    ("misc:printers", "GG_Printers", "ROLE", date(2017, 8, 7), OU_LEGACY, 4, "Printer administration delegation"),
    ("misc:wifi-guest", "Wifi-Guest-Admins", "ROLE", date(2018, 5, 21), OU_LEGACY, 2, "Guest wireless portal administrators"),
    ("misc:audit-2020", "Temp-Audit-2020", "PROJECT", date(2020, 2, 10), OU_APPLICATIONS, 2, "Read access for the 2020 external audit"),
    ("misc:migration-pilot", "Okta_Migration_Pilot", "PROJECT", date(2021, 10, 4), "OKTA", 11, "Okta rollout pilot users (wave 0)"),
    ("misc:atlas", "Project-Atlas-Team", "PROJECT", date(2024, 3, 11), OU_PROJECTS, 12, "Project Atlas working group"),
    ("misc:ml-platform", "eng-ml-platform", "TEAM", date(2024, 6, 17), OU_TEAMS, 0, "New ML platform team (created by habit, never populated)"),
    ("misc:offsite", "Offsite-2025-Planning", "PROJECT", date(2025, 6, 2), "OKTA", 9, "Planning group for the 2025 company offsite"),
)


def _at(day: date, *key) -> datetime:
    minutes = 14 * 60 + rng.below(8 * 60, "time", day.isoformat(), *key)
    return datetime.combine(day, time(minutes // 60, minutes % 60), tzinfo=timezone.utc)


def _plus(day: date, low: int, high: int, *key) -> date:
    return day + timedelta(days=low + rng.below(high - low + 1, *key))


@dataclass
class _G:
    key: str
    name: str
    source: str  # AD, OKTA, BUILT_IN
    kind: str
    created: date
    ou: str | None
    style: str
    description: str
    application: str | None = None
    tier: str | None = None
    department: str | None = None
    owner_id: str | None = None
    status: str = "ACTIVE"
    replaced_by: str | None = None
    okta_name: str | None = None
    sam: str | None = None
    ad_exists: bool = True
    okta_reports_sid: bool = True
    configured: bool | None = None  # None: decided by the general rule
    admin_count: bool = False
    protected: bool = False
    push_target: str | None = None  # for an Okta-mastered group: the AD group it is pushed to
    pushed_from: str | None = None  # for an AD push target: the Okta group that manages it
    last_change: date | None = None
    members: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Estate:
    applications: tuple[Application, ...]
    groups: tuple[Group, ...]
    nesting: tuple[tuple[str, str], ...]  # (parent key, child key)
    memberships: tuple[tuple[str, str], ...]  # (group key, person id), direct members only
    assignments: tuple[Assignment, ...]


class _Builder:
    def __init__(self, departments: tuple[Department, ...], people: tuple[Person, ...]) -> None:
        self.departments = {d.slug: d for d in departments}
        self.people = people
        self.active = [p for p in people if p.status == "ACTIVE"]
        self.former = [p for p in people if p.status == "TERMINATED"]
        self.by_id = {p.id: p for p in people}
        self.groups: dict[str, _G] = {}
        self.assignments: list[Assignment] = []
        self.apps: list[Application] = []

    # --- basics -------------------------------------------------------------------------

    def add(self, g: _G) -> _G:
        if g.key in self.groups:
            raise AssertionError(f"duplicate group key {g.key}")
        self.groups[g.key] = g
        return g

    def nest(self, parent: str, child: str) -> None:
        p = self.groups[parent]
        if p.source != "AD" or self.groups[child].source != "AD":
            raise AssertionError(f"only AD groups nest ({parent} <- {child})")
        if child not in p.children:
            p.children.append(child)

    def people_in(self, spec: str) -> list[Person]:
        """``dept`` or ``dept/team``: active people, in employee-number order."""
        dept, _, team = spec.partition("/")
        return [p for p in self.active if p.department == dept and (not team or p.team == team)]

    def pick_people(self, n: int, specs: list[str], *key) -> list[str]:
        pool = sorted({p.id for s in specs for p in self.people_in(s)})
        chosen = rng.ordered(pool, lambda x: x, "pick", *key)[:n]
        return sorted(chosen)

    def leader_of(self, dept: str) -> Person:
        ranked = {"executive": 0, "vp": 1, "director": 2, "manager": 3, "ic": 4}
        return min(self.people_in(dept), key=lambda p: (ranked[p.level], p.employee_number))

    def owner_for(self, dept: str, *key) -> str:
        pool = [p for p in self.people_in(dept) if p.level in ("manager", "director", "vp")] or self.people_in(dept)
        return rng.pick(sorted(pool, key=lambda p: p.employee_number), "owner", *key).id

    # --- organizational groups ------------------------------------------------------------

    def org_groups(self) -> None:
        self.add(_G("okta:everyone", "Everyone", "BUILT_IN", "BUILT_IN", OKTA_ADOPTED, None, "Okta built-in",
                    "Okta's built-in group of every user"))
        self.add(_G("all-staff", "All-Staff", "AD", "ALL_STAFF", date(2017, 2, 6), OU_LEGACY, "<Name>-<Scope>",
                    "Everyone. Direct members until 2019; since then the department groups are nested in it",
                    last_change=date(2020, 6, 15)))
        for slug, dept in sorted(self.departments.items(), key=lambda kv: kv[1].formed):
            formed = dept.formed
            legacy = formed < date(2019, 7, 1)
            name = f"GG_Dept_{DEPT_TOKEN[slug]}" if legacy else f"Dept-{DEPT_TOKEN[slug]}"
            g = self.add(_G(f"dept:{slug}", name, "AD", "DEPARTMENT", _plus(formed, 0, 20, "dept", slug),
                            OU_DEPARTMENTS, "GG_Dept_<Dept>" if legacy else "Dept-<Dept>",
                            f"{dept.name} department", department=slug,
                            owner_id=None if legacy else self.owner_for("people", "dept-owner", slug)))
            self.nest("all-staff", g.key)
            if slug in ("engineering", "data"):
                g.last_change = date(2022, 5, 23) if slug == "engineering" else date(2022, 2, 14)
                for team in dept.teams:
                    tg = self.team_group(slug, team.slug)
                    self.nest(g.key, tg.key)
            else:
                g.members = [p.id for p in self.people_in(slug)]
        for slug in sorted(self.departments):
            for team in self.departments[slug].teams:
                self.team_group(slug, team.slug)
        for key, name, location, created in SITE_GROUPS:
            g = self.add(_G(key, name, "AD", "ROLE", created, OU_LEGACY if created < date(2019, 7, 1) else OU_APPLICATIONS,
                            "GG_Site_<Site>" if name.startswith("GG_") else "Site-<Site>",
                            f"Everyone whose work location is {location} (badges, printers, Wi-Fi)",
                            owner_id=self.owner_for("operations", "site-owner", key)))
            g.members = [p.id for p in self.active if p.location == location]
        directors = self.add(_G("role:directors", "Role_Directors", "AD", "ROLE", date(2019, 3, 4), OU_LEGACY,
                                "Role_<Role>", "Directors and above (maintained by an HR export script)",
                                owner_id=self.owner_for("people", "role-owner", "directors")))
        directors.members = [p.id for p in self.active if p.level in ("director", "vp", "executive")]
        managers = self.add(_G("role:managers", "Role_PeopleManagers", "AD", "ROLE", date(2019, 3, 4), OU_LEGACY,
                               "Role_<Role>", "Every people manager (maintained by an HR export script)"))
        managers.members = [p.id for p in self.active if p.is_people_manager]
        eng = self.add(_G("role:eng-managers", "Engineering-Managers", "AD", "ROLE", date(2018, 5, 14), OU_LEGACY,
                          "<Dept>-<Role>", "Engineering people managers"))
        eng.members = [p.id for p in self.people_in("engineering") if p.is_people_manager]
        # 2022 Okta group rules: one per department, used by sign-on policies and Okta-only apps.
        for slug in sorted(self.departments):
            g = self.add(_G(f"okta-rule:{slug}", f"okta-dept-{slug}", "OKTA", "DEPARTMENT",
                            _plus(date(2022, 1, 10), 0, 120, "rule", slug), None,
                            "okta-dept-<dept>", f"Okta group rule: department = {self.departments[slug].name}",
                            department=slug, owner_id=self.owner_for("it", "rule-owner", slug)))
            g.members = [p.id for p in self.people_in(slug)]

    def team_group(self, dept: str, team: str) -> _G:
        key = f"team:{dept}/{team}"
        if key in self.groups:
            return self.groups[key]
        t = next(x for x in self.departments[dept].teams if x.slug == team)
        created = max(t.formed, self.departments[dept].formed)
        if dept == "engineering":
            name, style, created = f"eng-{team}", "eng-<team>", max(created, date(2019, 9, 16))
        elif dept == "data":
            token = "".join(WORD_CASE.get(w, w.capitalize()) for w in team.split("-"))
            name, style = f"Data-{token}-Team", "Data-<Team>-Team"
        else:
            token = "".join(WORD_CASE.get(w, w.capitalize()) for w in team.split("-"))
            name, style = f"{TEAM_PREFIX[dept]}-{token}", "<Dept>-<Team>"
            created = max(created, date(2019, 1, 7))
        created = min(_plus(created, 0, 30, "team", key), date(2023, 6, 30))
        g = self.add(_G(key, name, "AD", "TEAM", created, OU_TEAMS, style, f"{t.name} team", department=dept))
        g.members = [p.id for p in self.people_in(f"{dept}/{team}")]
        return g

    # --- audiences --------------------------------------------------------------------------

    def fill(self, g: _G, audience: str, *, nest: bool, key: str) -> None:
        """Give ``g`` the members ``audience`` describes, nested or copied as direct members."""
        if audience == "none" or not audience:
            return
        if audience.startswith("p:"):
            _, n, specs = audience.split(":", 2)
            g.members = sorted(set(g.members) | set(self.pick_people(int(n), specs.split(","), key)))
            return
        nest = nest and g.source == "AD"
        if audience == "all":
            if nest:
                self.nest(g.key, "all-staff")
            else:
                g.members = sorted({p.id for p in self.active})
            return
        if audience == "managers":
            if nest:
                self.nest(g.key, "role:managers")
            else:
                g.members = sorted({p.id for p in self.active if p.is_people_manager})
            return
        kind, _, specs = audience.partition(":")
        for spec in specs.split(","):
            if kind == "d":
                child = f"dept:{spec}"
                people = self.people_in(spec)
            else:
                dept, _, team = spec.partition("/")
                child = self.team_group(dept, team).key
                people = self.people_in(spec)
            if nest:
                self.nest(g.key, child)
            else:
                g.members = sorted(set(g.members) | {p.id for p in people})

    def drift(self, g: _G, audience: str, key: str) -> None:
        """A hand-maintained copy: some current members missing, a few people who moved on."""
        if not g.members or audience.startswith("p:"):
            return
        keep = [m for m in g.members if rng.unit("drift-drop", key, m) >= 0.08]
        extra_pool = sorted(p.id for p in self.active if p.id not in set(g.members))
        extra = rng.ordered(extra_pool, lambda x: x, "drift-add", key)[: max(1, len(g.members) // 40)]
        g.members = sorted(set(keep) | set(extra))

    # --- applications -------------------------------------------------------------------------

    def okta_integrated(self, spec: AppSpec) -> date:
        if spec.okta_integrated:
            return spec.okta_integrated
        if spec.adopted >= OKTA_ADOPTED:
            return _plus(spec.adopted, 0, 10, "integrated", spec.slug)
        core = {"mail", "chat", "video", "wiki", "file-sync", "password-manager", "vpn", "hris", "git", "issues"}
        if spec.slug in core:
            return _plus(date(2021, 10, 4), 0, 70, "integrated", spec.slug)
        return _plus(date(2022, 1, 10), 0, 535, "integrated", spec.slug)

    def legacy_name(self, spec: AppSpec, tier: str, era: str) -> tuple[str, str, str]:
        override = NAME_OVERRIDES.get((spec.slug, tier, "legacy"))
        if override:
            return override
        t, plural, short = spec.token, TIER_PLURAL[tier], TIER_SHORT[tier]
        if era == "legacy-ad":
            style = rng.pick(("gg", "dash", "under"), "legacy-style", spec.slug)
            if style == "gg":
                return (f"GG_App_{t}" if tier == "user" else f"GG_App_{t}_{plural}"), "GG_App_<App>[_<Tier>]", "AD"
            if style == "dash":
                return f"{t}-{plural}", "<App>-<Tier>", "AD"
            return f"{t}_{short}", "<App>_<Tier>", "AD"
        style = rng.pick(("app", "nm", "under", "app"), "b-style", spec.slug)
        if style == "app":
            return f"APP-{t}-{plural}", "APP-<App>-<Tier>", "AD"
        if style == "nm":
            return f"NM-{t.upper()}-{plural.upper()}", "NM-<APP>-<TIER>", "AD"
        return f"{t}_{short}", "<App>_<Tier>", "AD"

    def transitional_name(self, spec: AppSpec, tier: str) -> tuple[str, str, str]:
        override = NAME_OVERRIDES.get((spec.slug, tier, "transitional"))
        if override:
            return override
        t, plural = spec.token, TIER_PLURAL[tier]
        style = rng.pick(("okta_under", "okta_dash", "okta_lower"), "c-style", spec.slug)
        if style == "okta_under":
            return f"Okta_{t}_{plural}", "Okta_<App>_<Tier>", "OKTA"
        if style == "okta_dash":
            return f"OKTA-{t}-{plural}", "OKTA-<App>-<Tier>", "AD"
        return f"okta-{spec.slug}-{plural.lower()}", "okta-<app>-<tier>s", "OKTA"

    def application(self, spec: AppSpec, index: int) -> None:
        integrated = self.okta_integrated(spec)
        owner = self.owner_for(spec.owner_department, "app-owner", spec.slug)
        tiers = list(spec.tiers)
        legacy: dict[str, _G] = {}
        transitional: dict[str, _G] = {}
        modern: dict[str, _G] = {}
        pushed = "push-linked" in spec.notes

        # 1. Groups from before Okta.
        if spec.adopted < OKTA_ADOPTED:
            era = era_for(spec.adopted).key
            for tier in spec.legacy_tiers:
                if tier not in spec.tiers:
                    continue
                name, style, source = self.legacy_name(spec, tier, era)
                created = _plus(spec.adopted, 3, 40, "legacy-created", spec.slug, tier)
                ou = OU_LEGACY if era == "legacy-ad" else OU_APPLICATIONS
                if pushed:
                    ou = OU_PUSH
                g = self.add(_G(f"app:{spec.slug}:legacy:{tier}", name, source, "APP_ACCESS", created, ou, style,
                                f"{spec.label} {tier} access ({era_for(created).label.lower()})", spec.slug, tier))
                g.owner_id = self.legacy_owner(g.key)
                audience = spec.tiers[tier]
                as_nest = spec.slug == "warehouse" or (audience[:2] in ("d:", "t:") and rng.unit("legacy-nest", g.key) < 0.5)
                self.fill(g, audience, nest=as_nest or audience in ("all", "managers"), key=g.key)
                if not as_nest:
                    self.drift(g, audience, g.key)
                legacy[tier] = g

        # 2. Okta-era transitional groups.
        if spec.adopted < MODERN_NAMING_ADOPTED and not pushed:
            for tier in tiers:
                if spec.everyone and spec.tiers[tier] == "all" and tier not in legacy:
                    continue
                wanted = spec.transition == "okta" or tier not in legacy
                if not wanted or (spec.modern and spec.fate == "retired" and tier not in legacy and spec.adopted < OKTA_ADOPTED
                                  and rng.unit("skip-transitional", spec.slug, tier) < 0.5):
                    continue
                name, style, source = self.transitional_name(spec, tier)
                created = _plus(max(integrated, spec.adopted), 0, 6, "transitional-created", spec.slug, tier)
                created = min(created, date(2023, 9, 25))
                g = self.add(_G(f"app:{spec.slug}:transitional:{tier}", name, source, "APP_ACCESS", created,
                                OU_OKTA_TRANSITIONAL if source == "AD" else None, style,
                                f"{spec.label} {tier} access (Okta migration)", spec.slug, tier))
                g.owner_id = self.owner_for("it", "transitional-owner", g.key) if rng.unit("t-owner", g.key) < 0.6 else None
                audience = spec.tiers[tier]
                if source == "AD" and tier in legacy:
                    self.nest(g.key, legacy[tier].key)  # the migration wrapped the old group
                    g.last_change = created
                else:
                    self.fill(g, audience, nest=True, key=g.key)
                    if source == "OKTA" and not audience.startswith("p:"):
                        g.description += "; members copied in at migration time"
                        self.drift(g, audience, g.key)
                transitional[tier] = g

        # 3. The standard.
        if spec.modern:
            for i, tier in enumerate(tiers):
                created = spec.modern + timedelta(days=i // 3)
                g = self.add(_G(f"app:{spec.slug}:modern:{tier}", f"sg-okta-{spec.slug}-{tier}",
                                "OKTA" if pushed else "AD", "APP_ACCESS", created,
                                None if pushed else OU_MODERN_APPS, "sg-okta-<application>-<tier>",
                                f"{spec.label} {tier} access", spec.slug, tier, owner_id=owner))
                if "normalized-case" in spec.notes:
                    g.okta_name = g.name.upper()
                    g.description += " (created by the 2023 pilot script in upper case; AD renamed it in 2024)"
                modern[tier] = g
            self.modern_membership(spec, legacy, transitional, modern)

        if pushed:
            self.push_links(spec, legacy, modern)

        # Special cases the portfolio scenarios rely on.
        if "broad-power" in spec.notes and "power" in modern:
            self.nest(modern["power"].key, f"dept:{spec.owner_department}")
        if "stray-admin" in spec.notes:
            admin = modern.get("admin") or transitional.get("admin") or legacy.get("admin")
            stray = self.pick_people(1, ["marketing/demand-gen", "sales/sdr", "customer-success/support-t1"], "stray",
                                     spec.slug)
            admin.members = sorted(set(admin.members) | set(stray))
        if "protected-candidate" in spec.notes:
            g = legacy["admin"]
            g.admin_count = g.protected = True
            g.description += "; adminCount still set from a former protected-group membership"
        if "push-broken" in spec.notes:
            self.broken_push(spec, transitional["user"])

        self.app_assignments(spec, integrated, legacy, transitional, modern)
        self.apps.append(self.application_record(spec, index, integrated, owner))

    def legacy_owner(self, key: str) -> str | None:
        roll = rng.unit("legacy-owner", key)
        if roll < 0.25:
            return None
        if roll < 0.95:
            return rng.pick([p.id for p in self.active if p.department in ("it", "engineering")], "lo", key)
        departed = [p.id for p in self.former if p.termination_date and p.termination_date >= date(2020, 1, 1)
                    and p.department in ("it", "engineering", "operations")]
        return rng.pick(departed, "lo-former", key)

    def modern_membership(self, spec: AppSpec, legacy: dict[str, _G], transitional: dict[str, _G],
                          modern: dict[str, _G]) -> None:
        for tier, g in modern.items():
            audience = spec.tiers[tier]
            olds = [x for x in (transitional.get(tier), legacy.get(tier)) if x is not None]
            ad_olds = [x for x in olds if x.source == "AD"]
            if spec.fate == "nested" and ad_olds and g.source == "AD":
                self.nest(g.key, ad_olds[0].key)  # the newest AD predecessor carries the members
                if audience.startswith("p:"):
                    self.fill(g, audience, nest=False, key=g.key + ":direct")
            else:
                self.fill(g, audience, nest=True, key=g.key)
            for old in olds:
                old.replaced_by = g.key
                if spec.fate == "nested" and old in ad_olds:
                    old.description += f"; superseded by {g.name} but still nested in it"
                    continue
                first = tier == next(iter(spec.tiers))
                if spec.fate == "retired" or (spec.fate in ("retained", "assigned") and not first
                                              and rng.unit("keep-old", old.key) < 0.8) or (
                        spec.fate == "retained" and first and rng.unit("keep-first", old.key) < 0.65):
                    old.status = "RETIRED"
                    continue
                old.status = "DEPRECATED"
                old.description += f"; replaced by {g.name}"
                old.last_change = _plus(spec.modern, 0, 30, "deprecated", old.key)
                if spec.fate == "retained" and rng.unit("emptied", old.key) < 0.5:
                    old.members, old.children = [], []
                    old.description += " (emptied, not deleted)"

    def push_links(self, spec: AppSpec, legacy: dict[str, _G], modern: dict[str, _G]) -> None:
        """Payroll: the sg-okta-* groups are mastered in Okta and pushed into the old AD groups."""
        for tier, g in modern.items():
            g.members = sorted({p.id for p in self.expand(spec.tiers[tier], g.key)})
            target = legacy.get(tier)
            if target is None:
                target = self.add(_G(f"app:{spec.slug}:push:{tier}", g.name, "AD", "APP_ACCESS", g.created, OU_PUSH,
                                     "sg-okta-<application>-<tier>", f"Okta push target for {g.name}", spec.slug, tier))
                target.configured = False
            else:
                target.description += f"; since {spec.modern.isoformat()} managed by Okta Group Push from {g.name}"
                target.children = []
                g.configured = True
            target.members = list(g.members)
            target.status, target.last_change = "ACTIVE", spec.modern
            target.pushed_from = g.key
            target.replaced_by = g.key
            g.push_target = target.key
            g.description += f"; pushed to AD as {target.name}"

    def broken_push(self, spec: AppSpec, okta_group: _G) -> None:
        target = self.add(_G(f"app:{spec.slug}:push:user", "OKTA-Fax-Users", "AD", "APP_ACCESS", okta_group.created,
                             OU_PUSH, "OKTA-<App>-<Tier>", "Okta push target, deleted in the 2025 AD cleanup",
                             spec.slug, "user", ad_exists=False, status="DELETED"))
        target.pushed_from = okta_group.key
        okta_group.push_target = target.key
        okta_group.configured = True
        okta_group.status = "DELETED_IN_AD"
        okta_group.description += "; its pushed AD group was deleted in 2025, the push link was never removed"

    def expand(self, audience: str, key: str) -> list[Person]:
        tmp = _G("tmp", "tmp", "OKTA", "TMP", SNAPSHOT_DATE, None, "", "")
        self.fill(tmp, audience, nest=False, key=key)
        return [self.by_id[m] for m in tmp.members]

    def app_assignments(self, spec: AppSpec, integrated: date, legacy: dict[str, _G], transitional: dict[str, _G],
                        modern: dict[str, _G]) -> None:
        held = legacy.get("user") if "hold-candidate" in spec.notes else None

        def assign(g: _G, on: date) -> None:
            # A hold candidate's assignment was removed through OGWA's lifecycle (see the world seed).
            self.assignments.append(Assignment(rng.record_id("asgn", spec.slug, g.key), spec.slug, g.key, None, g.tier,
                                               on, present=g is not held))

        if spec.everyone:
            assign(self.groups["okta:everyone"], integrated)
        for tier in spec.tiers:
            m, t, l = modern.get(tier), transitional.get(tier), legacy.get(tier)
            if m is not None:
                assign(m, m.created)
                if spec.fate == "assigned" and tier == next(iter(spec.tiers)):
                    for old in (t, l):
                        if old is not None and not (old is l and t is not None and l.key in t.children):
                            assign(old, integrated if old is l else old.created)
                continue
            if t is not None:
                assign(t, t.created)
                if l is not None and t.source == "OKTA" and tier == next(iter(spec.tiers)):
                    assign(l, integrated)  # both stayed assigned after the migration
            elif l is not None:
                assign(l, integrated)
        if spec.direct_users:
            _, n, specs = spec.direct_users.split(":", 2)
            for pid in self.pick_people(int(n), specs.split(","), "direct", spec.slug):
                on = _plus(integrated, 5, max(6, (SNAPSHOT_DATE - integrated).days - 20), "direct-on", spec.slug, pid)
                self.assignments.append(Assignment(rng.record_id("asgu", spec.slug, pid), spec.slug, None, pid,
                                                   next(iter(spec.tiers), "user"), on))

    def application_record(self, spec: AppSpec, index: int, integrated: date, owner: str) -> Application:
        return Application(
            id=rng.record_id("oapp", spec.slug), uuid=str(rng.stable_uuid("application", spec.slug)), slug=spec.slug,
            label=spec.label, category=spec.category, sign_on_mode=spec.sso, provisioning=spec.provisioning,
            status=spec.status, adopted=spec.adopted, okta_integrated=integrated, retired=spec.retired,
            tiers=tuple(spec.tiers), admin_departments=spec.admin_departments, assignment_model=spec.model,
            standardized=spec.modern, owner_id=owner, owner_department=spec.owner_department,
            okta_app_id=f"{OKTA_APP_PREFIX}{index:03d}", usage_events_90d=0, usage_users_90d=0)

    # --- shares and the rest -------------------------------------------------------------------

    def shares(self) -> None:
        for dept, entries in SHARE_LEGACY.items():
            modern_on = SHARE_MODERN.get(dept)
            write_modern = read_modern = None
            if modern_on:
                owner = self.leader_of(dept).id
                write_modern = self.add(_G(f"share:{dept}:modern:write", f"sg-share-{dept}-write", "AD", "SHARE",
                                           _plus(modern_on, 0, 1, "w", dept), OU_MODERN_SHARES,
                                           "sg-share-<department>-write", f"{self.departments[dept].name} share, write",
                                           department=dept, owner_id=owner))
                read_modern = self.add(_G(f"share:{dept}:modern:read-only", f"sg-share-{dept}-read-only", "AD", "SHARE",
                                          modern_on, OU_MODERN_SHARES, "sg-share-<department>-read-only",
                                          f"{self.departments[dept].name} share, read-only", department=dept,
                                          owner_id=owner))
                self.nest(read_modern.key, f"dept:{dept}")
            nested_write = False
            for i, (name, access, created) in enumerate(entries):
                legacy = created < date(2019, 7, 1)
                ou = OU_LEGACY if legacy and not name.startswith("FS-") else OU_FILE_SHARES_LEGACY
                g = self.add(_G(f"share:{dept}:legacy:{i}", name, "AD", "SHARE", created, ou,
                                "FS-<Dept>-<R|RW>" if name.startswith("FS-") else "<Dept> share (legacy)",
                                f"{self.departments[dept].name} file share, {'write' if access == 'write' else 'read'}",
                                department=dept, owner_id=self.legacy_owner(f"share:{dept}:{i}")))
                if access == "read" and rng.unit("share-nest", g.key) < 0.6:
                    self.nest(g.key, f"dept:{dept}")
                else:
                    pool = self.people_in(dept)
                    share = 1.0 if access == "read" else 0.3
                    g.members = sorted(p.id for p in pool if rng.unit("share-member", g.key, p.id) < share)
                    self.drift(g, "d:" + dept, g.key)
                if modern_on is None:
                    continue
                replacement = write_modern if access == "write" else read_modern
                g.replaced_by = replacement.key
                if access == "write" and not nested_write:
                    self.nest(replacement.key, g.key)
                    g.description += f"; nested in {replacement.name} (still where write access is granted)"
                    nested_write = True
                    continue
                if rng.unit("share-retired", g.key) < 0.85:
                    g.status = "RETIRED"
                    continue
                g.status = "DEPRECATED"
                g.description += f"; replaced by {replacement.name}"
                g.last_change = _plus(modern_on, 5, 40, "share-deprecated", g.key)
                if rng.unit("share-emptied", g.key) < 0.5:
                    g.members, g.children = [], []
                    g.description += " (emptied, not deleted)"
            if write_modern is not None and not write_modern.children:
                write_modern.members = self.pick_people(max(2, len(self.people_in(dept)) // 4), [dept], "sw", dept)
        # First attempts at a share group, archived later: same CN, renamed sAMAccountName.
        for dept, name, sam, created, archived_on in ARCHIVED_SHARES:
            original = next(f"share:{dept}:legacy:{i}" for i, e in enumerate(SHARE_LEGACY[dept]) if e[0] == name)
            g = self.add(_G(f"share:{dept}:archive", name, "AD", "SHARE", created, OU_ARCHIVE, "<Dept>-RW",
                            f"Original {self.departments[dept].name} share group, archived {archived_on.year} (CN kept, "
                            "sAMAccountName renamed)", department=dept, sam=sam, status="DEPRECATED",
                            last_change=archived_on))
            g.replaced_by = original
        # Okta groups created during the migration by copying an AD share group's name.
        for key, name, app, tier, dept, created, description in OKTA_NAME_COPIES:
            g = self.add(_G(key, name, "OKTA", "APP_ACCESS", created, None, "reused share-group name", description,
                            app, tier, department=dept))
            g.members = self.pick_people(max(3, len(self.people_in(dept)) // 5), [dept], "copy", key)
            self.assignments.append(Assignment(rng.record_id("asgn", app, key), app, key, None, tier, created))

    def misc(self) -> None:
        for key, name, kind, created, ou, members, description in MISC_GROUPS:
            source = "OKTA" if ou == "OKTA" else "AD"
            g = self.add(_G(key, name, source, kind, created, None if source == "OKTA" else ou,
                            "non-standard name" if created >= MODERN_NAMING_ADOPTED else "ad hoc", description,
                            owner_id=self.legacy_owner(key) if created < MODERN_NAMING_ADOPTED
                            else self.owner_for("operations", "misc-owner", key)))
            if members:
                g.members = self.pick_people(members, ["operations", "engineering", "it", "product"], "misc", key)

    def terminated_artifacts(self) -> None:
        """A few disabled former employees left behind in legacy AD groups."""
        candidates = sorted(k for k, g in self.groups.items()
                            if g.source == "AD" and g.members and g.created < OKTA_ADOPTED and g.status != "RETIRED"
                            and g.kind in ("APP_ACCESS", "SHARE", "ROLE"))
        chosen = rng.ordered(candidates, lambda x: x, "artifact-groups")[:9]
        leavers = sorted(p.id for p in self.former if p.termination_date and p.termination_date >= date(2022, 1, 1))
        for key in sorted(chosen):
            g = self.groups[key]
            extra = rng.ordered(leavers, lambda x: x, "artifact-people", key)[: 1 + rng.below(2, "artifact-n", key)]
            g.members = sorted(set(g.members) | set(extra))


def build_estate(departments: tuple[Department, ...], people: tuple[Person, ...]) -> Estate:
    b = _Builder(departments, people)
    b.org_groups()
    for index, spec in enumerate(CATALOG, start=1):
        b.application(spec, index)
    b.shares()
    b.misc()
    b.terminated_artifacts()
    return _finish(b)


# --- identifiers, timestamps, and correlation expectations ------------------------------------


def _finish(b: _Builder) -> Estate:
    live = {k: g for k, g in b.groups.items() if g.status != "RETIRED"}
    for g in live.values():
        g.children = [c for c in g.children if c in live]
    assignments = [a for a in b.assignments if a.group_key is None or a.group_key in live]
    assigned = {a.group_key for a in assignments if a.group_key and a.present}
    order = sorted(live.values(), key=lambda g: (g.created, g.key))

    # The objectSid that Okta's first 2021 import batch never captured (0008): name search only.
    no_sid = [g.key for g in order if g.source == "AD" and g.ou in IMPORTED_OUS and g.created < OKTA_ADOPTED
              and g.key not in assigned and g.kind != "DEPARTMENT" and g.key not in MUST_BE_EXACT]
    missing_sid = set(rng.ordered(no_sid, lambda x: x, "no-sid")[:5]) | {"app:old-wiki:legacy:user"}

    sams: set[str] = set()
    groups: list[Group] = []
    rid = 1103
    okta_n = 0
    ad_names = [((g.sam or g.name).casefold(), g.name.casefold()) for g in order if g.source == "AD" and g.ad_exists]
    for g in order:
        okta_visible = g.source in ("OKTA", "BUILT_IN") or (g.ou in IMPORTED_OUS and g.ad_exists)
        okta_type = None if not okta_visible else {"AD": "APP_GROUP", "OKTA": "OKTA_GROUP", "BUILT_IN": "BUILT_IN"}[g.source]
        okta_id = None
        if okta_visible:
            if g.source == "BUILT_IN":
                okta_id = OKTA_EVERYONE_ID
            else:
                okta_n += 1
                okta_id = f"{OKTA_GROUP_PREFIX}{okta_n:04d}"
        guid = sid = sam = dn = None
        if g.source == "AD":
            rid += 1
            guid = str(rng.stable_uuid("ad-group", g.key))
            sid = f"{AD_DOMAIN_SID}-{rid}"
            sam = g.sam or g.name
            if sam.casefold() in sams:
                raise AssertionError(f"duplicate sAMAccountName {sam}")
            sams.add(sam.casefold())
            dn = f"CN={g.name},OU={g.ou},{DC}"
        reports_sid = g.source == "AD" and g.key not in missing_sid
        if g.configured is not None:
            configured = g.configured
        elif g.key in MUST_BE_EXACT:
            configured = True
        else:
            # The reviewed configuration covers every sg-okta-* group and department group created before
            # the last review, most groups still assigned, and some of the superseded ones.
            reviewable = okta_type == "APP_GROUP" and reports_sid and g.created <= CORRELATION_CONFIG_REVIEWED
            chance = (1.0 if g.style.startswith("sg-") or g.kind in ("DEPARTMENT", "ROLE", "ALL_STAFF")
                      else 0.92 if g.key in assigned else 0.45 if g.replaced_by is not None else 0.0)
            configured = reviewable and rng.unit("configured", g.key) < chance
        case = _correlation_case(g, okta_type, reports_sid, configured, b.groups, ad_names)
        created = _at(g.created, g.key)
        groups.append(Group(
            id=rng.record_id("dgrp", g.key), uuid=str(rng.stable_uuid("group", g.key)), key=g.key, name=g.name,
            okta_name=(g.okta_name or g.name) if okta_visible else None, source=g.source, okta_visible=okta_visible,
            okta_group_type=okta_type, okta_group_id=okta_id, kind=g.kind, era=era_for(g.created).key,
            naming_style=g.style, created_at=created, modified_at=_modified(g, created, g.key in assigned),
            owner_id=g.owner_id, description=g.description, application=g.application, tier=g.tier,
            department=g.department, status=g.status, replaced_by=g.replaced_by if g.replaced_by in live else None,
            ad_object_guid=guid, ad_sid=sid, ad_sam_account_name=sam, ad_distinguished_name=dn, ad_exists=g.ad_exists,
            okta_reports_sid=reports_sid, configured_mapping=configured, correlation_case=case,
            admin_count=g.admin_count, protected_from_deletion=g.protected, push_target=g.push_target))
    nesting = tuple(sorted((g.key, c) for g in live.values() for c in g.children))
    memberships = tuple(sorted((g.key, m) for g in live.values() for m in g.members))
    _check_acyclic(nesting)
    return Estate(tuple(b.apps), tuple(sorted(groups, key=lambda g: g.key)), nesting, memberships,
                  tuple(sorted(assignments, key=lambda a: a.id)))


def _correlation_case(g: _G, okta_type: str | None, reports_sid: bool, configured: bool, groups: dict[str, _G],
                      ad_names: list[tuple[str, str]]) -> str | None:
    """What the correlation engine should prove for this group (checked when the world is seeded)."""
    if okta_type is None:
        return None
    if okta_type == "BUILT_IN":
        return "BUILT_IN"
    if configured:
        if g.source == "OKTA":
            target = groups[g.push_target] if g.push_target else None
            if target is None or not target.ad_exists:
                return "CONFIGURED_TARGET_DELETED"
            return "LEGACY_AD_TO_MODERN_OKTA"
        if g.okta_name and g.okta_name != g.name:
            return "NORMALIZED_EXACT"
        return "EXACT" if g.style.startswith("sg-") else "LEGACY_NAME_EXACT"
    if okta_type == "APP_GROUP" and reports_sid:
        return "UNVERIFIED_STABLE_ID"
    value = (g.sam or g.name).casefold() if okta_type == "APP_GROUP" else g.name.casefold()
    if okta_type == "APP_GROUP":
        hits = sum(1 for sam, _ in ad_names if sam == value)
    else:
        hits = sum(1 for sam, cn in ad_names if value in (sam, cn))
    return "NO_MATCH" if hits == 0 else "NAME_ONLY" if hits == 1 else "MULTIPLE_MATCHES"


def _modified(g: _G, created: datetime, assigned: bool) -> datetime:
    if g.last_change is not None:
        return max(created, _at(g.last_change, "modified", g.key))
    if g.source == "BUILT_IN":
        return created
    if g.members and (assigned or g.kind in ("DEPARTMENT", "TEAM", "ROLE")) and g.status == "ACTIVE":
        return max(created, _at(SNAPSHOT_DATE - timedelta(days=2 + rng.below(110, "recent", g.key)), "m", g.key))
    if g.members:
        span = max(1, (SNAPSHOT_DATE - g.created).days)
        return max(created, _at(g.created + timedelta(days=int(span * (0.3 + 0.5 * rng.unit("mod", g.key)))),
                                "m", g.key))
    return created


def _check_acyclic(edges: tuple[tuple[str, str], ...]) -> None:
    children: dict[str, list[str]] = {}
    for parent, child in edges:
        children.setdefault(parent, []).append(child)
    state: dict[str, int] = {}

    def visit(node: str) -> None:
        if state.get(node) == 1:
            raise AssertionError(f"group nesting cycle through {node}")
        if state.get(node) == 2:
            return
        state[node] = 1
        for c in children.get(node, ()):
            visit(c)
        state[node] = 2

    for node in sorted(children):
        visit(node)
