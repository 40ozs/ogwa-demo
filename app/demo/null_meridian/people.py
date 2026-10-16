"""Null Meridian's organization and ten years of employment history.

The current organization is built first (exactly 1,800 active positions in fourteen
departments, with leaders, directors, managers, and individual contributors). Hire dates
follow the company's growth curve with attrition, so long-tenured and recent hires both
appear, and people in departments formed later (Data, Security, ...) were often hired into
an older department first. Former employees are generated from the same curve and never
count toward the 1,800.
"""

import math
from dataclasses import dataclass
from datetime import date, timedelta

from app.demo.null_meridian import rng
from app.governance.model import Department, EmploymentEvent, Person, Team
from app.demo.null_meridian.names import FAMILY_NAMES, FIRST_NAMES
from app.demo.null_meridian.profile import ACTIVE_EMPLOYEES, FOUNDED, OKTA_ADOPTED, OKTA_WAVES, PRIMARY_DOMAIN, SNAPSHOT_DATE

ENG = ("{r} I", "{r} II", "Senior {r}", "Staff {r}", "Principal {r}")
ENG_W = (14, 30, 36, 15, 5)
BIZ = ("Associate {r}", "{r}", "Senior {r}", "Lead {r}")
BIZ_W = (18, 42, 30, 10)
FLAT = ("{r}", "Senior {r}")
FLAT_W = (62, 38)


def _team(slug: str, name: str, role: str, ladder=BIZ, weights=BIZ_W, formed: date = FOUNDED) -> Team:
    return Team(slug, name, role, tuple(ladder), tuple(weights), formed)


def _d(y: int, m: int, d: int = 1) -> date:
    return date(y, m, d)


# slug, name, size, formed, leader title, executive owner, feeder, teams
_DEPARTMENTS = (
    ("engineering", "Engineering", 480, _d(2016, 10), "VP, Engineering", "cto", None, (
        _team("platform", "Platform", "Software Engineer", ENG, ENG_W),
        _team("core-api", "Core API", "Software Engineer", ENG, ENG_W),
        _team("payments", "Payments", "Software Engineer", ENG, ENG_W, _d(2018, 2)),
        _team("web", "Web Experience", "Frontend Engineer", ENG, ENG_W, _d(2017, 3)),
        _team("mobile", "Mobile", "Mobile Engineer", ENG, ENG_W, _d(2018, 9)),
        _team("integrations", "Integrations", "Software Engineer", ENG, ENG_W, _d(2019, 4)),
        _team("sre", "Site Reliability", "Site Reliability Engineer", ENG, ENG_W, _d(2018, 6)),
        _team("infrastructure", "Infrastructure", "Infrastructure Engineer", ENG, ENG_W, _d(2017, 6)),
        _team("devprod", "Developer Productivity", "Software Engineer", ENG, ENG_W, _d(2020, 8)),
        _team("qa", "QA Automation", "QA Engineer", ENG, ENG_W, _d(2018, 1)),
        _team("search", "Search", "Software Engineer", ENG, ENG_W, _d(2021, 2)),
        _team("notifications", "Notifications", "Software Engineer", ENG, ENG_W, _d(2022, 5)),
    )),
    ("sales", "Sales", 290, _d(2017, 4), "VP, Sales", "cro", None, (
        _team("enterprise", "Enterprise Sales", "Account Executive", FLAT, FLAT_W),
        _team("mid-market", "Mid-Market Sales", "Account Executive", FLAT, FLAT_W, _d(2018, 8)),
        _team("sdr", "Sales Development", "Sales Development Representative", BIZ, BIZ_W),
        _team("solutions", "Solutions Engineering", "Solutions Engineer", FLAT, FLAT_W, _d(2018, 3)),
        _team("partnerships", "Partnerships", "Partner Manager", FLAT, FLAT_W, _d(2020, 2)),
        _team("enablement", "Sales Enablement", "Enablement Specialist", FLAT, FLAT_W, _d(2021, 1)),
    )),
    ("customer-success", "Customer Success", 240, _d(2018, 1), "VP, Customer Success", "cro", "sales", (
        _team("support-t1", "Support Tier 1", "Support Specialist"),
        _team("support-t2", "Support Tier 2", "Support Engineer"),
        _team("csm", "Customer Success Management", "Customer Success Manager", FLAT, FLAT_W),
        _team("onboarding", "Onboarding", "Implementation Consultant", FLAT, FLAT_W, _d(2019, 3)),
        _team("renewals", "Renewals", "Renewals Specialist", FLAT, FLAT_W, _d(2020, 6)),
        _team("support-ops", "Support Operations", "Support Operations Analyst", FLAT, FLAT_W, _d(2021, 4)),
    )),
    ("operations", "Operations", 210, _d(2017, 1), "VP, Operations", "coo", None, (
        _team("bizops", "Business Operations", "Business Operations Analyst"),
        _team("revops", "Revenue Operations", "Revenue Operations Analyst", BIZ, BIZ_W, _d(2018, 10)),
        _team("workplace", "Workplace", "Workplace Coordinator", FLAT, FLAT_W),
        _team("pmo", "Program Management", "Program Manager", FLAT, FLAT_W, _d(2019, 1)),
        _team("vendor", "Vendor Management", "Procurement Specialist", FLAT, FLAT_W, _d(2019, 9)),
        _team("custops", "Customer Operations", "Operations Specialist", BIZ, BIZ_W, _d(2018, 5)),
    )),
    ("marketing", "Marketing", 118, _d(2017, 6), "VP, Marketing", "cmo", None, (
        _team("demand-gen", "Demand Generation", "Demand Generation Specialist"),
        _team("product-marketing", "Product Marketing", "Product Marketing Manager", FLAT, FLAT_W, _d(2018, 4)),
        _team("content", "Content", "Content Strategist", FLAT, FLAT_W),
        _team("brand", "Brand", "Brand Designer", FLAT, FLAT_W, _d(2019, 2)),
        _team("marketing-ops", "Marketing Operations", "Marketing Operations Analyst", FLAT, FLAT_W, _d(2019, 8)),
        _team("events", "Events", "Event Manager", FLAT, FLAT_W, _d(2020, 1)),
    )),
    ("product", "Product", 105, _d(2016, 10), "VP, Product Management", "cpo", None, (
        _team("core-product", "Core Product", "Product Manager",
              ("Associate Product Manager", "Product Manager", "Senior Product Manager", "Group Product Manager"), BIZ_W),
        _team("growth", "Growth", "Product Manager",
              ("Associate Product Manager", "Product Manager", "Senior Product Manager", "Group Product Manager"), BIZ_W,
              _d(2019, 6)),
        _team("platform-product", "Platform Product", "Product Manager", FLAT, FLAT_W, _d(2020, 3)),
        _team("product-ops", "Product Operations", "Product Operations Analyst", FLAT, FLAT_W, _d(2021, 9)),
    )),
    ("data", "Data", 85, _d(2020, 1), "Head of Data", "cto", "engineering", (
        _team("data-engineering", "Data Engineering", "Data Engineer", ENG, ENG_W),
        _team("analytics", "Analytics", "Data Analyst"),
        _team("data-science", "Data Science", "Data Scientist", ENG, ENG_W),
        _team("analytics-engineering", "Analytics Engineering", "Analytics Engineer", ENG, ENG_W, _d(2022, 2)),
    )),
    ("finance", "Finance", 60, _d(2017, 3), "VP, Finance", "cfo", None, (
        _team("accounting", "Accounting", "Accountant"),
        _team("fpa", "FP&A", "Financial Analyst", BIZ, BIZ_W, _d(2018, 7)),
        _team("billing", "Billing and Revenue", "Billing Specialist", FLAT, FLAT_W, _d(2019, 1)),
        _team("tax", "Tax and Treasury", "Tax Analyst", FLAT, FLAT_W, _d(2020, 9)),
    )),
    ("it", "Information Technology", 55, _d(2018, 6), "Director, IT", "coo", "operations", (
        _team("service-desk", "Service Desk", "IT Support Specialist"),
        _team("endpoint", "Endpoint Engineering", "Systems Engineer", FLAT, FLAT_W),
        _team("iam", "Identity and Access", "IAM Engineer", FLAT, FLAT_W, _d(2021, 6)),
        _team("corp-systems", "Corporate Systems", "Systems Administrator", FLAT, FLAT_W),
    )),
    ("people", "People / HR", 50, _d(2017, 9), "VP, People", "cpeo", "operations", (
        _team("people-partners", "People Partners", "People Partner", FLAT, FLAT_W),
        _team("talent", "Talent Acquisition", "Recruiter"),
        _team("total-rewards", "Total Rewards", "Compensation Analyst", FLAT, FLAT_W, _d(2019, 10)),
        _team("people-ops", "People Operations", "People Operations Specialist", FLAT, FLAT_W),
        _team("learning", "Learning and Development", "Learning Specialist", FLAT, FLAT_W, _d(2021, 3)),
    )),
    ("design", "Design", 45, _d(2018, 3), "Head of Design", "cpo", "product", (
        _team("product-design", "Product Design", "Product Designer",
              ("Product Designer", "Senior Product Designer", "Staff Product Designer"), (45, 40, 15)),
        _team("ux-research", "UX Research", "UX Researcher", FLAT, FLAT_W, _d(2019, 5)),
        _team("design-systems", "Design Systems", "Design Systems Designer", FLAT, FLAT_W, _d(2021, 8)),
    )),
    ("security", "Security", 30, _d(2020, 6), "Chief Information Security Officer", "cto", "it", (
        _team("secops", "Security Operations", "Security Analyst", FLAT, FLAT_W),
        _team("appsec", "Application Security", "Security Engineer", FLAT, FLAT_W),
        _team("grc", "Governance, Risk, and Compliance", "GRC Analyst", FLAT, FLAT_W),
    )),
    ("legal", "Legal", 20, _d(2019, 2), "Deputy General Counsel", "gc", None, (
        _team("commercial", "Commercial Legal", "Counsel", ("Counsel", "Senior Counsel", "Lead Counsel"), (50, 35, 15)),
        _team("privacy", "Privacy", "Privacy Counsel", FLAT, FLAT_W, _d(2020, 11)),
        _team("legal-ops", "Legal Operations", "Paralegal", FLAT, FLAT_W),
    )),
)

# The Executive department: role key, title, fixed hire date (founders start on day one).
EXECUTIVES = (
    ("ceo", "Chief Executive Officer", _d(2016, 10, 1)),
    ("cto", "Chief Technology Officer", _d(2016, 10, 1)),
    ("cpo", "Chief Product Officer", _d(2016, 10, 1)),
    ("cfo", "Chief Financial Officer", _d(2018, 2, 12)),
    ("cro", "Chief Revenue Officer", _d(2018, 9, 4)),
    ("gc", "General Counsel", _d(2019, 2, 4)),
    ("coo", "Chief Operating Officer", _d(2019, 5, 13)),
    ("cpeo", "Chief People Officer", _d(2020, 1, 6)),
    ("ea-1", "Executive Assistant", _d(2020, 9, 14)),
    ("cmo", "Chief Marketing Officer", _d(2021, 3, 1)),
    ("cos", "Chief of Staff", _d(2022, 6, 6)),
    ("ea-2", "Executive Assistant", _d(2024, 4, 15)),
)
EXECUTIVE_SIZE = len(EXECUTIVES)

# Where internal transfers into a department usually come from.
NEIGHBOURS = {
    "data": "engineering", "product": "engineering", "security": "it", "customer-success": "sales",
    "sales": "customer-success", "operations": "customer-success", "marketing": "sales", "design": "marketing",
    "it": "operations", "finance": "operations", "people": "operations", "engineering": "it",
}

LOCATIONS = (("Meridian HQ", 34), ("Remote (Americas)", 38), ("East Hub", 12), ("Remote (EMEA)", 11),
             ("North Hub", 5))

# Active headcount at each anniversary; the curve between points is linear.
GROWTH = ((_d(2016, 10), 8), (_d(2017, 10), 60), (_d(2018, 10), 190), (_d(2019, 10), 420), (_d(2020, 10), 680),
          (_d(2021, 10), 960), (_d(2022, 10), 1250), (_d(2023, 10), 1440), (_d(2024, 10), 1610),
          (_d(2025, 10), 1730), (_d(2026, 10), 1800))
ATTRITION_PER_YEAR = 0.11


def departments() -> tuple[Department, ...]:
    out = [Department(rng.record_id("dept", "executive"), "executive", "Executive", EXECUTIVE_SIZE, FOUNDED,
                      "Chief Executive Officer", "ceo", None, ())]
    for slug, name, size, formed, leader, owner, feeder, teams in _DEPARTMENTS:
        out.append(Department(rng.record_id("dept", slug), slug, name, size, formed, leader, owner, feeder, teams))
    if sum(d.size for d in out) != ACTIVE_EMPLOYEES:
        raise AssertionError("department sizes must total the active headcount")
    return tuple(out)


# --- the hiring curve ------------------------------------------------------------------


def _months() -> list[date]:
    out, y, m = [], FOUNDED.year, FOUNDED.month
    while date(y, m, 1) < SNAPSHOT_DATE:
        out.append(date(y, m, 1))
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


MONTHS = _months()  # 2016-10 .. 2026-09, 120 months


def headcount(on: date) -> float:
    for (d0, h0), (d1, h1) in zip(GROWTH, GROWTH[1:]):
        if d0 <= on <= d1:
            return h0 + (h1 - h0) * (on - d0).days / (d1 - d0).days
    return float(GROWTH[-1][1])


def _monthly_hires() -> list[float]:
    out = []
    for m in MONTHS:
        nxt = date(m.year + (m.month == 12), 1 if m.month == 12 else m.month + 1, 1)
        out.append(max(0.0, headcount(nxt) - headcount(m)) + ATTRITION_PER_YEAR / 12 * headcount(m))
    return out


def _survival_weights() -> list[float]:
    hires = _monthly_hires()
    n = len(MONTHS)
    # Early employees stayed longer than later cohorts (equity, founding teams).
    return [hires[i] * math.exp(-ATTRITION_PER_YEAR * (n - i) / 12) * (2.2 if i < 30 else 1.0) for i in range(n)]


def _day_in(month: date, *key) -> date:
    day = month + timedelta(days=rng.below(27, "day", *key))
    return min(day, SNAPSHOT_DATE - timedelta(days=3))


# --- positions -------------------------------------------------------------------------


@dataclass
class _Position:
    key: str
    department: str
    team: Team | None
    level: str
    rank: int | None  # IC ladder index
    title: str
    manager_key: str | None
    exec_role: str | None = None
    hire: date | None = None
    first_department: str | None = None  # set when hired into a feeder department


def _ic_title(team: Team, rank: int) -> str:
    return team.ladder[rank].format(r=team.role)


def _manager_title(dept: Department, team: Team) -> str:
    if team.ladder == ENG:
        return f"Engineering Manager, {team.name}"
    return f"Manager, {team.name}"


def _director_title(dept: Department, teams: tuple[Team, ...]) -> str:
    if dept.slug == "engineering":
        return f"Director of Engineering, {teams[0].name}"
    return f"Director, {teams[0].name}"


def _positions(depts: tuple[Department, ...]) -> list[_Position]:
    positions: list[_Position] = []
    for role, title, _ in EXECUTIVES:
        manager = None if role == "ceo" else "exec:ceo"
        positions.append(_Position(f"exec:{role}", "executive", None, "executive", None, title, manager, role))
    for dept in depts:
        if dept.slug == "executive":
            continue
        n = dept.size
        directors = round(n / 110) if n >= 150 else (1 if n >= 60 else 0)
        managers = math.ceil((n - 1 - directors) / 8)
        ics = n - 1 - directors - managers
        leader_level = "vp" if dept.leader_title.startswith(("VP", "Chief")) else "director"
        leader_key = f"{dept.slug}:leader"
        positions.append(_Position(leader_key, dept.slug, None, leader_level, None, dept.leader_title,
                                   f"exec:{dept.executive_owner}"))
        teams = dept.teams
        # Directors cover contiguous runs of teams; managers are spread over teams.
        chunks = rng.allocate(len(teams), [1] * directors) if directors else []
        director_of_team: dict[str, str] = {}
        start = 0
        for i, size in enumerate(chunks):
            covered = teams[start:start + size] or teams[-1:]
            key = f"{dept.slug}:director:{i}"
            positions.append(_Position(key, dept.slug, covered[0], "director", None,
                                       _director_title(dept, covered), leader_key))
            for t in covered:
                director_of_team[t.slug] = key
            start += size
        weights = [2 if t.slug in ("support-t1", "platform", "core-api", "sdr", "enterprise") else 1 for t in teams]
        per_team = rng.allocate(managers, weights)
        if managers >= len(teams):
            per_team = [max(1, c) for c in per_team]
            while sum(per_team) > managers:
                i = max(range(len(per_team)), key=lambda j: (per_team[j], -j))
                per_team[i] -= 1
        manager_keys: list[tuple[str, Team]] = []
        for team, count in zip(teams, per_team):
            for j in range(count):
                key = f"{dept.slug}:manager:{team.slug}:{j}"
                boss = director_of_team.get(team.slug, leader_key)
                positions.append(_Position(key, dept.slug, team, "manager", None, _manager_title(dept, team), boss))
                manager_keys.append((key, team))
        per_manager = rng.allocate(ics, [1] * len(manager_keys))
        for (mkey, team), count in zip(manager_keys, per_manager):
            for j in range(count):
                key = f"{mkey}:ic:{j}"
                rank = rng.weighted(list(zip(range(len(team.ladder)), team.weights)), "rank", key)
                positions.append(_Position(key, dept.slug, team, "ic", rank, _ic_title(team, rank), mkey))
    return positions


# --- hire dates for active positions ---------------------------------------------------


_SCORE = {"vp": 2.4, "director": 1.7, "manager": 1.1}


def _seniority(p: _Position) -> float:
    base = _SCORE.get(p.level, 0.25 * (p.rank or 0))
    if p.level in ("vp", "director") and rng.unit("external-hire", p.key) < 0.3:
        base = 0.0  # hired from outside, not grown internally
    return base + rng.unit("seniority", p.key) * 1.6


def _assign_hire_dates(depts: tuple[Department, ...], positions: list[_Position]) -> None:
    survival = _survival_weights()
    by_slug = {d.slug: d for d in depts}
    for role, _, hired in EXECUTIVES:
        p = next(x for x in positions if x.key == f"exec:{role}")
        p.hire = hired
    for dept in depts:
        if dept.slug == "executive":
            continue
        members = [p for p in positions if p.department == dept.slug]
        formed_i = next(i for i, m in enumerate(MONTHS) if m >= dept.formed.replace(day=1))
        weights = []
        for i, w in enumerate(survival):
            if i < formed_i:
                feeder = by_slug.get(dept.feeder) if dept.feeder else None
                ok = feeder is not None and MONTHS[i] >= feeder.formed.replace(day=1) and formed_i - i <= 30
                weights.append(w * 0.18 if ok else 0.0)
            else:
                weights.append(w * min(1.0, 0.6 + 0.4 * (i - formed_i) / 12))
        slots: list[date] = []
        for i, count in enumerate(rng.allocate(len(members), weights)):
            slots += [MONTHS[i]] * count
        ordered = sorted(members, key=lambda p: (-_seniority(p), p.key))
        for p, month in zip(ordered, slots):
            hire = _day_in(month, p.key)
            p.hire = hire
            if hire < dept.formed:
                p.first_department = dept.feeder


# --- people ----------------------------------------------------------------------------


def _ascii(name: str) -> str:
    return "".join(c for c in name.lower() if "a" <= c <= "z")


class _Names:
    """Allocates emails and sAMAccountNames in hire order, with deterministic collision suffixes."""

    def __init__(self) -> None:
        self.emails: set[str] = set()
        self.sams: set[str] = set()

    def email(self, first: str, last: str) -> str:
        base = f"{_ascii(first)}.{_ascii(last)}"
        local, n = base, 1
        while local in self.emails:
            n += 1
            local = f"{base}{n}"
        self.emails.add(local)
        return f"{local}@{PRIMARY_DOMAIN}"

    def sam(self, first: str, last: str, hired: date) -> str:
        # 2016-2019: first initial + family name; from mid-2019: first.last, both capped at 20.
        base = (_ascii(first)[0] + _ascii(last)) if hired < date(2019, 7, 1) else f"{_ascii(first)}.{_ascii(last)}"
        base = base[:18]
        sam, n = base, 1
        while sam in self.sams:
            n += 1
            sam = f"{base}{n}"
        self.sams.add(sam)
        return sam


@dataclass
class _Former:
    key: str
    department: str
    team: Team | None
    level: str
    rank: int | None
    title: str
    hire: date
    leave: date


def _formers(depts: tuple[Department, ...]) -> list[_Former]:
    """Former employees: attrition along the growth curve, with plausible tenures."""
    out: list[_Former] = []
    leavers = [ATTRITION_PER_YEAR / 12 * headcount(m) for m in MONTHS]
    counts = rng.allocate(round(sum(leavers)), leavers)
    working = [d for d in depts if d.slug != "executive"]
    for i, count in enumerate(counts):
        for j in range(count):
            key = f"former:{MONTHS[i].isoformat()}:{j}"
            leave = _day_in(MONTHS[i], key, "leave")
            max_months = max(3, (leave.year - FOUNDED.year) * 12 + leave.month - FOUNDED.month)
            tenure = 3 + int(rng.unit("tenure", key) ** 1.4 * min(66, max_months - 3))
            hire_month = MONTHS[max(0, i - tenure)]
            hire = min(_day_in(hire_month, key, "hire"), leave - timedelta(days=60))
            hire = max(hire, FOUNDED)
            candidates = [(d, d.size) for d in working if d.formed <= hire]
            dept = rng.weighted(candidates, "former-dept", key)
            teams = [t for t in dept.teams if t.formed <= hire] or list(dept.teams[:1])
            team = rng.pick(teams, "former-team", key)
            if rng.unit("former-manager", key) < 0.1:
                out.append(_Former(key, dept.slug, team, "manager", None, _manager_title(dept, team), hire, leave))
            else:
                rank = rng.weighted(list(zip(range(len(team.ladder)), team.weights)), "former-rank", key)
                out.append(_Former(key, dept.slug, team, "ic", rank, _ic_title(team, rank), hire, leave))
    return out


def _okta_activation(department: str, hire: date) -> date:
    return max(hire, OKTA_WAVES[department])


def build_people(depts: tuple[Department, ...]) -> tuple[tuple[Person, ...], tuple[EmploymentEvent, ...]]:
    positions = _positions(depts)
    _assign_hire_dates(depts, positions)
    formers = _formers(depts)
    by_slug = {d.slug: d for d in depts}

    # Employee numbers, names, emails, and accounts are allocated in hire order.
    entries: list[tuple[date, str, object]] = [(p.hire, p.key, p) for p in positions]
    entries += [(f.hire, f.key, f) for f in formers]
    entries.sort(key=lambda e: (e[0], 0 if isinstance(e[2], _Position) else 1, e[1]))
    names = _Names()
    person_of_key: dict[str, str] = {}
    staged: list[tuple[object, dict]] = []
    for n, (_, key, item) in enumerate(entries, start=1):
        number = f"NM{n:05d}"
        first = rng.pick(FIRST_NAMES, "first", number)
        last = rng.pick(FAMILY_NAMES, "last", number)
        uid = rng.stable_uuid("person", number)
        pid = f"psn_{uid.hex}"
        person_of_key[key] = pid
        hire = item.hire  # type: ignore[attr-defined]
        staged.append((item, dict(id=pid, uuid=str(uid), number=number, first=first, last=last,
                                  email=names.email(first, last), sam=names.sam(first, last, hire))))

    people: list[Person] = []
    events: list[EmploymentEvent] = []
    managers = {p.manager_key for p in positions if p.manager_key}
    for item, ident in staged:
        pid = ident["id"]
        location = rng.weighted(LOCATIONS, "location", ident["number"])
        if isinstance(item, _Position):
            p = item
            okta = _okta_activation(p.department, p.hire)
            people.append(Person(
                id=pid, uuid=ident["uuid"], employee_number=ident["number"], first_name=ident["first"],
                last_name=ident["last"], display_name=f"{ident['first']} {ident['last']}", email=ident["email"],
                upn=ident["email"], sam_account_name=ident["sam"], department=p.department,
                team=p.team.slug if p.team else None, title=p.title, level=p.level,
                manager_id=person_of_key[p.manager_key] if p.manager_key else None, location=location,
                status="ACTIVE", hire_date=p.hire, termination_date=None, okta_status="ACTIVE",
                okta_activated=okta, ad_account="ENABLED", is_people_manager=p.key in managers))
            events += _active_history(pid, p, by_slug, okta)
        else:
            f = item
            okta_status = "DEPROVISIONED" if f.leave >= OKTA_ADOPTED else "NONE"
            okta = _okta_activation(f.department, f.hire) if f.leave >= OKTA_WAVES[f.department] else None
            if okta is None:
                okta_status = "NONE"
            people.append(Person(
                id=pid, uuid=ident["uuid"], employee_number=ident["number"], first_name=ident["first"],
                last_name=ident["last"], display_name=f"{ident['first']} {ident['last']}", email=ident["email"],
                upn=ident["email"], sam_account_name=ident["sam"], department=f.department,
                team=f.team.slug if f.team else None, title=f.title, level=f.level, manager_id=None,
                location=location, status="TERMINATED", hire_date=f.hire, termination_date=f.leave,
                okta_status=okta_status, okta_activated=okta, ad_account="DISABLED", is_people_manager=False))
            events.append(_event(pid, f.hire, "HIRED", f.department, f.title, f"Hired into {by_slug[f.department].name}"))
            if okta is not None:
                events.append(_event(pid, okta, "OKTA_ACTIVATED", f.department, f.title, "Okta account activated"))
            events.append(_event(pid, f.leave, "TERMINATED", f.department, f.title, "Employment ended"))
            if okta is not None:
                events.append(_event(pid, f.leave, "OKTA_DEACTIVATED", f.department, f.title,
                                     "Okta account deprovisioned; AD account disabled"))
    people.sort(key=lambda p: p.employee_number)
    events.sort(key=lambda e: (e.person_id, e.on, e.kind, e.id))
    return tuple(people), tuple(events)


def _event(pid: str, on: date, kind: str, dept: str, title: str, detail: str) -> EmploymentEvent:
    return EmploymentEvent(rng.record_id("emp", pid, on.isoformat(), kind), pid, on, kind, dept, title, detail)


def _between(start: date, end: date, low: float, high: float, *key) -> date:
    span = (end - start).days
    frac = low + (high - low) * rng.unit(*key)
    return start + timedelta(days=max(1, int(span * frac)))


def _active_history(pid: str, p: _Position, depts: dict[str, Department], okta: date) -> list[EmploymentEvent]:
    out: list[EmploymentEvent] = []
    dept = depts[p.department]
    tenure_days = (SNAPSHOT_DATE - p.hire).days
    hire_dept = p.first_department or p.department
    hire_title = p.title
    transfer_on: date | None = None
    if p.first_department:
        transfer_on = dept.formed + timedelta(days=rng.below(21, "formation-move", p.key))
    elif p.level == "ic" and tenure_days > 730 and p.department in NEIGHBOURS and rng.unit("lateral", p.key) < 0.06:
        hire_dept = NEIGHBOURS[p.department]
        transfer_on = _between(p.hire, SNAPSHOT_DATE, 0.3, 0.7, "lateral-date", p.key)
    promotions: list[tuple[date, str, str]] = []  # (date, old title, new title)
    team = p.team
    if p.level in ("manager", "director", "vp") and tenure_days > 730 and rng.unit("grown", p.key) < 0.55:
        ladder_team = team or (dept.teams[0] if dept.teams else None)
        ic_title = _ic_title(ladder_team, len(ladder_team.ladder) - 2 if len(ladder_team.ladder) > 2 else 0) \
            if ladder_team else p.title
        hire_title = ic_title
        if p.level == "manager":
            promotions.append((_between(p.hire, SNAPSHOT_DATE, 0.35, 0.6, "promo", p.key), ic_title, p.title))
        else:
            middle = _manager_title(dept, ladder_team) if ladder_team else "Manager"
            first = _between(p.hire, SNAPSHOT_DATE, 0.2, 0.4, "promo1", p.key)
            second = _between(first, SNAPSHOT_DATE, 0.3, 0.6, "promo2", p.key)
            promotions += [(first, ic_title, middle), (second, middle, p.title)]
    elif p.level == "ic" and p.rank and p.rank >= 2 and tenure_days > 900 and rng.unit("ic-promo", p.key) < 0.5:
        previous = _ic_title(team, p.rank - 1)
        hire_title = previous
        promotions.append((_between(p.hire, SNAPSHOT_DATE, 0.4, 0.8, "ic-promo-date", p.key), previous, p.title))
    if transfer_on is not None and promotions and promotions[0][0] <= transfer_on:
        transfer_on = promotions[0][0] - timedelta(days=14) if promotions[0][0] - timedelta(days=14) > p.hire else None
        if transfer_on is None:
            hire_dept = p.department
    out.append(_event(pid, p.hire, "HIRED", hire_dept, hire_title, f"Hired into {depts[hire_dept].name}"))
    if transfer_on is not None:
        why = (f"{dept.name} formed; moved from {depts[hire_dept].name}" if p.first_department
               else f"Internal transfer from {depts[hire_dept].name}")
        out.append(_event(pid, transfer_on, "TRANSFERRED", p.department, hire_title, why))
    for on, old, new in promotions:
        kind = "PROMOTED" if p.level != "ic" else "TITLE_CHANGED"
        out.append(_event(pid, on, kind, p.department, new, f"{old} to {new}"))
    in_effect = hire_title
    for on, _, new in promotions:
        if on <= okta:
            in_effect = new
    okta_dept = p.department if transfer_on is None or okta >= transfer_on else hire_dept
    out.append(_event(pid, okta, "OKTA_ACTIVATED", okta_dept, in_effect,
                      "Okta account activated" + (" in the 2021-2022 rollout" if okta > p.hire else "")))
    return out
