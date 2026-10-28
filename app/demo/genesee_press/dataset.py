"""Builds OGWA's Genesee Press dataset from the vendored projection. Pure: no store, no network, no clock.

Every person, department, team, group, application, membership, nesting edge, assignment, owner
and date is the shared world's (``synthetic-enterprise``, projection ``ogwa``), read through
``app.demo.genesee_press.projection``. OGWA adds only what is OGWA's:

- its record shapes (``app.governance.model``) and internal ids, derived from canonical ids under
  the ``genesee-press-v1`` seed: ``psn_``/``emp_`` ids, uuids, and the group key ``directory:<id>``
  for a group the shared world added (OGWA's own groups keep their legacy keys);
- its overlay (``app.demo.genesee_press.overlay``) for the groups, applications and departments
  it already modelled;
- for the groups the shared world added (ADG's), these rules: kind from the canonical category
  (``CATEGORY_KIND``), naming style from ``app.governance.naming``, OU ``Groups``, never configured
  for correlation, adminCount and protection unset;
- what it computes: usage aggregates, the governance analysis (findings, health) and the
  correlation expectation of each Okta-visible group, by the same rules as the Null Meridian
  generator (``app.demo.null_meridian.estate._correlation_case``).

``build_dataset()`` is cached: the dataset is immutable and identical on every call.
"""

import re
from dataclasses import replace
from datetime import date, datetime, timezone
from functools import lru_cache
from typing import Any

from app.demo.genesee_press import profile
from app.demo.genesee_press.overlay import overlay
from app.demo.genesee_press.projection import vendored
from app.demo.null_meridian.dataset import SCENARIOS, NullMeridianDataset, _usage
from app.demo.null_meridian.profile import era_for
from app.demo.null_meridian.rng import Keyed
from app.governance.analysis import analyze, build_index
from app.governance.model import Application, Assignment, Department, EmploymentEvent, Group, Person, Team
from app.governance.naming import check_name, legacy_style

RNG = Keyed(profile.SEED)
DC = ",".join(f"DC={p}" for p in profile.AD_DNS_DOMAIN.split("."))
DEFAULT_OU = "Groups"

LEVELS = {"executive": "executive", "vp": "vp", "director": "director", "manager": "manager",
          "individual_contributor": "ic"}
OKTA_STATUS = {"enabled": "ACTIVE", "disabled": "DEPROVISIONED", None: "NONE"}
EVENT_KIND = {"hired": "HIRED", "terminated": "TERMINATED", "transferred": "TRANSFERRED"}
# OGWA's group kind for a canonical category it did not model itself (the shared world's ADG groups).
CATEGORY_KIND = {"app_access": "APP_ACCESS", "application": "APP_ACCESS", "share": "SHARE", "department": "DEPARTMENT",
                 "team": "TEAM", "role": "ROLE", "broad": "ROLE", "administrative": "ROLE", "distribution": "ROLE",
                 "all_staff": "ALL_STAFF", "project": "PROJECT", "acquisition": "PROJECT", "builtin": "BUILT_IN",
                 "built_in": "BUILT_IN", None: "ROLE"}


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")


def _day(text: str | None) -> date | None:
    return date.fromisoformat(text[:10]) if text else None


def _instant(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def _correlation_case(g: dict[str, Any], by_key: dict[str, dict[str, Any]], ad_names: list[tuple[str, str]]) -> str | None:
    """What the correlation engine should prove for an Okta-visible group (the Null Meridian generator's rule)."""
    okta_type = g["okta_group_type"]
    if okta_type is None:
        return None
    if okta_type == "BUILT_IN":
        return "BUILT_IN"
    if g["configured_mapping"]:
        if g["source"] == "OKTA":
            target = by_key.get(g["push_target"]) if g["push_target"] else None
            if target is None or not target["ad_exists"]:
                return "CONFIGURED_TARGET_DELETED"
            return "LEGACY_AD_TO_MODERN_OKTA"
        if g["okta_name"] and g["okta_name"] != g["name"]:
            return "NORMALIZED_EXACT"
        return "EXACT" if g["naming_style"].startswith(f"{profile.STANDARD_PREFIX}-") else "LEGACY_NAME_EXACT"
    if okta_type == "APP_GROUP" and g["okta_reports_sid"]:
        return "UNVERIFIED_STABLE_ID"
    value = (g["ad_sam_account_name"] or g["name"]).casefold() if okta_type == "APP_GROUP" else g["name"].casefold()
    if okta_type == "APP_GROUP":
        hits = sum(1 for sam, _ in ad_names if sam == value)
    else:
        hits = sum(1 for sam, cn in ad_names if value in (sam, cn))
    return "NO_MATCH" if hits == 0 else "NAME_ONLY" if hits == 1 else "MULTIPLE_MATCHES"


def _style(name: str, app_slugs: frozenset[str], dept_slugs: frozenset[str]) -> str:
    check = check_name(name, applications=app_slugs, departments=dept_slugs, prefix=profile.STANDARD_PREFIX)
    return check.style if check.standard else legacy_style(name)


@lru_cache(maxsize=1)
def build_dataset() -> NullMeridianDataset:
    proj, ov = vendored(), overlay()
    units = {u["canonical_id"]: u for u in proj.records("org_units.jsonl")}
    dept_over = ov["departments"]

    def department_of(unit_id: str | None) -> str | None:
        while unit_id and unit_id in units and units[unit_id]["unit_type"] != "department":
            unit_id = units[unit_id]["parent_canonical_id"]
        return dept_over[unit_id]["slug"] if unit_id in dept_over else None

    # --- people and their history ------------------------------------------------------------
    records = sorted(proj.records("people.jsonl"), key=lambda p: (p["employee_number"], p["canonical_id"]))
    person_id = {p["canonical_id"]: RNG.record_id("psn", p["canonical_id"]) for p in records}
    account_person = {}
    for p in records:
        for field in ("ad_account_canonical_id", "idp_account_canonical_id"):
            if p[field]:
                account_person[p[field]] = person_id[p["canonical_id"]]
    managers = {p["manager_canonical_id"] for p in records if p["employment_status"] == "active"}
    people = []
    for p in records:
        active = p["employment_status"] == "active"
        people.append(Person(
            id=person_id[p["canonical_id"]], uuid=str(RNG.stable_uuid("person", p["canonical_id"])),
            employee_number=p["employee_number"], first_name=p["first_name"], last_name=p["last_name"],
            display_name=p["display_name"], email=p["email"], upn=p["upn"], sam_account_name=p["sam_account_name"],
            department=dept_over[p["department_canonical_id"]]["slug"], team=slug(p["team"]) if p["team"] else None,
            title=p["title"] or "", level=LEVELS[p["level"]],
            manager_id=person_id.get(p["manager_canonical_id"]) if p["manager_canonical_id"] else None,
            location=p["location"], status="ACTIVE" if active else "TERMINATED", hire_date=_day(p["hire_date"]),
            termination_date=_day(p["termination_date"]), okta_status=OKTA_STATUS[p["idp_status"]],
            okta_activated=_day(p["idp_activated_at"]), ad_account="ENABLED" if p["ad_account"] == "enabled" else "DISABLED",
            is_people_manager=p["canonical_id"] in managers))
    by_canonical = {p["canonical_id"]: p for p in records}
    dept_name = {v["slug"]: units[k]["name"] for k, v in dept_over.items()}
    events = []
    for e in proj.records("employment_events.jsonl"):
        p = by_canonical[e["person_canonical_id"]]
        dept = department_of(e["to_unit_canonical_id"]) or dept_over[p["department_canonical_id"]]["slug"]
        kind = EVENT_KIND[e["event"]]
        detail = {"HIRED": f"Hired into {dept_name[dept]}", "TERMINATED": "Employment ended",
                  "TRANSFERRED": f"Internal transfer from {dept_name.get(department_of(e['from_unit_canonical_id']) or '', 'another unit')}"}[kind]
        events.append(EmploymentEvent(RNG.record_id("emp", e["canonical_id"]), person_id[p["canonical_id"]], _day(e["at"]),
                                      kind, dept, e["title"] or p["title"] or "", detail))
    for p in records:
        dept = dept_over[p["department_canonical_id"]]["slug"]
        if p["idp_activated_at"]:
            events.append(EmploymentEvent(RNG.record_id("emp", p["idp_account_canonical_id"], "activated"),
                                          person_id[p["canonical_id"]], _day(p["idp_activated_at"]), "OKTA_ACTIVATED",
                                          dept, p["title"] or "", "Okta account activated"))
        if p["idp_deactivated_at"]:
            events.append(EmploymentEvent(RNG.record_id("emp", p["idp_account_canonical_id"], "deactivated"),
                                          person_id[p["canonical_id"]], _day(p["idp_deactivated_at"]), "OKTA_DEACTIVATED",
                                          dept, p["title"] or "", "Okta account deprovisioned; AD account disabled"))
    events.sort(key=lambda e: (e.person_id, e.on, e.kind, e.id))

    # --- departments ---------------------------------------------------------------------------
    active_in = {}
    for person in people:
        if person.status == "ACTIVE":
            active_in[person.department] = active_in.get(person.department, 0) + 1
    departments = []
    for cid, d in dept_over.items():
        unit = units[cid]
        formed = _day(unit["founded_on"]) or profile.FOUNDED
        teams = tuple(Team(slug(t["name"]), t["name"], "", (), (), _day(t["founded_on"]) or formed)
                      for t in sorted(units.values(), key=lambda u: u["name"]) if t["parent_canonical_id"] == cid)
        departments.append(Department(unit["legacy_department_id"], d["slug"], unit["name"], active_in.get(d["slug"], 0),
                                      formed, d["leaderTitle"], d["executiveOwner"], d["feeder"], teams))
    departments.sort(key=lambda d: (d.slug != "executive", -d.size, d.name))

    # --- applications --------------------------------------------------------------------------
    app_over = ov["applications"]
    app_slug = {cid: o["slug"] for cid, o in app_over.items()}
    applications = []
    for a in sorted(proj.records("applications.jsonl"), key=lambda a: a["okta_app_id"]):
        o = app_over[a["canonical_id"]]
        applications.append(Application(
            id=a["legacy_app_id"], uuid=str(RNG.stable_uuid("application", o["slug"])), slug=o["slug"], label=a["name"],
            category=a["category"], sign_on_mode=o["signOnMode"], provisioning=o["provisioning"],
            status="ACTIVE" if a["lifecycle"] == "active" else "INACTIVE", adopted=_day(o["adopted"]),
            okta_integrated=_day(o["oktaIntegrated"]), retired=_day(o["retired"]), tiers=tuple(o["tiers"]),
            admin_departments=tuple(o["adminDepartments"]), assignment_model=o["assignmentModel"],
            standardized=_day(o["standardized"]), owner_id=person_id.get(o["owner"]) if o["owner"] else None,
            owner_department=o["ownerDepartment"], okta_app_id=a["okta_app_id"], usage_events_90d=0, usage_users_90d=0))

    # --- groups ----------------------------------------------------------------------------------
    group_over = ov["groups"]
    canonical_groups = proj.records("groups.jsonl")
    key_of = {g["canonical_id"]: group_over[g["canonical_id"]]["key"] if g["canonical_id"] in group_over
              else f"directory:{g['canonical_id']}" for g in canonical_groups}
    app_slugs = frozenset(app_slug.values())
    dept_slugs = frozenset(d.slug for d in departments)
    draft: dict[str, dict[str, Any]] = {}
    for g in canonical_groups:
        o = group_over.get(g["canonical_id"], {})
        category = g["category"]
        if g["source"] == "AD":
            source = "AD"
        else:
            source = "BUILT_IN" if CATEGORY_KIND.get(category) == "BUILT_IN" else "OKTA"
        status = {"active": "ACTIVE", "deprecated": "DEPRECATED", "deleted": "DELETED"}[g["lifecycle_status"]]
        if source == "OKTA" and "defect:push-target-deleted" in g["tags"]:
            status = "DELETED_IN_AD"
        name = o.get("displayName") or g["name"]
        visible = g["idp_visible"]
        okta_type = None if not visible else {"AD": "APP_GROUP", "OKTA": "OKTA_GROUP", "BUILT_IN": "BUILT_IN"}[source]
        created = _instant(g["created_at"])
        modified = max(created, _instant(o["modifiedAt"])) if o.get("modifiedAt") else created
        ad = source == "AD"
        draft[key_of[g["canonical_id"]]] = dict(
            id=RNG.record_id("dgrp", key_of[g["canonical_id"]]), uuid=str(RNG.stable_uuid("group", g["canonical_id"])),
            key=key_of[g["canonical_id"]], name=name, okta_name=(o.get("oktaName") or name) if visible else None,
            source=source, okta_visible=visible, okta_group_type=okta_type, okta_group_id=g["okta_group_id"],
            kind=o.get("kind") or CATEGORY_KIND[category], era=era_for(created.date()).key,
            naming_style=o.get("style") or _style(g["name"], app_slugs, dept_slugs), created_at=created,
            modified_at=modified,
            owner_id=person_id.get(g["owner_canonical_id"]) if g["owner_canonical_id"] else None,
            description=g["description"] or o.get("description") or "",
            application=app_slug.get(g["application_canonical_id"]), tier=g["tier"],
            department=o["department"] if "department" in o else department_of(g["org_unit_canonical_id"]),
            status=status, replaced_by=key_of[o["replacedBy"]] if o.get("replacedBy") else None,
            ad_object_guid=g["ad_object_guid"], ad_sid=g["ad_sid"], ad_sam_account_name=g["name"] if ad else None,
            ad_distinguished_name=f"CN={name},OU={o.get('ou') or DEFAULT_OU},{DC}" if ad else None,
            ad_exists=status != "DELETED" if ad else True,
            okta_reports_sid=o.get("oktaReportsSid", ad), configured_mapping=o.get("configuredMapping", False),
            correlation_case=None, admin_count=o.get("adminCount", False),
            protected_from_deletion=o.get("protectedFromDeletion", False),
            push_target=key_of[o["pushTarget"]] if o.get("pushTarget") else None)
    ad_names = [(d["ad_sam_account_name"].casefold(), d["name"].casefold()) for d in draft.values()
                if d["source"] == "AD" and d["ad_exists"]]
    for d in draft.values():
        d["correlation_case"] = _correlation_case(d, draft, ad_names)
    groups = tuple(Group(**draft[k]) for k in sorted(draft))

    # --- memberships, nesting, assignments --------------------------------------------------------
    members, nesting = set(), set()
    for m in proj.records("memberships.jsonl"):
        if not m["current"]:
            continue
        if m["member_kind"] == "group":
            nesting.add((key_of[m["group_canonical_id"]], key_of[m["member_canonical_id"]]))
        elif m["member_canonical_id"] in account_person:
            members.add((key_of[m["group_canonical_id"]], account_person[m["member_canonical_id"]]))
    assignments = []
    for a in proj.records("assignments.jsonl"):
        group = a["assignee_kind"] == "group"
        assignments.append(Assignment(
            id=a["legacy_assignment_id"], application=app_slug[a["application_canonical_id"]],
            group_key=key_of[a["assignee_canonical_id"]] if group else None,
            person_id=None if group else account_person[a["assignee_canonical_id"]], tier=a["tier"],
            created=_day(a["valid_from"]), present=a["current"]))

    people_t, nesting_t, members_t = tuple(people), tuple(sorted(nesting)), tuple(sorted(members))
    assignments_t = tuple(sorted(assignments, key=lambda a: a.id))
    index = build_index(people_t, groups, nesting_t, members_t, assignments_t)
    applications_t = _usage(tuple(applications), index, RNG)
    analysis = analyze(people=people_t, groups=groups, applications=applications_t, nesting=nesting_t,
                       memberships=members_t, assignments=assignments_t, standard_since=profile.MODERN_NAMING_ADOPTED,
                       finding_id=lambda code, subject: RNG.record_id("fnd", code, subject),
                       standard_prefix=profile.STANDARD_PREFIX)
    company = {
        "dataset": profile.DATASET_KEY, "seed": profile.SEED, "company": profile.COMPANY,
        "primaryDomain": profile.PRIMARY_DOMAIN, "founded": profile.FOUNDED.isoformat(),
        "oktaAdopted": profile.OKTA_ADOPTED.isoformat(), "modernNamingAdopted": profile.MODERN_NAMING_ADOPTED.isoformat(),
        "snapshotDate": profile.SNAPSHOT_DATE.isoformat(), "asOf": profile.AS_OF.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "activeEmployees": sum(1 for p in people_t if p.status == "ACTIVE"), "techDebt": profile.TECH_DEBT,
        "synthetic": True, "source": proj.source,
    }
    return NullMeridianDataset(tuple(departments), people_t, tuple(events), applications_t, groups, nesting_t, members_t,
                               assignments_t, analysis.findings, scenarios(), analysis, company, profile.STANDARD_PREFIX)


def scenarios():
    """The ten portfolio scenarios, worded for Genesee Press (``profile.localize``)."""
    return tuple(replace(s, title=profile.localize(s.title), summary=profile.localize(s.summary),
                         what_to_look_at=profile.localize(s.what_to_look_at),
                         candidate_key=profile.localize(s.candidate_key) if s.candidate_key else None) for s in SCENARIOS)


__all__ = ["CATEGORY_KIND", "RNG", "build_dataset", "scenarios", "slug"]
