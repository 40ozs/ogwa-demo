"""OGWA's own data about the shared world's groups, applications and departments (the overlay).

The shared world (``synthetic-enterprise``) owns every person, group, application, membership,
assignment, owner and date. What it does not model is OGWA's: how a group sits in OGWA's view of
the directory and Okta (its kind, naming style, OU, a display name or Okta name that differs from
the sAMAccountName, whether Okta's import captured its objectSid, whether the reviewed
correlation configuration lists it, adminCount and protection, the AD group an Okta group is
pushed to, the group that replaced it) and OGWA's catalogue facts about each application
(sign-on mode, provisioning, adoption and retirement dates, tiers, administering departments,
assignment model, owner).

PROJECTION-CONTRACT §5: app-owned data stays in the app and references canonical ids. The
overlay is ``config/genesee-press/ogwa-overlay.json``, keyed by canonical id. It was derived once,
by rule, from OGWA's own Null Meridian generator for the 401 groups and 81 applications the shared
world mapped from it (``legacy_group_key``, ``legacy_slug``); every value that names a person or
group is re-keyed through the shared world's mappings (an application's owner through
``legacy_employee_numbers``). Groups the shared world added (ADG's) have no overlay entry; their
OGWA attributes follow the documented rules in ``app.demo.genesee_press.dataset``.

    python -m app.demo.genesee_press overlay-check    exit 1 if the committed overlay differs
    python -m app.demo.genesee_press overlay-write    regenerate it from the legacy generator

At cutover (MIGRATION-STRATEGY phase 6) the legacy generator is removed and the committed overlay
becomes the source of these facts; no step reads the generator at runtime.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.demo.genesee_press.profile import localize

REPO_ROOT = Path(__file__).resolve().parents[3]
OVERLAY_PATH = REPO_ROOT / "config" / "genesee-press" / "ogwa-overlay.json"
FORMAT = "ogwa-genesee-press-overlay/1"


def _ou(dn: str | None, name: str) -> str | None:
    if not dn:
        return None
    head = f"CN={name},OU="
    if not dn.startswith(head):
        raise ValueError(f"unexpected distinguished name {dn}")
    return dn[len(head):dn.index(",DC=")]


def build_overlay(legacy, projection) -> dict[str, Any]:
    """The overlay document from the legacy Null Meridian dataset and the vendored projection."""
    groups = projection.records("groups.jsonl")
    canonical_of_key = {g["legacy_group_key"]: g["canonical_id"] for g in groups if g["legacy_group_key"]}
    by_canonical = {g["canonical_id"]: g for g in groups}
    if set(canonical_of_key) != {g.key for g in legacy.groups}:
        raise ValueError("the projection's legacy group keys are not exactly the legacy dataset's groups")
    group_entries = {}
    for g in sorted(legacy.groups, key=lambda x: canonical_of_key[x.key]):
        cid = canonical_of_key[g.key]
        canonical_name = by_canonical[cid]["name"]
        name = localize(g.name)
        okta_name = localize(g.okta_name) if g.okta_name else None
        group_entries[cid] = {
            "key": g.key, "kind": g.kind, "style": localize(g.naming_style), "ou": _ou(g.ad_distinguished_name, g.name),
            "displayName": name if name != canonical_name else None,
            "oktaName": okta_name if okta_name and okta_name != name else None,
            "description": localize(g.description), "department": g.department,
            "replacedBy": canonical_of_key.get(g.replaced_by) if g.replaced_by else None,
            "pushTarget": canonical_of_key.get(g.push_target) if g.push_target else None,
            "oktaReportsSid": g.okta_reports_sid, "configuredMapping": g.configured_mapping,
            "adminCount": g.admin_count, "protectedFromDeletion": g.protected_from_deletion,
            "modifiedAt": g.modified_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    apps = projection.records("applications.jsonl")
    canonical_of_slug = {a["legacy_slug"]: a["canonical_id"] for a in apps}
    numbers = {p.id: p.employee_number for p in legacy.people}
    person_of_number = {n: p["canonical_id"] for p in projection.records("people.jsonl") for n in p["legacy_employee_numbers"]}
    app_entries = {}
    for a in sorted(legacy.applications, key=lambda x: canonical_of_slug[x.slug]):
        app_entries[canonical_of_slug[a.slug]] = {
            "slug": a.slug, "signOnMode": a.sign_on_mode, "provisioning": a.provisioning, "adopted": a.adopted.isoformat(),
            "oktaIntegrated": a.okta_integrated.isoformat(), "retired": a.retired.isoformat() if a.retired else None,
            "tiers": list(a.tiers), "adminDepartments": list(a.admin_departments), "assignmentModel": a.assignment_model,
            "standardized": a.standardized.isoformat() if a.standardized else None,
            "owner": person_of_number[numbers[a.owner_id]] if a.owner_id else None, "ownerDepartment": a.owner_department,
        }
    canonical_of_dept = {u["legacy_department_id"]: u["canonical_id"] for u in projection.records("org_units.jsonl")
                         if u["legacy_department_id"]}
    dept_entries = {canonical_of_dept[d.id]: {"slug": d.slug, "leaderTitle": d.leader_title,
                                              "executiveOwner": d.executive_owner, "feeder": d.feeder}
                    for d in sorted(legacy.departments, key=lambda x: canonical_of_dept[x.id])}
    return {
        "format": FORMAT, "synthetic": True,
        "notice": "OGWA's own attributes of the shared synthetic world's groups, applications and departments, keyed by "
                  "canonical id. Derived by rule from OGWA's legacy Null Meridian generator; every person and group "
                  "reference is a canonical id.",
        "projection": projection.source,
        "departments": dept_entries, "applications": app_entries, "groups": group_entries,
    }


def render(document: dict[str, Any]) -> str:
    """One record per line under each section, keys sorted: reviewable and stable."""
    lines = ["{"]
    items = list(document.items())
    for i, (key, value) in enumerate(items):
        comma = "," if i < len(items) - 1 else ""
        if key in ("departments", "applications", "groups"):
            lines.append(f"  {json.dumps(key)}: {{")
            rows = list(value.items())
            for j, (k, v) in enumerate(rows):
                lines.append(f"    {json.dumps(k)}: {json.dumps(v, ensure_ascii=False, sort_keys=True)}"
                             + ("," if j < len(rows) - 1 else ""))
            lines.append(f"  }}{comma}")
        else:
            lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False, sort_keys=True)}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


@lru_cache(maxsize=1)
def overlay() -> dict[str, Any]:
    document = json.loads(OVERLAY_PATH.read_text(encoding="utf-8"))
    if document.get("format") != FORMAT or document.get("synthetic") is not True:
        raise ValueError(f"{OVERLAY_PATH.name} is not an {FORMAT} document")
    return document


__all__ = ["FORMAT", "OVERLAY_PATH", "build_overlay", "overlay", "render"]
