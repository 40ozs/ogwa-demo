"""The repository-owned, machine-readable Null Meridian contract, and the reviewed correlation
configuration the dataset implies.

``docs/demo/null-meridian.manifest.json`` lists the stable identifiers of every person,
department, group, and application, the group creation dates, nesting, direct memberships,
and assignments, so another fixture (the ADG Null Meridian fixture, for one) can use exactly
the same synthetic identities and group names. ``config/correlation.null-meridian.json`` is
the reviewed mapping configuration the demo correlates with. Both are generated from the seed
and committed; a test fails if either drifts from what the code generates.

    python -m app.demo.null_meridian check     exit 1 if a committed file differs
    python -m app.demo.null_meridian write     regenerate both files
"""

import json
from pathlib import Path
from typing import Any

from app.demo.null_meridian.dataset import NullMeridianDataset
from app.demo.null_meridian.profile import (
    AD_DNS_DOMAIN,
    AD_NETBIOS,
    MILESTONES,
    NAMING_ERAS,
    OKTA_AD_SOURCE_ID,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = REPO_ROOT / "docs" / "demo" / "null-meridian.manifest.json"
CORRELATION_PATH = REPO_ROOT / "config" / "correlation.null-meridian.json"
MANIFEST_FORMAT = "ogwa-null-meridian-manifest/1"
CORRELATION_REF = "config/correlation.null-meridian.json#"


USER_COLUMNS = ("uuid", "employeeNumber", "firstName", "lastName", "email", "samAccountName", "department", "team",
                "title", "level", "manager", "location", "status", "hireDate", "terminationDate", "oktaStatus")
GROUP_COLUMNS = ("uuid", "key", "name", "oktaName", "source", "kind", "era", "createdAt", "modifiedAt", "status",
                 "replacedBy", "pushTarget", "oktaGroupId", "oktaGroupType", "adObjectGuid", "adSid", "adSamAccountName",
                 "adDistinguishedName", "adExists", "application", "tier", "department", "owner")


def _table(columns: tuple[str, ...], rows: list[list[Any]]) -> dict[str, Any]:
    """Columnar: the column names once, then one row per record (keeps the file reviewable and small)."""
    return {"columns": list(columns), "rows": rows}


def _users(ds: NullMeridianDataset, numbers: dict[str, str]) -> dict[str, Any]:
    return _table(USER_COLUMNS, [[
        p.uuid, p.employee_number, p.first_name, p.last_name, p.email, p.sam_account_name, p.department, p.team, p.title,
        p.level, numbers.get(p.manager_id) if p.manager_id else None, p.location, p.status, p.hire_date.isoformat(),
        p.termination_date.isoformat() if p.termination_date else None, p.okta_status] for p in ds.people])


def _groups(ds: NullMeridianDataset, numbers: dict[str, str]) -> dict[str, Any]:
    rows = []
    for g in ds.groups:
        d = g.to_dict()
        d["owner"] = numbers.get(g.owner_id) if g.owner_id else None
        rows.append([d[c] for c in GROUP_COLUMNS])
    return _table(GROUP_COLUMNS, rows)


def manifest_document(ds: NullMeridianDataset) -> dict[str, Any]:
    numbers = {p.id: p.employee_number for p in ds.people}
    members: dict[str, list[str]] = {}
    for group, person in ds.memberships:
        members.setdefault(group, []).append(numbers[person])
    return {
        "format": MANIFEST_FORMAT,
        "synthetic": True,
        "notice": "Fictional company. Every person, group, application, and identifier is generated from the seed; "
                  "nothing is derived from any real tenant, directory, or organization.",
        "profile": ds.profile(),
        "activeDirectory": {"dnsDomain": AD_DNS_DOMAIN, "netbios": AD_NETBIOS},
        "namingEras": [{"key": e.key, "label": e.label, "start": e.start.isoformat(), "end": e.end.isoformat(),
                        "examples": e.description} for e in NAMING_ERAS],
        "milestones": [{"date": d, "event": e} for d, e in MILESTONES],
        "counts": ds.counts(),
        "departments": [{"id": d.id, "slug": d.slug, "name": d.name, "activeHeadcount": d.size,
                         "formed": d.formed.isoformat(), "teams": [t.slug for t in d.teams]} for d in ds.departments],
        "applications": [{"uuid": a.uuid, "id": a.id, "slug": a.slug, "label": a.label, "category": a.category,
                          "oktaAppId": a.okta_app_id, "signOnMode": a.sign_on_mode, "provisioning": a.provisioning,
                          "status": a.status, "adopted": a.adopted.isoformat(),
                          "oktaIntegrated": a.okta_integrated.isoformat(),
                          "standardized": a.standardized.isoformat() if a.standardized else None,
                          "tiers": list(a.tiers)} for a in ds.applications],
        "groups": _groups(ds, numbers),
        "nesting": [list(e) for e in ds.nesting],
        "memberships": {k: members[k] for k in sorted(members)},
        "assignments": [{"id": a.id, "application": a.application, "group": a.group_key,
                         "person": numbers.get(a.person_id) if a.person_id else None, "tier": a.tier,
                         "created": a.created.isoformat(), "present": a.present} for a in ds.assignments],
        "users": _users(ds, numbers),
    }


def correlation_document(ds: NullMeridianDataset) -> dict[str, Any]:
    mappings = []
    for g in ds.groups:
        if not g.configured_mapping or g.okta_group_id is None:
            continue
        # A pushed Okta group: the configuration names its AD push target.
        target = ds.group(g.push_target) if g.source == "OKTA" else g
        mappings.append({"oktaGroupId": g.okta_group_id, "adObjectGuid": target.ad_object_guid, "adSid": target.ad_sid,
                         "domain": AD_DNS_DOMAIN, "configurationRef": CORRELATION_REF + g.key})
    return {"format": "ogwa-synthetic-correlation/1", "correlation": {
        "directorySources": [{"oktaAppId": OKTA_AD_SOURCE_ID, "domain": AD_DNS_DOMAIN, "netbiosName": AD_NETBIOS}],
        "configuredMappings": sorted(mappings, key=lambda m: m["oktaGroupId"]),
    }}


def render(document: dict[str, Any]) -> str:
    """Stable JSON: top-level keys in order, one record per line for lists of records."""
    lines = ["{"]
    items = list(document.items())
    for i, (key, value) in enumerate(items):
        comma = "," if i < len(items) - 1 else ""
        if isinstance(value, list) and value and isinstance(value[0], (dict, list)):
            lines.append(f"  {json.dumps(key)}: [")
            for j, record in enumerate(value):
                lines.append("    " + json.dumps(record, ensure_ascii=False, sort_keys=isinstance(record, dict))
                             + ("," if j < len(value) - 1 else ""))
            lines.append(f"  ]{comma}")
        elif isinstance(value, dict) and set(value) == {"columns", "rows"}:
            lines.append(f"  {json.dumps(key)}: {{")
            lines.append(f'    "columns": {json.dumps(value["columns"])},')
            lines.append('    "rows": [')
            for j, row in enumerate(value["rows"]):
                lines.append("      " + json.dumps(row, ensure_ascii=False) + ("," if j < len(value["rows"]) - 1 else ""))
            lines.append("    ]")
            lines.append(f"  }}{comma}")
        elif isinstance(value, dict) and key in ("memberships",):
            lines.append(f"  {json.dumps(key)}: {{")
            sub = list(value.items())
            for j, (k, v) in enumerate(sub):
                lines.append(f"    {json.dumps(k)}: {json.dumps(v)}" + ("," if j < len(sub) - 1 else ""))
            lines.append(f"  }}{comma}")
        else:
            lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False, sort_keys=True)}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_correlation(document: dict[str, Any]) -> str:
    c = document["correlation"]
    lines = ["{", f'  "format": {json.dumps(document["format"])},', '  "correlation": {',
             f'    "directorySources": {json.dumps(c["directorySources"])},', '    "configuredMappings": [']
    for j, m in enumerate(c["configuredMappings"]):
        lines.append("      " + json.dumps(m) + ("," if j < len(c["configuredMappings"]) - 1 else ""))
    lines += ["    ]", "  }", "}"]
    return "\n".join(lines) + "\n"


def generated_files(ds: NullMeridianDataset) -> dict[Path, str]:
    return {MANIFEST_PATH: render(manifest_document(ds)), CORRELATION_PATH: render_correlation(correlation_document(ds))}
