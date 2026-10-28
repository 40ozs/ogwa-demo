"""Read-only views over the synthetic directory snapshot (migration 0012): people, directory
groups, membership paths, governance findings, and the demo's portfolio scenarios.

The snapshot is immutable once a store is seeded (append-only, at most one per store), so it
is loaded once per API instance and served from memory. Every SQL statement here is a SELECT;
a test pins that. A store without a snapshot (the classic demo world) answers
``available: false`` and empty lists, never an error.
"""

import json
import re
from datetime import date, timedelta
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from app.api.errors import ApiError, not_found
from app.api.validation import Page, Sort, sorted_by
from app.governance.index import DirectoryIndex
from app.store.store import Store

PERSON_ID_RE = re.compile(r"^psn_[0-9a-f]{32}$")
GROUP_ID_RE = re.compile(r"^dgrp_[0-9a-f]{32}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEVERITIES = ("ACTIONABLE", "QUESTIONABLE", "INFO")
HEALTH = ("ACTIONABLE", "QUESTIONABLE", "CLEAN")
PERSON_STATUSES = ("ACTIVE", "TERMINATED")
GROUP_SOURCES = ("AD", "OKTA", "BUILT_IN")
MAX_MEMBERS_LISTED = 200
MAX_ROUTES_LISTED = 300
SID_RE = re.compile(r"^S-1-5-21(?:-[0-9]{1,10}){4}$")
# Ranks, so severity and naming era sort by meaning rather than by spelling.
SEVERITY_RANK = {"CLEAN": 0, "INFO": 1, "QUESTIONABLE": 2, "ACTIONABLE": 3}
ERA_RANK = {"legacy-ad": 0, "app-specific": 1, "transitional-okta": 2, "modern": 3}


def _text(value: Any) -> str | None:
    return value.casefold() if isinstance(value, str) and value else None


# Sortable fields of each snapshot listing (``sort=``), keyed on the snapshot record as stored.
PEOPLE_SORT = {
    "displayName": lambda p: _text(p["displayName"]), "employeeNumber": lambda p: p["employeeNumber"],
    "email": lambda p: _text(p["email"]), "department": lambda p: _text(p["department"]),
    "title": lambda p: _text(p["title"]), "hireDate": lambda p: p["hireDate"], "status": lambda p: p["status"],
    "terminationDate": lambda p: p["terminationDate"],
}
GROUP_SORT = {
    "name": lambda g: _text(g["name"]), "source": lambda g: g["source"], "kind": lambda g: g["kind"],
    "era": lambda g: ERA_RANK.get(g["era"]), "createdAt": lambda g: g["createdAt"], "status": lambda g: g["status"],
    "effectiveMembers": lambda g: g["effectiveMembers"], "nestingDepth": lambda g: g["nestingDepth"],
    "health": lambda g: SEVERITY_RANK.get(g["health"]),
}
FINDING_SORT = {
    "severity": lambda f: SEVERITY_RANK.get(f["severity"]), "code": lambda f: f["code"],
    "subjectName": lambda f: _text(f["subjectName"]), "subjectKind": lambda f: f["subjectKind"],
}


def bad(message: str) -> ApiError:
    return ApiError(400, "MALFORMED_REQUEST", message)


def choice(query: dict[str, str], name: str, allowed: tuple[str, ...]) -> str | None:
    value = query.get(name)
    if value is not None and value not in allowed:
        raise bad(f"{name} must be one of {', '.join(allowed)}.")
    return value


def slug(query: dict[str, str], name: str) -> str | None:
    value = query.get(name)
    if value is not None and (len(value) > 60 or not SLUG_RE.match(value)):
        raise bad(f"{name} must be a lowercase slug.")
    return value


def search_text(query: dict[str, str]) -> str | None:
    value = query.get("q")
    if value is not None and not 1 <= len(value) <= 100:
        raise bad("q must be 1-100 characters.")
    return value.casefold() if value else None


@dataclass
class _Snapshot:
    info: dict[str, Any]
    company: dict[str, Any]
    departments: list[dict[str, Any]]
    people: dict[str, dict[str, Any]]
    people_order: list[str]
    events: dict[str, list[dict[str, Any]]]
    applications: dict[str, dict[str, Any]]  # by slug
    groups: dict[str, dict[str, Any]]  # by key
    group_order: list[str]
    group_by_id: dict[str, str]
    group_by_okta_ref: dict[str, str]
    nesting: list[tuple[str, str]]
    memberships: list[tuple[str, str]]
    assignments: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    findings_by_subject: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    scenarios: list[dict[str, Any]] = field(default_factory=list)

    @cached_property
    def group_by_ad_ref(self) -> dict[str, str]:
        return {g["adEvidenceId"]: k for k, g in self.groups.items() if g.get("adEvidenceId")}

    @cached_property
    def group_by_sid(self) -> dict[str, str]:
        return {g["adSid"]: k for k, g in self.groups.items() if g.get("adSid")}

    @cached_property
    def group_name_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for g in self.groups.values():
            counts[g["name"].casefold()] = counts.get(g["name"].casefold(), 0) + 1
        return counts

    @cached_property
    def deactivations(self) -> dict[str, Any]:
        """Deactivations per year of the snapshot's history, and in the 90 days before its date."""
        by_year: dict[str, int] = {}
        recent = 0
        as_of = str(self.info["asOf"])[:10]
        cutoff = (date.fromisoformat(as_of) - timedelta(days=90)).isoformat()
        for p in self.people.values():
            day = p.get("terminationDate")
            if p["status"] != "TERMINATED" or not day:
                continue
            by_year[day[:4]] = by_year.get(day[:4], 0) + 1
            recent += cutoff < day <= as_of
        return {"byYear": dict(sorted(by_year.items())), "last90Days": recent, "asOf": as_of}

    @cached_property
    def index(self) -> DirectoryIndex:
        return DirectoryIndex(
            group_kinds={k: g["kind"] for k, g in self.groups.items()}, nesting=self.nesting,
            memberships=self.memberships,
            active_people=[p for p, v in self.people.items() if v["status"] == "ACTIVE"],
            okta_people=[p for p, v in self.people.items() if v["status"] == "ACTIVE" and v["oktaStatus"] == "ACTIVE"],
            assignments=[(a["application"], a["groupKey"], a["personId"], a["tier"]) for a in self.assignments
                         if a["present"]])


class DirectoryView:
    def __init__(self, store: Store) -> None:
        self._store = store
        self._loaded = False
        self._snapshot: _Snapshot | None = None

    # --- loading --------------------------------------------------------------------------

    def preload(self) -> None:
        """Load the snapshot and its index now rather than on the first request."""
        snapshot = self._load()
        if snapshot is not None:
            snapshot.index  # noqa: B018 - a cached property; reading it builds the index

    def _load(self) -> _Snapshot | None:
        if self._loaded:
            return self._snapshot
        conn = self._store.connection
        info = conn.execute("SELECT id, dataset, seed, company, as_of, record_count, content_digest "
                            "FROM synthetic_directory_snapshots WHERE singleton = 1").fetchone()
        snap = None
        if info is not None:
            rows = conn.execute("SELECT kind, id, ref_a, ref_b, body FROM synthetic_directory_records "
                                "WHERE snapshot_id = ? ORDER BY kind, sort_key, id", (info["id"],)).fetchall()
            by_kind: dict[str, list] = {}
            for r in rows:
                by_kind.setdefault(r["kind"], []).append(r)
            body = lambda r: json.loads(r["body"])  # noqa: E731
            people = {r["id"]: body(r) for r in by_kind.get("PERSON", [])}
            events: dict[str, list] = {}
            for r in by_kind.get("EMPLOYMENT_EVENT", []):
                events.setdefault(r["ref_a"], []).append(body(r))
            groups = {r["ref_b"]: body(r) for r in by_kind.get("GROUP", [])}
            findings = [body(r) for r in by_kind.get("FINDING", [])]
            by_subject: dict[str, list] = {}
            for f in findings:
                by_subject.setdefault(f["subjectId"], []).append(f)
            company = body(by_kind["COMPANY"][0]) if by_kind.get("COMPANY") else {}
            snap = _Snapshot(
                info={"dataset": info["dataset"], "seed": info["seed"], "company": info["company"],
                      "asOf": info["as_of"], "recordCount": info["record_count"], "contentDigest": info["content_digest"]},
                company=company, departments=[body(r) for r in by_kind.get("DEPARTMENT", [])], people=people,
                people_order=[r["id"] for r in by_kind.get("PERSON", [])], events=events,
                applications={r["ref_a"]: body(r) for r in by_kind.get("APPLICATION", [])}, groups=groups,
                group_order=[r["ref_b"] for r in by_kind.get("GROUP", [])],
                group_by_id={g["id"]: k for k, g in groups.items()},
                group_by_okta_ref={g["oktaEvidenceId"]: k for k, g in groups.items() if g.get("oktaEvidenceId")},
                nesting=[(r["ref_a"], r["ref_b"]) for r in by_kind.get("NESTING", [])],
                memberships=[(r["ref_a"], r["ref_b"]) for r in by_kind.get("MEMBERSHIP", [])],
                assignments=[body(r) for r in by_kind.get("ASSIGNMENT", [])], findings=findings,
                findings_by_subject=by_subject, scenarios=[body(r) for r in by_kind.get("SCENARIO", [])])
        self._snapshot, self._loaded = snap, True
        return snap

    @property
    def available(self) -> bool:
        return self._load() is not None

    # --- shaping ------------------------------------------------------------------------------

    @staticmethod
    def person_summary(p: dict[str, Any]) -> dict[str, Any]:
        keep = ("id", "employeeNumber", "displayName", "email", "department", "team", "title", "level", "status",
                "hireDate", "terminationDate", "oktaStatus", "managerId")
        return {k: p[k] for k in keep}

    @staticmethod
    def group_summary(g: dict[str, Any]) -> dict[str, Any]:
        keep = ("id", "key", "name", "oktaName", "source", "kind", "era", "namingStyle", "createdAt", "modifiedAt",
                "status", "health", "effectiveMembers", "directMembers", "nestingDepth", "assignedTo", "application",
                "tier", "department", "oktaEvidenceId", "adEvidenceId", "correlationCase", "oktaVisible")
        return {k: g.get(k) for k in keep}

    @staticmethod
    def _qualifier(g: dict[str, Any]) -> str:
        """What tells two groups of the same name apart: the AD distinguished name, or the
        Okta group id, exactly as recorded (never derived from the name)."""
        if g["source"] == "AD" and g.get("adDistinguishedName"):
            return g["adDistinguishedName"]
        return g.get("oktaGroupId") or g["key"]

    def _naming(self, s: _Snapshot, g: dict[str, Any]) -> dict[str, Any]:
        return {"ambiguous": s.group_name_counts.get(g["name"].casefold(), 0) > 1, "qualifier": self._qualifier(g)}

    def _group_ref(self, s: _Snapshot, key: str | None) -> dict[str, Any] | None:
        if key is None or key not in s.groups:
            return None
        g = s.groups[key]
        return {"id": g["id"], "key": key, "name": g["name"], "kind": g["kind"], "health": g["health"],
                "source": g["source"], "status": g["status"], "oktaEvidenceId": g.get("oktaEvidenceId"),
                **self._naming(s, g)}

    def _person_ref(self, s: _Snapshot, pid: str | None) -> dict[str, Any] | None:
        if pid is None or pid not in s.people:
            return None
        p = s.people[pid]
        return {"id": pid, "displayName": p["displayName"], "title": p["title"], "status": p["status"],
                "department": p["department"]}

    # --- endpoints ------------------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        s = self._load()
        if s is None:
            return {"available": False, "note": "This store holds the classic lifecycle world; it has no directory "
                                                "snapshot. Seed the Genesee Press dataset to see people and groups."}
        counts = s.company.get("counts", {})
        return {"available": True, "snapshot": s.info, "profile": {k: v for k, v in s.company.items() if k != "counts"},
                "counts": counts, "departments": s.departments, "deactivations": s.deactivations,
                "applications": [{"id": a["id"], "slug": a["slug"], "label": a["label"], "category": a["category"],
                                  "status": a["status"], "health": a["health"], "entitledPeople": a["entitledPeople"],
                                  "standardized": a["standardized"], "assignmentModel": a["assignmentModel"],
                                  "signOnMode": a["signOnMode"], "provisioning": a["provisioning"]}
                                 for a in sorted(s.applications.values(), key=lambda a: a["label"].casefold())]}

    def people(self, page: Page, *, department: str | None, status: str | None, q: str | None,
               sort: Sort | None = None) -> dict[str, Any]:
        s = self._load()
        if s is None:
            return page.slice([])
        out = []
        for pid in s.people_order:
            p = s.people[pid]
            if department and p["department"] != department or status and p["status"] != status:
                continue
            if q and q not in p["displayName"].casefold() and q not in p["email"] and q not in p["employeeNumber"].casefold():
                continue
            out.append(p)
        listing = page.slice(sorted_by(out, sort, PEOPLE_SORT))  # filter, sort, page; then shape the page only
        return {**listing, "items": [self.person_summary(p) for p in listing["items"]]}

    def person(self, pid: str) -> dict[str, Any]:
        s = self._load()
        if s is None or not PERSON_ID_RE.match(pid) or pid not in s.people:
            raise not_found("person")
        p = s.people[pid]
        index = s.index
        reports = sorted((q for q in s.people.values() if q["managerId"] == pid and q["status"] == "ACTIVE"),
                         key=lambda q: q["employeeNumber"])
        routes = index.routes(pid)
        by_app: dict[str, list] = {}
        for r in routes[:MAX_ROUTES_LISTED]:
            by_app.setdefault(r.application, []).append(
                {"direct": r.direct, "chain": [self._group_ref(s, k) for k in r.chain]})
        access = []
        for slug_, items in sorted(by_app.items()):
            app = s.applications.get(slug_, {})
            access.append({"application": {"id": app.get("id"), "slug": slug_, "label": app.get("label", slug_),
                                           "status": app.get("status")},
                           "routes": items, "routeCount": len(items)})
        return {
            "person": p,
            "manager": self._person_ref(s, p["managerId"]),
            "directReports": [self._person_ref(s, q["id"]) for q in reports],
            "history": s.events.get(pid, []),
            "directGroups": [self._group_ref(s, k) for k in sorted(index.direct_groups(pid))],
            "access": access,
            "routesTruncated": len(routes) > MAX_ROUTES_LISTED,
            "findings": s.findings_by_subject.get(pid, []),
        }

    def groups(self, page: Page, *, era: str | None, health: str | None, source: str | None, q: str | None,
               sort: Sort | None = None) -> dict[str, Any]:
        s = self._load()
        if s is None:
            return page.slice([])
        out = []
        for key in s.group_order:
            g = s.groups[key]
            if era and g["era"] != era or health and g["health"] != health or source and g["source"] != source:
                continue
            if q and not self._matches(g, key, q):
                continue
            out.append(g)
        listing = page.slice(sorted_by(out, sort, GROUP_SORT))  # filter, sort, page; then shape the page only
        return {**listing, "items": [{**self.group_summary(g), **self._naming(s, g)} for g in listing["items"]]}

    @staticmethod
    def _matches(g: dict[str, Any], key: str, q: str) -> bool:
        """``q`` (already casefolded) against every name the group goes by, and every stable
        identifier it has: OGWA ids, objectSid, objectGUID, and the Okta group id."""
        names = (g["name"], g.get("oktaName"), g.get("adSamAccountName"), key)
        ids = (g["id"], g.get("adEvidenceId"), g.get("oktaEvidenceId"), g.get("adSid"), g.get("adObjectGuid"),
               g.get("oktaGroupId"))
        return any(q in n.casefold() for n in names if n) or any(q == i.casefold() for i in ids if i)

    def group(self, gid: str) -> dict[str, Any]:
        s = self._load()
        if s is None or not GROUP_ID_RE.match(gid) or gid not in s.group_by_id:
            raise not_found("directory group")
        return self._group_detail(s, s.group_by_id[gid])

    def group_for_okta_ref(self, okta_ref: str) -> dict[str, Any] | None:
        s = self._load()
        if s is None or okta_ref not in s.group_by_okta_ref:
            return None
        g = s.groups[s.group_by_okta_ref[okta_ref]]
        return {"id": g["id"], "era": g["era"], "namingStyle": g["namingStyle"], "createdAt": g["createdAt"],
                "health": g["health"], "status": g["status"], "effectiveMembers": g["effectiveMembers"]}

    def group_ref_for(self, ref: str) -> dict[str, Any] | None:
        """The snapshot group with this stable reference: its OGWA directory id, the OGWA id of
        its AD or Okta evidence, or its AD objectSid. Never a name."""
        s = self._load()
        if s is None:
            return None
        if GROUP_ID_RE.match(ref):
            key = s.group_by_id.get(ref)
        elif SID_RE.match(ref):
            key = s.group_by_sid.get(ref)
        else:
            key = s.group_by_ad_ref.get(ref) or s.group_by_okta_ref.get(ref)
        return self._group_ref(s, key)

    def person_ref_for(self, pid: str) -> dict[str, Any] | None:
        s = self._load()
        return None if s is None else self._person_ref(s, pid)

    def _group_detail(self, s: _Snapshot, key: str) -> dict[str, Any]:
        g = s.groups[key]
        index = s.index
        direct = sorted(index.direct_members(key), key=lambda p: s.people[p]["employeeNumber"])
        replaces = [self._group_ref(s, k) for k, o in sorted(s.groups.items()) if o.get("replacedBy") == key]
        sample = next(iter(sorted(index.effective(key), key=lambda p: s.people[p]["employeeNumber"])), None)
        return {
            "group": {**g, **self._naming(s, g)},
            "owner": self._person_ref(s, g.get("ownerId")),
            "parents": [self._group_ref(s, k) for k in index.parents(key)],
            "children": [self._group_ref(s, k) for k in index.children(key)],
            "replacedBy": self._group_ref(s, g.get("replacedBy")),
            "replaces": replaces,
            "pushTarget": self._group_ref(s, g.get("pushTarget")),
            "directMembers": [self._person_ref(s, p) for p in direct[:MAX_MEMBERS_LISTED]],
            "directMembersTruncated": len(direct) > MAX_MEMBERS_LISTED,
            "assignments": [{**a, "applicationLabel": s.applications.get(a["application"], {}).get("label")}
                            for a in s.assignments if a["groupKey"] == key],
            "findings": s.findings_by_subject.get(g["id"], []),
            "samplePath": None if sample is None else {
                "person": self._person_ref(s, sample),
                "chains": [[self._group_ref(s, k) for k in c] for c in index.chains(key, sample, limit=5)]},
        }

    def application_profile(self, application_id: str) -> dict[str, Any] | None:
        s = self._load()
        if s is None:
            return None
        app = next((a for a in s.applications.values() if a["id"] == application_id), None)
        if app is None:
            return None
        rows = [a for a in s.assignments if a["application"] == app["slug"]]
        return {
            "application": app,
            "owner": self._person_ref(s, app.get("ownerId")),
            "groupAssignments": [{**a, "group": self._group_ref(s, a["groupKey"])} for a in rows if a["groupKey"]],
            "directAssignments": [{**a, "person": self._person_ref(s, a["personId"])} for a in rows if a["personId"]],
            "findings": s.findings_by_subject.get(app["id"], []),
        }

    def findings(self, page: Page, *, severity: str | None, code: str | None, subject_kind: str | None,
                 sort: Sort | None = None) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
        s = self._load()
        if s is None:
            return page.slice([]), {}
        out = [f for f in s.findings if (not severity or f["severity"] == severity) and (not code or f["code"] == code)
               and (not subject_kind or f["subjectKind"] == subject_kind)]
        counts: dict[str, dict[str, int]] = {}
        for f in s.findings:
            counts.setdefault(f["severity"], {}).setdefault(f["code"], 0)
            counts[f["severity"]][f["code"]] += 1
        return page.slice(sorted_by(out, sort, FINDING_SORT)), counts

    def scenarios(self) -> list[dict[str, Any]]:
        s = self._load()
        if s is None:
            return []
        out = []
        for sc in s.scenarios:
            out.append({**sc, "groups": [self._group_ref(s, k) for k in sc["groupKeys"] if k in s.groups],
                        "applications": [{"id": s.applications[a]["id"], "slug": a, "label": s.applications[a]["label"]}
                                         for a in sc["applicationSlugs"] if a in s.applications]})
        return out
