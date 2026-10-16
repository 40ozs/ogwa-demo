"""Directory-snapshot records: people, groups, applications, assignments, and governance findings.

Plain, frozen, and serialized in a fixed order. The synthetic Null Meridian dataset is built
from them; the governance analysis (``app.governance.analysis``) reads them.
"""

from dataclasses import dataclass, field, fields
from datetime import date, datetime
from typing import Any


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in sorted(value.items())}
    return value


class Record:
    """Serialization shared by every dataset record: camelCase keys, ISO dates, sorted maps."""

    def to_dict(self) -> dict[str, Any]:
        out = {}
        for f in fields(self):  # type: ignore[arg-type]
            head, *rest = f.name.split("_")
            out[head + "".join(p.capitalize() for p in rest)] = _plain(getattr(self, f.name))
        return out


@dataclass(frozen=True)
class Team(Record):
    slug: str
    name: str
    role: str
    ladder: tuple[str, ...]
    weights: tuple[int, ...]
    formed: date


@dataclass(frozen=True)
class Department(Record):
    id: str
    slug: str
    name: str
    size: int
    formed: date
    leader_title: str
    executive_owner: str  # the executive role key the department reports to
    feeder: str | None  # where its earliest people worked before it was formed
    teams: tuple[Team, ...]


@dataclass(frozen=True)
class Person(Record):
    id: str
    uuid: str
    employee_number: str
    first_name: str
    last_name: str
    display_name: str
    email: str
    upn: str
    sam_account_name: str
    department: str
    team: str | None
    title: str
    level: str  # executive, vp, director, manager, ic
    manager_id: str | None
    location: str
    status: str  # ACTIVE or TERMINATED
    hire_date: date
    termination_date: date | None
    okta_status: str  # ACTIVE, DEPROVISIONED, or NONE (left before Okta)
    okta_activated: date | None
    ad_account: str  # ENABLED or DISABLED
    is_people_manager: bool


@dataclass(frozen=True)
class EmploymentEvent(Record):
    id: str
    person_id: str
    on: date
    kind: str  # HIRED, PROMOTED, TITLE_CHANGED, TRANSFERRED, OKTA_ACTIVATED, TERMINATED, OKTA_DEACTIVATED
    department: str
    title: str
    detail: str


@dataclass(frozen=True)
class Application(Record):
    id: str
    uuid: str
    slug: str
    label: str
    category: str
    sign_on_mode: str
    provisioning: str
    status: str  # ACTIVE or INACTIVE
    adopted: date
    okta_integrated: date
    retired: date | None
    tiers: tuple[str, ...]
    admin_departments: tuple[str, ...]
    assignment_model: str  # GROUP, DIRECT, or MIXED
    standardized: date | None  # when sg-okta-* groups replaced the old ones, if ever
    owner_id: str | None
    owner_department: str
    okta_app_id: str
    usage_events_90d: int
    usage_users_90d: int


@dataclass(frozen=True)
class Group(Record):
    id: str
    uuid: str
    key: str
    name: str
    okta_name: str | None  # Okta's copy of the name, when Okta sees the group (may differ in case)
    source: str  # AD, OKTA, or BUILT_IN
    okta_visible: bool
    okta_group_type: str | None  # APP_GROUP, OKTA_GROUP, BUILT_IN
    okta_group_id: str | None
    kind: str  # APP_ACCESS, SHARE, DEPARTMENT, TEAM, ROLE, ALL_STAFF, PROJECT, BUILT_IN
    era: str
    naming_style: str
    created_at: datetime
    modified_at: datetime
    owner_id: str | None
    description: str
    application: str | None  # app slug, for APP_ACCESS groups
    tier: str | None
    department: str | None
    status: str  # ACTIVE, DEPRECATED, or DELETED_IN_AD (an Okta object whose AD target is gone)
    replaced_by: str | None  # group key
    ad_object_guid: str | None
    ad_sid: str | None
    ad_sam_account_name: str | None
    ad_distinguished_name: str | None
    ad_exists: bool
    okta_reports_sid: bool  # whether Okta's imported copy carries objectSid (0008)
    configured_mapping: bool  # listed in config/correlation.null-meridian.json
    correlation_case: str | None  # what the correlation engine is expected to prove, if Okta sees it
    admin_count: bool = False
    protected_from_deletion: bool = False
    push_target: str | None = None  # an Okta group pushed to AD: the key of its AD group


@dataclass(frozen=True)
class Assignment(Record):
    id: str
    application: str  # app slug
    group_key: str | None
    person_id: str | None
    tier: str | None
    created: date
    present: bool = True


@dataclass(frozen=True)
class Finding(Record):
    id: str
    code: str
    severity: str  # ACTIONABLE, QUESTIONABLE, INFO
    subject_kind: str  # GROUP, APPLICATION, PERSON
    subject_id: str
    subject_name: str
    summary: str
    recommendation: str
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Scenario(Record):
    key: str
    number: int
    title: str
    summary: str
    what_to_look_at: str
    group_keys: tuple[str, ...]
    application_slugs: tuple[str, ...]
    candidate_key: str | None
