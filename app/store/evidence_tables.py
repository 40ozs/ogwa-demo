"""Mapping between evidence records and their tables.

Each evidence type has an anchor table (one row per internal id, holding the immutable
natural key) and an observation table (one append-only row per observation). Re-observing
an object adds an observation; it never overwrites the previous one.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.domain.evidence import Evidence, EvidenceSource, Provenance, ResultStatus
from app.domain.ids import IdKind
from app.domain.model import (
    ADGroup,
    ApplicationGroupAssignment,
    ApplicationUsageObservation,
    DependencyEvidence,
    DependencyFinding,
    DependencyKind,
    FindingCode,
    IdentityMapping,
    MappingConfidence,
    OktaApplication,
    OktaAppStatus,
    OktaGroup,
    OktaGroupType,
)
from app.store import codec
from app.store.codec import flag, parse_ts, ts, unflag

APP_WIDE_SCOPE = "*"


def provenance_from(row: sqlite3.Row) -> Provenance:
    return Provenance(
        source=EvidenceSource(row["source"]),
        observed_at=parse_ts(row["observed_at"]),
        scope=row["scope"],
        collector_version=row["collector_version"],
        result_status=ResultStatus(row["result_status"]),
    )


@dataclass(frozen=True)
class EvidenceSpec:
    cls: type
    anchor_table: str
    observation_table: str
    entity_column: str  # the observation table's reference to the anchor
    anchor_values: Callable[[Any], dict[str, Any]]  # immutable natural-key columns, excluding id
    observation_values: Callable[[Any], dict[str, Any]]
    build: Callable[[sqlite3.Connection, sqlite3.Row, sqlite3.Row], Evidence]
    write_children: Callable[[sqlite3.Connection, str, Any], None] | None = None


# --- builders -------------------------------------------------------------------------


def _application(conn, anchor, obs) -> OktaApplication:
    return OktaApplication(
        id=anchor["id"], okta_app_id=anchor["okta_app_id"], label=obs["label"], status=OktaAppStatus(obs["status"]),
        sign_on_mode=obs["sign_on_mode"], provenance=provenance_from(obs),
    )


def _group(conn, anchor, obs) -> OktaGroup:
    return OktaGroup(
        id=anchor["id"], okta_group_id=anchor["okta_group_id"], name=obs["name"], group_type=OktaGroupType(obs["group_type"]),
        provenance=provenance_from(obs), source_directory_id=obs["source_directory_id"],
        directory_external_id=obs["directory_external_id"], directory_qualified_name=obs["directory_qualified_name"],
        directory_object_sid_unverified=obs["directory_object_sid_unverified"],
    )


def _assignment(conn, anchor, obs) -> ApplicationGroupAssignment:
    return ApplicationGroupAssignment(
        id=anchor["id"], application_id=anchor["application_id"], okta_group_id=anchor["group_id"],
        present=unflag(obs["present"]), provenance=provenance_from(obs),
    )


def _usage(conn, anchor, obs) -> ApplicationUsageObservation:
    return ApplicationUsageObservation(
        id=anchor["id"], application_id=anchor["application_id"], okta_group_id=anchor["group_id"],
        window_start=parse_ts(obs["window_start"]), window_end=parse_ts(obs["window_end"]), event_count=obs["event_count"],
        distinct_user_count=obs["distinct_user_count"], last_activity_at=parse_ts(obs["last_activity_at"]),
        provenance=provenance_from(obs),
    )


def _ad_group(conn, anchor, obs) -> ADGroup:
    return ADGroup(
        id=anchor["id"], object_guid=anchor["object_guid"], domain=obs["domain"], exists=unflag(obs["group_exists"]),
        provenance=provenance_from(obs), sid=obs["sid"], distinguished_name=obs["distinguished_name"],
        sam_account_name=obs["sam_account_name"], admin_count=unflag(obs["admin_count"]),
        protected_from_accidental_deletion=unflag(obs["protected_from_accidental_deletion"]),
        is_critical_system_object=unflag(obs["is_critical_system_object"]), member_count=obs["member_count"],
    )


def _mapping(conn, anchor, obs) -> IdentityMapping:
    candidates = conn.execute(
        "SELECT ad_group_id FROM identity_mapping_candidates WHERE observation_id = ? ORDER BY ordinal",
        (obs["observation_id"],),
    ).fetchall()
    return IdentityMapping(
        id=anchor["id"], okta_group_id=anchor["group_id"], confidence=MappingConfidence(obs["confidence"]),
        ad_group_id=obs["ad_group_id"], reason=obs["reason"], provenance=provenance_from(obs),
        matched_attributes=codec.str_tuple(obs["matched_attributes"]),
        candidate_ad_group_ids=tuple(r["ad_group_id"] for r in candidates), configuration_ref=obs["configuration_ref"],
    )


def _mapping_children(conn, observation_id: str, record: IdentityMapping) -> None:
    for ordinal, ad_group_id in enumerate(record.candidate_ad_group_ids):
        conn.execute(
            "INSERT INTO identity_mapping_candidates (observation_id, ordinal, ad_group_id) VALUES (?, ?, ?)",
            (observation_id, ordinal, ad_group_id),
        )


def _dependency(conn, anchor, obs) -> DependencyEvidence:
    findings = conn.execute(
        "SELECT description, blocking, reference, code FROM dependency_findings WHERE observation_id = ? ORDER BY ordinal",
        (obs["observation_id"],),
    ).fetchall()
    return DependencyEvidence(
        id=anchor["id"], subject_id=anchor["subject_id"], kind=DependencyKind(anchor["kind"]),
        findings=tuple(
            DependencyFinding(f["description"], unflag(f["blocking"]), f["reference"],
                              FindingCode(f["code"]) if f["code"] is not None else None)
            for f in findings
        ),
        provenance=provenance_from(obs),
    )


def _dependency_children(conn, observation_id: str, record: DependencyEvidence) -> None:
    for ordinal, finding in enumerate(record.findings):
        conn.execute(
            "INSERT INTO dependency_findings (observation_id, ordinal, description, blocking, reference, code) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (observation_id, ordinal, finding.description, flag(finding.blocking), finding.reference,
             finding.code.value if finding.code else None),
        )


def _dependency_anchor(record: DependencyEvidence) -> dict[str, Any]:
    on_group = record.subject_id.startswith(IdKind.OKTA_GROUP.value + "_")
    return {
        "subject_id": record.subject_id,
        "subject_group_id": record.subject_id if on_group else None,
        "subject_ad_group_id": None if on_group else record.subject_id,
        "kind": record.kind.value,
    }


SPECS: tuple[EvidenceSpec, ...] = (
    EvidenceSpec(
        OktaApplication, "okta_applications", "okta_application_observations", "application_id",
        lambda r: {"okta_app_id": r.okta_app_id},
        lambda r: {"label": r.label, "status": r.status.value, "sign_on_mode": r.sign_on_mode},
        _application,
    ),
    EvidenceSpec(
        OktaGroup, "okta_groups", "okta_group_observations", "group_id",
        lambda r: {"okta_group_id": r.okta_group_id},
        lambda r: {
            "name": r.name, "group_type": r.group_type.value, "source_directory_id": r.source_directory_id,
            "directory_external_id": r.directory_external_id, "directory_qualified_name": r.directory_qualified_name,
            "directory_object_sid_unverified": r.directory_object_sid_unverified,
        },
        _group,
    ),
    EvidenceSpec(
        ApplicationGroupAssignment, "app_group_assignments", "assignment_observations", "assignment_id",
        lambda r: {"application_id": r.application_id, "group_id": r.okta_group_id},
        lambda r: {"present": flag(r.present)},
        _assignment,
    ),
    EvidenceSpec(
        ApplicationUsageObservation, "usage_scopes", "usage_observations", "usage_id",
        lambda r: {"application_id": r.application_id, "group_id": r.okta_group_id, "scope_key": r.okta_group_id or APP_WIDE_SCOPE},
        lambda r: {
            "window_start": ts(r.window_start), "window_end": ts(r.window_end), "event_count": r.event_count,
            "distinct_user_count": r.distinct_user_count, "last_activity_at": ts(r.last_activity_at),
        },
        _usage,
    ),
    EvidenceSpec(
        ADGroup, "ad_groups", "ad_group_observations", "ad_group_id",
        lambda r: {"object_guid": r.object_guid},
        lambda r: {
            "domain": r.domain, "group_exists": flag(r.exists), "sid": r.sid, "distinguished_name": r.distinguished_name,
            "sam_account_name": r.sam_account_name, "admin_count": flag(r.admin_count),
            "protected_from_accidental_deletion": flag(r.protected_from_accidental_deletion),
            "is_critical_system_object": flag(r.is_critical_system_object), "member_count": r.member_count,
        },
        _ad_group,
    ),
    EvidenceSpec(
        IdentityMapping, "identity_mappings", "identity_mapping_observations", "mapping_id",
        lambda r: {"group_id": r.okta_group_id},
        lambda r: {
            "confidence": r.confidence.value, "ad_group_id": r.ad_group_id, "reason": r.reason,
            "matched_attributes": codec.json_text(list(r.matched_attributes)), "configuration_ref": r.configuration_ref,
        },
        _mapping,
        _mapping_children,
    ),
    EvidenceSpec(
        DependencyEvidence, "dependency_checks", "dependency_observations", "check_id",
        _dependency_anchor,
        lambda r: {},
        _dependency,
        _dependency_children,
    ),
)

SPEC_BY_CLASS: dict[type, EvidenceSpec] = {s.cls: s for s in SPECS}


def spec_for(record_or_class: object) -> EvidenceSpec:
    cls = record_or_class if isinstance(record_or_class, type) else type(record_or_class)
    spec = SPEC_BY_CLASS.get(cls)
    if spec is None:
        raise TypeError(f"{cls.__name__} is not a stored evidence type")
    return spec
