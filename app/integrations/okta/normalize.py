"""Parse raw Okta JSON objects into normalized records. Fails closed per record.

A record missing a required field raises ``MalformedRecord``. The listing counts it and
reports itself PARTIAL, because a record that cannot be read might be the one that
matters (for example an assignment). Optional fields that are missing or unreadable
become None.
"""

import base64
import binascii
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from app.integrations.okta.models import (
    AppStatus,
    GroupType,
    OktaAppGroupAssignmentRecord,
    OktaAppRecord,
    OktaGroupMemberRecord,
    OktaGroupRecord,
)

OKTA_ID_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")

# Decisions D23 and D30: Okta-derived AD objectGUID decoding stays unverified until a known
# AD-backed Okta group is shown to decode to exactly the objectGUID that AD independently
# reports for that group (this build has no live connection to show it). While False, the
# decoded value never reaches domain evidence, so no identity mapping can rest on it.
# Changing this is a reviewed source change; tests pin it.
OBJECT_GUID_DECODING_VERIFIED = False
_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")
_MAX_TEXT = 1000


class MalformedRecord(ValueError):
    """A raw object lacks a required field or has one in an unexpected form."""


def is_okta_id(value: object) -> bool:
    return isinstance(value, str) and OKTA_ID_RE.match(value) is not None


def _required_id(raw: dict, key: str = "id") -> str:
    value = raw.get(key)
    if not is_okta_id(value):
        raise MalformedRecord(f"missing or invalid {key}")
    return value


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value[:_MAX_TEXT]
    return None


def parse_timestamp(value: Any) -> datetime | None:
    """An Okta ISO-8601 timestamp as an aware datetime, or None if absent or unreadable."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def decode_object_guid(external_id: str | None) -> str | None:
    """Decode the AD agent's base64 externalId to a canonical objectGUID, else None.

    Assumption, to be verified against one known group before any mapping relies on it:
    the Okta AD agent stores objectGUID as base64 of its 16-byte little-endian (.NET
    Guid) form. A value that does not decode to exactly 16 bytes is not guessed at.
    """
    if not external_id:
        return None
    try:
        raw = base64.b64decode(external_id, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 16:
        return None
    return str(uuid.UUID(bytes_le=raw))


def normalize_app(raw: Any) -> OktaAppRecord:
    if not isinstance(raw, dict):
        raise MalformedRecord("application is not an object")
    status = raw.get("status")
    if status not in AppStatus.__members__:
        raise MalformedRecord("missing or unrecognised application status")
    return OktaAppRecord(
        okta_app_id=_required_id(raw),
        status=AppStatus(status),
        label=_text(raw.get("label")),
        name=_text(raw.get("name")),
        sign_on_mode=_text(raw.get("signOnMode")),
        created=parse_timestamp(raw.get("created")),
        last_updated=parse_timestamp(raw.get("lastUpdated")),
    )


def _source_app_id(raw: dict) -> str | None:
    href = _dict(_dict(_dict(raw.get("_links")).get("source"))).get("href")
    if not isinstance(href, str):
        return None
    segments = [s for s in urlsplit(href).path.split("/") if s]
    # Expected shape: /api/v1/apps/<appId>
    if len(segments) >= 4 and segments[-2] == "apps" and is_okta_id(segments[-1]):
        return segments[-1]
    return None


def normalize_group(raw: Any) -> OktaGroupRecord:
    if not isinstance(raw, dict):
        raise MalformedRecord("group is not an object")
    group_id = _required_id(raw)
    group_type = raw.get("type")
    if group_type not in GroupType.__members__:
        raise MalformedRecord("missing or unrecognised group type")
    profile = _dict(raw.get("profile"))
    name = _text(profile.get("name"))
    if name is None:
        raise MalformedRecord("group has no profile.name")
    common = dict(
        okta_group_id=group_id,
        name=name,
        group_type=GroupType(group_type),
        last_updated=parse_timestamp(raw.get("lastUpdated")),
        last_membership_updated=parse_timestamp(raw.get("lastMembershipUpdated")),
    )
    if group_type != GroupType.APP_GROUP:
        # Directory attributes are meaningful only on imported groups (domain rule).
        return OktaGroupRecord(**common)
    external_id = _text(profile.get("externalId"))
    sid = _text(profile.get("objectSid"))
    return OktaGroupRecord(
        **common,
        source_app_id=_source_app_id(raw),
        directory_external_id=external_id,
        directory_object_guid_unverified=decode_object_guid(external_id),
        directory_object_sid=sid if sid and _SID_RE.match(sid) else None,
        directory_qualified_name=_text(profile.get("windowsDomainQualifiedName")),
        distinguished_name=_text(profile.get("dn")),
        sam_account_name=_text(profile.get("samAccountName")),
    )


def normalize_assignment(raw: Any, okta_app_id: str) -> OktaAppGroupAssignmentRecord:
    if not isinstance(raw, dict):
        raise MalformedRecord("assignment is not an object")
    group_id = _required_id(raw)
    priority = raw.get("priority")
    embedded = _dict(raw.get("_embedded")).get("group")
    group = normalize_group(embedded) if embedded is not None else None
    if group is not None and group.okta_group_id != group_id:
        raise MalformedRecord("embedded group id does not match the assignment")
    return OktaAppGroupAssignmentRecord(
        okta_app_id=okta_app_id,
        okta_group_id=group_id,
        priority=priority if isinstance(priority, int) and not isinstance(priority, bool) else None,
        last_updated=parse_timestamp(raw.get("lastUpdated")),
        group=group,
    )


def normalize_member(raw: Any) -> OktaGroupMemberRecord:
    if not isinstance(raw, dict):
        raise MalformedRecord("member is not an object")
    # Only id and status leave this module; profile (name, email, login) is dropped.
    return OktaGroupMemberRecord(okta_user_id=_required_id(raw), status=_text(raw.get("status")))


@dataclass(frozen=True)
class SsoEvent:
    """The parts of one System Log SSO event that usage aggregation needs."""

    published: datetime
    actor_id: str | None
    app_ids: tuple[str, ...]


def normalize_sso_event(raw: Any) -> SsoEvent:
    if not isinstance(raw, dict):
        raise MalformedRecord("event is not an object")
    published = parse_timestamp(raw.get("published"))
    if published is None:
        raise MalformedRecord("event has no readable published time")
    actor_id = _dict(raw.get("actor")).get("id")
    targets = raw.get("target")
    app_ids = tuple(
        t["id"] for t in (targets if isinstance(targets, list) else [])
        if isinstance(t, dict) and t.get("type") == "AppInstance" and is_okta_id(t.get("id"))
    )
    return SsoEvent(published=published, actor_id=actor_id if is_okta_id(actor_id) else None, app_ids=app_ids)
