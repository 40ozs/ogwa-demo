"""0003 — the identity-mapping review registry (P06).

One append-only chain of human review events per Okta group: PROPOSED (an operator
selected a pairing), APPROVED (an exact, verified pairing), REJECTED. A row is never
updated or deleted; a later row supersedes the earlier one. The database itself refuses a
row that does not extend its group's chain, an approval of a non-exact pairing, an
approval of a name-only match, and a non-human reviewer.

Only SQLite has the guard triggers; like 0002, this migration refuses to run on
PostgreSQL until equivalent guards exist (fail closed).

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

from app.store.migrations.v0001_core_schema import (
    CONFIDENCES,
    actor,
    digest,
    enum,
    internal_id,
    table,
    text,
    ts,
)

VERSION = 3
NAME = "mapping_registry"

# Frozen with this migration; a test compares them with the domain enums.
MAPPING_METHODS = ("CONFIGURED", "DIRECTORY_SOURCE_SID", "DIRECTORY_SOURCE_GUID", "OPERATOR_SELECTED", "NAME_MATCH")
REVIEW_STATUSES = ("PROPOSED", "APPROVED", "REJECTED")
EXACT = ("EXACT_STABLE_ID", "EXACT_DIRECTORY_SOURCE", "EXACT_CONFIGURED_MAPPING")

STATEMENTS: list[str] = [
    table(
        "mapping_reviews",
        internal_id("id", "mrev", pk=True),
        internal_id("okta_group_ref", "ogrp") + " REFERENCES okta_groups (id)",
        text("okta_group_id", 64),
        text("okta_group_name", 300),
        "sequence INTEGER NOT NULL CHECK (sequence >= 0)",
        internal_id("supersedes", "mrev", null=True) + " REFERENCES mapping_reviews (id)",
        "ad_object_guid TEXT NOT NULL CHECK (length(ad_object_guid) = 36 AND ad_object_guid = lower(ad_object_guid))",
        "ad_sid TEXT NOT NULL CHECK (substr(ad_sid, 1, 4) = 'S-1-' AND length(ad_sid) BETWEEN 7 AND 200)",
        text("ad_distinguished_name", 1000),
        text("ad_sam_account_name", 256),
        "ad_domain TEXT NOT NULL CHECK (length(ad_domain) BETWEEN 1 AND 255 AND ad_domain = lower(ad_domain))",
        enum("method", MAPPING_METHODS),
        enum("confidence", CONFIDENCES),
        enum("review_status", REVIEW_STATUSES),
        ts("verified_at"),
        digest("evidence_fingerprint"),
        *actor("decided_by", human_only=True),
        ts("decided_at"),
        text("reason", 2000),
        text("configuration_ref", 300, null=True),
        ts("recorded_at"),
        text("correlation_id", 100),
        "UNIQUE (okta_group_ref, sequence)",
        "CHECK ((sequence = 0) = (supersedes IS NULL))",
        "CHECK (verified_at <= decided_at)",
        f"CHECK (review_status <> 'APPROVED' OR confidence IN ({', '.join(repr(c) for c in EXACT)}))",
        "CHECK (review_status <> 'APPROVED' OR method <> 'NAME_MATCH')",
        "CHECK (review_status <> 'PROPOSED' OR method = 'OPERATOR_SELECTED')",
        "CHECK ((method = 'CONFIGURED') = (configuration_ref IS NOT NULL))",
    ),
    "CREATE INDEX ix_mapping_reviews_guid ON mapping_reviews (ad_object_guid)",
]


def _refuse(name: str, timing: str, message: str, when: str | None = None) -> str:
    assert "'" not in message, "trigger messages are embedded in single-quoted SQL"
    condition = f"\nWHEN {when}" if when else ""
    return (
        f"CREATE TRIGGER {name} {timing} ON mapping_reviews{condition}\n"
        f"BEGIN\n    SELECT RAISE(ABORT, '{message}');\nEND"
    )


_SQLITE = [
    _refuse("trg_mapping_reviews_no_update", "BEFORE UPDATE", "mapping_reviews is append-only"),
    _refuse("trg_mapping_reviews_no_delete", "BEFORE DELETE", "mapping_reviews is append-only"),
    _refuse(
        "trg_mapping_reviews_chain", "BEFORE INSERT", "a mapping review must extend its Okta group chain",
        "NEW.sequence <> (SELECT count(*) FROM mapping_reviews WHERE okta_group_ref = NEW.okta_group_ref) "
        "OR NEW.supersedes IS NOT (SELECT id FROM mapping_reviews WHERE okta_group_ref = NEW.okta_group_ref "
        "ORDER BY sequence DESC LIMIT 1) "
        "OR NEW.decided_at < coalesce((SELECT max(decided_at) FROM mapping_reviews "
        "WHERE okta_group_ref = NEW.okta_group_ref), NEW.decided_at)",
    ),
    _refuse(
        "trg_mapping_reviews_four_eyes", "BEFORE INSERT", "an operator selection needs a different approver",
        # Approving an operator selection: the superseded review is that selection, made by
        # someone else, or the same approved identity being re-acknowledged after drift.
        "NEW.review_status = 'APPROVED' AND NEW.method = 'OPERATOR_SELECTED' AND NOT EXISTS ("
        "SELECT 1 FROM mapping_reviews p WHERE p.id = NEW.supersedes "
        "AND p.ad_object_guid = NEW.ad_object_guid AND p.ad_sid = NEW.ad_sid AND ("
        "(p.review_status = 'PROPOSED' AND p.decided_by_id <> NEW.decided_by_id) "
        "OR (p.review_status = 'APPROVED' AND p.method = 'OPERATOR_SELECTED')))",
    ),
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
