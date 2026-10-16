"""0008 — Okta's directory objectSid, stored as unverified source metadata.

Owner decision: persist the objectSid that Okta's AD integration reports for an
imported group (``profile.objectSid``), explicitly as *unverified source metadata*. It is
not mapping evidence. D37 stays authoritative: on its own it cannot establish an exact
mapping until the mechanism is validated against a known AD-backed Okta group.

It is one more column of ``okta_group_observations``, so each value carries that
observation's provenance (source, observed_at, scope, collector version, result status)
and ages under the existing freshness rules. Nothing else changes:

1. ``ALTER TABLE … ADD COLUMN``: existing rows keep every value and gain NULL. Their
   digests are unchanged, because ``OktaGroup.material()`` includes the value only when
   it is present.
2. The CHECK allows a value only on an ``APP_GROUP`` row, and only in SID shape.
3. The append-only triggers of 0002 still cover the table (they are per table, not per
   column).

Only SQLite is implemented; like 0002–0007, this migration refuses to run on PostgreSQL.

NEVER EDIT THIS FILE AFTER IT HAS BEEN APPLIED ANYWHERE. Add a new migration instead.
"""

VERSION = 8
NAME = "okta_directory_sid"

COLUMN = "directory_object_sid_unverified"

STATEMENTS: list[str] = []

_SQLITE = [
    f"ALTER TABLE okta_group_observations ADD COLUMN {COLUMN} TEXT CHECK ({COLUMN} IS NULL OR "
    f"(group_type = 'APP_GROUP' AND length({COLUMN}) BETWEEN 7 AND 200 AND {COLUMN} GLOB 'S-1-[0-9]*-[0-9]*' "
    f"AND {COLUMN} NOT GLOB '*[^-S0-9]*'))",
]

# No "postgresql" entry: the runner refuses to apply this migration there.
DIALECT_STATEMENTS: dict[str, list[str]] = {"sqlite": _SQLITE}
