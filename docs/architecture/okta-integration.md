# Okta integration (read-only)

This build contains the Okta record layer only: the normalized record models
(`app/integrations/okta/models.py`) and the parser that turns raw Okta JSON into them
(`app/integrations/okta/normalize.py`). Correlation uses the models; the demo never runs the
parser. The read-only Okta HTTP client, with its authentication, request pacing, System Log
usage collection, and evidence conversion, is not included in this build. Okta-shaped data in
the demo comes from the synthetic datasets ([Synthetic data](#synthetic-data)).

## Boundary

```text
lifecycle / correlation code
        │  normalized records, Listing/Lookup results
        ▼
app/integrations/okta/          ← raw Okta JSON never crosses this line
  models.py    normalized records and result containers
  normalize.py raw JSON → normalized records (fails closed per record)
```

The package does no I/O. Raw payloads stay inside it, and callers see only the records
below, which carry the fields lifecycle and correlation need and nothing else: no user
profiles, emails, or logins.

## Normalized records

Raw payloads are reduced to the fields that lifecycle and correlation need:

| Record | Kept | Dropped |
| --- | --- | --- |
| `OktaAppRecord` | id, status (`ACTIVE`/`INACTIVE`), label, name, signOnMode, created, lastUpdated | settings, credentials blocks, links |
| `OktaGroupRecord` | id, `profile.name`, type (`OKTA_GROUP`/`APP_GROUP`/`BUILT_IN`), lastUpdated, lastMembershipUpdated. For `APP_GROUP`: source app id (from `_links.source`), `externalId` (raw and decoded objectGUID), `objectSid` (kept only if it has SID form), `windowsDomainQualifiedName`, `dn`, `samAccountName` | description, other profile attributes |
| `OktaAppGroupAssignmentRecord` | app id, group id, priority, lastUpdated, optional embedded group (its id must match the assignment) | assignment profile |
| `OktaGroupMemberRecord` | user id, status | **all profile data** (login, email, names) |
| `SsoEvent` (in `normalize.py`) | published, actor id, AppInstance target ids | everything else. The System Log usage aggregation that consumed it is not included in this build |

Required fields (`id`, app `status`, group `type`, group `profile.name`, event
`published`) are checked per record, and ids must be Okta ids (1–64 alphanumeric
characters). A record that fails raises `MalformedRecord`. Missing or unreadable optional
fields become `None`: text is kept only if it is non-blank (cut at 1,000 characters), and a
timestamp only if it is ISO-8601 with a time-zone offset.

Directory attributes are kept only for `APP_GROUP` groups. The domain model forbids
them on other types.

**objectGUID decoding is unverified, and gated (D23, D30).**
`decode_object_guid` treats the AD agent's `externalId` as base64 of the 16-byte
little-endian (.NET `Guid`) form. A value that is not valid base64 of exactly 16 bytes is
left undecoded (`None`), not guessed at. The result is kept only on the normalized record,
as `directory_object_guid_unverified`. The byte-order assumption has not been checked
against a real AD-backed Okta group, so `OBJECT_GUID_DECODING_VERIFIED` (in
`normalize.py`) is `False`. While it is, `OktaGroupIdentity.from_record`
(`app/correlation/model.py`) drops the decoded value and `OktaGroupIdentity` refuses any
`directory_object_guid`, so **no identity mapping can rest on an Okta-derived GUID**.
Tests pin the flag. It may be set to `True` only after it has been shown, for a **known
AD-backed Okta group** whose objectGUID is independently known from Active Directory, that
the Okta metadata decodes to exactly that GUID, and that proof has been recorded.

## Completeness

Okta results are wrapped in containers that carry a `ResultStatus`:

- `Listing[T]` (one paged listing): `scope`, `items`, `status`, `pages`, `record_count`,
  `malformed_records`, `duplicates_dropped`, `stop_reason`, `error_code`,
  `error_summary`, `notes`. It is `COMPLETE` only when every page was read and every
  record parsed (an empty result can be complete). A listing that stopped early is
  `PARTIAL` (items so far) or `FAILED` (no usable items), with the reason. A malformed
  record makes the listing `PARTIAL`, because the unreadable record might be the one that
  matters.
- `Lookup[T]` (one object): `found=False` with `COMPLETE` is a definite "does not exist".
- `StopReason` says why a listing did not finish: `AUTHENTICATION`, `RATE_LIMITED`,
  `TIMEOUT`, `HTTP_ERROR`, `BUDGET_EXHAUSTED`, `MALFORMED_PAGE`, `UNSAFE_NEXT_LINK`,
  `PAGE_LIMIT`, `ITEM_LIMIT`, `NOT_FOUND`. It is finer-grained than
  `CollectorErrorCode`.

No Okta client in this build fills these containers. Domain evidence carries the same
`ResultStatus` in its provenance, and only COMPLETE results can drive a lifecycle
decision (invariant E-2).

## Synthetic data

The demo datasets (`app/demo/synthetic_world.py` for the classic world,
`app/demo/null_meridian/` for Null Meridian) write Okta-shaped domain evidence straight
into the SYNTHETIC store: `OktaApplication`, `OktaGroup`, `ApplicationGroupAssignment`, and
`ApplicationUsageObservation` records with Okta-format ids (`0oaSYNTH…` applications,
`00gSYNTH…` groups) and provenance scopes such as `synthetic:okta:group:<id>`. They do not
pass raw Okta JSON through `normalize.py`.

`SyntheticOktaProvider` (`app/runtime/providers.py`) reads this inventory back from the
store. For correlation, `okta_group_identity` (`app/demo/synthetic_directory.py`) builds an
`OktaGroupIdentity` from a stored `OktaGroup`. The same gates apply as for a normalized
record: the stored `directory_external_id` (Okta's rendering of the objectGUID) is never
passed on as `directory_object_guid` (D30), and Okta's objectSid is passed on only as an
unverified directory-source claim (D37).
