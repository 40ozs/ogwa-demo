# Identity correlation (Okta group ↔ AD group)

Status: P06. Implemented in `app/correlation/` and tested against a synthetic forest only
(D22). No Okta tenant, directory, or AAP job was contacted, and nothing here can write to
any of them.

Related: [domain-model.md](domain-model.md#mapping-confidence),
[ad-integration.md](ad-integration.md), [okta-integration.md](okta-integration.md),
[persistence.md](persistence.md), [../security/safety-invariants.md](../security/safety-invariants.md#identity-correlation-invariants-p06).

## Purpose and limits

Correlation answers one question for one Okta group: **which AD group is its
counterpart, and how sure are we?** It produces evidence for review. It does not
authorize anything:

- a correlation result is never a reason to unassign, disable, or delete;
- a name-only match is always `NAME_ONLY` and can never become exact by itself;
- a mapping that stops holding is reported, not repaired;
- the only write is an append to OGWA's own mapping-review registry, made by a human.

## Components

| Module | What it does |
| --- | --- |
| `model.py` | Inputs (`OktaGroupIdentity`, `CorrelationConfig`, `DirectorySource`, `ConfiguredMapping`), AD lookups (`ADIdentity`, `ADIdentityLookup`), outputs (`CorrelationResult`, `CorrelationOutcome`, `DriftFinding`) |
| `directory.py` | `ADIdentityDirectory` port; `ReportBackedDirectory` over the P05 worker contract; `BoundedLookups` (cap and cache per correlation) |
| `engine.py` | `correlate()`: claims, cross-checks, drift, outcome |
| `evidence.py` | `mapping_evidence()`: the `IdentityMapping` record the lifecycle reads |
| `review.py` | `MappingReviewService` (inspect, search, select, approve, reject) and the registries |
| `app/domain/mapping_review.py` | `MappingReview`, the persisted registry record, and its chain rules |
| `app/store/migrations/v0003_mapping_registry.py` | The `mapping_reviews` table and its guard triggers |

```text
OktaGroupIdentity ──┐
CorrelationConfig ──┼──► correlate() ──► CorrelationResult ──► mapping_evidence() ──► IdentityMapping (lifecycle)
review history ─────┘        │                   │
                             ▼                   └──► MappingReviewService ──► mapping_reviews (append-only)
                  BoundedLookups ──► ADIdentityDirectory
                                       └─ ReportBackedDirectory ──► P05 worker (via read-only AAP job; not built yet)
```

## Inputs

### Okta side

`OktaGroupIdentity.from_record()` takes a normalized P04 `OktaGroupRecord`. For an
`APP_GROUP` it keeps the source app id, `objectSid`, `windowsDomainQualifiedName`, `dn`, and
`samAccountName`. **The decoded objectGUID is dropped** while
`OBJECT_GUID_DECODING_VERIFIED` is `False` (D23, D30); constructing an identity that carries
one raises. `complete` records whether the Okta observation was COMPLETE.

Stored Okta group evidence keeps the `objectSid` as `directory_object_sid_unverified`
(migration 0008, owner decision before P09), with the observation's own provenance and
freshness. It is passed to the engine as the directory-source claim, which D37 governs: it
may corroborate an exact mapping established by a configured pairing or a reviewed
selection; on its own it gives `UNVERIFIED_IDENTIFIER` / `UNVERIFIED_STABLE_ID`, and a
mismatch with the other claims is a `CONFLICT`. The stored evidence has no DN.

### Configuration (`CorrelationConfig.from_mapping`, strict JSON)

```json
{
  "directorySources": [
    { "oktaAppId": "0oaSYNTHDIRCORP1", "domain": "corp.synthetic.example", "netbiosName": "SYNTHCORP" }
  ],
  "configuredMappings": [
    { "oktaGroupId": "00gSYNTH0003", "adObjectGuid": "5e7e7000-0000-4000-8000-000000004101",
      "adSid": "S-1-5-21-1000000001-1000000002-1000000003-4101", "domain": "corp.synthetic.example",
      "configurationRef": "config/mappings.json#payroll" }
  ],
  "maxLookups": 10,
  "maxCandidates": 10
}
```

- `directorySources`: the Okta AD integration instances and the domain each imports from.
  An `APP_GROUP` from any other source is `UNCONFIGURED_SOURCE` and gets no stable-id path.
- `configuredMappings`: the reviewed, version-controlled pairs. One entry per Okta group.
  `adObjectGuid` is required; `adSid` and `domain` narrow and cross-check the lookup.
- Unknown keys, duplicate sources, duplicate Okta groups, non-canonical GUIDs, and limits
  outside 1–16 lookups or 1–25 candidates are refused.

Where this configuration lives, and who reviews it, is an owner decision (see the P06
report).

### AD side

Correlation never queries AD. It calls an `ADIdentityDirectory`:
`lookup(by, value, domain) -> ADIdentityLookup`, one exact-match lookup.

`ReportBackedDirectory` implements it over the P05 contract: each lookup is one
`ADReadRequest` with **every membership section switched off**, so the worker only
resolves identity, and `maxAmbiguousCandidates` set from `maxCandidates`. The report's
request echo must match the lookup; any contract error, transport failure, or mismatched
echo becomes a `FAILED` lookup, never an answer. In production the transport will be the
approved read-only AAP job, which does not exist yet; P06 feeds it the golden worker
reports only.

`BoundedLookups` wraps the directory for one correlation: identical lookups are answered
once, and once `maxLookups` have been sent every further lookup is `FAILED` without
reaching the directory.

**Completeness is stricter than the worker's.** The worker reports `Resolved` for one
objectGUID or SID hit even when another domain was unreachable, because those identifiers
are forest-unique. For correlation a lookup is decision-grade (`complete`) only if it was
answered, every domain in scope was searched, and the candidate list was not truncated.
Stable-id lookups are scoped to one domain whenever the domain is known, so this costs
nothing in the normal case.

## Claims and priority

Correlation collects **claims** about the counterpart, strongest first:

| Priority | Claim | Lookup(s) | Method if it wins | Confidence |
| --- | --- | --- | --- | --- |
| 1 | `configured`: the configuration names an objectGUID | objectGUID in its domain (forest if none) | `CONFIGURED` | `EXACT_CONFIGURED_MAPPING` |
| 2 | `directory-source`: imported by a configured AD integration, carries `objectSid`, metadata consistent | objectSid in the integration's domain | `DIRECTORY_SOURCE_SID` | `EXACT_STABLE_ID` — **not a basis until P11 (D37)**; see below |
| 2′ | as above with objectGUID | objectGUID | `DIRECTORY_SOURCE_GUID` | `EXACT_STABLE_ID` — **unreachable until D30 is satisfied** |
| 3 | `approved-review`: a human approved an exact pairing earlier | objectGUID in its recorded domain, cross-checked against its SID | the approval's method; `OPERATOR_SELECTED` gives `EXACT_CONFIGURED_MAPPING` citing `ogwa-mapping-registry:<review id>` | as stored |

Every claim is resolved by stable identifier only. **All claims must name the same AD
object.** The strongest one only decides the reported method.

**Owner decision D37.** While `DIRECTORY_SOURCE_SID_VERIFIED` is `False` (until P11
validates the mechanism against a known AD-backed Okta group), a directory-source SID claim,
or an earlier approval recorded by that method, may *corroborate* an exact mapping but is
never its *basis*. The strongest remaining claim decides the method. If no other claim
exists, the result is `UNVERIFIED_IDENTIFIER` with confidence `UNVERIFIED_STABLE_ID`
(method `DIRECTORY_SOURCE_SID`, matched on `objectSid` plus Okta's corroborating name or DN).
D56 rules out calling it "name only": the object was identified by a stable identifier
whose mechanism is unverified, which is neither a name match nor exact. It cannot be
approved directly, and the classifier reports it as `MAPPING_UNVERIFIED_IDENTIFIER`
(`MAPPING_REQUIRED`). A rejection records method `DIRECTORY_SOURCE_SID`. The route to an exact
mapping is then an operator selection approved by a different operator (D38). The P06
tests of the directory-source-exact path now run with the gate patched on, which is the
post-P11 state. Separate tests pin the gated default.

A GUID claim is checked like this:

1. objectGUID in the claimed domain.
2. Not found there: objectGUID across the forest. Found elsewhere → `AD_GROUP_CHANGED_DOMAIN`.
3. Found, but its SID differs from the claimed SID → `AD_SID_MISMATCH`.
4. Not found, or SID differs: look the claimed SID up. It resolves to another object →
   `IDENTITY_REASSIGNED`.
5. Not found anywhere, every lookup complete → `MAPPING_UNRESOLVABLE`.

A directory-source SID claim must also be **corroborated** by Okta's own copy of the name:
at least one of Okta's `samAccountName` (or the name part of the qualified name) and `dn`
must equal the AD object's. A mismatch in one is `OKTA_DIRECTORY_METADATA_STALE`
(informational: Okta's import lags a rename or move). A mismatch in both is
`OKTA_METADATA_INCONSISTENT` (blocking).

### Okta source state

| State | When | Consequence |
| --- | --- | --- |
| `VERIFIABLE` | `APP_GROUP`, configured source, a stable id, at least one name to corroborate, no inconsistency | directory-source claim |
| `ABSENT` | AD-sourced but no stable id, or no name to corroborate it | no directory claim; name search unless another claim exists |
| `INCONSISTENT` | DN outside the source's domain, qualified name in another NetBIOS domain or disagreeing with `samAccountName`, malformed qualified name, a stable id without a source, a builtin-domain SID | `OKTA_METADATA_INCONSISTENT`; outcome `CONFLICT` even with a configured mapping |
| `UNCONFIGURED_SOURCE` | `APP_GROUP` from a source that is not a configured AD integration | name search only |
| `NOT_DIRECTORY` | Okta-mastered `OKTA_GROUP` | name search only (unless configured or approved) |
| `BUILT_IN` | `Everyone` and similar | `NOT_FOUND`, no lookups |

### Name fallback

Only when there is **no claim at all**: one forest-wide exact lookup by
`samAccountName` (Okta's, if it has one) or by `name`. Pairings an operator rejected are
excluded and listed in `previously_rejected`.

| Search result | Outcome |
| --- | --- |
| one match, complete | `REVIEW_REQUIRED` (`NAME_ONLY`) |
| two or more | `AMBIGUOUS` (`DUPLICATE_CANDIDATES`) |
| none, every domain searched | `NOT_FOUND` |
| a domain unsearched, fewer than two matches | `INCOMPLETE` |

## Outcomes

| Outcome | Meaning | Exact? |
| --- | --- | --- |
| `RESOLVED` | One AD object; every claim agrees; every lookup and the Okta observation complete; no blocking drift | yes |
| `REVIEW_REQUIRED` | One AD object by name only | no |
| `UNVERIFIED_IDENTIFIER` | One AD object by a directory-source objectSid whose mechanism is not verified until P11 (D37, D56) | no |
| `AMBIGUOUS` | Several possible AD objects | no |
| `NOT_FOUND` | No counterpart; every domain in scope searched | no |
| `STALE` | A configured, verified, or Okta-reported identity no longer holds (`MAPPING_UNRESOLVABLE`, `AD_SID_MISMATCH`, `IDENTITY_REASSIGNED`, `AD_GROUP_CHANGED_DOMAIN`) | no |
| `CONFLICT` | Evidence disagrees (`SOURCE_CONFLICT`, `REJECTED_PAIRING`, `OKTA_SOURCE_CHANGED`, `OKTA_METADATA_INCONSISTENT`, `CONFIGURATION_REMOVED`) | no |
| `INCOMPLETE` | A lookup, the lookup budget, or the Okta observation was incomplete | no |

Precedence: `CONFLICT` > `STALE` > `INCOMPLETE` > the rest.

### Never auto-resolved

| Situation | Result |
| --- | --- |
| Several AD groups share the name | `AMBIGUOUS` |
| Okta source metadata absent | name search: `NAME_ONLY` at best |
| Okta source metadata inconsistent | `CONFLICT` |
| A domain in scope could not be searched | `INCOMPLETE` |
| A prior approval conflicts with current identity | `CONFLICT` (`SOURCE_CONFLICT`) |
| A formerly mapped SID or GUID now points elsewhere | `STALE` (`IDENTITY_REASSIGNED`, `AD_GROUP_CHANGED_DOMAIN`, `AD_SID_MISMATCH`) |
| An operator rejected the pairing | `CONFLICT` (`REJECTED_PAIRING`) |
| An approval relied on Okta metadata that is now gone, or on a removed configuration entry | `CONFLICT` |

## Drift

| Drift | Blocking | Detected by |
| --- | --- | --- |
| `OKTA_GROUP_RENAMED` | no | Okta name ≠ name at approval |
| `AD_GROUP_RENAMED` | no | sAMAccountName ≠ at approval (same GUID and SID) |
| `AD_GROUP_MOVED` | no | DN ≠ at approval (same GUID and SID) |
| `OKTA_DIRECTORY_METADATA_STALE` | no | Okta's name or DN lags AD, the other corroborates |
| `AD_GROUP_CHANGED_DOMAIN` | yes | GUID found only in another domain |
| `AD_SID_MISMATCH` | yes | GUID found, SID differs |
| `IDENTITY_REASSIGNED` | yes | claimed SID resolves to another GUID |
| `MAPPING_UNRESOLVABLE` | yes | claimed identity not found, every lookup complete |
| `DUPLICATE_CANDIDATES` | yes | several name matches |
| `SOURCE_CONFLICT` | yes | claims name different AD objects |
| `REJECTED_PAIRING` | yes | the resolved object was rejected by an operator |
| `OKTA_SOURCE_CHANGED` | yes | approval by Okta metadata that is no longer verifiable |
| `OKTA_METADATA_INCONSISTENT` | yes | see source state |
| `CONFIGURATION_REMOVED` | yes | approved configured mapping no longer configured |

Informational drift keeps a `RESOLVED` outcome: the stable identifiers still prove it is
the same object. It is still surfaced, it changes the evidence fingerprint (so lifecycle
approvals made before it are void), and the stored review keeps the old names until a
human approves again (**re-acknowledgement**). Nothing updates a stored review.

## Evidence fingerprint

`CorrelationResult.evidence_fingerprint` is a SHA-256 over the Okta identity, outcome,
method, confidence, target and candidate identities, matched attributes, drift, every
lookup (kind, value, scope, status, candidate GUIDs, unsearched domains), the approval in
force, and the pending selection. Timestamps are excluded, so re-observing identical facts
keeps it; any material change alters it. Every review action requires the fingerprint the
operator saw.

## Emitted `IdentityMapping`

`mapping_evidence(result, source=AD_VIA_AAP | SYNTHETIC, ids=ADStableIds(forest))`.
The mapping id is stable per Okta group (`mapping_id_for`), so **every run supersedes the
previous mapping**; an unresolved run never leaves an earlier exact mapping in force.

| Outcome | Confidence | Result status |
| --- | --- | --- |
| `RESOLVED` | `EXACT_*` from the method (`EXACT_CONFIGURED_MAPPING` uses source `CONFIGURED_MAPPING`, or `SYNTHETIC`) | `COMPLETE` |
| `REVIEW_REQUIRED` | `NAME_ONLY` | `COMPLETE` |
| `UNVERIFIED_IDENTIFIER` | `UNVERIFIED_STABLE_ID` (D56) | `COMPLETE` |
| `AMBIGUOUS` | `AMBIGUOUS` | `COMPLETE` if complete, else `PARTIAL` |
| `NOT_FOUND` | `NOT_FOUND` | `COMPLETE` |
| `STALE`, identity simply gone | `NOT_FOUND` | `COMPLETE` |
| other `STALE`, `CONFLICT` | `AMBIGUOUS` (≥ 2 objects) or `NOT_FOUND` | `FAILED` |
| `INCOMPLETE` | `AMBIGUOUS` (≥ 2 objects) or `NOT_FOUND` | `PARTIAL` |

`observed_at` is the oldest input (Okta observation or AD lookup), so freshness rules
apply to the weakest link. The lifecycle guards already allow only `EXACT_*` with
`COMPLETE` past review (M-1, M-2, E-2).

In the synthetic demo the ids come from the store's own AD group evidence
(`app.demo.synthetic_directory.StoreADGroupIds`; `ids` accepts any `ADGroupIds`), and the
demo's mapping evidence is made only this way (D75): `correlate_stored_group` runs the engine
over the synthetic directory with `config/correlation.synthetic.json`, whose configured
pairings name objectGUID and objectSid (D76). The seed records exactly what the engine
returns and stops if a scenario does not correlate as it expects. A group the configuration
does not name reaches only the name search, so it stays review-required (D78); no
verification gate is changed for the demo (D77).

`required_ad_object_guids` lists the AD objects the mapping references. Their `ADGroup`
evidence must be recorded from a **full** read-only AD read (P05 `ad_evidence`) before the
mapping can be stored; the store's foreign keys enforce it. Correlation never fabricates
an `ADGroup` record from an identity-only lookup, because such a record would look less
protected than the group may be.

## Operator review (service contract)

`MappingReviewService(directory, config, registry, clock)`. It is reached through the API's
`/mappings/{groupId}/…` routes. The operator UI (P09) shows mapping evidence and review history
read-only; it offers no mapping review action (see [ui.md](ui.md)).

| Call | Who | Rules | Records |
| --- | --- | --- | --- |
| `inspect(okta)` | anyone | re-runs correlation; returns result, history, `allowed_actions`, `approvable_guid` | nothing |
| `search(okta, operator, by, value, domain)` | human | one bounded exact-match lookup (`objectGUID`, `objectSid`, `distinguishedName`, `samAccountName`, `name`); no wildcards reach the worker | nothing |
| `select(okta, operator, search, object_guid, reason)` | human | the GUID must be in the search result; the search must be ≤ 30 minutes old; the object is re-verified by objectGUID in its own domain, and its SID must be unchanged | `PROPOSED`, `OPERATOR_SELECTED` |
| `approve(okta, operator, object_guid, expected_fingerprint, reason)` | human | fingerprint must match; either the correlation is `RESOLVED` to that object (new approval, or re-acknowledgement of drift), or it is the pending selection, re-verified, contradicting no other claim, and approved by a **different** human | `APPROVED` |
| `reject(okta, operator, object_guid, expected_fingerprint, reason)` | human | fingerprint must match; the object must be on screen (target, candidate, approval, or pending selection) | `REJECTED` |

`NAME_ONLY` cannot be approved: the operator must select the AD object explicitly, and a
second operator approves the selection. A rejection withdraws an approval of the same
object and stops future auto-resolution to it. Refusals raise `ReviewRefused` and record
nothing.

## Persistence (`mapping_reviews`, migration 0003)

One append-only chain per Okta group. Columns: `okta_group_ref`, `okta_group_id`,
`okta_group_name`, `sequence`, `supersedes`, `ad_object_guid`, `ad_sid`,
`ad_distinguished_name`, `ad_sam_account_name`, `ad_domain`, `method`, `confidence`,
`review_status`, `verified_at`, `evidence_fingerprint`, `decided_by_*`, `decided_at`,
`reason`, `configuration_ref`, `recorded_at`, `correlation_id`.

The database refuses: `UPDATE` and `DELETE`; a row that does not extend its group's chain
(sequence, `supersedes`, or an earlier `decided_at`); `APPROVED` with a non-exact confidence
or `NAME_MATCH`; `PROPOSED` for anything but an operator selection; a non-human reviewer;
and an approval of an operator selection that is neither the pending selection from a
different reviewer nor a re-acknowledgement of the same approved identity. Each review is
audited in the same transaction as `MAPPING_REVIEW_RECORDED` (migration 0005, D41). Reviews
audited before 0005 keep `APPROVAL_RECORDED` with details `kind: IDENTITY_MAPPING_REVIEW`,
unchanged. `verify_integrity` re-checks
every chain. Like 0002, the migration has no PostgreSQL implementation and refuses to run
there.

## Not covered yet

- Real transport for `ReportBackedDirectory` (the read-only AAP job, P05 §7) and any live
  lookup (P11, D18).
- Okta-side verification that `profile.objectSid` equals AD's `objectSid` for a known
  group. Gated by `DIRECTORY_SOURCE_SID_VERIFIED` (D37) until P11 verifies it on the same
  known group as D30.
- Trusts and other forests: only the configured forest is searched.
- Where the configuration lives and who reviews it.
- A dedicated audit action for mapping reviews (needs an audit-table migration).
