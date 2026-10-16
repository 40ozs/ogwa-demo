# Active Directory integration

OGWA reads Active Directory only through reports in a strict JSON contract. The Python side
lives in `app/integrations/ad/`:

- `contract.py`: the request and report schemas, lookup kinds, and limits;
- `assessment.py`: the emptiness facts and the protection status;
- `records.py`: conversion of a report to domain evidence.

The PowerShell reader (`OGWA.ADReader`) that produced such reports is not included in this
build. The golden fixtures in `tests/fixtures/ad/` are synthetic reports in the contract's
form. In the demo, AD evidence comes from the synthetic datasets, and identity lookups are
answered by the synthetic directory (`app/demo/synthetic_directory.py`).

## Boundary

```text
OGWA (Python)
  ADReadRequest.to_json()   ─────▶  one ogwa.ad.group-read-request/v1 document
                                    (report producer: not included in this build)
  parse_group_report()      ◀─────  one ogwa.ad.group-report/v1 document
  assess_emptiness / assess_protection
  ad_evidence → ADGroup + DependencyEvidence → Store
```

- `app/integrations/ad/` holds **no AD credential**, imports no network, process, or
  mutation code, and does no file I/O (`PythonBoundaryTests`).
- Both directions are validated strictly. Unknown keys, missing keys, wrong types, and
  out-of-range values raise `ContractError`, so contract drift fails closed instead of
  being read as "no members" or "not protected".

## Request: `ogwa.ad.group-read-request/v1`

```json
{
  "schema": "ogwa.ad.group-read-request/v1",
  "lookup": { "by": "objectGUID", "value": "5e7e7000-0000-4000-8000-000000104110", "domain": null },
  "include": { "directMembers": true, "nestedMembers": true, "primaryGroupReferences": true, "memberOf": true },
  "limits": { "maxDirectMembers": 1000, "maxNestedGroups": 100, "maxNestingDepth": 10,
              "maxPrimaryGroupReferences": 50, "maxParentGroups": 200, "maxAmbiguousCandidates": 10 }
}
```

- `lookup.by`: `objectGUID` or `objectSid` (stable; use these for decisions),
  `distinguishedName` (unique but changes on rename or move), `samAccountName`, or `name`
  (matches `name` or `sAMAccountName`; investigation only). `domain` optionally restricts
  the search to one forest domain.
- `ADReadRequest` defaults every `include` flag to true and every omitted limit to its
  default; `to_json()` always writes every key. `nestedMembers` requires `directMembers`.
- Refused with `ContractError`: an unknown lookup kind or limit; a value that is empty,
  longer than 1,024 characters, or has control characters or surrounding spaces; a
  malformed GUID or SID; a DN without a `DC=` component; a domain that is not a DNS name;
  a limit outside its range. A request echoed in a report must carry exactly these keys,
  in normalized form.

| Limit | Default | Ceiling | Effect when reached |
| --- | --- | --- | --- |
| `maxDirectMembers` | 1000 | 5000 | Members beyond it are counted but not classified; `Truncated` |
| `maxNestedGroups` | 100 | 500 | Nested expansion stops; `Truncated`, lower-bound count |
| `maxNestingDepth` | 10 | 20 | As above |
| `maxPrimaryGroupReferences` | 50 | 1000 | Counting stops; `Truncated`, lower-bound count |
| `maxParentGroups` | 200 | 1000 | `Truncated` |
| `maxAmbiguousCandidates` | 10 | 25 | Candidate list cut; `candidatesTruncated` |

## Report: `ogwa.ad.group-report/v1`

Top-level keys: `schema`, `worker` (`name` `OGWA.ADReader`, `version` `0.1.0`,
`readOnly: true`), `observedAt`, `request` (normalized echo, or null if invalid),
`forest`, `domains` (each with `contacted`, `reachable`, `error`), `resolution`, `group`,
`directMembers`, `nestedMembers`, `primaryGroupReferences`, `memberOf`, `protection`.
Every key is always present. The golden files in `tests/fixtures/ad/` are complete
examples.

`parse_group_report` also refuses: a report over 5,000,000 characters; another schema,
worker name, or version, or `readOnly` other than true; a missing request echo (allowed
only for `InvalidRequest`); a group on a report that is not `Resolved`, or none on one that
is; GUIDs not in canonical lowercase form; an `objectSid` that is not `domainSid`-`rid`; a
`builtinDomain` flag that disagrees with an `S-1-5-32-` SID; domain names that are not
lowercase DNS names; timestamps not in `YYYY-MM-DDTHH:MM:SSZ`; negative integers; `reachable`
set without `contacted` (or the reverse); and protection indicators outside the known set.

### Resolution

| Status | Meaning |
| --- | --- |
| `Resolved` | Exactly one group, proven unique. objectGUID, DN, and a domain SID are forest-unique, so one match settles it even if another domain was unreachable. Names (and builtin SIDs) require every domain in scope to be searched |
| `NotFound` | Every domain in scope was searched; nothing matched |
| `Ambiguous` | More than one group matched; candidates are listed |
| `Inconclusive` | A domain in scope could not be searched, so the result cannot be proven |
| `Failed` | A query failed, the reader could not run, or the group changed between search and read |
| `InvalidRequest` | The request was refused before any search |

### Sections

Each section has a `status`: `Complete`, `Truncated` (a limit was reached; counts are lower
bounds), `Partial` (something in scope could not be read), `Failed`, `NotRequested`, or
`NotApplicable` (the group was not resolved).

| Section | What it holds |
| --- | --- |
| `group` | objectGUID, objectSid, RID, domain SID, builtin flag, DN, sAMAccountName, name, domain, scope, category, `adminCount` (null if unset), `isCriticalSystemObject`, `protectedFromAccidentalDeletion` (**null if the security descriptor could not be read**), `primaryGroupToken`, timestamps |
| `directMembers` | Count of `member` values, counts per class (user, computer, group, FSP, contact, managed service account, other), member groups, unresolved members |
| `nestedMembers` | Expansion through member groups across domains: groups traversed, depth, principals reached plus objects using a nested group as their primary group, cycle flag, unexpanded references |
| `primaryGroupReferences` | Objects in the group's domain whose `primaryGroupID` is the group's RID |
| `memberOf` | Parent groups found in **every** forest domain (domain-local and universal parents can live anywhere); searched and unsearched domains |
| `protection` | Supporting indicators (`BuiltinDomainSid`, `WellKnownRid:<n>`, `AdminCount`, `CriticalSystemObject`, `ProtectedFromAccidentalDeletion`, `NestedInWellKnownGroup:<sid>`) and `Determined`/`Undetermined` |

## Emptiness (`ogwa-ad-empty/v1`)

Three facts, each `YES`, `NO`, or `UNKNOWN`. They are never collapsed into one boolean, and
each carries a statement of what was observed (`EmptinessAssessment.evidence`).

| Fact | YES when | NO when | Otherwise |
| --- | --- | --- | --- |
| `NoDirectMembers` | `member` has no values, read `Complete` | count > 0 (even if truncated) | UNKNOWN |
| `NoNestedMembers` | no principal or primary-group reference reached through member groups, `Complete` | count > 0 (a lower bound is enough) | UNKNOWN |
| `NoPrimaryGroupReferences` | no object has `primaryGroupID` = RID, `Complete` | count > 0 | UNKNOWN |

Verdict: `EMPTY` only if all three are YES; `NOT_EMPTY` if any is NO; otherwise
`UNDETERMINED`. A positive count is a fact even from an incomplete read, but zero proves
absence only from a complete one. Emptiness is independent of protection: the
`protected-group` scenario is `EMPTY` and `PROTECTED`.

## Protection

`assess_protection(report, ADProtectionPolicy)` returns `PROTECTED`, `NOT_PROTECTED`, or
`UNDETERMINED`. **Only `NOT_PROTECTED` permits retirement** (`blocks_retirement`).

Reasons (any one makes the group `PROTECTED`):

1. Durable identity: builtin-domain SID (`S-1-5-32-…`) or domain RID below 1000.
2. Nesting: a parent group with a well-known SID, or a configured protected parent.
3. Supporting attributes: `adminCount` set, `isCriticalSystemObject`,
   `ProtectedFromAccidentalDeletion`.
4. Configuration: objectGUID or SID denylist; privileged names (`DnsAdmins` and
   `DnsUpdateProxy` always, plus configured names; names only add protection); protected
   DN subtrees; a domain whose policy says `retirementAllowed: false`.
5. Any indicator in the report's `protection` section that OGWA did not derive itself
   (union, never subtraction).

Gaps (with no reason present, any gap makes the group `UNDETERMINED`):
`ProtectedFromAccidentalDeletion` unreadable; parent groups not fully read; the group's
domain has no OGWA protection policy (`governedDomains`); the report's protection facts
are `Undetermined`.

Policy configuration (shape; values synthetic), read by `ADProtectionPolicy.from_mapping`,
which refuses unknown keys:

```json
{
  "governedDomains": {
    "corp.synthetic.example": { "retirementAllowed": true, "protectedDnSuffixes": ["OU=Tier0,DC=corp,DC=synthetic,DC=example"] }
  },
  "protectedObjectGuids": [],
  "protectedSids": [],
  "protectedNames": []
}
```

## Domain evidence

`ad_evidence(report, policy=…, source=…, ids=ADStableIds(forest))` produces:

| Record | Content | COMPLETE only when |
| --- | --- | --- |
| `ADGroup` (resolved) | Identity, `admin_count`, `protected_from_accidental_deletion`, `is_critical_system_object`, `member_count` (direct) | Protection is not UNDETERMINED, and if PROTECTED, at least one reason is expressible in the record (well-known SID, adminCount, PFAD, critical). Otherwise PARTIAL, with `not_decision_grade` explaining why. The record never looks less protected than the assessment |
| `ADGroup(exists=False)` | Only for an objectGUID lookup that searched every domain | Always COMPLETE (a name not found proves nothing) |
| `DependencyEvidence(AD_GROUP_MEMBERS)` | Blocking findings for direct members and primary-group references | Both sections `Complete` |
| `DependencyEvidence(AD_NESTED_MEMBERSHIP)` | Blocking findings per parent (first 20, then a summary), member groups, nested principals; non-blocking cycle note | Both `nestedMembers` and `memberOf` `Complete` |

- Source is `AD_VIA_AAP` or `SYNTHETIC`; other sources are refused.
  `evidence_source_for_mode` gives `SYNTHETIC` for `LOCAL_SYNTHETIC`, the only execution
  mode of this build. `AD_VIA_AAP` is the source for reports read from a real directory.
- Internal ids derive from (forest, objectGUID), so a rename or move keeps the id, while
  the material digest changes (approvals are voided, A-2).
- `collector_result` maps a report to a `CollectorRunOutcome` status: `Inconclusive` →
  PARTIAL / `DOMAIN_UNREACHABLE`; `Failed`/`InvalidRequest` → FAILED / `OTHER`; otherwise
  COMPLETE only if every record is COMPLETE.
- A name-only match never becomes an exact identity mapping by itself (see
  [identity-correlation.md](identity-correlation.md)).

### Unverified live behaviors (owner decision D19)

Three behaviors of a live directory read cannot be proven without real AD. Until each one
is verified and added to `VERIFIED_LIVE_BEHAVIORS` in `records.py` (a reviewed source
change, empty today and pinned by tests), evidence from `AD_VIA_AAP` that depends on it is
capped at PARTIAL:

| Behavior | Evidence affected (real sources only) |
| --- | --- |
| `DELETION_PROTECTION_READABILITY` | Every resolved group: protection becomes UNDETERMINED unless a positive reason already makes it PROTECTED, so the `ADGroup` record is PARTIAL |
| `CROSS_DOMAIN_PARENT_LOOKUP` | Forests with more than one domain: `AD_NESTED_MEMBERSHIP` is PARTIAL, and protection is UNDETERMINED as above |
| `LARGE_GROUP_COMPLETENESS` | A direct count, or a nested principal count, of 1500 or more (the default LDAP `MaxValRange`): `AD_GROUP_MEMBERS` / `AD_NESTED_MEMBERSHIP` and `member_count` are PARTIAL |

`ADEvidence.unverified_live_behaviors` lists the gates applied. The emptiness facts are
unchanged (D20): a gate lowers decision grade, it never merges or rewrites facts.
Synthetic evidence is not gated. Unknown protection cannot be overridden (D21).

When protection is PROTECTED, the collector should divert the candidate to `PROTECTED`
(any state can move to a safer state with a reason, L-5). When it is UNDETERMINED, the
PARTIAL evidence keeps every forward guard closed (E-2, P-1).

## Tests

| Suite | Covers |
| --- | --- |
| `tests/test_ad_integration.py` | Contract strictness, requests, the golden scenarios, emptiness, protection, records, owner decisions D19/D21 |
| `tests/test_ad_contract_safety.py` | The Python boundary (no network, process, or mutation imports; no file I/O) and synthetic-only fixtures |

The golden reports in `tests/fixtures/ad/` are synthetic reports in the contract's form,
one per scenario. The Python suite parses every one of them, and identity correlation
tests read the same files.

## Known limits

- Not covered: parent groups in other forests through trusts (foreign security
  principals), and nested expansion into other forests. Foreign security principals count as
  members, so a group that has any is never `EMPTY`.
- Dependencies beyond membership (ACLs, GPOs, AAP, application configuration) are other
  dependency kinds. They are not collected here and stay uncovered.
