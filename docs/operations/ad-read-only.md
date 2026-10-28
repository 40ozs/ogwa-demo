# AD read-only operations

How to run the OGWA AD reader safely. Design and contract:
[../architecture/ad-integration.md](../architecture/ad-integration.md).

**Status (P05): no live read has been performed.** The reader has been tested only against
a synthetic directory. Production mutation is not authorized by this build, and the
reader has no way to perform it.

## What the reader can and cannot do

- It reads **one group per request**: identity, members, nesting, primary-group
  references, parent groups, and protection attributes.
- It uses only `Get-ADForest`, `Get-ADDomain`, `Get-ADDomainController`, `Get-ADGroup`, and
  `Get-ADObject`. Every search has an explicit result-size limit and targets one domain
  controller of one domain.
- It does not enumerate a forest's groups or users, it writes no files, and it takes no
  credential. It runs as the calling identity.

## Prerequisites for a live read

All of these must be true. If any is not, do not run a live read.

1. **Authorized host.** An AAP Windows execution host, or a management server that the AD
   owners approve for read-only queries, with the ActiveDirectory (RSAT) module installed.
   This developer workstation does not have RSAT. Do not install RSAT locally without
   authorization (D17).
2. **Read-only identity.** The account (normally the AAP machine credential) has
   directory read access only. It has no delegated write rights and is not a member of
   any administrative group. Confirm this with the AD owners.
3. **A configured safe test target.** One group, agreed with the AD owners, identified by
   **objectGUID** (not by name), small (a few members), not privileged, and in a domain
   listed in the protection policy. Record the agreement (ticket or change reference). Do
   not pick a target yourself.
4. **Protection policy.** A `governedDomains` entry for the target's domain (see the
   architecture doc). Groups in ungoverned domains are always `UNDETERMINED`.
5. **An AAP job template, if AAP is used**, that has been read and confirmed read-only (see
   "Proposed AAP job contract" in the architecture doc). Never launch a template whose
   content you have not verified, and never launch one that can change AD.

## Single-read probe

On the approved host, as the read-only identity:

```powershell
# 1. Request by objectGUID, with every limit at its smallest useful value.
@'
{
  "schema": "ogwa.ad.group-read-request/v1",
  "lookup": { "by": "objectGUID", "value": "<agreed test-target objectGUID>", "domain": "<its DNS domain>" },
  "limits": { "maxDirectMembers": 50, "maxNestedGroups": 10, "maxNestingDepth": 3,
              "maxPrimaryGroupReferences": 5, "maxParentGroups": 20, "maxAmbiguousCandidates": 2 }
}
'@ | Set-Content -LiteralPath .\request.json -Encoding UTF8

# 2. Read. Output goes to a git-ignored evidence folder, never into the repository.
Import-Module <path>\worker\OGWA.ADReader\OGWA.ADReader.psd1
Invoke-OgwaADReader -RequestPath .\request.json | Set-Content -LiteralPath <evidence>\ad-probe.json -Encoding UTF8
```

Setting `domain` keeps the group lookup in one domain. Parent groups are still searched in
every forest domain (one bounded query each), because parent groups can live anywhere.
To limit the probe to the target's domain, set `"include": { "memberOf": false }`. Protection
is then `Undetermined`, which is expected for a probe.

Then check, without sharing the file outside approved channels (it holds production
identifiers):

- `worker.readOnly` is `true` and `resolution.status` is `Resolved`;
- `group.objectGUID` is the requested one;
- `domains[*].reachable` shows which domains were contacted;
- `directMembers.count` matches what the AD owners expect for the target;
- `protectedFromAccidentalDeletion` is not null. If it is null, the identity cannot read
  security descriptors, and protection will always be `Undetermined`;
- the first-read checks listed under "Known limits" in the architecture doc.

Record the outcome in the run report under `docs/agent-runs/` with identifiers redacted.

Until P11 verifies them (D19), large-group completeness, cross-domain parent lookup, and
deletion-protection readability keep live evidence PARTIAL even when every section reports
`Complete`. That is expected. A probe proves the path works; it does not make evidence
decision-grade.

## Collection rules

- Look up by **objectGUID** (or objectSid). Use name lookups only to investigate, never as
  the basis of a decision. `Ambiguous` and `Inconclusive` are final answers for that run:
  do not "pick one".
- Run serially, one group at a time. No parallel jobs against domain controllers.
- Keep the default limits or lower them. Raising a limit to its ceiling needs a reason in
  the run record.
- A `Partial`, `Truncated`, or `Failed` section is not evidence of absence. OGWA records it
  as PARTIAL or FAILED, so it cannot drive a decision.
- Never use a live report as a test fixture. Fixtures in `tests/fixtures/ad/` are produced
  from the synthetic directory only.

## Reading results

| You see | Meaning | Action |
| --- | --- | --- |
| `Resolved`, emptiness `EMPTY`, protection `NOT_PROTECTED` | Membership evidence supports review. It is **not** authorization to retire. Other dependency kinds still need checks | Continue the lifecycle review |
| emptiness `NOT_EMPTY` | At least one fact is NO; the evidence says which | Not a retirement candidate on membership grounds |
| emptiness `UNDETERMINED` | Something was not read completely | Re-read later; never treat as empty |
| protection `PROTECTED` | Well-known, privileged, configured, or nested in a privileged group | The candidate goes to `PROTECTED` |
| protection `UNDETERMINED` | A gap (unreadable PFAD, unread parents, ungoverned domain) | Retirement is blocked until the gap is closed |
| `Inconclusive` | A domain was unreachable | Retry when the domain is reachable; check `domains[*].error` |
| `Failed` with "ActiveDirectory … not installed" | Wrong host | Use the approved host |

## If something looks wrong

- If anything suggests a change was made in AD, stop. Make no further reads, preserve the
  report, and notify the AD owners. The reader contains no mutation command, so treat this
  as a host or template problem.
- If a report contains data from the wrong domain or forest, stop and check the host's
  domain membership and the template's credential.
- Never paste reports, credentials, or production identifiers into chat or tickets
  outside approved channels.
