# Genesee Press: OGWA's demo company, from the shared synthetic world

Genesee Press is OGWA's default demo dataset (selector `genesee-press`, seed namespace
`genesee-press-v1`). It is the core of the shared synthetic world maintained in
[`40ozs/synthetic-enterprise`](https://github.com/40ozs/synthetic-enterprise): the same
fictional organization ADG demonstrates, with the same people, directory and identity
provider. OGWA no longer generates its own company for the demo; it reads the shared world's
OGWA projection, vendored in this repository at a pinned commit (SYNTH-OGWA-01).

The legacy dataset, Null Meridian ([null-meridian.md](null-meridian.md), selector
`null-meridian`), stays available and unchanged until this dataset's parity is accepted. Both
run through one seed path (`app.demo.null_meridian.world`, parameterized by an *edition*), so
every lifecycle rule, guard, correlation check and audit record is the same code.

## Where the data comes from

| What | Owner | Where |
|---|---|---|
| Organization, domain, AD forest, identity provider, departments and teams, people, employment history, groups, memberships, nesting, group owners, applications, assignments, identity-provider sync | the shared world | `vendor/synthetic-enterprise/standard-baseline/projections/ogwa/` (projection `ogwa@0.3.1`), pinned by [`SYNTHETIC_ENTERPRISE.lock`](../../SYNTHETIC_ENTERPRISE.lock) |
| OGWA's view of each group and application it already modelled: kind, naming style, OU, display/Okta name, whether Okta's import captured the objectSid, whether the reviewed correlation configuration lists it, adminCount/protection, push target, replacement; catalogue facts (sign-on mode, provisioning, adoption/retirement, tiers, administering departments, assignment model, owner) | OGWA | [`config/genesee-press/ogwa-overlay.json`](../../config/genesee-press/ogwa-overlay.json), keyed by canonical id |
| Lifecycle candidates GP-C01..GP-C11, policy releases GP-LIFECYCLE-004 1.1.0/1.2.0, walkthrough, findings, usage aggregates, correlation expectations | OGWA | `app/demo/null_meridian/world.py` (shared seed), `config/policies/genesee-press/`, computed by `app.governance` |

`python -m app.demo.genesee_press verify-vendor` checks the vendored files against the lock: the
manifest's SHA-256, the projection header's digest in the manifest, and every record file's digest
and record count. The dataset is built only after that check passes. Nothing at runtime fetches
`synthetic-enterprise` or anything else from the network.

### Updating the vendored projection

1. In `synthetic-enterprise`, build the standard baseline at the commit to adopt.
2. Copy its `manifest.json` and `projections/ogwa/` over `vendor/synthetic-enterprise/standard-baseline/`.
3. Update `SYNTHETIC_ENTERPRISE.lock`: `commit`, `manifest_sha256` (SHA-256 of the manifest),
   `projection`, `dataset`, `contract_version`.
4. Run `python -m app.demo.genesee_press verify-vendor`, `overlay-check`, `write`,
   `python -m app.demo.genesee_press.audit_sample --write`, then the tests. Re-pin the golden audit head
   in `tests/test_genesee_press.py` only for the intended change, and record it in
   [audit-anchors.md](../operations/audit-anchors.md).

Never edit a vendored file by hand.

## Company profile

| Fact | Value | Source |
|---|---|---|
| Name, domain | Genesee Press, `geneseepress.example` (reserved, RFC 2606) | projection `organization.jsonl` |
| AD forest | `corp.geneseepress.example`, NetBIOS `GPCORP` | projection |
| Identity provider adopted; naming standard adopted | 2021-10-01; 2023-10-01 (`sec-okta-*` / `sec-share-*`) | projection milestones |
| Snapshot | 2026-10-01T12:00:00Z | projection clock |
| People | 1,800 active, 640 former (2,440); employee numbers `GP-nnnnn` | projection |
| Departments, teams | 14 departments (OGWA's department ids kept), 61 teams | projection |
| Groups | 560: 509 AD, 50 Okta-mastered, `Everyone`; 298 Okta-visible | projection |
| Applications | 81 (76 active), generic names (`GP Intranet` formerly `NM Intranet`) | projection |
| Assignments | 247: 186 group, 61 individual (CRM 23) | projection |
| Okta-shaped ids | `00gSYNTHGP…`, `0oaSYNTHGP…`, directory integration `0oaSYNTHGPADDIR` (the shared world's rule `SYNTHNM → SYNTHGP`) | projection |
| AD object ids | OGWA's own SIDs and objectGUIDs for its 350 groups; the 171 groups the shared world added (from ADG) get the next RIDs in the same synthetic domain SID and a derived GUID (projection rule) | projection |

## Lifecycle candidates

The eleven candidates are the legacy NM-C01..NM-C11, renamed GP-C01..GP-C11
(synthetic-enterprise scenario `gp-ogwa-lifecycle-candidates`). Each reaches the same state; the
seed stops if any does not.

| Candidate | Group | State | Owner (canonical) |
|---|---|---|---|
| GP-C01 | `Timesheets_Users` | NEEDS_REVIEW | — |
| GP-C02 | `sec-okta-status-page-admin` | NEEDS_REVIEW | GP-00671 (formerly persona NM00693) |
| GP-C03 | `CRM-Sales` | DEPENDENCY_BLOCKED | — |
| GP-C04 | `Finance-RW` (Okta copy) | MAPPING_AMBIGUOUS | GP-00112 (NM01218) |
| GP-C05 | `Print-Users` | DEPENDENCY_BLOCKED | GP-01598 (NM02282) |
| GP-C06 | `WikiV1-Users` | NEEDS_REVIEW (approval refused) | GP-01333 (NM01439) |
| GP-C07 | `Okta_Fax_Users` | BLOCKED | — |
| GP-C08 | `GG_App_Fax` | HOLD | — |
| GP-C09 | `CloudLegacy_Admins` | PROTECTED | GP-01961 (NM02128) |
| GP-C10 | `KB-Admins` | NEEDS_REVIEW (conflicting evidence; no owner) | — |
| GP-C11 | `OKTA-AdAnalytics-Users` | APPROVED (the remediation drill) | — |

Owners and individual assignees are the canonical people the legacy personas were mapped to
(synthetic-enterprise D-NM-04): a group owner comes from the shared world's ownership; an
application owner, which only OGWA records, is re-keyed through the person's
`legacy_employee_numbers`.

## What changed from Null Meridian, and why

| | Null Meridian | Genesee Press | Why |
|---|---|---|---|
| Population | 2,809 generated (1,800 / 1,009) | 2,440 canonical (1,800 / 640) | the shared world's core population is ADG's (ADR-0003) |
| Groups | 401 | 560 | the shared directory is the union of ADG's and OGWA's catalogues, one group per sAMAccountName (572 before SYNTH-CROSSAPP-01 merged 12 case-only duplicates) |
| Group names | `sg-okta-*`, `sg-share-*` | `sec-okta-*`, `sec-share-*` (OGWA's naming standard takes the prefix) | ADR-0010 |
| Correlation outcomes | 201 / 45 / 42 / 7 / 3 | identical | every Okta-visible group is OGWA's, with the same overlay |
| Findings | 465 | 693 | computed over the larger directory (e.g. departed ADG owners). SYNTH-CROSSAPP-01: 714 → 693, the 12 case-only duplicates are one group each (−24 `DUPLICATE_NAME`, −12 `LEGACY_NAMING`; +15 `DEEP_NESTING` because `All-Staff` → `GG_Dept_Engineering` → `eng-payments` now continues into ADG's `ENG-Payments-Oncall`) |
| `All-Staff` effective members | 1,798 | 1,598 | the department groups' members are the canonical people (1,624 before SYNTH-CROSSAPP-01: the merged team groups now have ADG's members) |
| Golden audit head | `sha256:e8793f89…eb41` (1,458 events) | `sha256:f11f0a99…b39f` (1,617 events; SYNTH-OGWA-01: `83cfda60…aa17`, 1,629) | data change |

## Running it

```text
export OGWA_RUNTIME_MODE=demo                                      # genesee-press is the default dataset
python -m app.runtime reset-demo --confirm-synthetic-reset         # reseed var/ogwa-demo.sqlite3, validated
python -m app.runtime verify
python -m app.api serve                                            # http://127.0.0.1:8765/
python -m app.store reset-demo --confirm-synthetic-reset --dataset genesee-press   # developer reset
python -m app.demo.genesee_press check|write|summary|verify-vendor|overlay-check|overlay-write
python -m app.demo.genesee_press.audit_sample --check              # docs/demo/samples/genesee-press-audit-sample.json
```

A fresh Genesee Press store by this build always has audit head
`sha256:f11f0a99ec5aff7e40b9aeda7dc2a8e60df29bc273a745060b8d480ed1d4b39f` after 1,617 events
(`tests/test_genesee_press.py` pins it).

## Synthetic-only guarantee

Everything is the shared synthetic world's or OGWA's own generated configuration. No real
person, organization, tenant, directory, credential or system is represented; the domain is a
reserved name; the Okta-shaped ids carry `SYNTH`. Seeding runs only in `LOCAL_SYNTHETIC` mode
into a `SYNTHETIC` store and contacts nothing.
