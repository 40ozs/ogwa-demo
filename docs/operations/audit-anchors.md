# Audit-chain anchors

The audit trail is a hash chain: each event's digest covers the previous one, so
the head digest commits to every event before it. A chain can only prove it has
not been rewritten when its head is recorded **outside the database**. This
document is that record for the stores this repository's operators keep. It is
tracked in Git, so the anchors are durable and reviewable.

A scratchpad or other temporary backup copy of a store is **not** an anchor and
is not durable evidence (owner decision before P09). Only the values below are.

## How to check a store against an anchor

```text
python -m app.store verify --expected-audit-head <anchor>
```

The command re-verifies the migrations, the whole chain, evidence digests, and
candidate histories, and fails if the head differs. Once a store has recorded
further events, its head moves on, and the anchor then proves only the prefix up
to that event count. Record a new anchor whenever the owner wants to fix a later
point.

## Anchors

| Recorded | Store | Environment | Schema | Audit events | Audit head | Basis |
|---|---|---|---|---|---|---|
| 2026-10-05 | `var/ogwa-local.sqlite3` (git-ignored) | SYNTHETIC | 8 | 300 | `sha256:a3c53e52f912f99475162164fd05d67db32c3bfc8a68e0ae3e4e215d111ddd83` | **Current.** Reset and reseeded under D80, after migration 0008. Verified with `verify --expected-audit-head` on 2026-10-05. A fresh seed of the same build reproduces the same head (the demo seed is deterministic), so the value can be re-derived without any backup. |
| 2026-10-05 | `var/ogwa-local.sqlite3` | SYNTHETIC | 5 → 7 | 300 | `sha256:332f37897f9788f0cf759b8da5d1697e52e717157543fbc801eff4bb093987a1` | **Retired.** The P03-era demo seed. It was unchanged through the authorized upgrades 5 → 6 and 6 → 7, then replaced by the authorized reset (D80). The store it described no longer exists. |

**Migration 0009 (after P09).** Upgrading a store adds no audit event, so the current anchor
still proves `var/ogwa-local.sqlite3` after an 8 → 9 upgrade. The store was upgraded on
2026-10-05 at 19:05 under D117, and `verify --expected-audit-head` then succeeded at schema 9,
with 300 events and the same head (D118). The anchor row above is unchanged: it is still the
current anchor. A *fresh* seed made by the schema-9 build has a different head,
`sha256:1725028297bd24d02cef9de4c60a835aa7846df08131d37d94e194ef33f23124`, because its first
event (`STORE_INITIALIZED`) records `schema_version` 9 instead of 8. Every other event is
identical. That value is not an anchor until the owner has one recorded.

**Migration 0010 (P10).** This upgrade also adds no audit event: it rebuilds
`audit_events` with every row verbatim. The P10 build expects schema 10.

- **The store was upgraded on 2026-10-05 at 21:46 under D127** (P10 addendum 1).
  `verify --expected-audit-head` with the current anchor then succeeded at schema 10, with
  300 events and the same head, so the anchor row above is still the current anchor.
  Before the upgrade it was at schema 9 and matched the anchor too.
- **A rehearsal on a scratch copy**, which is not evidence (D96), went as expected:
  - the upgrade applied [10];
  - `verify --expected-audit-head` with the current anchor then succeeded at schema 10,
    with 300 events and the same head.
- **A fresh seed by the schema-10 build has a different head,**
  `sha256:e3c3c63635b957c90f8e6c3557332c695783a9763113eb591cddff22e45ae05d`, because its
  `STORE_INITIALIZED` event records `schema_version` 10. Like the schema-9 value, it is
  not an anchor.

**Migration 0011 (P10B).** This upgrade adds no audit event either: it rebuilds
`candidates`, `approvals`, `execution_jobs`, and `decisions` with every row verbatim and
does not touch `audit_events`. The P10B build expects schema 11.

- **A rehearsal on a scratch copy** (not evidence, D96) came first, as D150 requires: the
  upgrade applied [11]; `verify --expected-audit-head` with the current anchor succeeded at
  schema 11, with 300 events and the same head; and every row of the eight affected
  tables, 381 in all, was identical to the original's.
- **The store was upgraded on 2026-10-06 at 13:17 under D150** (P10B report).
  `verify --expected-audit-head` with the current anchor then succeeded at schema 11, with
  300 events and the same head, so the anchor row above is still the current anchor. The
  store keeps S12's legacy `AD_RETIREMENT` approval and dry-run job (D148).
- **A fresh seed by the schema-11 build differs more**: its world has sixteen scenarios
  (S15 and S16 were added) and S12 no longer records an `AD_RETIREMENT` approval. Its head,
  `sha256:7ae3b789a028b1edcebfdbbfd92120166ce53b0fb2ec5b92e30c2c9b3616a39f` after 441
  events, is not an anchor.

**Demo datasets (SYNTH-OGWA-01).** Fresh demo seeds are deterministic, so their heads are pinned
by tests rather than recorded as anchors: Genesee Press (`genesee-press-v1`, the default since
SYNTH-OGWA-01) `sha256:f11f0a99ec5aff7e40b9aeda7dc2a8e60df29bc273a745060b8d480ed1d4b39f` after
1,617 events (`tests/test_genesee_press.py`; re-pinned by SYNTH-CROSSAPP-01 for synthetic-enterprise dataset 2.1.0 /
`ogwa@0.3.1` only: 12 case-only duplicate groups merged into ADG's groups and ADG's SIDs/objectGUIDs adopted; the
SYNTH-OGWA-01 head was `sha256:83cfda606c7a05916a4f5f0bb184bbec7f4fa95a8ffd0d3c01707f031f77aa17` after 1,629 events); Null Meridian (legacy) unchanged at
`sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41` after 1,458 events.
The hosted demo's D1 holds the Null Meridian head until it is re-imported from a Genesee Press
build (docs/deployment/cloudflare-demo.md).

## Rules

- Add rows; never delete one. The only edit allowed is marking an anchor
  **Retired** when its store is replaced, citing the decision that replaced it.
- An anchor is recorded only after `verify --expected-audit-head` succeeds.
- No anchor for a store holding production data is recorded here without the
  owner's decision on where production anchors live.

**Migration 0012 (Null Meridian).** This upgrade adds two tables and no audit event, so an
upgraded store keeps its head. The default demo dataset is now Null Meridian. A fresh
Null Meridian seed by the schema-12 build has head
`sha256:cc90d3676294b858693a7375141c4bc9096e1eb133eb970ca3449d17d48b0ac6` (1,404 events;
`tests/test_null_meridian_seed.py` pins it), and a fresh classic seed
`sha256:756288191a0978715b88c35b1fe3d131613be86b2153a5fc0d8ebe965044ad09` (441 events). Like
the earlier fresh-seed values, neither is an anchor until the owner records one; no store under
`var/` was touched by that work.

**Demo Mode (OGWA-DEMO-INTEGRATION-01).** The demo store (`var/ogwa-demo.sqlite3`) reset by
`OGWA_RUNTIME_MODE=demo python -m app.runtime reset-demo` holds the same fresh Null Meridian
seed, so its head after a reset is the same
`sha256:cc90d3676294b858693a7375141c4bc9096e1eb133eb970ca3449d17d48b0ac6`
(`python -m app.runtime verify --expected-audit-head …` checks it). A demo store changes as
people use the demo and is reset rather than anchored; it is not an anchor either.

**OGWA-DEMO-01 (evidence quality).** The Null Meridian seed gained candidate NM-C10 and portfolio
scenario 9, and NM-C09's membership read now agrees with its AD group object. A fresh Null
Meridian seed (and a demo-store reset) by this build has head
`sha256:27a9fe4c79fc58f1f63adab38f4ba8272c86ed858f95c03885e9c3072b1643c8` (1,417 events;
`tests/test_null_meridian_seed.py` pins it), superseding the fresh-seed value above. The classic
seed is unchanged. As before, this is a fresh-seed value, not an anchor.

**OGWA-DEMO-02 (versioned policy).** The Null Meridian seed records NM-LIFECYCLE-004 v1.1.0 and
v1.2.0 as policy versions (two `POLICY_REVIEW_RECORDED` events), and every seeded decision,
refusal, and approval event now carries the policy reference it was judged by. A fresh Null
Meridian seed (and a demo-store reset) by this build has head
`sha256:86f4b226c849f90b4222c8cab2abd163c3f086da47fea2bb085c6a6d2b8729b0` (1,419 events;
`tests/test_null_meridian_seed.py` pins it), superseding the OGWA-DEMO-01 fresh-seed value above.
The classic seed is unchanged (its decisions record no reference). As before, this is a
fresh-seed value, not an anchor.

**OGWA-DEMO-03 (remediation drill).** The Null Meridian seed gained candidate NM-C11 (its evidence
collected again on the snapshot day and its Okta unassignment approved) and portfolio scenario 10.
A fresh Null Meridian seed (and a demo-store reset) by this build has head
`sha256:7269936f3375169c7c69966db47391ee3e79819bb57497a776e65ec02002998e` (1,456 events, head
sequence 1455; `tests/test_null_meridian_seed.py` pins it), superseding the OGWA-DEMO-01 fresh-seed
value above. The classic seed is unchanged. A remediation drill records nothing, so running one
never moves a head. As before, this is a fresh-seed value, not an anchor.

**OGWA-DEMO-04 (integration of OGWA-DEMO-02 and OGWA-DEMO-03).** Both lanes' seed changes, in
chronological order: v1.1.0, the triage, v1.2.0, then the snapshot day (NM-C11's re-collection,
approval, and `APPROVED` decision, which now record v1.2.0). A fresh Null Meridian seed (and a
demo-store reset) by this build has head
`sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41` (1,458 events, head
sequence 1457; `tests/test_null_meridian_seed.py` pins it), superseding both lanes' fresh-seed
values above: 1,417 (OGWA-DEMO-01) + 2 policy versions + 39 NM-C11 events. The classic seed is
unchanged. A remediation drill still records nothing. As before, this is a fresh-seed value, not
an anchor.
