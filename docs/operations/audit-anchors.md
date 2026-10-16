# Audit-chain anchors

The audit trail is a hash chain: each event's digest covers the previous one, so the head
digest commits to every event before it. A chain can only prove it has not been rewritten
when its head is recorded **outside the database**. An audit anchor is that record: a head
digest, with its event count, kept in this repository where it is durable and reviewable
(D94).

## Anchors

| Dataset | Audit events | Head sequence | Audit head |
| --- | --- | --- | --- |
| Null Meridian (default) | 1,458 | 1457 | `sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41` |

The seed is deterministic, so every fresh Null Meridian seed and every
`python -m app.runtime reset-demo --confirm-synthetic-reset` of a Null Meridian demo
store reproduces this head.
`tests/test_null_meridian_seed.py` pins it.

## How to check a store against an anchor

```text
python -m app.runtime verify --expected-audit-head sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41
```

In Docker:

```text
docker compose exec ogwa python -m app.runtime verify --expected-audit-head sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41
```

The command re-verifies the whole chain and the store's integrity, and fails if the head
differs. Actions taken in the local demo (approvals, transitions) record further events, so
the head moves on and no longer matches the anchor. A reset restores the anchored state.

A copy of a store, such as a temporary backup, is **not** an anchor and is not durable
evidence (D96). Only a head recorded here is.
