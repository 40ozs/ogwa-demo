# OGWA demo release `genesee-press-2.1.0-1670298c8de8`

This repository is a **one-way release mirror**. It is generated from a verified application
integration commit and the Genesee Press synthetic world; it is not a development repository.
Changes are made upstream and arrive here only through a new release export.

| | |
|---|---|
| Application source | `40ozs/ogwa` `integration/SYNTH-HOSTED-CUTOVER-MAC-01` @ `1670298c8de8862473ed0c1384282b21827fcd2c` |
| Synthetic world | `40ozs/synthetic-enterprise` @ `ce7c0c7d9fbc82c67e596dde95cf5e2432acf450` |
| Dataset / contract | `synthetic-enterprise-world@2.1.0` / `0.2.0` |
| Projection | `ogwa@0.3.1` (lock `SYNTHETIC_ENTERPRISE.lock`, commit `ce7c0c7d9fbc82c67e596dde95cf5e2432acf450`) |
| Integration record | `docs/demo/reports/SYNTH-CROSSAPP-01-report.md` @ `296b528e5927f579f2513b6c43b750f50f1de8e8` |
| Release generated | 2026-10-29T06:21:21Z by `tools/cutover/demo_release.py` (SYNTH-HOSTED-CUTOVER-MAC-01) |

Machine-readable provenance: [`demo-release.json`](demo-release.json). Every file's digest:
[`demo-release/files.sha256`](demo-release/files.sha256).

## Verify

```sh
python3 demo-release/verify_release.py
```

checks that the tree is exactly the recorded release (no file added, removed or edited) and
that no prohibited file type is present. The release is reproducible: in
`40ozs/synthetic-enterprise`,

```sh
python3 tools/cutover/demo_release.py compare --app ogwa --source <ogwa checkout> --se . --demo <this checkout>
```

re-exports from the recorded commits and requires a byte-identical tree.

## What this release contains

The OGWA application at the verified integration commit, with the vendored Genesee Press projection
(`ogwa@0.3.1`) as the default dataset and Null Meridian kept as the documented legacy fixture. It replaces
the earlier hand-maintained public copy (`417ed5a`, kept in this repository's history as the rollback
point): its demo-only code edits and Docker packaging are not carried forward; this tree is the upstream
application exactly. No file is altered during export.

Left out on purpose: the internal run reports (`docs/agent-runs/`), the project-status ledger and nine
architecture/security documents that record development provenance, and the source repository's
self-hosted CI. Some documents still link to the omitted reports. No source history is included.

## Hosted demo: database first, then the Worker

`cloudflare/worker/wrangler.jsonc` selects `OGWA_DEMO_DATASET=genesee-press`. The hosted D1 must hold this
build's Genesee Press store (audit head `sha256:f11f0a99…d4b39f`, 1,617 events, three import phases)
**before** a Worker from this release is deployed, or the Worker answers 503. Follow
[docs/deployment/cloudflare-demo.md](docs/deployment/cloudflare-demo.md) "Re-import for Genesee Press" from
a checkout of this repository: build, a fresh D1 bound in `wrangler.jsonc`, the three phases, verify,
deploy, then `python scripts/hosted_smoke.py <url>`. Binding a new D1 is a change upstream and a new release.
