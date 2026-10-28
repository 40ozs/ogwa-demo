# Execution modes

Every OGWA process runs in exactly one mode, set by `OGWA_EXECUTION_MODE`.

| Mode | Network | External mutation | Permitted in this build |
| --- | --- | --- | --- |
| `LOCAL_SYNTHETIC` (default) | Loopback hosts only | Synthetic targets only | Yes |
| `READ_ONLY_PRODUCTION` | HTTPS to explicitly allowlisted hosts | Denied | Yes |
| `DRY_RUN_MUTATION` | HTTPS to explicitly allowlisted hosts | Planned and recorded, never executed | Yes |
| `PRODUCTION_MUTATION` | — | — | **No — startup refuses** |

Unset or blank means `LOCAL_SYNTHETIC`. An unrecognised value fails startup; it never
falls back to a default.

The execution mode is separate from the **runtime mode** (`OGWA_RUNTIME_MODE`). Its
`production` default is the standard runtime described here, unchanged. Its `demo` value is
a sealed profile that forces `LOCAL_SYNTHETIC`, refuses every live-integration setting and
credential, and serves a synthetic dataset (by default Null Meridian,
[../demo/null-meridian.md](../demo/null-meridian.md)) from its own store, refusing any store
whose dataset identity evidence does not agree. See [../demo-mode.md](../demo-mode.md).

## Enforcement points

1. **Build constant.** `app/core/build.py` sets `BUILD_ALLOWS_PRODUCTION_MUTATION = False`.
   No configuration can change it.
2. **Settings loader** (`app/core/config.py`) rejects `PRODUCTION_MUTATION`, rejects any
   unrecognised `OGWA_*` key (so `OGWA_ALLOW_PRODUCTION_MUTATION=true` and similar
   override attempts fail startup), and rejects out-of-range or unsafe values.
3. **Startup** (`app/core/startup.py`) re-checks the build policy and logs a banner showing
   the mode. Modes that can reach real systems are announced at `WARNING`.
4. **Mutation policy** (`app/core/safety.py`). `MutationPolicy` can only be built through
   `MutationPolicy.for_mode()`, which also refuses `PRODUCTION_MUTATION`. Every
   mutation-capable component subclasses `MutationCapableService` and must receive a policy
   by keyword injection; there is no default. `_perform()` refuses execution against any
   non-synthetic target, even if `decide()` were later changed by mistake.
5. **HTTP split** (`app/core/http_client.py` vs `app/core/http_mutation.py`).
   `ReadOnlyHttpClient` has only `get()`/`head()` and refuses other methods even through
   internals. `MutatingHttpClient` lives in a separate module, requires a `MutationPolicy`,
   and never retries. A test fails if any module outside a reviewed allowlist imports it.
6. **Destination policy.** Every client needs an explicit host allowlist. HTTPS is required
   for non-loopback hosts. In `LOCAL_SYNTHETIC` only loopback hosts can be allowlisted or
   contacted, so a synthetic run cannot reach a real system.

## Remediation (P10)

The remediation path is built and is dry-run only. Every adapter holds a
`DRY_RUN_MUTATION` policy. Every request resolves to `SIMULATED`, `WHATIF`,
`VALIDATION_ONLY`, or `BLOCKED`. In `READ_ONLY_PRODUCTION`, a remediation request fails the
`EXECUTION_MODE_PERMITS_DRY_RUN` gate. The layers and gates are in
[mutation-gates.md](mutation-gates.md).

OGWA-DEMO-03's synthetic drills run only in `LOCAL_SYNTHETIC` (a `DRY_RUN_MUTATION` or
`READ_ONLY_PRODUCTION` process answers `SYNTHETIC_DRILL_UNAVAILABLE`), over a SYNTHETIC
store, and change only an in-memory provider fixture
([../architecture/remediation-execution.md](../architecture/remediation-execution.md)).

P10B added the AD quarantine and deletion stages in `LOCAL_SYNTHETIC` only (D152). Their
lifecycle steps and remediation operations are dry runs like every other; no production
deletion, quarantine, or restoration path exists (D153), and there is no restore operation
at all (D149).

## Enabling production mutation (not authorized)

This prompt package does not authorize production mutation. A future build that needs it
must, at minimum:

- change the build constant through a reviewed source change;
- add an explicit, per-operation authorization step (human approval recorded in the audit
  store), not just a mode switch;
- add each executor module to `APPROVED_MUTATING_IMPORTERS` in
  `tests/test_mutation_safety.py`, again through review;
- prove the AD/Okta/AAP operations involved, their scopes, and their rollback paths.

Changing an environment variable alone will never be enough.
