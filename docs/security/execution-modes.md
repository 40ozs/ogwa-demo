# Execution modes

This build runs in one execution mode, `LOCAL_SYNTHETIC`. `OGWA_EXECUTION_MODE` may be left
unset or set to `LOCAL_SYNTHETIC`; any other value refuses startup with "This public build
supports Demo Mode only. Live integrations are unavailable." It never falls back to a
default.

| Mode | Meaning | In this build |
| --- | --- | --- |
| `LOCAL_SYNTHETIC` | Synthetic data only; external mutation reaches synthetic targets only | The only mode. Always active |
| `READ_ONLY_PRODUCTION` | Read-only discovery against real systems | Refused by configuration |
| `DRY_RUN_MUTATION` | Mutations planned and recorded, never executed | Refused by configuration as a process mode. Remediation adapters and the dry-run planner hold a `DRY_RUN_MUTATION` policy internally (below) |
| `PRODUCTION_MUTATION` | Real external mutation | Refused by configuration (`ProductionMutationNotPermitted`) and by the build constant |

The three other values stay in the vocabulary because the store's schema, its environment
marker rules, the database CHECK constraints, and the mutation policy name them: they are
what those gates refuse.

The runtime mode (`OGWA_RUNTIME_MODE`) is likewise always `demo`. The demo serves a
synthetic dataset (by default Null Meridian,
[../demo/null-meridian.md](../demo/null-meridian.md)) from its own store and refuses any
store whose dataset identity evidence does not agree. See [../demo-mode.md](../demo-mode.md).

## Enforcement points

1. **Build constant.** `app/core/build.py` sets `BUILD_ALLOWS_PRODUCTION_MUTATION = False`.
   No configuration can change it.
2. **Settings loader** (`app/core/config.py`). `Settings` has no field that could hold
   another mode: its execution mode is always `LOCAL_SYNTHETIC`. The loader refuses any
   other `OGWA_EXECUTION_MODE` (`PRODUCTION_MUTATION` with `ProductionMutationNotPermitted`),
   any unrecognised `OGWA_*` key (so `OGWA_ALLOW_PRODUCTION_MUTATION=true` and similar
   override attempts fail startup), the former live-integration keys, and other tools'
   credential variables ([credentials.md](credentials.md)).
3. **Startup** (`app/core/startup.py`) re-checks the build policy and logs a banner showing
   the runtime mode, the execution mode, and `live_integrations=unavailable`.
4. **Mutation policy** (`app/core/safety.py`). `MutationPolicy` can only be built through
   `MutationPolicy.for_mode()`, which also refuses `PRODUCTION_MUTATION`. Every
   mutation-capable component subclasses `MutationCapableService` and must receive a policy
   by keyword injection; there is no default. `_perform()` refuses execution against any
   non-synthetic target, even if `decide()` were later changed by mistake.
5. **No outbound client.** The build includes no Okta, AD, or AAP client and no outbound
   HTTP client. `NoOutboundClientTests` (`tests/test_mutation_safety.py`) fails if any
   application module imports a network, process, or HTTP-client module; the one approved
   server import is the demo's WSGI server in `app/api/local.py`. `DemoOnlyEscapeTests`
   (`tests/test_runtime_mode.py`) checks that no live integration module or worker is in
   the build.

## Remediation

The remediation path is dry-run only. Every adapter holds a `DRY_RUN_MUTATION` policy.
Every request resolves to `SIMULATED`, `WHATIF`, `VALIDATION_ONLY`, or `BLOCKED`. The
`EXECUTION_MODE_PERMITS_DRY_RUN` gate refuses a process mode that cannot plan
(`READ_ONLY_PRODUCTION` or anything unknown). The layers and gates are in
[mutation-gates.md](mutation-gates.md).

Synthetic drills run only in `LOCAL_SYNTHETIC` (any other mode answers
`SYNTHETIC_DRILL_UNAVAILABLE`), over a SYNTHETIC store, and change only an in-memory
provider fixture
([../architecture/remediation-execution.md](../architecture/remediation-execution.md)).

The AD quarantine and deletion stages exist in `LOCAL_SYNTHETIC` only (D152). Their
lifecycle steps and remediation operations are dry runs like every other; no production
deletion, quarantine, or restoration path exists (D153), and there is no restore operation
at all (D149).

## Enabling production mutation (not authorized)

No setting can enable production mutation. A build that supported it would need, at
minimum:

- a reviewed source change to the build constant;
- an explicit, per-operation authorization step (human approval recorded in the audit
  store), not just a mode switch;
- an outbound client for each system involved, which this build does not include and
  `NoOutboundClientTests` refuses;
- proof of the AD, Okta, and AAP operations involved, their scopes, and their rollback
  paths.

Changing an environment variable alone will never be enough.
