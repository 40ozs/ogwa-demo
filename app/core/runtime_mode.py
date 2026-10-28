"""The runtime mode: which data source and integration providers an OGWA process uses.

The runtime mode is a deployment boundary, set only by ``OGWA_RUNTIME_MODE`` in the
process environment. No API route, UI control, or request can read-and-change it.

- ``production`` is the standard OGWA runtime. Every existing rule applies unchanged,
  including the execution mode (``app.core.modes``) and its defaults. It is the default
  when ``OGWA_RUNTIME_MODE`` is unset, so existing deployments behave exactly as before.
- ``demo`` is a sealed profile for showing the real application over a deterministic
  synthetic dataset. It forces ``LOCAL_SYNTHETIC``, refuses every live-integration
  setting and credential, uses its own demo store, and selects only synthetic providers
  (``app.runtime.providers``). See docs/demo-mode.md.

The execution mode governs whether external state may change. The runtime mode governs
where data comes from. A demo process is always ``LOCAL_SYNTHETIC``, but a
``LOCAL_SYNTHETIC`` process is not necessarily a demo: developers still use that
execution mode under the production runtime, as before.
"""

from enum import StrEnum

from app.core.errors import ConfigError

RUNTIME_MODE_ENV_VAR = "OGWA_RUNTIME_MODE"


class RuntimeMode(StrEnum):
    PRODUCTION = "production"
    DEMO = "demo"


DEFAULT_RUNTIME_MODE = RuntimeMode.PRODUCTION


def parse_runtime_mode(raw: str | None) -> RuntimeMode:
    """Unset or blank selects the standard (production) runtime. Anything unknown fails closed."""
    if raw is None or not raw.strip():
        return DEFAULT_RUNTIME_MODE
    try:
        return RuntimeMode(raw.strip().lower())
    except ValueError:
        allowed = ", ".join(m.value for m in RuntimeMode)
        raise ConfigError(
            f"Unknown {RUNTIME_MODE_ENV_VAR} value {raw.strip()[:40]!r}; expected one of: {allowed}"
        ) from None
