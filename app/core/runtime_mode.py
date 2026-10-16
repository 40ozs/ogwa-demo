"""The runtime mode. This build has exactly one: ``demo``.

OGWA runs the real application over a deterministic synthetic dataset, with synthetic
providers only (``app.runtime.providers``). It includes no live Okta, Active Directory, or
AAP integration, and no setting can switch it into a live or production runtime. See
docs/demo-mode.md.

``OGWA_RUNTIME_MODE`` may be left unset or set to ``demo``. Any other value refuses startup.
"""

from enum import StrEnum

from app.core.errors import ConfigError

RUNTIME_MODE_ENV_VAR = "OGWA_RUNTIME_MODE"
DEMO_ONLY_MESSAGE = "This public build supports Demo Mode only. Live integrations are unavailable."


class RuntimeMode(StrEnum):
    DEMO = "demo"


def parse_runtime_mode(raw: str | None) -> RuntimeMode:
    """Unset, blank, or ``demo`` gives the demo runtime. Anything else fails closed."""
    if raw is None or not raw.strip() or raw.strip().lower() == RuntimeMode.DEMO:
        return RuntimeMode.DEMO
    raise ConfigError(f"{DEMO_ONLY_MESSAGE} {RUNTIME_MODE_ENV_VAR} may only be demo, not {raw.strip()[:40]!r}.")
