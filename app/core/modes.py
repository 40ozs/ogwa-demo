"""The canonical execution mode.

Every OGWA process runs in exactly one mode. The mode decides which network
destinations are reachable and whether external state may be changed.
"""

from enum import StrEnum

from app.core.build import BUILD_ALLOWS_PRODUCTION_MUTATION
from app.core.errors import ConfigError, ProductionMutationNotPermitted

MODE_ENV_VAR = "OGWA_EXECUTION_MODE"


class ExecutionMode(StrEnum):
    # Synthetic data only; outbound HTTP is limited to loopback hosts.
    LOCAL_SYNTHETIC = "LOCAL_SYNTHETIC"
    # Read-only discovery against real systems; no external mutation.
    READ_ONLY_PRODUCTION = "READ_ONLY_PRODUCTION"
    # Mutations are planned and recorded but never executed.
    DRY_RUN_MUTATION = "DRY_RUN_MUTATION"
    # Real external mutation. Rejected by this build.
    PRODUCTION_MUTATION = "PRODUCTION_MUTATION"


DEFAULT_MODE = ExecutionMode.LOCAL_SYNTHETIC

EXTERNAL_MUTATION_SUMMARY: dict[ExecutionMode, str] = {
    ExecutionMode.LOCAL_SYNTHETIC: "synthetic targets only",
    ExecutionMode.READ_ONLY_PRODUCTION: "disabled",
    ExecutionMode.DRY_RUN_MUTATION: "plan only, never executed",
    ExecutionMode.PRODUCTION_MUTATION: "not permitted by this build",
}


def parse_mode(raw: str | None) -> ExecutionMode:
    """Parse a mode name. Unset or blank means the default; anything unknown fails closed."""
    if raw is None or not raw.strip():
        return DEFAULT_MODE
    try:
        return ExecutionMode(raw.strip().upper())
    except ValueError:
        allowed = ", ".join(m.value for m in ExecutionMode)
        raise ConfigError(
            f"Unknown {MODE_ENV_VAR} value {raw.strip()[:40]!r}; expected one of: {allowed}"
        ) from None


def assert_mode_permitted_by_build(mode: ExecutionMode) -> None:
    if mode is ExecutionMode.PRODUCTION_MUTATION and not BUILD_ALLOWS_PRODUCTION_MUTATION:
        raise ProductionMutationNotPermitted(
            "PRODUCTION_MUTATION is not permitted by this build. It cannot be enabled "
            "through configuration; see docs/security/execution-modes.md."
        )
