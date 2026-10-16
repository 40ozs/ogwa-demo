"""The execution mode vocabulary.

This build runs only in ``LOCAL_SYNTHETIC`` (``app.core.config`` accepts no other mode).
The other modes stay in the vocabulary because the store's schema, its environment marker
rules, and the mutation-policy gates name them: they are what those gates refuse.
"""

from enum import StrEnum

from app.core.build import BUILD_ALLOWS_PRODUCTION_MUTATION
from app.core.errors import ProductionMutationNotPermitted

MODE_ENV_VAR = "OGWA_EXECUTION_MODE"


class ExecutionMode(StrEnum):
    # Synthetic data only. The only mode this build runs in.
    LOCAL_SYNTHETIC = "LOCAL_SYNTHETIC"
    # Read-only discovery against real systems. Not available in this build.
    READ_ONLY_PRODUCTION = "READ_ONLY_PRODUCTION"
    # Mutations planned and recorded but never executed. Not available in this build.
    DRY_RUN_MUTATION = "DRY_RUN_MUTATION"
    # Real external mutation. Rejected by this build.
    PRODUCTION_MUTATION = "PRODUCTION_MUTATION"


EXTERNAL_MUTATION_SUMMARY: dict[ExecutionMode, str] = {
    ExecutionMode.LOCAL_SYNTHETIC: "synthetic targets only",
    ExecutionMode.READ_ONLY_PRODUCTION: "disabled",
    ExecutionMode.DRY_RUN_MUTATION: "plan only, never executed",
    ExecutionMode.PRODUCTION_MUTATION: "not permitted by this build",
}


def assert_mode_permitted_by_build(mode: ExecutionMode) -> None:
    if mode is ExecutionMode.PRODUCTION_MUTATION and not BUILD_ALLOWS_PRODUCTION_MUTATION:
        raise ProductionMutationNotPermitted(
            "PRODUCTION_MUTATION is not permitted by this build. It cannot be enabled "
            "through configuration; see docs/security/execution-modes.md."
        )
