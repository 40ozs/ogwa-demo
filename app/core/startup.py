"""Application startup: load settings, enforce build policy, announce the active mode."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass

from app import __version__
from app.core.build import BUILD_ALLOWS_PRODUCTION_MUTATION
from app.core.config import Settings, load_settings
from app.core.modes import EXTERNAL_MUTATION_SUMMARY, ExecutionMode, assert_mode_permitted_by_build
from app.core.safety import MutationPolicy


@dataclass(frozen=True)
class RuntimeContext:
    settings: Settings
    mutation_policy: MutationPolicy


def startup_banner(settings: Settings) -> str:
    return (
        f"OGWA {__version__} starting | runtime_mode={settings.runtime_mode.value} | "
        f"execution_mode={settings.mode.value} | "
        f"external_mutation={EXTERNAL_MUTATION_SUMMARY[settings.mode]} | "
        f"production_mutation_permitted_by_build={str(BUILD_ALLOWS_PRODUCTION_MUTATION).lower()}"
    )


def bootstrap(environ: Mapping[str, str] | None = None, *, logger: logging.Logger | None = None) -> RuntimeContext:
    """Validate configuration and build the runtime context. Raises ConfigError to refuse startup."""
    log = logger or logging.getLogger("ogwa.startup")
    settings = load_settings(environ)
    assert_mode_permitted_by_build(settings.mode)  # defence in depth; load_settings also checks
    policy = MutationPolicy.for_mode(settings.mode)
    # Anything that can reach real systems is announced at WARNING so it stands out.
    level = logging.INFO if settings.mode is ExecutionMode.LOCAL_SYNTHETIC else logging.WARNING
    log.log(level, startup_banner(settings), extra={"ogwa": settings.diagnostics()})
    return RuntimeContext(settings=settings, mutation_policy=policy)
