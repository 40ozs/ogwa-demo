"""Settings loaded from the process environment, validated to fail closed.

OGWA reads the process environment only. It does not auto-load ``.env`` files.

This build runs in Demo Mode only (``app.core.runtime_mode``, docs/demo-mode.md): the
runtime mode is always ``demo`` and the execution mode always ``LOCAL_SYNTHETIC``.
``Settings`` has no field that could hold anything else. Startup refuses:

- unknown ``OGWA_*`` keys, so a typo or an attempted override (for example
  ``OGWA_ALLOW_PRODUCTION_MUTATION``) cannot silently change behaviour;
- a runtime or execution mode other than the demo's;
- the live-integration keys of earlier builds (Okta, AAP, outbound HTTP): this build has no
  live integration for them to configure;
- credential variables of Okta, AAP/AWX, and AD tooling: a demo process holds no production
  credentials.

Error messages name variables, never their values.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from app.core.build import BUILD_ALLOWS_PRODUCTION_MUTATION
from app.core.database_url import DATABASE_URL_ENV_VAR, DatabaseTarget, parse_database_url
from app.core.errors import ConfigError, ProductionMutationNotPermitted
from app.core.modes import EXTERNAL_MUTATION_SUMMARY, MODE_ENV_VAR, ExecutionMode
from app.core.runtime_mode import DEMO_ONLY_MESSAGE, RUNTIME_MODE_ENV_VAR, RuntimeMode, parse_runtime_mode

ENV_PREFIX = "OGWA_"
DEMO_DATASET_ENV_VAR = "OGWA_DEMO_DATASET"

KNOWN_KEYS = frozenset({MODE_ENV_VAR, RUNTIME_MODE_ENV_VAR, DEMO_DATASET_ENV_VAR, "OGWA_LOG_LEVEL",
                        DATABASE_URL_ENV_VAR})

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# The canonical demo dataset's selector in the registry app.demo.datasets (Null Meridian, seed
# namespace null-meridian-v1). The registry, not this module, decides which selectors exist;
# a test holds this default equal to the registry's.
DEFAULT_DEMO_DATASET = "null-meridian"
_DATASET_KEY = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# Settings of earlier builds that pointed at, authenticated to, or tuned the transport to a
# live system. This build has none of those integrations, so any of them is refused.
LIVE_INTEGRATION_KEYS = (
    "OGWA_OKTA_ORG_URL", "OGWA_OKTA_API_TOKEN", "OGWA_AAP_URL", "OGWA_AAP_TOKEN",
    "OGWA_HTTP_CONNECT_TIMEOUT_SECONDS", "OGWA_HTTP_READ_TIMEOUT_SECONDS", "OGWA_HTTP_MAX_RETRIES",
    "OGWA_HTTP_MAX_CONCURRENCY",
)
# Credential variables of other Okta, AAP/AWX, and AD tooling. OGWA never reads them, but
# their presence means production credentials reached a demo process.
FORBIDDEN_FOREIGN_CREDENTIALS = (
    "OKTA_API_TOKEN", "OKTA_CLIENT_TOKEN", "OKTA_CLIENT_SECRET", "OKTA_CLIENT_PRIVATEKEY", "OKTA_PRIVATE_KEY",
    "CONTROLLER_PASSWORD", "CONTROLLER_OAUTH_TOKEN", "TOWER_PASSWORD", "TOWER_OAUTH_TOKEN", "AAP_TOKEN",
    "AD_BIND_PASSWORD", "LDAP_BIND_PASSWORD",
)


@dataclass(frozen=True)
class Settings:
    demo_dataset: str = DEFAULT_DEMO_DATASET
    log_level: str = "INFO"
    database: DatabaseTarget = field(default_factory=lambda: parse_database_url(None))

    @property
    def runtime_mode(self) -> RuntimeMode:
        return RuntimeMode.DEMO

    @property
    def mode(self) -> ExecutionMode:
        return ExecutionMode.LOCAL_SYNTHETIC

    def diagnostics(self) -> dict[str, str]:
        """Configuration summary safe to log or print. It holds no secret: this build reads none."""
        return {
            "runtime_mode": self.runtime_mode.value,
            "demo.dataset": self.demo_dataset,
            "execution_mode": self.mode.value,
            "external_mutation": EXTERNAL_MUTATION_SUMMARY[self.mode],
            "live_integrations": "unavailable",
            "production_mutation_permitted_by_build": str(BUILD_ALLOWS_PRODUCTION_MUTATION).lower(),
            "log_level": self.log_level,
            "database.backend": self.database.backend,
            "database.location": self.database.location,
        }


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    full_env = os.environ if environ is None else environ
    env = _ogwa_entries(full_env)

    live = [key for key in LIVE_INTEGRATION_KEYS if key in env]
    if live:
        raise ConfigError(f"{DEMO_ONLY_MESSAGE} Unset {', '.join(live)}: this build includes no Okta, AAP, or "
                          "other live integration for them to configure.")
    unknown = sorted(set(env) - KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            f"{DEMO_ONLY_MESSAGE} Unrecognised configuration keys: {', '.join(unknown)}. Unknown {ENV_PREFIX}* keys "
            "are rejected so a typo or attempted override cannot silently change behaviour."
        )
    parse_runtime_mode(env.get(RUNTIME_MODE_ENV_VAR))
    _check_execution_mode(env.get(MODE_ENV_VAR))
    upper = {key.upper(): value for key, value in full_env.items()}
    foreign = [key for key in FORBIDDEN_FOREIGN_CREDENTIALS if (upper.get(key) or "").strip()]
    if foreign:
        raise ConfigError(f"{DEMO_ONLY_MESSAGE} Refusing to start with production credential variables in the "
                          f"environment ({', '.join(foreign)}). A demo process must hold no production credentials; "
                          "remove them.")

    dataset = env.get(DEMO_DATASET_ENV_VAR, "").strip() or DEFAULT_DEMO_DATASET
    if not _DATASET_KEY.match(dataset):
        raise ConfigError(f"{DEMO_DATASET_ENV_VAR} must be a dataset key such as {DEFAULT_DEMO_DATASET}")

    log_level = env.get("OGWA_LOG_LEVEL", "").strip().upper() or "INFO"
    if log_level not in LOG_LEVELS:
        raise ConfigError(f"OGWA_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}")

    database = parse_database_url(env.get(DATABASE_URL_ENV_VAR))
    if database.path is None:
        raise ConfigError("The demo needs a demo store file; an in-memory database cannot hold the seeded demo "
                          "dataset")
    return Settings(demo_dataset=dataset, log_level=log_level, database=database)


def _check_execution_mode(raw: str | None) -> None:
    """``OGWA_EXECUTION_MODE`` may be unset or ``LOCAL_SYNTHETIC``; this build runs no other mode."""
    value = (raw or "").strip().upper()
    if not value or value == ExecutionMode.LOCAL_SYNTHETIC:
        return
    error = ProductionMutationNotPermitted if value == ExecutionMode.PRODUCTION_MUTATION else ConfigError
    raise error(f"{DEMO_ONLY_MESSAGE} {MODE_ENV_VAR} may only be {ExecutionMode.LOCAL_SYNTHETIC.value}, "
                f"not {value[:40]!r}.")


def _ogwa_entries(environ: Mapping[str, str]) -> dict[str, str]:
    # Windows environment names are case-insensitive, so normalise. Blank values mean unset,
    # but the key still has to be recognised. Two spellings of one key (possible on POSIX) are
    # refused: which one wins would depend on the environment's order.
    entries: dict[str, str] = {}
    for key, value in environ.items():
        name = key.upper()
        if not name.startswith(ENV_PREFIX):
            continue
        if name in entries:
            raise ConfigError(f"{name} is set more than once with different letter case; set it once")
        entries[name] = value or ""
    return entries
