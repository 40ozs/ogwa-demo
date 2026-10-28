"""Settings loaded from the process environment, validated to fail closed.

OGWA reads the process environment only. It does not auto-load ``.env`` files.
Unknown ``OGWA_*`` keys are rejected so a typo or an attempted override (for example
``OGWA_ALLOW_PRODUCTION_MUTATION``) cannot silently change behaviour.

``OGWA_RUNTIME_MODE=demo`` selects the sealed demo profile (``app.core.runtime_mode``,
docs/demo-mode.md). It is validated here, before anything else is built: the demo profile
forces ``LOCAL_SYNTHETIC``, refuses every live-integration setting and known credential
variable, and uses its own demo store, never the production default store.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.core.build import BUILD_ALLOWS_PRODUCTION_MUTATION
from app.core.database_url import DATABASE_URL_ENV_VAR, DatabaseTarget, parse_database_url
from app.core.errors import ConfigError
from app.core.http_client import HttpPolicy, is_loopback_host
from app.core.modes import (
    DEFAULT_MODE,
    EXTERNAL_MUTATION_SUMMARY,
    MODE_ENV_VAR,
    ExecutionMode,
    assert_mode_permitted_by_build,
    parse_mode,
)
from app.core.runtime_mode import DEFAULT_RUNTIME_MODE, RUNTIME_MODE_ENV_VAR, RuntimeMode, parse_runtime_mode
from app.core.secret import Secret

ENV_PREFIX = "OGWA_"
DEMO_DATASET_ENV_VAR = "OGWA_DEMO_DATASET"

SECRET_KEYS = frozenset({"OGWA_OKTA_API_TOKEN", "OGWA_AAP_TOKEN"})
KNOWN_KEYS = frozenset(
    {
        MODE_ENV_VAR,
        RUNTIME_MODE_ENV_VAR,
        DEMO_DATASET_ENV_VAR,
        "OGWA_LOG_LEVEL",
        "OGWA_HTTP_CONNECT_TIMEOUT_SECONDS",
        "OGWA_HTTP_READ_TIMEOUT_SECONDS",
        "OGWA_HTTP_MAX_RETRIES",
        "OGWA_HTTP_MAX_CONCURRENCY",
        "OGWA_OKTA_ORG_URL",
        "OGWA_AAP_URL",
        DATABASE_URL_ENV_VAR,
    }
    | SECRET_KEYS
)

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# --- the demo profile ------------------------------------------------------------------

# The demo's own store. The production default (DEFAULT_DATABASE_URL) is refused in demo.
DEMO_DATABASE_URL = "sqlite:///var/ogwa-demo.sqlite3"
# The canonical demo dataset's selector in the registry app.demo.datasets (Genesee Press, seed
# namespace genesee-press-v1, from the shared synthetic world). The registry, not this module,
# decides which selectors exist; a test holds this default equal to the registry's.
DEFAULT_DEMO_DATASET = "genesee-press"
_DATASET_KEY = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# OGWA settings that point at, or authenticate to, a live system. Any of them in demo is a
# contradiction, so demo refuses to start rather than ignore it.
DEMO_FORBIDDEN_KEYS = ("OGWA_OKTA_ORG_URL", "OGWA_OKTA_API_TOKEN", "OGWA_AAP_URL", "OGWA_AAP_TOKEN")
# Credential variables of other Okta, AAP/AWX, and AD tooling. OGWA never reads them, but
# their presence in a demo process means production credentials reached a public demo.
DEMO_FORBIDDEN_FOREIGN_CREDENTIALS = (
    "OKTA_API_TOKEN", "OKTA_CLIENT_TOKEN", "OKTA_CLIENT_SECRET", "OKTA_CLIENT_PRIVATEKEY", "OKTA_PRIVATE_KEY",
    "CONTROLLER_PASSWORD", "CONTROLLER_OAUTH_TOKEN", "TOWER_PASSWORD", "TOWER_OAUTH_TOKEN", "AAP_TOKEN",
    "AD_BIND_PASSWORD", "LDAP_BIND_PASSWORD",
)


@dataclass(frozen=True)
class Settings:
    mode: ExecutionMode = DEFAULT_MODE
    log_level: str = "INFO"
    http: HttpPolicy = field(default_factory=HttpPolicy)
    okta_org_url: str | None = None
    okta_api_token: Secret | None = field(default=None, repr=False)
    aap_url: str | None = None
    aap_token: Secret | None = field(default=None, repr=False)
    database: DatabaseTarget = field(default_factory=lambda: parse_database_url(None))
    runtime_mode: RuntimeMode = DEFAULT_RUNTIME_MODE
    demo_dataset: str | None = None  # set only in the demo runtime

    @property
    def is_demo(self) -> bool:
        return self.runtime_mode is RuntimeMode.DEMO

    def diagnostics(self) -> dict[str, str]:
        """Configuration summary safe to log or print: secrets appear only as <set>/<unset>."""
        return {
            "runtime_mode": self.runtime_mode.value,
            "demo.dataset": self.demo_dataset or "<unset>",
            "execution_mode": self.mode.value,
            "external_mutation": EXTERNAL_MUTATION_SUMMARY[self.mode],
            "production_mutation_permitted_by_build": str(BUILD_ALLOWS_PRODUCTION_MUTATION).lower(),
            "log_level": self.log_level,
            "http.connect_timeout_seconds": f"{self.http.connect_timeout:g}",
            "http.read_timeout_seconds": f"{self.http.read_timeout:g}",
            "http.max_retries": str(self.http.max_retries),
            "http.max_concurrency": str(self.http.max_concurrency),
            "okta.org_host": _host_or_unset(self.okta_org_url),
            "okta.api_token": _presence(self.okta_api_token),
            "aap.host": _host_or_unset(self.aap_url),
            "aap.token": _presence(self.aap_token),
            "database.backend": self.database.backend,
            "database.location": self.database.location,
        }


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    full_env = os.environ if environ is None else environ
    env = _ogwa_entries(full_env)

    unknown = sorted(set(env) - KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            f"Unrecognised configuration keys: {', '.join(unknown)}. Unknown {ENV_PREFIX}* keys are "
            "rejected so a typo or attempted override cannot silently change behaviour."
        )

    mode = parse_mode(env.get(MODE_ENV_VAR))
    assert_mode_permitted_by_build(mode)
    runtime_mode = parse_runtime_mode(env.get(RUNTIME_MODE_ENV_VAR))
    demo_dataset = None
    if runtime_mode is RuntimeMode.DEMO:
        demo_dataset = _check_demo_profile(env, full_env, mode)
    elif env.get(DEMO_DATASET_ENV_VAR, "").strip():
        raise ConfigError(f"{DEMO_DATASET_ENV_VAR} is set, but {RUNTIME_MODE_ENV_VAR} is not demo. Unset it, or "
                          f"select {RUNTIME_MODE_ENV_VAR}=demo deliberately.")

    log_level = env.get("OGWA_LOG_LEVEL", "").strip().upper() or "INFO"
    if log_level not in LOG_LEVELS:
        raise ConfigError(f"OGWA_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}")

    try:
        http = HttpPolicy(
            connect_timeout=_number(env, "OGWA_HTTP_CONNECT_TIMEOUT_SECONDS", 5.0, float),
            read_timeout=_number(env, "OGWA_HTTP_READ_TIMEOUT_SECONDS", 30.0, float),
            max_retries=_number(env, "OGWA_HTTP_MAX_RETRIES", 3, int),
            max_concurrency=_number(env, "OGWA_HTTP_MAX_CONCURRENCY", 2, int),
        )
    except ValueError as exc:
        raise ConfigError(f"Unsafe HTTP configuration: {exc}") from None

    okta_api_token = _secret(env, "OGWA_OKTA_API_TOKEN")
    aap_token = _secret(env, "OGWA_AAP_TOKEN")
    if mode is ExecutionMode.LOCAL_SYNTHETIC and (okta_api_token or aap_token):
        raise ConfigError(
            "LOCAL_SYNTHETIC mode must not be configured with live integration credentials "
            "(OGWA_OKTA_API_TOKEN, OGWA_AAP_TOKEN). Unset them, or select READ_ONLY_PRODUCTION deliberately."
        )

    return Settings(
        mode=mode,
        log_level=log_level,
        http=http,
        okta_org_url=_service_url(env, "OGWA_OKTA_ORG_URL", mode),
        okta_api_token=okta_api_token,
        aap_url=_service_url(env, "OGWA_AAP_URL", mode),
        aap_token=aap_token,
        database=_database(env, runtime_mode),
        runtime_mode=runtime_mode,
        demo_dataset=demo_dataset,
    )


def _check_demo_profile(env: Mapping[str, str], full_env: Mapping[str, str], mode: ExecutionMode) -> str:
    """Refuse any configuration that contradicts the demo profile. Returns the dataset key.

    Error messages name variables, never their values."""
    if mode is not ExecutionMode.LOCAL_SYNTHETIC:
        raise ConfigError(f"{RUNTIME_MODE_ENV_VAR}=demo runs only in LOCAL_SYNTHETIC mode, not {mode.value}. Unset "
                          f"{MODE_ENV_VAR} or set it to LOCAL_SYNTHETIC.")
    live = [key for key in DEMO_FORBIDDEN_KEYS if env.get(key, "").strip()]
    if live:
        raise ConfigError(f"{RUNTIME_MODE_ENV_VAR}=demo must not be configured with live integration settings or "
                          f"credentials ({', '.join(live)}). The demo contacts no Okta tenant or AAP controller; "
                          "unset them.")
    upper = {key.upper(): value for key, value in full_env.items()}
    foreign = [key for key in DEMO_FORBIDDEN_FOREIGN_CREDENTIALS if (upper.get(key) or "").strip()]
    if foreign:
        raise ConfigError(f"{RUNTIME_MODE_ENV_VAR}=demo refuses to start with production credential variables in "
                          f"its environment ({', '.join(foreign)}). A demo deployment must hold no production "
                          "credentials; remove them.")
    dataset = env.get(DEMO_DATASET_ENV_VAR, "").strip() or DEFAULT_DEMO_DATASET
    if not _DATASET_KEY.match(dataset):
        raise ConfigError(f"{DEMO_DATASET_ENV_VAR} must be a dataset key such as {DEFAULT_DEMO_DATASET}")
    return dataset


def _database(env: Mapping[str, str], runtime_mode: RuntimeMode) -> DatabaseTarget:
    raw = env.get(DATABASE_URL_ENV_VAR)
    if runtime_mode is not RuntimeMode.DEMO:
        return parse_database_url(raw)
    target = parse_database_url(raw if (raw or "").strip() else DEMO_DATABASE_URL)
    if target.path is None:
        raise ConfigError(f"{RUNTIME_MODE_ENV_VAR}=demo needs a demo store file; an in-memory database cannot "
                          "hold the seeded demo dataset")
    if target.path == parse_database_url(None).path:
        raise ConfigError(f"{RUNTIME_MODE_ENV_VAR}=demo refuses the production default store "
                          f"({DATABASE_URL_ENV_VAR} default). Leave {DATABASE_URL_ENV_VAR} unset to use the demo "
                          f"store, {DEMO_DATABASE_URL}.")
    return target


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


def _number(env: Mapping[str, str], key: str, default, kind):
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        return kind(raw)
    except ValueError:
        raise ConfigError(f"{key} must be a {'whole number' if kind is int else 'number'}") from None


def _secret(env: Mapping[str, str], key: str) -> Secret | None:
    raw = env.get(key, "").strip()
    return Secret(raw) if raw else None


def _service_url(env: Mapping[str, str], key: str, mode: ExecutionMode) -> str | None:
    raw = env.get(key, "").strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    if not parts.scheme or not parts.hostname:
        raise ConfigError(f"{key} must be an absolute URL")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"{key} must not embed credentials")
    if parts.query or parts.fragment:
        raise ConfigError(f"{key} must be a base URL without query or fragment")
    loopback = is_loopback_host(parts.hostname)
    if mode is ExecutionMode.LOCAL_SYNTHETIC and not loopback:
        raise ConfigError(f"{key} must point at a loopback host in LOCAL_SYNTHETIC mode")
    if parts.scheme != "https" and not (loopback and parts.scheme == "http"):
        raise ConfigError(f"{key} must use https")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def _host_or_unset(url: str | None) -> str:
    return urlsplit(url).hostname or "<unset>" if url else "<unset>"


def _presence(secret: Secret | None) -> str:
    return "<set>" if secret is not None else "<unset>"
