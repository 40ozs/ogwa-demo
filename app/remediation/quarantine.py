"""Loads the deployment's quarantine OU configuration (owner decision D136).

The file is separate from the candidate policy and from the remediation allowlist. The
server reads it at start-up; no API route reads it back for editing or writes it, so no
operator can change it. A change is a deployment change, reviewed like any other.

The format is strict: exactly ``format``, ``environment``, and ``quarantineOus``, which maps
each lowercase DNS domain name to one explicit OU distinguished name inside that domain. A
configuration is accepted only for the store environment it names.
"""

import json
from pathlib import Path
from typing import Any

from app.core.errors import ConfigError
from app.domain.errors import InvalidRecord
from app.domain.quarantine import QUARANTINE_OUS_FORMAT, QuarantineOus
from app.store.environment import DatabaseEnvironment

REPO_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_QUARANTINE_OUS_PATH = REPO_ROOT / "config" / "quarantine-ous.synthetic.json"


def load_quarantine_ous(path: Path, *, environment: DatabaseEnvironment) -> QuarantineOus:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"quarantine OU configuration {Path(path).name} cannot be read: {type(exc).__name__}") from None
    return parse_quarantine_ous(data, environment=environment)


def parse_quarantine_ous(data: Any, *, environment: DatabaseEnvironment) -> QuarantineOus:
    if not isinstance(data, dict) or set(data) != {"format", "environment", "quarantineOus"}:
        raise ConfigError("the quarantine OU configuration must have exactly: format, environment, quarantineOus")
    if data["format"] != QUARANTINE_OUS_FORMAT:
        raise ConfigError(f"the quarantine OU configuration format must be {QUARANTINE_OUS_FORMAT}")
    if data["environment"] != environment.value:
        raise ConfigError(f"the quarantine OU configuration is for {str(data['environment'])[:20]}, not this "
                          f"{environment.value} store")
    raw = data["quarantineOus"]
    if not isinstance(raw, dict) or not raw:
        raise ConfigError("quarantineOus must map each domain to its quarantine OU")
    try:
        return QuarantineOus(environment.value, tuple(sorted(raw.items())))
    except (InvalidRecord, TypeError) as exc:
        raise ConfigError(f"quarantineOus: {exc}") from None


def synthetic_quarantine_ous() -> QuarantineOus:
    """The synthetic world's quarantine OUs (``config/quarantine-ous.synthetic.json``)."""
    return load_quarantine_ous(SYNTHETIC_QUARANTINE_OUS_PATH, environment=DatabaseEnvironment.SYNTHETIC)
