"""Authentication adapter boundary (D51).

An ``IdentityAdapter`` turns a sign-in credential into verified ``PrincipalClaims``: who
the person is (a stable subject) and which identity-provider groups they belong to (stable
group ids, D47). Everything after that (sessions, roles, permissions) is the same for every
adapter, so the adapter is the only place a real identity provider will plug in.

This build has exactly one adapter, ``SyntheticIdentityAdapter``. It signs in a principal
from a synthetic directory file with no password, and it refuses to exist outside
``LOCAL_SYNTHETIC`` mode with a SYNTHETIC store (D50). There is deliberately no adapter
that trusts a request header, and no JWT/OIDC verification: that needs an approved
verification library or service first (D51).
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.store.environment import DatabaseEnvironment

SYNTHETIC_IDP_FORMAT = "ogwa-synthetic-idp/v1"
SYNTHETIC_ISSUER = "urn:ogwa:synthetic-idp"
_SUBJECT_RE = re.compile(r"^synthetic\.[a-z0-9.-]{1,80}$")
_SYNTHETIC_GROUP_RE = re.compile(r"^00gSYNTH[A-Za-z0-9]{1,40}$")
MAX_GROUPS_PER_PRINCIPAL = 200


class AuthenticationFailed(Exception):
    """The credential did not identify a principal. The message is safe to return."""


@dataclass(frozen=True)
class PrincipalClaims:
    issuer: str
    subject: str  # stable subject identifier; becomes the audit Actor id
    display_name: str
    groups: frozenset[str]  # stable identity-provider group ids, never display names
    authenticated_at: datetime
    method: str  # how the adapter verified the person, e.g. "synthetic"


class IdentityAdapter(Protocol):
    issuer: str
    method: str

    def authenticate(self, credential: dict[str, Any], *, now: datetime) -> PrincipalClaims:
        """Verify ``credential`` and return the claims, or raise AuthenticationFailed."""
        ...


@dataclass(frozen=True)
class SyntheticPrincipal:
    subject: str
    display_name: str
    groups: frozenset[str]


@dataclass(frozen=True)
class SyntheticDirectory:
    issuer: str
    group_names: dict[str, str]  # id -> display name (informational only)
    principals: dict[str, SyntheticPrincipal]


def load_synthetic_directory(path: Path) -> SyntheticDirectory:
    """Parse a synthetic IdP file strictly. Only synthetic-shaped identifiers are accepted."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"synthetic identity directory {Path(path).name} cannot be read: {type(exc).__name__}") from None
    _keys(data, {"format", "issuer", "groups", "principals"}, "synthetic directory")
    if data["format"] != SYNTHETIC_IDP_FORMAT:
        raise ConfigError(f"synthetic directory format must be {SYNTHETIC_IDP_FORMAT}")
    if data["issuer"] != SYNTHETIC_ISSUER:
        raise ConfigError(f"synthetic directory issuer must be {SYNTHETIC_ISSUER}")
    groups: dict[str, str] = {}
    for entry in _list(data["groups"], "groups"):
        _keys(entry, {"id", "displayName"}, "group")
        gid = entry["id"]
        if not isinstance(gid, str) or not _SYNTHETIC_GROUP_RE.match(gid) or gid in groups:
            raise ConfigError("every synthetic group id must be unique and match 00gSYNTH<alphanumerics>")
        groups[gid] = _text(entry["displayName"], "group displayName")
    principals: dict[str, SyntheticPrincipal] = {}
    for entry in _list(data["principals"], "principals"):
        _keys(entry, {"subject", "displayName", "groups"}, "principal")
        subject = entry["subject"]
        if not isinstance(subject, str) or not _SUBJECT_RE.match(subject) or subject in principals:
            raise ConfigError("every synthetic subject must be unique and start with 'synthetic.'")
        member_of = _list(entry["groups"], "principal groups")
        if len(member_of) > MAX_GROUPS_PER_PRINCIPAL or any(g not in groups for g in member_of):
            raise ConfigError(f"principal {subject} names an unknown group")
        principals[subject] = SyntheticPrincipal(subject, _text(entry["displayName"], "displayName"), frozenset(member_of))
    return SyntheticDirectory(data["issuer"], groups, principals)


class SyntheticIdentityAdapter:
    """Local development sign-in for synthetic principals. Never available against real data."""

    method = "synthetic"

    def __init__(self, directory: SyntheticDirectory, *, mode: ExecutionMode, environment: DatabaseEnvironment) -> None:
        if mode is not ExecutionMode.LOCAL_SYNTHETIC or environment is not DatabaseEnvironment.SYNTHETIC:
            raise ConfigError(
                "The synthetic identity adapter is only available in LOCAL_SYNTHETIC mode with a SYNTHETIC store "
                "(D50). No production identity adapter exists in this build (D51)."
            )
        self._directory = directory
        self.issuer = directory.issuer

    def authenticate(self, credential: dict[str, Any], *, now: datetime) -> PrincipalClaims:
        if set(credential) != {"subject"} or not isinstance(credential.get("subject"), str):
            raise AuthenticationFailed("Synthetic sign-in takes exactly one field: subject.")
        principal = self._directory.principals.get(credential["subject"])
        if principal is None:
            raise AuthenticationFailed("No such synthetic principal.")
        return PrincipalClaims(
            issuer=self.issuer, subject=principal.subject, display_name=principal.display_name,
            groups=principal.groups, authenticated_at=now, method=self.method,
        )


def _keys(value: Any, expected: set[str], what: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ConfigError(f"{what} must have exactly the keys: {', '.join(sorted(expected))}")


def _list(value: Any, what: str) -> list:
    if not isinstance(value, list):
        raise ConfigError(f"{what} must be a list")
    return value


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ConfigError(f"{what} must be a non-empty string of at most 200 characters")
    return value
