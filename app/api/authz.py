"""Application roles, permissions, and deployment-controlled role bindings.

Roles come only from role bindings: deployment configuration that names a **stable
identity-provider group id** and the OGWA role it grants (D47, D48). A display-name match
grants nothing, a binding for another issuer grants nothing, and no API route can read or
change bindings at run time beyond an administrator's read-only view.

Each role maps to a fixed set of permissions in code (``ROLE_PERMISSIONS``). Separation of
duties is a property of that table and is pinned by tests:

- no role both approves and plans execution, or both advances and approves;
- ``ADMINISTRATOR`` holds no lifecycle, review, approval, or execution permission;
- ``EXECUTION_EXECUTE`` (real execution) is granted to no role in this build.

A principal may hold several roles (D49). Four-eyes is then enforced per action and per
principal by the services, independent of the roles held.
"""

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.api.identity import PrincipalClaims
from app.core.errors import ConfigError
from app.domain.actors import Actor, ActorKind
from app.store.environment import DatabaseEnvironment

ROLE_BINDINGS_FORMAT = "ogwa-role-bindings/v1"
_GROUP_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
# Keys that would bind by name. Refused with an explanation rather than as merely "unknown".
_NAME_KEYS = frozenset({"displayName", "groupName", "name", "group"})


class Role(StrEnum):
    VIEWER = "VIEWER"
    IDENTITY_AUTOMATION = "IDENTITY_AUTOMATION"  # D46; the prompt's "Reviewer": proposes and advances
    SECURITY_IAM = "SECURITY_IAM"  # D46; the prompt's "Approver"
    EXECUTOR = "EXECUTOR"  # plans dry runs against a valid approval
    ADMINISTRATOR = "ADMINISTRATOR"  # audit and system visibility only


class Permission(StrEnum):
    READ_INVENTORY = "READ_INVENTORY"  # dashboard, inventory, candidates, evidence, decisions, approvals, jobs, collectors
    READ_AUDIT = "READ_AUDIT"  # the global audit chain
    READ_SYSTEM = "READ_SYSTEM"  # role bindings (read-only), store integrity, configuration summary
    MAPPING_PROPOSE = "MAPPING_PROPOSE"  # inspect, bounded AD search, and select a pairing (PROPOSED)
    MAPPING_APPROVE = "MAPPING_APPROVE"  # approve an exact pairing; never one the same person selected
    MAPPING_REJECT = "MAPPING_REJECT"  # reject a pairing (a safer action)
    LIFECYCLE_ADVANCE = "LIFECYCLE_ADVANCE"  # forward steps that need no approval, and re-entry after a block
    LIFECYCLE_DIVERT = "LIFECYCLE_DIVERT"  # move a candidate to a safer state with a reason
    APPROVAL_DECIDE = "APPROVAL_DECIDE"  # record an approval or rejection for a lifecycle stage
    EXECUTION_PLAN_DRY_RUN = "EXECUTION_PLAN_DRY_RUN"  # plan a dry run and record the dry-run step
    EXECUTION_EXECUTE = "EXECUTION_EXECUTE"  # real execution; granted to no role in this build


P = Permission
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({P.READ_INVENTORY}),
    Role.IDENTITY_AUTOMATION: frozenset({
        P.READ_INVENTORY, P.READ_AUDIT, P.MAPPING_PROPOSE, P.MAPPING_REJECT, P.LIFECYCLE_ADVANCE, P.LIFECYCLE_DIVERT,
    }),
    Role.SECURITY_IAM: frozenset({
        P.READ_INVENTORY, P.READ_AUDIT, P.MAPPING_APPROVE, P.MAPPING_REJECT, P.APPROVAL_DECIDE, P.LIFECYCLE_DIVERT,
    }),
    Role.EXECUTOR: frozenset({P.READ_INVENTORY, P.EXECUTION_PLAN_DRY_RUN}),
    Role.ADMINISTRATOR: frozenset({P.READ_INVENTORY, P.READ_AUDIT, P.READ_SYSTEM}),
}

WRITE_PERMISSIONS = frozenset(P) - {P.READ_INVENTORY, P.READ_AUDIT, P.READ_SYSTEM}


@dataclass(frozen=True)
class RoleBinding:
    idp_group_id: str
    role: Role
    note: str


@dataclass(frozen=True)
class RoleBindings:
    environment: DatabaseEnvironment
    issuer: str
    bindings: tuple[RoleBinding, ...]

    def roles_for(self, claims: PrincipalClaims) -> frozenset[Role]:
        """Roles granted by the claims' group ids. Claims from another issuer get none."""
        if claims.issuer != self.issuer:
            return frozenset()
        return frozenset(b.role for b in self.bindings if b.idp_group_id in claims.groups)

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment.value, "issuer": self.issuer, "editable": False,
            "bindings": [{"idpGroupId": b.idp_group_id, "role": b.role.value, "note": b.note} for b in self.bindings],
        }


def load_role_bindings(path: Path, *, environment: DatabaseEnvironment) -> RoleBindings:
    """Parse a bindings file strictly. Its environment must match the store it will guard."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"role bindings {Path(path).name} cannot be read: {type(exc).__name__}") from None
    return parse_role_bindings(data, environment=environment)


def parse_role_bindings(data: Any, *, environment: DatabaseEnvironment) -> RoleBindings:
    if not isinstance(data, dict) or set(data) != {"format", "environment", "issuer", "bindings"}:
        raise ConfigError("role bindings must have exactly: format, environment, issuer, bindings")
    if data["format"] != ROLE_BINDINGS_FORMAT:
        raise ConfigError(f"role bindings format must be {ROLE_BINDINGS_FORMAT}")
    if data["environment"] != environment.value:
        raise ConfigError(f"role bindings are for {data['environment']!s:.20}, not this {environment.value} store")
    issuer = data["issuer"]
    if not isinstance(issuer, str) or not issuer.strip() or len(issuer) > 300:
        raise ConfigError("role bindings issuer must be a non-empty string")
    if not isinstance(data["bindings"], list):
        raise ConfigError("bindings must be a list")
    bindings: list[RoleBinding] = []
    for entry in data["bindings"]:
        if isinstance(entry, dict) and _NAME_KEYS & set(entry):
            raise ConfigError("a role binding names a stable IdP group id (idpGroupId), never a group name (D47)")
        if not isinstance(entry, dict) or set(entry) != {"idpGroupId", "role", "note"}:
            raise ConfigError("each binding must have exactly: idpGroupId, role, note")
        gid, role = entry["idpGroupId"], entry["role"]
        if not isinstance(gid, str) or not _GROUP_ID_RE.match(gid):
            raise ConfigError("idpGroupId must be 1-100 characters from [A-Za-z0-9._:-]")
        if role not in {r.value for r in Role}:
            raise ConfigError(f"unknown role {str(role)[:40]!r}")
        if not isinstance(entry["note"], str) or len(entry["note"]) > 200:
            raise ConfigError("note must be a string of at most 200 characters")
        binding = RoleBinding(gid, Role(role), entry["note"])
        if any(b.idp_group_id == gid and b.role is binding.role for b in bindings):
            raise ConfigError(f"duplicate binding of {gid} to {role}")
        bindings.append(binding)
    return RoleBindings(environment, issuer, tuple(bindings))


@dataclass(frozen=True)
class Principal:
    """An authenticated person and what they may do in this request."""

    claims: PrincipalClaims
    roles: frozenset[Role]

    @property
    def subject(self) -> str:
        return self.claims.subject

    @property
    def actor(self) -> Actor:
        return Actor(ActorKind.HUMAN, self.claims.subject)

    @property
    def permissions(self) -> frozenset[Permission]:
        granted: set[Permission] = set()
        for role in self.roles:
            granted |= ROLE_PERMISSIONS[role]
        return frozenset(granted)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject, "displayName": self.claims.display_name, "issuer": self.claims.issuer,
            "authenticationMethod": self.claims.method,
            "authenticatedAt": self.claims.authenticated_at.isoformat(),
            "roles": sorted(r.value for r in self.roles),
            "permissions": sorted(p.value for p in self.permissions),
        }
