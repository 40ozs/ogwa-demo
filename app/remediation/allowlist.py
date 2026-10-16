"""The server-side remediation allowlist: which operations exist, and what answers each.

A browser chooses an operation and names one target by its OGWA id. Everything else comes
from here, from deployment configuration that no API route reads back or changes: the
adapter that answers the dry run and, for the AAP adapter, the one job template, the survey
variable that carries the worker request, and the reviewed record that pins the template.
No request can name a template, a script, a command, a host, or an OU.

Each domain's quarantine OU is not here: it is separate deployment-controlled configuration
(``config/quarantine-ous.*.json``, owner decision D136). Format v1 named the OUs in the
quarantine entry; v2 does not, and a v1 file is refused with a pointer to the new file.

The format is strict (exact keys, closed values, bounded text). An operation that is not
listed is not available: its dry runs are BLOCKED. The SYNTHETIC adapter is accepted only
in a SYNTHETIC environment's allowlist, so a production deployment can never be answered
by a synthetic simulation.
"""

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.core.errors import ConfigError
from app.domain.remediation import RemediationOperation
from app.remediation.aap import MAX_TEMPLATE_ID, ReviewedTemplate
from app.store.environment import DatabaseEnvironment

ALLOWLIST_FORMAT = "ogwa-remediation-allowlist/v2"
_V1_FORMAT = "ogwa-remediation-allowlist/v1"
_VARIABLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{7,64}$")


class AdapterKind(StrEnum):
    SYNTHETIC = "SYNTHETIC"  # LOCAL_SYNTHETIC only: simulates against the synthetic world
    AAP = "AAP"  # validates the launch of one allowlisted, reviewed job template; never launches


@dataclass(frozen=True)
class AapTemplateBinding:
    template_id: int
    template_name: str
    request_variable: str  # the survey variable that would carry the worker request
    reviewed: ReviewedTemplate


@dataclass(frozen=True)
class AllowlistEntry:
    operation: RemediationOperation
    adapter: AdapterKind
    aap: AapTemplateBinding | None = None


@dataclass(frozen=True)
class RemediationAllowlist:
    environment: DatabaseEnvironment
    entries: tuple[AllowlistEntry, ...]

    def entry(self, operation: RemediationOperation) -> AllowlistEntry | None:
        return next((e for e in self.entries if e.operation is operation), None)


def load_allowlist(path: Path, *, environment: DatabaseEnvironment) -> RemediationAllowlist:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"remediation allowlist {Path(path).name} cannot be read: {type(exc).__name__}") from None
    return parse_allowlist(data, environment=environment)


def parse_allowlist(data: Any, *, environment: DatabaseEnvironment) -> RemediationAllowlist:
    if not isinstance(data, dict) or set(data) != {"format", "environment", "operations"}:
        raise ConfigError("the remediation allowlist must have exactly: format, environment, operations")
    if data["format"] == _V1_FORMAT:
        raise ConfigError(f"remediation allowlist {_V1_FORMAT} named quarantine OUs; they are now separate "
                          f"deployment configuration (D136). Move them to the quarantine OU file and use "
                          f"{ALLOWLIST_FORMAT}")
    if data["format"] != ALLOWLIST_FORMAT:
        raise ConfigError(f"the remediation allowlist format must be {ALLOWLIST_FORMAT}")
    if data["environment"] != environment.value:
        raise ConfigError(f"the remediation allowlist is for {str(data['environment'])[:20]}, not this "
                          f"{environment.value} store")
    operations = data["operations"]
    if not isinstance(operations, dict):
        raise ConfigError("operations must be an object keyed by operation name")
    entries = []
    for name, raw in operations.items():
        if name not in {o.value for o in RemediationOperation}:
            raise ConfigError(f"unknown remediation operation {str(name)[:40]!r}")
        entries.append(_entry(RemediationOperation(name), raw, environment))
    return RemediationAllowlist(environment, tuple(entries))


def _entry(operation: RemediationOperation, raw: Any, environment: DatabaseEnvironment) -> AllowlistEntry:
    where = f"operations.{operation.value}"
    if not isinstance(raw, dict) or raw.get("adapter") not in {k.value for k in AdapterKind}:
        raise ConfigError(f"{where}.adapter must be one of: {', '.join(k.value for k in AdapterKind)}")
    adapter = AdapterKind(raw["adapter"])
    allowed = {"adapter"}
    if adapter is AdapterKind.AAP:
        allowed |= {"jobTemplateId", "jobTemplateName", "requestVariable", "reviewedPlaybook", "reviewedProjectId",
                    "reviewedProjectRevision"}
    if set(raw) != allowed:
        raise ConfigError(f"{where} must have exactly: {', '.join(sorted(allowed))}")
    if adapter is AdapterKind.SYNTHETIC and environment is not DatabaseEnvironment.SYNTHETIC:
        raise ConfigError(f"{where}: the SYNTHETIC adapter is only for a SYNTHETIC environment")
    aap = _aap_binding(raw, where) if adapter is AdapterKind.AAP else None
    return AllowlistEntry(operation, adapter, aap)


def _aap_binding(raw: dict, where: str) -> AapTemplateBinding:
    template_id, project_id = raw["jobTemplateId"], raw["reviewedProjectId"]
    for value, key in ((template_id, "jobTemplateId"), (project_id, "reviewedProjectId")):
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_TEMPLATE_ID:
            raise ConfigError(f"{where}.{key} must be a whole number from 1 to {MAX_TEMPLATE_ID}")
    variable = raw["requestVariable"]
    if not isinstance(variable, str) or not _VARIABLE_RE.match(variable):
        raise ConfigError(f"{where}.requestVariable must be a survey variable name")
    revision = raw["reviewedProjectRevision"]
    if not isinstance(revision, str) or not _REVISION_RE.match(revision):
        raise ConfigError(f"{where}.reviewedProjectRevision must be a commit hash")
    try:
        reviewed = ReviewedTemplate(template_id=template_id, name=raw["jobTemplateName"],
                                    playbook=raw["reviewedPlaybook"], project_id=project_id,
                                    project_revision=revision, survey_variables=(variable,))
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None
    return AapTemplateBinding(template_id, reviewed.name, variable, reviewed)
