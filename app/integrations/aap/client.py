"""Read-only AAP discovery: job-template and workflow metadata, survey contracts, and the
safety class of each template (P10). GET requests only.

This client never launches, creates, edits, copies, or deletes anything in AAP. It is built
on ``ReadOnlyHttpClient`` (GET and HEAD only) and imports neither the mutating client nor
the mutation policy. It reads, in this order:

1. ``GET /api/v2/me/``: whether the identity is a superuser. A superuser is refused before
   any other request. Discovery must run as a dedicated read-only OGWA identity (D123),
   separate from any that can change AAP (docs/security/credentials.md); only the user id
   and the two role flags are kept, never a name or an email address.
2. ``GET /api/v2/users/{id}/roles/``, ``/users/{id}/teams/``, and each team's
   ``/teams/{id}/roles/``: every role the identity holds, directly or through a team, must
   be read-only (``Read``, ``Auditor``, ``Member``). The System Auditor flag is accepted and
   is the most an OGWA identity may hold (D124). Any other role, or roles that cannot be read
   completely, refuse the identity before any template is listed: it must not be able to
   launch, create, update, delete, or administer AAP objects (D125).
3. ``GET /api/v2/job_templates/`` and ``GET /api/v2/workflow_job_templates/``: paged with a
   page budget, following ``next`` only on the same origin and path, and never twice. Each
   template also reports what this identity may do to it (``user_capabilities``). Any of
   start, edit, delete, copy, or schedule stops discovery (D125); a template that does not
   report them makes the report PARTIAL.
4. ``GET /api/v2/{job,workflow_job}_templates/{id}/survey_spec/``: each question's variable,
   type, and whether it is required. Defaults and choices are never kept, so a password
   question's value is never read into OGWA.
5. ``GET /api/v2/projects/{id}/``: the project's SCM revision, only for a template that a
   reviewed record pins (the only templates that could be KNOWN_READ_ONLY).

Anything malformed, cut short, or over budget makes the report PARTIAL; a template that
cannot be read is reported as a problem, never as safe. Classification is
``app.remediation.aap.classify_template``.

No live run happened in P10: no approved read-only OGWA AAP identity exists.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.http_client import HttpResponse, ReadOnlyHttpClient
from app.core.modes import ExecutionMode
from app.core.secret import Secret
from app.remediation.aap import (
    ReviewedTemplate,
    SurveyQuestion,
    TemplateClassification,
    TemplateKind,
    TemplateMetadata,
    classify_template,
)

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 200
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_REQUESTS = 300
_JOB_TEMPLATE_FLAGS = ("ask_job_type_on_launch", "ask_variables_on_launch", "ask_scm_branch_on_launch",
                       "ask_inventory_on_launch", "ask_credential_on_launch", "survey_enabled")
# Discovery runs in READ_ONLY_PRODUCTION, or against a loopback test server in LOCAL_SYNTHETIC.
DISCOVERY_MODES = frozenset({ExecutionMode.READ_ONLY_PRODUCTION, ExecutionMode.LOCAL_SYNTHETIC})
# AAP roles that only read. Every other role (Admin, Execute, Update, Use, Approve, the
# "... Admin" roles, Ad Hoc) can launch, create, change, or administer something (D125).
READ_ONLY_ROLE_NAMES = frozenset({"Read", "Auditor", "Member"})
# What a template reports this identity may do to it; any of them is a write (D125).
WRITE_CAPABILITIES = ("start", "edit", "delete", "copy", "schedule")
MAX_TEAMS = 50


class AapDiscoveryError(Exception):
    """Discovery could not proceed: configuration, an AAP refusal, or a malformed answer."""


class AapIdentityRefused(AapDiscoveryError):
    """The identity could change AAP. Discovery runs only as a read-only identity."""


@dataclass(frozen=True)
class AapIdentity:
    user_id: int
    is_superuser: bool
    is_system_auditor: bool
    roles: tuple[str, ...] = ()  # the read-only role names held, directly or through teams, once verified
    read_only_verified: bool = False


@dataclass(frozen=True)
class DiscoveryReport:
    identity: AapIdentity
    complete: bool
    classifications: tuple[TemplateClassification, ...]
    problems: tuple[str, ...]
    requests_made: int

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for c in self.classifications:
            counts[c.safety.value] = counts.get(c.safety.value, 0) + 1
        return {
            "identity": {"userId": self.identity.user_id, "isSuperuser": self.identity.is_superuser,
                         "isSystemAuditor": self.identity.is_system_auditor, "roles": list(self.identity.roles),
                         "readOnlyVerified": self.identity.read_only_verified},
            "status": "COMPLETE" if self.complete else "PARTIAL", "countsBySafety": counts,
            "candidates": [c.to_dict() for c in self.classifications if c.relevance],
            "templates": [c.to_dict() for c in self.classifications], "problems": list(self.problems),
            "requestsMade": self.requests_made, "launched": 0,
        }


def _int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{what} is not a positive whole number")
    return value


def _bool(raw: dict, name: str) -> bool:
    value = raw.get(name)
    if not isinstance(value, bool):
        raise ValueError(f"{name} is missing or not a boolean")
    return value


class AapReadOnlyClient:
    def __init__(self, *, base_url: str, token: Secret, http: ReadOnlyHttpClient, page_size: int = DEFAULT_PAGE_SIZE,
                 max_pages: int = DEFAULT_MAX_PAGES, max_requests: int = DEFAULT_MAX_REQUESTS) -> None:
        if not isinstance(http, ReadOnlyHttpClient):
            raise TypeError("AAP discovery uses the read-only HTTP client")
        if not isinstance(token, Secret):
            raise TypeError("the AAP token must be a Secret")
        if http.mode not in DISCOVERY_MODES:
            raise AapDiscoveryError(f"AAP discovery does not run in {http.mode.value} mode")
        if not 1 <= page_size <= MAX_PAGE_SIZE or not 1 <= max_pages <= 100 or not 1 <= max_requests <= 1000:
            raise ValueError("page_size, max_pages, or max_requests is out of range")
        parts = urlsplit(base_url)
        if not parts.scheme or not parts.hostname or parts.query or parts.fragment or parts.username:
            raise AapDiscoveryError("the AAP base URL must be scheme://host[:port] without credentials or query")
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._token = token
        self._http = http
        self._page_size = page_size
        self._max_pages = max_pages
        self._max_requests = max_requests
        self._requests = 0

    @classmethod
    def from_settings(cls, settings: Settings, *, transport=None, **kwargs: Any) -> "AapReadOnlyClient":
        """The client for OGWA_AAP_URL with OGWA_AAP_TOKEN. Both must be set; the token comes from
        an approved source (docs/security/credentials.md) and is never logged or stored."""
        if settings.mode not in DISCOVERY_MODES:
            raise AapDiscoveryError(f"AAP discovery does not run in {settings.mode.value} mode")
        if not settings.aap_url or settings.aap_token is None:
            raise AapDiscoveryError("AAP discovery needs OGWA_AAP_URL and a read-only OGWA_AAP_TOKEN")
        http = ReadOnlyHttpClient(mode=settings.mode, http_policy=settings.http,
                                  allowed_hosts=[urlsplit(settings.aap_url).hostname], transport=transport)
        return cls(base_url=settings.aap_url, token=settings.aap_token, http=http, **kwargs)

    @property
    def requests_made(self) -> int:
        return self._requests

    # --- transport ---------------------------------------------------------------------

    def _get_json(self, path: str) -> Any:
        if self._requests >= self._max_requests:
            raise AapDiscoveryError("the AAP request budget is spent")
        self._requests += 1
        response: HttpResponse = self._http.get(self._origin + path,
                                                headers={"Authorization": f"Bearer {self._token.reveal()}"})
        if response.status in (401, 403):
            raise AapDiscoveryError(f"AAP refused the request ({response.status}); check the read-only identity")
        if response.status == 404:
            return None
        if response.status != 200:
            raise AapDiscoveryError(f"AAP answered {response.status}")
        try:
            return json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AapDiscoveryError("AAP's answer is not JSON") from None

    def _list(self, endpoint: str) -> tuple[list[dict], bool]:
        """Every item of a paged listing, and whether every page was read."""
        path = f"/api/v2/{endpoint}/"
        url = f"{path}?page_size={self._page_size}&order_by=id"
        seen: set[str] = set()
        items: list[dict] = []
        for _ in range(self._max_pages):
            if url in seen:
                return items, False  # a page that leads back to itself
            seen.add(url)
            data = self._get_json(url)
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
                return items, False
            items.extend(results)
            following = data.get("next")
            if following is None:
                return items, True
            parts = urlsplit(str(following))
            if (parts.scheme or parts.netloc) and f"{parts.scheme}://{parts.netloc}" != self._origin:
                return items, False  # never follow a link to another origin
            if parts.path != path:
                return items, False
            url = parts.path + (f"?{parts.query}" if parts.query else "")
        return items, False  # page budget spent

    # --- reads -------------------------------------------------------------------------

    def identity(self) -> AapIdentity:
        data = self._get_json("/api/v2/me/")
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict):
            raise AapDiscoveryError("AAP did not describe exactly one current user")
        user = results[0]
        try:
            return AapIdentity(_int(user.get("id"), "user id"), _bool(user, "is_superuser"),
                               _bool(user, "is_system_auditor"))
        except ValueError as exc:
            raise AapDiscoveryError(f"AAP's description of the current user is malformed: {exc}") from None

    def _roles(self, endpoint: str, holder: str) -> tuple[list[str], list[str]]:
        """(role names, problems) for one role listing. A listing that cannot be read
        completely refuses the identity: its scope cannot be confirmed (D125)."""
        roles, complete = self._list(endpoint)
        if not complete:
            raise AapIdentityRefused(f"the roles {holder} holds could not be read completely, so the identity's "
                                     "read-only scope cannot be confirmed (D125)")
        names, problems = [], []
        for role in roles:
            name = role.get("name")
            summary = role.get("summary_fields") if isinstance(role.get("summary_fields"), dict) else {}
            resource = summary.get("resource_type")
            where = f" on a {str(resource)[:40]}" if isinstance(resource, str) and resource else ""
            if isinstance(name, str) and name in READ_ONLY_ROLE_NAMES:
                names.append(name)
            else:
                problems.append(f"{holder} holds the role {str(name)[:40]!r}{where}")
        return names, problems

    def verify_read_only(self, identity: AapIdentity) -> AapIdentity:
        """The identity, once every role it holds, directly or through a team, is proven read-only.

        Refuses a superuser and any other role: an OGWA identity must not be able to launch,
        create, update, delete, or administer AAP objects (D125). The System Auditor flag is
        accepted, and is the most it may hold (D124)."""
        if identity.is_superuser:
            raise AapIdentityRefused("the AAP identity is a superuser, which can change AAP; discovery runs only as "
                                     "a dedicated read-only identity (D123, D125)")
        names, problems = self._roles(f"users/{identity.user_id}/roles", "the identity")
        teams, complete = self._list(f"users/{identity.user_id}/teams")
        if not complete or len(teams) > MAX_TEAMS:
            raise AapIdentityRefused("the identity's teams could not be read completely, so its read-only scope "
                                     "cannot be confirmed (D125)")
        for team in teams:
            try:
                team_id = _int(team.get("id"), "team id")
            except ValueError:
                raise AapIdentityRefused("a team of the identity is malformed, so its read-only scope cannot be "
                                         "confirmed (D125)") from None
            team_names, team_problems = self._roles(f"teams/{team_id}/roles", f"team {team_id}")
            names += team_names
            problems += team_problems
        if problems:
            raise AapIdentityRefused("the AAP identity can do more than read, and an OGWA identity must not be able to "
                                     "launch, create, update, delete, or administer AAP objects (D125): "
                                     + "; ".join(problems[:10]))
        return replace(identity, roles=tuple(sorted(set(names))), read_only_verified=True)

    @staticmethod
    def _capabilities(kind: TemplateKind, raw: dict) -> list[str] | None:
        """What the template says this identity may do to it that is a write; None if it does
        not say (the identity's scope is then unconfirmed for it)."""
        summary = raw.get("summary_fields")
        capabilities = summary.get("user_capabilities") if isinstance(summary, dict) else None
        if not isinstance(capabilities, dict):
            return None
        writes = []
        for name in WRITE_CAPABILITIES:
            value = capabilities.get(name, False)
            if not isinstance(value, bool):
                return None
            if value:
                writes.append(name)
        return writes

    def survey(self, kind: TemplateKind, template_id: int) -> tuple[SurveyQuestion, ...] | None:
        """The survey's questions, or None if it could not be read. Defaults are never kept."""
        data = self._get_json(f"/api/v2/{kind.value}s/{template_id}/survey_spec/")
        if data is None:
            return None  # 404: not read, which is never the same as an empty survey
        if data == {}:
            return ()
        spec = data.get("spec") if isinstance(data, dict) else None
        if not isinstance(spec, list) or not all(isinstance(q, dict) for q in spec):
            return None
        try:
            return tuple(SurveyQuestion(q.get("variable"), q.get("type"), q.get("required")) for q in spec)
        except ValueError:
            return None

    def project_revision(self, project_id: int) -> str | None:
        data = self._get_json(f"/api/v2/projects/{project_id}/")
        revision = data.get("scm_revision") if isinstance(data, dict) else None
        return revision if isinstance(revision, str) and revision else None

    @staticmethod
    def _metadata(kind: TemplateKind, raw: dict) -> TemplateMetadata:
        if kind is TemplateKind.JOB_TEMPLATE:
            flags = {name: _bool(raw, name) for name in _JOB_TEMPLATE_FLAGS}
            job_type = raw.get("job_type")
            if not isinstance(job_type, str):
                raise ValueError("job_type is missing")
            playbook, project = raw.get("playbook"), raw.get("project")
            return TemplateMetadata(kind, _int(raw.get("id"), "id"), str(raw.get("name") or ""), job_type,
                                    playbook if isinstance(playbook, str) and playbook else None,
                                    project if isinstance(project, int) and not isinstance(project, bool) else None,
                                    **flags)
        # A workflow is never known read-only, so missing launch flags are recorded as True
        # (the less safe reading): nothing about it can look safer than it is.
        flags = {name: raw.get(name) if isinstance(raw.get(name), bool) else True for name in _JOB_TEMPLATE_FLAGS}
        flags["survey_enabled"] = _bool(raw, "survey_enabled")
        return TemplateMetadata(kind, _int(raw.get("id"), "id"), str(raw.get("name") or ""), None, None, None, **flags)

    def discover(self, *, reviewed: Iterable[ReviewedTemplate] = (), max_surveys: int = 100) -> DiscoveryReport:
        """Read and classify every job template and workflow the identity can see. Launches nothing.

        The identity is verified read-only first (D125); a template that says the identity could
        start, edit, delete, copy, or schedule it stops discovery at once."""
        identity = self.verify_read_only(self.identity())
        reviewed = tuple(reviewed)
        pinned = {r.template_id for r in reviewed}
        problems: list[str] = []
        complete = True
        metadata: list[TemplateMetadata] = []
        surveys_read = 0
        for kind, endpoint in ((TemplateKind.JOB_TEMPLATE, "job_templates"),
                               (TemplateKind.WORKFLOW_JOB_TEMPLATE, "workflow_job_templates")):
            items, listed = self._list(endpoint)
            if not listed:
                complete = False
                problems.append(f"the {endpoint} listing was not read completely")
            # The identity's own capabilities first, before anything else is read (D125).
            for raw in items:
                writes = self._capabilities(kind, raw)
                if writes:
                    raise AapIdentityRefused(f"the AAP identity could {', '.join(writes)} {kind.value} "
                                             f"{str(raw.get('id'))[:20]}; an OGWA identity must not be able to launch "
                                             "or change AAP objects (D125). Discovery stopped")
            for raw in items:
                label = f"{kind.value} {str(raw.get('id'))[:20]}"
                if self._capabilities(kind, raw) is None:
                    complete = False
                    problems.append(f"{label}: AAP does not report the identity's capabilities on it, so its "
                                    "read-only scope is unconfirmed there")
                try:
                    meta = self._metadata(kind, raw)
                except ValueError as exc:
                    complete = False
                    problems.append(f"{label}: {exc}")
                    continue
                if not meta.survey_enabled:
                    meta = replace(meta, survey=())
                elif surveys_read < max_surveys:
                    surveys_read += 1
                    meta = replace(meta, survey=self.survey(kind, meta.template_id))
                if meta.survey is None:  # not read (404, malformed, over budget): never an empty survey (F10)
                    complete = False
                    problems.append(f"{label}: its survey was not read, so the template stays UNKNOWN")
                if meta.template_id in pinned and kind is TemplateKind.JOB_TEMPLATE and meta.project_id is not None:
                    meta = replace(meta, project_revision=self.project_revision(meta.project_id))
                metadata.append(meta)
        classifications = tuple(classify_template(m, reviewed) for m in metadata)
        return DiscoveryReport(identity, complete, classifications, tuple(problems), self._requests)
