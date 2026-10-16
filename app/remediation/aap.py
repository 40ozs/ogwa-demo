"""AAP job templates as OGWA sees them: template metadata, and its safety class.

OGWA never launches an AAP job, and this build has no AAP client: the plan-only AAP adapter
is reachable only from an allowlist that names it, which the demo refuses. This module
classifies template metadata:

- ``KNOWN_READ_ONLY``: a job template in check mode whose job type cannot be changed at
  launch, that takes no extra variables, SCM branch, inventory, or credential at launch, and
  that matches, field for field, a reviewed record pinned in deployment configuration
  (template id, name, playbook, project, the project's revision, and the survey variables).
  Check mode alone proves nothing: a task can opt out with ``check_mode: false``. Only a
  human review of the pinned playbook revision makes a template known read-only.
- ``MUTATION_CAPABLE``: a job template that runs in ``run`` mode, or whose job type can be
  switched at launch.
- ``UNKNOWN``: everything else: every workflow (a workflow can run any node type, and its
  node graph is not evaluated here), incomplete metadata, and every check-mode template
  without a matching reviewed record.

``UNKNOWN`` is treated exactly like ``MUTATION_CAPABLE``: neither is ever launched. The
``relevance`` terms only help a person find templates that look related to group lifecycle
work; they never change a classification.

This module is pure: it reads nothing and imports no HTTP client.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

MAX_TEMPLATE_ID = 1_000_000_000
SURVEY_TYPES = frozenset({"text", "textarea", "password", "integer", "float", "multiplechoice", "multiselect"})
# Words that suggest a template touches group lifecycle work. Triage only (see module doc).
RELEVANCE_TERMS = ("ogwa", "okta", "active directory", "adgroup", "ad_group", "ad-group", "ad group",
                   "group removal", "groupremoval", "quarantine", "unassign")


class TemplateKind(StrEnum):
    JOB_TEMPLATE = "job_template"
    WORKFLOW_JOB_TEMPLATE = "workflow_job_template"


class TemplateSafety(StrEnum):
    KNOWN_READ_ONLY = "KNOWN_READ_ONLY"
    MUTATION_CAPABLE = "MUTATION_CAPABLE"
    UNKNOWN = "UNKNOWN"


def _check_template_id(value: object, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_TEMPLATE_ID:
        raise ValueError(f"{what} must be a whole number from 1 to {MAX_TEMPLATE_ID}")
    return value


def _check_label(value: object, what: str, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"{what} must be a non-empty string of at most {max_length} characters")
    return value


@dataclass(frozen=True)
class SurveyQuestion:
    """One survey input. Defaults and choices are never kept; a password's value is never read."""

    variable: str
    type: str
    required: bool

    def __post_init__(self) -> None:
        _check_label(self.variable, "survey variable", 128)
        if self.type not in SURVEY_TYPES:
            raise ValueError(f"unknown survey question type {str(self.type)[:30]!r}")
        if not isinstance(self.required, bool):
            raise ValueError("required must be a bool")

    @property
    def secret(self) -> bool:
        return self.type == "password"


@dataclass(frozen=True)
class TemplateMetadata:
    kind: TemplateKind
    template_id: int
    name: str
    job_type: str | None  # "run" or "check"; None for a workflow
    playbook: str | None
    project_id: int | None
    ask_job_type_on_launch: bool
    ask_variables_on_launch: bool
    ask_scm_branch_on_launch: bool
    ask_inventory_on_launch: bool
    ask_credential_on_launch: bool
    survey_enabled: bool
    survey: tuple[SurveyQuestion, ...] | None = None  # None: not read
    project_revision: str | None = None  # read only for templates a reviewed record pins

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TemplateKind):
            raise ValueError("kind must be a TemplateKind")
        _check_template_id(self.template_id, "template_id")
        _check_label(self.name, "name")
        for name in ("ask_job_type_on_launch", "ask_variables_on_launch", "ask_scm_branch_on_launch",
                     "ask_inventory_on_launch", "ask_credential_on_launch", "survey_enabled"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a bool")
        if self.survey is not None and not (isinstance(self.survey, tuple)
                                            and all(isinstance(q, SurveyQuestion) for q in self.survey)):
            raise ValueError("survey must be a tuple of SurveyQuestion or None")
        if self.project_id is not None:
            _check_template_id(self.project_id, "project_id")

    @property
    def survey_variables(self) -> tuple[str, ...] | None:
        return None if self.survey is None else tuple(sorted(q.variable for q in self.survey))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value, "id": self.template_id, "name": self.name, "jobType": self.job_type,
            "playbook": self.playbook, "projectId": self.project_id, "projectRevision": self.project_revision,
            "askJobTypeOnLaunch": self.ask_job_type_on_launch, "askVariablesOnLaunch": self.ask_variables_on_launch,
            "askScmBranchOnLaunch": self.ask_scm_branch_on_launch,
            "askInventoryOnLaunch": self.ask_inventory_on_launch,
            "askCredentialOnLaunch": self.ask_credential_on_launch, "surveyEnabled": self.survey_enabled,
            "survey": None if self.survey is None else [
                {"variable": q.variable, "type": q.type, "required": q.required, "secret": q.secret}
                for q in self.survey],
        }


@dataclass(frozen=True)
class ReviewedTemplate:
    """A human review of one job template, pinned in deployment configuration. The only way
    a template can be KNOWN_READ_ONLY."""

    template_id: int
    name: str
    playbook: str
    project_id: int
    project_revision: str
    survey_variables: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_template_id(self.template_id, "template_id")
        _check_label(self.name, "name")
        _check_label(self.playbook, "playbook")
        _check_template_id(self.project_id, "project_id")
        _check_label(self.project_revision, "project_revision", 100)
        if not isinstance(self.survey_variables, tuple) or list(self.survey_variables) != sorted(set(self.survey_variables)):
            raise ValueError("survey_variables must be a sorted tuple without duplicates")
        for variable in self.survey_variables:
            _check_label(variable, "survey variable", 128)


@dataclass(frozen=True)
class TemplateClassification:
    template: TemplateMetadata
    safety: TemplateSafety
    reasons: tuple[str, ...]
    relevance: tuple[str, ...] = ()

    @property
    def launchable_for_what_if(self) -> bool:
        """Even a known read-only template is never launched in this build; this says only
        whether a future build could prepare a what-if launch of it."""
        return self.safety is TemplateSafety.KNOWN_READ_ONLY

    def to_dict(self) -> dict[str, Any]:
        return {"template": self.template.to_dict(), "safety": self.safety.value, "reasons": list(self.reasons),
                "relevance": list(self.relevance), "launched": False}


def relevance_terms(meta: TemplateMetadata) -> tuple[str, ...]:
    text = f"{meta.name} {meta.playbook or ''}".lower()
    return tuple(term for term in RELEVANCE_TERMS if term in text)


def classify_template(meta: TemplateMetadata, reviewed: Iterable[ReviewedTemplate] = ()) -> TemplateClassification:
    """The template's safety class and why. Fails closed: anything not proven is UNKNOWN."""
    if not isinstance(meta, TemplateMetadata):
        raise TypeError("meta must be TemplateMetadata")
    relevance = relevance_terms(meta)

    def result(safety: TemplateSafety, *reasons: str) -> TemplateClassification:
        return TemplateClassification(meta, safety, tuple(reasons), relevance)

    if meta.kind is TemplateKind.WORKFLOW_JOB_TEMPLATE:
        return result(TemplateSafety.UNKNOWN, "a workflow can run any node type (job templates, project or inventory "
                                              "updates, approvals); its node graph is not evaluated, so it is never "
                                              "known read-only")
    mutation = []
    if meta.job_type == "run":
        mutation.append("job_type is run: the playbook makes changes")
    if meta.ask_job_type_on_launch:
        mutation.append("the job type can be switched to run at launch")
    if mutation:
        return result(TemplateSafety.MUTATION_CAPABLE, *mutation)
    if meta.job_type != "check":
        return result(TemplateSafety.UNKNOWN, f"unrecognised job_type {str(meta.job_type)[:20]!r}")

    pins = [r for r in reviewed if r.template_id == meta.template_id]
    if not pins:
        return result(TemplateSafety.UNKNOWN, "check mode is not proof of read-only (a task can opt out with "
                                              "check_mode: false), and no reviewed record pins this template")
    pin = pins[0]
    drift = []
    if meta.name != pin.name:
        drift.append("its name")
    if meta.playbook != pin.playbook:
        drift.append("its playbook")
    if meta.project_id != pin.project_id:
        drift.append("its project")
    if meta.project_revision is None:
        drift.append("its project revision (not read)")
    elif meta.project_revision != pin.project_revision:
        drift.append("its project revision (the playbook content may have changed)")
    if meta.survey_variables is None:
        drift.append("its survey (not read)")
    elif meta.survey_variables != pin.survey_variables:
        drift.append("its survey variables")
    for flag, what in (("ask_variables_on_launch", "extra variables"), ("ask_scm_branch_on_launch", "an SCM branch"),
                       ("ask_inventory_on_launch", "an inventory"), ("ask_credential_on_launch", "credentials")):
        if getattr(meta, flag):
            drift.append(f"it accepts {what} at launch")
    if drift:
        return result(TemplateSafety.UNKNOWN, "the template no longer matches its reviewed record: " + "; ".join(drift))
    return result(TemplateSafety.KNOWN_READ_ONLY, "check mode with a fixed job type, matching its reviewed record "
                                                  "(name, playbook, project revision, survey) field for field")
