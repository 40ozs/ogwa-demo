"""Remediation adapters: where a request that passed every gate is answered.

Every adapter is a ``MutationCapableService`` holding a ``DRY_RUN_MUTATION`` mutation policy,
which can only ever answer PLAN_ONLY, and passes ``_never`` as the operation, so the
mutation-policy guardrail itself proves that nothing runs. No adapter has a code path that contacts or
changes an external system:

- ``SyntheticRemediationAdapter`` answers ``SIMULATED``: it computes the change against the
  synthetic world's recorded evidence. It serves a SYNTHETIC store only and refuses any
  non-synthetic evidence.
- ``AapRemediationAdapter`` answers ``VALIDATION_ONLY``: it builds the launch of the one
  allowlisted AAP job template, carrying a ``WhatIf`` worker request, and validates it
  against the template's observed metadata and its reviewed record. It never sends it: it
  holds no HTTP client, and the mutating client may not be imported (D8). A template that
  is not KNOWN_READ_ONLY, or has not been observed, is BLOCKED.

``WHATIF`` comes from the PowerShell worker (``app.remediation.worker``), never from here.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from app.core.errors import MutationBlockedError
from app.core.modes import ExecutionMode
from app.core.safety import MutationCapableService, MutationDecision, MutationPolicy, MutationRequest
from app.domain.evidence import EvidenceSource, stable_digest
from app.domain.policy import EvidenceBundle
from app.domain.quarantine import QuarantineOus
from app.domain.remediation import (
    PlannedChange,
    RemediationOperation,
    RemediationOutcome,
    RemediationTarget,
)
from app.remediation.aap import TemplateMetadata, TemplateSafety, classify_template
from app.remediation.allowlist import AdapterKind, AllowlistEntry
from app.remediation.worker import worker_request
from app.store.environment import DatabaseEnvironment

O = RemediationOperation
SIMULATION_NOTE = "simulated against the synthetic world's recorded evidence; no system was contacted or changed"
AAP_VALIDATION_NOTE = ("the launch request was built and validated against the allowlisted, reviewed template; "
                       "it was never sent, because this build cannot launch AAP jobs")


@dataclass(frozen=True)
class RemediationPlan:
    """A request that passed every gate: one operation on one resolved target."""

    candidate_id: str
    operation: RemediationOperation
    target: RemediationTarget
    evidence: EvidenceBundle
    entry: AllowlistEntry
    correlation_id: str
    # The deployment's quarantine OUs (D136): where a quarantine would move the group.
    quarantine_ous: QuarantineOus | None = None


@dataclass(frozen=True)
class AdapterAnswer:
    outcome: RemediationOutcome
    planned_changes: tuple[PlannedChange, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.outcome is RemediationOutcome.BLOCKED:
            if not self.notes or self.planned_changes:
                raise ValueError("a BLOCKED answer gives its reason and plans nothing")
        elif not self.planned_changes:
            raise ValueError(f"a {self.outcome.value} answer describes the change")


def refused(reason: str) -> AdapterAnswer:
    return AdapterAnswer(RemediationOutcome.BLOCKED, notes=(reason,))


class RemediationAdapter(MutationCapableService):
    """Base class. Its mutation policy is DRY_RUN_MUTATION, so ``_perform`` can only plan."""

    name: ClassVar[str] = "ABSTRACT"
    answers: ClassVar[frozenset[RemediationOutcome]] = frozenset({RemediationOutcome.BLOCKED})

    def __init__(self) -> None:
        super().__init__(mutation_policy=MutationPolicy.for_mode(ExecutionMode.DRY_RUN_MUTATION))

    def dry_run(self, plan: RemediationPlan) -> AdapterAnswer:
        if not isinstance(plan, RemediationPlan):
            raise TypeError("plan must be a RemediationPlan")
        if plan.entry.operation is not plan.operation:
            return refused("the allowlist entry is for a different operation")
        answer = self._answer(plan)
        if answer.outcome not in self.answers:
            raise MutationBlockedError(f"the {self.name} adapter cannot answer {answer.outcome.value}")
        return answer

    def _answer(self, plan: RemediationPlan) -> AdapterAnswer:
        raise NotImplementedError

    def _plan_only(self, system: str, action: str, target: str, *, synthetic: bool) -> None:
        outcome = self._perform(MutationRequest(system=system, action=action, target=target,
                                                target_is_synthetic=synthetic), self._never)
        if outcome.decision is not MutationDecision.PLAN_ONLY or outcome.executed:
            raise MutationBlockedError("a remediation adapter produced something other than a plan")

    @staticmethod
    def _never() -> None:
        raise MutationBlockedError("a remediation adapter never executes in this build (D8)")


# --- distinguished names -----------------------------------------------------------------


def split_rdn(dn: str) -> tuple[str, str]:
    """(first RDN, parent DN), splitting at the first comma that is not escaped."""
    escaped = False
    for index, char in enumerate(dn):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ",":
            return dn[:index], dn[index + 1:]
    return dn, ""


# --- the synthetic adapter -------------------------------------------------------------


class SyntheticRemediationAdapter(RemediationAdapter):
    name = "SYNTHETIC"
    answers = frozenset({RemediationOutcome.SIMULATED, RemediationOutcome.BLOCKED})

    def _answer(self, plan: RemediationPlan) -> AdapterAnswer:
        if plan.entry.adapter is not AdapterKind.SYNTHETIC:
            return refused("the allowlist does not assign this operation to the synthetic adapter")
        if any(r.provenance.source is not EvidenceSource.SYNTHETIC for r in plan.evidence.records()):
            return refused("the synthetic adapter simulates synthetic targets only; this evidence is not synthetic")
        if plan.operation is O.OKTA_GROUP_UNASSIGN:
            return self._unassign(plan)
        if plan.operation is O.AD_GROUP_QUARANTINE:
            return self._quarantine(plan)
        return self._delete(plan)

    def _unassign(self, plan: RemediationPlan) -> AdapterAnswer:
        ev, target = plan.evidence, plan.target
        assignment = ev.assignment(target.target_id)
        application = next((a for a in ev.applications if assignment and a.id == assignment.application_id), None)
        group = ev.okta_group
        if assignment is None or application is None or group is None:
            return refused("the assignment, its application, or its group is not in the recorded evidence")
        if not assignment.present:
            return refused("the assignment was already observed absent")
        others = sum(1 for a in ev.assignments if a.present and a.id != assignment.id)
        self._plan_only("okta", "unassign_group_from_application", target.target_id, synthetic=True)
        return AdapterAnswer(RemediationOutcome.SIMULATED, (PlannedChange(
            "okta", "unassign_group_from_application", target.target_id,
            f"Remove the assignment of Okta group {group.okta_group_id} ({group.name}) to application "
            f"{application.okta_app_id} ({application.label}).",
            details=(("after.present", "false"), ("before.present", "true"), ("okta_app_id", application.okta_app_id),
                     ("okta_group_id", group.okta_group_id), ("other_assignments_of_candidate", str(others)))),),
            (SIMULATION_NOTE,))

    def _quarantine(self, plan: RemediationPlan) -> AdapterAnswer:
        ad = plan.evidence.ad_group
        ou = plan.quarantine_ous.ou_for(ad.domain) if plan.quarantine_ous is not None else None
        if ou is None:
            return refused(f"no quarantine OU is configured for {ad.domain} (D136)")
        rdn, parent = split_rdn(ad.distinguished_name)
        if parent.lower() == ou.lower():
            return refused("the group is already in the quarantine OU")
        moved = f"{rdn},{ou}"
        self._plan_only("ad", "move_group_to_quarantine", ad.id, synthetic=True)
        return AdapterAnswer(RemediationOutcome.SIMULATED, (PlannedChange(
            "ad", "move_group_to_quarantine", ad.id,
            f"Move AD group {ad.sam_account_name} ({ad.object_guid}, {ad.domain}) into the quarantine OU.",
            details=(("after.distinguishedName", moved), ("before.distinguishedName", ad.distinguished_name),
                     ("domain", ad.domain), ("objectGUID", ad.object_guid))),),
            (SIMULATION_NOTE,))

    def _delete(self, plan: RemediationPlan) -> AdapterAnswer:
        ad = plan.evidence.ad_group
        if ad.member_count != 0:
            return refused("the group must be observed with zero direct members before a deletion is simulated")
        self._plan_only("ad", "delete_group", ad.id, synthetic=True)
        return AdapterAnswer(RemediationOutcome.SIMULATED, (PlannedChange(
            "ad", "delete_group", ad.id, f"Delete AD group {ad.sam_account_name} ({ad.object_guid}) in {ad.domain}.",
            details=(("distinguishedName", ad.distinguished_name), ("domain", ad.domain),
                     ("objectGUID", ad.object_guid), ("objectSid", ad.sid))),),
            (SIMULATION_NOTE,))


# --- the AAP adapter -------------------------------------------------------------------


class AapRemediationAdapter(RemediationAdapter):
    """Validates, and never sends, the launch of the one allowlisted job template.

    ``observed`` is template metadata from read-only discovery, keyed by template id. This
    adapter holds no HTTP client: it cannot read AAP, let alone launch a job."""

    name = "AAP"
    answers = frozenset({RemediationOutcome.VALIDATION_ONLY, RemediationOutcome.BLOCKED})

    def __init__(self, observed: Mapping[int, TemplateMetadata] | None = None) -> None:
        super().__init__()
        self._observed = dict(observed or {})

    def _answer(self, plan: RemediationPlan) -> AdapterAnswer:
        binding = plan.entry.aap
        if plan.entry.adapter is not AdapterKind.AAP or binding is None:
            return refused("no AAP job template is allowlisted for this operation")
        observed = self._observed.get(binding.template_id)
        if observed is None:
            return refused(f"AAP job template {binding.template_id} has not been observed by read-only discovery, so "
                           "it cannot be validated")
        classification = classify_template(observed, (binding.reviewed,))
        if classification.safety is not TemplateSafety.KNOWN_READ_ONLY:
            return refused(f"AAP job template {binding.template_id} is {classification.safety.value} "
                           f"({'; '.join(classification.reasons)}); only a reviewed what-if template may be prepared")
        question = next((q for q in observed.survey or () if q.variable == binding.request_variable), None)
        if question is None or question.secret or question.type not in ("text", "textarea"):
            return refused("the template's survey has no plain-text variable to carry the worker request")
        quarantine_ou = None
        if plan.operation is O.AD_GROUP_QUARANTINE:
            domain = plan.target.value("domain") or ""
            quarantine_ou = plan.quarantine_ous.ou_for(domain) if plan.quarantine_ous is not None else None
            if quarantine_ou is None:
                return refused("no quarantine OU is configured for the group's domain (D136)")
        request = worker_request(plan.operation, plan.target, mode="WhatIf", correlation_id=plan.correlation_id,
                                 quarantine_ou=quarantine_ou)
        payload = {"extra_vars": {binding.request_variable: json.dumps(request, sort_keys=True)}}
        self._plan_only("aap", f"launch_job_template:{binding.template_id}", plan.target.target_id, synthetic=False)
        return AdapterAnswer(RemediationOutcome.VALIDATION_ONLY, (PlannedChange(
            "aap", "launch_job_template", plan.target.target_id,
            f"Would launch AAP job template {binding.template_id} ({binding.template_name}) in check mode with a "
            "WhatIf worker request. Not sent: this build cannot launch AAP jobs.",
            details=(("job_template_id", str(binding.template_id)), ("job_type", "check"),
                     ("launch_payload_digest", stable_digest(payload)), ("worker_mode", "WhatIf"))),),
            (AAP_VALIDATION_NOTE,))


def adapter_for(entry: AllowlistEntry, *, environment: DatabaseEnvironment,
                observed_templates: Mapping[int, TemplateMetadata] | None = None) -> RemediationAdapter:
    """The adapter the server-side allowlist assigns to an operation."""
    if entry.adapter is AdapterKind.SYNTHETIC:
        if environment is not DatabaseEnvironment.SYNTHETIC:
            raise MutationBlockedError("the synthetic remediation adapter serves a SYNTHETIC store only")
        return SyntheticRemediationAdapter()
    return AapRemediationAdapter(observed_templates)
