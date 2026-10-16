"""Mutation policy: the single gate between OGWA and any change to an external system.

Every component that can change state in Okta, AD, AAP, or another external system
must subclass ``MutationCapableService`` and receive a ``MutationPolicy`` by explicit
injection. There is no default policy and no global fallback.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.errors import MutationBlockedError
from app.core.modes import ExecutionMode, assert_mode_permitted_by_build

_log = logging.getLogger("ogwa.mutation")

# Guards the constructor so policies come only from MutationPolicy.for_mode().
_FACTORY_TOKEN = object()


class MutationDecision(StrEnum):
    EXECUTE = "EXECUTE"
    PLAN_ONLY = "PLAN_ONLY"
    DENY = "DENY"


@dataclass(frozen=True)
class MutationRequest:
    system: str  # e.g. "okta", "ad", "aap"
    action: str  # e.g. "remove_group_member"
    target: str  # identifier of the object to change; synthetic in tests and docs
    target_is_synthetic: bool = False


@dataclass(frozen=True)
class MutationOutcome:
    request: MutationRequest
    decision: MutationDecision
    executed: bool
    reason: str
    result: Any = None


class MutationPolicy:
    __slots__ = ("_mode",)

    def __init__(self, mode: ExecutionMode, *, _token: object = None) -> None:
        if _token is not _FACTORY_TOKEN:
            raise TypeError("Create a MutationPolicy with MutationPolicy.for_mode(); direct construction is not allowed")
        if not isinstance(mode, ExecutionMode):
            raise TypeError("mode must be an ExecutionMode")
        assert_mode_permitted_by_build(mode)
        self._mode = mode

    @classmethod
    def for_mode(cls, mode: ExecutionMode) -> "MutationPolicy":
        return cls(mode, _token=_FACTORY_TOKEN)

    @property
    def mode(self) -> ExecutionMode:
        return self._mode

    def decide(self, request: MutationRequest) -> tuple[MutationDecision, str]:
        match self._mode:
            case ExecutionMode.LOCAL_SYNTHETIC if request.target_is_synthetic:
                return MutationDecision.EXECUTE, "synthetic target in LOCAL_SYNTHETIC mode"
            case ExecutionMode.LOCAL_SYNTHETIC:
                return MutationDecision.DENY, "LOCAL_SYNTHETIC mode only changes synthetic targets"
            case ExecutionMode.DRY_RUN_MUTATION:
                return MutationDecision.PLAN_ONLY, "DRY_RUN_MUTATION mode plans but never executes"
            case ExecutionMode.READ_ONLY_PRODUCTION:
                return MutationDecision.DENY, "READ_ONLY_PRODUCTION mode forbids external mutation"
            case _:
                return MutationDecision.DENY, f"{self._mode.value} is not permitted to mutate in this build"

    def __repr__(self) -> str:
        return f"MutationPolicy(mode={self._mode.value})"


def require_mutation_policy(policy: object) -> MutationPolicy:
    if not isinstance(policy, MutationPolicy):
        raise TypeError("A mutation-capable service requires an explicit MutationPolicy; none was provided")
    return policy


class MutationCapableService:
    """Base class for anything that can change state in an external system."""

    def __init__(self, *, mutation_policy: MutationPolicy) -> None:
        self._mutation_policy = require_mutation_policy(mutation_policy)

    @property
    def mutation_policy(self) -> MutationPolicy:
        return self._mutation_policy

    def _perform(self, request: MutationRequest, operation: Callable[[], Any]) -> MutationOutcome:
        """Run ``operation`` only if the policy says EXECUTE; otherwise plan or refuse."""
        decision, reason = self._mutation_policy.decide(request)
        _log.info(
            "mutation.decision",
            extra={
                "ogwa": {
                    "mode": self._mutation_policy.mode.value,
                    "system": request.system,
                    "action": request.action,
                    "target": request.target,
                    "target_is_synthetic": request.target_is_synthetic,
                    "decision": decision.value,
                }
            },
        )
        if decision is MutationDecision.DENY:
            raise MutationBlockedError(reason)
        if decision is MutationDecision.PLAN_ONLY:
            return MutationOutcome(request, decision, executed=False, reason=reason)
        # Belt and braces: this build only ever executes against synthetic targets.
        if not (self._mutation_policy.mode is ExecutionMode.LOCAL_SYNTHETIC and request.target_is_synthetic):
            raise MutationBlockedError("Execution against non-synthetic targets is not permitted in this build")
        return MutationOutcome(request, decision, executed=True, reason=reason, result=operation())
