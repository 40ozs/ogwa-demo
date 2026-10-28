"""Candidate-classification policy (P07): thresholds, their document form, and versions.

``CandidatePolicy`` holds every threshold the classifier uses. None of them is business
truth in code: each has a default, a floor or ceiling the configuration cannot cross, and
a place in a strict JSON document (``to_document`` / ``from_document``). The lifecycle's
own policy (``LifecyclePolicy``) is part of the document, so the classifier and the
lifecycle guards always judge a candidate by the same numbers.

A configuration change is a ``PolicyVersion``: the canonical document, its digest, the
Identity/Automation human who proposed it, a **different** Security/IAM human who approved
it (D33), and why. Versions form one
append-only chain (``version_append_problems``); the store keeps them and audits each one.
Every classification names the digest of the policy that produced it.

A policy decides what is worth a human's attention. It never authorizes a change in Okta
or AD.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from functools import cached_property
from typing import Any

from app.domain.actors import Actor, ActorKind
from app.domain.errors import InvalidRecord
from app.domain.evidence import FreshnessPolicy, check_digest, stable_digest
from app.domain.ids import IdKind, check_id, check_text, check_utc
from app.domain.model import DependencyKind
from app.domain.policy import LifecyclePolicy

POLICY_FORMAT = "ogwa-candidate-policy/v1"

# Floors and ceilings. Configuration may move a threshold inside them, never past them.
LOW_USAGE_SIGN_IN_CEILING = 1000
REVIEW_WINDOW_FLOOR = timedelta(days=7)
RECENT_LOGIN_FLOOR = timedelta(days=1)
MAX_DOCUMENT_LENGTH = 100_000


@dataclass(frozen=True)
class CandidatePolicy:
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)
    # At or below this many sign-ins in the window, usage is LOW (the conventional
    # low-usage threshold of 5). Above it, the application is in use.
    low_usage_max_sign_ins: int = 5
    # Optional second ceiling on distinct users. None: sign-ins alone decide.
    low_usage_max_unique_users: int | None = None
    # The shortest usage window that may support any usage signal. A window shorter than
    # the lifecycle's retirement window (90 days, D27) is a review signal only.
    review_min_usage_window: timedelta = timedelta(days=30)
    # High usage counts as ACTIVE only if the latest observed sign-in is this recent.
    recent_login_window: timedelta = timedelta(days=30)

    def __post_init__(self) -> None:
        if not isinstance(self.lifecycle, LifecyclePolicy):
            raise InvalidRecord("lifecycle must be a LifecyclePolicy")
        floor = self.lifecycle.max_usage_events_for_candidate
        if not _is_int(self.low_usage_max_sign_ins) or not floor <= self.low_usage_max_sign_ins <= LOW_USAGE_SIGN_IN_CEILING:
            raise InvalidRecord(
                f"low_usage_max_sign_ins must be between the candidacy threshold ({floor}) and {LOW_USAGE_SIGN_IN_CEILING}"
            )
        users = self.low_usage_max_unique_users
        if users is not None and (not _is_int(users) or not 0 <= users <= self.low_usage_max_sign_ins):
            raise InvalidRecord("low_usage_max_unique_users must be None or between 0 and low_usage_max_sign_ins")
        retirement = self.lifecycle.min_usage_window
        if not isinstance(self.review_min_usage_window, timedelta) or not (
            REVIEW_WINDOW_FLOOR <= self.review_min_usage_window <= retirement
        ):
            raise InvalidRecord(f"review_min_usage_window must be between {REVIEW_WINDOW_FLOOR} and {retirement}")
        if not isinstance(self.recent_login_window, timedelta) or not (
            RECENT_LOGIN_FLOOR <= self.recent_login_window <= retirement
        ):
            raise InvalidRecord(f"recent_login_window must be between {RECENT_LOGIN_FLOOR} and {retirement}")

    # --- document form -----------------------------------------------------------------

    def to_document(self) -> dict[str, Any]:
        """The complete, explicit configuration. Every key is always present."""
        lc = self.lifecycle
        fr = lc.freshness
        return {
            "format": POLICY_FORMAT,
            "usage": {
                "lowUsageMaxSignIns": self.low_usage_max_sign_ins,
                "lowUsageMaxUniqueUsers": self.low_usage_max_unique_users,
                "reviewMinWindowDays": _whole(self.review_min_usage_window, timedelta(days=1), "review_min_usage_window"),
                "recentLoginWindowDays": _whole(self.recent_login_window, timedelta(days=1), "recent_login_window"),
                "retirementWindowDays": _whole(lc.min_usage_window, timedelta(days=1), "min_usage_window"),
                "retirementMaxSignIns": lc.max_usage_events_for_candidate,
            },
            "freshness": {
                "reviewHours": _whole(fr.review, timedelta(hours=1), "freshness.review"),
                "approvalHours": _whole(fr.approval, timedelta(hours=1), "freshness.approval"),
                "executionHours": _whole(fr.execution, timedelta(hours=1), "freshness.execution"),
                "clockSkewMinutes": _whole(fr.clock_skew, timedelta(minutes=1), "freshness.clock_skew"),
            },
            "lifecycle": {
                "holdPeriodDays": _whole(lc.hold_period, timedelta(days=1), "hold_period"),
                "approvalMaxTtlHours": _whole(lc.approval_max_ttl, timedelta(hours=1), "approval_max_ttl"),
            },
            "requiredDependencyKinds": sorted(k.value for k in lc.required_dependency_kinds),
            "protected": {
                "oktaGroupIds": sorted(lc.protected_okta_group_ids),
                "adObjectGuids": sorted(lc.protected_ad_object_guids),
                "adSids": sorted(lc.protected_ad_sids),
            },
            "adDirectorySourceIds": sorted(lc.ad_directory_source_ids),
        }

    @classmethod
    def from_document(cls, data: Any) -> "CandidatePolicy":
        """Strict: every key is required and no other key is accepted."""
        doc = _section(data, "policy", {"format", "usage", "freshness", "lifecycle", "requiredDependencyKinds",
                                         "protected", "adDirectorySourceIds"})
        if doc["format"] != POLICY_FORMAT:
            raise InvalidRecord(f"policy format must be {POLICY_FORMAT!r}")
        usage = _section(doc["usage"], "usage", {"lowUsageMaxSignIns", "lowUsageMaxUniqueUsers", "reviewMinWindowDays",
                                                 "recentLoginWindowDays", "retirementWindowDays", "retirementMaxSignIns"})
        fresh = _section(doc["freshness"], "freshness", {"reviewHours", "approvalHours", "executionHours", "clockSkewMinutes"})
        life = _section(doc["lifecycle"], "lifecycle", {"holdPeriodDays", "approvalMaxTtlHours"})
        protected = _section(doc["protected"], "protected", {"oktaGroupIds", "adObjectGuids", "adSids"})
        kinds = _strings(doc["requiredDependencyKinds"], "requiredDependencyKinds")
        try:
            required = frozenset(DependencyKind(k) for k in kinds)
        except ValueError:
            raise InvalidRecord("requiredDependencyKinds names an unknown dependency kind") from None
        users = usage["lowUsageMaxUniqueUsers"]
        lifecycle = LifecyclePolicy(
            freshness=FreshnessPolicy(
                review=timedelta(hours=_int(fresh["reviewHours"], "reviewHours")),
                approval=timedelta(hours=_int(fresh["approvalHours"], "approvalHours")),
                execution=timedelta(hours=_int(fresh["executionHours"], "executionHours")),
                clock_skew=timedelta(minutes=_int(fresh["clockSkewMinutes"], "clockSkewMinutes")),
            ),
            min_usage_window=timedelta(days=_int(usage["retirementWindowDays"], "retirementWindowDays")),
            max_usage_events_for_candidate=_int(usage["retirementMaxSignIns"], "retirementMaxSignIns"),
            hold_period=timedelta(days=_int(life["holdPeriodDays"], "holdPeriodDays")),
            approval_max_ttl=timedelta(hours=_int(life["approvalMaxTtlHours"], "approvalMaxTtlHours")),
            required_dependency_kinds=required,
            protected_okta_group_ids=frozenset(_strings(protected["oktaGroupIds"], "oktaGroupIds")),
            protected_ad_object_guids=frozenset(_strings(protected["adObjectGuids"], "adObjectGuids")),
            protected_ad_sids=frozenset(_strings(protected["adSids"], "adSids")),
            ad_directory_source_ids=frozenset(_strings(doc["adDirectorySourceIds"], "adDirectorySourceIds")),
        )
        return cls(
            lifecycle=lifecycle,
            low_usage_max_sign_ins=_int(usage["lowUsageMaxSignIns"], "lowUsageMaxSignIns"),
            low_usage_max_unique_users=None if users is None else _int(users, "lowUsageMaxUniqueUsers"),
            review_min_usage_window=timedelta(days=_int(usage["reviewMinWindowDays"], "reviewMinWindowDays")),
            recent_login_window=timedelta(days=_int(usage["recentLoginWindowDays"], "recentLoginWindowDays")),
        )

    @classmethod
    def from_json(cls, text: str) -> "CandidatePolicy":
        if not isinstance(text, str) or len(text) > MAX_DOCUMENT_LENGTH:
            raise InvalidRecord(f"policy document must be a string of at most {MAX_DOCUMENT_LENGTH} characters")
        try:
            data = json.loads(text, parse_constant=_refuse_constant, object_pairs_hook=_no_duplicate_keys)
        except ValueError as exc:
            raise InvalidRecord(f"policy document is not valid JSON: {exc}") from None
        return cls.from_document(data)

    def canonical_json(self) -> str:
        return canonical_json(self.to_document())

    @cached_property
    def digest(self) -> str:
        return stable_digest(self.to_document())


def canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _int(value: object, name: str) -> int:
    if not _is_int(value):
        raise InvalidRecord(f"{name} must be an integer")
    return value  # type: ignore[return-value]


def _whole(value: timedelta, unit: timedelta, name: str) -> int:
    if value % unit:
        raise InvalidRecord(f"{name} must be a whole number of {unit}")
    return value // unit


def _section(value: object, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidRecord(f"{name} must be an object")
    missing, unknown = keys - set(value), set(value) - keys
    if missing or unknown:
        raise InvalidRecord(f"{name}: missing keys {sorted(missing)}, unknown keys {sorted(unknown)}")
    return value


def _strings(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise InvalidRecord(f"{name} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise InvalidRecord(f"{name} contains duplicates")
    return value


def _refuse_constant(name: str) -> None:
    raise ValueError(f"{name} is not allowed")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


# --- versions ----------------------------------------------------------------------------


class PolicyRole(StrEnum):
    """The role under which a person acted on a policy version (owner decision D33).

    Recorded by the caller. Until OGWA authenticates operators, the operator API must derive
    it from the operator's verified group membership, never from free input.
    """

    IDENTITY_AUTOMATION = "IDENTITY_AUTOMATION"  # may propose a policy change
    SECURITY_IAM = "SECURITY_IAM"  # may approve a policy change proposed by someone else


PROPOSER_ROLE = PolicyRole.IDENTITY_AUTOMATION
APPROVER_ROLE = PolicyRole.SECURITY_IAM


@dataclass(frozen=True)
class PolicyVersion:
    """One approved policy configuration. Proposed by Identity/Automation, approved by a
    different Security/IAM reviewer (D33)."""

    id: str
    sequence: int  # position in the policy chain, from 0
    supersedes: str | None  # the previous version; None only for the first
    policy_digest: str
    document: str  # canonical JSON of the policy document
    proposed_by: Actor
    approved_by: Actor
    decided_at: datetime
    reason: str
    proposer_role: PolicyRole
    approver_role: PolicyRole

    def __post_init__(self) -> None:
        check_id(self.id, IdKind.POLICY_VERSION, "id")
        if self.proposer_role is not PROPOSER_ROLE:
            raise InvalidRecord(f"a policy change is proposed by {PROPOSER_ROLE.value} (D33)")
        if self.approver_role is not APPROVER_ROLE:
            raise InvalidRecord(f"a policy change is approved by {APPROVER_ROLE.value} (D33)")
        if not _is_int(self.sequence) or self.sequence < 0:
            raise InvalidRecord("sequence must be a non-negative integer")
        if (self.sequence == 0) != (self.supersedes is None):
            raise InvalidRecord("only the first policy version (sequence 0) has no superseded version")
        if self.supersedes is not None:
            check_id(self.supersedes, IdKind.POLICY_VERSION, "supersedes")
        check_digest(self.policy_digest, "policy_digest")
        for name in ("proposed_by", "approved_by"):
            actor = getattr(self, name)
            if not isinstance(actor, Actor) or actor.kind is not ActorKind.HUMAN:
                raise InvalidRecord(f"{name} must be a human Actor")
        if self.proposed_by == self.approved_by:
            raise InvalidRecord("a policy change needs an approver other than its proposer")
        check_utc(self.decided_at, "decided_at")
        check_text(self.reason, "reason")
        policy = CandidatePolicy.from_json(self.document)
        if policy.canonical_json() != self.document:
            raise InvalidRecord("document must be the canonical JSON of the policy")
        if policy.digest != self.policy_digest:
            raise InvalidRecord("policy_digest does not match the document")

    @cached_property
    def policy(self) -> CandidatePolicy:
        return CandidatePolicy.from_json(self.document)

    @classmethod
    def create(cls, policy: CandidatePolicy, *, id: str, previous: "PolicyVersion | None", proposed_by: Actor,
               proposer_role: PolicyRole, approved_by: Actor, approver_role: PolicyRole, decided_at: datetime,
               reason: str) -> "PolicyVersion":
        return cls(
            proposer_role=proposer_role,
            approver_role=approver_role,
            id=id,
            sequence=0 if previous is None else previous.sequence + 1,
            supersedes=None if previous is None else previous.id,
            policy_digest=policy.digest,
            document=policy.canonical_json(),
            proposed_by=proposed_by,
            approved_by=approved_by,
            decided_at=decided_at,
            reason=reason,
        )


def version_append_problems(history: tuple[PolicyVersion, ...], version: PolicyVersion) -> list[str]:
    """Why ``version`` cannot extend ``history`` (the policy chain, oldest first)."""
    if not isinstance(version, PolicyVersion):
        return ["version must be a PolicyVersion"]
    problems = []
    if any(v.id == version.id for v in history):
        problems.append(f"policy version {version.id} is already recorded")
    if version.sequence != len(history):
        problems.append(f"policy version sequence {version.sequence} does not continue the chain (expected {len(history)})")
    if version.supersedes != (history[-1].id if history else None):
        problems.append("a policy version must supersede the latest version")
    if history:
        latest = history[-1]
        if version.decided_at < latest.decided_at:
            problems.append("a policy version cannot be dated before the version it supersedes")
        if version.policy_digest == latest.policy_digest:
            problems.append("the policy is unchanged from the current version")
    return problems
