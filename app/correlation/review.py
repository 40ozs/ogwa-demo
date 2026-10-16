"""Service contract for operator review of identity mappings. No UI yet.

What a future operator can do, and the rules each action enforces:

| Action | Rules |
| --- | --- |
| ``inspect`` | Re-runs correlation (read-only lookups) and lists what may be done next |
| ``search`` | One bounded, exact-match AD lookup (no wildcards; at most ``max_candidates`` results) |
| ``select`` | Pick one AD object from a fresh search result. Re-verified by objectGUID; recorded as PROPOSED |
| ``approve`` | Only an exact, verified pairing: a RESOLVED correlation, or the pending selection approved by a *different* human. The operator must have seen the current evidence (fingerprint) |
| ``reject`` | Any pairing on screen: the proposal, a candidate, the pending selection, or the approval in force |

Every action re-evaluates the evidence first and refuses if it changed since the operator
looked (``expected_fingerprint``). Refusals raise ``ReviewRefused`` and record nothing.
Nothing here writes to Okta or AD; the only write is an append to the mapping registry.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from functools import cached_property
from typing import Protocol

from app.correlation.directory import ADIdentityDirectory, BoundedLookups
from app.correlation.engine import correlate
from app.correlation.model import (
    ADIdentity,
    ADIdentityLookup,
    CorrelationConfig,
    CorrelationOutcome,
    CorrelationResult,
    OktaGroupIdentity,
)
from app.domain.actors import Actor, ActorKind
from app.domain.evidence import stable_digest
from app.domain.ids import IdKind, new_id
from app.domain.mapping_review import (
    METHOD_CONFIDENCE,
    MappingMethod,
    MappingReview,
    ReviewStatus,
    pending_selection,
    review_append_problems,
)
from app.integrations.ad.contract import LookupKind

DEFAULT_SEARCH_MAX_AGE = timedelta(minutes=30)


class ReviewRefused(Exception):
    """The review action was refused. Nothing was recorded."""


class ReviewAction(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    SELECT = "SELECT"
    SEARCH = "SEARCH"


class MappingRegistry(Protocol):
    def history(self, okta_group_ref: str) -> tuple[MappingReview, ...]:
        """Every review of one Okta group, oldest first."""
        ...

    def append(self, review: MappingReview) -> None:
        """Append one review. Must refuse a review that does not extend the chain."""
        ...


class InMemoryMappingRegistry:
    """For tests and synthetic demos. The store-backed registry is ``Store.record_mapping_review``."""

    def __init__(self) -> None:
        self._reviews: dict[str, list[MappingReview]] = {}

    def history(self, okta_group_ref: str) -> tuple[MappingReview, ...]:
        return tuple(self._reviews.get(okta_group_ref, ()))

    def append(self, review: MappingReview) -> None:
        problems = review_append_problems(self.history(review.okta_group_ref), review)
        if problems:
            raise ReviewRefused("; ".join(problems))
        self._reviews.setdefault(review.okta_group_ref, []).append(review)


class StoreMappingRegistry:
    """The registry persisted in the OGWA store (migration 0003)."""

    def __init__(self, store) -> None:
        self._store = store

    def history(self, okta_group_ref: str) -> tuple[MappingReview, ...]:
        return tuple(self._store.mapping_reviews(okta_group_ref))

    def append(self, review: MappingReview) -> None:
        from app.store.errors import StoreConflict

        try:
            self._store.record_mapping_review(review)
        except StoreConflict as exc:
            raise ReviewRefused(str(exc)) from None


@dataclass(frozen=True)
class SearchResult:
    """One operator search. ``digest`` lets ``select`` prove the choice came from it."""

    okta_group_ref: str
    lookup: ADIdentityLookup
    searched_by: Actor

    @cached_property
    def digest(self) -> str:
        return stable_digest({"okta_group_ref": self.okta_group_ref, "lookup": self.lookup.material(),
                              "observed_at": self.lookup.observed_at, "searched_by": str(self.searched_by)})


@dataclass(frozen=True)
class MappingInspection:
    result: CorrelationResult
    history: tuple[MappingReview, ...]
    allowed_actions: frozenset[ReviewAction] = field(default=frozenset())
    approvable_guid: str | None = None  # the pairing ``approve`` would accept now

    @property
    def evidence_fingerprint(self) -> str:
        return self.result.evidence_fingerprint


class MappingReviewService:
    def __init__(self, *, directory: ADIdentityDirectory, config: CorrelationConfig, registry: MappingRegistry,
                 clock: Callable[[], datetime], search_max_age: timedelta = DEFAULT_SEARCH_MAX_AGE) -> None:
        self._directory = directory
        self._config = config
        self._registry = registry
        self._clock = clock
        self._search_max_age = search_max_age

    # --- read ---------------------------------------------------------------------------

    def inspect(self, okta: OktaGroupIdentity) -> MappingInspection:
        history = self._registry.history(okta.okta_group_ref)
        result = correlate(okta, directory=self._directory, config=self._config, clock=self._clock, history=history)
        approvable = _approvable(result, history)
        actions = {ReviewAction.SEARCH, ReviewAction.SELECT}
        if approvable is not None:
            actions.add(ReviewAction.APPROVE)
        if _rejectable(result):
            actions.add(ReviewAction.REJECT)
        return MappingInspection(result, history, frozenset(actions), approvable[0] if approvable else None)

    def search(self, okta: OktaGroupIdentity, *, operator: Actor, by: LookupKind, value: str,
               domain: str | None = None) -> SearchResult:
        _human(operator)
        try:
            by = LookupKind(by)
        except ValueError:
            raise ReviewRefused(f"cannot search by {by!r}") from None
        bounded = BoundedLookups(self._directory, max_lookups=1, clock=self._clock)
        return SearchResult(okta.okta_group_ref, bounded.lookup(by, value, domain), operator)

    # --- write ----------------------------------------------------------------------------

    def select(self, okta: OktaGroupIdentity, *, operator: Actor, search: SearchResult, object_guid: str,
               reason: str) -> MappingReview:
        """Propose the pairing with one AD object from ``search``. A different human must approve it."""
        _human(operator)
        now = self._clock()
        if not isinstance(search, SearchResult) or search.okta_group_ref != okta.okta_group_ref:
            raise ReviewRefused("the search result is for a different Okta group")
        if now - search.lookup.observed_at > self._search_max_age:
            raise ReviewRefused("the search result is too old; search again")
        chosen = next((c for c in search.lookup.candidates if c.object_guid == object_guid), None)
        if chosen is None:
            raise ReviewRefused("the selected AD object is not among the search results")
        # Re-verify the choice by its stable id, scoped to its own domain.
        check = BoundedLookups(self._directory, max_lookups=1, clock=self._clock).lookup(
            LookupKind.OBJECT_GUID, object_guid, chosen.domain)
        current = check.resolved if check.complete else None
        if current is None:
            raise ReviewRefused(f"the selected AD object could not be re-verified by objectGUID ({check.status.value})")
        if current.object_sid is None or current.sam_account_name is None:
            raise ReviewRefused("the selected AD object has no SID or sAMAccountName to record")
        if chosen.object_sid != current.object_sid:
            raise ReviewRefused("the selected AD object changed since the search")
        history = self._registry.history(okta.okta_group_ref)
        fingerprint = stable_digest({"okta": okta.material(), "selected": current.material(), "search": search.digest})
        return self._append(okta, history, current, MappingMethod.OPERATOR_SELECTED, ReviewStatus.PROPOSED,
                            operator, now, reason, fingerprint, verified_at=check.observed_at)

    def approve(self, okta: OktaGroupIdentity, *, operator: Actor, object_guid: str, expected_fingerprint: str,
                reason: str) -> MappingReview:
        _human(operator)
        inspection = self._current(okta, expected_fingerprint)
        result, history = inspection.result, inspection.history
        approvable = _approvable(result, history)
        if approvable is None or approvable[0] != object_guid:
            raise ReviewRefused(_why_not_approvable(result, history, object_guid))
        # The selector-is-not-approver rule is enforced by review_append_problems (and the database).
        _, target, method, verified_at = approvable
        configuration_ref = self._configuration_ref(okta, result, method)
        return self._append(okta, history, target, method, ReviewStatus.APPROVED, operator, self._clock(), reason,
                            result.evidence_fingerprint, verified_at=verified_at, configuration_ref=configuration_ref)

    def reject(self, okta: OktaGroupIdentity, *, operator: Actor, object_guid: str, expected_fingerprint: str,
               reason: str) -> MappingReview:
        _human(operator)
        inspection = self._current(okta, expected_fingerprint)
        result, history = inspection.result, inspection.history
        identity, verified_at = _on_screen(result, object_guid)
        if identity is None:
            raise ReviewRefused("only a pairing shown by the current correlation can be rejected")
        method = _method_for(result, object_guid)
        return self._append(okta, history, identity, method, ReviewStatus.REJECTED, operator, self._clock(), reason,
                            result.evidence_fingerprint, verified_at=verified_at,
                            configuration_ref=self._configuration_ref(okta, result, method))

    # --- internals ------------------------------------------------------------------------

    def _configuration_ref(self, okta: OktaGroupIdentity, result: CorrelationResult, method: MappingMethod) -> str | None:
        if method is not MappingMethod.CONFIGURED:
            return None
        configured = self._config.configured(okta.okta_group_id)
        if configured is not None:
            return configured.configuration_ref
        if result.approval is not None and result.approval.method is MappingMethod.CONFIGURED:
            return result.approval.configuration_ref
        return None

    def _current(self, okta: OktaGroupIdentity, expected_fingerprint: str) -> MappingInspection:
        inspection = self.inspect(okta)
        if inspection.evidence_fingerprint != expected_fingerprint:
            raise ReviewRefused("the correlation evidence changed since it was reviewed; inspect again")
        return inspection

    def _append(self, okta: OktaGroupIdentity, history: tuple[MappingReview, ...], identity: ADIdentity,
                method: MappingMethod, status: ReviewStatus, operator: Actor, now: datetime, reason: str,
                fingerprint: str, *, verified_at: datetime, configuration_ref: str | None = None) -> MappingReview:
        try:
            review = MappingReview(
                id=new_id(IdKind.MAPPING_REVIEW), okta_group_ref=okta.okta_group_ref, okta_group_id=okta.okta_group_id,
                okta_group_name=okta.name, sequence=len(history), supersedes=history[-1].id if history else None,
                ad_object_guid=identity.object_guid, ad_sid=identity.object_sid,
                ad_distinguished_name=identity.distinguished_name, ad_sam_account_name=identity.sam_account_name,
                ad_domain=identity.domain, method=method, confidence=METHOD_CONFIDENCE[method], review_status=status,
                verified_at=min(verified_at, now), evidence_fingerprint=fingerprint, decided_by=operator,
                decided_at=now, reason=reason, configuration_ref=configuration_ref,
            )
        except Exception as exc:
            raise ReviewRefused(f"review cannot be recorded: {exc}") from None
        problems = review_append_problems(history, review)
        if problems:
            raise ReviewRefused("; ".join(problems))
        self._registry.append(review)
        return review


def _human(operator: Actor) -> None:
    if not isinstance(operator, Actor) or operator.kind is not ActorKind.HUMAN:
        raise ReviewRefused("only a named human operator can review mappings")


def _approvable(result: CorrelationResult, history: tuple[MappingReview, ...]):
    """(guid, identity, method, verified_at) that ``approve`` would accept now, or None."""
    lookup_time = {lk.candidates[0].object_guid: lk.observed_at for lk in result.lookups
                   if lk.resolved is not None and lk.complete}
    approval = result.approval
    if result.outcome is CorrelationOutcome.RESOLVED and result.target is not None:
        target = result.target
        if target.object_sid is None or target.sam_account_name is None:
            return None
        if approval is not None and approval.ad_object_guid == target.object_guid and not result.drift:
            return None  # already approved and nothing changed; re-approval only acknowledges drift
        # RESOLVED always has an exact method; MappingReview itself refuses an approved NAME_MATCH.
        return target.object_guid, target, result.method, lookup_time.get(target.object_guid, result.evaluated_at)

    pending = pending_selection(history)
    check = result.pending
    if pending is None or check is None or check.target is None or not check.complete or check.blocked:
        return None
    if check.target.object_guid != pending.ad_object_guid or check.target.object_sid != pending.ad_sid:
        return None
    # The selection must not contradict any other evidence.
    if result.outcome in (CorrelationOutcome.CONFLICT, CorrelationOutcome.STALE):
        return None
    if any(c.target is not None and c.target.object_guid != pending.ad_object_guid for c in result.claims):
        return None
    if check.target.sam_account_name is None:
        return None
    return (pending.ad_object_guid, check.target, MappingMethod.OPERATOR_SELECTED,
            lookup_time.get(pending.ad_object_guid, result.evaluated_at))


def _why_not_approvable(result: CorrelationResult, history: tuple[MappingReview, ...], guid: str) -> str:
    if result.outcome is CorrelationOutcome.REVIEW_REQUIRED:
        return ("a NAME_ONLY match cannot be approved; select the AD object explicitly, "
                "and a second operator approves the selection")
    if result.outcome is CorrelationOutcome.UNVERIFIED_IDENTIFIER:
        return ("an unverified directory-source identifier cannot be approved before P11 (D37); select the AD "
                "object explicitly, and a second operator approves the selection")
    if result.outcome in (CorrelationOutcome.CONFLICT, CorrelationOutcome.STALE, CorrelationOutcome.INCOMPLETE):
        return f"correlation is {result.outcome.value}; resolve the cause before approving"
    if result.outcome is CorrelationOutcome.RESOLVED and result.target and result.target.object_guid != guid:
        return "the correlation resolved to a different AD object"
    if pending_selection(history) is None:
        return "there is no exact verified pairing or pending selection to approve"
    return "the pending selection could not be re-verified or contradicts other evidence"


def _rejectable(result: CorrelationResult) -> bool:
    return bool(result.candidates or result.approval or (result.pending and result.pending.claimed_guid))


def _on_screen(result: CorrelationResult, guid: str) -> tuple[ADIdentity | None, datetime]:
    """The identity of a pairing the operator can see, with when AD last confirmed it."""
    for candidate in result.candidates:
        if candidate.object_guid == guid and candidate.object_sid and candidate.sam_account_name:
            seen = [lk.observed_at for lk in result.lookups if any(c.object_guid == guid for c in lk.candidates)]
            return candidate, min(seen) if seen else result.evaluated_at
    if result.approval is not None and result.approval.ad_object_guid == guid:
        return _identity_of(result.approval), result.approval.verified_at
    if result.pending is not None and result.pending.claimed_guid == guid and result.pending.target is not None:
        target = result.pending.target
        if target.object_sid and target.sam_account_name:
            return target, result.evaluated_at
    return None, result.evaluated_at


def _identity_of(review: MappingReview) -> ADIdentity:
    return ADIdentity(object_guid=review.ad_object_guid, object_sid=review.ad_sid,
                      distinguished_name=review.ad_distinguished_name, sam_account_name=review.ad_sam_account_name,
                      domain=review.ad_domain)


def _method_for(result: CorrelationResult, guid: str) -> MappingMethod:
    if result.approval is not None and result.approval.ad_object_guid == guid:
        return result.approval.method
    if result.pending is not None and result.pending.claimed_guid == guid:
        return MappingMethod.OPERATOR_SELECTED
    if result.method is not None and result.target is not None and result.target.object_guid == guid:
        return result.method
    for claim in result.claims:
        if claim.target is not None and claim.target.object_guid == guid and claim.method is not None:
            return claim.method
    return MappingMethod.NAME_MATCH
