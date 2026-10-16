"""Okta-to-AD identity correlation. Pure decision logic over bounded, read-only lookups.

Evidence is gathered as *claims*, strongest first:

1. ``configured``: the reviewed mapping configuration names an objectGUID (and maybe a SID);
2. ``directory-source``: the Okta group was imported by a configured AD integration and
   carries the group's objectSid (or, once D30 is satisfied, its objectGUID);
3. ``approved-review``: a human earlier approved an exact pairing; it is re-verified by its
   stored objectGUID and SID on every run.

Every claim is resolved in AD by stable identifier only, scoped to its domain. All claims
must agree on one AD object. Any disagreement, a stale identity, or an incomplete lookup
stops the correlation from resolving; nothing is repaired silently. Only when there is no
claim at all does correlation fall back to a name search, and a name match is NAME_ONLY:
review evidence, never an exact mapping.
"""

from collections.abc import Callable, Iterable
from datetime import datetime

from app.correlation import model as correlation_model
from app.correlation.directory import ADIdentityDirectory, BoundedLookups
from app.correlation.model import (
    ADIdentity,
    ADIdentityLookup,
    ClaimCheck,
    CorrelationConfig,
    CorrelationOutcome,
    CorrelationResult,
    DirectorySource,
    DriftFinding,
    DriftKind,
    LookupStatus,
    OktaGroupIdentity,
    OktaSourceState,
    _same_text,
)
from app.domain.errors import InvalidRecord
from app.domain.mapping_review import (
    METHOD_CONFIDENCE,
    MappingMethod,
    MappingReview,
    current_approval,
    pending_selection,
    rejected_guids,
)
from app.domain.model import MappingConfidence, OktaGroupType
from app.integrations.ad.contract import LookupKind

# Blocking drift that means the evidence disagrees (CONFLICT) versus an identity that no
# longer holds (STALE).
_CONFLICT_DRIFT = frozenset({
    DriftKind.SOURCE_CONFLICT,
    DriftKind.REJECTED_PAIRING,
    DriftKind.OKTA_SOURCE_CHANGED,
    DriftKind.OKTA_METADATA_INCONSISTENT,
    DriftKind.CONFIGURATION_REMOVED,
})
_STALE_DRIFT = frozenset({
    DriftKind.MAPPING_UNRESOLVABLE,
    DriftKind.AD_SID_MISMATCH,
    DriftKind.IDENTITY_REASSIGNED,
    DriftKind.AD_GROUP_CHANGED_DOMAIN,
})


def correlate(
    okta: OktaGroupIdentity,
    *,
    directory: ADIdentityDirectory,
    config: CorrelationConfig,
    clock: Callable[[], datetime],
    history: Iterable[MappingReview] = (),
) -> CorrelationResult:
    """Correlate one Okta group with its AD counterpart. Read-only; never raises for AD problems."""
    history = tuple(history)
    if any(r.okta_group_ref != okta.okta_group_ref for r in history):
        raise InvalidRecord("review history belongs to a different Okta group")
    return _Correlation(okta, directory, config, clock, history).run()


class _Correlation:
    def __init__(self, okta, directory, config, clock, history) -> None:
        self.okta: OktaGroupIdentity = okta
        self.config: CorrelationConfig = config
        self.clock = clock
        self.lookups = BoundedLookups(directory, max_lookups=config.max_lookups, clock=clock)
        self.history: tuple[MappingReview, ...] = history
        self.approval = current_approval(history)
        self.rejected = rejected_guids(history)
        self.drift: list[DriftFinding] = []
        self.reasons: list[str] = []

    # --- entry ------------------------------------------------------------------------

    def run(self) -> CorrelationResult:
        state, source, problems = assess_okta_source(self.okta, self.config)
        for problem in problems:
            self.drift.append(DriftFinding(DriftKind.OKTA_METADATA_INCONSISTENT, problem))
        if state is OktaSourceState.BUILT_IN:
            self.reasons.append("Okta built-in groups have no AD counterpart")
            outcome = CorrelationOutcome.NOT_FOUND if self.okta.complete else CorrelationOutcome.INCOMPLETE
            return self._result(outcome, state, MappingConfidence.NOT_FOUND)

        claims = self._claims(state, source)
        pending = self._pending_check()
        if claims:
            return self._from_claims(claims, state, source, pending)
        return self._from_name_search(state, source, pending)

    # --- claims -----------------------------------------------------------------------

    def _claims(self, state: OktaSourceState, source: DirectorySource | None) -> list[ClaimCheck]:
        claims = []
        configured = self.config.configured(self.okta.okta_group_id)
        if configured is not None:
            claims.append(self._check_guid(MappingMethod.CONFIGURED, "configured", configured.ad_object_guid,
                                           configured.ad_sid, configured.domain))
        if state is OktaSourceState.VERIFIABLE:
            assert source is not None
            if self.okta.directory_object_guid is not None:
                claims.append(self._check_guid(MappingMethod.DIRECTORY_SOURCE_GUID, "directory-source",
                                               self.okta.directory_object_guid, self.okta.directory_object_sid,
                                               source.domain))
            else:
                claims.append(self._check_sid(MappingMethod.DIRECTORY_SOURCE_SID, "directory-source",
                                              self.okta.directory_object_sid, source.domain))
        if self.approval is not None:
            a = self.approval
            claims.append(self._check_guid(a.method, "approved-review", a.ad_object_guid, a.ad_sid, a.ad_domain))
        return claims

    def _pending_check(self) -> ClaimCheck | None:
        proposal = pending_selection(self.history)
        if proposal is None:
            return None
        return self._check_guid(MappingMethod.OPERATOR_SELECTED, "pending-selection", proposal.ad_object_guid,
                                proposal.ad_sid, proposal.ad_domain)

    def _check_guid(self, method: MappingMethod, basis: str, guid: str, sid: str | None, domain: str | None) -> ClaimCheck:
        """Resolve a claimed objectGUID (and cross-check its SID) without trusting either alone."""
        drift: list[DriftFinding] = []
        first = self.lookups.lookup(LookupKind.OBJECT_GUID, guid, domain)
        checks = [first]
        target = first.resolved if first.complete else None
        if first.status is LookupStatus.NOT_FOUND and domain is not None:
            # Not in its domain: moved to another domain (same GUID, new SID), or gone.
            forest = self.lookups.lookup(LookupKind.OBJECT_GUID, guid, None)
            checks.append(forest)
            if forest.complete and forest.resolved is not None:
                target = forest.resolved
                drift.append(DriftFinding(DriftKind.AD_GROUP_CHANGED_DOMAIN,
                                          f"{basis}: objectGUID {guid} is now in {target.domain}, not {domain}"))
        if target is not None and sid is not None and target.object_sid != sid:
            drift.append(DriftFinding(DriftKind.AD_SID_MISMATCH,
                                      f"{basis}: objectGUID {guid} has SID {target.object_sid}, expected {sid}"))
        if sid is not None and (target is None or target.object_sid != sid):
            by_sid = self.lookups.lookup(LookupKind.OBJECT_SID, sid, domain)
            checks.append(by_sid)
            other = by_sid.resolved if by_sid.complete else None
            if other is not None and other.object_guid != guid:
                drift.append(DriftFinding(DriftKind.IDENTITY_REASSIGNED,
                                          f"{basis}: SID {sid} now resolves to objectGUID {other.object_guid}, not {guid}"))
        complete = all(c.complete for c in checks)
        if target is None and complete:
            drift.append(DriftFinding(DriftKind.MAPPING_UNRESOLVABLE,
                                      f"{basis}: objectGUID {guid} no longer resolves in the searched domains"))
        if not complete:
            self.reasons.append(f"{basis}: AD lookup incomplete ({_lookup_problem(checks)})")
        return ClaimCheck(method=method, basis=basis, claimed_guid=guid, claimed_sid=sid, target=target,
                          complete=complete, drift=tuple(drift))

    def _check_sid(self, method: MappingMethod, basis: str, sid: str, domain: str) -> ClaimCheck:
        lookup = self.lookups.lookup(LookupKind.OBJECT_SID, sid, domain)
        drift: list[DriftFinding] = []
        target = lookup.resolved if lookup.complete else None
        if lookup.complete and target is None:
            drift.append(DriftFinding(DriftKind.MAPPING_UNRESOLVABLE,
                                      f"{basis}: Okta's objectSid {sid} does not resolve in {domain}"))
        if not lookup.complete:
            self.reasons.append(f"{basis}: AD lookup incomplete ({_lookup_problem([lookup])})")
        if target is not None:
            drift += self._corroborate(basis, target, domain)
        return ClaimCheck(method=method, basis=basis, claimed_guid=None, claimed_sid=sid, target=target,
                          complete=lookup.complete, drift=tuple(drift))

    def _corroborate(self, basis: str, target: ADIdentity, domain: str) -> list[DriftFinding]:
        """Okta's own copy of the name or DN must agree with the object its stable id resolves to."""
        okta = self.okta
        drift = []
        if target.domain != domain:
            return [DriftFinding(DriftKind.OKTA_METADATA_INCONSISTENT,
                                 f"{basis}: resolved in {target.domain}, but the Okta source imports from {domain}")]
        sam, dn = okta.effective_sam, okta.distinguished_name
        sam_ok, dn_ok = _same_text(sam, target.sam_account_name), _same_text(dn, target.distinguished_name)
        if not (sam_ok or dn_ok):
            return [DriftFinding(DriftKind.OKTA_METADATA_INCONSISTENT,
                                 f"{basis}: neither Okta's sAMAccountName nor its DN matches the AD object "
                                 f"{target.object_guid} that its objectSid resolves to")]
        if sam is not None and not sam_ok:
            drift.append(DriftFinding(DriftKind.OKTA_DIRECTORY_METADATA_STALE,
                                      f"{basis}: Okta has sAMAccountName {sam!r}, AD has {target.sam_account_name!r}"))
        if dn is not None and not dn_ok:
            drift.append(DriftFinding(DriftKind.OKTA_DIRECTORY_METADATA_STALE,
                                      f"{basis}: Okta has DN {dn!r}, AD has {target.distinguished_name!r}"))
        return drift

    def _from_claims(self, claims: list[ClaimCheck], state: OktaSourceState, source: DirectorySource | None,
                     pending: ClaimCheck | None) -> CorrelationResult:
        for claim in claims:
            self.drift.extend(claim.drift)
        identities = {}
        for claim in claims:
            guid = claim.target.object_guid if claim.target else claim.claimed_guid
            if guid is not None:
                identities.setdefault(guid, []).append(claim.basis)
        if len(identities) > 1:
            detail = "; ".join(f"{', '.join(bases)} -> {guid}" for guid, bases in sorted(identities.items()))
            self.drift.append(DriftFinding(DriftKind.SOURCE_CONFLICT, f"evidence names different AD objects: {detail}"))

        approval = self.approval
        bases = {c.basis for c in claims}
        if approval is not None and bases == {"approved-review"}:
            if approval.method in (MappingMethod.DIRECTORY_SOURCE_SID, MappingMethod.DIRECTORY_SOURCE_GUID):
                self.drift.append(DriftFinding(
                    DriftKind.OKTA_SOURCE_CHANGED,
                    f"approved by {approval.method.value}, but Okta's directory metadata is now {state.value}"))
            if approval.method is MappingMethod.CONFIGURED:
                self.drift.append(DriftFinding(DriftKind.CONFIGURATION_REMOVED,
                                               f"approved configured mapping {approval.configuration_ref} is no longer configured"))

        targets = {c.target.object_guid: c.target for c in claims if c.target is not None}
        target = next(iter(targets.values())) if len(targets) == 1 and len(identities) == 1 else None
        if target is not None:
            if target.object_guid in self.rejected:
                self.drift.append(DriftFinding(DriftKind.REJECTED_PAIRING,
                                               f"an operator rejected pairing with AD object {target.object_guid}"))
            if approval is not None and approval.ad_object_guid == target.object_guid:
                self.drift += _renames(self.okta, approval, target)

        incomplete = not self.okta.complete or not all(c.complete for c in claims)
        if not self.okta.complete:
            self.reasons.append("the Okta group observation was not complete")
        kinds = {d.kind for d in self.drift if d.blocking}
        candidates = tuple(targets[g] for g in sorted(targets))
        if kinds & _CONFLICT_DRIFT:
            outcome = CorrelationOutcome.CONFLICT
        elif kinds & _STALE_DRIFT:
            outcome = CorrelationOutcome.STALE
        elif incomplete or target is None:
            outcome = CorrelationOutcome.INCOMPLETE
        else:
            outcome = CorrelationOutcome.RESOLVED
        if outcome is not CorrelationOutcome.RESOLVED:
            self.reasons.insert(0, f"not resolved: {outcome.value}")
            return self._result(outcome, state, MappingConfidence.NOT_FOUND, candidates=candidates, claims=claims,
                                pending=pending)

        assert target is not None
        trusted = [c for c in claims if _may_be_exact(c)]
        if not trusted:
            # D37/D56: only an unverified directory-source objectSid identifies the object.
            # Reported as what it is (an unverified stable identifier), never as a name match.
            basis = claims[0]
            matched = _matched_attributes(MappingMethod.DIRECTORY_SOURCE_SID, basis, self.okta, target)
            self.reasons.insert(0, f"UNVERIFIED_IDENTIFIER: Okta's directory-source objectSid resolves to "
                                   f"{target.object_guid}, but that mechanism is not verified against real AD until "
                                   "P11 (D37); not exact. An operator selection approved by a different operator "
                                   "makes it exact (D38)")
            return self._result(CorrelationOutcome.UNVERIFIED_IDENTIFIER, state, MappingConfidence.UNVERIFIED_STABLE_ID,
                                method=MappingMethod.DIRECTORY_SOURCE_SID, target=target, candidates=(target,),
                                matched=matched, claims=claims, pending=pending)
        basis = _strongest(trusted)
        method = basis.method
        assert method is not None
        configuration_ref = None
        if method is MappingMethod.CONFIGURED:
            configured = self.config.configured(self.okta.okta_group_id)
            configuration_ref = configured.configuration_ref if configured else None
        elif method is MappingMethod.OPERATOR_SELECTED:
            configuration_ref = approval.registry_ref if approval else None
        matched = _matched_attributes(method, basis, self.okta, target)
        self.reasons.insert(0, f"resolved by {method.value} ({basis.basis}); "
                               f"{len(claims)} source(s) agree on objectGUID {target.object_guid}")
        return self._result(outcome, state, METHOD_CONFIDENCE[method], method=method, target=target,
                            candidates=(target,), matched=matched, configuration_ref=configuration_ref,
                            claims=claims, pending=pending)

    # --- name fallback -----------------------------------------------------------------

    def _from_name_search(self, state: OktaSourceState, source: DirectorySource | None,
                          pending: ClaimCheck | None) -> CorrelationResult:
        sam = self.okta.effective_sam
        by, value = (LookupKind.SAM_ACCOUNT_NAME, sam) if sam else (LookupKind.NAME, self.okta.name)
        attribute = "samAccountName" if by is LookupKind.SAM_ACCOUNT_NAME else "name"
        self.reasons.append(f"no stable identifier or configured mapping; searched AD by {attribute} only "
                            f"(Okta source {state.value})")
        lookup = self.lookups.lookup(by, value, None)
        found = lookup.candidates
        kept = tuple(c for c in found if c.object_guid not in self.rejected)
        rejected = tuple(sorted(c.object_guid for c in found if c.object_guid in self.rejected))
        if rejected:
            self.reasons.append(f"{len(rejected)} candidate(s) excluded: an operator rejected the pairing")
        if len(kept) > 1:
            self.drift.append(DriftFinding(DriftKind.DUPLICATE_CANDIDATES,
                                           f"{len(kept)} AD groups match {attribute} {value!r}"
                                           + (" (list truncated)" if lookup.candidates_truncated else "")))

        if state is OktaSourceState.INCONSISTENT:
            outcome = CorrelationOutcome.CONFLICT
        elif not self.okta.complete:
            outcome = CorrelationOutcome.INCOMPLETE
            self.reasons.append("the Okta group observation was not complete")
        elif len(kept) > 1:
            outcome = CorrelationOutcome.AMBIGUOUS
        elif not lookup.complete:
            outcome = CorrelationOutcome.INCOMPLETE
            self.reasons.append(f"name search incomplete ({_lookup_problem([lookup])})")
        elif len(kept) == 1:
            outcome = CorrelationOutcome.REVIEW_REQUIRED
        else:
            outcome = CorrelationOutcome.NOT_FOUND
        if outcome is CorrelationOutcome.REVIEW_REQUIRED:
            target = kept[0]
            self.reasons.insert(0, f"NAME_ONLY: one AD group matches {attribute}; human review required")
            return self._result(outcome, state, MappingConfidence.NAME_ONLY, method=MappingMethod.NAME_MATCH,
                                target=target, candidates=kept, matched=(attribute,), pending=pending,
                                previously_rejected=rejected)
        confidence = MappingConfidence.AMBIGUOUS if outcome is CorrelationOutcome.AMBIGUOUS else MappingConfidence.NOT_FOUND
        return self._result(outcome, state, confidence, candidates=kept, pending=pending, previously_rejected=rejected)

    # --- result -----------------------------------------------------------------------

    def _result(self, outcome, state, confidence, *, method=None, target=None, candidates=(), matched=(),
                configuration_ref=None, claims=(), pending=None, previously_rejected=()) -> CorrelationResult:
        if self.lookups.refused:
            self.reasons.append(f"{self.lookups.refused} lookup(s) refused: budget of {self.config.max_lookups} spent")
        return CorrelationResult(
            okta=self.okta, outcome=outcome, okta_source=state, confidence=confidence, evaluated_at=self.clock(),
            method=method, target=target, candidates=tuple(candidates), matched_attributes=tuple(matched),
            configuration_ref=configuration_ref, drift=tuple(_unique(self.drift)), reasons=tuple(self.reasons),
            claims=tuple(claims), lookups=tuple(self.lookups.results), approval=self.approval, pending=pending,
            previously_rejected=tuple(previously_rejected),
        )


# --- helpers ---------------------------------------------------------------------------


def assess_okta_source(okta: OktaGroupIdentity, config: CorrelationConfig) -> tuple[OktaSourceState, DirectorySource | None, list[str]]:
    """Whether the Okta group's directory metadata can support a stable-id correlation."""
    if okta.group_type is OktaGroupType.BUILT_IN:
        return OktaSourceState.BUILT_IN, None, []
    if okta.group_type is OktaGroupType.OKTA_GROUP:
        return OktaSourceState.NOT_DIRECTORY, None, []
    stable = okta.directory_object_sid or okta.directory_object_guid
    if okta.source_app_id is None:
        if stable:
            return OktaSourceState.INCONSISTENT, None, ["Okta carries a directory identifier but no source integration"]
        return OktaSourceState.ABSENT, None, []
    source = config.source(okta.source_app_id)
    if source is None:
        return OktaSourceState.UNCONFIGURED_SOURCE, None, []
    problems = []
    if okta.distinguished_name is not None:
        dn_domain = _dn_domain(okta.distinguished_name)
        if dn_domain != source.domain:
            problems.append(f"Okta's DN is in {dn_domain or 'no domain'}, but the source imports from {source.domain}")
    if okta.directory_qualified_name is not None:
        netbios, qualified_sam = okta.qualified_sam
        if qualified_sam is None:
            problems.append("Okta's windowsDomainQualifiedName is not DOMAIN\\name")
        else:
            if source.netbios_name and netbios and not _same_text(netbios, source.netbios_name):
                problems.append(f"Okta's qualified name is in domain {netbios!r}, not {source.netbios_name!r}")
            if okta.sam_account_name is not None and not _same_text(qualified_sam, okta.sam_account_name):
                problems.append("Okta's qualified name and sAMAccountName disagree")
    if okta.directory_object_sid is not None and okta.directory_object_sid.startswith("S-1-5-32-"):
        problems.append("Okta carries a builtin-domain SID, which is not unique to one domain")
    if problems:
        return OktaSourceState.INCONSISTENT, source, problems
    if not stable or not (okta.effective_sam or okta.distinguished_name):
        return OktaSourceState.ABSENT, source, []
    return OktaSourceState.VERIFIABLE, source, []


def _dn_domain(dn: str) -> str | None:
    parts = [p.strip() for p in dn.split(",")]
    labels = [p[3:] for p in parts if p[:3].upper() == "DC="]
    return ".".join(labels).lower() if labels else None


def _renames(okta: OktaGroupIdentity, approval: MappingReview, target: ADIdentity) -> list[DriftFinding]:
    drift = []
    if okta.name != approval.okta_group_name:
        drift.append(DriftFinding(DriftKind.OKTA_GROUP_RENAMED,
                                  f"Okta group was {approval.okta_group_name!r} when approved, now {okta.name!r}"))
    if not _same_text(target.sam_account_name, approval.ad_sam_account_name):
        drift.append(DriftFinding(DriftKind.AD_GROUP_RENAMED,
                                  f"AD sAMAccountName was {approval.ad_sam_account_name!r} when approved, "
                                  f"now {target.sam_account_name!r}"))
    if not _same_text(target.distinguished_name, approval.ad_distinguished_name):
        drift.append(DriftFinding(DriftKind.AD_GROUP_MOVED,
                                  f"AD DN was {approval.ad_distinguished_name!r} when approved, "
                                  f"now {target.distinguished_name!r}"))
    return drift


_BASIS_ORDER = ("configured", "directory-source", "approved-review")


def _strongest(claims: list[ClaimCheck]) -> ClaimCheck:
    return min(claims, key=lambda c: _BASIS_ORDER.index(c.basis))


def _may_be_exact(claim: ClaimCheck) -> bool:
    """Whether a claim may be the basis of an exact mapping. Any claim may corroborate one.

    A directory-source objectSid, or an earlier approval recorded by that method, is not a
    basis until it is verified (D37). Read at call time so the gate cannot be cached.
    """
    return claim.method is not MappingMethod.DIRECTORY_SOURCE_SID or correlation_model.DIRECTORY_SOURCE_SID_VERIFIED


def _matched_attributes(method: MappingMethod, basis: ClaimCheck, okta: OktaGroupIdentity,
                        target: ADIdentity) -> tuple[str, ...]:
    if method is MappingMethod.DIRECTORY_SOURCE_SID or method is MappingMethod.DIRECTORY_SOURCE_GUID:
        attrs = ["objectGUID"] if method is MappingMethod.DIRECTORY_SOURCE_GUID else []
        attrs.append("objectSid")
        if _same_text(okta.effective_sam, target.sam_account_name):
            attrs.append("samAccountName")
        if _same_text(okta.distinguished_name, target.distinguished_name):
            attrs.append("distinguishedName")
        return tuple(attrs)
    attrs = ["objectGUID"]
    if basis.claimed_sid is not None:
        attrs.append("objectSid")
    return tuple(attrs)


def _lookup_problem(lookups: list[ADIdentityLookup]) -> str:
    for lookup in lookups:
        if lookup.complete:
            continue
        if lookup.unsearched_domains:
            return f"{lookup.by.value} lookup could not search {', '.join(sorted(lookup.unsearched_domains))}"
        if lookup.candidates_truncated:
            return f"{lookup.by.value} lookup returned more candidates than the limit"
        return f"{lookup.by.value} lookup {lookup.status.value}" + (f": {lookup.error}" if lookup.error else "")
    return "unknown"


def _unique(findings: list[DriftFinding]) -> list[DriftFinding]:
    seen, out = set(), []
    for f in findings:
        if (f.kind, f.detail) not in seen:
            seen.add((f.kind, f.detail))
            out.append(f)
    return out
