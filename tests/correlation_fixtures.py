"""Synthetic fixtures for identity correlation. Every name, id, SID, and GUID is invented.

The synthetic forest has three domains. ``SyntheticDirectory`` answers identity lookups
with the same resolution rules as the AD report contract: narrowest scope, the
SID's own domain for a SID lookup, and "Inconclusive" when a domain in scope cannot be
searched. It never touches a real directory.
"""

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from unittest import mock

from app.correlation import model as correlation_model
from app.correlation.model import (
    ADIdentity,
    ADIdentityLookup,
    ConfiguredMapping,
    CorrelationConfig,
    DirectorySource,
    LookupStatus,
    OktaGroupIdentity,
)
from app.domain.actors import Actor, ActorKind
from app.domain.ids import IdKind
from app.domain.model import OktaGroupType
from app.integrations.ad.contract import LookupKind


def sid_verified(test):
    """Run ``test`` as if the mechanism had been verified directory-source objectSid matches (D37).

    The default (False) makes such a match review evidence only; these tests cover the path
    the code keeps for a verified mechanism.
    """
    return mock.patch.object(correlation_model, "DIRECTORY_SOURCE_SID_VERIFIED", True)(test)

T = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)

CORP = "corp.synthetic.example"
EMEA = "emea.corp.synthetic.example"
APAC = "apac.corp.synthetic.example"
DOMAIN_SIDS = {
    CORP: "S-1-5-21-1000000001-1000000002-1000000003",
    EMEA: "S-1-5-21-2000000001-2000000002-2000000003",
    APAC: "S-1-5-21-3000000001-3000000002-3000000003",
}
NETBIOS = {CORP: "SYNTHCORP", EMEA: "SYNTHEMEA", APAC: "SYNTHAPAC"}

CORP_SOURCE = "0oaSYNTHDIRCORP1"  # the synthetic Okta AD integration for CORP
EMEA_SOURCE = "0oaSYNTHDIREMEA1"
OTHER_SOURCE = "0oaSYNTHWORKDAY1"  # an app integration that is not AD

OPERATOR_1 = Actor(ActorKind.HUMAN, "synthetic-operator-1")
OPERATOR_2 = Actor(ActorKind.HUMAN, "synthetic-operator-2")
SYSTEM = Actor(ActorKind.SYSTEM, "collector/synthetic")


def dc(domain: str) -> str:
    return ",".join(f"DC={label}" for label in domain.split("."))


def ad_group(n: int, name: str, domain: str = CORP, *, ou: str = "Groups", sam: str | None = None,
             rid: int | None = None) -> ADIdentity:
    return ADIdentity(
        object_guid=f"5e7e7000-0000-4000-8000-{n:012d}",
        object_sid=f"{DOMAIN_SIDS[domain]}-{rid or n}",
        distinguished_name=f"CN={name},OU={ou},{dc(domain)}",
        sam_account_name=sam or name,
        domain=domain,
    )


def ref(n: int) -> str:
    return f"{IdKind.OKTA_GROUP.value}_{n:032x}"


def okta_ad_group(n: int, ad: ADIdentity | None, *, name: str | None = None, source: str | None = CORP_SOURCE,
                  sid: str | None = "same", sam: str | None = "same", dn: str | None = "same",
                  qualified: str | None = "same", complete: bool = True,
                  observed_at: datetime = T) -> OktaGroupIdentity:
    """An Okta APP_GROUP imported from AD. ``"same"`` copies the attribute from ``ad``."""
    def pick(value, from_ad):
        return from_ad if value == "same" else value
    netbios = NETBIOS.get(ad.domain) if ad else None
    return OktaGroupIdentity(
        okta_group_ref=ref(n), okta_group_id=f"00gSYNTH{n:04d}", name=name or (ad.sam_account_name if ad else f"SYNTH-{n}"),
        group_type=OktaGroupType.APP_GROUP, observed_at=observed_at, complete=complete, source_app_id=source,
        directory_object_sid=pick(sid, ad.object_sid if ad else None),
        directory_qualified_name=pick(qualified, f"{netbios}\\{ad.sam_account_name}" if ad else None),
        distinguished_name=pick(dn, ad.distinguished_name if ad else None),
        sam_account_name=pick(sam, ad.sam_account_name if ad else None),
    )


def okta_native_group(n: int, name: str, *, group_type: OktaGroupType = OktaGroupType.OKTA_GROUP,
                      complete: bool = True) -> OktaGroupIdentity:
    return OktaGroupIdentity(okta_group_ref=ref(n), okta_group_id=f"00gSYNTH{n:04d}", name=name,
                             group_type=group_type, observed_at=T, complete=complete)


def config(*mappings: ConfiguredMapping, **kw) -> CorrelationConfig:
    sources = (
        DirectorySource(okta_app_id=CORP_SOURCE, domain=CORP, netbios_name=NETBIOS[CORP]),
        DirectorySource(okta_app_id=EMEA_SOURCE, domain=EMEA, netbios_name=NETBIOS[EMEA]),
    )
    return CorrelationConfig(directory_sources=sources, configured_mappings=tuple(mappings), **kw)


def configured(n: int, ad: ADIdentity, *, sid: bool = True, domain: bool = True) -> ConfiguredMapping:
    return ConfiguredMapping(okta_group_id=f"00gSYNTH{n:04d}", ad_object_guid=ad.object_guid,
                             configuration_ref=f"config/synthetic-mappings.json#group-{n}",
                             ad_sid=ad.object_sid if sid else None, domain=ad.domain if domain else None)


class Clock:
    def __init__(self, start: datetime = T + timedelta(minutes=5)) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _cn(dn: str) -> str:
    first = dn.split(",", 1)[0]
    return first[3:] if first[:3].upper() == "CN=" else first


class SyntheticDirectory:
    """An in-memory forest answering exact-match lookups like the AD reader."""

    def __init__(self, groups: Iterable[ADIdentity] = (), *, clock: Clock, unreachable: Iterable[str] = (),
                 failing: Iterable[str] = (), domains: Iterable[str] = (CORP, EMEA, APAC)) -> None:
        self.groups = list(groups)
        self.clock = clock
        self.unreachable = set(unreachable)
        self.failing = set(failing)
        self.domains = sorted(domains)
        self.calls: list[tuple[LookupKind, str, str | None]] = []

    # Test helpers to change the synthetic world between runs.
    def remove(self, guid: str) -> None:
        self.groups = [g for g in self.groups if g.object_guid != guid]

    def replace(self, guid: str, **changes) -> None:
        self.groups = [replace(g, **changes) if g.object_guid == guid else g for g in self.groups]

    def add(self, *groups: ADIdentity) -> None:
        self.groups.extend(groups)

    def _matches(self, group: ADIdentity, by: LookupKind, value: str) -> bool:
        if by is LookupKind.OBJECT_GUID:
            return group.object_guid == value.lower()
        if by is LookupKind.OBJECT_SID:
            return group.object_sid == value
        if by is LookupKind.DISTINGUISHED_NAME:
            return group.distinguished_name.casefold() == value.casefold()
        if by is LookupKind.SAM_ACCOUNT_NAME:
            return (group.sam_account_name or "").casefold() == value.casefold()
        return value.casefold() in {_cn(group.distinguished_name).casefold(), (group.sam_account_name or "").casefold()}

    def lookup(self, by: LookupKind, value: str, domain: str | None) -> ADIdentityLookup:
        self.calls.append((by, value, domain))
        now = self.clock()
        builtin = by is LookupKind.OBJECT_SID and value.startswith("S-1-5-32-")
        if domain is not None:
            scope = [domain]
        elif by is LookupKind.OBJECT_SID and not builtin:
            owner = next((d for d, sid in DOMAIN_SIDS.items() if value.rsplit("-", 1)[0] == sid and d in self.domains), None)
            if owner is None:
                return ADIdentityLookup(by=by, value=value, domain=None, status=LookupStatus.NOT_FOUND, observed_at=now,
                                        searched_domains=tuple(self.domains))
            scope = [owner]
        else:
            scope = list(self.domains)
        searched = [d for d in scope if d not in self.unreachable and d not in self.failing]
        unsearched = [d for d in scope if d not in searched]
        found = sorted((g for g in self.groups if g.domain in searched and self._matches(g, by, value)),
                       key=lambda g: g.distinguished_name)
        forest_unique = by in (LookupKind.OBJECT_GUID, LookupKind.DISTINGUISHED_NAME) or (
            by is LookupKind.OBJECT_SID and not builtin)
        if len(found) > 1:
            status = LookupStatus.AMBIGUOUS
        elif len(found) == 1 and (forest_unique or not unsearched):
            status = LookupStatus.RESOLVED
        elif not found and not unsearched:
            status = LookupStatus.NOT_FOUND
        elif any(d in self.failing for d in scope):
            status = LookupStatus.FAILED
            found = []
        else:
            status = LookupStatus.INCOMPLETE
        return ADIdentityLookup(by=by, value=value, domain=domain, status=status, observed_at=now,
                                candidates=tuple(found), searched_domains=tuple(searched),
                                unsearched_domains=tuple(unsearched),
                                error="synthetic domain unreachable" if unsearched else None)


class LimitedDirectory(SyntheticDirectory):
    """Keeps at most ``limit`` candidates, flagging truncation like the worker."""

    def __init__(self, *args, limit: int, **kw) -> None:
        super().__init__(*args, **kw)
        self.limit = limit

    def lookup(self, by, value, domain):
        result = super().lookup(by, value, domain)
        if len(result.candidates) > self.limit:
            return replace(result, candidates=result.candidates[: self.limit], candidates_truncated=True)
        return result
