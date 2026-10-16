"""A synthetic AD identity directory for the local demo (owner decision).

``StoreSyntheticDirectory`` answers the correlation engine's exact-match identity lookups
from the AD group evidence already recorded in a SYNTHETIC store, with the AD report
contract's resolution rules: the narrowest scope, a SID's own domain for a SID lookup, and AMBIGUOUS
for more than one match. It reads the store and nothing else: no directory, network, or
process is touched. It refuses to exist anywhere but a SYNTHETIC store in
``LOCAL_SYNTHETIC`` mode. This build has no AD adapter or reader.

``SyntheticMappingGateway`` gives the operator API what mapping review needs: the Okta
identity of a stored group and a ``MappingReviewService`` over this directory and the
store's own review registry.

``correlate_stored_group`` is how the demo's identity-mapping evidence is made (owner
decision): the correlation engine runs over this directory with
the synthetic correlation configuration, and the lifecycle reads exactly what the engine
proved. The configuration (``config/correlation.synthetic.json``) is the demo's reviewed
mapping configuration: it names each exact pairing by objectGUID and objectSid, and the
engine still has to resolve both in the directory. A group it does not name falls back to
the name search, so it can never be exact. No verification gate is changed for the demo:
the Okta-derived objectGUID stays unused (D30) and Okta's stored directory objectSid
(0008) stays unverified (D37): it corroborates a configured pairing, never replaces it.
"""

import json
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.correlation.directory import failed_lookup
from app.correlation.engine import correlate
from app.correlation.evidence import mapping_evidence
from app.correlation.model import (
    ADIdentity,
    ADIdentityLookup,
    CorrelationConfig,
    CorrelationResult,
    LookupStatus,
    OktaGroupIdentity,
)
from app.correlation.review import MappingReviewService, StoreMappingRegistry
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.model import ADGroup, IdentityMapping, OktaGroup
from app.integrations.ad.contract import LookupKind
from app.store.environment import DatabaseEnvironment
from app.store.errors import StoreError
from app.store.store import Store

MAX_SYNTHETIC_GROUPS = 10_000
SYNTHETIC_CORRELATION_PATH = Path(__file__).resolve().parents[2] / "config" / "correlation.synthetic.json"
SYNTHETIC_CORRELATION_FORMAT = "ogwa-synthetic-correlation/1"
SYNTHETIC_DOMAIN_SUFFIX = ".synthetic.example"
# The fictional Null Meridian company's AD domain (app.demo.null_meridian). It is named, not
# matched by suffix: nothing else under that name is ever accepted as synthetic.
NULL_MERIDIAN_AD_DOMAIN = "corp.nullmeridian.info"
_CONFIGURATION_REF_PREFIXES = ("config/correlation.synthetic.json#", "config/correlation.null-meridian.json#")
_SYNTHETIC_GROUP_RE = re.compile(r"^00gSYNTH[A-Za-z0-9]{1,40}$")
_SYNTHETIC_APP_RE = re.compile(r"^0oaSYNTH[A-Za-z0-9]{1,40}$")


def _require_synthetic(store: Store) -> None:
    if store.mode is not ExecutionMode.LOCAL_SYNTHETIC or store.marker.environment is not DatabaseEnvironment.SYNTHETIC:
        raise ConfigError("the synthetic AD directory exists only for a SYNTHETIC store in LOCAL_SYNTHETIC mode; "
                          "there is no production AD adapter in this build")


def load_synthetic_correlation_config(path: Path = SYNTHETIC_CORRELATION_PATH) -> CorrelationConfig:
    """Parse the synthetic correlation configuration strictly. Only synthetic identifiers are accepted."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"synthetic correlation configuration {Path(path).name} cannot be read: "
                          f"{type(exc).__name__}") from None
    if not isinstance(data, dict) or set(data) != {"format", "correlation"}:
        raise ConfigError("synthetic correlation configuration takes exactly 'format' and 'correlation'")
    if data["format"] != SYNTHETIC_CORRELATION_FORMAT:
        raise ConfigError(f"synthetic correlation configuration format must be {SYNTHETIC_CORRELATION_FORMAT}")
    try:
        config = CorrelationConfig.from_mapping(data["correlation"])
    except InvalidRecord as exc:
        raise ConfigError(f"synthetic correlation configuration is invalid: {exc}") from None
    for source in config.directory_sources:
        if not _SYNTHETIC_APP_RE.match(source.okta_app_id) or not is_synthetic_domain(source.domain):
            raise ConfigError("every synthetic directory source must be a 0oaSYNTH integration of a "
                              f"*{SYNTHETIC_DOMAIN_SUFFIX} or the {NULL_MERIDIAN_AD_DOMAIN} domain")
    for mapping in config.configured_mappings:
        if not _SYNTHETIC_GROUP_RE.match(mapping.okta_group_id):
            raise ConfigError("every configured synthetic mapping must name a 00gSYNTH Okta group")
        if mapping.domain is None or not is_synthetic_domain(mapping.domain):
            raise ConfigError(f"configured synthetic mapping {mapping.okta_group_id} must be scoped to a "
                              f"*{SYNTHETIC_DOMAIN_SUFFIX} or the {NULL_MERIDIAN_AD_DOMAIN} domain")
        if mapping.ad_sid is None:
            raise ConfigError(f"configured synthetic mapping {mapping.okta_group_id} must name the objectSid as "
                              "well as the objectGUID")
        if not mapping.configuration_ref.startswith(_CONFIGURATION_REF_PREFIXES):
            raise ConfigError(f"configured synthetic mapping {mapping.okta_group_id} must have a configurationRef "
                              f"under {' or '.join(_CONFIGURATION_REF_PREFIXES)}")
    return config


def is_synthetic_domain(domain: str) -> bool:
    return domain.endswith(SYNTHETIC_DOMAIN_SUFFIX) or domain == NULL_MERIDIAN_AD_DOMAIN


def _cn(dn: str) -> str:
    first = dn.split(",", 1)[0]
    return first[3:] if first[:3].upper() == "CN=" else first


class StoreSyntheticDirectory:
    """Identity lookups over the latest recorded synthetic AD group observations."""

    def __init__(self, store: Store, *, clock: Callable[[], datetime]) -> None:
        _require_synthetic(store)
        self._store = store
        self._clock = clock
        self._frozen: list[ADIdentity] | None = None

    def frozen(self) -> "StoreSyntheticDirectory":
        """A copy that reads the store's AD groups once and keeps them. For a seed that records
        every AD group first and then correlates many Okta groups; the answers are the same as
        a fresh read as long as no AD evidence is recorded in between."""
        copy = StoreSyntheticDirectory(self._store, clock=self._clock)
        copy._frozen = self._groups()
        return copy

    def at(self, clock: Callable[[], datetime]) -> "StoreSyntheticDirectory":
        """The same directory (and frozen groups, if any) reporting lookups at ``clock``."""
        copy = StoreSyntheticDirectory(self._store, clock=clock)
        copy._frozen = self._frozen
        return copy

    def _groups(self) -> list[ADIdentity]:
        if self._frozen is not None:
            return self._frozen
        rows = self._store.connection.execute("SELECT id FROM ad_groups ORDER BY id LIMIT ?", (MAX_SYNTHETIC_GROUPS,))
        groups = []
        for row in rows.fetchall():
            g = self._store.latest(ADGroup, row["id"])
            if g is None or not g.exists or g.distinguished_name is None:
                continue  # a deleted or unreadable group has no identity to offer
            groups.append(ADIdentity(object_guid=g.object_guid, object_sid=g.sid, distinguished_name=g.distinguished_name,
                                     sam_account_name=g.sam_account_name, domain=g.domain))
        return groups

    @staticmethod
    def _matches(group: ADIdentity, by: LookupKind, value: str) -> bool:
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
        now = self._clock()
        try:
            by = LookupKind(by)
            groups = self._groups()
            domains = sorted({g.domain for g in groups})
            if domain is not None:
                scope = [domain.lower()]
            elif by is LookupKind.OBJECT_SID and not value.startswith("S-1-5-32-"):
                owner = {g.object_sid.rsplit("-", 1)[0]: g.domain for g in groups if g.object_sid}.get(value.rsplit("-", 1)[0])
                scope = [owner] if owner else []
            else:
                scope = domains
            found = sorted((g for g in groups if g.domain in scope and self._matches(g, by, value)),
                           key=lambda g: g.distinguished_name)
        except Exception as exc:  # the port must report directory problems, never raise
            return failed_lookup(by, value, domain, now, f"synthetic directory error: {type(exc).__name__}")
        status = (LookupStatus.AMBIGUOUS if len(found) > 1 else
                  LookupStatus.RESOLVED if found else LookupStatus.NOT_FOUND)
        return ADIdentityLookup(by=by, value=value, domain=domain, status=status, observed_at=now,
                                candidates=tuple(found), searched_domains=tuple(scope))


def okta_group_identity(group: OktaGroup) -> OktaGroupIdentity:
    """What correlation may use from a stored Okta group observation.

    The stored ``directory_external_id`` is Okta's own rendering of the AD objectGUID.
    Its decoding is unverified (D23, D30), so it is never passed on as
    ``directory_object_guid``. Okta's objectSid (0008) is passed on as the directory-source
    claim; the engine treats it as unverified (D37), so it can corroborate a
    configured or reviewed pairing but never make one exact. The store holds no DN for
    Okta groups.
    """
    directory = group.source_directory_id is not None
    return OktaGroupIdentity(
        okta_group_ref=group.id, okta_group_id=group.okta_group_id, name=group.name, group_type=group.group_type,
        observed_at=group.provenance.observed_at, complete=group.provenance.result_status is ResultStatus.COMPLETE,
        source_app_id=group.source_directory_id if directory else None,
        directory_object_sid=group.directory_object_sid_unverified if directory else None,
        directory_qualified_name=group.directory_qualified_name if directory else None,
    )


class StoreADGroupIds:
    """Resolves an objectGUID to the id of the ADGroup evidence already in the synthetic store."""

    def __init__(self, store: Store) -> None:
        _require_synthetic(store)
        self._store = store

    def ad_group(self, object_guid: str) -> str:
        row = self._store.connection.execute("SELECT id FROM ad_groups WHERE object_guid = ?",
                                             (object_guid.lower(),)).fetchone()
        if row is None:
            raise StoreError(f"no AD group evidence is recorded for objectGUID {object_guid}")
        return row["id"]


def correlate_stored_group(store: Store, okta_group_ref: str, *, config: CorrelationConfig,
                           clock: Callable[[], datetime],
                           directory: "StoreSyntheticDirectory | None" = None) -> tuple[CorrelationResult, IdentityMapping]:
    """Correlate one stored Okta group over the synthetic directory, and the mapping evidence it yields.

    Records nothing: the caller records the returned ``IdentityMapping`` as SYNTHETIC
    evidence. Review history from the store's registry is included, as in the operator API.
    ``directory`` lets a seed reuse one directory (see ``StoreSyntheticDirectory.frozen``)
    across many correlations; by default each correlation reads the store afresh.
    """
    _require_synthetic(store)
    group = store.latest(OktaGroup, okta_group_ref)
    if group is None:
        raise StoreError(f"no Okta group evidence is recorded for {okta_group_ref}")
    if directory is None:
        directory = StoreSyntheticDirectory(store, clock=clock)
    result = correlate(okta_group_identity(group), directory=directory.at(clock),
                       config=config, clock=clock, history=StoreMappingRegistry(store).history(okta_group_ref))
    return result, mapping_evidence(result, source=EvidenceSource.SYNTHETIC, ids=StoreADGroupIds(store)).mapping


class SyntheticMappingGateway:
    """The operator API's mapping-review gateway for the local synthetic demo."""

    def __init__(self, store: Store, *, clock: Callable[[], datetime], config: CorrelationConfig | None = None) -> None:
        _require_synthetic(store)
        self._store = store
        # The configuration the demo's mapping evidence was correlated with, so an
        # inspection reproduces what the lifecycle reads until something changes.
        if config is None:
            from app.demo.datasets import dataset_of

            config = load_synthetic_correlation_config(dataset_of(store).correlation_path)
        self.service = MappingReviewService(directory=StoreSyntheticDirectory(store, clock=clock), config=config,
                                            registry=StoreMappingRegistry(store), clock=clock)

    def okta_identity(self, okta_group_ref: str) -> OktaGroupIdentity | None:
        group = self._store.latest(OktaGroup, okta_group_ref)
        return None if group is None else okta_group_identity(group)
