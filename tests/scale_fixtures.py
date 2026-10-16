"""A synthetic tenant ten or more times the demo's size, for the large-tenant listing tests.

Every name, id, SID, and GUID here is invented. Group names repeat (each is shared by three
groups, across three synthetic domains) and do not follow id order, so a sort by name has
ties that only the stable id can break. Every tenth mapping found no AD group, so sorts by AD
group have missing values. Everything is written through the store's own writes, so each
record is digest-checked when it is read back.
"""

from datetime import timedelta

from app.api.local import build_local_api
from app.domain.ids import IdKind, deterministic_ids
from app.domain.lifecycle import LifecycleCandidate
from app.domain.model import DependencyKind, MappingConfidence
from tests.api_fixtures import VIEWER, ApiClient
from tests.domain_fixtures import (
    SYNTHETIC_DOMAIN_SID, SYSTEM, T0, ad_group, application, assignment, blocking_finding, dependency, fixed_id,
    mapping, okta_group,
)
from tests.store_fixtures import MutableClock, new_store


class ScaleTenant:
    def __init__(self, groups: int = 3000, applications: int = 60) -> None:
        self.groups = groups
        self.clock = MutableClock()
        self.store = new_store(clock=self.clock)
        record = lambda r: self.store.record_evidence(r, actor=SYSTEM)  # noqa: E731
        names = groups // 3
        with deterministic_ids("scale-tenant"):
            for i in range(1, applications + 1):
                record(application(T0, id=fixed_id(IdKind.OKTA_APPLICATION, i), okta_app_id=f"0oaSCALE{i:08d}",
                                   label=f"Scale App {i % 20:02d}"))
            for i in range(1, groups + 1):
                name, guid = f"SCALE-GROUP-{i * 7919 % names:05d}", f"5ca1e000-0000-4000-8000-{i:012x}"
                gid, adg = fixed_id(IdKind.OKTA_GROUP, i), fixed_id(IdKind.AD_GROUP, i)
                record(okta_group(T0, id=gid, okta_group_id=f"00gSCALE{i:08d}", name=name,
                                  directory_external_id=guid, directory_qualified_name=f"SYNTH\\{name}"))
                record(ad_group(T0, id=adg, object_guid=guid, domain=f"d{i % 3}.synthetic.example",
                                sid=f"{SYNTHETIC_DOMAIN_SID}-{10000 + i}", sam_account_name=name,
                                distinguished_name=f"CN={name},OU=Groups,DC=d{i % 3},DC=synthetic,DC=example"))
                if i % 10:
                    record(mapping(T0, id=fixed_id(IdKind.IDENTITY_MAPPING, i), okta_group_id=gid, ad_group_id=adg))
                else:
                    record(mapping(T0, MappingConfidence.NOT_FOUND, id=fixed_id(IdKind.IDENTITY_MAPPING, i),
                                   okta_group_id=gid))
                if i % 5 == 0:
                    record(dependency(T0, DependencyKind.AD_ACL_REFERENCE, i, subject_id=adg if i % 2 else gid,
                                      findings=(blocking_finding(),) if i % 15 == 0 else ()))
                if i % 4 == 0:
                    asgn = fixed_id(IdKind.ASSIGNMENT, i)
                    record(assignment(T0, id=asgn, application_id=fixed_id(IdKind.OKTA_APPLICATION, i % applications + 1),
                                      okta_group_id=gid))
                    self.store.create_candidate(LifecycleCandidate.discover(
                        okta_group_id=gid, assignment_ids=(asgn,), proposed_by=SYSTEM,
                        now=T0 + timedelta(minutes=i % 7), reason_codes=("ZERO_USAGE_90D",)))
        self.api = build_local_api(self.store, clock=self.clock, synthetic_directory=False)

    def client(self, subject: str = VIEWER) -> ApiClient:
        client = ApiClient(self.api)
        assert client.sign_in(subject).status == 201
        return client

    def close(self) -> None:
        self.store.close()
