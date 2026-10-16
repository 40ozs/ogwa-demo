"""Store test helpers. Synthetic data only; every database is in memory or in a temp directory."""

import contextlib
import dataclasses
from datetime import datetime, timedelta
from unittest import mock

from app.core.database_url import DatabaseTarget, parse_database_url
from app.core.modes import ExecutionMode
from app.domain.actors import Actor, ActorKind
from app.store.environment import DatabaseEnvironment
from app.store.store import Store
from tests.domain_fixtures import T0

INIT_ACTOR = Actor(ActorKind.HUMAN, "synthetic-store-admin")


class MutableClock:
    """A store clock the test controls. Starts well after every domain-fixture timestamp."""

    def __init__(self, start: datetime = T0 + timedelta(days=60)) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def memory_target() -> DatabaseTarget:
    return parse_database_url("sqlite:///:memory:")


def file_target(path) -> DatabaseTarget:
    return DatabaseTarget(backend="sqlite", path=path)


def new_store(target: DatabaseTarget | None = None, *, environment=DatabaseEnvironment.SYNTHETIC,
              mode=ExecutionMode.LOCAL_SYNTHETIC, clock=None) -> Store:
    return Store.initialize(target or memory_target(), environment=environment, mode=mode, actor=INIT_ACTOR,
                            clock=clock or MutableClock())


def table_dump(store: Store) -> dict[str, list[tuple]]:
    """Every row of every table, in a stable order, for byte-for-byte comparison."""
    conn = store.connection
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    dump = {}
    for table in tables:
        columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
        order = ", ".join(columns)
        dump[table] = [tuple(row) for row in conn.execute(f"SELECT {order} FROM {table} ORDER BY {order}")]
    return dump


# Evidence columns added after v0001, by the migration that added them. ``build_held_at``
# leaves them out of reads and writes when the build is held below that migration.
LATER_EVIDENCE_COLUMNS = {
    "okta_group_observations": {"directory_object_sid_unverified": 8},
}


@contextlib.contextmanager
def build_held_at(version: int):
    """The build as it was at schema ``version``, for tests that seed an older store and migrate it.

    Holds ``LATEST_VERSION`` at ``version``, writes and reads evidence without the columns
    later migrations added, and seeds the demo world without the values only those columns
    can hold (Okta's directory objectSid before 0008). A record that still carries such a
    value fails loudly rather than being dropped.
    """
    from app.demo import synthetic_world
    from app.store import evidence_tables, migrator
    from app.store import reset as reset_module
    from app.store import store as store_module

    with contextlib.ExitStack() as stack:
        for module in (migrator, store_module):
            stack.enter_context(mock.patch.object(module, "LATEST_VERSION", version))
        specs = []
        for spec in evidence_tables.SPECS:
            later = {c for c, v in LATER_EVIDENCE_COLUMNS.get(spec.observation_table, {}).items() if v > version}
            specs.append(_without_columns(spec, later) if later else spec)
        specs = tuple(specs)
        stack.enter_context(mock.patch.dict(evidence_tables.SPEC_BY_CLASS, {s.cls: s for s in specs}))
        for module in (evidence_tables, store_module, reset_module):
            stack.enter_context(mock.patch.object(module, "SPECS", specs))
        if version < 8:
            original = synthetic_world._World.okta_group

            def okta_group_without_sid(self, *args, sid=None, **kwargs):
                return original(self, *args, **kwargs)

            stack.enter_context(mock.patch.object(synthetic_world._World, "okta_group", okta_group_without_sid))
        if version < 11:
            # Before 0011: no AD-stage candidate columns, the legacy AD_RETIREMENT stage was
            # still recordable, and the demo world had fourteen scenarios with S12's single AD stage.
            stack.enter_context(mock.patch.object(store_module, "_ad_stage_columns", _no_ad_stage_columns))
            stack.enter_context(mock.patch.object(store_module, "_ad_stage_fields", lambda row: {}))
            stack.enter_context(mock.patch.object(store_module, "LEGACY_APPROVAL_STAGES", frozenset()))
            stack.enter_context(mock.patch.object(store_module, "LEGACY_JOB_KINDS", frozenset()))
            scenarios = synthetic_world.SCENARIOS
            stack.enter_context(mock.patch.object(synthetic_world, "SCENARIOS",
                                                  (*scenarios[:11], legacy_s12, *scenarios[12:14])))
        yield


def _no_ad_stage_columns(candidate) -> dict:
    for name in ("quarantine_approver", "quarantine_hold_until", "deletion_proposer", "deletion_proposed_at"):
        if getattr(candidate, name) is not None:
            raise AssertionError(f"{name} has a value, but the build is held before migration 0011 adds it")
    return {}


def legacy_s12(w) -> None:
    """S12 exactly as the demo world seeded it before migration 0011: the single AD
    stage's AD_RETIREMENT approval and dry-run job, and a refused RETIREMENT_DRY_RUN step.
    Seeding it at schema 10 gives the 0011 tests real legacy rows to preserve (D148)."""
    from app.demo.synthetic_world import (
        AS_OF, CORP, DAY, HOUR, MINUTE, REVIEWER_2, Condition, synthetic_guid, synthetic_sid,
    )
    from app.domain.approval import ApprovalStage
    from app.domain.evidence import ResultStatus
    from app.domain.execution import JobKind
    from app.domain.lifecycle import LifecycleState
    from app.domain.model import DependencyKind, MappingConfidence, OktaAppStatus

    t = AS_OF - 40 * DAY
    some_kinds = frozenset({DependencyKind.OKTA_OTHER_APP_ASSIGNMENT, DependencyKind.OKTA_POLICY_REFERENCE,
                            DependencyKind.AD_GROUP_MEMBERS})
    ids = w.standard(12, t, app_name="SYNTH Asset Register (v1)", app_status=OktaAppStatus.INACTIVE,
                     group_name="SYNTH-APP-ASSET-REGISTER", dep_kinds=some_kinds)
    cid = w.candidate(ids, t + 30 * MINUTE, "APP_INACTIVE", "ZERO_USAGE_90D")
    w.walk_to_hold(cid, ids, "S12", t)
    hold_until = w.store.load_candidate(cid).hold_until
    w.step(cid, LifecycleState.REVALIDATION_REQUIRED, hold_until + HOUR, reason="hold period ended")
    p = AS_OF - DAY
    guid = synthetic_guid(12 * 16)
    w.application("S12", "0oaSYNTHAPP12", "SYNTH Asset Register (v1)", OktaAppStatus.INACTIVE, p)
    w.okta_group("S12", "00gSYNTHGRP12", "SYNTH-APP-ASSET-REGISTER", p, guid=guid, sid=synthetic_sid(CORP, 5120))
    w.assignment("S12", ids.app, ids.group, p, present=False)
    w.usage("S12", ids.app, p)
    w.ad_group("S12", "SYNTH-APP-ASSET-REGISTER", guid, 5120, p)
    w.correlate("S12", ids.group, p, MappingConfidence.EXACT_CONFIGURED_MAPPING)
    w.dependencies("S12", ids.group, ids.ad_group, p, some_kinds | {DependencyKind.AD_ACL_REFERENCE},
                   statuses={DependencyKind.AD_ACL_REFERENCE: ResultStatus.PARTIAL})
    approval = w.approve(cid, "S12-ad", ApprovalStage.AD_RETIREMENT, p + HOUR, REVIEWER_2)
    job = w.dry_run(cid, "S12-ad", JobKind.AD_RETIREMENT, approval, p + HOUR + 10 * MINUTE, p + HOUR + 40 * MINUTE,
                    (ids.ad_group,))
    w.step(cid, LifecycleState.RETIREMENT_DRY_RUN, p + 2 * HOUR, approval=approval, job=job, expect_refusal=True)
    w.result("S12", "Partial dependency coverage at retirement", (Condition.DEPENDENCY_COVERAGE_PARTIAL_OR_UNKNOWN,),
             cid, "Hold ended and revalidation began, but AD retirement is refused: coverage is PARTIAL.")


def _without_columns(spec, columns: set[str]):
    def values(record):
        out = spec.observation_values(record)
        for column in columns:
            if out.pop(column) is not None:
                raise AssertionError(f"{column} has a value, but the build is held before the migration that adds it")
        return out

    def build(conn, anchor, obs):
        return spec.build(conn, anchor, {**{k: obs[k] for k in obs.keys()}, **dict.fromkeys(columns)})

    return dataclasses.replace(spec, observation_values=values, build=build)
