"""Loads the Genesee Press dataset into a SYNTHETIC store, through the shared seed path.

The seed is ``app.demo.null_meridian.world`` with the Genesee Press edition: the same inventory
evidence, the same eleven lifecycle candidates (GP-C01 .. GP-C11, formerly NM-C01 .. NM-C11), the
same policy releases (GP-LIFECYCLE-004 1.1.0 and 1.2.0), the same snapshot day and the same
directory snapshot, over the shared world's Genesee Press core. Seeding stops if any candidate
ends in another state than its scenario states, or if the correlation engine proves anything
other than the dataset expects.
"""

from functools import cache

from app.core.database_url import DatabaseTarget
from app.demo.genesee_press import policy, profile
from app.demo.genesee_press.dataset import RNG, build_dataset
from app.demo.genesee_press.manifest import CORRELATION_PATH
from app.demo.null_meridian import world as shared
from app.demo.null_meridian.edition import Edition

POLICY = policy.current_release().rules.lifecycle
COLLECTED = profile.AS_OF - 7 * shared.DAY
RECOLLECTED = profile.AS_OF - 6 * shared.HOUR


@cache
def edition() -> Edition:
    return Edition(profile.DATASET_KEY, profile.SEED, profile.COMPANY, profile.PRIMARY_DOMAIN, profile.AS_OF,
                   profile.SNAPSHOT_DATE, profile.AD_DNS_DOMAIN, profile.AD_NETBIOS, profile.OKTA_AD_SOURCE_ID,
                   CORRELATION_PATH, RNG, "GP-C", build_dataset, policy, profile.localize)


def candidates():
    return shared.candidates_for(edition())


def directory_snapshot(ds, candidate_ids):
    return shared.directory_snapshot(ds, candidate_ids, edition())


def seed_genesee_press(store):
    return shared.seed_null_meridian(store, edition())


def create_genesee_press_store(target: DatabaseTarget, *, clock=None):
    """Initialize a new SYNTHETIC store at ``target`` and load Genesee Press. Deterministic end to end."""
    return shared.create_null_meridian_store(target, clock=clock, edition=edition())


__all__ = ["COLLECTED", "POLICY", "RECOLLECTED", "candidates", "create_genesee_press_store", "directory_snapshot",
           "edition", "seed_genesee_press"]
