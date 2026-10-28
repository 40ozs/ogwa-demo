"""The facts a directory dataset gives the shared seed path (``app.demo.null_meridian.world``).

The seed path (inventory evidence, the eleven lifecycle candidates, the policy releases, the
snapshot day, the directory snapshot) is written once. An *edition* names everything it takes
from the dataset: the selector and seed namespace, the company and its AD forest, the Okta
directory integration, the reviewed correlation configuration, the keyed draws, the candidate
labels and wording, the dataset builder, and the policy releases.

Two editions exist:

- ``NULL_MERIDIAN`` (``null-meridian``): the legacy generator (``app.demo.null_meridian``). Kept,
  unchanged, until the Genesee Press dataset's parity is accepted (SYNTH-OGWA-01).
- ``app.demo.genesee_press.EDITION`` (``genesee-press``): the shared synthetic world's Genesee
  Press core, read from the vendored ``synthetic-enterprise`` projection.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any


def _same(text: str) -> str:
    return text


@dataclass(frozen=True)
class Edition:
    key: str
    seed: str
    company: str
    primary_domain: str
    as_of: datetime
    snapshot_date: date
    ad_dns_domain: str
    ad_netbios: str
    okta_ad_source_id: str
    correlation_path: Path
    rng: Any  # app.demo.null_meridian.rng, or an rng.Keyed with the same functions
    candidate_prefix: str  # "NM-C": candidates NM-C01 .. NM-C11
    dataset: Callable[[], Any]  # () -> NullMeridianDataset
    policy: ModuleType | Any  # releases(), current_release(), policy_version(release, id=, previous=)
    text: Callable[[str], str] = _same  # the edition's wording of the shared candidate and scenario text


@cache
def null_meridian() -> Edition:
    from app.demo.null_meridian import policy, profile, rng
    from app.demo.null_meridian.dataset import build_dataset
    from app.demo.null_meridian.manifest import CORRELATION_PATH

    return Edition(profile.DATASET_KEY, profile.SEED, profile.COMPANY, profile.PRIMARY_DOMAIN, profile.AS_OF,
                   profile.SNAPSHOT_DATE, profile.AD_DNS_DOMAIN, profile.AD_NETBIOS, profile.OKTA_AD_SOURCE_ID,
                   CORRELATION_PATH, rng, "NM-C", build_dataset, policy)


__all__ = ["Edition", "null_meridian"]
