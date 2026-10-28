"""Genesee Press's synthetic lifecycle policy, GP-LIFECYCLE-004, and its recorded history.

The same two releases as the Null Meridian demo's NM-LIFECYCLE-004 (``app.demo.null_meridian.policy``),
re-labelled for Genesee Press and bound to its synthetic AD integration (``0oaSYNTHGPADDIR``):
``config/policies/genesee-press/GP-LIFECYCLE-004-{1.1.0,1.2.0}.json``. Every rule is unchanged, so
every candidate is judged exactly as before. The proposer and approver are the same synthetic
people; nothing here is a production policy.
"""

from functools import lru_cache

from app.demo.genesee_press.profile import OKTA_AD_SOURCE_ID
from app.demo.null_meridian.policy import POLICY_APPROVER, POLICY_AUTHOR, RELEASE_VERSIONS, policy_version
from app.demo.null_meridian.policy import REPO_ROOT
from app.domain.errors import InvalidRecord
from app.domain.policy_release import PolicyRelease, release_history_problems

RELEASE_DIR = REPO_ROOT / "config" / "policies" / "genesee-press"
POLICY_ID = "GP-LIFECYCLE-004"


def release_path(version: str):
    return RELEASE_DIR / f"{POLICY_ID}-{version}.json"


@lru_cache(maxsize=1)
def releases() -> tuple[PolicyRelease, ...]:
    """Every release of GP-LIFECYCLE-004, oldest first, checked as one chain."""
    out = tuple(PolicyRelease.from_json(release_path(v).read_text(encoding="utf-8")) for v in RELEASE_VERSIONS)
    problems = release_history_problems(out)
    for release in out:
        if release.policy_id != POLICY_ID or not release.synthetic:
            problems.append(f"{release.name} is not a synthetic {POLICY_ID} release")
        if not release.rules.lifecycle.ad_directory_source_ids <= {OKTA_AD_SOURCE_ID}:
            problems.append(f"{release.name} names an AD integration that is not the synthetic one")
    if problems:
        raise InvalidRecord(f"{POLICY_ID} releases are inconsistent: {'; '.join(problems)}")
    return out


def current_release() -> PolicyRelease:
    return releases()[-1]


__all__ = ["POLICY_APPROVER", "POLICY_AUTHOR", "POLICY_ID", "RELEASE_DIR", "current_release", "policy_version",
           "release_path", "releases"]
