"""Null Meridian's synthetic lifecycle policy, NM-LIFECYCLE-004, and its recorded history (OGWA-DEMO-02).

The releases are reviewer-readable JSON files (``config/policies/null-meridian/``, format
``ogwa-policy-release/v1``). Each embeds an unchanged ``ogwa-candidate-policy/v1`` document, so the
demo is judged by the same rules format, parser, floors, and ceilings as any other policy.

- **1.1.0** (effective 2026-04-01): the first recorded version. Approval evidence may be up to 14 days old.
- **1.2.0** (effective 2026-09-28): approval evidence at most 7 days old. Its rules are exactly the
  policy the demo always ran (``world.POLICY``), so every classification digest is unchanged.

Seeding records both through the store's real policy-version chain (append-only, two different
people, audited; D32, D33): 1.1.0 before the candidates are triaged on 2026-09-24/25, so their
decisions are judged by and record 1.1.0, and 1.2.0 afterwards, so the live demo (2026-10-01)
judges by 1.2.0. The proposer and approver are synthetic people; nothing here is a production
policy, and Null Meridian seeding refuses any store that is not SYNTHETIC.
"""

from functools import lru_cache
from pathlib import Path

from app.demo.null_meridian.profile import OKTA_AD_SOURCE_ID
from app.domain.actors import Actor, ActorKind
from app.domain.candidate_policy import PolicyRole, PolicyVersion
from app.domain.errors import InvalidRecord
from app.domain.policy_release import PolicyRelease, release_history_problems

REPO_ROOT = Path(__file__).resolve().parents[3]
RELEASE_DIR = REPO_ROOT / "config" / "policies" / "null-meridian"
POLICY_ID = "NM-LIFECYCLE-004"
RELEASE_VERSIONS = ("1.1.0", "1.2.0")

# Synthetic people (D33): Identity/Automation proposes, a different Security/IAM reviewer approves.
POLICY_AUTHOR = Actor(ActorKind.HUMAN, "synthetic.policy.author")
POLICY_APPROVER = Actor(ActorKind.HUMAN, "synthetic.security.reviewer")


def release_path(version: str) -> Path:
    return RELEASE_DIR / f"{POLICY_ID}-{version}.json"


@lru_cache(maxsize=1)
def releases() -> tuple[PolicyRelease, ...]:
    """Every release of NM-LIFECYCLE-004, oldest first, checked as one chain."""
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


def policy_version(release: PolicyRelease, *, id: str, previous: PolicyVersion | None) -> PolicyVersion:
    """The recorded version of ``release``, approved when it took effect."""
    return PolicyVersion.create(
        release.rules, id=id, previous=previous, proposed_by=POLICY_AUTHOR, proposer_role=PolicyRole.IDENTITY_AUTOMATION,
        approved_by=POLICY_APPROVER, approver_role=PolicyRole.SECURITY_IAM, decided_at=release.effective_from,
        reason=f"{release.name}: {release.changes[0] if release.changes else release.title}")


__all__ = ["POLICY_APPROVER", "POLICY_AUTHOR", "POLICY_ID", "RELEASE_DIR", "current_release", "policy_version",
           "release_path", "releases"]
