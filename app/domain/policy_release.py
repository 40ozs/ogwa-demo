"""Named, versioned policy releases, and the policy reference a decision records (OGWA-DEMO-02).

A ``CandidatePolicy`` (``ogwa-candidate-policy/v1``) is the rules: thresholds, freshness windows,
required dependency kinds, and protected lists, identified by the SHA-256 digest of its canonical
document. A ``PolicyRelease`` gives one such document a stable human identity:

- ``policy_id``: a stable identifier that never changes across versions (``NM-LIFECYCLE-004``);
- ``version``: an explicit semantic version (``1.2.0``), strictly increasing along the chain;
- ``effective_from``, ``supersedes``, and ``changes``: when it took effect, which version it
  replaced, and what changed, in words.

The release document (``ogwa-policy-release/v1``) is strict JSON with the policy document
embedded unchanged, so the release adds identity and never a second way to express a rule.
``release_digest`` covers the whole release; ``policy_digest`` is the rules' own digest, the one
every classification already names.

A release is not an approval. In a store, the policy in force is still the latest approved
``PolicyVersion`` (D32, D33): append-only, two-person, audited. A release only names the content
of a version, matched by ``policy_digest``; a version whose digest no release carries has no
release identity, and every surface says so instead of guessing one.

``PolicyRef`` is what a decision records about the policy that judged it, at the moment it was
judged: the rules' digest, whether the policy was a recorded version or the unrecorded synthetic
demo policy, the version's id and sequence, and the release identity when there is one. A later
version never rewrites it: the reference is stored with the decision's audit event and read
back as stored.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cached_property
from typing import Any

from app.domain.candidate_policy import (
    MAX_DOCUMENT_LENGTH,
    CandidatePolicy,
    _no_duplicate_keys,
    _refuse_constant,
    _section,
    canonical_json,
)
from app.domain.errors import InvalidRecord
from app.domain.evidence import check_digest, stable_digest
from app.domain.ids import IdKind, check_id, check_text, check_utc

RELEASE_FORMAT = "ogwa-policy-release/v1"

POLICY_ID_RE = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+")
SEMVER_RE = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
MAX_POLICY_ID = 64
MAX_TITLE = 200
MAX_PURPOSE = 1000
MAX_CHANGE = 500
MAX_CHANGES = 20
_RELEASE_KEYS = {"format", "policyId", "version", "title", "purpose", "effectiveFrom", "supersedes", "changes",
                 "synthetic", "policy"}
_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"

# Where the policy in force came from. Every API/UI surface labels the unrecorded one (D66).
RECORDED_SOURCE = "RECORDED_VERSION"
DEMO_SOURCE = "UNRECORDED_SYNTHETIC_DEMO"
POLICY_SOURCES = (RECORDED_SOURCE, DEMO_SOURCE)


def check_policy_id(value: object, field: str = "policy_id") -> str:
    if not isinstance(value, str) or len(value) > MAX_POLICY_ID or not POLICY_ID_RE.fullmatch(value):
        raise InvalidRecord(f"{field} must be an upper-case identifier with at least one hyphen, at most "
                            f"{MAX_POLICY_ID} characters (for example NM-LIFECYCLE-004)")
    return value


def check_version(value: object, field: str = "version") -> str:
    if not isinstance(value, str) or not SEMVER_RE.fullmatch(value):
        raise InvalidRecord(f"{field} must be a semantic version MAJOR.MINOR.PATCH without leading zeros")
    return value


def version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in check_version(version).split("."))
    return major, minor, patch


def _format_time(at: datetime) -> str:
    return at.astimezone(timezone.utc).strftime(_TIMESTAMP)


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise InvalidRecord(f"{field} must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, _TIMESTAMP).replace(tzinfo=timezone.utc)
    except ValueError:
        raise InvalidRecord(f"{field} must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ") from None


@dataclass(frozen=True)
class PolicyRelease:
    policy_id: str
    version: str
    title: str
    purpose: str
    effective_from: datetime
    supersedes: str | None  # the version this one replaced; None only for the first release
    changes: tuple[str, ...]  # what changed from ``supersedes``, in words
    synthetic: bool  # a demo/fixture release: never a production policy
    rules: CandidatePolicy

    def __post_init__(self) -> None:
        check_policy_id(self.policy_id)
        check_version(self.version)
        check_text(self.title, "title", max_length=MAX_TITLE)
        check_text(self.purpose, "purpose", max_length=MAX_PURPOSE)
        check_utc(self.effective_from, "effective_from")
        if self.effective_from.utcoffset().total_seconds() or self.effective_from.microsecond:
            raise InvalidRecord("effective_from must be a whole-second UTC time")
        if self.supersedes is not None:
            check_version(self.supersedes, "supersedes")
            if version_key(self.supersedes) >= version_key(self.version):
                raise InvalidRecord("a release must supersede a lower version")
        if not isinstance(self.changes, tuple) or len(self.changes) > MAX_CHANGES:
            raise InvalidRecord(f"changes must be a tuple of at most {MAX_CHANGES} entries")
        for change in self.changes:
            check_text(change, "change", max_length=MAX_CHANGE)
        if self.supersedes is not None and not self.changes:
            raise InvalidRecord("a release that supersedes another must say what changed")
        if not isinstance(self.synthetic, bool):
            raise InvalidRecord("synthetic must be a boolean")
        if not isinstance(self.rules, CandidatePolicy):
            raise InvalidRecord("rules must be a CandidatePolicy")

    @property
    def name(self) -> str:
        return f"{self.policy_id} v{self.version}"

    @property
    def policy_digest(self) -> str:
        return self.rules.digest

    def to_document(self) -> dict[str, Any]:
        return {
            "format": RELEASE_FORMAT,
            "policyId": self.policy_id,
            "version": self.version,
            "title": self.title,
            "purpose": self.purpose,
            "effectiveFrom": _format_time(self.effective_from),
            "supersedes": self.supersedes,
            "changes": list(self.changes),
            "synthetic": self.synthetic,
            "policy": self.rules.to_document(),
        }

    @classmethod
    def from_document(cls, data: Any) -> "PolicyRelease":
        """Strict: every key is required and no other key is accepted."""
        doc = _section(data, "release", _RELEASE_KEYS)
        if doc["format"] != RELEASE_FORMAT:
            raise InvalidRecord(f"release format must be {RELEASE_FORMAT!r}")
        changes = doc["changes"]
        if not isinstance(changes, list) or not all(isinstance(c, str) for c in changes):
            raise InvalidRecord("changes must be a list of strings")
        if not isinstance(doc["synthetic"], bool):
            raise InvalidRecord("synthetic must be a boolean")
        for key in ("policyId", "version", "title", "purpose"):
            if not isinstance(doc[key], str):
                raise InvalidRecord(f"{key} must be a string")
        return cls(
            policy_id=doc["policyId"], version=doc["version"], title=doc["title"], purpose=doc["purpose"],
            effective_from=_parse_time(doc["effectiveFrom"], "effectiveFrom"), supersedes=doc["supersedes"],
            changes=tuple(changes), synthetic=doc["synthetic"], rules=CandidatePolicy.from_document(doc["policy"]),
        )

    @classmethod
    def from_json(cls, text: str) -> "PolicyRelease":
        if not isinstance(text, str) or len(text) > MAX_DOCUMENT_LENGTH:
            raise InvalidRecord(f"release document must be a string of at most {MAX_DOCUMENT_LENGTH} characters")
        try:
            data = json.loads(text, parse_constant=_refuse_constant, object_pairs_hook=_no_duplicate_keys)
        except ValueError as exc:
            raise InvalidRecord(f"release document is not valid JSON: {exc}") from None
        return cls.from_document(data)

    def canonical_json(self) -> str:
        return canonical_json(self.to_document())

    def readable_json(self) -> str:
        """The form a reviewer reads: identity first, then the rules, indented. Same content as
        ``canonical_json``; only the layout differs, and the digest is over the canonical form."""
        return json.dumps(self.to_document(), indent=2, ensure_ascii=False) + "\n"

    @cached_property
    def release_digest(self) -> str:
        return stable_digest(self.to_document())

    def summary(self) -> dict[str, Any]:
        """The release's identity, without its rules."""
        return {"policyId": self.policy_id, "version": self.version, "name": self.name, "title": self.title,
                "effectiveFrom": _format_time(self.effective_from), "supersedes": self.supersedes,
                "changes": list(self.changes), "synthetic": self.synthetic, "releaseDigest": self.release_digest,
                "policyDigest": self.policy_digest}


def release_history_problems(releases: tuple[PolicyRelease, ...]) -> list[str]:
    """Why ``releases`` (oldest first) is not one policy's release chain.

    One policy id; strictly increasing versions and effective times; each release supersedes the
    one before it; and no two releases carry the same rules, so a rules digest names at most one
    release and a version bump always changes what the policy decides.
    """
    if not releases:
        return ["a release chain needs at least one release"]
    problems = []
    if any(not isinstance(r, PolicyRelease) for r in releases):
        return ["every release must be a PolicyRelease"]
    if len({r.policy_id for r in releases}) != 1:
        problems.append("a release chain holds one policy id")
    if releases[0].supersedes is not None:
        problems.append(f"the first release ({releases[0].version}) cannot supersede {releases[0].supersedes}")
    seen: dict[str, str] = {}
    for n, release in enumerate(releases):
        if release.policy_digest in seen:
            problems.append(f"{release.version} has the same rules as {seen[release.policy_digest]}")
        seen.setdefault(release.policy_digest, release.version)
        if n == 0:
            continue
        previous = releases[n - 1]
        if version_key(release.version) <= version_key(previous.version):
            problems.append(f"{release.version} does not follow {previous.version}")
        if release.supersedes != previous.version:
            problems.append(f"{release.version} must supersede {previous.version}, not {release.supersedes}")
        if release.effective_from <= previous.effective_from:
            problems.append(f"{release.version} must take effect after {previous.version}")
    return problems


def release_for_digest(releases: tuple[PolicyRelease, ...], policy_digest: str) -> PolicyRelease | None:
    """The release whose rules have this digest, or None: never the nearest or the latest."""
    return next((r for r in releases if r.policy_digest == policy_digest), None)


# --- the reference a decision records ------------------------------------------------------------

POLICY_DETAIL_KEYS = ("policy_digest", "policy_source", "policy_version_id", "policy_sequence", "policy_id",
                      "policy_release", "policy_release_digest")
_NONE = "-"


@dataclass(frozen=True)
class PolicyRef:
    """The exact policy that judged one decision, as recorded with it."""

    policy_digest: str  # the rules' digest (CandidatePolicy.digest)
    source: str  # RECORDED_SOURCE or DEMO_SOURCE
    version_id: str | None = None  # the recorded PolicyVersion, when recorded
    sequence: int | None = None  # its position in the store's policy chain
    policy_id: str | None = None  # the release identity, when a release carries these rules
    version: str | None = None
    release_digest: str | None = None

    def __post_init__(self) -> None:
        check_digest(self.policy_digest, "policy_digest")
        if self.source not in POLICY_SOURCES:
            raise InvalidRecord(f"policy source must be one of {', '.join(POLICY_SOURCES)}")
        if self.source == RECORDED_SOURCE:
            check_id(self.version_id, IdKind.POLICY_VERSION, "version_id")
            if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 0:
                raise InvalidRecord("a recorded policy reference needs the version's sequence")
        elif self.version_id is not None or self.sequence is not None:
            raise InvalidRecord("an unrecorded policy has no version id or sequence")
        named = (self.policy_id, self.version, self.release_digest)
        if any(v is None for v in named) and any(v is not None for v in named):
            raise InvalidRecord("a release identity needs its policy id, version, and release digest together")
        if self.policy_id is not None:
            check_policy_id(self.policy_id)
            check_version(self.version)
            check_digest(self.release_digest, "release_digest")

    @classmethod
    def of(cls, *, policy_digest: str, source: str, version_id: str | None = None, sequence: int | None = None,
           release: PolicyRelease | None = None) -> "PolicyRef":
        if release is not None and release.policy_digest != policy_digest:
            raise InvalidRecord("the release does not carry these rules")
        return cls(policy_digest=policy_digest, source=source, version_id=version_id, sequence=sequence,
                   policy_id=release.policy_id if release else None, version=release.version if release else None,
                   release_digest=release.release_digest if release else None)

    @property
    def recorded(self) -> bool:
        return self.source == RECORDED_SOURCE

    @property
    def name(self) -> str | None:
        return f"{self.policy_id} v{self.version}" if self.policy_id else None

    def audit_details(self) -> dict[str, str]:
        """The reference as audit-event details: every key always present, "-" for none."""
        values = (self.policy_digest, self.source, self.version_id, self.sequence, self.policy_id, self.version,
                  self.release_digest)
        return {key: _NONE if value is None else str(value) for key, value in zip(POLICY_DETAIL_KEYS, values)}

    @classmethod
    def from_audit_details(cls, details: tuple[tuple[str, str], ...]) -> "PolicyRef | None":
        """The reference an event recorded, or None if it recorded none. All keys or none."""
        found = {k: v for k, v in details if k in POLICY_DETAIL_KEYS}
        if not found:
            return None
        if set(found) != set(POLICY_DETAIL_KEYS):
            raise InvalidRecord("an event's policy reference must carry every policy key")
        value = {k: None if v == _NONE else v for k, v in found.items()}
        sequence = value["policy_sequence"]
        if sequence is not None and not sequence.isdigit():
            raise InvalidRecord("policy_sequence must be a non-negative integer")
        return cls(policy_digest=value["policy_digest"], source=value["policy_source"],
                   version_id=value["policy_version_id"], sequence=None if sequence is None else int(sequence),
                   policy_id=value["policy_id"], version=value["policy_release"],
                   release_digest=value["policy_release_digest"])

    def to_dict(self) -> dict[str, Any]:
        return {"policyId": self.policy_id, "version": self.version, "name": self.name,
                "releaseDigest": self.release_digest, "policyDigest": self.policy_digest, "source": self.source,
                "recorded": self.recorded, "versionId": self.version_id, "versionSequence": self.sequence}


def strip_policy_details(details: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return tuple(pair for pair in details if pair[0] not in POLICY_DETAIL_KEYS)


__all__ = [
    "DEMO_SOURCE", "POLICY_DETAIL_KEYS", "POLICY_SOURCES", "RECORDED_SOURCE", "RELEASE_FORMAT", "PolicyRef",
    "PolicyRelease", "check_policy_id", "check_version", "release_for_digest", "release_history_problems",
    "strip_policy_details", "version_key",
]
