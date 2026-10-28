"""The vendored ``synthetic-enterprise`` projection for OGWA, read and verified (PROJECTION-CONTRACT §1).

OGWA never fetches ``synthetic-enterprise``. The OGWA projection of the shared world's standard
baseline snapshot is vendored at a pinned commit in ``vendor/synthetic-enterprise/<snapshot>/``
(the snapshot's ``manifest.json`` and ``projections/ogwa/``), and ``SYNTHETIC_ENTERPRISE.lock``
records where it came from. Before any record is used:

1. the manifest's SHA-256 must equal the lock's ``manifest_sha256``;
2. the manifest's OGWA ``header_sha256`` must equal the vendored ``projection.json``;
3. every record file must match the digest and record count in that header, and the manifest's
   per-file digest;
4. the header's projection, version, contract and dataset must be the ones the lock pins.

Updating is an explicit change in this repository: re-vendor at a new commit and update the lock
(``docs/demo/genesee-press.md``). Nothing here reads the network, the clock, or anything outside
the repository.
"""

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCK_PATH = REPO_ROOT / "SYNTHETIC_ENTERPRISE.lock"
VENDOR_ROOT = REPO_ROOT / "vendor" / "synthetic-enterprise"
PROJECTION = "ogwa"


class ProjectionError(ValueError):
    """The vendored projection does not match its lock, or is not one this build reads."""


@dataclass(frozen=True)
class VendoredProjection:
    lock: dict[str, Any]
    header: dict[str, Any]
    files: dict[str, tuple[dict[str, Any], ...]]  # record file name -> records, in file order

    def records(self, name: str) -> tuple[dict[str, Any], ...]:
        return self.files[name]

    @property
    def organization(self) -> dict[str, Any]:
        (org,) = self.files["organization.jsonl"]
        return org

    @property
    def source(self) -> dict[str, Any]:
        """What the store's snapshot and the docs cite: repository, commit, snapshot, versions, digests."""
        return {"repository": self.lock["repository"], "commit": self.lock["commit"], "snapshot": self.lock["snapshot"],
                "projection": self.lock["projection"], "dataset": self.lock["dataset"],
                "contractVersion": self.lock["contract_version"], "manifestSha256": self.lock["manifest_sha256"],
                "canonicalDigest": self.header["canonical_digest"]}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectionError(f"{path.name} cannot be read: {type(exc).__name__}") from None
    required = {"repository", "commit", "snapshot", "contract_version", "dataset", "projection", "manifest_sha256"}
    if not isinstance(lock, dict) or not required <= set(lock):
        raise ProjectionError(f"{path.name} must name {', '.join(sorted(required))}")
    if lock["projection"].split("@")[0] != PROJECTION:
        raise ProjectionError(f"{path.name} pins {lock['projection']}, not the {PROJECTION} projection")
    return lock


def load(lock_path: Path = LOCK_PATH, vendor_root: Path = VENDOR_ROOT) -> VendoredProjection:
    """Read and verify the vendored projection. Raises ProjectionError on any mismatch."""
    lock = read_lock(lock_path)
    root = vendor_root / lock["snapshot"]
    manifest_bytes = (root / "manifest.json").read_bytes()
    if _sha256(manifest_bytes) != lock["manifest_sha256"]:
        raise ProjectionError("the vendored manifest.json does not match SYNTHETIC_ENTERPRISE.lock")
    manifest = json.loads(manifest_bytes)
    folder = root / "projections" / PROJECTION
    header_bytes = (folder / "projection.json").read_bytes()
    entry = manifest.get("projections", {}).get(PROJECTION)
    if entry is None or entry["header_sha256"] != _sha256(header_bytes):
        raise ProjectionError("the vendored projection.json does not match the vendored manifest")
    header = json.loads(header_bytes)
    name, _, version = lock["projection"].partition("@")
    if (header["projection"], header["projection_version"]) != (name, version):
        raise ProjectionError(f"the vendored projection is {header['projection']}@{header['projection_version']}, "
                              f"the lock pins {lock['projection']}")
    if header["contract_version"] != lock["contract_version"] or header["dataset"] != lock["dataset"]:
        raise ProjectionError("the vendored projection's contract or dataset version is not the one the lock pins")
    files: dict[str, tuple[dict[str, Any], ...]] = {}
    for file_name, info in sorted(header["record_files"].items()):
        data = (folder / file_name).read_bytes()
        digest = _sha256(data)
        listed = manifest["files"].get(f"projections/{PROJECTION}/{file_name}", {}).get("sha256")
        if digest != info["sha256"] or digest != listed:
            raise ProjectionError(f"vendored {file_name} does not match its digest")
        records = tuple(json.loads(line) for line in data.decode("utf-8").splitlines())
        if len(records) != info["records"]:
            raise ProjectionError(f"vendored {file_name} has {len(records)} records, its header says {info['records']}")
        files[file_name] = records
    return VendoredProjection(lock, header, files)


@lru_cache(maxsize=1)
def vendored() -> VendoredProjection:
    """The verified projection this build reads (cached: the files never change at runtime)."""
    return load()


__all__ = ["LOCK_PATH", "ProjectionError", "VENDOR_ROOT", "VendoredProjection", "load", "read_lock", "vendored"]
