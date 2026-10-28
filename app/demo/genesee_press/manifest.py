"""The committed, machine-readable record of the Genesee Press dataset OGWA loads, and the reviewed
correlation configuration it implies.

``docs/demo/genesee-press.manifest.json`` lists what OGWA built from the vendored projection: every
person, department, group and application with OGWA's identifiers, group creation dates, nesting,
direct memberships and assignments. The shared world itself is ``synthetic-enterprise``; this file
is OGWA's reviewable view of it, so a diff shows exactly what a re-vendor changed.
``config/correlation.genesee-press.json`` is the reviewed mapping configuration the demo correlates
with. Both are generated and committed; a test fails if either drifts.

    python -m app.demo.genesee_press check     exit 1 if a committed file differs
    python -m app.demo.genesee_press write     regenerate both files
"""

from pathlib import Path

from app.demo.genesee_press import profile
from app.demo.null_meridian.dataset import NullMeridianDataset
from app.demo.null_meridian.manifest import correlation_document, manifest_document, render, render_correlation

REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = REPO_ROOT / "docs" / "demo" / "genesee-press.manifest.json"
CORRELATION_PATH = REPO_ROOT / "config" / "correlation.genesee-press.json"
MANIFEST_FORMAT = "ogwa-genesee-press-manifest/1"
CORRELATION_REF = "config/correlation.genesee-press.json#"
NOTICE = ("Fictional company. Every person, group, application, membership and assignment is the shared synthetic "
          "world's (synthetic-enterprise, projection ogwa; see profile.source); OGWA adds only its own identifiers, "
          "attributes and computed findings. Nothing is derived from any real tenant, directory, or organization.")


def generated_files(ds: NullMeridianDataset) -> dict[Path, str]:
    ad = (profile.AD_DNS_DOMAIN, profile.AD_NETBIOS)
    manifest = manifest_document(ds, manifest_format=MANIFEST_FORMAT, active_directory=ad,
                                 naming_eras=profile.GP_NAMING_ERAS, milestones=profile.MILESTONES, notice=NOTICE)
    correlation = correlation_document(ds, okta_ad_source_id=profile.OKTA_AD_SOURCE_ID, active_directory=ad,
                                       reference=CORRELATION_REF)
    return {MANIFEST_PATH: render(manifest), CORRELATION_PATH: render_correlation(correlation)}


__all__ = ["CORRELATION_PATH", "CORRELATION_REF", "MANIFEST_FORMAT", "MANIFEST_PATH", "generated_files"]
