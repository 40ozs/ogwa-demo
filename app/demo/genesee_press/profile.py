"""The Genesee Press demo dataset's profile: the shared world's facts plus OGWA's own constants.

The organization, its domain, its AD forest and its identity-provider adoption come from the
vendored ``synthetic-enterprise`` projection (``organization.jsonl``, the snapshot clock), never
from a copy here. What is OGWA's own stays here: the dataset selector, the seed namespace of the
store's audit identity, the synthetic AD domain SID and the Okta-shaped identifiers (``SYNTHGP``,
the shared world's documented rule ``SYNTHNM -> SYNTHGP``).

``geneseepress.example`` is a reserved name (RFC 2606): nothing under it is resolved, mailed,
or contacted.
"""

import json
import re
from datetime import date, datetime

from app.demo.genesee_press.projection import LOCK_PATH, VENDOR_ROOT
from app.demo.null_meridian.profile import NAMING_ERAS, OKTA_WAVES, NamingEra

DATASET_KEY = "genesee-press"
SEED = "genesee-press-v1"


def _vendored_facts() -> tuple[dict, dict]:
    """The organization record and the snapshot clock, read straight from the vendored files.

    ``app.demo.genesee_press.projection.load`` verifies every digest before the dataset is built; this
    module only needs two small facts at import time (the dataset registry reads them)."""
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    folder = VENDOR_ROOT / lock["snapshot"] / "projections" / "ogwa"
    header = json.loads((folder / "projection.json").read_text(encoding="utf-8"))
    (org,) = [json.loads(line) for line in (folder / "organization.jsonl").read_text(encoding="utf-8").splitlines()]
    return org, header["clock"]


_ORG, _CLOCK = _vendored_facts()
COMPANY: str = _ORG["name"]
PRIMARY_DOMAIN: str = _ORG["primary_domain"]
FOUNDED = date.fromisoformat(_ORG["founded_on"])
OKTA_ADOPTED = date.fromisoformat(_ORG["identity_provider_adopted_on"])
MODERN_NAMING_ADOPTED = date.fromisoformat(next(m["on"] for m in _ORG["milestones"] if "naming standard" in m["label"]))
AS_OF = datetime.fromisoformat(_CLOCK["effective_as_of"].replace("Z", "+00:00"))
SNAPSHOT_DATE = AS_OF.date()
AD_DNS_DOMAIN: str = _ORG["directory_dns_domain"]
AD_NETBIOS: str = _ORG["directory_netbios_name"]
MILESTONES: tuple[tuple[str, str], ...] = tuple((m["on"], m["label"]) for m in _ORG["milestones"])
TECH_DEBT = "moderate"

# OGWA's own synthetic identifiers. The domain SID is the one OGWA's directory ids already use
# (the projection's ad_sid); the Okta ids follow the shared world's SYNTHGP rule.
AD_DOMAIN_SID = "S-1-5-21-3100000001-3100000002-3100000003"
OKTA_AD_SOURCE_ID: str = _ORG["okta_directory_source_id"]
OKTA_EVERYONE_ID = "00gSYNTHGPEVERYONE"
STANDARD_PREFIX = "sec"  # the naming standard: sec-okta-* / sec-share-* (app.governance.naming)


def localize(text: str) -> str:
    """OGWA's shared demo wording for Genesee Press: the shared world's documented renames applied to
    the Null Meridian text the two datasets share (synthetic-enterprise D-01A-03, D-01A-06).

    ``NM-Cnn`` -> ``GP-Cnn`` (and every other ``NM-`` name, such as ``NM-SALESENG-USERS``); ``NM-LIFECYCLE`` -> ``GP-LIFECYCLE``; ``Null Meridian`` -> ``Genesee Press``;
    a group name's ``sg-`` / ``SG-`` prefix -> ``sec-`` / ``SEC-``; ``NM Intranet`` -> ``GP Intranet``;
    the ``NM-<APP>`` naming pattern -> ``GP-<APP>``; the site ``Meridian HQ`` -> ``Genesee HQ``."""
    text = text.replace("Null Meridian", COMPANY).replace("NM-LIFECYCLE", "GP-LIFECYCLE").replace("NM Intranet", "GP Intranet")
    text = text.replace("NM-<APP>", "GP-<APP>").replace("Meridian HQ", "Genesee HQ")
    text = re.sub(r"(?<![A-Za-z0-9])NM-(?=[A-Z0-9])", "GP-", text)  # NM-C10, NM-SALESENG-USERS
    text = re.sub(r"(?<![A-Za-z0-9])sg-", "sec-", text)
    return re.sub(r"(?<![A-Za-z0-9])SG-", "SEC-", text)


GP_NAMING_ERAS: tuple[NamingEra, ...] = tuple(
    NamingEra(e.key, localize(e.label), e.start, e.end, localize(e.description)) for e in NAMING_ERAS)

__all__ = ["AD_DNS_DOMAIN", "AD_DOMAIN_SID", "AD_NETBIOS", "AS_OF", "COMPANY", "DATASET_KEY", "FOUNDED",
           "GP_NAMING_ERAS", "MILESTONES", "MODERN_NAMING_ADOPTED", "OKTA_AD_SOURCE_ID", "OKTA_ADOPTED", "OKTA_EVERYONE_ID",
           "OKTA_WAVES", "PRIMARY_DOMAIN", "SEED", "SNAPSHOT_DATE", "STANDARD_PREFIX", "localize"]
