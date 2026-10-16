"""Each governed AD domain's quarantine OU (owner decision D136).

The mappings are deployment-controlled configuration, separate from the candidate policy:
the server reads them at start-up (``app.remediation.quarantine.load_quarantine_ous``), and
no API route reads them back for editing or changes them, so no operator can. The lifecycle
uses them to recognise a confirmed quarantine (the group observed as a direct child of its
domain's quarantine OU), and the remediation adapters to name where a quarantine would
move the group.

There is no unquarantine or restore operation (D149). A group that leaves its quarantine OU
blocks the deletion stage; the candidate cannot go back.

Nothing here performs I/O.
"""

import re
from dataclasses import dataclass

from app.domain.errors import InvalidRecord
from app.domain.model import ADGroup

QUARANTINE_OUS_FORMAT = "ogwa-quarantine-ous/v1"
MAX_OU_LENGTH = 512
_DNS_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_UNSAFE = re.compile(r"[*?%\x00-\x1f\x7f]")


def domain_dn(domain: str) -> str:
    """``corp.example`` -> ``DC=corp,DC=example``."""
    return ",".join(f"DC={label}" for label in domain.split("."))


def dn_parts(dn: str) -> tuple[str, ...] | None:
    """The RDNs of a distinguished name, normalised for comparison (trimmed, case-folded).

    Splits on commas that are not escaped with a backslash. None for an empty or malformed DN.
    """
    parts, current, escaped = [], [], False
    for ch in dn:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            current.append(ch)
            escaped = True
        elif ch == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if escaped:
        return None
    parts.append("".join(current))
    normalised = []
    for part in parts:
        name, sep, value = part.partition("=")
        if not sep or not name.strip() or not value.strip():
            return None
        normalised.append(f"{name.strip().casefold()}={value.strip().casefold()}")
    return tuple(normalised)


@dataclass(frozen=True)
class QuarantineOus:
    """Domain DNS name -> the OU distinguished name a quarantined group of that domain is in."""

    environment: str  # the store environment this configuration is for (SYNTHETIC, DEVELOPMENT, PRODUCTION)
    ous: tuple[tuple[str, str], ...]  # (domain, OU distinguished name), sorted by domain

    def __post_init__(self) -> None:
        if self.environment not in ("SYNTHETIC", "DEVELOPMENT", "PRODUCTION"):
            raise InvalidRecord("environment must be SYNTHETIC, DEVELOPMENT, or PRODUCTION")
        if not isinstance(self.ous, tuple) or not self.ous:
            raise InvalidRecord("at least one domain must have a quarantine OU")
        domains = [d for d, _ in self.ous]
        if len(set(domains)) != len(domains) or domains != sorted(domains):
            raise InvalidRecord("each domain appears once, in sorted order")
        for domain, ou in self.ous:
            if not isinstance(domain, str) or not _DNS_RE.match(domain):
                raise InvalidRecord("quarantine OU keys must be lowercase DNS domain names")
            if not isinstance(ou, str) or not 0 < len(ou) <= MAX_OU_LENGTH or _UNSAFE.search(ou):
                raise InvalidRecord(f"the quarantine OU for {domain} must be an explicit distinguished name")
            parts = dn_parts(ou)
            suffix = dn_parts(domain_dn(domain))
            if parts is None or not parts[0].startswith("ou=") or len(parts) <= len(suffix) \
                    or parts[-len(suffix):] != suffix:
                raise InvalidRecord(f"the quarantine OU for {domain} must be an OU inside that domain")

    def ou_for(self, domain: str) -> str | None:
        return dict(self.ous).get(domain.lower())

    def in_quarantine(self, group: ADGroup) -> bool | None:
        """Whether the group is a direct child of its domain's quarantine OU.

        None when that cannot be told: no OU is configured for the domain, the group was not
        found, or its distinguished name is missing or malformed.
        """
        ou = self.ou_for(group.domain)
        if ou is None or not group.exists or not group.distinguished_name:
            return None
        parts = dn_parts(group.distinguished_name)
        if parts is None or len(parts) < 2:
            return None
        return parts[1:] == dn_parts(ou)


def quarantine_location_problems(group: ADGroup | None, ous: "QuarantineOus | None", *, quarantined: bool) -> list[str]:
    """Why the mapped AD group is not where this step needs it: outside its quarantine OU
    before the quarantine, inside it afterwards. Unknown is a problem either way."""
    if group is None:
        return []  # reported by the mapping and existence checks
    if ous is None:
        return ["no quarantine OU configuration is loaded, so the group's quarantine cannot be determined (D136)"]
    if ous.ou_for(group.domain) is None:
        return [f"no quarantine OU is configured for {group.domain} (D136)"]
    where = ous.in_quarantine(group)
    if where is None:
        return ["the AD group's location cannot be determined (no distinguished name was observed)"]
    if quarantined and not where:
        return ["the AD group is not in its domain's quarantine OU; the post-quarantine stages need it there, and "
                "there is no restore path (D144, D149)"]
    if not quarantined and where:
        return ["the AD group is already in its quarantine OU, although OGWA recorded no quarantine; resolve this "
                "outside OGWA before going further"]
    return []
