"""The group naming standard (introduced 2023-10-01) and recognition of the conventions before it.

Standard grammar::

    sg-okta-<application>-<tier>          tier: user, standard, power, developer, approver,
                                                admin, readonly, billing
    sg-share-<department>-<access>        access: read-only, write

``<application>`` and ``<department>`` are normalized slugs: lowercase letters and digits in
hyphen-separated words. A name is standard only if it parses and its slug names a known
application or department; the caller supplies those.
"""

import re
from dataclasses import dataclass

TIERS = ("user", "standard", "power", "developer", "approver", "admin", "readonly", "billing")
SHARE_ACCESS = ("read-only", "write")
SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
MODERN_APP_RE = re.compile(rf"^sg-okta-(?P<slug>{SLUG})-(?P<tier>{'|'.join(TIERS)})$")
MODERN_SHARE_RE = re.compile(rf"^sg-share-(?P<slug>{SLUG})-(?P<access>{'|'.join(SHARE_ACCESS)})$")
SLUG_RE = re.compile(rf"^{SLUG}$")

# Recognizable historical conventions, most specific first: (label, pattern).
LEGACY_STYLES: tuple[tuple[str, re.Pattern], ...] = (
    ("GG_App_<App>[_<Tier>]", re.compile(r"^GG_App_[A-Za-z0-9]+(_[A-Za-z]+)?$")),
    ("GG_Dept_<Dept>", re.compile(r"^GG_Dept_[A-Za-z]+$")),
    ("GG_<Area>_<Access>", re.compile(r"^GG_[A-Za-z]+_[A-Za-z]+$")),
    ("GG_<Name>", re.compile(r"^GG_[A-Za-z]+$")),
    ("APP-<App>-<Tier>", re.compile(r"^APP-[A-Za-z0-9]+-[A-Za-z]+$")),
    ("NM-<APP>-<TIER>", re.compile(r"^NM-[A-Z0-9]+-[A-Z]+$")),
    ("Okta_<App>_<Tier>", re.compile(r"^Okta_[A-Za-z0-9]+_[A-Za-z]+$")),
    ("OKTA-<App>-<Tier>", re.compile(r"^OKTA-[A-Za-z0-9]+-[A-Za-z]+$")),
    ("okta-<app>-<tier>s", re.compile(r"^okta-[a-z0-9-]+$")),
    ("FS-<Dept>-<R|RW>", re.compile(r"^FS-[A-Za-z]+-(R|RW)$")),
    ("Share_<Dept>_<Access>", re.compile(r"^Share_[A-Za-z]+_[A-Za-z]+$")),
    ("<Dept>-RW / <Dept>_Read", re.compile(r"^[A-Za-z]+(-RW|_Read)$")),
    ("Dept-<Dept>", re.compile(r"^Dept-[A-Za-z]+$")),
    ("Role_<Role>", re.compile(r"^Role_[A-Za-z]+$")),
    ("eng-<team>", re.compile(r"^eng-[a-z0-9-]+$")),
    ("<Dept>-<Team>[-Team]", re.compile(r"^[A-Z][A-Za-z]*-[A-Z][A-Za-z0-9]*(-Team)?$")),
    ("<App>_<Tier>", re.compile(r"^[A-Z][A-Za-z0-9]*_[A-Za-z]+$")),
    ("<Name>-<Name>", re.compile(r"^[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$")),
)


@dataclass(frozen=True)
class NameCheck:
    standard: str | None  # "sg-okta", "sg-share", or None
    slug: str | None
    qualifier: str | None  # tier or access
    conforms: bool  # parses AND names a known application or department
    style: str  # the convention the name follows
    problem: str | None


def check_name(name: str, *, applications: frozenset[str], departments: frozenset[str]) -> NameCheck:
    m = MODERN_APP_RE.match(name)
    if m:
        known = m["slug"] in applications
        return NameCheck("sg-okta", m["slug"], m["tier"], known, "sg-okta-<application>-<tier>",
                         None if known else f"unknown application slug {m['slug']!r}")
    m = MODERN_SHARE_RE.match(name)
    if m:
        known = m["slug"] in departments
        return NameCheck("sg-share", m["slug"], m["access"], known, "sg-share-<department>-<access>",
                         None if known else f"unknown department slug {m['slug']!r}")
    if name.lower().startswith(("sg-okta-", "sg-share-")):
        problem = "not in canonical lower case" if MODERN_APP_RE.match(name.lower()) or MODERN_SHARE_RE.match(
            name.lower()) else "does not follow the sg-okta / sg-share grammar"
        return NameCheck(None, None, None, False, "malformed sg-*", problem)
    return NameCheck(None, None, None, False, legacy_style(name), "pre-standard naming")


def legacy_style(name: str) -> str:
    for label, pattern in LEGACY_STYLES:
        if pattern.match(name):
            return label
    return "other"
