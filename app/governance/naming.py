"""The group naming standard (introduced 2023-10-01) and recognition of the conventions before it.

Standard grammar::

    sg-okta-<application>-<tier>          tier: user, standard, power, developer, approver,
                                                admin, readonly, billing
    sg-share-<department>-<access>        access: read-only, write

``<application>`` and ``<department>`` are normalized slugs: lowercase letters and digits in
hyphen-separated words. A name is standard only if it parses and its slug names a known
application or department; the caller supplies those.

The standard's prefix is the organization's: ``sg`` for Null Meridian (the default), ``sec`` for
Genesee Press, whose shared synthetic world renamed every ``sg-*`` group to ``sec-*``
(synthetic-enterprise ADR-0010). ``check_name(..., prefix="sec")`` applies the same grammar.
"""

import re
from dataclasses import dataclass

TIERS = ("user", "standard", "power", "developer", "approver", "admin", "readonly", "billing")
SHARE_ACCESS = ("read-only", "write")
SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"


def _modern_app_re(prefix: str) -> re.Pattern:
    return re.compile(rf"^{prefix}-okta-(?P<slug>{SLUG})-(?P<tier>{'|'.join(TIERS)})$")


def _modern_share_re(prefix: str) -> re.Pattern:
    return re.compile(rf"^{prefix}-share-(?P<slug>{SLUG})-(?P<access>{'|'.join(SHARE_ACCESS)})$")


MODERN_APP_RE = _modern_app_re("sg")
MODERN_SHARE_RE = _modern_share_re("sg")
_GRAMMAR = {"sg": (MODERN_APP_RE, MODERN_SHARE_RE), "sec": (_modern_app_re("sec"), _modern_share_re("sec"))}
SLUG_RE = re.compile(rf"^{SLUG}$")

# Recognizable historical conventions, most specific first: (label, pattern).
LEGACY_STYLES: tuple[tuple[str, re.Pattern], ...] = (
    ("GG_App_<App>[_<Tier>]", re.compile(r"^GG_App_[A-Za-z0-9]+(_[A-Za-z]+)?$")),
    ("GG_Dept_<Dept>", re.compile(r"^GG_Dept_[A-Za-z]+$")),
    ("GG_<Area>_<Access>", re.compile(r"^GG_[A-Za-z]+_[A-Za-z]+$")),
    ("GG_<Name>", re.compile(r"^GG_[A-Za-z]+$")),
    ("APP-<App>-<Tier>", re.compile(r"^APP-[A-Za-z0-9]+-[A-Za-z]+$")),
    ("NM-<APP>-<TIER>", re.compile(r"^NM-[A-Z0-9]+-[A-Z]+$")),
    ("GP-<APP>-<TIER>", re.compile(r"^GP-[A-Z0-9]+-[A-Z]+$")),
    ("Okta_<App>_<Tier>", re.compile(r"^Okta_[A-Za-z0-9]+_[A-Za-z]+$")),
    ("OKTA-<App>-<Tier>", re.compile(r"^OKTA-[A-Za-z0-9]+-[A-Za-z]+$")),
    ("okta-<app>-<tier>s", re.compile(r"^okta-[a-z0-9-]+$")),
    ("FS-<Dept>-<R|RW>", re.compile(r"^FS-[A-Za-z]+-(R|RW)$")),
    ("Share_<Dept>_<Access>", re.compile(r"^Share_[A-Za-z]+_[A-Za-z]+$")),
    ("<Dept>-RW / <Dept>_Read", re.compile(r"^[A-Za-z]+(-RW|_Read)$")),
    ("Dept-<Dept>", re.compile(r"^Dept-[A-Za-z]+$")),
    ("Role_<Role>", re.compile(r"^Role_[A-Za-z]+$")),
    ("eng-<team>", re.compile(r"^eng-[a-z0-9-]+$")),
    # The shared world's prefix for groups derived from DG-* groups (synthetic-enterprise ADR-0010).
    ("di-<name>", re.compile(r"^di-[a-z0-9-]+$")),
    ("<Dept>-<Team>[-Team]", re.compile(r"^[A-Z][A-Za-z]*-[A-Z][A-Za-z0-9]*(-Team)?$")),
    ("<App>_<Tier>", re.compile(r"^[A-Z][A-Za-z0-9]*_[A-Za-z]+$")),
    ("<Name>-<Name>", re.compile(r"^[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$")),
)


@dataclass(frozen=True)
class NameCheck:
    standard: str | None  # "<prefix>-okta", "<prefix>-share", or None
    slug: str | None
    qualifier: str | None  # tier or access
    conforms: bool  # parses AND names a known application or department
    style: str  # the convention the name follows
    problem: str | None


def check_name(name: str, *, applications: frozenset[str], departments: frozenset[str], prefix: str = "sg") -> NameCheck:
    app_re, share_re = _GRAMMAR[prefix]
    m = app_re.match(name)
    if m:
        known = m["slug"] in applications
        return NameCheck(f"{prefix}-okta", m["slug"], m["tier"], known, f"{prefix}-okta-<application>-<tier>",
                         None if known else f"unknown application slug {m['slug']!r}")
    m = share_re.match(name)
    if m:
        known = m["slug"] in departments
        return NameCheck(f"{prefix}-share", m["slug"], m["access"], known, f"{prefix}-share-<department>-<access>",
                         None if known else f"unknown department slug {m['slug']!r}")
    if name.lower().startswith((f"{prefix}-okta-", f"{prefix}-share-")):
        problem = "not in canonical lower case" if app_re.match(name.lower()) or share_re.match(
            name.lower()) else f"does not follow the {prefix}-okta / {prefix}-share grammar"
        return NameCheck(None, None, None, False, f"malformed {prefix}-*", problem)
    return NameCheck(None, None, None, False, legacy_style(name), "pre-standard naming")


def legacy_style(name: str) -> str:
    for label, pattern in LEGACY_STYLES:
        if pattern.match(name):
            return label
    return "other"
