"""The canonical Null Meridian company profile: one fictional company, fixed in code.

Everything in the Null Meridian dataset is derived from the constants here and the seed
``null-meridian-v1``. Nothing is read from a tenant, a forest, or any other system. The
domain ``nullmeridian.info`` is the fictional company's own name; OGWA never resolves it,
sends mail to it, or contacts anything under it.
"""

from dataclasses import dataclass
from datetime import date, datetime, timezone

DATASET_KEY = "null-meridian"
SEED = "null-meridian-v1"
COMPANY = "Null Meridian"
PRIMARY_DOMAIN = "nullmeridian.info"
FOUNDED = date(2016, 10, 1)
OKTA_ADOPTED = date(2021, 10, 1)
MODERN_NAMING_ADOPTED = date(2023, 10, 1)
SNAPSHOT_DATE = date(2026, 10, 1)
# The dataset's "now": evidence and lifecycle history are dated relative to it.
AS_OF = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
ACTIVE_EMPLOYEES = 1800
TECH_DEBT = "moderate"

# The fictional company's AD forest: one domain, under the company's own fictional name.
AD_DNS_DOMAIN = "corp.nullmeridian.info"
AD_NETBIOS = "NMCORP"
AD_DOMAIN_SID = "S-1-5-21-3100000001-3100000002-3100000003"
# Okta-shaped identifiers carry "SYNTH" so they can never be mistaken for a real tenant's.
OKTA_AD_SOURCE_ID = "0oaSYNTHNMADDIR"
OKTA_APP_PREFIX = "0oaSYNTHNM"
OKTA_GROUP_PREFIX = "00gSYNTHNM"
OKTA_EVERYONE_ID = "00gSYNTHNMEVERYONE"
# The date the reviewed correlation configuration was last updated. Groups created after it
# are not in config/correlation.null-meridian.json yet.
CORRELATION_CONFIG_REVIEWED = date(2026, 7, 1)


@dataclass(frozen=True)
class NamingEra:
    key: str
    label: str
    start: date
    end: date  # exclusive
    description: str


NAMING_ERAS: tuple[NamingEra, ...] = (
    NamingEra("legacy-ad", "Legacy AD and share conventions", date(2016, 10, 1), date(2019, 7, 1),
              "GG_* global groups, <Dept>-RW / <Dept>_Read share groups, Share_<Dept>_Modify, <App>-Users"),
    NamingEra("app-specific", "Inconsistent application-specific conventions", date(2019, 7, 1), date(2021, 10, 1),
              "APP-<App>-Users, <App>_Dev, NM-<APP>-USERS, <App>-<Dept>, FS-<Dept>-R, Dept-<Dept>"),
    NamingEra("transitional-okta", "Transitional Okta conventions", date(2021, 10, 1), date(2023, 10, 1),
              "Okta_<App>_Users, OKTA-<App>-Admins, okta-<app>-<tier>s, okta-dept-<dept>"),
    NamingEra("modern", "sg-okta-* / sg-share-* standard", date(2023, 10, 1), date(2026, 10, 2),
              "sg-okta-<application>-<tier>, sg-share-<department>-read-only|write"),
)

MILESTONES: tuple[tuple[str, str], ...] = (
    ("2016-10-01", "Null Meridian founded"),
    ("2018-01-01", "Rapid SaaS and file-share growth begins (2018-2020)"),
    ("2021-10-01", "Okta introduced; AD groups imported, applications migrated in waves"),
    ("2021-10-01", "Migration and hybrid access period begins (2021-2023)"),
    ("2023-10-01", "sg-okta-* / sg-share-* naming standard introduced"),
    ("2024-01-01", "Continued cleanup; legacy structures only partly retired (2024-2026)"),
    ("2026-10-01", "Demo snapshot"),
)

# Okta rollout waves (2021-10 .. 2022-02): when each department's people were activated.
OKTA_WAVES: dict[str, date] = {
    "it": date(2021, 10, 1), "security": date(2021, 10, 1), "engineering": date(2021, 10, 18),
    "product": date(2021, 11, 8), "design": date(2021, 11, 8), "data": date(2021, 11, 8),
    "executive": date(2021, 11, 29), "finance": date(2021, 11, 29), "legal": date(2021, 11, 29),
    "people": date(2021, 11, 29), "sales": date(2022, 1, 10), "marketing": date(2022, 1, 10),
    "customer-success": date(2022, 2, 7), "operations": date(2022, 2, 7),
}


def era_for(day: date) -> NamingEra:
    for era in NAMING_ERAS:
        if era.start <= day < era.end:
            return era
    raise ValueError(f"{day} is outside Null Meridian's history")
