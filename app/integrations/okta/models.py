"""Normalized Okta records and result containers.

Raw Okta payloads stay inside ``app.integrations.okta``. Callers see only these
records, which carry the fields lifecycle and correlation need and nothing else. In
particular, there are no user profiles, emails, or logins: group members are reduced to
user id and status, and usage keeps only counts.

Every listing reports completeness. ``status`` is COMPLETE only when every page was
read and every record parsed. A listing that stopped early is PARTIAL (items so far) or
FAILED (no usable items), with the reason.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Generic, TypeVar

from app.domain.collection import CollectorErrorCode
from app.domain.evidence import ResultStatus

T = TypeVar("T")


class AppStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class GroupType(StrEnum):
    OKTA_GROUP = "OKTA_GROUP"
    APP_GROUP = "APP_GROUP"
    BUILT_IN = "BUILT_IN"


@dataclass(frozen=True)
class OktaAppRecord:
    okta_app_id: str
    status: AppStatus
    label: str | None
    name: str | None  # Okta's integration key, e.g. "salesforce"; not the display label
    sign_on_mode: str | None
    created: datetime | None
    last_updated: datetime | None


@dataclass(frozen=True)
class OktaGroupRecord:
    okta_group_id: str
    name: str
    group_type: GroupType
    last_updated: datetime | None
    last_membership_updated: datetime | None
    # APP_GROUP only: the Okta app instance (for example the AD integration) that sources it.
    source_app_id: str | None = None
    # Directory attributes as imported by the Okta AD agent. Raw values are kept so that
    # correlation decides what they mean; nothing here is a match by itself.
    directory_external_id: str | None = None
    # Decoded from externalId under an UNVERIFIED byte-order assumption (D23, D30): not a
    # stable-id basis until P11 proves it against a known AD-backed Okta group.
    directory_object_guid_unverified: str | None = None
    directory_object_sid: str | None = None
    directory_qualified_name: str | None = None  # windowsDomainQualifiedName, e.g. DOMAIN\name
    distinguished_name: str | None = None
    sam_account_name: str | None = None


@dataclass(frozen=True)
class OktaAppGroupAssignmentRecord:
    okta_app_id: str
    okta_group_id: str
    priority: int | None
    last_updated: datetime | None
    group: OktaGroupRecord | None = None  # present only when the listing embedded the group


@dataclass(frozen=True)
class OktaGroupMemberRecord:
    okta_user_id: str
    status: str | None


class StopReason(StrEnum):
    """Why a listing did not finish. Finer-grained than CollectorErrorCode."""

    AUTHENTICATION = "AUTHENTICATION"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    HTTP_ERROR = "HTTP_ERROR"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    MALFORMED_PAGE = "MALFORMED_PAGE"
    UNSAFE_NEXT_LINK = "UNSAFE_NEXT_LINK"
    PAGE_LIMIT = "PAGE_LIMIT"
    ITEM_LIMIT = "ITEM_LIMIT"
    NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True)
class Listing(Generic[T]):
    """The result of one paged listing."""

    scope: str  # what was queried, e.g. "okta:app:<id>:groups"; no query values
    items: tuple[T, ...]  # empty when records were streamed to a sink instead of kept
    status: ResultStatus
    pages: int
    record_count: int = 0  # records accepted (kept or streamed)
    malformed_records: int = 0
    duplicates_dropped: int = 0
    stop_reason: StopReason | None = None
    error_code: CollectorErrorCode | None = None
    error_summary: str | None = None
    notes: tuple[str, ...] = field(default=())

    @property
    def complete(self) -> bool:
        return self.status is ResultStatus.COMPLETE


@dataclass(frozen=True)
class Lookup(Generic[T]):
    """The result of fetching one object. ``found=False`` with COMPLETE means a definite 404."""

    scope: str
    item: T | None
    found: bool
    status: ResultStatus
    error_code: CollectorErrorCode | None = None
    error_summary: str | None = None

    @property
    def complete(self) -> bool:
        return self.status is ResultStatus.COMPLETE
