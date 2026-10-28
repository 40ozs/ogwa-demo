"""Read-only Okta integration. See docs/architecture/okta-integration.md.

Public surface:

- ``OktaReadOnlyClient``: GET-only management API client (apps, assignments, groups,
  members, System Log), with budget, pacing, and completeness reporting;
- ``collect_application_usage``: bounded-window usage aggregation;
- ``evidence``: conversion to domain evidence and collector-run outcomes;
- ``auth``: scope-checked access-token grants. No token exchange in this build.
"""

from app.integrations.okta.auth import AccessTokenGrant, OktaCredentialError, StaticGrantProvider
from app.integrations.okta.client import COLLECTOR_VERSION, OktaReadOnlyClient, ProbeResult
from app.integrations.okta.models import Listing, Lookup
from app.integrations.okta.pacing import PacingPolicy
from app.integrations.okta.usage import UsageStrategy, collect_application_usage

__all__ = [
    "COLLECTOR_VERSION",
    "AccessTokenGrant",
    "Listing",
    "Lookup",
    "OktaCredentialError",
    "OktaReadOnlyClient",
    "PacingPolicy",
    "ProbeResult",
    "StaticGrantProvider",
    "UsageStrategy",
    "collect_application_usage",
]
