"""Credentials for the read-only Okta client.

The intended production model (owner decision D6) is a dedicated OAuth 2.0 service
application that uses client credentials with ``private_key_jwt`` and is granted only
the read scopes below. **This build does not perform the token exchange.** That needs
a POST to the Okta token endpoint and RS256 signing. The read-only HTTP client cannot
send a POST (D8), and the standard library has no RSA signing (D5). Both need an owner
decision; see docs/architecture/okta-integration.md.

What exists here:

- ``AccessTokenGrant``: an access token plus the scopes and expiry the issuer reported;
- ``StaticGrantProvider``: holds one grant that an approved external mechanism produced;
- scope checks that refuse a credential broader than the read set, and refuse a call
  whose scope the grant lacks, both before any request is sent.

SSWS API tokens are deliberately unsupported (D6). ``OGWA_OKTA_API_TOKEN`` is not read
by this package.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from app.core.secret import Secret

SCOPE_APPS_READ = "okta.apps.read"
SCOPE_GROUPS_READ = "okta.groups.read"
SCOPE_LOGS_READ = "okta.logs.read"

# The complete set OGWA discovery may hold. A grant with any other scope is refused,
# so a credential that can also write (for example okta.apps.manage) is never used.
PERMITTED_SCOPES = frozenset({SCOPE_APPS_READ, SCOPE_GROUPS_READ, SCOPE_LOGS_READ})

# Refuse a token this close to expiry rather than have it expire mid-page.
EXPIRY_MARGIN = timedelta(seconds=60)


class OktaCredentialError(Exception):
    """The credential is missing, expired, too broad, or lacks a required scope."""


@dataclass(frozen=True)
class AccessTokenGrant:
    access_token: Secret = field(repr=False)
    scopes: frozenset[str]
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.access_token, Secret):
            raise TypeError("access_token must be a Secret")
        if not isinstance(self.scopes, frozenset) or not all(isinstance(s, str) and s for s in self.scopes):
            raise TypeError("scopes must be a frozenset of non-empty strings")
        if not isinstance(self.expires_at, datetime) or self.expires_at.utcoffset() is None:
            raise TypeError("expires_at must be a timezone-aware datetime")
        excess = sorted(self.scopes - PERMITTED_SCOPES)
        if excess:
            raise OktaCredentialError(
                f"credential carries scopes outside the read-only set ({', '.join(excess)}); "
                "OGWA discovery refuses credentials broader than it needs"
            )
        if not self.scopes:
            raise OktaCredentialError("credential carries no scopes")


class OktaCredentialProvider(Protocol):
    def current_grant(self, now: datetime) -> AccessTokenGrant: ...


class StaticGrantProvider:
    """One grant obtained by an approved mechanism outside OGWA. It is never refreshed."""

    def __init__(self, grant: AccessTokenGrant) -> None:
        if not isinstance(grant, AccessTokenGrant):
            raise TypeError("grant must be an AccessTokenGrant")
        self._grant = grant

    def current_grant(self, now: datetime) -> AccessTokenGrant:
        return self._grant

    def __repr__(self) -> str:
        return "StaticGrantProvider(<grant>)"


def authorization_header(provider: OktaCredentialProvider, required_scope: str, now: datetime) -> str:
    """The Authorization header value for a call needing ``required_scope``, or raise."""
    if required_scope not in PERMITTED_SCOPES:
        raise OktaCredentialError(f"{required_scope} is not a scope OGWA discovery may use")
    grant = provider.current_grant(now)
    if not isinstance(grant, AccessTokenGrant):
        raise OktaCredentialError("credential provider returned no grant")
    if grant.expires_at - EXPIRY_MARGIN <= now:
        raise OktaCredentialError("access token is expired or about to expire")
    if required_scope not in grant.scopes:
        raise OktaCredentialError(f"credential lacks the {required_scope} scope")
    return f"Bearer {grant.access_token.reveal()}"
