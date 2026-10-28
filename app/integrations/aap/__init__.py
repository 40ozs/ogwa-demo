"""Read-only AAP discovery (P10). See ``client.py`` and docs/architecture/remediation.md."""

from app.integrations.aap.client import (
    AapDiscoveryError,
    AapIdentity,
    AapIdentityRefused,
    AapReadOnlyClient,
    DiscoveryReport,
)

__all__ = ["AapDiscoveryError", "AapIdentity", "AapIdentityRefused", "AapReadOnlyClient", "DiscoveryReport"]
