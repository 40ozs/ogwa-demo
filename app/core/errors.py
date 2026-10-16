"""Exception types for OGWA's safety guardrails."""


class OgwaSafetyError(Exception):
    """Base class for errors raised by a guardrail refusing to proceed."""


class ConfigError(OgwaSafetyError):
    """Configuration is invalid or unsafe. Startup must not continue."""


class ProductionMutationNotPermitted(ConfigError):
    """PRODUCTION_MUTATION was requested but this build does not permit it."""


class MutationBlockedError(OgwaSafetyError):
    """A state-changing operation was refused by the active mutation policy."""


class NetworkPolicyError(OgwaSafetyError):
    """An outbound request violated the network policy (host, scheme, or mode)."""
