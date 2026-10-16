"""Store error types."""

from app.core.errors import OgwaSafetyError


class StoreError(OgwaSafetyError):
    """The store refused an operation."""


class StoreConflict(StoreError):
    """The write conflicts with what is already recorded (duplicate, mismatch, or race)."""


class StoreIntegrityError(StoreError):
    """Stored data failed verification: tampering, corruption, or a bypassed write path."""


class EnvironmentRefused(StoreError):
    """The database's environment marker does not permit this operation or mode."""


class MigrationError(StoreError):
    """The schema cannot be migrated safely."""
