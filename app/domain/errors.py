"""Domain error types."""

from app.core.errors import OgwaSafetyError


class DomainError(OgwaSafetyError):
    """Base class for domain-rule failures."""


class InvalidRecord(DomainError, ValueError):
    """A domain record violates one of its invariants and must not exist."""


class TransitionRefused(DomainError):
    """A lifecycle transition was requested but its preconditions are not met."""

    def __init__(self, source: str, target: str, problems: list[str] | tuple[str, ...]) -> None:
        self.source = source
        self.target = target
        self.problems = tuple(problems)
        detail = "; ".join(self.problems) or "no reason given"
        super().__init__(f"Transition {source} -> {target} refused: {detail}")
