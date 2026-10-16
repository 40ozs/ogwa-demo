"""Who did something: a named human operator or an OGWA system component."""

from dataclasses import dataclass
from enum import StrEnum

from app.domain.ids import check_enum, check_text


class ActorKind(StrEnum):
    HUMAN = "HUMAN"  # an authenticated operator; the id is their stable subject identifier
    SYSTEM = "SYSTEM"  # an OGWA component, e.g. "collector/okta-usage"


@dataclass(frozen=True)
class Actor:
    kind: ActorKind
    id: str

    def __post_init__(self) -> None:
        check_enum(self.kind, ActorKind, "actor kind")
        check_text(self.id, "actor id", max_length=200)

    def __str__(self) -> str:
        return f"{self.kind.value.lower()}:{self.id}"
