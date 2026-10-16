"""A wrapper that keeps credential values out of logs, reprs, and serialized output."""

import hmac

from app.core.redaction import REDACTED, register_secret


class Secret:
    """Holds a credential. Only ``reveal()`` returns the value.

    str/repr/format all render as a placeholder, and pickling or copying is refused so a
    secret cannot leak into caches, fixtures, or evidence files by accident.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ValueError("Secret value must be a non-empty string")
        self._value = value
        register_secret(value)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Secret('{REDACTED}')"

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, format_spec: str) -> str:
        return REDACTED

    def __reduce_ex__(self, protocol):
        raise TypeError("Secret values must not be serialized or copied")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    __hash__ = None  # type: ignore[assignment]
