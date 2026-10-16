"""Keyed, version-independent determinism for the Null Meridian generator.

No ``random`` module and no iteration over unordered sets: every choice is a SHA-256 of
the seed and a label that names the decision, so one choice never shifts another and
the output is identical on every Python version and platform.
"""

import hashlib
import uuid
from collections.abc import Sequence
from typing import TypeVar

from app.demo.null_meridian.profile import SEED

T = TypeVar("T")

# Every stable identifier in the dataset is a UUIDv5 under this namespace.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:ogwa:synthetic:{SEED}")


def stable_uuid(*parts: object) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, "/".join(str(p) for p in parts))


def record_id(prefix: str, *parts: object) -> str:
    """An id in OGWA's internal shape (``<prefix>_<32 hex>``) whose hex is a UUIDv5."""
    return f"{prefix}_{stable_uuid(prefix, *parts).hex}"


def h(*parts: object) -> int:
    text = SEED + "|" + "|".join(str(p) for p in parts)
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")


def unit(*parts: object) -> float:
    """A number in [0, 1)."""
    return h(*parts) / 2 ** 64


def below(n: int, *parts: object) -> int:
    if n <= 0:
        raise ValueError("below() needs a positive bound")
    return h(*parts) % n


def pick(options: Sequence[T], *parts: object) -> T:
    return options[below(len(options), *parts)]


def weighted(options: Sequence[tuple[T, float]], *parts: object) -> T:
    total = sum(w for _, w in options)
    point = unit(*parts) * total
    for value, w in options:
        point -= w
        if point < 0:
            return value
    return options[-1][0]


def ordered(items: Sequence[T], key, *parts: object) -> list[T]:
    """A deterministic shuffle: ``key`` gives each item a stable label."""
    return sorted(items, key=lambda item: (h(*parts, key(item)), key(item)))


def allocate(total: int, weights: Sequence[float]) -> list[int]:
    """Split ``total`` in proportion to ``weights`` exactly (largest remainder, ties by index)."""
    s = sum(weights)
    if total == 0 or s <= 0:
        return [0] * len(weights)
    raw = [total * w / s for w in weights]
    counts = [int(r) for r in raw]
    order = sorted(range(len(weights)), key=lambda i: (-(raw[i] - counts[i]), i))
    for i in order[: total - sum(counts)]:
        counts[i] += 1
    return counts
