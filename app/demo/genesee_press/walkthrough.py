"""The reviewer walkthrough of the Genesee Press demo: the Null Meridian walkthrough's two parts on
GP-C10 and GP-C11, worded for Genesee Press (``profile.localize``). Text and candidate keys only."""

from typing import Any

from app.demo.genesee_press.profile import localize
from app.demo.null_meridian import walkthrough as nm


def _local(value: Any) -> Any:
    if isinstance(value, str):
        return localize(value)
    if isinstance(value, dict):
        return {k: _local(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_local(v) for v in value)
    return value


def walkthrough(public: bool = False) -> dict[str, Any]:
    return _local(nm.walkthrough(public))


__all__ = ["walkthrough"]
