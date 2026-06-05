"""Generic dataclass ↔ dict helpers.

Replaces the per-module ``_to_dict`` / ``_from_dict`` pairs found in
legal_hold, nydfs_notification, risk register, lineage, and similar
modules with a single reusable pair.  The helpers handle:

* ``Enum`` members → ``.value``
* Nested ``dataclass`` instances (recursively)
* ``dict`` / ``list`` containers
* ``None`` passthrough

These functions intentionally avoid ``dataclasses.asdict`` because
that recurses into *all* fields including Pydantic models and custom
containers, which can fail or produce unwanted output.  The logic
here mirrors the hand-rolled versions it replaces.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any


def dataclass_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a dataclass instance to a plain dict, recursively.

    * ``Enum`` values are replaced with ``.value``.
    * Nested dataclass instances are recursed into.
    * ``list`` and ``dict`` containers are recursed element-wise.
    * Everything else is returned as-is.
    """
    if not dataclasses.is_dataclass(obj) or isinstance(obj, type):
        raise TypeError(f"expected a dataclass instance, got {type(obj).__name__}")
    return {k: _convert(v) for k, v in vars(obj).items()}


def _convert(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _convert(v) for k, v in vars(value).items()}
    if isinstance(value, dict):
        return {k: _convert(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_convert(v) for v in value]
    return value


__all__ = ["dataclass_to_dict"]
