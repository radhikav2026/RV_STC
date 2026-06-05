"""Telecom Guardrails Pack — telecommunications AI compliance.

A standalone, dependency-light package providing telecom-specific
AI guardrails, CPNI protection, TCPA compliance, and pen testing
primitives. Designed to plug into any agent observability platform
via a generic interface.
"""

from telecom_pack.base import (
    GuardrailResult,
    TelecomTraceContext,
    Validator,
)

__all__ = [
    "GuardrailResult",
    "TelecomTraceContext",
    "Validator",
]
