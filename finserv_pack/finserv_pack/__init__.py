"""FinServ Guardrails Pack — extracted from STC Framework.

A standalone, dependency-light package providing financial-services-specific
AI guardrails, PII redaction, and pen testing primitives. Designed to plug
into any agent observability platform via a generic interface.
"""

from finserv_pack.base import (
    GuardrailResult,
    TraceContext,
    Validator,
)

__all__ = [
    "GuardrailResult",
    "TraceContext",
    "Validator",
]
