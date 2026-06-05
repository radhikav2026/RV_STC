"""Generic base types for the FinServ Pack.

These types define the interface that any host platform must implement.
They have ZERO dependency on stc_framework — the pack is self-contained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceContext:
    """The data a validator needs to evaluate.

    Map your platform's trace format into this structure via an adapter.
    """

    # Required: the user's input and the model's output
    query: str
    response: str

    # Optional: retrieved context (RAG chunks, tool outputs, etc.)
    context: str = ""
    source_chunks: list[dict[str, Any]] = field(default_factory=list)

    # Optional: metadata about the request
    trace_id: str = ""
    tenant_id: str = ""
    model_id: str = ""
    data_tier: str = "public"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailResult:
    """The output of a guardrail evaluation."""

    rule_name: str
    passed: bool
    severity: str = "low"  # critical | high | medium | low
    action: str = "pass"  # pass | warn | block | escalate
    details: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_now)


@runtime_checkable
class Validator(Protocol):
    """Protocol implemented by every guardrail in the pack.

    To integrate: implement an adapter that converts your trace format
    to TraceContext, then call validator.evaluate(ctx).
    """

    rule_name: str
    severity: str

    async def evaluate(self, ctx: TraceContext) -> GuardrailResult: ...


# --- Errors ---


class FinServError(Exception):
    """Base error for FinServ Pack violations."""

    def __init__(self, message: str, *, rule: str = "", evidence: dict[str, Any] | None = None):
        self.rule = rule
        self.evidence = evidence or {}
        super().__init__(message)


class SuitabilityViolation(FinServError):
    """Reg BI suitability check failed."""


class NumericalAccuracyViolation(FinServError):
    """Ungrounded numbers detected in AI output."""


class BiasViolation(FinServError):
    """Adverse impact detected (4/5ths rule)."""


class DataSovereigntyViolation(FinServError):
    """Blocked PII/NPI entity detected."""
