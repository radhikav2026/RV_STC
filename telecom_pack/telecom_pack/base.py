"""Generic base types for the Telecom Pack.

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
class TelecomTraceContext:
    """The data a telecom validator needs to evaluate.

    Map your platform's trace format into this structure via an adapter.
    """

    # Required: the user's input and the model's output
    query: str
    response: str

    # Optional: retrieved context (RAG chunks, knowledge base, etc.)
    context: str = ""
    source_chunks: list[dict[str, Any]] = field(default_factory=list)

    # Subscriber / account metadata
    subscriber_id: str = ""
    account_type: str = ""  # consumer | enterprise | government
    service_type: str = ""  # wireless | fios | broadband | business
    interaction_channel: str = ""  # chat | voice | ivr | app | web

    # CPNI-sensitive fields
    cpni_present: bool = False
    authenticated: bool = False
    authentication_method: str = ""  # pin | password | biometric | none

    # Network context
    network_segment: str = ""  # private_5g | mpls | sd_wan | public
    cell_id: str = ""

    # Regulatory context
    jurisdiction: str = ""  # US state or country code — regulation varies
    call_reason: str = ""  # billing | technical | retention | sales | emergency

    # Enterprise managed-service context
    enterprise_customer: str = ""
    enterprise_industry: str = ""  # financial_services | healthcare | defense

    # General metadata
    trace_id: str = ""
    tenant_id: str = ""
    model_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailResult:
    """The output of a guardrail evaluation."""

    rule_name: str
    passed: bool
    severity: str = "low"  # critical | high | medium | low
    action: str = "pass"  # pass | warn | block | escalate
    details: str = ""
    regulation: str = ""  # e.g. "47 USC 222", "TCPA", "FCC 255"
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_now)


@runtime_checkable
class Validator(Protocol):
    """Protocol implemented by every guardrail in the pack."""

    rule_name: str
    severity: str

    async def evaluate(self, ctx: TelecomTraceContext) -> GuardrailResult: ...


# --- Errors ---


class TelecomComplianceError(Exception):
    """Base error for Telecom Pack violations."""

    def __init__(self, message: str, *, rule: str = "", evidence: dict[str, Any] | None = None):
        self.rule = rule
        self.evidence = evidence or {}
        super().__init__(message)


class CPNIViolation(TelecomComplianceError):
    """Customer Proprietary Network Information leakage detected."""


class TCPAViolation(TelecomComplianceError):
    """Telephone Consumer Protection Act violation detected."""


class SlamCramViolation(TelecomComplianceError):
    """Unauthorized service change (slamming) or charge (cramming) detected."""
