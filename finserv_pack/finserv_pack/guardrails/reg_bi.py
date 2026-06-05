"""Reg BI — Regulation Best Interest suitability validator.

SEC 17 CFR 240.15l-1 requires broker-dealers recommending securities
to act in the retail customer's best interest. This validator evaluates
AI-generated advisory content against a customer profile and flags
unsuitable recommendations.

Extracted from: stc_framework/compliance/reg_bi.py (MIT license)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from finserv_pack.base import (
    FinServError,
    GuardrailResult,
    SuitabilityViolation,
    TraceContext,
)


class SuitabilityResult(str, Enum):
    SUITABLE = "suitable"
    UNSUITABLE = "unsuitable"
    NEEDS_REVIEW = "needs_review"
    NOT_APPLICABLE = "not_applicable"


# Risk-indicator keyword sets — product-class proxies.
_HIGH_RISK_INDICATORS = (
    "derivatives",
    "options",
    "leveraged etf",
    "futures",
    "margin account",
    "penny stock",
    "private placement",
    "crypto",
    "cryptocurrency",
    "structured product",
    "inverse etf",
    "cfd",
    "contract for difference",
)

_LOW_RISK_INDICATORS = (
    "treasury bond",
    "money market",
    "certificate of deposit",
    "municipal bond",
    "index fund",
    "savings account",
    "government bond",
    "investment grade bond",
)


@dataclass
class CustomerProfile:
    """Customer suitability profile — populate from your CRM/KYC system."""

    customer_id: str
    risk_tolerance: str = "moderate"  # conservative | moderate | aggressive
    investment_objectives: list[str] = field(default_factory=list)
    time_horizon: str = "long"  # short | medium | long
    age_bracket: str = "unknown"  # young | middle | senior | unknown
    accredited: bool = False
    annual_income_bracket: str = "unknown"  # low | medium | high | unknown
    net_worth_bracket: str = "unknown"


@dataclass
class SuitabilityCheckResult:
    customer_id: str
    result: SuitabilityResult
    reasons: list[str] = field(default_factory=list)
    risk_level_detected: str = "moderate"
    needs_disclosure: bool = False


class RegBIValidator:
    """Reg BI suitability guardrail.

    Evaluates whether AI-generated financial content is suitable for
    the target customer's risk profile.

    Usage:
        validator = RegBIValidator(enforce=True)
        result = await validator.evaluate(ctx)
        # Or with explicit customer profile:
        check = await validator.check(content="...", customer=CustomerProfile(...))
    """

    rule_name = "reg_bi_suitability"
    severity = "critical"

    def __init__(self, *, enforce: bool = False, on_violation: Any = None) -> None:
        self._enforce = enforce
        self._on_violation = on_violation

    def _detect_risk_level(self, content: str) -> str:
        lowered = content.lower()
        if any(ind in lowered for ind in _HIGH_RISK_INDICATORS):
            return "high"
        if any(ind in lowered for ind in _LOW_RISK_INDICATORS):
            return "low"
        return "moderate"

    async def check(
        self,
        *,
        content: str,
        customer: CustomerProfile,
    ) -> SuitabilityCheckResult:
        """Run suitability check against a specific customer profile."""
        risk_level = self._detect_risk_level(content)
        reasons: list[str] = []
        result = SuitabilityResult.SUITABLE

        if risk_level == "high" and customer.risk_tolerance == "conservative":
            reasons.append(
                "high-risk product recommended to conservative-risk-tolerance customer"
            )
            result = SuitabilityResult.UNSUITABLE
        elif risk_level == "high" and not customer.accredited and customer.age_bracket == "senior":
            reasons.append(
                "high-risk product recommended to non-accredited senior customer"
            )
            result = SuitabilityResult.NEEDS_REVIEW
        elif risk_level == "low" and customer.risk_tolerance == "aggressive":
            reasons.append(
                "low-risk product may not meet aggressive investor objectives"
            )
            result = SuitabilityResult.NEEDS_REVIEW

        check_result = SuitabilityCheckResult(
            customer_id=customer.customer_id,
            result=result,
            reasons=reasons,
            risk_level_detected=risk_level,
            needs_disclosure=result is not SuitabilityResult.SUITABLE,
        )

        if self._enforce and result is SuitabilityResult.UNSUITABLE:
            raise SuitabilityViolation(
                f"Reg BI: unsuitable for customer {customer.customer_id!r}",
                rule="reg_bi",
                evidence={"reasons": reasons, "risk_level": risk_level},
            )

        return check_result

    async def evaluate(self, ctx: TraceContext) -> GuardrailResult:
        """Evaluate via the generic Validator interface.

        Expects ctx.metadata["customer"] to be a CustomerProfile or dict
        with customer fields. If no customer context is available, returns
        NOT_APPLICABLE.
        """
        customer_data = ctx.metadata.get("customer")
        if customer_data is None:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity=self.severity,
                action="pass",
                details="No customer profile in context; skipping Reg BI check",
            )

        if isinstance(customer_data, dict):
            customer = CustomerProfile(**customer_data)
        elif isinstance(customer_data, CustomerProfile):
            customer = customer_data
        else:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity=self.severity,
                action="pass",
                details="Unrecognized customer profile format",
            )

        result = await self.check(content=ctx.response, customer=customer)

        passed = result.result in (SuitabilityResult.SUITABLE, SuitabilityResult.NOT_APPLICABLE)
        action = "pass" if passed else ("block" if result.result == SuitabilityResult.UNSUITABLE else "warn")

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=passed,
            severity=self.severity,
            action=action,
            details="; ".join(result.reasons) if result.reasons else "Suitable",
            evidence={
                "customer_id": result.customer_id,
                "suitability_result": result.result.value,
                "risk_level_detected": result.risk_level_detected,
                "needs_disclosure": result.needs_disclosure,
            },
        )
