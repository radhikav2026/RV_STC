"""Tests for Rate Plan Fairness Validator."""

from __future__ import annotations

import pytest
from telecom_pack.base import TelecomTraceContext
from telecom_pack.guardrails.rate_plan_fairness import RatePlanFairnessValidator


@pytest.fixture
def validator() -> RatePlanFairnessValidator:
    return RatePlanFairnessValidator()


def _ctx(response: str) -> TelecomTraceContext:
    return TelecomTraceContext(query="What plans do you have?", response=response)


async def test_clean_response(validator: RatePlanFairnessValidator) -> None:
    result = await validator.evaluate(_ctx("We have three plans. Please visit our website for full details."))
    assert result.passed is True


async def test_savings_without_fees_flagged(validator: RatePlanFairnessValidator) -> None:
    result = await validator.evaluate(
        _ctx("Switch to our new plan and save $30 per month! The Unlimited Plus plan is $50/mo.")
    )
    assert result.passed is False
    assert "savings_claims_without_fees" in result.evidence


async def test_savings_with_fees_is_ok(validator: RatePlanFairnessValidator) -> None:
    result = await validator.evaluate(
        _ctx(
            "Save $20/month with our Essential plan at $40/mo. "
            "Note: taxes and fees apply, and there is a $35 activation fee. "
            "The contract term is 24 months."
        )
    )
    assert result.passed is True


async def test_deceptive_comparison_flagged(validator: RatePlanFairnessValidator) -> None:
    result = await validator.evaluate(
        _ctx("This plan is better in every way than your current plan. No reason not to switch!")
    )
    assert result.passed is False
    assert "deceptive_comparison" in result.evidence
    assert result.severity == "high"


async def test_plan_without_terms_flagged(validator: RatePlanFairnessValidator) -> None:
    result = await validator.evaluate(_ctx("The Premium Unlimited plan is $75/mo with 100GB hotspot data."))
    assert result.passed is False
    assert "plan_without_terms" in result.evidence
