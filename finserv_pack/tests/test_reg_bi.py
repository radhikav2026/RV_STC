"""Tests for Reg BI suitability validator."""

import pytest

from finserv_pack.base import TraceContext
from finserv_pack.guardrails.reg_bi import (
    CustomerProfile,
    RegBIValidator,
    SuitabilityResult,
)


@pytest.fixture
def conservative_senior():
    return CustomerProfile(
        customer_id="C-001",
        risk_tolerance="conservative",
        age_bracket="senior",
        accredited=False,
    )


@pytest.fixture
def aggressive_investor():
    return CustomerProfile(
        customer_id="C-002",
        risk_tolerance="aggressive",
        accredited=True,
    )


class TestRegBICheck:
    async def test_high_risk_to_conservative_is_unsuitable(self, conservative_senior):
        v = RegBIValidator()
        result = await v.check(
            content="Consider investing in crypto derivatives for better returns.",
            customer=conservative_senior,
        )
        assert result.result == SuitabilityResult.UNSUITABLE
        assert "conservative" in result.reasons[0]
        assert result.risk_level_detected == "high"

    async def test_low_risk_to_aggressive_needs_review(self, aggressive_investor):
        v = RegBIValidator()
        result = await v.check(
            content="A treasury bond ladder would be very safe.",
            customer=aggressive_investor,
        )
        assert result.result == SuitabilityResult.NEEDS_REVIEW
        assert "aggressive" in result.reasons[0]

    async def test_moderate_to_moderate_is_suitable(self):
        v = RegBIValidator()
        customer = CustomerProfile(customer_id="C-003", risk_tolerance="moderate")
        result = await v.check(
            content="A diversified portfolio of stocks and bonds.",
            customer=customer,
        )
        assert result.result == SuitabilityResult.SUITABLE
        assert result.reasons == []

    async def test_enforce_raises_on_unsuitable(self, conservative_senior):
        from finserv_pack.base import SuitabilityViolation

        v = RegBIValidator(enforce=True)
        with pytest.raises(SuitabilityViolation):
            await v.check(
                content="Buy leveraged ETF positions immediately.",
                customer=conservative_senior,
            )

    async def test_high_risk_senior_non_accredited_needs_review(self):
        customer = CustomerProfile(
            customer_id="C-004",
            risk_tolerance="moderate",
            age_bracket="senior",
            accredited=False,
        )
        v = RegBIValidator()
        result = await v.check(
            content="Futures contracts can provide good hedging opportunities.",
            customer=customer,
        )
        assert result.result == SuitabilityResult.NEEDS_REVIEW


class TestRegBIEvaluate:
    async def test_evaluate_with_customer_in_metadata(self):
        v = RegBIValidator()
        ctx = TraceContext(
            query="What should I invest in?",
            response="You should buy crypto options.",
            metadata={
                "customer": {
                    "customer_id": "C-010",
                    "risk_tolerance": "conservative",
                }
            },
        )
        result = await v.evaluate(ctx)
        assert not result.passed
        assert result.action == "block"
        assert result.evidence["suitability_result"] == "unsuitable"

    async def test_evaluate_without_customer_skips(self):
        v = RegBIValidator()
        ctx = TraceContext(
            query="General question",
            response="General answer about markets.",
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert "No customer profile" in result.details

    async def test_evaluate_suitable_passes(self):
        v = RegBIValidator()
        ctx = TraceContext(
            query="What's a good investment?",
            response="Index funds offer broad market exposure.",
            metadata={
                "customer": {
                    "customer_id": "C-011",
                    "risk_tolerance": "moderate",
                }
            },
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert result.action == "pass"
