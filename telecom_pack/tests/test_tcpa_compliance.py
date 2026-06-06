"""Tests for TCPA Compliance Validator."""

from __future__ import annotations

import pytest
from telecom_pack.base import TelecomTraceContext
from telecom_pack.guardrails.tcpa_compliance import TCPAComplianceValidator


@pytest.fixture
def validator() -> TCPAComplianceValidator:
    return TCPAComplianceValidator()


def _ctx(response: str, *, call_reason: str = "billing") -> TelecomTraceContext:
    return TelecomTraceContext(
        query="Help with my account",
        response=response,
        call_reason=call_reason,
    )


async def test_clean_response(validator: TCPAComplianceValidator) -> None:
    result = await validator.evaluate(_ctx("Your balance is $45.00. Is there anything else?"))
    assert result.passed is True


async def test_detects_marketing_language(validator: TCPAComplianceValidator) -> None:
    result = await validator.evaluate(_ctx("Don't miss this exclusive offer! Upgrade now and save $20/month!"))
    assert result.passed is False
    assert "marketing_language" in result.evidence


async def test_marketing_in_sales_context_is_medium(validator: TCPAComplianceValidator) -> None:
    result = await validator.evaluate(
        _ctx(
            "We have an exclusive offer — free month of premium!",
            call_reason="sales",
        )
    )
    assert result.passed is False
    assert result.severity == "medium"


async def test_detects_autodialer_references(validator: TCPAComplianceValidator) -> None:
    result = await validator.evaluate(_ctx("I'll send a bulk SMS to notify all affected customers about the outage."))
    assert result.passed is False
    assert "autodialer_references" in result.evidence
    assert result.action == "block"


async def test_detects_dnc_bypass(validator: TCPAComplianceValidator) -> None:
    result = await validator.evaluate(_ctx("I can override the DNC status for this customer to proceed with the call."))
    assert result.passed is False
    assert result.severity == "critical"
    assert result.action == "block"
    assert "dnc_violations" in result.evidence


async def test_automated_message_flagged(validator: TCPAComplianceValidator) -> None:
    result = await validator.evaluate(_ctx("We can set up a pre-recorded message for the outbound campaign."))
    assert result.passed is False
    assert "autodialer_references" in result.evidence
