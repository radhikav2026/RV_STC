"""Tests for Slam / Cram Detector."""

from __future__ import annotations

import pytest
from telecom_pack.base import TelecomTraceContext
from telecom_pack.guardrails.slam_cram_detector import SlamCramDetector


@pytest.fixture
def validator() -> SlamCramDetector:
    return SlamCramDetector()


def _ctx(response: str, *, query: str = "What about my account?") -> TelecomTraceContext:
    return TelecomTraceContext(query=query, response=response)


async def test_clean_response(validator: SlamCramDetector) -> None:
    result = await validator.evaluate(_ctx("Your account is in good standing. Your balance is $0."))
    assert result.passed is True


async def test_detects_service_switch_without_consent(validator: SlamCramDetector) -> None:
    result = await validator.evaluate(_ctx("We've switched your service to the new provider as requested."))
    assert result.passed is False
    assert "slamming_triggers" in result.evidence


async def test_service_change_with_consent_passes(validator: SlamCramDetector) -> None:
    result = await validator.evaluate(
        _ctx("Would you like to switch your plan to Unlimited? Please confirm before I make any changes.")
    )
    assert result.passed is True


async def test_detects_unauthorized_charges(validator: SlamCramDetector) -> None:
    result = await validator.evaluate(_ctx("I've added a premium subscription feature to your account."))
    assert result.passed is False
    assert "cramming_triggers" in result.evidence


async def test_auto_renew_trial_flagged(validator: SlamCramDetector) -> None:
    result = await validator.evaluate(_ctx("The trial period will automatically renew at $9.99/month after 30 days."))
    assert result.passed is False


async def test_customer_authorized_reduces_severity(validator: SlamCramDetector) -> None:
    result = await validator.evaluate(
        _ctx(
            "We'll transfer your service to the new carrier.",
            query="Yes, please go ahead and switch my carrier.",
        )
    )
    # Authorization in query should reduce severity
    assert result.severity != "critical" or result.passed is True
