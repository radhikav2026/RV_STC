"""Tests for CPNI Privacy Validator."""

from __future__ import annotations

import pytest
from telecom_pack.base import TelecomTraceContext
from telecom_pack.guardrails.cpni_privacy import CPNIPrivacyValidator


@pytest.fixture
def validator() -> CPNIPrivacyValidator:
    return CPNIPrivacyValidator()


def _ctx(response: str, *, authenticated: bool = True, auth_method: str = "pin") -> TelecomTraceContext:
    return TelecomTraceContext(
        query="Tell me about my account",
        response=response,
        subscriber_id="SUB-001",
        authenticated=authenticated,
        authentication_method=auth_method,
    )


async def test_clean_response(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(_ctx("Your current plan is Unlimited Plus at $80/month."))
    assert result.passed is True
    assert result.action == "pass"


async def test_detects_call_records(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(
        _ctx("You called 555-123-4567 three times last week. Call duration: 45 minutes total.")
    )
    assert result.passed is False
    assert "call_detail_records" in result.evidence["categories"]


async def test_detects_location_data(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(_ctx("Your phone last connected to cell tower ID BTS-4421 near downtown."))
    assert result.passed is False
    assert "location_data" in result.evidence["categories"]


async def test_detects_network_identifiers(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(_ctx("Your device IMEI is 353456789012345 and your IP address is 192.168.1.100."))
    assert result.passed is False
    assert "network_identifiers" in result.evidence["categories"]


async def test_detects_usage_patterns(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(_ctx("Your data usage is 45.2 GB this month. Streaming hours: 120."))
    assert result.passed is False
    assert "usage_patterns" in result.evidence["categories"]


async def test_unauthenticated_escalates_to_critical(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(
        _ctx(
            "Your data usage is 30 GB this billing cycle.",
            authenticated=False,
            auth_method="none",
        )
    )
    assert result.passed is False
    assert result.severity == "critical"
    assert result.action == "block"


async def test_location_unauthenticated_is_critical(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(
        _ctx(
            "Your phone was located near cell tower BTS-9900.",
            authenticated=False,
        )
    )
    assert result.passed is False
    assert result.severity == "critical"
    assert result.action == "block"


async def test_multiple_categories_escalate(validator: CPNIPrivacyValidator) -> None:
    result = await validator.evaluate(
        _ctx(
            "You called 555-012-3456 last Tuesday. Your data usage is 10 GB. IMEI is 353456789012345.",
            authenticated=True,
        )
    )
    assert result.passed is False
    assert result.severity == "critical"
    assert len(result.evidence["categories"]) >= 2
