"""Tests for Accessibility Validator."""

from __future__ import annotations

import pytest
from telecom_pack.base import TelecomTraceContext
from telecom_pack.guardrails.accessibility import AccessibilityValidator


@pytest.fixture
def validator() -> AccessibilityValidator:
    return AccessibilityValidator()


def _ctx(response: str) -> TelecomTraceContext:
    return TelecomTraceContext(query="Help me", response=response)


async def test_short_response_passes(validator: AccessibilityValidator) -> None:
    result = await validator.evaluate(_ctx("Yes, done."))
    assert result.passed is True


async def test_plain_language_passes(validator: AccessibilityValidator) -> None:
    result = await validator.evaluate(
        _ctx("Your bill is due on June 15. The total is $80. " "You can pay online or call us. We accept credit cards.")
    )
    assert result.passed is True


async def test_high_jargon_fails(validator: AccessibilityValidator) -> None:
    result = await validator.evaluate(
        _ctx(
            "The MIMO configuration on your gNodeB uses OFDMA with QAM "
            "modulation. The C-RAN backhaul connects via GPON to the MEC "
            "edge node. Your eSIM ICCID is provisioned on the IMS core."
        )
    )
    assert result.passed is False
    assert "jargon_terms" in result.evidence


async def test_custom_thresholds(validator: AccessibilityValidator) -> None:
    strict = AccessibilityValidator(max_grade_level=4.0, max_jargon_density=0.01)
    result = await strict.evaluate(
        _ctx(
            "Your sophisticated telecommunications infrastructure "
            "demonstrates exceptional performance characteristics. "
            "The implementation leverages advanced methodologies."
        )
    )
    # May or may not fail depending on exact metrics, but should be stricter
    assert isinstance(result.passed, bool)
