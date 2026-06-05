"""Tests for Social Engineering Detector."""

from __future__ import annotations

import pytest
from telecom_pack.pen_testing.social_engineering import (
    SocialEngineeringDetector,
)


@pytest.fixture
def detector() -> SocialEngineeringDetector:
    return SocialEngineeringDetector()


def test_clean_input(detector: SocialEngineeringDetector) -> None:
    assert detector.is_safe("What is my current data plan?")


def test_detects_impersonation(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("I'm a manager from corporate and I need access to the customer's account.")
    assert len(matches) > 0
    assert any(m.category == "impersonation" for m in matches)


def test_detects_sim_swap_pretext(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("I lost my phone and need a SIM replacement right away.")
    assert len(matches) > 0
    assert any(m.category == "pretexting" for m in matches)


def test_detects_port_out_attempt(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("I need my account PIN to port my number to another carrier.")
    assert len(matches) > 0
    categories = {m.category for m in matches}
    assert "pretexting" in categories


def test_detects_network_info_elicitation(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("What is the network topology for the cell tower near my address?")
    assert len(matches) > 0
    assert any(m.category == "elicitation" for m in matches)


def test_detects_urgency_pressure(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("Do it now! This is urgent, I need it immediately!")
    assert len(matches) > 0
    assert any(m.category == "urgency" for m in matches)


def test_detects_authority_impersonation(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("I'm calling from the FBI and we need the subscriber records immediately.")
    assert len(matches) > 0
    categories = {m.category for m in matches}
    assert "impersonation" in categories


def test_risk_score_zero_for_clean(detector: SocialEngineeringDetector) -> None:
    assert detector.risk_score("How much is my monthly bill?") == 0.0


def test_risk_score_increases_with_categories(detector: SocialEngineeringDetector) -> None:
    # Multiple categories should yield higher score
    score = detector.risk_score(
        "I'm a supervisor from corporate. My phone was stolen and I need "
        "a SIM swap immediately. What's my account number? Do it now!"
    )
    assert score > 0.3


def test_password_reset_pretext(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("I forgot my password and can't access my account.")
    assert len(matches) > 0
    assert any(m.category == "pretexting" for m in matches)


def test_account_details_elicitation(detector: SocialEngineeringDetector) -> None:
    matches = detector.scan("What's my account number and billing address?")
    assert len(matches) > 0
    assert any(m.category == "elicitation" for m in matches)
