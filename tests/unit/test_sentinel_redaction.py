"""Tests for :mod:`stc_framework.sentinel.redaction`.

Covers the ``PIIRedactor`` class using the regex-based fallback engine
(Presidio is not installed in the base dev environment). Tests the
MASK/BLOCK entity config, each fallback regex pattern, and metrics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from stc_framework.errors import DataSovereigntyViolation
from stc_framework.observability.metrics import get_metrics
from stc_framework.sentinel.redaction import PIIRedactor, RedactionResult
from stc_framework.spec.loader import load_spec

_FIXTURE_DIR = Path(__file__).parents[1] / "fixtures"


@pytest.fixture()
def spec():
    return load_spec(_FIXTURE_DIR / "minimal_spec.yaml")


@pytest.fixture()
def redactor(spec):
    """Fallback-only redactor (presidio_enabled=False)."""
    return PIIRedactor(spec, presidio_enabled=False)


def test_no_pii_returns_unchanged(redactor):
    result = redactor.redact("Hello, how can I help?")
    assert result.text == "Hello, how can I help?"
    assert result.redactions == []
    assert result.entity_counts == {}


def test_email_redacted(redactor):
    result = redactor.redact("Contact us at foo@example.com for details.")
    assert "<EMAIL_ADDRESS>" in result.text
    assert "foo@example.com" not in result.text
    assert result.entity_counts.get("EMAIL_ADDRESS", 0) >= 1


def test_us_ssn_redacted(redactor):
    result = redactor.redact("SSN is 123-45-6789 on record.")
    assert "<US_SSN>" in result.text
    assert "123-45-6789" not in result.text
    assert "US_SSN" in result.entity_counts


def test_credit_card_blocked_by_default_spec(redactor):
    """Minimal spec has CREDIT_CARD as BLOCK — should raise."""
    with pytest.raises(DataSovereigntyViolation, match="CREDIT_CARD"):
        redactor.redact("Card: 4111 1111 1111 1111")


def test_credit_card_masked_when_configured(spec):
    """With CREDIT_CARD set to MASK, it's redacted not blocked."""
    spec.sentinel.pii_redaction.entities_config["CREDIT_CARD"] = "MASK"
    r = PIIRedactor(spec, presidio_enabled=False)
    result = r.redact("Card: 4111 1111 1111 1111")
    assert "<CREDIT_CARD>" in result.text
    assert "4111 1111 1111 1111" not in result.text
    assert "CREDIT_CARD" in result.entity_counts


def test_phone_number_redacted(redactor):
    result = redactor.redact("Call +1 (555) 123-4567 now.")
    assert "<PHONE_NUMBER>" in result.text
    assert "+1 (555) 123-4567" not in result.text
    assert "PHONE_NUMBER" in result.entity_counts


def test_url_redacted(redactor):
    result = redactor.redact("Visit https://example.com/path?q=1 for info.")
    assert "<URL>" in result.text
    assert "https://example.com/path?q=1" not in result.text
    assert "URL" in result.entity_counts


def test_block_entity_raises_violation(spec):
    """When entity config is BLOCK, DataSovereigntyViolation is raised."""
    # Patch the spec to block EMAIL_ADDRESS
    spec.sentinel.pii_redaction.entities_config["EMAIL_ADDRESS"] = "BLOCK"
    redactor = PIIRedactor(spec, presidio_enabled=False)
    with pytest.raises(DataSovereigntyViolation, match=r"Blocked entity.*EMAIL_ADDRESS"):
        redactor.redact("Send to blocked@example.com")


def test_multiple_entities_in_one_text(redactor):
    text = "Email: a@b.com SSN: 123-45-6789"
    result = redactor.redact(text)
    assert "<EMAIL_ADDRESS>" in result.text
    assert "<US_SSN>" in result.text
    assert len(result.redactions) >= 2


def test_redaction_metrics_incremented(redactor):
    metrics = get_metrics()
    before = metrics.redaction_events_total.labels(entity_type="EMAIL_ADDRESS")._value.get()
    redactor.redact("test@test.com")
    after = metrics.redaction_events_total.labels(entity_type="EMAIL_ADDRESS")._value.get()
    assert after >= before + 1


def test_redaction_result_structure(redactor):
    result = redactor.redact("SSN 123-45-6789")
    assert isinstance(result, RedactionResult)
    assert len(result.redactions) >= 1
    r = result.redactions[0]
    assert "entity_type" in r
    assert "start" in r
    assert "end" in r
    assert "score" in r
