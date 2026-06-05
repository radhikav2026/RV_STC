"""Tests for transparency/disclosure validator."""

import pytest

from finserv_pack.base import TraceContext
from finserv_pack.guardrails.transparency import (
    DEFAULT_DISCLOSURE,
    TransparencyValidator,
)


class TestTransparencyValidator:
    async def test_response_with_disclosure_passes(self):
        v = TransparencyValidator()
        ctx = TraceContext(
            query="Advice?",
            response=f"Here is my analysis.\n\n— {DEFAULT_DISCLOSURE}",
            tenant_id="T-1",
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert result.evidence["disclosure_present"] is True

    async def test_response_without_disclosure_fails(self):
        v = TransparencyValidator()
        ctx = TraceContext(
            query="Advice?",
            response="You should invest in tech stocks.",
            tenant_id="T-1",
        )
        result = await v.evaluate(ctx)
        assert not result.passed
        assert "disclosure missing" in result.details.lower()

    async def test_apply_disclosure_stamps_content(self):
        v = TransparencyValidator()
        content = "Your portfolio is performing well."
        stamped = v.apply_disclosure(content)
        assert DEFAULT_DISCLOSURE in stamped
        assert content in stamped

    async def test_apply_disclosure_is_idempotent(self):
        v = TransparencyValidator()
        content = f"Analysis.\n\n— {DEFAULT_DISCLOSURE}"
        stamped = v.apply_disclosure(content)
        assert stamped == content  # not double-stamped

    async def test_custom_disclosure_text(self):
        custom = "AI-generated. Not financial advice."
        v = TransparencyValidator(disclosure_text=custom)
        ctx = TraceContext(
            query="q",
            response=f"Answer.\n\n— {custom}",
        )
        result = await v.evaluate(ctx)
        assert result.passed

    async def test_consent_check_passes_when_consented(self):
        v = TransparencyValidator(require_disclosure=False)
        v.record_consent(tenant_id="T-1", customer_id="C-1", consented=True)
        ctx = TraceContext(
            query="q",
            response="Answer.",
            tenant_id="T-1",
            metadata={"customer_id": "C-1"},
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert result.evidence["customer_consent"] is True

    async def test_consent_check_fails_when_not_consented(self):
        v = TransparencyValidator(require_disclosure=False)
        ctx = TraceContext(
            query="q",
            response="Answer.",
            tenant_id="T-1",
            metadata={"customer_id": "C-99"},
        )
        result = await v.evaluate(ctx)
        assert not result.passed
        assert "not consented" in result.details.lower()

    async def test_record_consent_and_revoke(self):
        v = TransparencyValidator()
        v.record_consent(tenant_id="T-1", customer_id="C-1", consented=True)
        assert v.check_consent(tenant_id="T-1", customer_id="C-1") is True
        v.record_consent(tenant_id="T-1", customer_id="C-1", consented=False)
        assert v.check_consent(tenant_id="T-1", customer_id="C-1") is False
