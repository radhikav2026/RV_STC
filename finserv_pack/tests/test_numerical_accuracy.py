"""Tests for numerical accuracy validator."""

import pytest

from finserv_pack.base import TraceContext
from finserv_pack.guardrails.numerical_accuracy import NumericalAccuracyValidator


class TestNumericalAccuracy:
    async def test_all_numbers_grounded_passes(self):
        v = NumericalAccuracyValidator(tolerance_percent=1.0)
        ctx = TraceContext(
            query="What was the revenue?",
            response="Revenue was $4.2 billion in Q3.",
            context="Q3 revenue: $4.2 billion.",
            source_chunks=[{"text": "The company reported $4.2 billion in Q3 revenue."}],
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert "grounded" in result.details.lower()

    async def test_hallucinated_number_fails(self):
        v = NumericalAccuracyValidator(tolerance_percent=1.0)
        ctx = TraceContext(
            query="What was the revenue?",
            response="Revenue was $9.8 billion, a record high.",
            context="Q3 revenue: $4.2 billion.",
            source_chunks=[{"text": "Revenue was $4.2 billion."}],
        )
        result = await v.evaluate(ctx)
        assert not result.passed
        assert result.action == "block"
        assert "ungrounded" in result.details.lower()

    async def test_no_numbers_in_response_passes(self):
        v = NumericalAccuracyValidator()
        ctx = TraceContext(
            query="How is the market?",
            response="Markets are performing well this quarter.",
            context="The market has been strong.",
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert "No numerical claims" in result.details

    async def test_percentage_grounded(self):
        v = NumericalAccuracyValidator(tolerance_percent=2.0)
        ctx = TraceContext(
            query="What's the yield?",
            response="The current yield is 4.5%.",
            context="Bond yield: 4.5%.",
            source_chunks=[],
        )
        result = await v.evaluate(ctx)
        assert result.passed

    async def test_tolerance_allows_close_match(self):
        v = NumericalAccuracyValidator(tolerance_percent=5.0)
        ctx = TraceContext(
            query="Revenue?",
            response="Revenue was approximately $4.18 billion.",
            context="$4.2 billion revenue reported.",
            source_chunks=[],
        )
        result = await v.evaluate(ctx)
        assert result.passed

    async def test_evidence_contains_numbers(self):
        v = NumericalAccuracyValidator()
        ctx = TraceContext(
            query="Numbers?",
            response="The stock is at $150.00 with a PE of 25.3.",
            context="Stock price $150.00, PE ratio 25.3.",
            source_chunks=[],
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert "response_numbers" in result.evidence
