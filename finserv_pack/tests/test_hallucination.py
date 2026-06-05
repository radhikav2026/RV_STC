"""Tests for hallucination/grounding validator."""

import pytest

from finserv_pack.base import TraceContext
from finserv_pack.guardrails.hallucination import HallucinationValidator


class TestHallucinationValidator:
    async def test_well_grounded_response_passes(self):
        v = HallucinationValidator(threshold=0.5)
        ctx = TraceContext(
            query="What did the report say?",
            response="The annual report indicates strong revenue growth. Profits increased significantly over the prior year.",
            context="The annual report shows strong revenue growth with profits increasing significantly over the prior year period.",
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert "Grounding score" in result.details

    async def test_ungrounded_response_fails(self):
        v = HallucinationValidator(threshold=0.8)
        ctx = TraceContext(
            query="What did the report say?",
            response="The company announced a major acquisition of TechCorp for twelve billion dollars. The CEO resigned immediately after.",
            context="The quarterly earnings showed modest growth in the technology sector.",
        )
        result = await v.evaluate(ctx)
        assert not result.passed
        assert result.action == "block"

    async def test_no_context_blocks_substantial_response(self):
        v = HallucinationValidator()
        ctx = TraceContext(
            query="Tell me about the company",
            response="The company was founded in 1995 and has grown to become a major player in the financial services industry with over 50,000 employees worldwide.",
            context="",
        )
        result = await v.evaluate(ctx)
        assert not result.passed
        assert "no source context" in result.details.lower()

    async def test_short_response_passes(self):
        v = HallucinationValidator()
        ctx = TraceContext(
            query="Is it up?",
            response="Yes, it is up.",
            context="Market data...",
        )
        result = await v.evaluate(ctx)
        assert result.passed
        assert "too short" in result.details.lower()

    async def test_evidence_contains_grounding_score(self):
        v = HallucinationValidator(threshold=0.5)
        ctx = TraceContext(
            query="Summarize",
            response="Revenue grew by twenty percent over the last fiscal year. This was driven by strong demand.",
            context="Revenue increased twenty percent in the last fiscal year due to strong demand in core markets.",
        )
        result = await v.evaluate(ctx)
        assert "grounding_score" in result.evidence
        assert "total_sentences" in result.evidence
