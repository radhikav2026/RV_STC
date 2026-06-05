"""Tests for bias/fairness monitor."""

import pytest

from finserv_pack.base import BiasViolation, TraceContext
from finserv_pack.guardrails.bias_fairness import (
    ADVERSE_IMPACT_RATIO,
    BiasFairnessMonitor,
)


class TestBiasFairnessMonitor:
    async def test_no_adverse_impact_when_rates_similar(self):
        monitor = BiasFairnessMonitor()
        monitor.record(group="group_a", score=0.90)
        monitor.record(group="group_a", score=0.88)
        monitor.record(group="group_b", score=0.85)
        monitor.record(group="group_b", score=0.87)

        report = await monitor.evaluate_fairness()
        assert not report.has_adverse_impact

    async def test_adverse_impact_detected(self):
        monitor = BiasFairnessMonitor()
        # Reference group gets high scores
        for _ in range(10):
            monitor.record(group="majority", score=0.95)
        # Protected group gets significantly lower scores
        for _ in range(10):
            monitor.record(group="minority", score=0.50)

        report = await monitor.evaluate_fairness()
        assert report.has_adverse_impact
        assert any(f.adverse_impact for f in report.findings)
        adverse = [f for f in report.findings if f.adverse_impact]
        assert adverse[0].ratio < ADVERSE_IMPACT_RATIO

    async def test_enforce_raises_on_adverse_impact(self):
        monitor = BiasFairnessMonitor(enforce=True)
        for _ in range(10):
            monitor.record(group="majority", score=0.95)
        for _ in range(10):
            monitor.record(group="minority", score=0.30)

        with pytest.raises(BiasViolation):
            await monitor.evaluate_fairness()

    async def test_empty_scores_returns_empty_report(self):
        monitor = BiasFairnessMonitor()
        report = await monitor.evaluate_fairness()
        assert report.reference_group == ""
        assert not report.has_adverse_impact

    async def test_reset_clears_data(self):
        monitor = BiasFairnessMonitor()
        monitor.record(group="a", score=0.5)
        monitor.reset()
        assert monitor.snapshot() == {}

    async def test_snapshot_returns_means(self):
        monitor = BiasFairnessMonitor()
        monitor.record(group="a", score=0.8)
        monitor.record(group="a", score=0.6)
        snap = monitor.snapshot()
        assert abs(snap["a"] - 0.7) < 0.01

    async def test_invalid_score_raises(self):
        monitor = BiasFairnessMonitor()
        with pytest.raises(ValueError):
            monitor.record(group="a", score=1.5)
        with pytest.raises(ValueError):
            monitor.record(group="a", score=-0.1)

    async def test_evaluate_via_trace_context(self):
        monitor = BiasFairnessMonitor()
        # Feed several traces
        for score in [0.9, 0.85, 0.92]:
            ctx = TraceContext(
                query="q", response="r",
                metadata={"group": "majority", "quality_score": score},
            )
            await monitor.evaluate(ctx)
        for score in [0.5, 0.45, 0.48]:
            ctx = TraceContext(
                query="q", response="r",
                metadata={"group": "minority", "quality_score": score},
            )
            await monitor.evaluate(ctx)

        # Final evaluation should detect adverse impact
        ctx = TraceContext(
            query="q", response="r",
            metadata={"group": "minority", "quality_score": 0.50},
        )
        result = await monitor.evaluate(ctx)
        assert not result.passed
        assert result.action == "warn"
