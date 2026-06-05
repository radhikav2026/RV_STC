"""Bias & fairness monitor — disparate-impact detection.

Tracks per-demographic-group response quality and computes the 4/5ths
rule (EEOC) ratio. A ratio below 0.80 between any protected group and
the reference group is evidence of adverse impact.

Regulatory mapping: ECOA (Equal Credit Opportunity Act), Fair Lending,
CFPB enforcement guidance on AI-assisted decisioning.

Extracted from: stc_framework/compliance/bias_fairness.py (MIT license)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import mean
from typing import Any

from finserv_pack.base import BiasViolation, GuardrailResult, TraceContext

ADVERSE_IMPACT_RATIO = 0.80


@dataclass
class FairnessMetric:
    group: str
    reference_group: str
    group_rate: float
    reference_rate: float
    ratio: float
    adverse_impact: bool


@dataclass
class BiasReport:
    reference_group: str
    per_group: dict[str, float] = field(default_factory=dict)
    findings: list[FairnessMetric] = field(default_factory=list)
    has_adverse_impact: bool = False


class BiasFairnessMonitor:
    """In-memory fairness tracker using the 4/5ths (80%) rule.

    Usage:
        monitor = BiasFairnessMonitor()
        # Feed scores from your evaluation pipeline:
        monitor.record(group="group_a", score=0.9)
        monitor.record(group="group_b", score=0.6)
        # Check for adverse impact:
        report = await monitor.evaluate_fairness()
        if report.has_adverse_impact:
            # alert compliance team
    """

    rule_name = "bias_fairness"
    severity = "high"

    def __init__(self, *, enforce: bool = False) -> None:
        self._scores: dict[str, list[float]] = defaultdict(list)
        self._enforce = enforce

    def record(self, *, group: str, score: float) -> None:
        """Record a response quality score (0.0–1.0) for a demographic group."""
        if not 0.0 <= score <= 1.0:
            raise ValueError("score must be in [0.0, 1.0]")
        self._scores[group].append(score)

    async def evaluate_fairness(self, *, reference_group: str | None = None) -> BiasReport:
        """Evaluate fairness across all recorded groups."""
        if not self._scores:
            return BiasReport(reference_group=reference_group or "")

        per_group = {g: mean(scores) if scores else 0.0 for g, scores in self._scores.items()}
        ref = reference_group or max(per_group, key=lambda k: per_group[k])
        ref_rate = per_group[ref]
        findings: list[FairnessMetric] = []
        has_adverse = False

        for group, rate in per_group.items():
            if group == ref:
                continue
            if ref_rate <= 0:
                continue
            ratio = rate / ref_rate
            adverse = ratio < ADVERSE_IMPACT_RATIO
            if adverse:
                has_adverse = True
            findings.append(
                FairnessMetric(
                    group=group,
                    reference_group=ref,
                    group_rate=rate,
                    reference_rate=ref_rate,
                    ratio=ratio,
                    adverse_impact=adverse,
                )
            )

        report = BiasReport(
            reference_group=ref,
            per_group=per_group,
            findings=findings,
            has_adverse_impact=has_adverse,
        )

        if self._enforce and has_adverse:
            adverse_groups = [f.group for f in findings if f.adverse_impact]
            raise BiasViolation(
                f"Adverse impact detected for groups: {adverse_groups}",
                rule="bias_fairness",
                evidence={"findings": [f.__dict__ for f in findings if f.adverse_impact]},
            )

        return report

    async def evaluate(self, ctx: TraceContext) -> GuardrailResult:
        """Evaluate via the generic Validator interface.

        Expects ctx.metadata to contain:
        - "group": demographic group of the current request
        - "score": quality score (0-1) for this response

        Call this for every request, then periodically check evaluate_fairness().
        """
        group = ctx.metadata.get("group")
        score = ctx.metadata.get("quality_score")

        if group is None or score is None:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity=self.severity,
                action="pass",
                details="No demographic group/score in context; skipping bias check",
            )

        self.record(group=group, score=float(score))
        report = await self.evaluate_fairness()

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=not report.has_adverse_impact,
            severity=self.severity,
            action="pass" if not report.has_adverse_impact else "warn",
            details=(
                "No adverse impact detected"
                if not report.has_adverse_impact
                else f"Adverse impact detected in {len([f for f in report.findings if f.adverse_impact])} group(s)"
            ),
            evidence={
                "reference_group": report.reference_group,
                "per_group_rates": report.per_group,
                "adverse_findings": [f.__dict__ for f in report.findings if f.adverse_impact],
            },
        )

    def reset(self) -> None:
        """Clear all recorded scores."""
        self._scores.clear()

    def snapshot(self) -> dict[str, float]:
        """Return current mean scores per group."""
        return {g: mean(scores) if scores else 0.0 for g, scores in self._scores.items()}
