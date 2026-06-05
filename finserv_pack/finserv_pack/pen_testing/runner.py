"""Pen-test runner for AI + infra attacks.

A parameterized runner that walks every payload in a pen-test catalog,
invokes a caller-supplied probe function, and classifies the response.
Categories are tagged with MITRE ATLAS + OWASP LLM Top 10 identifiers
so the report is directly usable as compliance evidence.

The runner is a *simulator* — it invokes a caller-supplied probe_fn for
each payload and classifies the response. Integrations with live LLM/API
layers plug in by providing a probe_fn that sends the payload.

Extracted from: stc_framework/security/pen_testing.py (MIT license)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from finserv_pack.pen_testing.patterns import Pattern, PatternCatalog, default_pen_catalog


class TestResult(str, Enum):
    """Pen test outcome."""

    __test__ = False  # Prevent pytest collection

    PASS = "pass"    # Attack got through (defence gap)
    FAIL = "fail"    # Attack was blocked (defence worked)
    SKIP = "skip"    # Test was skipped
    ERROR = "error"  # Probe raised an exception


@dataclass
class PenTestResult:
    """Result of a single pen-test payload execution."""

    test_id: str
    test_name: str
    category: str
    result: TestResult
    severity: str
    evidence: str = ""
    mitre: str = ""
    owasp: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Probe function type: async callable.
# Takes a Pattern, returns "blocked" (defence succeeded) or "allowed" (defence gap).
ProbeFn = Callable[[Pattern], Awaitable[str]]


class PenTestRunner:
    """Iterates pen-test payloads against a probe function.

    Usage:
        async def probe(pattern: Pattern) -> str:
            response = await your_agent.send(pattern.regex)
            if was_blocked(response):
                return "blocked"
            return "allowed"

        runner = PenTestRunner(probe_fn=probe)
        results = await runner.run_all()
        summary = PenTestRunner.summarise(results)
        # summary = {"total": 10, "counts": {"pass": 2, "fail": 8}, "mitre_coverage": {...}}
    """

    def __init__(
        self,
        probe_fn: ProbeFn,
        *,
        catalog: PatternCatalog | None = None,
    ) -> None:
        self._probe = probe_fn
        self._catalog = catalog or default_pen_catalog()

    async def run_all(self) -> list[PenTestResult]:
        """Run all payloads in the catalog."""
        return await self.run_by_category(None)

    async def run_by_category(self, category: str | None) -> list[PenTestResult]:
        """Run payloads filtered by category (None = all)."""
        results: list[PenTestResult] = []
        for name in self._catalog.names():
            pattern = self._catalog.get(name)
            meta = pattern.metadata
            pattern_category = str(meta.get("category", "ai_adversarial"))
            if category is not None and category != pattern_category:
                continue
            try:
                verdict = await self._probe(pattern)
            except Exception as exc:
                results.append(
                    PenTestResult(
                        test_id=pattern.name,
                        test_name=pattern.name,
                        category=pattern_category,
                        result=TestResult.ERROR,
                        severity=pattern.severity,
                        evidence=f"probe raised {type(exc).__name__}: {exc}",
                        mitre=str(meta.get("mitre", "")),
                        owasp=str(meta.get("owasp", "")),
                    )
                )
                continue
            # "blocked" = defence worked (FAIL as attack test)
            # "allowed" = gap (PASS as attack test — attack succeeded)
            test_result = TestResult.PASS if verdict == "allowed" else TestResult.FAIL
            results.append(
                PenTestResult(
                    test_id=pattern.name,
                    test_name=pattern.name,
                    category=pattern_category,
                    result=test_result,
                    severity=pattern.severity,
                    evidence=verdict,
                    mitre=str(meta.get("mitre", "")),
                    owasp=str(meta.get("owasp", "")),
                )
            )
        return results

    @staticmethod
    def summarise(results: list[PenTestResult]) -> dict[str, Any]:
        """Generate a compliance-evidence summary from test results.

        Returns:
            {
                "total": int,
                "counts": {"pass": N, "fail": N, "skip": N, "error": N},
                "mitre_coverage": {"AML.T0051": N, ...},
                "owasp_coverage": {"LLM01": N, ...},
                "by_category": {"prompt_injection": N, ...},
                "critical_gaps": [PenTestResult, ...]  # attacks that got through
            }
        """
        counts: dict[str, int] = {r.value: 0 for r in TestResult}
        mitre: dict[str, int] = {}
        owasp: dict[str, int] = {}
        by_category: dict[str, int] = {}
        critical_gaps: list[PenTestResult] = []

        for r in results:
            counts[r.result.value] += 1
            if r.mitre:
                mitre[r.mitre] = mitre.get(r.mitre, 0) + 1
            if r.owasp:
                owasp[r.owasp] = owasp.get(r.owasp, 0) + 1
            by_category[r.category] = by_category.get(r.category, 0) + 1
            if r.result == TestResult.PASS and r.severity in ("critical", "high"):
                critical_gaps.append(r)

        return {
            "total": len(results),
            "counts": counts,
            "mitre_coverage": mitre,
            "owasp_coverage": owasp,
            "by_category": by_category,
            "critical_gaps": critical_gaps,
        }
