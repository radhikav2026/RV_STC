"""Telecom pen-test runner — account takeover + CPNI exfiltration simulation.

A parameterized runner that walks telecom-specific attack payloads,
invokes a caller-supplied probe function, and classifies the response.
Categories are tagged with MITRE ATLAS and OWASP identifiers.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


class TestResult(str, Enum):
    """Pen test outcome."""

    __test__ = False  # Prevent pytest collection

    PASS = "pass"  # Attack got through (defence gap)
    FAIL = "fail"  # Attack was blocked (defence worked)
    SKIP = "skip"
    ERROR = "error"


@dataclass
class TelecomPenTestResult:
    """Result of a single telecom pen-test payload execution."""

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


@dataclass(frozen=True)
class TelecomPayload:
    """A single pen-test payload entry."""

    name: str
    prompt: str
    category: str
    severity: str = "high"
    description: str = ""
    expected_block: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


ProbeFn = Callable[[TelecomPayload], Awaitable[str]]


def _load_payloads(path: Path) -> list[TelecomPayload]:
    """Load telecom pen-test payloads from a YAML file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("payloads", [])
    payloads: list[TelecomPayload] = []
    for entry in raw:
        payloads.append(
            TelecomPayload(
                name=str(entry["name"]),
                prompt=str(entry["prompt"]),
                category=str(entry.get("category", "social_engineering")),
                severity=str(entry.get("severity", "high")),
                description=str(entry.get("description", "")),
                expected_block=bool(entry.get("expected_block", True)),
                metadata=dict(entry.get("metadata", {})),
            )
        )
    return payloads


_DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=4)
def default_telecom_payloads() -> list[TelecomPayload]:
    """Load the bundled telecom pen-test payloads."""
    return _load_payloads(_DATA_DIR / "telecom_payloads.yaml")


class TelecomPenTestRunner:
    """Iterates telecom-specific pen-test payloads against a probe function.

    Usage::

        async def probe(payload: TelecomPayload) -> str:
            response = await your_agent.send(payload.prompt)
            if was_blocked(response):
                return "blocked"
            return "allowed"

        runner = TelecomPenTestRunner(probe_fn=probe)
        results = await runner.run_all()
        summary = TelecomPenTestRunner.summarise(results)
    """

    def __init__(
        self,
        probe_fn: ProbeFn,
        *,
        payloads: list[TelecomPayload] | None = None,
    ) -> None:
        self._probe = probe_fn
        self._payloads = payloads or default_telecom_payloads()

    async def run_all(self) -> list[TelecomPenTestResult]:
        """Run all payloads."""
        return await self.run_by_category(None)

    async def run_by_category(self, category: str | None) -> list[TelecomPenTestResult]:
        """Run payloads filtered by category (None = all)."""
        results: list[TelecomPenTestResult] = []
        for payload in self._payloads:
            if category is not None and payload.category != category:
                continue
            try:
                verdict = await self._probe(payload)
            except Exception as exc:
                results.append(
                    TelecomPenTestResult(
                        test_id=payload.name,
                        test_name=payload.name,
                        category=payload.category,
                        result=TestResult.ERROR,
                        severity=payload.severity,
                        evidence=f"probe raised {type(exc).__name__}: {exc}",
                        mitre=str(payload.metadata.get("mitre", "")),
                        owasp=str(payload.metadata.get("owasp", "")),
                    )
                )
                continue
            test_result = TestResult.PASS if verdict == "allowed" else TestResult.FAIL
            results.append(
                TelecomPenTestResult(
                    test_id=payload.name,
                    test_name=payload.name,
                    category=payload.category,
                    result=test_result,
                    severity=payload.severity,
                    evidence=verdict,
                    mitre=str(payload.metadata.get("mitre", "")),
                    owasp=str(payload.metadata.get("owasp", "")),
                )
            )
        return results

    @staticmethod
    def summarise(results: list[TelecomPenTestResult]) -> dict[str, Any]:
        """Generate a compliance-evidence summary."""
        counts: dict[str, int] = {"pass": 0, "fail": 0, "skip": 0, "error": 0}
        by_category: dict[str, dict[str, int]] = {}
        for r in results:
            counts[r.result.value] = counts.get(r.result.value, 0) + 1
            cat = by_category.setdefault(r.category, {"pass": 0, "fail": 0, "skip": 0, "error": 0})
            cat[r.result.value] = cat.get(r.result.value, 0) + 1

        return {
            "total": len(results),
            "counts": counts,
            "by_category": by_category,
            "defence_rate": (round(counts["fail"] / max(counts["fail"] + counts["pass"], 1), 2)),
        }
