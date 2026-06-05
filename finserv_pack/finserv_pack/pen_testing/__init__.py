"""Pen testing module — MITRE ATLAS + OWASP LLM Top 10 attack simulation.

Provides:
- PenTestRunner: parameterized attack simulator
- InjectionDetector: 20+ multilingual injection detection rules
- Pattern catalogs: YAML-based, tagged to compliance frameworks
"""

from finserv_pack.pen_testing.injection import InjectionDetector, InjectionMatch
from finserv_pack.pen_testing.runner import PenTestResult, PenTestRunner, TestResult
from finserv_pack.pen_testing.patterns import Pattern, PatternCatalog, load_catalog

__all__ = [
    "InjectionDetector",
    "InjectionMatch",
    "Pattern",
    "PatternCatalog",
    "PenTestResult",
    "PenTestRunner",
    "TestResult",
    "load_catalog",
]
