"""YAML-backed pattern catalog loader.

Loads pen-test payloads and threat-detection patterns from YAML files.
Each pattern is tagged with MITRE ATLAS and OWASP LLM Top 10 identifiers
so reports are directly usable as compliance evidence.

Extracted from: stc_framework/_internal/patterns.py (MIT license)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Pattern:
    """A single pattern entry from a catalog."""

    name: str
    regex: re.Pattern[str]
    severity: str = "medium"
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, text: str) -> bool:
        return bool(self.regex.search(text))


class PatternCatalog:
    """In-memory catalog of compiled patterns keyed by name."""

    def __init__(self, patterns: list[Pattern]):
        self._patterns = {p.name: p for p in patterns}

    def __len__(self) -> int:
        return len(self._patterns)

    def names(self) -> list[str]:
        return sorted(self._patterns.keys())

    def get(self, name: str) -> Pattern:
        return self._patterns[name]

    def scan(self, text: str) -> list[Pattern]:
        """Return all patterns that match the given text."""
        return [p for p in self._patterns.values() if p.matches(text)]


def load_catalog(path: str | Path) -> PatternCatalog:
    """Load a YAML pattern file into a PatternCatalog.

    Expected format::

        patterns:
          - name: direct_injection_override_en
            regex: "(?i)ignore (all )?(previous|prior|above) instructions?"
            severity: critical
            description: "Direct prompt injection"
            metadata:
              mitre: AML.T0051
              owasp: LLM01
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    raw = data.get("patterns", [])
    if not isinstance(raw, list):
        raise ValueError(f"pattern file {path!s}: expected 'patterns' to be a list")
    compiled: list[Pattern] = []
    for entry in raw:
        if not isinstance(entry, dict) or "name" not in entry or "regex" not in entry:
            raise ValueError(f"pattern file {path!s}: entry missing name/regex: {entry!r}")
        compiled.append(
            Pattern(
                name=str(entry["name"]),
                regex=re.compile(str(entry["regex"])),
                severity=str(entry.get("severity", "medium")),
                description=str(entry.get("description", "")),
                metadata=dict(entry.get("metadata", {})),
            )
        )
    return PatternCatalog(compiled)


_DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=8)
def default_pen_catalog() -> PatternCatalog:
    """Load the bundled pen-test payload catalog."""
    return load_catalog(_DATA_DIR / "pen_payloads.yaml")


@lru_cache(maxsize=8)
def default_threat_catalog() -> PatternCatalog:
    """Load the bundled runtime threat-detection catalog."""
    return load_catalog(_DATA_DIR / "threat_patterns.yaml")
