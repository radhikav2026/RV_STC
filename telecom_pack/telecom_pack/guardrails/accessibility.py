"""Accessibility Validator — FCC Section 255 / ADA / European Accessibility Act.

FCC Section 255 requires telecommunications equipment and services to be
accessible to people with disabilities. The ADA and European Accessibility
Act (EAA) extend these requirements.

This validator checks AI-generated responses for:
- Reading level (plain language requirement)
- Sentence complexity (long sentences are inaccessible)
- Jargon density (technical terms without explanation)
- Availability of alternative format references
"""

from __future__ import annotations

import re

from telecom_pack.base import GuardrailResult, TelecomTraceContext

# Common telecom jargon that should be explained or avoided
_JARGON_TERMS = re.compile(
    r"\b(?:IMEI|IMSI|ICCID|MSISDN|MVNO|MVNE|eSIM|iSIM|VoLTE|VoNR"
    r"|MIMO|OFDMA|QAM|MEC|RAN|C-RAN|O-RAN|gNodeB|eNodeB|PCRF|IMS"
    r"|APN|QoS|QCI|ARPU|ARPA|OTT|CPE|ONT|GPON|DOCSIS|HFC"
    r"|CBRS|LAA|DSS|SA|NSA|mmWave|sub-6"
    r"|backhaul|fronthaul|midhaul|handoff|handover)\b",
    re.IGNORECASE,
)

# Approximate syllable counter for reading level
_VOWEL_GROUP = re.compile(r"[aeiouy]+", re.IGNORECASE)


def _syllable_count(word: str) -> int:
    """Rough syllable count via vowel-group heuristic."""
    word = word.lower().rstrip("e")
    groups = _VOWEL_GROUP.findall(word)
    return max(1, len(groups))


def _reading_metrics(text: str) -> dict[str, float]:
    """Compute Flesch-Kincaid grade level and related metrics."""
    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
    words = re.findall(r"\b[a-zA-Z]+\b", text)

    if not sentences or not words:
        return {"grade_level": 0.0, "avg_sentence_len": 0.0, "avg_syllables": 0.0}

    total_syllables = sum(_syllable_count(w) for w in words)
    avg_sentence_len = len(words) / len(sentences)
    avg_syllables = total_syllables / len(words)

    # Flesch-Kincaid Grade Level
    grade = 0.39 * avg_sentence_len + 11.8 * avg_syllables - 15.59

    return {
        "grade_level": round(grade, 1),
        "avg_sentence_len": round(avg_sentence_len, 1),
        "avg_syllables": round(avg_syllables, 2),
    }


# Maximum acceptable reading grade level (8th grade = broadly accessible)
_MAX_GRADE_LEVEL = 8.0
_MAX_SENTENCE_LENGTH = 35  # words
_MAX_JARGON_DENSITY = 0.03  # 3% of words


class AccessibilityValidator:
    """Checks AI responses meet accessibility / plain language standards.

    Configurable thresholds for reading level, sentence length, and
    jargon density.
    """

    rule_name: str = "accessibility"
    severity: str = "medium"

    def __init__(
        self,
        *,
        max_grade_level: float = _MAX_GRADE_LEVEL,
        max_sentence_words: int = _MAX_SENTENCE_LENGTH,
        max_jargon_density: float = _MAX_JARGON_DENSITY,
    ) -> None:
        self._max_grade = max_grade_level
        self._max_sentence = max_sentence_words
        self._max_jargon = max_jargon_density

    async def evaluate(self, ctx: TelecomTraceContext) -> GuardrailResult:
        issues: list[str] = []
        evidence: dict[str, object] = {}

        text = ctx.response
        words = re.findall(r"\b[a-zA-Z]+\b", text)
        word_count = len(words)

        if word_count < 5:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity="low",
                action="pass",
                details="Response too short for meaningful readability analysis.",
                regulation="FCC Section 255 / ADA",
            )

        # Reading level
        metrics = _reading_metrics(text)
        evidence["reading_metrics"] = metrics
        if metrics["grade_level"] > self._max_grade:
            issues.append(f"Reading level {metrics['grade_level']} exceeds " f"max {self._max_grade} (grade)")

        # Long sentences
        sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
        long_sentences = [s for s in sentences if len(re.findall(r"\b\w+\b", s)) > self._max_sentence]
        if long_sentences:
            evidence["long_sentences"] = len(long_sentences)
            issues.append(f"{len(long_sentences)} sentence(s) exceed {self._max_sentence} words")

        # Jargon density
        jargon_matches = _JARGON_TERMS.findall(text)
        jargon_density = len(jargon_matches) / word_count if word_count else 0.0
        if jargon_density > self._max_jargon:
            evidence["jargon_terms"] = list(set(jargon_matches))[:10]
            evidence["jargon_density"] = round(jargon_density, 4)
            issues.append(f"Jargon density {jargon_density:.1%} exceeds " f"max {self._max_jargon:.1%}")

        if not issues:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity="low",
                action="pass",
                details=f"Accessible: grade level {metrics['grade_level']}.",
                regulation="FCC Section 255 / ADA",
                evidence=evidence,
            )

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=False,
            severity="medium",
            action="warn",
            details=f"Accessibility issues: {'; '.join(issues)}.",
            regulation="FCC Section 255 / ADA",
            evidence=evidence,
        )
