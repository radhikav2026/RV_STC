"""Slam / Cram Detector — FCC Anti-Slamming Rules (47 CFR 64.1100-1195).

"Slamming" is the unauthorized switching of a customer's telephone service
provider. "Cramming" is placing unauthorized charges on a customer's bill.

This validator detects when AI-generated responses could constitute:
- Unauthorized service changes (slamming triggers)
- Unauthorized charge additions (cramming triggers)
- Misleading consent language that could trick a customer into agreeing
- Missing explicit authorization for service modifications
"""

from __future__ import annotations

import re

from telecom_pack.base import GuardrailResult, TelecomTraceContext

# Patterns that indicate service switching without clear consent
_SLAMMING_PATTERNS = [
    re.compile(
        r"\b(?:switch(?:ed|ing)?|chang(?:ed|ing)?|transfer(?:red|ring)?|mov(?:ed|ing)?)\s+"
        r"(?:your|the)?\s*(?:service|provider|carrier|plan|account)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:already|automatically|been)\s+(?:switch|chang|transfer|mov|migrat)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:we(?:'ve|'ll| will| have))\s+(?:switch|chang|transfer|mov|upgrad|migrat)",
        re.IGNORECASE,
    ),
]

# Patterns that indicate unauthorized charges
_CRAMMING_PATTERNS = [
    re.compile(
        r"\b(?:add(?:ed|ing)?|charg(?:ed|ing)?|bill(?:ed|ing)?)\s+(?:a\s+)?"
        r"(?:fee|charge|service|feature|add-on|premium|subscription)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:included|bundled|complimentary)\s+(?:for\s+)?(?:the\s+)?first\s+\d+\s+(?:month|day|week)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:trial|promotional)\s+(?:period|offer)\s+(?:will\s+)?(?:auto|automatically)\s*(?:renew|convert|bill)",
        re.IGNORECASE,
    ),
]

# Consent verification phrases — presence reduces severity
_CONSENT_PHRASES = re.compile(
    r"\b(?:do you (?:agree|authorize|approve|confirm|consent)"
    r"|would you like (?:to|me to)"
    r"|please confirm"
    r"|with your (?:permission|approval|authorization)"
    r"|before (?:I|we) (?:make|proceed|process))\b",
    re.IGNORECASE,
)

# Explicit authorization phrases
_AUTHORIZATION_PHRASES = re.compile(
    r"\b(?:I (?:authorize|approve|agree|consent|confirm)"
    r"|yes,?\s+(?:please|go ahead|proceed)"
    r"|please\s+go\s+ahead"
    r"|go\s+ahead\s+and\s+(?:switch|change|transfer|cancel|add|remove)"
    r"|authorized by (?:customer|subscriber|account holder))\b",
    re.IGNORECASE,
)


class SlamCramDetector:
    """Detects slamming and cramming risk in AI responses.

    Flags service changes and charge additions that lack explicit
    customer authorization.
    """

    rule_name: str = "slam_cram_detector"
    severity: str = "high"

    async def evaluate(self, ctx: TelecomTraceContext) -> GuardrailResult:
        issues: list[str] = []
        evidence: dict[str, list[str]] = {}

        has_consent_request = bool(_CONSENT_PHRASES.search(ctx.response))
        has_authorization = bool(_AUTHORIZATION_PHRASES.search(ctx.query))

        # Check for slamming patterns
        slam_matches = []
        for pat in _SLAMMING_PATTERNS:
            for m in pat.finditer(ctx.response):
                slam_matches.append(m.group().strip())
        if slam_matches:
            evidence["slamming_triggers"] = slam_matches
            if not has_consent_request:
                issues.append(f"{len(slam_matches)} service change reference(s) " f"without consent verification")

        # Check for cramming patterns
        cram_matches = []
        for pat in _CRAMMING_PATTERNS:
            for m in pat.finditer(ctx.response):
                cram_matches.append(m.group().strip())
        if cram_matches:
            evidence["cramming_triggers"] = cram_matches
            if not has_consent_request:
                issues.append(f"{len(cram_matches)} charge addition reference(s) " f"without consent verification")

        if not issues:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity="low",
                action="pass",
                details="No slamming or cramming risk detected.",
                regulation="47 CFR 64.1100-1195",
            )

        evidence["has_consent_request"] = [str(has_consent_request)]
        evidence["has_customer_authorization"] = [str(has_authorization)]

        severity = "critical" if not has_authorization and slam_matches else "high"
        action = "block" if severity == "critical" else "warn"

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=False,
            severity=severity,
            action=action,
            details=f"Slam/cram risk: {'; '.join(issues)}.",
            regulation="47 CFR 64.1100-1195",
            evidence=evidence,
        )
