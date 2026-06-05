"""TCPA Compliance Validator — Telephone Consumer Protection Act.

The TCPA (47 USC 227) restricts telemarketing calls, auto-dialed calls,
pre-recorded messages, and unsolicited text messages. FCC regulations
under 47 CFR 64.1200 add further requirements.

This validator detects when AI-generated content:
- Contains unsolicited marketing language without consent verification
- Recommends or initiates auto-dialed communications
- Generates pre-recorded message scripts for outbound campaigns
- Produces SMS/text content without opt-in verification
- Targets numbers on the National Do Not Call Registry
"""

from __future__ import annotations

import re

from telecom_pack.base import GuardrailResult, TelecomTraceContext

# Patterns indicating marketing / promotional content
_MARKETING_PATTERNS = [
    re.compile(r"\b(?:exclusive|limited[- ]time|special)\s+(?:offer|deal|promotion|discount|savings?)", re.IGNORECASE),
    re.compile(r"\b(?:upgrade|switch)\s+(?:now|today)\s+(?:and|to)\s+(?:save|get)", re.IGNORECASE),
    re.compile(r"\bact\s+(?:now|fast|quickly)\b", re.IGNORECASE),
    re.compile(r"\b(?:free|complimentary)\s+(?:month|trial|upgrade|device|phone|tablet)", re.IGNORECASE),
    re.compile(r"\bdon'?t\s+miss\s+(?:out|this)", re.IGNORECASE),
    re.compile(r"\b(?:call|text|dial)\s+(?:us\s+)?(?:now|today)\s+(?:at|to)\b", re.IGNORECASE),
]

# Patterns indicating auto-dialing or automated outreach
_AUTODIALER_PATTERNS = [
    re.compile(r"\b(?:auto[- ]?dial|robo[- ]?call|predictive\s+dial|power\s+dial|blast)", re.IGNORECASE),
    re.compile(r"\b(?:send\s+(?:a\s+)?(?:bulk|mass|batch)\s+(?:SMS|text|message))", re.IGNORECASE),
    re.compile(r"\b(?:automated|pre[- ]?recorded)\s+(?:message|voice|call)", re.IGNORECASE),
    re.compile(r"\b(?:broadcast|campaign)\s+(?:message|SMS|text)", re.IGNORECASE),
]

# Patterns suggesting DNC registry violations
_DNC_PATTERNS = [
    re.compile(r"\bdo\s+not\s+call\s+(?:list|registry|status)", re.IGNORECASE),
    re.compile(r"\bDNC\s+(?:status|check|list|override|bypass)", re.IGNORECASE),
    re.compile(r"\b(?:ignore|skip|bypass|override)\s+(?:DNC|do.not.call|opt.out)", re.IGNORECASE),
]

# Interaction types considered sales/marketing contexts
_SALES_CHANNELS = {"sales", "retention", "upsell", "marketing", "outbound"}


class TCPAComplianceValidator:
    """Detects TCPA-violating content in AI responses.

    Flags responses that contain telemarketing language, auto-dial
    recommendations, or DNC bypass suggestions. Severity depends on
    whether the interaction is a sales context and whether consent
    has been verified.
    """

    rule_name: str = "tcpa_compliance"
    severity: str = "high"

    async def evaluate(self, ctx: TelecomTraceContext) -> GuardrailResult:
        issues: list[str] = []
        evidence: dict[str, list[str]] = {}
        is_sales = ctx.call_reason.lower() in _SALES_CHANNELS

        # Check for DNC bypass — always critical
        dnc_matches = []
        for pat in _DNC_PATTERNS:
            for m in pat.finditer(ctx.response):
                dnc_matches.append(m.group().strip())
        if dnc_matches:
            evidence["dnc_violations"] = dnc_matches
            issues.append(f"{len(dnc_matches)} DNC bypass reference(s)")

        # Check for auto-dialer recommendations
        auto_matches = []
        for pat in _AUTODIALER_PATTERNS:
            for m in pat.finditer(ctx.response):
                auto_matches.append(m.group().strip())
        if auto_matches:
            evidence["autodialer_references"] = auto_matches
            issues.append(f"{len(auto_matches)} auto-dialer reference(s)")

        # Check for unsolicited marketing language
        marketing_matches = []
        for pat in _MARKETING_PATTERNS:
            for m in pat.finditer(ctx.response):
                marketing_matches.append(m.group().strip())
        if marketing_matches:
            evidence["marketing_language"] = marketing_matches
            issues.append(f"{len(marketing_matches)} marketing phrase(s)")

        if not issues:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity="low",
                action="pass",
                details="No TCPA concerns detected.",
                regulation="47 USC 227",
            )

        # Severity: DNC bypass = critical, autodialer = high, marketing = medium
        if dnc_matches:
            severity = "critical"
            action = "block"
        elif auto_matches:
            severity = "high"
            action = "block"
        elif is_sales:
            severity = "medium"
            action = "warn"
        else:
            severity = "low"
            action = "warn"

        evidence["call_reason"] = [ctx.call_reason]
        evidence["is_sales_context"] = [str(is_sales)]

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=False,
            severity=severity,
            action=action,
            details=f"TCPA issues: {'; '.join(issues)}.",
            regulation="47 USC 227 / 47 CFR 64.1200",
            evidence=evidence,
        )
