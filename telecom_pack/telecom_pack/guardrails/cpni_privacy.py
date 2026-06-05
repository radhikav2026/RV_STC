"""CPNI Privacy Validator — 47 USC Section 222.

Customer Proprietary Network Information (CPNI) includes call records,
call location data, service usage patterns, and network information that
carriers collect in the course of providing service. Under federal law,
carriers may not disclose CPNI without customer approval, except for
the purpose of providing the service itself.

This validator scans AI responses for potential CPNI leakage:
- Call detail records (CDRs): numbers called, call duration, timestamps
- Location data: cell tower IDs, GPS coordinates, location history
- Usage patterns: data consumption, browsing categories, app usage
- Network information: IP addresses, device identifiers, SIM data
- Account details when authentication is insufficient
"""

from __future__ import annotations

import re

from telecom_pack.base import GuardrailResult, TelecomTraceContext

# Patterns that indicate CPNI data in a response
_CDR_PATTERNS = [
    re.compile(r"\b(?:called|dialed|received from)\b[^.\n]{0,40}\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", re.IGNORECASE),
    re.compile(r"\bcall(?:ed|s)?\s+(?:on|at)\s+\d{1,2}[:/]\d{2}", re.IGNORECASE),
    re.compile(r"\b(?:call\s+)?duration\s*[:=]?\s*\d+\s*(?:min|sec|hour|minute|second)", re.IGNORECASE),
    re.compile(r"\b(?:incoming|outgoing|missed)\s+calls?\s*[:=]?\s*\d+", re.IGNORECASE),
]

_LOCATION_PATTERNS = [
    re.compile(r"\bcell\s*(?:tower|site|id)\s*[:=#]?\s*\w+", re.IGNORECASE),
    re.compile(r"\blat(?:itude)?\s*[:=]\s*[-]?\d+\.\d+", re.IGNORECASE),
    re.compile(r"\blon(?:gitude)?\s*[:=]\s*[-]?\d+\.\d+", re.IGNORECASE),
    re.compile(r"\b(?:location|located|pinged|triangulated)\s+(?:at|near|around)\b", re.IGNORECASE),
    re.compile(r"\bgps\s+coordinates?\b", re.IGNORECASE),
]

_USAGE_PATTERNS = [
    re.compile(r"\b\d+(?:\.\d+)?\s*(?:GB|MB|TB)\b", re.IGNORECASE),
    re.compile(r"\bbrowsing\s+(?:history|pattern|categories)", re.IGNORECASE),
    re.compile(r"\bapp\s+usage\s+(?:data|pattern|history)", re.IGNORECASE),
    re.compile(r"\bstreaming\s+(?:hours?|minutes?|consumption)", re.IGNORECASE),
]

_NETWORK_PATTERNS = [
    re.compile(r"\bIMEI\b[^.\n]{0,20}\d{15}", re.IGNORECASE),
    re.compile(r"\bIMSI\b[^.\n]{0,20}\d{15}", re.IGNORECASE),
    re.compile(r"\bICCID\b[^.\n]{0,20}\d{19,20}", re.IGNORECASE),
    re.compile(r"\bMSISDN\b[^.\n]{0,20}\+?\d{10,15}", re.IGNORECASE),
    re.compile(r"\bMAC\s*(?:address)?\s*[:=]?\s*(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", re.IGNORECASE),
    re.compile(r"\bIP\s*(?:address)?\b[^.\n]{0,15}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
]

_ALL_PATTERNS: list[tuple[str, list[re.Pattern[str]]]] = [
    ("call_detail_records", _CDR_PATTERNS),
    ("location_data", _LOCATION_PATTERNS),
    ("usage_patterns", _USAGE_PATTERNS),
    ("network_identifiers", _NETWORK_PATTERNS),
]


class CPNIPrivacyValidator:
    """Detects CPNI leakage in AI-generated responses.

    Severity escalates when:
    - Authentication is missing or weak
    - Multiple CPNI categories are exposed in one response
    - Location data is present (highest sensitivity)
    """

    rule_name: str = "cpni_privacy"
    severity: str = "critical"

    async def evaluate(self, ctx: TelecomTraceContext) -> GuardrailResult:
        findings: dict[str, list[str]] = {}

        for category, patterns in _ALL_PATTERNS:
            matches: list[str] = []
            for pat in patterns:
                for m in pat.finditer(ctx.response):
                    matches.append(m.group().strip())
            if matches:
                findings[category] = matches

        if not findings:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity="low",
                action="pass",
                details="No CPNI data detected in response.",
                regulation="47 USC 222",
            )

        # Severity escalation — each factor independently raises severity:
        #   critical+block: unauthenticated, multi-category, or location data
        #   high+warn:      single non-location category, authenticated
        category_count = len(findings)
        has_location = "location_data" in findings
        unauthenticated = not ctx.authenticated

        if unauthenticated or category_count >= 2 or has_location:
            severity = "critical"
            action = "block"
        else:
            severity = "high"
            action = "warn"

        total_matches = sum(len(v) for v in findings.values())
        categories = sorted(findings.keys())

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=False,
            severity=severity,
            action=action,
            details=(
                f"CPNI leakage detected: {total_matches} match(es) across "
                f"{categories}. Authenticated={ctx.authenticated}."
            ),
            regulation="47 USC 222",
            evidence={
                "findings": {k: v[:5] for k, v in findings.items()},
                "categories": categories,
                "authenticated": ctx.authenticated,
                "authentication_method": ctx.authentication_method,
                "subscriber_id": ctx.subscriber_id,
            },
        )
