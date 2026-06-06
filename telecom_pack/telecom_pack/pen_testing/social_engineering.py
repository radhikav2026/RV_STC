"""Social engineering detection for telecom AI interactions.

Detects attempts to manipulate AI customer service into:
- Revealing CPNI or account details without proper authentication
- Performing unauthorized account changes (SIM swaps, port-outs)
- Bypassing identity verification procedures
- Extracting network infrastructure information
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SocialEngineeringMatch:
    """A single social engineering detection hit."""

    rule: str
    snippet: str
    category: str  # impersonation | pretexting | elicitation | urgency


# --- Detection Rules ---

_IMPERSONATION_RULES = [
    (
        "impersonation.employee",
        re.compile(
            r"\b(?:I(?:'m| am)\s+(?:a|an|the)\s+)?"
            r"(?:manager|supervisor|technician|engineer|employee|agent|rep(?:resentative)?)"
            r"\s+(?:at|from|with|for)\s+(?:the\s+)?(?:company|corporate|HQ|headquarters)",
            re.IGNORECASE,
        ),
    ),
    (
        "impersonation.authority",
        re.compile(
            r"\b(?:I(?:'m| am)\s+(?:calling|writing)\s+from\s+)"
            r"(?:the\s+)?(?:FCC|FBI|police|law\s+enforcement|court|attorney|legal)",
            re.IGNORECASE,
        ),
    ),
    (
        "impersonation.account_holder",
        re.compile(
            r"\b(?:my\s+(?:husband|wife|spouse|partner|parent|child|son|daughter)"
            r"\s+(?:asked|told|wants)\s+me\s+to\s+(?:call|change|cancel|add|remove))\b",
            re.IGNORECASE,
        ),
    ),
]

_PRETEXTING_RULES = [
    (
        "pretexting.sim_swap",
        re.compile(
            r"\b(?:lost|stolen|damaged|broken)\s+(?:my\s+)?(?:phone|device|SIM|handset)"
            r"|(?:SIM\s+(?:swap|replacement|change))"
            r"|(?:new\s+SIM\s+(?:card|for))",
            re.IGNORECASE,
        ),
    ),
    (
        "pretexting.port_out",
        re.compile(
            r"\b(?:port(?:ing)?\s+(?:out|my\s+number|to\s+(?:another|a\s+new))"
            r"|transfer(?:ring)?\s+(?:my\s+)?number"
            r"|(?:account|transfer)\s+(?:PIN|number|code))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "pretexting.password_reset",
        re.compile(
            r"\b(?:forgot|lost|can'?t\s+(?:remember|access))\s+(?:my\s+)?"
            r"(?:password|PIN|passcode|security\s+(?:question|answer))\b",
            re.IGNORECASE,
        ),
    ),
]

_ELICITATION_RULES = [
    (
        "elicitation.network_info",
        re.compile(
            r"\b(?:what\s+(?:is|are)\s+(?:the|your)\s+)?"
            r"(?:cell\s+tower|base\s+station|network\s+(?:config|topology|infrastructure)"
            r"|IP\s+range|subnet|VLAN|routing\s+table|BGP|peering)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "elicitation.account_details",
        re.compile(
            r"\b(?:what(?:'s| is)\s+(?:the|my)\s+)?"
            r"(?:account\s+number|billing\s+address|SSN|social\s+security"
            r"|last\s+four|payment\s+(?:method|info|details)|credit\s+card)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "elicitation.usage_data",
        re.compile(
            r"\b(?:who\s+(?:did\s+I\s+call|called\s+me)"
            r"|(?:my\s+)?call\s+(?:history|log|records)"
            r"|(?:my\s+)?(?:text|SMS|message)\s+(?:history|log|records)"
            r"|(?:my\s+)?(?:data|browsing)\s+(?:history|usage))\b",
            re.IGNORECASE,
        ),
    ),
]

_URGENCY_RULES = [
    (
        "urgency.pressure",
        re.compile(
            r"\b(?:(?:do\s+it\s+)?(?:right\s+)?now|immediately|ASAP|urgent(?:ly)?"
            r"|(?:this\s+is\s+(?:an?\s+)?)?emergency|time[- ]sensitive"
            r"|(?:I(?:'m| am)\s+)?(?:in\s+a\s+)?(?:hurry|rush))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "urgency.threat",
        re.compile(
            r"\b(?:(?:I(?:'ll| will)\s+)?(?:sue|report|complain|cancel|escalate|contact)"
            r"\s+(?:if|unless|you(?:r\s+(?:manager|supervisor))?))"
            r"|(?:(?:your|the)\s+)?(?:manager|supervisor|legal)\b",
            re.IGNORECASE,
        ),
    ),
]

_ALL_RULES: list[tuple[str, list[tuple[str, re.Pattern[str]]]]] = [
    ("impersonation", _IMPERSONATION_RULES),
    ("pretexting", _PRETEXTING_RULES),
    ("elicitation", _ELICITATION_RULES),
    ("urgency", _URGENCY_RULES),
]


class SocialEngineeringDetector:
    """Detects social engineering attempts in telecom customer interactions.

    Scans the *query* (customer input) for manipulation tactics.
    Returns a list of matches with category labels for audit evidence.
    """

    def scan(self, text: str) -> list[SocialEngineeringMatch]:
        """Return all social engineering indicators found in *text*."""
        matches: list[SocialEngineeringMatch] = []
        for category, rules in _ALL_RULES:
            for rule_name, pattern in rules:
                for m in pattern.finditer(text):
                    matches.append(
                        SocialEngineeringMatch(
                            rule=rule_name,
                            snippet=m.group().strip(),
                            category=category,
                        )
                    )
        return matches

    def is_safe(self, text: str) -> bool:
        """Return True if no social engineering indicators are detected."""
        return len(self.scan(text)) == 0

    def risk_score(self, text: str) -> float:
        """Return a 0.0-1.0 risk score based on category coverage.

        Higher score = more categories triggered = higher manipulation risk.
        """
        matches = self.scan(text)
        if not matches:
            return 0.0
        categories_hit = {m.category for m in matches}
        # 4 categories total; score by coverage + volume
        coverage = len(categories_hit) / 4.0
        volume = min(len(matches) / 10.0, 1.0)
        return round(min(0.6 * coverage + 0.4 * volume, 1.0), 2)
