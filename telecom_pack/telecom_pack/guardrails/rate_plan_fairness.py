"""Rate Plan Fairness Validator — FCC Truth-in-Billing / FTC Act Section 5.

FCC Truth-in-Billing rules (47 CFR 64.2400-2401) require that bills
be clearly organized, use plain language, and not contain misleading
descriptions. FTC Act Section 5 prohibits unfair or deceptive acts.

This validator detects when AI-generated responses:
- Make misleading savings claims without substantiation
- Omit material fees, taxes, or surcharges from plan comparisons
- Use deceptive comparison tactics (cherry-picked metrics)
- Recommend downgrades disguised as upgrades
- Fail to disclose early termination fees or contract terms
"""

from __future__ import annotations

import re

from telecom_pack.base import GuardrailResult, TelecomTraceContext

# Unsubstantiated savings claims
_SAVINGS_PATTERNS = [
    re.compile(r"\bsave\s+(?:up\s+to\s+)?\$?\d+", re.IGNORECASE),
    re.compile(r"\b\d+%\s+(?:off|cheaper|less|savings?|discount)", re.IGNORECASE),
    re.compile(r"\b(?:cut|reduce|lower)\s+your\s+bill\s+by\b", re.IGNORECASE),
    re.compile(r"\bhalf\s+(?:the\s+)?(?:price|cost)\b", re.IGNORECASE),
]

# Fee omission indicators — response mentions a plan but no fees/taxes
_FEE_TERMS = re.compile(
    r"\b(?:activation\s+fee|early\s+termination|ETF|surcharge|regulatory\s+fee"
    r"|admin(?:istrative)?\s+fee|taxes?\s+and\s+fees?"
    r"|device\s+payment|installment|autopay\s+(?:discount|required))\b",
    re.IGNORECASE,
)

_PLAN_MENTION = re.compile(
    r"\b(?:plan|package|bundle|tier|unlimited|premium|basic|essential|start|plus|pro)\b",
    re.IGNORECASE,
)

_PRICE_MENTION = re.compile(r"\$\d+(?:\.\d{2})?(?:\s*/\s*(?:mo|month|line))?", re.IGNORECASE)

# Deceptive comparison patterns
_DECEPTIVE_COMPARISON = [
    re.compile(r"\b(?:better|superior|faster)\s+(?:in\s+every\s+way|than\s+(?:your|the)\s+current)", re.IGNORECASE),
    re.compile(r"\bno\s+(?:reason|downside)\s+(?:not\s+)?to\s+(?:switch|upgrade)", re.IGNORECASE),
    re.compile(r"\b(?:exactly|just)\s+the\s+same\s+(?:but|except)\s+cheaper", re.IGNORECASE),
]

# Contract term omission
_CONTRACT_TERMS = re.compile(
    r"\b(?:contract|agreement|commitment|term)\s*(?:length|period|duration)?"
    r"(?:\s*[:=]\s*\d+\s*(?:month|year|mo|yr))?\b",
    re.IGNORECASE,
)


class RatePlanFairnessValidator:
    """Detects misleading plan comparisons and fee omissions.

    Checks:
    1. Savings claims present → must also mention fees/taxes
    2. Plan recommendation present → must mention contract terms
    3. No deceptive absolute comparison language
    """

    rule_name: str = "rate_plan_fairness"
    severity: str = "medium"

    async def evaluate(self, ctx: TelecomTraceContext) -> GuardrailResult:
        issues: list[str] = []
        evidence: dict[str, list[str]] = {}

        has_plan = bool(_PLAN_MENTION.search(ctx.response))
        has_price = bool(_PRICE_MENTION.search(ctx.response))
        has_fees_disclosed = bool(_FEE_TERMS.search(ctx.response))
        has_contract_disclosed = bool(_CONTRACT_TERMS.search(ctx.response))

        # Check savings claims
        savings_matches = []
        for pat in _SAVINGS_PATTERNS:
            for m in pat.finditer(ctx.response):
                savings_matches.append(m.group().strip())
        if savings_matches and not has_fees_disclosed:
            evidence["savings_claims_without_fees"] = savings_matches
            issues.append(f"{len(savings_matches)} savings claim(s) without fee disclosure")

        # Check plan recommendation without contract terms
        if has_plan and has_price and not has_contract_disclosed:
            issues.append("Plan recommendation without contract/term disclosure")
            evidence["plan_without_terms"] = ["plan + price mentioned, no contract terms"]

        # Check deceptive comparison language
        deceptive_matches = []
        for pat in _DECEPTIVE_COMPARISON:
            for m in pat.finditer(ctx.response):
                deceptive_matches.append(m.group().strip())
        if deceptive_matches:
            evidence["deceptive_comparison"] = deceptive_matches
            issues.append(f"{len(deceptive_matches)} deceptive comparison phrase(s)")

        if not issues:
            return GuardrailResult(
                rule_name=self.rule_name,
                passed=True,
                severity="low",
                action="pass",
                details="No rate plan fairness concerns detected.",
                regulation="47 CFR 64.2401 / FTC Act Sec 5",
            )

        severity = "high" if deceptive_matches else "medium"
        action = "warn"

        return GuardrailResult(
            rule_name=self.rule_name,
            passed=False,
            severity=severity,
            action=action,
            details=f"Fairness issues: {'; '.join(issues)}.",
            regulation="47 CFR 64.2401 / FTC Act Sec 5",
            evidence=evidence,
        )
