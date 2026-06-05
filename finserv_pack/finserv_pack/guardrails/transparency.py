"""AI transparency & disclosure validator.

SEC guidance and MiFID II require that clients be informed when AI is
used to generate financial advice/recommendations. This module:

1. Validates that AI-generated client-facing output includes a required
   disclosure statement.
2. Tracks customer consent for AI-generated interactions.

Extracted from: stc_framework/compliance/transparency.py (MIT license)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from finserv_pack.base import GuardrailResult, TraceContext

DEFAULT_DISCLOSURE = (
    "This response was generated with the assistance of an AI system. "
    "It is for informational purposes only and does not constitute investment advice."
)


@dataclass
class ConsentRecord:
    customer_id: str
    tenant_id: str
    consented: bool
    consented_at: str = ""
    revoked_at: str | None = None
    version: str = "v1"


class TransparencyValidator:
    """Validates AI disclosure is present and consent is recorded.

    Usage:
        validator = TransparencyValidator(disclosure_text="AI-generated content.")
        result = await validator.evaluate(ctx)

        # Or use directly:
        stamped = validator.apply_disclosure("Here is your portfolio analysis...")
    """

    rule_name = "ai_transparency"
    severity = "high"

    def __init__(
        self,
        *,
        disclosure_text: str = DEFAULT_DISCLOSURE,
        require_disclosure: bool = True,
        consent_store: dict[str, ConsentRecord] | None = None,
    ) -> None:
        self._disclosure = disclosure_text
        self._require_disclosure = require_disclosure
        self._consent_store: dict[str, ConsentRecord] = consent_store or {}

    def apply_disclosure(self, content: str, *, prepend: bool = False) -> str:
        """Stamp content with the disclosure notice (idempotent)."""
        if self._disclosure in content:
            return content
        if prepend:
            return f"{self._disclosure}\n\n{content}"
        return f"{content}\n\n— {self._disclosure}"

    def has_disclosure(self, content: str) -> bool:
        """Check if content already contains the disclosure."""
        return self._disclosure in content

    def record_consent(
        self,
        *,
        tenant_id: str,
        customer_id: str,
        consented: bool,
        version: str = "v1",
    ) -> ConsentRecord:
        """Record customer consent for AI-generated interactions."""
        now = datetime.now(timezone.utc).isoformat()
        record = ConsentRecord(
            customer_id=customer_id,
            tenant_id=tenant_id,
            consented=consented,
            consented_at=now if consented else "",
            revoked_at=now if not consented else None,
            version=version,
        )
        key = f"{tenant_id}:{customer_id}"
        self._consent_store[key] = record
        return record

    def check_consent(self, *, tenant_id: str, customer_id: str) -> bool:
        """Check if customer has consented to AI interactions."""
        key = f"{tenant_id}:{customer_id}"
        record = self._consent_store.get(key)
        return bool(record and record.consented)

    async def evaluate(self, ctx: TraceContext) -> GuardrailResult:
        """Evaluate via the generic Validator interface.

        Checks:
        1. If require_disclosure=True, verifies the response contains
           the disclosure statement.
        2. If ctx.metadata contains "customer_id", verifies consent.
        """
        issues: list[str] = []
        evidence: dict[str, Any] = {}

        # Check disclosure
        if self._require_disclosure and not self.has_disclosure(ctx.response):
            issues.append("AI disclosure missing from client-facing response")
            evidence["disclosure_present"] = False
        else:
            evidence["disclosure_present"] = True

        # Check consent if customer info available
        customer_id = ctx.metadata.get("customer_id")
        if customer_id and ctx.tenant_id:
            has_consent = self.check_consent(
                tenant_id=ctx.tenant_id, customer_id=customer_id
            )
            evidence["customer_consent"] = has_consent
            if not has_consent:
                issues.append(
                    f"Customer {customer_id} has not consented to AI interactions"
                )

        passed = len(issues) == 0
        return GuardrailResult(
            rule_name=self.rule_name,
            passed=passed,
            severity=self.severity,
            action="pass" if passed else "warn",
            details="; ".join(issues) if issues else "Disclosure present, consent verified",
            evidence=evidence,
        )
