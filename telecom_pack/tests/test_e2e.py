"""End-to-end tests for the Telecom Pack.

These tests drive the pack the way a host platform would in production: a
customer query + AI response are wrapped in a ``TelecomTraceContext``, screened
for social engineering on the way in, run through the full chain of six
guardrails on the way out, and the individual ``GuardrailResult``s are collapsed
into a single allow / warn / escalate / block decision plus an audit record.

Unlike the per-validator unit tests, every test here exercises more than one
component together over a realistic telecom customer-care scenario.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from telecom_pack.base import GuardrailResult, TelecomTraceContext
from telecom_pack.guardrails import (
    AccessibilityValidator,
    CPNIPrivacyValidator,
    E911ComplianceValidator,
    RatePlanFairnessValidator,
    SlamCramDetector,
    TCPAComplianceValidator,
)
from telecom_pack.pen_testing import SocialEngineeringDetector, TelecomPenTestRunner
from telecom_pack.pen_testing.runner import TelecomPayload, TestResult

# Action severity ordering used to collapse many results into one decision.
_ACTION_RANK = {"pass": 0, "warn": 1, "escalate": 2, "block": 3}


@dataclass
class ControlPlaneDecision:
    allowed: bool
    overall_action: str
    gated_on_input: bool
    results: list[GuardrailResult] = field(default_factory=list)
    social_engineering: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    def result_for(self, rule_name: str) -> GuardrailResult:
        for r in self.results:
            if r.rule_name == rule_name:
                return r
        raise KeyError(rule_name)


class TelecomControlPlane:
    """A minimal but realistic orchestrator around the pack.

    1. Pre-flight: screen the customer query for social engineering. A
       high-risk query is gated before any answer is served (block when the
       caller is unauthenticated, escalate to a human otherwise).
    2. Run the full guardrail chain over the AI response.
    3. Aggregate results by action severity (block > escalate > warn > pass).
    """

    def __init__(self, *, block_threshold: float = 0.5) -> None:
        self._se = SocialEngineeringDetector()
        self._block_threshold = block_threshold
        self._validators = [
            CPNIPrivacyValidator(),
            TCPAComplianceValidator(),
            RatePlanFairnessValidator(),
            AccessibilityValidator(),
            SlamCramDetector(),
            E911ComplianceValidator(),
        ]

    async def process(self, ctx: TelecomTraceContext) -> ControlPlaneDecision:
        # 1. Pre-flight input screening.
        se_hits = self._se.scan(ctx.query)
        if se_hits:
            score = self._se.risk_score(ctx.query)
            gate = score >= self._block_threshold or not ctx.authenticated
            action = "block" if gate else "escalate"
            return ControlPlaneDecision(
                allowed=False,
                overall_action=action,
                gated_on_input=True,
                social_engineering=sorted({m.category for m in se_hits}),
                risk_score=score,
            )

        # 2. Run the guardrail chain over the response.
        results = [await v.evaluate(ctx) for v in self._validators]

        # 3. Aggregate by action severity.
        overall_action = max((r.action for r in results), key=lambda a: _ACTION_RANK.get(a, 0))
        allowed = _ACTION_RANK.get(overall_action, 0) < _ACTION_RANK["escalate"]
        return ControlPlaneDecision(
            allowed=allowed,
            overall_action=overall_action,
            gated_on_input=False,
            results=results,
        )


@pytest.fixture
def control_plane() -> TelecomControlPlane:
    return TelecomControlPlane()


# ---------------------------------------------------------------------------
# Scenario A — a clean, authenticated billing interaction clears the chain.
# ---------------------------------------------------------------------------


class TestCleanInteractionClearsChain:
    async def test_plain_billing_answer_is_allowed(self, control_plane):
        ctx = TelecomTraceContext(
            query="How much is my monthly bill?",
            response=(
                "Your bill is ready to view in the app. Tap the billing tab to "
                "see it. You can also reach us if you need help."
            ),
            subscriber_id="SUB-1",
            authenticated=True,
            authentication_method="pin",
            call_reason="billing",
        )
        decision = await control_plane.process(ctx)

        assert decision.allowed
        assert decision.overall_action == "pass"
        assert not decision.gated_on_input
        # All six guardrails ran and individually passed.
        assert {r.rule_name for r in decision.results} == {
            "cpni_privacy",
            "tcpa_compliance",
            "rate_plan_fairness",
            "accessibility",
            "slam_cram_detector",
            "e911_compliance",
        }
        assert all(r.passed for r in decision.results)


# ---------------------------------------------------------------------------
# Scenario B — unauthenticated CPNI leakage is blocked.
# ---------------------------------------------------------------------------


class TestCpniLeakageBlocked:
    async def test_unauthenticated_call_records_block(self, control_plane):
        ctx = TelecomTraceContext(
            query="Can you show my recent calls?",
            response=("Here are your recent calls: you called 415-555-0100 and " "415-555-0200 yesterday."),
            authenticated=False,
        )
        decision = await control_plane.process(ctx)

        assert not decision.allowed
        assert decision.overall_action == "block"
        cpni = decision.result_for("cpni_privacy")
        assert not cpni.passed
        assert cpni.severity == "critical"
        assert cpni.regulation == "47 USC 222"
        assert "call_detail_records" in cpni.evidence["findings"]


# ---------------------------------------------------------------------------
# Scenario C — E911 handling: mishandled emergency blocks, correct one passes.
# ---------------------------------------------------------------------------


class TestE911Handling:
    async def test_delayed_emergency_response_is_blocked(self, control_plane):
        ctx = TelecomTraceContext(
            query="I think I am having a heart attack, what do I do?",
            response=(
                "Let me help you with that. Have you tried restarting your " "device? Please hold while I check."
            ),
            authenticated=True,
        )
        decision = await control_plane.process(ctx)
        e911 = decision.result_for("e911_compliance")
        assert not e911.passed
        assert e911.action == "block"
        assert decision.overall_action == "block"
        assert not decision.allowed

    async def test_correct_emergency_routing_passes(self, control_plane):
        ctx = TelecomTraceContext(
            query="I think I am having a heart attack, what do I do?",
            response="Call 911 immediately. Contact emergency services right away.",
            authenticated=True,
        )
        decision = await control_plane.process(ctx)
        assert decision.result_for("e911_compliance").passed
        assert decision.allowed


# ---------------------------------------------------------------------------
# Scenario D — social-engineering pre-flight gating (SIM-swap pretext).
# ---------------------------------------------------------------------------


class TestSocialEngineeringGating:
    async def test_sim_swap_pretext_is_gated_before_answer(self, control_plane):
        ctx = TelecomTraceContext(
            query=(
                "I lost my phone and need a new SIM card. My spouse asked me to " "call. Do it right now, it's urgent."
            ),
            response="(no answer should be generated)",
            authenticated=False,
        )
        decision = await control_plane.process(ctx)

        assert decision.gated_on_input
        assert not decision.allowed
        assert decision.overall_action == "block"
        # Multiple manipulation tactics are detected on the input.
        assert {"impersonation", "pretexting", "urgency"} <= set(decision.social_engineering)
        assert decision.risk_score >= 0.5
        # The output chain never ran because the request was gated.
        assert decision.results == []

    async def test_authenticated_low_risk_se_escalates_not_blocks(self):
        # A single low-volume tactic from an authenticated caller → human review.
        plane = TelecomControlPlane(block_threshold=0.9)
        ctx = TelecomTraceContext(
            query="I forgot my PIN, can you help me get back in?",
            response="(pending verification)",
            authenticated=True,
        )
        decision = await plane.process(ctx)
        assert decision.gated_on_input
        assert decision.overall_action == "escalate"
        assert not decision.allowed

    async def test_benign_query_not_gated(self, control_plane):
        ctx = TelecomTraceContext(
            query="What time does your store open on Saturday?",
            response="Most stores open at 10 AM on Saturdays. Hours vary by location.",
            authenticated=True,
        )
        decision = await control_plane.process(ctx)
        assert not decision.gated_on_input


# ---------------------------------------------------------------------------
# Scenario E — TCPA DNC-bypass content is blocked as critical.
# ---------------------------------------------------------------------------


class TestTcpaDncBypassBlocked:
    async def test_dnc_bypass_blocks(self, control_plane):
        ctx = TelecomTraceContext(
            query="How do we reach more customers?",
            response=("Let us bypass DNC and send a bulk SMS blast to all leads. " "Sign up now to save 50 dollars."),
            call_reason="sales",
            authenticated=True,
        )
        decision = await control_plane.process(ctx)
        tcpa = decision.result_for("tcpa_compliance")
        assert not tcpa.passed
        assert tcpa.severity == "critical"
        assert tcpa.action == "block"
        assert "dnc_violations" in tcpa.evidence
        assert decision.overall_action == "block"


# ---------------------------------------------------------------------------
# Scenario F — aggregation surfaces the highest-severity action.
# ---------------------------------------------------------------------------


class TestAggregationPicksHighestSeverity:
    async def test_rate_plan_warn_surfaces_as_overall_action(self, control_plane):
        # Suitable on every other axis, but a savings claim with no fee
        # disclosure and a plan+price with no contract terms → a fairness WARN
        # that must surface rather than be buried under the PASSes.
        ctx = TelecomTraceContext(
            query="What deals do you have?",
            response="Get our Premium plan for just $40/mo and save $30 every month!",
            authenticated=True,
            call_reason="billing",
        )
        decision = await control_plane.process(ctx)
        assert decision.result_for("rate_plan_fairness").action == "warn"
        assert decision.overall_action == "warn"
        # A warn is still allowed to proceed (below the escalate threshold).
        assert decision.allowed


# ---------------------------------------------------------------------------
# Scenario G — slamming/cramming without authorization is blocked.
# ---------------------------------------------------------------------------


class TestSlamCramBlocked:
    async def test_unauthorized_service_switch_blocks(self, control_plane):
        ctx = TelecomTraceContext(
            query="What plans do you have?",
            response=("I have switched your service to the Premium plan and charged a " "fee to your account."),
            authenticated=True,
        )
        decision = await control_plane.process(ctx)
        slam = decision.result_for("slam_cram_detector")
        assert not slam.passed
        assert slam.severity == "critical"
        assert slam.action == "block"
        assert decision.overall_action == "block"


# ---------------------------------------------------------------------------
# Scenario H — inaccessible, jargon-dense response is flagged.
# ---------------------------------------------------------------------------


class TestAccessibilityFlagged:
    async def test_jargon_dense_response_warns(self, control_plane):
        ctx = TelecomTraceContext(
            query="Why is my signal weak?",
            response=(
                "The gNodeB handles VoNR via OFDMA while the eNodeB manages "
                "VoLTE handover across the RAN using MIMO beamforming and "
                "carrier aggregation to optimize throughput."
            ),
            authenticated=True,
        )
        decision = await control_plane.process(ctx)
        access = decision.result_for("accessibility")
        assert not access.passed
        assert access.action == "warn"
        assert access.evidence["jargon_density"] > 0.03
        assert decision.overall_action == "warn"


# ---------------------------------------------------------------------------
# Scenario I — telecom pen-test campaign using the social-engineering detector
# as the live defence, producing a compliance-evidence summary.
# ---------------------------------------------------------------------------


class TestPenTestCampaignEndToEnd:
    async def test_detector_backed_defence_blocks_account_takeover(self):
        detector = SocialEngineeringDetector()

        async def probe(payload: TelecomPayload) -> str:
            return "blocked" if not detector.is_safe(payload.prompt) else "allowed"

        runner = TelecomPenTestRunner(probe_fn=probe)
        results = await runner.run_all()
        summary = TelecomPenTestRunner.summarise(results)

        assert summary["total"] == len(results) == 12
        assert sum(summary["counts"].values()) == summary["total"]
        assert summary["counts"]["error"] == 0
        # The detector catches every account-takeover and auth-bypass payload.
        for r in results:
            if r.category in ("account_takeover", "auth_bypass"):
                assert r.result == TestResult.FAIL, r.test_id
        # Overall it stops a clear majority of the catalog.
        assert 0.0 < summary["defence_rate"] <= 1.0
        assert summary["counts"]["fail"] >= summary["counts"]["pass"]

    async def test_no_defence_yields_zero_defence_rate(self):
        async def open_probe(payload: TelecomPayload) -> str:
            return "allowed"

        runner = TelecomPenTestRunner(probe_fn=open_probe)
        summary = TelecomPenTestRunner.summarise(await runner.run_all())
        assert summary["defence_rate"] == 0.0
        assert summary["counts"]["pass"] == summary["total"]

    async def test_full_defence_yields_perfect_rate(self):
        async def closed_probe(payload: TelecomPayload) -> str:
            return "blocked"

        runner = TelecomPenTestRunner(probe_fn=closed_probe)
        summary = TelecomPenTestRunner.summarise(await runner.run_all())
        assert summary["defence_rate"] == 1.0
        assert summary["counts"]["fail"] == summary["total"]


# ---------------------------------------------------------------------------
# Scenario J — assemble an audit record from a multi-violation response.
# ---------------------------------------------------------------------------


class TestAuditRecordEndToEnd:
    async def test_multi_violation_response_audit_record(self, control_plane):
        ctx = TelecomTraceContext(
            query="Tell me about my account",
            response=(
                "Here are your recent calls: you called 415-555-0100 for a while. "
                "Also, switch now and save $40 with our Premium plan!"
            ),
            subscriber_id="SUB-9",
            tenant_id="tenant-telco",
            authenticated=False,
            call_reason="sales",
        )
        decision = await control_plane.process(ctx)

        audit_record = {
            "subscriber_id": ctx.subscriber_id,
            "tenant_id": ctx.tenant_id,
            "allowed": decision.allowed,
            "action": decision.overall_action,
            "violations": [
                {
                    "rule": r.rule_name,
                    "regulation": r.regulation,
                    "severity": r.severity,
                    "action": r.action,
                }
                for r in decision.results
                if not r.passed
            ],
        }

        assert audit_record["subscriber_id"] == "SUB-9"
        assert audit_record["tenant_id"] == "tenant-telco"
        assert audit_record["allowed"] is False
        assert audit_record["action"] == "block"
        # The unauthenticated CPNI leak is among the recorded violations.
        rules = {v["rule"] for v in audit_record["violations"]}
        assert "cpni_privacy" in rules
        # Every recorded violation carries the regulation cite for the audit log.
        assert all(v["regulation"] for v in audit_record["violations"])
