"""Tests for the VeryTrace / EngineInput → TraceContext adapter."""

import pytest

from finserv_pack.adapter import from_engine_input, from_verytrace
from finserv_pack.base import TraceContext


SAMPLE_RAW_TRACE = {
    "verytrace_id": "vt-abc-123",
    "created_at": "2026-06-05T14:00:00Z",
    "event_ref": {
        "event_id": "ev-1",
        "span_id": "sp-1",
        "run_id": "run-1",
        "trace_id": "tr-1",
    },
    "operator_identity": {
        "operator_id": "user-1",
        "tenant_id": "tenant-1",
    },
    "llm_payload": {
        "input_data": {
            "messages": [
                {"role": "system", "content": "You are a financial advisor."},
                {"role": "user", "content": "What should I invest in?"},
            ],
            "instructions": "Be conservative in recommendations.",
        },
        "output_data": {"content": "Consider treasury bonds for stable returns."},
        "thinking": "User appears to want safe investment options.",
        "reasoning": "Based on market conditions, bonds are appropriate.",
    },
    "engine_input": {
        "input_id": "ei-001",
        "agent_type_hash": "hash-1",
        "agent_instance_key": "inst-1",
        "agent_card": {
            "identity": {"agent_id": "fin-advisor", "name": "Financial Advisor", "version": "1.0"},
            "avs_governance": {"owner": "team-wealth", "transparency_disclosure": {"required": True}},
            "avs_purpose": {
                "primary_goal": "provide investment guidance",
                "declared_risk_level": "medium",
                "deployment_context": {"environment": "production"},
            },
            "avs_authority": {"mandate": {}, "boundary_definition": {}},
            "avs_safety_controls": {
                "applied_controls": {"human_oversight_declared": True},
                "supply_chain": {"model_provenance": "anthropic", "dependencies": []},
            },
            "avs_registers": {"risk_register": {}, "control_register": {}},
        },
        "runtime_signals": {
            "upstream_errors": [],
            "resource_anomalies": [],
        },
        "history": {
            "prior_verdicts": [],
            "change_log": [],
            "feedback_log": [],
        },
    },
    "evaluation_context": {},
}


class TestFromVerytrace:
    def test_extracts_user_query(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.query == "What should I invest in?"

    def test_extracts_response(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.response == "Consider treasury bonds for stable returns."

    def test_extracts_trace_id(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.trace_id == "vt-abc-123"

    def test_extracts_tenant_id(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.tenant_id == "tenant-1"

    def test_extracts_model_id_from_supply_chain(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.model_id == "anthropic"

    def test_builds_context_from_thinking_and_reasoning(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert "User appears to want safe investment options" in ctx.context
        assert "bonds are appropriate" in ctx.context

    def test_metadata_contains_agent_card(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert "agent_card" in ctx.metadata
        assert ctx.metadata["agent_card"]["identity"]["agent_id"] == "fin-advisor"

    def test_metadata_contains_declared_risk_level(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.metadata["declared_risk_level"] == "medium"

    def test_metadata_contains_operator_id(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.metadata["operator_id"] == "user-1"

    def test_metadata_contains_instructions(self):
        ctx = from_verytrace(SAMPLE_RAW_TRACE)
        assert ctx.metadata["instructions"] == "Be conservative in recommendations."

    def test_handles_structured_reasoning_with_facts(self):
        raw = {
            **SAMPLE_RAW_TRACE,
            "llm_payload": {
                "input_data": {"messages": [{"role": "user", "content": "Revenue?"}]},
                "output_data": {"content": "Revenue was $4.2B."},
                "thinking": "",
                "reasoning": {
                    "context": "Q3 earnings call",
                    "assumptions": ["Based on filed 10-K"],
                    "facts_cited": ["Revenue: $4.2 billion", "Up 15% YoY"],
                    "conclusion": "Strong growth quarter.",
                },
            },
        }
        ctx = from_verytrace(raw)
        assert "Q3 earnings call" in ctx.context
        assert "Based on filed 10-K" in ctx.context
        assert len(ctx.source_chunks) == 2
        assert ctx.source_chunks[0]["text"] == "Revenue: $4.2 billion"

    def test_handles_empty_messages(self):
        raw = {
            "verytrace_id": "vt-empty",
            "llm_payload": {
                "input_data": {"messages": []},
                "output_data": {"content": "Hello"},
            },
        }
        ctx = from_verytrace(raw)
        assert ctx.query == ""
        assert ctx.response == "Hello"

    def test_handles_minimal_payload(self):
        raw = {"verytrace_id": "vt-minimal"}
        ctx = from_verytrace(raw)
        assert ctx.trace_id == "vt-minimal"
        assert ctx.query == ""
        assert ctx.response == ""

    def test_multi_turn_extracts_last_user_message(self):
        raw = {
            "verytrace_id": "vt-multi",
            "llm_payload": {
                "input_data": {
                    "messages": [
                        {"role": "user", "content": "Hello"},
                        {"role": "assistant", "content": "Hi there!"},
                        {"role": "user", "content": "What about crypto?"},
                    ]
                },
                "output_data": {"content": "Crypto is volatile."},
            },
        }
        ctx = from_verytrace(raw)
        assert ctx.query == "What about crypto?"


class TestFromEngineInput:
    """Test with mock Pydantic-like objects."""

    def test_extracts_from_typed_model(self):
        # Simulate a typed EngineInput with attrs
        class MockReasoningTrace:
            context = "Annual report data"
            assumptions = None
            facts_cited = ["Revenue: $10M", "EBITDA: $2M"]
            conclusion = "Profitable"

        class MockOperatorIdentity:
            operator_id = "user-99"
            tenant_id = "tenant-finco"
            role = "analyst"

        class MockTrace:
            run_id = "run-xyz"
            started_at = None
            ended_at = None
            duration_ms = 150.0
            operator_identity = MockOperatorIdentity()
            user_query = "What is the EBITDA margin?"
            final_output = "The EBITDA margin is 20% based on $2M EBITDA over $10M revenue."
            final_reasoning_trace = MockReasoningTrace()
            outcome = None
            spans = []

        class MockSupplyChain:
            model_provenance = "openai"
            dependencies = []

        class MockSafetyControls:
            applied_controls = None
            supply_chain = MockSupplyChain()

        class MockPurpose:
            primary_goal = "financial analysis"
            declared_risk_level = "low"
            deployment_context = None

        class MockGovernance:
            owner = "team-x"
            transparency_disclosure = None

        class MockAgentCard:
            identity = None
            capabilities = None
            skills = []
            avs_governance = MockGovernance()
            avs_purpose = MockPurpose()
            avs_authority = None
            avs_safety_controls = MockSafetyControls()
            avs_registers = None

        class MockEngineInput:
            schema_version = "1.0.0"
            input_id = "ei-typed-001"
            created_at = "2026-06-05T14:00:00Z"
            agent_card = MockAgentCard()
            trace = MockTrace()
            runtime_signals = None
            history = None

        ctx = from_engine_input(MockEngineInput())
        assert ctx.query == "What is the EBITDA margin?"
        assert "EBITDA margin is 20%" in ctx.response
        assert ctx.tenant_id == "tenant-finco"
        assert ctx.trace_id == "ei-typed-001"
        assert ctx.model_id == "openai"
        assert "Annual report data" in ctx.context
        assert len(ctx.source_chunks) == 2
        assert ctx.source_chunks[0]["text"] == "Revenue: $10M"
        assert ctx.metadata["declared_risk_level"] == "low"

    def test_handles_none_trace(self):
        class MockEngineInput:
            input_id = "ei-no-trace"
            trace = None
            agent_card = None
            runtime_signals = None
            history = None

        ctx = from_engine_input(MockEngineInput())
        assert ctx.trace_id == "ei-no-trace"
        assert ctx.query == ""
        assert ctx.response == ""


class TestEndToEndWithGuardrails:
    """Integration test: raw trace → adapter → guardrail evaluation."""

    async def test_reg_bi_via_adapter(self):
        from finserv_pack.guardrails.reg_bi import RegBIValidator

        raw = {
            **SAMPLE_RAW_TRACE,
            "llm_payload": {
                "input_data": {
                    "messages": [{"role": "user", "content": "Invest for my grandma"}]
                },
                "output_data": {"content": "Buy crypto derivatives and leveraged ETF positions."},
                "thinking": "",
                "reasoning": "",
            },
        }
        ctx = from_verytrace(raw)
        # Add customer profile to metadata
        ctx.metadata["customer"] = {
            "customer_id": "grandma-001",
            "risk_tolerance": "conservative",
            "age_bracket": "senior",
        }

        result = await RegBIValidator().evaluate(ctx)
        assert not result.passed
        assert result.action == "block"
        assert result.evidence["suitability_result"] == "unsuitable"

    async def test_numerical_accuracy_via_adapter(self):
        from finserv_pack.guardrails.numerical_accuracy import NumericalAccuracyValidator

        raw = {
            "verytrace_id": "vt-num",
            "llm_payload": {
                "input_data": {"messages": [{"role": "user", "content": "Revenue?"}]},
                "output_data": {"content": "Revenue was $99 billion last quarter."},
                "thinking": "",
                "reasoning": {
                    "facts_cited": ["Revenue: $4.2 billion in Q3"],
                    "conclusion": "Strong results",
                },
            },
            "engine_input": {"agent_card": {}},
        }
        ctx = from_verytrace(raw)
        result = await NumericalAccuracyValidator().evaluate(ctx)
        assert not result.passed  # $99B is not in source

    async def test_hallucination_via_adapter(self):
        from finserv_pack.guardrails.hallucination import HallucinationValidator

        raw = {
            "verytrace_id": "vt-hal",
            "llm_payload": {
                "input_data": {"messages": [{"role": "user", "content": "Summary?"}]},
                "output_data": {
                    "content": "The company acquired TechCorp for twelve billion and expanded into space mining operations across three continents."
                },
                "thinking": "The quarterly report mentions modest domestic growth.",
                "reasoning": "",
            },
        }
        ctx = from_verytrace(raw)
        result = await HallucinationValidator(threshold=0.8).evaluate(ctx)
        assert not result.passed  # Response is ungrounded
