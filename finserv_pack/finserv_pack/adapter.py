"""Adapter: VeryTrace / EngineInput → TraceContext.

Converts the raw VeryTrace dict (from Redis/API) or the typed EngineInput
Pydantic model into the FinServ Pack's generic TraceContext so guardrails
can evaluate agent traces from your platform.

Usage:
    from finserv_pack.adapter import from_verytrace, from_engine_input

    # From raw dict (Redis/API):
    ctx = from_verytrace(raw_dict)

    # From typed EngineInput model:
    ctx = from_engine_input(engine_input)

    # Then run guardrails:
    result = await RegBIValidator().evaluate(ctx)
"""

from __future__ import annotations

from typing import Any

from finserv_pack.base import TraceContext


def from_verytrace(raw: dict[str, Any]) -> TraceContext:
    """Convert a raw VeryTrace dict (from Redis/API) to TraceContext.

    Expected shape:
    {
        "verytrace_id": "vt-abc-123",
        "event_ref": {"trace_id": "tr-1", ...},
        "operator_identity": {"operator_id": "user-1", "tenant_id": "tenant-1"},
        "llm_payload": {
            "input_data": {"messages": [...], "instructions": "..."},
            "output_data": {"content": "..."},
            "thinking": "...",
            "reasoning": "..."
        },
        "engine_input": {
            "agent_card": {...},
            "runtime_signals": {...},
            "history": {...}
        },
        "evaluation_context": {}
    }
    """
    # Extract query from messages
    llm_payload = raw.get("llm_payload", {})
    input_data = llm_payload.get("input_data", {})
    messages = input_data.get("messages", [])
    query = _extract_user_query(messages)

    # Extract response
    output_data = llm_payload.get("output_data", {})
    response = output_data.get("content", "")

    # Extract reasoning/context
    thinking = llm_payload.get("thinking", "")
    reasoning = llm_payload.get("reasoning", "")
    context = _build_context(thinking, reasoning)

    # Extract IDs
    event_ref = raw.get("event_ref", {})
    trace_id = raw.get("verytrace_id", event_ref.get("trace_id", ""))
    operator_identity = raw.get("operator_identity", {})
    tenant_id = operator_identity.get("tenant_id", "")

    # Extract agent card and engine_input for metadata
    engine_input = raw.get("engine_input", {})
    agent_card = engine_input.get("agent_card", {})
    history = engine_input.get("history", {})
    runtime_signals = engine_input.get("runtime_signals", {})

    # Build source chunks from reasoning trace if available
    source_chunks = _extract_source_chunks(reasoning)

    # Build metadata with everything the validators might need
    metadata: dict[str, Any] = {
        "agent_card": agent_card,
        "operator_id": operator_identity.get("operator_id", ""),
        "instructions": input_data.get("instructions", ""),
        "runtime_signals": runtime_signals,
        "history": history,
        "event_ref": event_ref,
    }

    # If agent_card has risk/governance info, surface it
    if agent_card:
        avs_purpose = agent_card.get("avs_purpose", {})
        if avs_purpose:
            metadata["declared_risk_level"] = avs_purpose.get("declared_risk_level", "")

        avs_governance = agent_card.get("avs_governance", {})
        if avs_governance:
            metadata["transparency_disclosure"] = avs_governance.get(
                "transparency_disclosure", {}
            )

    # Extract model provenance for model_id
    model_id = ""
    avs_safety = agent_card.get("avs_safety_controls", {})
    if avs_safety:
        supply_chain = avs_safety.get("supply_chain", {})
        model_id = supply_chain.get("model_provenance", "")

    return TraceContext(
        query=query,
        response=response,
        context=context,
        source_chunks=source_chunks,
        trace_id=trace_id,
        tenant_id=tenant_id,
        model_id=model_id,
        metadata=metadata,
    )


def from_engine_input(engine_input: Any) -> TraceContext:
    """Convert a typed EngineInput (Pydantic model) to TraceContext.

    Works with the EngineInput model that has:
    - engine_input.trace.user_query
    - engine_input.trace.final_output
    - engine_input.trace.final_reasoning_trace
    - engine_input.trace.operator_identity
    - engine_input.agent_card
    - engine_input.history
    - engine_input.runtime_signals
    """
    trace = getattr(engine_input, "trace", None)

    # Extract query/response from trace
    query = ""
    response = ""
    context = ""
    source_chunks: list[dict[str, Any]] = []
    tenant_id = ""
    trace_id = getattr(engine_input, "input_id", "")

    if trace is not None:
        query = getattr(trace, "user_query", "") or ""
        response = getattr(trace, "final_output", "") or ""

        # Extract context from reasoning trace
        reasoning_trace = getattr(trace, "final_reasoning_trace", None)
        if reasoning_trace is not None:
            context_parts = []
            rt_context = getattr(reasoning_trace, "context", "")
            if rt_context:
                context_parts.append(str(rt_context))
            facts_cited = getattr(reasoning_trace, "facts_cited", None)
            if facts_cited:
                for fact in facts_cited:
                    source_chunks.append({"text": str(fact)})
                context_parts.append(" ".join(str(f) for f in facts_cited))
            context = " ".join(context_parts)

        # Extract tenant_id from operator_identity
        op_identity = getattr(trace, "operator_identity", None)
        if op_identity is not None:
            tenant_id = getattr(op_identity, "tenant_id", "") or ""

        # Extract run_id as trace_id if not already set
        if not trace_id:
            trace_id = getattr(trace, "run_id", "") or ""

    # Extract agent card info
    agent_card = getattr(engine_input, "agent_card", None)
    model_id = ""
    metadata: dict[str, Any] = {}

    if agent_card is not None:
        metadata["agent_card"] = _model_to_dict(agent_card)

        # Model provenance
        avs_safety = getattr(agent_card, "avs_safety_controls", None)
        if avs_safety:
            supply_chain = getattr(avs_safety, "supply_chain", None)
            if supply_chain:
                model_id = getattr(supply_chain, "model_provenance", "") or ""

        # Risk level
        avs_purpose = getattr(agent_card, "avs_purpose", None)
        if avs_purpose:
            metadata["declared_risk_level"] = getattr(avs_purpose, "declared_risk_level", "")

        # Transparency disclosure
        avs_governance = getattr(agent_card, "avs_governance", None)
        if avs_governance:
            metadata["transparency_disclosure"] = _model_to_dict(
                getattr(avs_governance, "transparency_disclosure", None)
            )

    # Extract history for bias/fairness
    history = getattr(engine_input, "history", None)
    if history is not None:
        metadata["history"] = _model_to_dict(history)
        # Extract decision_batch for bias monitoring (SI-02)
        decision_batch = getattr(history, "decision_batch", None)
        if decision_batch:
            metadata["decision_batch"] = [_model_to_dict(d) for d in decision_batch]

    # Runtime signals
    runtime_signals = getattr(engine_input, "runtime_signals", None)
    if runtime_signals is not None:
        metadata["runtime_signals"] = _model_to_dict(runtime_signals)

    return TraceContext(
        query=query,
        response=response,
        context=context,
        source_chunks=source_chunks,
        trace_id=trace_id,
        tenant_id=tenant_id,
        model_id=model_id,
        metadata=metadata,
    )


# --- Helpers ---


def _extract_user_query(messages: list[dict[str, Any]]) -> str:
    """Extract the last user message from the messages array."""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return msg.get("content", "")
    # Fallback: return last message content regardless of role
    if messages:
        return messages[-1].get("content", "")
    return ""


def _build_context(thinking: str | Any, reasoning: str | Any) -> str:
    """Build context string from thinking/reasoning fields."""
    parts = []
    if thinking and isinstance(thinking, str):
        parts.append(thinking)
    if reasoning:
        if isinstance(reasoning, str):
            parts.append(reasoning)
        elif isinstance(reasoning, dict):
            # reasoning can be {conclusion: ...}
            conclusion = reasoning.get("conclusion", "")
            if conclusion:
                parts.append(str(conclusion))
            # Also grab any context/assumptions
            for key in ("context", "assumptions", "facts_cited"):
                val = reasoning.get(key)
                if val:
                    if isinstance(val, list):
                        parts.append(" ".join(str(v) for v in val))
                    else:
                        parts.append(str(val))
    return " ".join(parts)


def _extract_source_chunks(reasoning: str | Any) -> list[dict[str, Any]]:
    """Extract source chunks from reasoning if it's structured."""
    chunks: list[dict[str, Any]] = []
    if isinstance(reasoning, dict):
        facts = reasoning.get("facts_cited", [])
        if isinstance(facts, list):
            for fact in facts:
                chunks.append({"text": str(fact)})
    return chunks


def _model_to_dict(obj: Any) -> Any:
    """Convert a Pydantic model (or any object) to a dict safely."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return {}
