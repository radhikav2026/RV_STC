# FinServ Pack

Financial-services-specific AI guardrails, extracted from the [STC Framework](https://github.com/ambastha-nitesh/stc-framework) (MIT license).

## What's Included

### Guardrails (5 validators)

| Validator | Regulatory Mapping | What It Does |
|-----------|-------------------|-------------|
| `RegBIValidator` | SEC 17 CFR 240.15l-1 | Flags unsuitable product recommendations for customer risk profiles |
| `NumericalAccuracyValidator` | FINRA 2210 | Blocks responses with numbers not grounded in source documents |
| `HallucinationValidator` | FINRA 2210, SEC AI guidance | Detects ungrounded claims (word-overlap or embedding-based) |
| `BiasFairnessMonitor` | ECOA, Fair Lending, CFPB | 4/5ths rule (EEOC) disparate impact detection |
| `TransparencyValidator` | SEC AI disclosure, MiFID II | Validates AI disclosure present + customer consent |

### PII Redaction (Phase 2)
- `PIIRedactor` — dual-engine (Presidio NER + regex fallback)
- `Tokenizer` — HMAC-SHA256 surrogate tokenization

### Pen Testing (Phase 2)
- `PenTestRunner` — MITRE ATLAS + OWASP LLM Top 10 tagged payload catalog

## Installation

```bash
pip install finserv-pack
# Or with PII redaction support:
pip install finserv-pack[presidio]
```

## Quick Start

```python
import asyncio
from finserv_pack.base import TraceContext
from finserv_pack.guardrails import (
    RegBIValidator,
    NumericalAccuracyValidator,
    HallucinationValidator,
)

async def main():
    ctx = TraceContext(
        query="What should I invest in?",
        response="You should buy crypto derivatives for maximum returns.",
        context="Customer portfolio review document...",
        metadata={
            "customer": {
                "customer_id": "C-123",
                "risk_tolerance": "conservative",
                "age_bracket": "senior",
            }
        },
    )

    # Run all validators
    validators = [
        RegBIValidator(enforce=False),
        NumericalAccuracyValidator(tolerance_percent=1.0),
        HallucinationValidator(threshold=0.8),
    ]

    for v in validators:
        result = await v.evaluate(ctx)
        print(f"{result.rule_name}: {'PASS' if result.passed else 'FAIL'} — {result.details}")

asyncio.run(main())
```

## Generic Interface

The pack uses a **platform-agnostic interface**. To integrate with your platform:

1. Map your trace format → `TraceContext`
2. Call `validator.evaluate(ctx)` → get a `GuardrailResult`
3. Feed the result into your existing rule engine / dashboard

```python
# Adapter example (you write this to match your platform):
def adapt_trace(your_trace) -> TraceContext:
    return TraceContext(
        query=your_trace.input_text,
        response=your_trace.output_text,
        context=your_trace.retrieved_context,
        source_chunks=your_trace.rag_chunks,
        trace_id=your_trace.id,
        tenant_id=your_trace.org_id,
        metadata=your_trace.extra,
    )
```

## License

MIT — originally extracted from [stc-framework](https://github.com/ambastha-nitesh/stc-framework) with author permission.
