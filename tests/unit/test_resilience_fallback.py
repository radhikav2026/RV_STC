"""Tests for :mod:`stc_framework.resilience.fallback`.

Covers the ``run_with_fallback`` chain executor: primary success,
primary failure with retryable/non-retryable errors, fallback chains,
on_fallback callback, and exhaustion behaviour.
"""

from __future__ import annotations

import pytest

from stc_framework.errors import LLMUnavailable, STCError
from stc_framework.resilience.fallback import run_with_fallback


@pytest.mark.asyncio
async def test_primary_success_no_fallback_called():
    called = {"fb": 0}

    async def primary():
        return "primary_result"

    async def fb():
        called["fb"] += 1
        return "fb_result"

    result = await run_with_fallback(primary, [fb], label="test")
    assert result == "primary_result"
    assert called["fb"] == 0


@pytest.mark.asyncio
async def test_generic_exception_triggers_fallback():
    """Non-STCError exceptions also trigger fallback chain."""

    async def primary():
        raise RuntimeError("unexpected crash")

    async def fb():
        return "recovered"

    result = await run_with_fallback(primary, [fb], label="test")
    assert result == "recovered"


@pytest.mark.asyncio
async def test_on_fallback_callback_invoked():
    """The on_fallback callback receives the index and exception."""
    invocations: list[tuple[int, BaseException]] = []

    async def primary():
        raise LLMUnavailable(message="down", retryable=True)

    async def fb():
        return "ok"

    await run_with_fallback(
        primary,
        [fb],
        label="test",
        on_fallback=lambda idx, exc: invocations.append((idx, exc)),
    )
    assert len(invocations) == 1
    assert invocations[0][0] == 1
    assert isinstance(invocations[0][1], LLMUnavailable)


@pytest.mark.asyncio
async def test_all_fallbacks_fail_raises_last_error():
    """When all fallbacks fail, the last exception is raised."""

    async def primary():
        raise LLMUnavailable(message="primary down", retryable=True)

    async def fb1():
        raise RuntimeError("fb1 down")

    async def fb2():
        raise ValueError("fb2 down")

    with pytest.raises(ValueError, match="fb2 down"):
        await run_with_fallback(primary, [fb1, fb2], label="test")


@pytest.mark.asyncio
async def test_non_retryable_stc_error_in_fallback_reraises():
    """Non-retryable STCError in fallback is raised immediately."""

    async def primary():
        raise LLMUnavailable(message="primary down", retryable=True)

    async def fb1():
        raise STCError(message="fatal", retryable=False)

    async def fb2():
        return "should not reach"

    with pytest.raises(STCError, match="fatal"):
        await run_with_fallback(primary, [fb1, fb2], label="test")


@pytest.mark.asyncio
async def test_empty_fallback_list_raises_primary_error():
    """Empty fallback list raises the primary error."""

    async def primary():
        raise LLMUnavailable(message="down", retryable=True)

    with pytest.raises(LLMUnavailable, match="down"):
        await run_with_fallback(primary, [], label="test")


@pytest.mark.asyncio
async def test_second_fallback_succeeds():
    """Second fallback in the chain is tried after first fails."""

    async def primary():
        raise RuntimeError("primary fail")

    async def fb1():
        raise RuntimeError("fb1 fail")

    async def fb2():
        return "fb2_ok"

    result = await run_with_fallback(primary, [fb1, fb2], label="test")
    assert result == "fb2_ok"
