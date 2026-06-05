"""Tests for :mod:`stc_framework.resilience.timeout`.

Covers the ``atimeout`` async context manager — both the native
``asyncio.timeout`` path (Python 3.11+) and the 3.10 fallback shim.
"""

from __future__ import annotations

import asyncio

import pytest

from stc_framework.resilience.timeout import atimeout


@pytest.mark.asyncio
async def test_atimeout_no_timeout_when_fast():
    """Context exits cleanly when body completes in time."""
    async with atimeout(1.0):
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_atimeout_raises_timeout_error_on_overrun():
    """TimeoutError raised when body exceeds the deadline."""
    with pytest.raises(asyncio.TimeoutError):
        async with atimeout(0.05):
            await asyncio.sleep(5.0)


@pytest.mark.asyncio
async def test_atimeout_propagates_internal_exceptions():
    """Non-timeout exceptions propagate normally."""
    with pytest.raises(ValueError, match="custom"):
        async with atimeout(1.0):
            raise ValueError("custom")


@pytest.mark.asyncio
async def test_atimeout_zero_seconds_fires_immediately():
    """A zero-second timeout fires immediately on any await."""
    with pytest.raises(asyncio.TimeoutError):
        async with atimeout(0.0):
            await asyncio.sleep(10.0)


@pytest.mark.asyncio
async def test_atimeout_cancellation_propagates():
    """CancelledError from outside the timeout propagates as-is."""

    async def _cancel_self():
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await asyncio.sleep(0)

    with pytest.raises(asyncio.CancelledError):
        async with atimeout(5.0):
            await _cancel_self()
