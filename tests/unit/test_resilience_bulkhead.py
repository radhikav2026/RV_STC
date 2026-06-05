"""Tests for :mod:`stc_framework.resilience.bulkhead`.

Covers the ``Bulkhead`` class: normal acquire/release, timeout rejection,
try_acquire (non-blocking), in_use counter, and invalid limit.
"""

from __future__ import annotations

import asyncio

import pytest

from stc_framework.errors import BulkheadFull
from stc_framework.resilience.bulkhead import Bulkhead


def test_bulkhead_invalid_limit_raises():
    with pytest.raises(ValueError, match="limit must be >= 1"):
        Bulkhead("bad", limit=0)


@pytest.mark.asyncio
async def test_acquire_and_release():
    bh = Bulkhead("test", limit=2)
    assert bh.in_use == 0
    async with bh.acquire():
        assert bh.in_use == 1
    assert bh.in_use == 0


@pytest.mark.asyncio
async def test_acquire_no_timeout_blocks_until_free():
    """Without timeout, acquire() blocks until a slot frees up."""
    bh = Bulkhead("test", limit=1)
    released = asyncio.Event()

    async def hold_and_release():
        async with bh.acquire():
            await asyncio.sleep(0.05)
        released.set()

    task = asyncio.create_task(hold_and_release())
    await asyncio.sleep(0.01)  # let the task acquire the slot
    # This will block until the slot is released
    async with bh.acquire():
        assert released.is_set()
    await task


@pytest.mark.asyncio
async def test_acquire_timeout_raises_bulkhead_full():
    bh = Bulkhead("test", limit=1)
    async with bh.acquire():
        with pytest.raises(BulkheadFull):
            async with bh.acquire(timeout=0.01):
                pass


def test_try_acquire_success():
    bh = Bulkhead("test", limit=2)
    assert bh.try_acquire() is True
    assert bh.in_use == 1
    assert bh.try_acquire() is True
    assert bh.in_use == 2


def test_try_acquire_fails_when_full():
    bh = Bulkhead("test", limit=1)
    assert bh.try_acquire() is True
    assert bh.try_acquire() is False
    assert bh.in_use == 1


@pytest.mark.asyncio
async def test_in_use_tracks_concurrent_slots():
    bh = Bulkhead("test", limit=3)
    async with bh.acquire():
        assert bh.in_use == 1
        async with bh.acquire():
            assert bh.in_use == 2
        assert bh.in_use == 1
    assert bh.in_use == 0
