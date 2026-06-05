"""Tests for :mod:`stc_framework.governance.retention`.

Covers the ``apply_retention`` function with various store
configurations: audit backend pruning, history pruning, token pruning,
and the audit record emitted on completion.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from stc_framework.governance.retention import RetentionSummary, apply_retention


def _make_audit_spec(retention_days=30, policies=None):
    """Build a mock audit spec with retention_days and policies."""
    audit_spec = MagicMock()
    audit_spec.retention_days = retention_days
    if policies is None:
        policies = MagicMock()
        # Simulate model_fields with some day values
        type(policies).model_fields = {"default_days": None, "erasure_days": None}
        policies.default_days = 30
        policies.erasure_days = 180
    audit_spec.retention_policies = policies
    return audit_spec


def _make_system(audit_spec=None, audit_backend=None, history=None, tokenizer_store=None):
    """Build a mock system with the needed attributes."""
    system = MagicMock()
    if audit_spec is None:
        audit_spec = _make_audit_spec()
    system.spec.audit = audit_spec

    if audit_backend is not None:
        audit_obj = MagicMock()
        audit_obj.backend = audit_backend
        audit_obj.emit = AsyncMock()
        system._audit = audit_obj
    else:
        system._audit = None

    if history is not None:
        system.trainer = MagicMock()
        system.trainer.history = history
    else:
        system.trainer = None

    if tokenizer_store is not None:
        gateway = MagicMock()
        tokenizer = MagicMock()
        tokenizer._store = tokenizer_store
        gateway._tokenizer = tokenizer
        system.gateway = gateway
    else:
        system.gateway = None

    return system


@pytest.mark.asyncio
async def test_retention_no_stores():
    """No stores available — returns zero summary."""
    system = _make_system()
    summary = await apply_retention(system)
    assert isinstance(summary, RetentionSummary)
    assert summary.audit_removed == 0
    assert summary.history_removed == 0
    assert summary.tokens_removed == 0


@pytest.mark.asyncio
async def test_retention_audit_prune():
    """Audit backend with prune_before is called and count returned."""
    backend = MagicMock()
    backend.prune_before = MagicMock(return_value=5)
    system = _make_system(audit_backend=backend)
    summary = await apply_retention(system)
    assert summary.audit_removed == 5
    backend.prune_before.assert_called_once()


@pytest.mark.asyncio
async def test_retention_audit_prune_exception_swallowed():
    """Audit backend that raises returns 0 instead of propagating."""
    backend = MagicMock()
    backend.prune_before = MagicMock(side_effect=Exception("WORM"))
    system = _make_system(audit_backend=backend)
    summary = await apply_retention(system)
    assert summary.audit_removed == 0


@pytest.mark.asyncio
async def test_retention_with_forever_policy():
    """If any policy is forever (negative days), audit prune is skipped."""
    policies = MagicMock()
    type(policies).model_fields = {"default_days": None, "seal_days": None}
    policies.default_days = 30
    policies.seal_days = -1  # forever
    audit_spec = _make_audit_spec(policies=policies)
    backend = MagicMock()
    backend.prune_before = MagicMock(return_value=10)
    system = _make_system(audit_spec=audit_spec, audit_backend=backend)
    summary = await apply_retention(system)
    assert summary.audit_removed == 0
    backend.prune_before.assert_not_called()


@pytest.mark.asyncio
async def test_retention_history_pruned():
    """History store prune_before is called and count returned."""
    history = MagicMock()
    history.prune_before = MagicMock(return_value=3)
    system = _make_system(history=history)
    summary = await apply_retention(system)
    assert summary.history_removed == 3


@pytest.mark.asyncio
async def test_retention_token_store_pruned():
    """Token store prune_before is called and count returned."""
    store = MagicMock()
    store.prune_before = MagicMock(return_value=7)
    system = _make_system(tokenizer_store=store)
    summary = await apply_retention(system)
    assert summary.tokens_removed == 7


@pytest.mark.asyncio
async def test_retention_emits_audit_record():
    """When audit is available, an AuditRecord is emitted."""
    backend = MagicMock()
    backend.prune_before = MagicMock(return_value=2)
    system = _make_system(audit_backend=backend)
    await apply_retention(system)
    system._audit.emit.assert_called_once()
    record = system._audit.emit.call_args[0][0]
    assert record.event_type == "retention_sweep"
    assert record.extra["audit_removed"] == 2


@pytest.mark.asyncio
async def test_retention_summary_fields():
    """RetentionSummary dataclass has expected defaults."""
    s = RetentionSummary(retention_days=90)
    assert s.retention_days == 90
    assert s.audit_removed == 0
    assert s.history_removed == 0
    assert s.tokens_removed == 0
