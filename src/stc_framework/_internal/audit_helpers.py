"""Audit-emit helper to eliminate the ``if self._audit …`` boilerplate.

Most domain modules follow this pattern on every state-changing operation::

    if self._audit is not None:
        await self._audit.emit(
            AuditRecord(
                event_type=AuditEvent.SOMETHING.value,
                persona="compliance",
                extra={...},
            )
        )

:class:`AuditEmitter` wraps the null-check and the
``AuditRecord`` construction so callers collapse to a single
``await self._emitter.emit(...)`` call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from stc_framework.observability.audit import AuditRecord

if TYPE_CHECKING:
    from stc_framework.governance.events import AuditEvent
    from stc_framework.observability.audit import AuditLogger


class AuditEmitter:
    """Thin wrapper that null-checks the logger and builds ``AuditRecord``."""

    __slots__ = ("_audit", "_persona")

    def __init__(self, audit: AuditLogger | None, *, persona: str) -> None:
        self._audit = audit
        self._persona = persona

    async def emit(
        self,
        event: AuditEvent,
        *,
        tenant_id: str | None = None,
        extra: dict[str, Any] | None = None,
        **record_kwargs: Any,
    ) -> None:
        """Emit an audit record if a logger is configured; silently no-op otherwise."""
        if self._audit is None:
            return
        await self._audit.emit(
            AuditRecord(
                event_type=event.value,
                persona=self._persona,
                tenant_id=tenant_id,
                extra=extra or {},
                **record_kwargs,
            )
        )

    @property
    def enabled(self) -> bool:
        return self._audit is not None


__all__ = ["AuditEmitter"]
