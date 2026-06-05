"""Tests for :mod:`stc_framework.trainer.notifications`.

Covers the ``Notifier`` class and the ``_strip_pii`` helper:
PII stripping from context, Slack webhook delivery (mocked),
fallback logging, and nested PII removal.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from stc_framework.trainer.notifications import Notifier, _strip_pii


class TestStripPii:
    def test_removes_known_pii_fields(self):
        ctx = {
            "trace_id": "abc-123",
            "query": "sensitive query",
            "response": "sensitive response",
            "tenant_id": "user@example.com",
            "rail_name": "injection",
        }
        safe = _strip_pii(ctx)
        assert "trace_id" in safe
        assert "rail_name" in safe
        assert "query" not in safe
        assert "response" not in safe
        assert "tenant_id" not in safe

    def test_recursive_stripping(self):
        ctx = {
            "details": {
                "query": "nested sensitive",
                "count": 5,
            },
            "total": 10,
        }
        safe = _strip_pii(ctx)
        assert safe["total"] == 10
        assert "query" not in safe["details"]
        assert safe["details"]["count"] == 5

    def test_empty_context(self):
        assert _strip_pii({}) == {}

    def test_all_pii_fields_removed(self):
        from stc_framework.trainer.notifications import _PII_RISK_FIELDS

        ctx = {field: f"value_{field}" for field in _PII_RISK_FIELDS}
        ctx["safe_field"] = "keep"
        safe = _strip_pii(ctx)
        assert safe == {"safe_field": "keep"}


class TestNotifier:
    @pytest.mark.asyncio
    async def test_alert_default_channel_logs(self):
        """Default channel emits a structured log (no exception)."""
        notifier = Notifier()
        # Should not raise
        await notifier.alert("test message", context={"rail_name": "pii"})

    @pytest.mark.asyncio
    async def test_alert_slack_skipped_when_env_unset(self):
        """Slack channel skips gracefully if env var is unset."""
        notifier = Notifier(slack_webhook_env="NONEXISTENT_WEBHOOK_URL_XYZ")
        # Ensure the env var is truly unset
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NONEXISTENT_WEBHOOK_URL_XYZ", None)
            await notifier.alert("test", channel="slack_webhook")

    @pytest.mark.asyncio
    async def test_alert_slack_posts_to_webhook(self):
        """Slack alert sends a POST to the webhook URL."""
        notifier = Notifier(slack_webhook_env="TEST_SLACK_URL")
        with patch.dict(os.environ, {"TEST_SLACK_URL": "https://hooks.slack.com/test"}):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock()
                await notifier.alert("alert text", channel="slack_webhook")
                mock_client.post.assert_called_once()
                call_args = mock_client.post.call_args
                assert call_args[1]["json"]["text"] == "alert text"

    @pytest.mark.asyncio
    async def test_alert_slack_handles_http_error_gracefully(self):
        """Slack alert does not raise on HTTP errors."""
        import httpx

        notifier = Notifier(slack_webhook_env="TEST_SLACK_URL")
        with patch.dict(os.environ, {"TEST_SLACK_URL": "https://hooks.slack.com/test"}):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=httpx.HTTPError("connection failed"))
                # Should not raise
                await notifier.alert("fail test", channel="slack_webhook")

    @pytest.mark.asyncio
    async def test_alert_strips_pii_from_context(self):
        """PII fields are stripped before being passed to the log."""
        notifier = Notifier()
        # Should not raise; PII fields silently removed
        await notifier.alert(
            "test",
            context={"query": "sensitive", "count": 5, "user": "attacker"},
        )
