"""Tests for gh_audit.services.telemetry."""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

if TYPE_CHECKING:
    import pytest

from gh_audit.services.telemetry import Telemetry

_PATCH_IMPORT = "gh_audit.services.telemetry._try_import_posthog"


def _make_mock_posthog() -> tuple[MagicMock, MagicMock]:
    """Return a PostHog class mock and its client instance."""
    mock_cls = MagicMock()
    mock_client = MagicMock()
    mock_client.consumers = []
    mock_client.exception_capture = None
    mock_client.join = MagicMock()
    mock_cls.return_value = mock_client
    return mock_cls, mock_client


class TestTelemetry:
    @patch(_PATCH_IMPORT)
    def test_disabled_via_constructor(self, mock_import: MagicMock) -> None:
        telemetry = Telemetry(organization="contoso", enabled=False)
        telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
        mock_import.assert_not_called()

    @patch(_PATCH_IMPORT)
    def test_disabled_via_env(
        self, mock_import: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GH_AUDIT_TELEMETRY_DISABLED", "1")
        telemetry = Telemetry(organization="contoso")
        telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
        mock_import.assert_not_called()

    @patch(_PATCH_IMPORT)
    def test_enabled_by_default_creates_hardened_client(self, mock_import: MagicMock) -> None:
        mock_cls, _ = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")

        assert telemetry._enabled is True
        mock_cls.assert_called_once_with(
            "phc_LvjlUfKx4Sm3edklc1sdLF2kcQCXsPehD08oHDw6RKj",
            host="https://eu.i.posthog.com",
            enable_exception_autocapture=True,
        )

    @patch("gh_audit.services.telemetry.socket")
    @patch(_PATCH_IMPORT)
    def test_distinct_id_hashes_org_and_hostname(
        self, mock_import: MagicMock, mock_socket: MagicMock
    ) -> None:
        mock_cls, _ = _make_mock_posthog()
        mock_import.return_value = mock_cls
        mock_socket.gethostname.return_value = "host-1"

        telemetry = Telemetry(organization="contoso")

        assert telemetry._distinct_id == hashlib.sha256(b"contoso|host-1").hexdigest()

    @patch(_PATCH_IMPORT)
    def test_track_scanner_launched_includes_system_metadata(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")

        props = mock_client.capture.call_args.kwargs["properties"]
        assert props["auth_method"] == "pat"
        assert props["tool_version"] == "0.1.0"
        assert props["organization"] == "contoso"
        assert "run_id" in props
        assert "os" in props
        assert "python_version" in props
        assert "cpu_architecture" in props
        assert "os_version" in props
        assert "is_tty" in props
        assert "console_encoding" in props

    @patch(_PATCH_IMPORT)
    def test_launch_context_is_bound_into_later_events(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
        telemetry.track_discovery_started(command="discover")

        props = mock_client.capture.call_args.kwargs["properties"]
        assert props["organization"] == "contoso"
        assert props["auth_method"] == "pat"
        assert props["tool_version"] == "0.1.0"
        assert "os" in props
        assert "python_version" in props
        assert props["command"] == "discover"

    @patch(_PATCH_IMPORT)
    def test_discovery_failed_includes_stack_trace(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")

        try:
            raise ValueError("bad scan data")
        except ValueError as exc:
            telemetry.track_discovery_failed(error=exc, command="discover")

        props = mock_client.capture.call_args.kwargs["properties"]
        assert props["error_type"] == "ValueError"
        assert props["error_message"] == "bad scan data"
        assert "stack_trace" in props
        assert "ValueError" in props["stack_trace"]
        assert props["command"] == "discover"

    @patch(_PATCH_IMPORT)
    def test_track_warning_includes_full_error_context(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")

        try:
            raise RuntimeError("workflow fetch failed")
        except RuntimeError as exc:
            telemetry.track_warning(
                "repo_enrichment_warning",
                error=exc,
                command="discover",
                operation="workflow_list",
                category="operations",
                repo="repo-1",
                warning_scope="repo",
            )

        assert mock_client.capture.call_args.kwargs["event"] == "repo_enrichment_warning"
        props = mock_client.capture.call_args.kwargs["properties"]
        assert props["warning_scope"] == "repo"
        assert props["operation"] == "workflow_list"
        assert props["category"] == "operations"
        assert props["repo"] == "repo-1"
        assert props["error_type"] == "RuntimeError"
        assert "stack_trace" in props

    @patch(_PATCH_IMPORT)
    def test_track_warning_supports_non_exception_warning(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        telemetry.track_warning(
            "enterprise_discovery_warning",
            command="discover",
            operation="enterprise_info",
            category="enterprise",
            warning_scope="enterprise",
            warning_message="Enterprise info not accessible (check permissions)",
        )

        assert mock_client.capture.call_args.kwargs["event"] == "enterprise_discovery_warning"
        props = mock_client.capture.call_args.kwargs["properties"]
        assert props["warning_message"] == "Enterprise info not accessible (check permissions)"
        assert props["warning_scope"] == "enterprise"
        assert props["operation"] == "enterprise_info"
        assert "error_type" not in props

    @patch(_PATCH_IMPORT)
    def test_capture_exception_delegates_to_native_sdk_path(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        exc = RuntimeError("boom")

        telemetry.capture_exception(exc)

        mock_client.capture_exception.assert_called_once()
        call_args = mock_client.capture_exception.call_args
        assert call_args.args[0] is exc
        assert call_args.kwargs["distinct_id"] == telemetry._distinct_id
        props = call_args.kwargs["properties"]
        assert props["organization"] == "contoso"
        assert "run_id" in props
        assert "os" in props
        assert "python_version" in props

    @patch(_PATCH_IMPORT)
    def test_capture_exception_swallows_client_errors(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_client.capture_exception.side_effect = RuntimeError("network")
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        telemetry.capture_exception(RuntimeError("boom"))

    @patch(_PATCH_IMPORT)
    def test_shutdown_pauses_consumers_with_timeout(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        consumer_1 = MagicMock()
        consumer_2 = MagicMock()
        mock_client.consumers = [consumer_1, consumer_2]
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        telemetry.shutdown()

        consumer_1.pause.assert_called_once()
        consumer_2.pause.assert_called_once()
        consumer_1.join.assert_called_once()
        consumer_2.join.assert_called_once()
        assert consumer_1.join.call_args.kwargs["timeout"] == 2.0
        assert consumer_2.join.call_args.kwargs["timeout"] == 2.0
        mock_client.shutdown.assert_not_called()
        mock_client.flush.assert_not_called()

    @patch(_PATCH_IMPORT)
    def test_constructor_unregisters_atexit_handler(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_import.return_value = mock_cls

        with patch("gh_audit.services.telemetry.atexit") as mock_atexit:
            Telemetry(organization="contoso")
            mock_atexit.unregister.assert_called_once_with(mock_client.join)

    @patch(_PATCH_IMPORT)
    def test_constructor_silences_posthog_loggers(self, mock_import: MagicMock) -> None:
        mock_cls, _ = _make_mock_posthog()
        mock_import.return_value = mock_cls

        Telemetry(organization="contoso")

        assert logging.getLogger("posthog").level > logging.CRITICAL
        assert logging.getLogger("urllib3.connectionpool").level > logging.CRITICAL

    @patch(_PATCH_IMPORT)
    def test_shutdown_restores_threading_excepthook(self, mock_import: MagicMock) -> None:
        mock_cls, _ = _make_mock_posthog()
        mock_import.return_value = mock_cls

        original_hook = threading.excepthook
        telemetry = Telemetry(organization="contoso")
        threading.excepthook = lambda args: None  # type: ignore[assignment]

        telemetry.shutdown()

        assert threading.excepthook is original_hook

    @patch(_PATCH_IMPORT)
    def test_shutdown_closes_exception_capture(self, mock_import: MagicMock) -> None:
        mock_cls, mock_client = _make_mock_posthog()
        mock_exception_capture = MagicMock()
        mock_client.exception_capture = mock_exception_capture
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        telemetry.shutdown()

        mock_exception_capture.close.assert_called_once()

    def test_posthog_import_failure_degrades_gracefully(self) -> None:
        with patch(_PATCH_IMPORT, return_value=None):
            telemetry = Telemetry(organization="contoso")
            assert telemetry._enabled is False
            assert telemetry._client is None
            telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
            telemetry.capture_exception(RuntimeError("boom"))
            telemetry.shutdown()

    @patch(_PATCH_IMPORT)
    def test_constructor_failure_degrades_gracefully(self, mock_import: MagicMock) -> None:
        mock_cls = MagicMock()
        mock_cls.side_effect = RuntimeError("SSL certificate verify failed")
        mock_import.return_value = mock_cls

        telemetry = Telemetry(organization="contoso")
        assert telemetry._client is None
        telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
        telemetry.capture_exception(RuntimeError("boom"))
        telemetry.shutdown()
