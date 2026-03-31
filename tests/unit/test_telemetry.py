"""Tests for gh_audit.services.telemetry — bounded PostHog telemetry."""

from __future__ import annotations

import hashlib
import socket
from unittest.mock import MagicMock

import pytest

from gh_audit.services.telemetry import Telemetry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expected_distinct_id(org: str) -> str:
    hostname = socket.gethostname()
    raw = f"{org}|{hostname}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Enabled / disabled logic
# ---------------------------------------------------------------------------


def test_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg")
    assert t._enabled is True


def test_disabled_via_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=False)
    assert t._enabled is False


def test_disabled_via_env_var_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_TELEMETRY_DISABLED", "1")
    t = Telemetry(organization="myorg", enabled=True)
    assert t._enabled is False


def test_disabled_via_env_var_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_TELEMETRY_DISABLED", "true")
    t = Telemetry(organization="myorg", enabled=True)
    assert t._enabled is False


def test_disabled_via_env_var_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_TELEMETRY_DISABLED", "yes")
    t = Telemetry(organization="myorg", enabled=True)
    assert t._enabled is False


def test_env_var_0_does_not_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_TELEMETRY_DISABLED", "0")
    t = Telemetry(organization="myorg", enabled=True)
    assert t._enabled is True


# ---------------------------------------------------------------------------
# Distinct ID — SHA-256 of "org|hostname"
# ---------------------------------------------------------------------------


def test_distinct_id_is_64_char_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg")
    assert len(t._distinct_id) == 64
    assert all(c in "0123456789abcdef" for c in t._distinct_id)


def test_same_org_same_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t1 = Telemetry(organization="acme")
    t2 = Telemetry(organization="acme")
    assert t1._distinct_id == t2._distinct_id


def test_different_org_different_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t1 = Telemetry(organization="orgA")
    t2 = Telemetry(organization="orgB")
    assert t1._distinct_id != t2._distinct_id


def test_distinct_id_matches_expected_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    org = "myorg"
    t = Telemetry(organization=org)
    assert t._distinct_id == _expected_distinct_id(org)


# ---------------------------------------------------------------------------
# Noop when disabled
# ---------------------------------------------------------------------------


def test_all_track_methods_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=False)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
    t.track_discovery_started()
    t.track_discovery_completed(duration_seconds=1.5, repo_count=10)
    t.track_discovery_failed(error_type="AuthError")
    t.track_report_started(html=True, excel=False)
    t.track_report_completed(html=True, excel=False)
    t.track_report_failed(error_type="IOError")
    t.capture_exception(ValueError("boom"))
    t.shutdown()

    mock_client.capture.assert_not_called()
    mock_client.shutdown.assert_not_called()


# ---------------------------------------------------------------------------
# Capture when enabled — using mock PostHog client
# ---------------------------------------------------------------------------


def test_track_scanner_launched_captures_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_scanner_launched(auth_method="pat", tool_version="0.1.0")

    mock_client.capture.assert_called_once()
    call_kwargs = mock_client.capture.call_args
    # capture(distinct_id, event, properties)
    args = call_kwargs[0] if call_kwargs[0] else []
    kwargs = call_kwargs[1] if call_kwargs[1] else {}
    all_args = {**kwargs}
    if len(args) >= 1:
        all_args.setdefault("distinct_id", args[0])
    if len(args) >= 2:
        all_args.setdefault("event", args[1])
    if len(args) >= 3:
        all_args.setdefault("properties", args[2])

    assert all_args.get("event") == "scanner_launched" or "scanner_launched" in str(call_kwargs)


def test_track_discovery_completed_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_discovery_completed(
        duration_seconds=5.0,
        repo_count=42,
        member_count=10,
        package_count=3,
        workflow_count=7,
        issue_count=100,
    )

    mock_client.capture.assert_called_once()


def test_track_discovery_started_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_discovery_started()

    mock_client.capture.assert_called_once()


def test_track_discovery_failed_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_discovery_failed(error_type="NetworkError")

    mock_client.capture.assert_called_once()


def test_track_report_started_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_report_started(html=True, excel=True)

    mock_client.capture.assert_called_once()


def test_track_report_completed_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_report_completed(html=False, excel=True)

    mock_client.capture.assert_called_once()


def test_track_report_failed_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.track_report_failed(error_type="PermissionError")

    mock_client.capture.assert_called_once()


def test_capture_exception_sends_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.capture_exception(RuntimeError("oops"))

    mock_client.capture.assert_called_once()


# ---------------------------------------------------------------------------
# Never raise — resilience tests
# ---------------------------------------------------------------------------


def test_never_raises_with_none_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    t._client = None  # simulate broken/missing client

    # None of these should raise
    t.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
    t.track_discovery_started()
    t.track_discovery_completed(duration_seconds=1.0, repo_count=5)
    t.track_discovery_failed(error_type="Timeout")
    t.track_report_started(html=True, excel=False)
    t.track_report_completed(html=True, excel=False)
    t.track_report_failed(error_type="IOError")
    t.capture_exception(ValueError("broken"))
    t.shutdown()


def test_never_raises_with_broken_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)

    broken_client = MagicMock()
    broken_client.capture.side_effect = RuntimeError("PostHog network failure")
    broken_client.shutdown.side_effect = RuntimeError("shutdown failure")
    t._client = broken_client

    t.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
    t.track_discovery_started()
    t.track_discovery_completed(duration_seconds=2.0, repo_count=0)
    t.track_discovery_failed(error_type="AuthError")
    t.track_report_started(html=False, excel=True)
    t.track_report_completed(html=False, excel=True)
    t.track_report_failed(error_type="ValueError")
    t.capture_exception(Exception("anything"))
    t.shutdown()


def test_shutdown_safe_with_none_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    t._client = None
    t.shutdown()  # must not raise


def test_shutdown_calls_client_shutdown_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    t = Telemetry(organization="myorg", enabled=True)
    mock_client = MagicMock()
    t._client = mock_client

    t.shutdown()

    mock_client.shutdown.assert_called_once()


# ---------------------------------------------------------------------------
# PostHog import missing — simulated via patching
# ---------------------------------------------------------------------------


def test_graceful_when_posthog_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Telemetry should silently become a no-op if PostHog is not installed."""
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)

    # Patch the module-level Posthog name to None (simulating ImportError path)
    import gh_audit.services.telemetry as telemetry_mod

    original = telemetry_mod.Posthog
    try:
        telemetry_mod.Posthog = None  # type: ignore[attr-defined]
        t = Telemetry(organization="myorg", enabled=True)
        assert t._client is None
        # All methods must be safe
        t.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
        t.track_discovery_started()
        t.track_discovery_completed(duration_seconds=0.5, repo_count=1)
        t.shutdown()
    finally:
        telemetry_mod.Posthog = original  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Minimal smoke test matching task description
# ---------------------------------------------------------------------------


def test_task_description_example(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_TELEMETRY_DISABLED", raising=False)
    telemetry = Telemetry(organization="myorg", enabled=True)
    # This must not raise regardless of PostHog availability
    telemetry.track_scanner_launched(auth_method="pat", tool_version="0.1.0")
