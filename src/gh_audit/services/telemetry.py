"""Bounded PostHog telemetry — never raises, never blocks the user.

Design constraints
------------------
- Disabled by ``GH_AUDIT_TELEMETRY_DISABLED=1`` env var or ``enabled=False``.
- Hashed distinct ID: ``SHA-256(org_name + "|" + hostname)`` — no raw PII.
- PostHog client created with ``sync_mode=False`` (fire-and-forget).
- 2-second connection timeout; no retries.
- All public methods are wrapped in try/except — never raise to callers.
- Only debug-level structlog output on any failure.
"""

from __future__ import annotations

import hashlib
import os
import socket
from typing import Any

import structlog

try:
    from posthog import Posthog
except ImportError:  # pragma: no cover
    Posthog = None  # type: ignore[misc,assignment]

_log = structlog.get_logger(__name__)

_POSTHOG_API_KEY = "phc_LvjlUfKx4Sm3edklc1sdLF2kcQCXsPehD08oHDw6RKj"
_POSTHOG_HOST = "https://eu.i.posthog.com"

_DISABLED_VALUES = {"1", "true", "yes", "on"}


def _compute_distinct_id(organization: str) -> str:
    hostname = socket.gethostname()
    raw = f"{organization}|{hostname}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_env_disabled() -> bool:
    value = os.environ.get("GH_AUDIT_TELEMETRY_DISABLED", "").lower()
    return value in _DISABLED_VALUES


class Telemetry:
    """Thin PostHog wrapper with bounded, silent failure behaviour."""

    def __init__(self, *, organization: str, enabled: bool = True) -> None:
        self._enabled: bool = enabled and not _is_env_disabled()
        self._distinct_id: str = _compute_distinct_id(organization)
        self._client: Any = None

        if self._enabled:
            self._client = self._init_client()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_client(self) -> Any:
        if Posthog is None:
            _log.debug("posthog_unavailable", reason="import_missing")
            return None
        try:
            client = Posthog(
                api_key=_POSTHOG_API_KEY,
                host=_POSTHOG_HOST,
                sync_mode=False,
                timeout=2,
            )
            return client
        except Exception as exc:
            _log.debug("telemetry_init_failed", error=str(exc))
            return None

    def _capture(self, event: str, properties: dict[str, Any] | None = None) -> None:
        if not self._enabled or self._client is None:
            return
        try:
            self._client.capture(
                distinct_id=self._distinct_id,
                event=event,
                properties=properties or {},
            )
        except Exception as exc:
            _log.debug("telemetry_capture_failed", event=event, error=str(exc))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track_scanner_launched(self, *, auth_method: str, tool_version: str) -> None:
        try:
            self._capture(
                "scanner_launched",
                {"auth_method": auth_method, "tool_version": tool_version},
            )
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_scanner_launched", error=str(exc))

    def track_discovery_started(self) -> None:
        try:
            self._capture("discovery_started")
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_discovery_started", error=str(exc))

    def track_discovery_completed(
        self,
        *,
        duration_seconds: float,
        repo_count: int = 0,
        member_count: int = 0,
        package_count: int = 0,
        workflow_count: int = 0,
        issue_count: int = 0,
    ) -> None:
        try:
            self._capture(
                "discovery_completed",
                {
                    "duration_seconds": duration_seconds,
                    "repo_count": repo_count,
                    "member_count": member_count,
                    "package_count": package_count,
                    "workflow_count": workflow_count,
                    "issue_count": issue_count,
                },
            )
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_discovery_completed", error=str(exc))

    def track_discovery_failed(self, *, error_type: str) -> None:
        try:
            self._capture("discovery_failed", {"error_type": error_type})
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_discovery_failed", error=str(exc))

    def track_report_started(self, *, html: bool, excel: bool) -> None:
        try:
            self._capture("report_started", {"html": html, "excel": excel})
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_report_started", error=str(exc))

    def track_report_completed(self, *, html: bool, excel: bool) -> None:
        try:
            self._capture("report_completed", {"html": html, "excel": excel})
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_report_completed", error=str(exc))

    def track_report_failed(self, *, error_type: str) -> None:
        try:
            self._capture("report_failed", {"error_type": error_type})
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_error", method="track_report_failed", error=str(exc))

    def capture_exception(self, exc: Exception) -> None:
        try:
            self._capture(
                "exception_captured",
                {"error_type": type(exc).__name__, "error_message": str(exc)},
            )
        except Exception as inner:  # noqa: BLE001
            _log.debug("telemetry_error", method="capture_exception", error=str(inner))

    def shutdown(self) -> None:
        if not self._enabled or self._client is None:
            return
        try:
            self._client.shutdown()
        except Exception as exc:  # noqa: BLE001
            _log.debug("telemetry_shutdown_failed", error=str(exc))
