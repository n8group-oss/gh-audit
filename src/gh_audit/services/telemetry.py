"""Bounded PostHog telemetry for gh-audit.

Design constraints
------------------
- Disabled by ``GH_AUDIT_TELEMETRY_DISABLED=1`` env var or ``enabled=False``.
- Hashed distinct ID: ``SHA-256(org_name + "|" + hostname)`` — no raw PII.
- Uses PostHog native exception capture for Error Tracking.
- Never raises to callers.
- Avoids CLI hangs during shutdown on blocked networks.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import locale
import logging
import os
import platform
import socket
import threading
import traceback
import uuid

import structlog

from gh_audit.__about__ import __version__

_log = structlog.get_logger(__name__)

_DEFAULT_POSTHOG_API_KEY = "phc_LvjlUfKx4Sm3edklc1sdLF2kcQCXsPehD08oHDw6RKj"
_POSTHOG_HOST = "https://eu.i.posthog.com"
_DISABLED_VALUES = {"1", "true", "yes", "on"}
_MAX_ERROR_MESSAGE_LEN = 1024
_MAX_STACK_TRACE_LEN = 4096
_SHUTDOWN_TIMEOUT_SECONDS = 2.0


def _try_import_posthog() -> type | None:
    """Import Posthog class, returning None if the package is unavailable."""
    try:
        from posthog import Posthog

        return Posthog
    except Exception:
        return None


def _compute_distinct_id(organization: str) -> str:
    raw = f"{organization}|{socket.gethostname()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_env_disabled() -> bool:
    value = os.environ.get("GH_AUDIT_TELEMETRY_DISABLED", "").strip().lower()
    return value in _DISABLED_VALUES


class Telemetry:
    """Hardened PostHog wrapper with silent failure behaviour."""

    def __init__(self, *, organization: str, enabled: bool = True) -> None:
        self._organization = organization
        self._enabled = enabled and not _is_env_disabled()
        self._distinct_id = _compute_distinct_id(organization)
        self._client: object | None = None
        self._run_context: dict[str, object] = {
            "organization": organization,
            "run_id": uuid.uuid4().hex,
        }

        if not self._enabled:
            return

        posthog_cls = _try_import_posthog()
        if posthog_cls is None:
            self._enabled = False
            return

        try:
            client = posthog_cls(
                _DEFAULT_POSTHOG_API_KEY,
                host=_POSTHOG_HOST,
                enable_exception_autocapture=True,
            )
            self._client = client

            with contextlib.suppress(Exception):
                atexit.unregister(client.join)

            with contextlib.suppress(Exception):
                disabled_level = logging.CRITICAL + 1
                logging.getLogger("posthog").setLevel(disabled_level)
                logging.getLogger("urllib3.connectionpool").setLevel(disabled_level)

            self._original_threading_excepthook = threading.excepthook
        except Exception as exc:
            _log.debug("telemetry_init_failed", error=str(exc))
            self._client = None

    def bind_context(self, **properties: object) -> None:
        """Merge additional per-run context into all future events."""
        for key, value in properties.items():
            if value is not None:
                self._run_context[key] = value

    def _base_properties(self) -> dict[str, object]:
        return dict(self._run_context)

    @staticmethod
    def _system_properties() -> dict[str, object]:
        props: dict[str, object] = {"tool_version": __version__}
        for key, fn in (
            ("os", platform.system),
            ("os_version", platform.version),
            ("python_version", platform.python_version),
            ("cpu_architecture", platform.machine),
        ):
            try:
                props[key] = fn()
            except Exception:
                props[key] = "unknown"
        return props

    @staticmethod
    def _launch_properties(*, auth_method: str, tool_version: str) -> dict[str, object]:
        props = Telemetry._system_properties()
        props["auth_method"] = auth_method
        props["tool_version"] = tool_version

        try:
            import sys as _sys

            props["console_encoding"] = getattr(_sys.stdout, "encoding", None) or "unknown"
            props["is_tty"] = bool(hasattr(_sys.stdout, "isatty") and _sys.stdout.isatty())
        except Exception:
            props["console_encoding"] = "unknown"
            props["is_tty"] = False

        try:
            props["locale_encoding"] = locale.getpreferredencoding(False)
        except Exception:
            props["locale_encoding"] = "unknown"

        return props

    @staticmethod
    def _format_error_properties(error: BaseException) -> dict[str, object]:
        tb = "".join(traceback.format_exception(error)) if error.__traceback__ else ""
        return {
            "error_type": type(error).__name__,
            "error_message": str(error)[:_MAX_ERROR_MESSAGE_LEN],
            "stack_trace": tb[:_MAX_STACK_TRACE_LEN],
        }

    def _capture(self, event: str, properties: dict[str, object] | None = None) -> None:
        if not self._enabled or self._client is None:
            return

        payload = self._base_properties()
        if properties:
            payload.update(properties)

        try:
            self._client.capture(  # type: ignore[attr-defined]
                distinct_id=self._distinct_id,
                event=event,
                properties=payload,
            )
        except Exception as exc:
            _log.debug("telemetry_capture_failed", telemetry_event=event, error=str(exc))

    def track_scanner_launched(self, *, auth_method: str, tool_version: str) -> None:
        properties = self._launch_properties(auth_method=auth_method, tool_version=tool_version)
        self.bind_context(**properties)
        self._capture(
            "scanner_launched",
            properties,
        )

    def track_discovery_started(self, **properties: object) -> None:
        self._capture("discovery_started", dict(properties))

    def track_discovery_completed(self, **properties: object) -> None:
        self._capture("discovery_completed", dict(properties))

    def track_discovery_failed(self, *, error: BaseException, **properties: object) -> None:
        payload = self._format_error_properties(error)
        payload.update(properties)
        self._capture("discovery_failed", payload)

    def track_report_started(self, *, html: bool, excel: bool, **properties: object) -> None:
        payload = {"html": html, "excel": excel}
        payload.update(properties)
        self._capture("report_started", payload)

    def track_report_completed(self, *, html: bool, excel: bool, **properties: object) -> None:
        payload = {"html": html, "excel": excel}
        payload.update(properties)
        self._capture("report_completed", payload)

    def track_report_failed(self, *, error: BaseException, **properties: object) -> None:
        payload = self._format_error_properties(error)
        payload.update(properties)
        self._capture("report_failed", payload)

    def track_assess_started(self, **properties: object) -> None:
        self._capture("assess_started", dict(properties))

    def track_assess_completed(self, **properties: object) -> None:
        self._capture("assess_completed", dict(properties))

    def track_assess_failed(self, *, error: BaseException, **properties: object) -> None:
        payload = self._format_error_properties(error)
        payload.update(properties)
        self._capture("assess_failed", payload)

    def track_multi_org_started(self, **properties: object) -> None:
        self._capture("multi_org_started", dict(properties))

    def track_multi_org_completed(self, **properties: object) -> None:
        self._capture("multi_org_completed", dict(properties))

    def track_multi_org_failed(self, *, error: BaseException, **properties: object) -> None:
        payload = self._format_error_properties(error)
        payload.update(properties)
        self._capture("multi_org_failed", payload)

    def track_feature_used(self, feature: str, **properties: object) -> None:
        payload = {"feature": feature}
        payload.update(properties)
        self._capture("feature_used", payload)

    def track_warning(
        self,
        event: str,
        *,
        error: BaseException | None = None,
        command: str | None = None,
        operation: str | None = None,
        category: str | None = None,
        repo: str | None = None,
        warning_scope: str | None = None,
        warning_message: str | None = None,
        **properties: object,
    ) -> None:
        payload: dict[str, object] = {}
        if error is not None:
            payload.update(self._format_error_properties(error))
        if command is not None:
            payload["command"] = command
        if operation is not None:
            payload["operation"] = operation
        if category is not None:
            payload["category"] = category
        if repo is not None:
            payload["repo"] = repo
        if warning_scope is not None:
            payload["warning_scope"] = warning_scope
        if warning_message is not None:
            payload["warning_message"] = warning_message
        payload.update(properties)
        self._capture(event, payload)

    def capture_exception(self, exception: BaseException) -> None:
        if not self._enabled or self._client is None:
            return
        try:
            properties = self._system_properties()
            properties.update(self._base_properties())
            self._client.capture_exception(  # type: ignore[attr-defined]
                exception,
                distinct_id=self._distinct_id,
                properties=properties,
            )
        except Exception as exc:
            _log.debug("telemetry_capture_exception_failed", error=str(exc))

    def shutdown(self) -> None:
        """Shut down the PostHog client with a bounded timeout."""
        if not self._enabled or self._client is None:
            return
        try:
            client = self._client

            if hasattr(self, "_original_threading_excepthook"):
                with contextlib.suppress(Exception):
                    threading.excepthook = self._original_threading_excepthook

            if hasattr(client, "exception_capture") and client.exception_capture:
                with contextlib.suppress(Exception):
                    client.exception_capture.close()

            for consumer in getattr(client, "consumers", []) or []:
                with contextlib.suppress(Exception):
                    consumer.pause()
            for consumer in getattr(client, "consumers", []) or []:
                with contextlib.suppress(Exception):
                    consumer.join(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        except Exception as exc:
            _log.debug("telemetry_shutdown_failed", error=str(exc))
        finally:
            self._client = None
