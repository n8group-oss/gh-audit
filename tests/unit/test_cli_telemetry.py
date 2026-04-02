"""Focused CLI telemetry tests for discover/report/assess lifecycle events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from gh_audit.cli.app import app
from gh_audit.exceptions import ScannerError
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.security import SecurityInfo
from gh_audit.models.user import OrgMemberSummary

runner = CliRunner()


def _make_inventory(organization: str = "testorg") -> Inventory:
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 31, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization=organization,
            auth_method="pat",
            scan_profile="standard",
        ),
        summary=InventorySummary(total_repos=1, private_repos=1),
        repositories=[
            RepositoryInventoryItem(
                name="repo-a",
                full_name=f"{organization}/repo-a",
                visibility="private",
                security=SecurityInfo(dependabot_enabled=False),
            )
        ],
        users=OrgMemberSummary(total=1, admins=0, members=1),
    )


def _write_inventory(tmp_path: Path, organization: str = "testorg") -> Path:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        _make_inventory(organization).model_dump_json(indent=2), encoding="utf-8"
    )
    return inventory_path


def _make_settings(organization: str = "test-org") -> MagicMock:
    settings = MagicMock()
    settings.organization = organization
    settings.auth_method = "pat"
    settings.telemetry_disabled = False
    return settings


def test_discover_tracks_lifecycle_on_success(tmp_path: Path) -> None:
    settings = _make_settings()
    inventory = _make_inventory("test-org")
    telemetry = MagicMock()

    with (
        patch("gh_audit.cli.app.resolve_settings", return_value=settings),
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.cli.app._run_discover", new_callable=AsyncMock, return_value=inventory),
    ):
        result = runner.invoke(
            app,
            [
                "discover",
                "--organization",
                "test-org",
                "--token",
                "ghp_test123",
                "--output-dir",
                str(tmp_path),
                "--no-report",
                "--no-excel",
            ],
        )

    assert result.exit_code == 0
    telemetry.track_scanner_launched.assert_called_once()
    telemetry.track_discovery_started.assert_called_once()
    telemetry.track_discovery_completed.assert_called_once()
    telemetry.shutdown.assert_called_once()


def test_discover_tracks_scanner_error_failure(tmp_path: Path) -> None:
    settings = _make_settings()
    telemetry = MagicMock()
    error = ScannerError("auth failed", exit_code=3)

    with (
        patch("gh_audit.cli.app.resolve_settings", return_value=settings),
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.cli.app._run_discover", new_callable=AsyncMock, side_effect=error),
    ):
        result = runner.invoke(
            app,
            [
                "discover",
                "--organization",
                "test-org",
                "--token",
                "ghp_test123",
                "--output-dir",
                str(tmp_path),
                "--no-report",
                "--no-excel",
            ],
        )

    assert result.exit_code == 3
    telemetry.track_discovery_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once_with(error)
    telemetry.shutdown.assert_called_once()


def test_discover_tracks_unexpected_failure(tmp_path: Path) -> None:
    settings = _make_settings()
    telemetry = MagicMock()
    error = RuntimeError("boom")

    with (
        patch("gh_audit.cli.app.resolve_settings", return_value=settings),
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.cli.app._run_discover", new_callable=AsyncMock, side_effect=error),
    ):
        result = runner.invoke(
            app,
            [
                "discover",
                "--organization",
                "test-org",
                "--token",
                "ghp_test123",
                "--output-dir",
                str(tmp_path),
                "--no-report",
                "--no-excel",
            ],
        )

    assert result.exit_code == 1
    telemetry.track_discovery_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once_with(error)
    telemetry.shutdown.assert_called_once()


def test_discover_tracks_report_warning_without_aborting(tmp_path: Path) -> None:
    settings = _make_settings()
    inventory = _make_inventory("test-org")
    telemetry = MagicMock()
    report_instance = MagicMock()
    report_instance.generate.side_effect = RuntimeError("html failed")

    with (
        patch("gh_audit.cli.app.resolve_settings", return_value=settings),
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.cli.app._run_discover", new_callable=AsyncMock, return_value=inventory),
        patch("gh_audit.services.reporting.ReportService", return_value=report_instance),
    ):
        result = runner.invoke(
            app,
            [
                "discover",
                "--organization",
                "test-org",
                "--token",
                "ghp_test123",
                "--output-dir",
                str(tmp_path),
                "--report",
                "--no-excel",
            ],
        )

    assert result.exit_code == 0
    telemetry.track_warning.assert_called_once()
    assert telemetry.track_warning.call_args.args[0] == "report_warning"


def test_discover_tracks_failure_after_scan_when_writing_inventory(tmp_path: Path) -> None:
    settings = _make_settings()
    inventory = _make_inventory("test-org")
    telemetry = MagicMock()
    error = RuntimeError("disk full")

    with (
        patch("gh_audit.cli.app.resolve_settings", return_value=settings),
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.cli.app._run_discover", new_callable=AsyncMock, return_value=inventory),
        patch("pathlib.Path.write_text", side_effect=error),
    ):
        result = runner.invoke(
            app,
            [
                "discover",
                "--organization",
                "test-org",
                "--token",
                "ghp_test123",
                "--output-dir",
                str(tmp_path),
                "--no-report",
                "--no-excel",
            ],
        )

    assert result.exit_code == 1
    telemetry.track_discovery_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once_with(error)
    telemetry.shutdown.assert_called_once()


def test_report_tracks_lifecycle_on_success(tmp_path: Path) -> None:
    inventory_path = _write_inventory(tmp_path)
    telemetry = MagicMock()
    report_instance = MagicMock()

    with (
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry) as telemetry_cls,
        patch("gh_audit.services.reporting.ReportService", return_value=report_instance),
    ):
        result = runner.invoke(
            app,
            [
                "report",
                "--inventory",
                str(inventory_path),
                "--html",
                "--no-excel",
            ],
        )

    assert result.exit_code == 0
    telemetry_cls.assert_called_once_with(organization="testorg", enabled=True)
    telemetry.track_scanner_launched.assert_called_once()
    telemetry.track_report_started.assert_called_once()
    telemetry.track_report_completed.assert_called_once()
    telemetry.shutdown.assert_called_once()


def test_report_tracks_report_warning_without_aborting(tmp_path: Path) -> None:
    inventory_path = _write_inventory(tmp_path)
    telemetry = MagicMock()
    report_instance = MagicMock()
    report_instance.generate.side_effect = RuntimeError("html failed")

    with (
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.services.reporting.ReportService", return_value=report_instance),
    ):
        result = runner.invoke(
            app,
            [
                "report",
                "--inventory",
                str(inventory_path),
                "--html",
                "--no-excel",
            ],
        )

    assert result.exit_code == 0
    telemetry.track_warning.assert_called_once()
    assert telemetry.track_warning.call_args.args[0] == "report_warning"


def test_report_tracks_unexpected_failure(tmp_path: Path) -> None:
    inventory_path = _write_inventory(tmp_path)
    telemetry = MagicMock()
    error = RuntimeError("path resolution failed")

    with (
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.cli.app.OutputPaths.from_json_path", side_effect=error),
    ):
        result = runner.invoke(app, ["report", "--inventory", str(inventory_path)])

    assert result.exit_code == 1
    telemetry.track_report_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once_with(error)
    telemetry.shutdown.assert_called_once()


def test_report_tracks_missing_inventory_failure(tmp_path: Path) -> None:
    telemetry = MagicMock()

    with patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry) as telemetry_cls:
        result = runner.invoke(app, ["report", "--inventory", str(tmp_path / "missing.json")])

    assert result.exit_code == 1
    telemetry_cls.assert_called_once_with(organization="unknown", enabled=True)
    telemetry.track_scanner_launched.assert_called_once()
    telemetry.track_report_started.assert_called_once()
    telemetry.track_report_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once()
    telemetry.shutdown.assert_called_once()


def test_assess_tracks_lifecycle_on_success(tmp_path: Path) -> None:
    inventory_path = _write_inventory(tmp_path)
    output_path = tmp_path / "assessment.html"
    telemetry = MagicMock()
    rule_engine = MagicMock()
    rule_engine.run.return_value = []

    with (
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry) as telemetry_cls,
        patch("gh_audit.rules.registry.RuleEngine.default", return_value=rule_engine),
        patch("gh_audit.services.assessment.AssessmentService"),
    ):
        result = runner.invoke(
            app,
            ["assess", "--input", str(inventory_path), "--output", str(output_path)],
        )

    assert result.exit_code == 0
    telemetry_cls.assert_called_once_with(organization="testorg", enabled=True)
    telemetry.track_scanner_launched.assert_called_once()
    telemetry.track_assess_started.assert_called_once()
    telemetry.track_assess_completed.assert_called_once()
    telemetry.shutdown.assert_called_once()


def test_assess_tracks_failure(tmp_path: Path) -> None:
    inventory_path = _write_inventory(tmp_path)
    output_path = tmp_path / "assessment.html"
    telemetry = MagicMock()
    rule_engine = MagicMock()
    rule_engine.run.return_value = []
    error = RuntimeError("render failed")
    assessment_service = MagicMock()
    assessment_service.generate.side_effect = error

    with (
        patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry),
        patch("gh_audit.rules.registry.RuleEngine.default", return_value=rule_engine),
        patch("gh_audit.services.assessment.AssessmentService", return_value=assessment_service),
    ):
        result = runner.invoke(
            app,
            ["assess", "--input", str(inventory_path), "--output", str(output_path)],
        )

    assert result.exit_code == 1
    telemetry.track_assess_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once_with(error)
    telemetry.shutdown.assert_called_once()


def test_assess_tracks_invalid_inventory_failure(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    telemetry = MagicMock()

    with patch("gh_audit.services.telemetry.Telemetry", return_value=telemetry) as telemetry_cls:
        result = runner.invoke(
            app, ["assess", "--input", str(bad), "--output", str(tmp_path / "out.html")]
        )

    assert result.exit_code == 1
    telemetry_cls.assert_called_once_with(organization="unknown", enabled=True)
    telemetry.track_scanner_launched.assert_called_once()
    telemetry.track_assess_started.assert_called_once()
    telemetry.track_assess_failed.assert_called_once()
    telemetry.capture_exception.assert_called_once()
    telemetry.shutdown.assert_called_once()
