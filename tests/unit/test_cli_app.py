"""Tests for the CLI application (app.py).

Uses typer.testing.CliRunner to exercise commands without spawning subprocesses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from gh_audit.__about__ import __version__
from gh_audit.cli.app import app
from gh_audit.exceptions import ConfigError

runner = CliRunner()


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


class TestVersion:
    """The --version / -V flag prints the version string."""

    def test_version_long(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_version_short(self):
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert __version__ in result.stdout


# ---------------------------------------------------------------------------
# init command
# ---------------------------------------------------------------------------


class TestInitCommand:
    """The init command is reachable and shows help."""

    def test_init_help(self):
        result = runner.invoke(app, ["init", "--help"])
        assert result.exit_code == 0
        assert "init" in result.stdout.lower() or "credential" in result.stdout.lower()


# ---------------------------------------------------------------------------
# discover --help
# ---------------------------------------------------------------------------


class TestDiscoverHelp:
    """The discover command exposes all required flags."""

    def test_discover_help_exits_zero(self):
        result = runner.invoke(app, ["discover", "--help"])
        assert result.exit_code == 0

    @pytest.mark.parametrize(
        "flag,args",
        [
            ("--organization", ["--organization", "x", "--help"]),
            ("--token", ["--token", "x", "--help"]),
            ("--app-id", ["--app-id", "123", "--help"]),
            ("--private-key-path", ["--private-key-path", "/tmp/k", "--help"]),
            ("--installation-id", ["--installation-id", "123", "--help"]),
            ("--api-url", ["--api-url", "https://x", "--help"]),
            ("--env-path", ["--env-path", "/tmp/.env", "--help"]),
            ("--output-dir", ["--output-dir", "/tmp", "--help"]),
            ("--output", ["--output", "/tmp/out", "--help"]),
            ("--scan-profile", ["--scan-profile", "standard", "--help"]),
            ("--scan-large-files", ["--scan-large-files", "--help"]),
            ("--scan-workflow-contents", ["--scan-workflow-contents", "--help"]),
            ("--security-alert-counts", ["--security-alert-counts", "--help"]),
            ("--include-archived", ["--include-archived", "--help"]),
            ("--repo-limit", ["--repo-limit", "10", "--help"]),
            ("--concurrency", ["--concurrency", "5", "--help"]),
            ("--report", ["--report", "--help"]),
            ("--excel", ["--excel", "--help"]),
            ("--verbose", ["--verbose", "--help"]),
            ("--debug", ["--debug", "--help"]),
            ("--log-format", ["--log-format", "json", "--help"]),
            ("--no-telemetry", ["--no-telemetry", "--help"]),
        ],
    )
    def test_discover_has_flag(self, flag: str, args: list[str]):
        """Verify the flag is accepted by the parser (pass flag + --help)."""
        result = runner.invoke(app, ["discover", *args])
        assert result.exit_code == 0, f"Flag {flag} not recognized"


# ---------------------------------------------------------------------------
# discover — ConfigError handling
# ---------------------------------------------------------------------------


class TestDiscoverConfigError:
    """When resolve_settings raises ConfigError the CLI prints the error and exits 1."""

    @patch("gh_audit.cli.app.resolve_settings")
    def test_config_error_shows_message(self, mock_resolve):
        mock_resolve.side_effect = ConfigError("Organization is required.")
        result = runner.invoke(app, ["discover", "--organization", "test-org"])
        assert result.exit_code == 1
        output = result.stdout + (result.stderr or "")
        assert "Organization is required." in output


# ---------------------------------------------------------------------------
# discover — happy path (mocked)
# ---------------------------------------------------------------------------


class TestDiscoverHappyPath:
    """Discover command runs through the full flow when everything is mocked."""

    @patch("gh_audit.services.excel_export.ExcelExportService")
    @patch("gh_audit.services.reporting.ReportService")
    @patch("gh_audit.services.discovery.DiscoveryService")
    @patch("gh_audit.adapters.github_graphql.GitHubGraphQLClient")
    @patch("gh_audit.adapters.github_rest.GitHubRestClient")
    @patch("gh_audit.services.telemetry.Telemetry")
    @patch("gh_audit.cli.app.resolve_settings")
    def test_discover_success(
        self,
        mock_resolve,
        mock_telemetry_cls,
        mock_rest_cls,
        mock_gql_cls,
        mock_discovery_cls,
        mock_report_cls,
        mock_excel_cls,
        tmp_path,
    ):
        # Set up config mock
        config = MagicMock()
        config.organization = "test-org"
        config.token = MagicMock()
        config.token.get_secret_value.return_value = "ghp_test123"
        config.app_id = None
        config.auth_method = "pat"
        config.api_url = "https://api.github.com"
        config.graphql_url = "https://api.github.com/graphql"
        config.scan_profile = "standard"
        config.scan_large_files = False
        config.scan_workflow_contents = False
        config.security_alert_counts = False
        config.repo_limit = None
        config.concurrency = 8
        config.include_archived = True
        config.telemetry_disabled = False
        mock_resolve.return_value = config

        # Set up telemetry mock
        mock_telemetry = MagicMock()
        mock_telemetry_cls.return_value = mock_telemetry

        # Set up REST client mock
        mock_rest = MagicMock()
        mock_rest.verify_credentials = AsyncMock(return_value={"login": "test-org"})
        mock_rest.rate_limit_remaining = 4999
        mock_rest.close = AsyncMock()
        mock_rest_cls.return_value = mock_rest

        # Set up GraphQL client mock
        mock_gql = MagicMock()
        mock_gql.close = AsyncMock()
        mock_gql_cls.return_value = mock_gql

        # Set up discovery mock — return a minimal Inventory
        mock_service = MagicMock()
        mock_inventory = MagicMock()
        mock_inventory.summary = MagicMock()
        mock_inventory.summary.total_repos = 5
        mock_inventory.repositories = [MagicMock()] * 5
        mock_inventory.users = MagicMock()
        mock_inventory.users.total = 10
        mock_inventory.packages = []
        mock_inventory.projects = []
        mock_inventory.metadata = MagicMock()
        mock_inventory.model_dump_json.return_value = "{}"
        mock_service.discover = AsyncMock(return_value=mock_inventory)
        mock_discovery_cls.return_value = mock_service

        # Set up report mock
        mock_report = MagicMock()
        mock_report.generate = MagicMock()
        mock_report_cls.return_value = mock_report

        # Set up excel mock
        mock_excel_cls.generate = MagicMock()

        output_dir = str(tmp_path)
        result = runner.invoke(
            app,
            [
                "discover",
                "--organization",
                "test-org",
                "--token",
                "ghp_test123",
                "--output-dir",
                output_dir,
                "--no-telemetry",
            ],
        )
        # The command should complete (exit 0)
        assert result.exit_code == 0, f"Output:\n{result.stdout}"
        assert "test-org" in result.stdout


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


class TestReportCommand:
    """The report command is reachable and shows help with expected flags."""

    def test_report_help(self):
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0

    @pytest.mark.parametrize(
        "flag,args",
        [
            ("--inventory", ["--inventory", "/tmp/x.json", "--help"]),
            ("--html", ["--html", "--help"]),
            ("--excel", ["--excel", "--help"]),
            ("--output-dir", ["--output-dir", "/tmp", "--help"]),
            ("--verbose", ["--verbose", "--help"]),
            ("--debug", ["--debug", "--help"]),
            ("--log-format", ["--log-format", "json", "--help"]),
        ],
    )
    def test_report_has_flag(self, flag: str, args: list[str]):
        """Verify the flag is accepted by the parser."""
        result = runner.invoke(app, ["report", *args])
        assert result.exit_code == 0, f"Flag {flag} not recognized"

    def test_report_missing_inventory(self):
        """report with a non-existent inventory file exits 1."""
        result = runner.invoke(
            app,
            [
                "report",
                "--inventory",
                "/nonexistent/path.json",
            ],
        )
        assert result.exit_code == 1
        output = result.stdout + (result.stderr or "")
        assert "not found" in output.lower() or "ERROR" in output


# ---------------------------------------------------------------------------
# No args shows help
# ---------------------------------------------------------------------------


class TestNoArgs:
    """Invoking with no arguments shows help (no_args_is_help=True)."""

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer/Click exits with code 0 or 2 when showing help via no_args_is_help
        assert result.exit_code in (0, 2)
        assert "discover" in result.stdout
