"""Tests for the --config flag on the discover command (multi-org scanning).

Uses typer.testing.CliRunner to exercise the CLI without spawning subprocesses.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from gh_audit.cli.app import app
from gh_audit.exceptions import ConfigError
from gh_audit.models.multi_org import MultiOrgSummary, OrgScanResult

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, content: str) -> Path:
    """Write YAML text to a file and return the path."""
    path.write_text(content, encoding="utf-8")
    return path


def _make_summary(*, succeeded: int = 1, failed: int = 0) -> MultiOrgSummary:
    """Build a MultiOrgSummary with the requested success/failure mix."""
    orgs: list[OrgScanResult] = []
    for i in range(succeeded):
        orgs.append(
            OrgScanResult(
                name=f"org-ok-{i}",
                status="success",
                total_repos=10,
                duration_seconds=1.0,
            )
        )
    for i in range(failed):
        orgs.append(
            OrgScanResult(
                name=f"org-fail-{i}",
                status="failed",
                error="boom",
                duration_seconds=0.5,
            )
        )
    return MultiOrgSummary(
        tool_version="0.1.0",
        config_file="test.yaml",
        organizations=orgs,
    )


# ---------------------------------------------------------------------------
# discover --help shows --config
# ---------------------------------------------------------------------------


class TestDiscoverHelpConfig:
    """The discover command accepts the --config flag."""

    def test_config_flag_accepted(self):
        result = runner.invoke(app, ["discover", "--config", "/tmp/config.yml", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Mutual exclusion: --config and --organization
# ---------------------------------------------------------------------------


class TestConfigOrgMutualExclusion:
    """--config and --organization are mutually exclusive."""

    def test_config_and_organization_together_exits_1(self, tmp_path: Path):
        cfg = _write_yaml(tmp_path / "scan.yaml", "organizations:\n  - name: x\n    token: t\n")
        result = runner.invoke(
            app,
            [
                "discover",
                "--config",
                str(cfg),
                "--organization",
                "some-org",
            ],
        )
        assert result.exit_code == 1
        output = (result.stdout + (result.stderr or "")).lower()
        assert "mutually exclusive" in output


# ---------------------------------------------------------------------------
# --config with missing file
# ---------------------------------------------------------------------------


class TestConfigMissingFile:
    """--config pointing to a non-existent file prints error and exits 1."""

    @patch("gh_audit.cli.app.load_config")
    def test_missing_file_exits_1(self, mock_load_config: MagicMock, tmp_path: Path):
        missing = tmp_path / "nonexistent.yaml"
        mock_load_config.side_effect = ConfigError(f"Config file not found: {missing}")

        result = runner.invoke(app, ["discover", "--config", str(missing)])
        assert result.exit_code == 1
        output = (result.stdout + (result.stderr or "")).lower()
        assert "not found" in output or "error" in output


# ---------------------------------------------------------------------------
# --config with invalid YAML
# ---------------------------------------------------------------------------


class TestConfigInvalidYaml:
    """--config with a file that fails validation prints error and exits 1."""

    @patch("gh_audit.cli.app.load_config")
    def test_invalid_yaml_exits_1(self, mock_load_config: MagicMock, tmp_path: Path):
        bad = _write_yaml(tmp_path / "bad.yaml", "not: valid: yaml: [[[")
        mock_load_config.side_effect = ConfigError("Invalid YAML in config file: ...")

        result = runner.invoke(app, ["discover", "--config", str(bad)])
        assert result.exit_code == 1
        output = (result.stdout + (result.stderr or "")).lower()
        assert "error" in output


# ---------------------------------------------------------------------------
# --config happy path — all orgs succeed
# ---------------------------------------------------------------------------


class TestConfigHappyPath:
    """--config with a valid file calls run_all_orgs and exits 0 on success."""

    @patch("gh_audit.cli.app.generate_summary_html")
    @patch("gh_audit.cli.app.run_all_orgs", new_callable=AsyncMock)
    @patch("gh_audit.cli.app.load_config")
    def test_all_succeed_exits_0(
        self,
        mock_load_config: MagicMock,
        mock_run_all: AsyncMock,
        mock_gen_html: MagicMock,
        tmp_path: Path,
    ):
        cfg_file = _write_yaml(
            tmp_path / "scan.yaml",
            "organizations:\n  - name: test-org\n    token: ghp_abc\n",
        )

        mock_config = MagicMock()
        mock_load_config.return_value = mock_config

        summary = _make_summary(succeeded=2, failed=0)
        mock_run_all.return_value = summary

        result = runner.invoke(
            app,
            ["discover", "--config", str(cfg_file), "--output-dir", str(tmp_path)],
        )

        assert result.exit_code == 0, f"Output:\n{result.stdout}"
        assert "2 succeeded" in result.stdout
        assert "0 failed" in result.stdout
        mock_run_all.assert_called_once()
        # Summary JSON should be written
        json_files = list(tmp_path.glob("*-summary.json"))
        assert len(json_files) == 1

    @patch("gh_audit.cli.app.generate_summary_html")
    @patch("gh_audit.cli.app.run_all_orgs", new_callable=AsyncMock)
    @patch("gh_audit.cli.app.load_config")
    def test_run_all_orgs_receives_cli_overrides(
        self,
        mock_load_config: MagicMock,
        mock_run_all: AsyncMock,
        mock_gen_html: MagicMock,
        tmp_path: Path,
    ):
        cfg_file = _write_yaml(
            tmp_path / "scan.yaml",
            "organizations:\n  - name: org\n    token: ghp_x\n",
        )
        mock_load_config.return_value = MagicMock()
        mock_run_all.return_value = _make_summary(succeeded=1)

        result = runner.invoke(
            app,
            [
                "discover",
                "--config",
                str(cfg_file),
                "--output-dir",
                str(tmp_path),
                "--scan-profile",
                "deep",
                "--concurrency",
                "4",
            ],
        )

        assert result.exit_code == 0, f"Output:\n{result.stdout}"
        call_kwargs = mock_run_all.call_args[1]
        overrides = call_kwargs["cli_overrides"]
        assert overrides["scan_profile"] == "deep"
        assert overrides["concurrency"] == 4


# ---------------------------------------------------------------------------
# --config with failures — exits 1
# ---------------------------------------------------------------------------


class TestConfigWithFailures:
    """--config exits 1 when any org fails."""

    @patch("gh_audit.cli.app.generate_summary_html")
    @patch("gh_audit.cli.app.run_all_orgs", new_callable=AsyncMock)
    @patch("gh_audit.cli.app.load_config")
    def test_partial_failure_exits_1(
        self,
        mock_load_config: MagicMock,
        mock_run_all: AsyncMock,
        mock_gen_html: MagicMock,
        tmp_path: Path,
    ):
        cfg_file = _write_yaml(
            tmp_path / "scan.yaml",
            "organizations:\n  - name: org\n    token: t\n",
        )
        mock_load_config.return_value = MagicMock()

        summary = _make_summary(succeeded=1, failed=1)
        mock_run_all.return_value = summary

        result = runner.invoke(
            app,
            ["discover", "--config", str(cfg_file), "--output-dir", str(tmp_path)],
        )

        assert result.exit_code == 1
        assert "1 succeeded" in result.stdout
        assert "1 failed" in result.stdout


# ---------------------------------------------------------------------------
# --config generates summary HTML
# ---------------------------------------------------------------------------


class TestConfigSummaryHtml:
    """--config generates a summary HTML report by default."""

    @patch("gh_audit.cli.app.generate_summary_html")
    @patch("gh_audit.cli.app.run_all_orgs", new_callable=AsyncMock)
    @patch("gh_audit.cli.app.load_config")
    def test_summary_html_generated(
        self,
        mock_load_config: MagicMock,
        mock_run_all: AsyncMock,
        mock_gen_html: MagicMock,
        tmp_path: Path,
    ):
        cfg_file = _write_yaml(
            tmp_path / "scan.yaml",
            "organizations:\n  - name: org\n    token: t\n",
        )
        mock_load_config.return_value = MagicMock()
        mock_run_all.return_value = _make_summary(succeeded=1)

        result = runner.invoke(
            app,
            ["discover", "--config", str(cfg_file), "--output-dir", str(tmp_path)],
        )

        assert result.exit_code == 0, f"Output:\n{result.stdout}"
        mock_gen_html.assert_called_once()
        # The second argument should be the summary HTML path
        call_args = mock_gen_html.call_args
        html_path = call_args[0][1]
        assert str(html_path).endswith("-summary.html")
