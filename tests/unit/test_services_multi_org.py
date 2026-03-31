"""Tests for gh_audit.services.multi_org — config loader, merger, and runner."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from gh_audit.exceptions import ConfigError
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.multi_org import MultiOrgConfig, OrgEntry
from gh_audit.models.user import OrgMemberSummary
from gh_audit.services.multi_org import (
    _expand_env_vars,
    build_scanner_config,
    load_config,
    run_all_orgs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, content: str) -> Path:
    """Write YAML text to a file and return the path."""
    path.write_text(content, encoding="utf-8")
    return path


def _minimal_yaml() -> str:
    return """\
organizations:
  - name: my-org
    token: ghp_test123
"""


def _yaml_with_defaults() -> str:
    return """\
defaults:
  scan_profile: deep
  concurrency: 4
organizations:
  - name: org-a
    token: ghp_aaa
  - name: org-b
    token: ghp_bbb
    concurrency: 16
"""


def _yaml_with_env_var() -> str:
    return """\
organizations:
  - name: my-org
    token: "${GH_AUDIT_TEST_TOKEN}"
"""


def _pat_org(**kwargs) -> OrgEntry:
    defaults = {"name": "test-org", "token": "ghp_test"}
    defaults.update(kwargs)
    return OrgEntry(**defaults)


def _make_inventory(org: str = "test-org") -> Inventory:
    """Build a minimal valid Inventory for testing."""
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="1.0",
            generated_at="2026-01-01T00:00:00Z",
            tool_version="0.1.0",
            organization=org,
            auth_method="pat",
            scan_profile="standard",
            scan_warnings=[],
        ),
        summary=InventorySummary(
            total_repos=5,
            total_size_bytes=1024,
            total_issues=10,
            total_workflow_count=3,
            total_packages=2,
            total_projects=1,
        ),
        repositories=[],
        users=OrgMemberSummary(total=7, admins=2, members=4, outside_collaborators=1),
    )


# ---------------------------------------------------------------------------
# _expand_env_vars
# ---------------------------------------------------------------------------


class TestExpandEnvVars:
    """Environment variable expansion in config token values."""

    def test_expand_single_var(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "ghp_secret")
        assert _expand_env_vars("${MY_TOKEN}") == "ghp_secret"

    def test_expand_var_with_surrounding_text(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "secret")
        assert _expand_env_vars("prefix_${MY_TOKEN}_suffix") == "prefix_secret_suffix"

    def test_no_expansion_needed(self):
        assert _expand_env_vars("plain_text") == "plain_text"

    def test_missing_env_var_raises_config_error(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR_12345", raising=False)
        with pytest.raises(ConfigError, match="NONEXISTENT_VAR_12345"):
            _expand_env_vars("${NONEXISTENT_VAR_12345}")

    def test_multiple_vars(self, monkeypatch):
        monkeypatch.setenv("A", "hello")
        monkeypatch.setenv("B", "world")
        assert _expand_env_vars("${A}-${B}") == "hello-world"


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    """load_config reads and validates YAML multi-org configs."""

    def test_parses_valid_yaml(self, tmp_path):
        path = _write_yaml(tmp_path / "config.yml", _minimal_yaml())
        config = load_config(path)

        assert isinstance(config, MultiOrgConfig)
        assert len(config.organizations) == 1
        assert config.organizations[0].name == "my-org"
        assert config.organizations[0].token == "ghp_test123"

    def test_parses_yaml_with_defaults(self, tmp_path):
        path = _write_yaml(tmp_path / "config.yml", _yaml_with_defaults())
        config = load_config(path)

        assert config.defaults["scan_profile"] == "deep"
        assert config.defaults["concurrency"] == 4
        assert len(config.organizations) == 2

    def test_expands_env_var_in_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GH_AUDIT_TEST_TOKEN", "ghp_from_env")
        path = _write_yaml(tmp_path / "config.yml", _yaml_with_env_var())
        config = load_config(path)

        assert config.organizations[0].token == "ghp_from_env"

    def test_raises_config_error_for_missing_env_var(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GH_AUDIT_TEST_TOKEN", raising=False)
        path = _write_yaml(tmp_path / "config.yml", _yaml_with_env_var())

        with pytest.raises(ConfigError, match="GH_AUDIT_TEST_TOKEN"):
            load_config(path)

    def test_raises_config_error_for_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "nonexistent.yml")

    def test_raises_config_error_for_invalid_yaml(self, tmp_path):
        path = _write_yaml(tmp_path / "bad.yml", ":\n  :\n  - [invalid: yaml: {")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(path)

    def test_raises_config_error_for_validation_failure(self, tmp_path):
        # Missing required 'organizations' field
        path = _write_yaml(tmp_path / "config.yml", "defaults:\n  concurrency: 4\n")
        with pytest.raises(ConfigError, match="validation failed"):
            load_config(path)

    def test_raises_config_error_for_non_mapping(self, tmp_path):
        path = _write_yaml(tmp_path / "config.yml", "- just\n- a\n- list\n")
        with pytest.raises(ConfigError, match="mapping"):
            load_config(path)

    def test_expands_env_var_in_private_key_path(self, tmp_path, monkeypatch):
        """I4: ${ENV_VAR} in private_key_path must be expanded on load."""
        monkeypatch.setenv("GH_APP_KEY_PATH", "/tmp/key.pem")
        yaml_text = """\
organizations:
  - name: my-org
    app_id: 1
    private_key_path: "${GH_APP_KEY_PATH}"
    installation_id: 2
"""
        path = _write_yaml(tmp_path / "config.yml", yaml_text)
        config = load_config(path)
        assert config.organizations[0].private_key_path == "/tmp/key.pem"

    def test_missing_env_var_in_private_key_path_raises(self, tmp_path, monkeypatch):
        """I4: unset env var in private_key_path raises ConfigError."""
        monkeypatch.delenv("GH_APP_KEY_PATH_MISSING", raising=False)
        yaml_text = """\
organizations:
  - name: my-org
    app_id: 1
    private_key_path: "${GH_APP_KEY_PATH_MISSING}"
    installation_id: 2
"""
        path = _write_yaml(tmp_path / "config.yml", yaml_text)
        with pytest.raises(ConfigError, match="GH_APP_KEY_PATH_MISSING"):
            load_config(path)


# ---------------------------------------------------------------------------
# build_scanner_config
# ---------------------------------------------------------------------------


class TestBuildScannerConfig:
    """build_scanner_config merges CLI > per-org > defaults > built-in."""

    def test_basic_merge_with_pat(self):
        org = _pat_org(name="acme")
        config = build_scanner_config(org, defaults={}, cli_overrides={})

        assert config.organization == "acme"
        assert config.token is not None
        assert config.token.get_secret_value() == "ghp_test"

    def test_cli_overrides_win(self):
        org = _pat_org(concurrency=4)
        config = build_scanner_config(
            org,
            defaults={"concurrency": 2},
            cli_overrides={"concurrency": 32},
        )
        assert config.concurrency == 32

    def test_per_org_overrides_defaults(self):
        org = _pat_org(concurrency=16)
        config = build_scanner_config(
            org,
            defaults={"concurrency": 4},
            cli_overrides={},
        )
        assert config.concurrency == 16

    def test_defaults_fill_missing_values(self):
        org = _pat_org()  # concurrency=None (OrgEntry default)
        config = build_scanner_config(
            org,
            defaults={"concurrency": 4, "scan_profile": "deep"},
            cli_overrides={},
        )
        assert config.concurrency == 4
        assert config.scan_profile == "deep"

    def test_builtin_defaults_when_all_none(self):
        org = _pat_org()
        config = build_scanner_config(org, defaults={}, cli_overrides={})

        # ScannerConfig built-in defaults
        assert config.api_url == "https://api.github.com"
        assert config.scan_profile == "standard"
        assert config.concurrency == 8
        assert config.include_archived is True

    def test_token_is_secret_str(self):
        org = _pat_org()
        config = build_scanner_config(org, defaults={}, cli_overrides={})
        assert isinstance(config.token, SecretStr)

    def test_app_auth_fields(self):
        org = OrgEntry(
            name="app-org",
            app_id=123,
            private_key_path="/tmp/key.pem",
            installation_id=456,
        )
        config = build_scanner_config(org, defaults={}, cli_overrides={})

        assert config.app_id == 123
        assert config.installation_id == 456
        assert config.token is None

    def test_api_url_from_per_org(self):
        org = _pat_org(api_url="https://github.example.com/api/v3")
        config = build_scanner_config(org, defaults={}, cli_overrides={})
        assert config.api_url == "https://github.example.com/api/v3"

    def test_multiple_fields_merged(self):
        org = _pat_org(scan_large_files=True)
        config = build_scanner_config(
            org,
            defaults={"concurrency": 4, "include_archived": False},
            cli_overrides={"repo_limit": 50},
        )
        assert config.scan_large_files is True
        assert config.concurrency == 4
        assert config.include_archived is False
        assert config.repo_limit == 50


# ---------------------------------------------------------------------------
# run_all_orgs
# ---------------------------------------------------------------------------


class TestRunAllOrgs:
    """run_all_orgs scans each organization and returns a MultiOrgSummary."""

    @pytest.fixture
    def mock_discovery(self):
        """Patch DiscoveryService.discover to return a minimal Inventory."""
        inventory = _make_inventory()
        with patch("gh_audit.services.multi_org.DiscoveryService") as MockDiscovery:
            instance = MockDiscovery.return_value
            instance.discover = AsyncMock(return_value=inventory)
            yield MockDiscovery, inventory

    @pytest.fixture
    def mock_clients(self):
        """Patch client constructors and verify_credentials."""
        with (
            patch("gh_audit.services.multi_org.GitHubRestClient") as MockRest,
            patch("gh_audit.services.multi_org.GitHubGraphQLClient") as MockGql,
        ):
            rest_instance = MockRest.return_value
            rest_instance.verify_credentials = AsyncMock(return_value={})
            rest_instance.close = AsyncMock()
            MockGql.return_value.close = AsyncMock()
            yield MockRest, MockGql

    @pytest.fixture
    def mock_reports(self):
        """Patch ReportService and ExcelExportService."""
        with (
            patch("gh_audit.services.multi_org.ReportService") as MockReport,
            patch("gh_audit.services.multi_org.ExcelExportService") as MockExcel,
        ):
            MockReport.return_value.generate = MagicMock()
            MockExcel.generate = MagicMock()
            yield MockReport, MockExcel

    @pytest.mark.asyncio
    async def test_returns_summary_with_results(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        config = MultiOrgConfig(
            organizations=[
                {"name": "org-a", "token": "ghp_aaa"},
                {"name": "org-b", "token": "ghp_bbb"},
            ]
        )

        summary = await run_all_orgs(
            config,
            config_path=Path("multi-org.yml"),
            output_dir=tmp_path,
        )

        assert len(summary.organizations) == 2
        assert summary.organizations[0].name == "org-a"
        assert summary.organizations[1].name == "org-b"
        assert summary.config_file == "multi-org.yml"

    @pytest.mark.asyncio
    async def test_successful_org_has_correct_status(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        summary = await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
        )

        result = summary.organizations[0]
        assert result.status == "success"
        assert result.total_repos == 5
        assert result.total_members == 7
        assert result.total_workflows == 3
        assert result.total_issues == 10
        assert result.total_packages == 2
        assert result.total_projects == 1

    @pytest.mark.asyncio
    async def test_continues_after_org_failure(self, tmp_path, mock_clients, mock_reports):
        """When one org fails, the runner continues with the next."""
        inventories = [
            RuntimeError("API down"),
            _make_inventory("org-b"),
        ]
        call_count = 0

        async def _discover_side_effect():
            nonlocal call_count
            result = inventories[call_count]
            call_count += 1
            if isinstance(result, Exception):
                raise result
            return result

        with patch("gh_audit.services.multi_org.DiscoveryService") as MockDiscovery:
            instance = MockDiscovery.return_value
            instance.discover = AsyncMock(side_effect=_discover_side_effect)

            config = MultiOrgConfig(
                organizations=[
                    {"name": "org-a", "token": "ghp_aaa"},
                    {"name": "org-b", "token": "ghp_bbb"},
                ]
            )

            summary = await run_all_orgs(
                config,
                config_path=Path("config.yml"),
                output_dir=tmp_path,
            )

        assert len(summary.organizations) == 2
        assert summary.organizations[0].status == "failed"
        assert summary.organizations[1].status == "success"

    @pytest.mark.asyncio
    async def test_failed_org_records_error_message(self, tmp_path, mock_clients, mock_reports):
        with patch("gh_audit.services.multi_org.DiscoveryService") as MockDiscovery:
            instance = MockDiscovery.return_value
            instance.discover = AsyncMock(side_effect=RuntimeError("connection refused"))

            config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

            summary = await run_all_orgs(
                config,
                config_path=Path("config.yml"),
                output_dir=tmp_path,
            )

        result = summary.organizations[0]
        assert result.status == "failed"
        assert result.error == "connection refused"

    @pytest.mark.asyncio
    async def test_saves_inventory_json(self, tmp_path, mock_clients, mock_discovery, mock_reports):
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
        )

        date_prefix = date.today().isoformat()
        json_path = tmp_path / "org-a" / f"{date_prefix}-inventory.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["metadata"]["organization"] == "test-org"

    @pytest.mark.asyncio
    async def test_generates_html_when_enabled(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        MockReport, _ = mock_reports
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
            generate_html=True,
        )

        MockReport.return_value.generate.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_html_when_disabled(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        MockReport, _ = mock_reports
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
            generate_html=False,
        )

        MockReport.return_value.generate.assert_not_called()

    @pytest.mark.asyncio
    async def test_generates_excel_when_enabled(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        _, MockExcel = mock_reports
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
            generate_excel=True,
        )

        MockExcel.generate.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_excel_when_disabled(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        _, MockExcel = mock_reports
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
            generate_excel=False,
        )

        MockExcel.generate.assert_not_called()

    @pytest.mark.asyncio
    async def test_tool_version_in_summary(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        summary = await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
        )

        from gh_audit.__about__ import __version__

        assert summary.tool_version == __version__

    @pytest.mark.asyncio
    async def test_clients_are_closed_on_success(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        """C2: REST and GraphQL clients must be closed after each org scan."""
        MockRest, MockGql = mock_clients
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
        )

        MockRest.return_value.close.assert_awaited_once()
        MockGql.return_value.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_clients_are_closed_on_failure(self, tmp_path, mock_clients, mock_reports):
        """C2: REST and GraphQL clients must be closed even when discovery raises."""
        MockRest, MockGql = mock_clients
        with patch("gh_audit.services.multi_org.DiscoveryService") as MockDiscovery:
            MockDiscovery.return_value.discover = AsyncMock(side_effect=RuntimeError("boom"))
            config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

            await run_all_orgs(
                config,
                config_path=Path("config.yml"),
                output_dir=tmp_path,
            )

        MockRest.return_value.close.assert_awaited_once()
        MockGql.return_value.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_inventory_filename_uses_date_prefix(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        """I5: per-org inventory JSON filename must start with date prefix."""
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        await run_all_orgs(
            config,
            config_path=Path("config.yml"),
            output_dir=tmp_path,
        )

        date_prefix = date.today().isoformat()
        json_path = tmp_path / "org-a" / f"{date_prefix}-inventory.json"
        assert json_path.exists(), f"Expected {json_path} to exist"
        # Old name must NOT exist
        old_path = tmp_path / "org-a" / "org-a-inventory.json"
        assert not old_path.exists(), "Old org-name prefix file must not be created"

    @pytest.mark.asyncio
    async def test_cli_api_url_override_forwarded(
        self, tmp_path, mock_clients, mock_discovery, mock_reports
    ):
        """I6: api_url passed as cli_override must reach build_scanner_config."""
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_aaa"}])

        from gh_audit.services.multi_org import build_scanner_config

        with patch(
            "gh_audit.services.multi_org.build_scanner_config",
            wraps=build_scanner_config,
        ) as mock_build:
            await run_all_orgs(
                config,
                config_path=Path("config.yml"),
                cli_overrides={"api_url": "https://github.example.com/api/v3"},
                output_dir=tmp_path,
            )

        _call_kwargs = mock_build.call_args
        assert _call_kwargs is not None
        cli_overrides_arg = _call_kwargs.args[2]
        assert cli_overrides_arg.get("api_url") == "https://github.example.com/api/v3"
