"""Tests for gh_audit.cli.credential_resolver — credential resolution logic.

Resolution hierarchy: CLI args > env vars > .env file
"""

from __future__ import annotations

import pathlib
import textwrap

import pytest

from gh_audit.cli.credential_resolver import parse_env_file, resolve_settings
from gh_audit.exceptions import ConfigError
from gh_audit.models.config import ScannerConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_env_file(tmp_path: pathlib.Path, content: str) -> pathlib.Path:
    """Write a .env file to tmp_path and return the path."""
    env_file = tmp_path / ".env"
    env_file.write_text(textwrap.dedent(content))
    return env_file


# ---------------------------------------------------------------------------
# parse_env_file — unit tests
# ---------------------------------------------------------------------------


class TestParseEnvFile:
    """parse_env_file handles all .env syntax variants."""

    def test_simple_key_value(self, tmp_path):
        path = _write_env_file(tmp_path, "KEY=VALUE\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_double_quoted_value(self, tmp_path):
        path = _write_env_file(tmp_path, 'KEY="VALUE"\n')
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_single_quoted_value(self, tmp_path):
        path = _write_env_file(tmp_path, "KEY='VALUE'\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_comment_lines_ignored(self, tmp_path):
        path = _write_env_file(tmp_path, "# this is a comment\nKEY=VALUE\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_inline_comment_ignored(self, tmp_path):
        # Only leading # comments; inline comments are NOT stripped (values may contain #)
        path = _write_env_file(tmp_path, "KEY=VALUE\n")
        result = parse_env_file(path)
        assert result["KEY"] == "VALUE"

    def test_blank_lines_ignored(self, tmp_path):
        path = _write_env_file(tmp_path, "\nKEY=VALUE\n\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_export_prefix_stripped(self, tmp_path):
        path = _write_env_file(tmp_path, "export KEY=VALUE\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_export_prefix_with_quotes(self, tmp_path):
        path = _write_env_file(tmp_path, 'export KEY="VALUE"\n')
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_multiple_keys(self, tmp_path):
        path = _write_env_file(
            tmp_path,
            """\
            GH_SCANNER_TOKEN=ghp_test
            GH_SCANNER_ORGANIZATION=myorg
            """,
        )
        result = parse_env_file(path)
        assert result["GH_SCANNER_TOKEN"] == "ghp_test"
        assert result["GH_SCANNER_ORGANIZATION"] == "myorg"

    def test_nonexistent_file_returns_empty_dict(self, tmp_path):
        result = parse_env_file(tmp_path / "nonexistent.env")
        assert result == {}

    def test_smart_quote_left_double_stripped(self, tmp_path):
        # Unicode left double quotation mark U+201C
        path = _write_env_file(tmp_path, "KEY=\u201cVALUE\u201d\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_smart_quote_left_single_stripped(self, tmp_path):
        # Unicode left single quotation mark U+2018
        path = _write_env_file(tmp_path, "KEY=\u2018VALUE\u2019\n")
        assert parse_env_file(path) == {"KEY": "VALUE"}

    def test_value_with_equals_sign(self, tmp_path):
        # Value itself contains = (e.g. a base64 token with padding)
        path = _write_env_file(tmp_path, "KEY=abc=def=\n")
        assert parse_env_file(path) == {"KEY": "abc=def="}

    def test_value_with_spaces_in_quotes(self, tmp_path):
        path = _write_env_file(tmp_path, 'KEY="hello world"\n')
        assert parse_env_file(path) == {"KEY": "hello world"}


# ---------------------------------------------------------------------------
# resolve_settings — auth method detection
# ---------------------------------------------------------------------------


class TestResolveSettingsAuthMethod:
    """resolve_settings correctly detects PAT vs GitHub App."""

    def test_github_app_auth_method(self, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text("fake-pem")
        settings = resolve_settings(
            app_id=1,
            private_key_path=str(key_file),
            installation_id=2,
            organization="myorg",
        )
        assert settings.auth_method == "github_app"

    def test_pat_auth_method(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        settings = resolve_settings(token="ghp_test", organization="myorg")
        assert settings.auth_method == "pat"

    def test_returns_scanner_config_instance(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        settings = resolve_settings(token="ghp_test", organization="myorg")
        assert isinstance(settings, ScannerConfig)


# ---------------------------------------------------------------------------
# resolve_settings — resolution hierarchy (CLI > env > .env)
# ---------------------------------------------------------------------------


class TestResolveSettingsHierarchy:
    """CLI args take precedence over env vars which take precedence over .env."""

    def test_cli_overrides_env_token(self, monkeypatch):
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_from_env")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "env-org")
        settings = resolve_settings(token="ghp_from_cli", organization="cli-org")
        assert settings.token.get_secret_value() == "ghp_from_cli"
        assert settings.organization == "cli-org"

    def test_cli_overrides_env_organization(self, monkeypatch):
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "env-org")
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_env")
        settings = resolve_settings(organization="cli-org")
        assert settings.organization == "cli-org"

    def test_env_used_when_no_cli_token(self, monkeypatch):
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_from_env")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "env-org")
        settings = resolve_settings()
        assert settings.token.get_secret_value() == "ghp_from_env"
        assert settings.organization == "env-org"

    def test_dotenv_fallback_when_no_env_vars(self, monkeypatch, tmp_path):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        env_file = _write_env_file(
            tmp_path,
            """\
            GH_SCANNER_TOKEN=ghp_dotenv
            GH_SCANNER_ORGANIZATION=dotenv-org
            """,
        )
        settings = resolve_settings(env_path=env_file)
        assert settings.token.get_secret_value() == "ghp_dotenv"
        assert settings.organization == "dotenv-org"

    def test_cli_overrides_dotenv(self, monkeypatch, tmp_path):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        env_file = _write_env_file(
            tmp_path,
            """\
            GH_SCANNER_TOKEN=ghp_dotenv
            GH_SCANNER_ORGANIZATION=dotenv-org
            """,
        )
        settings = resolve_settings(token="ghp_cli", organization="cli-org", env_path=env_file)
        assert settings.token.get_secret_value() == "ghp_cli"
        assert settings.organization == "cli-org"

    def test_env_overrides_dotenv(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_env")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "env-org")
        env_file = _write_env_file(
            tmp_path,
            """\
            GH_SCANNER_TOKEN=ghp_dotenv
            GH_SCANNER_ORGANIZATION=dotenv-org
            """,
        )
        settings = resolve_settings(env_path=env_file)
        assert settings.token.get_secret_value() == "ghp_env"
        assert settings.organization == "env-org"

    def test_env_path_override(self, monkeypatch, tmp_path):
        """env_path kwarg overrides default .env lookup location."""
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        custom_env = tmp_path / "custom.env"
        custom_env.write_text("GH_SCANNER_TOKEN=ghp_custom\nGH_SCANNER_ORGANIZATION=custom-org\n")
        settings = resolve_settings(env_path=custom_env)
        assert settings.token.get_secret_value() == "ghp_custom"
        assert settings.organization == "custom-org"


# ---------------------------------------------------------------------------
# resolve_settings — token validation
# ---------------------------------------------------------------------------


class TestResolveSettingsTokenValidation:
    """Non-ASCII tokens must be rejected with ConfigError."""

    def test_ascii_token_accepted(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        settings = resolve_settings(token="ghp_ASCII_only_123", organization="myorg")
        assert settings.token.get_secret_value() == "ghp_ASCII_only_123"

    def test_non_ascii_token_raises_config_error(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        with pytest.raises(ConfigError) as exc_info:
            resolve_settings(token="ghp_\u00e9l\u00e8ve", organization="myorg")
        assert exc_info.value.exit_code == 2

    def test_non_ascii_token_from_env_raises_config_error(self, monkeypatch):
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_caf\u00e9")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
        with pytest.raises(ConfigError):
            resolve_settings()

    def test_non_ascii_token_from_dotenv_raises_config_error(self, monkeypatch, tmp_path):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        env_file = _write_env_file(
            tmp_path,
            "GH_SCANNER_TOKEN=ghp_caf\u00e9\nGH_SCANNER_ORGANIZATION=myorg\n",
        )
        with pytest.raises(ConfigError):
            resolve_settings(env_path=env_file)


# ---------------------------------------------------------------------------
# resolve_settings — optional fields and defaults
# ---------------------------------------------------------------------------


class TestResolveSettingsOptionalFields:
    """Optional fields are forwarded correctly."""

    def test_api_url_from_cli(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_API_URL", raising=False)
        settings = resolve_settings(
            token="ghp_test",
            organization="myorg",
            api_url="https://github.example.com/api/v3",
        )
        assert settings.api_url == "https://github.example.com/api/v3"

    def test_api_url_from_env(self, monkeypatch):
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
        monkeypatch.setenv("GH_SCANNER_API_URL", "https://ghes.example.com/api/v3")
        settings = resolve_settings()
        assert settings.api_url == "https://ghes.example.com/api/v3"

    def test_api_url_default_when_not_set(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_API_URL", raising=False)
        settings = resolve_settings(token="ghp_test", organization="myorg")
        assert settings.api_url == "https://api.github.com"

    def test_telemetry_disabled_from_env(self, monkeypatch):
        monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
        monkeypatch.setenv("GH_SCANNER_TELEMETRY_DISABLED", "true")
        settings = resolve_settings()
        assert settings.telemetry_disabled is True

    def test_app_credentials_from_env(self, monkeypatch, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text("fake-pem")
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.setenv("GH_SCANNER_APP_ID", "42")
        monkeypatch.setenv("GH_SCANNER_PRIVATE_KEY_PATH", str(key_file))
        monkeypatch.setenv("GH_SCANNER_INSTALLATION_ID", "99")
        monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "app-org")
        settings = resolve_settings()
        assert settings.auth_method == "github_app"
        assert settings.app_id == 42
        assert settings.installation_id == 99

    def test_app_credentials_from_dotenv(self, monkeypatch, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text("fake-pem")
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_APP_ID", raising=False)
        monkeypatch.delenv("GH_SCANNER_PRIVATE_KEY_PATH", raising=False)
        monkeypatch.delenv("GH_SCANNER_INSTALLATION_ID", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        env_file = _write_env_file(
            tmp_path,
            f"""\
            GH_SCANNER_APP_ID=7
            GH_SCANNER_PRIVATE_KEY_PATH={key_file}
            GH_SCANNER_INSTALLATION_ID=55
            GH_SCANNER_ORGANIZATION=dotenv-app-org
            """,
        )
        settings = resolve_settings(env_path=env_file)
        assert settings.auth_method == "github_app"
        assert settings.app_id == 7

    def test_missing_all_credentials_raises_config_error(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        monkeypatch.delenv("GH_SCANNER_APP_ID", raising=False)
        monkeypatch.delenv("GH_SCANNER_PRIVATE_KEY_PATH", raising=False)
        monkeypatch.delenv("GH_SCANNER_INSTALLATION_ID", raising=False)
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        with pytest.raises(ConfigError):
            resolve_settings(organization="myorg")

    def test_missing_organization_raises_config_error(self, monkeypatch):
        monkeypatch.delenv("GH_SCANNER_ORGANIZATION", raising=False)
        monkeypatch.delenv("GH_SCANNER_TOKEN", raising=False)
        with pytest.raises(ConfigError):
            resolve_settings(token="ghp_test")
