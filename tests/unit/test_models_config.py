"""Tests for gh_audit.models.config — ScannerConfig model."""

from __future__ import annotations

import pathlib

import pytest
from pydantic import ValidationError

from gh_audit.models.config import ScannerConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pat_config(**kwargs) -> ScannerConfig:
    """Build a minimal PAT-authenticated ScannerConfig."""
    defaults = {"organization": "my-org", "token": "ghp_test123"}
    defaults.update(kwargs)
    return ScannerConfig(**defaults)


def _app_config(**kwargs) -> ScannerConfig:
    """Build a minimal GitHub App-authenticated ScannerConfig."""
    defaults = {
        "organization": "my-org",
        "app_id": 12345,
        "private_key_path": pathlib.Path("/tmp/key.pem"),
        "installation_id": 67890,
    }
    defaults.update(kwargs)
    return ScannerConfig(**defaults)


# ---------------------------------------------------------------------------
# Default values (PAT auth path)
# ---------------------------------------------------------------------------


class TestScannerConfigDefaults:
    """Defaults match the spec exactly."""

    def test_scan_profile_default(self):
        settings = _pat_config()
        assert settings.scan_profile == "standard"

    def test_concurrency_default(self):
        settings = _pat_config()
        assert settings.concurrency == 8

    def test_security_alert_counts_default(self):
        settings = _pat_config()
        assert settings.security_alert_counts is False

    def test_scan_large_files_default(self):
        settings = _pat_config()
        assert settings.scan_large_files is False

    def test_scan_workflow_contents_default(self):
        settings = _pat_config()
        assert settings.scan_workflow_contents is False

    def test_repo_limit_default_is_none(self):
        settings = _pat_config()
        assert settings.repo_limit is None

    def test_api_url_default(self):
        settings = _pat_config()
        assert settings.api_url == "https://api.github.com"

    def test_telemetry_disabled_default(self):
        settings = _pat_config()
        assert settings.telemetry_disabled is False

    def test_include_archived_default(self):
        settings = _pat_config()
        assert settings.include_archived is True


# ---------------------------------------------------------------------------
# Auth method detection
# ---------------------------------------------------------------------------


class TestAuthMethod:
    """auth_method property returns correct string."""

    def test_pat_auth_method(self):
        settings = _pat_config()
        assert settings.auth_method == "pat"

    def test_github_app_auth_method(self):
        settings = _app_config()
        assert settings.auth_method == "github_app"


# ---------------------------------------------------------------------------
# graphql_url derivation
# ---------------------------------------------------------------------------


class TestGraphQLUrl:
    """graphql_url derived from api_url."""

    def test_default_github_dot_com(self):
        settings = _pat_config()
        assert settings.graphql_url == "https://api.github.com/graphql"

    def test_ghes_api_v3_path(self):
        settings = _pat_config(api_url="https://github.example.com/api/v3")
        assert settings.graphql_url == "https://github.example.com/api/graphql"

    def test_trailing_slash_stripped(self):
        settings = _pat_config(api_url="https://api.github.com/")
        assert settings.graphql_url == "https://api.github.com/graphql"

    def test_ghes_with_trailing_slash(self):
        settings = _pat_config(api_url="https://github.example.com/api/v3/")
        assert settings.graphql_url == "https://github.example.com/api/graphql"


# ---------------------------------------------------------------------------
# Token as SecretStr
# ---------------------------------------------------------------------------


class TestTokenSecurity:
    """Token must be stored as SecretStr to prevent accidental logging."""

    def test_token_not_exposed_in_repr(self):
        settings = _pat_config(token="ghp_supersecret")
        assert "ghp_supersecret" not in repr(settings)

    def test_token_not_exposed_in_str(self):
        settings = _pat_config(token="ghp_supersecret")
        assert "ghp_supersecret" not in str(settings)

    def test_token_get_secret_value(self):
        settings = _pat_config(token="ghp_supersecret")
        assert settings.token.get_secret_value() == "ghp_supersecret"


# ---------------------------------------------------------------------------
# Auth validation
# ---------------------------------------------------------------------------


class TestAuthValidation:
    """Either token or full app credentials are required."""

    def test_no_auth_raises_validation_error(self):
        with pytest.raises(ValidationError):
            ScannerConfig(organization="my-org")

    def test_partial_app_config_missing_private_key_raises(self):
        with pytest.raises(ValidationError):
            ScannerConfig(
                organization="my-org",
                app_id=12345,
                installation_id=67890,
                # private_key_path missing
            )

    def test_partial_app_config_missing_installation_id_raises(self):
        with pytest.raises(ValidationError):
            ScannerConfig(
                organization="my-org",
                app_id=12345,
                private_key_path=pathlib.Path("/tmp/key.pem"),
                # installation_id missing
            )

    def test_partial_app_config_missing_app_id_raises(self):
        with pytest.raises(ValidationError):
            ScannerConfig(
                organization="my-org",
                private_key_path=pathlib.Path("/tmp/key.pem"),
                installation_id=67890,
                # app_id missing
            )

    def test_full_pat_config_valid(self):
        settings = _pat_config()
        assert settings.token is not None

    def test_full_app_config_valid(self):
        settings = _app_config()
        assert settings.app_id == 12345
        assert settings.installation_id == 67890
        assert settings.private_key_path == pathlib.Path("/tmp/key.pem")


# ---------------------------------------------------------------------------
# Extra fields forbidden
# ---------------------------------------------------------------------------


class TestExtraFieldsForbidden:
    """extra='forbid' rejects unknown fields."""

    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            ScannerConfig(
                organization="my-org",
                token="ghp_test",
                unknown_field="bad",
            )


# ---------------------------------------------------------------------------
# Organization field required
# ---------------------------------------------------------------------------


class TestOrganizationRequired:
    """organization field is required."""

    def test_missing_organization_raises(self):
        with pytest.raises(ValidationError):
            ScannerConfig(token="ghp_test")


# ---------------------------------------------------------------------------
# Field value constraints
# ---------------------------------------------------------------------------


class TestFieldConstraints:
    """Validate field constraints like concurrency bounds."""

    def test_concurrency_accepts_positive_int(self):
        settings = _pat_config(concurrency=16)
        assert settings.concurrency == 16

    def test_repo_limit_none_means_no_limit(self):
        settings = _pat_config(repo_limit=None)
        assert settings.repo_limit is None

    def test_repo_limit_positive_int(self):
        settings = _pat_config(repo_limit=500)
        assert settings.repo_limit == 500

    def test_scan_profile_deep(self):
        settings = _pat_config(scan_profile="deep")
        assert settings.scan_profile == "deep"

    def test_scan_profile_invalid_raises(self):
        with pytest.raises(ValidationError):
            _pat_config(scan_profile="full")

    def test_scan_profile_minimal_invalid_raises(self):
        with pytest.raises(ValidationError):
            _pat_config(scan_profile="minimal")


# ---------------------------------------------------------------------------
# Deep profile auto-enables sub-features
# ---------------------------------------------------------------------------


class TestDeepProfileAutoEnable:
    """scan_profile='deep' auto-enables scan_large_files, scan_workflow_contents, security_alert_counts."""

    def test_deep_enables_scan_large_files(self):
        settings = _pat_config(scan_profile="deep")
        assert settings.scan_large_files is True

    def test_deep_enables_scan_workflow_contents(self):
        settings = _pat_config(scan_profile="deep")
        assert settings.scan_workflow_contents is True

    def test_deep_enables_security_alert_counts(self):
        settings = _pat_config(scan_profile="deep")
        assert settings.security_alert_counts is True

    def test_standard_does_not_auto_enable(self):
        settings = _pat_config(scan_profile="standard")
        assert settings.scan_large_files is False
        assert settings.scan_workflow_contents is False
        assert settings.security_alert_counts is False
