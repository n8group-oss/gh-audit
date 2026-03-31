"""Tests for gh_audit.models.multi_org — multi-org config and summary models."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from gh_audit.models.multi_org import (
    MultiOrgConfig,
    MultiOrgSummary,
    OrgEntry,
    OrgScanResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pat_entry(**kwargs) -> OrgEntry:
    defaults = {"name": "my-org", "token": "ghp_test123"}
    defaults.update(kwargs)
    return OrgEntry(**defaults)


def _app_entry(**kwargs) -> OrgEntry:
    defaults = {
        "name": "my-org",
        "app_id": 12345,
        "private_key_path": "/tmp/key.pem",
        "installation_id": 67890,
    }
    defaults.update(kwargs)
    return OrgEntry(**defaults)


def _success_result(**kwargs) -> OrgScanResult:
    defaults = {"name": "my-org", "status": "success"}
    defaults.update(kwargs)
    return OrgScanResult(**defaults)


def _failed_result(**kwargs) -> OrgScanResult:
    defaults = {"name": "my-org", "status": "failed", "error": "timeout"}
    defaults.update(kwargs)
    return OrgScanResult(**defaults)


# ---------------------------------------------------------------------------
# OrgEntry — PAT auth
# ---------------------------------------------------------------------------


class TestOrgEntryPatAuth:
    """OrgEntry with PAT authentication."""

    def test_pat_entry_valid(self):
        entry = _pat_entry()
        assert entry.name == "my-org"
        assert entry.token == "ghp_test123"

    def test_pat_entry_app_fields_are_none(self):
        entry = _pat_entry()
        assert entry.app_id is None
        assert entry.private_key_path is None
        assert entry.installation_id is None

    def test_pat_entry_api_url_default_none(self):
        entry = _pat_entry()
        assert entry.api_url is None

    def test_pat_entry_scan_profile_default_none(self):
        entry = _pat_entry()
        assert entry.scan_profile is None


# ---------------------------------------------------------------------------
# OrgEntry — App auth
# ---------------------------------------------------------------------------


class TestOrgEntryAppAuth:
    """OrgEntry with GitHub App authentication."""

    def test_app_entry_valid(self):
        entry = _app_entry()
        assert entry.name == "my-org"
        assert entry.app_id == 12345
        assert entry.private_key_path == "/tmp/key.pem"
        assert entry.installation_id == 67890

    def test_app_entry_token_is_none(self):
        entry = _app_entry()
        assert entry.token is None


# ---------------------------------------------------------------------------
# OrgEntry — auth validation errors
# ---------------------------------------------------------------------------


class TestOrgEntryAuthValidation:
    """OrgEntry raises ValidationError for missing/incomplete auth."""

    def test_no_auth_raises_validation_error(self):
        with pytest.raises(ValidationError) as exc_info:
            OrgEntry(name="my-org")
        assert "my-org" in str(exc_info.value)

    def test_partial_app_auth_missing_private_key_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            OrgEntry(name="bad-org", app_id=1, installation_id=2)
        assert "bad-org" in str(exc_info.value)

    def test_partial_app_auth_missing_installation_id_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            OrgEntry(name="bad-org", app_id=1, private_key_path="/tmp/key.pem")
        assert "bad-org" in str(exc_info.value)

    def test_partial_app_auth_missing_app_id_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            OrgEntry(name="bad-org", private_key_path="/tmp/key.pem", installation_id=2)
        assert "bad-org" in str(exc_info.value)

    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            OrgEntry(name="my-org", token="ghp_test", unexpected_field="value")

    def test_dual_auth_pat_and_app_raises(self):
        """I3: providing both PAT and all App credentials must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            OrgEntry(
                name="dual-org",
                token="ghp_test",
                app_id=1,
                private_key_path="/tmp/key.pem",
                installation_id=2,
            )
        assert "not both" in str(exc_info.value)

    def test_dual_auth_error_message_includes_org_name(self):
        """I3: error message must reference the organisation name."""
        with pytest.raises(ValidationError) as exc_info:
            OrgEntry(
                name="acme-corp",
                token="ghp_secret",
                app_id=999,
                private_key_path="/tmp/key.pem",
                installation_id=42,
            )
        assert "acme-corp" in str(exc_info.value)


# ---------------------------------------------------------------------------
# OrgEntry — per-org overrides
# ---------------------------------------------------------------------------


class TestOrgEntryOverrides:
    """Per-org optional override fields."""

    def test_api_url_override(self):
        entry = _pat_entry(api_url="https://github.example.com/api/v3")
        assert entry.api_url == "https://github.example.com/api/v3"

    def test_scan_profile_override(self):
        entry = _pat_entry(scan_profile="deep")
        assert entry.scan_profile == "deep"

    def test_scan_large_files_override(self):
        entry = _pat_entry(scan_large_files=True)
        assert entry.scan_large_files is True

    def test_scan_workflow_contents_override(self):
        entry = _pat_entry(scan_workflow_contents=True)
        assert entry.scan_workflow_contents is True

    def test_security_alert_counts_override(self):
        entry = _pat_entry(security_alert_counts=True)
        assert entry.security_alert_counts is True

    def test_repo_limit_override(self):
        entry = _pat_entry(repo_limit=100)
        assert entry.repo_limit == 100

    def test_concurrency_override(self):
        entry = _pat_entry(concurrency=4)
        assert entry.concurrency == 4

    def test_include_archived_override(self):
        entry = _pat_entry(include_archived=False)
        assert entry.include_archived is False

    def test_all_optional_override_fields_default_none(self):
        entry = _pat_entry()
        assert entry.scan_large_files is None
        assert entry.scan_workflow_contents is None
        assert entry.security_alert_counts is None
        assert entry.repo_limit is None
        assert entry.concurrency is None
        assert entry.include_archived is None


# ---------------------------------------------------------------------------
# MultiOrgConfig
# ---------------------------------------------------------------------------


class TestMultiOrgConfig:
    """MultiOrgConfig root config model."""

    def test_minimal_config(self):
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_abc"}])
        assert len(config.organizations) == 1
        assert config.organizations[0].name == "org-a"

    def test_defaults_empty_by_default(self):
        config = MultiOrgConfig(organizations=[{"name": "org-a", "token": "ghp_abc"}])
        assert config.defaults == {}

    def test_with_defaults(self):
        config = MultiOrgConfig(
            defaults={"scan_profile": "deep", "concurrency": 4},
            organizations=[{"name": "org-a", "token": "ghp_abc"}],
        )
        assert config.defaults["scan_profile"] == "deep"
        assert config.defaults["concurrency"] == 4

    def test_multiple_orgs(self):
        config = MultiOrgConfig(
            organizations=[
                {"name": "org-a", "token": "ghp_abc"},
                {"name": "org-b", "token": "ghp_def"},
            ]
        )
        assert len(config.organizations) == 2

    def test_empty_organizations_raises(self):
        with pytest.raises(ValidationError):
            MultiOrgConfig(organizations=[])

    def test_missing_organizations_raises(self):
        with pytest.raises(ValidationError):
            MultiOrgConfig()

    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            MultiOrgConfig(
                organizations=[{"name": "org-a", "token": "ghp_abc"}],
                unexpected="value",
            )


# ---------------------------------------------------------------------------
# OrgScanResult
# ---------------------------------------------------------------------------


class TestOrgScanResult:
    """OrgScanResult per-org result model."""

    def test_success_result_defaults(self):
        result = _success_result()
        assert result.name == "my-org"
        assert result.status == "success"
        assert result.error is None
        assert result.total_repos == 0
        assert result.total_size_bytes == 0
        assert result.total_members == 0
        assert result.total_workflows == 0
        assert result.total_issues == 0
        assert result.total_packages == 0
        assert result.total_projects == 0
        assert result.warnings_count == 0
        assert result.duration_seconds == 0.0

    def test_success_result_with_data(self):
        result = _success_result(
            total_repos=42,
            total_size_bytes=1024,
            total_members=10,
            total_workflows=5,
            total_issues=20,
            total_packages=3,
            total_projects=2,
            warnings_count=1,
            duration_seconds=12.5,
            scan_profile="standard",
            auth_method="pat",
        )
        assert result.total_repos == 42
        assert result.total_size_bytes == 1024
        assert result.total_members == 10
        assert result.total_workflows == 5
        assert result.total_issues == 20
        assert result.total_packages == 3
        assert result.total_projects == 2
        assert result.warnings_count == 1
        assert result.duration_seconds == 12.5
        assert result.scan_profile == "standard"
        assert result.auth_method == "pat"

    def test_failed_result(self):
        result = _failed_result()
        assert result.status == "failed"
        assert result.error == "timeout"

    def test_failed_result_optional_fields_default(self):
        result = _failed_result()
        assert result.scan_profile is None
        assert result.auth_method is None

    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            OrgScanResult(name="my-org", status="success", bogus="field")


# ---------------------------------------------------------------------------
# MultiOrgSummary — totals property
# ---------------------------------------------------------------------------


class TestMultiOrgSummaryTotals:
    """MultiOrgSummary.totals aggregates only successful orgs."""

    def _make_summary(self, orgs: list[OrgScanResult]) -> MultiOrgSummary:
        return MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=orgs,
        )

    def test_totals_aggregate_successful_only(self):
        orgs = [
            _success_result(
                name="org-a",
                total_repos=10,
                total_size_bytes=500,
                total_members=5,
                total_workflows=3,
                total_issues=8,
                total_packages=1,
                total_projects=2,
            ),
            _failed_result(
                name="org-b",
                total_repos=99,  # should NOT be counted
            ),
            _success_result(
                name="org-c",
                total_repos=20,
                total_size_bytes=300,
                total_members=7,
                total_workflows=2,
                total_issues=4,
                total_packages=2,
                total_projects=1,
            ),
        ]
        summary = self._make_summary(orgs)
        totals = summary.totals

        assert totals.total_repos == 30
        assert totals.total_size_bytes == 800
        assert totals.total_members == 12
        assert totals.total_workflows == 5
        assert totals.total_issues == 12
        assert totals.total_packages == 3
        assert totals.total_projects == 3

    def test_totals_count_orgs(self):
        orgs = [
            _success_result(name="org-a"),
            _success_result(name="org-b"),
            _failed_result(name="org-c"),
        ]
        summary = self._make_summary(orgs)
        totals = summary.totals

        assert totals.organizations_scanned == 3
        assert totals.organizations_succeeded == 2
        assert totals.organizations_failed == 1

    def test_totals_all_failed(self):
        orgs = [
            _failed_result(name="org-a"),
            _failed_result(name="org-b"),
        ]
        summary = self._make_summary(orgs)
        totals = summary.totals

        assert totals.organizations_scanned == 2
        assert totals.organizations_succeeded == 0
        assert totals.organizations_failed == 2
        assert totals.total_repos == 0

    def test_totals_empty_orgs(self):
        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=[],
        )
        totals = summary.totals
        assert totals.organizations_scanned == 0
        assert totals.total_repos == 0

    def test_generated_at_is_utc_datetime(self):
        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=[],
        )
        assert isinstance(summary.generated_at, datetime)
        assert summary.generated_at.tzinfo is not None

    def test_schema_version_default(self):
        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=[],
        )
        assert summary.schema_version == "1.0.0"

    def test_tool_version_stored(self):
        summary = MultiOrgSummary(
            tool_version="2.3.4",
            config_file="multi-org.yml",
            organizations=[],
        )
        assert summary.tool_version == "2.3.4"

    def test_config_file_stored(self):
        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="/path/to/multi-org.yml",
            organizations=[],
        )
        assert summary.config_file == "/path/to/multi-org.yml"

    def test_model_dump_includes_totals_key(self):
        """C1: totals must appear in model_dump() output (computed_field)."""
        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=[
                OrgScanResult(name="org-a", status="success", total_repos=7),
            ],
        )
        dumped = summary.model_dump()
        assert "totals" in dumped
        assert dumped["totals"]["total_repos"] == 7
        assert dumped["totals"]["organizations_scanned"] == 1

    def test_model_dump_json_includes_totals_key(self):
        """C1: totals must appear in model_dump_json() output."""
        import json

        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=[],
        )
        parsed = json.loads(summary.model_dump_json())
        assert "totals" in parsed


# ---------------------------------------------------------------------------
# JSON roundtrip
# ---------------------------------------------------------------------------


class TestJsonRoundtrip:
    """model_dump_json / model_validate_json roundtrip."""

    def test_org_entry_pat_roundtrip(self):
        entry = _pat_entry(api_url="https://api.github.com", concurrency=4)
        json_str = entry.model_dump_json()
        restored = OrgEntry.model_validate_json(json_str)
        assert restored.name == entry.name
        assert restored.token == entry.token
        assert restored.concurrency == entry.concurrency

    def test_org_entry_app_roundtrip(self):
        entry = _app_entry()
        json_str = entry.model_dump_json()
        restored = OrgEntry.model_validate_json(json_str)
        assert restored.app_id == entry.app_id
        assert restored.installation_id == entry.installation_id

    def test_multi_org_summary_roundtrip(self):
        summary = MultiOrgSummary(
            tool_version="0.1.0",
            config_file="multi-org.yml",
            organizations=[
                _success_result(name="org-a", total_repos=5),
                _failed_result(name="org-b"),
            ],
        )
        json_str = summary.model_dump_json()
        restored = MultiOrgSummary.model_validate_json(json_str)
        assert len(restored.organizations) == 2
        assert restored.organizations[0].name == "org-a"
        assert restored.totals.organizations_scanned == 2
        assert restored.totals.organizations_succeeded == 1
        assert restored.totals.organizations_failed == 1
