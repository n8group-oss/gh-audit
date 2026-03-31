"""Unit tests for security detail models.

Covers:
- Construction with defaults for every model
- Field types and values
- extra="forbid" rejection of unknown fields
- JSON roundtrip for SecurityDetail
- Integration with RepositoryInventoryItem
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.security_detail import (
    CodeScanningAlertInfo,
    CodeScanningSetup,
    DependabotAlertInfo,
    SBOMSummary,
    SecretScanningAlertInfo,
    SecurityDetail,
)
from gh_audit.models.repository import RepositoryInventoryItem


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_repo(**kwargs) -> RepositoryInventoryItem:
    defaults = dict(name="repo", full_name="org/repo", visibility="private")
    defaults.update(kwargs)
    return RepositoryInventoryItem(**defaults)


# ---------------------------------------------------------------------------
# DependabotAlertInfo
# ---------------------------------------------------------------------------


class TestDependabotAlertInfo:
    def test_minimal_construction(self):
        alert = DependabotAlertInfo(
            severity="high",
            package_name="lodash",
            manifest_path="package-lock.json",
            state="open",
        )
        assert alert.severity == "high"
        assert alert.package_name == "lodash"
        assert alert.manifest_path == "package-lock.json"
        assert alert.state == "open"
        assert alert.ghsa_id is None
        assert alert.cve_id is None
        assert alert.fixed_version is None

    def test_full_construction(self):
        alert = DependabotAlertInfo(
            severity="critical",
            package_name="express",
            manifest_path="package.json",
            state="fixed",
            ghsa_id="GHSA-1234-5678",
            cve_id="CVE-2026-0001",
            fixed_version="4.18.3",
        )
        assert alert.severity == "critical"
        assert alert.ghsa_id == "GHSA-1234-5678"
        assert alert.cve_id == "CVE-2026-0001"
        assert alert.fixed_version == "4.18.3"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            DependabotAlertInfo(
                severity="low",
                package_name="pkg",
                manifest_path="path",
                state="open",
                unknown="bad",
            )


# ---------------------------------------------------------------------------
# CodeScanningAlertInfo
# ---------------------------------------------------------------------------


class TestCodeScanningAlertInfo:
    def test_minimal_construction(self):
        alert = CodeScanningAlertInfo(
            rule_id="js/xss",
            tool_name="CodeQL",
            state="open",
        )
        assert alert.rule_id == "js/xss"
        assert alert.severity is None
        assert alert.security_severity is None
        assert alert.tool_name == "CodeQL"
        assert alert.state == "open"
        assert alert.dismissed_reason is None

    def test_full_construction(self):
        alert = CodeScanningAlertInfo(
            rule_id="py/sql-injection",
            severity="error",
            security_severity="critical",
            tool_name="CodeQL",
            state="dismissed",
            dismissed_reason="won't fix",
        )
        assert alert.severity == "error"
        assert alert.security_severity == "critical"
        assert alert.dismissed_reason == "won't fix"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            CodeScanningAlertInfo(
                rule_id="x",
                tool_name="t",
                state="open",
                surprise="bad",
            )


# ---------------------------------------------------------------------------
# SecretScanningAlertInfo
# ---------------------------------------------------------------------------


class TestSecretScanningAlertInfo:
    def test_minimal_construction(self):
        alert = SecretScanningAlertInfo(
            secret_type="github_personal_access_token",
            state="open",
        )
        assert alert.secret_type == "github_personal_access_token"
        assert alert.secret_type_display_name is None
        assert alert.state == "open"
        assert alert.resolution is None
        assert alert.push_protection_bypassed is False

    def test_full_construction(self):
        alert = SecretScanningAlertInfo(
            secret_type="aws_access_key_id",
            secret_type_display_name="AWS Access Key ID",
            state="resolved",
            resolution="revoked",
            push_protection_bypassed=True,
        )
        assert alert.secret_type_display_name == "AWS Access Key ID"
        assert alert.resolution == "revoked"
        assert alert.push_protection_bypassed is True

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SecretScanningAlertInfo(
                secret_type="x",
                state="open",
                nope="bad",
            )


# ---------------------------------------------------------------------------
# SBOMSummary
# ---------------------------------------------------------------------------


class TestSBOMSummary:
    def test_all_defaults(self):
        sbom = SBOMSummary()
        assert sbom.dependency_count == 0
        assert sbom.package_managers == []

    def test_full_construction(self):
        sbom = SBOMSummary(
            dependency_count=42,
            package_managers=["npm", "pip"],
        )
        assert sbom.dependency_count == 42
        assert sbom.package_managers == ["npm", "pip"]

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SBOMSummary(unknown="bad")

    def test_package_managers_default_is_independent(self):
        s1 = SBOMSummary()
        s2 = SBOMSummary()
        s1.package_managers.append("npm")
        assert s2.package_managers == []


# ---------------------------------------------------------------------------
# CodeScanningSetup
# ---------------------------------------------------------------------------


class TestCodeScanningSetup:
    def test_all_defaults(self):
        setup = CodeScanningSetup()
        assert setup.default_setup_enabled is False
        assert setup.languages == []

    def test_full_construction(self):
        setup = CodeScanningSetup(
            default_setup_enabled=True,
            languages=["python", "javascript"],
        )
        assert setup.default_setup_enabled is True
        assert setup.languages == ["python", "javascript"]

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            CodeScanningSetup(extra="bad")

    def test_languages_default_is_independent(self):
        s1 = CodeScanningSetup()
        s2 = CodeScanningSetup()
        s1.languages.append("go")
        assert s2.languages == []


# ---------------------------------------------------------------------------
# SecurityDetail
# ---------------------------------------------------------------------------


class TestSecurityDetail:
    def test_all_defaults(self):
        sd = SecurityDetail()
        assert sd.dependabot_alerts == []
        assert sd.code_scanning_alerts == []
        assert sd.secret_scanning_alerts == []
        assert sd.sbom_summary is None
        assert sd.code_scanning_setup is None
        assert sd.security_configuration_name is None

    def test_full_construction(self):
        sd = SecurityDetail(
            dependabot_alerts=[
                DependabotAlertInfo(
                    severity="high",
                    package_name="lodash",
                    manifest_path="package.json",
                    state="open",
                )
            ],
            code_scanning_alerts=[
                CodeScanningAlertInfo(
                    rule_id="js/xss",
                    tool_name="CodeQL",
                    state="open",
                )
            ],
            secret_scanning_alerts=[
                SecretScanningAlertInfo(
                    secret_type="github_pat",
                    state="open",
                )
            ],
            sbom_summary=SBOMSummary(dependency_count=10, package_managers=["npm"]),
            code_scanning_setup=CodeScanningSetup(default_setup_enabled=True, languages=["python"]),
            security_configuration_name="default-security",
        )
        assert len(sd.dependabot_alerts) == 1
        assert len(sd.code_scanning_alerts) == 1
        assert len(sd.secret_scanning_alerts) == 1
        assert sd.sbom_summary.dependency_count == 10
        assert sd.code_scanning_setup.default_setup_enabled is True
        assert sd.security_configuration_name == "default-security"

    def test_defaults_are_independent(self):
        s1 = SecurityDetail()
        s2 = SecurityDetail()
        s1.dependabot_alerts.append(
            DependabotAlertInfo(severity="low", package_name="p", manifest_path="m", state="open")
        )
        assert s2.dependabot_alerts == []

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SecurityDetail(surprise="bad")

    def test_json_roundtrip(self):
        sd = SecurityDetail(
            dependabot_alerts=[
                DependabotAlertInfo(
                    severity="critical",
                    package_name="express",
                    manifest_path="package.json",
                    state="open",
                    ghsa_id="GHSA-xxxx",
                    cve_id="CVE-2026-0001",
                    fixed_version="4.18.3",
                )
            ],
            code_scanning_alerts=[
                CodeScanningAlertInfo(
                    rule_id="py/sql-injection",
                    severity="error",
                    security_severity="high",
                    tool_name="CodeQL",
                    state="dismissed",
                    dismissed_reason="false positive",
                )
            ],
            secret_scanning_alerts=[
                SecretScanningAlertInfo(
                    secret_type="aws_access_key_id",
                    secret_type_display_name="AWS Access Key",
                    state="resolved",
                    resolution="revoked",
                    push_protection_bypassed=True,
                )
            ],
            sbom_summary=SBOMSummary(dependency_count=100, package_managers=["npm", "pip"]),
            code_scanning_setup=CodeScanningSetup(
                default_setup_enabled=True, languages=["python", "javascript"]
            ),
            security_configuration_name="org-default",
        )
        json_str = sd.model_dump_json()
        sd2 = SecurityDetail.model_validate_json(json_str)
        assert sd2.dependabot_alerts[0].cve_id == "CVE-2026-0001"
        assert sd2.code_scanning_alerts[0].dismissed_reason == "false positive"
        assert sd2.secret_scanning_alerts[0].push_protection_bypassed is True
        assert sd2.sbom_summary.package_managers == ["npm", "pip"]
        assert sd2.code_scanning_setup.languages == ["python", "javascript"]
        assert sd2.security_configuration_name == "org-default"


# ---------------------------------------------------------------------------
# RepositoryInventoryItem security_detail field
# ---------------------------------------------------------------------------


class TestRepositorySecurityDetailField:
    def test_security_detail_is_none_by_default(self):
        repo = _make_repo()
        assert repo.security_detail is None

    def test_security_detail_can_be_set(self):
        sd = SecurityDetail(
            dependabot_alerts=[
                DependabotAlertInfo(
                    severity="high",
                    package_name="pkg",
                    manifest_path="go.sum",
                    state="open",
                )
            ],
        )
        repo = _make_repo(security_detail=sd)
        assert repo.security_detail is not None
        assert len(repo.security_detail.dependabot_alerts) == 1

    def test_empty_security_detail_differs_from_none(self):
        """Empty SecurityDetail = scanned and found nothing; None = not scanned."""
        repo_scanned = _make_repo(security_detail=SecurityDetail())
        repo_not_scanned = _make_repo()
        assert repo_scanned.security_detail is not None
        assert repo_scanned.security_detail.dependabot_alerts == []
        assert repo_not_scanned.security_detail is None

    def test_security_detail_with_sbom(self):
        sd = SecurityDetail(
            sbom_summary=SBOMSummary(dependency_count=50, package_managers=["npm"]),
        )
        repo = _make_repo(security_detail=sd)
        assert repo.security_detail.sbom_summary.dependency_count == 50

    def test_security_detail_with_code_scanning_setup(self):
        sd = SecurityDetail(
            code_scanning_setup=CodeScanningSetup(default_setup_enabled=True, languages=["python"]),
        )
        repo = _make_repo(security_detail=sd)
        assert repo.security_detail.code_scanning_setup.default_setup_enabled is True

    def test_security_detail_with_config_name(self):
        sd = SecurityDetail(security_configuration_name="enterprise-default")
        repo = _make_repo(security_detail=sd)
        assert repo.security_detail.security_configuration_name == "enterprise-default"
