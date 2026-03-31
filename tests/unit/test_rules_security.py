"""Unit tests for security assessment rules (SEC-001 through SEC-007)."""

from __future__ import annotations

from datetime import datetime, timezone


from gh_audit.models.finding import Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.security import SecurityInfo
from gh_audit.models.security_detail import (
    CodeScanningAlertInfo,
    DependabotAlertInfo,
    SBOMSummary,
    SecretScanningAlertInfo,
    SecurityDetail,
)
from gh_audit.models.user import OrgMemberSummary
from gh_audit.rules.security import (
    sec_001_critical_dependabot_alerts,
    sec_002_critical_code_scanning_alerts,
    sec_003_secret_scanning_push_protection_bypass,
    sec_004_dependabot_not_enabled,
    sec_005_code_scanning_not_enabled,
    sec_006_secret_scanning_not_enabled,
    sec_007_no_sbom,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo(
    name: str = "test-repo",
    *,
    security: SecurityInfo | None = None,
    security_detail: SecurityDetail | None = None,
) -> RepositoryInventoryItem:
    """Build a minimal RepositoryInventoryItem for rule testing."""
    return RepositoryInventoryItem(
        name=name,
        full_name=f"testorg/{name}",
        visibility="private",
        security=security or SecurityInfo(),
        security_detail=security_detail,
    )


def _inv(repos: list[RepositoryInventoryItem]) -> Inventory:
    """Build a minimal Inventory wrapping the given repos."""
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization="testorg",
            auth_method="pat",
            scan_profile="total",
            active_categories=["security"],
        ),
        summary=InventorySummary(total_repos=len(repos)),
        repositories=repos,
        users=OrgMemberSummary(total=0, admins=0, members=0),
    )


# ===================================================================
# SEC-001: Critical/high Dependabot alerts
# ===================================================================


class TestSec001CriticalDependabotAlerts:
    def test_fires_on_open_critical_dependabot_alert(self) -> None:
        repo = _repo(
            "vuln-repo",
            security_detail=SecurityDetail(
                dependabot_alerts=[
                    DependabotAlertInfo(
                        severity="critical",
                        state="open",
                        package_name="lodash",
                        manifest_path="package.json",
                    ),
                ]
            ),
        )
        findings = sec_001_critical_dependabot_alerts(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-001"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.critical
        assert f.scope == Scope.repo
        assert f.repo_name == "vuln-repo"

    def test_fires_on_open_high_dependabot_alert(self) -> None:
        repo = _repo(
            "vuln-repo",
            security_detail=SecurityDetail(
                dependabot_alerts=[
                    DependabotAlertInfo(
                        severity="high",
                        state="open",
                        package_name="express",
                        manifest_path="package.json",
                    ),
                ]
            ),
        )
        findings = sec_001_critical_dependabot_alerts(_inv([repo]))
        assert len(findings) == 1

    def test_no_finding_when_alert_is_fixed(self) -> None:
        repo = _repo(
            "safe-repo",
            security_detail=SecurityDetail(
                dependabot_alerts=[
                    DependabotAlertInfo(
                        severity="critical",
                        state="fixed",
                        package_name="lodash",
                        manifest_path="package.json",
                    ),
                ]
            ),
        )
        findings = sec_001_critical_dependabot_alerts(_inv([repo]))
        assert findings == []

    def test_no_finding_when_severity_is_low(self) -> None:
        repo = _repo(
            "safe-repo",
            security_detail=SecurityDetail(
                dependabot_alerts=[
                    DependabotAlertInfo(
                        severity="low",
                        state="open",
                        package_name="debug",
                        manifest_path="package.json",
                    ),
                ]
            ),
        )
        findings = sec_001_critical_dependabot_alerts(_inv([repo]))
        assert findings == []

    def test_skips_when_security_detail_is_none(self) -> None:
        repo = _repo("no-detail")
        findings = sec_001_critical_dependabot_alerts(_inv([repo]))
        assert findings == []

    def test_counts_multiple_alerts(self) -> None:
        repo = _repo(
            "multi-vuln",
            security_detail=SecurityDetail(
                dependabot_alerts=[
                    DependabotAlertInfo(
                        severity="critical",
                        state="open",
                        package_name="lodash",
                        manifest_path="package.json",
                    ),
                    DependabotAlertInfo(
                        severity="high",
                        state="open",
                        package_name="express",
                        manifest_path="package.json",
                    ),
                    DependabotAlertInfo(
                        severity="medium",
                        state="open",
                        package_name="debug",
                        manifest_path="package.json",
                    ),
                ]
            ),
        )
        findings = sec_001_critical_dependabot_alerts(_inv([repo]))
        assert len(findings) == 1  # One finding per repo, not per alert


# ===================================================================
# SEC-002: Critical/high code scanning alerts
# ===================================================================


class TestSec002CriticalCodeScanningAlerts:
    def test_fires_on_open_critical_code_scanning_alert(self) -> None:
        repo = _repo(
            "vuln-repo",
            security_detail=SecurityDetail(
                code_scanning_alerts=[
                    CodeScanningAlertInfo(
                        rule_id="js/sql-injection",
                        security_severity="critical",
                        tool_name="CodeQL",
                        state="open",
                    ),
                ]
            ),
        )
        findings = sec_002_critical_code_scanning_alerts(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-002"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.critical
        assert f.scope == Scope.repo
        assert f.repo_name == "vuln-repo"

    def test_fires_on_open_high_code_scanning_alert(self) -> None:
        repo = _repo(
            "vuln-repo",
            security_detail=SecurityDetail(
                code_scanning_alerts=[
                    CodeScanningAlertInfo(
                        rule_id="js/xss",
                        security_severity="high",
                        tool_name="CodeQL",
                        state="open",
                    ),
                ]
            ),
        )
        findings = sec_002_critical_code_scanning_alerts(_inv([repo]))
        assert len(findings) == 1

    def test_no_finding_when_alert_is_dismissed(self) -> None:
        repo = _repo(
            "safe-repo",
            security_detail=SecurityDetail(
                code_scanning_alerts=[
                    CodeScanningAlertInfo(
                        rule_id="js/sql-injection",
                        security_severity="critical",
                        tool_name="CodeQL",
                        state="dismissed",
                    ),
                ]
            ),
        )
        findings = sec_002_critical_code_scanning_alerts(_inv([repo]))
        assert findings == []

    def test_no_finding_when_severity_is_medium(self) -> None:
        repo = _repo(
            "safe-repo",
            security_detail=SecurityDetail(
                code_scanning_alerts=[
                    CodeScanningAlertInfo(
                        rule_id="js/redundant-check",
                        security_severity="medium",
                        tool_name="CodeQL",
                        state="open",
                    ),
                ]
            ),
        )
        findings = sec_002_critical_code_scanning_alerts(_inv([repo]))
        assert findings == []

    def test_skips_when_security_detail_is_none(self) -> None:
        repo = _repo("no-detail")
        findings = sec_002_critical_code_scanning_alerts(_inv([repo]))
        assert findings == []

    def test_skips_alert_with_none_security_severity(self) -> None:
        repo = _repo(
            "no-severity",
            security_detail=SecurityDetail(
                code_scanning_alerts=[
                    CodeScanningAlertInfo(
                        rule_id="js/something",
                        security_severity=None,
                        tool_name="CodeQL",
                        state="open",
                    ),
                ]
            ),
        )
        findings = sec_002_critical_code_scanning_alerts(_inv([repo]))
        assert findings == []


# ===================================================================
# SEC-003: Secret scanning push protection bypass
# ===================================================================


class TestSec003SecretScanningPushProtectionBypass:
    def test_fires_on_open_bypassed_secret(self) -> None:
        repo = _repo(
            "leaked-repo",
            security_detail=SecurityDetail(
                secret_scanning_alerts=[
                    SecretScanningAlertInfo(
                        secret_type="github_personal_access_token",
                        state="open",
                        push_protection_bypassed=True,
                    ),
                ]
            ),
        )
        findings = sec_003_secret_scanning_push_protection_bypass(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-003"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.critical
        assert f.scope == Scope.repo
        assert f.repo_name == "leaked-repo"

    def test_no_finding_when_not_bypassed(self) -> None:
        repo = _repo(
            "safe-repo",
            security_detail=SecurityDetail(
                secret_scanning_alerts=[
                    SecretScanningAlertInfo(
                        secret_type="github_personal_access_token",
                        state="open",
                        push_protection_bypassed=False,
                    ),
                ]
            ),
        )
        findings = sec_003_secret_scanning_push_protection_bypass(_inv([repo]))
        assert findings == []

    def test_no_finding_when_resolved(self) -> None:
        repo = _repo(
            "resolved-repo",
            security_detail=SecurityDetail(
                secret_scanning_alerts=[
                    SecretScanningAlertInfo(
                        secret_type="github_personal_access_token",
                        state="resolved",
                        push_protection_bypassed=True,
                    ),
                ]
            ),
        )
        findings = sec_003_secret_scanning_push_protection_bypass(_inv([repo]))
        assert findings == []

    def test_skips_when_security_detail_is_none(self) -> None:
        repo = _repo("no-detail")
        findings = sec_003_secret_scanning_push_protection_bypass(_inv([repo]))
        assert findings == []


# ===================================================================
# SEC-004: Dependabot not enabled
# ===================================================================


class TestSec004DependabotNotEnabled:
    def test_fires_when_dependabot_disabled(self) -> None:
        repo = _repo(
            "no-dependabot",
            security=SecurityInfo(dependabot_enabled=False),
        )
        findings = sec_004_dependabot_not_enabled(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-004"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "no-dependabot"

    def test_no_finding_when_enabled(self) -> None:
        repo = _repo(
            "safe-repo",
            security=SecurityInfo(dependabot_enabled=True),
        )
        findings = sec_004_dependabot_not_enabled(_inv([repo]))
        assert findings == []

    def test_skips_when_unknown(self) -> None:
        repo = _repo(
            "unknown-repo",
            security=SecurityInfo(dependabot_enabled=None),
        )
        findings = sec_004_dependabot_not_enabled(_inv([repo]))
        assert findings == []

    def test_skips_archived_repos(self) -> None:
        repo = _repo("archived-repo", security=SecurityInfo(dependabot_enabled=False))
        repo.archived = True
        findings = sec_004_dependabot_not_enabled(_inv([repo]))
        assert findings == []


# ===================================================================
# SEC-005: Code scanning not enabled
# ===================================================================


class TestSec005CodeScanningNotEnabled:
    def test_fires_when_code_scanning_disabled(self) -> None:
        repo = _repo(
            "no-scanning",
            security=SecurityInfo(code_scanning_enabled=False),
        )
        findings = sec_005_code_scanning_not_enabled(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-005"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "no-scanning"

    def test_no_finding_when_enabled(self) -> None:
        repo = _repo(
            "safe-repo",
            security=SecurityInfo(code_scanning_enabled=True),
        )
        findings = sec_005_code_scanning_not_enabled(_inv([repo]))
        assert findings == []

    def test_skips_when_unknown(self) -> None:
        repo = _repo(
            "unknown-repo",
            security=SecurityInfo(code_scanning_enabled=None),
        )
        findings = sec_005_code_scanning_not_enabled(_inv([repo]))
        assert findings == []

    def test_skips_archived_repos(self) -> None:
        repo = _repo("archived-repo", security=SecurityInfo(code_scanning_enabled=False))
        repo.archived = True
        findings = sec_005_code_scanning_not_enabled(_inv([repo]))
        assert findings == []


# ===================================================================
# SEC-006: Secret scanning not enabled
# ===================================================================


class TestSec006SecretScanningNotEnabled:
    def test_fires_when_secret_scanning_disabled(self) -> None:
        repo = _repo(
            "no-secrets",
            security=SecurityInfo(secret_scanning_enabled=False),
        )
        findings = sec_006_secret_scanning_not_enabled(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-006"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "no-secrets"

    def test_no_finding_when_enabled(self) -> None:
        repo = _repo(
            "safe-repo",
            security=SecurityInfo(secret_scanning_enabled=True),
        )
        findings = sec_006_secret_scanning_not_enabled(_inv([repo]))
        assert findings == []

    def test_skips_when_unknown(self) -> None:
        repo = _repo(
            "unknown-repo",
            security=SecurityInfo(secret_scanning_enabled=None),
        )
        findings = sec_006_secret_scanning_not_enabled(_inv([repo]))
        assert findings == []

    def test_skips_archived_repos(self) -> None:
        repo = _repo("archived-repo", security=SecurityInfo(secret_scanning_enabled=False))
        repo.archived = True
        findings = sec_006_secret_scanning_not_enabled(_inv([repo]))
        assert findings == []


# ===================================================================
# SEC-007: No SBOM
# ===================================================================


class TestSec007NoSbom:
    def test_fires_when_security_detail_has_no_sbom(self) -> None:
        repo = _repo(
            "no-sbom",
            security_detail=SecurityDetail(sbom_summary=None),
        )
        findings = sec_007_no_sbom(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-007"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.info
        assert f.scope == Scope.repo
        assert f.repo_name == "no-sbom"

    def test_no_finding_when_sbom_present(self) -> None:
        repo = _repo(
            "has-sbom",
            security_detail=SecurityDetail(
                sbom_summary=SBOMSummary(dependency_count=42, package_managers=["npm"]),
            ),
        )
        findings = sec_007_no_sbom(_inv([repo]))
        assert findings == []

    def test_skips_when_security_detail_is_none(self) -> None:
        repo = _repo("no-detail")
        findings = sec_007_no_sbom(_inv([repo]))
        assert findings == []


# ===================================================================
# Cross-cutting: multiple repos
# ===================================================================


class TestMultipleRepos:
    def test_sec_001_fires_for_each_affected_repo(self) -> None:
        repos = [
            _repo(
                "vuln-a",
                security_detail=SecurityDetail(
                    dependabot_alerts=[
                        DependabotAlertInfo(
                            severity="critical",
                            state="open",
                            package_name="a",
                            manifest_path="a.json",
                        ),
                    ]
                ),
            ),
            _repo("clean", security_detail=SecurityDetail()),
            _repo(
                "vuln-b",
                security_detail=SecurityDetail(
                    dependabot_alerts=[
                        DependabotAlertInfo(
                            severity="high",
                            state="open",
                            package_name="b",
                            manifest_path="b.json",
                        ),
                    ]
                ),
            ),
        ]
        findings = sec_001_critical_dependabot_alerts(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"vuln-a", "vuln-b"}

    def test_sec_004_fires_for_each_disabled_repo(self) -> None:
        repos = [
            _repo("disabled-a", security=SecurityInfo(dependabot_enabled=False)),
            _repo("enabled", security=SecurityInfo(dependabot_enabled=True)),
            _repo("disabled-b", security=SecurityInfo(dependabot_enabled=False)),
        ]
        findings = sec_004_dependabot_not_enabled(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"disabled-a", "disabled-b"}
