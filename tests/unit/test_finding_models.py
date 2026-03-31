"""Unit tests for assessment finding models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from gh_audit.models.finding import (
    AssessmentResult,
    Finding,
    Pillar,
    Scope,
    Severity,
)


class TestSeverityEnum:
    def test_values(self) -> None:
        assert Severity.critical == "critical"
        assert Severity.warning == "warning"
        assert Severity.info == "info"

    def test_ordering(self) -> None:
        ordered = sorted(
            [Severity.info, Severity.critical, Severity.warning],
            key=lambda s: ["critical", "warning", "info"].index(s.value),
        )
        assert ordered == [Severity.critical, Severity.warning, Severity.info]


class TestPillarEnum:
    def test_all_pillars(self) -> None:
        assert set(Pillar) == {
            Pillar.security,
            Pillar.governance,
            Pillar.operations,
            Pillar.adoption,
            Pillar.enterprise,
        }


class TestFinding:
    def test_repo_scoped(self) -> None:
        f = Finding(
            rule_id="SEC-001",
            pillar=Pillar.security,
            severity=Severity.critical,
            scope=Scope.repo,
            repo_name="my-repo",
            title="5 critical Dependabot alerts",
            detail="Repository org/my-repo has 5 open critical alerts.",
            remediation="Review and fix or dismiss alerts.",
        )
        assert f.rule_id == "SEC-001"
        assert f.pillar == Pillar.security
        assert f.severity == Severity.critical
        assert f.scope == Scope.repo
        assert f.repo_name == "my-repo"

    def test_org_scoped(self) -> None:
        f = Finding(
            rule_id="GOV-003",
            pillar=Pillar.governance,
            severity=Severity.critical,
            scope=Scope.org,
            title="2FA not required",
            detail="Organization does not require 2FA.",
            remediation="Enable 2FA requirement in org settings.",
        )
        assert f.repo_name is None

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                rule_id="X",
                pillar=Pillar.security,
                severity=Severity.info,
                scope=Scope.org,
                title="t",
                detail="d",
                remediation="r",
                unknown="x",
            )


class TestAssessmentResult:
    def test_construction(self) -> None:
        finding = Finding(
            rule_id="SEC-001",
            pillar=Pillar.security,
            severity=Severity.critical,
            scope=Scope.repo,
            repo_name="r",
            title="t",
            detail="d",
            remediation="r",
        )
        result = AssessmentResult(
            organization="myorg",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            inventory_generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            scan_profile="total",
            active_categories=["security", "governance"],
            findings=[finding],
        )
        assert result.organization == "myorg"
        assert len(result.findings) == 1

    def test_empty_findings(self) -> None:
        result = AssessmentResult(
            organization="myorg",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            inventory_generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            scan_profile="standard",
            active_categories=[],
            findings=[],
        )
        assert result.findings == []

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            AssessmentResult(
                organization="o",
                generated_at=datetime.now(timezone.utc),
                inventory_generated_at=datetime.now(timezone.utc),
                scan_profile="standard",
                active_categories=[],
                findings=[],
                unknown="x",
            )
