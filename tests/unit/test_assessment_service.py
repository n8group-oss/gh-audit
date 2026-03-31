"""Unit tests for assessment report generation."""

from __future__ import annotations

from datetime import datetime, timezone

from gh_audit.models.finding import AssessmentResult, Finding, Pillar, Scope, Severity
from gh_audit.services.assessment import AssessmentService


def _result(findings=None):
    return AssessmentResult(
        organization="testorg",
        generated_at=datetime(2026, 3, 29, 12, 0, tzinfo=timezone.utc),
        inventory_generated_at=datetime(2026, 3, 29, 10, 0, tzinfo=timezone.utc),
        scan_profile="total",
        active_categories=["security", "governance"],
        findings=findings or [],
    )


def _finding(
    rule_id="SEC-001",
    pillar=Pillar.security,
    severity=Severity.critical,
    scope=Scope.repo,
    repo_name="repo-a",
):
    return Finding(
        rule_id=rule_id,
        pillar=pillar,
        severity=severity,
        scope=scope,
        repo_name=repo_name,
        title=f"Test {rule_id}",
        detail=f"Detail {rule_id}",
        remediation=f"Fix {rule_id}",
    )


class TestAssessmentService:
    def test_generates_html(self, tmp_path):
        output = tmp_path / "assessment.html"
        AssessmentService().generate(_result([_finding()]), output)
        assert output.exists()
        content = output.read_text()
        assert "testorg" in content
        assert "SEC-001" in content

    def test_contains_executive_summary(self, tmp_path):
        result = _result(
            [
                _finding("SEC-001", severity=Severity.critical),
                _finding("GOV-001", pillar=Pillar.governance, severity=Severity.warning),
                _finding("ADO-001", pillar=Pillar.adoption, severity=Severity.info),
            ]
        )
        output = tmp_path / "assessment.html"
        AssessmentService().generate(result, output)
        content = output.read_text()
        assert "Critical" in content
        assert "Warning" in content

    def test_contains_pillar_breakdown(self, tmp_path):
        result = _result(
            [_finding(), _finding("GOV-001", pillar=Pillar.governance, severity=Severity.warning)]
        )
        output = tmp_path / "assessment.html"
        AssessmentService().generate(result, output)
        content = output.read_text()
        assert "Security" in content
        assert "Governance" in content

    def test_contains_findings_table(self, tmp_path):
        output = tmp_path / "assessment.html"
        AssessmentService().generate(_result([_finding()]), output)
        content = output.read_text()
        assert "repo-a" in content
        assert "Fix SEC-001" in content

    def test_empty_findings(self, tmp_path):
        output = tmp_path / "assessment.html"
        AssessmentService().generate(_result([]), output)
        content = output.read_text()
        assert "No findings" in content

    def test_org_scope_shows_dash(self, tmp_path):
        output = tmp_path / "assessment.html"
        AssessmentService().generate(
            _result([_finding("GOV-003", scope=Scope.org, repo_name=None)]), output
        )
        content = output.read_text()
        assert "GOV-003" in content

    def test_unassessed_pillars_shown(self, tmp_path):
        """Pillars without scanned categories show 'Not assessed'."""
        result = AssessmentResult(
            organization="testorg",
            generated_at=datetime(2026, 3, 29, 12, 0, tzinfo=timezone.utc),
            inventory_generated_at=datetime(2026, 3, 29, 10, 0, tzinfo=timezone.utc),
            scan_profile="standard",
            active_categories=[],  # no categories scanned
            findings=[],
        )
        output = tmp_path / "assessment.html"
        AssessmentService().generate(result, output)
        content = output.read_text()
        assert "Not assessed" in content
        assert "Operations" in content
        assert "Adoption" in content
        assert "Enterprise" in content

    def test_limited_assessment_warning(self, tmp_path):
        """Warning shown when some pillars can't be assessed."""
        result = AssessmentResult(
            organization="testorg",
            generated_at=datetime(2026, 3, 29, 12, 0, tzinfo=timezone.utc),
            inventory_generated_at=datetime(2026, 3, 29, 10, 0, tzinfo=timezone.utc),
            scan_profile="standard",
            active_categories=["security"],  # only security scanned
            findings=[_finding()],
        )
        output = tmp_path / "assessment.html"
        AssessmentService().generate(result, output)
        content = output.read_text()
        assert "Limited assessment" in content
        assert "Operations" in content
        assert "Adoption" in content
        assert "Enterprise" in content

    def test_no_warning_when_all_categories_scanned(self, tmp_path):
        """No warning when all categories are scanned."""
        result = AssessmentResult(
            organization="testorg",
            generated_at=datetime(2026, 3, 29, 12, 0, tzinfo=timezone.utc),
            inventory_generated_at=datetime(2026, 3, 29, 10, 0, tzinfo=timezone.utc),
            scan_profile="total",
            active_categories=["security", "governance", "operations", "adoption", "enterprise"],
            findings=[_finding()],
        )
        output = tmp_path / "assessment.html"
        AssessmentService().generate(result, output)
        content = output.read_text()
        assert "Limited assessment" not in content
        assert "Not assessed" not in content
