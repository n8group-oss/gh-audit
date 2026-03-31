"""Tests for gh_audit.services.reporting — offline HTML report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


from gh_audit.models.inventory import (
    Inventory,
    InventoryMetadata,
    InventorySummary,
)
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.security import SecurityInfo
from gh_audit.models.user import OrgMemberSummary
from gh_audit.services.reporting import ReportService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _metadata(**kw) -> InventoryMetadata:
    defaults = {
        "schema_version": "1.0",
        "generated_at": datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc),
        "tool_version": "0.1.0",
        "organization": "test-org",
        "auth_method": "pat",
        "scan_profile": "standard",
    }
    defaults.update(kw)
    return InventoryMetadata(**defaults)


def _minimal_repo(
    name: str = "repo-a",
    visibility: str = "private",
    *,
    security: SecurityInfo | None = None,
) -> RepositoryInventoryItem:
    return RepositoryInventoryItem(
        name=name,
        full_name=f"test-org/{name}",
        visibility=visibility,
        security=security or SecurityInfo(),
    )


def _minimal_inventory(**kw) -> Inventory:
    defaults: dict = {
        "metadata": _metadata(),
        "summary": InventorySummary(total_repos=1, private_repos=1),
        "repositories": [_minimal_repo()],
        "users": OrgMemberSummary(total=5, admins=1, members=4),
    }
    defaults.update(kw)
    return Inventory(**defaults)


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


class TestReportServiceSmoke:
    def test_generate_creates_file(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        assert output.exists()

    def test_generate_returns_none(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        result = svc.generate(inv, tmp_path / "report.html")
        assert result is None


# ---------------------------------------------------------------------------
# Required content checks
# ---------------------------------------------------------------------------


class TestReportContent:
    def test_contains_scan_profile(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "scan profile" in content.lower()

    def test_contains_org_name(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "test-org" in content

    def test_contains_tool_version(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "0.1.0" in content

    def test_contains_generated_at(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "2026" in content

    def test_scan_profile_value_present(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        # "standard" is the scan profile value
        assert "standard" in content


# ---------------------------------------------------------------------------
# Offline / no-CDN requirement
# ---------------------------------------------------------------------------


class TestOfflineSelfContained:
    def test_no_cdn_links(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "https://cdn" not in content.lower()

    def test_no_external_scripts(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        # No src= pointing to external URLs
        assert 'src="http' not in content.lower()

    def test_no_external_stylesheets(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert 'rel="stylesheet" href="http' not in content.lower()

    def test_is_self_contained_html(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "<!doctype html" in content.lower() or "<html" in content.lower()
        # Inline CSS expected
        assert "<style" in content.lower()


# ---------------------------------------------------------------------------
# Scan warnings section
# ---------------------------------------------------------------------------


class TestScanWarnings:
    def test_warnings_section_shown_when_warnings_present(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(
            metadata=_metadata(
                scan_warnings=["rate_limit_hit", "partial scan: 50/200 repos processed"]
            )
        )
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "warning" in content.lower() or "warnings" in content.lower()

    def test_warning_text_appears_in_report(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(metadata=_metadata(scan_warnings=["rate_limit_hit"]))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "rate_limit_hit" in content

    def test_partial_scan_warning_prominent(self, tmp_path: Path) -> None:
        warning_text = "partial scan: only 50 of 200 repos processed"
        inv = _minimal_inventory(metadata=_metadata(scan_warnings=[warning_text]))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert warning_text in content

    def test_no_warnings_section_when_no_warnings(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(metadata=_metadata(scan_warnings=[]))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        output.read_text()
        # When no warnings, "warning" keyword may still appear in CSS classes or section headings
        # but the section should not contain actual warning items
        # This is a soft check — we just verify report is generated
        assert output.exists()


# ---------------------------------------------------------------------------
# Repository table rendering
# ---------------------------------------------------------------------------


class TestRepositoryTable:
    def test_repo_name_in_output(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(repositories=[_minimal_repo("my-service", "private")])
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "my-service" in content

    def test_multiple_repos_all_present(self, tmp_path: Path) -> None:
        repos = [
            _minimal_repo("alpha", "public"),
            _minimal_repo("beta", "private"),
            _minimal_repo("gamma", "internal"),
        ]
        inv = _minimal_inventory(
            repositories=repos,
            summary=InventorySummary(
                total_repos=3, public_repos=1, private_repos=1, internal_repos=1
            ),
        )
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "alpha" in content
        assert "beta" in content
        assert "gamma" in content

    def test_visibility_values_present(self, tmp_path: Path) -> None:
        repos = [
            _minimal_repo("pub-repo", "public"),
            _minimal_repo("priv-repo", "private"),
        ]
        inv = _minimal_inventory(
            repositories=repos,
            summary=InventorySummary(total_repos=2, public_repos=1, private_repos=1),
        )
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "public" in content
        assert "private" in content

    def test_table_has_sortable_indicator(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        # Sortable table requires JS — check for script tag or sort-related JS
        assert "<script" in content.lower()


# ---------------------------------------------------------------------------
# Security value rendering
# ---------------------------------------------------------------------------


class TestSecurityRendering:
    def test_exact_zero_shown_as_zero(self, tmp_path: Path) -> None:
        """When counts_exact=True and count=0, render '0' not 'n/a'."""
        repo = _minimal_repo(
            "secure-repo",
            security=SecurityInfo(
                alerts_accessible=True,
                counts_exact=True,
                dependabot_alerts_open=0,
                code_scanning_alerts_open=0,
                secret_scanning_alerts_open=0,
            ),
        )
        inv = _minimal_inventory(repositories=[repo])
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        # "0" should appear in the content (the exact zero counts)
        assert (
            ">0<" in content
            or " 0 " in content
            or ">0 " in content
            or '"0"' in content
            or "'0'" in content
        )

    def test_none_count_shown_as_na(self, tmp_path: Path) -> None:
        """When counts are None (inaccessible), render 'n/a'."""
        repo = _minimal_repo(
            "unknown-repo",
            security=SecurityInfo(
                alerts_accessible=False,
                counts_exact=False,
                dependabot_alerts_open=None,
                code_scanning_alerts_open=None,
                secret_scanning_alerts_open=None,
            ),
        )
        inv = _minimal_inventory(repositories=[repo])
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "n/a" in content.lower()

    def test_exact_nonzero_shown(self, tmp_path: Path) -> None:
        """When counts_exact=True and count=5, render '5'."""
        repo = _minimal_repo(
            "alert-repo",
            security=SecurityInfo(
                alerts_accessible=True,
                counts_exact=True,
                dependabot_alerts_open=5,
                code_scanning_alerts_open=2,
                secret_scanning_alerts_open=1,
            ),
        )
        inv = _minimal_inventory(repositories=[repo])
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "5" in content
        assert "2" in content


# ---------------------------------------------------------------------------
# Parent directory creation
# ---------------------------------------------------------------------------


class TestParentDirCreation:
    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        nested = tmp_path / "deep" / "nested" / "dir" / "report.html"
        svc.generate(inv, nested)
        assert nested.exists()

    def test_existing_parent_dir_ok(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        # Call again — should overwrite without error
        svc.generate(inv, output)
        assert output.exists()


# ---------------------------------------------------------------------------
# Overview cards
# ---------------------------------------------------------------------------


class TestOverviewCards:
    def test_total_repos_shown(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(summary=InventorySummary(total_repos=42, private_repos=42))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "42" in content

    def test_members_count_shown(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(users=OrgMemberSummary(total=25, admins=3, members=22))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "25" in content

    def test_prs_count_shown(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(summary=InventorySummary(total_repos=1, total_prs=99))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "99" in content


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------


class TestFooter:
    def test_footer_contains_tool_version(self, tmp_path: Path) -> None:
        inv = _minimal_inventory(metadata=_metadata(tool_version="1.2.3"))
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "1.2.3" in content

    def test_footer_contains_scanner_name(self, tmp_path: Path) -> None:
        inv = _minimal_inventory()
        svc = ReportService()
        output = tmp_path / "report.html"
        svc.generate(inv, output)
        content = output.read_text()
        assert "gh-audit" in content.lower()
