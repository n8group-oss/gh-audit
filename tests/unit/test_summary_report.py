"""Tests for summary HTML report generation and SummaryPaths output helpers."""

from __future__ import annotations

import pathlib

import pytest

from gh_audit.cli.output_paths import SummaryPaths
from gh_audit.models.multi_org import MultiOrgSummary, OrgScanResult
from gh_audit.services.summary_report import generate_summary_html


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _success_result(**kwargs) -> OrgScanResult:
    defaults = {"name": "my-org", "status": "success"}
    defaults.update(kwargs)
    return OrgScanResult(**defaults)


def _failed_result(**kwargs) -> OrgScanResult:
    defaults = {"name": "failed-org", "status": "failed", "error": "connection timeout"}
    defaults.update(kwargs)
    return OrgScanResult(**defaults)


def _make_summary(orgs: list[OrgScanResult], **kwargs) -> MultiOrgSummary:
    defaults = {
        "tool_version": "1.2.3",
        "config_file": "multi-org.yml",
        "organizations": orgs,
    }
    defaults.update(kwargs)
    return MultiOrgSummary(**defaults)


# ---------------------------------------------------------------------------
# TestSummaryPaths
# ---------------------------------------------------------------------------


class TestSummaryPaths:
    """SummaryPaths output path helpers."""

    def test_from_directory_json_ends_with_summary_json(self, tmp_path):
        paths = SummaryPaths.from_directory(tmp_path)
        assert paths.json.name.endswith("-summary.json")

    def test_from_directory_report_ends_with_summary_html(self, tmp_path):
        paths = SummaryPaths.from_directory(tmp_path)
        assert paths.report.name.endswith("-summary.html")

    def test_from_directory_json_parent_is_directory(self, tmp_path):
        paths = SummaryPaths.from_directory(tmp_path)
        assert paths.json.parent == tmp_path

    def test_from_directory_report_parent_is_directory(self, tmp_path):
        paths = SummaryPaths.from_directory(tmp_path)
        assert paths.report.parent == tmp_path

    def test_from_directory_paths_are_pathlib_path(self, tmp_path):
        paths = SummaryPaths.from_directory(tmp_path)
        assert isinstance(paths.json, pathlib.Path)
        assert isinstance(paths.report, pathlib.Path)

    def test_from_directory_prefix_is_date_isoformat(self, tmp_path):
        from datetime import date

        paths = SummaryPaths.from_directory(tmp_path)
        today = date.today().isoformat()
        assert paths.json.name.startswith(today)
        assert paths.report.name.startswith(today)

    def test_from_directory_frozen_dataclass(self, tmp_path):
        paths = SummaryPaths.from_directory(tmp_path)
        with pytest.raises((AttributeError, TypeError)):
            paths.json = tmp_path / "other.json"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestSummaryHTML — generate_summary_html
# ---------------------------------------------------------------------------


class TestSummaryHTML:
    """generate_summary_html produces a valid offline HTML summary report."""

    def _build_summary(self) -> MultiOrgSummary:
        return _make_summary(
            [
                _success_result(
                    name="org-alpha",
                    total_repos=42,
                    total_size_bytes=1_073_741_824,  # 1 GB
                    total_members=15,
                    total_workflows=8,
                    total_issues=100,
                    total_packages=3,
                    total_projects=2,
                    duration_seconds=30.5,
                    scan_profile="standard",
                ),
                _success_result(
                    name="org-beta",
                    total_repos=10,
                    total_size_bytes=536_870_912,  # 0.5 GB
                    total_members=5,
                    total_workflows=2,
                    total_issues=20,
                    total_packages=1,
                    total_projects=0,
                    duration_seconds=12.0,
                    scan_profile="deep",
                ),
                _failed_result(
                    name="org-gamma",
                    error="authentication failed: bad credentials",
                ),
            ]
        )

    def test_generates_file(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        assert output.exists()

    def test_output_is_nonempty(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        assert output.stat().st_size > 0

    def test_contains_org_alpha(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "org-alpha" in content

    def test_contains_org_beta(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "org-beta" in content

    def test_shows_failed_org_name(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "org-gamma" in content

    def test_shows_failed_org_error(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "authentication failed" in content

    def test_contains_tool_version(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "1.2.3" in content

    def test_contains_config_file(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "multi-org.yml" in content

    def test_contains_totals_row(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        # Totals row should be present
        assert "Totals" in content or "totals" in content.lower()

    def test_contains_repo_count(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        # org-alpha has 42 repos
        assert "42" in content

    def test_no_cdn_links(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "https://cdn" not in content

    def test_no_external_stylesheet_links(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert '<link rel="stylesheet"' not in content

    def test_no_external_script_src(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert 'src="http' not in content

    def test_creates_parent_dirs(self, tmp_path):
        summary = self._build_summary()
        nested = tmp_path / "a" / "b" / "c" / "summary.html"
        generate_summary_html(summary, nested)
        assert nested.exists()

    def test_header_title_present(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "Cross-Organization" in content or "cross-org" in content.lower()

    def test_footer_present(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "gh-audit" in content

    def test_success_status_indicated(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "success" in content.lower()

    def test_failed_status_indicated(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "failed" in content.lower() or "fail" in content.lower()

    def test_valid_html_doctype(self, tmp_path):
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content or "<!doctype html>" in content.lower()

    def test_empty_org_list(self, tmp_path):
        summary = _make_summary([])
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content or "<!doctype html>" in content.lower()

    def test_totals_match_model(self, tmp_path):
        """Total repos (52 = 42+10) should appear in the output."""
        summary = self._build_summary()
        output = tmp_path / "summary.html"
        generate_summary_html(summary, output)
        content = output.read_text(encoding="utf-8")
        # 42 + 10 = 52 total repos across successful orgs
        assert "52" in content
