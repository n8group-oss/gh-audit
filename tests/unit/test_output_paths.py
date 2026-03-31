"""Tests for gh_audit.cli.output_paths — output path helpers."""

from __future__ import annotations

import pathlib


from gh_audit.cli.output_paths import OutputPaths


# ---------------------------------------------------------------------------
# From explicit JSON path
# ---------------------------------------------------------------------------


class TestOutputPathsFromJsonPath:
    """OutputPaths.from_json_path builds all siblings from an explicit JSON path."""

    def test_json_path_name_ends_with_inventory_json(self, tmp_path):
        json_path = tmp_path / "my-org-inventory.json"
        paths = OutputPaths.from_json_path(json_path)
        assert paths.json.name.endswith("-inventory.json")

    def test_json_path_stored(self, tmp_path):
        json_path = tmp_path / "my-org-inventory.json"
        paths = OutputPaths.from_json_path(json_path)
        assert paths.json == json_path

    def test_report_name_ends_with_report_html(self, tmp_path):
        json_path = tmp_path / "my-org-inventory.json"
        paths = OutputPaths.from_json_path(json_path)
        assert paths.report.name.endswith("-report.html")

    def test_excel_name_ends_with_inventory_xlsx(self, tmp_path):
        json_path = tmp_path / "my-org-inventory.json"
        paths = OutputPaths.from_json_path(json_path)
        assert paths.excel.name.endswith("-inventory.xlsx")

    def test_all_paths_in_same_directory(self, tmp_path):
        json_path = tmp_path / "my-org-inventory.json"
        paths = OutputPaths.from_json_path(json_path)
        assert paths.json.parent == tmp_path
        assert paths.report.parent == tmp_path
        assert paths.excel.parent == tmp_path

    def test_slug_preserved_in_all_names(self, tmp_path):
        json_path = tmp_path / "acme-corp-inventory.json"
        paths = OutputPaths.from_json_path(json_path)
        assert "acme-corp" in paths.json.name
        assert "acme-corp" in paths.report.name
        assert "acme-corp" in paths.excel.name


# ---------------------------------------------------------------------------
# From output directory + org name
# ---------------------------------------------------------------------------


class TestOutputPathsFromDirectory:
    """OutputPaths.from_directory builds paths under a directory."""

    def test_json_name_ends_with_inventory_json(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert paths.json.name.endswith("-inventory.json")

    def test_report_name_ends_with_report_html(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert paths.report.name.endswith("-report.html")

    def test_excel_name_ends_with_inventory_xlsx(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert paths.excel.name.endswith("-inventory.xlsx")

    def test_all_paths_under_output_dir(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="acme")
        assert paths.json.parent == tmp_path
        assert paths.report.parent == tmp_path
        assert paths.excel.parent == tmp_path

    def test_org_name_included_in_filenames(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="octocat")
        assert "octocat" in paths.json.name
        assert "octocat" in paths.report.name
        assert "octocat" in paths.excel.name

    def test_paths_are_pathlib_path_instances(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert isinstance(paths.json, pathlib.Path)
        assert isinstance(paths.report, pathlib.Path)
        assert isinstance(paths.excel, pathlib.Path)


# ---------------------------------------------------------------------------
# Spec assertions from task description
# ---------------------------------------------------------------------------


class TestSpecAssertions:
    """Exact assertions from the task spec."""

    def test_json_name_ends_with_inventory_json(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert paths.json.name.endswith("-inventory.json")

    def test_report_name_ends_with_report_html(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert paths.report.name.endswith("-report.html")

    def test_excel_name_ends_with_inventory_xlsx(self, tmp_path):
        paths = OutputPaths.from_directory(tmp_path, org="my-org")
        assert paths.excel.name.endswith("-inventory.xlsx")
