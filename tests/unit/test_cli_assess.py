"""Unit tests for the assess CLI command."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from gh_audit.cli.app import app
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.security import SecurityInfo
from gh_audit.models.user import OrgMemberSummary

runner = CliRunner()


def _make_inventory_json(tmp_path: Path) -> Path:
    inv = Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization="testorg",
            auth_method="pat",
            scan_profile="standard",
        ),
        summary=InventorySummary(total_repos=1),
        repositories=[
            RepositoryInventoryItem(
                name="repo-a",
                full_name="testorg/repo-a",
                visibility="private",
                security=SecurityInfo(dependabot_enabled=False),
            )
        ],
        users=OrgMemberSummary(total=1, admins=0, members=1),
    )
    path = tmp_path / "inventory.json"
    path.write_text(inv.model_dump_json(indent=2), encoding="utf-8")
    return path


class TestAssessCommand:
    def test_produces_html_report(self, tmp_path: Path) -> None:
        inv_path = _make_inventory_json(tmp_path)
        output = tmp_path / "assessment.html"
        result = runner.invoke(app, ["assess", "--input", str(inv_path), "--output", str(output)])
        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text()
        assert "testorg" in content

    def test_prints_summary(self, tmp_path: Path) -> None:
        inv_path = _make_inventory_json(tmp_path)
        output = tmp_path / "assessment.html"
        result = runner.invoke(app, ["assess", "--input", str(inv_path), "--output", str(output)])
        assert result.exit_code == 0
        # The output should mention findings count
        assert "finding" in result.stdout.lower() or "assessment" in result.stdout.lower()

    def test_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["assess", "--help"])
        assert result.exit_code == 0

    def test_input_flag_accepted(self) -> None:
        result = runner.invoke(app, ["assess", "--input", "/tmp/x.json", "--help"])
        assert result.exit_code == 0

    def test_output_flag_accepted(self) -> None:
        result = runner.invoke(app, ["assess", "--output", "/tmp/x.html", "--help"])
        assert result.exit_code == 0

    def test_missing_input_file(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "assess",
                "--input",
                str(tmp_path / "nonexistent.json"),
                "--output",
                str(tmp_path / "out.html"),
            ],
        )
        assert result.exit_code != 0

    def test_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "assess",
                "--input",
                str(bad),
                "--output",
                str(tmp_path / "out.html"),
            ],
        )
        assert result.exit_code != 0

    def test_schema_version_mismatch_warns(self, tmp_path: Path) -> None:
        """Schema version mismatch should warn but still produce a report."""
        inv = Inventory(
            metadata=InventoryMetadata(
                schema_version="0.1",  # old version
                generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
                tool_version="0.1.0",
                organization="testorg",
                auth_method="pat",
                scan_profile="standard",
            ),
            summary=InventorySummary(total_repos=0),
            repositories=[],
            users=OrgMemberSummary(total=0, admins=0, members=0),
        )
        inv_path = tmp_path / "inventory.json"
        inv_path.write_text(inv.model_dump_json(indent=2), encoding="utf-8")
        output = tmp_path / "assessment.html"
        result = runner.invoke(app, ["assess", "--input", str(inv_path), "--output", str(output)])
        assert result.exit_code == 0  # still succeeds
        assert output.exists()
        assert "schema" in result.stdout.lower() or "version" in result.stdout.lower()
