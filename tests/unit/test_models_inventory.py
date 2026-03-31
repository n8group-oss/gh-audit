"""Tests for gh_audit.models.inventory — Inventory, InventoryMetadata,
InventorySummary and cross-cutting model integration."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from gh_audit.models.inventory import (
    Inventory,
    InventoryMetadata,
    InventorySummary,
)
from gh_audit.models.packages import PackageInfo
from gh_audit.models.projects import ProjectInfo
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc)


def _metadata(**kw) -> InventoryMetadata:
    defaults = {
        "schema_version": "1.0",
        "generated_at": _now(),
        "tool_version": "0.1.0",
        "organization": "my-org",
        "auth_method": "pat",
        "scan_profile": "standard",
    }
    defaults.update(kw)
    return InventoryMetadata(**defaults)


def _minimal_repo(name: str = "repo-a", visibility: str = "private") -> RepositoryInventoryItem:
    return RepositoryInventoryItem(
        name=name,
        full_name=f"my-org/{name}",
        visibility=visibility,
    )


def _empty_inventory(**kw) -> Inventory:
    defaults: dict = {
        "metadata": _metadata(),
        "summary": InventorySummary(),
        "repositories": [],
        "users": OrgMemberSummary(),
    }
    defaults.update(kw)
    return Inventory(**defaults)


# ---------------------------------------------------------------------------
# InventoryMetadata
# ---------------------------------------------------------------------------


class TestInventoryMetadata:
    def test_minimal_construction(self):
        m = _metadata()
        assert m.organization == "my-org"
        assert m.auth_method == "pat"
        assert m.api_url == "https://api.github.com"
        assert m.scan_profile == "standard"

    def test_scan_options_default_empty_dict(self):
        m = _metadata()
        assert m.scan_options == {}

    def test_scan_warnings_default_empty_list(self):
        m = _metadata()
        assert m.scan_warnings == []

    def test_api_url_custom(self):
        m = _metadata(api_url="https://github.example.com/api/v3")
        assert m.api_url == "https://github.example.com/api/v3"

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            _metadata(unexpected_field="oops")

    def test_scan_options_stores_flags(self):
        m = _metadata(scan_options={"scan_large_files": True, "concurrency": 16})
        assert m.scan_options["scan_large_files"] is True
        assert m.scan_options["concurrency"] == 16

    def test_scan_options_not_shared(self):
        a = _metadata()
        b = _metadata()
        a.scan_options["x"] = 1
        assert "x" not in b.scan_options


# ---------------------------------------------------------------------------
# InventorySummary defaults
# ---------------------------------------------------------------------------


class TestInventorySummaryDefaults:
    def test_all_counts_default_zero(self):
        s = InventorySummary()
        assert s.total_repos == 0
        assert s.public_repos == 0
        assert s.private_repos == 0
        assert s.internal_repos == 0
        assert s.archived_repos == 0
        assert s.forked_repos == 0
        assert s.template_repos == 0
        assert s.total_size_bytes == 0
        assert s.total_branches == 0
        assert s.total_prs == 0
        assert s.total_issues == 0
        assert s.repos_with_large_files == 0
        assert s.repos_with_lfs == 0
        assert s.repos_with_workflows == 0
        assert s.total_workflow_count == 0
        assert s.repos_with_self_hosted_runners == 0
        assert s.repos_with_dependabot == 0
        assert s.repos_with_code_scanning == 0
        assert s.repos_with_secret_scanning == 0
        assert s.total_packages == 0
        assert s.total_projects == 0

    def test_packages_by_type_default_empty_dict(self):
        s = InventorySummary()
        assert s.packages_by_type == {}

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            InventorySummary(mystery=999)

    def test_packages_by_type_not_shared(self):
        a = InventorySummary()
        b = InventorySummary()
        a.packages_by_type["npm"] = 5
        assert "npm" not in b.packages_by_type


# ---------------------------------------------------------------------------
# OrgMemberSummary
# ---------------------------------------------------------------------------


class TestOrgMemberSummaryDefaults:
    def test_all_zero_by_default(self):
        u = OrgMemberSummary()
        assert u.total == 0
        assert u.admins == 0
        assert u.members == 0
        assert u.outside_collaborators == 0

    def test_construction_with_values(self):
        u = OrgMemberSummary(total=100, admins=5, members=90, outside_collaborators=5)
        assert u.total == 100
        assert u.admins == 5

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            OrgMemberSummary(strangers=99)


# ---------------------------------------------------------------------------
# PackageInfo
# ---------------------------------------------------------------------------


class TestPackageInfo:
    def test_construction(self):
        p = PackageInfo(name="my-lib", package_type="npm")
        assert p.name == "my-lib"
        assert p.package_type == "npm"
        assert p.visibility == "private"

    def test_visibility_custom(self):
        p = PackageInfo(name="pub-lib", package_type="pypi", visibility="public")
        assert p.visibility == "public"

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            PackageInfo(name="x", package_type="npm", oops=True)


# ---------------------------------------------------------------------------
# ProjectInfo
# ---------------------------------------------------------------------------


class TestProjectInfo:
    def test_construction(self):
        p = ProjectInfo(title="Q1 Sprint")
        assert p.title == "Q1 Sprint"
        assert p.item_count == 0
        assert p.closed is False

    def test_closed_project(self):
        p = ProjectInfo(title="Old Sprint", item_count=50, closed=True)
        assert p.closed is True
        assert p.item_count == 50

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            ProjectInfo(title="x", oops=True)


# ---------------------------------------------------------------------------
# Inventory root model construction
# ---------------------------------------------------------------------------


class TestInventoryConstruction:
    def test_minimal_empty_inventory(self):
        inv = _empty_inventory()
        assert inv.metadata.organization == "my-org"
        assert inv.summary.total_repos == 0
        assert inv.repositories == []
        assert inv.users.total == 0
        assert inv.packages == []
        assert inv.projects == []

    def test_inventory_with_repositories(self):
        repos = [
            _minimal_repo("repo-a", "public"),
            _minimal_repo("repo-b", "private"),
        ]
        inv = _empty_inventory(repositories=repos, summary=InventorySummary(total_repos=2))
        assert len(inv.repositories) == 2
        assert inv.summary.total_repos == 2

    def test_inventory_with_packages(self):
        pkgs = [
            PackageInfo(name="pkg-a", package_type="npm"),
            PackageInfo(name="pkg-b", package_type="pypi"),
        ]
        inv = _empty_inventory(packages=pkgs)
        assert len(inv.packages) == 2

    def test_inventory_with_projects(self):
        projects = [
            ProjectInfo(title="Roadmap", item_count=10),
            ProjectInfo(title="Backlog", item_count=30, closed=True),
        ]
        inv = _empty_inventory(projects=projects)
        assert len(inv.projects) == 2
        assert inv.projects[1].closed is True

    def test_inventory_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            Inventory(
                metadata=_metadata(),
                summary=InventorySummary(),
                repositories=[],
                users=OrgMemberSummary(),
                extra_nonsense="bad",
            )

    def test_packages_default_empty_list(self):
        inv = _empty_inventory()
        assert inv.packages == []

    def test_projects_default_empty_list(self):
        inv = _empty_inventory()
        assert inv.projects == []


# ---------------------------------------------------------------------------
# JSON serialization roundtrip
# ---------------------------------------------------------------------------


class TestInventorySerialization:
    def test_roundtrip_empty(self):
        original = _empty_inventory()
        restored = Inventory.model_validate_json(original.model_dump_json())
        assert restored.metadata.organization == "my-org"
        assert restored.repositories == []
        assert restored.packages == []
        assert restored.projects == []

    def test_roundtrip_with_repos_and_packages(self):
        from gh_audit.models.security import SecurityInfo
        from gh_audit.models.repository import LargeFileScan

        original = Inventory(
            metadata=_metadata(
                scan_options={"scan_large_files": False, "concurrency": 8},
                scan_warnings=["rate_limit_hit"],
            ),
            summary=InventorySummary(
                total_repos=1,
                private_repos=1,
                total_packages=1,
                packages_by_type={"npm": 1},
            ),
            repositories=[
                RepositoryInventoryItem(
                    name="api",
                    full_name="my-org/api",
                    visibility="private",
                    language="Python",
                    security=SecurityInfo(
                        dependabot_enabled=True,
                        alerts_accessible=True,
                        counts_exact=True,
                        dependabot_alerts_open=0,
                        code_scanning_alerts_open=None,
                        secret_scanning_alerts_open=None,
                    ),
                    large_file_scan=LargeFileScan(enabled=False),
                )
            ],
            users=OrgMemberSummary(total=5, admins=1, members=4),
            packages=[PackageInfo(name="my-pkg", package_type="npm")],
            projects=[ProjectInfo(title="Sprint 1", item_count=5)],
        )
        restored = Inventory.model_validate_json(original.model_dump_json())
        assert restored == original
        repo = restored.repositories[0]
        assert repo.security.dependabot_alerts_open == 0
        assert repo.security.code_scanning_alerts_open is None
        assert repo.large_file_scan.enabled is False
        assert restored.packages[0].name == "my-pkg"
        assert restored.projects[0].title == "Sprint 1"

    def test_roundtrip_preserves_datetime(self):
        original = _empty_inventory()
        restored = Inventory.model_validate_json(original.model_dump_json())
        assert restored.metadata.generated_at == original.metadata.generated_at
