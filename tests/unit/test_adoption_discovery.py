"""Unit tests for adoption category discovery integration."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gh_audit.models.config import ScannerConfig
from gh_audit.services.discovery import DiscoveryService


def _make_config(*, categories: list[str] | None = None, **kwargs) -> ScannerConfig:
    defaults = dict(
        organization="myorg",
        token="ghp_fake_token",
        scan_profile="standard",
        categories=categories or [],
    )
    defaults.update(kwargs)
    return ScannerConfig(**defaults)


def _make_graphql_repo(name: str = "my-repo") -> dict:
    return {
        "name": name,
        "nameWithOwner": f"myorg/{name}",
        "description": None,
        "visibility": "PRIVATE",
        "isArchived": False,
        "isFork": False,
        "isTemplate": False,
        "primaryLanguage": None,
        "repositoryTopics": {"nodes": []},
        "defaultBranchRef": {"name": "main"},
        "diskUsage": 100,
        "refs": {"totalCount": 1},
        "pullRequests": {"totalCount": 0},
        "closedPullRequests": {"totalCount": 0},
        "mergedPullRequests": {"totalCount": 0},
        "issues": {"totalCount": 0},
        "closedIssues": {"totalCount": 0},
        "licenseInfo": None,
        "createdAt": "2025-01-01T00:00:00Z",
        "updatedAt": "2025-06-01T00:00:00Z",
        "pushedAt": "2025-06-01T00:00:00Z",
    }


def _make_rest_client(*, with_adoption: bool = False) -> AsyncMock:
    rest = AsyncMock()
    # Base endpoints (return empty/minimal by default)
    rest.verify_credentials.return_value = {"login": "myorg", "type": "Organization"}
    rest.list_org_members.return_value = []
    rest.list_outside_collaborators.return_value = []
    rest.list_packages.return_value = []
    rest.list_rulesets.return_value = []
    rest.get_security_features.return_value = {}

    if with_adoption:
        # Copilot
        rest.get_copilot_billing.return_value = {
            "seat_breakdown": {"total": 50, "active_this_cycle": 40},
        }
        rest.get_copilot_metrics.return_value = [
            {"total_suggestions_count": 100, "total_acceptances_count": 70, "language": "python"},
            {
                "total_suggestions_count": 50,
                "total_acceptances_count": 30,
                "language": "typescript",
            },
        ]
        # Per-repo
        rest.get_repo_traffic_views.return_value = {"count": 200, "uniques": 80}
        rest.get_repo_traffic_clones.return_value = {"count": 30, "uniques": 15}
        rest.get_repo_community_profile.return_value = {
            "health_percentage": 71,
            "files": {
                "readme": {"url": "..."},
                "contributing": None,
                "license": {"spdx_id": "MIT"},
                "code_of_conduct": None,
                "issue_template": None,
                "pull_request_template": None,
            },
        }
        rest.get_repo_commit_activity.return_value = [
            {"total": 5, "week": 1700000000},
            {"total": 0, "week": 1700600000},
            {"total": 3, "week": 1701200000},
        ]
        rest.get_workflow_runs_count.return_value = 10
    else:
        rest.get_copilot_billing.return_value = None
        rest.get_copilot_metrics.return_value = []
        rest.get_repo_traffic_views.return_value = None
        rest.get_repo_traffic_clones.return_value = None
        rest.get_repo_community_profile.return_value = None
        rest.get_repo_commit_activity.return_value = []
        rest.get_workflow_runs_count.return_value = 0

    return rest


def _make_graphql_client() -> AsyncMock:
    gql = AsyncMock()
    gql.fetch_all_repos.return_value = [_make_graphql_repo()]
    gql.fetch_projects.return_value = []
    return gql


@pytest.mark.asyncio
class TestStandardProfileNoAdoption:
    async def test_adoption_is_none(self) -> None:
        config = _make_config()
        svc = DiscoveryService(
            config=config,
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
        )
        inv = await svc.discover()
        assert inv.adoption is None
        assert inv.repositories[0].traffic is None
        assert inv.repositories[0].community_profile is None
        assert inv.repositories[0].commit_activity_90d is None
        assert inv.repositories[0].actions_run_summary is None


@pytest.mark.asyncio
class TestAdoptionCategoryEnabled:
    async def test_adoption_populated(self) -> None:
        config = _make_config(categories=["adoption"])
        rest = _make_rest_client(with_adoption=True)
        svc = DiscoveryService(
            config=config,
            rest_client=rest,
            graphql_client=_make_graphql_client(),
        )
        inv = await svc.discover()

        # Org-level
        assert inv.adoption is not None
        assert inv.adoption.copilot is not None
        assert inv.adoption.copilot.total_seats == 50
        assert inv.adoption.copilot.active_seats == 40
        assert inv.adoption.org_community_health.repos_with_readme == 1
        assert inv.adoption.org_community_health.repos_with_license == 1
        assert inv.adoption.org_community_health.average_health_percentage == 71.0

        # Per-repo
        repo = inv.repositories[0]
        assert repo.traffic is not None
        assert repo.traffic.views_14d == 200
        assert repo.traffic.unique_visitors_14d == 80
        assert repo.traffic.clones_14d == 30
        assert repo.community_profile is not None
        assert repo.community_profile.health_percentage == 71
        assert repo.community_profile.has_readme is True
        assert repo.community_profile.has_license is True
        assert repo.community_profile.has_contributing is False
        assert repo.commit_activity_90d is not None
        assert repo.commit_activity_90d.total_commits == 8
        assert repo.commit_activity_90d.active_weeks == 2
        assert repo.actions_run_summary is not None

        # Metadata
        assert "adoption" in inv.metadata.active_categories


@pytest.mark.asyncio
class TestAdoptionGracefulDegradation:
    async def test_copilot_failure_records_warning(self) -> None:
        config = _make_config(categories=["adoption"])
        rest = _make_rest_client(with_adoption=True)
        rest.get_copilot_billing.side_effect = Exception("Copilot API error")
        rest.get_copilot_metrics.side_effect = Exception("Copilot API error")
        svc = DiscoveryService(
            config=config,
            rest_client=rest,
            graphql_client=_make_graphql_client(),
        )
        inv = await svc.discover()
        assert inv.adoption is not None
        assert inv.adoption.copilot is None
        assert any("Copilot" in w for w in inv.metadata.scan_warnings)

    async def test_traffic_failure_records_warning(self) -> None:
        config = _make_config(categories=["adoption"])
        rest = _make_rest_client(with_adoption=True)
        rest.get_repo_traffic_views.side_effect = Exception("forbidden")
        rest.get_repo_traffic_clones.side_effect = Exception("forbidden")
        svc = DiscoveryService(
            config=config,
            rest_client=rest,
            graphql_client=_make_graphql_client(),
        )
        inv = await svc.discover()
        repo = inv.repositories[0]
        assert repo.traffic is None
        assert any("Traffic" in w or "traffic" in w for w in repo.warnings)

    async def test_community_profile_failure(self) -> None:
        config = _make_config(categories=["adoption"])
        rest = _make_rest_client(with_adoption=True)
        rest.get_repo_community_profile.side_effect = Exception("error")
        svc = DiscoveryService(
            config=config,
            rest_client=rest,
            graphql_client=_make_graphql_client(),
        )
        inv = await svc.discover()
        repo = inv.repositories[0]
        assert repo.community_profile is None
        assert any("community" in w.lower() for w in repo.warnings)
