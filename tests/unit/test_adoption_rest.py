"""Unit tests for adoption-related REST methods."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from gh_audit.adapters.github_rest import GitHubRestClient

BASE = "https://api.github.com"


@pytest.fixture
def client() -> GitHubRestClient:
    return GitHubRestClient(token="ghp_test", base_url=BASE)


@pytest.mark.asyncio
class TestGetCopilotBilling:
    @respx.mock
    async def test_returns_billing(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/orgs/myorg/copilot/billing").mock(
            return_value=Response(
                200, json={"seat_breakdown": {"total": 50, "active_this_cycle": 40}}
            )
        )
        result = await client.get_copilot_billing("myorg")
        assert result is not None
        assert result["seat_breakdown"]["total"] == 50

    @respx.mock
    async def test_returns_none_on_404(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/orgs/myorg/copilot/billing").mock(return_value=Response(404))
        result = await client.get_copilot_billing("myorg")
        assert result is None

    @respx.mock
    async def test_returns_none_on_403(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/orgs/myorg/copilot/billing").mock(return_value=Response(403))
        result = await client.get_copilot_billing("myorg")
        assert result is None


@pytest.mark.asyncio
class TestGetCopilotMetrics:
    @respx.mock
    async def test_returns_metrics(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/orgs/myorg/copilot/metrics").mock(
            return_value=Response(200, json=[{"day": "2026-03-01", "total_suggestions_count": 100}])
        )
        result = await client.get_copilot_metrics("myorg")
        assert len(result) == 1
        assert result[0]["total_suggestions_count"] == 100

    @respx.mock
    async def test_returns_empty_on_403(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/orgs/myorg/copilot/metrics").mock(return_value=Response(403))
        result = await client.get_copilot_metrics("myorg")
        assert result == []


@pytest.mark.asyncio
class TestGetRepoTrafficViews:
    @respx.mock
    async def test_returns_views(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/traffic/views").mock(
            return_value=Response(200, json={"count": 500, "uniques": 200})
        )
        result = await client.get_repo_traffic_views("myorg", "myrepo")
        assert result is not None
        assert result["count"] == 500

    @respx.mock
    async def test_returns_none_on_403(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/traffic/views").mock(return_value=Response(403))
        result = await client.get_repo_traffic_views("myorg", "myrepo")
        assert result is None


@pytest.mark.asyncio
class TestGetRepoTrafficClones:
    @respx.mock
    async def test_returns_clones(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/traffic/clones").mock(
            return_value=Response(200, json={"count": 50, "uniques": 30})
        )
        result = await client.get_repo_traffic_clones("myorg", "myrepo")
        assert result is not None
        assert result["count"] == 50

    @respx.mock
    async def test_returns_none_on_403(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/traffic/clones").mock(return_value=Response(403))
        result = await client.get_repo_traffic_clones("myorg", "myrepo")
        assert result is None


@pytest.mark.asyncio
class TestGetRepoCommunityProfile:
    @respx.mock
    async def test_returns_profile(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/community/profile").mock(
            return_value=Response(
                200, json={"health_percentage": 85, "files": {"readme": {"url": "..."}}}
            )
        )
        result = await client.get_repo_community_profile("myorg", "myrepo")
        assert result is not None
        assert result["health_percentage"] == 85

    @respx.mock
    async def test_returns_none_on_404(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/community/profile").mock(return_value=Response(404))
        result = await client.get_repo_community_profile("myorg", "myrepo")
        assert result is None


@pytest.mark.asyncio
class TestGetRepoCommitActivity:
    @respx.mock
    async def test_returns_activity(self, client: GitHubRestClient) -> None:
        weeks = [{"total": 10, "week": 1700000000}] * 13
        respx.get(f"{BASE}/repos/myorg/myrepo/stats/commit_activity").mock(
            return_value=Response(200, json=weeks)
        )
        result = await client.get_repo_commit_activity("myorg", "myrepo")
        assert len(result) == 13

    @respx.mock
    async def test_returns_empty_on_403(self, client: GitHubRestClient) -> None:
        respx.get(f"{BASE}/repos/myorg/myrepo/stats/commit_activity").mock(
            return_value=Response(403)
        )
        result = await client.get_repo_commit_activity("myorg", "myrepo")
        assert result == []

    @respx.mock
    async def test_returns_empty_on_202(self, client: GitHubRestClient) -> None:
        """GitHub returns 202 when stats are being computed (not yet ready)."""
        respx.get(f"{BASE}/repos/myorg/myrepo/stats/commit_activity").mock(
            return_value=Response(202)
        )
        result = await client.get_repo_commit_activity("myorg", "myrepo")
        assert result == []


@pytest.mark.asyncio
class TestGetWorkflowRunsCount:
    @respx.mock
    async def test_returns_count(self, client: GitHubRestClient) -> None:
        respx.get(url__regex=rf"{BASE}/repos/myorg/myrepo/actions/runs.*").mock(
            return_value=Response(200, json={"total_count": 42, "workflow_runs": []})
        )
        result = await client.get_workflow_runs_count(
            "myorg", "myrepo", conclusion="success", created=">=2026-01-01"
        )
        assert result == 42

    @respx.mock
    async def test_returns_zero_on_403(self, client: GitHubRestClient) -> None:
        respx.get(url__regex=rf"{BASE}/repos/myorg/myrepo/actions/runs.*").mock(
            return_value=Response(403)
        )
        result = await client.get_workflow_runs_count(
            "myorg", "myrepo", conclusion="success", created=">=2026-01-01"
        )
        assert result == 0
