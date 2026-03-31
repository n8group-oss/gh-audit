"""Tests for gh_audit.adapters.github_graphql — GraphQL client with pagination
and budget tracking.

Tests verify:
    - fetch_repos_bulk returns (repos, has_next, cursor, cost) tuple
    - fetch_repos_bulk with no next page: has_next=False, cursor=None
    - fetch_repos_bulk with next page: has_next=True, cursor set
    - fetch_all_repos auto-paginates across multiple pages
    - fetch_projects returns project list
    - fetch_projects paginates across multiple pages
    - GraphQL error with null data raises APIError
    - GraphQL partial error (data + errors) returns data without crashing
    - Cost extraction from extensions.cost
    - Default cost (1) when extensions not present
    - Retry on HTTP 502 then success
    - Retry on HTTP 503 then success
    - Raises APIError after max retries exceeded
    - GraphQLCost dataclass fields: requested and remaining
"""

from __future__ import annotations

import httpx
import pytest
import respx

from gh_audit.adapters.github_graphql import GitHubGraphQLClient, GraphQLCost
from gh_audit.exceptions import APIError

GRAPHQL_URL = "https://api.github.com/graphql"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_node(name: str = "repo1") -> dict:
    """Return a minimal repository node as returned by the GraphQL API."""
    return {
        "name": name,
        "nameWithOwner": f"myorg/{name}",
        "visibility": "PUBLIC",
        "isArchived": False,
        "isFork": False,
        "isTemplate": False,
        "primaryLanguage": {"name": "Python"},
        "repositoryTopics": {"nodes": []},
        "diskUsage": 100,
        "defaultBranchRef": {"name": "main"},
        "description": "A test repo",
        "refs": {"totalCount": 1},
        "openPRs": {"totalCount": 0},
        "closedPRs": {"totalCount": 0},
        "mergedPRs": {"totalCount": 0},
        "openIssues": {"totalCount": 0},
        "closedIssues": {"totalCount": 0},
        "labels": {"nodes": []},
        "branchProtectionRules": {"totalCount": 0},
        "object": None,
    }


def _repos_response(
    nodes: list[dict],
    *,
    has_next: bool = False,
    end_cursor: str | None = None,
    total_count: int | None = None,
    with_cost: bool = True,
) -> dict:
    """Build a mock GraphQL response for the repos query."""
    body: dict = {
        "data": {
            "organization": {
                "repositories": {
                    "totalCount": total_count if total_count is not None else len(nodes),
                    "pageInfo": {
                        "hasNextPage": has_next,
                        "endCursor": end_cursor,
                    },
                    "nodes": nodes,
                }
            }
        }
    }
    if with_cost:
        body["extensions"] = {"cost": {"requestedQueryCost": 10, "remainingPoints": 4990}}
    return body


def _projects_response(
    nodes: list[dict],
    *,
    has_next: bool = False,
    end_cursor: str | None = None,
) -> dict:
    """Build a mock GraphQL response for the projects query."""
    return {
        "data": {
            "organization": {
                "projectsV2": {
                    "totalCount": len(nodes),
                    "pageInfo": {
                        "hasNextPage": has_next,
                        "endCursor": end_cursor,
                    },
                    "nodes": nodes,
                }
            }
        },
        "extensions": {"cost": {"requestedQueryCost": 5, "remainingPoints": 4995}},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Return a GitHubGraphQLClient with a fake PAT token."""
    c = GitHubGraphQLClient(token="ghp_testtoken")
    yield c


# ---------------------------------------------------------------------------
# GraphQLCost dataclass
# ---------------------------------------------------------------------------


class TestGraphQLCost:
    """GraphQLCost carries requested and remaining budget."""

    def test_fields_are_set(self):
        cost = GraphQLCost(requested=10, remaining=4990)
        assert cost.requested == 10
        assert cost.remaining == 4990

    def test_remaining_can_be_none(self):
        cost = GraphQLCost(requested=1, remaining=None)
        assert cost.remaining is None

    def test_requested_is_int(self):
        cost = GraphQLCost(requested=7, remaining=100)
        assert isinstance(cost.requested, int)


# ---------------------------------------------------------------------------
# fetch_repos_bulk — basic
# ---------------------------------------------------------------------------


class TestFetchReposBulk:
    """fetch_repos_bulk returns (repos, has_next, cursor, cost)."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_tuple_shape(self, client):
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(200, json=_repos_response([_repo_node("alpha")]))
        )
        repos, has_next, cursor, cost = await client.fetch_repos_bulk("myorg")
        assert isinstance(repos, list)
        assert isinstance(has_next, bool)
        assert isinstance(cost, GraphQLCost)

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_next_page(self, client):
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(
                200,
                json=_repos_response([_repo_node("alpha")], has_next=False, end_cursor=None),
            )
        )
        repos, has_next, cursor, cost = await client.fetch_repos_bulk("myorg")
        assert has_next is False
        assert cursor is None
        assert len(repos) == 1
        assert repos[0]["name"] == "alpha"

    @respx.mock
    @pytest.mark.asyncio
    async def test_has_next_page_with_cursor(self, client):
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(
                200,
                json=_repos_response(
                    [_repo_node("beta")],
                    has_next=True,
                    end_cursor="cursor_abc",
                ),
            )
        )
        repos, has_next, cursor, cost = await client.fetch_repos_bulk("myorg")
        assert has_next is True
        assert cursor == "cursor_abc"

    @respx.mock
    @pytest.mark.asyncio
    async def test_cost_extracted_from_extensions(self, client):
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(
                200,
                json=_repos_response([_repo_node()], with_cost=True),
            )
        )
        _, _, _, cost = await client.fetch_repos_bulk("myorg")
        assert cost.requested == 10
        assert cost.remaining == 4990

    @respx.mock
    @pytest.mark.asyncio
    async def test_default_cost_when_no_extensions(self, client):
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(
                200,
                json=_repos_response([_repo_node()], with_cost=False),
            )
        )
        _, _, _, cost = await client.fetch_repos_bulk("myorg")
        assert cost.requested == 1
        assert cost.remaining is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_sends_cursor_variable_when_provided(self, client):
        route = respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(200, json=_repos_response([_repo_node()]))
        )
        await client.fetch_repos_bulk("myorg", cursor="Y3Vyc29y")
        request_body = route.calls[0].request.content
        import json

        body = json.loads(request_body)
        assert body["variables"]["cursor"] == "Y3Vyc29y"


# ---------------------------------------------------------------------------
# fetch_all_repos — auto-pagination
# ---------------------------------------------------------------------------


class TestFetchAllRepos:
    """fetch_all_repos auto-paginates until has_next is False."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_single_page(self, client):
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(
                200,
                json=_repos_response(
                    [_repo_node("alpha"), _repo_node("beta")],
                    has_next=False,
                ),
            )
        )
        result = await client.fetch_all_repos("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "alpha"

    @respx.mock
    @pytest.mark.asyncio
    async def test_two_pages(self, client):
        call_count = {"n": 0}

        def side_effect(request):
            import json

            body = json.loads(request.content)
            cursor = body.get("variables", {}).get("cursor")
            call_count["n"] += 1
            if cursor is None:
                return httpx.Response(
                    200,
                    json=_repos_response(
                        [_repo_node("page1_repo")],
                        has_next=True,
                        end_cursor="cursor_page2",
                    ),
                )
            return httpx.Response(
                200,
                json=_repos_response(
                    [_repo_node("page2_repo")],
                    has_next=False,
                    end_cursor=None,
                ),
            )

        respx.post(GRAPHQL_URL).mock(side_effect=side_effect)
        result = await client.fetch_all_repos("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "page1_repo"
        assert result[1]["name"] == "page2_repo"
        assert call_count["n"] == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_three_pages(self, client):
        call_count = {"n": 0}
        cursors = [None, "cursor2", "cursor3"]
        page_repos = [["r1"], ["r2", "r3"], ["r4"]]

        def side_effect(request):
            import json

            body = json.loads(request.content)
            body.get("variables", {}).get("cursor")
            i = call_count["n"]
            call_count["n"] += 1
            is_last = i == 2
            next_cursor = cursors[i + 1] if not is_last else None
            nodes = [_repo_node(n) for n in page_repos[i]]
            return httpx.Response(
                200,
                json=_repos_response(
                    nodes,
                    has_next=not is_last,
                    end_cursor=next_cursor,
                ),
            )

        respx.post(GRAPHQL_URL).mock(side_effect=side_effect)
        result = await client.fetch_all_repos("myorg")
        assert len(result) == 4
        assert call_count["n"] == 3


# ---------------------------------------------------------------------------
# fetch_projects
# ---------------------------------------------------------------------------


class TestFetchProjects:
    """fetch_projects returns all project nodes (auto-paginates)."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_project_list(self, client):
        nodes = [
            {"title": "Project Alpha", "closed": False, "items": {"totalCount": 5}},
            {"title": "Project Beta", "closed": True, "items": {"totalCount": 10}},
        ]
        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(200, json=_projects_response(nodes))
        )
        result = await client.fetch_projects("myorg")
        assert len(result) == 2
        assert result[0]["title"] == "Project Alpha"
        assert result[1]["closed"] is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_paginates_projects(self, client):
        call_count = {"n": 0}

        def side_effect(request):
            import json

            body = json.loads(request.content)
            cursor = body.get("variables", {}).get("cursor")
            call_count["n"] += 1
            if cursor is None:
                nodes = [{"title": "P1", "closed": False, "items": {"totalCount": 0}}]
                return httpx.Response(
                    200,
                    json=_projects_response(nodes, has_next=True, end_cursor="proj_cursor"),
                )
            nodes = [{"title": "P2", "closed": False, "items": {"totalCount": 0}}]
            return httpx.Response(200, json=_projects_response(nodes, has_next=False))

        respx.post(GRAPHQL_URL).mock(side_effect=side_effect)
        result = await client.fetch_projects("myorg")
        assert len(result) == 2
        assert result[0]["title"] == "P1"
        assert result[1]["title"] == "P2"
        assert call_count["n"] == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_project_list(self, client):
        respx.post(GRAPHQL_URL).mock(return_value=httpx.Response(200, json=_projects_response([])))
        result = await client.fetch_projects("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# GraphQL error handling
# ---------------------------------------------------------------------------


class TestGraphQLErrorHandling:
    """Error responses are handled per data-nullability rules."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_null_data_with_errors_raises_api_error(self, client):
        """data=null + errors array → raise APIError."""
        body = {
            "data": None,
            "errors": [{"message": "Could not resolve to an Organization"}],
        }
        respx.post(GRAPHQL_URL).mock(return_value=httpx.Response(200, json=body))
        with pytest.raises(APIError, match="Could not resolve"):
            await client.fetch_repos_bulk("nonexistent-org")

    @respx.mock
    @pytest.mark.asyncio
    async def test_partial_error_with_data_returns_data(self, client):
        """data non-null + errors array → return data (partial success), no crash."""
        body = {
            "data": {
                "organization": {
                    "repositories": {
                        "totalCount": 1,
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [_repo_node("partial-repo")],
                    }
                }
            },
            "errors": [
                {
                    "message": "Some field could not be fetched",
                    "path": ["organization", "repositories", "nodes", 0, "labels"],
                }
            ],
        }
        respx.post(GRAPHQL_URL).mock(return_value=httpx.Response(200, json=body))
        # Should NOT raise; returns partial data
        repos, has_next, cursor, cost = await client.fetch_repos_bulk("myorg")
        assert len(repos) == 1
        assert repos[0]["name"] == "partial-repo"

    @respx.mock
    @pytest.mark.asyncio
    async def test_missing_organization_raises_api_error(self, client):
        """data present but organization=null → raise APIError."""
        body = {
            "data": {"organization": None},
            "errors": [{"message": "Organization not found"}],
        }
        respx.post(GRAPHQL_URL).mock(return_value=httpx.Response(200, json=body))
        with pytest.raises(APIError):
            await client.fetch_repos_bulk("ghost-org")


# ---------------------------------------------------------------------------
# Retry on HTTP 502/503
# ---------------------------------------------------------------------------


class TestRetry:
    """GraphQL client retries on 502/503 up to max 2 times."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_502_then_succeeds(self, client):
        from unittest.mock import AsyncMock, patch

        route = respx.post(GRAPHQL_URL)
        route.side_effect = [
            httpx.Response(502, text="Bad Gateway"),
            httpx.Response(200, json=_repos_response([_repo_node("after-retry")])),
        ]
        with patch(
            "gh_audit.adapters.github_graphql.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            repos, _, _, _ = await client.fetch_repos_bulk("myorg")
        assert repos[0]["name"] == "after-retry"
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_503_then_succeeds(self, client):
        from unittest.mock import AsyncMock, patch

        route = respx.post(GRAPHQL_URL)
        route.side_effect = [
            httpx.Response(503, text="Service Unavailable"),
            httpx.Response(200, json=_repos_response([_repo_node("after-503")])),
        ]
        with patch(
            "gh_audit.adapters.github_graphql.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            repos, _, _, _ = await client.fetch_repos_bulk("myorg")
        assert repos[0]["name"] == "after-503"

    @respx.mock
    @pytest.mark.asyncio
    async def test_raises_api_error_after_max_retries(self, client):
        from unittest.mock import AsyncMock, patch

        respx.post(GRAPHQL_URL).mock(
            return_value=httpx.Response(503, text="Persistent Unavailable")
        )
        with patch(
            "gh_audit.adapters.github_graphql.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            with pytest.raises(APIError):
                await client.fetch_repos_bulk("myorg")


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    @pytest.mark.asyncio
    async def test_close_does_not_raise(self, client):
        """close() should complete without error."""
        await client.close()
