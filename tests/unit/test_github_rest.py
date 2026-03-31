"""Tests for gh_audit.adapters.github_rest — capability-aware REST client.

Tests verify:
    - list_repos returns parsed JSON
    - get_tree returns tree data
    - get_file_content decodes base64 content
    - get_file_content returns None on 404
    - list_workflows returns workflow list
    - count_dependabot_alerts returns AlertCountResult(count=None, accessible=False) on 403
    - count_dependabot_alerts returns AlertCountResult(count=N, accessible=True) on 200
    - rate_limit_remaining tracked from response headers
    - list_rulesets returns None on 403
    - list_org_members returns member list
    - list_packages returns packages
    - verify_credentials raises AuthenticationError on 401
    - retry on 503 (first call returns 503, second call returns 200)
"""

from __future__ import annotations

import base64

import httpx
import pytest
import respx

from gh_audit.adapters.base import AlertCountResult
from gh_audit.adapters.github_rest import GitHubRestClient
from gh_audit.exceptions import AuthenticationError

BASE = "https://api.github.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Return a GitHubRestClient with a fake token."""
    c = GitHubRestClient(token="ghp_testtoken")
    yield c


# ---------------------------------------------------------------------------
# verify_credentials
# ---------------------------------------------------------------------------


class TestVerifyCredentials:
    """verify_credentials() raises AuthenticationError on 401/403."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_org_data_on_success(self, client):
        respx.get(f"{BASE}/orgs/myorg").mock(
            return_value=httpx.Response(200, json={"login": "myorg", "id": 1})
        )
        result = await client.verify_credentials("myorg")
        assert result["login"] == "myorg"

    @respx.mock
    @pytest.mark.asyncio
    async def test_raises_authentication_error_on_401(self, client):
        respx.get(f"{BASE}/orgs/myorg").mock(
            return_value=httpx.Response(401, json={"message": "Bad credentials"})
        )
        with pytest.raises(AuthenticationError):
            await client.verify_credentials("myorg")

    @respx.mock
    @pytest.mark.asyncio
    async def test_raises_authentication_error_on_403(self, client):
        respx.get(f"{BASE}/orgs/myorg").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        with pytest.raises(AuthenticationError):
            await client.verify_credentials("myorg")


# ---------------------------------------------------------------------------
# list_repos
# ---------------------------------------------------------------------------


class TestListRepos:
    """list_repos() returns all repos across paginated responses."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_parsed_json(self, client):
        respx.get(f"{BASE}/orgs/myorg/repos").mock(
            return_value=httpx.Response(
                200,
                json=[{"name": "repo1"}, {"name": "repo2"}],
                headers={"x-ratelimit-remaining": "4999", "x-ratelimit-reset": "9999999999"},
            )
        )
        result = await client.list_repos("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "repo1"
        assert result[1]["name"] == "repo2"

    @respx.mock
    @pytest.mark.asyncio
    async def test_paginates_via_link_header(self, client):
        page2_url = f"{BASE}/orgs/myorg/repos?page=2&per_page=100"
        call_count = {"n": 0}

        def side_effect(request):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return httpx.Response(
                    200,
                    json=[{"name": "repo1"}],
                    headers={"Link": f'<{page2_url}>; rel="next"'},
                )
            return httpx.Response(200, json=[{"name": "repo2"}])

        respx.get(url__regex=r".*/orgs/myorg/repos.*").mock(side_effect=side_effect)
        result = await client.list_repos("myorg")
        assert len(result) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_rate_limit_remaining_tracked(self, client):
        respx.get(f"{BASE}/orgs/myorg/repos").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "x-ratelimit-remaining": "1234",
                    "x-ratelimit-reset": "9999999999",
                },
            )
        )
        await client.list_repos("myorg")
        assert client.rate_limit_remaining == 1234


# ---------------------------------------------------------------------------
# list_org_members
# ---------------------------------------------------------------------------


class TestListOrgMembers:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_member_list(self, client):
        respx.get(f"{BASE}/orgs/myorg/members").mock(
            return_value=httpx.Response(200, json=[{"login": "alice"}, {"login": "bob"}])
        )
        result = await client.list_org_members("myorg")
        assert len(result) == 2
        assert result[0]["login"] == "alice"

    @respx.mock
    @pytest.mark.asyncio
    async def test_passes_role_param(self, client):
        route = respx.get(f"{BASE}/orgs/myorg/members").mock(
            return_value=httpx.Response(200, json=[])
        )
        await client.list_org_members("myorg", role="admin")
        assert route.called
        # Verify role param was sent
        called_url = str(route.calls[0].request.url)
        assert "role=admin" in called_url


# ---------------------------------------------------------------------------
# list_outside_collaborators
# ---------------------------------------------------------------------------


class TestListOutsideCollaborators:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_collaborator_list(self, client):
        respx.get(f"{BASE}/orgs/myorg/outside_collaborators").mock(
            return_value=httpx.Response(200, json=[{"login": "external"}])
        )
        result = await client.list_outside_collaborators("myorg")
        assert len(result) == 1
        assert result[0]["login"] == "external"


# ---------------------------------------------------------------------------
# list_packages
# ---------------------------------------------------------------------------


class TestListPackages:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_packages(self, client):
        respx.get(f"{BASE}/orgs/myorg/packages").mock(
            return_value=httpx.Response(
                200,
                json=[{"name": "my-package", "package_type": "npm"}],
            )
        )
        result = await client.list_packages("myorg", "npm")
        assert len(result) == 1
        assert result[0]["name"] == "my-package"


# ---------------------------------------------------------------------------
# get_tree
# ---------------------------------------------------------------------------


class TestGetTree:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_tree_data(self, client):
        tree_data = {"sha": "abc123", "tree": [{"path": "README.md", "type": "blob"}]}
        respx.get(f"{BASE}/repos/myorg/repo1/git/trees/abc123").mock(
            return_value=httpx.Response(200, json=tree_data)
        )
        result = await client.get_tree("myorg", "repo1", "abc123")
        assert result["sha"] == "abc123"
        assert len(result["tree"]) == 1


# ---------------------------------------------------------------------------
# get_file_content
# ---------------------------------------------------------------------------


class TestGetFileContent:
    @respx.mock
    @pytest.mark.asyncio
    async def test_decodes_base64_content(self, client):
        raw_content = "Hello, world!"
        encoded = base64.b64encode(raw_content.encode()).decode()
        respx.get(f"{BASE}/repos/myorg/repo1/contents/README.md").mock(
            return_value=httpx.Response(
                200,
                json={"content": encoded + "\n", "encoding": "base64"},
            )
        )
        result = await client.get_file_content("myorg", "repo1", "README.md")
        assert result == raw_content

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, client):
        respx.get(f"{BASE}/repos/myorg/repo1/contents/missing.txt").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await client.get_file_content("myorg", "repo1", "missing.txt")
        assert result is None


# ---------------------------------------------------------------------------
# list_workflows
# ---------------------------------------------------------------------------


class TestListWorkflows:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_workflow_list(self, client):
        workflows_data = {
            "total_count": 2,
            "workflows": [
                {"id": 1, "name": "CI", "path": ".github/workflows/ci.yml"},
                {"id": 2, "name": "CD", "path": ".github/workflows/cd.yml"},
            ],
        }
        respx.get(f"{BASE}/repos/myorg/repo1/actions/workflows").mock(
            return_value=httpx.Response(200, json=workflows_data)
        )
        result = await client.list_workflows("myorg", "repo1")
        assert len(result) == 2
        assert result[0]["name"] == "CI"


# ---------------------------------------------------------------------------
# get_workflow_file
# ---------------------------------------------------------------------------


class TestGetWorkflowFile:
    @respx.mock
    @pytest.mark.asyncio
    async def test_decodes_workflow_file(self, client):
        content = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest"
        encoded = base64.b64encode(content.encode()).decode()
        respx.get(f"{BASE}/repos/myorg/repo1/contents/.github/workflows/ci.yml").mock(
            return_value=httpx.Response(200, json={"content": encoded, "encoding": "base64"})
        )
        result = await client.get_workflow_file("myorg", "repo1", ".github/workflows/ci.yml")
        assert result == content

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, client):
        respx.get(f"{BASE}/repos/myorg/repo1/contents/.github/workflows/missing.yml").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await client.get_workflow_file("myorg", "repo1", ".github/workflows/missing.yml")
        assert result is None


# ---------------------------------------------------------------------------
# count_dependabot_alerts
# ---------------------------------------------------------------------------


class TestCountDependabotAlerts:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_inaccessible_on_403(self, client):
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await client.count_dependabot_alerts("myorg", "repo1")
        assert result.count is None
        assert result.accessible is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_count_on_success(self, client):
        alerts = [{"number": 1}, {"number": 2}, {"number": 3}]
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(200, json=alerts)
        )
        result = await client.count_dependabot_alerts("myorg", "repo1")
        assert result.count == 3
        assert result.accessible is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_inaccessible_on_404(self, client):
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await client.count_dependabot_alerts("myorg", "repo1")
        assert result.count is None
        assert result.accessible is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_sends_state_open_param(self, client):
        """Alert requests must include state=open query parameter."""
        route = respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        await client.count_dependabot_alerts("myorg", "repo1")
        assert route.called
        called_url = str(route.calls[0].request.url)
        assert "state=open" in called_url

    @respx.mock
    @pytest.mark.asyncio
    async def test_paginates_alert_counts(self, client):
        """Alert counting must paginate through all pages."""
        page2_url = f"{BASE}/repos/myorg/repo1/dependabot/alerts?page=2&per_page=100&state=open"
        call_count = {"n": 0}

        def side_effect(request):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return httpx.Response(
                    200,
                    json=[{"number": 1}, {"number": 2}],
                    headers={"Link": f'<{page2_url}>; rel="next"'},
                )
            return httpx.Response(200, json=[{"number": 3}])

        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            side_effect=side_effect
        )
        result = await client.count_dependabot_alerts("myorg", "repo1")
        assert result.count == 3
        assert result.accessible is True
        assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# count_code_scanning_alerts
# ---------------------------------------------------------------------------


class TestCountCodeScanningAlerts:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_inaccessible_on_403(self, client):
        respx.get(url__regex=r".*/repos/myorg/repo1/code-scanning/alerts.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await client.count_code_scanning_alerts("myorg", "repo1")
        assert result.count is None
        assert result.accessible is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_count_on_success(self, client):
        alerts = [{"number": 1}]
        respx.get(url__regex=r".*/repos/myorg/repo1/code-scanning/alerts.*").mock(
            return_value=httpx.Response(200, json=alerts)
        )
        result = await client.count_code_scanning_alerts("myorg", "repo1")
        assert result.count == 1
        assert result.accessible is True


# ---------------------------------------------------------------------------
# count_secret_scanning_alerts
# ---------------------------------------------------------------------------


class TestCountSecretScanningAlerts:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_inaccessible_on_403(self, client):
        respx.get(url__regex=r".*/repos/myorg/repo1/secret-scanning/alerts.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await client.count_secret_scanning_alerts("myorg", "repo1")
        assert result.count is None
        assert result.accessible is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_count_on_success(self, client):
        alerts = [{"number": 1}, {"number": 2}]
        respx.get(url__regex=r".*/repos/myorg/repo1/secret-scanning/alerts.*").mock(
            return_value=httpx.Response(200, json=alerts)
        )
        result = await client.count_secret_scanning_alerts("myorg", "repo1")
        assert result.count == 2
        assert result.accessible is True


# ---------------------------------------------------------------------------
# get_security_features
# ---------------------------------------------------------------------------


class TestGetSecurityFeatures:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_security_features(self, client):
        features = {
            "vulnerability_alerts_enabled": True,
            "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
        }
        respx.get(f"{BASE}/repos/myorg/repo1").mock(return_value=httpx.Response(200, json=features))
        result = await client.get_security_features("myorg", "repo1")
        assert result["vulnerability_alerts_enabled"] is True


# ---------------------------------------------------------------------------
# list_rulesets
# ---------------------------------------------------------------------------


class TestListRulesets:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_rulesets_on_success(self, client):
        rulesets = [{"id": 1, "name": "main-protection"}]
        respx.get(f"{BASE}/repos/myorg/repo1/rulesets").mock(
            return_value=httpx.Response(200, json=rulesets)
        )
        result = await client.list_rulesets("myorg", "repo1")
        assert result is not None
        assert len(result) == 1
        assert result[0]["name"] == "main-protection"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_403(self, client):
        respx.get(f"{BASE}/repos/myorg/repo1/rulesets").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await client.list_rulesets("myorg", "repo1")
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, client):
        respx.get(f"{BASE}/repos/myorg/repo1/rulesets").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await client.list_rulesets("myorg", "repo1")
        assert result is None


# ---------------------------------------------------------------------------
# AlertCountResult dataclass
# ---------------------------------------------------------------------------


class TestAlertCountResult:
    """AlertCountResult dataclass behaves correctly."""

    def test_accessible_result(self):
        result = AlertCountResult(count=5, accessible=True)
        assert result.count == 5
        assert result.accessible is True

    def test_inaccessible_result(self):
        result = AlertCountResult(count=None, accessible=False)
        assert result.count is None
        assert result.accessible is False


# ---------------------------------------------------------------------------
# Rate-limit tracking
# ---------------------------------------------------------------------------


class TestRateLimitTracking:
    @respx.mock
    @pytest.mark.asyncio
    async def test_rate_limit_remaining_updated_after_request(self, client):
        respx.get(f"{BASE}/orgs/myorg").mock(
            return_value=httpx.Response(
                200,
                json={"login": "myorg"},
                headers={
                    "x-ratelimit-remaining": "42",
                    "x-ratelimit-reset": "9999999999",
                },
            )
        )
        assert client.rate_limit_remaining is None
        await client.verify_credentials("myorg")
        assert client.rate_limit_remaining == 42

    @respx.mock
    @pytest.mark.asyncio
    async def test_rate_limit_reset_updated_after_request(self, client):
        respx.get(f"{BASE}/orgs/myorg").mock(
            return_value=httpx.Response(
                200,
                json={"login": "myorg"},
                headers={
                    "x-ratelimit-remaining": "100",
                    "x-ratelimit-reset": "1234567890",
                },
            )
        )
        await client.verify_credentials("myorg")
        assert client.rate_limit_reset == 1234567890


# ---------------------------------------------------------------------------
# Retry on transient errors
# ---------------------------------------------------------------------------


class TestRetryOnTransientErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_503_then_succeeds(self, client):
        """First call returns 503, second returns 200 — should succeed."""
        from unittest.mock import AsyncMock, patch

        route = respx.get(f"{BASE}/orgs/myorg/repos")
        route.side_effect = [
            httpx.Response(503, json={"message": "Service Unavailable"}),
            httpx.Response(200, json=[{"name": "repo1"}]),
        ]
        with patch("gh_audit.adapters.github_rest.asyncio.sleep", new_callable=AsyncMock):
            result = await client.list_repos("myorg")
        assert len(result) == 1
        assert result[0]["name"] == "repo1"
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_raises_after_max_retries_exceeded(self, client):
        """Persistent 503 should raise after 3 retries (4 total attempts)."""
        from unittest.mock import AsyncMock, patch

        respx.get(f"{BASE}/orgs/myorg/repos").mock(
            return_value=httpx.Response(503, json={"message": "Service Unavailable"})
        )
        from gh_audit.exceptions import APIError

        with patch("gh_audit.adapters.github_rest.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(APIError):
                await client.list_repos("myorg")


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    @pytest.mark.asyncio
    async def test_close_does_not_raise(self, client):
        """close() should complete without error."""
        await client.close()
