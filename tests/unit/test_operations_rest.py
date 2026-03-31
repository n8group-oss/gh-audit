"""Tests for operations REST methods added to GitHubRestClient.

Covers:
    - list_org_runners (200 with nested key and 403)
    - list_org_runner_groups (200 with nested key and 403)
    - list_org_installations (200 paginated)
    - list_org_webhooks (200 and 403)
    - list_repo_webhooks (200 and 403)
    - list_repo_environments (200 with nested key and 403)
    - list_repo_deploy_keys (200 paginated)
    - list_repo_action_secrets (200 with nested key and 403)
    - list_repo_action_variables (200 with nested key and 403)
    - get_repo_actions_permissions (200 and 403)
"""

from __future__ import annotations

import httpx
import pytest
import respx

from gh_audit.adapters.github_rest import GitHubRestClient

BASE = "https://api.github.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rest_client():
    return GitHubRestClient(token="ghp_test", base_url="https://api.github.com")


# ---------------------------------------------------------------------------
# list_org_runners
# ---------------------------------------------------------------------------


class TestListOrgRunners:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_runners_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runners.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "runners": [
                        {"id": 1, "name": "runner-1", "os": "Linux", "status": "online"},
                        {"id": 2, "name": "runner-2", "os": "Windows", "status": "offline"},
                    ],
                },
            )
        )
        result = await rest_client.list_org_runners("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "runner-1"
        assert result[1]["name"] == "runner-2"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runners.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_runners("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runners.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_org_runners("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_runners(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runners.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "runners": []})
        )
        result = await rest_client.list_org_runners("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_runner_groups
# ---------------------------------------------------------------------------


class TestListOrgRunnerGroups:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_groups_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runner-groups.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "runner_groups": [
                        {"id": 1, "name": "default", "visibility": "all"},
                        {"id": 2, "name": "production", "visibility": "selected"},
                    ],
                },
            )
        )
        result = await rest_client.list_org_runner_groups("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "default"
        assert result[1]["name"] == "production"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runner-groups.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_runner_groups("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runner-groups.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_org_runner_groups("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_groups(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/runner-groups.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "runner_groups": []})
        )
        result = await rest_client.list_org_runner_groups("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_installations
# ---------------------------------------------------------------------------


class TestListOrgInstallations:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_installations(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/installations.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "installations": [
                        {"id": 1, "app_slug": "dependabot"},
                        {"id": 2, "app_slug": "ci-bot"},
                    ],
                },
            )
        )
        result = await rest_client.list_org_installations("myorg")
        assert len(result) == 2
        assert result[0]["app_slug"] == "dependabot"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_installations(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/installations.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "installations": []})
        )
        result = await rest_client.list_org_installations("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_org_installations_returns_empty_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/installations.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_installations("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_webhooks
# ---------------------------------------------------------------------------


class TestListOrgWebhooks:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_webhooks(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/hooks.*").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "config": {"url": "https://hooks.slack.com/services/xxx"},
                        "events": ["push"],
                        "active": True,
                    },
                ],
            )
        )
        result = await rest_client.list_org_webhooks("myorg")
        assert len(result) == 1
        assert result[0]["events"] == ["push"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/hooks.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_webhooks("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/hooks.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_org_webhooks("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_webhooks(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/hooks.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_org_webhooks("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_repo_webhooks
# ---------------------------------------------------------------------------


class TestListRepoWebhooks:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_webhooks(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/hooks.*").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "config": {"url": "https://ci.example.com/hook"},
                        "events": ["push", "pull_request"],
                        "active": True,
                    },
                ],
            )
        )
        result = await rest_client.list_repo_webhooks("myorg", "api-service")
        assert len(result) == 1
        assert result[0]["events"] == ["push", "pull_request"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/hooks.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_repo_webhooks("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/hooks.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_repo_webhooks("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_webhooks(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/hooks.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_repo_webhooks("myorg", "api-service")
        assert result == []


# ---------------------------------------------------------------------------
# list_repo_environments
# ---------------------------------------------------------------------------


class TestListRepoEnvironments:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_environments_from_nested_key(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/environments").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "environments": [
                        {"id": 1, "name": "production"},
                        {"id": 2, "name": "staging"},
                    ],
                },
            )
        )
        result = await rest_client.list_repo_environments("myorg", "api-service")
        assert len(result) == 2
        assert result[0]["name"] == "production"
        assert result[1]["name"] == "staging"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/environments").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_repo_environments("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/environments").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_repo_environments("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_environments(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/environments").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "environments": []})
        )
        result = await rest_client.list_repo_environments("myorg", "api-service")
        assert result == []


# ---------------------------------------------------------------------------
# list_repo_deploy_keys
# ---------------------------------------------------------------------------


class TestListRepoDeployKeys:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_deploy_keys(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/keys.*").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"id": 1, "title": "CI key", "read_only": True},
                    {"id": 2, "title": "Deploy key", "read_only": False},
                ],
            )
        )
        result = await rest_client.list_repo_deploy_keys("myorg", "api-service")
        assert len(result) == 2
        assert result[0]["title"] == "CI key"
        assert result[1]["title"] == "Deploy key"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_keys(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/keys.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_repo_deploy_keys("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_repo_deploy_keys_returns_empty_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/keys.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_repo_deploy_keys("myorg", "api-service")
        assert result == []


# ---------------------------------------------------------------------------
# list_repo_action_secrets
# ---------------------------------------------------------------------------


class TestListRepoActionSecrets:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_secrets_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/actions/secrets.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "secrets": [
                        {"name": "DOCKER_TOKEN"},
                        {"name": "NPM_TOKEN"},
                    ],
                },
            )
        )
        result = await rest_client.list_repo_action_secrets("myorg", "api-service")
        assert len(result) == 2
        assert result[0]["name"] == "DOCKER_TOKEN"
        assert result[1]["name"] == "NPM_TOKEN"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/actions/secrets.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_repo_action_secrets("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_secrets(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/actions/secrets.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "secrets": []})
        )
        result = await rest_client.list_repo_action_secrets("myorg", "api-service")
        assert result == []


# ---------------------------------------------------------------------------
# list_repo_action_variables
# ---------------------------------------------------------------------------


class TestListRepoActionVariables:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_variables_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/actions/variables.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "variables": [
                        {"name": "DEPLOY_ENV", "value": "prod"},
                        {"name": "LOG_LEVEL", "value": "info"},
                    ],
                },
            )
        )
        result = await rest_client.list_repo_action_variables("myorg", "api-service")
        assert len(result) == 2
        assert result[0]["name"] == "DEPLOY_ENV"
        assert result[1]["name"] == "LOG_LEVEL"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/actions/variables.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_repo_action_variables("myorg", "api-service")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_variables(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/api-service/actions/variables.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "variables": []})
        )
        result = await rest_client.list_repo_action_variables("myorg", "api-service")
        assert result == []


# ---------------------------------------------------------------------------
# get_repo_actions_permissions
# ---------------------------------------------------------------------------


class TestGetRepoActionsPermissions:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_permissions_on_success(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/actions/permissions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "enabled": True,
                    "allowed_actions": "all",
                    "selected_actions_url": "https://api.github.com/repos/myorg/api-service/actions/permissions/selected-actions",
                },
            )
        )
        result = await rest_client.get_repo_actions_permissions("myorg", "api-service")
        assert result is not None
        assert result["enabled"] is True
        assert result["allowed_actions"] == "all"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_403(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/actions/permissions").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.get_repo_actions_permissions("myorg", "api-service")
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/actions/permissions").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.get_repo_actions_permissions("myorg", "api-service")
        assert result is None
