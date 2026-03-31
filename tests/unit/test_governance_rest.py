"""Tests for governance REST methods added to GitHubRestClient.

Covers:
    - list_teams
    - list_team_members
    - list_team_repos
    - list_org_rulesets (200 and 403)
    - get_org_ruleset_detail (200 and 404)
    - list_custom_roles (200 with nested key and 403)
    - list_custom_properties_schema (200 and 403)
    - get_repo_custom_properties (200 dict mapping and 403)
    - list_repo_teams
    - list_org_action_secrets (nested key)
    - list_org_action_variables (nested key)
    - list_org_dependabot_secrets (nested key)
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
# list_teams
# ---------------------------------------------------------------------------


class TestListTeams:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_team_list(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/teams").mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 1, "slug": "backend", "name": "Backend"}],
            )
        )
        result = await rest_client.list_teams("myorg")
        assert len(result) == 1
        assert result[0]["slug"] == "backend"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_teams(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/teams").mock(return_value=httpx.Response(200, json=[]))
        result = await rest_client.list_teams("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_team_members
# ---------------------------------------------------------------------------


class TestListTeamMembers:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_member_list(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/teams/backend/members").mock(
            return_value=httpx.Response(
                200,
                json=[{"login": "alice"}, {"login": "bob"}],
            )
        )
        result = await rest_client.list_team_members("myorg", "backend")
        assert len(result) == 2
        assert result[0]["login"] == "alice"
        assert result[1]["login"] == "bob"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_members(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/teams/empty-team/members").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_team_members("myorg", "empty-team")
        assert result == []


# ---------------------------------------------------------------------------
# list_team_repos
# ---------------------------------------------------------------------------


class TestListTeamRepos:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_repo_list(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/teams/backend/repos").mock(
            return_value=httpx.Response(
                200,
                json=[{"name": "api-service"}, {"name": "shared-lib"}],
            )
        )
        result = await rest_client.list_team_repos("myorg", "backend")
        assert len(result) == 2
        assert result[0]["name"] == "api-service"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_repos(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/teams/backend/repos").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_team_repos("myorg", "backend")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_rulesets
# ---------------------------------------------------------------------------


class TestListOrgRulesets:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_rulesets_on_success(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/rulesets.*").mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 10, "name": "protect-main"}, {"id": 11, "name": "protect-dev"}],
            )
        )
        result = await rest_client.list_org_rulesets("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "protect-main"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/rulesets.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_rulesets("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/rulesets.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_org_rulesets("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# get_org_ruleset_detail
# ---------------------------------------------------------------------------


class TestGetOrgRulesetDetail:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_detail_on_success(self, rest_client):
        detail = {
            "id": 10,
            "name": "protect-main",
            "conditions": {"ref_name": {"include": ["refs/heads/main"]}},
            "rules": [{"type": "required_pull_request_reviews"}],
        }
        respx.get(f"{BASE}/orgs/myorg/rulesets/10").mock(
            return_value=httpx.Response(200, json=detail)
        )
        result = await rest_client.get_org_ruleset_detail("myorg", 10)
        assert result is not None
        assert result["id"] == 10
        assert result["name"] == "protect-main"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/rulesets/999").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.get_org_ruleset_detail("myorg", 999)
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_403(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/rulesets/10").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.get_org_ruleset_detail("myorg", 10)
        assert result is None


# ---------------------------------------------------------------------------
# list_custom_roles
# ---------------------------------------------------------------------------


class TestListCustomRoles:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_roles_from_nested_key(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/custom-repository-roles").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "custom_roles": [
                        {"id": 1, "name": "ci-runner"},
                        {"id": 2, "name": "security-reviewer"},
                    ],
                },
            )
        )
        result = await rest_client.list_custom_roles("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "ci-runner"
        assert result[1]["name"] == "security-reviewer"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/custom-repository-roles").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_custom_roles("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_roles(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/custom-repository-roles").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "custom_roles": []})
        )
        result = await rest_client.list_custom_roles("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_custom_properties_schema
# ---------------------------------------------------------------------------


class TestListCustomPropertiesSchema:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_properties_on_success(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/properties/schema").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"property_name": "environment", "value_type": "single_select"},
                    {"property_name": "team", "value_type": "string"},
                ],
            )
        )
        result = await rest_client.list_custom_properties_schema("myorg")
        assert len(result) == 2
        assert result[0]["property_name"] == "environment"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/properties/schema").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_custom_properties_schema("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(f"{BASE}/orgs/myorg/properties/schema").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_custom_properties_schema("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# get_repo_custom_properties
# ---------------------------------------------------------------------------


class TestGetRepoCustomProperties:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_dict_mapping(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/properties/values").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"property_name": "environment", "value": "production"},
                    {"property_name": "team", "value": "backend"},
                ],
            )
        )
        result = await rest_client.get_repo_custom_properties("myorg", "api-service")
        assert result == {"environment": "production", "team": "backend"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_403(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/properties/values").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.get_repo_custom_properties("myorg", "api-service")
        assert result == {}

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_404(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/properties/values").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.get_repo_custom_properties("myorg", "api-service")
        assert result == {}

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_dict_when_no_properties(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/properties/values").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.get_repo_custom_properties("myorg", "api-service")
        assert result == {}


# ---------------------------------------------------------------------------
# list_repo_teams
# ---------------------------------------------------------------------------


class TestListRepoTeams:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_teams(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/teams").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"slug": "backend", "permission": "push"},
                    {"slug": "devops", "permission": "admin"},
                ],
            )
        )
        result = await rest_client.list_repo_teams("myorg", "api-service")
        assert len(result) == 2
        assert result[0]["slug"] == "backend"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_teams(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/api-service/teams").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_repo_teams("myorg", "api-service")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_action_secrets
# ---------------------------------------------------------------------------


class TestListOrgActionSecrets:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_secrets_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/secrets.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "secrets": [
                        {"name": "DOCKER_TOKEN", "visibility": "all"},
                        {"name": "NPM_TOKEN", "visibility": "selected"},
                    ],
                },
            )
        )
        result = await rest_client.list_org_action_secrets("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "DOCKER_TOKEN"
        assert result[1]["name"] == "NPM_TOKEN"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/secrets.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_action_secrets("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_secrets(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/secrets.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "secrets": []})
        )
        result = await rest_client.list_org_action_secrets("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_action_variables
# ---------------------------------------------------------------------------


class TestListOrgActionVariables:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_variables_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/variables.*").mock(
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
        result = await rest_client.list_org_action_variables("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "DEPLOY_ENV"
        assert result[1]["name"] == "LOG_LEVEL"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/variables.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_action_variables("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_variables(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/actions/variables.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "variables": []})
        )
        result = await rest_client.list_org_action_variables("myorg")
        assert result == []


# ---------------------------------------------------------------------------
# list_org_dependabot_secrets
# ---------------------------------------------------------------------------


class TestListOrgDependabotSecrets:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_secrets_from_nested_key(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/dependabot/secrets.*").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "secrets": [
                        {"name": "NUGET_TOKEN", "visibility": "all"},
                        {"name": "MAVEN_PASSWORD", "visibility": "selected"},
                    ],
                },
            )
        )
        result = await rest_client.list_org_dependabot_secrets("myorg")
        assert len(result) == 2
        assert result[0]["name"] == "NUGET_TOKEN"
        assert result[1]["name"] == "MAVEN_PASSWORD"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/dependabot/secrets.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_org_dependabot_secrets("myorg")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_secrets(self, rest_client):
        respx.get(url__regex=r".*/orgs/myorg/dependabot/secrets.*").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "secrets": []})
        )
        result = await rest_client.list_org_dependabot_secrets("myorg")
        assert result == []
