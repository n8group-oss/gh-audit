"""Tests for security detail REST methods added to GitHubRestClient.

Covers:
    - list_dependabot_alerts_detail (200 paginated and 403)
    - list_code_scanning_alerts_detail (200 paginated and 403)
    - list_secret_scanning_alerts_detail (200 paginated and 403)
    - get_repo_sbom (200 and 403/404)
    - get_code_scanning_default_setup (200 and 403/404)
    - get_repo_security_configuration (200 and 403/404)
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
# list_dependabot_alerts_detail
# ---------------------------------------------------------------------------


class TestListDependabotAlertsDetail:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_alerts(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "number": 1,
                        "state": "open",
                        "security_vulnerability": {
                            "severity": "high",
                            "package": {"name": "lodash"},
                        },
                    },
                    {
                        "number": 2,
                        "state": "fixed",
                        "security_vulnerability": {
                            "severity": "low",
                            "package": {"name": "express"},
                        },
                    },
                ],
            )
        )
        result = await rest_client.list_dependabot_alerts_detail("myorg", "repo1")
        assert len(result) == 2
        assert result[0]["state"] == "open"
        assert result[1]["state"] == "fixed"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_dependabot_alerts_detail("myorg", "repo1")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_dependabot_alerts_detail("myorg", "repo1")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_alerts(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/dependabot/alerts.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_dependabot_alerts_detail("myorg", "repo1")
        assert result == []


# ---------------------------------------------------------------------------
# list_code_scanning_alerts_detail
# ---------------------------------------------------------------------------


class TestListCodeScanningAlertsDetail:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_alerts(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/code-scanning/alerts.*").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "number": 1,
                        "state": "open",
                        "rule": {"id": "js/xss", "severity": "error"},
                        "tool": {"name": "CodeQL"},
                    },
                ],
            )
        )
        result = await rest_client.list_code_scanning_alerts_detail("myorg", "repo1")
        assert len(result) == 1
        assert result[0]["rule"]["id"] == "js/xss"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/code-scanning/alerts.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_code_scanning_alerts_detail("myorg", "repo1")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/code-scanning/alerts.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_code_scanning_alerts_detail("myorg", "repo1")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_alerts(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/code-scanning/alerts.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_code_scanning_alerts_detail("myorg", "repo1")
        assert result == []


# ---------------------------------------------------------------------------
# list_secret_scanning_alerts_detail
# ---------------------------------------------------------------------------


class TestListSecretScanningAlertsDetail:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_alerts(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/secret-scanning/alerts.*").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "number": 1,
                        "state": "open",
                        "secret_type": "github_personal_access_token",
                        "secret_type_display_name": "GitHub Personal Access Token",
                    },
                ],
            )
        )
        result = await rest_client.list_secret_scanning_alerts_detail("myorg", "repo1")
        assert len(result) == 1
        assert result[0]["secret_type"] == "github_personal_access_token"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_403(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/secret-scanning/alerts.*").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.list_secret_scanning_alerts_detail("myorg", "repo1")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/secret-scanning/alerts.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.list_secret_scanning_alerts_detail("myorg", "repo1")
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_alerts(self, rest_client):
        respx.get(url__regex=r".*/repos/myorg/repo1/secret-scanning/alerts.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await rest_client.list_secret_scanning_alerts_detail("myorg", "repo1")
        assert result == []


# ---------------------------------------------------------------------------
# get_repo_sbom
# ---------------------------------------------------------------------------


class TestGetRepoSbom:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_sbom_on_success(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/dependency-graph/sbom").mock(
            return_value=httpx.Response(
                200,
                json={
                    "sbom": {
                        "spdxVersion": "SPDX-2.3",
                        "packages": [
                            {"name": "lodash", "externalRefs": []},
                            {"name": "express", "externalRefs": []},
                        ],
                    }
                },
            )
        )
        result = await rest_client.get_repo_sbom("myorg", "repo1")
        assert result is not None
        assert len(result["sbom"]["packages"]) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_403(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/dependency-graph/sbom").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.get_repo_sbom("myorg", "repo1")
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/dependency-graph/sbom").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.get_repo_sbom("myorg", "repo1")
        assert result is None


# ---------------------------------------------------------------------------
# get_code_scanning_default_setup
# ---------------------------------------------------------------------------


class TestGetCodeScanningDefaultSetup:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_setup_on_success(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/code-scanning/default-setup").mock(
            return_value=httpx.Response(
                200,
                json={
                    "state": "configured",
                    "languages": ["python", "javascript"],
                },
            )
        )
        result = await rest_client.get_code_scanning_default_setup("myorg", "repo1")
        assert result is not None
        assert result["state"] == "configured"
        assert result["languages"] == ["python", "javascript"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_403(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/code-scanning/default-setup").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.get_code_scanning_default_setup("myorg", "repo1")
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/code-scanning/default-setup").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.get_code_scanning_default_setup("myorg", "repo1")
        assert result is None


# ---------------------------------------------------------------------------
# get_repo_security_configuration
# ---------------------------------------------------------------------------


class TestGetRepoSecurityConfiguration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_config_on_success(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/code-security-configuration").mock(
            return_value=httpx.Response(
                200,
                json={
                    "configuration": {
                        "name": "org-default-security",
                        "description": "Default security config",
                    },
                },
            )
        )
        result = await rest_client.get_repo_security_configuration("myorg", "repo1")
        assert result is not None
        assert result["configuration"]["name"] == "org-default-security"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_403(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/code-security-configuration").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        result = await rest_client.get_repo_security_configuration("myorg", "repo1")
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, rest_client):
        respx.get(f"{BASE}/repos/myorg/repo1/code-security-configuration").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await rest_client.get_repo_security_configuration("myorg", "repo1")
        assert result is None
