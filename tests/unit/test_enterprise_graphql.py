"""Tests for enterprise GraphQL queries: fetch_enterprise_info and fetch_enterprise_billing.

Tests verify:
    - fetch_enterprise_info returns normalised data on success
    - fetch_enterprise_info returns None when _post raises an exception
    - fetch_enterprise_info handles null samlIdentityProvider
    - fetch_enterprise_billing returns normalised billing data
    - fetch_enterprise_billing returns None on error
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from gh_audit.adapters.github_graphql import GitHubGraphQLClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Return a GitHubGraphQLClient with a fake PAT token."""
    return GitHubGraphQLClient(token="ghp_testtoken")


# ---------------------------------------------------------------------------
# Canned responses
# ---------------------------------------------------------------------------


def _enterprise_info_response(*, saml: dict | None = None) -> dict:
    """Build a mock GraphQL response for enterprise info."""
    if saml is None:
        saml = {"issuer": "https://idp.example.com", "ssoUrl": "https://sso.example.com"}
    return {
        "data": {
            "enterprise": {
                "name": "Acme Corp",
                "slug": "acme",
                "members": {"totalCount": 250},
                "admins": {"totalCount": 5},
                "outsideCollaborators": {"totalCount": 12},
                "ownerInfo": {
                    "samlIdentityProvider": saml,
                    "domains": {
                        "nodes": [
                            {"domain": "acme.com", "isVerified": True},
                            {"domain": "acme.io", "isVerified": False},
                            {"domain": "acme.dev", "isVerified": True},
                        ]
                    },
                    "ipAllowListEnabledSetting": "ENABLED",
                    "ipAllowListEntries": {"totalCount": 3},
                    "ipAllowListForInstalledAppsEnabledSetting": "ENABLED",
                },
            }
        }
    }


def _enterprise_info_no_saml_response() -> dict:
    """Build a mock GraphQL response with samlIdentityProvider = null."""
    resp = _enterprise_info_response()
    resp["data"]["enterprise"]["ownerInfo"]["samlIdentityProvider"] = None
    return resp


def _enterprise_billing_response() -> dict:
    """Build a mock GraphQL response for enterprise billing."""
    return {
        "data": {
            "enterprise": {
                "billingInfo": {
                    "totalLicenses": 500,
                    "allLicensableUsersCount": 250,
                    "bandwidthUsageInGb": 42.5,
                    "bandwidthQuotaInGb": 100.0,
                    "storageUsageInGb": 15.3,
                    "storageQuotaInGb": 50.0,
                }
            }
        }
    }


# ---------------------------------------------------------------------------
# fetch_enterprise_info
# ---------------------------------------------------------------------------


class TestFetchEnterpriseInfo:
    """fetch_enterprise_info returns normalised enterprise overview data."""

    @pytest.mark.asyncio
    async def test_returns_normalised_data_on_success(self, client):
        mock_response = _enterprise_info_response()
        with patch.object(client, "_post", new_callable=AsyncMock, return_value=mock_response):
            result = await client.fetch_enterprise_info("acme")

        assert result is not None
        assert result["name"] == "Acme Corp"
        assert result["slug"] == "acme"
        assert result["members_count"] == 250
        assert result["admins_count"] == 5
        assert result["outside_collaborators_count"] == 12

        # SAML
        assert result["saml"]["enabled"] is True
        assert result["saml"]["issuer"] == "https://idp.example.com"
        assert result["saml"]["sso_url"] == "https://sso.example.com"

        # Verified domains (only verified ones)
        assert result["verified_domains"] == ["acme.com", "acme.dev"]

        # IP allow list
        assert result["ip_allow_list"]["enabled"] is True
        assert result["ip_allow_list"]["entries_count"] == 3
        assert result["ip_allow_list"]["for_installed_apps"] is True

    @pytest.mark.asyncio
    async def test_returns_none_when_post_raises(self, client):
        with patch.object(
            client, "_post", new_callable=AsyncMock, side_effect=Exception("network")
        ):
            result = await client.fetch_enterprise_info("acme")

        assert result is None

    @pytest.mark.asyncio
    async def test_handles_null_saml_identity_provider(self, client):
        mock_response = _enterprise_info_no_saml_response()
        with patch.object(client, "_post", new_callable=AsyncMock, return_value=mock_response):
            result = await client.fetch_enterprise_info("acme")

        assert result is not None
        assert result["saml"]["enabled"] is False
        assert result["saml"]["issuer"] is None
        assert result["saml"]["sso_url"] is None


# ---------------------------------------------------------------------------
# fetch_enterprise_billing
# ---------------------------------------------------------------------------


class TestFetchEnterpriseBilling:
    """fetch_enterprise_billing returns normalised billing/license info."""

    @pytest.mark.asyncio
    async def test_returns_normalised_billing_data(self, client):
        mock_response = _enterprise_billing_response()
        with patch.object(client, "_post", new_callable=AsyncMock, return_value=mock_response):
            result = await client.fetch_enterprise_billing("acme")

        assert result is not None
        assert result["total_licenses"] == 500
        assert result["used_licenses"] == 250
        assert result["bandwidth_usage_gb"] == 42.5
        assert result["bandwidth_quota_gb"] == 100.0
        assert result["storage_usage_gb"] == 15.3
        assert result["storage_quota_gb"] == 50.0

    @pytest.mark.asyncio
    async def test_returns_none_on_error(self, client):
        with patch.object(
            client, "_post", new_callable=AsyncMock, side_effect=Exception("timeout")
        ):
            result = await client.fetch_enterprise_billing("acme")

        assert result is None


# ---------------------------------------------------------------------------
# fetch_enterprise_policies
# ---------------------------------------------------------------------------


def _enterprise_policies_response() -> dict:
    return {
        "data": {
            "enterprise": {
                "ownerInfo": {
                    "membersCanCreateRepositoriesSetting": "ALL",
                    "membersCanChangeRepositoryVisibilitySetting": "ENABLED",
                    "membersCanDeleteRepositoriesSetting": "DISABLED",
                    "membersCanForkPrivateRepositoriesSetting": "NO_POLICY",
                    "twoFactorRequiredSetting": "ENABLED",
                    "defaultRepositoryPermissionSetting": "READ",
                    "repositoryDeployKeySetting": "ENABLED",
                }
            }
        }
    }


class TestFetchEnterprisePolicies:
    @pytest.mark.asyncio
    async def test_returns_normalised_policies(self, client):
        with patch.object(
            client,
            "_post",
            new_callable=AsyncMock,
            return_value=_enterprise_policies_response(),
        ):
            result = await client.fetch_enterprise_policies("acme")

        assert result is not None
        assert result["default_repository_permission"] == "read"
        assert result["members_can_create_repositories"] == "all"
        assert result["members_can_change_repo_visibility"] == "enabled"
        assert result["members_can_delete_repositories"] == "disabled"
        assert result["members_can_fork_private_repos"] is None  # NO_POLICY -> None
        assert result["two_factor_required"] == "enabled"
        assert result["repository_deploy_key_setting"] == "enabled"

    @pytest.mark.asyncio
    async def test_returns_none_on_error(self, client):
        with patch.object(
            client, "_post", new_callable=AsyncMock, side_effect=Exception("forbidden")
        ):
            result = await client.fetch_enterprise_policies("acme")

        assert result is None
