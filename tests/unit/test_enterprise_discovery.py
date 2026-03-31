"""Unit tests for enterprise category discovery integration."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gh_audit.models.config import ScannerConfig
from gh_audit.services.discovery import DiscoveryService


def _make_config(
    *, categories: list[str] | None = None, enterprise_slug: str | None = None, **kwargs
) -> ScannerConfig:
    defaults = dict(
        organization="myorg",
        token="ghp_fake_token",
        scan_profile="standard",
        categories=categories or [],
        enterprise_slug=enterprise_slug,
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


def _make_rest_client() -> AsyncMock:
    rest = AsyncMock()
    rest.verify_credentials.return_value = {"login": "myorg", "type": "Organization"}
    rest.list_org_members.return_value = []
    rest.list_outside_collaborators.return_value = []
    rest.list_packages.return_value = []
    rest.list_rulesets.return_value = []
    rest.get_security_features.return_value = {}
    return rest


def _make_graphql_client(*, with_enterprise: bool = False) -> AsyncMock:
    gql = AsyncMock()
    gql.fetch_all_repos.return_value = [_make_graphql_repo()]
    gql.fetch_projects.return_value = []

    if with_enterprise:
        gql.fetch_enterprise_info.return_value = {
            "name": "Acme Corp",
            "slug": "acme",
            "members_count": 500,
            "admins_count": 10,
            "outside_collaborators_count": 20,
            "saml": {
                "enabled": True,
                "issuer": "https://idp.example.com",
                "sso_url": "https://sso.example.com",
            },
            "verified_domains": ["acme.com"],
            "ip_allow_list": {"enabled": True, "entries_count": 5, "for_installed_apps": False},
        }
        gql.fetch_enterprise_billing.return_value = {
            "total_licenses": 1000,
            "used_licenses": 800,
            "bandwidth_usage_gb": 5.5,
            "bandwidth_quota_gb": 50.0,
            "storage_usage_gb": 12.3,
            "storage_quota_gb": 100.0,
        }
        gql.fetch_enterprise_policies.return_value = {
            "default_repository_permission": "read",
            "members_can_create_repositories": "all",
            "members_can_change_repo_visibility": None,
            "members_can_delete_repositories": None,
            "members_can_fork_private_repos": None,
            "two_factor_required": "enabled",
            "repository_deploy_key_setting": None,
        }
    else:
        gql.fetch_enterprise_info.return_value = None
        gql.fetch_enterprise_billing.return_value = None
        gql.fetch_enterprise_policies.return_value = None

    return gql


@pytest.mark.asyncio
class TestNoEnterpriseCategory:
    async def test_enterprise_is_none_without_category(self) -> None:
        config = _make_config()
        svc = DiscoveryService(
            config=config,
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
        )
        inv = await svc.discover()
        assert inv.enterprise is None

    async def test_enterprise_category_without_slug_is_none(self) -> None:
        """Enterprise category requires enterprise_slug — resolve_active_categories removes it without slug."""
        config = _make_config(categories=["enterprise"])
        svc = DiscoveryService(
            config=config,
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(with_enterprise=True),
        )
        inv = await svc.discover()
        assert inv.enterprise is None
        assert "enterprise" not in inv.metadata.active_categories


@pytest.mark.asyncio
class TestEnterpriseCategoryEnabled:
    async def test_enterprise_populated(self) -> None:
        config = _make_config(categories=["enterprise"], enterprise_slug="acme")
        rest = _make_rest_client()
        gql = _make_graphql_client(with_enterprise=True)
        svc = DiscoveryService(config=config, rest_client=rest, graphql_client=gql)
        inv = await svc.discover()

        assert inv.enterprise is not None
        assert inv.enterprise.name == "Acme Corp"
        assert inv.enterprise.slug == "acme"
        assert inv.enterprise.members_count == 500
        assert inv.enterprise.admins_count == 10
        assert inv.enterprise.outside_collaborators_count == 20
        assert inv.enterprise.saml is not None
        assert inv.enterprise.saml.enabled is True
        assert inv.enterprise.saml.issuer == "https://idp.example.com"
        assert inv.enterprise.ip_allow_list is not None
        assert inv.enterprise.ip_allow_list.enabled is True
        assert inv.enterprise.ip_allow_list.entries_count == 5
        assert inv.enterprise.verified_domains == ["acme.com"]
        assert inv.enterprise.billing is not None
        assert inv.enterprise.billing.total_licenses == 1000
        assert inv.enterprise.billing.used_licenses == 800
        assert inv.enterprise.policies is not None
        assert inv.enterprise.policies.two_factor_required == "enabled"
        assert inv.enterprise.policies.default_repository_permission == "read"

        assert "enterprise" in inv.metadata.active_categories


@pytest.mark.asyncio
class TestEnterpriseGracefulDegradation:
    async def test_info_failure_records_warning(self) -> None:
        config = _make_config(categories=["enterprise"], enterprise_slug="acme")
        gql = _make_graphql_client(with_enterprise=True)
        gql.fetch_enterprise_info.side_effect = Exception("GraphQL error")
        svc = DiscoveryService(config=config, rest_client=_make_rest_client(), graphql_client=gql)
        inv = await svc.discover()
        assert inv.enterprise is None
        assert any("Enterprise" in w or "enterprise" in w for w in inv.metadata.scan_warnings)

    async def test_billing_failure_still_returns_enterprise(self) -> None:
        config = _make_config(categories=["enterprise"], enterprise_slug="acme")
        gql = _make_graphql_client(with_enterprise=True)
        gql.fetch_enterprise_billing.side_effect = Exception("billing error")
        svc = DiscoveryService(config=config, rest_client=_make_rest_client(), graphql_client=gql)
        inv = await svc.discover()
        assert inv.enterprise is not None
        assert inv.enterprise.billing is None
        assert any("billing" in w.lower() for w in inv.metadata.scan_warnings)

    async def test_policies_failure_still_returns_enterprise(self) -> None:
        config = _make_config(categories=["enterprise"], enterprise_slug="acme")
        gql = _make_graphql_client(with_enterprise=True)
        gql.fetch_enterprise_policies.side_effect = Exception("policies error")
        svc = DiscoveryService(config=config, rest_client=_make_rest_client(), graphql_client=gql)
        inv = await svc.discover()
        assert inv.enterprise is not None
        assert inv.enterprise.policies is None
        assert any("policies" in w.lower() for w in inv.metadata.scan_warnings)
