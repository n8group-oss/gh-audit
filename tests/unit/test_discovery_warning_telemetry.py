"""Warning telemetry coverage for DiscoveryService partial failures."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from gh_audit.models.config import ScannerConfig
from gh_audit.services.discovery import DiscoveryService


def _make_config(
    *,
    organization: str = "myorg",
    categories: list[str] | None = None,
    enterprise_slug: str | None = None,
) -> ScannerConfig:
    return ScannerConfig(
        organization=organization,
        token="ghp_fake_token",
        categories=categories or [],
        enterprise_slug=enterprise_slug,
    )


def _make_graphql_repo(name: str = "repo1", org: str = "myorg") -> dict:
    return {
        "name": name,
        "nameWithOwner": f"{org}/{name}",
        "visibility": "PRIVATE",
        "isArchived": False,
        "isFork": False,
        "isTemplate": False,
        "primaryLanguage": {"name": "Python"},
        "repositoryTopics": {"nodes": []},
        "diskUsage": 1024,
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


@pytest.mark.asyncio
async def test_enrich_workflows_emits_repo_warning_and_preserves_warning_text() -> None:
    rest = AsyncMock()
    rest.list_workflows.side_effect = RuntimeError("workflow api down")
    gql = AsyncMock()
    telemetry = MagicMock()
    service = DiscoveryService(
        rest_client=rest,
        graphql_client=gql,
        config=_make_config(),
    )
    service._telemetry = telemetry

    item = service._map_graphql_base(_make_graphql_repo())
    warnings: list[str] = []

    await service._enrich_workflows("myorg", "repo1", item, warnings)

    assert warnings == ["Failed to list workflows: workflow api down"]
    telemetry.track_warning.assert_called_once_with(
        "repo_enrichment_warning",
        error=rest.list_workflows.side_effect,
        command="discover",
        operation="list_workflows",
        category="actions",
        organization="myorg",
        repo="repo1",
        warning_scope="repo_enrichment",
    )


@pytest.mark.asyncio
async def test_discover_packages_emits_org_warning_and_preserves_warning_text() -> None:
    rest = AsyncMock()
    rest.list_packages.side_effect = RuntimeError("package api down")
    gql = AsyncMock()
    telemetry = MagicMock()
    service = DiscoveryService(
        rest_client=rest,
        graphql_client=gql,
        config=_make_config(),
    )
    service._telemetry = telemetry

    scan_warnings: list[str] = []
    packages = await service._discover_packages("myorg", scan_warnings)

    assert packages == []
    assert "Failed to list npm packages: package api down" in scan_warnings
    telemetry.track_warning.assert_any_call(
        "org_discovery_warning",
        error=rest.list_packages.side_effect,
        command="discover",
        operation="list_packages",
        category="packages",
        organization="myorg",
        repo=None,
        warning_scope="org_discovery",
        package_type="npm",
    )


@pytest.mark.asyncio
async def test_discover_enterprise_billing_emits_enterprise_warning_and_preserves_warning_text() -> (
    None
):
    rest = AsyncMock()
    gql = AsyncMock()
    gql.fetch_enterprise_info.return_value = {
        "name": "Example Enterprise",
        "slug": "ent-1",
        "saml": {},
        "ip_allow_list": {},
    }
    gql.fetch_enterprise_billing.side_effect = RuntimeError("billing api down")
    gql.fetch_enterprise_policies.return_value = None
    telemetry = MagicMock()
    service = DiscoveryService(
        rest_client=rest,
        graphql_client=gql,
        config=_make_config(categories=["enterprise"], enterprise_slug="ent-1"),
    )
    service._telemetry = telemetry

    scan_warnings: list[str] = []
    enterprise = await service._discover_enterprise(scan_warnings)

    assert enterprise is not None
    assert scan_warnings == ["Enterprise billing discovery failed: billing api down"]
    telemetry.track_warning.assert_called_once_with(
        "enterprise_discovery_warning",
        error=gql.fetch_enterprise_billing.side_effect,
        command="discover",
        operation="fetch_enterprise_billing",
        category="enterprise",
        organization="myorg",
        repo=None,
        warning_scope="enterprise_discovery",
        enterprise_slug="ent-1",
    )


@pytest.mark.asyncio
async def test_discover_governance_org_policies_emits_org_warning() -> None:
    rest = AsyncMock()
    rest.list_teams.return_value = []
    rest.list_org_rulesets.return_value = []
    rest.verify_credentials.side_effect = RuntimeError("org settings down")
    rest.list_custom_roles.return_value = []
    rest.list_custom_properties_schema.return_value = []
    rest.list_org_action_secrets.return_value = []
    rest.list_org_action_variables.return_value = []
    rest.list_org_dependabot_secrets.return_value = []
    gql = AsyncMock()
    telemetry = MagicMock()
    service = DiscoveryService(
        rest_client=rest,
        graphql_client=gql,
        config=_make_config(categories=["governance"]),
    )
    service._telemetry = telemetry

    scan_warnings: list[str] = []
    governance = await service._discover_governance("myorg", scan_warnings)

    assert governance is not None
    assert scan_warnings == ["Org policies discovery failed: org settings down"]
    telemetry.track_warning.assert_called_once_with(
        "org_discovery_warning",
        error=rest.verify_credentials.side_effect,
        command="discover",
        operation="verify_credentials",
        category="governance",
        organization="myorg",
        repo=None,
        warning_scope="org_discovery",
    )


@pytest.mark.asyncio
async def test_enrich_repo_actions_permissions_emits_repo_warning() -> None:
    rest = AsyncMock()
    rest.list_repo_environments.return_value = []
    rest.list_repo_deploy_keys.return_value = []
    rest.list_repo_webhooks.return_value = []
    rest.list_repo_action_secrets.return_value = []
    rest.list_repo_action_variables.return_value = []
    rest.get_repo_actions_permissions.side_effect = RuntimeError("permissions down")
    gql = AsyncMock()
    telemetry = MagicMock()
    service = DiscoveryService(
        rest_client=rest,
        graphql_client=gql,
        config=_make_config(categories=["operations"]),
    )
    service._telemetry = telemetry

    repo = service._map_graphql_base(_make_graphql_repo())
    await service._enrich_repos_operations("myorg", [repo], [])

    assert "Actions permissions fetch failed" in repo.warnings
    telemetry.track_warning.assert_called_once_with(
        "repo_enrichment_warning",
        error=rest.get_repo_actions_permissions.side_effect,
        command="discover",
        operation="get_repo_actions_permissions",
        category="operations",
        organization="myorg",
        repo="repo1",
        warning_scope="repo_enrichment",
    )


@pytest.mark.asyncio
async def test_enrich_repo_code_scanning_setup_emits_repo_warning() -> None:
    rest = AsyncMock()
    rest.list_dependabot_alerts_detail.return_value = []
    rest.list_code_scanning_alerts_detail.return_value = []
    rest.list_secret_scanning_alerts_detail.return_value = []
    rest.get_repo_sbom.return_value = None
    rest.get_code_scanning_default_setup.side_effect = RuntimeError("setup down")
    rest.get_repo_security_configuration.return_value = None
    gql = AsyncMock()
    telemetry = MagicMock()
    service = DiscoveryService(
        rest_client=rest,
        graphql_client=gql,
        config=_make_config(categories=["security"]),
    )
    service._telemetry = telemetry

    repo = service._map_graphql_base(_make_graphql_repo())
    await service._enrich_repos_security_detail("myorg", [repo], [])

    assert "Code scanning setup fetch failed" in repo.warnings
    telemetry.track_warning.assert_called_once_with(
        "repo_enrichment_warning",
        error=rest.get_code_scanning_default_setup.side_effect,
        command="discover",
        operation="get_code_scanning_default_setup",
        category="security",
        organization="myorg",
        repo="repo1",
        warning_scope="repo_enrichment",
    )
