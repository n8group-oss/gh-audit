"""Tests for operations category integration in DiscoveryService.

Covers:
- Standard profile: operations is None
- Operations category: operations populated (runners, groups, apps, webhooks)
- Per-repo enrichment: environments, deploy keys, webhooks, secrets/variables counts
- Graceful degradation: each endpoint failure adds warning
- active_categories includes "operations"
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gh_audit.adapters.base import AlertCountResult
from gh_audit.models.config import ScannerConfig
from gh_audit.services.discovery import DiscoveryService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *,
    organization: str = "myorg",
    scan_profile: str = "standard",
    categories: list[str] | None = None,
    concurrency: int = 4,
    **kwargs,
) -> ScannerConfig:
    """Build a ScannerConfig with PAT auth for testing."""
    return ScannerConfig(
        organization=organization,
        token="ghp_fake_token",
        scan_profile=scan_profile,
        categories=categories or [],
        concurrency=concurrency,
        **kwargs,
    )


def _make_graphql_repo(
    name: str = "repo1",
    *,
    org: str = "myorg",
    visibility: str = "PRIVATE",
) -> dict:
    """Build a minimal GraphQL repo node."""
    return {
        "name": name,
        "nameWithOwner": f"{org}/{name}",
        "visibility": visibility,
        "isArchived": False,
        "isFork": False,
        "isTemplate": False,
        "primaryLanguage": {"name": "Python"},
        "repositoryTopics": {"nodes": []},
        "diskUsage": 1024,
        "defaultBranchRef": {"name": "main"},
        "description": "A test repo",
        "refs": {"totalCount": 3},
        "openPRs": {"totalCount": 1},
        "closedPRs": {"totalCount": 0},
        "mergedPRs": {"totalCount": 2},
        "openIssues": {"totalCount": 1},
        "closedIssues": {"totalCount": 3},
        "labels": {"nodes": [{"name": "bug", "issues": {"totalCount": 1}}]},
        "branchProtectionRules": {"totalCount": 1},
        "object": None,
    }


def _make_graphql_client(repos: list[dict] | None = None) -> AsyncMock:
    """Build a mock GraphQL client."""
    gql = AsyncMock()
    gql.fetch_all_repos.return_value = repos if repos is not None else [_make_graphql_repo()]
    gql.fetch_projects.return_value = []
    return gql


def _make_rest_client(*, with_operations: bool = False) -> AsyncMock:
    """Build a mock REST client with sensible defaults.

    When ``with_operations=True``, operations endpoints return sample data
    instead of empty defaults.
    """
    rest = AsyncMock()

    # Standard discovery defaults
    rest.list_workflows.return_value = []
    rest.get_workflow_file.return_value = None
    rest.get_tree.return_value = {"tree": [], "truncated": False}
    rest.count_dependabot_alerts.return_value = AlertCountResult.inaccessible()
    rest.count_code_scanning_alerts.return_value = AlertCountResult.inaccessible()
    rest.count_secret_scanning_alerts.return_value = AlertCountResult.inaccessible()
    rest.get_security_features.return_value = {
        "security_and_analysis": {
            "advanced_security": {"status": "enabled"},
            "dependabot_security_updates": {"status": "enabled"},
            "secret_scanning": {"status": "enabled"},
        }
    }
    rest.list_rulesets.return_value = []
    rest.list_org_members.return_value = []
    rest.list_outside_collaborators.return_value = []
    rest.list_packages.return_value = []

    # Operations endpoint defaults (empty)
    rest.list_org_runners.return_value = []
    rest.list_org_runner_groups.return_value = []
    rest.list_org_installations.return_value = []
    rest.list_org_webhooks.return_value = []
    rest.list_repo_environments.return_value = []
    rest.list_repo_deploy_keys.return_value = []
    rest.list_repo_webhooks.return_value = []
    rest.list_repo_action_secrets.return_value = []
    rest.list_repo_action_variables.return_value = []
    rest.get_repo_actions_permissions.return_value = None

    if with_operations:
        rest.list_org_runners.return_value = [
            {
                "name": "runner-1",
                "os": "Linux",
                "status": "online",
                "labels": [{"name": "self-hosted"}, {"name": "linux"}],
                "busy": False,
                "runner_group_name": "Default",
            },
            {
                "name": "runner-2",
                "os": "Windows",
                "status": "offline",
                "labels": [{"name": "self-hosted"}, {"name": "windows"}],
                "busy": True,
                "runner_group_name": "CI",
            },
        ]

        rest.list_org_runner_groups.return_value = [
            {
                "name": "Default",
                "visibility": "all",
                "allows_public_repositories": False,
                "runners_count": 1,
                "selected_repositories_count": None,
            },
            {
                "name": "CI",
                "visibility": "selected",
                "allows_public_repositories": True,
                "runners_count": 1,
                "selected_repositories_count": 5,
            },
        ]

        rest.list_org_installations.return_value = [
            {
                "app": {"name": "Renovate", "slug": "renovate"},
                "permissions": {"issues": "read", "pull_requests": "write"},
                "events": ["push", "pull_request"],
                "repository_selection": "selected",
            },
        ]

        rest.list_org_webhooks.return_value = [
            {
                "config": {
                    "url": "https://hooks.slack.com/services/abc",
                    "content_type": "json",
                    "insecure_ssl": "0",
                },
                "events": ["push", "pull_request"],
                "active": True,
            },
        ]

        # Repo-level operations data
        rest.list_repo_environments.return_value = [
            {
                "name": "production",
                "protection_rules": [
                    {"type": "wait_timer", "wait_timer": 30},
                    {
                        "type": "required_reviewers",
                        "reviewers": [{"login": "alice"}, {"login": "bob"}],
                    },
                ],
                "deployment_branch_policy": {
                    "protected_branches": True,
                    "custom_branch_policies": False,
                },
                "can_admins_bypass": False,
            },
            {
                "name": "staging",
                "protection_rules": [],
                "deployment_branch_policy": None,
                "can_admins_bypass": True,
            },
        ]

        rest.list_repo_deploy_keys.return_value = [
            {"title": "deploy-key-1", "read_only": True, "created_at": "2025-01-01T00:00:00Z"},
        ]

        rest.list_repo_webhooks.return_value = [
            {
                "config": {
                    "url": "https://ci.example.com/webhook",
                    "content_type": "form",
                    "insecure_ssl": "1",
                },
                "events": ["push"],
                "active": False,
            },
        ]

        rest.list_repo_action_secrets.return_value = [
            {"name": "SECRET_A"},
            {"name": "SECRET_B"},
        ]

        rest.list_repo_action_variables.return_value = [
            {"name": "VAR_A"},
        ]

        rest.get_repo_actions_permissions.return_value = {
            "enabled": True,
            "allowed_actions": "selected",
        }

    return rest


# ---------------------------------------------------------------------------
# Test: standard profile — operations is None
# ---------------------------------------------------------------------------


class TestStandardProfileNoOperations:
    """Standard profile without categories should not produce operations data."""

    @pytest.mark.asyncio
    async def test_operations_is_none(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations is None

    @pytest.mark.asyncio
    async def test_repo_operations_fields_are_none(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.environments is None
        assert repo.deploy_keys is None
        assert repo.repo_webhooks is None
        assert repo.repo_secrets_count is None
        assert repo.repo_variables_count is None
        assert repo.actions_permissions is None

    @pytest.mark.asyncio
    async def test_operations_rest_methods_not_called(self):
        rest = _make_rest_client()
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        await svc.discover()
        rest.list_org_runners.assert_not_called()
        rest.list_org_runner_groups.assert_not_called()
        rest.list_org_installations.assert_not_called()
        rest.list_org_webhooks.assert_not_called()
        rest.list_repo_environments.assert_not_called()
        rest.list_repo_deploy_keys.assert_not_called()
        rest.list_repo_webhooks.assert_not_called()
        rest.list_repo_action_secrets.assert_not_called()
        rest.list_repo_action_variables.assert_not_called()
        rest.get_repo_actions_permissions.assert_not_called()


# ---------------------------------------------------------------------------
# Test: operations category enabled — operations populated
# ---------------------------------------------------------------------------


class TestOperationsCategoryEnabled:
    """When operations category is active, operations data should be populated."""

    @pytest.mark.asyncio
    async def test_operations_inventory_populated(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations is not None

    @pytest.mark.asyncio
    async def test_runners_discovered(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.operations.runners) == 2
        assert inventory.operations.runners[0].name == "runner-1"
        assert inventory.operations.runners[0].os == "Linux"
        assert inventory.operations.runners[0].status == "online"
        assert "self-hosted" in inventory.operations.runners[0].labels
        assert inventory.operations.runners[1].busy is True

    @pytest.mark.asyncio
    async def test_runner_groups_discovered(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.operations.runner_groups) == 2
        assert inventory.operations.runner_groups[0].name == "Default"
        assert inventory.operations.runner_groups[0].visibility == "all"
        assert inventory.operations.runner_groups[1].name == "CI"
        assert inventory.operations.runner_groups[1].repo_count == 5

    @pytest.mark.asyncio
    async def test_installed_apps_discovered(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.operations.installed_apps) == 1
        app = inventory.operations.installed_apps[0]
        assert app.app_name == "Renovate"
        assert app.app_slug == "renovate"
        assert app.permissions == {"issues": "read", "pull_requests": "write"}
        assert app.events == ["push", "pull_request"]
        assert app.repository_selection == "selected"

    @pytest.mark.asyncio
    async def test_org_webhooks_discovered(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.operations.org_webhooks) == 1
        hook = inventory.operations.org_webhooks[0]
        assert hook.url_domain == "hooks.slack.com"
        assert hook.events == ["push", "pull_request"]
        assert hook.active is True
        assert hook.content_type == "json"
        assert hook.insecure_ssl is False


# ---------------------------------------------------------------------------
# Test: per-repo enrichment
# ---------------------------------------------------------------------------


class TestRepoOperationsEnrichment:
    """Per-repo operations enrichment should populate repo-level fields."""

    @pytest.mark.asyncio
    async def test_environments_populated(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.environments is not None
        assert len(repo.environments) == 2
        prod = repo.environments[0]
        assert prod.name == "production"
        assert prod.protection_rules is not None
        assert prod.protection_rules.wait_timer == 30
        assert prod.protection_rules.required_reviewers == 2
        assert prod.protection_rules.branch_policy == "protected"
        assert prod.can_admins_bypass is False

    @pytest.mark.asyncio
    async def test_staging_environment_no_protection(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        staging = repo.environments[1]
        assert staging.name == "staging"
        assert staging.protection_rules is None

    @pytest.mark.asyncio
    async def test_deploy_keys_populated(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.deploy_keys is not None
        assert len(repo.deploy_keys) == 1
        assert repo.deploy_keys[0].title == "deploy-key-1"
        assert repo.deploy_keys[0].read_only is True

    @pytest.mark.asyncio
    async def test_repo_webhooks_populated(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.repo_webhooks is not None
        assert len(repo.repo_webhooks) == 1
        hook = repo.repo_webhooks[0]
        assert hook.url_domain == "ci.example.com"
        assert hook.content_type == "form"
        assert hook.insecure_ssl is True
        assert hook.active is False

    @pytest.mark.asyncio
    async def test_repo_secrets_count(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.repo_secrets_count == 2

    @pytest.mark.asyncio
    async def test_repo_variables_count(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.repo_variables_count == 1

    @pytest.mark.asyncio
    async def test_actions_permissions_populated(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.actions_permissions is not None
        assert repo.actions_permissions.enabled is True
        assert repo.actions_permissions.allowed_actions == "selected"


# ---------------------------------------------------------------------------
# Test: active_categories in metadata
# ---------------------------------------------------------------------------


class TestOperationsMetadataCategories:
    """Metadata should reflect active operations category."""

    @pytest.mark.asyncio
    async def test_active_categories_includes_operations(self):
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "operations" in inventory.metadata.active_categories

    @pytest.mark.asyncio
    async def test_categories_in_scan_options(self):
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "operations" in inventory.metadata.scan_options["categories"]


# ---------------------------------------------------------------------------
# Test: graceful degradation
# ---------------------------------------------------------------------------


class TestOperationsGracefulDegradation:
    """Operations discovery should degrade gracefully on failures."""

    @pytest.mark.asyncio
    async def test_runners_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_org_runners.side_effect = Exception("403 Forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations is not None
        assert inventory.operations.runners == []
        assert any("Runners discovery failed" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_runner_groups_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_org_runner_groups.side_effect = Exception("403 Forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations.runner_groups == []
        assert any("Runner groups discovery failed" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_installed_apps_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_org_installations.side_effect = Exception("network error")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations.installed_apps == []
        assert any("Installed apps discovery failed" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_org_webhooks_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_org_webhooks.side_effect = Exception("timeout")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations.org_webhooks == []
        assert any("Org webhooks discovery failed" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_repo_environments_failure_sets_empty_list(self):
        rest = _make_rest_client()
        rest.list_repo_environments.side_effect = Exception("forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.environments == []
        assert any("Environments fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_repo_deploy_keys_failure_sets_empty_list(self):
        rest = _make_rest_client()
        rest.list_repo_deploy_keys.side_effect = Exception("forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.deploy_keys == []
        assert any("Deploy keys fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_repo_webhooks_failure_sets_empty_list(self):
        rest = _make_rest_client()
        rest.list_repo_webhooks.side_effect = Exception("forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.repo_webhooks == []
        assert any("Repo webhooks fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_repo_secrets_failure_sets_zero(self):
        rest = _make_rest_client()
        rest.list_repo_action_secrets.side_effect = Exception("forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.repo_secrets_count == 0
        assert any("Repo secrets count fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_repo_variables_failure_sets_zero(self):
        rest = _make_rest_client()
        rest.list_repo_action_variables.side_effect = Exception("forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.repo_variables_count == 0
        assert any("Repo variables count fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_actions_permissions_failure_sets_defaults(self):
        rest = _make_rest_client()
        rest.get_repo_actions_permissions.side_effect = Exception("forbidden")
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.actions_permissions is not None
        assert repo.actions_permissions.enabled is True
        assert any("Actions permissions fetch failed" in w for w in repo.warnings)


# ---------------------------------------------------------------------------
# Test: total profile enables operations
# ---------------------------------------------------------------------------


class TestTotalProfileEnablesOperations:
    """Total profile should automatically enable all categories including operations."""

    @pytest.mark.asyncio
    async def test_total_profile_operations_not_none(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.operations is not None

    @pytest.mark.asyncio
    async def test_total_profile_active_categories_include_operations(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "operations" in inventory.metadata.active_categories

    @pytest.mark.asyncio
    async def test_total_profile_runners_discovered(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.operations.runners) == 2

    @pytest.mark.asyncio
    async def test_total_profile_repo_enrichment(self):
        rest = _make_rest_client(with_operations=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.environments is not None
        assert repo.deploy_keys is not None
        assert repo.repo_webhooks is not None
        assert repo.repo_secrets_count is not None
        assert repo.repo_variables_count is not None
        assert repo.actions_permissions is not None


# ---------------------------------------------------------------------------
# Test: multiple repos operations enrichment
# ---------------------------------------------------------------------------


class TestMultipleReposOperationsEnrichment:
    """Operations enrichment should work across multiple repos."""

    @pytest.mark.asyncio
    async def test_all_repos_enriched(self):
        repos = [
            _make_graphql_repo(name="repo1"),
            _make_graphql_repo(name="repo2"),
            _make_graphql_repo(name="repo3"),
        ]
        rest = _make_rest_client(with_operations=True)
        config = _make_config(categories=["operations"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos=repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 3
        for repo in inventory.repositories:
            assert repo.environments is not None
            assert repo.deploy_keys is not None
            assert repo.repo_webhooks is not None
            assert repo.repo_secrets_count is not None
            assert repo.repo_variables_count is not None
            assert repo.actions_permissions is not None
