"""Tests for governance category integration in DiscoveryService."""

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


def _make_rest_client(*, with_governance: bool = False) -> AsyncMock:
    """Build a mock REST client with sensible defaults.

    When ``with_governance=True``, governance endpoints return sample data
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

    # Governance endpoint defaults
    rest.list_teams.return_value = []
    rest.list_org_rulesets.return_value = []
    rest.get_org_ruleset_detail.return_value = None
    rest.verify_credentials.return_value = {}
    rest.list_custom_roles.return_value = []
    rest.list_custom_properties_schema.return_value = []
    rest.list_org_action_secrets.return_value = []
    rest.list_org_action_variables.return_value = []
    rest.list_org_dependabot_secrets.return_value = []
    rest.get_repo_custom_properties.return_value = {}
    rest.list_repo_teams.return_value = []

    if with_governance:
        rest.list_teams.return_value = [
            {
                "name": "Platform",
                "slug": "platform",
                "description": "Platform team",
                "privacy": "closed",
                "permission": "push",
                "members_count": 5,
                "repos_count": 10,
                "parent": None,
            },
            {
                "name": "Security",
                "slug": "security",
                "description": "Security team",
                "privacy": "secret",
                "permission": "admin",
                "members_count": 3,
                "repos_count": 20,
                "parent": {"slug": "platform"},
            },
        ]

        rest.list_org_rulesets.return_value = [{"id": 1, "name": "branch-protect"}]
        rest.get_org_ruleset_detail.return_value = {
            "name": "branch-protect",
            "enforcement": "active",
            "target": "branch",
            "source_type": "Organization",
            "rules": [{"type": "required_status_checks"}],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
            "bypass_actors": [{"actor_id": 1, "actor_type": "Team"}],
        }

        rest.verify_credentials.return_value = {
            "default_repository_permission": "read",
            "members_can_create_repositories": True,
            "members_can_create_public_repositories": False,
            "members_can_create_private_repositories": True,
            "members_can_create_internal_repositories": True,
            "members_can_fork_private_repositories": False,
            "members_can_delete_repositories": False,
            "members_can_change_repo_visibility": False,
            "two_factor_requirement_enabled": True,
            "web_commit_signoff_required": False,
        }

        rest.list_custom_roles.return_value = [
            {
                "name": "security-reviewer",
                "description": "Can review security alerts",
                "permissions": ["read", "security_events"],
            }
        ]

        rest.list_custom_properties_schema.return_value = [
            {
                "property_name": "team-owner",
                "value_type": "string",
                "required": True,
                "description": "Owning team",
                "allowed_values": [],
            }
        ]

        rest.list_org_action_secrets.return_value = [
            {"name": "DEPLOY_KEY"},
            {"name": "NPM_TOKEN"},
        ]
        rest.list_org_action_variables.return_value = [
            {"name": "ENVIRONMENT"},
        ]
        rest.list_org_dependabot_secrets.return_value = [
            {"name": "PRIVATE_REGISTRY_TOKEN"},
        ]

        # Repo-level governance
        rest.list_rulesets.return_value = [
            {
                "name": "repo-branch-rule",
                "enforcement": "active",
                "target": "branch",
                "source_type": "Repository",
                "rules": [{"type": "pull_request"}],
                "conditions": None,
                "bypass_actors": [],
            }
        ]
        rest.get_repo_custom_properties.return_value = {"team-owner": "platform"}
        rest.list_repo_teams.return_value = [
            {"slug": "platform", "permission": "push"},
            {"slug": "security", "permission": "admin"},
        ]

    return rest


# ---------------------------------------------------------------------------
# Test: standard profile — governance is None
# ---------------------------------------------------------------------------


class TestStandardProfileNoGovernance:
    """Standard profile without categories should not produce governance data."""

    @pytest.mark.asyncio
    async def test_governance_is_none(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is None

    @pytest.mark.asyncio
    async def test_repo_governance_fields_are_none(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.rulesets_detail is None
        assert repo.custom_properties is None
        assert repo.teams_with_access is None

    @pytest.mark.asyncio
    async def test_governance_rest_methods_not_called(self):
        rest = _make_rest_client()
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        await svc.discover()
        rest.list_teams.assert_not_called()
        rest.list_org_rulesets.assert_not_called()
        rest.list_custom_roles.assert_not_called()
        rest.list_custom_properties_schema.assert_not_called()
        rest.list_repo_teams.assert_not_called()
        rest.get_repo_custom_properties.assert_not_called()


# ---------------------------------------------------------------------------
# Test: governance category enabled — governance populated
# ---------------------------------------------------------------------------


class TestGovernanceCategoryEnabled:
    """When governance category is active, governance data should be populated."""

    @pytest.mark.asyncio
    async def test_governance_inventory_populated(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is not None

    @pytest.mark.asyncio
    async def test_teams_discovered(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.governance.teams) == 2
        assert inventory.governance.teams[0].name == "Platform"
        assert inventory.governance.teams[0].slug == "platform"
        assert inventory.governance.teams[0].member_count == 5
        assert inventory.governance.teams[1].parent_team == "platform"

    @pytest.mark.asyncio
    async def test_org_rulesets_discovered(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.governance.org_rulesets) == 1
        rs = inventory.governance.org_rulesets[0]
        assert rs.name == "branch-protect"
        assert rs.enforcement == "active"
        assert rs.source_type == "Organization"
        assert len(rs.rules) == 1

    @pytest.mark.asyncio
    async def test_org_policies_discovered(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        policies = inventory.governance.org_policies
        assert policies.two_factor_requirement_enabled is True
        assert policies.default_repository_permission == "read"
        assert policies.members_can_create_public_repositories is False
        assert policies.members_can_fork_private_repositories is False

    @pytest.mark.asyncio
    async def test_custom_roles_discovered(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.governance.custom_roles) == 1
        assert inventory.governance.custom_roles[0].name == "security-reviewer"

    @pytest.mark.asyncio
    async def test_custom_properties_schema_discovered(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.governance.custom_properties_schema) == 1
        prop = inventory.governance.custom_properties_schema[0]
        assert prop.property_name == "team-owner"
        assert prop.required is True

    @pytest.mark.asyncio
    async def test_org_secrets_variables_counts(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance.org_secrets_count == 2
        assert inventory.governance.org_variables_count == 1
        assert inventory.governance.org_dependabot_secrets_count == 1

    @pytest.mark.asyncio
    async def test_repo_rulesets_detail_populated(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.rulesets_detail is not None
        assert len(repo.rulesets_detail) == 1
        assert repo.rulesets_detail[0].name == "repo-branch-rule"
        assert repo.branch_protection.ruleset_count == 1

    @pytest.mark.asyncio
    async def test_repo_custom_properties_populated(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.custom_properties is not None
        assert repo.custom_properties["team-owner"] == "platform"

    @pytest.mark.asyncio
    async def test_repo_teams_with_access_populated(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.teams_with_access is not None
        assert len(repo.teams_with_access) == 2
        slugs = {t.team_slug for t in repo.teams_with_access}
        assert slugs == {"platform", "security"}


# ---------------------------------------------------------------------------
# Test: active_categories in metadata
# ---------------------------------------------------------------------------


class TestMetadataCategories:
    """Metadata should reflect active categories."""

    @pytest.mark.asyncio
    async def test_active_categories_in_metadata(self):
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "governance" in inventory.metadata.active_categories

    @pytest.mark.asyncio
    async def test_categories_in_scan_options(self):
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "categories" in inventory.metadata.scan_options
        assert "governance" in inventory.metadata.scan_options["categories"]

    @pytest.mark.asyncio
    async def test_empty_categories_when_standard(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.active_categories == []

    @pytest.mark.asyncio
    async def test_enterprise_slug_in_metadata(self):
        config = _make_config(
            categories=["governance"],
            enterprise_slug="my-enterprise",
        )
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.enterprise_slug == "my-enterprise"

    @pytest.mark.asyncio
    async def test_enterprise_slug_none_by_default(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.enterprise_slug is None


# ---------------------------------------------------------------------------
# Test: graceful degradation
# ---------------------------------------------------------------------------


class TestGovernanceGracefulDegradation:
    """Governance discovery should degrade gracefully on failures."""

    @pytest.mark.asyncio
    async def test_custom_roles_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_custom_roles.side_effect = Exception("403 Forbidden")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is not None
        assert inventory.governance.custom_roles == []
        assert any("Custom roles" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_teams_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_teams.side_effect = Exception("network error")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is not None
        assert inventory.governance.teams == []
        assert any("Teams discovery failed" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_org_rulesets_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_org_rulesets.side_effect = Exception("timeout")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is not None
        assert inventory.governance.org_rulesets == []
        assert any("Org rulesets" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_org_policies_failure_records_warning(self):
        rest = _make_rest_client()
        rest.verify_credentials.side_effect = Exception("auth error")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is not None
        # Should fall back to default empty OrgPolicies
        assert inventory.governance.org_policies.default_repository_permission is None
        assert any("Org policies" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_custom_properties_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_custom_properties_schema.side_effect = Exception("forbidden")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance.custom_properties_schema == []
        assert any("Custom properties" in w for w in inventory.metadata.scan_warnings)

    @pytest.mark.asyncio
    async def test_repo_rulesets_detail_failure_sets_empty_list(self):
        rest = _make_rest_client()
        rest.list_rulesets.side_effect = Exception("forbidden")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.rulesets_detail == []
        assert any("Rulesets detail" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_repo_teams_failure_sets_empty_list(self):
        rest = _make_rest_client()
        rest.list_repo_teams.side_effect = Exception("forbidden")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.teams_with_access == []

    @pytest.mark.asyncio
    async def test_repo_custom_properties_failure_sets_empty_dict(self):
        rest = _make_rest_client()
        rest.get_repo_custom_properties.side_effect = Exception("forbidden")
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.custom_properties == {}


# ---------------------------------------------------------------------------
# Test: total profile enables governance
# ---------------------------------------------------------------------------


class TestTotalProfileEnablesGovernance:
    """Total profile should automatically enable all categories including governance."""

    @pytest.mark.asyncio
    async def test_total_profile_governance_not_none(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.governance is not None

    @pytest.mark.asyncio
    async def test_total_profile_active_categories_include_governance(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "governance" in inventory.metadata.active_categories

    @pytest.mark.asyncio
    async def test_total_profile_teams_discovered(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.governance.teams) == 2

    @pytest.mark.asyncio
    async def test_total_profile_repo_enrichment(self):
        rest = _make_rest_client(with_governance=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.rulesets_detail is not None
        assert repo.custom_properties is not None
        assert repo.teams_with_access is not None


# ---------------------------------------------------------------------------
# Test: multiple repos governance enrichment
# ---------------------------------------------------------------------------


class TestMultipleReposGovernanceEnrichment:
    """Governance enrichment should work across multiple repos."""

    @pytest.mark.asyncio
    async def test_all_repos_enriched(self):
        repos = [
            _make_graphql_repo(name="repo1"),
            _make_graphql_repo(name="repo2"),
            _make_graphql_repo(name="repo3"),
        ]
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos=repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 3
        for repo in inventory.repositories:
            assert repo.rulesets_detail is not None
            assert repo.custom_properties is not None
            assert repo.teams_with_access is not None


# ---------------------------------------------------------------------------
# Test: I-1 — no duplicate list_rulesets calls when governance active
# ---------------------------------------------------------------------------


class TestNoduplicateRulesetsCallsWhenGovernanceActive:
    """When governance is active, list_rulesets must be called only once per repo
    (in _enrich_repos_governance), not again in _build_repo_item."""

    @pytest.mark.asyncio
    async def test_list_rulesets_called_once_per_repo_when_governance_active(self):
        """list_rulesets must be called exactly once per repo (by governance enrichment),
        not twice (once in _build_repo_item and once in _enrich_repos_governance)."""
        repos = [
            _make_graphql_repo(name="repo1"),
            _make_graphql_repo(name="repo2"),
        ]
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos=repos),
            config=config,
        )
        await svc.discover()

        # With 2 repos and governance active, list_rulesets should be called
        # exactly once per repo (only by governance enrichment).
        assert rest.list_rulesets.call_count == 2

    @pytest.mark.asyncio
    async def test_list_rulesets_called_once_per_repo_when_governance_inactive(self):
        """Without governance, list_rulesets is called once per repo in _build_repo_item."""
        repos = [
            _make_graphql_repo(name="repo1"),
            _make_graphql_repo(name="repo2"),
        ]
        rest = _make_rest_client()
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos=repos),
            config=config,
        )
        await svc.discover()

        # Without governance, list_rulesets called once per repo in _build_repo_item.
        assert rest.list_rulesets.call_count == 2

    @pytest.mark.asyncio
    async def test_ruleset_count_set_from_governance_enrichment(self):
        """When governance is active and rulesets are skipped in _build_repo_item,
        branch_protection.ruleset_count must still be populated from governance enrichment."""
        rest = _make_rest_client(with_governance=True)
        config = _make_config(categories=["governance"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        # governance enrichment sets ruleset_count from list_rulesets detail
        assert repo.branch_protection.ruleset_count == 1
