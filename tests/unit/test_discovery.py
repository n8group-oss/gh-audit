"""Tests for gh_audit.services.discovery — DiscoveryService orchestration."""

from __future__ import annotations

import asyncio
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
    scan_large_files: bool = False,
    scan_workflow_contents: bool = False,
    security_alert_counts: bool = False,
    repo_limit: int | None = None,
    concurrency: int = 4,
    include_archived: bool = True,
) -> ScannerConfig:
    """Build a ScannerConfig with PAT auth for testing."""
    return ScannerConfig(
        organization=organization,
        token="ghp_fake_token",
        scan_profile=scan_profile,
        scan_large_files=scan_large_files,
        scan_workflow_contents=scan_workflow_contents,
        security_alert_counts=security_alert_counts,
        repo_limit=repo_limit,
        concurrency=concurrency,
        include_archived=include_archived,
    )


def _make_graphql_repo(
    name: str = "repo1",
    *,
    org: str = "myorg",
    visibility: str = "PRIVATE",
    is_archived: bool = False,
    is_fork: bool = False,
    is_template: bool = False,
    language: str | None = "Python",
    topics: list[str] | None = None,
    disk_usage: int = 1024,
    default_branch: str | None = "main",
    description: str | None = "A test repo",
    branch_count: int = 5,
    open_prs: int = 3,
    closed_prs: int = 1,
    merged_prs: int = 10,
    open_issues: int = 7,
    closed_issues: int = 20,
    labels: list[dict] | None = None,
    branch_protection_count: int = 1,
    gitattributes_text: str | None = None,
) -> dict:
    """Build a GraphQL repo node dict matching what fetch_all_repos returns."""
    topic_nodes = [{"topic": {"name": t}} for t in (topics or [])]
    label_nodes = labels or [{"name": "bug", "issues": {"totalCount": 5}}]
    return {
        "name": name,
        "nameWithOwner": f"{org}/{name}",
        "visibility": visibility,
        "isArchived": is_archived,
        "isFork": is_fork,
        "isTemplate": is_template,
        "primaryLanguage": {"name": language} if language else None,
        "repositoryTopics": {"nodes": topic_nodes},
        "diskUsage": disk_usage,
        "defaultBranchRef": {"name": default_branch} if default_branch else None,
        "description": description,
        "refs": {"totalCount": branch_count},
        "openPRs": {"totalCount": open_prs},
        "closedPRs": {"totalCount": closed_prs},
        "mergedPRs": {"totalCount": merged_prs},
        "openIssues": {"totalCount": open_issues},
        "closedIssues": {"totalCount": closed_issues},
        "labels": {"nodes": label_nodes},
        "branchProtectionRules": {"totalCount": branch_protection_count},
        "object": {"text": gitattributes_text} if gitattributes_text else None,
    }


def _make_rest_client() -> AsyncMock:
    """Build a mock REST client with sensible defaults."""
    rest = AsyncMock()
    rest.list_workflows.return_value = []
    rest.get_workflow_file.return_value = None
    rest.get_tree.return_value = {"tree": [], "truncated": False}
    rest.get_file_content.return_value = None
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
    return rest


def _make_graphql_client(repos: list[dict] | None = None) -> AsyncMock:
    """Build a mock GraphQL client."""
    gql = AsyncMock()
    gql.fetch_all_repos.return_value = repos if repos is not None else [_make_graphql_repo()]
    gql.fetch_projects.return_value = []
    return gql


# ---------------------------------------------------------------------------
# Standard profile tests
# ---------------------------------------------------------------------------


class TestStandardProfile:
    """Standard profile should skip expensive operations."""

    @pytest.mark.asyncio
    async def test_scan_profile_recorded_in_metadata(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.scan_profile == "standard"

    @pytest.mark.asyncio
    async def test_large_file_scan_not_completed(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].large_file_scan.completed is False

    @pytest.mark.asyncio
    async def test_security_counts_not_exact(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].security.counts_exact is False

    @pytest.mark.asyncio
    async def test_actions_analysis_level_listing(self):
        rest = _make_rest_client()
        rest.list_workflows.return_value = [
            {"name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}
        ]
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].actions.analysis_level == "listing"

    @pytest.mark.asyncio
    async def test_get_tree_not_called_when_large_files_disabled(self):
        rest = _make_rest_client()
        config = _make_config(scan_profile="standard", scan_large_files=False)
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        await svc.discover()
        rest.get_tree.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_workflow_file_not_called_when_contents_disabled(self):
        rest = _make_rest_client()
        rest.list_workflows.return_value = [
            {"name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}
        ]
        config = _make_config(scan_profile="standard", scan_workflow_contents=False)
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        await svc.discover()
        rest.get_workflow_file.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_count_not_called_when_security_alerts_disabled(self):
        rest = _make_rest_client()
        config = _make_config(scan_profile="standard", security_alert_counts=False)
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        await svc.discover()
        rest.count_dependabot_alerts.assert_not_called()
        rest.count_code_scanning_alerts.assert_not_called()
        rest.count_secret_scanning_alerts.assert_not_called()


# ---------------------------------------------------------------------------
# Deep profile tests
# ---------------------------------------------------------------------------


class TestDeepProfile:
    """Deep profile should perform all expensive operations."""

    @pytest.mark.asyncio
    async def test_scan_profile_deep_recorded(self):
        config = _make_config(
            scan_profile="deep",
            scan_large_files=True,
            scan_workflow_contents=True,
            security_alert_counts=True,
        )
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.scan_profile == "deep"

    @pytest.mark.asyncio
    async def test_large_file_scan_completed_when_tree_returned(self):
        rest = _make_rest_client()
        rest.get_tree.return_value = {
            "tree": [{"path": "bigfile.bin", "size": 200_000_000, "type": "blob"}],
            "truncated": False,
        }
        config = _make_config(
            scan_profile="deep",
            scan_large_files=True,
            scan_workflow_contents=True,
            security_alert_counts=True,
        )
        gql = _make_graphql_client([_make_graphql_repo(default_branch="main")])
        svc = DiscoveryService(rest_client=rest, graphql_client=gql, config=config)
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.large_file_scan.completed is True
        assert repo.large_file_scan.enabled is True
        assert len(repo.large_file_scan.files) == 1
        assert repo.large_file_scan.files[0].path == "bigfile.bin"
        assert repo.large_file_scan.files[0].size_bytes == 200_000_000

    @pytest.mark.asyncio
    async def test_actions_analysis_level_parsed_when_contents_enabled(self):
        rest = _make_rest_client()
        rest.list_workflows.return_value = [
            {"name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}
        ]
        rest.get_workflow_file.return_value = (
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        config = _make_config(
            scan_profile="deep",
            scan_large_files=True,
            scan_workflow_contents=True,
            security_alert_counts=True,
        )
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.actions.analysis_level == "parsed"
        assert "actions/checkout@v4" in repo.actions.actions_used

    @pytest.mark.asyncio
    async def test_security_counts_exact_when_accessible(self):
        rest = _make_rest_client()
        rest.count_dependabot_alerts.return_value = AlertCountResult.from_count(5)
        rest.count_code_scanning_alerts.return_value = AlertCountResult.from_count(2)
        rest.count_secret_scanning_alerts.return_value = AlertCountResult.from_count(0)
        config = _make_config(
            scan_profile="deep",
            scan_large_files=True,
            scan_workflow_contents=True,
            security_alert_counts=True,
        )
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sec = inventory.repositories[0].security
        assert sec.counts_exact is True
        assert sec.alerts_accessible is True
        assert sec.dependabot_alerts_open == 5
        assert sec.code_scanning_alerts_open == 2
        assert sec.secret_scanning_alerts_open == 0

    @pytest.mark.asyncio
    async def test_self_hosted_runner_detection_via_deep_parse(self):
        rest = _make_rest_client()
        rest.list_workflows.return_value = [
            {"name": "Deploy", "path": ".github/workflows/deploy.yml", "state": "active"}
        ]
        rest.get_workflow_file.return_value = (
            "jobs:\n  deploy:\n    runs-on: self-hosted\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        config = _make_config(
            scan_profile="deep",
            scan_large_files=True,
            scan_workflow_contents=True,
            security_alert_counts=True,
        )
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].actions.uses_self_hosted_runners is True


# ---------------------------------------------------------------------------
# Graceful degradation tests
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    """Discovery should not fail when optional endpoints are inaccessible."""

    @pytest.mark.asyncio
    async def test_rulesets_forbidden_returns_none_count(self):
        rest = _make_rest_client()
        rest.list_rulesets.return_value = None  # forbidden
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.branch_protection.ruleset_count is None
        assert any("ruleset" in w.lower() for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_security_alerts_inaccessible(self):
        rest = _make_rest_client()
        rest.count_dependabot_alerts.return_value = AlertCountResult.inaccessible()
        rest.count_code_scanning_alerts.return_value = AlertCountResult.inaccessible()
        rest.count_secret_scanning_alerts.return_value = AlertCountResult.inaccessible()
        config = _make_config(security_alert_counts=True)
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sec = inventory.repositories[0].security
        assert sec.alerts_accessible is False
        assert sec.counts_exact is False
        assert sec.dependabot_alerts_open is None
        assert sec.code_scanning_alerts_open is None
        assert sec.secret_scanning_alerts_open is None

    @pytest.mark.asyncio
    async def test_workflow_content_fetch_fails_gracefully(self):
        rest = _make_rest_client()
        rest.list_workflows.return_value = [
            {"name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}
        ]
        rest.get_workflow_file.side_effect = Exception("network error")
        config = _make_config(scan_workflow_contents=True)
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        # Should still return inventory, not raise
        assert repo.actions.has_workflows is True
        assert any("workflow" in w.lower() for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_get_tree_failure_handled_gracefully(self):
        rest = _make_rest_client()
        rest.get_tree.side_effect = Exception("tree fetch failed")
        config = _make_config(scan_large_files=True)
        gql = _make_graphql_client([_make_graphql_repo(default_branch="main")])
        svc = DiscoveryService(rest_client=rest, graphql_client=gql, config=config)
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.large_file_scan.completed is False
        assert any("large file" in w.lower() or "tree" in w.lower() for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_security_features_failure_handled_gracefully(self):
        rest = _make_rest_client()
        rest.get_security_features.side_effect = Exception("forbidden")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        # Features should remain None (unknown)
        assert repo.security.dependabot_enabled is None
        assert any("security" in w.lower() for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_inventory_still_returned_with_all_failures(self):
        """Even when everything optional fails, we get a valid inventory."""
        rest = _make_rest_client()
        rest.list_workflows.side_effect = Exception("fail")
        rest.list_rulesets.side_effect = Exception("fail")
        rest.get_security_features.side_effect = Exception("fail")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 1
        assert inventory.repositories[0].name == "repo1"


# ---------------------------------------------------------------------------
# repo_limit tests
# ---------------------------------------------------------------------------


class TestRepoLimit:
    """repo_limit should trim repos before deep analysis."""

    @pytest.mark.asyncio
    async def test_repo_limit_applied(self):
        repos = [_make_graphql_repo(f"repo{i}") for i in range(5)]
        config = _make_config(repo_limit=2)
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 2

    @pytest.mark.asyncio
    async def test_repo_limit_none_means_all(self):
        repos = [_make_graphql_repo(f"repo{i}") for i in range(5)]
        config = _make_config(repo_limit=None)
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 5

    @pytest.mark.asyncio
    async def test_repo_limit_larger_than_total(self):
        repos = [_make_graphql_repo(f"repo{i}") for i in range(3)]
        config = _make_config(repo_limit=100)
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 3


# ---------------------------------------------------------------------------
# LFS detection from GraphQL .gitattributes
# ---------------------------------------------------------------------------


class TestLFSDetection:
    """LFS patterns should be parsed from the GraphQL .gitattributes object."""

    @pytest.mark.asyncio
    async def test_lfs_detected_from_gitattributes(self):
        repo = _make_graphql_repo(gitattributes_text="*.bin filter=lfs diff=lfs merge=lfs\n")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        lfs = inventory.repositories[0].lfs_info
        assert lfs.has_lfs is True
        assert "*.bin" in lfs.patterns

    @pytest.mark.asyncio
    async def test_no_lfs_when_gitattributes_absent(self):
        repo = _make_graphql_repo(gitattributes_text=None)
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        lfs = inventory.repositories[0].lfs_info
        assert lfs.has_lfs is False
        assert lfs.patterns == []

    @pytest.mark.asyncio
    async def test_no_lfs_when_no_lfs_filters(self):
        repo = _make_graphql_repo(gitattributes_text="*.txt text\n")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        lfs = inventory.repositories[0].lfs_info
        assert lfs.has_lfs is False
        assert lfs.patterns == []


# ---------------------------------------------------------------------------
# Large file detection from tree
# ---------------------------------------------------------------------------


class TestLargeFileDetection:
    """Large-file scan should find files exceeding the threshold."""

    @pytest.mark.asyncio
    async def test_large_files_found_in_tree(self):
        rest = _make_rest_client()
        rest.get_tree.return_value = {
            "tree": [
                {"path": "small.txt", "size": 100, "type": "blob"},
                {"path": "big.bin", "size": 200_000_000, "type": "blob"},
                {"path": "subdir", "type": "tree"},
            ],
            "truncated": False,
        }
        config = _make_config(scan_large_files=True)
        gql = _make_graphql_client([_make_graphql_repo(default_branch="main")])
        svc = DiscoveryService(rest_client=rest, graphql_client=gql, config=config)
        inventory = await svc.discover()
        lfs_scan = inventory.repositories[0].large_file_scan
        assert lfs_scan.completed is True
        assert len(lfs_scan.files) == 1
        assert lfs_scan.files[0].path == "big.bin"

    @pytest.mark.asyncio
    async def test_truncated_tree_marked(self):
        rest = _make_rest_client()
        rest.get_tree.return_value = {"tree": [], "truncated": True}
        config = _make_config(scan_large_files=True)
        gql = _make_graphql_client([_make_graphql_repo(default_branch="main")])
        svc = DiscoveryService(rest_client=rest, graphql_client=gql, config=config)
        inventory = await svc.discover()
        assert inventory.repositories[0].large_file_scan.truncated is True

    @pytest.mark.asyncio
    async def test_no_default_branch_skips_large_file_scan(self):
        rest = _make_rest_client()
        config = _make_config(scan_large_files=True)
        gql = _make_graphql_client([_make_graphql_repo(default_branch=None)])
        svc = DiscoveryService(rest_client=rest, graphql_client=gql, config=config)
        inventory = await svc.discover()
        assert inventory.repositories[0].large_file_scan.completed is False
        rest.get_tree.assert_not_called()


# ---------------------------------------------------------------------------
# Summary counts
# ---------------------------------------------------------------------------


class TestSummaryCounts:
    """Summary should aggregate repo-level data correctly."""

    @pytest.mark.asyncio
    async def test_summary_counts_basic(self):
        repos = [
            _make_graphql_repo("pub-repo", visibility="PUBLIC", disk_usage=500),
            _make_graphql_repo("priv-repo", visibility="PRIVATE", disk_usage=300, is_fork=True),
            _make_graphql_repo(
                "internal-repo", visibility="INTERNAL", disk_usage=200, is_archived=True
            ),
        ]
        rest = _make_rest_client()
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        s = inventory.summary
        assert s.total_repos == 3
        assert s.public_repos == 1
        assert s.private_repos == 1
        assert s.internal_repos == 1
        assert s.archived_repos == 1
        assert s.forked_repos == 1

    @pytest.mark.asyncio
    async def test_summary_size_in_bytes(self):
        """diskUsage from GraphQL is in KB — summary should convert to bytes."""
        repos = [_make_graphql_repo(disk_usage=1024)]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        # 1024 KB = 1048576 bytes
        assert inventory.summary.total_size_bytes == 1024 * 1024

    @pytest.mark.asyncio
    async def test_summary_workflow_counts(self):
        rest = _make_rest_client()
        rest.list_workflows.return_value = [
            {"name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
            {"name": "CD", "path": ".github/workflows/cd.yml", "state": "active"},
        ]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.summary.repos_with_workflows == 1
        assert inventory.summary.total_workflow_count == 2

    @pytest.mark.asyncio
    async def test_summary_lfs_repos_counted(self):
        repos = [
            _make_graphql_repo("lfs-repo", gitattributes_text="*.bin filter=lfs\n"),
            _make_graphql_repo("no-lfs-repo"),
        ]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.summary.repos_with_lfs == 1

    @pytest.mark.asyncio
    async def test_summary_security_features_counted(self):
        rest = _make_rest_client()
        rest.get_security_features.return_value = {
            "security_and_analysis": {
                "dependabot_security_updates": {"status": "enabled"},
                "secret_scanning": {"status": "enabled"},
                "advanced_security": {"status": "enabled"},
            }
        }
        repos = [_make_graphql_repo("sec-repo")]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.summary.repos_with_dependabot == 1
        assert inventory.summary.repos_with_secret_scanning == 1

    @pytest.mark.asyncio
    async def test_summary_template_repos_counted(self):
        repos = [
            _make_graphql_repo("template1", is_template=True),
            _make_graphql_repo("normal1"),
        ]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.summary.template_repos == 1


# ---------------------------------------------------------------------------
# User discovery
# ---------------------------------------------------------------------------


class TestUserDiscovery:
    """Org member discovery should aggregate admins, members, and outside collaborators."""

    @pytest.mark.asyncio
    async def test_user_counts(self):
        rest = _make_rest_client()
        rest.list_org_members.side_effect = lambda org, role="all": {
            "admin": [{"login": "admin1"}],
            "member": [{"login": "member1"}, {"login": "member2"}],
        }.get(role, [])
        rest.list_outside_collaborators.return_value = [{"login": "collab1"}]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.users.admins == 1
        assert inventory.users.members == 2
        assert inventory.users.outside_collaborators == 1
        assert inventory.users.total == 4

    @pytest.mark.asyncio
    async def test_user_discovery_failure_recorded_as_warning(self):
        rest = _make_rest_client()
        rest.list_org_members.side_effect = Exception("forbidden")
        rest.list_outside_collaborators.side_effect = Exception("forbidden")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.users.total == 0
        assert any(
            "member" in w.lower() or "user" in w.lower() for w in inventory.metadata.scan_warnings
        )


# ---------------------------------------------------------------------------
# Package discovery
# ---------------------------------------------------------------------------


class TestPackageDiscovery:
    """Package discovery should scan all package types."""

    @pytest.mark.asyncio
    async def test_packages_discovered_across_types(self):
        rest = _make_rest_client()

        def list_packages_side_effect(org, package_type):
            if package_type == "npm":
                return [{"name": "pkg1", "package_type": "npm", "visibility": "public"}]
            if package_type == "docker":
                return [{"name": "img1", "package_type": "docker", "visibility": "private"}]
            return []

        rest.list_packages.side_effect = list_packages_side_effect
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.packages) == 2
        names = {p.name for p in inventory.packages}
        assert "pkg1" in names
        assert "img1" in names
        assert inventory.summary.total_packages == 2
        assert inventory.summary.packages_by_type.get("npm") == 1
        assert inventory.summary.packages_by_type.get("docker") == 1

    @pytest.mark.asyncio
    async def test_package_discovery_failure_recorded_as_warning(self):
        rest = _make_rest_client()
        rest.list_packages.side_effect = Exception("forbidden")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.packages == []
        assert any("package" in w.lower() for w in inventory.metadata.scan_warnings)


# ---------------------------------------------------------------------------
# Project discovery
# ---------------------------------------------------------------------------


class TestProjectDiscovery:
    """Project discovery should use GraphQL fetch_projects."""

    @pytest.mark.asyncio
    async def test_projects_discovered(self):
        gql = _make_graphql_client()
        gql.fetch_projects.return_value = [
            {"title": "Project Alpha", "closed": False, "items": {"totalCount": 10}},
            {"title": "Project Beta", "closed": True, "items": {"totalCount": 5}},
        ]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=gql,
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.projects) == 2
        assert inventory.summary.total_projects == 2
        assert inventory.projects[0].title == "Project Alpha"
        assert inventory.projects[0].item_count == 10
        assert inventory.projects[1].closed is True

    @pytest.mark.asyncio
    async def test_project_discovery_failure_recorded_as_warning(self):
        gql = _make_graphql_client()
        gql.fetch_projects.side_effect = Exception("fail")
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=gql,
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.projects == []
        assert any("project" in w.lower() for w in inventory.metadata.scan_warnings)


# ---------------------------------------------------------------------------
# Metadata tests
# ---------------------------------------------------------------------------


class TestMetadata:
    """Metadata should capture scan configuration correctly."""

    @pytest.mark.asyncio
    async def test_metadata_organization(self):
        config = _make_config(organization="testorg")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.organization == "testorg"

    @pytest.mark.asyncio
    async def test_metadata_auth_method(self):
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.metadata.auth_method == "pat"

    @pytest.mark.asyncio
    async def test_metadata_scan_options_include_flags(self):
        config = _make_config(
            scan_large_files=True,
            scan_workflow_contents=True,
            security_alert_counts=True,
        )
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        opts = inventory.metadata.scan_options
        assert opts["scan_large_files"] is True
        assert opts["scan_workflow_contents"] is True
        assert opts["security_alert_counts"] is True

    @pytest.mark.asyncio
    async def test_metadata_tool_version(self):
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        from gh_audit.__about__ import __version__

        assert inventory.metadata.tool_version == __version__


# ---------------------------------------------------------------------------
# GraphQL field mapping
# ---------------------------------------------------------------------------


class TestGraphQLFieldMapping:
    """Verify all GraphQL fields map correctly to RepositoryInventoryItem."""

    @pytest.mark.asyncio
    async def test_basic_fields_mapped(self):
        repo = _make_graphql_repo(
            name="my-repo",
            org="myorg",
            visibility="INTERNAL",
            is_archived=True,
            is_fork=True,
            is_template=True,
            language="Rust",
            topics=["cli", "tool"],
            disk_usage=2048,
            default_branch="develop",
            description="Test description",
            branch_count=12,
            open_prs=4,
            closed_prs=2,
            merged_prs=15,
            open_issues=8,
            closed_issues=30,
        )
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        r = inventory.repositories[0]
        assert r.name == "my-repo"
        assert r.full_name == "myorg/my-repo"
        assert r.visibility == "internal"
        assert r.archived is True
        assert r.fork is True
        assert r.is_template is True
        assert r.language == "Rust"
        assert r.topics == ["cli", "tool"]
        assert r.size_bytes == 2048 * 1024
        assert r.default_branch == "develop"
        assert r.description == "Test description"
        assert r.branch_count == 12
        assert r.pr_count_open == 4
        assert r.pr_count_closed == 2
        assert r.pr_count_merged == 15
        assert r.issue_count_open == 8
        assert r.issue_count_closed == 30

    @pytest.mark.asyncio
    async def test_label_distribution_mapped(self):
        repo = _make_graphql_repo(
            labels=[
                {"name": "bug", "issues": {"totalCount": 5}},
                {"name": "feature", "issues": {"totalCount": 3}},
            ]
        )
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        dist = inventory.repositories[0].issue_label_distribution
        assert dist == {"bug": 5, "feature": 3}

    @pytest.mark.asyncio
    async def test_none_primary_language(self):
        repo = _make_graphql_repo(language=None)
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].language is None


# ---------------------------------------------------------------------------
# include_archived filtering
# ---------------------------------------------------------------------------


class TestIncludeArchived:
    """When include_archived=False, archived repos should be excluded."""

    @pytest.mark.asyncio
    async def test_archived_excluded_when_disabled(self):
        repos = [
            _make_graphql_repo("active-repo", is_archived=False),
            _make_graphql_repo("archived-repo", is_archived=True),
        ]
        config = _make_config(include_archived=False)
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 1
        assert inventory.repositories[0].name == "active-repo"

    @pytest.mark.asyncio
    async def test_archived_included_when_enabled(self):
        repos = [
            _make_graphql_repo("active-repo", is_archived=False),
            _make_graphql_repo("archived-repo", is_archived=True),
        ]
        config = _make_config(include_archived=True)
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 2


# ---------------------------------------------------------------------------
# Concurrency / semaphore
# ---------------------------------------------------------------------------


class TestConcurrency:
    """Discovery should use a semaphore for bounded concurrency."""

    @pytest.mark.asyncio
    async def test_concurrency_bounded_by_semaphore(self):
        """Verify that concurrent tasks are bounded by config.concurrency."""
        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        AsyncMock(return_value=[])

        async def tracked_list_workflows(owner, repo):
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent
            await asyncio.sleep(0.01)  # simulate work
            async with lock:
                current_concurrent -= 1
            return []

        rest = _make_rest_client()
        rest.list_workflows.side_effect = tracked_list_workflows

        repos = [_make_graphql_repo(f"repo{i}") for i in range(10)]
        config = _make_config(concurrency=3)
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos),
            config=config,
        )
        await svc.discover()
        assert max_concurrent <= 3


# ---------------------------------------------------------------------------
# Branch protection mapping
# ---------------------------------------------------------------------------


class TestBranchProtection:
    """Branch protection info from GraphQL and REST rulesets."""

    @pytest.mark.asyncio
    async def test_branch_protection_count_from_graphql(self):
        repo = _make_graphql_repo(branch_protection_count=3)
        config = _make_config()
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client([repo]),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].branch_protection.protected_branches == 3

    @pytest.mark.asyncio
    async def test_ruleset_count_from_rest(self):
        rest = _make_rest_client()
        rest.list_rulesets.return_value = [{"id": 1}, {"id": 2}]
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert inventory.repositories[0].branch_protection.ruleset_count == 2


# ---------------------------------------------------------------------------
# Security features mapping
# ---------------------------------------------------------------------------


class TestSecurityFeatures:
    """Security feature enablement from REST get_security_features."""

    @pytest.mark.asyncio
    async def test_security_features_mapped(self):
        rest = _make_rest_client()
        rest.get_security_features.return_value = {
            "security_and_analysis": {
                "dependabot_security_updates": {"status": "enabled"},
                "secret_scanning": {"status": "enabled"},
                "advanced_security": {"status": "disabled"},
            }
        }
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sec = inventory.repositories[0].security
        assert sec.dependabot_enabled is True
        assert sec.secret_scanning_enabled is True

    @pytest.mark.asyncio
    async def test_code_scanning_from_advanced_security(self):
        rest = _make_rest_client()
        rest.get_security_features.return_value = {
            "security_and_analysis": {
                "advanced_security": {"status": "enabled"},
            }
        }
        config = _make_config()
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sec = inventory.repositories[0].security
        assert sec.code_scanning_enabled is True
