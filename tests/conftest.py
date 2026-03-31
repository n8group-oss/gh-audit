"""Shared pytest fixtures for gh-audit tests."""

from __future__ import annotations

import pathlib
from unittest.mock import AsyncMock

import pytest

from gh_audit.adapters.base import AlertCountResult


@pytest.fixture
def tmp_env_file(tmp_path: pathlib.Path) -> pathlib.Path:
    """Return a Path for a temporary .env file (not yet created on disk).

    Tests that need a pre-populated .env file should write content into this
    path before passing it to the component under test.
    """
    return tmp_path / ".env"


@pytest.fixture
def make_graphql_repo():
    """Factory fixture that returns GraphQL repo node dicts.

    Usage::

        def test_foo(make_graphql_repo):
            node = make_graphql_repo(name="my-repo", visibility="PUBLIC")
    """

    def _make(
        name: str = "repo1",
        *,
        org: str = "testorg",
        visibility: str = "PRIVATE",
        is_archived: bool = False,
        is_fork: bool = False,
        is_template: bool = False,
        language: str | None = "Python",
        topics: list[str] | None = None,
        disk_usage: int = 1024,
        default_branch: str | None = "main",
        description: str | None = "A test repository",
        branch_count: int = 3,
        open_prs: int = 2,
        closed_prs: int = 1,
        merged_prs: int = 5,
        open_issues: int = 4,
        closed_issues: int = 10,
        labels: list[dict] | None = None,
        branch_protection_count: int = 1,
        gitattributes_text: str | None = None,
    ) -> dict:
        """Build a GraphQL repository node dict matching fetch_all_repos output."""
        topic_nodes = [{"topic": {"name": t}} for t in (topics or [])]
        label_nodes = (
            labels
            if labels is not None
            else [
                {"name": "bug", "issues": {"totalCount": 3}},
            ]
        )
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

    return _make


@pytest.fixture
def mock_rest_client() -> AsyncMock:
    """Return a mock REST client with sensible defaults for all methods."""
    rest = AsyncMock()
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
    return rest


@pytest.fixture
def mock_graphql_client(make_graphql_repo) -> AsyncMock:
    """Return a mock GraphQL client that returns a single default repo."""
    gql = AsyncMock()
    gql.fetch_all_repos.return_value = [make_graphql_repo()]
    gql.fetch_projects.return_value = []
    return gql


@pytest.fixture
def sample_config():
    """Minimal ScannerConfig suitable for testing (PAT auth, standard profile)."""
    from pydantic import SecretStr

    from gh_audit.models.config import ScannerConfig

    return ScannerConfig(
        token=SecretStr("ghp_test"),
        organization="testorg",
    )
