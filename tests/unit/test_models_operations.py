"""Unit tests for operations models.

Covers:
- Construction with defaults for every model
- Field types and values
- extra="forbid" rejection of unknown fields
- JSON roundtrip for OperationsInventory
- Integration with Inventory and RepositoryInventoryItem
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.operations import (
    ActionsPermissions,
    DeployKeyInfo,
    EnvironmentInfo,
    EnvironmentProtection,
    InstalledAppInfo,
    OperationsInventory,
    RunnerGroupInfo,
    RunnerInfo,
    SecretMetadata,
    VariableMetadata,
    WebhookInfo,
)
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_metadata(**kwargs) -> InventoryMetadata:
    from datetime import datetime, timezone

    defaults = dict(
        schema_version="2.0",
        generated_at=datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc),
        tool_version="0.1.0",
        organization="test-org",
        auth_method="pat",
        scan_profile="standard",
    )
    defaults.update(kwargs)
    return InventoryMetadata(**defaults)


def _make_repo(**kwargs) -> RepositoryInventoryItem:
    defaults = dict(name="repo", full_name="org/repo", visibility="private")
    defaults.update(kwargs)
    return RepositoryInventoryItem(**defaults)


def _make_inventory(**kwargs) -> Inventory:
    defaults = dict(
        metadata=_make_metadata(),
        summary=InventorySummary(),
        repositories=[],
        users=OrgMemberSummary(total=0, members=0),
    )
    defaults.update(kwargs)
    return Inventory(**defaults)


# ---------------------------------------------------------------------------
# RunnerInfo
# ---------------------------------------------------------------------------


class TestRunnerInfo:
    def test_minimal_construction(self):
        runner = RunnerInfo(name="runner-1", os="Linux", status="online")
        assert runner.name == "runner-1"
        assert runner.os == "Linux"
        assert runner.status == "online"
        assert runner.labels == []
        assert runner.busy is False
        assert runner.runner_group_name is None

    def test_full_construction(self):
        runner = RunnerInfo(
            name="runner-2",
            os="Windows",
            status="offline",
            labels=["self-hosted", "x64"],
            busy=True,
            runner_group_name="default",
        )
        assert runner.os == "Windows"
        assert runner.status == "offline"
        assert runner.labels == ["self-hosted", "x64"]
        assert runner.busy is True
        assert runner.runner_group_name == "default"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            RunnerInfo(name="r", os="Linux", status="online", unknown_field="bad")

    def test_labels_default_is_independent(self):
        r1 = RunnerInfo(name="a", os="Linux", status="online")
        r2 = RunnerInfo(name="b", os="Linux", status="online")
        r1.labels.append("custom")
        assert r2.labels == []


# ---------------------------------------------------------------------------
# RunnerGroupInfo
# ---------------------------------------------------------------------------


class TestRunnerGroupInfo:
    def test_minimal_construction(self):
        rg = RunnerGroupInfo(name="default", visibility="all")
        assert rg.name == "default"
        assert rg.visibility == "all"
        assert rg.allows_public_repos is False
        assert rg.runner_count == 0
        assert rg.repo_count is None

    def test_full_construction(self):
        rg = RunnerGroupInfo(
            name="production",
            visibility="selected",
            allows_public_repos=True,
            runner_count=5,
            repo_count=10,
        )
        assert rg.allows_public_repos is True
        assert rg.runner_count == 5
        assert rg.repo_count == 10

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            RunnerGroupInfo(name="x", visibility="all", surprise="bad")


# ---------------------------------------------------------------------------
# InstalledAppInfo
# ---------------------------------------------------------------------------


class TestInstalledAppInfo:
    def test_minimal_construction(self):
        app = InstalledAppInfo(app_name="Dependabot", app_slug="dependabot")
        assert app.app_name == "Dependabot"
        assert app.app_slug == "dependabot"
        assert app.permissions == {}
        assert app.events == []
        assert app.repository_selection == "all"

    def test_full_construction(self):
        app = InstalledAppInfo(
            app_name="CI Bot",
            app_slug="ci-bot",
            permissions={"checks": "write", "pull_requests": "read"},
            events=["push", "pull_request"],
            repository_selection="selected",
        )
        assert app.permissions == {"checks": "write", "pull_requests": "read"}
        assert app.events == ["push", "pull_request"]
        assert app.repository_selection == "selected"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            InstalledAppInfo(app_name="X", app_slug="x", nope="bad")

    def test_permissions_default_is_independent(self):
        a1 = InstalledAppInfo(app_name="A", app_slug="a")
        a2 = InstalledAppInfo(app_name="B", app_slug="b")
        a1.permissions["issues"] = "write"
        assert a2.permissions == {}

    def test_events_default_is_independent(self):
        a1 = InstalledAppInfo(app_name="A", app_slug="a")
        a2 = InstalledAppInfo(app_name="B", app_slug="b")
        a1.events.append("push")
        assert a2.events == []


# ---------------------------------------------------------------------------
# WebhookInfo
# ---------------------------------------------------------------------------


class TestWebhookInfo:
    def test_minimal_construction(self):
        wh = WebhookInfo(url_domain="example.com")
        assert wh.url_domain == "example.com"
        assert wh.events == []
        assert wh.active is True
        assert wh.content_type == "json"
        assert wh.insecure_ssl is False

    def test_full_construction(self):
        wh = WebhookInfo(
            url_domain="hooks.slack.com",
            events=["push", "pull_request"],
            active=False,
            content_type="form",
            insecure_ssl=True,
        )
        assert wh.url_domain == "hooks.slack.com"
        assert wh.events == ["push", "pull_request"]
        assert wh.active is False
        assert wh.content_type == "form"
        assert wh.insecure_ssl is True

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            WebhookInfo(url_domain="example.com", extra="bad")

    def test_events_default_is_independent(self):
        w1 = WebhookInfo(url_domain="a.com")
        w2 = WebhookInfo(url_domain="b.com")
        w1.events.append("push")
        assert w2.events == []


# ---------------------------------------------------------------------------
# SecretMetadata
# ---------------------------------------------------------------------------


class TestSecretMetadata:
    def test_construction(self):
        s = SecretMetadata(
            name="DEPLOY_KEY",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-03-01T00:00:00Z",
            visibility="all",
        )
        assert s.name == "DEPLOY_KEY"
        assert s.created_at == "2026-01-01T00:00:00Z"
        assert s.updated_at == "2026-03-01T00:00:00Z"
        assert s.visibility == "all"
        assert s.selected_repositories_count is None

    def test_with_selected_repos(self):
        s = SecretMetadata(
            name="NPM_TOKEN",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-02-01T00:00:00Z",
            visibility="selected",
            selected_repositories_count=5,
        )
        assert s.selected_repositories_count == 5

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SecretMetadata(
                name="X",
                created_at="t",
                updated_at="t",
                visibility="all",
                sneaky="bad",
            )


# ---------------------------------------------------------------------------
# VariableMetadata
# ---------------------------------------------------------------------------


class TestVariableMetadata:
    def test_construction(self):
        v = VariableMetadata(
            name="DEPLOY_ENV",
            value="production",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-03-01T00:00:00Z",
            visibility="all",
        )
        assert v.name == "DEPLOY_ENV"
        assert v.value == "production"
        assert v.visibility == "all"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            VariableMetadata(
                name="X",
                value="v",
                created_at="t",
                updated_at="t",
                visibility="all",
                nope="bad",
            )


# ---------------------------------------------------------------------------
# EnvironmentProtection
# ---------------------------------------------------------------------------


class TestEnvironmentProtection:
    def test_all_defaults(self):
        ep = EnvironmentProtection()
        assert ep.wait_timer == 0
        assert ep.required_reviewers == 0
        assert ep.branch_policy is None

    def test_full_construction(self):
        ep = EnvironmentProtection(
            wait_timer=30,
            required_reviewers=2,
            branch_policy="protected",
        )
        assert ep.wait_timer == 30
        assert ep.required_reviewers == 2
        assert ep.branch_policy == "protected"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            EnvironmentProtection(unknown="bad")


# ---------------------------------------------------------------------------
# EnvironmentInfo
# ---------------------------------------------------------------------------


class TestEnvironmentInfo:
    def test_minimal_construction(self):
        env = EnvironmentInfo(name="production")
        assert env.name == "production"
        assert env.protection_rules is None
        assert env.secrets_count == 0
        assert env.variables_count == 0
        assert env.can_admins_bypass is True

    def test_full_construction(self):
        env = EnvironmentInfo(
            name="staging",
            protection_rules=EnvironmentProtection(wait_timer=10, required_reviewers=1),
            secrets_count=3,
            variables_count=2,
            can_admins_bypass=False,
        )
        assert env.protection_rules.wait_timer == 10
        assert env.protection_rules.required_reviewers == 1
        assert env.secrets_count == 3
        assert env.variables_count == 2
        assert env.can_admins_bypass is False

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            EnvironmentInfo(name="x", surprise="bad")


# ---------------------------------------------------------------------------
# DeployKeyInfo
# ---------------------------------------------------------------------------


class TestDeployKeyInfo:
    def test_minimal_construction(self):
        dk = DeployKeyInfo(title="CI key", created_at="2026-01-01T00:00:00Z")
        assert dk.title == "CI key"
        assert dk.read_only is True
        assert dk.created_at == "2026-01-01T00:00:00Z"

    def test_full_construction(self):
        dk = DeployKeyInfo(
            title="Deploy",
            read_only=False,
            created_at="2026-03-15T10:00:00Z",
        )
        assert dk.read_only is False

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            DeployKeyInfo(title="x", created_at="t", extra="bad")


# ---------------------------------------------------------------------------
# ActionsPermissions
# ---------------------------------------------------------------------------


class TestActionsPermissions:
    def test_all_defaults(self):
        ap = ActionsPermissions()
        assert ap.enabled is True
        assert ap.allowed_actions == "all"
        assert ap.default_token_permissions == "read"

    def test_full_construction(self):
        ap = ActionsPermissions(
            enabled=False,
            allowed_actions="local_only",
            default_token_permissions="write",
        )
        assert ap.enabled is False
        assert ap.allowed_actions == "local_only"
        assert ap.default_token_permissions == "write"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            ActionsPermissions(nope="bad")


# ---------------------------------------------------------------------------
# OperationsInventory
# ---------------------------------------------------------------------------


class TestOperationsInventory:
    def test_all_defaults(self):
        ops = OperationsInventory()
        assert ops.runners == []
        assert ops.runner_groups == []
        assert ops.installed_apps == []
        assert ops.org_webhooks == []
        assert ops.org_secrets_metadata == []
        assert ops.org_variables_metadata == []

    def test_with_runners(self):
        runner = RunnerInfo(name="runner-1", os="Linux", status="online")
        ops = OperationsInventory(runners=[runner])
        assert len(ops.runners) == 1
        assert ops.runners[0].name == "runner-1"

    def test_with_runner_groups(self):
        rg = RunnerGroupInfo(name="default", visibility="all", runner_count=3)
        ops = OperationsInventory(runner_groups=[rg])
        assert len(ops.runner_groups) == 1
        assert ops.runner_groups[0].runner_count == 3

    def test_with_installed_apps(self):
        app = InstalledAppInfo(app_name="CI Bot", app_slug="ci-bot")
        ops = OperationsInventory(installed_apps=[app])
        assert len(ops.installed_apps) == 1

    def test_with_webhooks(self):
        wh = WebhookInfo(url_domain="hooks.slack.com", events=["push"])
        ops = OperationsInventory(org_webhooks=[wh])
        assert len(ops.org_webhooks) == 1

    def test_with_secrets_metadata(self):
        s = SecretMetadata(
            name="TOKEN",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            visibility="all",
        )
        ops = OperationsInventory(org_secrets_metadata=[s])
        assert len(ops.org_secrets_metadata) == 1

    def test_with_variables_metadata(self):
        v = VariableMetadata(
            name="ENV",
            value="prod",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            visibility="all",
        )
        ops = OperationsInventory(org_variables_metadata=[v])
        assert len(ops.org_variables_metadata) == 1

    def test_defaults_are_independent(self):
        o1 = OperationsInventory()
        o2 = OperationsInventory()
        o1.runners.append(RunnerInfo(name="r", os="Linux", status="online"))
        assert o2.runners == []

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            OperationsInventory(surprise="bad")

    def test_json_roundtrip(self):
        ops = OperationsInventory(
            runners=[
                RunnerInfo(
                    name="runner-1",
                    os="Linux",
                    status="online",
                    labels=["self-hosted"],
                    busy=True,
                    runner_group_name="default",
                )
            ],
            runner_groups=[
                RunnerGroupInfo(
                    name="default",
                    visibility="all",
                    allows_public_repos=True,
                    runner_count=2,
                )
            ],
            installed_apps=[
                InstalledAppInfo(
                    app_name="CI Bot",
                    app_slug="ci-bot",
                    permissions={"checks": "write"},
                    events=["push"],
                    repository_selection="selected",
                )
            ],
            org_webhooks=[
                WebhookInfo(
                    url_domain="hooks.slack.com",
                    events=["push", "pull_request"],
                    active=True,
                )
            ],
            org_secrets_metadata=[
                SecretMetadata(
                    name="DEPLOY_KEY",
                    created_at="2026-01-01T00:00:00Z",
                    updated_at="2026-03-01T00:00:00Z",
                    visibility="all",
                )
            ],
            org_variables_metadata=[
                VariableMetadata(
                    name="DEPLOY_ENV",
                    value="production",
                    created_at="2026-01-01T00:00:00Z",
                    updated_at="2026-03-01T00:00:00Z",
                    visibility="all",
                )
            ],
        )
        json_str = ops.model_dump_json()
        ops2 = OperationsInventory.model_validate_json(json_str)
        assert ops2.runners[0].name == "runner-1"
        assert ops2.runners[0].labels == ["self-hosted"]
        assert ops2.runner_groups[0].name == "default"
        assert ops2.installed_apps[0].app_slug == "ci-bot"
        assert ops2.installed_apps[0].permissions == {"checks": "write"}
        assert ops2.org_webhooks[0].url_domain == "hooks.slack.com"
        assert ops2.org_secrets_metadata[0].name == "DEPLOY_KEY"
        assert ops2.org_variables_metadata[0].value == "production"


# ---------------------------------------------------------------------------
# Inventory integration
# ---------------------------------------------------------------------------


class TestInventoryOperationsField:
    def test_operations_is_none_by_default(self):
        inv = _make_inventory()
        assert inv.operations is None

    def test_operations_can_be_set(self):
        ops = OperationsInventory(runners=[RunnerInfo(name="r1", os="Linux", status="online")])
        inv = _make_inventory(operations=ops)
        assert inv.operations is not None
        assert len(inv.operations.runners) == 1

    def test_operations_full_population(self):
        ops = OperationsInventory(
            runners=[RunnerInfo(name="r1", os="Linux", status="online")],
            installed_apps=[InstalledAppInfo(app_name="Bot", app_slug="bot")],
            org_webhooks=[WebhookInfo(url_domain="example.com")],
        )
        inv = _make_inventory(operations=ops)
        assert inv.operations.runners[0].name == "r1"
        assert inv.operations.installed_apps[0].app_slug == "bot"
        assert inv.operations.org_webhooks[0].url_domain == "example.com"


# ---------------------------------------------------------------------------
# RepositoryInventoryItem operations fields
# ---------------------------------------------------------------------------


class TestRepositoryOperationsFields:
    def test_operations_fields_are_none_by_default(self):
        repo = _make_repo()
        assert repo.environments is None
        assert repo.deploy_keys is None
        assert repo.repo_webhooks is None
        assert repo.repo_secrets_count is None
        assert repo.repo_variables_count is None
        assert repo.actions_permissions is None

    def test_set_environments(self):
        env = EnvironmentInfo(name="production", secrets_count=2)
        repo = _make_repo(environments=[env])
        assert len(repo.environments) == 1
        assert repo.environments[0].name == "production"
        assert repo.environments[0].secrets_count == 2

    def test_set_environments_with_protection(self):
        env = EnvironmentInfo(
            name="staging",
            protection_rules=EnvironmentProtection(wait_timer=10, required_reviewers=1),
        )
        repo = _make_repo(environments=[env])
        assert repo.environments[0].protection_rules.wait_timer == 10

    def test_set_deploy_keys(self):
        dk = DeployKeyInfo(title="CI key", created_at="2026-01-01T00:00:00Z")
        repo = _make_repo(deploy_keys=[dk])
        assert len(repo.deploy_keys) == 1
        assert repo.deploy_keys[0].title == "CI key"

    def test_set_repo_webhooks(self):
        wh = WebhookInfo(url_domain="hooks.slack.com", events=["push"])
        repo = _make_repo(repo_webhooks=[wh])
        assert len(repo.repo_webhooks) == 1

    def test_set_repo_secrets_count(self):
        repo = _make_repo(repo_secrets_count=5)
        assert repo.repo_secrets_count == 5

    def test_set_repo_variables_count(self):
        repo = _make_repo(repo_variables_count=3)
        assert repo.repo_variables_count == 3

    def test_set_actions_permissions(self):
        ap = ActionsPermissions(enabled=True, allowed_actions="local_only")
        repo = _make_repo(actions_permissions=ap)
        assert repo.actions_permissions.allowed_actions == "local_only"

    def test_empty_lists_differ_from_none(self):
        """Empty list = scanned and found nothing; None = not scanned."""
        repo_scanned = _make_repo(environments=[], deploy_keys=[], repo_webhooks=[])
        repo_not_scanned = _make_repo()
        assert repo_scanned.environments == []
        assert repo_not_scanned.environments is None
        assert repo_scanned.deploy_keys == []
        assert repo_not_scanned.deploy_keys is None

    def test_zero_count_differs_from_none(self):
        repo_scanned = _make_repo(repo_secrets_count=0, repo_variables_count=0)
        repo_not_scanned = _make_repo()
        assert repo_scanned.repo_secrets_count == 0
        assert repo_not_scanned.repo_secrets_count is None
