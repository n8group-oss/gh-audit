"""Unit tests for operations assessment rules (OPS-001 through OPS-004)."""

from __future__ import annotations

from datetime import datetime, timezone


from gh_audit.models.finding import Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.operations import (
    ActionsPermissions,
    DeployKeyInfo,
    EnvironmentInfo,
    EnvironmentProtection,
    WebhookInfo,
)
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary
from gh_audit.rules.operations import (
    ops_001_unprotected_environment,
    ops_002_insecure_webhook,
    ops_003_write_deploy_key,
    ops_004_permissive_actions,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo(
    name: str = "test-repo",
    *,
    environments: list[EnvironmentInfo] | None = None,
    repo_webhooks: list[WebhookInfo] | None = None,
    deploy_keys: list[DeployKeyInfo] | None = None,
    actions_permissions: ActionsPermissions | None = None,
) -> RepositoryInventoryItem:
    """Build a minimal RepositoryInventoryItem for operations rule testing."""
    kwargs: dict = {
        "name": name,
        "full_name": f"testorg/{name}",
        "visibility": "private",
    }
    if environments is not None:
        kwargs["environments"] = environments
    if repo_webhooks is not None:
        kwargs["repo_webhooks"] = repo_webhooks
    if deploy_keys is not None:
        kwargs["deploy_keys"] = deploy_keys
    if actions_permissions is not None:
        kwargs["actions_permissions"] = actions_permissions
    return RepositoryInventoryItem(**kwargs)


def _inv(repos: list[RepositoryInventoryItem]) -> Inventory:
    """Build a minimal Inventory wrapping the given repos."""
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization="testorg",
            auth_method="pat",
            scan_profile="total",
            active_categories=["operations"],
        ),
        summary=InventorySummary(total_repos=len(repos)),
        repositories=repos,
        users=OrgMemberSummary(total=0, admins=0, members=0),
    )


# ===================================================================
# OPS-001: Unprotected environment
# ===================================================================


class TestOps001UnprotectedEnvironment:
    def test_fires_when_environment_has_no_protection(self) -> None:
        repo = _repo(
            "unprotected-env",
            environments=[
                EnvironmentInfo(name="production", protection_rules=None),
            ],
        )
        findings = ops_001_unprotected_environment(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OPS-001"
        assert f.pillar == Pillar.operations
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "unprotected-env"

    def test_no_finding_when_environment_has_protection(self) -> None:
        repo = _repo(
            "protected-env",
            environments=[
                EnvironmentInfo(
                    name="production",
                    protection_rules=EnvironmentProtection(required_reviewers=1),
                ),
            ],
        )
        findings = ops_001_unprotected_environment(_inv([repo]))
        assert findings == []

    def test_skips_when_environments_is_none(self) -> None:
        repo = _repo("not-scanned", environments=None)
        findings = ops_001_unprotected_environment(_inv([repo]))
        assert findings == []

    def test_no_finding_when_environments_is_empty(self) -> None:
        repo = _repo("no-envs", environments=[])
        findings = ops_001_unprotected_environment(_inv([repo]))
        assert findings == []

    def test_one_finding_per_unprotected_environment(self) -> None:
        """Each unprotected environment produces a separate finding."""
        repo = _repo(
            "multi-env",
            environments=[
                EnvironmentInfo(name="staging", protection_rules=None),
                EnvironmentInfo(
                    name="production",
                    protection_rules=EnvironmentProtection(required_reviewers=2),
                ),
                EnvironmentInfo(name="dev", protection_rules=None),
            ],
        )
        findings = ops_001_unprotected_environment(_inv([repo]))
        assert len(findings) == 2
        env_names = {f.detail for f in findings}
        # Both staging and dev should be mentioned
        assert any("staging" in d for d in env_names)
        assert any("dev" in d for d in env_names)

    def test_fires_across_multiple_repos(self) -> None:
        repos = [
            _repo(
                "repo-a",
                environments=[
                    EnvironmentInfo(name="prod", protection_rules=None),
                ],
            ),
            _repo(
                "repo-b",
                environments=[
                    EnvironmentInfo(
                        name="prod",
                        protection_rules=EnvironmentProtection(required_reviewers=1),
                    ),
                ],
            ),
            _repo(
                "repo-c",
                environments=[
                    EnvironmentInfo(name="staging", protection_rules=None),
                ],
            ),
        ]
        findings = ops_001_unprotected_environment(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"repo-a", "repo-c"}


# ===================================================================
# OPS-002: Insecure webhook
# ===================================================================


class TestOps002InsecureWebhook:
    def test_fires_when_webhook_has_insecure_ssl(self) -> None:
        repo = _repo(
            "insecure-hooks",
            repo_webhooks=[
                WebhookInfo(url_domain="example.com", insecure_ssl=True),
            ],
        )
        findings = ops_002_insecure_webhook(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OPS-002"
        assert f.pillar == Pillar.operations
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "insecure-hooks"

    def test_no_finding_when_all_webhooks_secure(self) -> None:
        repo = _repo(
            "secure-hooks",
            repo_webhooks=[
                WebhookInfo(url_domain="example.com", insecure_ssl=False),
                WebhookInfo(url_domain="other.com", insecure_ssl=False),
            ],
        )
        findings = ops_002_insecure_webhook(_inv([repo]))
        assert findings == []

    def test_skips_when_webhooks_is_none(self) -> None:
        repo = _repo("not-scanned", repo_webhooks=None)
        findings = ops_002_insecure_webhook(_inv([repo]))
        assert findings == []

    def test_no_finding_when_webhooks_is_empty(self) -> None:
        repo = _repo("no-hooks", repo_webhooks=[])
        findings = ops_002_insecure_webhook(_inv([repo]))
        assert findings == []

    def test_aggregates_count_in_one_finding_per_repo(self) -> None:
        """Multiple insecure webhooks produce one finding with aggregate count."""
        repo = _repo(
            "multi-insecure",
            repo_webhooks=[
                WebhookInfo(url_domain="a.com", insecure_ssl=True),
                WebhookInfo(url_domain="b.com", insecure_ssl=False),
                WebhookInfo(url_domain="c.com", insecure_ssl=True),
            ],
        )
        findings = ops_002_insecure_webhook(_inv([repo]))
        assert len(findings) == 1  # Aggregated, not per-webhook
        assert "2" in findings[0].detail  # Count of insecure webhooks

    def test_fires_for_multiple_repos(self) -> None:
        repos = [
            _repo(
                "repo-a",
                repo_webhooks=[
                    WebhookInfo(url_domain="a.com", insecure_ssl=True),
                ],
            ),
            _repo(
                "repo-b",
                repo_webhooks=[
                    WebhookInfo(url_domain="b.com", insecure_ssl=False),
                ],
            ),
            _repo(
                "repo-c",
                repo_webhooks=[
                    WebhookInfo(url_domain="c.com", insecure_ssl=True),
                ],
            ),
        ]
        findings = ops_002_insecure_webhook(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"repo-a", "repo-c"}


# ===================================================================
# OPS-003: Write deploy key
# ===================================================================


class TestOps003WriteDeployKey:
    def test_fires_when_deploy_key_has_write_access(self) -> None:
        repo = _repo(
            "write-key",
            deploy_keys=[
                DeployKeyInfo(title="ci-key", read_only=False, created_at="2025-01-01T00:00:00Z"),
            ],
        )
        findings = ops_003_write_deploy_key(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OPS-003"
        assert f.pillar == Pillar.operations
        assert f.severity == Severity.info
        assert f.scope == Scope.repo
        assert f.repo_name == "write-key"

    def test_no_finding_when_all_keys_read_only(self) -> None:
        repo = _repo(
            "read-keys",
            deploy_keys=[
                DeployKeyInfo(title="ci-key", read_only=True, created_at="2025-01-01T00:00:00Z"),
                DeployKeyInfo(title="deploy", read_only=True, created_at="2025-02-01T00:00:00Z"),
            ],
        )
        findings = ops_003_write_deploy_key(_inv([repo]))
        assert findings == []

    def test_skips_when_deploy_keys_is_none(self) -> None:
        repo = _repo("not-scanned", deploy_keys=None)
        findings = ops_003_write_deploy_key(_inv([repo]))
        assert findings == []

    def test_no_finding_when_deploy_keys_is_empty(self) -> None:
        repo = _repo("no-keys", deploy_keys=[])
        findings = ops_003_write_deploy_key(_inv([repo]))
        assert findings == []

    def test_reports_each_write_key(self) -> None:
        """Each write-access deploy key produces a separate finding."""
        repo = _repo(
            "multi-write",
            deploy_keys=[
                DeployKeyInfo(title="ci-key", read_only=False, created_at="2025-01-01T00:00:00Z"),
                DeployKeyInfo(title="deploy", read_only=True, created_at="2025-02-01T00:00:00Z"),
                DeployKeyInfo(
                    title="admin-key", read_only=False, created_at="2025-03-01T00:00:00Z"
                ),
            ],
        )
        findings = ops_003_write_deploy_key(_inv([repo]))
        assert len(findings) == 2

    def test_fires_across_multiple_repos(self) -> None:
        repos = [
            _repo(
                "repo-a",
                deploy_keys=[
                    DeployKeyInfo(
                        title="key-a", read_only=False, created_at="2025-01-01T00:00:00Z"
                    ),
                ],
            ),
            _repo(
                "repo-b",
                deploy_keys=[
                    DeployKeyInfo(title="key-b", read_only=True, created_at="2025-01-01T00:00:00Z"),
                ],
            ),
            _repo(
                "repo-c",
                deploy_keys=[
                    DeployKeyInfo(
                        title="key-c", read_only=False, created_at="2025-01-01T00:00:00Z"
                    ),
                ],
            ),
        ]
        findings = ops_003_write_deploy_key(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"repo-a", "repo-c"}


# ===================================================================
# OPS-004: Permissive actions
# ===================================================================


class TestOps004PermissiveActions:
    def test_fires_when_allowed_actions_is_all(self) -> None:
        repo = _repo(
            "permissive-actions",
            actions_permissions=ActionsPermissions(allowed_actions="all"),
        )
        findings = ops_004_permissive_actions(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "OPS-004"
        assert f.pillar == Pillar.operations
        assert f.severity == Severity.info
        assert f.scope == Scope.repo
        assert f.repo_name == "permissive-actions"

    def test_no_finding_when_allowed_actions_is_selected(self) -> None:
        repo = _repo(
            "restricted",
            actions_permissions=ActionsPermissions(allowed_actions="selected"),
        )
        findings = ops_004_permissive_actions(_inv([repo]))
        assert findings == []

    def test_no_finding_when_allowed_actions_is_local_only(self) -> None:
        repo = _repo(
            "local-only",
            actions_permissions=ActionsPermissions(allowed_actions="local_only"),
        )
        findings = ops_004_permissive_actions(_inv([repo]))
        assert findings == []

    def test_skips_when_actions_permissions_is_none(self) -> None:
        repo = _repo("not-scanned", actions_permissions=None)
        findings = ops_004_permissive_actions(_inv([repo]))
        assert findings == []

    def test_fires_for_multiple_repos(self) -> None:
        repos = [
            _repo(
                "repo-a",
                actions_permissions=ActionsPermissions(allowed_actions="all"),
            ),
            _repo(
                "repo-b",
                actions_permissions=ActionsPermissions(allowed_actions="selected"),
            ),
            _repo(
                "repo-c",
                actions_permissions=ActionsPermissions(allowed_actions="all"),
            ),
        ]
        findings = ops_004_permissive_actions(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"repo-a", "repo-c"}
