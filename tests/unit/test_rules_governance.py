"""Unit tests for governance assessment rules (GOV-001 through GOV-004)."""

from __future__ import annotations

from datetime import datetime, timezone


from gh_audit.models.finding import Pillar, Scope, Severity
from gh_audit.models.governance import GovernanceInventory, OrgPolicies, RepoTeamAccess
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import BranchProtectionSummary, RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary
from gh_audit.rules.governance import (
    gov_001_no_branch_protection,
    gov_002_no_teams_assigned,
    gov_003_2fa_not_required,
    gov_004_permissive_default_permission,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo(
    name: str = "test-repo",
    *,
    branch_protection: BranchProtectionSummary | None = None,
    teams_with_access: list[RepoTeamAccess] | None = None,
) -> RepositoryInventoryItem:
    """Build a minimal RepositoryInventoryItem for governance rule testing."""
    kwargs: dict = {
        "name": name,
        "full_name": f"testorg/{name}",
        "visibility": "private",
    }
    if branch_protection is not None:
        kwargs["branch_protection"] = branch_protection
    if teams_with_access is not None:
        kwargs["teams_with_access"] = teams_with_access
    return RepositoryInventoryItem(**kwargs)


def _inv(
    repos: list[RepositoryInventoryItem] | None = None,
    *,
    governance: GovernanceInventory | None = None,
) -> Inventory:
    """Build a minimal Inventory wrapping repos and optional governance data."""
    repos = repos or []
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization="testorg",
            auth_method="pat",
            scan_profile="total",
            active_categories=["governance"],
        ),
        summary=InventorySummary(total_repos=len(repos)),
        repositories=repos,
        users=OrgMemberSummary(total=0, admins=0, members=0),
        governance=governance,
    )


# ===================================================================
# GOV-001: No branch protection
# ===================================================================


class TestGov001NoBranchProtection:
    def test_fires_when_no_protection_and_no_rulesets(self) -> None:
        repo = _repo(
            "unprotected",
            branch_protection=BranchProtectionSummary(protected_branches=0, ruleset_count=0),
        )
        findings = gov_001_no_branch_protection(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "GOV-001"
        assert f.pillar == Pillar.governance
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "unprotected"

    def test_no_finding_when_protected_branches_exist(self) -> None:
        repo = _repo(
            "protected",
            branch_protection=BranchProtectionSummary(protected_branches=1, ruleset_count=0),
        )
        findings = gov_001_no_branch_protection(_inv([repo]))
        assert findings == []

    def test_no_finding_when_rulesets_exist(self) -> None:
        repo = _repo(
            "has-rulesets",
            branch_protection=BranchProtectionSummary(protected_branches=0, ruleset_count=2),
        )
        findings = gov_001_no_branch_protection(_inv([repo]))
        assert findings == []

    def test_skips_when_ruleset_count_is_none(self) -> None:
        """When ruleset_count is None (unknown), skip -- can't confirm no rulesets."""
        repo = _repo(
            "unknown-rulesets",
            branch_protection=BranchProtectionSummary(protected_branches=0, ruleset_count=None),
        )
        findings = gov_001_no_branch_protection(_inv([repo]))
        assert findings == []

    def test_fires_for_multiple_unprotected_repos(self) -> None:
        repos = [
            _repo(
                "unprotected-a",
                branch_protection=BranchProtectionSummary(protected_branches=0, ruleset_count=0),
            ),
            _repo(
                "protected",
                branch_protection=BranchProtectionSummary(protected_branches=1, ruleset_count=0),
            ),
            _repo(
                "unprotected-b",
                branch_protection=BranchProtectionSummary(protected_branches=0, ruleset_count=0),
            ),
        ]
        findings = gov_001_no_branch_protection(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"unprotected-a", "unprotected-b"}


# ===================================================================
# GOV-002: No teams assigned
# ===================================================================


class TestGov002NoTeamsAssigned:
    def test_fires_when_teams_list_is_empty(self) -> None:
        repo = _repo("no-teams", teams_with_access=[])
        findings = gov_002_no_teams_assigned(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "GOV-002"
        assert f.pillar == Pillar.governance
        assert f.severity == Severity.info
        assert f.scope == Scope.repo
        assert f.repo_name == "no-teams"

    def test_no_finding_when_teams_assigned(self) -> None:
        repo = _repo(
            "has-teams",
            teams_with_access=[
                RepoTeamAccess(team_slug="devs", permission="push"),
            ],
        )
        findings = gov_002_no_teams_assigned(_inv([repo]))
        assert findings == []

    def test_skips_when_teams_is_none(self) -> None:
        """When teams_with_access is None (not scanned), skip."""
        repo = _repo("not-scanned", teams_with_access=None)
        findings = gov_002_no_teams_assigned(_inv([repo]))
        assert findings == []

    def test_fires_for_multiple_teamless_repos(self) -> None:
        repos = [
            _repo("no-teams-a", teams_with_access=[]),
            _repo(
                "has-teams",
                teams_with_access=[
                    RepoTeamAccess(team_slug="ops", permission="admin"),
                ],
            ),
            _repo("no-teams-b", teams_with_access=[]),
        ]
        findings = gov_002_no_teams_assigned(_inv(repos))
        assert len(findings) == 2
        names = {f.repo_name for f in findings}
        assert names == {"no-teams-a", "no-teams-b"}


# ===================================================================
# GOV-003: 2FA not required
# ===================================================================


class TestGov0032faNotRequired:
    def test_fires_when_2fa_is_false(self) -> None:
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(two_factor_requirement_enabled=False),
            ),
        )
        findings = gov_003_2fa_not_required(inv)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "GOV-003"
        assert f.pillar == Pillar.governance
        assert f.severity == Severity.critical
        assert f.scope == Scope.org
        assert f.repo_name is None

    def test_no_finding_when_2fa_is_true(self) -> None:
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(two_factor_requirement_enabled=True),
            ),
        )
        findings = gov_003_2fa_not_required(inv)
        assert findings == []

    def test_no_finding_when_2fa_is_none(self) -> None:
        """When 2FA status is None (unknown), do not flag."""
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(two_factor_requirement_enabled=None),
            ),
        )
        findings = gov_003_2fa_not_required(inv)
        assert findings == []

    def test_returns_empty_when_governance_is_none(self) -> None:
        inv = _inv(governance=None)
        findings = gov_003_2fa_not_required(inv)
        assert findings == []


# ===================================================================
# GOV-004: Permissive default repository permission
# ===================================================================


class TestGov004PermissiveDefaultPermission:
    def test_fires_when_default_is_write(self) -> None:
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(default_repository_permission="write"),
            ),
        )
        findings = gov_004_permissive_default_permission(inv)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "GOV-004"
        assert f.pillar == Pillar.governance
        assert f.severity == Severity.warning
        assert f.scope == Scope.org
        assert f.repo_name is None

    def test_fires_when_default_is_admin(self) -> None:
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(default_repository_permission="admin"),
            ),
        )
        findings = gov_004_permissive_default_permission(inv)
        assert len(findings) == 1
        assert findings[0].rule_id == "GOV-004"

    def test_no_finding_when_default_is_read(self) -> None:
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(default_repository_permission="read"),
            ),
        )
        findings = gov_004_permissive_default_permission(inv)
        assert findings == []

    def test_no_finding_when_default_is_none(self) -> None:
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(default_repository_permission=None),
            ),
        )
        findings = gov_004_permissive_default_permission(inv)
        assert findings == []

    def test_returns_empty_when_governance_is_none(self) -> None:
        inv = _inv(governance=None)
        findings = gov_004_permissive_default_permission(inv)
        assert findings == []

    def test_no_finding_when_default_is_pull(self) -> None:
        """'pull' is a read-equivalent and should not trigger."""
        inv = _inv(
            governance=GovernanceInventory(
                org_policies=OrgPolicies(default_repository_permission="pull"),
            ),
        )
        findings = gov_004_permissive_default_permission(inv)
        assert findings == []
