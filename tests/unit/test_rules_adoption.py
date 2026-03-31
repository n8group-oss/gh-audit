"""Unit tests for adoption assessment rules (ADO-001 through ADO-003)."""

from __future__ import annotations

from datetime import datetime, timezone


from gh_audit.models.adoption import (
    ActionsRunSummary,
    CommitActivityInfo,
    CommunityProfileInfo,
)
from gh_audit.models.finding import Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary
from gh_audit.rules.adoption import (
    ado_001_no_readme,
    ado_002_stale_repo,
    ado_003_low_actions_success_rate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo(
    name: str = "test-repo",
    *,
    community_profile: CommunityProfileInfo | None = None,
    commit_activity_90d: CommitActivityInfo | None = None,
    actions_run_summary: ActionsRunSummary | None = None,
    archived: bool = False,
) -> RepositoryInventoryItem:
    """Build a minimal RepositoryInventoryItem for adoption rule testing."""
    kwargs: dict = {
        "name": name,
        "full_name": f"testorg/{name}",
        "visibility": "private",
        "archived": archived,
    }
    if community_profile is not None:
        kwargs["community_profile"] = community_profile
    if commit_activity_90d is not None:
        kwargs["commit_activity_90d"] = commit_activity_90d
    if actions_run_summary is not None:
        kwargs["actions_run_summary"] = actions_run_summary
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
            active_categories=["adoption"],
        ),
        summary=InventorySummary(total_repos=len(repos)),
        repositories=repos,
        users=OrgMemberSummary(total=0, admins=0, members=0),
    )


# ===================================================================
# ADO-001: No README
# ===================================================================


class TestAdo001NoReadme:
    def test_fires_when_readme_missing(self) -> None:
        repo = _repo(
            "no-readme",
            community_profile=CommunityProfileInfo(has_readme=False),
        )
        findings = ado_001_no_readme(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "ADO-001"
        assert f.pillar == Pillar.adoption
        assert f.severity == Severity.info
        assert f.scope == Scope.repo
        assert f.repo_name == "no-readme"

    def test_no_finding_when_readme_present(self) -> None:
        repo = _repo(
            "has-readme",
            community_profile=CommunityProfileInfo(has_readme=True),
        )
        findings = ado_001_no_readme(_inv([repo]))
        assert findings == []

    def test_skips_when_community_profile_is_none(self) -> None:
        repo = _repo("not-scanned", community_profile=None)
        findings = ado_001_no_readme(_inv([repo]))
        assert findings == []


# ===================================================================
# ADO-002: Stale repo
# ===================================================================


class TestAdo002StaleRepo:
    def test_fires_when_zero_commits(self) -> None:
        repo = _repo(
            "stale-repo",
            commit_activity_90d=CommitActivityInfo(total_commits=0, active_weeks=0),
        )
        findings = ado_002_stale_repo(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "ADO-002"
        assert f.pillar == Pillar.adoption
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "stale-repo"

    def test_no_finding_when_commits_exist(self) -> None:
        repo = _repo(
            "active-repo",
            commit_activity_90d=CommitActivityInfo(total_commits=10, active_weeks=3),
        )
        findings = ado_002_stale_repo(_inv([repo]))
        assert findings == []

    def test_skips_when_commit_activity_is_none(self) -> None:
        repo = _repo("not-scanned", commit_activity_90d=None)
        findings = ado_002_stale_repo(_inv([repo]))
        assert findings == []

    def test_skips_when_repo_is_archived(self) -> None:
        repo = _repo(
            "archived-repo",
            commit_activity_90d=CommitActivityInfo(total_commits=0, active_weeks=0),
            archived=True,
        )
        findings = ado_002_stale_repo(_inv([repo]))
        assert findings == []


# ===================================================================
# ADO-003: Low Actions success rate
# ===================================================================


class TestAdo003LowActionsSuccessRate:
    def test_fires_when_success_rate_below_50_percent(self) -> None:
        repo = _repo(
            "failing-actions",
            actions_run_summary=ActionsRunSummary(
                total_runs_90d=100,
                by_conclusion={"success": 30, "failure": 70},
            ),
        )
        findings = ado_003_low_actions_success_rate(_inv([repo]))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "ADO-003"
        assert f.pillar == Pillar.adoption
        assert f.severity == Severity.warning
        assert f.scope == Scope.repo
        assert f.repo_name == "failing-actions"
        assert "30" in f.title  # percentage in title

    def test_no_finding_when_success_rate_at_50_percent(self) -> None:
        repo = _repo(
            "okay-actions",
            actions_run_summary=ActionsRunSummary(
                total_runs_90d=100,
                by_conclusion={"success": 50, "failure": 50},
            ),
        )
        findings = ado_003_low_actions_success_rate(_inv([repo]))
        assert findings == []

    def test_no_finding_when_success_rate_above_50_percent(self) -> None:
        repo = _repo(
            "good-actions",
            actions_run_summary=ActionsRunSummary(
                total_runs_90d=100,
                by_conclusion={"success": 80, "failure": 20},
            ),
        )
        findings = ado_003_low_actions_success_rate(_inv([repo]))
        assert findings == []

    def test_skips_when_actions_run_summary_is_none(self) -> None:
        repo = _repo("not-scanned", actions_run_summary=None)
        findings = ado_003_low_actions_success_rate(_inv([repo]))
        assert findings == []

    def test_skips_when_total_runs_is_zero(self) -> None:
        repo = _repo(
            "no-runs",
            actions_run_summary=ActionsRunSummary(
                total_runs_90d=0,
                by_conclusion={},
            ),
        )
        findings = ado_003_low_actions_success_rate(_inv([repo]))
        assert findings == []

    def test_fires_when_no_successes_in_by_conclusion(self) -> None:
        repo = _repo(
            "all-failures",
            actions_run_summary=ActionsRunSummary(
                total_runs_90d=10,
                by_conclusion={"failure": 10},
            ),
        )
        findings = ado_003_low_actions_success_rate(_inv([repo]))
        assert len(findings) == 1
        assert "0" in findings[0].title  # 0% success rate
