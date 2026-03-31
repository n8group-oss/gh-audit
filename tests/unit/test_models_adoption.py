"""Unit tests for adoption category models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.adoption import (
    ActionsRunSummary,
    AdoptionInventory,
    CommitActivityInfo,
    CommunityProfileInfo,
    CopilotInfo,
    OrgCommunityHealth,
    TrafficInfo,
)


class TestCopilotInfo:
    def test_defaults(self) -> None:
        info = CopilotInfo()
        assert info.total_seats == 0
        assert info.active_seats is None
        assert info.suggestions_count is None
        assert info.acceptances_count is None
        assert info.top_languages == []

    def test_full(self) -> None:
        info = CopilotInfo(
            total_seats=50,
            active_seats=40,
            suggestions_count=1200,
            acceptances_count=800,
            top_languages=["python", "typescript"],
        )
        assert info.total_seats == 50
        assert info.top_languages == ["python", "typescript"]

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            CopilotInfo(unknown_field="x")


class TestOrgCommunityHealth:
    def test_defaults(self) -> None:
        h = OrgCommunityHealth()
        assert h.repos_with_readme == 0
        assert h.repos_with_license == 0
        assert h.repos_with_contributing == 0
        assert h.repos_with_code_of_conduct == 0
        assert h.repos_with_issue_template == 0
        assert h.repos_with_pr_template == 0
        assert h.average_health_percentage == 0.0

    def test_full(self) -> None:
        h = OrgCommunityHealth(
            repos_with_readme=10,
            repos_with_license=8,
            repos_with_contributing=6,
            repos_with_code_of_conduct=4,
            repos_with_issue_template=5,
            repos_with_pr_template=3,
            average_health_percentage=72.5,
        )
        assert h.repos_with_readme == 10
        assert h.repos_with_license == 8
        assert h.repos_with_contributing == 6
        assert h.repos_with_code_of_conduct == 4
        assert h.repos_with_issue_template == 5
        assert h.repos_with_pr_template == 3
        assert h.average_health_percentage == 72.5

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            OrgCommunityHealth(unknown_field="x")


class TestTrafficInfo:
    def test_defaults(self) -> None:
        t = TrafficInfo()
        assert t.views_14d is None
        assert t.unique_visitors_14d is None
        assert t.clones_14d is None
        assert t.unique_cloners_14d is None

    def test_with_data(self) -> None:
        t = TrafficInfo(views_14d=100, unique_visitors_14d=50, clones_14d=20, unique_cloners_14d=10)
        assert t.views_14d == 100

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TrafficInfo(unknown_field="x")


class TestCommitActivityInfo:
    def test_defaults(self) -> None:
        c = CommitActivityInfo()
        assert c.total_commits == 0
        assert c.active_weeks == 0

    def test_full(self) -> None:
        c = CommitActivityInfo(total_commits=250, active_weeks=11)
        assert c.total_commits == 250
        assert c.active_weeks == 11

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            CommitActivityInfo(unknown_field="x")


class TestCommunityProfileInfo:
    def test_defaults(self) -> None:
        p = CommunityProfileInfo()
        assert p.health_percentage == 0
        assert p.has_readme is False
        assert p.has_contributing is False
        assert p.has_license is False
        assert p.has_code_of_conduct is False
        assert p.has_issue_template is False
        assert p.has_pull_request_template is False

    def test_full(self) -> None:
        p = CommunityProfileInfo(
            health_percentage=85,
            has_readme=True,
            has_contributing=True,
            has_license=True,
            has_code_of_conduct=True,
            has_issue_template=True,
            has_pull_request_template=True,
        )
        assert p.health_percentage == 85
        assert p.has_readme is True
        assert p.has_contributing is True
        assert p.has_license is True
        assert p.has_code_of_conduct is True
        assert p.has_issue_template is True
        assert p.has_pull_request_template is True

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            CommunityProfileInfo(unknown_field="x")


class TestActionsRunSummary:
    def test_defaults(self) -> None:
        s = ActionsRunSummary()
        assert s.total_runs_90d == 0
        assert s.by_conclusion == {}

    def test_with_data(self) -> None:
        s = ActionsRunSummary(
            total_runs_90d=138,
            by_conclusion={"success": 120, "failure": 15, "cancelled": 3},
        )
        assert s.total_runs_90d == 138
        assert s.by_conclusion["success"] == 120

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ActionsRunSummary(unknown_field="x")


class TestAdoptionInventory:
    def test_defaults(self) -> None:
        inv = AdoptionInventory(org_community_health=OrgCommunityHealth())
        assert inv.copilot is None
        assert inv.org_community_health.repos_with_readme == 0

    def test_with_copilot(self) -> None:
        inv = AdoptionInventory(
            copilot=CopilotInfo(total_seats=10),
            org_community_health=OrgCommunityHealth(repos_with_readme=5),
        )
        assert inv.copilot is not None
        assert inv.copilot.total_seats == 10
        assert inv.org_community_health.repos_with_readme == 5

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            AdoptionInventory(org_community_health=OrgCommunityHealth(), unknown="x")
