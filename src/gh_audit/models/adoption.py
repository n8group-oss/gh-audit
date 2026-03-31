"""Adoption category models — Copilot, traffic, community health, Actions runs.

Design rule: ``None`` means "not scanned or not accessible".
             ``0`` / ``[]`` / ``False`` means "known value".
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CopilotInfo(BaseModel):
    """Copilot billing and usage metrics."""

    model_config = {"extra": "forbid"}

    total_seats: int = 0
    active_seats: int | None = None
    suggestions_count: int | None = None
    """Suggestions in the last 28 days."""
    acceptances_count: int | None = None
    """Acceptances in the last 28 days."""
    top_languages: list[str] = Field(default_factory=list)


class OrgCommunityHealth(BaseModel):
    """Aggregated community health across all scanned repos."""

    model_config = {"extra": "forbid"}

    repos_with_readme: int = 0
    repos_with_license: int = 0
    repos_with_contributing: int = 0
    repos_with_code_of_conduct: int = 0
    repos_with_issue_template: int = 0
    repos_with_pr_template: int = 0
    average_health_percentage: float = 0.0


class TrafficInfo(BaseModel):
    """Repository traffic data (last 14 days)."""

    model_config = {"extra": "forbid"}

    views_14d: int | None = None
    """Total views.  None if no push access."""
    unique_visitors_14d: int | None = None
    clones_14d: int | None = None
    unique_cloners_14d: int | None = None


class CommitActivityInfo(BaseModel):
    """Commit activity over the last ~90 days (13 weeks)."""

    model_config = {"extra": "forbid"}

    total_commits: int = 0
    active_weeks: int = 0
    """Number of weeks (out of ~13) with at least one commit."""


class CommunityProfileInfo(BaseModel):
    """Community profile / health metrics for a single repository."""

    model_config = {"extra": "forbid"}

    health_percentage: int = 0
    has_readme: bool = False
    has_contributing: bool = False
    has_license: bool = False
    has_code_of_conduct: bool = False
    has_issue_template: bool = False
    has_pull_request_template: bool = False


class ActionsRunSummary(BaseModel):
    """Actions workflow run summary for the last ~90 days."""

    model_config = {"extra": "forbid"}

    total_runs_90d: int = 0
    by_conclusion: dict[str, int] = Field(default_factory=dict)
    """Counts by conclusion, e.g. ``{"success": 120, "failure": 15}``."""


class AdoptionInventory(BaseModel):
    """Org-level adoption data."""

    model_config = {"extra": "forbid"}

    copilot: CopilotInfo | None = None
    """Copilot billing and metrics.  None if no Copilot subscription."""
    org_community_health: OrgCommunityHealth
