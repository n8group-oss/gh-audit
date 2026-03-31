"""ActionsInfo and WorkflowInfo — GitHub Actions inventory for one repository."""

from __future__ import annotations

from pydantic import BaseModel, Field


class WorkflowInfo(BaseModel):
    """Metadata for a single GitHub Actions workflow file."""

    model_config = {"extra": "forbid"}

    name: str
    """Workflow name (from the ``name:`` field or filename)."""

    path: str
    """Path within the repository (e.g. ``.github/workflows/ci.yml``)."""

    state: str = "active"
    """Workflow state as returned by the API (``active``, ``disabled_manually``, etc.)."""


class ActionsInfo(BaseModel):
    """GitHub Actions summary for one repository."""

    model_config = {"extra": "forbid"}

    has_workflows: bool = False
    """True if any workflow files were found."""

    workflow_count: int = 0
    """Number of workflow files discovered."""

    workflows: list[WorkflowInfo] = Field(default_factory=list)
    """Per-workflow metadata (populated at listing level)."""

    actions_used: list[str] = Field(default_factory=list)
    """Deduplicated action references extracted from workflow contents (deep parse)."""

    uses_self_hosted_runners: bool = False
    """True if any workflow references a self-hosted runner label."""

    analysis_level: str = "listing"
    """Depth of analysis: ``"listing"`` (headers only) or ``"parsed"`` (full content)."""
