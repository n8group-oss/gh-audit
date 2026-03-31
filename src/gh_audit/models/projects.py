"""ProjectInfo — GitHub Projects (v2) entry."""

from __future__ import annotations

from pydantic import BaseModel


class ProjectInfo(BaseModel):
    """A single GitHub Project (v2) discovered in the organization."""

    model_config = {"extra": "forbid"}

    title: str
    """Project title."""

    item_count: int = 0
    """Number of items (issues, PRs, drafts) in the project."""

    closed: bool = False
    """True if the project has been closed."""
