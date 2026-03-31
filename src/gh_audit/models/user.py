"""OrgMemberSummary — organization membership counts."""

from __future__ import annotations

from pydantic import BaseModel


class OrgMemberSummary(BaseModel):
    """Summary of organization membership numbers."""

    model_config = {"extra": "forbid"}

    total: int = 0
    """Total number of members (all roles)."""

    admins: int = 0
    """Members with org-owner / admin role."""

    members: int = 0
    """Regular members."""

    outside_collaborators: int = 0
    """Outside collaborators (not formal org members)."""
