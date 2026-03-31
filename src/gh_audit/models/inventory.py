"""Root inventory models — Inventory, InventoryMetadata, InventorySummary.

These are the top-level data contracts written to disk (JSON) after each scan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from gh_audit.models.adoption import AdoptionInventory
from gh_audit.models.enterprise import EnterpriseInventory
from gh_audit.models.governance import GovernanceInventory
from gh_audit.models.operations import OperationsInventory
from gh_audit.models.packages import PackageInfo
from gh_audit.models.projects import ProjectInfo
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary


# ---------------------------------------------------------------------------
# Metadata block
# ---------------------------------------------------------------------------


class InventoryMetadata(BaseModel):
    """Scan provenance and configuration snapshot."""

    model_config = {"extra": "forbid"}

    schema_version: str
    """Inventory schema version (semver string, e.g. ``"1.0"``)."""

    generated_at: datetime
    """UTC timestamp when this inventory was produced."""

    tool_version: str
    """gh-audit version string."""

    organization: str
    """GitHub organization login that was scanned."""

    auth_method: str
    """Authentication method used: ``"pat"`` or ``"github_app"``."""

    api_url: str = "https://api.github.com"
    """REST API base URL (overridable for GHES)."""

    scan_profile: str
    """Scan depth profile: ``'standard'``, ``'deep'``, or ``'total'``."""

    scan_options: dict[str, Any] = Field(default_factory=dict)
    """Effective scan flags at the time of the run (e.g. ``scan_large_files``)."""

    scan_warnings: list[str] = Field(default_factory=list)
    """Org-level warnings encountered during the scan."""

    active_categories: list[str] = Field(default_factory=list)
    """Categories that were enabled for this scan (e.g. ``["governance", "security"]``)."""

    enterprise_slug: str | None = None
    """Enterprise slug when scanning a GHES or EMU instance; ``None`` for github.com."""


# ---------------------------------------------------------------------------
# Summary block
# ---------------------------------------------------------------------------


class InventorySummary(BaseModel):
    """Aggregated counts across all repositories and resources."""

    model_config = {"extra": "forbid"}

    # Repository counts
    total_repos: int = 0
    public_repos: int = 0
    private_repos: int = 0
    internal_repos: int = 0
    archived_repos: int = 0
    forked_repos: int = 0
    template_repos: int = 0

    # Size / activity
    total_size_bytes: int = 0
    total_branches: int = 0
    total_prs: int = 0
    total_issues: int = 0

    # Large files / LFS
    repos_with_large_files: int = 0
    repos_with_lfs: int = 0

    # Actions
    repos_with_workflows: int = 0
    total_workflow_count: int = 0
    repos_with_self_hosted_runners: int = 0

    # Security
    repos_with_dependabot: int = 0
    repos_with_code_scanning: int = 0
    repos_with_secret_scanning: int = 0

    # Packages
    total_packages: int = 0
    packages_by_type: dict[str, int] = Field(default_factory=dict)
    """Package counts keyed by registry type (e.g. ``{"npm": 3, "pypi": 1}``)."""

    # Projects
    total_projects: int = 0


# ---------------------------------------------------------------------------
# Root inventory
# ---------------------------------------------------------------------------


class Inventory(BaseModel):
    """Complete gh-audit inventory for one organization scan."""

    model_config = {"extra": "forbid"}

    metadata: InventoryMetadata
    summary: InventorySummary
    repositories: list[RepositoryInventoryItem]
    users: OrgMemberSummary
    packages: list[PackageInfo] = Field(default_factory=list)
    projects: list[ProjectInfo] = Field(default_factory=list)
    governance: GovernanceInventory | None = None
    """Governance data (teams, rulesets, policies, etc.).  None = governance category not scanned."""

    operations: OperationsInventory | None = None
    """Operations data (runners, apps, webhooks, etc.).  None = operations category not scanned."""

    adoption: AdoptionInventory | None = None
    """Adoption data (Copilot, traffic, community health).  None = adoption category not scanned."""

    enterprise: EnterpriseInventory | None = None
    """Enterprise data (billing, policies, SAML, etc.).  None = enterprise category not scanned."""
