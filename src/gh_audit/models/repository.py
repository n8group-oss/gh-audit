"""RepositoryInventoryItem and associated sub-models.

Design rule: ``None`` means "not scanned or not accessible".
             ``0``    means "known to be zero".
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from gh_audit.models.actions import ActionsInfo
from gh_audit.models.adoption import (
    ActionsRunSummary,
    CommitActivityInfo,
    CommunityProfileInfo,
    TrafficInfo,
)
from gh_audit.models.governance import RepoTeamAccess, RulesetDetail
from gh_audit.models.operations import (
    ActionsPermissions,
    DeployKeyInfo,
    EnvironmentInfo,
    WebhookInfo,
)
from gh_audit.models.security import SecurityInfo
from gh_audit.models.security_detail import SecurityDetail


# ---------------------------------------------------------------------------
# Large-file scan sub-models
# ---------------------------------------------------------------------------


class LargeFileInfo(BaseModel):
    """A single file that exceeded the large-file threshold."""

    model_config = {"extra": "forbid"}

    path: str
    """Repository-relative path of the large file."""

    size_bytes: int
    """File size in bytes."""


class LargeFileScan(BaseModel):
    """Metadata and results for the large-file scan pass."""

    model_config = {"extra": "forbid"}

    enabled: bool = False
    """Was this scan requested (i.e. ``scan_large_files`` flag was set)?"""

    completed: bool = False
    """Did the scan finish without error?"""

    truncated: bool = False
    """Was the repository tree response truncated before full traversal?"""

    threshold_bytes: int = 104857600
    """Minimum file size to report (default 100 MB)."""

    files: list[LargeFileInfo] = Field(default_factory=list)
    """Files whose size exceeded ``threshold_bytes``."""


# ---------------------------------------------------------------------------
# LFS sub-model
# ---------------------------------------------------------------------------


class LFSInfo(BaseModel):
    """Git LFS presence information for one repository."""

    model_config = {"extra": "forbid"}

    has_lfs: bool = False
    """True if a ``.gitattributes`` with LFS patterns was detected."""

    patterns: list[str] = Field(default_factory=list)
    """LFS filter patterns found in ``.gitattributes``."""


# ---------------------------------------------------------------------------
# Branch protection sub-model
# ---------------------------------------------------------------------------


class BranchProtectionSummary(BaseModel):
    """Summary of branch protection configuration."""

    model_config = {"extra": "forbid"}

    protected_branches: int = 0
    """Number of branches with protection rules."""

    ruleset_count: int | None = None
    """Number of repository rulesets.  None = not checked or forbidden."""


# ---------------------------------------------------------------------------
# Root per-repository model
# ---------------------------------------------------------------------------


class RepositoryInventoryItem(BaseModel):
    """Full inventory record for a single GitHub repository."""

    model_config = {"extra": "forbid"}

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    name: str
    """Repository name (without owner prefix)."""

    full_name: str
    """Full ``owner/name`` slug."""

    description: str | None = None
    """Repository description (may be None)."""

    visibility: str
    """Visibility: ``public``, ``private``, or ``internal``."""

    # ------------------------------------------------------------------
    # Repository flags
    # ------------------------------------------------------------------

    archived: bool = False
    fork: bool = False
    is_template: bool = False

    # ------------------------------------------------------------------
    # Language / classification
    # ------------------------------------------------------------------

    language: str | None = None
    """Primary language detected by GitHub."""

    topics: list[str] = Field(default_factory=list)
    """Repository topic tags."""

    default_branch: str | None = None

    # ------------------------------------------------------------------
    # Size
    # ------------------------------------------------------------------

    size_bytes: int = 0
    """Repository size in bytes (as reported by the API)."""

    # ------------------------------------------------------------------
    # Activity counts — 0 means known-zero
    # ------------------------------------------------------------------

    branch_count: int = 0

    pr_count_open: int = 0
    pr_count_closed: int = 0
    pr_count_merged: int = 0

    issue_count_open: int = 0
    issue_count_closed: int = 0

    issue_label_distribution: dict[str, int] = Field(default_factory=dict)
    """Mapping of label name → open issue count."""

    # ------------------------------------------------------------------
    # Sub-models
    # ------------------------------------------------------------------

    large_file_scan: LargeFileScan = Field(default_factory=LargeFileScan)
    lfs_info: LFSInfo = Field(default_factory=LFSInfo)
    actions: ActionsInfo = Field(default_factory=ActionsInfo)
    security: SecurityInfo = Field(default_factory=SecurityInfo)
    branch_protection: BranchProtectionSummary = Field(default_factory=BranchProtectionSummary)

    # ------------------------------------------------------------------
    # Governance (null = governance category not scanned)
    # ------------------------------------------------------------------

    rulesets_detail: list[RulesetDetail] | None = None
    """Full ruleset definitions for this repository.  None = not scanned."""

    custom_properties: dict[str, Any] | None = None
    """Custom property values set on this repository.  None = not scanned."""

    teams_with_access: list[RepoTeamAccess] | None = None
    """Teams that have explicit access to this repository.  None = not scanned."""

    # ------------------------------------------------------------------
    # Operations (null = operations category not scanned)
    # ------------------------------------------------------------------

    environments: list[EnvironmentInfo] | None = None
    """Deployment environments for this repository.  None = not scanned."""

    deploy_keys: list[DeployKeyInfo] | None = None
    """Deploy keys configured on this repository.  None = not scanned."""

    repo_webhooks: list[WebhookInfo] | None = None
    """Webhooks configured on this repository.  None = not scanned."""

    repo_secrets_count: int | None = None
    """Number of repository-level Actions secrets.  None = not scanned."""

    repo_variables_count: int | None = None
    """Number of repository-level Actions variables.  None = not scanned."""

    actions_permissions: ActionsPermissions | None = None
    """Actions permissions configuration for this repository.  None = not scanned."""

    # ------------------------------------------------------------------
    # Security detail (null = security category not scanned)
    # ------------------------------------------------------------------

    security_detail: SecurityDetail | None = None
    """Comprehensive security alert details for this repository.  None = not scanned."""

    # ------------------------------------------------------------------
    # Adoption (null = adoption category not scanned)
    # ------------------------------------------------------------------

    traffic: TrafficInfo | None = None
    """Traffic data (last 14 days).  None = adoption not scanned."""

    commit_activity_90d: CommitActivityInfo | None = None
    """Commit activity over ~90 days.  None = adoption not scanned."""

    community_profile: CommunityProfileInfo | None = None
    """Community health profile.  None = adoption not scanned."""

    actions_run_summary: ActionsRunSummary | None = None
    """Actions run summary (~90 days).  None = adoption not scanned."""

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    warnings: list[str] = Field(default_factory=list)
    """Non-fatal issues encountered while scanning this repository."""
