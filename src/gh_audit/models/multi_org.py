"""Multi-organization config and summary models.

Supports YAML-driven multi-org scanning:

- ``OrgEntry`` — per-organization config with optional auth overrides.
- ``MultiOrgConfig`` — root config model (list of OrgEntry + shared defaults).
- ``OrgScanResult`` — per-org result after a scan run.
- ``SummaryTotals`` — aggregated totals across successful orgs.
- ``MultiOrgSummary`` — cross-org summary with a computed ``totals`` property.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, computed_field, model_validator


class OrgEntry(BaseModel):
    """Per-organization configuration entry."""

    model_config = {"extra": "forbid"}

    # Required
    name: str
    """GitHub organization login name."""

    # PAT auth
    token: str | None = None
    """Personal Access Token."""

    # App auth
    app_id: int | None = None
    """GitHub App ID."""

    private_key_path: str | None = None
    """Path to the GitHub App private key (PEM file)."""

    installation_id: int | None = None
    """GitHub App installation ID for this organization."""

    # Per-org overrides (all optional — None means use defaults)
    api_url: str | None = None
    """Per-org API URL override (e.g. for GHES)."""

    scan_profile: str | None = None
    """Per-org scan profile override. None = use defaults."""

    scan_large_files: bool | None = None
    """Per-org large-file scan override."""

    scan_workflow_contents: bool | None = None
    """Per-org workflow-contents scan override."""

    security_alert_counts: bool | None = None
    """Per-org security alert counts override."""

    repo_limit: int | None = None
    """Per-org max repositories limit override."""

    concurrency: int | None = None
    """Per-org concurrency override."""

    include_archived: bool | None = None
    """Per-org archived repositories override."""

    categories: list[str] | None = None
    """Per-org discovery categories override."""

    enterprise_slug: str | None = None
    """Per-org enterprise slug for enterprise category."""

    @model_validator(mode="after")
    def _require_auth(self) -> "OrgEntry":
        """Enforce that exactly one auth method is fully supplied."""
        has_pat = self.token is not None
        has_app = (
            self.app_id is not None
            and self.private_key_path is not None
            and self.installation_id is not None
        )
        if has_pat and has_app:
            raise ValueError(
                f"Organization '{self.name}': provide either 'token' (PAT) or "
                "GitHub App credentials, not both."
            )
        if not has_pat and not has_app:
            raise ValueError(
                f"Organization '{self.name}': authentication credentials are required. "
                "Provide either 'token' (PAT) or all three of "
                "'app_id', 'private_key_path', and 'installation_id' (GitHub App)."
            )
        return self


class MultiOrgConfig(BaseModel):
    """Root multi-org YAML config model."""

    model_config = {"extra": "forbid"}

    defaults: dict[str, Any] = Field(default_factory=dict)
    """Shared defaults applied to all organizations unless overridden."""

    organizations: list[OrgEntry] = Field(min_length=1)
    """List of organizations to scan. At least one is required."""


class OrgScanResult(BaseModel):
    """Result record for a single organization scan."""

    model_config = {"extra": "forbid"}

    name: str
    """Organization login name."""

    status: str
    """'success' or 'failed'."""

    error: str | None = None
    """Error message populated on failure."""

    scan_profile: str | None = None
    """Scan profile used for this org."""

    auth_method: str | None = None
    """Authentication method used ('pat' or 'github_app')."""

    total_repos: int = 0
    total_size_bytes: int = 0
    total_members: int = 0
    total_workflows: int = 0
    total_issues: int = 0
    total_packages: int = 0
    total_projects: int = 0
    warnings_count: int = 0
    duration_seconds: float = 0.0


class SummaryTotals(BaseModel):
    """Aggregated totals across all successfully scanned organizations."""

    organizations_scanned: int = 0
    organizations_succeeded: int = 0
    organizations_failed: int = 0

    total_repos: int = 0
    total_size_bytes: int = 0
    total_members: int = 0
    total_workflows: int = 0
    total_issues: int = 0
    total_packages: int = 0
    total_projects: int = 0


class MultiOrgSummary(BaseModel):
    """Cross-organization scan summary."""

    schema_version: str = "1.0.0"

    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    """UTC timestamp when the summary was generated."""

    tool_version: str
    """gh-audit version string (from __about__)."""

    config_file: str
    """Path to the multi-org config file used for this run."""

    organizations: list[OrgScanResult]
    """Per-organization scan results."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def totals(self) -> SummaryTotals:
        """Compute aggregated totals from organizations list.

        Only successful organizations contribute to numeric totals.
        """
        successful = [o for o in self.organizations if o.status == "success"]
        failed = [o for o in self.organizations if o.status != "success"]

        return SummaryTotals(
            organizations_scanned=len(self.organizations),
            organizations_succeeded=len(successful),
            organizations_failed=len(failed),
            total_repos=sum(o.total_repos for o in successful),
            total_size_bytes=sum(o.total_size_bytes for o in successful),
            total_members=sum(o.total_members for o in successful),
            total_workflows=sum(o.total_workflows for o in successful),
            total_issues=sum(o.total_issues for o in successful),
            total_packages=sum(o.total_packages for o in successful),
            total_projects=sum(o.total_projects for o in successful),
        )
