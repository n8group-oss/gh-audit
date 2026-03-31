"""Security detail models: full alert info, SBOM, code scanning setup, security configuration.

Design rule: ``None`` on a security detail field means "security category not scanned".
             An empty list means "scanned and found nothing".
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Dependabot alert info
# ---------------------------------------------------------------------------


class DependabotAlertInfo(BaseModel):
    """Detail for a single Dependabot alert."""

    model_config = {"extra": "forbid"}

    severity: str
    """Alert severity: ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``."""

    package_name: str
    """Name of the vulnerable package."""

    manifest_path: str
    """Path to the manifest file declaring this dependency."""

    state: str
    """Alert state: ``"open"``, ``"dismissed"``, ``"fixed"``, or ``"auto_dismissed"``."""

    ghsa_id: str | None = None
    """GitHub Security Advisory ID, if available."""

    cve_id: str | None = None
    """CVE identifier, if available."""

    fixed_version: str | None = None
    """Version that fixes the vulnerability, if known."""


# ---------------------------------------------------------------------------
# Code scanning alert info
# ---------------------------------------------------------------------------


class CodeScanningAlertInfo(BaseModel):
    """Detail for a single code scanning alert."""

    model_config = {"extra": "forbid"}

    rule_id: str
    """Identifier of the rule that triggered this alert."""

    severity: str | None = None
    """Rule severity (may differ from security severity)."""

    security_severity: str | None = None
    """Security severity: ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``."""

    tool_name: str
    """Name of the analysis tool that produced this alert."""

    state: str
    """Alert state: ``"open"``, ``"dismissed"``, or ``"fixed"``."""

    dismissed_reason: str | None = None
    """Reason for dismissal, if dismissed."""


# ---------------------------------------------------------------------------
# Secret scanning alert info
# ---------------------------------------------------------------------------


class SecretScanningAlertInfo(BaseModel):
    """Detail for a single secret scanning alert."""

    model_config = {"extra": "forbid"}

    secret_type: str
    """Type of secret detected (e.g. ``"github_personal_access_token"``)."""

    secret_type_display_name: str | None = None
    """Human-readable display name for the secret type."""

    state: str
    """Alert state: ``"open"`` or ``"resolved"``."""

    resolution: str | None = None
    """Resolution status if resolved (e.g. ``"false_positive"``, ``"revoked"``)."""

    push_protection_bypassed: bool = False
    """Whether push protection was bypassed for this secret."""


# ---------------------------------------------------------------------------
# SBOM summary
# ---------------------------------------------------------------------------


class SBOMSummary(BaseModel):
    """Summary of the Software Bill of Materials for a repository."""

    model_config = {"extra": "forbid"}

    dependency_count: int = 0
    """Total number of dependencies in the SBOM."""

    package_managers: list[str] = Field(default_factory=list)
    """Package managers/ecosystems found (e.g. ``["npm", "pip"]``)."""


# ---------------------------------------------------------------------------
# Code scanning setup
# ---------------------------------------------------------------------------


class CodeScanningSetup(BaseModel):
    """Code scanning default setup configuration for a repository."""

    model_config = {"extra": "forbid"}

    default_setup_enabled: bool = False
    """Whether the default code scanning setup is enabled."""

    languages: list[str] = Field(default_factory=list)
    """Languages configured for code scanning."""


# ---------------------------------------------------------------------------
# Top-level security detail (per-repo)
# ---------------------------------------------------------------------------


class SecurityDetail(BaseModel):
    """Comprehensive security detail for a single repository.

    Attached to ``RepositoryInventoryItem.security_detail``.
    """

    model_config = {"extra": "forbid"}

    dependabot_alerts: list[DependabotAlertInfo] = Field(default_factory=list)
    """Full Dependabot alert details."""

    code_scanning_alerts: list[CodeScanningAlertInfo] = Field(default_factory=list)
    """Full code scanning alert details."""

    secret_scanning_alerts: list[SecretScanningAlertInfo] = Field(default_factory=list)
    """Full secret scanning alert details."""

    sbom_summary: SBOMSummary | None = None
    """SBOM summary; None if SBOM not accessible."""

    code_scanning_setup: CodeScanningSetup | None = None
    """Code scanning default setup config; None if not accessible."""

    security_configuration_name: str | None = None
    """Name of the security configuration attached to this repository."""
