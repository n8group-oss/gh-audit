"""Enterprise category models — billing, policies, SAML, IP allow list, teams.

Design rule: ``None`` means "not scanned or not accessible".
             ``0`` / ``[]`` / ``False`` means "known value".
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from gh_audit.models.governance import RulesetDetail


class EnterpriseBilling(BaseModel):
    """Enterprise billing and license usage."""

    model_config = {"extra": "forbid"}

    total_licenses: int = 0
    used_licenses: int = 0
    bandwidth_usage_gb: float = 0.0
    bandwidth_quota_gb: float = 0.0
    storage_usage_gb: float = 0.0
    storage_quota_gb: float = 0.0


class EnterprisePolicies(BaseModel):
    """Enterprise-level policy settings."""

    model_config = {"extra": "forbid"}

    default_repository_permission: str | None = None
    members_can_create_repositories: str | None = None
    """``"all"``, ``"private"``, or ``"disabled"``."""
    members_can_change_repo_visibility: str | None = None
    members_can_delete_repositories: str | None = None
    members_can_fork_private_repos: str | None = None
    two_factor_required: str | None = None
    """``"enabled"``, ``"disabled"``, or ``"no_policy"``."""
    repository_deploy_key_setting: str | None = None


class EnterpriseSAML(BaseModel):
    """Enterprise SAML/SSO status (no secrets stored)."""

    model_config = {"extra": "forbid"}

    enabled: bool = False
    issuer: str | None = None
    sso_url: str | None = None


class EnterpriseIPAllowList(BaseModel):
    """Enterprise IP allow list summary."""

    model_config = {"extra": "forbid"}

    enabled: bool = False
    entries_count: int = 0
    for_installed_apps: bool = False


class EnterpriseTeamInfo(BaseModel):
    """Enterprise-level team summary."""

    model_config = {"extra": "forbid"}

    name: str
    slug: str
    member_count: int = 0
    org_count: int = 0


class EnterpriseInventory(BaseModel):
    """Enterprise-level data. Only populated with ``--enterprise`` flag."""

    model_config = {"extra": "forbid"}

    name: str
    slug: str
    billing: EnterpriseBilling | None = None
    policies: EnterprisePolicies | None = None
    saml: EnterpriseSAML | None = None
    ip_allow_list: EnterpriseIPAllowList | None = None
    verified_domains: list[str] = Field(default_factory=list)
    enterprise_rulesets: list[RulesetDetail] = Field(default_factory=list)
    enterprise_teams: list[EnterpriseTeamInfo] = Field(default_factory=list)
    members_count: int = 0
    admins_count: int = 0
    outside_collaborators_count: int = 0
