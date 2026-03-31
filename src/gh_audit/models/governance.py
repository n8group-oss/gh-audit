"""Governance-related models: teams, rulesets, org policies, custom roles/properties.

Design rule: ``None`` on a governance field means "governance category not scanned".
             An empty list means "scanned and found nothing".
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Team models
# ---------------------------------------------------------------------------


class TeamInfo(BaseModel):
    """A GitHub organization team."""

    model_config = {"extra": "forbid"}

    name: str
    """Display name of the team."""

    slug: str
    """URL-safe team identifier."""

    description: str | None = None
    """Team description."""

    privacy: str
    """Visibility: ``"closed"`` or ``"secret"``."""

    permission: str
    """Base permission: ``"pull"``, ``"push"``, ``"admin"``, ``"maintain"``, or ``"triage"``."""

    member_count: int = 0
    """Number of members in this team."""

    repo_count: int = 0
    """Number of repositories this team has access to."""

    parent_team: str | None = None
    """Slug of parent team if this is a nested team."""


# ---------------------------------------------------------------------------
# Ruleset model
# ---------------------------------------------------------------------------


class RulesetDetail(BaseModel):
    """Full detail of a GitHub ruleset (org-level or repo-level)."""

    model_config = {"extra": "forbid"}

    name: str
    """Ruleset display name."""

    enforcement: str
    """Enforcement mode: ``"disabled"``, ``"active"``, or ``"evaluate"``."""

    target: str
    """Target object type: ``"branch"``, ``"tag"``, or ``"push"``."""

    source_type: str
    """Where the ruleset is defined: ``"Repository"`` or ``"Organization"``."""

    rules: list[dict] = Field(default_factory=list)
    """Individual rule objects as returned by the API."""

    conditions: dict | None = None
    """Ref conditions that scope which branches/tags this ruleset applies to."""

    bypass_actors: list[dict] = Field(default_factory=list)
    """Actors that can bypass this ruleset."""


# ---------------------------------------------------------------------------
# Org policy model
# ---------------------------------------------------------------------------


class OrgPolicies(BaseModel):
    """Organization-level member permission policies."""

    model_config = {"extra": "forbid"}

    default_repository_permission: str | None = None
    """Default base permission for all org members (``"read"``, ``"write"``, etc.)."""

    members_can_create_repositories: bool | None = None
    members_can_create_public_repositories: bool | None = None
    members_can_create_private_repositories: bool | None = None
    members_can_create_internal_repositories: bool | None = None
    members_can_fork_private_repositories: bool | None = None
    members_can_delete_repositories: bool | None = None
    members_can_change_repo_visibility: bool | None = None
    two_factor_requirement_enabled: bool | None = None
    web_commit_signoff_required: bool | None = None


# ---------------------------------------------------------------------------
# Custom role model
# ---------------------------------------------------------------------------


class CustomRoleInfo(BaseModel):
    """A custom repository role defined at the organization level."""

    model_config = {"extra": "forbid"}

    name: str
    """Role display name."""

    description: str | None = None
    """Optional role description."""

    permissions: list[str] = Field(default_factory=list)
    """Fine-grained permissions granted by this role."""


# ---------------------------------------------------------------------------
# Custom property schema model
# ---------------------------------------------------------------------------


class CustomPropertySchema(BaseModel):
    """Schema definition for an org-level custom property."""

    model_config = {"extra": "forbid"}

    property_name: str
    """The name/key of the custom property."""

    value_type: str
    """Data type: ``"string"``, ``"single_select"``, ``"multi_select"``, or ``"true_false"``."""

    required: bool = False
    """Whether a value is required on every repository."""

    description: str | None = None
    """Optional description shown in the UI."""

    allowed_values: list[str] = Field(default_factory=list)
    """Allowed values for select types; empty for free-form string/true_false."""


# ---------------------------------------------------------------------------
# Repo-team access sub-model
# ---------------------------------------------------------------------------


class RepoTeamAccess(BaseModel):
    """A team's access record for a specific repository."""

    model_config = {"extra": "forbid"}

    team_slug: str
    """Slug of the team that has access."""

    permission: str
    """Access level: ``"pull"``, ``"push"``, ``"admin"``, ``"maintain"``, or ``"triage"``."""


# ---------------------------------------------------------------------------
# Top-level governance inventory
# ---------------------------------------------------------------------------


class GovernanceInventory(BaseModel):
    """Aggregated governance data collected at the organization level."""

    model_config = {"extra": "forbid"}

    teams: list[TeamInfo] = Field(default_factory=list)
    """All teams in the organization."""

    org_rulesets: list[RulesetDetail] = Field(default_factory=list)
    """Organization-level rulesets."""

    org_policies: OrgPolicies = Field(default_factory=OrgPolicies)
    """Member permission policies for the organization."""

    custom_roles: list[CustomRoleInfo] = Field(default_factory=list)
    """Custom repository roles defined in the organization."""

    custom_properties_schema: list[CustomPropertySchema] = Field(default_factory=list)
    """Schema definitions for organization custom properties."""

    org_secrets_count: int = 0
    """Number of organization-level Actions secrets."""

    org_variables_count: int = 0
    """Number of organization-level Actions variables."""

    org_dependabot_secrets_count: int = 0
    """Number of organization-level Dependabot secrets."""
