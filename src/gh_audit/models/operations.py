"""Operations-related models: runners, apps, webhooks, secrets, environments, deploy keys.

Design rule: ``None`` on an operations field means "operations category not scanned".
             An empty list means "scanned and found nothing".
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Runner models
# ---------------------------------------------------------------------------


class RunnerInfo(BaseModel):
    """A self-hosted Actions runner registered to the organization."""

    model_config = {"extra": "forbid"}

    name: str
    """Runner display name."""

    os: str
    """Operating system: ``"Linux"``, ``"Windows"``, ``"macOS"``."""

    status: str
    """Runner status: ``"online"`` or ``"offline"``."""

    labels: list[str] = Field(default_factory=list)
    """Labels assigned to this runner."""

    busy: bool = False
    """Whether the runner is currently executing a job."""

    runner_group_name: str | None = None
    """Name of the runner group this runner belongs to."""


class RunnerGroupInfo(BaseModel):
    """A self-hosted runner group in the organization."""

    model_config = {"extra": "forbid"}

    name: str
    """Runner group display name."""

    visibility: str
    """Visibility: ``"all"``, ``"selected"``, or ``"private"``."""

    allows_public_repos: bool = False
    """Whether the group allows runners to be used by public repositories."""

    runner_count: int = 0
    """Number of runners in this group."""

    repo_count: int | None = None
    """Number of repositories with access (None if visibility is not 'selected')."""


# ---------------------------------------------------------------------------
# Installed app model
# ---------------------------------------------------------------------------


class InstalledAppInfo(BaseModel):
    """A GitHub App installed on the organization."""

    model_config = {"extra": "forbid"}

    app_name: str
    """Display name of the GitHub App."""

    app_slug: str
    """URL-safe identifier of the GitHub App."""

    permissions: dict[str, str] = Field(default_factory=dict)
    """Permissions granted: mapping of scope to access level (e.g. ``{"issues": "read"}``)."""

    events: list[str] = Field(default_factory=list)
    """Webhook events the app subscribes to."""

    repository_selection: str = "all"
    """Repository access: ``"all"`` or ``"selected"``."""


# ---------------------------------------------------------------------------
# Webhook model
# ---------------------------------------------------------------------------


class WebhookInfo(BaseModel):
    """A webhook configured on the organization or repository."""

    model_config = {"extra": "forbid"}

    url_domain: str
    """Domain portion of the webhook URL (no scheme, path, or query)."""

    events: list[str] = Field(default_factory=list)
    """Events that trigger this webhook."""

    active: bool = True
    """Whether the webhook is active."""

    content_type: str = "json"
    """Payload content type: ``"json"`` or ``"form"``."""

    insecure_ssl: bool = False
    """Whether SSL verification is disabled."""


# ---------------------------------------------------------------------------
# Secret / variable metadata models
# ---------------------------------------------------------------------------


class SecretMetadata(BaseModel):
    """Metadata for an organization-level Actions secret (value is never exposed)."""

    model_config = {"extra": "forbid"}

    name: str
    """Secret name."""

    created_at: str
    """ISO 8601 creation timestamp."""

    updated_at: str
    """ISO 8601 last-update timestamp."""

    visibility: str
    """Visibility: ``"all"``, ``"private"``, or ``"selected"``."""

    selected_repositories_count: int | None = None
    """Number of repositories with access (None if visibility is not 'selected')."""


class VariableMetadata(BaseModel):
    """Metadata for an organization-level Actions variable."""

    model_config = {"extra": "forbid"}

    name: str
    """Variable name."""

    value: str
    """Variable value."""

    created_at: str
    """ISO 8601 creation timestamp."""

    updated_at: str
    """ISO 8601 last-update timestamp."""

    visibility: str
    """Visibility: ``"all"``, ``"private"``, or ``"selected"``."""


# ---------------------------------------------------------------------------
# Environment models
# ---------------------------------------------------------------------------


class EnvironmentProtection(BaseModel):
    """Protection rules for a deployment environment."""

    model_config = {"extra": "forbid"}

    wait_timer: int = 0
    """Minutes to wait before allowing deployments."""

    required_reviewers: int = 0
    """Number of required reviewers before deployment."""

    branch_policy: str | None = None
    """Branch deployment policy: ``"protected"`` or ``"custom"``; None if unrestricted."""


class EnvironmentInfo(BaseModel):
    """A deployment environment configured on a repository."""

    model_config = {"extra": "forbid"}

    name: str
    """Environment name."""

    protection_rules: EnvironmentProtection | None = None
    """Protection configuration; None if no protection rules are set."""

    secrets_count: int = 0
    """Number of secrets scoped to this environment."""

    variables_count: int = 0
    """Number of variables scoped to this environment."""

    can_admins_bypass: bool = True
    """Whether admins can bypass protection rules."""


# ---------------------------------------------------------------------------
# Deploy key model
# ---------------------------------------------------------------------------


class DeployKeyInfo(BaseModel):
    """A deploy key configured on a repository."""

    model_config = {"extra": "forbid"}

    title: str
    """Deploy key title/label."""

    read_only: bool = True
    """Whether the key has read-only access."""

    created_at: str
    """ISO 8601 creation timestamp."""


# ---------------------------------------------------------------------------
# Actions permissions model
# ---------------------------------------------------------------------------


class ActionsPermissions(BaseModel):
    """Actions permissions configuration for a repository."""

    model_config = {"extra": "forbid"}

    enabled: bool = True
    """Whether GitHub Actions is enabled for this repository."""

    allowed_actions: str = "all"
    """Which actions are allowed: ``"all"``, ``"local_only"``, or ``"selected"``."""

    default_token_permissions: str = "read"
    """Default GITHUB_TOKEN permission level: ``"read"`` or ``"write"``."""


# ---------------------------------------------------------------------------
# Top-level operations inventory
# ---------------------------------------------------------------------------


class OperationsInventory(BaseModel):
    """Aggregated operations data collected at the organization level."""

    model_config = {"extra": "forbid"}

    runners: list[RunnerInfo] = Field(default_factory=list)
    """Self-hosted runners registered to the organization."""

    runner_groups: list[RunnerGroupInfo] = Field(default_factory=list)
    """Runner groups configured in the organization."""

    installed_apps: list[InstalledAppInfo] = Field(default_factory=list)
    """GitHub Apps installed on the organization."""

    org_webhooks: list[WebhookInfo] = Field(default_factory=list)
    """Webhooks configured at the organization level."""

    org_secrets_metadata: list[SecretMetadata] = Field(default_factory=list)
    """Metadata for organization-level Actions secrets."""

    org_variables_metadata: list[VariableMetadata] = Field(default_factory=list)
    """Metadata for organization-level Actions variables."""
