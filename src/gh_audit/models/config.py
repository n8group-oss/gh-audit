"""ScannerConfig — the single source of truth for all scanner configuration.

Supports two authentication modes:
    - PAT (Personal Access Token): supply ``token``
    - GitHub App: supply ``app_id``, ``private_key_path``, and ``installation_id``

The model uses ``extra='forbid'`` so unexpected fields raise a ValidationError
immediately rather than being silently ignored.

``token`` is stored as ``SecretStr`` to prevent accidental logging.

GHES support: ``graphql_url`` is derived from ``api_url``:
    - https://api.github.com            -> https://api.github.com/graphql
    - https://github.example.com/api/v3 -> https://github.example.com/api/graphql
"""

from __future__ import annotations

import pathlib
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

_VALID_CATEGORIES = frozenset({"governance", "operations", "security", "adoption", "enterprise"})


class ScannerConfig(BaseModel):
    """Full configuration for a single gh-audit run."""

    model_config = {"extra": "forbid"}

    # ------------------------------------------------------------------
    # Required
    # ------------------------------------------------------------------

    organization: str
    """GitHub organization (login) to scan."""

    # ------------------------------------------------------------------
    # Auth — PAT path
    # ------------------------------------------------------------------

    token: SecretStr | None = None
    """Personal Access Token.  Mutually exclusive with GitHub App credentials."""

    # ------------------------------------------------------------------
    # Auth — GitHub App path
    # ------------------------------------------------------------------

    app_id: int | None = None
    """GitHub App ID."""

    private_key_path: pathlib.Path | None = None
    """Path to the GitHub App private key (PEM file)."""

    installation_id: int | None = None
    """GitHub App installation ID for the target organization."""

    # ------------------------------------------------------------------
    # API / connectivity
    # ------------------------------------------------------------------

    api_url: str = "https://api.github.com"
    """Base REST API URL.  Override for GitHub Enterprise Server."""

    # ------------------------------------------------------------------
    # Scan behaviour
    # ------------------------------------------------------------------

    scan_profile: Literal["standard", "deep", "total"] = "standard"
    """Scan depth profile: 'standard', 'deep', or 'total'."""

    scan_large_files: bool = False
    """Include large-file (LFS) statistics in the inventory."""

    scan_workflow_contents: bool = False
    """Fetch and analyse workflow file contents for deep Actions analysis."""

    security_alert_counts: bool = False
    """Include Dependabot / code-scanning / secret-scanning alert counts."""

    repo_limit: int | None = None
    """Maximum number of repositories to process. None means no limit."""

    concurrency: int = 8
    """Number of concurrent API calls."""

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    telemetry_disabled: bool = False
    """Opt out of anonymous usage telemetry."""

    include_archived: bool = True
    """Include archived repositories in the scan."""

    categories: list[str] = Field(default_factory=list)
    """Discovery categories to enable (governance, operations, security, adoption, enterprise)."""

    enterprise_slug: str | None = None
    """Enterprise slug for enterprise category discovery."""

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _require_auth(self) -> "ScannerConfig":
        """Enforce that exactly one auth method is fully supplied."""
        has_pat = self.token is not None
        has_app = (
            self.app_id is not None
            and self.private_key_path is not None
            and self.installation_id is not None
        )
        if not has_pat and not has_app:
            raise ValueError(
                "Authentication credentials are required.  "
                "Provide either 'token' (PAT) or all three of "
                "'app_id', 'private_key_path', and 'installation_id' (GitHub App)."
            )
        return self

    @field_validator("categories")
    @classmethod
    def _validate_categories(cls, v: list[str]) -> list[str]:
        invalid = set(v) - _VALID_CATEGORIES
        if invalid:
            raise ValueError(
                f"Invalid categories: {invalid}. Valid: {', '.join(sorted(_VALID_CATEGORIES))}"
            )
        return sorted(set(v))  # deduplicate and sort

    @model_validator(mode="after")
    def _profile_enables_features(self) -> "ScannerConfig":
        """Auto-enable sub-features for deep/total profiles."""
        if self.scan_profile in ("deep", "total"):
            self.scan_large_files = True
            self.scan_workflow_contents = True
            self.security_alert_counts = True
        if self.scan_profile == "total":
            all_cats = {"governance", "operations", "security", "adoption", "enterprise"}
            self.categories = sorted(all_cats | set(self.categories))
        return self

    @field_validator("api_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def auth_method(self) -> Literal["pat", "github_app"]:
        """Return which authentication method is active."""
        if self.token is not None:
            return "pat"
        return "github_app"

    @property
    def graphql_url(self) -> str:
        """Derive the GraphQL endpoint URL from ``api_url``.

        Rules
        -----
        - ``https://api.github.com``         -> ``https://api.github.com/graphql``
        - ``https://github.example.com/api/v3`` -> ``https://github.example.com/api/graphql``

        The trailing ``/v3`` segment (if present) is replaced with ``/graphql``.
        For the default github.com API URL we simply append ``/graphql``.
        """
        base = self.api_url  # trailing slash already stripped by validator
        if base.endswith("/v3"):
            return base[: -len("/v3")] + "/graphql"
        return base + "/graphql"


def resolve_active_categories(config: ScannerConfig) -> set[str]:
    """Determine which categories are active based on config."""
    cats = set(config.categories)
    if "enterprise" in cats and not config.enterprise_slug:
        cats.discard("enterprise")
    return cats
