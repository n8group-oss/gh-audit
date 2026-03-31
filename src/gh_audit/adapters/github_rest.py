"""GitHub REST API client with capability-aware optional endpoints.

Design principles
-----------------
- Shared ``httpx.AsyncClient`` with auth headers and API version set via defaults.
- GitHub API version header on every request (``X-GitHub-Api-Version: 2022-11-28``).
- Rate-limit tracking from ``x-ratelimit-remaining`` and ``x-ratelimit-reset`` headers.
- Pre-emptive wait when rate_limit_remaining < 10.
- Up to 3 retries with exponential backoff for 429 and 503.
- **Fatal** endpoints (verify_credentials, list_repos, etc.) raise ``AuthenticationError``
  on 401/403.
- **Optional** endpoints (security alerts, rulesets) return typed ``AlertCountResult``
  or ``None`` on 403/404 rather than raising.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from typing import Optional

import httpx

from gh_audit.adapters.base import AlertCountResult
from gh_audit.auth.github_app import GitHubAppAuth
from gh_audit.exceptions import APIError, AuthenticationError

_log = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_GITHUB_API_VERSION = "2022-11-28"
_ACCEPT_HEADER = "application/vnd.github+json"

# Retry configuration
_MAX_RETRIES = 3
_RETRY_STATUSES = {429, 503}
_RATE_LIMIT_PREEMPTIVE_THRESHOLD = 10


def _parse_link_next(link_header: str) -> str | None:
    """Parse the ``Link`` response header and return the URL for rel="next".

    Returns None if there is no next page.
    """
    for part in link_header.split(","):
        part = part.strip()
        match = re.match(r'<([^>]+)>;\s*rel="next"', part)
        if match:
            return match.group(1)
    return None


class GitHubRestClient:
    """Async GitHub REST API client.

    Parameters
    ----------
    token:
        Personal access token (PAT). Used as a Bearer token if ``app_auth``
        is not provided.
    app_auth:
        GitHub App authentication helper. When provided, ``app_auth.get_token()``
        is called before each request to obtain a fresh installation token.
    base_url:
        Override for GitHub Enterprise Server. Defaults to
        ``https://api.github.com``.
    """

    def __init__(
        self,
        token: str | None = None,
        app_auth: Optional[GitHubAppAuth] = None,
        base_url: str = _GITHUB_API_BASE,
    ) -> None:
        self._token = token
        self._app_auth = app_auth
        self._base_url = base_url.rstrip("/")

        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset: int | None = None

        # Do NOT set base_url on the client — we construct full URLs ourselves
        # to avoid conflicts when following absolute Link header URLs.
        self._client = httpx.AsyncClient(
            headers={
                "Accept": _ACCEPT_HEADER,
                "X-GitHub-Api-Version": _GITHUB_API_VERSION,
            },
            timeout=30.0,
        )

    # ------------------------------------------------------------------
    # Public API — core (fatal on auth failure)
    # ------------------------------------------------------------------

    async def verify_credentials(self, org: str) -> dict:
        """Verify credentials by fetching org details.

        Raises
        ------
        AuthenticationError
            On 401 or 403.
        """
        return await self._get_core(f"/orgs/{org}")

    async def list_repos(self, org: str) -> list[dict]:
        """Return all repositories for the given organisation (paginated)."""
        return await self._get_paginated(
            f"/orgs/{org}/repos",
            params={"per_page": 100},
        )

    async def list_org_members(self, org: str, *, role: str = "all") -> list[dict]:
        """Return all organisation members (paginated)."""
        return await self._get_paginated(
            f"/orgs/{org}/members",
            params={"role": role, "per_page": 100},
        )

    async def list_outside_collaborators(self, org: str) -> list[dict]:
        """Return all outside collaborators for the organisation (paginated)."""
        return await self._get_paginated(
            f"/orgs/{org}/outside_collaborators",
            params={"per_page": 100},
        )

    async def list_packages(self, org: str, package_type: str) -> list[dict]:
        """Return all packages of the given type for the organisation (paginated)."""
        return await self._get_paginated(
            f"/orgs/{org}/packages",
            params={"package_type": package_type, "per_page": 100},
        )

    async def get_tree(self, owner: str, repo: str, tree_sha: str) -> dict:
        """Return the git tree for the given SHA (recursive)."""
        return await self._get_core(
            f"/repos/{owner}/{repo}/git/trees/{tree_sha}",
            params={"recursive": "1"},
        )

    async def get_file_content(self, owner: str, repo: str, path: str) -> str | None:
        """Return the decoded text content of a file, or None on 404."""
        return await self._get_file_content_inner(owner, repo, path)

    async def list_workflows(self, owner: str, repo: str) -> list[dict]:
        """Return all Actions workflows for the repository."""
        data = await self._get_core(f"/repos/{owner}/{repo}/actions/workflows")
        return data.get("workflows", [])

    async def get_workflow_file(self, owner: str, repo: str, path: str) -> str | None:
        """Return decoded workflow YAML content, or None on 404."""
        return await self._get_file_content_inner(owner, repo, path)

    # ------------------------------------------------------------------
    # Public API — optional endpoints (non-fatal on 403/404)
    # ------------------------------------------------------------------

    async def count_dependabot_alerts(self, owner: str, repo: str) -> AlertCountResult:
        """Return the count of open Dependabot alerts, or inaccessible result."""
        return await self._count_alerts(f"/repos/{owner}/{repo}/dependabot/alerts")

    async def count_code_scanning_alerts(self, owner: str, repo: str) -> AlertCountResult:
        """Return the count of open code-scanning alerts, or inaccessible result."""
        return await self._count_alerts(f"/repos/{owner}/{repo}/code-scanning/alerts")

    async def count_secret_scanning_alerts(self, owner: str, repo: str) -> AlertCountResult:
        """Return the count of open secret-scanning alerts, or inaccessible result."""
        return await self._count_alerts(f"/repos/{owner}/{repo}/secret-scanning/alerts")

    async def get_security_features(self, owner: str, repo: str) -> dict:
        """Return repository security-and-analysis feature settings."""
        return await self._get_core(f"/repos/{owner}/{repo}")

    async def list_rulesets(self, owner: str, repo: str) -> list[dict] | None:
        """Return repository rulesets, or None if the endpoint is forbidden/unavailable."""
        url = self._url(f"/repos/{owner}/{repo}/rulesets")
        response = await self._request_with_retry_url(url)
        if response.status_code in (403, 404):
            return None
        self._raise_for_status(response)
        return response.json()

    # ------------------------------------------------------------------
    # Public API — governance endpoints (non-fatal on 403/404)
    # ------------------------------------------------------------------

    async def list_teams(self, org: str) -> list[dict]:
        """List all teams in the organization."""
        return await self._get_paginated(f"/orgs/{org}/teams", params={"per_page": 100})

    async def list_team_members(self, org: str, team_slug: str) -> list[dict]:
        """List members of a team."""
        return await self._get_paginated(f"/orgs/{org}/teams/{team_slug}/members")

    async def list_team_repos(self, org: str, team_slug: str) -> list[dict]:
        """List repositories accessible to a team."""
        return await self._get_paginated(f"/orgs/{org}/teams/{team_slug}/repos")

    async def list_org_rulesets(self, org: str) -> list[dict]:
        """List organization rulesets (paginated)."""
        try:
            return await self._get_paginated(f"/orgs/{org}/rulesets", params={"per_page": 100})
        except Exception:
            return []

    async def get_org_ruleset_detail(self, org: str, ruleset_id: int) -> dict | None:
        """Get detailed ruleset including rules and conditions."""
        response = await self._get(f"/orgs/{org}/rulesets/{ruleset_id}")
        if response.status_code != 200:
            return None
        return response.json()

    async def list_custom_roles(self, org: str) -> list[dict]:
        """List custom repository roles. Returns [] on 403 (requires Enterprise Cloud)."""
        response = await self._get(f"/orgs/{org}/custom-repository-roles")
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        return data.get("custom_roles", [])

    async def list_custom_properties_schema(self, org: str) -> list[dict]:
        """List custom property definitions for the organization."""
        response = await self._get(f"/orgs/{org}/properties/schema")
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        return response.json()

    async def get_repo_custom_properties(self, owner: str, repo: str) -> dict:
        """Get custom property values for a repository."""
        response = await self._get(f"/repos/{owner}/{repo}/properties/values")
        if response.status_code in (403, 404):
            return {}
        if response.status_code != 200:
            return {}
        # API returns a list of {property_name, value} objects
        result = {}
        for prop in response.json():
            result[prop.get("property_name", "")] = prop.get("value")
        return result

    async def list_repo_teams(self, owner: str, repo: str) -> list[dict]:
        """List teams with access to a repository."""
        return await self._get_paginated(f"/repos/{owner}/{repo}/teams")

    async def list_org_action_secrets(self, org: str) -> list[dict]:
        """List organization Actions secrets (metadata only, paginated)."""
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/orgs/{org}/actions/secrets",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("secrets", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def list_org_action_variables(self, org: str) -> list[dict]:
        """List organization Actions variables (paginated)."""
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/orgs/{org}/actions/variables",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("variables", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def list_org_dependabot_secrets(self, org: str) -> list[dict]:
        """List organization Dependabot secrets (metadata only, paginated)."""
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/orgs/{org}/dependabot/secrets",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("secrets", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    # ------------------------------------------------------------------
    # Public API — operations endpoints (non-fatal on 403/404)
    # ------------------------------------------------------------------

    async def list_org_runners(self, org: str) -> list[dict]:
        """List self-hosted runners for the organization.

        Returns [] on 403/404 (requires admin:org scope).
        """
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/orgs/{org}/actions/runners",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("runners", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def list_org_runner_groups(self, org: str) -> list[dict]:
        """List runner groups for the organization.

        Returns [] on 403/404 (requires admin:org scope).
        """
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/orgs/{org}/actions/runner-groups",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("runner_groups", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def list_org_installations(self, org: str) -> list[dict]:
        """List GitHub Apps installed on the organization."""
        all_items = []
        page = 1
        while True:
            response = await self._get(
                f"/orgs/{org}/installations",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("installations", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def list_org_webhooks(self, org: str) -> list[dict]:
        """List organization webhooks.

        Returns [] on 403 (requires admin:org_hook scope).
        """
        response = await self._get(f"/orgs/{org}/hooks", params={"per_page": "100"})
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        return response.json()

    async def list_repo_webhooks(self, owner: str, repo: str) -> list[dict]:
        """List repository webhooks.

        Returns [] on 403 (requires admin access to the repository).
        """
        response = await self._get(f"/repos/{owner}/{repo}/hooks", params={"per_page": "100"})
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        return response.json()

    async def list_repo_environments(self, owner: str, repo: str) -> list[dict]:
        """List deployment environments for a repository.

        Returns [] on 403/404.
        """
        response = await self._get(f"/repos/{owner}/{repo}/environments")
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        return data.get("environments", [])

    async def list_repo_deploy_keys(self, owner: str, repo: str) -> list[dict]:
        """List deploy keys for a repository."""
        response = await self._get(f"/repos/{owner}/{repo}/keys", params={"per_page": "100"})
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        return response.json()

    async def list_repo_action_secrets(self, owner: str, repo: str) -> list[dict]:
        """List repository Actions secrets (metadata only).

        Returns [] on 403/404.
        """
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/repos/{owner}/{repo}/actions/secrets",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("secrets", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def list_repo_action_variables(self, owner: str, repo: str) -> list[dict]:
        """List repository Actions variables.

        Returns [] on 403/404.
        """
        all_items: list[dict] = []
        page = 1
        while True:
            response = await self._get(
                f"/repos/{owner}/{repo}/actions/variables",
                params={"per_page": "100", "page": str(page)},
            )
            if response.status_code in (403, 404):
                return []
            if response.status_code != 200:
                return all_items
            data = response.json()
            items = data.get("variables", [])
            all_items.extend(items)
            if len(all_items) >= data.get("total_count", 0) or len(items) < 100:
                break
            page += 1
        return all_items

    async def get_repo_actions_permissions(self, owner: str, repo: str) -> dict | None:
        """Get Actions permissions for a repository.

        Returns None on 403/404.
        """
        response = await self._get(f"/repos/{owner}/{repo}/actions/permissions")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    # ------------------------------------------------------------------
    # Public API — security detail endpoints (non-fatal on 403/404)
    # ------------------------------------------------------------------

    async def list_dependabot_alerts_detail(self, owner: str, repo: str) -> list[dict]:
        """Full Dependabot alerts with all fields. Paginated. Returns [] on 403/404."""
        try:
            return await self._get_paginated(
                f"/repos/{owner}/{repo}/dependabot/alerts",
                params={"per_page": 100},
            )
        except Exception:
            return []

    async def list_code_scanning_alerts_detail(self, owner: str, repo: str) -> list[dict]:
        """Full code scanning alerts. Paginated. Returns [] on 403/404."""
        try:
            return await self._get_paginated(
                f"/repos/{owner}/{repo}/code-scanning/alerts",
                params={"per_page": 100},
            )
        except Exception:
            return []

    async def list_secret_scanning_alerts_detail(self, owner: str, repo: str) -> list[dict]:
        """Full secret scanning alerts. Paginated. Returns [] on 403/404."""
        try:
            return await self._get_paginated(
                f"/repos/{owner}/{repo}/secret-scanning/alerts",
                params={"per_page": 100},
            )
        except Exception:
            return []

    async def get_repo_sbom(self, owner: str, repo: str) -> dict | None:
        """Get SBOM for repo. Returns None on 403/404."""
        response = await self._get(f"/repos/{owner}/{repo}/dependency-graph/sbom")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    async def get_code_scanning_default_setup(self, owner: str, repo: str) -> dict | None:
        """Get code scanning default setup config. Returns None on 403/404."""
        response = await self._get(f"/repos/{owner}/{repo}/code-scanning/default-setup")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    async def get_repo_security_configuration(self, owner: str, repo: str) -> dict | None:
        """Get security configuration attached to repo. Returns None on 403/404."""
        response = await self._get(f"/repos/{owner}/{repo}/code-security-configuration")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    # ------------------------------------------------------------------
    # Public API — adoption endpoints (non-fatal on 403/404)
    # ------------------------------------------------------------------

    async def get_copilot_billing(self, org: str) -> dict | None:
        """Get Copilot billing/seat info for org. Returns None on 403/404."""
        response = await self._get(f"/orgs/{org}/copilot/billing")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    async def get_copilot_metrics(self, org: str) -> list[dict]:
        """Get Copilot usage metrics for org. Returns [] on 403/404."""
        response = await self._get(f"/orgs/{org}/copilot/metrics")
        if response.status_code in (403, 404):
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        return data if isinstance(data, list) else []

    async def get_repo_traffic_views(self, owner: str, repo: str) -> dict | None:
        """Get repo traffic views (last 14 days). Returns None on 403/404."""
        response = await self._get(f"/repos/{owner}/{repo}/traffic/views")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    async def get_repo_traffic_clones(self, owner: str, repo: str) -> dict | None:
        """Get repo traffic clones (last 14 days). Returns None on 403/404."""
        response = await self._get(f"/repos/{owner}/{repo}/traffic/clones")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    async def get_repo_community_profile(self, owner: str, repo: str) -> dict | None:
        """Get community profile / health metrics. Returns None on 403/404."""
        response = await self._get(f"/repos/{owner}/{repo}/community/profile")
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            return None
        return response.json()

    async def get_repo_commit_activity(self, owner: str, repo: str) -> list[dict]:
        """Get weekly commit activity (last year). Returns [] on 403/404/202."""
        response = await self._get(f"/repos/{owner}/{repo}/stats/commit_activity")
        if response.status_code in (202, 403, 404):
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        return data if isinstance(data, list) else []

    async def get_workflow_runs_count(
        self, owner: str, repo: str, *, conclusion: str, created: str
    ) -> int:
        """Get total_count of workflow runs matching conclusion + date filter.

        Uses per_page=1 to minimize data transfer — we only need the count.
        Returns 0 on 403/404.
        """
        response = await self._get(
            f"/repos/{owner}/{repo}/actions/runs",
            params={
                "status": "completed",
                "conclusion": conclusion,
                "created": created,
                "per_page": 1,
            },
        )
        if response.status_code in (403, 404):
            return 0
        if response.status_code != 200:
            return 0
        return response.json().get("total_count", 0)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        """Construct a full URL from a path."""
        return self._base_url + path

    async def _auth_headers(self) -> dict[str, str]:
        """Build the Authorization header for the current request."""
        if self._app_auth is not None:
            token = await self._app_auth.get_token()
        elif self._token is not None:
            token = self._token
        else:
            return {}
        return {"Authorization": f"Bearer {token}"}

    async def _get(self, path: str, *, params: dict | None = None) -> httpx.Response:
        """GET a single resource and return the raw response (no error raising)."""
        url = self._url(path)
        return await self._request_with_retry_url(url, params=params)

    async def _get_core(self, path: str, *, params: dict | None = None) -> dict:
        """GET a single resource, raising AuthenticationError on 401/403."""
        url = self._url(path)
        response = await self._request_with_retry_url(url, params=params)
        if response.status_code in (401, 403):
            raise AuthenticationError(
                f"GitHub API authentication failed for {path} (HTTP {response.status_code})"
            )
        self._raise_for_status(response)
        return response.json()

    async def _get_paginated(self, path: str, *, params: dict | None = None) -> list[dict]:
        """GET all pages of a list endpoint, following Link rel=next headers."""
        results: list[dict] = []

        # First page uses the constructed URL + params
        next_url: str | None = self._url(path)
        current_params: dict | None = params

        while next_url:
            response = await self._request_with_retry_url(next_url, params=current_params)

            if response.status_code in (401, 403):
                raise AuthenticationError(
                    f"GitHub API authentication failed for {path} (HTTP {response.status_code})"
                )
            self._raise_for_status(response)

            page = response.json()
            if isinstance(page, list):
                results.extend(page)

            # Subsequent pages use the absolute URL from Link header (no extra params)
            current_params = None
            link = response.headers.get("Link", "")
            next_url = _parse_link_next(link) if link else None

        return results

    async def _get_file_content_inner(self, owner: str, repo: str, path: str) -> str | None:
        """Shared implementation for file content retrieval."""
        url = self._url(f"/repos/{owner}/{repo}/contents/{path}")
        response = await self._request_with_retry_url(url)
        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            raise AuthenticationError(
                f"GitHub API authentication failed for /repos/{owner}/{repo}/contents/{path} "
                f"(HTTP {response.status_code})"
            )
        self._raise_for_status(response)

        data = response.json()
        if data.get("encoding") == "base64":
            # GitHub adds newlines inside the base64 — strip before decoding
            raw = data["content"].replace("\n", "").replace(" ", "")
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        return data.get("content", "")

    async def _count_alerts(self, path: str) -> AlertCountResult:
        """Generic implementation for security-alert count endpoints.

        Fetches open alerts with pagination to get an exact count.
        """
        total = 0
        next_url: str | None = self._url(path)
        current_params: dict | None = {"state": "open", "per_page": 100}

        while next_url:
            response = await self._request_with_retry_url(next_url, params=current_params)
            if response.status_code in (403, 404):
                return AlertCountResult.inaccessible()
            self._raise_for_status(response)

            page = response.json()
            if isinstance(page, list):
                total += len(page)

            # Subsequent pages use the absolute URL from Link header (no extra params)
            current_params = None
            link = response.headers.get("Link", "")
            next_url = _parse_link_next(link) if link else None

        return AlertCountResult.from_count(total)

    async def _request_with_retry_url(
        self,
        url: str,
        *,
        method: str = "GET",
        params: dict | None = None,
    ) -> httpx.Response:
        """Execute an HTTP request by full URL with retry on 429 / 503."""
        auth_headers = await self._auth_headers()

        last_response: httpx.Response | None = None
        for attempt in range(_MAX_RETRIES + 1):
            # Pre-emptive rate-limit wait
            if (
                self.rate_limit_remaining is not None
                and self.rate_limit_remaining < _RATE_LIMIT_PREEMPTIVE_THRESHOLD
            ):
                reset_at = self.rate_limit_reset or 0
                wait = max(0.0, reset_at - time.time())
                if wait > 0:
                    _log.warning("Pre-emptive rate-limit wait: %.1fs", wait)
                    await asyncio.sleep(wait)

            response = await self._client.request(method, url, params=params, headers=auth_headers)
            self._update_rate_limit(response)

            if response.status_code not in _RETRY_STATUSES:
                return response

            last_response = response

            if attempt < _MAX_RETRIES:
                backoff = 2**attempt  # 1s, 2s, 4s
                retry_after_header = response.headers.get("Retry-After")
                if retry_after_header:
                    try:
                        backoff = int(retry_after_header)
                    except ValueError:
                        pass
                _log.warning(
                    "HTTP %s on %s — retrying in %ds (attempt %d/%d)",
                    response.status_code,
                    url,
                    backoff,
                    attempt + 1,
                    _MAX_RETRIES,
                )
                await asyncio.sleep(backoff)

        # All retries exhausted
        assert last_response is not None
        raise APIError(
            f"HTTP {last_response.status_code} after {_MAX_RETRIES} retries: {url}",
            status_code=last_response.status_code,
        )

    def _update_rate_limit(self, response: httpx.Response) -> None:
        """Extract and store rate-limit headers from a response."""
        remaining = response.headers.get("x-ratelimit-remaining")
        reset = response.headers.get("x-ratelimit-reset")
        if remaining is not None:
            try:
                self.rate_limit_remaining = int(remaining)
            except ValueError:
                pass
        if reset is not None:
            try:
                self.rate_limit_reset = int(reset)
            except ValueError:
                pass

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        """Raise ``APIError`` for non-2xx responses not handled elsewhere."""
        if response.is_success:
            return
        raise APIError(
            f"GitHub API error (HTTP {response.status_code}): {response.text[:200]}",
            status_code=response.status_code,
        )
