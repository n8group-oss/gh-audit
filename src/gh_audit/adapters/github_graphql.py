"""GitHub GraphQL API client with pagination and budget tracking.

Design principles
-----------------
- Single ``httpx.AsyncClient`` shared across all requests.
- Token or GitHub App auth — same pattern as the REST client.
- ``GraphQLCost`` captures query cost from ``extensions.cost`` when present;
  falls back to a default cost of 1 when the field is absent.
- ``fetch_repos_bulk`` fetches one page (100 repos) and returns pagination state
  so callers can drive their own loop or use ``fetch_all_repos``.
- ``fetch_all_repos`` auto-paginates until ``hasNextPage`` is False.
- ``fetch_projects`` auto-paginates projectsV2 until complete.
- Error handling:
  - ``data=null`` + ``errors`` → raise ``APIError`` (fatal).
  - ``data`` non-null + ``errors`` → log warnings, return partial data.
- Bounded retries (max 2) with exponential back-off on HTTP 502/503.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from gh_audit.auth.github_app import GitHubAppAuth
from gh_audit.exceptions import APIError

_log = logging.getLogger(__name__)

_GRAPHQL_URL = "https://api.github.com/graphql"
_MAX_RETRIES = 2
_RETRY_STATUSES = {502, 503}

# ---------------------------------------------------------------------------
# Cost tracking dataclass
# ---------------------------------------------------------------------------

_REPOS_QUERY = """
query($org: String!, $cursor: String) {
  organization(login: $org) {
    repositories(first: 100, after: $cursor, orderBy: {field: NAME, direction: ASC}) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        nameWithOwner
        visibility
        isArchived
        isFork
        isTemplate
        primaryLanguage { name }
        repositoryTopics(first: 20) { nodes { topic { name } } }
        diskUsage
        defaultBranchRef { name }
        description
        refs(refPrefix: "refs/heads/") { totalCount }
        openPRs: pullRequests(states: OPEN) { totalCount }
        closedPRs: pullRequests(states: CLOSED) { totalCount }
        mergedPRs: pullRequests(states: MERGED) { totalCount }
        openIssues: issues(states: OPEN) { totalCount }
        closedIssues: issues(states: CLOSED) { totalCount }
        labels(first: 100) { nodes { name issues { totalCount } } }
        branchProtectionRules { totalCount }
        object(expression: "HEAD:.gitattributes") { ... on Blob { text } }
      }
    }
  }
}
""".strip()

_PROJECTS_QUERY = """
query($org: String!, $cursor: String) {
  organization(login: $org) {
    projectsV2(first: 100, after: $cursor) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes { title closed items { totalCount } }
    }
  }
}
""".strip()


@dataclass
class GraphQLCost:
    """Tracks query cost from the GraphQL response extensions.

    Parameters
    ----------
    requested:
        Number of query-cost points consumed by this request.
    remaining:
        Remaining budget (from ``extensions.cost.remainingPoints``), or
        ``None`` when the server did not include cost information.
    """

    requested: int
    remaining: int | None


def _extract_cost(response_body: dict) -> GraphQLCost:
    """Extract ``GraphQLCost`` from ``extensions.cost``, or return default."""
    cost_data = response_body.get("extensions", {}).get("cost")
    if cost_data:
        return GraphQLCost(
            requested=int(cost_data.get("requestedQueryCost", 1)),
            remaining=cost_data.get("remainingPoints"),
        )
    return GraphQLCost(requested=1, remaining=None)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GitHubGraphQLClient:
    """Async GitHub GraphQL API client with pagination and budget tracking.

    Parameters
    ----------
    token:
        Personal access token (PAT). Used as Bearer auth when ``app_auth``
        is not provided.
    app_auth:
        GitHub App authentication helper. When supplied, a fresh installation
        token is fetched before each request.
    graphql_url:
        Override for GitHub Enterprise Server. Defaults to
        ``https://api.github.com/graphql``.
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        app_auth: Optional[GitHubAppAuth] = None,
        graphql_url: str = _GRAPHQL_URL,
    ) -> None:
        self._token = token
        self._app_auth = app_auth
        self._graphql_url = graphql_url

        self._client = httpx.AsyncClient(timeout=30.0)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_repos_bulk(
        self, org: str, *, cursor: str | None = None
    ) -> tuple[list[dict], bool, str | None, GraphQLCost]:
        """Fetch one page (up to 100) of repositories for *org*.

        Parameters
        ----------
        org:
            GitHub organisation login.
        cursor:
            Pagination cursor from a previous call's ``endCursor``.

        Returns
        -------
        tuple[list[dict], bool, str | None, GraphQLCost]
            ``(repos, has_next_page, end_cursor, cost)``
        """
        variables: dict = {"org": org}
        if cursor is not None:
            variables["cursor"] = cursor

        body = await self._post({"query": _REPOS_QUERY, "variables": variables})
        cost = _extract_cost(body)

        self._check_for_fatal_errors(body, context=f"fetch_repos_bulk(org={org!r})")

        org_data = (body.get("data") or {}).get("organization") or {}
        repos_data = org_data.get("repositories", {})
        nodes: list[dict] = repos_data.get("nodes", [])
        page_info: dict = repos_data.get("pageInfo", {})
        has_next: bool = bool(page_info.get("hasNextPage", False))
        end_cursor: str | None = page_info.get("endCursor")

        return nodes, has_next, end_cursor, cost

    async def fetch_all_repos(self, org: str) -> list[dict]:
        """Fetch **all** repositories for *org*, auto-paginating.

        Returns
        -------
        list[dict]
            Combined list of repository nodes from all pages.
        """
        all_repos: list[dict] = []
        cursor: str | None = None

        while True:
            repos, has_next, cursor, _ = await self.fetch_repos_bulk(org, cursor=cursor)
            all_repos.extend(repos)
            if not has_next:
                break

        return all_repos

    async def fetch_projects(self, org: str) -> list[dict]:
        """Fetch all GitHub Projects (v2) for *org*, auto-paginating.

        Returns
        -------
        list[dict]
            Combined list of project nodes from all pages.
        """
        all_projects: list[dict] = []
        cursor: str | None = None

        while True:
            variables: dict = {"org": org}
            if cursor is not None:
                variables["cursor"] = cursor

            body = await self._post({"query": _PROJECTS_QUERY, "variables": variables})
            self._check_for_fatal_errors(body, context=f"fetch_projects(org={org!r})")

            org_data = (body.get("data") or {}).get("organization") or {}
            projects_data = org_data.get("projectsV2", {})
            nodes: list[dict] = projects_data.get("nodes", [])
            page_info: dict = projects_data.get("pageInfo", {})
            has_next: bool = bool(page_info.get("hasNextPage", False))
            cursor = page_info.get("endCursor")

            all_projects.extend(nodes)
            if not has_next:
                break

        return all_projects

    async def fetch_enterprise_info(self, slug: str) -> dict | None:
        """Fetch enterprise overview: members, SAML, domains, IP allow list.

        Returns a normalised dict or None on error.
        """
        query = """
        query($slug: String!) {
          enterprise(slug: $slug) {
            name
            slug
            members(first: 0) { totalCount }
            admins: members(first: 0, role: ADMIN) { totalCount }
            outsideCollaborators(first: 0) { totalCount }
            ownerInfo {
              samlIdentityProvider {
                issuer
                ssoUrl
              }
              domains(first: 100) {
                nodes { domain isVerified }
              }
              ipAllowListEnabledSetting
              ipAllowListEntries(first: 0) { totalCount }
              ipAllowListForInstalledAppsEnabledSetting
            }
          }
        }
        """
        try:
            body = await self._post({"query": query, "variables": {"slug": slug}})
            self._check_for_fatal_errors(body, context=f"enterprise info for {slug}")
            ent = body["data"]["enterprise"]
            owner = ent.get("ownerInfo") or {}

            saml_raw = owner.get("samlIdentityProvider")
            saml = {
                "enabled": saml_raw is not None,
                "issuer": saml_raw.get("issuer") if saml_raw else None,
                "sso_url": saml_raw.get("ssoUrl") if saml_raw else None,
            }

            domains = (owner.get("domains") or {}).get("nodes") or []
            verified = [d["domain"] for d in domains if d.get("isVerified")]

            ip_enabled = owner.get("ipAllowListEnabledSetting", "DISABLED") == "ENABLED"
            ip_apps = (
                owner.get("ipAllowListForInstalledAppsEnabledSetting", "DISABLED") == "ENABLED"
            )
            ip_count = (owner.get("ipAllowListEntries") or {}).get("totalCount", 0)

            return {
                "name": ent["name"],
                "slug": ent["slug"],
                "members_count": (ent.get("members") or {}).get("totalCount", 0),
                "admins_count": (ent.get("admins") or {}).get("totalCount", 0),
                "outside_collaborators_count": (
                    (ent.get("outsideCollaborators") or {}).get("totalCount", 0)
                ),
                "saml": saml,
                "verified_domains": verified,
                "ip_allow_list": {
                    "enabled": ip_enabled,
                    "entries_count": ip_count,
                    "for_installed_apps": ip_apps,
                },
            }
        except Exception:
            return None

    async def fetch_enterprise_billing(self, slug: str) -> dict | None:
        """Fetch enterprise billing/license info.

        Returns a normalised dict or None on error.
        """
        query = """
        query($slug: String!) {
          enterprise(slug: $slug) {
            billingInfo {
              totalLicenses
              allLicensableUsersCount
              bandwidthUsageInGb
              bandwidthQuotaInGb
              storageUsageInGb
              storageQuotaInGb
            }
          }
        }
        """
        try:
            body = await self._post({"query": query, "variables": {"slug": slug}})
            self._check_for_fatal_errors(body, context=f"enterprise billing for {slug}")
            billing = body["data"]["enterprise"]["billingInfo"]
            return {
                "total_licenses": billing.get("totalLicenses", 0),
                "used_licenses": billing.get("allLicensableUsersCount", 0),
                "bandwidth_usage_gb": billing.get("bandwidthUsageInGb", 0.0),
                "bandwidth_quota_gb": billing.get("bandwidthQuotaInGb", 0.0),
                "storage_usage_gb": billing.get("storageUsageInGb", 0.0),
                "storage_quota_gb": billing.get("storageQuotaInGb", 0.0),
            }
        except Exception:
            return None

    async def fetch_enterprise_policies(self, slug: str) -> dict | None:
        """Fetch enterprise-level policy settings.

        Returns a normalised dict or None on error.
        """
        query = """
        query($slug: String!) {
          enterprise(slug: $slug) {
            ownerInfo {
              membersCanCreateRepositoriesSetting
              membersCanChangeRepositoryVisibilitySetting
              membersCanDeleteRepositoriesSetting
              membersCanForkPrivateRepositoriesSetting
              twoFactorRequiredSetting
              defaultRepositoryPermissionSetting
              repositoryDeployKeySetting
            }
          }
        }
        """
        try:
            body = await self._post({"query": query, "variables": {"slug": slug}})
            self._check_for_fatal_errors(body, context=f"enterprise policies for {slug}")
            owner = body["data"]["enterprise"]["ownerInfo"]

            def _setting(val: str | None) -> str | None:
                if val is None or val == "NO_POLICY":
                    return None
                return val.lower()

            return {
                "default_repository_permission": _setting(
                    owner.get("defaultRepositoryPermissionSetting")
                ),
                "members_can_create_repositories": _setting(
                    owner.get("membersCanCreateRepositoriesSetting")
                ),
                "members_can_change_repo_visibility": _setting(
                    owner.get("membersCanChangeRepositoryVisibilitySetting")
                ),
                "members_can_delete_repositories": _setting(
                    owner.get("membersCanDeleteRepositoriesSetting")
                ),
                "members_can_fork_private_repos": _setting(
                    owner.get("membersCanForkPrivateRepositoriesSetting")
                ),
                "two_factor_required": _setting(owner.get("twoFactorRequiredSetting")),
                "repository_deploy_key_setting": _setting(owner.get("repositoryDeployKeySetting")),
            }
        except Exception:
            return None

    async def fetch_enterprise_teams(self, slug: str) -> list[dict]:
        """Fetch enterprise teams with member/org counts.

        Stub — enterprise teams require iterating all orgs via the
        ``enterprise.organizations`` connection. Returns [] for now.
        """
        return []

    async def fetch_enterprise_rulesets(self, slug: str) -> list[dict]:
        """Fetch enterprise-level rulesets.

        Stub — enterprise rulesets use REST (``GET /enterprises/{ent}/rulesets``),
        not GraphQL. Returns [] for now.
        """
        return []

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _auth_headers(self) -> dict[str, str]:
        """Build the Authorization header for the current request."""
        if self._app_auth is not None:
            token = await self._app_auth.get_token()
        elif self._token is not None:
            token = self._token
        else:
            return {}
        return {"Authorization": f"Bearer {token}"}

    async def _post(self, payload: dict) -> dict:
        """POST *payload* to the GraphQL endpoint with retry on 502/503.

        Returns
        -------
        dict
            Parsed JSON response body.

        Raises
        ------
        APIError
            On persistent HTTP errors after retries are exhausted.
        """
        auth_headers = await self._auth_headers()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **auth_headers,
        }

        last_response: httpx.Response | None = None

        for attempt in range(_MAX_RETRIES + 1):
            response = await self._client.post(
                self._graphql_url,
                json=payload,
                headers=headers,
            )

            if response.status_code not in _RETRY_STATUSES:
                # Non-2xx that isn't a retry target → surface as APIError
                if not response.is_success:
                    raise APIError(
                        f"GraphQL HTTP error {response.status_code}: {response.text[:200]}",
                        status_code=response.status_code,
                    )
                return response.json()

            last_response = response

            if attempt < _MAX_RETRIES:
                backoff = 2**attempt  # 1s, 2s
                _log.warning(
                    "HTTP %s from GraphQL endpoint — retrying in %ds (attempt %d/%d)",
                    response.status_code,
                    backoff,
                    attempt + 1,
                    _MAX_RETRIES,
                )
                await asyncio.sleep(backoff)

        # All retries exhausted
        assert last_response is not None
        raise APIError(
            f"GraphQL HTTP {last_response.status_code} after "
            f"{_MAX_RETRIES} retries: {self._graphql_url}",
            status_code=last_response.status_code,
        )

    @staticmethod
    def _check_for_fatal_errors(body: dict, *, context: str) -> None:
        """Inspect a GraphQL response body and act on ``errors``.

        Rules
        -----
        - ``data`` is ``None`` **and** ``errors`` is present → raise ``APIError``.
        - ``data`` is non-null **and** ``errors`` is present → log warnings,
          continue (partial success).
        - No ``errors`` field → nothing to do.
        """
        errors = body.get("errors")
        if not errors:
            return

        data = body.get("data")

        if data is None:
            # Fatal: the whole query failed
            messages = "; ".join(e.get("message", "unknown") for e in errors)
            raise APIError(f"GraphQL query failed: {messages}")

        # Check for null organization (also fatal)
        org_data = data.get("organization")
        if org_data is None:
            messages = "; ".join(e.get("message", "unknown") for e in errors)
            raise APIError(f"GraphQL query returned null organization in {context}: {messages}")

        # Partial error: log warnings, return normally
        for err in errors:
            msg = err.get("message", "unknown GraphQL error")
            path = err.get("path")
            _log.warning(
                "GraphQL partial error in %s (path=%s): %s",
                context,
                path,
                msg,
            )
