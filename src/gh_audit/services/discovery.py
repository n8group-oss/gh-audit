"""Discovery orchestration — the core service that ties all adapters together.

Responsibilities
----------------
- Fetch all repositories via GraphQL (bulk metadata + counts).
- Apply ``repo_limit`` and ``include_archived`` filters before deep analysis.
- Run per-repo deep tasks concurrently, bounded by ``asyncio.Semaphore``.
- Skip expensive operations unless enabled by scan profile / flags.
- Discover org-level resources: users, packages, projects.
- Build summary from aggregated repo data.
- Aggregate warnings at repo and scan level; never raise on optional failures.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from gh_audit.__about__ import __version__
from gh_audit.models.actions import ActionsInfo, WorkflowInfo
from gh_audit.models.config import ScannerConfig, resolve_active_categories
from gh_audit.models.governance import (
    CustomPropertySchema,
    CustomRoleInfo,
    GovernanceInventory,
    OrgPolicies,
    RepoTeamAccess,
    RulesetDetail,
    TeamInfo,
)
from gh_audit.models.operations import (
    ActionsPermissions,
    DeployKeyInfo,
    EnvironmentInfo,
    EnvironmentProtection,
    InstalledAppInfo,
    OperationsInventory,
    RunnerGroupInfo,
    RunnerInfo,
    SecretMetadata,
    VariableMetadata,
    WebhookInfo,
)
from gh_audit.models.adoption import (
    ActionsRunSummary,
    AdoptionInventory,
    CommitActivityInfo,
    CommunityProfileInfo,
    CopilotInfo,
    OrgCommunityHealth,
    TrafficInfo,
)
from gh_audit.models.security_detail import (
    CodeScanningAlertInfo,
    CodeScanningSetup,
    DependabotAlertInfo,
    SBOMSummary,
    SecretScanningAlertInfo,
    SecurityDetail,
)
from gh_audit.models.enterprise import (
    EnterpriseBilling,
    EnterpriseInventory,
    EnterpriseIPAllowList,
    EnterprisePolicies,
    EnterpriseSAML,
)
from gh_audit.models.inventory import (
    Inventory,
    InventoryMetadata,
    InventorySummary,
)
from gh_audit.models.packages import PackageInfo
from gh_audit.models.projects import ProjectInfo
from gh_audit.models.repository import (
    BranchProtectionSummary,
    LargeFileInfo,
    LFSInfo,
    RepositoryInventoryItem,
)
from gh_audit.models.user import OrgMemberSummary
from gh_audit.services.workflow_parser import analyze_workflow_yaml

_log = logging.getLogger(__name__)

_SCHEMA_VERSION = "2.0"

_PACKAGE_TYPES = ["npm", "maven", "rubygems", "docker", "nuget", "container"]


class DiscoveryService:
    """Orchestrates a full organization scan.

    Parameters
    ----------
    rest_client:
        Async GitHub REST API client.
    graphql_client:
        Async GitHub GraphQL API client.
    config:
        Scanner configuration for this run.
    """

    def __init__(
        self,
        *,
        rest_client,
        graphql_client,
        config: ScannerConfig,
        telemetry=None,
    ) -> None:
        self._rest = rest_client
        self._gql = graphql_client
        self._config = config
        self._telemetry = telemetry

    def _record_warning(
        self,
        warnings: list[str],
        message: str,
        *,
        event: str,
        operation: str,
        category: str | None,
        organization: str | None = None,
        repo: str | None = None,
        error: BaseException | None = None,
        **properties,
    ) -> None:
        """Append a human-readable warning and emit structured telemetry."""
        warnings.append(message)

        if self._telemetry is None:
            return

        payload = dict(properties)
        if error is None:
            payload["warning_message"] = message

        self._telemetry.track_warning(
            event,
            error=error,
            command="discover",
            operation=operation,
            category=category,
            organization=organization or self._config.organization,
            repo=repo,
            warning_scope=event.removesuffix("_warning"),
            **payload,
        )

    async def discover(self) -> Inventory:
        """Execute the full discovery flow and return a complete Inventory."""
        org = self._config.organization
        scan_warnings: list[str] = []

        # 1. Fetch all repos via GraphQL
        graphql_repos = await self._gql.fetch_all_repos(org)

        # Filter archived if requested
        if not self._config.include_archived:
            graphql_repos = [r for r in graphql_repos if not r.get("isArchived", False)]

        # 2. Apply repo_limit
        if self._config.repo_limit is not None:
            graphql_repos = graphql_repos[: self._config.repo_limit]

        # 3. Resolve active categories before repo processing (needed to skip rulesets)
        active_cats = resolve_active_categories(self._config)

        # 4. Process each repo concurrently with semaphore
        semaphore = asyncio.Semaphore(self._config.concurrency)
        skip_rulesets = "governance" in active_cats

        async def _process_repo(gql_node: dict) -> RepositoryInventoryItem:
            async with semaphore:
                return await self._build_repo_item(gql_node, skip_rulesets=skip_rulesets)

        repo_items = await asyncio.gather(*[_process_repo(node) for node in graphql_repos])
        repo_items = list(repo_items)

        # 5. Org-level discovery: users, packages, projects
        users = await self._discover_users(org, scan_warnings)
        packages = await self._discover_packages(org, scan_warnings)
        projects = await self._discover_projects(org, scan_warnings)

        # 6. Governance category
        governance = None
        if "governance" in active_cats:
            governance = await self._discover_governance(org, scan_warnings)
            await self._enrich_repos_governance(org, repo_items, scan_warnings)

        # 6b. Operations category
        operations = None
        if "operations" in active_cats:
            operations = await self._discover_operations(org, scan_warnings)
            await self._enrich_repos_operations(org, repo_items, scan_warnings)

        # 6c. Security detail category (per-repo only, no org-level model)
        if "security" in active_cats:
            await self._enrich_repos_security_detail(org, repo_items, scan_warnings)

        # 6d. Adoption category
        adoption = None
        if "adoption" in active_cats:
            adoption = await self._discover_adoption(org, scan_warnings)
            await self._enrich_repos_adoption(org, repo_items, scan_warnings)
            # Aggregate community health from enriched repos
            profiles = [r.community_profile for r in repo_items if r.community_profile is not None]
            if profiles:
                adoption.org_community_health = OrgCommunityHealth(
                    repos_with_readme=sum(1 for p in profiles if p.has_readme),
                    repos_with_license=sum(1 for p in profiles if p.has_license),
                    repos_with_contributing=sum(1 for p in profiles if p.has_contributing),
                    repos_with_code_of_conduct=sum(1 for p in profiles if p.has_code_of_conduct),
                    repos_with_issue_template=sum(1 for p in profiles if p.has_issue_template),
                    repos_with_pr_template=sum(1 for p in profiles if p.has_pull_request_template),
                    average_health_percentage=sum(p.health_percentage for p in profiles)
                    / len(profiles),
                )

        # 6e. Enterprise category
        enterprise = None
        if "enterprise" in active_cats:
            enterprise = await self._discover_enterprise(scan_warnings)

        # 7. Build summary
        summary = self._build_summary(repo_items, packages, projects)

        # 8. Build metadata
        metadata = InventoryMetadata(
            schema_version=_SCHEMA_VERSION,
            generated_at=datetime.now(timezone.utc),
            tool_version=__version__,
            organization=org,
            auth_method=self._config.auth_method,
            api_url=self._config.api_url,
            scan_profile=self._config.scan_profile,
            scan_options={
                "scan_large_files": self._config.scan_large_files,
                "scan_workflow_contents": self._config.scan_workflow_contents,
                "security_alert_counts": self._config.security_alert_counts,
                "repo_limit": self._config.repo_limit,
                "concurrency": self._config.concurrency,
                "include_archived": self._config.include_archived,
                "categories": sorted(active_cats),
            },
            scan_warnings=scan_warnings,
            active_categories=sorted(active_cats),
            enterprise_slug=self._config.enterprise_slug,
        )

        return Inventory(
            metadata=metadata,
            summary=summary,
            repositories=repo_items,
            users=users,
            packages=packages,
            projects=projects,
            governance=governance,
            operations=operations,
            adoption=adoption,
            enterprise=enterprise,
        )

    # ------------------------------------------------------------------
    # Per-repo processing
    # ------------------------------------------------------------------

    async def _build_repo_item(
        self, node: dict, *, skip_rulesets: bool = False
    ) -> RepositoryInventoryItem:
        """Map a GraphQL repo node + REST enrichment to a RepositoryInventoryItem."""
        org = self._config.organization
        name = node["name"]
        warnings: list[str] = []

        # Base fields from GraphQL
        item = self._map_graphql_base(node)

        # LFS detection from .gitattributes
        item.lfs_info = self._parse_lfs(node)

        # REST enrichment tasks (run concurrently within the semaphore)
        tasks = []

        # Always: list_workflows
        tasks.append(self._enrich_workflows(org, name, item, warnings))

        # Rulesets (skip when governance category will handle it to avoid duplicate API calls)
        if not skip_rulesets:
            tasks.append(self._enrich_rulesets(org, name, item, warnings))

        # Always: get_security_features
        tasks.append(self._enrich_security_features(org, name, item, warnings))

        # Conditional: large file scan
        if self._config.scan_large_files:
            tasks.append(self._enrich_large_files(org, name, item, warnings))

        # Conditional: security alert counts
        if self._config.security_alert_counts:
            tasks.append(self._enrich_alert_counts(org, name, item, warnings))

        await asyncio.gather(*tasks)

        # Conditional: workflow content parsing (needs workflows list first)
        if self._config.scan_workflow_contents and item.actions.workflows:
            await self._enrich_workflow_contents(org, name, item, warnings)

        item.warnings = warnings
        return item

    def _map_graphql_base(self, node: dict) -> RepositoryInventoryItem:
        """Map GraphQL node fields to RepositoryInventoryItem base fields."""
        lang_node = node.get("primaryLanguage")
        default_branch_ref = node.get("defaultBranchRef")
        topic_nodes = node.get("repositoryTopics", {}).get("nodes", [])

        label_nodes = node.get("labels", {}).get("nodes", [])
        label_dist = {
            lbl["name"]: lbl["issues"]["totalCount"]
            for lbl in label_nodes
            if isinstance(lbl, dict) and "name" in lbl
        }

        return RepositoryInventoryItem(
            name=node["name"],
            full_name=node["nameWithOwner"],
            description=node.get("description"),
            visibility=node.get("visibility", "PRIVATE").lower(),
            archived=node.get("isArchived", False),
            fork=node.get("isFork", False),
            is_template=node.get("isTemplate", False),
            language=lang_node["name"] if lang_node else None,
            topics=[t["topic"]["name"] for t in topic_nodes],
            default_branch=default_branch_ref["name"] if default_branch_ref else None,
            size_bytes=node.get("diskUsage", 0) * 1024,  # KB -> bytes
            branch_count=node.get("refs", {}).get("totalCount", 0),
            pr_count_open=node.get("openPRs", {}).get("totalCount", 0),
            pr_count_closed=node.get("closedPRs", {}).get("totalCount", 0),
            pr_count_merged=node.get("mergedPRs", {}).get("totalCount", 0),
            issue_count_open=node.get("openIssues", {}).get("totalCount", 0),
            issue_count_closed=node.get("closedIssues", {}).get("totalCount", 0),
            issue_label_distribution=label_dist,
            branch_protection=BranchProtectionSummary(
                protected_branches=node.get("branchProtectionRules", {}).get("totalCount", 0),
            ),
        )

    def _parse_lfs(self, node: dict) -> LFSInfo:
        """Parse LFS patterns from .gitattributes content in the GraphQL node."""
        obj = node.get("object")
        if not obj or not isinstance(obj, dict):
            return LFSInfo()

        text = obj.get("text", "")
        if not text:
            return LFSInfo()

        patterns = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "filter=lfs" in line:
                # First token is the pattern
                parts = line.split()
                if parts:
                    patterns.append(parts[0])

        if patterns:
            return LFSInfo(has_lfs=True, patterns=patterns)
        return LFSInfo()

    # ------------------------------------------------------------------
    # REST enrichment tasks
    # ------------------------------------------------------------------

    async def _enrich_workflows(
        self,
        org: str,
        repo: str,
        item: RepositoryInventoryItem,
        warnings: list[str],
    ) -> None:
        """Fetch workflow listings from REST."""
        try:
            workflows = await self._rest.list_workflows(org, repo)
            workflow_infos = [
                WorkflowInfo(
                    name=w.get("name", ""),
                    path=w.get("path", ""),
                    state=w.get("state", "active"),
                )
                for w in workflows
            ]
            item.actions = ActionsInfo(
                has_workflows=len(workflow_infos) > 0,
                workflow_count=len(workflow_infos),
                workflows=workflow_infos,
            )
        except Exception as exc:
            _log.warning("Failed to list workflows for %s/%s: %s", org, repo, exc)
            self._record_warning(
                warnings,
                f"Failed to list workflows: {exc}",
                event="repo_enrichment_warning",
                operation="list_workflows",
                category="actions",
                organization=org,
                repo=repo,
                error=exc,
            )

    async def _enrich_workflow_contents(
        self,
        org: str,
        repo: str,
        item: RepositoryInventoryItem,
        warnings: list[str],
    ) -> None:
        """Fetch and parse workflow file contents for deep analysis."""
        all_actions: set[str] = set()
        uses_self_hosted = False

        for wf in item.actions.workflows:
            try:
                content = await self._rest.get_workflow_file(org, repo, wf.path)
                if content:
                    analysis = analyze_workflow_yaml(content)
                    all_actions.update(analysis.actions_used)
                    if analysis.uses_self_hosted_runners:
                        uses_self_hosted = True
            except Exception as exc:
                _log.warning(
                    "Failed to fetch workflow %s for %s/%s: %s",
                    wf.path,
                    org,
                    repo,
                    exc,
                )
                warnings.append(f"Failed to fetch workflow {wf.path}: {exc}")

        item.actions.actions_used = sorted(all_actions)
        item.actions.uses_self_hosted_runners = uses_self_hosted
        item.actions.analysis_level = "parsed"

    async def _enrich_rulesets(
        self,
        org: str,
        repo: str,
        item: RepositoryInventoryItem,
        warnings: list[str],
    ) -> None:
        """Fetch repository rulesets from REST."""
        try:
            rulesets = await self._rest.list_rulesets(org, repo)
            if rulesets is None:
                # Forbidden
                item.branch_protection.ruleset_count = None
                self._record_warning(
                    warnings,
                    f"Rulesets not accessible for {org}/{repo}",
                    event="repo_enrichment_warning",
                    operation="list_rulesets",
                    category="governance",
                    organization=org,
                    repo=repo,
                )
            else:
                item.branch_protection.ruleset_count = len(rulesets)
        except Exception as exc:
            _log.warning("Failed to list rulesets for %s/%s: %s", org, repo, exc)
            item.branch_protection.ruleset_count = None
            self._record_warning(
                warnings,
                f"Failed to list rulesets: {exc}",
                event="repo_enrichment_warning",
                operation="list_rulesets",
                category="governance",
                organization=org,
                repo=repo,
                error=exc,
            )

    async def _enrich_security_features(
        self,
        org: str,
        repo: str,
        item: RepositoryInventoryItem,
        warnings: list[str],
    ) -> None:
        """Fetch security feature enablement from REST."""
        try:
            data = await self._rest.get_security_features(org, repo)
            sa = data.get("security_and_analysis", {})

            dependabot = sa.get("dependabot_security_updates", {})
            secret_scanning = sa.get("secret_scanning", {})
            advanced = sa.get("advanced_security", {})

            item.security.dependabot_enabled = (
                dependabot.get("status") == "enabled" if dependabot else None
            )
            item.security.secret_scanning_enabled = (
                secret_scanning.get("status") == "enabled" if secret_scanning else None
            )
            item.security.code_scanning_enabled = (
                advanced.get("status") == "enabled" if advanced else None
            )
        except Exception as exc:
            _log.warning("Failed to get security features for %s/%s: %s", org, repo, exc)
            self._record_warning(
                warnings,
                f"Failed to get security features: {exc}",
                event="repo_enrichment_warning",
                operation="get_security_features",
                category="security",
                organization=org,
                repo=repo,
                error=exc,
            )

    async def _enrich_large_files(
        self,
        org: str,
        repo: str,
        item: RepositoryInventoryItem,
        warnings: list[str],
    ) -> None:
        """Scan the git tree for files exceeding the large-file threshold."""
        item.large_file_scan.enabled = True

        default_branch = item.default_branch
        if not default_branch:
            # Can't scan without a default branch
            return

        try:
            tree_data = await self._rest.get_tree(org, repo, default_branch)
            truncated = tree_data.get("truncated", False)
            item.large_file_scan.truncated = truncated

            threshold = item.large_file_scan.threshold_bytes
            large_files = []
            for entry in tree_data.get("tree", []):
                if entry.get("type") != "blob":
                    continue
                size = entry.get("size", 0)
                if size and size >= threshold:
                    large_files.append(LargeFileInfo(path=entry["path"], size_bytes=size))

            item.large_file_scan.files = large_files
            item.large_file_scan.completed = True
        except Exception as exc:
            _log.warning("Failed to scan large files for %s/%s: %s", org, repo, exc)
            warnings.append(f"Failed to scan large files (tree fetch): {exc}")

    async def _enrich_alert_counts(
        self,
        org: str,
        repo: str,
        item: RepositoryInventoryItem,
        warnings: list[str],
    ) -> None:
        """Fetch security alert counts from REST."""
        try:
            dep, code, secret = await asyncio.gather(
                self._rest.count_dependabot_alerts(org, repo),
                self._rest.count_code_scanning_alerts(org, repo),
                self._rest.count_secret_scanning_alerts(org, repo),
            )

            all_accessible = dep.accessible and code.accessible and secret.accessible
            any_accessible = dep.accessible or code.accessible or secret.accessible

            item.security.dependabot_alerts_open = dep.count
            item.security.code_scanning_alerts_open = code.count
            item.security.secret_scanning_alerts_open = secret.count
            item.security.alerts_accessible = any_accessible
            item.security.counts_exact = all_accessible
        except Exception as exc:
            _log.warning("Failed to count alerts for %s/%s: %s", org, repo, exc)
            warnings.append(f"Failed to count security alerts: {exc}")

    # ------------------------------------------------------------------
    # Org-level discovery
    # ------------------------------------------------------------------

    async def _discover_users(self, org: str, scan_warnings: list[str]) -> OrgMemberSummary:
        """Discover organization members and outside collaborators."""
        try:
            admins, members, collabs = await asyncio.gather(
                self._rest.list_org_members(org, role="admin"),
                self._rest.list_org_members(org, role="member"),
                self._rest.list_outside_collaborators(org),
            )
            admin_count = len(admins)
            member_count = len(members)
            collab_count = len(collabs)
            return OrgMemberSummary(
                total=admin_count + member_count + collab_count,
                admins=admin_count,
                members=member_count,
                outside_collaborators=collab_count,
            )
        except Exception as exc:
            _log.warning("Failed to discover users for %s: %s", org, exc)
            self._record_warning(
                scan_warnings,
                f"Failed to discover org members: {exc}",
                event="org_discovery_warning",
                operation="list_org_members",
                category="users",
                organization=org,
                error=exc,
            )
            return OrgMemberSummary()

    async def _discover_packages(self, org: str, scan_warnings: list[str]) -> list[PackageInfo]:
        """Discover packages across all registry types."""
        all_packages: list[PackageInfo] = []

        for pkg_type in _PACKAGE_TYPES:
            try:
                raw_packages = await self._rest.list_packages(org, pkg_type)
                for pkg in raw_packages:
                    all_packages.append(
                        PackageInfo(
                            name=pkg.get("name", ""),
                            package_type=pkg.get("package_type", pkg_type),
                            visibility=pkg.get("visibility", "private"),
                        )
                    )
            except Exception as exc:
                _log.warning("Failed to list %s packages for %s: %s", pkg_type, org, exc)
                self._record_warning(
                    scan_warnings,
                    f"Failed to list {pkg_type} packages: {exc}",
                    event="org_discovery_warning",
                    operation="list_packages",
                    category="packages",
                    organization=org,
                    error=exc,
                    package_type=pkg_type,
                )

        return all_packages

    async def _discover_projects(self, org: str, scan_warnings: list[str]) -> list[ProjectInfo]:
        """Discover GitHub Projects (v2) via GraphQL."""
        try:
            raw_projects = await self._gql.fetch_projects(org)
            return [
                ProjectInfo(
                    title=p.get("title", ""),
                    item_count=p.get("items", {}).get("totalCount", 0),
                    closed=p.get("closed", False),
                )
                for p in raw_projects
            ]
        except Exception as exc:
            _log.warning("Failed to discover projects for %s: %s", org, exc)
            self._record_warning(
                scan_warnings,
                f"Failed to discover projects: {exc}",
                event="org_discovery_warning",
                operation="fetch_projects",
                category="projects",
                organization=org,
                error=exc,
            )
            return []

    # ------------------------------------------------------------------
    # Governance category discovery
    # ------------------------------------------------------------------

    async def _discover_governance(self, org: str, scan_warnings: list[str]) -> GovernanceInventory:
        """Discover org-level governance data."""
        # Fetch teams with member/repo counts
        teams_raw: list[dict] = []
        try:
            teams_raw = await self._rest.list_teams(org)
        except Exception as exc:
            scan_warnings.append(f"Teams discovery failed: {exc}")

        teams = []
        for t in teams_raw:
            teams.append(
                TeamInfo(
                    name=t.get("name", ""),
                    slug=t.get("slug", ""),
                    description=t.get("description"),
                    privacy=t.get("privacy", "closed"),
                    permission=t.get("permission", "pull"),
                    member_count=t.get("members_count", 0),
                    repo_count=t.get("repos_count", 0),
                    parent_team=(t.get("parent", {}).get("slug") if t.get("parent") else None),
                )
            )

        # Fetch org rulesets with detail
        org_rulesets: list[RulesetDetail] = []
        try:
            rulesets_raw = await self._rest.list_org_rulesets(org)
            for rs in rulesets_raw:
                rs_id = rs.get("id")
                if rs_id:
                    detail = await self._rest.get_org_ruleset_detail(org, rs_id)
                    if detail:
                        org_rulesets.append(
                            RulesetDetail(
                                name=detail.get("name", ""),
                                enforcement=detail.get("enforcement", "disabled"),
                                target=detail.get("target", "branch"),
                                source_type=detail.get("source_type", "Organization"),
                                rules=detail.get("rules", []),
                                conditions=detail.get("conditions"),
                                bypass_actors=detail.get("bypass_actors", []),
                            )
                        )
        except Exception as exc:
            scan_warnings.append(f"Org rulesets discovery failed: {exc}")

        # Fetch org policies from org settings
        policies = OrgPolicies()
        try:
            org_data = await self._rest.verify_credentials(org)
            policies = OrgPolicies(
                default_repository_permission=org_data.get("default_repository_permission"),
                members_can_create_repositories=org_data.get("members_can_create_repositories"),
                members_can_create_public_repositories=org_data.get(
                    "members_can_create_public_repositories"
                ),
                members_can_create_private_repositories=org_data.get(
                    "members_can_create_private_repositories"
                ),
                members_can_create_internal_repositories=org_data.get(
                    "members_can_create_internal_repositories"
                ),
                members_can_fork_private_repositories=org_data.get(
                    "members_can_fork_private_repositories"
                ),
                members_can_delete_repositories=org_data.get("members_can_delete_repositories"),
                members_can_change_repo_visibility=org_data.get(
                    "members_can_change_repo_visibility"
                ),
                two_factor_requirement_enabled=org_data.get("two_factor_requirement_enabled"),
                web_commit_signoff_required=org_data.get("web_commit_signoff_required"),
            )
        except Exception as exc:
            self._record_warning(
                scan_warnings,
                f"Org policies discovery failed: {exc}",
                event="org_discovery_warning",
                operation="verify_credentials",
                category="governance",
                organization=org,
                error=exc,
            )

        # Custom roles (may 403 on non-Enterprise)
        custom_roles: list[CustomRoleInfo] = []
        try:
            roles_raw = await self._rest.list_custom_roles(org)
            custom_roles = [
                CustomRoleInfo(
                    name=r.get("name", ""),
                    description=r.get("description"),
                    permissions=r.get("permissions", []),
                )
                for r in roles_raw
            ]
        except Exception as exc:
            scan_warnings.append(f"Custom roles discovery failed: {exc}")

        # Custom properties schema
        props_schema: list[CustomPropertySchema] = []
        try:
            props_raw = await self._rest.list_custom_properties_schema(org)
            props_schema = [
                CustomPropertySchema(
                    property_name=p.get("property_name", ""),
                    value_type=p.get("value_type", "string"),
                    required=p.get("required", False),
                    description=p.get("description"),
                    allowed_values=p.get("allowed_values", []),
                )
                for p in props_raw
            ]
        except Exception as exc:
            scan_warnings.append(f"Custom properties discovery failed: {exc}")

        # Org secrets/variables counts
        secrets_count = 0
        variables_count = 0
        dependabot_secrets_count = 0
        try:
            secrets = await self._rest.list_org_action_secrets(org)
            secrets_count = len(secrets)
        except Exception as exc:
            scan_warnings.append(f"Org Actions secrets discovery failed: {exc}")
        try:
            variables = await self._rest.list_org_action_variables(org)
            variables_count = len(variables)
        except Exception as exc:
            scan_warnings.append(f"Org Actions variables discovery failed: {exc}")
        try:
            dep_secrets = await self._rest.list_org_dependabot_secrets(org)
            dependabot_secrets_count = len(dep_secrets)
        except Exception as exc:
            scan_warnings.append(f"Org Dependabot secrets discovery failed: {exc}")

        return GovernanceInventory(
            teams=teams,
            org_rulesets=org_rulesets,
            org_policies=policies,
            custom_roles=custom_roles,
            custom_properties_schema=props_schema,
            org_secrets_count=secrets_count,
            org_variables_count=variables_count,
            org_dependabot_secrets_count=dependabot_secrets_count,
        )

    async def _enrich_repos_governance(
        self,
        org: str,
        repos: list[RepositoryInventoryItem],
        scan_warnings: list[str],
    ) -> None:
        """Enrich repos with governance data (concurrent with semaphore)."""
        semaphore = asyncio.Semaphore(self._config.concurrency)

        async def _enrich_one(repo: RepositoryInventoryItem) -> None:
            async with semaphore:
                name = repo.name
                # Rulesets detail
                try:
                    rulesets_raw = await self._rest.list_rulesets(org, name)
                    if rulesets_raw is not None:
                        repo.rulesets_detail = [
                            RulesetDetail(
                                name=rs.get("name", ""),
                                enforcement=rs.get("enforcement", "disabled"),
                                target=rs.get("target", "branch"),
                                source_type=rs.get("source_type", "Repository"),
                                rules=rs.get("rules", []),
                                conditions=rs.get("conditions"),
                                bypass_actors=rs.get("bypass_actors", []),
                            )
                            for rs in rulesets_raw
                        ]
                        # Update ruleset_count from detail
                        repo.branch_protection.ruleset_count = len(repo.rulesets_detail)
                    else:
                        repo.rulesets_detail = []
                except Exception:
                    repo.rulesets_detail = []
                    repo.warnings.append("Rulesets detail fetch failed")

                # Custom properties
                try:
                    repo.custom_properties = await self._rest.get_repo_custom_properties(org, name)
                except Exception:
                    repo.custom_properties = {}

                # Teams with access
                try:
                    teams_raw = await self._rest.list_repo_teams(org, name)
                    repo.teams_with_access = [
                        RepoTeamAccess(
                            team_slug=t.get("slug", ""),
                            permission=t.get("permission", "pull"),
                        )
                        for t in teams_raw
                    ]
                except Exception:
                    repo.teams_with_access = []

        await asyncio.gather(*[_enrich_one(r) for r in repos])

    # ------------------------------------------------------------------
    # Operations category discovery
    # ------------------------------------------------------------------

    async def _discover_operations(self, org: str, scan_warnings: list[str]) -> OperationsInventory:
        """Discover org-level operations data."""
        # Runners
        runners: list[RunnerInfo] = []
        try:
            runners_raw = await self._rest.list_org_runners(org)
            runners = [
                RunnerInfo(
                    name=r.get("name", ""),
                    os=r.get("os", ""),
                    status=r.get("status", "offline"),
                    labels=[lbl.get("name", "") for lbl in r.get("labels", [])],
                    busy=r.get("busy", False),
                    runner_group_name=r.get("runner_group_name"),
                )
                for r in runners_raw
            ]
        except Exception as exc:
            scan_warnings.append(f"Runners discovery failed: {exc}")

        # Runner groups
        runner_groups: list[RunnerGroupInfo] = []
        try:
            groups_raw = await self._rest.list_org_runner_groups(org)
            runner_groups = [
                RunnerGroupInfo(
                    name=g.get("name", ""),
                    visibility=g.get("visibility", "all"),
                    allows_public_repos=g.get("allows_public_repositories", False),
                    runner_count=g.get("runners_count", 0),
                    repo_count=g.get("selected_repositories_count"),
                )
                for g in groups_raw
            ]
        except Exception as exc:
            scan_warnings.append(f"Runner groups discovery failed: {exc}")

        # Installed apps
        installed_apps: list[InstalledAppInfo] = []
        try:
            apps_raw = await self._rest.list_org_installations(org)
            for app in apps_raw:
                installed_apps.append(
                    InstalledAppInfo(
                        app_name=app.get("app", {}).get("name", ""),
                        app_slug=app.get("app", {}).get("slug", ""),
                        permissions=app.get("permissions", {}),
                        events=app.get("events", []),
                        repository_selection=app.get("repository_selection", "all"),
                    )
                )
        except Exception as exc:
            scan_warnings.append(f"Installed apps discovery failed: {exc}")

        # Org webhooks
        org_webhooks: list[WebhookInfo] = []
        try:
            hooks_raw = await self._rest.list_org_webhooks(org)
            for hook in hooks_raw:
                domain = urlparse(hook.get("config", {}).get("url", "")).netloc or "unknown"
                org_webhooks.append(
                    WebhookInfo(
                        url_domain=domain,
                        events=hook.get("events", []),
                        active=hook.get("active", True),
                        content_type=hook.get("config", {}).get("content_type", "json"),
                        insecure_ssl=hook.get("config", {}).get("insecure_ssl", "0") == "1",
                    )
                )
        except Exception as exc:
            scan_warnings.append(f"Org webhooks discovery failed: {exc}")

        # Org secrets/variables metadata
        org_secrets_metadata: list[SecretMetadata] = []
        try:
            secrets_raw = await self._rest.list_org_action_secrets(org)
            org_secrets_metadata = [
                SecretMetadata(
                    name=s.get("name", ""),
                    created_at=s.get("created_at", ""),
                    updated_at=s.get("updated_at", ""),
                    visibility=s.get("visibility", "private"),
                    selected_repositories_count=s.get("selected_repositories_count"),
                )
                for s in secrets_raw
            ]
        except Exception as exc:
            scan_warnings.append(f"Org secrets metadata discovery failed: {exc}")

        org_variables_metadata: list[VariableMetadata] = []
        try:
            variables_raw = await self._rest.list_org_action_variables(org)
            org_variables_metadata = [
                VariableMetadata(
                    name=v.get("name", ""),
                    value=v.get("value", ""),
                    created_at=v.get("created_at", ""),
                    updated_at=v.get("updated_at", ""),
                    visibility=v.get("visibility", "private"),
                )
                for v in variables_raw
            ]
        except Exception as exc:
            scan_warnings.append(f"Org variables metadata discovery failed: {exc}")

        return OperationsInventory(
            runners=runners,
            runner_groups=runner_groups,
            installed_apps=installed_apps,
            org_webhooks=org_webhooks,
            org_secrets_metadata=org_secrets_metadata,
            org_variables_metadata=org_variables_metadata,
        )

    async def _enrich_repos_operations(
        self,
        org: str,
        repos: list[RepositoryInventoryItem],
        scan_warnings: list[str],
    ) -> None:
        """Enrich repos with operations data (concurrent with semaphore)."""
        semaphore = asyncio.Semaphore(self._config.concurrency)

        async def _enrich_one(repo: RepositoryInventoryItem) -> None:
            async with semaphore:
                name = repo.name

                # Environments
                try:
                    envs_raw = await self._rest.list_repo_environments(org, name)
                    repo.environments = [self._map_environment(env) for env in envs_raw]
                except Exception:
                    repo.environments = []
                    repo.warnings.append("Environments fetch failed")

                # Deploy keys
                try:
                    keys_raw = await self._rest.list_repo_deploy_keys(org, name)
                    repo.deploy_keys = [
                        DeployKeyInfo(
                            title=k.get("title", ""),
                            read_only=k.get("read_only", True),
                            created_at=k.get("created_at", ""),
                        )
                        for k in keys_raw
                    ]
                except Exception:
                    repo.deploy_keys = []
                    repo.warnings.append("Deploy keys fetch failed")

                # Repo webhooks
                try:
                    hooks_raw = await self._rest.list_repo_webhooks(org, name)
                    repo.repo_webhooks = [
                        WebhookInfo(
                            url_domain=urlparse(h.get("config", {}).get("url", "")).netloc
                            or "unknown",
                            events=h.get("events", []),
                            active=h.get("active", True),
                            content_type=h.get("config", {}).get("content_type", "json"),
                            insecure_ssl=h.get("config", {}).get("insecure_ssl", "0") == "1",
                        )
                        for h in hooks_raw
                    ]
                except Exception:
                    repo.repo_webhooks = []
                    repo.warnings.append("Repo webhooks fetch failed")

                # Repo secrets count
                try:
                    secrets = await self._rest.list_repo_action_secrets(org, name)
                    repo.repo_secrets_count = len(secrets)
                except Exception:
                    repo.repo_secrets_count = 0
                    repo.warnings.append("Repo secrets count fetch failed")

                # Repo variables count
                try:
                    variables = await self._rest.list_repo_action_variables(org, name)
                    repo.repo_variables_count = len(variables)
                except Exception:
                    repo.repo_variables_count = 0
                    repo.warnings.append("Repo variables count fetch failed")

                # Actions permissions
                try:
                    perms_raw = await self._rest.get_repo_actions_permissions(org, name)
                    if perms_raw is not None:
                        repo.actions_permissions = ActionsPermissions(
                            enabled=perms_raw.get("enabled", True),
                            allowed_actions=perms_raw.get("allowed_actions", "all"),
                        )
                    else:
                        repo.actions_permissions = ActionsPermissions()
                except Exception as exc:
                    repo.actions_permissions = ActionsPermissions()
                    self._record_warning(
                        repo.warnings,
                        "Actions permissions fetch failed",
                        event="repo_enrichment_warning",
                        operation="get_repo_actions_permissions",
                        category="operations",
                        organization=org,
                        repo=name,
                        error=exc,
                    )

        await asyncio.gather(*[_enrich_one(r) for r in repos])

    # ------------------------------------------------------------------
    # Security detail category discovery
    # ------------------------------------------------------------------

    async def _enrich_repos_security_detail(
        self,
        org: str,
        repos: list[RepositoryInventoryItem],
        scan_warnings: list[str],
    ) -> None:
        """Enrich repos with full security detail (concurrent with semaphore)."""
        semaphore = asyncio.Semaphore(self._config.concurrency)

        async def _enrich_one(repo: RepositoryInventoryItem) -> None:
            async with semaphore:
                name = repo.name

                # Dependabot alerts
                dependabot_alerts: list[DependabotAlertInfo] = []
                try:
                    raw = await self._rest.list_dependabot_alerts_detail(org, name)
                    for alert in raw:
                        vuln = alert.get("security_vulnerability", {}) or {}
                        pkg = vuln.get("package", {}) or {}
                        advisory = alert.get("security_advisory", {}) or {}
                        first_patched = vuln.get("first_patched_version") or {}
                        identifiers = advisory.get("identifiers", [])
                        cve_id = None
                        for ident in identifiers:
                            if ident.get("type") == "CVE":
                                cve_id = ident.get("value")
                                break
                        dependabot_alerts.append(
                            DependabotAlertInfo(
                                severity=vuln.get("severity", alert.get("severity", "unknown")),
                                package_name=pkg.get("name", ""),
                                manifest_path=alert.get("dependency", {}).get("manifest_path", ""),
                                state=alert.get("state", "open"),
                                ghsa_id=advisory.get("ghsa_id"),
                                cve_id=cve_id,
                                fixed_version=first_patched.get("identifier"),
                            )
                        )
                except Exception:
                    repo.warnings.append("Dependabot alerts detail fetch failed")

                # Code scanning alerts
                code_scanning_alerts: list[CodeScanningAlertInfo] = []
                try:
                    raw = await self._rest.list_code_scanning_alerts_detail(org, name)
                    for alert in raw:
                        rule = alert.get("rule", {}) or {}
                        tool = alert.get("tool", {}) or {}
                        code_scanning_alerts.append(
                            CodeScanningAlertInfo(
                                rule_id=rule.get("id", ""),
                                severity=rule.get("severity"),
                                security_severity=rule.get("security_severity_level"),
                                tool_name=tool.get("name", ""),
                                state=alert.get("state", "open"),
                                dismissed_reason=alert.get("dismissed_reason"),
                            )
                        )
                except Exception:
                    repo.warnings.append("Code scanning alerts detail fetch failed")

                # Secret scanning alerts
                secret_scanning_alerts: list[SecretScanningAlertInfo] = []
                try:
                    raw = await self._rest.list_secret_scanning_alerts_detail(org, name)
                    for alert in raw:
                        secret_scanning_alerts.append(
                            SecretScanningAlertInfo(
                                secret_type=alert.get("secret_type", ""),
                                secret_type_display_name=alert.get("secret_type_display_name"),
                                state=alert.get("state", "open"),
                                resolution=alert.get("resolution"),
                                push_protection_bypassed=alert.get(
                                    "push_protection_bypassed", False
                                )
                                or False,
                            )
                        )
                except Exception:
                    repo.warnings.append("Secret scanning alerts detail fetch failed")

                # SBOM
                sbom_summary: SBOMSummary | None = None
                try:
                    raw_sbom = await self._rest.get_repo_sbom(org, name)
                    if raw_sbom is not None:
                        sbom = raw_sbom.get("sbom", {}) or {}
                        packages = sbom.get("packages", [])
                        # Extract unique package managers from externalRefs or purl
                        managers: set[str] = set()
                        for pkg in packages:
                            for ref in pkg.get("externalRefs", []):
                                locator = ref.get("referenceLocator", "")
                                if locator.startswith("pkg:"):
                                    # Extract ecosystem from purl: "pkg:npm/..." -> "npm"
                                    parts = locator[4:].split("/", 1)
                                    if parts:
                                        managers.add(parts[0])
                        sbom_summary = SBOMSummary(
                            dependency_count=len(packages),
                            package_managers=sorted(managers),
                        )
                except Exception:
                    repo.warnings.append("SBOM fetch failed")

                # Code scanning default setup
                code_scanning_setup: CodeScanningSetup | None = None
                try:
                    raw_setup = await self._rest.get_code_scanning_default_setup(org, name)
                    if raw_setup is not None:
                        code_scanning_setup = CodeScanningSetup(
                            default_setup_enabled=raw_setup.get("state", "") == "configured",
                            languages=raw_setup.get("languages", []),
                        )
                except Exception as exc:
                    self._record_warning(
                        repo.warnings,
                        "Code scanning setup fetch failed",
                        event="repo_enrichment_warning",
                        operation="get_code_scanning_default_setup",
                        category="security",
                        organization=org,
                        repo=name,
                        error=exc,
                    )

                # Security configuration
                security_config_name: str | None = None
                try:
                    raw_config = await self._rest.get_repo_security_configuration(org, name)
                    if raw_config is not None:
                        config_data = raw_config.get("configuration", {}) or {}
                        security_config_name = config_data.get("name")
                except Exception:
                    repo.warnings.append("Security configuration fetch failed")

                repo.security_detail = SecurityDetail(
                    dependabot_alerts=dependabot_alerts,
                    code_scanning_alerts=code_scanning_alerts,
                    secret_scanning_alerts=secret_scanning_alerts,
                    sbom_summary=sbom_summary,
                    code_scanning_setup=code_scanning_setup,
                    security_configuration_name=security_config_name,
                )

        await asyncio.gather(*[_enrich_one(r) for r in repos])

    # ------------------------------------------------------------------
    # Adoption category discovery
    # ------------------------------------------------------------------

    async def _discover_adoption(
        self,
        org: str,
        scan_warnings: list[str],
    ) -> AdoptionInventory:
        """Org-level adoption discovery: Copilot + placeholder community health."""
        copilot: CopilotInfo | None = None
        try:
            billing = await self._rest.get_copilot_billing(org)
            if billing is not None:
                seat_breakdown = billing.get("seat_breakdown", {})
                metrics_raw = await self._rest.get_copilot_metrics(org)
                total_suggestions = sum(m.get("total_suggestions_count", 0) for m in metrics_raw)
                total_acceptances = sum(m.get("total_acceptances_count", 0) for m in metrics_raw)
                lang_counts: dict[str, int] = {}
                for m in metrics_raw:
                    lang = m.get("language", "")
                    if lang:
                        lang_counts[lang] = lang_counts.get(lang, 0) + m.get(
                            "total_suggestions_count", 0
                        )
                top_languages = sorted(lang_counts, key=lambda k: lang_counts[k], reverse=True)[:10]
                copilot = CopilotInfo(
                    total_seats=seat_breakdown.get("total", 0),
                    active_seats=seat_breakdown.get("active_this_cycle"),
                    suggestions_count=total_suggestions if metrics_raw else None,
                    acceptances_count=total_acceptances if metrics_raw else None,
                    top_languages=top_languages,
                )
        except Exception as exc:
            scan_warnings.append(f"Copilot discovery failed: {exc}")

        return AdoptionInventory(
            copilot=copilot,
            org_community_health=OrgCommunityHealth(),
        )

    async def _enrich_repos_adoption(
        self,
        org: str,
        repos: list[RepositoryInventoryItem],
        scan_warnings: list[str],
    ) -> None:
        """Enrich repos with adoption data (concurrent with semaphore)."""
        from datetime import timedelta

        ninety_days_ago = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
        created_filter = f">={ninety_days_ago}"

        semaphore = asyncio.Semaphore(self._config.concurrency)

        async def _enrich_one(repo: RepositoryInventoryItem) -> None:
            async with semaphore:
                name = repo.name

                # Traffic (views + clones fetched concurrently)
                try:
                    views, clones = await asyncio.gather(
                        self._rest.get_repo_traffic_views(org, name),
                        self._rest.get_repo_traffic_clones(org, name),
                    )
                    if views is not None or clones is not None:
                        repo.traffic = TrafficInfo(
                            views_14d=views.get("count") if views else None,
                            unique_visitors_14d=views.get("uniques") if views else None,
                            clones_14d=clones.get("count") if clones else None,
                            unique_cloners_14d=clones.get("uniques") if clones else None,
                        )
                except Exception:
                    repo.warnings.append("Traffic fetch failed")

                # Community profile
                try:
                    profile = await self._rest.get_repo_community_profile(org, name)
                    if profile is not None:
                        files = profile.get("files", {})
                        repo.community_profile = CommunityProfileInfo(
                            health_percentage=profile.get("health_percentage", 0),
                            has_readme=files.get("readme") is not None,
                            has_contributing=files.get("contributing") is not None,
                            has_license=files.get("license") is not None,
                            has_code_of_conduct=files.get("code_of_conduct") is not None,
                            has_issue_template=files.get("issue_template") is not None,
                            has_pull_request_template=files.get("pull_request_template")
                            is not None,
                        )
                except Exception:
                    repo.warnings.append("Community profile fetch failed")

                # Commit activity
                try:
                    weeks = await self._rest.get_repo_commit_activity(org, name)
                    if weeks:
                        # API returns 52 weeks; slice to last ~13 for 90-day window
                        recent = weeks[-13:]
                        total = sum(w.get("total", 0) for w in recent)
                        active = sum(1 for w in recent if w.get("total", 0) > 0)
                        repo.commit_activity_90d = CommitActivityInfo(
                            total_commits=total,
                            active_weeks=active,
                        )
                    else:
                        repo.commit_activity_90d = CommitActivityInfo()
                except Exception:
                    repo.warnings.append("Commit activity fetch failed")

                # Actions run summary (3 filtered count queries)
                try:
                    by_conclusion: dict[str, int] = {}
                    total = 0
                    for conclusion in ("success", "failure", "cancelled"):
                        count = await self._rest.get_workflow_runs_count(
                            org,
                            name,
                            conclusion=conclusion,
                            created=created_filter,
                        )
                        if count > 0:
                            by_conclusion[conclusion] = count
                            total += count
                    repo.actions_run_summary = ActionsRunSummary(
                        total_runs_90d=total,
                        by_conclusion=by_conclusion,
                    )
                except Exception:
                    repo.warnings.append("Actions run summary fetch failed")

        await asyncio.gather(*[_enrich_one(r) for r in repos])

    @staticmethod
    def _map_environment(env: dict) -> EnvironmentInfo:
        """Map a raw environment dict to an EnvironmentInfo model."""
        protection = None
        rules = env.get("protection_rules", [])
        if rules:
            wait_timer = 0
            required_reviewers = 0
            for rule in rules:
                rule_type = rule.get("type", "")
                if rule_type == "wait_timer":
                    wait_timer = rule.get("wait_timer", 0)
                elif rule_type == "required_reviewers":
                    reviewers = rule.get("reviewers", [])
                    required_reviewers = len(reviewers)
            protection = EnvironmentProtection(
                wait_timer=wait_timer,
                required_reviewers=required_reviewers,
            )

        deployment_branch_policy = env.get("deployment_branch_policy")
        if deployment_branch_policy is not None and protection is None:
            protection = EnvironmentProtection()
        if deployment_branch_policy is not None and protection is not None:
            if deployment_branch_policy.get("protected_branches"):
                protection.branch_policy = "protected"
            elif deployment_branch_policy.get("custom_branch_policies"):
                protection.branch_policy = "custom"

        return EnvironmentInfo(
            name=env.get("name", ""),
            protection_rules=protection,
            secrets_count=0,  # Would require extra API call
            variables_count=0,  # Would require extra API call
            can_admins_bypass=env.get("can_admins_bypass", True),
        )

    # ------------------------------------------------------------------
    # Enterprise discovery
    # ------------------------------------------------------------------

    async def _discover_enterprise(
        self,
        scan_warnings: list[str],
    ) -> EnterpriseInventory | None:
        """Enterprise-level discovery via GraphQL.

        Note: enterprise_teams and enterprise_rulesets fields on
        EnterpriseInventory are not yet populated — enterprise teams require
        iterating all orgs, and rulesets require a REST endpoint.
        """
        slug = self._config.enterprise_slug
        if not slug:
            return None

        # Fetch main enterprise info
        try:
            info = await self._gql.fetch_enterprise_info(slug)
        except Exception as exc:
            self._record_warning(
                scan_warnings,
                f"Enterprise info discovery failed: {exc}",
                event="enterprise_discovery_warning",
                operation="fetch_enterprise_info",
                category="enterprise",
                error=exc,
                enterprise_slug=slug,
            )
            return None

        if info is None:
            self._record_warning(
                scan_warnings,
                "Enterprise info not accessible (check permissions)",
                event="enterprise_discovery_warning",
                operation="fetch_enterprise_info",
                category="enterprise",
                enterprise_slug=slug,
            )
            return None

        # SAML
        saml_raw = info.get("saml", {})
        saml = EnterpriseSAML(
            enabled=saml_raw.get("enabled", False),
            issuer=saml_raw.get("issuer"),
            sso_url=saml_raw.get("sso_url"),
        )

        # IP allow list
        ip_raw = info.get("ip_allow_list", {})
        ip_allow_list = EnterpriseIPAllowList(
            enabled=ip_raw.get("enabled", False),
            entries_count=ip_raw.get("entries_count", 0),
            for_installed_apps=ip_raw.get("for_installed_apps", False),
        )

        # Billing (separate query, may fail independently)
        billing: EnterpriseBilling | None = None
        try:
            billing_raw = await self._gql.fetch_enterprise_billing(slug)
            if billing_raw is not None:
                billing = EnterpriseBilling(
                    total_licenses=billing_raw.get("total_licenses", 0),
                    used_licenses=billing_raw.get("used_licenses", 0),
                    bandwidth_usage_gb=billing_raw.get("bandwidth_usage_gb", 0.0),
                    bandwidth_quota_gb=billing_raw.get("bandwidth_quota_gb", 0.0),
                    storage_usage_gb=billing_raw.get("storage_usage_gb", 0.0),
                    storage_quota_gb=billing_raw.get("storage_quota_gb", 0.0),
                )
        except Exception as exc:
            self._record_warning(
                scan_warnings,
                f"Enterprise billing discovery failed: {exc}",
                event="enterprise_discovery_warning",
                operation="fetch_enterprise_billing",
                category="enterprise",
                error=exc,
                enterprise_slug=slug,
            )

        # Policies (separate query, may fail independently)
        policies: EnterprisePolicies | None = None
        try:
            policies_raw = await self._gql.fetch_enterprise_policies(slug)
            if policies_raw is not None:
                policies = EnterprisePolicies(**policies_raw)
        except Exception as exc:
            self._record_warning(
                scan_warnings,
                f"Enterprise policies discovery failed: {exc}",
                event="enterprise_discovery_warning",
                operation="fetch_enterprise_policies",
                category="enterprise",
                error=exc,
                enterprise_slug=slug,
            )

        return EnterpriseInventory(
            name=info["name"],
            slug=info["slug"],
            billing=billing,
            policies=policies,
            saml=saml,
            ip_allow_list=ip_allow_list,
            verified_domains=info.get("verified_domains", []),
            members_count=info.get("members_count", 0),
            admins_count=info.get("admins_count", 0),
            outside_collaborators_count=info.get("outside_collaborators_count", 0),
        )

    # ------------------------------------------------------------------
    # Summary builder
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        repos: list[RepositoryInventoryItem],
        packages: list[PackageInfo],
        projects: list[ProjectInfo],
    ) -> InventorySummary:
        """Aggregate repo-level data into an InventorySummary."""
        visibility_counts = Counter(r.visibility for r in repos)
        packages_by_type = Counter(p.package_type for p in packages)

        return InventorySummary(
            total_repos=len(repos),
            public_repos=visibility_counts.get("public", 0),
            private_repos=visibility_counts.get("private", 0),
            internal_repos=visibility_counts.get("internal", 0),
            archived_repos=sum(1 for r in repos if r.archived),
            forked_repos=sum(1 for r in repos if r.fork),
            template_repos=sum(1 for r in repos if r.is_template),
            total_size_bytes=sum(r.size_bytes for r in repos),
            total_branches=sum(r.branch_count for r in repos),
            total_prs=sum(r.pr_count_open + r.pr_count_closed + r.pr_count_merged for r in repos),
            total_issues=sum(r.issue_count_open + r.issue_count_closed for r in repos),
            repos_with_large_files=sum(1 for r in repos if r.large_file_scan.files),
            repos_with_lfs=sum(1 for r in repos if r.lfs_info.has_lfs),
            repos_with_workflows=sum(1 for r in repos if r.actions.has_workflows),
            total_workflow_count=sum(r.actions.workflow_count for r in repos),
            repos_with_self_hosted_runners=sum(
                1 for r in repos if r.actions.uses_self_hosted_runners
            ),
            repos_with_dependabot=sum(1 for r in repos if r.security.dependabot_enabled is True),
            repos_with_code_scanning=sum(
                1 for r in repos if r.security.code_scanning_enabled is True
            ),
            repos_with_secret_scanning=sum(
                1 for r in repos if r.security.secret_scanning_enabled is True
            ),
            total_packages=len(packages),
            packages_by_type=dict(packages_by_type),
            total_projects=len(projects),
        )
