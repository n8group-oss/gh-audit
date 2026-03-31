"""Tests for security detail category integration in DiscoveryService.

Covers:
- Standard profile: security_detail is None
- Security category: security_detail populated on each repo
- Dependabot alerts mapped correctly
- Code scanning alerts mapped correctly
- Secret scanning alerts mapped correctly
- SBOM summary extracted
- Code scanning default setup mapped
- Security configuration name extracted
- Graceful degradation: each endpoint failure adds warning
- active_categories includes "security"
- Total profile enables security category
- Multiple repos enrichment
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gh_audit.adapters.base import AlertCountResult
from gh_audit.models.config import ScannerConfig
from gh_audit.services.discovery import DiscoveryService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *,
    organization: str = "myorg",
    scan_profile: str = "standard",
    categories: list[str] | None = None,
    concurrency: int = 4,
    **kwargs,
) -> ScannerConfig:
    return ScannerConfig(
        organization=organization,
        token="ghp_fake_token",
        scan_profile=scan_profile,
        categories=categories or [],
        concurrency=concurrency,
        **kwargs,
    )


def _make_graphql_repo(
    name: str = "repo1",
    *,
    org: str = "myorg",
    visibility: str = "PRIVATE",
) -> dict:
    return {
        "name": name,
        "nameWithOwner": f"{org}/{name}",
        "visibility": visibility,
        "isArchived": False,
        "isFork": False,
        "isTemplate": False,
        "primaryLanguage": {"name": "Python"},
        "repositoryTopics": {"nodes": []},
        "diskUsage": 1024,
        "defaultBranchRef": {"name": "main"},
        "description": "A test repo",
        "refs": {"totalCount": 3},
        "openPRs": {"totalCount": 1},
        "closedPRs": {"totalCount": 0},
        "mergedPRs": {"totalCount": 2},
        "openIssues": {"totalCount": 1},
        "closedIssues": {"totalCount": 3},
        "labels": {"nodes": [{"name": "bug", "issues": {"totalCount": 1}}]},
        "branchProtectionRules": {"totalCount": 1},
        "object": None,
    }


def _make_graphql_client(repos: list[dict] | None = None) -> AsyncMock:
    gql = AsyncMock()
    gql.fetch_all_repos.return_value = repos if repos is not None else [_make_graphql_repo()]
    gql.fetch_projects.return_value = []
    return gql


def _make_rest_client(*, with_security_detail: bool = False) -> AsyncMock:
    rest = AsyncMock()

    # Standard discovery defaults
    rest.list_workflows.return_value = []
    rest.get_workflow_file.return_value = None
    rest.get_tree.return_value = {"tree": [], "truncated": False}
    rest.count_dependabot_alerts.return_value = AlertCountResult.inaccessible()
    rest.count_code_scanning_alerts.return_value = AlertCountResult.inaccessible()
    rest.count_secret_scanning_alerts.return_value = AlertCountResult.inaccessible()
    rest.get_security_features.return_value = {
        "security_and_analysis": {
            "advanced_security": {"status": "enabled"},
            "dependabot_security_updates": {"status": "enabled"},
            "secret_scanning": {"status": "enabled"},
        }
    }
    rest.list_rulesets.return_value = []
    rest.list_org_members.return_value = []
    rest.list_outside_collaborators.return_value = []
    rest.list_packages.return_value = []

    # Security detail endpoint defaults (empty)
    rest.list_dependabot_alerts_detail.return_value = []
    rest.list_code_scanning_alerts_detail.return_value = []
    rest.list_secret_scanning_alerts_detail.return_value = []
    rest.get_repo_sbom.return_value = None
    rest.get_code_scanning_default_setup.return_value = None
    rest.get_repo_security_configuration.return_value = None

    if with_security_detail:
        rest.list_dependabot_alerts_detail.return_value = [
            {
                "number": 1,
                "state": "open",
                "dependency": {"manifest_path": "package-lock.json"},
                "security_vulnerability": {
                    "severity": "high",
                    "package": {"name": "lodash"},
                    "first_patched_version": {"identifier": "4.17.21"},
                },
                "security_advisory": {
                    "ghsa_id": "GHSA-xxxx-yyyy",
                    "identifiers": [
                        {"type": "CVE", "value": "CVE-2026-0001"},
                        {"type": "GHSA", "value": "GHSA-xxxx-yyyy"},
                    ],
                },
            },
            {
                "number": 2,
                "state": "fixed",
                "dependency": {"manifest_path": "yarn.lock"},
                "security_vulnerability": {
                    "severity": "critical",
                    "package": {"name": "express"},
                    "first_patched_version": None,
                },
                "security_advisory": {
                    "ghsa_id": "GHSA-aaaa-bbbb",
                    "identifiers": [{"type": "GHSA", "value": "GHSA-aaaa-bbbb"}],
                },
            },
        ]

        rest.list_code_scanning_alerts_detail.return_value = [
            {
                "number": 1,
                "state": "open",
                "rule": {
                    "id": "js/xss",
                    "severity": "error",
                    "security_severity_level": "high",
                },
                "tool": {"name": "CodeQL"},
                "dismissed_reason": None,
            },
        ]

        rest.list_secret_scanning_alerts_detail.return_value = [
            {
                "number": 1,
                "state": "open",
                "secret_type": "github_personal_access_token",
                "secret_type_display_name": "GitHub Personal Access Token",
                "resolution": None,
                "push_protection_bypassed": True,
            },
        ]

        rest.get_repo_sbom.return_value = {
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "lodash",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/lodash@4.17.21",
                            }
                        ],
                    },
                    {
                        "name": "requests",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests@2.28.0",
                            }
                        ],
                    },
                ],
            }
        }

        rest.get_code_scanning_default_setup.return_value = {
            "state": "configured",
            "languages": ["python", "javascript"],
        }

        rest.get_repo_security_configuration.return_value = {
            "configuration": {
                "name": "org-default-security",
                "description": "Default security config",
            },
        }

    return rest


# ---------------------------------------------------------------------------
# Test: standard profile — security_detail is None
# ---------------------------------------------------------------------------


class TestStandardProfileNoSecurityDetail:
    """Standard profile without categories should not produce security detail."""

    @pytest.mark.asyncio
    async def test_security_detail_is_none(self):
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail is None

    @pytest.mark.asyncio
    async def test_security_detail_rest_methods_not_called(self):
        rest = _make_rest_client()
        config = _make_config(scan_profile="standard")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        await svc.discover()
        rest.list_dependabot_alerts_detail.assert_not_called()
        rest.list_code_scanning_alerts_detail.assert_not_called()
        rest.list_secret_scanning_alerts_detail.assert_not_called()
        rest.get_repo_sbom.assert_not_called()
        rest.get_code_scanning_default_setup.assert_not_called()
        rest.get_repo_security_configuration.assert_not_called()


# ---------------------------------------------------------------------------
# Test: security category enabled — detail populated
# ---------------------------------------------------------------------------


class TestSecurityCategoryEnabled:
    """When security category is active, security_detail should be populated."""

    @pytest.mark.asyncio
    async def test_security_detail_not_none(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail is not None

    @pytest.mark.asyncio
    async def test_dependabot_alerts_mapped(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert len(sd.dependabot_alerts) == 2

        alert1 = sd.dependabot_alerts[0]
        assert alert1.severity == "high"
        assert alert1.package_name == "lodash"
        assert alert1.manifest_path == "package-lock.json"
        assert alert1.state == "open"
        assert alert1.ghsa_id == "GHSA-xxxx-yyyy"
        assert alert1.cve_id == "CVE-2026-0001"
        assert alert1.fixed_version == "4.17.21"

        alert2 = sd.dependabot_alerts[1]
        assert alert2.severity == "critical"
        assert alert2.package_name == "express"
        assert alert2.state == "fixed"
        assert alert2.cve_id is None  # no CVE in identifiers
        assert alert2.fixed_version is None  # first_patched_version is None

    @pytest.mark.asyncio
    async def test_code_scanning_alerts_mapped(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert len(sd.code_scanning_alerts) == 1

        alert = sd.code_scanning_alerts[0]
        assert alert.rule_id == "js/xss"
        assert alert.severity == "error"
        assert alert.security_severity == "high"
        assert alert.tool_name == "CodeQL"
        assert alert.state == "open"
        assert alert.dismissed_reason is None

    @pytest.mark.asyncio
    async def test_secret_scanning_alerts_mapped(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert len(sd.secret_scanning_alerts) == 1

        alert = sd.secret_scanning_alerts[0]
        assert alert.secret_type == "github_personal_access_token"
        assert alert.secret_type_display_name == "GitHub Personal Access Token"
        assert alert.state == "open"
        assert alert.resolution is None
        assert alert.push_protection_bypassed is True

    @pytest.mark.asyncio
    async def test_sbom_summary_extracted(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert sd.sbom_summary is not None
        assert sd.sbom_summary.dependency_count == 2
        assert sorted(sd.sbom_summary.package_managers) == ["npm", "pypi"]

    @pytest.mark.asyncio
    async def test_code_scanning_setup_mapped(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert sd.code_scanning_setup is not None
        assert sd.code_scanning_setup.default_setup_enabled is True
        assert sd.code_scanning_setup.languages == ["python", "javascript"]

    @pytest.mark.asyncio
    async def test_security_configuration_name_extracted(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert sd.security_configuration_name == "org-default-security"


# ---------------------------------------------------------------------------
# Test: active_categories in metadata
# ---------------------------------------------------------------------------


class TestSecurityMetadataCategories:
    @pytest.mark.asyncio
    async def test_active_categories_includes_security(self):
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "security" in inventory.metadata.active_categories

    @pytest.mark.asyncio
    async def test_categories_in_scan_options(self):
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=_make_rest_client(),
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "security" in inventory.metadata.scan_options["categories"]


# ---------------------------------------------------------------------------
# Test: graceful degradation
# ---------------------------------------------------------------------------


class TestSecurityDetailGracefulDegradation:
    @pytest.mark.asyncio
    async def test_dependabot_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_dependabot_alerts_detail.side_effect = Exception("forbidden")
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail is not None
        assert repo.security_detail.dependabot_alerts == []
        assert any("Dependabot alerts detail fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_code_scanning_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_code_scanning_alerts_detail.side_effect = Exception("forbidden")
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail.code_scanning_alerts == []
        assert any("Code scanning alerts detail fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_secret_scanning_failure_records_warning(self):
        rest = _make_rest_client()
        rest.list_secret_scanning_alerts_detail.side_effect = Exception("forbidden")
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail.secret_scanning_alerts == []
        assert any("Secret scanning alerts detail fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_sbom_failure_records_warning(self):
        rest = _make_rest_client()
        rest.get_repo_sbom.side_effect = Exception("network error")
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail.sbom_summary is None
        assert any("SBOM fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_code_scanning_setup_failure_records_warning(self):
        rest = _make_rest_client()
        rest.get_code_scanning_default_setup.side_effect = Exception("timeout")
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail.code_scanning_setup is None
        assert any("Code scanning setup fetch failed" in w for w in repo.warnings)

    @pytest.mark.asyncio
    async def test_security_configuration_failure_records_warning(self):
        rest = _make_rest_client()
        rest.get_repo_security_configuration.side_effect = Exception("error")
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail.security_configuration_name is None
        assert any("Security configuration fetch failed" in w for w in repo.warnings)


# ---------------------------------------------------------------------------
# Test: total profile enables security
# ---------------------------------------------------------------------------


class TestTotalProfileEnablesSecurity:
    @pytest.mark.asyncio
    async def test_total_profile_security_detail_not_none(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        repo = inventory.repositories[0]
        assert repo.security_detail is not None

    @pytest.mark.asyncio
    async def test_total_profile_active_categories_include_security(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        assert "security" in inventory.metadata.active_categories

    @pytest.mark.asyncio
    async def test_total_profile_dependabot_alerts_discovered(self):
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(scan_profile="total")
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert len(sd.dependabot_alerts) == 2


# ---------------------------------------------------------------------------
# Test: multiple repos enrichment
# ---------------------------------------------------------------------------


class TestMultipleReposSecurityEnrichment:
    @pytest.mark.asyncio
    async def test_all_repos_enriched(self):
        repos = [
            _make_graphql_repo(name="repo1"),
            _make_graphql_repo(name="repo2"),
            _make_graphql_repo(name="repo3"),
        ]
        rest = _make_rest_client(with_security_detail=True)
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(repos=repos),
            config=config,
        )
        inventory = await svc.discover()
        assert len(inventory.repositories) == 3
        for repo in inventory.repositories:
            assert repo.security_detail is not None
            assert len(repo.security_detail.dependabot_alerts) == 2
            assert len(repo.security_detail.code_scanning_alerts) == 1
            assert len(repo.security_detail.secret_scanning_alerts) == 1
            assert repo.security_detail.sbom_summary is not None
            assert repo.security_detail.code_scanning_setup is not None
            assert repo.security_detail.security_configuration_name is not None


# ---------------------------------------------------------------------------
# Test: empty results (no alerts/no SBOM)
# ---------------------------------------------------------------------------


class TestSecurityDetailEmptyResults:
    @pytest.mark.asyncio
    async def test_empty_alerts_and_no_sbom(self):
        rest = _make_rest_client()  # defaults: all empty
        config = _make_config(categories=["security"])
        svc = DiscoveryService(
            rest_client=rest,
            graphql_client=_make_graphql_client(),
            config=config,
        )
        inventory = await svc.discover()
        sd = inventory.repositories[0].security_detail
        assert sd is not None
        assert sd.dependabot_alerts == []
        assert sd.code_scanning_alerts == []
        assert sd.secret_scanning_alerts == []
        assert sd.sbom_summary is None
        assert sd.code_scanning_setup is None
        assert sd.security_configuration_name is None
