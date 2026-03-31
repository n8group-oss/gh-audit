"""Unit tests for enterprise category models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.enterprise import (
    EnterpriseBilling,
    EnterpriseInventory,
    EnterpriseIPAllowList,
    EnterprisePolicies,
    EnterpriseSAML,
    EnterpriseTeamInfo,
)


class TestEnterpriseBilling:
    def test_defaults(self) -> None:
        b = EnterpriseBilling()
        assert b.total_licenses == 0
        assert b.used_licenses == 0
        assert b.bandwidth_usage_gb == 0.0
        assert b.bandwidth_quota_gb == 0.0
        assert b.storage_usage_gb == 0.0
        assert b.storage_quota_gb == 0.0

    def test_with_data(self) -> None:
        b = EnterpriseBilling(total_licenses=500, used_licenses=450, storage_usage_gb=12.5)
        assert b.total_licenses == 500
        assert b.used_licenses == 450
        assert b.storage_usage_gb == 12.5

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            EnterpriseBilling(unknown="x")


class TestEnterprisePolicies:
    def test_defaults(self) -> None:
        p = EnterprisePolicies()
        assert p.default_repository_permission is None
        assert p.members_can_create_repositories is None
        assert p.members_can_change_repo_visibility is None
        assert p.members_can_delete_repositories is None
        assert p.members_can_fork_private_repos is None
        assert p.two_factor_required is None
        assert p.repository_deploy_key_setting is None

    def test_with_data(self) -> None:
        p = EnterprisePolicies(
            default_repository_permission="read",
            two_factor_required="enabled",
        )
        assert p.default_repository_permission == "read"
        assert p.two_factor_required == "enabled"

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            EnterprisePolicies(unknown="x")


class TestEnterpriseSAML:
    def test_defaults(self) -> None:
        s = EnterpriseSAML()
        assert s.enabled is False
        assert s.issuer is None
        assert s.sso_url is None

    def test_enabled(self) -> None:
        s = EnterpriseSAML(
            enabled=True, issuer="https://idp.example.com", sso_url="https://sso.example.com"
        )
        assert s.enabled is True
        assert s.issuer == "https://idp.example.com"

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            EnterpriseSAML(unknown="x")


class TestEnterpriseIPAllowList:
    def test_defaults(self) -> None:
        ip = EnterpriseIPAllowList()
        assert ip.enabled is False
        assert ip.entries_count == 0
        assert ip.for_installed_apps is False

    def test_with_data(self) -> None:
        ip = EnterpriseIPAllowList(enabled=True, entries_count=10, for_installed_apps=True)
        assert ip.enabled is True
        assert ip.entries_count == 10

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            EnterpriseIPAllowList(unknown="x")


class TestEnterpriseTeamInfo:
    def test_defaults(self) -> None:
        t = EnterpriseTeamInfo(name="Platform", slug="platform")
        assert t.member_count == 0
        assert t.org_count == 0

    def test_full(self) -> None:
        t = EnterpriseTeamInfo(name="Eng", slug="eng", member_count=50, org_count=3)
        assert t.name == "Eng"
        assert t.member_count == 50

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            EnterpriseTeamInfo(name="x", slug="x", unknown="y")


class TestEnterpriseInventory:
    def test_minimal(self) -> None:
        inv = EnterpriseInventory(name="My Enterprise", slug="my-enterprise")
        assert inv.name == "My Enterprise"
        assert inv.billing is None
        assert inv.policies is None
        assert inv.saml is None
        assert inv.ip_allow_list is None
        assert inv.verified_domains == []
        assert inv.enterprise_rulesets == []
        assert inv.enterprise_teams == []
        assert inv.members_count == 0
        assert inv.admins_count == 0
        assert inv.outside_collaborators_count == 0

    def test_full(self) -> None:
        inv = EnterpriseInventory(
            name="Acme Corp",
            slug="acme",
            billing=EnterpriseBilling(total_licenses=1000, used_licenses=800),
            policies=EnterprisePolicies(two_factor_required="enabled"),
            saml=EnterpriseSAML(enabled=True),
            ip_allow_list=EnterpriseIPAllowList(enabled=True, entries_count=5),
            verified_domains=["acme.com", "acme.io"],
            enterprise_teams=[EnterpriseTeamInfo(name="Engineering", slug="eng", member_count=50)],
            members_count=800,
            admins_count=10,
            outside_collaborators_count=20,
        )
        assert inv.billing.total_licenses == 1000
        assert inv.policies.two_factor_required == "enabled"
        assert len(inv.verified_domains) == 2
        assert inv.enterprise_teams[0].member_count == 50

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            EnterpriseInventory(name="x", slug="x", unknown="y")
