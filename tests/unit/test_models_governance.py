"""Unit tests for governance models.

Covers:
- Construction with defaults for every model
- Field types and values
- extra="forbid" rejection of unknown fields
- JSON roundtrip for GovernanceInventory
- Integration with Inventory and RepositoryInventoryItem
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.governance import (
    CustomPropertySchema,
    CustomRoleInfo,
    GovernanceInventory,
    OrgPolicies,
    RepoTeamAccess,
    RulesetDetail,
    TeamInfo,
)
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.repository import RepositoryInventoryItem
from gh_audit.models.user import OrgMemberSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_metadata(**kwargs) -> InventoryMetadata:
    from datetime import datetime, timezone

    defaults = dict(
        schema_version="2.0",
        generated_at=datetime(2026, 3, 27, 12, 0, 0, tzinfo=timezone.utc),
        tool_version="0.1.0",
        organization="test-org",
        auth_method="pat",
        scan_profile="standard",
    )
    defaults.update(kwargs)
    return InventoryMetadata(**defaults)


def _make_repo(**kwargs) -> RepositoryInventoryItem:
    defaults = dict(name="repo", full_name="org/repo", visibility="private")
    defaults.update(kwargs)
    return RepositoryInventoryItem(**defaults)


def _make_inventory(**kwargs) -> Inventory:
    defaults = dict(
        metadata=_make_metadata(),
        summary=InventorySummary(),
        repositories=[],
        users=OrgMemberSummary(total=0, members=0),
    )
    defaults.update(kwargs)
    return Inventory(**defaults)


# ---------------------------------------------------------------------------
# TeamInfo
# ---------------------------------------------------------------------------


class TestTeamInfo:
    def test_minimal_construction(self):
        team = TeamInfo(name="Devs", slug="devs", privacy="closed", permission="push")
        assert team.name == "Devs"
        assert team.slug == "devs"
        assert team.privacy == "closed"
        assert team.permission == "push"
        assert team.description is None
        assert team.member_count == 0
        assert team.repo_count == 0
        assert team.parent_team is None

    def test_full_construction(self):
        team = TeamInfo(
            name="Backend",
            slug="backend",
            description="Backend engineers",
            privacy="secret",
            permission="admin",
            member_count=5,
            repo_count=12,
            parent_team="engineering",
        )
        assert team.description == "Backend engineers"
        assert team.privacy == "secret"
        assert team.permission == "admin"
        assert team.member_count == 5
        assert team.repo_count == 12
        assert team.parent_team == "engineering"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            TeamInfo(name="X", slug="x", privacy="closed", permission="pull", unknown_field="bad")


# ---------------------------------------------------------------------------
# RulesetDetail
# ---------------------------------------------------------------------------


class TestRulesetDetail:
    def test_minimal_construction(self):
        rs = RulesetDetail(
            name="protect-main",
            enforcement="active",
            target="branch",
            source_type="Repository",
        )
        assert rs.name == "protect-main"
        assert rs.enforcement == "active"
        assert rs.target == "branch"
        assert rs.source_type == "Repository"
        assert rs.rules == []
        assert rs.conditions is None
        assert rs.bypass_actors == []

    def test_with_rules_list(self):
        rs = RulesetDetail(
            name="org-rule",
            enforcement="evaluate",
            target="tag",
            source_type="Organization",
            rules=[{"type": "deletion"}, {"type": "required_signatures"}],
            conditions={"ref_name": {"include": ["refs/heads/main"]}},
            bypass_actors=[{"actor_id": 1, "actor_type": "Team"}],
        )
        assert len(rs.rules) == 2
        assert rs.rules[0]["type"] == "deletion"
        assert rs.conditions is not None
        assert len(rs.bypass_actors) == 1

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            RulesetDetail(
                name="x",
                enforcement="active",
                target="branch",
                source_type="Repository",
                surprise="yes",
            )

    def test_rules_default_is_independent(self):
        """Each instance gets its own list (no shared mutable default)."""
        r1 = RulesetDetail(
            name="a", enforcement="active", target="branch", source_type="Repository"
        )
        r2 = RulesetDetail(
            name="b", enforcement="active", target="branch", source_type="Repository"
        )
        r1.rules.append({"type": "deletion"})
        assert r2.rules == []


# ---------------------------------------------------------------------------
# OrgPolicies
# ---------------------------------------------------------------------------


class TestOrgPolicies:
    def test_all_defaults_are_none(self):
        p = OrgPolicies()
        assert p.default_repository_permission is None
        assert p.members_can_create_repositories is None
        assert p.members_can_create_public_repositories is None
        assert p.members_can_create_private_repositories is None
        assert p.members_can_create_internal_repositories is None
        assert p.members_can_fork_private_repositories is None
        assert p.members_can_delete_repositories is None
        assert p.members_can_change_repo_visibility is None
        assert p.two_factor_requirement_enabled is None
        assert p.web_commit_signoff_required is None

    def test_set_values(self):
        p = OrgPolicies(
            default_repository_permission="read",
            two_factor_requirement_enabled=True,
            members_can_create_repositories=False,
        )
        assert p.default_repository_permission == "read"
        assert p.two_factor_requirement_enabled is True
        assert p.members_can_create_repositories is False

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            OrgPolicies(not_a_policy=True)


# ---------------------------------------------------------------------------
# CustomRoleInfo
# ---------------------------------------------------------------------------


class TestCustomRoleInfo:
    def test_minimal_construction(self):
        role = CustomRoleInfo(name="read-plus")
        assert role.name == "read-plus"
        assert role.description is None
        assert role.permissions == []

    def test_with_permissions(self):
        role = CustomRoleInfo(
            name="ci-runner",
            description="Can trigger CI",
            permissions=["read", "write_checks"],
        )
        assert role.description == "Can trigger CI"
        assert "read" in role.permissions

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            CustomRoleInfo(name="x", sneaky=True)


# ---------------------------------------------------------------------------
# CustomPropertySchema
# ---------------------------------------------------------------------------


class TestCustomPropertySchema:
    def test_minimal_construction(self):
        prop = CustomPropertySchema(property_name="env", value_type="string")
        assert prop.property_name == "env"
        assert prop.value_type == "string"
        assert prop.required is False
        assert prop.description is None
        assert prop.allowed_values == []

    def test_with_allowed_values(self):
        prop = CustomPropertySchema(
            property_name="tier",
            value_type="single_select",
            required=True,
            description="Service tier",
            allowed_values=["gold", "silver", "bronze"],
        )
        assert prop.required is True
        assert prop.allowed_values == ["gold", "silver", "bronze"]

    def test_multi_select_type(self):
        prop = CustomPropertySchema(
            property_name="tags",
            value_type="multi_select",
            allowed_values=["frontend", "backend", "infra"],
        )
        assert prop.value_type == "multi_select"

    def test_true_false_type(self):
        prop = CustomPropertySchema(property_name="is_critical", value_type="true_false")
        assert prop.value_type == "true_false"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            CustomPropertySchema(property_name="x", value_type="string", nope="bad")


# ---------------------------------------------------------------------------
# RepoTeamAccess
# ---------------------------------------------------------------------------


class TestRepoTeamAccess:
    def test_construction(self):
        rta = RepoTeamAccess(team_slug="backend", permission="push")
        assert rta.team_slug == "backend"
        assert rta.permission == "push"

    def test_all_permissions(self):
        for perm in ("pull", "push", "admin", "maintain", "triage"):
            rta = RepoTeamAccess(team_slug="t", permission=perm)
            assert rta.permission == perm

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            RepoTeamAccess(team_slug="t", permission="pull", extra="bad")


# ---------------------------------------------------------------------------
# GovernanceInventory
# ---------------------------------------------------------------------------


class TestGovernanceInventory:
    def test_all_defaults(self):
        g = GovernanceInventory()
        assert g.teams == []
        assert g.org_rulesets == []
        assert isinstance(g.org_policies, OrgPolicies)
        assert g.custom_roles == []
        assert g.custom_properties_schema == []
        assert g.org_secrets_count == 0
        assert g.org_variables_count == 0
        assert g.org_dependabot_secrets_count == 0

    def test_with_teams(self):
        team = TeamInfo(name="Devs", slug="devs", privacy="closed", permission="push")
        g = GovernanceInventory(teams=[team])
        assert len(g.teams) == 1
        assert g.teams[0].slug == "devs"

    def test_with_rulesets(self):
        rs = RulesetDetail(
            name="main-protect",
            enforcement="active",
            target="branch",
            source_type="Organization",
        )
        g = GovernanceInventory(org_rulesets=[rs])
        assert len(g.org_rulesets) == 1

    def test_counts(self):
        g = GovernanceInventory(
            org_secrets_count=3,
            org_variables_count=5,
            org_dependabot_secrets_count=2,
        )
        assert g.org_secrets_count == 3
        assert g.org_variables_count == 5
        assert g.org_dependabot_secrets_count == 2

    def test_defaults_are_independent(self):
        g1 = GovernanceInventory()
        g2 = GovernanceInventory()
        g1.teams.append(TeamInfo(name="X", slug="x", privacy="closed", permission="pull"))
        assert g2.teams == []

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            GovernanceInventory(surprise="bad")

    def test_json_roundtrip(self):
        g = GovernanceInventory(
            teams=[TeamInfo(name="Devs", slug="devs", privacy="closed", permission="push")],
            org_rulesets=[
                RulesetDetail(
                    name="protect",
                    enforcement="active",
                    target="branch",
                    source_type="Repository",
                    rules=[{"type": "deletion"}],
                )
            ],
            org_policies=OrgPolicies(two_factor_requirement_enabled=True),
            custom_roles=[CustomRoleInfo(name="read-plus", permissions=["read"])],
            custom_properties_schema=[
                CustomPropertySchema(
                    property_name="env",
                    value_type="single_select",
                    allowed_values=["prod", "staging"],
                )
            ],
            org_secrets_count=4,
            org_variables_count=2,
            org_dependabot_secrets_count=1,
        )
        json_str = g.model_dump_json()
        g2 = GovernanceInventory.model_validate_json(json_str)
        assert g2.teams[0].slug == "devs"
        assert g2.org_rulesets[0].rules[0]["type"] == "deletion"
        assert g2.org_policies.two_factor_requirement_enabled is True
        assert g2.custom_roles[0].name == "read-plus"
        assert g2.custom_properties_schema[0].allowed_values == ["prod", "staging"]
        assert g2.org_secrets_count == 4
        assert g2.org_variables_count == 2
        assert g2.org_dependabot_secrets_count == 1


# ---------------------------------------------------------------------------
# Inventory integration
# ---------------------------------------------------------------------------


class TestInventoryGovernanceField:
    def test_governance_is_none_by_default(self):
        inv = _make_inventory()
        assert inv.governance is None

    def test_governance_can_be_set(self):
        g = GovernanceInventory(org_secrets_count=7)
        inv = _make_inventory(governance=g)
        assert inv.governance is not None
        assert inv.governance.org_secrets_count == 7

    def test_governance_full_population(self):
        g = GovernanceInventory(
            teams=[TeamInfo(name="Ops", slug="ops", privacy="closed", permission="admin")],
            org_policies=OrgPolicies(members_can_create_repositories=False),
        )
        inv = _make_inventory(governance=g)
        assert inv.governance.teams[0].slug == "ops"
        assert inv.governance.org_policies.members_can_create_repositories is False


# ---------------------------------------------------------------------------
# RepositoryInventoryItem governance fields
# ---------------------------------------------------------------------------


class TestRepositoryGovernanceFields:
    def test_governance_fields_are_none_by_default(self):
        repo = _make_repo()
        assert repo.rulesets_detail is None
        assert repo.custom_properties is None
        assert repo.teams_with_access is None

    def test_set_rulesets_detail(self):
        rs = RulesetDetail(
            name="protect-main",
            enforcement="active",
            target="branch",
            source_type="Repository",
        )
        repo = _make_repo(rulesets_detail=[rs])
        assert len(repo.rulesets_detail) == 1
        assert repo.rulesets_detail[0].name == "protect-main"

    def test_set_custom_properties(self):
        repo = _make_repo(custom_properties={"env": "prod", "tier": "gold"})
        assert repo.custom_properties["env"] == "prod"

    def test_set_teams_with_access(self):
        teams = [
            RepoTeamAccess(team_slug="backend", permission="push"),
            RepoTeamAccess(team_slug="security", permission="pull"),
        ]
        repo = _make_repo(teams_with_access=teams)
        assert len(repo.teams_with_access) == 2
        assert repo.teams_with_access[0].team_slug == "backend"

    def test_empty_lists_differ_from_none(self):
        """Empty list = scanned and found nothing; None = not scanned."""
        repo_scanned = _make_repo(rulesets_detail=[], teams_with_access=[])
        repo_not_scanned = _make_repo()
        assert repo_scanned.rulesets_detail == []
        assert repo_not_scanned.rulesets_detail is None


# ---------------------------------------------------------------------------
# InventoryMetadata new fields
# ---------------------------------------------------------------------------


class TestInventoryMetadataNewFields:
    def test_active_categories_defaults_empty(self):
        meta = _make_metadata()
        assert meta.active_categories == []

    def test_enterprise_slug_defaults_none(self):
        meta = _make_metadata()
        assert meta.enterprise_slug is None

    def test_active_categories_set(self):
        meta = _make_metadata(active_categories=["governance", "security"])
        assert "governance" in meta.active_categories
        assert "security" in meta.active_categories

    def test_enterprise_slug_set(self):
        meta = _make_metadata(enterprise_slug="my-enterprise")
        assert meta.enterprise_slug == "my-enterprise"

    def test_active_categories_defaults_are_independent(self):
        m1 = _make_metadata()
        m2 = _make_metadata()
        m1.active_categories.append("governance")
        assert m2.active_categories == []

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            _make_metadata(bad_field="oops")
