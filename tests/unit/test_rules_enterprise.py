"""Unit tests for enterprise assessment rules (ENT-001 through ENT-003)."""

from __future__ import annotations

from datetime import datetime, timezone


from gh_audit.models.enterprise import (
    EnterpriseInventory,
    EnterpriseIPAllowList,
    EnterprisePolicies,
    EnterpriseSAML,
)
from gh_audit.models.finding import Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.user import OrgMemberSummary
from gh_audit.rules.enterprise import (
    ent_001_2fa_not_required,
    ent_002_saml_not_enabled,
    ent_003_ip_allow_list_disabled,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inv(enterprise: EnterpriseInventory | None = None) -> Inventory:
    """Build a minimal Inventory with the given enterprise data."""
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization="testorg",
            auth_method="pat",
            scan_profile="total",
            active_categories=["enterprise"],
        ),
        summary=InventorySummary(total_repos=0),
        repositories=[],
        users=OrgMemberSummary(total=0, admins=0, members=0),
        enterprise=enterprise,
    )


# ===================================================================
# ENT-001: 2FA not required
# ===================================================================


class TestEnt0012faNotRequired:
    def test_fires_when_2fa_disabled(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            policies=EnterprisePolicies(two_factor_required="disabled"),
        )
        findings = ent_001_2fa_not_required(_inv(ent))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "ENT-001"
        assert f.pillar == Pillar.enterprise
        assert f.severity == Severity.critical
        assert f.scope == Scope.org
        assert f.repo_name is None

    def test_fires_when_2fa_is_none(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            policies=EnterprisePolicies(two_factor_required=None),
        )
        findings = ent_001_2fa_not_required(_inv(ent))
        assert len(findings) == 1

    def test_no_finding_when_2fa_enabled(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            policies=EnterprisePolicies(two_factor_required="enabled"),
        )
        findings = ent_001_2fa_not_required(_inv(ent))
        assert findings == []

    def test_returns_empty_when_enterprise_is_none(self) -> None:
        findings = ent_001_2fa_not_required(_inv(None))
        assert findings == []

    def test_returns_empty_when_policies_is_none(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            policies=None,
        )
        findings = ent_001_2fa_not_required(_inv(ent))
        assert findings == []


# ===================================================================
# ENT-002: SAML not enabled
# ===================================================================


class TestEnt002SamlNotEnabled:
    def test_fires_when_saml_disabled(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            saml=EnterpriseSAML(enabled=False),
        )
        findings = ent_002_saml_not_enabled(_inv(ent))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "ENT-002"
        assert f.pillar == Pillar.enterprise
        assert f.severity == Severity.warning
        assert f.scope == Scope.org
        assert f.repo_name is None

    def test_no_finding_when_saml_enabled(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            saml=EnterpriseSAML(enabled=True),
        )
        findings = ent_002_saml_not_enabled(_inv(ent))
        assert findings == []

    def test_returns_empty_when_enterprise_is_none(self) -> None:
        findings = ent_002_saml_not_enabled(_inv(None))
        assert findings == []

    def test_returns_empty_when_saml_is_none(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            saml=None,
        )
        findings = ent_002_saml_not_enabled(_inv(ent))
        assert findings == []


# ===================================================================
# ENT-003: IP allow list disabled
# ===================================================================


class TestEnt003IpAllowListDisabled:
    def test_fires_when_ip_allow_list_disabled(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            ip_allow_list=EnterpriseIPAllowList(enabled=False),
        )
        findings = ent_003_ip_allow_list_disabled(_inv(ent))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "ENT-003"
        assert f.pillar == Pillar.enterprise
        assert f.severity == Severity.info
        assert f.scope == Scope.org
        assert f.repo_name is None

    def test_no_finding_when_ip_allow_list_enabled(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            ip_allow_list=EnterpriseIPAllowList(enabled=True),
        )
        findings = ent_003_ip_allow_list_disabled(_inv(ent))
        assert findings == []

    def test_returns_empty_when_enterprise_is_none(self) -> None:
        findings = ent_003_ip_allow_list_disabled(_inv(None))
        assert findings == []

    def test_returns_empty_when_ip_allow_list_is_none(self) -> None:
        ent = EnterpriseInventory(
            name="Acme",
            slug="acme",
            ip_allow_list=None,
        )
        findings = ent_003_ip_allow_list_disabled(_inv(ent))
        assert findings == []
