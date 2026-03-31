"""Enterprise assessment rules (ENT-001 through ENT-003).

Each function takes an ``Inventory`` and returns ``list[Finding]``.
"""

from __future__ import annotations

from gh_audit.models.finding import Finding, Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory


def ent_001_2fa_not_required(inventory: Inventory) -> list[Finding]:
    """Flag when the enterprise does not require two-factor authentication."""
    if inventory.enterprise is None or inventory.enterprise.policies is None:
        return []
    if inventory.enterprise.policies.two_factor_required != "enabled":
        return [
            Finding(
                rule_id="ENT-001",
                pillar=Pillar.enterprise,
                severity=Severity.critical,
                scope=Scope.org,
                title="Enterprise 2FA not required",
                detail=(
                    f"Two-factor authentication is not required for enterprise "
                    f"'{inventory.enterprise.name}'."
                ),
                remediation=(
                    "Enable the enterprise-level 2FA requirement in "
                    "Settings > Authentication security to enforce 2FA for all members."
                ),
            )
        ]
    return []


def ent_002_saml_not_enabled(inventory: Inventory) -> list[Finding]:
    """Flag when enterprise SAML/SSO is not enabled."""
    if inventory.enterprise is None or inventory.enterprise.saml is None:
        return []
    if inventory.enterprise.saml.enabled is False:
        return [
            Finding(
                rule_id="ENT-002",
                pillar=Pillar.enterprise,
                severity=Severity.warning,
                scope=Scope.org,
                title="Enterprise SAML SSO not enabled",
                detail=(
                    f"SAML single sign-on is not enabled for enterprise "
                    f"'{inventory.enterprise.name}'."
                ),
                remediation=(
                    "Enable SAML SSO in the enterprise settings to centralise "
                    "authentication and improve identity management."
                ),
            )
        ]
    return []


def ent_003_ip_allow_list_disabled(inventory: Inventory) -> list[Finding]:
    """Flag when the enterprise IP allow list is not enabled."""
    if inventory.enterprise is None or inventory.enterprise.ip_allow_list is None:
        return []
    if inventory.enterprise.ip_allow_list.enabled is False:
        return [
            Finding(
                rule_id="ENT-003",
                pillar=Pillar.enterprise,
                severity=Severity.info,
                scope=Scope.org,
                title="Enterprise IP allow list disabled",
                detail=(
                    f"IP allow list is not enabled for enterprise '{inventory.enterprise.name}'."
                ),
                remediation=(
                    "Enable the enterprise IP allow list and add trusted IP ranges "
                    "to restrict access to your GitHub resources."
                ),
            )
        ]
    return []
