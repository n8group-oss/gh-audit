"""Rule engine and registry for the assessment system.

The engine runs a list of rule functions against an Inventory and collects
findings. Individual rule failures are logged and skipped.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from gh_audit.models.finding import Finding, Severity
from gh_audit.models.inventory import Inventory

_log = logging.getLogger(__name__)

RuleFunc = Callable[[Inventory], list[Finding]]

_SEVERITY_ORDER = {Severity.critical: 0, Severity.warning: 1, Severity.info: 2}


class RuleEngine:
    """Evaluate assessment rules against an inventory."""

    def __init__(self, rules: list[RuleFunc]) -> None:
        self._rules = rules

    @classmethod
    def default(cls) -> "RuleEngine":
        """Create an engine with all registered v1 rules."""
        from gh_audit.rules import adoption, enterprise, governance, operations, security

        all_rules: list[RuleFunc] = [
            # Security
            security.sec_001_critical_dependabot_alerts,
            security.sec_002_critical_code_scanning_alerts,
            security.sec_003_secret_scanning_push_protection_bypass,
            security.sec_004_dependabot_not_enabled,
            security.sec_005_code_scanning_not_enabled,
            security.sec_006_secret_scanning_not_enabled,
            security.sec_007_no_sbom,
            # Governance
            governance.gov_001_no_branch_protection,
            governance.gov_002_no_teams_assigned,
            governance.gov_003_2fa_not_required,
            governance.gov_004_permissive_default_permission,
            # Operations
            operations.ops_001_unprotected_environment,
            operations.ops_002_insecure_webhook,
            operations.ops_003_write_deploy_key,
            operations.ops_004_permissive_actions,
            # Adoption
            adoption.ado_001_no_readme,
            adoption.ado_002_stale_repo,
            adoption.ado_003_low_actions_success_rate,
            # Enterprise
            enterprise.ent_001_2fa_not_required,
            enterprise.ent_002_saml_not_enabled,
            enterprise.ent_003_ip_allow_list_disabled,
        ]
        return cls(rules=all_rules)

    def run(self, inventory: Inventory) -> list[Finding]:
        """Run all rules and return findings sorted by severity."""
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                findings.extend(rule(inventory))
            except Exception:
                _log.warning(
                    "Rule %s failed, skipping", getattr(rule, "__name__", rule), exc_info=True
                )
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        return findings
