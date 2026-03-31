"""Governance assessment rules (GOV-001 through GOV-004).

Each function takes an ``Inventory`` and returns ``list[Finding]``.
"""

from __future__ import annotations

from gh_audit.models.finding import Finding, Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory


def gov_001_no_branch_protection(inventory: Inventory) -> list[Finding]:
    """Flag repos with no branch protection rules and no rulesets."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        bp = repo.branch_protection
        # If ruleset_count is None we can't confirm absence -- skip.
        if bp.ruleset_count is None:
            continue
        if bp.protected_branches == 0 and bp.ruleset_count == 0:
            findings.append(
                Finding(
                    rule_id="GOV-001",
                    pillar=Pillar.governance,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="No branch protection",
                    detail=(f"{repo.name} has no branch protection rules and no rulesets."),
                    remediation=(
                        "Configure branch protection rules or repository rulesets "
                        "to enforce review and status-check requirements on key branches."
                    ),
                )
            )
    return findings


def gov_002_no_teams_assigned(inventory: Inventory) -> list[Finding]:
    """Flag repos where no teams have been granted access."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        # None means not scanned -- skip.
        if repo.teams_with_access is None:
            continue
        if len(repo.teams_with_access) == 0:
            findings.append(
                Finding(
                    rule_id="GOV-002",
                    pillar=Pillar.governance,
                    severity=Severity.info,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="No teams assigned",
                    detail=f"{repo.name} has no teams with access.",
                    remediation=(
                        "Assign at least one team to this repository to ensure "
                        "access is managed through team membership rather than "
                        "individual collaborators."
                    ),
                )
            )
    return findings


def gov_003_2fa_not_required(inventory: Inventory) -> list[Finding]:
    """Flag org where two-factor authentication is not required."""
    if inventory.governance is None:
        return []
    if inventory.governance.org_policies.two_factor_requirement_enabled is False:
        return [
            Finding(
                rule_id="GOV-003",
                pillar=Pillar.governance,
                severity=Severity.critical,
                scope=Scope.org,
                title="Two-factor authentication not required",
                detail=(
                    "The organization does not require two-factor authentication for its members."
                ),
                remediation=(
                    "Enable the two-factor authentication requirement in the "
                    "organization security settings to protect all member accounts."
                ),
            )
        ]
    return []


def gov_004_permissive_default_permission(inventory: Inventory) -> list[Finding]:
    """Flag org where the default repository permission is write or admin."""
    if inventory.governance is None:
        return []
    perm = inventory.governance.org_policies.default_repository_permission
    if perm in ("write", "admin"):
        return [
            Finding(
                rule_id="GOV-004",
                pillar=Pillar.governance,
                severity=Severity.warning,
                scope=Scope.org,
                title="Permissive default repository permission",
                detail=(
                    f"The organization default repository permission is "
                    f'"{perm}", granting broad access to all members.'
                ),
                remediation=(
                    'Set the default repository permission to "read" or "none" '
                    "and grant elevated access through teams on a per-repository basis."
                ),
            )
        ]
    return []
