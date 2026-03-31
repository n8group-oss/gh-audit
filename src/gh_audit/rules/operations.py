"""Operations assessment rules (OPS-001 through OPS-004).

Each function takes an ``Inventory`` and returns ``list[Finding]``.
"""

from __future__ import annotations

from gh_audit.models.finding import Finding, Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory


def ops_001_unprotected_environment(inventory: Inventory) -> list[Finding]:
    """Flag repos with environments where protection_rules is None.

    Each unprotected environment produces a separate finding.
    """
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.environments is None:
            continue
        for env in repo.environments:
            if env.protection_rules is None:
                findings.append(
                    Finding(
                        rule_id="OPS-001",
                        pillar=Pillar.operations,
                        severity=Severity.warning,
                        scope=Scope.repo,
                        repo_name=repo.name,
                        title="Unprotected deployment environment",
                        detail=(
                            f'Environment "{env.name}" in {repo.name} has no protection rules.'
                        ),
                        remediation=(
                            "Add protection rules (required reviewers, wait timers, "
                            "or branch policies) to deployment environments to prevent "
                            "unreviewed deployments."
                        ),
                    )
                )
    return findings


def ops_002_insecure_webhook(inventory: Inventory) -> list[Finding]:
    """Flag repos with webhooks where insecure_ssl is True.

    Aggregate count in one finding per repo.
    """
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.repo_webhooks is None:
            continue
        insecure = [w for w in repo.repo_webhooks if w.insecure_ssl is True]
        if insecure:
            findings.append(
                Finding(
                    rule_id="OPS-002",
                    pillar=Pillar.operations,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Insecure webhook (SSL verification disabled)",
                    detail=(
                        f"{len(insecure)} webhook(s) in {repo.name} have SSL verification disabled."
                    ),
                    remediation=(
                        "Enable SSL verification on all webhooks to ensure "
                        "payloads are delivered over secure connections."
                    ),
                )
            )
    return findings


def ops_003_write_deploy_key(inventory: Inventory) -> list[Finding]:
    """Flag repos with deploy keys where read_only is False.

    Each write-access deploy key produces a separate finding.
    """
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.deploy_keys is None:
            continue
        for key in repo.deploy_keys:
            if key.read_only is False:
                findings.append(
                    Finding(
                        rule_id="OPS-003",
                        pillar=Pillar.operations,
                        severity=Severity.info,
                        scope=Scope.repo,
                        repo_name=repo.name,
                        title="Deploy key with write access",
                        detail=(f'Deploy key "{key.title}" in {repo.name} has write access.'),
                        remediation=(
                            "Use read-only deploy keys unless write access is strictly "
                            "required. Write-access deploy keys increase the blast radius "
                            "if compromised."
                        ),
                    )
                )
    return findings


def ops_004_permissive_actions(inventory: Inventory) -> list[Finding]:
    """Flag repos where actions_permissions.allowed_actions == 'all'."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.actions_permissions is None:
            continue
        if repo.actions_permissions.allowed_actions == "all":
            findings.append(
                Finding(
                    rule_id="OPS-004",
                    pillar=Pillar.operations,
                    severity=Severity.info,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Permissive Actions configuration",
                    detail=(f"{repo.name} allows all GitHub Actions to run without restriction."),
                    remediation=(
                        "Restrict allowed actions to a curated list or organization-only "
                        "actions to reduce supply chain risk."
                    ),
                )
            )
    return findings
