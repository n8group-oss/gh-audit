"""Adoption assessment rules (ADO-001 through ADO-003).

Each function takes an ``Inventory`` and returns ``list[Finding]``.
"""

from __future__ import annotations

from gh_audit.models.finding import Finding, Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory


def ado_001_no_readme(inventory: Inventory) -> list[Finding]:
    """Flag repos where the community profile indicates no README."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.community_profile is None:
            continue
        if repo.community_profile.has_readme is False:
            findings.append(
                Finding(
                    rule_id="ADO-001",
                    pillar=Pillar.adoption,
                    severity=Severity.info,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Repository has no README",
                    detail=(
                        f"{repo.name} does not have a README file. "
                        f"A README is essential for onboarding contributors "
                        f"and documenting purpose."
                    ),
                    remediation=(
                        "Add a README.md to the repository root describing the "
                        "project purpose, setup instructions, and contribution guidelines."
                    ),
                )
            )
    return findings


def ado_002_stale_repo(inventory: Inventory) -> list[Finding]:
    """Flag non-archived repos with zero commits in the last 90 days."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.archived is True:
            continue
        if repo.commit_activity_90d is None:
            continue
        if repo.commit_activity_90d.total_commits == 0:
            findings.append(
                Finding(
                    rule_id="ADO-002",
                    pillar=Pillar.adoption,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Stale repository (no commits in 90 days)",
                    detail=(
                        f"{repo.name} has had no commits in the last 90 days. "
                        f"Consider archiving the repository if it is no longer maintained."
                    ),
                    remediation=(
                        "Archive the repository if it is no longer actively maintained, "
                        "or investigate whether the project should be revived or consolidated."
                    ),
                )
            )
    return findings


def ado_003_low_actions_success_rate(inventory: Inventory) -> list[Finding]:
    """Flag repos where Actions success rate is below 50%."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.actions_run_summary is None:
            continue
        if repo.actions_run_summary.total_runs_90d == 0:
            continue
        successes = repo.actions_run_summary.by_conclusion.get("success", 0)
        rate = successes / repo.actions_run_summary.total_runs_90d
        pct = int(rate * 100)
        if rate < 0.5:
            findings.append(
                Finding(
                    rule_id="ADO-003",
                    pillar=Pillar.adoption,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title=f"Low Actions success rate ({pct}%)",
                    detail=(
                        f"{repo.name} has an Actions success rate of {pct}% "
                        f"({successes}/{repo.actions_run_summary.total_runs_90d} runs) "
                        f"over the last 90 days."
                    ),
                    remediation=(
                        "Investigate failing workflow runs and fix the underlying issues. "
                        "Low success rates reduce developer confidence and slow delivery."
                    ),
                )
            )
    return findings
