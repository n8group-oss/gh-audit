"""Security assessment rules (SEC-001 through SEC-007).

Each function takes an ``Inventory`` and returns ``list[Finding]``.
"""

from __future__ import annotations

from gh_audit.models.finding import Finding, Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory


def sec_001_critical_dependabot_alerts(inventory: Inventory) -> list[Finding]:
    """Flag repos with open critical/high Dependabot alerts."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.security_detail is None:
            continue
        matching = [
            a
            for a in repo.security_detail.dependabot_alerts
            if a.state == "open" and a.severity in ("critical", "high")
        ]
        if matching:
            findings.append(
                Finding(
                    rule_id="SEC-001",
                    pillar=Pillar.security,
                    severity=Severity.critical,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Open critical/high Dependabot alerts",
                    detail=(
                        f"{len(matching)} open critical/high Dependabot alert(s) in {repo.name}."
                    ),
                    remediation=(
                        "Review and remediate open Dependabot alerts. "
                        "Update vulnerable dependencies or dismiss with justification."
                    ),
                )
            )
    return findings


def sec_002_critical_code_scanning_alerts(inventory: Inventory) -> list[Finding]:
    """Flag repos with open critical/high code scanning alerts."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.security_detail is None:
            continue
        matching = [
            a
            for a in repo.security_detail.code_scanning_alerts
            if a.state == "open" and a.security_severity in ("critical", "high")
        ]
        if matching:
            findings.append(
                Finding(
                    rule_id="SEC-002",
                    pillar=Pillar.security,
                    severity=Severity.critical,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Open critical/high code scanning alerts",
                    detail=(
                        f"{len(matching)} open critical/high code scanning alert(s) in {repo.name}."
                    ),
                    remediation=(
                        "Review and fix open code scanning alerts. "
                        "Address the identified vulnerabilities in the source code."
                    ),
                )
            )
    return findings


def sec_003_secret_scanning_push_protection_bypass(inventory: Inventory) -> list[Finding]:
    """Flag repos with open secret scanning alerts where push protection was bypassed."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.security_detail is None:
            continue
        matching = [
            a
            for a in repo.security_detail.secret_scanning_alerts
            if a.state == "open" and a.push_protection_bypassed is True
        ]
        if matching:
            findings.append(
                Finding(
                    rule_id="SEC-003",
                    pillar=Pillar.security,
                    severity=Severity.critical,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Secret scanning push protection bypassed",
                    detail=(
                        f"{len(matching)} open secret(s) with push protection "
                        f"bypass in {repo.name}."
                    ),
                    remediation=(
                        "Rotate the exposed secrets immediately. "
                        "Review push protection bypass policies and restrict bypass permissions."
                    ),
                )
            )
    return findings


def sec_004_dependabot_not_enabled(inventory: Inventory) -> list[Finding]:
    """Flag non-archived repos where Dependabot is explicitly disabled."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.archived:
            continue
        if repo.security.dependabot_enabled is False:
            findings.append(
                Finding(
                    rule_id="SEC-004",
                    pillar=Pillar.security,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Dependabot not enabled",
                    detail=f"Dependabot alerts are not enabled on {repo.name}.",
                    remediation=(
                        "Enable Dependabot alerts in the repository security settings "
                        "to receive notifications about vulnerable dependencies."
                    ),
                )
            )
    return findings


def sec_005_code_scanning_not_enabled(inventory: Inventory) -> list[Finding]:
    """Flag non-archived repos where code scanning is explicitly disabled."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.archived:
            continue
        if repo.security.code_scanning_enabled is False:
            findings.append(
                Finding(
                    rule_id="SEC-005",
                    pillar=Pillar.security,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Code scanning not enabled",
                    detail=f"Code scanning is not enabled on {repo.name}.",
                    remediation=(
                        "Enable code scanning (e.g. CodeQL) in the repository security "
                        "settings to detect vulnerabilities in source code."
                    ),
                )
            )
    return findings


def sec_006_secret_scanning_not_enabled(inventory: Inventory) -> list[Finding]:
    """Flag non-archived repos where secret scanning is explicitly disabled."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.archived:
            continue
        if repo.security.secret_scanning_enabled is False:
            findings.append(
                Finding(
                    rule_id="SEC-006",
                    pillar=Pillar.security,
                    severity=Severity.warning,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="Secret scanning not enabled",
                    detail=f"Secret scanning is not enabled on {repo.name}.",
                    remediation=(
                        "Enable secret scanning in the repository security settings "
                        "to detect accidentally committed secrets."
                    ),
                )
            )
    return findings


def sec_007_no_sbom(inventory: Inventory) -> list[Finding]:
    """Flag repos with security detail scanned but no SBOM summary."""
    findings: list[Finding] = []
    for repo in inventory.repositories:
        if repo.security_detail is None:
            continue
        if repo.security_detail.sbom_summary is None:
            findings.append(
                Finding(
                    rule_id="SEC-007",
                    pillar=Pillar.security,
                    severity=Severity.info,
                    scope=Scope.repo,
                    repo_name=repo.name,
                    title="No SBOM available",
                    detail=f"No Software Bill of Materials found for {repo.name}.",
                    remediation=(
                        "Generate an SBOM for this repository to improve supply chain "
                        "visibility. GitHub can automatically generate dependency graphs."
                    ),
                )
            )
    return findings
