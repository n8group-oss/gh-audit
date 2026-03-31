"""ExcelExportService — generates a multi-sheet Excel workbook from an Inventory.

Sheet contract (10 sheets, in order):
1.  Summary       — org metadata + high-level stats (metric/value pairs)
2.  Repositories  — one row per repo with core fields
3.  Actions       — one row per workflow
4.  Security      — per-repo security enablement and alert counts
5.  Issues        — per-repo issue counts and top labels
6.  Packages      — name, type, visibility
7.  Projects      — title, item_count, closed (Yes/No)
8.  Users         — role, count
9.  Large Files   — repo name, file path, size_mb
10. Warnings      — repo name (or "Scan"), warning text

Partial-scan semantics:
- bool | None fields → "Yes" / "No" / "n/a"
- int  | None counts → number / "n/a"

Formatting applied to all data sheets:
- Header row: blue fill (#4472C4) + white bold font
- Freeze header row (freeze_panes = "A2")
- Column widths auto-sized to max(header_length, 10)
"""

from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from gh_audit import branding
from gh_audit.models.inventory import Inventory

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

_HEADER_FILL = PatternFill(fill_type="solid", fgColor="4472C4")
_HEADER_FONT = Font(bold=True, color="FFFFFF")
_MIN_COL_WIDTH = 10


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _bool_na(value: bool | None) -> str:
    """Convert bool | None to 'Yes' / 'No' / 'n/a'."""
    if value is None:
        return "n/a"
    return "Yes" if value else "No"


def _int_na(value: int | None) -> int | str:
    """Return the integer value or 'n/a' when None."""
    if value is None:
        return "n/a"
    return value


def _style_header_row(ws: Worksheet, headers: list[str]) -> None:
    """Write the header row with blue fill, white bold font, and auto column widths."""
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(horizontal="center")

    # Auto-width: use header length as minimum width
    for col_idx, header in enumerate(headers, start=1):
        col_letter = get_column_letter(col_idx)
        ws.column_dimensions[col_letter].width = max(len(header) + 2, _MIN_COL_WIDTH)

    # Freeze the header row
    ws.freeze_panes = "A2"


# ---------------------------------------------------------------------------
# Sheet builders
# ---------------------------------------------------------------------------


def _build_summary(ws: Worksheet, inventory: Inventory) -> None:
    """Summary sheet: metric/value pairs, no frozen header (metadata, not data)."""
    meta = inventory.metadata
    summary = inventory.summary

    rows = [
        ("Organization", meta.organization),
        ("Tool Version", meta.tool_version),
        ("Schema Version", meta.schema_version),
        ("Generated At", str(meta.generated_at)),
        ("Auth Method", meta.auth_method),
        ("Scan Profile", meta.scan_profile),
        ("API URL", meta.api_url),
        # --- repo counts ---
        ("Total Repositories", summary.total_repos),
        ("Public Repositories", summary.public_repos),
        ("Private Repositories", summary.private_repos),
        ("Internal Repositories", summary.internal_repos),
        ("Archived Repositories", summary.archived_repos),
        ("Forked Repositories", summary.forked_repos),
        ("Template Repositories", summary.template_repos),
        # --- activity ---
        ("Total Size (bytes)", summary.total_size_bytes),
        ("Total Branches", summary.total_branches),
        ("Total PRs", summary.total_prs),
        ("Total Issues", summary.total_issues),
        # --- large files / LFS ---
        ("Repos with Large Files", summary.repos_with_large_files),
        ("Repos with LFS", summary.repos_with_lfs),
        # --- actions ---
        ("Repos with Workflows", summary.repos_with_workflows),
        ("Total Workflows", summary.total_workflow_count),
        ("Repos with Self-Hosted Runners", summary.repos_with_self_hosted_runners),
        # --- security ---
        ("Repos with Dependabot", summary.repos_with_dependabot),
        ("Repos with Code Scanning", summary.repos_with_code_scanning),
        ("Repos with Secret Scanning", summary.repos_with_secret_scanning),
        # --- packages / projects ---
        ("Total Packages", summary.total_packages),
        ("Total Projects", summary.total_projects),
    ]

    ws["A1"] = "Metric"
    ws["B1"] = "Value"
    ws["A1"].font = Font(bold=True)
    ws["B1"].font = Font(bold=True)

    for row_idx, (metric, value) in enumerate(rows, start=2):
        ws.cell(row=row_idx, column=1, value=metric)
        ws.cell(row=row_idx, column=2, value=value)

    # Blank separator row then N8 Group branding
    branding_start = len(rows) + 3  # +2 for header row, +1 for blank separator
    branding_rows = [
        ("About", f"gh-audit is a free tool by {branding.COMPANY_NAME}"),
        ("Website", branding.WEBSITE),
        ("Contact", branding.SALES_EMAIL),
        ("Services", ", ".join(branding.SERVICES)),
    ]
    for offset, (label, value) in enumerate(branding_rows):
        ws.cell(row=branding_start + offset, column=1, value=label)
        ws.cell(row=branding_start + offset, column=2, value=value)

    ws.column_dimensions["A"].width = 36
    ws.column_dimensions["B"].width = 30


def _build_repositories(ws: Worksheet, inventory: Inventory) -> None:
    headers = [
        "Repository",
        "Visibility",
        "Language",
        "Size (bytes)",
        "Branches",
        "Open PRs",
        "Merged PRs",
        "Open Issues",
        "Closed Issues",
        "Workflows",
        "Archived",
        "Fork",
        "Template",
        "LFS",
        "Large Files Count",
    ]
    _style_header_row(ws, headers)

    for repo in inventory.repositories:
        ws.append(
            [
                repo.name,
                repo.visibility,
                repo.language or "",
                repo.size_bytes,
                repo.branch_count,
                repo.pr_count_open,
                repo.pr_count_merged,
                repo.issue_count_open,
                repo.issue_count_closed,
                repo.actions.workflow_count,
                _bool_na(repo.archived),
                _bool_na(repo.fork),
                _bool_na(repo.is_template),
                _bool_na(repo.lfs_info.has_lfs),
                len(repo.large_file_scan.files),
            ]
        )


def _build_actions(ws: Worksheet, inventory: Inventory) -> None:
    headers = ["Repository", "Workflow Name", "Path", "State"]
    _style_header_row(ws, headers)

    for repo in inventory.repositories:
        for wf in repo.actions.workflows:
            ws.append([repo.name, wf.name, wf.path, wf.state])


def _build_security(ws: Worksheet, inventory: Inventory) -> None:
    headers = [
        "Repository",
        "Dependabot Enabled",
        "Dependabot Alerts",
        "Code Scanning Enabled",
        "Code Scanning Alerts",
        "Secret Scanning Enabled",
        "Secret Scanning Alerts",
    ]
    _style_header_row(ws, headers)

    for repo in inventory.repositories:
        sec = repo.security
        ws.append(
            [
                repo.name,
                _bool_na(sec.dependabot_enabled),
                _int_na(sec.dependabot_alerts_open),
                _bool_na(sec.code_scanning_enabled),
                _int_na(sec.code_scanning_alerts_open),
                _bool_na(sec.secret_scanning_enabled),
                _int_na(sec.secret_scanning_alerts_open),
            ]
        )


def _build_issues(ws: Worksheet, inventory: Inventory) -> None:
    # Gather all label keys across repos for extra columns
    all_labels: list[str] = []
    seen: set[str] = set()
    for repo in inventory.repositories:
        for label in repo.issue_label_distribution:
            if label not in seen:
                all_labels.append(label)
                seen.add(label)

    headers = ["Repository", "Open Issues", "Closed Issues"] + all_labels
    _style_header_row(ws, headers)

    for repo in inventory.repositories:
        label_counts = [repo.issue_label_distribution.get(lbl, 0) for lbl in all_labels]
        ws.append([repo.name, repo.issue_count_open, repo.issue_count_closed] + label_counts)


def _build_packages(ws: Worksheet, inventory: Inventory) -> None:
    headers = ["Name", "Type", "Visibility"]
    _style_header_row(ws, headers)

    for pkg in inventory.packages:
        ws.append([pkg.name, pkg.package_type, pkg.visibility])


def _build_projects(ws: Worksheet, inventory: Inventory) -> None:
    headers = ["Title", "Item Count", "Closed"]
    _style_header_row(ws, headers)

    for proj in inventory.projects:
        ws.append([proj.title, proj.item_count, _bool_na(proj.closed)])


def _build_users(ws: Worksheet, inventory: Inventory) -> None:
    headers = ["Role", "Count"]
    _style_header_row(ws, headers)

    users = inventory.users
    ws.append(["Admin", users.admins])
    ws.append(["Member", users.members])
    ws.append(["Outside Collaborator", users.outside_collaborators])
    ws.append(["Total", users.total])


def _build_large_files(ws: Worksheet, inventory: Inventory) -> None:
    headers = ["Repository", "File Path", "Size (MB)"]
    _style_header_row(ws, headers)

    for repo in inventory.repositories:
        for lf in repo.large_file_scan.files:
            size_mb = round(lf.size_bytes / (1024 * 1024), 2)
            ws.append([repo.name, lf.path, size_mb])


def _build_warnings(ws: Worksheet, inventory: Inventory) -> None:
    headers = ["Source", "Warning"]
    _style_header_row(ws, headers)

    # Scan-level warnings first
    for warning in inventory.metadata.scan_warnings:
        ws.append(["Scan", warning])

    # Per-repo warnings
    for repo in inventory.repositories:
        for warning in repo.warnings:
            ws.append([repo.name, warning])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ExcelExportService:
    """Generate a multi-sheet Excel workbook from a completed Inventory."""

    @staticmethod
    def generate(inventory: Inventory, output_path: Path) -> None:
        """Write the Excel workbook to *output_path*.

        Parameters
        ----------
        inventory:
            Complete scan inventory.
        output_path:
            Destination ``.xlsx`` file path.  Parent directories are created
            automatically.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        wb = Workbook()

        # Remove the default empty sheet created by openpyxl
        wb.remove(wb.active)  # type: ignore[arg-type]

        # Build sheets in required order
        _build_summary(wb.create_sheet("Summary"), inventory)
        _build_repositories(wb.create_sheet("Repositories"), inventory)
        _build_actions(wb.create_sheet("Actions"), inventory)
        _build_security(wb.create_sheet("Security"), inventory)
        _build_issues(wb.create_sheet("Issues"), inventory)
        _build_packages(wb.create_sheet("Packages"), inventory)
        _build_projects(wb.create_sheet("Projects"), inventory)
        _build_users(wb.create_sheet("Users"), inventory)
        _build_large_files(wb.create_sheet("Large Files"), inventory)
        _build_warnings(wb.create_sheet("Warnings"), inventory)

        # Governance sheets (only when governance data present)
        if inventory.governance is not None:
            gov = inventory.governance

            # Teams sheet
            ws = wb.create_sheet("Teams")
            teams_headers = ["Team", "Permission", "Privacy", "Members", "Repos", "Parent"]
            _style_header_row(ws, teams_headers)
            for idx, team in enumerate(gov.teams, 2):
                ws.cell(row=idx, column=1, value=team.name)
                ws.cell(row=idx, column=2, value=team.permission)
                ws.cell(row=idx, column=3, value=team.privacy)
                ws.cell(row=idx, column=4, value=team.member_count)
                ws.cell(row=idx, column=5, value=team.repo_count)
                ws.cell(row=idx, column=6, value=team.parent_team or "")

            # Org Policies sheet
            ws = wb.create_sheet("Org Policies")
            pol_headers = ["Policy", "Value"]
            _style_header_row(ws, pol_headers)
            pol = gov.org_policies
            pol_rows = [
                ("Default repo permission", pol.default_repository_permission),
                ("2FA required", _bool_na(pol.two_factor_requirement_enabled)),
                ("Web commit sign-off", _bool_na(pol.web_commit_signoff_required)),
                ("Members can create repos", _bool_na(pol.members_can_create_repositories)),
                ("Members can fork private", _bool_na(pol.members_can_fork_private_repositories)),
                ("Members can delete repos", _bool_na(pol.members_can_delete_repositories)),
                (
                    "Members can change visibility",
                    _bool_na(pol.members_can_change_repo_visibility),
                ),
            ]
            for idx, (policy, value) in enumerate(pol_rows, 2):
                ws.cell(row=idx, column=1, value=policy)
                ws.cell(row=idx, column=2, value=value if value is not None else "n/a")

            # Org Rulesets sheet
            ws = wb.create_sheet("Org Rulesets")
            rs_headers = ["Name", "Enforcement", "Target", "Source", "Rules Count"]
            _style_header_row(ws, rs_headers)
            for idx, rs in enumerate(gov.org_rulesets, 2):
                ws.cell(row=idx, column=1, value=rs.name)
                ws.cell(row=idx, column=2, value=rs.enforcement)
                ws.cell(row=idx, column=3, value=rs.target)
                ws.cell(row=idx, column=4, value=rs.source_type)
                ws.cell(row=idx, column=5, value=len(rs.rules))

        # Operations sheets (only when operations data present)
        if inventory.operations is not None:
            ops = inventory.operations

            # Runners sheet
            ws = wb.create_sheet("Runners")
            runners_headers = ["Name", "OS", "Status", "Labels", "Group"]
            _style_header_row(ws, runners_headers)
            for idx, runner in enumerate(ops.runners, 2):
                ws.cell(row=idx, column=1, value=runner.name)
                ws.cell(row=idx, column=2, value=runner.os)
                ws.cell(row=idx, column=3, value=runner.status)
                ws.cell(row=idx, column=4, value=", ".join(runner.labels))
                ws.cell(row=idx, column=5, value=runner.runner_group_name or "")

            # Environments sheet
            ws = wb.create_sheet("Environments")
            env_headers = [
                "Repository",
                "Environment",
                "Wait Timer",
                "Required Reviewers",
                "Branch Policy",
                "Can Admins Bypass",
            ]
            _style_header_row(ws, env_headers)
            env_row = 2
            for repo in inventory.repositories:
                if repo.environments:
                    for env in repo.environments:
                        ws.cell(row=env_row, column=1, value=repo.name)
                        ws.cell(row=env_row, column=2, value=env.name)
                        prot = env.protection_rules
                        ws.cell(row=env_row, column=3, value=prot.wait_timer if prot else 0)
                        ws.cell(
                            row=env_row,
                            column=4,
                            value=prot.required_reviewers if prot else 0,
                        )
                        ws.cell(
                            row=env_row,
                            column=5,
                            value=prot.branch_policy if prot and prot.branch_policy else "none",
                        )
                        ws.cell(
                            row=env_row,
                            column=6,
                            value=_bool_na(env.can_admins_bypass),
                        )
                        env_row += 1

            # Installed Apps sheet
            ws = wb.create_sheet("Installed Apps")
            apps_headers = ["Name", "Slug", "Repo Selection", "Events Count"]
            _style_header_row(ws, apps_headers)
            for idx, app in enumerate(ops.installed_apps, 2):
                ws.cell(row=idx, column=1, value=app.app_name)
                ws.cell(row=idx, column=2, value=app.app_slug)
                ws.cell(row=idx, column=3, value=app.repository_selection)
                ws.cell(row=idx, column=4, value=len(app.events))

        # Security detail sheets (only when any repo has security_detail)
        has_security_detail = any(r.security_detail is not None for r in inventory.repositories)
        if has_security_detail:
            # Dependabot Alerts sheet
            ws = wb.create_sheet("Dependabot Alerts")
            dep_headers = [
                "Repository",
                "Severity",
                "Package",
                "Manifest",
                "State",
                "GHSA ID",
                "CVE",
                "Fixed Version",
            ]
            _style_header_row(ws, dep_headers)
            dep_row = 2
            for repo in inventory.repositories:
                if repo.security_detail:
                    for alert in repo.security_detail.dependabot_alerts:
                        ws.cell(row=dep_row, column=1, value=repo.name)
                        ws.cell(row=dep_row, column=2, value=alert.severity)
                        ws.cell(row=dep_row, column=3, value=alert.package_name)
                        ws.cell(row=dep_row, column=4, value=alert.manifest_path)
                        ws.cell(row=dep_row, column=5, value=alert.state)
                        ws.cell(row=dep_row, column=6, value=alert.ghsa_id or "")
                        ws.cell(row=dep_row, column=7, value=alert.cve_id or "")
                        ws.cell(row=dep_row, column=8, value=alert.fixed_version or "")
                        dep_row += 1

            # Code Scanning Alerts sheet
            ws = wb.create_sheet("Code Scanning Alerts")
            cs_headers = ["Repository", "Rule", "Severity", "Security Severity", "Tool", "State"]
            _style_header_row(ws, cs_headers)
            cs_row = 2
            for repo in inventory.repositories:
                if repo.security_detail:
                    for alert in repo.security_detail.code_scanning_alerts:
                        ws.cell(row=cs_row, column=1, value=repo.name)
                        ws.cell(row=cs_row, column=2, value=alert.rule_id)
                        ws.cell(row=cs_row, column=3, value=alert.severity or "")
                        ws.cell(row=cs_row, column=4, value=alert.security_severity or "")
                        ws.cell(row=cs_row, column=5, value=alert.tool_name)
                        ws.cell(row=cs_row, column=6, value=alert.state)
                        cs_row += 1

            # Secret Scanning Alerts sheet
            ws = wb.create_sheet("Secret Scanning Alerts")
            ss_headers = [
                "Repository",
                "Secret Type",
                "State",
                "Resolution",
                "Push Protection Bypassed",
            ]
            _style_header_row(ws, ss_headers)
            ss_row = 2
            for repo in inventory.repositories:
                if repo.security_detail:
                    for alert in repo.security_detail.secret_scanning_alerts:
                        ws.cell(row=ss_row, column=1, value=repo.name)
                        ws.cell(
                            row=ss_row,
                            column=2,
                            value=alert.secret_type_display_name or alert.secret_type,
                        )
                        ws.cell(row=ss_row, column=3, value=alert.state)
                        ws.cell(row=ss_row, column=4, value=alert.resolution or "")
                        ws.cell(
                            row=ss_row,
                            column=5,
                            value=_bool_na(alert.push_protection_bypassed),
                        )
                        ss_row += 1

        # Adoption sheets (only when adoption data present)
        if inventory.adoption is not None:
            adoption = inventory.adoption

            # Copilot sheet (only if copilot data is available)
            if adoption.copilot is not None:
                ws = wb.create_sheet("Copilot")
                cop_headers = ["Metric", "Value"]
                _style_header_row(ws, cop_headers)
                cop_rows = [
                    ("Total Seats", adoption.copilot.total_seats),
                    ("Active Seats", _int_na(adoption.copilot.active_seats)),
                    ("Suggestions (28d)", _int_na(adoption.copilot.suggestions_count)),
                    ("Acceptances (28d)", _int_na(adoption.copilot.acceptances_count)),
                    (
                        "Top Languages",
                        ", ".join(adoption.copilot.top_languages)
                        if adoption.copilot.top_languages
                        else "n/a",
                    ),
                ]
                for idx, (metric, value) in enumerate(cop_rows, 2):
                    ws.cell(row=idx, column=1, value=metric)
                    ws.cell(row=idx, column=2, value=value)

            # Traffic sheet
            traffic_repos = [r for r in inventory.repositories if r.traffic is not None]
            if traffic_repos:
                ws = wb.create_sheet("Traffic")
                traffic_headers = [
                    "Repository",
                    "Views",
                    "Unique Visitors",
                    "Clones",
                    "Unique Cloners",
                ]
                _style_header_row(ws, traffic_headers)
                for idx, repo in enumerate(traffic_repos, 2):
                    t = repo.traffic
                    ws.cell(row=idx, column=1, value=repo.name)
                    ws.cell(row=idx, column=2, value=_int_na(t.views_14d))
                    ws.cell(row=idx, column=3, value=_int_na(t.unique_visitors_14d))
                    ws.cell(row=idx, column=4, value=_int_na(t.clones_14d))
                    ws.cell(row=idx, column=5, value=_int_na(t.unique_cloners_14d))

            # Community Health sheet
            health_repos = [r for r in inventory.repositories if r.community_profile is not None]
            if health_repos:
                ws = wb.create_sheet("Community Health")
                health_headers = [
                    "Repository",
                    "Health %",
                    "README",
                    "License",
                    "Contributing",
                    "Code of Conduct",
                    "Issue Template",
                    "PR Template",
                ]
                _style_header_row(ws, health_headers)
                for idx, repo in enumerate(health_repos, 2):
                    cp = repo.community_profile
                    ws.cell(row=idx, column=1, value=repo.name)
                    ws.cell(row=idx, column=2, value=cp.health_percentage)
                    ws.cell(row=idx, column=3, value=_bool_na(cp.has_readme))
                    ws.cell(row=idx, column=4, value=_bool_na(cp.has_license))
                    ws.cell(row=idx, column=5, value=_bool_na(cp.has_contributing))
                    ws.cell(row=idx, column=6, value=_bool_na(cp.has_code_of_conduct))
                    ws.cell(row=idx, column=7, value=_bool_na(cp.has_issue_template))
                    ws.cell(row=idx, column=8, value=_bool_na(cp.has_pull_request_template))

            # Actions Runs sheet
            runs_repos = [r for r in inventory.repositories if r.actions_run_summary is not None]
            if runs_repos:
                ws = wb.create_sheet("Actions Runs")
                runs_headers = [
                    "Repository",
                    "Total Runs (90d)",
                    "Success",
                    "Failure",
                    "Cancelled",
                ]
                _style_header_row(ws, runs_headers)
                for idx, repo in enumerate(runs_repos, 2):
                    ars = repo.actions_run_summary
                    ws.cell(row=idx, column=1, value=repo.name)
                    ws.cell(row=idx, column=2, value=ars.total_runs_90d)
                    ws.cell(row=idx, column=3, value=ars.by_conclusion.get("success", 0))
                    ws.cell(row=idx, column=4, value=ars.by_conclusion.get("failure", 0))
                    ws.cell(row=idx, column=5, value=ars.by_conclusion.get("cancelled", 0))

        # Enterprise sheets (only when enterprise data present)
        if inventory.enterprise is not None:
            ent = inventory.enterprise

            # Enterprise overview sheet
            ws = wb.create_sheet("Enterprise")
            ent_headers = ["Property", "Value"]
            _style_header_row(ws, ent_headers)
            ent_rows: list[tuple[str, str | int | float]] = [
                ("Name", ent.name),
                ("Slug", ent.slug),
                ("Members", ent.members_count),
                ("Admins", ent.admins_count),
                ("Outside Collaborators", ent.outside_collaborators_count),
                ("SAML Enabled", _bool_na(ent.saml.enabled if ent.saml else None)),
                (
                    "IP Allow List Enabled",
                    _bool_na(ent.ip_allow_list.enabled if ent.ip_allow_list else None),
                ),
                (
                    "IP Allow List Entries",
                    ent.ip_allow_list.entries_count if ent.ip_allow_list else 0,
                ),
                (
                    "Verified Domains",
                    ", ".join(ent.verified_domains) if ent.verified_domains else "",
                ),
            ]
            if ent.billing is not None:
                ent_rows.extend(
                    [
                        ("Total Licenses", ent.billing.total_licenses),
                        ("Used Licenses", ent.billing.used_licenses),
                        ("Storage Usage (GB)", ent.billing.storage_usage_gb),
                        ("Storage Quota (GB)", ent.billing.storage_quota_gb),
                        ("Bandwidth Usage (GB)", ent.billing.bandwidth_usage_gb),
                        ("Bandwidth Quota (GB)", ent.billing.bandwidth_quota_gb),
                    ]
                )
            if ent.policies is not None:
                ent_rows.extend(
                    [
                        ("2FA Required", ent.policies.two_factor_required or "n/a"),
                        (
                            "Default Repo Permission",
                            ent.policies.default_repository_permission or "n/a",
                        ),
                    ]
                )
            for idx, (prop, value) in enumerate(ent_rows, 2):
                ws.cell(row=idx, column=1, value=prop)
                ws.cell(row=idx, column=2, value=value)

            # Enterprise Teams sheet
            if ent.enterprise_teams:
                ws = wb.create_sheet("Enterprise Teams")
                teams_headers = ["Name", "Slug", "Members", "Orgs"]
                _style_header_row(ws, teams_headers)
                for idx, team in enumerate(ent.enterprise_teams, 2):
                    ws.cell(row=idx, column=1, value=team.name)
                    ws.cell(row=idx, column=2, value=team.slug)
                    ws.cell(row=idx, column=3, value=team.member_count)
                    ws.cell(row=idx, column=4, value=team.org_count)

        wb.save(str(output_path))
