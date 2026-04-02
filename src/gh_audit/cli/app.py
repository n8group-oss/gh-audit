"""gh-audit CLI application entry point.

Four commands:
    init      — interactive credential setup
    discover  — scan an organization and produce inventory + reports
    report    — regenerate reports from an existing inventory JSON
    assess    — assess an inventory against best-practice rules
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import structlog
import typer

from gh_audit.__about__ import __version__
from gh_audit.branding import CLI_BANNER
from gh_audit.cli.credential_resolver import resolve_settings
from gh_audit.cli.output import print_error, print_info, print_ok, print_warn
from gh_audit.cli.output_paths import OutputPaths, SummaryPaths
from gh_audit.exceptions import ConfigError, ScannerError
from gh_audit.services.multi_org import load_config, run_all_orgs
from gh_audit.services.summary_report import generate_summary_html

# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="gh-audit",
    help="GitHub audit, governance, and inventory for organizations.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        print(f"gh-audit {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """gh-audit — GitHub audit, governance, and inventory for organizations."""


# ---------------------------------------------------------------------------
# Structlog configuration
# ---------------------------------------------------------------------------


def _configure_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
    log_format: str = "text",
) -> None:
    """Configure structlog + stdlib logging."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        format="%(message)s",
        level=level,
        stream=sys.stderr,
        force=True,
    )

    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _start_command_telemetry(
    *,
    command: str,
    organization: str,
    enabled: bool,
    auth_method: str,
    tool_version: str,
    scan_profile: str | None = None,
    api_url: str | None = None,
    active_categories: list[str] | None = None,
    enterprise_slug: str | None = None,
):
    """Create telemetry, bind run context, and emit the launch event."""
    from gh_audit.services.telemetry import Telemetry

    telemetry = Telemetry(organization=organization, enabled=enabled)
    telemetry.bind_context(
        command=command,
        scan_profile=scan_profile,
        api_url=api_url,
        active_categories=list(active_categories or []),
        enterprise_slug=enterprise_slug,
    )
    telemetry.track_scanner_launched(
        auth_method=auth_method,
        tool_version=tool_version,
    )
    return telemetry


# ---------------------------------------------------------------------------
# init command
# ---------------------------------------------------------------------------


@app.command()
def init() -> None:
    """Interactive credential setup for gh-audit."""
    from gh_audit.adapters.github_rest import GitHubRestClient

    print_info("gh-audit credential setup")
    print()

    choice = ""
    while choice not in ("1", "2"):
        choice = typer.prompt(
            "Authentication method:\n  1) GitHub App (recommended)\n  2) Personal Access Token (PAT)\nChoice",
            default="1",
        )

    lines: list[str] = []

    if choice == "1":
        app_id = typer.prompt("GitHub App ID")
        installation_id = typer.prompt("Installation ID")
        private_key_path = typer.prompt("Path to private key PEM file")
        organization = typer.prompt("Organization")

        lines.append(f"GH_AUDIT_APP_ID={app_id}")
        lines.append(f"GH_AUDIT_INSTALLATION_ID={installation_id}")
        lines.append(f"GH_AUDIT_PRIVATE_KEY_PATH={private_key_path}")
        lines.append(f"GH_AUDIT_ORGANIZATION={organization}")
    else:
        token = typer.prompt("Personal Access Token", hide_input=True)
        organization = typer.prompt("Organization")

        lines.append(f"GH_AUDIT_TOKEN={token}")
        lines.append(f"GH_AUDIT_ORGANIZATION={organization}")

    # Verify credentials before writing .env
    if choice == "2":
        # PAT: verify via API
        rest = GitHubRestClient(token=token, base_url="https://api.github.com")
        try:
            result = asyncio.run(rest.verify_credentials(organization))
            org_name = result.get("login", organization)
            print_ok(f"Credentials verified for organization: {org_name}")
        except Exception as exc:
            print_error(f"Credential verification failed: {exc}")
            print_error("Configuration was NOT saved.")
            raise typer.Exit(code=1)
        finally:
            asyncio.run(rest.close())
    else:
        # GitHub App: cannot verify without building JWT; defer to first discover
        print_info("GitHub App credentials saved. Run 'gh-audit discover' to verify.")

    env_path = Path(".env")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print_ok(f"Configuration saved to {env_path}")


# ---------------------------------------------------------------------------
# discover command
# ---------------------------------------------------------------------------


@app.command()
def discover(
    # --- Multi-org config ---
    config: Optional[Path] = typer.Option(None, "--config", help="YAML config for multi-org scan."),
    # --- Auth / connection ---
    organization: Optional[str] = typer.Option(None, help="GitHub organization to scan."),
    token: Optional[str] = typer.Option(None, help="Personal Access Token (PAT)."),
    app_id: Optional[int] = typer.Option(None, help="GitHub App ID."),
    private_key_path: Optional[Path] = typer.Option(
        None, help="Path to GitHub App private key PEM."
    ),
    installation_id: Optional[int] = typer.Option(None, help="GitHub App installation ID."),
    api_url: Optional[str] = typer.Option(None, help="GitHub REST API base URL."),
    env_path: Optional[Path] = typer.Option(None, help="Path to .env file."),
    # --- Output ---
    output_dir: Optional[Path] = typer.Option(None, help="Directory for output files."),
    output: Optional[Path] = typer.Option(None, help="Explicit JSON output path."),
    # --- Scan profile ---
    scan_profile: Optional[str] = typer.Option(None, help="Scan depth: standard or deep."),
    scan_large_files: Optional[bool] = typer.Option(
        None, "--scan-large-files/--no-scan-large-files", help="Include large-file analysis."
    ),
    scan_workflow_contents: Optional[bool] = typer.Option(
        None,
        "--scan-workflow-contents/--no-scan-workflow-contents",
        help="Fetch workflow file contents.",
    ),
    security_alert_counts: Optional[bool] = typer.Option(
        None,
        "--security-alert-counts/--no-security-alert-counts",
        help="Include security alert counts.",
    ),
    include_archived: Optional[bool] = typer.Option(
        None, "--include-archived/--exclude-archived", help="Include archived repositories."
    ),
    repo_limit: Optional[int] = typer.Option(None, help="Maximum repositories to scan."),
    concurrency: Optional[int] = typer.Option(None, help="Concurrent API calls."),
    # --- Discovery categories ---
    category: Optional[list[str]] = typer.Option(
        None, "--category", help="Discovery category to enable (repeatable)."
    ),
    enterprise: Optional[str] = typer.Option(
        None, "--enterprise", help="Enterprise slug for enterprise category."
    ),
    # --- Report flags ---
    report: Optional[bool] = typer.Option(
        None, "--report/--no-report", help="Generate HTML report."
    ),
    excel: Optional[bool] = typer.Option(
        None, "--excel/--no-excel", help="Generate Excel workbook."
    ),
    # --- Logging / telemetry ---
    verbose: bool = typer.Option(False, "--verbose", "-v", help="INFO-level logging."),
    debug: bool = typer.Option(False, "--debug", help="DEBUG-level logging."),
    log_format: str = typer.Option("text", "--log-format", help="Log format: text or json."),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous telemetry."),
) -> None:
    """Scan a GitHub organization and produce an inventory."""
    # --- Multi-org dispatch ---
    if config is not None and organization is not None:
        print_error("--config and --organization are mutually exclusive.")
        raise typer.Exit(code=1)

    if config is not None:
        _discover_multi_org(
            config,
            output_dir=output_dir,
            api_url=api_url,
            scan_profile=scan_profile,
            scan_large_files=scan_large_files,
            scan_workflow_contents=scan_workflow_contents,
            security_alert_counts=security_alert_counts,
            include_archived=include_archived,
            repo_limit=repo_limit,
            concurrency=concurrency,
            category=category,
            enterprise=enterprise,
            generate_html=report if report is not None else True,
            generate_excel=excel if excel is not None else False,
            no_telemetry=no_telemetry,
            verbose=verbose,
            debug=debug,
            log_format=log_format,
        )
        return

    from gh_audit.adapters.github_graphql import GitHubGraphQLClient
    from gh_audit.adapters.github_rest import GitHubRestClient
    from gh_audit.auth.github_app import GitHubAppAuth
    from gh_audit.services.discovery import DiscoveryService
    from gh_audit.services.excel_export import ExcelExportService
    from gh_audit.services.reporting import ReportService

    # 1. Configure logging
    _configure_logging(verbose=verbose, debug=debug, log_format=log_format)

    # 2. Print banner
    print(f"gh-audit v{__version__}")

    # 3. Resolve credentials
    try:
        settings = resolve_settings(
            token=token,
            organization=organization,
            app_id=app_id,
            private_key_path=str(private_key_path) if private_key_path else None,
            installation_id=installation_id,
            api_url=api_url,
            scan_profile=scan_profile,
            scan_large_files=scan_large_files,
            scan_workflow_contents=scan_workflow_contents,
            security_alert_counts=security_alert_counts,
            repo_limit=repo_limit,
            concurrency=concurrency,
            include_archived=include_archived,
            telemetry_disabled=no_telemetry or None,
            env_path=env_path,
            categories=category,
            enterprise_slug=enterprise,
        )
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)

    # 4. Initialize telemetry
    telemetry = _start_command_telemetry(
        command="discover",
        organization=settings.organization,
        enabled=not settings.telemetry_disabled,
        auth_method=settings.auth_method,
        tool_version=__version__,
        api_url=getattr(settings, "api_url", None),
        scan_profile=getattr(settings, "scan_profile", None),
        active_categories=list(getattr(settings, "categories", []) or []),
        enterprise_slug=getattr(settings, "enterprise_slug", None),
    )

    # 5. Run discovery
    telemetry.track_discovery_started()
    try:
        import time as _time

        if output is not None:
            paths = OutputPaths.from_json_path(output)
        elif output_dir is not None:
            paths = OutputPaths.from_directory(output_dir, org=settings.organization)
        else:
            paths = OutputPaths.from_directory(Path("."), org=settings.organization)

        _start = _time.monotonic()
        inventory = asyncio.run(
            _run_discover(
                settings=settings,
                telemetry=telemetry,
                GitHubRestClient=GitHubRestClient,
                GitHubGraphQLClient=GitHubGraphQLClient,
                GitHubAppAuth=GitHubAppAuth,
                DiscoveryService=DiscoveryService,
            )
        )
        _elapsed = _time.monotonic() - _start
        # 6. Save inventory JSON
        paths.json.parent.mkdir(parents=True, exist_ok=True)
        paths.json.write_text(inventory.model_dump_json(indent=2), encoding="utf-8")
        print_ok(f"Inventory saved to {paths.json}")
        print_info(f"Discovered {inventory.summary.total_repos} repositories in {_elapsed:.1f}s")

        # 7. Generate HTML report (non-blocking failure)
        generate_html = report if report is not None else True
        if generate_html:
            try:
                ReportService().generate(inventory, paths.report)
                print_ok(f"Report saved to {paths.report}")
            except Exception as exc:
                telemetry.track_warning(
                    "report_warning",
                    error=exc,
                    command="discover",
                    operation="generate_html_report",
                    warning_scope="report",
                )
                print_warn(f"HTML report generation failed: {exc}")

        # 8. Generate Excel workbook (non-blocking failure)
        generate_excel = excel if excel is not None else True
        if generate_excel:
            try:
                ExcelExportService.generate(inventory, paths.excel)
                print_ok(f"Excel workbook saved to {paths.excel}")
            except Exception as exc:
                telemetry.track_warning(
                    "report_warning",
                    error=exc,
                    command="discover",
                    operation="generate_excel_report",
                    warning_scope="report",
                )
                print_warn(f"Excel export failed: {exc}")

        # 9. Print summary
        summary = inventory.summary
        print()
        print(f"Organization: {settings.organization}")
        print(f"Repositories: {summary.total_repos}")
        print(f"  Public:     {summary.public_repos}")
        print(f"  Private:    {summary.private_repos}")
        print(f"  Internal:   {summary.internal_repos}")
        print(f"  Archived:   {summary.archived_repos}")
        print(f"  Forked:     {summary.forked_repos}")
        print()
        print(f"Output: {paths.json}")
        print()
        print(CLI_BANNER)

        telemetry.track_discovery_completed(
            command="discover",
            duration_seconds=_elapsed,
            repo_count=inventory.summary.total_repos,
            member_count=inventory.users.total,
            package_count=len(inventory.packages),
            workflow_count=inventory.summary.total_workflow_count,
            issue_count=inventory.summary.total_issues,
        )
    except ScannerError as exc:
        print_error(str(exc))
        telemetry.track_discovery_failed(error=exc)
        telemetry.capture_exception(exc)
        raise typer.Exit(code=exc.exit_code)
    except Exception as exc:
        print_error(f"Unexpected error: {exc}")
        telemetry.track_discovery_failed(error=exc)
        telemetry.capture_exception(exc)
        raise typer.Exit(code=1)
    finally:
        telemetry.shutdown()


def _discover_multi_org(
    config_path: Path,
    *,
    output_dir: Path | None,
    api_url: str | None,
    scan_profile: str | None,
    scan_large_files: bool | None,
    scan_workflow_contents: bool | None,
    security_alert_counts: bool | None,
    include_archived: bool | None,
    repo_limit: int | None,
    concurrency: int | None,
    category: list[str] | None,
    enterprise: str | None,
    generate_html: bool,
    generate_excel: bool,
    no_telemetry: bool,
    verbose: bool,
    debug: bool,
    log_format: str,
) -> None:
    """Run multi-org discovery from a YAML config file."""
    # 1. Configure logging
    _configure_logging(verbose=verbose, debug=debug, log_format=log_format)

    # 2. Print banner
    print(f"gh-audit v{__version__}")

    # 3. Load config
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)

    # 4. Build CLI overrides dict from non-None flags
    overrides: dict[str, object] = {}
    if api_url is not None:
        overrides["api_url"] = api_url
    if scan_profile is not None:
        overrides["scan_profile"] = scan_profile
    if scan_large_files is not None:
        overrides["scan_large_files"] = scan_large_files
    if scan_workflow_contents is not None:
        overrides["scan_workflow_contents"] = scan_workflow_contents
    if security_alert_counts is not None:
        overrides["security_alert_counts"] = security_alert_counts
    if include_archived is not None:
        overrides["include_archived"] = include_archived
    if repo_limit is not None:
        overrides["repo_limit"] = repo_limit
    if concurrency is not None:
        overrides["concurrency"] = concurrency
    if category is not None:
        overrides["categories"] = list(category)
    if enterprise is not None:
        overrides["enterprise_slug"] = enterprise

    # 5. Resolve output directory
    resolved_dir = output_dir if output_dir is not None else Path(".")
    resolved_dir.mkdir(parents=True, exist_ok=True)

    # 6. Run all orgs
    summary = asyncio.run(
        run_all_orgs(
            config,
            config_path=config_path,
            cli_overrides=overrides,
            output_dir=resolved_dir,
            generate_html=generate_html,
            generate_excel=generate_excel,
            no_telemetry=no_telemetry,
        )
    )

    # 7. Write summary JSON
    summary_paths = SummaryPaths.from_directory(resolved_dir)
    summary_paths.json.parent.mkdir(parents=True, exist_ok=True)
    summary_paths.json.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    print_ok(f"Summary saved to {summary_paths.json}")

    # 8. Generate summary HTML
    try:
        generate_summary_html(summary, summary_paths.report)
        print_ok(f"Summary report saved to {summary_paths.report}")
    except Exception as exc:
        print_warn(f"Summary HTML generation failed: {exc}")

    # 9. Print results
    totals = summary.totals
    print()
    print(
        f"Summary: {totals.organizations_succeeded} succeeded, {totals.organizations_failed} failed"
    )
    print()
    print(CLI_BANNER)

    # 10. Exit code
    if totals.organizations_failed > 0:
        raise typer.Exit(code=1)


async def _run_discover(
    *,
    settings,
    telemetry,
    GitHubRestClient,
    GitHubGraphQLClient,
    GitHubAppAuth,
    DiscoveryService,
):
    """Execute the async discovery flow.

    Returns the completed Inventory.
    """
    rest = None
    gql = None

    try:
        # Build auth
        app_auth = None
        token_value: str | None = None

        if settings.auth_method == "github_app":
            app_auth = GitHubAppAuth(
                app_id=settings.app_id,
                private_key_path=settings.private_key_path,
                installation_id=settings.installation_id,
                api_url=settings.api_url,
            )
        else:
            token_value = settings.token.get_secret_value()

        # Build clients
        rest = GitHubRestClient(
            token=token_value,
            app_auth=app_auth,
            base_url=settings.api_url,
        )
        gql = GitHubGraphQLClient(
            token=token_value,
            app_auth=app_auth,
            graphql_url=settings.graphql_url,
        )

        # Verify credentials
        await rest.verify_credentials(settings.organization)
        rate_info = rest.rate_limit_remaining
        rate_display = f"{rate_info}/hr" if rate_info is not None else "unknown"
        print_ok(f"Credentials verified ({settings.auth_method}, rate limit: {rate_display})")

        # Run discovery
        service = DiscoveryService(
            rest_client=rest,
            graphql_client=gql,
            config=settings,
            telemetry=telemetry,
        )
        inventory = await service.discover()

        return inventory

    finally:
        if rest is not None:
            await rest.close()
        if gql is not None:
            await gql.close()


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


@app.command()
def report(
    inventory_path: Path = typer.Option(..., "--inventory", help="Path to inventory JSON file."),
    html: Optional[bool] = typer.Option(None, "--html/--no-html", help="Generate HTML report."),
    excel: Optional[bool] = typer.Option(
        None, "--excel/--no-excel", help="Generate Excel workbook."
    ),
    output_dir: Optional[Path] = typer.Option(None, help="Output directory for reports."),
    # --- Logging ---
    verbose: bool = typer.Option(False, "--verbose", "-v", help="INFO-level logging."),
    debug: bool = typer.Option(False, "--debug", help="DEBUG-level logging."),
    log_format: str = typer.Option("text", "--log-format", help="Log format: text or json."),
) -> None:
    """Regenerate reports from an existing inventory JSON file."""
    from gh_audit.models.inventory import Inventory
    from gh_audit.services.excel_export import ExcelExportService
    from gh_audit.services.reporting import ReportService

    # Configure logging
    _configure_logging(verbose=verbose, debug=debug, log_format=log_format)
    telemetry = None
    inv = None
    try:
        if not inventory_path.exists():
            raise FileNotFoundError(str(inventory_path))

        raw = inventory_path.read_text(encoding="utf-8")
        inv = Inventory.model_validate_json(raw)
        telemetry = _start_command_telemetry(
            command="report",
            organization=inv.metadata.organization,
            enabled=True,
            auth_method=inv.metadata.auth_method,
            tool_version=inv.metadata.tool_version,
            scan_profile=inv.metadata.scan_profile,
            api_url=inv.metadata.api_url,
            active_categories=list(inv.metadata.active_categories),
            enterprise_slug=inv.metadata.enterprise_slug,
        )

        # Determine output paths
        generate_html = html if html is not None else True
        generate_excel = excel if excel is not None else True
        telemetry.track_report_started(html=generate_html, excel=generate_excel, command="report")

        if output_dir is not None:
            paths = OutputPaths.from_directory(output_dir, org=inv.metadata.organization)
        else:
            paths = OutputPaths.from_json_path(inventory_path)

        if generate_html:
            try:
                ReportService().generate(inv, paths.report)
                print_ok(f"Report saved to {paths.report}")
            except Exception as exc:
                telemetry.track_warning(
                    "report_warning",
                    error=exc,
                    command="report",
                    operation="generate_html_report",
                    warning_scope="report",
                )
                print_warn(f"HTML report generation failed: {exc}")

        if generate_excel:
            try:
                ExcelExportService.generate(inv, paths.excel)
                print_ok(f"Excel workbook saved to {paths.excel}")
            except Exception as exc:
                telemetry.track_warning(
                    "report_warning",
                    error=exc,
                    command="report",
                    operation="generate_excel_report",
                    warning_scope="report",
                )
                print_warn(f"Excel export failed: {exc}")

        telemetry.track_report_completed(
            html=generate_html,
            excel=generate_excel,
            command="report",
        )
        print_ok("Report generation complete.")
    except Exception as exc:
        generate_html = html if html is not None else True
        generate_excel = excel if excel is not None else True
        if telemetry is None:
            telemetry = _start_command_telemetry(
                command="report",
                organization="unknown",
                enabled=True,
                auth_method="unknown",
                tool_version=__version__,
            )
            telemetry.track_report_started(
                html=generate_html,
                excel=generate_excel,
                command="report",
            )

        if isinstance(exc, FileNotFoundError):
            print_error(f"Inventory file not found: {inventory_path}")
        elif inv is None:
            print_error(f"Failed to load inventory: {exc}")
        else:
            print_error(f"Report generation failed: {exc}")

        telemetry.track_report_failed(error=exc, command="report")
        telemetry.capture_exception(exc)
        raise typer.Exit(code=1)
    finally:
        if telemetry is not None:
            telemetry.shutdown()


# ---------------------------------------------------------------------------
# assess command
# ---------------------------------------------------------------------------


@app.command()
def assess(
    input_path: Path = typer.Option(
        "output/inventory.json",
        "--input",
        help="Path to inventory JSON file.",
    ),
    output_path: Path = typer.Option(
        "output/assessment.html",
        "--output",
        help="Path for assessment HTML report.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="INFO-level logging."),
    debug: bool = typer.Option(False, "--debug", help="DEBUG-level logging."),
    log_format: str = typer.Option("text", "--log-format", help="Log format: text or json."),
) -> None:
    """Assess an inventory against best-practice rules and generate a findings report."""
    from datetime import datetime, timezone

    from gh_audit.models.finding import AssessmentResult
    from gh_audit.models.inventory import Inventory
    from gh_audit.rules.registry import RuleEngine
    from gh_audit.services.assessment import AssessmentService

    _configure_logging(verbose=verbose, debug=debug, log_format=log_format)
    telemetry = None
    inventory = None
    try:
        if not input_path.exists():
            raise FileNotFoundError(str(input_path))

        raw = input_path.read_text(encoding="utf-8")
        inventory = Inventory.model_validate_json(raw)
        telemetry = _start_command_telemetry(
            command="assess",
            organization=inventory.metadata.organization,
            enabled=True,
            auth_method=inventory.metadata.auth_method,
            tool_version=inventory.metadata.tool_version,
            scan_profile=inventory.metadata.scan_profile,
            api_url=inventory.metadata.api_url,
            active_categories=list(inventory.metadata.active_categories),
            enterprise_slug=inventory.metadata.enterprise_slug,
        )
        telemetry.track_assess_started()

        # Warn on schema version mismatch
        from gh_audit.services.discovery import _SCHEMA_VERSION

        if inventory.metadata.schema_version != _SCHEMA_VERSION:
            print_warn(
                f"Inventory schema version {inventory.metadata.schema_version!r} "
                f"differs from expected {_SCHEMA_VERSION!r}. "
                f"Assessment results may be incomplete."
            )

        engine = RuleEngine.default()
        findings = engine.run(inventory)

        result = AssessmentResult(
            organization=inventory.metadata.organization,
            generated_at=datetime.now(timezone.utc),
            inventory_generated_at=inventory.metadata.generated_at,
            scan_profile=inventory.metadata.scan_profile,
            active_categories=inventory.metadata.active_categories,
            findings=findings,
        )

        AssessmentService().generate(result, output_path)
        critical = sum(1 for f in findings if f.severity.value == "critical")
        warning = sum(1 for f in findings if f.severity.value == "warning")
        info = sum(1 for f in findings if f.severity.value == "info")
        telemetry.track_assess_completed(
            command="assess",
            finding_count=len(findings),
            critical_count=critical,
            warning_count=warning,
            info_count=info,
        )
    except Exception as exc:
        if telemetry is None:
            telemetry = _start_command_telemetry(
                command="assess",
                organization="unknown",
                enabled=True,
                auth_method="unknown",
                tool_version=__version__,
            )
            telemetry.track_assess_started()

        if isinstance(exc, FileNotFoundError):
            print_error(f"Inventory file not found: {input_path}")
        elif inventory is None:
            print_error(f"Failed to load inventory: {exc}")
        else:
            print_error(f"Assessment report generation failed: {exc}")

        telemetry.track_assess_failed(error=exc, command="assess")
        telemetry.capture_exception(exc)
        raise typer.Exit(code=1)
    finally:
        if telemetry is not None:
            telemetry.shutdown()

    print_ok(f"Assessment complete: {critical} critical, {warning} warning, {info} info findings")
    print_ok(f"Report saved to {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> None:
    """Entry point for the gh-audit CLI (used by pyproject.toml scripts)."""
    app()


if __name__ == "__main__":
    run()
