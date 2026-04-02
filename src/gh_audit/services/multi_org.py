"""Multi-organization scanning service.

Provides:
- ``load_config`` — read and validate a YAML multi-org config file.
- ``build_scanner_config`` — merge CLI > per-org > defaults > built-in layers.
- ``run_all_orgs`` — sequential runner that scans each org and returns a summary.
"""

from __future__ import annotations

import os
import re
import time
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr

from gh_audit.__about__ import __version__
from gh_audit.adapters.github_graphql import GitHubGraphQLClient
from gh_audit.adapters.github_rest import GitHubRestClient
from gh_audit.auth.github_app import GitHubAppAuth
from gh_audit.cli.output import print_error, print_info
from gh_audit.exceptions import ConfigError
from gh_audit.models.config import ScannerConfig
from gh_audit.models.inventory import Inventory
from gh_audit.models.multi_org import (
    MultiOrgConfig,
    MultiOrgSummary,
    OrgEntry,
    OrgScanResult,
)
from gh_audit.services.discovery import DiscoveryService
from gh_audit.services.excel_export import ExcelExportService
from gh_audit.services.reporting import ReportService
from gh_audit.services.telemetry import Telemetry

# ---------------------------------------------------------------------------
# Environment variable expansion
# ---------------------------------------------------------------------------

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _expand_env_vars(value: str) -> str:
    """Replace ``${VAR_NAME}`` patterns with environment variable values.

    Raises
    ------
    ConfigError
        If a referenced environment variable is not set.
    """

    def _replacer(match: re.Match) -> str:
        var_name = match.group(1)
        try:
            return os.environ[var_name]
        except KeyError:
            raise ConfigError(
                f"Environment variable '{var_name}' is not set "
                f"(referenced in config as '${{{var_name}}}')"
            )

    return _ENV_VAR_PATTERN.sub(_replacer, value)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def load_config(path: Path) -> MultiOrgConfig:
    """Read a YAML multi-org config file and return a validated model.

    Environment variable references (``${VAR}``) in string values under
    ``organizations[].token`` are expanded before Pydantic validation.

    Parameters
    ----------
    path:
        Path to the YAML configuration file.

    Raises
    ------
    ConfigError
        If the file is not found, contains invalid YAML, fails validation,
        or references undefined environment variables.
    """
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Failed to read config file: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in config file: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Config file must contain a YAML mapping at the top level")

    # Expand ${ENV_VAR} in token and private_key_path fields for each organization
    for org in data.get("organizations", []):
        if isinstance(org, dict):
            if isinstance(org.get("token"), str):
                org["token"] = _expand_env_vars(org["token"])
            if isinstance(org.get("private_key_path"), str):
                org["private_key_path"] = _expand_env_vars(org["private_key_path"])

    try:
        return MultiOrgConfig.model_validate(data)
    except Exception as exc:
        raise ConfigError(f"Config validation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Config merging
# ---------------------------------------------------------------------------

# Fields that can be overridden at per-org and CLI level.
_MERGE_FIELDS = (
    "api_url",
    "scan_profile",
    "scan_large_files",
    "scan_workflow_contents",
    "security_alert_counts",
    "repo_limit",
    "concurrency",
    "include_archived",
    "categories",
    "enterprise_slug",
)


def build_scanner_config(
    org: OrgEntry,
    defaults: dict[str, Any],
    cli_overrides: dict[str, Any],
) -> ScannerConfig:
    """Merge three configuration layers into a ``ScannerConfig``.

    Priority order (highest wins): CLI overrides > per-org > defaults > built-in.

    Parameters
    ----------
    org:
        Per-organization entry from the multi-org config.
    defaults:
        Shared defaults section from the multi-org config.
    cli_overrides:
        Values provided via CLI flags.
    """
    merged: dict[str, Any] = {"organization": org.name}

    # Auth — always from the per-org entry
    if org.token is not None:
        merged["token"] = SecretStr(org.token)
    else:
        merged["app_id"] = org.app_id
        merged["private_key_path"] = org.private_key_path
        merged["installation_id"] = org.installation_id

    # Merge each overridable field: CLI > per-org > defaults
    for field in _MERGE_FIELDS:
        cli_val = cli_overrides.get(field)
        org_val = getattr(org, field, None)
        default_val = defaults.get(field)

        if cli_val is not None:
            merged[field] = cli_val
        elif org_val is not None:
            merged[field] = org_val
        elif default_val is not None:
            merged[field] = default_val
        # else: let ScannerConfig use its built-in default

    return ScannerConfig(**merged)


# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------


async def run_all_orgs(
    config: MultiOrgConfig,
    *,
    config_path: Path,
    cli_overrides: dict[str, Any] | None = None,
    output_dir: Path,
    generate_html: bool = True,
    generate_excel: bool = False,
    no_telemetry: bool = False,
) -> MultiOrgSummary:
    """Scan every organization in *config* sequentially.

    For each org:
    1. Build a ``ScannerConfig`` with merged settings.
    2. Construct REST + GraphQL clients with appropriate auth.
    3. Verify credentials.
    4. Run ``DiscoveryService.discover()``.
    5. Save inventory JSON (and optionally HTML report / Excel export).
    6. Record an ``OrgScanResult``.

    On ANY exception the org is marked as failed and processing continues.

    Parameters
    ----------
    config:
        Validated multi-org config.
    config_path:
        Path to the original config file (stored in the summary).
    cli_overrides:
        CLI flag values that override per-org and default settings.
    output_dir:
        Root output directory. Each org gets a subdirectory.
    generate_html:
        Whether to generate an HTML report per org.
    generate_excel:
        Whether to generate an Excel export per org.
    no_telemetry:
        Disable anonymous usage telemetry.
    """
    overrides = dict(cli_overrides or {})
    if no_telemetry:
        overrides["telemetry_disabled"] = True

    total = len(config.organizations)
    results: list[OrgScanResult] = []
    aggregate_t0 = time.monotonic()
    telemetry = Telemetry(
        organization="multi-org",
        enabled=not no_telemetry,
    )
    telemetry.bind_context(
        command="multi_org",
        multi_org=True,
        config_file=str(config_path),
        organization_count=total,
        generate_html=generate_html,
        generate_excel=generate_excel,
    )
    telemetry.track_scanner_launched(
        auth_method=_multi_org_auth_method(config),
        tool_version=__version__,
    )
    telemetry.track_multi_org_started(
        command="multi_org",
        organizations_total=total,
    )

    try:
        for idx, org_entry in enumerate(config.organizations, start=1):
            org_name = org_entry.name
            print_info(f"[{idx}/{total}] {org_name}")

            t0 = time.monotonic()
            try:
                settings = build_scanner_config(org_entry, config.defaults, overrides)

                # Build clients
                rest_client, gql_client = _build_clients(settings)
                try:
                    # Verify credentials
                    await rest_client.verify_credentials(org_name)

                    # Run discovery
                    svc = DiscoveryService(
                        rest_client=rest_client,
                        graphql_client=gql_client,
                        config=settings,
                        telemetry=telemetry,
                    )
                    inventory = await svc.discover()

                    # Write outputs
                    org_dir = output_dir / org_name
                    org_dir.mkdir(parents=True, exist_ok=True)

                    date_prefix = date.today().isoformat()
                    _save_inventory_json(inventory, org_dir / f"{date_prefix}-inventory.json")

                    if generate_html:
                        ReportService().generate(inventory, org_dir / f"{org_name}-report.html")

                    if generate_excel:
                        ExcelExportService.generate(
                            inventory, org_dir / f"{org_name}-inventory.xlsx"
                        )

                    duration = time.monotonic() - t0
                    result = _build_success_result(org_name, settings, inventory, duration)
                finally:
                    await rest_client.close()
                    await gql_client.close()

            except Exception as exc:
                duration = time.monotonic() - t0
                print_error(f"{org_name}: {exc}")
                telemetry.track_warning(
                    "multi_org_warning",
                    error=exc,
                    command="multi_org",
                    operation="scan_organization",
                    organization=org_name,
                    warning_scope="multi_org",
                )
                result = OrgScanResult(
                    name=org_name,
                    status="failed",
                    error=str(exc),
                    duration_seconds=round(duration, 2),
                )

            results.append(result)

        summary = MultiOrgSummary(
            tool_version=__version__,
            config_file=str(config_path),
            organizations=results,
        )
        totals = summary.totals
        telemetry.track_multi_org_completed(
            command="multi_org",
            organizations_scanned=totals.organizations_scanned,
            organizations_succeeded=totals.organizations_succeeded,
            organizations_failed=totals.organizations_failed,
            warning_count=sum(result.warnings_count for result in results),
            duration_seconds=round(time.monotonic() - aggregate_t0, 2),
        )
        return summary
    except Exception as exc:
        telemetry.track_multi_org_failed(
            error=exc,
            command="multi_org",
            organizations_total=total,
        )
        telemetry.capture_exception(exc)
        raise
    finally:
        telemetry.shutdown()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_clients(
    settings: ScannerConfig,
) -> tuple[GitHubRestClient, GitHubGraphQLClient]:
    """Build REST and GraphQL clients from scanner config."""
    if settings.auth_method == "github_app":
        app_auth = GitHubAppAuth(
            app_id=settings.app_id,  # type: ignore[arg-type]
            private_key_path=settings.private_key_path,  # type: ignore[arg-type]
            installation_id=settings.installation_id,  # type: ignore[arg-type]
            api_url=settings.api_url,
        )
        rest = GitHubRestClient(app_auth=app_auth, base_url=settings.api_url)
        gql = GitHubGraphQLClient(app_auth=app_auth, graphql_url=settings.graphql_url)
    else:
        token = settings.token.get_secret_value()  # type: ignore[union-attr]
        rest = GitHubRestClient(token=token, base_url=settings.api_url)
        gql = GitHubGraphQLClient(token=token, graphql_url=settings.graphql_url)

    return rest, gql


def _multi_org_auth_method(config: MultiOrgConfig) -> str:
    """Return a representative auth method for a multi-org run."""
    methods = {"pat" if org.token is not None else "github_app" for org in config.organizations}
    if len(methods) == 1:
        return methods.pop()
    return "mixed"


def _save_inventory_json(inventory: Inventory, path: Path) -> None:
    """Serialize inventory to JSON and write to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    json_str = inventory.model_dump_json(indent=2)
    path.write_text(json_str, encoding="utf-8")


def _build_success_result(
    org_name: str,
    settings: ScannerConfig,
    inventory: Inventory,
    duration: float,
) -> OrgScanResult:
    """Build an OrgScanResult from a successful scan."""
    summary = inventory.summary
    warnings_count = len(inventory.metadata.scan_warnings) + sum(
        len(r.warnings) for r in inventory.repositories
    )

    return OrgScanResult(
        name=org_name,
        status="success",
        scan_profile=settings.scan_profile,
        auth_method=settings.auth_method,
        total_repos=summary.total_repos,
        total_size_bytes=summary.total_size_bytes,
        total_members=inventory.users.total,
        total_workflows=summary.total_workflow_count,
        total_issues=summary.total_issues,
        total_packages=summary.total_packages,
        total_projects=summary.total_projects,
        warnings_count=warnings_count,
        duration_seconds=round(duration, 2),
    )
