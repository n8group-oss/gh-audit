"""Contract tests for PostHog dashboard definitions."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_module() -> ModuleType:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "create_posthog_dashboards.py"
    spec = importlib.util.spec_from_file_location("create_posthog_dashboards", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dashboard_map(module: ModuleType) -> dict[str, dict[str, object]]:
    dashboards = getattr(module, "DASHBOARDS")
    return {dashboard["name"]: dashboard for dashboard in dashboards}


def _dashboard_events(dashboard: dict[str, object]) -> set[str]:
    events: set[str] = set()
    for insight in dashboard["insights"]:
        series = insight["query"]["source"]["series"]
        for node in series:
            events.add(node["event"])
    return events


def _dashboard_breakdowns(dashboard: dict[str, object]) -> set[str]:
    breakdowns: set[str] = set()
    for insight in dashboard["insights"]:
        breakdown_filter = insight["query"]["source"].get("breakdownFilter")
        if not breakdown_filter:
            continue
        for breakdown in breakdown_filter.get("breakdowns", []):
            breakdowns.add(breakdown["property"])
    return breakdowns


def test_defines_canonical_dashboard_set() -> None:
    module = _load_module()

    dashboards = _dashboard_map(module)

    assert set(dashboards) == {
        "gh-audit \u2014 Usage & Adoption",
        "gh-audit \u2014 Health & Errors",
        "gh-audit \u2014 Warning Hotspots",
    }


def test_warning_dashboard_covers_warning_families_and_breakdowns() -> None:
    module = _load_module()

    dashboard = _dashboard_map(module)["gh-audit \u2014 Warning Hotspots"]

    assert {
        "repo_enrichment_warning",
        "org_discovery_warning",
        "enterprise_discovery_warning",
        "report_warning",
        "multi_org_warning",
    } <= _dashboard_events(dashboard)
    assert {"warning_scope", "operation", "category"} <= _dashboard_breakdowns(dashboard)


def test_health_dashboard_keeps_native_exception_and_failure_views() -> None:
    module = _load_module()

    dashboard = _dashboard_map(module)["gh-audit \u2014 Health & Errors"]

    assert {
        "$exception",
        "discovery_failed",
        "report_failed",
        "assess_failed",
        "multi_org_failed",
    } <= _dashboard_events(dashboard)
    assert {"$exception_type", "tool_version"} <= _dashboard_breakdowns(dashboard)


def test_usage_dashboard_covers_command_category_and_version_adoption() -> None:
    module = _load_module()

    dashboard = _dashboard_map(module)["gh-audit \u2014 Usage & Adoption"]

    assert {
        "scanner_launched",
        "discovery_completed",
        "report_completed",
        "assess_completed",
        "multi_org_completed",
    } <= _dashboard_events(dashboard)
    assert {
        "command",
        "active_categories",
        "tool_version",
        "auth_method",
        "scan_profile",
    } <= _dashboard_breakdowns(dashboard)
