#!/usr/bin/env python3
"""Create (or recreate) PostHog dashboards for gh-audit telemetry.

Requirements:
    pip install httpx

Usage:
    # Using 1Password:
    POSTHOG_API_KEY=$(op read "op://Private/posthog.com/Other Fields/API Key") \
        python scripts/create_posthog_dashboards.py

    # Or set the key directly:
    POSTHOG_API_KEY=phx_... python scripts/create_posthog_dashboards.py

    # Delete existing dashboards first (by name match), then recreate:
    POSTHOG_API_KEY=phx_... python scripts/create_posthog_dashboards.py --recreate
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POSTHOG_HOST = "https://eu.posthog.com"
ENVIRONMENT_ID = 149031  # gh-audit project

USAGE_DASHBOARD_NAME = "gh-audit \u2014 Usage & Adoption"
USAGE_DASHBOARD_DESC = "gh-audit adoption, discovery volumes, system metadata, and feature usage"

HEALTH_DASHBOARD_NAME = "gh-audit \u2014 Health & Errors"
HEALTH_DASHBOARD_DESC = "Reliability, error tracking, crash reports, and performance monitoring"

WARNINGS_DASHBOARD_NAME = "gh-audit \u2014 Warning Hotspots"
WARNINGS_DASHBOARD_DESC = (
    "Structured warning telemetry for discovery, reporting, and multi-org partial failures"
)


# ---------------------------------------------------------------------------
# Insight definitions
# ---------------------------------------------------------------------------


def _trend(
    event: str,
    *,
    math: str = "total",
    math_property: str | None = None,
    custom_name: str | None = None,
    properties: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build a single EventsNode for a TrendsQuery series."""
    node: dict[str, Any] = {"kind": "EventsNode", "math": math, "event": event}
    if math_property:
        node["math_property"] = math_property
    if custom_name:
        node["custom_name"] = custom_name
    if properties:
        node["properties"] = properties
    return node


def _query(
    series: list[dict[str, Any]],
    *,
    breakdown_property: str | None = None,
    formula: str | None = None,
    date_from: str = "-90d",
    interval: str = "week",
) -> dict[str, Any]:
    """Build an InsightVizNode query."""
    source: dict[str, Any] = {
        "kind": "TrendsQuery",
        "series": series,
        "interval": interval,
        "dateRange": {"date_from": date_from},
        "trendsFilter": {"showValuesOnSeries": True},
        "version": 2,
    }
    if breakdown_property:
        source["breakdownFilter"] = {
            "breakdowns": [{"type": "event", "property": breakdown_property}]
        }
    if formula:
        source["trendsFilter"]["formula"] = formula
    return {"kind": "InsightVizNode", "source": source}


def _event_display_name(event: str) -> str:
    """Convert telemetry event names into compact chart labels."""
    label = (
        event.removesuffix("_warning")
        .removesuffix("_completed")
        .removesuffix("_failed")
        .replace("multi_org", "multi-org")
        .replace("_", " ")
    )
    return label.title()


WARNING_EVENTS = [
    "repo_enrichment_warning",
    "org_discovery_warning",
    "enterprise_discovery_warning",
    "report_warning",
    "multi_org_warning",
]

FAILURE_EVENTS = [
    "discovery_failed",
    "report_failed",
    "assess_failed",
    "multi_org_failed",
]

COMPLETION_EVENTS = [
    "discovery_completed",
    "report_completed",
    "assess_completed",
    "multi_org_completed",
]


# -- Usage & Adoption insights -----------------------------------------------

USAGE_INSIGHTS: list[dict[str, object]] = [
    {
        "name": "Scanner Launches",
        "description": "Total scanner launches over time",
        "query": _query([_trend("scanner_launched")]),
    },
    {
        "name": "Unique Instances",
        "description": "Unique scanner instances (distinct_id) over time",
        "query": _query([_trend("scanner_launched", math="dau")]),
    },
    {
        "name": "Platform Distribution",
        "description": "Scanner launches broken down by operating system",
        "query": _query([_trend("scanner_launched")], breakdown_property="os"),
    },
    {
        "name": "Python Version Distribution",
        "description": "Scanner launches broken down by Python version",
        "query": _query([_trend("scanner_launched")], breakdown_property="python_version"),
    },
    {
        "name": "Version Adoption",
        "description": "Scanner launches broken down by tool_version",
        "query": _query([_trend("scanner_launched")], breakdown_property="tool_version"),
    },
    {
        "name": "Auth Method Distribution",
        "description": "Scanner launches broken down by authentication method",
        "query": _query([_trend("scanner_launched")], breakdown_property="auth_method"),
    },
    {
        "name": "Command Distribution",
        "description": "Scanner launches broken down by command",
        "query": _query([_trend("scanner_launched")], breakdown_property="command"),
    },
    {
        "name": "Scan Profile Distribution",
        "description": "Scanner launches broken down by scan profile",
        "query": _query([_trend("scanner_launched")], breakdown_property="scan_profile"),
    },
    {
        "name": "Active Category Distribution",
        "description": "Scanner launches broken down by active categories",
        "query": _query([_trend("scanner_launched")], breakdown_property="active_categories"),
    },
    {
        "name": "Discoveries Over Time",
        "description": "Count of completed discoveries over time",
        "query": _query([_trend("discovery_completed")]),
    },
    {
        "name": "Total Repos Discovered",
        "description": "Sum of repo_count from completed discoveries",
        "query": _query([_trend("discovery_completed", math="sum", math_property="repo_count")]),
    },
    {
        "name": "Total Members Discovered",
        "description": "Sum of member_count from completed discoveries",
        "query": _query([_trend("discovery_completed", math="sum", math_property="member_count")]),
    },
    {
        "name": "Total Packages Discovered",
        "description": "Sum of package_count from completed discoveries",
        "query": _query([_trend("discovery_completed", math="sum", math_property="package_count")]),
    },
    {
        "name": "Total Workflows Discovered",
        "description": "Sum of workflow_count from completed discoveries",
        "query": _query(
            [_trend("discovery_completed", math="sum", math_property="workflow_count")]
        ),
    },
    {
        "name": "Total Issues Discovered",
        "description": "Sum of issue_count from completed discoveries",
        "query": _query([_trend("discovery_completed", math="sum", math_property="issue_count")]),
    },
    {
        "name": "Reports Generated",
        "description": "Completed reports over time",
        "query": _query([_trend("report_completed")]),
    },
    {
        "name": "Assessments Completed",
        "description": "Completed assessments over time",
        "query": _query([_trend("assess_completed")]),
    },
    {
        "name": "Multi-Org Runs Completed",
        "description": "Completed multi-org runs over time",
        "query": _query([_trend("multi_org_completed")]),
    },
    {
        "name": "Completed Commands by Type",
        "description": "Completed discovery, report, assess, and multi-org commands",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in COMPLETION_EVENTS]
        ),
    },
]


# -- Health & Errors insights -------------------------------------------------

HEALTH_INSIGHTS: list[dict[str, object]] = [
    {
        "name": "Discovery Success Rate",
        "description": "Percentage of discoveries that complete successfully",
        "query": _query(
            [
                _trend("discovery_completed", custom_name="Completed"),
                _trend("discovery_failed", custom_name="Failed"),
            ],
            formula="A / (A + B) * 100",
        ),
    },
    {
        "name": "Failed vs Successful Discoveries",
        "description": "Side-by-side comparison of completed and failed discoveries",
        "query": _query(
            [
                _trend("discovery_completed", custom_name="Completed"),
                _trend("discovery_failed", custom_name="Failed"),
            ]
        ),
    },
    {
        "name": "Discovery Errors by Type",
        "description": "Discovery failures broken down by error_type",
        "query": _query([_trend("discovery_failed")], breakdown_property="error_type"),
    },
    {
        "name": "Report Failures Over Time",
        "description": "Report generation failures over time",
        "query": _query([_trend("report_failed")]),
    },
    {
        "name": "Report Errors by Type",
        "description": "Report failures broken down by error_type",
        "query": _query([_trend("report_failed")], breakdown_property="error_type"),
    },
    {
        "name": "Assess Failures Over Time",
        "description": "Assessment failures over time",
        "query": _query([_trend("assess_failed")]),
    },
    {
        "name": "Assess Errors by Type",
        "description": "Assessment failures broken down by error_type",
        "query": _query([_trend("assess_failed")], breakdown_property="error_type"),
    },
    {
        "name": "Multi-Org Failures Over Time",
        "description": "Multi-org execution failures over time",
        "query": _query([_trend("multi_org_failed")]),
    },
    {
        "name": "Multi-Org Errors by Type",
        "description": "Multi-org failures broken down by error_type",
        "query": _query([_trend("multi_org_failed")], breakdown_property="error_type"),
    },
    {
        "name": "Avg Discovery Duration",
        "description": "Average duration_seconds for completed discoveries",
        "query": _query(
            [
                _trend(
                    "discovery_completed",
                    math="avg",
                    math_property="duration_seconds",
                )
            ]
        ),
    },
    {
        "name": "P95 Discovery Duration",
        "description": "95th percentile duration_seconds for completed discoveries",
        "query": _query(
            [
                _trend(
                    "discovery_completed",
                    math="p95",
                    math_property="duration_seconds",
                )
            ]
        ),
    },
    {
        "name": "All Errors Combined",
        "description": "Combined discovery and report failures over time",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in FAILURE_EVENTS]
        ),
    },
    {
        "name": "Failures by Tool Version",
        "description": "Failures broken down by tool_version",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in FAILURE_EVENTS],
            breakdown_property="tool_version",
        ),
    },
    {
        "name": "Exceptions (Autocapture)",
        "description": "SDK-captured exceptions ($exception events) over time",
        "query": _query([_trend("$exception")]),
    },
    {
        "name": "Exceptions by Type",
        "description": "SDK-captured exceptions broken down by exception type",
        "query": _query([_trend("$exception")], breakdown_property="$exception_type"),
    },
]


# -- Warning Hotspots insights ------------------------------------------------

WARNING_INSIGHTS: list[dict[str, object]] = [
    {
        "name": "Warnings Over Time",
        "description": "Structured warning events over time by warning family",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in WARNING_EVENTS]
        ),
    },
    {
        "name": "Warnings by Scope",
        "description": "Structured warnings broken down by warning scope",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in WARNING_EVENTS],
            breakdown_property="warning_scope",
        ),
    },
    {
        "name": "Warnings by Operation",
        "description": "Structured warnings broken down by operation",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in WARNING_EVENTS],
            breakdown_property="operation",
        ),
    },
    {
        "name": "Warnings by Category",
        "description": "Structured warnings broken down by category",
        "query": _query(
            [_trend(event, custom_name=_event_display_name(event)) for event in WARNING_EVENTS],
            breakdown_property="category",
        ),
    },
    {
        "name": "Report Warnings Over Time",
        "description": "Non-fatal report-generation warnings over time",
        "query": _query([_trend("report_warning")]),
    },
    {
        "name": "Multi-Org Warnings Over Time",
        "description": "Per-organization warnings emitted during multi-org runs",
        "query": _query([_trend("multi_org_warning")]),
    },
]


DASHBOARDS: list[dict[str, object]] = [
    {
        "name": USAGE_DASHBOARD_NAME,
        "description": USAGE_DASHBOARD_DESC,
        "insights": USAGE_INSIGHTS,
    },
    {
        "name": HEALTH_DASHBOARD_NAME,
        "description": HEALTH_DASHBOARD_DESC,
        "insights": HEALTH_INSIGHTS,
    },
    {
        "name": WARNINGS_DASHBOARD_NAME,
        "description": WARNINGS_DASHBOARD_DESC,
        "insights": WARNING_INSIGHTS,
    },
]


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def _api_url(path: str) -> str:
    return f"{POSTHOG_HOST}/api/environments/{ENVIRONMENT_ID}{path}"


def _create_dashboard(client: httpx.Client, name: str, description: str) -> int:
    """Create a dashboard and return its ID."""
    resp = client.post(
        _api_url("/dashboards/"),
        json={"name": name, "description": description, "pinned": True},
    )
    resp.raise_for_status()
    dashboard_id: int = resp.json()["id"]
    print(f"  Created dashboard: {name} (id={dashboard_id})")
    return dashboard_id


def _create_insight(
    client: httpx.Client,
    dashboard_id: int,
    insight: dict[str, object],
) -> int:
    """Create an insight tile linked to a dashboard. Returns insight ID."""
    payload = {
        "name": insight["name"],
        "description": insight["description"],
        "dashboards": [dashboard_id],
        "query": insight["query"],
    }
    resp = client.post(_api_url("/insights/"), json=payload)
    resp.raise_for_status()
    insight_id: int = resp.json()["id"]
    print(f"    + {insight['name']} (id={insight_id})")
    return insight_id


def _delete_dashboards_by_name(client: httpx.Client, names: set[str]) -> None:
    """Soft-delete any dashboards matching the given names."""
    resp = client.get(_api_url("/dashboards/"))
    resp.raise_for_status()
    for dashboard in resp.json().get("results", []):
        if dashboard["name"] in names and not dashboard.get("deleted"):
            patch_resp = client.patch(
                _api_url(f"/dashboards/{dashboard['id']}/"),
                json={"deleted": True},
            )
            patch_resp.raise_for_status()
            print(f"  Deleted dashboard: {dashboard['name']} (id={dashboard['id']})")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create PostHog dashboards for gh-audit telemetry."
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete existing dashboards with matching names before creating new ones.",
    )
    args = parser.parse_args()

    api_key = os.environ.get("POSTHOG_API_KEY", "")
    if not api_key:
        print(
            "ERROR: POSTHOG_API_KEY environment variable is required.\n"
            "  Create a Personal API Key at https://eu.posthog.com/settings/user-api-keys",
            file=sys.stderr,
        )
        return 1

    if not api_key.startswith("phx_"):
        print(
            "WARNING: API key does not start with 'phx_'. "
            "Make sure you are using a Personal API Key, not a project API key.",
            file=sys.stderr,
        )

    headers = {"Authorization": f"Bearer {api_key}"}

    with httpx.Client(headers=headers, timeout=30.0) as client:
        dashboard_names = {dashboard["name"] for dashboard in DASHBOARDS}

        if args.recreate:
            print("Deleting existing dashboards...")
            _delete_dashboards_by_name(client, dashboard_names)
            print()

        dashboard_urls: list[tuple[str, int]] = []
        total = 0
        for dashboard in DASHBOARDS:
            print(f"Creating '{dashboard['name']}'...")
            dashboard_id = _create_dashboard(
                client,
                str(dashboard["name"]),
                str(dashboard["description"]),
            )
            insights = dashboard["insights"]
            for insight in insights:
                _create_insight(client, dashboard_id, insight)
            print(f"  -> {len(insights)} tiles created\n")
            dashboard_urls.append((str(dashboard["name"]), dashboard_id))
            total += len(insights)

        print(f"Done! {len(DASHBOARDS)} dashboards, {total} insight tiles.")
        for name, dashboard_id in dashboard_urls:
            print(f"  {name}: {POSTHOG_HOST}/project/{ENVIRONMENT_ID}/dashboard/{dashboard_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
