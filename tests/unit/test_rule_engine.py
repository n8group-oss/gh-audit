"""Unit tests for the rule engine and registry."""

from __future__ import annotations

from datetime import datetime, timezone


from gh_audit.models.finding import Finding, Pillar, Scope, Severity
from gh_audit.models.inventory import Inventory, InventoryMetadata, InventorySummary
from gh_audit.models.user import OrgMemberSummary
from gh_audit.rules.registry import RuleEngine


def _make_inventory() -> Inventory:
    return Inventory(
        metadata=InventoryMetadata(
            schema_version="2.0",
            generated_at=datetime(2026, 3, 29, tzinfo=timezone.utc),
            tool_version="0.1.0",
            organization="testorg",
            auth_method="pat",
            scan_profile="total",
            active_categories=["security"],
        ),
        summary=InventorySummary(total_repos=0),
        repositories=[],
        users=OrgMemberSummary(total=0, admins=0, members=0),
    )


def _dummy_rule_a(inventory: Inventory) -> list[Finding]:
    return [
        Finding(
            rule_id="TEST-001",
            pillar=Pillar.security,
            severity=Severity.critical,
            scope=Scope.org,
            title="Test critical",
            detail="d",
            remediation="r",
        )
    ]


def _dummy_rule_b(inventory: Inventory) -> list[Finding]:
    return [
        Finding(
            rule_id="TEST-002",
            pillar=Pillar.governance,
            severity=Severity.info,
            scope=Scope.org,
            title="Test info",
            detail="d",
            remediation="r",
        )
    ]


def _failing_rule(inventory: Inventory) -> list[Finding]:
    raise RuntimeError("Rule exploded")


class TestRuleEngine:
    def test_runs_all_rules(self) -> None:
        engine = RuleEngine(rules=[_dummy_rule_a, _dummy_rule_b])
        findings = engine.run(_make_inventory())
        assert len(findings) == 2

    def test_sorts_by_severity(self) -> None:
        engine = RuleEngine(rules=[_dummy_rule_b, _dummy_rule_a])
        findings = engine.run(_make_inventory())
        assert findings[0].severity == Severity.critical
        assert findings[1].severity == Severity.info

    def test_empty_rules(self) -> None:
        engine = RuleEngine(rules=[])
        findings = engine.run(_make_inventory())
        assert findings == []

    def test_rule_failure_is_skipped(self) -> None:
        engine = RuleEngine(rules=[_failing_rule, _dummy_rule_a])
        findings = engine.run(_make_inventory())
        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"

    def test_default_engine_has_all_rules(self) -> None:
        engine = RuleEngine.default()
        assert len(engine._rules) == 21
