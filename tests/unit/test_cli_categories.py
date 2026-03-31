"""Tests for --category and --enterprise CLI flags, credential resolver env vars,
and OrgEntry model additions for categories and enterprise_slug.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from gh_audit.cli.app import app
from gh_audit.cli.credential_resolver import resolve_settings
from gh_audit.models.multi_org import OrgEntry

runner = CliRunner()


# ---------------------------------------------------------------------------
# CLI --help shows new flags
# ---------------------------------------------------------------------------


def test_discover_accepts_category_flag() -> None:
    result = runner.invoke(app, ["discover", "--category", "governance", "--help"])
    assert result.exit_code == 0


def test_discover_accepts_enterprise_flag() -> None:
    result = runner.invoke(app, ["discover", "--enterprise", "my-ent", "--help"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# OrgEntry model — categories and enterprise_slug fields
# ---------------------------------------------------------------------------


def test_org_entry_with_categories() -> None:
    org = OrgEntry(name="o", token="ghp_x", categories=["governance", "security"])
    assert org.categories == ["governance", "security"]


def test_org_entry_with_enterprise_slug() -> None:
    org = OrgEntry(name="o", token="ghp_x", enterprise_slug="my-ent")
    assert org.enterprise_slug == "my-ent"


def test_org_entry_categories_default_is_none() -> None:
    org = OrgEntry(name="o", token="ghp_x")
    assert org.categories is None


def test_org_entry_enterprise_slug_default_is_none() -> None:
    org = OrgEntry(name="o", token="ghp_x")
    assert org.enterprise_slug is None


# ---------------------------------------------------------------------------
# resolve_settings — GH_SCANNER_CATEGORIES env var
# ---------------------------------------------------------------------------


def test_resolve_settings_categories_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_CATEGORIES", "governance,security")
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    # Use a non-existent .env so file doesn't interfere
    settings = resolve_settings(env_path="/nonexistent/.env")
    assert "governance" in settings.categories
    assert "security" in settings.categories


def test_resolve_settings_categories_strips_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_CATEGORIES", " governance , security ")
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    settings = resolve_settings(env_path="/nonexistent/.env")
    assert "governance" in settings.categories
    assert "security" in settings.categories


def test_resolve_settings_categories_cli_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_CATEGORIES", "security")
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    settings = resolve_settings(
        categories=["governance"],
        env_path="/nonexistent/.env",
    )
    assert "governance" in settings.categories
    # CLI wins; env "security" should not be present
    assert "security" not in settings.categories


def test_resolve_settings_categories_empty_when_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_SCANNER_CATEGORIES", raising=False)
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    settings = resolve_settings(env_path="/nonexistent/.env")
    assert settings.categories == []


# ---------------------------------------------------------------------------
# resolve_settings — GH_SCANNER_ENTERPRISE_SLUG env var
# ---------------------------------------------------------------------------


def test_resolve_settings_enterprise_slug_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_SCANNER_ENTERPRISE_SLUG", "my-ent")
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    settings = resolve_settings(env_path="/nonexistent/.env")
    assert settings.enterprise_slug == "my-ent"


def test_resolve_settings_enterprise_slug_cli_overrides_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GH_SCANNER_ENTERPRISE_SLUG", "env-ent")
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    settings = resolve_settings(
        enterprise_slug="cli-ent",
        env_path="/nonexistent/.env",
    )
    assert settings.enterprise_slug == "cli-ent"


def test_resolve_settings_enterprise_slug_none_when_not_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GH_SCANNER_ENTERPRISE_SLUG", raising=False)
    monkeypatch.setenv("GH_SCANNER_TOKEN", "ghp_test")
    monkeypatch.setenv("GH_SCANNER_ORGANIZATION", "myorg")
    settings = resolve_settings(env_path="/nonexistent/.env")
    assert settings.enterprise_slug is None
