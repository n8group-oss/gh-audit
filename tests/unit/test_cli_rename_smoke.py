"""Smoke tests for the package/CLI rename to gh-audit."""

from __future__ import annotations

from importlib import import_module

from typer.testing import CliRunner


def test_gh_audit_about_module_is_importable() -> None:
    about = import_module("gh_audit.__about__")
    assert hasattr(about, "__version__")


def test_gh_audit_cli_app_name() -> None:
    cli_module = import_module("gh_audit.cli.app")
    assert cli_module.app.info.name == "gh-audit"


def test_gh_audit_version_output() -> None:
    cli_module = import_module("gh_audit.cli.app")
    about = import_module("gh_audit.__about__")

    result = CliRunner().invoke(cli_module.app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"gh-audit {about.__version__}"
