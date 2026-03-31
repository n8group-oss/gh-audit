"""Packaging smoke tests — verify the package installs and basic metadata is correct."""

import importlib


def test_package_importable():
    """gh_audit package can be imported."""
    import gh_audit  # noqa: F401


def test_version_defined():
    """__version__ is defined and non-empty."""
    import gh_audit

    assert hasattr(gh_audit, "__version__")
    assert isinstance(gh_audit.__version__, str)
    assert len(gh_audit.__version__) > 0


def test_subpackages_importable():
    """All subpackages can be imported without errors."""
    subpackages = [
        "gh_audit.cli",
        "gh_audit.adapters",
        "gh_audit.auth",
        "gh_audit.models",
        "gh_audit.services",
    ]
    for pkg in subpackages:
        mod = importlib.import_module(pkg)
        assert mod is not None, f"Failed to import {pkg}"


def test_entry_point_callable():
    """The CLI entry point function exists and is callable."""
    from gh_audit.cli.app import run

    assert callable(run)
