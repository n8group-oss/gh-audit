"""Tests for category framework extensions to ScannerConfig.

Covers:
- total scan profile acceptance and auto-enable behaviour
- categories field validation and deduplication
- enterprise_slug field
- resolve_active_categories helper
- Regression: standard and deep profiles unchanged
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.config import ScannerConfig, resolve_active_categories


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pat_config(**kwargs) -> ScannerConfig:
    """Build a minimal PAT-authenticated ScannerConfig."""
    defaults = {"organization": "my-org", "token": "ghp_test123"}
    defaults.update(kwargs)
    return ScannerConfig(**defaults)


# ---------------------------------------------------------------------------
# total profile
# ---------------------------------------------------------------------------


class TestTotalProfile:
    """scan_profile='total' is accepted and behaves correctly."""

    def test_total_profile_accepted(self):
        cfg = _pat_config(scan_profile="total")
        assert cfg.scan_profile == "total"

    def test_total_enables_scan_large_files(self):
        cfg = _pat_config(scan_profile="total")
        assert cfg.scan_large_files is True

    def test_total_enables_scan_workflow_contents(self):
        cfg = _pat_config(scan_profile="total")
        assert cfg.scan_workflow_contents is True

    def test_total_enables_security_alert_counts(self):
        cfg = _pat_config(scan_profile="total")
        assert cfg.security_alert_counts is True

    def test_total_auto_populates_all_five_categories(self):
        cfg = _pat_config(scan_profile="total")
        assert set(cfg.categories) == {
            "governance",
            "operations",
            "security",
            "adoption",
            "enterprise",
        }

    def test_total_categories_are_sorted(self):
        cfg = _pat_config(scan_profile="total")
        assert cfg.categories == sorted(cfg.categories)

    def test_total_merges_with_pre_existing_categories(self):
        """User-supplied categories are kept; total adds the rest."""
        cfg = _pat_config(scan_profile="total", categories=["governance"])
        assert set(cfg.categories) == {
            "governance",
            "operations",
            "security",
            "adoption",
            "enterprise",
        }


# ---------------------------------------------------------------------------
# categories field
# ---------------------------------------------------------------------------


class TestCategoriesField:
    """categories field validation and deduplication."""

    def test_categories_default_is_empty(self):
        cfg = _pat_config()
        assert cfg.categories == []

    def test_valid_single_category_accepted(self):
        cfg = _pat_config(categories=["governance"])
        assert cfg.categories == ["governance"]

    def test_all_five_valid_categories_accepted(self):
        cats = ["governance", "operations", "security", "adoption", "enterprise"]
        cfg = _pat_config(categories=cats)
        assert set(cfg.categories) == set(cats)

    def test_invalid_category_raises_validation_error(self):
        with pytest.raises(ValidationError) as exc_info:
            _pat_config(categories=["invalid_cat"])
        assert "Invalid categories" in str(exc_info.value)

    def test_mixed_valid_invalid_raises_validation_error(self):
        with pytest.raises(ValidationError):
            _pat_config(categories=["governance", "bogus"])

    def test_duplicate_categories_are_deduplicated(self):
        cfg = _pat_config(categories=["governance", "governance", "operations"])
        assert cfg.categories.count("governance") == 1

    def test_categories_are_sorted_after_dedup(self):
        cfg = _pat_config(categories=["operations", "governance"])
        assert cfg.categories == ["governance", "operations"]


# ---------------------------------------------------------------------------
# enterprise_slug field
# ---------------------------------------------------------------------------


class TestEnterpriseSlugField:
    """enterprise_slug field is optional and stored correctly."""

    def test_enterprise_slug_default_is_none(self):
        cfg = _pat_config()
        assert cfg.enterprise_slug is None

    def test_enterprise_slug_set(self):
        cfg = _pat_config(enterprise_slug="my-enterprise")
        assert cfg.enterprise_slug == "my-enterprise"


# ---------------------------------------------------------------------------
# resolve_active_categories
# ---------------------------------------------------------------------------


class TestResolveActiveCategories:
    """resolve_active_categories returns the correct active set."""

    def test_empty_categories_returns_empty_set(self):
        cfg = _pat_config()
        assert resolve_active_categories(cfg) == set()

    def test_non_enterprise_categories_returned_as_is(self):
        cfg = _pat_config(categories=["governance", "operations"])
        assert resolve_active_categories(cfg) == {"governance", "operations"}

    def test_enterprise_dropped_when_no_slug(self):
        cfg = _pat_config(categories=["governance", "enterprise"])
        result = resolve_active_categories(cfg)
        assert "enterprise" not in result
        assert "governance" in result

    def test_enterprise_kept_when_slug_present(self):
        cfg = _pat_config(categories=["enterprise"], enterprise_slug="acme-corp")
        result = resolve_active_categories(cfg)
        assert "enterprise" in result

    def test_all_categories_with_slug(self):
        cfg = _pat_config(scan_profile="total", enterprise_slug="acme-corp")
        result = resolve_active_categories(cfg)
        assert result == {"governance", "operations", "security", "adoption", "enterprise"}

    def test_all_categories_without_slug_drops_enterprise(self):
        cfg = _pat_config(scan_profile="total")
        result = resolve_active_categories(cfg)
        assert "enterprise" not in result
        assert result == {"governance", "operations", "security", "adoption"}


# ---------------------------------------------------------------------------
# Regression: standard and deep profiles unchanged
# ---------------------------------------------------------------------------


class TestExistingProfilesUnchanged:
    """Existing standard and deep profiles continue to work as before."""

    def test_standard_does_not_auto_enable_features(self):
        cfg = _pat_config(scan_profile="standard")
        assert cfg.scan_large_files is False
        assert cfg.scan_workflow_contents is False
        assert cfg.security_alert_counts is False

    def test_standard_does_not_auto_populate_categories(self):
        cfg = _pat_config(scan_profile="standard")
        assert cfg.categories == []

    def test_deep_enables_sub_features(self):
        cfg = _pat_config(scan_profile="deep")
        assert cfg.scan_large_files is True
        assert cfg.scan_workflow_contents is True
        assert cfg.security_alert_counts is True

    def test_deep_does_not_auto_populate_categories(self):
        cfg = _pat_config(scan_profile="deep")
        assert cfg.categories == []

    def test_deep_with_explicit_categories_kept(self):
        cfg = _pat_config(scan_profile="deep", categories=["governance"])
        assert cfg.categories == ["governance"]
