"""Tests for gh_audit.models.security — SecurityInfo model."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.security import SecurityInfo


# ---------------------------------------------------------------------------
# Default values — None means "not scanned / unknown"
# ---------------------------------------------------------------------------


class TestSecurityInfoDefaults:
    """All fields default to None or False as per spec."""

    def test_dependabot_enabled_default_is_none(self):
        info = SecurityInfo()
        assert info.dependabot_enabled is None

    def test_code_scanning_enabled_default_is_none(self):
        info = SecurityInfo()
        assert info.code_scanning_enabled is None

    def test_secret_scanning_enabled_default_is_none(self):
        info = SecurityInfo()
        assert info.secret_scanning_enabled is None

    def test_alerts_accessible_default_is_false(self):
        info = SecurityInfo()
        assert info.alerts_accessible is False

    def test_counts_exact_default_is_false(self):
        info = SecurityInfo()
        assert info.counts_exact is False

    def test_dependabot_alerts_open_default_is_none(self):
        info = SecurityInfo()
        assert info.dependabot_alerts_open is None

    def test_code_scanning_alerts_open_default_is_none(self):
        info = SecurityInfo()
        assert info.code_scanning_alerts_open is None

    def test_secret_scanning_alerts_open_default_is_none(self):
        info = SecurityInfo()
        assert info.secret_scanning_alerts_open is None


# ---------------------------------------------------------------------------
# Null vs zero semantics
# ---------------------------------------------------------------------------


class TestSecurityNullVsZeroSemantics:
    """None = not scanned; 0 = known to be zero. These must NOT be confused."""

    def test_none_is_not_zero(self):
        info = SecurityInfo()
        assert info.dependabot_alerts_open is None
        assert info.dependabot_alerts_open != 0

    def test_zero_is_explicitly_settable(self):
        info = SecurityInfo(dependabot_alerts_open=0)
        assert info.dependabot_alerts_open == 0

    def test_counts_when_accessible_with_zero_counts(self):
        info = SecurityInfo(
            alerts_accessible=True,
            counts_exact=True,
            dependabot_alerts_open=0,
            code_scanning_alerts_open=0,
            secret_scanning_alerts_open=0,
        )
        assert info.alerts_accessible is True
        assert info.counts_exact is True
        assert info.dependabot_alerts_open == 0

    def test_counts_when_accessible_with_real_counts(self):
        info = SecurityInfo(
            alerts_accessible=True,
            counts_exact=True,
            dependabot_alerts_open=5,
            code_scanning_alerts_open=3,
            secret_scanning_alerts_open=1,
        )
        assert info.dependabot_alerts_open == 5
        assert info.code_scanning_alerts_open == 3
        assert info.secret_scanning_alerts_open == 1

    def test_not_accessible_counts_remain_none(self):
        """When alerts are not accessible, counts stay None (not converted to 0)."""
        info = SecurityInfo(alerts_accessible=False)
        assert info.dependabot_alerts_open is None
        assert info.code_scanning_alerts_open is None
        assert info.secret_scanning_alerts_open is None


# ---------------------------------------------------------------------------
# Feature enabled flags
# ---------------------------------------------------------------------------


class TestSecurityFeatureFlags:
    """Enabled flags can be True, False, or None (unknown)."""

    def test_all_enabled_true(self):
        info = SecurityInfo(
            dependabot_enabled=True,
            code_scanning_enabled=True,
            secret_scanning_enabled=True,
        )
        assert info.dependabot_enabled is True
        assert info.code_scanning_enabled is True
        assert info.secret_scanning_enabled is True

    def test_all_enabled_false(self):
        info = SecurityInfo(
            dependabot_enabled=False,
            code_scanning_enabled=False,
            secret_scanning_enabled=False,
        )
        assert info.dependabot_enabled is False
        assert info.code_scanning_enabled is False
        assert info.secret_scanning_enabled is False

    def test_mixed_flags(self):
        info = SecurityInfo(
            dependabot_enabled=True,
            code_scanning_enabled=None,
            secret_scanning_enabled=False,
        )
        assert info.dependabot_enabled is True
        assert info.code_scanning_enabled is None
        assert info.secret_scanning_enabled is False


# ---------------------------------------------------------------------------
# Extra fields forbidden
# ---------------------------------------------------------------------------


class TestSecurityInfoExtraForbidden:
    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            SecurityInfo(unknown_flag=True)


# ---------------------------------------------------------------------------
# JSON serialization roundtrip
# ---------------------------------------------------------------------------


class TestSecurityInfoSerialization:
    """model_dump_json / model_validate_json preserve None vs False distinction."""

    def test_roundtrip_defaults(self):
        original = SecurityInfo()
        json_str = original.model_dump_json()
        restored = SecurityInfo.model_validate_json(json_str)
        assert restored == original
        assert restored.dependabot_alerts_open is None
        assert restored.alerts_accessible is False

    def test_roundtrip_with_values(self):
        original = SecurityInfo(
            dependabot_enabled=True,
            alerts_accessible=True,
            counts_exact=True,
            dependabot_alerts_open=7,
            code_scanning_alerts_open=0,
            secret_scanning_alerts_open=None,
        )
        json_str = original.model_dump_json()
        restored = SecurityInfo.model_validate_json(json_str)
        assert restored.dependabot_enabled is True
        assert restored.alerts_accessible is True
        assert restored.counts_exact is True
        assert restored.dependabot_alerts_open == 7
        assert restored.code_scanning_alerts_open == 0
        assert restored.secret_scanning_alerts_open is None
