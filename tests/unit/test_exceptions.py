"""Tests for gh_audit.exceptions — base exception hierarchy."""

from __future__ import annotations

import pytest

from gh_audit.exceptions import (
    APIError,
    AuthenticationError,
    ConfigError,
    RateLimitError,
    ScannerError,
)


class TestScannerError:
    """ScannerError base class behaviour."""

    def test_is_exception(self):
        err = ScannerError("boom")
        assert isinstance(err, Exception)

    def test_default_exit_code_is_1(self):
        err = ScannerError("boom")
        assert err.exit_code == 1

    def test_custom_exit_code(self):
        err = ScannerError("boom", exit_code=3)
        assert err.exit_code == 3

    def test_message_accessible(self):
        err = ScannerError("something went wrong")
        assert str(err) == "something went wrong"

    def test_can_be_raised_and_caught(self):
        with pytest.raises(ScannerError, match="test error"):
            raise ScannerError("test error")


class TestConfigError:
    """ConfigError is a ScannerError with exit_code 2."""

    def test_inherits_scanner_error(self):
        err = ConfigError("bad config")
        assert isinstance(err, ScannerError)

    def test_default_exit_code_is_2(self):
        err = ConfigError("bad config")
        assert err.exit_code == 2

    def test_can_override_exit_code(self):
        err = ConfigError("bad config", exit_code=5)
        assert err.exit_code == 5

    def test_message_preserved(self):
        err = ConfigError("missing token")
        assert "missing token" in str(err)


class TestAuthenticationError:
    """AuthenticationError is a ScannerError with exit_code 3."""

    def test_inherits_scanner_error(self):
        err = AuthenticationError("auth failed")
        assert isinstance(err, ScannerError)

    def test_default_exit_code_is_3(self):
        err = AuthenticationError("auth failed")
        assert err.exit_code == 3

    def test_message_preserved(self):
        err = AuthenticationError("invalid PAT")
        assert "invalid PAT" in str(err)


class TestAPIError:
    """APIError is a ScannerError with exit_code 4, carries status_code."""

    def test_inherits_scanner_error(self):
        err = APIError("request failed")
        assert isinstance(err, ScannerError)

    def test_default_exit_code_is_4(self):
        err = APIError("request failed")
        assert err.exit_code == 4

    def test_status_code_stored(self):
        err = APIError("not found", status_code=404)
        assert err.status_code == 404

    def test_status_code_defaults_to_none(self):
        err = APIError("request failed")
        assert err.status_code is None

    def test_message_preserved(self):
        err = APIError("server error", status_code=500)
        assert "server error" in str(err)


class TestRateLimitError:
    """RateLimitError is an APIError with exit_code 5, carries retry_after."""

    def test_inherits_api_error(self):
        err = RateLimitError("rate limited")
        assert isinstance(err, APIError)

    def test_inherits_scanner_error(self):
        err = RateLimitError("rate limited")
        assert isinstance(err, ScannerError)

    def test_default_exit_code_is_5(self):
        err = RateLimitError("rate limited")
        assert err.exit_code == 5

    def test_retry_after_stored(self):
        err = RateLimitError("rate limited", retry_after=60)
        assert err.retry_after == 60

    def test_retry_after_defaults_to_none(self):
        err = RateLimitError("rate limited")
        assert err.retry_after is None

    def test_message_preserved(self):
        err = RateLimitError("too many requests")
        assert "too many requests" in str(err)


class TestExceptionHierarchy:
    """Verify exception hierarchy relationships."""

    def test_config_error_caught_as_scanner_error(self):
        with pytest.raises(ScannerError):
            raise ConfigError("config problem")

    def test_auth_error_caught_as_scanner_error(self):
        with pytest.raises(ScannerError):
            raise AuthenticationError("auth problem")

    def test_api_error_caught_as_scanner_error(self):
        with pytest.raises(ScannerError):
            raise APIError("api problem")

    def test_rate_limit_caught_as_api_error(self):
        with pytest.raises(APIError):
            raise RateLimitError("rate limited")

    def test_rate_limit_caught_as_scanner_error(self):
        with pytest.raises(ScannerError):
            raise RateLimitError("rate limited")
