"""Tests for gh_audit.cli.output — ASCII-only terminal output helpers."""

from __future__ import annotations

import io


from gh_audit.cli.output import (
    print_error,
    print_info,
    print_ok,
    print_warn,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture(func, *args, **kwargs) -> str:
    """Call func with a StringIO stream and return what was written."""
    buf = io.StringIO()
    func(*args, stream=buf, **kwargs)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tag format tests
# ---------------------------------------------------------------------------


class TestPrintOk:
    """print_ok writes [OK] prefix, ASCII only."""

    def test_contains_ok_tag(self):
        out = _capture(print_ok, "all good")
        assert "[OK]" in out

    def test_contains_message(self):
        out = _capture(print_ok, "all good")
        assert "all good" in out

    def test_no_emoji(self):
        out = _capture(print_ok, "test message")
        assert all(ord(c) < 128 for c in out), f"Non-ASCII found: {out!r}"

    def test_ends_with_newline(self):
        out = _capture(print_ok, "message")
        assert out.endswith("\n")


class TestPrintError:
    """print_error writes [ERROR] prefix, ASCII only."""

    def test_contains_error_tag(self):
        out = _capture(print_error, "something failed")
        assert "[ERROR]" in out

    def test_contains_message(self):
        out = _capture(print_error, "something failed")
        assert "something failed" in out

    def test_no_emoji(self):
        out = _capture(print_error, "test message")
        assert all(ord(c) < 128 for c in out), f"Non-ASCII found: {out!r}"

    def test_ends_with_newline(self):
        out = _capture(print_error, "message")
        assert out.endswith("\n")


class TestPrintWarn:
    """print_warn writes [WARN] prefix, ASCII only."""

    def test_contains_warn_tag(self):
        out = _capture(print_warn, "be careful")
        assert "[WARN]" in out

    def test_contains_message(self):
        out = _capture(print_warn, "be careful")
        assert "be careful" in out

    def test_no_emoji(self):
        out = _capture(print_warn, "test message")
        assert all(ord(c) < 128 for c in out), f"Non-ASCII found: {out!r}"

    def test_ends_with_newline(self):
        out = _capture(print_warn, "message")
        assert out.endswith("\n")


class TestPrintInfo:
    """print_info writes [INFO] prefix, ASCII only."""

    def test_contains_info_tag(self):
        out = _capture(print_info, "fyi")
        assert "[INFO]" in out

    def test_contains_message(self):
        out = _capture(print_info, "fyi")
        assert "fyi" in out

    def test_no_emoji(self):
        out = _capture(print_info, "test message")
        assert all(ord(c) < 128 for c in out), f"Non-ASCII found: {out!r}"

    def test_ends_with_newline(self):
        out = _capture(print_info, "message")
        assert out.endswith("\n")


# ---------------------------------------------------------------------------
# Default stream is sys.stdout (smoke check — does not raise)
# ---------------------------------------------------------------------------


class TestDefaultStream:
    """Functions work without explicit stream argument."""

    def test_print_ok_no_stream_arg(self, capsys):
        print_ok("works")
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_print_error_no_stream_arg(self, capsys):
        print_error("oops")
        captured = capsys.readouterr()
        assert "[ERROR]" in captured.err

    def test_print_warn_no_stream_arg(self, capsys):
        print_warn("heads up")
        captured = capsys.readouterr()
        assert "[WARN]" in captured.out

    def test_print_info_no_stream_arg(self, capsys):
        print_info("fyi")
        captured = capsys.readouterr()
        assert "[INFO]" in captured.out
