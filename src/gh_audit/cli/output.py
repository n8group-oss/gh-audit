"""ASCII-only terminal output helpers.

All output uses plain ASCII bracket tags — no emoji, no Unicode box-drawing
characters — so the tool works correctly on legacy Windows CMD consoles and
any terminal with a limited character set.

Tag format:
    [OK]    — success / confirmation
    [ERROR] — failure / problem
    [WARN]  — warning, non-fatal
    [INFO]  — informational

Usage::

    from gh_audit.cli.output import print_ok, print_error, print_warn, print_info

    print_ok("Scan complete.")
    print_error("Connection refused.")
    print_warn("Rate limit at 80%.")
    print_info("Fetching repositories...")
"""

from __future__ import annotations

import sys
from typing import IO


def _write(tag: str, message: str, stream: IO[str] | None) -> None:
    """Write a tagged line to *stream* (defaults to sys.stdout)."""
    out = stream if stream is not None else sys.stdout
    out.write(f"{tag} {message}\n")


def print_ok(message: str, *, stream: IO[str] | None = None) -> None:
    """Write an [OK] tagged line."""
    _write("[OK]", message, stream)


def print_error(message: str, *, stream: IO[str] | None = None) -> None:
    """Write an [ERROR] tagged line to stderr."""
    _write("[ERROR]", message, stream or sys.stderr)


def print_warn(message: str, *, stream: IO[str] | None = None) -> None:
    """Write a [WARN] tagged line."""
    _write("[WARN]", message, stream)


def print_info(message: str, *, stream: IO[str] | None = None) -> None:
    """Write an [INFO] tagged line."""
    _write("[INFO]", message, stream)
