"""gh-audit exception hierarchy.

All exceptions carry an exit_code so the CLI can use SystemExit(err.exit_code).

Exit code conventions:
    1  — generic / unclassified scanner error
    2  — configuration error
    3  — authentication error
    4  — API error
    5  — rate-limit error
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for all gh-audit errors.

    Parameters
    ----------
    message:
        Human-readable description of the error.
    exit_code:
        Process exit code to use when the error reaches the CLI boundary.
        Defaults to 1.
    """

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class ConfigError(ScannerError):
    """Raised when configuration is invalid or incomplete.

    Default exit_code: 2
    """

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message, exit_code=exit_code)


class AuthenticationError(ScannerError):
    """Raised when credentials are missing, expired, or rejected.

    Default exit_code: 3
    """

    def __init__(self, message: str, *, exit_code: int = 3) -> None:
        super().__init__(message, exit_code=exit_code)


class APIError(ScannerError):
    """Raised when a GitHub API call fails.

    Parameters
    ----------
    message:
        Human-readable description of the failure.
    status_code:
        HTTP status code returned by the API, if available.
    exit_code:
        Process exit code. Defaults to 4.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        exit_code: int = 4,
    ) -> None:
        super().__init__(message, exit_code=exit_code)
        self.status_code = status_code


class RateLimitError(APIError):
    """Raised when the GitHub API rate limit is exceeded.

    Parameters
    ----------
    message:
        Human-readable description of the failure.
    retry_after:
        Number of seconds to wait before retrying, if provided by the API.
    status_code:
        HTTP status code (typically 429 or 403).
    exit_code:
        Process exit code. Defaults to 5.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: int | None = None,
        status_code: int | None = None,
        exit_code: int = 5,
    ) -> None:
        super().__init__(message, status_code=status_code, exit_code=exit_code)
        self.retry_after = retry_after
