"""Credential resolution for gh-audit.

Merges configuration from three sources in priority order:

    1. Explicit CLI keyword arguments (highest priority)
    2. Environment variables (``GH_SCANNER_*``)
    3. A ``.env`` file (lowest priority)

The ``resolve_settings()`` function is the single entry point used by CLI
commands and tests.  It returns a validated ``ScannerConfig`` instance or
raises ``ConfigError`` for invalid/missing configuration.

Implementation notes
--------------------
- **No python-dotenv**: python-dotenv corrupts multi-line values and some
  special characters inside PyInstaller bundles.  We ship a minimal custom
  parser instead.
- Smart quotes (U+201C/D left/right double, U+2018/9 left/right single) are
  stripped from values so users with "smart" editors don't get mysterious
  failures.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any, Dict, Optional

from pydantic import ValidationError

from gh_audit.exceptions import ConfigError
from gh_audit.models.config import ScannerConfig

# ---------------------------------------------------------------------------
# Environment variable names
# ---------------------------------------------------------------------------

_ENV_TOKEN = "GH_SCANNER_TOKEN"
_ENV_ORGANIZATION = "GH_SCANNER_ORGANIZATION"
_ENV_API_URL = "GH_SCANNER_API_URL"
_ENV_APP_ID = "GH_SCANNER_APP_ID"
_ENV_PRIVATE_KEY_PATH = "GH_SCANNER_PRIVATE_KEY_PATH"
_ENV_INSTALLATION_ID = "GH_SCANNER_INSTALLATION_ID"
_ENV_TELEMETRY_DISABLED = "GH_SCANNER_TELEMETRY_DISABLED"
_ENV_CATEGORIES = "GH_SCANNER_CATEGORIES"
_ENV_ENTERPRISE_SLUG = "GH_SCANNER_ENTERPRISE_SLUG"

# Smart / curly quote characters to strip from .env values
_SMART_QUOTES = "\u201c\u201d\u2018\u2019"


# ---------------------------------------------------------------------------
# Custom .env parser
# ---------------------------------------------------------------------------


def parse_env_file(path: pathlib.Path | str) -> Dict[str, str]:
    """Parse a ``.env`` file and return a dict of key-value pairs.

    Handles:
    - ``KEY=VALUE``
    - ``KEY="VALUE"`` / ``KEY='VALUE'``
    - ``export KEY=VALUE`` prefix
    - ``# comment`` and blank lines
    - Smart / curly quotes stripped from values
    - Values may contain ``=`` (e.g. base64 tokens)

    Returns an empty dict if the file does not exist.
    """
    path = pathlib.Path(path)
    if not path.exists():
        return {}

    result: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        # Skip blank lines and comments
        if not line or line.startswith("#"):
            continue

        # Strip optional 'export ' prefix
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()

        # Split on first '=' only so values can contain '='
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue

        # Strip outer regular quotes (single or double)
        if len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
                value = value[1:-1]

        # Strip smart / curly quotes from both ends
        value = value.strip(_SMART_QUOTES)

        result[key] = value

    return result


# ---------------------------------------------------------------------------
# resolve_settings
# ---------------------------------------------------------------------------


def resolve_settings(
    *,
    token: Optional[str] = None,
    organization: Optional[str] = None,
    app_id: Optional[int] = None,
    private_key_path: Optional[str] = None,
    installation_id: Optional[int] = None,
    api_url: Optional[str] = None,
    scan_profile: Optional[str] = None,
    scan_large_files: Optional[bool] = None,
    scan_workflow_contents: Optional[bool] = None,
    security_alert_counts: Optional[bool] = None,
    repo_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    telemetry_disabled: Optional[bool] = None,
    include_archived: Optional[bool] = None,
    categories: list[str] | None = None,
    enterprise_slug: Optional[str] = None,
    env_path: Optional[pathlib.Path | str] = None,
) -> ScannerConfig:
    """Resolve all scanner settings and return a validated ``ScannerConfig``.

    Parameters
    ----------
    token:
        Personal Access Token (PAT).  Overrides env / .env.
    organization:
        GitHub organization login.  Overrides env / .env.
    app_id:
        GitHub App ID.  Overrides env / .env.
    private_key_path:
        Path to the GitHub App private key PEM.  Overrides env / .env.
    installation_id:
        GitHub App installation ID.  Overrides env / .env.
    api_url:
        Base REST API URL.  Overrides env / .env.
    scan_profile / scan_large_files / …:
        Forwarded directly to ``ScannerConfig`` (CLI values win).
    telemetry_disabled:
        Opt out of telemetry.  Overrides env / .env.
    env_path:
        Path to a ``.env`` file.  Defaults to ``./.env`` if not specified.
        Pass a non-existent path to disable .env loading.

    Returns
    -------
    ScannerConfig
        Validated configuration object.

    Raises
    ------
    ConfigError
        If credentials are missing, incomplete, or the token contains
        non-ASCII characters.
    """
    # --- Step 1: load .env file (lowest priority) ---
    if env_path is None:
        _env_file_path = pathlib.Path(".env")
    else:
        _env_file_path = pathlib.Path(env_path)
    dot_env = parse_env_file(_env_file_path)

    def _get(env_key: str) -> Optional[str]:
        """Read env var, then .env fallback."""
        return os.environ.get(env_key) or dot_env.get(env_key) or None

    # --- Step 2: merge sources (CLI wins > env > .env) ---

    # token
    resolved_token: Optional[str] = token or _get(_ENV_TOKEN)

    # organization
    resolved_org: Optional[str] = organization or _get(_ENV_ORGANIZATION)

    # api_url
    resolved_api_url: Optional[str] = api_url or _get(_ENV_API_URL)

    # app credentials
    resolved_app_id: Optional[int]
    if app_id is not None:
        resolved_app_id = app_id
    else:
        raw = _get(_ENV_APP_ID)
        resolved_app_id = int(raw) if raw is not None else None

    resolved_private_key_path: Optional[str] = private_key_path or _get(_ENV_PRIVATE_KEY_PATH)

    resolved_installation_id: Optional[int]
    if installation_id is not None:
        resolved_installation_id = installation_id
    else:
        raw = _get(_ENV_INSTALLATION_ID)
        resolved_installation_id = int(raw) if raw is not None else None

    # telemetry
    resolved_telemetry: Optional[bool]
    if telemetry_disabled is not None:
        resolved_telemetry = telemetry_disabled
    else:
        raw = _get(_ENV_TELEMETRY_DISABLED)
        if raw is not None:
            resolved_telemetry = raw.lower() in ("1", "true", "yes")
        else:
            resolved_telemetry = None

    # categories
    resolved_categories: list[str]
    if categories is not None:
        resolved_categories = list(categories)
    else:
        raw_cats = _get(_ENV_CATEGORIES)
        if raw_cats:
            resolved_categories = [c.strip() for c in raw_cats.split(",") if c.strip()]
        else:
            resolved_categories = []

    # enterprise_slug
    resolved_enterprise_slug: Optional[str] = enterprise_slug or _get(_ENV_ENTERPRISE_SLUG)

    # --- Step 3: validate token is ASCII-only ---
    if resolved_token is not None:
        try:
            resolved_token.encode("ascii")
        except UnicodeEncodeError:
            raise ConfigError(
                "Token contains non-ASCII characters. "
                "GitHub tokens are always ASCII — check for encoding issues."
            )

    # --- Step 4: validate organization is present ---
    if not resolved_org:
        raise ConfigError(
            "Organization is required.  Pass --organization / set GH_SCANNER_ORGANIZATION."
        )

    # --- Step 5: assemble kwargs for ScannerConfig ---
    kwargs: Dict[str, Any] = {"organization": resolved_org}

    if resolved_token is not None:
        kwargs["token"] = resolved_token
    if resolved_app_id is not None:
        kwargs["app_id"] = resolved_app_id
    if resolved_private_key_path is not None:
        kwargs["private_key_path"] = pathlib.Path(resolved_private_key_path)
    if resolved_installation_id is not None:
        kwargs["installation_id"] = resolved_installation_id
    if resolved_api_url is not None:
        kwargs["api_url"] = resolved_api_url
    if scan_profile is not None:
        kwargs["scan_profile"] = scan_profile
    if scan_large_files is not None:
        kwargs["scan_large_files"] = scan_large_files
    if scan_workflow_contents is not None:
        kwargs["scan_workflow_contents"] = scan_workflow_contents
    if security_alert_counts is not None:
        kwargs["security_alert_counts"] = security_alert_counts
    if repo_limit is not None:
        kwargs["repo_limit"] = repo_limit
    if concurrency is not None:
        kwargs["concurrency"] = concurrency
    if resolved_telemetry is not None:
        kwargs["telemetry_disabled"] = resolved_telemetry
    if include_archived is not None:
        kwargs["include_archived"] = include_archived
    if resolved_categories:
        kwargs["categories"] = resolved_categories
    if resolved_enterprise_slug is not None:
        kwargs["enterprise_slug"] = resolved_enterprise_slug

    # --- Step 6: construct and return ---
    try:
        return ScannerConfig(**kwargs)
    except ValidationError as exc:
        # Surface Pydantic errors as ConfigError for uniform handling
        messages = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"Configuration validation failed: {messages}") from exc
