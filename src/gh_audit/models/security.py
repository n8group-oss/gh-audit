"""SecurityInfo — per-repository security feature state and alert counts.

Design rule: ``None`` means "not scanned or not accessible".
             ``0``    means "known to be zero".
Never silently convert unknown to zero.
"""

from __future__ import annotations

from pydantic import BaseModel


class SecurityInfo(BaseModel):
    """Security feature enablement and alert counts for one repository."""

    model_config = {"extra": "forbid"}

    # ------------------------------------------------------------------
    # Feature enablement — None = unknown (not checked / not accessible)
    # ------------------------------------------------------------------

    dependabot_enabled: bool | None = None
    """Whether Dependabot alerts are enabled.  None = unknown."""

    code_scanning_enabled: bool | None = None
    """Whether code scanning is enabled.  None = unknown."""

    secret_scanning_enabled: bool | None = None
    """Whether secret scanning is enabled.  None = unknown."""

    # ------------------------------------------------------------------
    # Alert-endpoint accessibility
    # ------------------------------------------------------------------

    alerts_accessible: bool = False
    """Were the alert API endpoints reachable with the supplied credentials?"""

    counts_exact: bool = False
    """Are the alert counts below from actual API pagination (not estimates)?"""

    # ------------------------------------------------------------------
    # Alert counts — None = not counted / not accessible; 0 = known zero
    # ------------------------------------------------------------------

    dependabot_alerts_open: int | None = None
    """Open Dependabot alerts.  None = not counted."""

    code_scanning_alerts_open: int | None = None
    """Open code-scanning alerts.  None = not counted."""

    secret_scanning_alerts_open: int | None = None
    """Open secret-scanning alerts.  None = not counted."""
