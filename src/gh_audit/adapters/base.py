"""Base types shared across GitHub API adapters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AlertCountResult:
    """Result for optional security-alert count endpoints.

    Parameters
    ----------
    count:
        Number of alerts, or None if the endpoint was inaccessible.
    accessible:
        Whether the endpoint was reachable (True = count is valid, False = forbidden/unavailable).
    """

    count: int | None
    accessible: bool

    @classmethod
    def inaccessible(cls) -> "AlertCountResult":
        """Return a result indicating the endpoint could not be reached."""
        return cls(count=None, accessible=False)

    @classmethod
    def from_count(cls, count: int) -> "AlertCountResult":
        """Return a result with a valid count."""
        return cls(count=count, accessible=True)
