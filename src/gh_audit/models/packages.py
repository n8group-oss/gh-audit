"""PackageInfo — GitHub Packages registry entry."""

from __future__ import annotations

from pydantic import BaseModel


class PackageInfo(BaseModel):
    """A single package published to GitHub Packages."""

    model_config = {"extra": "forbid"}

    name: str
    """Package name."""

    package_type: str
    """Registry type: ``npm``, ``pypi``, ``maven``, ``rubygems``, ``docker``, ``nuget``, etc."""

    visibility: str = "private"
    """Package visibility: ``public`` or ``private``."""
