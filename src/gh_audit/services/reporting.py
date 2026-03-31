"""ReportService — generates an offline, self-contained HTML discovery report.

Design constraints
------------------
- No CDN links, no external asset fetches of any kind.
- Pure CSS for layout/charts; SVG doughnuts via ``stroke-dasharray``.
- Inline CSS + minimal inline JS (table sort only).
- PyInstaller-safe template resolution via ``sys._MEIPASS`` detection.
- Security alert counts rendered carefully:
  - ``0``   only when ``counts_exact is True`` and count == 0
  - ``n/a`` when count is ``None`` (not scanned / inaccessible)
"""

from __future__ import annotations

import sys
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from gh_audit import branding
from gh_audit.models.inventory import Inventory


def _get_template_dir() -> Path:
    """Return the templates directory, compatible with both normal and PyInstaller runs."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # PyInstaller one-file bundle: templates are unpacked to _MEIPASS
        return Path(getattr(sys, "_MEIPASS")) / "gh_audit" / "templates"
    # Normal Python environment: use importlib.resources
    return Path(str(files("gh_audit") / "templates"))


class ReportService:
    """Generate an offline, self-contained HTML discovery report from an Inventory."""

    _TEMPLATE_NAME = "discovery_report.html.j2"

    def generate(self, inventory: Inventory, output_path: Path) -> None:
        """Render the HTML report and write it to *output_path*.

        Parameters
        ----------
        inventory:
            Complete scan inventory.
        output_path:
            Destination file path.  Parent directories are created as needed.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        template_dir = _get_template_dir()
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "j2"]),
            keep_trailing_newline=True,
        )

        template = env.get_template(self._TEMPLATE_NAME)

        # model_dump(mode="json") handles SecretStr and datetime serialisation
        data = inventory.model_dump(mode="json")

        # Compute security detail aggregates for the template
        has_security_detail = any(
            r.get("security_detail") is not None for r in data["repositories"]
        )

        html = template.render(
            metadata=data["metadata"],
            summary=data["summary"],
            repositories=data["repositories"],
            users=data["users"],
            packages=data["packages"],
            projects=data["projects"],
            governance=data.get("governance"),
            operations=data.get("operations"),
            has_security_detail=has_security_detail,
            adoption=data.get("adoption"),
            enterprise=data.get("enterprise"),
            branding=branding.get_template_context(),
        )

        output_path.write_text(html, encoding="utf-8")
