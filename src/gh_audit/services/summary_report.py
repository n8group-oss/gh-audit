"""summary_report — generates an offline, self-contained cross-org summary HTML report.

Design constraints
------------------
- No CDN links, no external asset fetches of any kind.
- Inline CSS only.
- ASCII-friendly output (no raw emoji in text).
- PyInstaller-safe template resolution via ``sys._MEIPASS`` detection.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from gh_audit import branding
from gh_audit.models.multi_org import MultiOrgSummary
from gh_audit.services.reporting import _get_template_dir

_TEMPLATE_NAME = "summary_report.html.j2"


def generate_summary_html(summary: MultiOrgSummary, output_path: Path) -> None:
    """Generate cross-org summary HTML report and write it to *output_path*.

    Parameters
    ----------
    summary:
        Complete multi-org scan summary.
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

    template = env.get_template(_TEMPLATE_NAME)

    # model_dump(mode="json") handles datetime serialisation
    summary_data = summary.model_dump(mode="json")
    totals_data = summary.totals.model_dump(mode="json")

    html = template.render(
        summary=summary_data,
        totals=totals_data,
        branding=branding.get_template_context(),
    )

    output_path.write_text(html, encoding="utf-8")
