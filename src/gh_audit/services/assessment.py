"""AssessmentService — generates a standalone HTML assessment report."""

from __future__ import annotations

import sys
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from gh_audit import branding
from gh_audit.models.finding import AssessmentResult, Pillar, Severity


def _get_template_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")) / "gh_audit" / "templates"
    return Path(str(files("gh_audit") / "templates"))


class AssessmentService:
    _TEMPLATE_NAME = "assessment_report.html.j2"

    def generate(self, result: AssessmentResult, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        template_dir = _get_template_dir()
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "j2"]),
            keep_trailing_newline=True,
        )
        template = env.get_template(self._TEMPLATE_NAME)

        findings = result.findings
        count_critical = sum(1 for f in findings if f.severity == Severity.critical)
        count_warning = sum(1 for f in findings if f.severity == Severity.warning)
        count_info = sum(1 for f in findings if f.severity == Severity.info)

        pillar_counts: dict[str, dict[str, int]] = {}
        for pillar in Pillar:
            pf = [f for f in findings if f.pillar == pillar]
            if pf:
                pillar_counts[pillar.value] = {
                    "critical": sum(1 for f in pf if f.severity == Severity.critical),
                    "warning": sum(1 for f in pf if f.severity == Severity.warning),
                    "info": sum(1 for f in pf if f.severity == Severity.info),
                    "total": len(pf),
                }

        # Determine which pillars could be assessed based on active categories.
        # Pillar → required category mapping:
        #   security: partially always available (SEC-004/005/006), fully needs "security"
        #   governance: partially always available (GOV-001), fully needs "governance"
        #   operations: needs "operations"
        #   adoption: needs "adoption"
        #   enterprise: needs "enterprise"
        cats = set(result.active_categories)
        assessed_pillars: set[str] = set()
        # Security and governance pillars have rules that always run (base data),
        # so they are always at least partially assessed.
        assessed_pillars.add("security")
        assessed_pillars.add("governance")
        if "operations" in cats:
            assessed_pillars.add("operations")
        if "adoption" in cats:
            assessed_pillars.add("adoption")
        if "enterprise" in cats:
            assessed_pillars.add("enterprise")

        all_pillar_names = [p.value for p in Pillar]
        unassessed_pillars = [p for p in all_pillar_names if p not in assessed_pillars]

        data = result.model_dump(mode="json")
        html = template.render(
            organization=result.organization,
            generated_at=data["generated_at"],
            inventory_generated_at=data["inventory_generated_at"],
            scan_profile=result.scan_profile,
            active_categories=result.active_categories,
            findings=data["findings"],
            count_critical=count_critical,
            count_warning=count_warning,
            count_info=count_info,
            count_total=len(findings),
            pillar_counts=pillar_counts,
            unassessed_pillars=unassessed_pillars,
            branding=branding.get_template_context(),
        )
        output_path.write_text(html, encoding="utf-8")
