"""Output path helpers for gh-audit.

Provides small dataclasses that hold canonical output file paths.

``OutputPaths`` — per-org scan output:

    - ``json``   — machine-readable inventory  (``<slug>-inventory.json``)
    - ``report`` — human-readable HTML report  (``<slug>-report.html``)
    - ``excel``  — Excel workbook              (``<slug>-inventory.xlsx``)

Two construction methods are provided:

    ``OutputPaths.from_json_path(json_path)``
        Derive siblings from an explicit JSON path.  The slug is extracted
        from the JSON filename by stripping the ``-inventory.json`` suffix.

    ``OutputPaths.from_directory(directory, org)``
        Build all three paths under *directory* using *org* as the slug.

Usage::

    paths = OutputPaths.from_directory(pathlib.Path("/tmp/scan"), org="my-org")
    # paths.json   -> /tmp/scan/my-org-inventory.json
    # paths.report -> /tmp/scan/my-org-report.html
    # paths.excel  -> /tmp/scan/my-org-inventory.xlsx

``SummaryPaths`` — cross-org summary output:

    - ``json``   — machine-readable summary  (``<date>-summary.json``)
    - ``report`` — human-readable HTML       (``<date>-summary.html``)

Usage::

    paths = SummaryPaths.from_directory(pathlib.Path("/tmp/scan"))
    # paths.json   -> /tmp/scan/2026-03-27-summary.json
    # paths.report -> /tmp/scan/2026-03-27-summary.html
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass


_JSON_SUFFIX = "-inventory.json"
_REPORT_SUFFIX = "-report.html"
_EXCEL_SUFFIX = "-inventory.xlsx"

_SUMMARY_JSON_SUFFIX = "-summary.json"
_SUMMARY_REPORT_SUFFIX = "-summary.html"


@dataclass(frozen=True)
class OutputPaths:
    """Immutable trio of output file paths for one scan run."""

    json: pathlib.Path
    report: pathlib.Path
    excel: pathlib.Path

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_json_path(cls, json_path: pathlib.Path) -> "OutputPaths":
        """Build sibling paths from an explicit JSON inventory path.

        The slug is extracted by stripping the ``-inventory.json`` suffix from
        the JSON file name.  If the name does not end with that suffix the
        full stem is used as the slug.

        Parameters
        ----------
        json_path:
            Path to the ``.json`` inventory file (need not exist yet).
        """
        name = json_path.name
        if name.endswith(_JSON_SUFFIX):
            slug = name[: -len(_JSON_SUFFIX)]
        else:
            slug = json_path.stem

        directory = json_path.parent
        return cls._from_slug(directory, slug, override_json=json_path)

    @classmethod
    def from_directory(cls, directory: pathlib.Path, *, org: str) -> "OutputPaths":
        """Build all three paths under *directory* using *org* as the slug.

        Parameters
        ----------
        directory:
            Target output directory (need not exist yet).
        org:
            GitHub organization login used as the filename slug.
        """
        return cls._from_slug(directory, org)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @classmethod
    def _from_slug(
        cls,
        directory: pathlib.Path,
        slug: str,
        *,
        override_json: pathlib.Path | None = None,
    ) -> "OutputPaths":
        json_path = (
            override_json if override_json is not None else directory / f"{slug}{_JSON_SUFFIX}"
        )
        report_path = directory / f"{slug}{_REPORT_SUFFIX}"
        excel_path = directory / f"{slug}{_EXCEL_SUFFIX}"
        return cls(json=json_path, report=report_path, excel=excel_path)


@dataclass(frozen=True)
class SummaryPaths:
    """Immutable pair of output file paths for a cross-org summary run."""

    json: pathlib.Path
    report: pathlib.Path

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_directory(cls, directory: pathlib.Path) -> "SummaryPaths":
        """Build both paths under *directory* using today's date as the prefix.

        Parameters
        ----------
        directory:
            Target output directory (need not exist yet).
        """
        from datetime import date

        prefix = date.today().isoformat()
        return cls(
            json=directory / f"{prefix}{_SUMMARY_JSON_SUFFIX}",
            report=directory / f"{prefix}{_SUMMARY_REPORT_SUFFIX}",
        )
