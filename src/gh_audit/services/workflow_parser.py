"""Workflow YAML parser for deep GitHub Actions analysis.

Provides :func:`analyze_workflow_yaml` which inspects a workflow file's content
and returns a :class:`WorkflowAnalysis` describing which actions are used and
whether self-hosted runners are referenced.

Design goals:
- Never raises — always returns a :class:`WorkflowAnalysis`.
- Tolerant of malformed or empty input; issues are recorded as warnings.
- Actions list is deduplicated and sorted for deterministic output.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class WorkflowAnalysis:
    """Result of parsing a single GitHub Actions workflow file.

    Attributes:
        actions_used: Sorted, deduplicated list of ``uses:`` action references
            found across all job steps (e.g. ``"actions/checkout@v4"``).
        uses_self_hosted_runners: ``True`` if at least one job's ``runs-on``
            is or contains the string ``"self-hosted"``.  Matrix expressions
            (``${{ … }}``) are skipped conservatively (``False``).
        warnings: Human-readable messages describing any parse issues or
            non-fatal anomalies encountered while analysing the content.
    """

    actions_used: list[str] = field(default_factory=list)
    uses_self_hosted_runners: bool = False
    warnings: list[str] = field(default_factory=list)


def _empty() -> WorkflowAnalysis:
    """Return a blank :class:`WorkflowAnalysis` with no data."""
    return WorkflowAnalysis(actions_used=[], uses_self_hosted_runners=False, warnings=[])


def _is_self_hosted(runs_on: object) -> bool:
    """Return True if *runs_on* references a self-hosted runner.

    Skips matrix-expression strings (``${{ … }}``) conservatively.
    """
    if isinstance(runs_on, str):
        if "${{" in runs_on:
            # Dynamic expression — cannot determine at parse time.
            return False
        return runs_on.strip() == "self-hosted"
    if isinstance(runs_on, list):
        return any(isinstance(item, str) and item.strip() == "self-hosted" for item in runs_on)
    return False


def analyze_workflow_yaml(content: str) -> WorkflowAnalysis:
    """Parse *content* as a GitHub Actions workflow YAML and extract metadata.

    Args:
        content: Raw text of a ``.github/workflows/*.yml`` file.

    Returns:
        A :class:`WorkflowAnalysis` describing the workflow.  Never raises.
    """
    # --- guard: empty / whitespace-only content ---
    if not content or not content.strip():
        return _empty()

    # --- parse YAML ---
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return WorkflowAnalysis(
            actions_used=[],
            uses_self_hosted_runners=False,
            warnings=[f"YAML parse error: {exc}"],
        )

    # safe_load on non-mapping content (e.g. plain string) returns non-dict
    if not isinstance(data, dict):
        return _empty()

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return _empty()

    actions: set[str] = set()
    self_hosted = False

    for _job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # --- runs-on detection ---
        runs_on = job.get("runs-on")
        if runs_on is not None and _is_self_hosted(runs_on):
            self_hosted = True

        # --- step action extraction ---
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str) and uses.strip():
                actions.add(uses.strip())

    return WorkflowAnalysis(
        actions_used=sorted(actions),
        uses_self_hosted_runners=self_hosted,
        warnings=[],
    )
