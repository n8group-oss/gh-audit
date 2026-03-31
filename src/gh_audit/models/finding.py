"""Assessment finding models -- severity, pillar, scope, and finding detail.

Used by the assessment engine to represent best-practice rule violations.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity level."""

    critical = "critical"
    warning = "warning"
    info = "info"


class Pillar(str, Enum):
    """Well-Architected pillar that a finding belongs to."""

    security = "security"
    governance = "governance"
    operations = "operations"
    adoption = "adoption"
    enterprise = "enterprise"


class Scope(str, Enum):
    """Whether a finding applies to the whole org or a specific repo."""

    org = "org"
    repo = "repo"


class Finding(BaseModel):
    """A single assessment finding (rule violation or recommendation)."""

    model_config = {"extra": "forbid"}

    rule_id: str
    """Rule identifier, e.g. ``SEC-001``."""

    pillar: Pillar
    severity: Severity
    scope: Scope

    repo_name: str | None = None
    """Repository name for repo-scoped findings; None for org-level."""

    title: str
    """Short human-readable summary of the finding."""

    detail: str
    """Specific details (counts, names, context)."""

    remediation: str
    """Actionable guidance on how to fix the finding."""


class AssessmentResult(BaseModel):
    """Complete output of an assessment run."""

    model_config = {"extra": "forbid"}

    organization: str
    generated_at: datetime
    inventory_generated_at: datetime
    scan_profile: str
    active_categories: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
