"""Tests for gh_audit.services.workflow_parser — analyze_workflow_yaml()."""

from __future__ import annotations


from gh_audit.services.workflow_parser import WorkflowAnalysis, analyze_workflow_yaml


# ---------------------------------------------------------------------------
# Helper YAML snippets
# ---------------------------------------------------------------------------

SINGLE_ACTION_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

MULTI_ACTION_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - run: npm install
      - uses: actions/checkout@v4
"""

SELF_HOSTED_STRING_YAML = """\
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
"""

SELF_HOSTED_LIST_YAML = """\
jobs:
  build:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4
"""

UBUNTU_ONLY_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

MATRIX_RUNS_ON_YAML = """\
jobs:
  build:
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
"""

MIXED_RUNNERS_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
"""

SCRIPT_STEPS_ONLY_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
      - name: Install
        run: pip install .
"""

NO_STEPS_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
"""

COMPOSITE_ACTION_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: my-org/my-repo/.github/actions/setup@v1
      - uses: actions/checkout@v4
"""

MALFORMED_YAML = """\
jobs:
  build:
    runs-on: [ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

EMPTY_STRING = ""

NONE_LIKE_YAML = "   \n\n   "


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


class TestWorkflowAnalysisDataclass:
    """WorkflowAnalysis is a proper dataclass with the required fields."""

    def test_has_actions_used_field(self):
        analysis = WorkflowAnalysis(actions_used=[], uses_self_hosted_runners=False, warnings=[])
        assert analysis.actions_used == []

    def test_has_uses_self_hosted_runners_field(self):
        analysis = WorkflowAnalysis(actions_used=[], uses_self_hosted_runners=True, warnings=[])
        assert analysis.uses_self_hosted_runners is True

    def test_has_warnings_field(self):
        analysis = WorkflowAnalysis(
            actions_used=[], uses_self_hosted_runners=False, warnings=["oops"]
        )
        assert analysis.warnings == ["oops"]


# ---------------------------------------------------------------------------
# Single action extraction
# ---------------------------------------------------------------------------


class TestSingleActionExtraction:
    """Extract a single uses: step."""

    def test_action_is_in_actions_used(self):
        analysis = analyze_workflow_yaml(SINGLE_ACTION_YAML)
        assert "actions/checkout@v4" in analysis.actions_used

    def test_actions_used_length_is_one(self):
        analysis = analyze_workflow_yaml(SINGLE_ACTION_YAML)
        assert len(analysis.actions_used) == 1

    def test_no_warnings_on_valid_yaml(self):
        analysis = analyze_workflow_yaml(SINGLE_ACTION_YAML)
        assert analysis.warnings == []


# ---------------------------------------------------------------------------
# Multiple actions — deduplicated and sorted
# ---------------------------------------------------------------------------


class TestMultipleActionsDeduplication:
    """Duplicate uses: entries are deduplicated; result is sorted."""

    def test_duplicates_removed(self):
        analysis = analyze_workflow_yaml(MULTI_ACTION_YAML)
        # actions/checkout@v4 appears twice — should appear once
        assert analysis.actions_used.count("actions/checkout@v4") == 1

    def test_result_is_sorted(self):
        analysis = analyze_workflow_yaml(MULTI_ACTION_YAML)
        assert analysis.actions_used == sorted(analysis.actions_used)

    def test_correct_unique_actions(self):
        analysis = analyze_workflow_yaml(MULTI_ACTION_YAML)
        assert set(analysis.actions_used) == {
            "actions/checkout@v4",
            "actions/setup-node@v3",
        }


# ---------------------------------------------------------------------------
# Self-hosted runner detection
# ---------------------------------------------------------------------------


class TestSelfHostedStringRunsOn:
    """String value 'self-hosted' triggers uses_self_hosted_runners=True."""

    def test_self_hosted_string_detected(self):
        analysis = analyze_workflow_yaml(SELF_HOSTED_STRING_YAML)
        assert analysis.uses_self_hosted_runners is True


class TestSelfHostedListRunsOn:
    """List containing 'self-hosted' triggers uses_self_hosted_runners=True."""

    def test_self_hosted_in_list_detected(self):
        analysis = analyze_workflow_yaml(SELF_HOSTED_LIST_YAML)
        assert analysis.uses_self_hosted_runners is True


class TestUbuntuOnlyRunsOn:
    """ubuntu-latest does not trigger uses_self_hosted_runners."""

    def test_ubuntu_latest_is_not_self_hosted(self):
        analysis = analyze_workflow_yaml(UBUNTU_ONLY_YAML)
        assert analysis.uses_self_hosted_runners is False


class TestMatrixExpressionRunsOn:
    """Matrix expressions (${{ ... }}) are skipped — no false positive."""

    def test_matrix_expression_does_not_set_self_hosted(self):
        analysis = analyze_workflow_yaml(MATRIX_RUNS_ON_YAML)
        assert analysis.uses_self_hosted_runners is False

    def test_matrix_expression_does_not_produce_warning(self):
        analysis = analyze_workflow_yaml(MATRIX_RUNS_ON_YAML)
        assert analysis.warnings == []


class TestMixedRunners:
    """Multiple jobs — any self-hosted job sets uses_self_hosted_runners=True."""

    def test_self_hosted_in_one_job_sets_flag(self):
        analysis = analyze_workflow_yaml(MIXED_RUNNERS_YAML)
        assert analysis.uses_self_hosted_runners is True

    def test_actions_from_both_jobs_extracted(self):
        analysis = analyze_workflow_yaml(MIXED_RUNNERS_YAML)
        assert set(analysis.actions_used) == {
            "actions/checkout@v4",
            "actions/setup-python@v5",
        }


# ---------------------------------------------------------------------------
# Script steps — not included in actions_used
# ---------------------------------------------------------------------------


class TestScriptStepsExcluded:
    """run: steps must not appear in actions_used."""

    def test_script_steps_not_in_actions_used(self):
        analysis = analyze_workflow_yaml(SCRIPT_STEPS_ONLY_YAML)
        assert analysis.actions_used == []

    def test_no_false_self_hosted(self):
        analysis = analyze_workflow_yaml(SCRIPT_STEPS_ONLY_YAML)
        assert analysis.uses_self_hosted_runners is False


# ---------------------------------------------------------------------------
# No steps key
# ---------------------------------------------------------------------------


class TestNoStepsKey:
    """Jobs without a steps key return empty actions_used."""

    def test_no_steps_returns_empty_actions(self):
        analysis = analyze_workflow_yaml(NO_STEPS_YAML)
        assert analysis.actions_used == []

    def test_no_steps_no_warnings(self):
        analysis = analyze_workflow_yaml(NO_STEPS_YAML)
        assert analysis.warnings == []


# ---------------------------------------------------------------------------
# Composite action references
# ---------------------------------------------------------------------------


class TestCompositeActionReferences:
    """org/repo/path@ref composite action references are extracted correctly."""

    def test_composite_action_extracted(self):
        analysis = analyze_workflow_yaml(COMPOSITE_ACTION_YAML)
        assert "my-org/my-repo/.github/actions/setup@v1" in analysis.actions_used

    def test_composite_and_standard_sorted(self):
        analysis = analyze_workflow_yaml(COMPOSITE_ACTION_YAML)
        assert analysis.actions_used == sorted(analysis.actions_used)


# ---------------------------------------------------------------------------
# Malformed YAML
# ---------------------------------------------------------------------------


class TestMalformedYaml:
    """Malformed YAML returns empty analysis with a warning — never raises."""

    def test_does_not_raise(self):
        result = analyze_workflow_yaml(MALFORMED_YAML)
        assert isinstance(result, WorkflowAnalysis)

    def test_actions_used_is_empty(self):
        result = analyze_workflow_yaml(MALFORMED_YAML)
        assert result.actions_used == []

    def test_uses_self_hosted_runners_is_false(self):
        result = analyze_workflow_yaml(MALFORMED_YAML)
        assert result.uses_self_hosted_runners is False

    def test_warning_is_present(self):
        result = analyze_workflow_yaml(MALFORMED_YAML)
        assert len(result.warnings) >= 1

    def test_warning_mentions_parse_error(self):
        result = analyze_workflow_yaml(MALFORMED_YAML)
        assert any("parse" in w.lower() or "yaml" in w.lower() for w in result.warnings)


# ---------------------------------------------------------------------------
# Empty / whitespace-only content
# ---------------------------------------------------------------------------


class TestEmptyContent:
    """Empty string returns an empty WorkflowAnalysis with no warnings."""

    def test_empty_string_does_not_raise(self):
        result = analyze_workflow_yaml(EMPTY_STRING)
        assert isinstance(result, WorkflowAnalysis)

    def test_empty_string_actions_is_empty(self):
        result = analyze_workflow_yaml(EMPTY_STRING)
        assert result.actions_used == []

    def test_empty_string_self_hosted_is_false(self):
        result = analyze_workflow_yaml(EMPTY_STRING)
        assert result.uses_self_hosted_runners is False

    def test_empty_string_no_warnings(self):
        result = analyze_workflow_yaml(EMPTY_STRING)
        assert result.warnings == []

    def test_whitespace_only_no_raise(self):
        result = analyze_workflow_yaml(NONE_LIKE_YAML)
        assert isinstance(result, WorkflowAnalysis)

    def test_whitespace_only_actions_is_empty(self):
        result = analyze_workflow_yaml(NONE_LIKE_YAML)
        assert result.actions_used == []

    def test_whitespace_only_no_warnings(self):
        result = analyze_workflow_yaml(NONE_LIKE_YAML)
        assert result.warnings == []


# ---------------------------------------------------------------------------
# Task description acceptance criteria (verbatim)
# ---------------------------------------------------------------------------


class TestAcceptanceCriteria:
    """Verbatim acceptance criteria from the task description."""

    def test_acceptance_criteria_example(self):
        yaml_content = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: self-hosted\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        analysis = analyze_workflow_yaml(yaml_content)
        assert analysis.actions_used == ["actions/checkout@v4"]
        assert analysis.uses_self_hosted_runners is True
