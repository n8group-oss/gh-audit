"""Tests for gh_audit.models.repository — RepositoryInventoryItem and sub-models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gh_audit.models.repository import (
    BranchProtectionSummary,
    LargeFileInfo,
    LargeFileScan,
    LFSInfo,
    RepositoryInventoryItem,
)
from gh_audit.models.actions import ActionsInfo
from gh_audit.models.security import SecurityInfo


# ---------------------------------------------------------------------------
# LargeFileScan defaults
# ---------------------------------------------------------------------------


class TestLargeFileScanDefaults:
    """Default values for LargeFileScan match the spec."""

    def test_enabled_default_is_false(self):
        scan = LargeFileScan()
        assert scan.enabled is False

    def test_completed_default_is_false(self):
        scan = LargeFileScan()
        assert scan.completed is False

    def test_truncated_default_is_false(self):
        scan = LargeFileScan()
        assert scan.truncated is False

    def test_threshold_bytes_default(self):
        scan = LargeFileScan()
        assert scan.threshold_bytes == 104857600  # 100 MB

    def test_files_default_is_empty_list(self):
        scan = LargeFileScan()
        assert scan.files == []

    def test_files_are_not_shared_between_instances(self):
        """Mutable default must use default_factory, not a shared list."""
        a = LargeFileScan()
        b = LargeFileScan()
        a.files.append(LargeFileInfo(path="x", size_bytes=1))
        assert b.files == []


class TestLargeFileScanSemantics:
    """Enabled/completed/truncated semantics."""

    def test_not_enabled_means_not_run(self):
        scan = LargeFileScan()
        assert scan.enabled is False
        assert scan.completed is False

    def test_enabled_but_not_completed(self):
        scan = LargeFileScan(enabled=True)
        assert scan.enabled is True
        assert scan.completed is False

    def test_enabled_completed_not_truncated(self):
        scan = LargeFileScan(enabled=True, completed=True)
        assert scan.completed is True
        assert scan.truncated is False

    def test_enabled_completed_truncated(self):
        scan = LargeFileScan(enabled=True, completed=True, truncated=True)
        assert scan.truncated is True

    def test_with_files(self):
        scan = LargeFileScan(
            enabled=True,
            completed=True,
            files=[
                LargeFileInfo(path="data/large.bin", size_bytes=200_000_000),
                LargeFileInfo(path="media/video.mp4", size_bytes=150_000_000),
            ],
        )
        assert len(scan.files) == 2
        assert scan.files[0].path == "data/large.bin"
        assert scan.files[1].size_bytes == 150_000_000


class TestLargeFileScanExtraForbidden:
    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            LargeFileScan(unexpected=True)


# ---------------------------------------------------------------------------
# LargeFileInfo
# ---------------------------------------------------------------------------


class TestLargeFileInfo:
    def test_basic_construction(self):
        info = LargeFileInfo(path="blob/big.tar.gz", size_bytes=500_000_000)
        assert info.path == "blob/big.tar.gz"
        assert info.size_bytes == 500_000_000

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            LargeFileInfo(path="x", size_bytes=1, extra="nope")


# ---------------------------------------------------------------------------
# LFSInfo
# ---------------------------------------------------------------------------


class TestLFSInfoDefaults:
    def test_has_lfs_default_false(self):
        lfs = LFSInfo()
        assert lfs.has_lfs is False

    def test_patterns_default_empty_list(self):
        lfs = LFSInfo()
        assert lfs.patterns == []

    def test_patterns_not_shared(self):
        a = LFSInfo()
        b = LFSInfo()
        a.patterns.append("*.psd")
        assert b.patterns == []

    def test_with_patterns(self):
        lfs = LFSInfo(has_lfs=True, patterns=["*.psd", "*.mp4"])
        assert lfs.has_lfs is True
        assert lfs.patterns == ["*.psd", "*.mp4"]

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            LFSInfo(unknown=True)


# ---------------------------------------------------------------------------
# BranchProtectionSummary
# ---------------------------------------------------------------------------


class TestBranchProtectionSummaryDefaults:
    def test_protected_branches_default_zero(self):
        bps = BranchProtectionSummary()
        assert bps.protected_branches == 0

    def test_ruleset_count_default_none(self):
        """None = not checked / forbidden (not the same as 0 rulesets)."""
        bps = BranchProtectionSummary()
        assert bps.ruleset_count is None

    def test_ruleset_count_zero_is_distinct_from_none(self):
        bps = BranchProtectionSummary(ruleset_count=0)
        assert bps.ruleset_count == 0

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            BranchProtectionSummary(oops=1)


# ---------------------------------------------------------------------------
# RepositoryInventoryItem defaults
# ---------------------------------------------------------------------------


class TestRepositoryInventoryItemDefaults:
    """Minimal construction and default values."""

    def _minimal(self) -> RepositoryInventoryItem:
        return RepositoryInventoryItem(
            name="my-repo",
            full_name="my-org/my-repo",
            visibility="private",
        )

    def test_minimal_construction(self):
        repo = self._minimal()
        assert repo.name == "my-repo"
        assert repo.full_name == "my-org/my-repo"
        assert repo.visibility == "private"

    def test_description_default_none(self):
        repo = self._minimal()
        assert repo.description is None

    def test_archived_default_false(self):
        repo = self._minimal()
        assert repo.archived is False

    def test_fork_default_false(self):
        repo = self._minimal()
        assert repo.fork is False

    def test_is_template_default_false(self):
        repo = self._minimal()
        assert repo.is_template is False

    def test_language_default_none(self):
        repo = self._minimal()
        assert repo.language is None

    def test_topics_default_empty_list(self):
        repo = self._minimal()
        assert repo.topics == []

    def test_default_branch_default_none(self):
        repo = self._minimal()
        assert repo.default_branch is None

    def test_size_bytes_default_zero(self):
        repo = self._minimal()
        assert repo.size_bytes == 0

    def test_branch_count_default_zero(self):
        repo = self._minimal()
        assert repo.branch_count == 0

    def test_pr_counts_default_zero(self):
        repo = self._minimal()
        assert repo.pr_count_open == 0
        assert repo.pr_count_closed == 0
        assert repo.pr_count_merged == 0

    def test_issue_counts_default_zero(self):
        repo = self._minimal()
        assert repo.issue_count_open == 0
        assert repo.issue_count_closed == 0

    def test_issue_label_distribution_default_empty_dict(self):
        repo = self._minimal()
        assert repo.issue_label_distribution == {}

    def test_warnings_default_empty_list(self):
        repo = self._minimal()
        assert repo.warnings == []

    def test_large_file_scan_default(self):
        repo = self._minimal()
        assert isinstance(repo.large_file_scan, LargeFileScan)
        assert repo.large_file_scan.completed is False
        assert repo.large_file_scan.truncated is False
        assert repo.large_file_scan.files == []

    def test_lfs_info_default(self):
        repo = self._minimal()
        assert isinstance(repo.lfs_info, LFSInfo)
        assert repo.lfs_info.has_lfs is False

    def test_actions_default(self):
        repo = self._minimal()
        assert isinstance(repo.actions, ActionsInfo)
        assert repo.actions.has_workflows is False

    def test_security_default(self):
        repo = self._minimal()
        assert isinstance(repo.security, SecurityInfo)
        assert repo.security.dependabot_alerts_open is None
        assert repo.security.counts_exact is False
        assert repo.security.alerts_accessible is False

    def test_branch_protection_default(self):
        repo = self._minimal()
        assert isinstance(repo.branch_protection, BranchProtectionSummary)
        assert repo.branch_protection.protected_branches == 0


# ---------------------------------------------------------------------------
# Mutable defaults not shared
# ---------------------------------------------------------------------------


class TestRepositoryInventoryItemMutableDefaults:
    def _minimal(self, **kw) -> RepositoryInventoryItem:
        return RepositoryInventoryItem(
            name="repo", full_name="org/repo", visibility="private", **kw
        )

    def test_topics_not_shared(self):
        a = self._minimal()
        b = self._minimal()
        a.topics.append("python")
        assert b.topics == []

    def test_warnings_not_shared(self):
        a = self._minimal()
        b = self._minimal()
        a.warnings.append("some warning")
        assert b.warnings == []

    def test_label_distribution_not_shared(self):
        a = self._minimal()
        b = self._minimal()
        a.issue_label_distribution["bug"] = 3
        assert b.issue_label_distribution == {}


# ---------------------------------------------------------------------------
# Extra fields forbidden
# ---------------------------------------------------------------------------


class TestRepositoryInventoryItemExtraForbidden:
    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError):
            RepositoryInventoryItem(
                name="repo",
                full_name="org/repo",
                visibility="public",
                mystery_field="oops",
            )


# ---------------------------------------------------------------------------
# JSON serialization roundtrip
# ---------------------------------------------------------------------------


class TestRepositoryInventoryItemSerialization:
    def test_roundtrip_minimal(self):
        original = RepositoryInventoryItem(name="repo", full_name="org/repo", visibility="private")
        restored = RepositoryInventoryItem.model_validate_json(original.model_dump_json())
        assert restored == original

    def test_roundtrip_with_all_fields(self):
        original = RepositoryInventoryItem(
            name="big-repo",
            full_name="org/big-repo",
            visibility="public",
            description="A big repository",
            archived=True,
            fork=False,
            is_template=False,
            language="Python",
            topics=["ml", "data"],
            default_branch="main",
            size_bytes=123456,
            branch_count=10,
            pr_count_open=2,
            pr_count_closed=50,
            pr_count_merged=100,
            issue_count_open=5,
            issue_count_closed=200,
            issue_label_distribution={"bug": 3, "feature": 7},
            large_file_scan=LargeFileScan(
                enabled=True,
                completed=True,
                files=[LargeFileInfo(path="data.bin", size_bytes=200_000_000)],
            ),
            lfs_info=LFSInfo(has_lfs=True, patterns=["*.psd"]),
            security=SecurityInfo(
                dependabot_enabled=True,
                alerts_accessible=True,
                counts_exact=True,
                dependabot_alerts_open=2,
                code_scanning_alerts_open=0,
                secret_scanning_alerts_open=None,
            ),
            branch_protection=BranchProtectionSummary(protected_branches=2, ruleset_count=1),
            warnings=["rate_limited"],
        )
        restored = RepositoryInventoryItem.model_validate_json(original.model_dump_json())
        assert restored == original
        assert restored.security.dependabot_alerts_open == 2
        assert restored.security.code_scanning_alerts_open == 0
        assert restored.security.secret_scanning_alerts_open is None
        assert restored.large_file_scan.files[0].path == "data.bin"
