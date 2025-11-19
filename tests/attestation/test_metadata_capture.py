"""
Tests for scan metadata capture.

Tests metadata capture from three sources:
1. Scan arguments (from_scan_args)
2. Git context (capture_git_context)
3. CI environment (capture_ci_metadata)
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess
from scripts.core.attestation.metadata_capture import MetadataCapture


class TestFromScanArgs:
    """Tests for from_scan_args method."""

    def test_capture_all_standard_args(self):
        """Test capturing all standard scan arguments."""
        capture = MetadataCapture()

        metadata = capture.from_scan_args(
            profile="balanced",
            tools=["trivy", "semgrep"],
            repos=["repo1", "repo2"],
            images=["nginx:latest"],
            urls=["https://example.com"],
            threads=4,
            timeout=600,
        )

        assert metadata["profile"] == "balanced"
        assert metadata["profile_name"] == "balanced"  # Duplicate for compatibility
        assert metadata["tools"] == ["trivy", "semgrep"]
        assert metadata["repos"] == ["repo1", "repo2"]
        assert metadata["images"] == ["nginx:latest"]
        assert metadata["urls"] == ["https://example.com"]
        assert metadata["threads"] == 4
        assert metadata["timeout"] == 600

    def test_capture_minimal_args(self):
        """Test capturing with no arguments (all None)."""
        capture = MetadataCapture()

        metadata = capture.from_scan_args()

        assert metadata == {}

    def test_capture_only_profile(self):
        """Test capturing only profile argument."""
        capture = MetadataCapture()

        metadata = capture.from_scan_args(profile="fast")

        assert metadata == {"profile": "fast", "profile_name": "fast"}

    def test_capture_only_tools(self):
        """Test capturing only tools argument."""
        capture = MetadataCapture()

        metadata = capture.from_scan_args(tools=["trivy"])

        assert metadata == {"tools": ["trivy"]}

    def test_capture_with_kwargs(self):
        """Test capturing additional kwargs."""
        capture = MetadataCapture()

        metadata = capture.from_scan_args(
            profile="balanced",
            custom_field="value",
            another_field=123,
        )

        assert metadata["profile"] == "balanced"
        assert metadata["custom_field"] == "value"
        assert metadata["another_field"] == 123

    def test_capture_empty_lists(self):
        """Test capturing empty lists."""
        capture = MetadataCapture()

        metadata = capture.from_scan_args(
            tools=[],
            repos=[],
        )

        assert metadata["tools"] == []
        assert metadata["repos"] == []


class TestCaptureGitContext:
    """Tests for capture_git_context method."""

    @patch("subprocess.run")
    def test_capture_commit(self, mock_run):
        """Test capturing git commit SHA."""
        capture = MetadataCapture()

        # Mock git commands - only commit succeeds
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "rev-parse" in cmd and "HEAD" in cmd and "--abbrev-ref" not in cmd:
                return MagicMock(returncode=0, stdout="abc123def456\n")
            else:
                return MagicMock(returncode=1, stdout="")

        mock_run.side_effect = side_effect

        context = capture.capture_git_context("/repo/path")

        assert context["commit"] == "abc123def456"

    @patch("subprocess.run")
    def test_capture_branch(self, mock_run):
        """Test capturing git branch name."""
        capture = MetadataCapture()

        # Mock git commands
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "rev-parse" in cmd and "HEAD" in cmd and "--abbrev-ref" not in cmd:
                return MagicMock(returncode=0, stdout="abc123\n")
            elif "rev-parse" in cmd and "--abbrev-ref" in cmd:
                return MagicMock(returncode=0, stdout="main\n")
            else:
                return MagicMock(returncode=1, stdout="")

        mock_run.side_effect = side_effect

        context = capture.capture_git_context("/repo/path")

        assert context["branch"] == "main"

    @patch("subprocess.run")
    def test_capture_tag(self, mock_run):
        """Test capturing git tag (if on exact tag)."""
        capture = MetadataCapture()

        # Mock git commands
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "describe" in cmd and "--tags" in cmd:
                return MagicMock(returncode=0, stdout="v1.0.0\n")
            else:
                return MagicMock(returncode=0, stdout="dummy\n")

        mock_run.side_effect = side_effect

        context = capture.capture_git_context("/repo/path")

        assert context["tag"] == "v1.0.0"

    @patch("subprocess.run")
    def test_capture_all_git_info(self, mock_run):
        """Test capturing commit, branch, and tag together."""
        capture = MetadataCapture()

        # Mock git commands
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "rev-parse" in cmd and "HEAD" in cmd and "--abbrev-ref" not in cmd:
                return MagicMock(returncode=0, stdout="abc123\n")
            elif "rev-parse" in cmd and "--abbrev-ref" in cmd:
                return MagicMock(returncode=0, stdout="main\n")
            elif "describe" in cmd:
                return MagicMock(returncode=0, stdout="v1.0.0\n")
            else:
                return MagicMock(returncode=1, stdout="")

        mock_run.side_effect = side_effect

        context = capture.capture_git_context("/repo/path")

        assert context["commit"] == "abc123"
        assert context["branch"] == "main"
        assert context["tag"] == "v1.0.0"

    @patch("subprocess.run")
    def test_capture_no_tag(self, mock_run):
        """Test capturing when not on a tag."""
        capture = MetadataCapture()

        # Mock git commands - tag command fails
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "describe" in cmd:
                return MagicMock(returncode=1, stdout="")
            else:
                return MagicMock(returncode=0, stdout="dummy\n")

        mock_run.side_effect = side_effect

        context = capture.capture_git_context("/repo/path")

        assert "tag" not in context

    @patch("subprocess.run")
    def test_capture_git_failure(self, mock_run):
        """Test handling git command failure."""
        capture = MetadataCapture()

        # All git commands fail
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        context = capture.capture_git_context("/repo/path")

        assert context == {}

    @patch("subprocess.run")
    def test_capture_git_timeout(self, mock_run):
        """Test handling git command timeout."""
        capture = MetadataCapture()

        # Git command times out
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=5)

        context = capture.capture_git_context("/repo/path")

        assert context == {}

    @patch("subprocess.run")
    def test_capture_git_exception(self, mock_run):
        """Test handling general git exception."""
        capture = MetadataCapture()

        # Git command raises exception
        mock_run.side_effect = Exception("Git not found")

        context = capture.capture_git_context("/repo/path")

        assert context == {}


class TestCaptureCIMetadata:
    """Tests for capture_ci_metadata method."""

    @patch.dict(
        "os.environ",
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "jimmy058910/jmo-security-repo",
            "GITHUB_SHA": "abc123def456",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW": "CI",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_NUMBER": "67",
        },
    )
    def test_capture_github_actions_metadata(self):
        """Test capturing GitHub Actions CI metadata."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata["ci_provider"] == "github"
        assert metadata["repository"] == "jimmy058910/jmo-security-repo"
        assert metadata["commit"] == "abc123def456"
        assert metadata["ref"] == "refs/heads/main"
        assert metadata["workflow"] == "CI"
        assert metadata["run_id"] == "12345"
        assert metadata["run_number"] == "67"

    @patch.dict(
        "os.environ",
        {
            "GITLAB_CI": "true",
            "CI_PROJECT_PATH": "mygroup/myproject",
            "CI_COMMIT_SHA": "xyz789abc012",
            "CI_COMMIT_REF_NAME": "develop",
            "CI_PIPELINE_ID": "98765",
            "CI_PIPELINE_URL": "https://gitlab.com/pipeline/98765",
            "CI_JOB_ID": "54321",
            "CI_JOB_NAME": "test",
        },
    )
    def test_capture_gitlab_ci_metadata(self):
        """Test capturing GitLab CI metadata."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata["ci_provider"] == "gitlab"
        assert metadata["repository"] == "mygroup/myproject"
        assert metadata["commit"] == "xyz789abc012"
        assert metadata["ref"] == "develop"
        assert metadata["pipeline_id"] == "98765"
        assert metadata["pipeline_url"] == "https://gitlab.com/pipeline/98765"
        assert metadata["job_id"] == "54321"
        assert metadata["job_name"] == "test"

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_capture_generic_ci_metadata(self):
        """Test capturing generic CI metadata (CI=true only)."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata["ci_provider"] == "generic"
        assert len(metadata) == 1  # Only provider field

    @patch.dict("os.environ", {}, clear=True)
    def test_capture_local_no_metadata(self):
        """Test capturing when not in CI (local)."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata == {}

    @patch.dict(
        "os.environ",
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "test/repo",
            # Missing other GitHub fields
        },
    )
    def test_capture_partial_github_metadata(self):
        """Test capturing partial GitHub metadata (missing fields)."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata["ci_provider"] == "github"
        assert metadata["repository"] == "test/repo"
        # None values should be excluded
        assert "commit" not in metadata or metadata.get("commit") is None
        assert "ref" not in metadata or metadata.get("ref") is None

    @patch.dict(
        "os.environ",
        {
            "GITLAB_CI": "true",
            "CI_PROJECT_PATH": "test/project",
            # Missing other GitLab fields
        },
    )
    def test_capture_partial_gitlab_metadata(self):
        """Test capturing partial GitLab metadata (missing fields)."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata["ci_provider"] == "gitlab"
        assert metadata["repository"] == "test/project"
        # None values should be excluded
        assert "commit" not in metadata or metadata.get("commit") is None
        assert "pipeline_id" not in metadata or metadata.get("pipeline_id") is None

    @patch.dict(
        "os.environ",
        {
            "GITHUB_ACTIONS": "true",
            "GITLAB_CI": "true",
        },
    )
    def test_github_takes_precedence_over_gitlab(self):
        """Test GitHub Actions takes precedence over GitLab CI."""
        capture = MetadataCapture()

        metadata = capture.capture_ci_metadata()

        assert metadata["ci_provider"] == "github"


class TestMetadataCaptureIntegration:
    """Integration tests for MetadataCapture."""

    def test_initialization(self):
        """Test MetadataCapture initialization."""
        capture = MetadataCapture()
        assert capture is not None

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    def test_combined_capture(self, mock_run):
        """Test combining scan args, git context, and CI metadata."""
        capture = MetadataCapture()

        # Mock git commands
        mock_run.return_value = MagicMock(returncode=0, stdout="abc123\n")

        # Capture scan args
        scan_metadata = capture.from_scan_args(
            profile="balanced",
            tools=["trivy"],
        )

        # Capture git context
        git_context = capture.capture_git_context("/repo")

        # Capture CI metadata
        ci_metadata = capture.capture_ci_metadata()

        # Combine all metadata
        combined = {**scan_metadata, **git_context, **ci_metadata}

        assert combined["profile"] == "balanced"
        assert combined["tools"] == ["trivy"]
        assert "commit" in combined  # From git context
