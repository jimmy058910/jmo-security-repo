"""Tests for repository flow module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def test_repo_flow_module_imports():
    """Test that repo_flow module can be imported."""
    try:
        from scripts.cli.wizard_flows import repo_flow

        assert repo_flow is not None
    except ImportError as e:
        pytest.fail(f"Failed to import repo_flow: {e}")


def test_repo_flow_class_exists():
    """Test that RepoFlow class exists."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    assert RepoFlow is not None


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_initialization(mock_base_init):
    """Test RepoFlow initialization."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()

    assert flow is not None


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_detect_targets(mock_base_init, tmp_path):
    """Test repo flow target detection."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    # Create mock repos
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / ".git").mkdir()

    # Initialize flow and mock detector
    flow = RepoFlow()
    flow.detector = MagicMock()
    flow.detector.detect_repos.return_value = [repo1]

    targets = flow.detect_targets()

    assert isinstance(targets, dict)
    assert "repos" in targets
    assert targets["repos"] == [repo1]


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_prompt_user(mock_base_init):
    """Test repo flow user prompts."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()
    flow.detected_targets = {"repos": [MagicMock(name="test-repo")]}
    flow.prompter = MagicMock()
    flow.prompter.print_header.return_value = None
    flow.prompter.print_summary_box.return_value = None
    flow.prompter.print_info.return_value = None
    flow.prompter.prompt_choice.return_value = "balanced"
    flow.prompter.prompt_yes_no.return_value = True

    options = flow.prompt_user()

    assert isinstance(options, dict)
    assert options["profile"] == "balanced"
    assert options["emit_artifacts"] is True


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_print_detected_repos_single(mock_base_init):
    """Test printing detected repositories with single repo."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()
    flow.prompter = MagicMock()

    mock_repo = MagicMock()
    mock_repo.name = "test-repo"
    targets = {"repos": [mock_repo]}

    flow._print_detected_repos(targets)

    flow.prompter.print_summary_box.assert_called_once()
    call_args = flow.prompter.print_summary_box.call_args
    assert call_args[0][0] == "🔍 Detected Repositories"
    items = call_args[0][1]
    assert "Repositories: 1 detected" in items
    assert "  → test-repo" in items


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_print_detected_repos_multiple(mock_base_init):
    """Test printing detected repositories with multiple repos (>5)."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()
    flow.prompter = MagicMock()

    # Create 7 mock repos with explicit .name attributes
    mock_repos = []
    for i in range(7):
        repo = MagicMock()
        repo.name = f"repo{i}"
        mock_repos.append(repo)
    targets = {"repos": mock_repos}

    flow._print_detected_repos(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "Repositories: 7 detected" in items
    # Should show first 5 repos
    assert "  → repo0" in items
    assert "  → repo4" in items
    # Should show "and 2 more"
    assert "  ... and 2 more" in items


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_print_detected_repos_none(mock_base_init):
    """Test printing when no repositories detected."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()
    flow.prompter = MagicMock()

    targets = {"repos": []}

    flow._print_detected_repos(targets)

    flow.prompter.print_warning.assert_called_once_with(
        "No repositories detected in current directory"
    )


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_build_command_with_repos(mock_base_init, tmp_path):
    """Test build command with detected repos."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()

    repo = tmp_path / "test-repo"
    repo.mkdir()

    targets = {"repos": [repo]}
    options = {"profile": "fast"}

    cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "scan" in cmd
    assert "--profile" in cmd
    assert "fast" in cmd
    assert "--repo" in cmd
    assert str(repo) in cmd


@patch("scripts.cli.wizard_flows.repo_flow.BaseWizardFlow.__init__", return_value=None)
def test_repo_flow_build_command_without_repos(mock_base_init):
    """Test build command without detected repos."""
    from scripts.cli.wizard_flows.repo_flow import RepoFlow

    flow = RepoFlow()

    targets = {"repos": []}
    options = {"profile": "balanced"}

    cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "scan" in cmd
    assert "--profile" in cmd
    assert "balanced" in cmd
    # No --repo flag should be added
    assert "--repo" not in cmd
