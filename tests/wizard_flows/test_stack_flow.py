"""Tests for stack flow module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_stack_flow_module_imports():
    """Test that stack_flow module can be imported."""
    try:
        from scripts.cli.wizard_flows import stack_flow

        assert stack_flow is not None
    except ImportError as e:
        pytest.fail(f"Failed to import stack_flow: {e}")


def test_entire_stack_flow_class_exists():
    """Test that EntireStackFlow class exists."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    assert EntireStackFlow is not None


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_initialization(mock_base_init):
    """Test EntireStackFlow initialization."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    assert flow is not None


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_detect_targets(mock_base_init):
    """Test EntireStackFlow target detection."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()
    flow.detector = MagicMock()
    flow.detector.detect_repos.return_value = [Path("/repo1")]
    flow.detector.detect_images.return_value = ["nginx:latest"]
    flow.detector.detect_iac.return_value = [Path("main.tf")]
    flow.detector.detect_web_apps.return_value = ["http://localhost:8080"]

    targets = flow.detect_targets()

    assert isinstance(targets, dict)
    assert "repos" in targets
    assert "images" in targets
    assert "iac" in targets
    assert "web" in targets


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_prompt_user(mock_base_init):
    """Test EntireStackFlow user prompts."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()
    flow.detected_targets = {
        "repos": [Path("/repo1")],
        "images": [],
        "iac": [],
        "web": [],
    }
    flow.prompter = MagicMock()
    flow.prompter.print_summary_box.return_value = None
    flow.prompter.prompt_choice.return_value = "balanced"
    flow.prompter.prompt_yes_no.side_effect = [True, True]

    options = flow.prompt_user()

    assert isinstance(options, dict)
    assert "profile" in options
    assert "emit_artifacts" in options
    assert "parallel" in options


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_build_command(mock_base_init, tmp_path):
    """Test EntireStackFlow command building."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    targets = {
        "repos": [Path("/repo1")],
        "images": ["nginx:latest", "postgres:14"],
        "iac": [Path("main.tf")],
        "web": ["http://localhost:8080"],
    }

    options = {"profile": "balanced", "emit_artifacts": True, "parallel": True}

    # Change to tmp_path for testing
    with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path_cls:
        mock_path_cls.return_value = tmp_path / "detected-images.txt"
        cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "scan" in cmd
    assert "--profile" in cmd
    assert "balanced" in cmd


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_recommendations(mock_base_init):
    """Test EntireStackFlow recommendation generation."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    # Test _has_dockerfile
    with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path:
        mock_cwd = MagicMock()
        mock_cwd.glob.return_value = [Path("Dockerfile")]
        mock_path.cwd.return_value = mock_cwd

        result = flow._has_dockerfile()
        assert isinstance(result, bool)


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_helper_methods(mock_base_init):
    """Test EntireStackFlow helper methods."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    # Test with mocked Path
    with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path:
        mock_cwd = MagicMock()
        mock_terraform_dir = MagicMock()
        mock_terraform_dir.exists.return_value = False
        mock_cwd.__truediv__ = lambda self, x: mock_terraform_dir
        mock_path.cwd.return_value = mock_cwd

        result = flow._has_terraform_dir()
        assert isinstance(result, bool)


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_recommendations_dockerfile(mock_base_init, tmp_path):
    """Test recommendations when Dockerfile exists but no images."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    targets = {
        "repos": [Path("/repo1")],
        "images": [],  # No images despite Dockerfile
        "iac": [],
        "web": [],
    }

    with patch("scripts.cli.wizard_flows.stack_flow.Path.cwd", return_value=tmp_path):
        # Create Dockerfile
        (tmp_path / "Dockerfile").write_text("FROM nginx")

        recommendations = flow._generate_recommendations(targets)

        assert isinstance(recommendations, list)
        # Should recommend building image
        assert any("docker build" in r.lower() for r in recommendations)


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_recommendations_terraform(mock_base_init, tmp_path):
    """Test recommendations when terraform dir exists but not initialized."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    targets = {
        "repos": [Path("/repo1")],
        "images": [],
        "iac": [],  # No IaC despite terraform dir
        "web": [],
    }

    with patch("scripts.cli.wizard_flows.stack_flow.Path.cwd", return_value=tmp_path):
        # Create terraform dir
        (tmp_path / "terraform").mkdir()

        recommendations = flow._generate_recommendations(targets)

        assert isinstance(recommendations, list)
        # Should recommend terraform init
        assert any("terraform init" in r.lower() for r in recommendations)


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_recommendations_gitlab(mock_base_init, tmp_path):
    """Test recommendations when .gitlab-ci.yml exists."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    targets = {"repos": [Path("/repo1")], "images": [], "iac": [], "web": []}

    with patch("scripts.cli.wizard_flows.stack_flow.Path.cwd", return_value=tmp_path):
        # Create .gitlab-ci.yml
        (tmp_path / ".gitlab-ci.yml").write_text("stages:\n  - test")

        recommendations = flow._generate_recommendations(targets)

        assert isinstance(recommendations, list)
        # Should recommend GitLab scanning
        assert any("gitlab" in r.lower() for r in recommendations)


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_recommendations_k8s(mock_base_init, tmp_path):
    """Test recommendations when kubernetes dir exists."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    targets = {"repos": [Path("/repo1")], "images": [], "iac": [], "web": []}

    with patch("scripts.cli.wizard_flows.stack_flow.Path.cwd", return_value=tmp_path):
        # Create kubernetes dir
        (tmp_path / "kubernetes").mkdir()

        recommendations = flow._generate_recommendations(targets)

        assert isinstance(recommendations, list)
        # Should recommend K8s scanning
        assert any(
            "k8s" in r.lower() or "kubernetes" in r.lower() for r in recommendations
        )


@patch("scripts.cli.wizard_flows.stack_flow.BaseWizardFlow.__init__", return_value=None)
def test_entire_stack_flow_recommendations_github_workflows(mock_base_init, tmp_path):
    """Test recommendations when GitHub Actions workflows exist."""
    from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

    flow = EntireStackFlow()

    targets = {"repos": [Path("/repo1")], "images": [], "iac": [], "web": []}

    with patch("scripts.cli.wizard_flows.stack_flow.Path.cwd", return_value=tmp_path):
        # Create .github/workflows dir
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI")

        recommendations = flow._generate_recommendations(targets)

        assert isinstance(recommendations, list)
        # Should recommend GitHub Actions audit
        assert any(
            "github actions" in r.lower() or "ci/cd" in r.lower()
            for r in recommendations
        )
