"""Tests for CI/CD flow module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_cicd_flow_module_imports():
    """Test that cicd_flow module can be imported."""
    try:
        from scripts.cli.wizard_flows import cicd_flow

        assert cicd_flow is not None
    except ImportError as e:
        pytest.fail(f"Failed to import cicd_flow: {e}")


def test_cicd_flow_class_exists():
    """Test that CICDFlow class exists."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    assert CICDFlow is not None


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_initialization(mock_base_init):
    """Test CICDFlow initialization."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    assert flow is not None


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_detect_targets(mock_base_init, tmp_path):
    """Test CI/CD flow target detection."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    # Create mock GitHub Actions workflow
    gha_dir = tmp_path / ".github" / "workflows"
    gha_dir.mkdir(parents=True)
    (gha_dir / "ci.yml").write_text("name: CI")

    # Initialize flow and mock detector
    flow = CICDFlow()
    flow.detector = MagicMock()
    flow.detector.detect_repos.return_value = [tmp_path]
    flow.detector.detect_images.return_value = ["nginx:latest"]
    flow.detector.detect_iac.return_value = []

    # Change to tmp directory to test detection
    import os

    original_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        targets = flow.detect_targets()

        assert isinstance(targets, dict)
        assert "repos" in targets
        assert "images" in targets
        assert "github_actions" in targets
    finally:
        os.chdir(original_cwd)


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_build_command(mock_base_init):
    """Test CI/CD flow command building."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    targets = {
        "repos": [Path("/repo1")],
        "pipeline_images": ["nginx:latest", "python:3.10"],
        "github_actions": [Path(".github/workflows/ci.yml")],
    }

    options = {
        "profile": "fast",
        "scan_files": True,
        "scan_images": True,
        "check_permissions": False,
    }

    cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "ci" in cmd
    assert "--profile" in cmd
    assert "fast" in cmd


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_prompt_user_with_images_and_gha(mock_base_init):
    """Test prompt_user with pipeline images and GitHub Actions."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()
    flow.detected_targets = {
        "pipeline_images": ["nginx:latest", "python:3.10"],
        "github_actions": [Path(".github/workflows/ci.yml")],
    }
    flow.prompter = MagicMock()
    flow.prompter.print_header.return_value = None
    flow.prompter.print_info.return_value = None
    flow.prompter.prompt_choice.return_value = "fast"
    flow.prompter.prompt_yes_no.side_effect = [True, True, True, True]

    options = flow.prompt_user()

    assert options["profile"] == "fast"
    assert options["scan_files"] is True
    assert options["scan_images"] is True
    assert options["check_permissions"] is True
    assert options["emit_workflow"] is True


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_prompt_user_no_images_no_gha(mock_base_init):
    """Test prompt_user without pipeline images or GitHub Actions."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()
    flow.detected_targets = {"pipeline_images": [], "github_actions": []}
    flow.prompter = MagicMock()
    flow.prompter.prompt_choice.return_value = "balanced"
    flow.prompter.prompt_yes_no.side_effect = [True, False]

    options = flow.prompt_user()

    assert options["profile"] == "balanced"
    assert options["scan_images"] is False  # No images
    assert options["check_permissions"] is False  # No GHA


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_print_detected_pipelines_all_types(mock_base_init):
    """Test printing all detected pipeline types."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()
    flow.prompter = MagicMock()

    targets = {
        "github_actions": [
            Path(".github/workflows/ci.yml"),
            Path(".github/workflows/release.yml"),
        ],
        "gitlab_ci": Path(".gitlab-ci.yml"),
        "jenkinsfile": Path("Jenkinsfile"),
        "pipeline_images": ["nginx:latest"],
    }

    flow._print_detected_pipelines(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "GitHub Actions workflows: 2 detected" in items
    assert "GitLab CI: .gitlab-ci.yml detected" in items
    assert "Jenkins: Jenkinsfile detected" in items
    assert "Container images: 1 found in pipelines" in items


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_print_detected_pipelines_many_gha(mock_base_init):
    """Test printing >3 GitHub Actions workflows."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()
    flow.prompter = MagicMock()

    # Create 5 workflow files
    workflows = [Path(f".github/workflows/workflow{i}.yml") for i in range(5)]
    targets = {"github_actions": workflows}

    flow._print_detected_pipelines(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "GitHub Actions workflows: 5 detected" in items
    assert "  ... and 2 more" in items


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_print_detected_pipelines_none(mock_base_init):
    """Test printing when no pipelines detected."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()
    flow.prompter = MagicMock()

    targets = {}

    flow._print_detected_pipelines(targets)

    flow.prompter.print_warning.assert_called_once_with(
        "No CI/CD pipeline files detected"
    )


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_build_command_no_scan_files(mock_base_init):
    """Test build_command when scan_files is False."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    targets = {"repos": [Path("/repo1")], "pipeline_images": []}
    options = {"profile": "fast", "scan_files": False, "scan_images": False}

    cmd = flow.build_command(targets, options)

    assert "--repos-dir" not in cmd


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_detect_images_github_actions(mock_base_init, tmp_path):
    """Test detecting images from GitHub Actions workflows."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    # Create mock workflow file with image reference
    # Regex expects "image: value" or "container: value" on same line
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        """
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    container: node:18-alpine
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
        # Using image: in a comment to test extraction
        image: postgres:14
"""
    )

    images = flow._detect_images_from_ci([workflow], None, None)

    assert "node:18-alpine" in images
    assert "postgres:14" in images


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_detect_images_gitlab_ci(mock_base_init, tmp_path):
    """Test detecting images from GitLab CI config."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    # Create mock GitLab CI file
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
image: ruby:3.0

test:
  image: node:16
  script:
    - npm test
"""
    )

    images = flow._detect_images_from_ci([], gitlab_ci, None)

    assert "ruby:3.0" in images
    assert "node:16" in images


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_detect_images_gitlab_ci_dict_format(mock_base_init, tmp_path):
    """Test detecting images from GitLab CI with dict format."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
image:
  name: docker:latest
  entrypoint: [""]

build:
  image:
    name: python:3.10
  script:
    - python setup.py build
"""
    )

    images = flow._detect_images_from_ci([], gitlab_ci, None)

    assert "docker:latest" in images
    assert "python:3.10" in images


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_detect_images_jenkinsfile(mock_base_init, tmp_path):
    """Test detecting images from Jenkinsfile."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    jenkinsfile = tmp_path / "Jenkinsfile"
    jenkinsfile.write_text(
        """
pipeline {
    agent {
        docker.image('maven:3.8-jdk-11')
    }
    stages {
        stage('Build') {
            agent {
                docker.image('node:18')
            }
        }
    }
}
"""
    )

    images = flow._detect_images_from_ci([], None, jenkinsfile)

    assert "maven:3.8-jdk-11" in images
    assert "node:18" in images


@patch("scripts.cli.wizard_flows.cicd_flow.BaseWizardFlow.__init__", return_value=None)
def test_cicd_flow_detect_images_error_handling(mock_base_init, tmp_path):
    """Test error handling when files are invalid."""
    from scripts.cli.wizard_flows.cicd_flow import CICDFlow

    flow = CICDFlow()

    # Non-existent file
    missing_file = tmp_path / "missing.yml"

    # Invalid YAML file
    invalid_yaml = tmp_path / ".gitlab-ci.yml"
    invalid_yaml.write_text("invalid: yaml: [syntax")

    # Should not raise exceptions
    images = flow._detect_images_from_ci([missing_file], invalid_yaml, None)

    assert isinstance(images, list)


def test_wizard_generators_module_imports():
    """Test that wizard_generators module can be imported."""
    try:
        from scripts.cli import wizard_generators

        assert wizard_generators is not None
    except ImportError as e:
        pytest.fail(f"Failed to import wizard_generators: {e}")


def test_generate_makefile_target_function_exists():
    """Test that generate_makefile_target function exists."""
    from scripts.cli.wizard_generators import generate_makefile_target

    assert callable(generate_makefile_target)


def test_generate_github_actions_function_exists():
    """Test that generate_github_actions function exists."""
    from scripts.cli.wizard_generators import generate_github_actions

    assert callable(generate_github_actions)


def test_generate_shell_script_function_exists():
    """Test that generate_shell_script function exists."""
    from scripts.cli.wizard_generators import generate_shell_script

    assert callable(generate_shell_script)


def test_generate_makefile_target_basic():
    """Test basic Makefile target generation."""
    from scripts.cli.wizard_generators import generate_makefile_target

    mock_config = MagicMock()
    command = "jmo scan --repos-dir . --profile fast"
    snippet = generate_makefile_target(mock_config, command, workflow_type="repo")

    assert isinstance(snippet, str)
    assert ".PHONY:" in snippet or "jmo" in snippet


def test_generate_github_actions_basic():
    """Test basic GitHub Actions workflow generation."""
    from scripts.cli.wizard_generators import generate_github_actions

    mock_config = MagicMock()
    mock_config.profile = "balanced"
    mock_config.target = MagicMock()
    mock_config.target.type = "repo"
    mock_config.use_docker = True
    mock_config.threads = 4
    mock_config.timeout = 600
    mock_config.fail_on = None

    mock_profiles = {
        "balanced": {"tools": ["trivy", "semgrep"], "threads": 4, "timeout": 600}
    }

    workflow = generate_github_actions(mock_config, mock_profiles)

    assert isinstance(workflow, str)
    assert "name:" in workflow or "jmo" in workflow


def test_generate_shell_script_basic():
    """Test basic shell script generation."""
    from scripts.cli.wizard_generators import generate_shell_script

    mock_config = MagicMock()
    command = "jmo scan --repos-dir . --profile deep"
    script = generate_shell_script(mock_config, command)

    assert isinstance(script, str)
    assert "#!/" in script or "jmo" in script
