"""Unit tests for CI/CD security audit workflow.

Tests cover:
- Target detection (GitHub Actions, GitLab CI, Jenkins)
- Image extraction from CI pipeline files
- User prompting for CI/CD-specific options
- Command building for CI/CD scans
- Pipeline file summary printing

Architecture Note:
- Uses tmp_path fixture for file operations
- Mocks PromptHelper for user interaction
- Tests image extraction from YAML and Jenkinsfile
"""

from pathlib import Path
from unittest.mock import patch


from scripts.cli.wizard_flows.cicd_flow import CICDFlow


# ========== Category 1: Target Detection ==========


def test_detect_targets_github_actions(tmp_path, monkeypatch):
    """Test detect_targets finds GitHub Actions workflows."""
    monkeypatch.chdir(tmp_path)

    # Create GitHub Actions workflows
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    (workflows_dir / "ci.yml").write_text("name: CI")
    (workflows_dir / "release.yaml").write_text("name: Release")

    flow = CICDFlow()
    targets = flow.detect_targets()

    assert len(targets["github_actions"]) == 2
    assert any("ci.yml" in str(f) for f in targets["github_actions"])
    assert any("release.yaml" in str(f) for f in targets["github_actions"])


def test_detect_targets_gitlab_ci(tmp_path, monkeypatch):
    """Test detect_targets finds .gitlab-ci.yml."""
    monkeypatch.chdir(tmp_path)

    (tmp_path / ".gitlab-ci.yml").write_text("stages: [build, test]")

    flow = CICDFlow()
    targets = flow.detect_targets()

    assert targets["gitlab_ci"] is not None
    assert targets["gitlab_ci"].name == ".gitlab-ci.yml"


def test_detect_targets_jenkinsfile(tmp_path, monkeypatch):
    """Test detect_targets finds Jenkinsfile."""
    monkeypatch.chdir(tmp_path)

    (tmp_path / "Jenkinsfile").write_text("pipeline { }")

    flow = CICDFlow()
    targets = flow.detect_targets()

    assert targets["jenkinsfile"] is not None
    assert targets["jenkinsfile"].name == "Jenkinsfile"


def test_detect_targets_no_cicd_files(tmp_path, monkeypatch):
    """Test detect_targets with no CI/CD files."""
    monkeypatch.chdir(tmp_path)

    flow = CICDFlow()
    targets = flow.detect_targets()

    assert targets["github_actions"] == []
    assert targets["gitlab_ci"] is None
    assert targets["jenkinsfile"] is None


def test_detect_targets_includes_repos_images_iac(tmp_path, monkeypatch):
    """Test detect_targets includes standard detections."""
    monkeypatch.chdir(tmp_path)

    # Create a repo
    (tmp_path / "myrepo" / ".git").mkdir(parents=True)

    flow = CICDFlow()
    targets = flow.detect_targets()

    assert "repos" in targets
    assert "images" in targets
    assert "iac" in targets


# ========== Category 2: Image Detection from CI Files ==========


def test_detect_images_from_github_actions(tmp_path, monkeypatch):
    """Test _detect_images_from_ci extracts images from GitHub Actions."""
    monkeypatch.chdir(tmp_path)

    workflow_content = """
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    container: python:3.10
    services:
      postgres:
        image: postgres:14
"""
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    workflow_file = workflows_dir / "ci.yml"
    workflow_file.write_text(workflow_content)

    flow = CICDFlow()
    images = flow._detect_images_from_ci([workflow_file], None, None)

    assert "python:3.10" in images
    assert "postgres:14" in images


def test_detect_images_from_gitlab_ci_string_image(tmp_path):
    """Test _detect_images_from_ci extracts images from GitLab CI (string format)."""
    gitlab_ci_content = """
image: python:3.11

stages:
  - test
  - deploy

test:
  script:
    - pytest
"""
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(gitlab_ci_content)

    flow = CICDFlow()
    images = flow._detect_images_from_ci([], gitlab_ci, None)

    assert "python:3.11" in images


def test_detect_images_from_gitlab_ci_dict_image(tmp_path):
    """Test _detect_images_from_ci extracts images from GitLab CI (dict format)."""
    gitlab_ci_content = """
image:
  name: python:3.11
  entrypoint: [""]

build:
  image:
    name: node:18
  script:
    - npm build
"""
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(gitlab_ci_content)

    flow = CICDFlow()
    images = flow._detect_images_from_ci([], gitlab_ci, None)

    assert "python:3.11" in images
    assert "node:18" in images


def test_detect_images_from_jenkinsfile(tmp_path):
    """Test _detect_images_from_ci extracts images from Jenkinsfile."""
    jenkinsfile_content = """
pipeline {
    agent {
        docker.image('python:3.10')
    }
    stages {
        stage('Test') {
            agent {
                docker.image('node:18-alpine')
            }
        }
    }
}
"""
    jenkinsfile = tmp_path / "Jenkinsfile"
    jenkinsfile.write_text(jenkinsfile_content)

    flow = CICDFlow()
    images = flow._detect_images_from_ci([], None, jenkinsfile)

    assert "python:3.10" in images
    assert "node:18-alpine" in images


def test_detect_images_deduplication(tmp_path, monkeypatch):
    """Test _detect_images_from_ci deduplicates images."""
    monkeypatch.chdir(tmp_path)

    # Same image in multiple workflows
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    (workflows_dir / "ci1.yml").write_text("jobs:\n  test:\n    container: python:3.10")
    (workflows_dir / "ci2.yml").write_text("jobs:\n  test:\n    image: python:3.10")

    workflow_files = list(workflows_dir.glob("*.yml"))

    flow = CICDFlow()
    images = flow._detect_images_from_ci(workflow_files, None, None)

    assert images.count("python:3.10") == 1


def test_detect_images_handles_file_errors(tmp_path):
    """Test _detect_images_from_ci handles missing or invalid files gracefully."""
    flow = CICDFlow()

    # Non-existent files
    images = flow._detect_images_from_ci(
        [Path("/nonexistent/workflow.yml")],
        Path("/nonexistent/.gitlab-ci.yml"),
        Path("/nonexistent/Jenkinsfile"),
    )

    assert images == []


def test_detect_images_handles_invalid_yaml(tmp_path):
    """Test _detect_images_from_ci handles invalid YAML gracefully."""
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text("invalid: yaml: content: [")

    flow = CICDFlow()
    images = flow._detect_images_from_ci([], gitlab_ci, None)

    assert images == []


# ========== Category 3: User Prompting ==========


def test_prompt_user_fast_profile_no_images():
    """Test prompt_user with fast profile and no pipeline images."""
    flow = CICDFlow()
    flow.detected_targets = {
        "github_actions": [],
        "gitlab_ci": None,
        "jenkinsfile": None,
        "pipeline_images": [],
    }

    with (
        patch.object(flow.prompter, "prompt_choice", return_value="fast"),
        patch.object(
            flow.prompter, "prompt_yes_no", side_effect=[True, True]
        ) as _mock_yes_no,
    ):
        options = flow.prompt_user()

        assert options["profile"] == "fast"
        assert options["scan_files"] is True
        assert options["scan_images"] is False  # No images detected
        assert options["check_permissions"] is False  # No GitHub Actions
        assert options["emit_workflow"] is True


def test_prompt_user_with_pipeline_images():
    """Test prompt_user with detected pipeline images."""
    flow = CICDFlow()
    flow.detected_targets = {
        "github_actions": [],
        "pipeline_images": ["python:3.10", "postgres:14"],
    }

    with (
        patch.object(flow.prompter, "prompt_choice", return_value="balanced"),
        patch.object(flow.prompter, "prompt_yes_no", side_effect=[True, True, True]),
    ):
        options = flow.prompt_user()

        assert options["profile"] == "balanced"
        assert options["scan_images"] is True


def test_prompt_user_with_github_actions():
    """Test prompt_user with GitHub Actions detected (permissions check)."""
    flow = CICDFlow()
    flow.detected_targets = {
        "github_actions": [Path(".github/workflows/ci.yml")],
        "pipeline_images": [],
    }

    with (
        patch.object(flow.prompter, "prompt_choice", return_value="fast"),
        patch.object(flow.prompter, "prompt_yes_no", side_effect=[True, True, True]),
    ):
        options = flow.prompt_user()

        assert options["check_permissions"] is True


# ========== Category 4: Pipeline Summary Printing ==========


def test_print_detected_pipelines_github_actions(capsys):
    """Test _print_detected_pipelines with GitHub Actions."""
    flow = CICDFlow()
    targets = {
        "github_actions": [
            Path(".github/workflows/ci.yml"),
            Path(".github/workflows/release.yml"),
        ],
    }

    flow._print_detected_pipelines(targets)

    captured = capsys.readouterr()
    assert "GitHub Actions workflows: 2 detected" in captured.out
    assert "ci.yml" in captured.out


def test_print_detected_pipelines_many_workflows(capsys):
    """Test _print_detected_pipelines with more than 3 workflows (shows '... and N more')."""
    flow = CICDFlow()
    targets = {
        "github_actions": [
            Path(f".github/workflows/workflow{i}.yml") for i in range(5)
        ],
    }

    flow._print_detected_pipelines(targets)

    captured = capsys.readouterr()
    assert "GitHub Actions workflows: 5 detected" in captured.out
    assert "... and 2 more" in captured.out


def test_print_detected_pipelines_gitlab_ci(capsys):
    """Test _print_detected_pipelines with GitLab CI."""
    flow = CICDFlow()
    targets = {"gitlab_ci": Path(".gitlab-ci.yml")}

    flow._print_detected_pipelines(targets)

    captured = capsys.readouterr()
    assert "GitLab CI: .gitlab-ci.yml detected" in captured.out


def test_print_detected_pipelines_jenkinsfile(capsys):
    """Test _print_detected_pipelines with Jenkinsfile."""
    flow = CICDFlow()
    targets = {"jenkinsfile": Path("Jenkinsfile")}

    flow._print_detected_pipelines(targets)

    captured = capsys.readouterr()
    assert "Jenkins: Jenkinsfile detected" in captured.out


def test_print_detected_pipelines_with_images(capsys):
    """Test _print_detected_pipelines with pipeline images."""
    flow = CICDFlow()
    targets = {
        "pipeline_images": ["python:3.10", "postgres:14", "redis:alpine"],
    }

    flow._print_detected_pipelines(targets)

    captured = capsys.readouterr()
    assert "Container images: 3 found in pipelines" in captured.out


def test_print_detected_pipelines_no_pipelines(capsys):
    """Test _print_detected_pipelines with no CI/CD files."""
    flow = CICDFlow()
    targets = {}

    flow._print_detected_pipelines(targets)

    captured = capsys.readouterr()
    assert "No CI/CD pipeline files detected" in captured.out


# ========== Category 5: Command Building ==========


def test_build_command_basic():
    """Test build_command with basic options."""
    flow = CICDFlow()
    targets = {"repos": [Path(".")], "pipeline_images": []}
    options = {
        "profile": "fast",
        "scan_files": True,
        "scan_images": False,
    }

    cmd = flow.build_command(targets, options)

    assert "jmo" in cmd
    assert "ci" in cmd
    assert "--profile" in cmd
    assert "fast" in cmd
    assert "--fail-on" in cmd
    assert "HIGH" in cmd
    assert "--repos-dir" in cmd


def test_build_command_with_images(tmp_path, monkeypatch):
    """Test build_command with pipeline images."""
    monkeypatch.chdir(tmp_path)

    flow = CICDFlow()
    targets = {
        "repos": [],
        "pipeline_images": ["python:3.10", "postgres:14"],
    }
    options = {
        "profile": "balanced",
        "scan_files": False,
        "scan_images": True,
    }

    cmd = flow.build_command(targets, options)

    assert "--images-file" in cmd
    assert "pipeline-images.txt" in cmd
    # Verify file was created
    assert (tmp_path / "pipeline-images.txt").exists()


def test_build_command_scan_files_no_repos():
    """Test build_command when scan_files=True but no repos detected."""
    flow = CICDFlow()
    targets = {"repos": [], "pipeline_images": []}
    options = {
        "profile": "fast",
        "scan_files": True,
        "scan_images": False,
    }

    cmd = flow.build_command(targets, options)

    assert "--repos-dir" not in cmd


def test_build_command_scan_images_no_images():
    """Test build_command when scan_images=True but no images detected."""
    flow = CICDFlow()
    targets = {"repos": [], "pipeline_images": []}
    options = {
        "profile": "fast",
        "scan_files": False,
        "scan_images": True,
    }

    cmd = flow.build_command(targets, options)

    assert "--images-file" not in cmd
