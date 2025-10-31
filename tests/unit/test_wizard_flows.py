#!/usr/bin/env python3
"""Tests for wizard workflow classes."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from scripts.cli.wizard_flows import (
    BaseWizardFlow,
    RepoFlow,
    EntireStackFlow,
    CICDFlow,
    DeploymentFlow,
    DependencyFlow,
    TargetDetector,
    PromptHelper,
)


class TestTargetDetector:
    """Tests for TargetDetector class."""

    def test_detect_repos(self, tmp_path):
        """Test repository detection."""
        # Create test repo
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)

        assert len(repos) == 1
        assert repos[0].name == "test-repo"

    def test_detect_repos_no_repos(self, tmp_path):
        """Test repository detection with no repos."""
        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)

        assert repos == []

    def test_detect_package_files_python(self, tmp_path):
        """Test Python package file detection."""
        # Create Python package files
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "setup.py").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 3
        file_names = [f.name for f in package_files]
        assert "requirements.txt" in file_names
        assert "pyproject.toml" in file_names
        assert "setup.py" in file_names

    def test_detect_package_files_javascript(self, tmp_path):
        """Test JavaScript package file detection."""
        (tmp_path / "package.json").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "package.json"

    def test_detect_package_files_go(self, tmp_path):
        """Test Go package file detection."""
        (tmp_path / "go.mod").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "go.mod"

    def test_detect_package_files_rust(self, tmp_path):
        """Test Rust package file detection."""
        (tmp_path / "Cargo.toml").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "Cargo.toml"

    def test_detect_package_files_java_maven(self, tmp_path):
        """Test Java Maven package file detection."""
        (tmp_path / "pom.xml").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "pom.xml"

    def test_detect_lock_files_python(self, tmp_path):
        """Test Python lock file detection."""
        (tmp_path / "poetry.lock").touch()
        (tmp_path / "Pipfile.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 2
        file_names = [f.name for f in lock_files]
        assert "poetry.lock" in file_names
        assert "Pipfile.lock" in file_names

    def test_detect_lock_files_javascript(self, tmp_path):
        """Test JavaScript lock file detection."""
        (tmp_path / "package-lock.json").touch()
        (tmp_path / "yarn.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 2
        file_names = [f.name for f in lock_files]
        assert "package-lock.json" in file_names
        assert "yarn.lock" in file_names

    def test_detect_images_from_compose(self, tmp_path):
        """Test image detection from docker-compose.yml."""
        compose_content = """version: '3'
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert len(images) == 2
        assert "nginx:latest" in images
        assert "postgres:14" in images

    def test_detect_iac_terraform(self, tmp_path):
        """Test Terraform IaC detection."""
        (tmp_path / "main.tf").touch()
        (tmp_path / "terraform.tfstate").touch()

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        assert len(iac_files) == 2

    def test_detect_web_apps_from_compose(self, tmp_path):
        """Test web app detection from docker-compose ports."""
        compose_content = """version: '3'
services:
  web:
    ports:
      - "8080:80"
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert "http://localhost:8080" in urls


class TestRepoFlow:
    """Tests for RepoFlow workflow."""

    def test_detect_targets(self, tmp_path):
        """Test repository target detection."""
        # Create test repo
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = RepoFlow()
            targets = flow.detect_targets()

        assert "repos" in targets
        assert len(targets["repos"]) == 1

    def test_prompt_user(self):
        """Test user prompting."""
        flow = RepoFlow()
        flow.prompter = Mock()
        flow.prompter.prompt_choice.return_value = "balanced"
        flow.prompter.prompt_yes_no.return_value = True

        options = flow.prompt_user()

        assert options["profile"] == "balanced"
        assert options["emit_artifacts"] is True

    def test_build_command(self):
        """Test command building."""
        flow = RepoFlow()
        targets = {"repos": [Path("/test/repo")]}
        options = {"profile": "fast"}

        cmd = flow.build_command(targets, options)

        assert cmd[0] == "jmo"
        assert cmd[1] == "scan"
        assert "--profile" in cmd
        assert "fast" in cmd
        assert "--repo" in cmd


class TestEntireStackFlow:
    """Tests for EntireStackFlow workflow."""

    def test_detect_targets_multiple_types(self, tmp_path):
        """Test detection of multiple target types."""
        # Create repo
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        # Create docker-compose
        compose_content = """version: '3'
services:
  web:
    image: nginx:latest
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        # Create IaC
        (tmp_path / "main.tf").touch()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = EntireStackFlow()
            targets = flow.detect_targets()

        assert "repos" in targets
        assert "images" in targets
        assert "iac" in targets
        assert len(targets["repos"]) == 1
        assert len(targets["images"]) == 1
        assert len(targets["iac"]) == 1

    def test_generate_recommendations_dockerfile(self, tmp_path):
        """Test recommendation generation when Dockerfile exists."""
        (tmp_path / "Dockerfile").touch()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = EntireStackFlow()
            targets = {"images": [], "repos": [], "iac": [], "web": []}
            recommendations = flow._generate_recommendations(targets)

        assert len(recommendations) > 0
        assert any("docker build" in rec for rec in recommendations)

    def test_generate_recommendations_terraform(self, tmp_path):
        """Test recommendation generation when terraform directory exists."""
        (tmp_path / "terraform").mkdir()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = EntireStackFlow()
            targets = {"images": [], "repos": [], "iac": [], "web": []}
            recommendations = flow._generate_recommendations(targets)

        assert len(recommendations) > 0
        assert any("terraform init" in rec for rec in recommendations)

    def test_build_command_multi_target(self, tmp_path):
        """Test command building with multiple targets."""
        flow = EntireStackFlow()
        targets = {
            "repos": [Path("/test/repo")],
            "images": ["nginx:latest"],
            "iac": [Path("/test/main.tf")],
            "web": ["http://localhost:3000"],
        }
        options = {"profile": "balanced"}

        cmd = flow.build_command(targets, options)

        assert "--repos-dir" in cmd
        assert "--images-file" in cmd
        assert "--terraform-state" in cmd
        assert "--url" in cmd


class TestCICDFlow:
    """Tests for CICDFlow workflow."""

    def test_detect_targets_github_actions(self, tmp_path):
        """Test detection of GitHub Actions workflows."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").touch()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = CICDFlow()
            targets = flow.detect_targets()

        assert "github_actions" in targets
        assert len(targets["github_actions"]) == 1

    def test_detect_targets_gitlab_ci(self, tmp_path):
        """Test detection of GitLab CI."""
        (tmp_path / ".gitlab-ci.yml").touch()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = CICDFlow()
            targets = flow.detect_targets()

        assert targets["gitlab_ci"] is not None

    def test_detect_images_from_ci_github(self, tmp_path):
        """Test image extraction from GitHub Actions."""
        workflow_content = """name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    container: python:3.11
"""
        workflow_file = tmp_path / "ci.yml"
        workflow_file.write_text(workflow_content)

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = CICDFlow()
            images = flow._detect_images_from_ci([workflow_file], None, None)

        assert "python:3.11" in images

    def test_detect_images_from_ci_gitlab(self, tmp_path):
        """Test image extraction from GitLab CI."""
        gitlab_content = """image: node:18

test:
  image: postgres:14
  script:
    - npm test
"""
        gitlab_file = tmp_path / ".gitlab-ci.yml"
        gitlab_file.write_text(gitlab_content)

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = CICDFlow()
            images = flow._detect_images_from_ci([], gitlab_file, None)

        assert "node:18" in images
        assert "postgres:14" in images


class TestDeploymentFlow:
    """Tests for DeploymentFlow workflow."""

    def test_detect_environment_from_env_var(self):
        """Test environment detection from environment variable."""
        with patch.dict("os.environ", {"ENVIRONMENT": "production"}):
            flow = DeploymentFlow()
            env = flow._detect_environment()

        assert env == "production"

    def test_detect_environment_default(self):
        """Test environment detection defaults to staging."""
        with patch.dict("os.environ", {}, clear=True):
            flow = DeploymentFlow()
            env = flow._detect_environment()

        assert env == "staging"

    def test_prompt_user_production(self):
        """Test user prompting for production environment."""
        flow = DeploymentFlow()
        flow.detected_targets = {"environment": "production"}
        flow.prompter = Mock()
        flow.prompter.prompt_choice.side_effect = ["production", "deep", "CRITICAL"]

        options = flow.prompt_user()

        assert options["environment"] == "production"
        assert options["profile"] == "deep"
        assert options["fail_on"] == "CRITICAL"

    def test_prompt_user_staging(self):
        """Test user prompting for staging environment."""
        flow = DeploymentFlow()
        flow.detected_targets = {"environment": "staging"}
        flow.prompter = Mock()
        flow.prompter.prompt_choice.side_effect = ["staging", "balanced", "HIGH"]

        options = flow.prompt_user()

        assert options["environment"] == "staging"
        assert options["profile"] == "balanced"
        assert options["fail_on"] == "HIGH"


class TestDependencyFlow:
    """Tests for DependencyFlow workflow."""

    def test_detect_targets_python(self, tmp_path):
        """Test detection of Python dependencies."""
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "poetry.lock").touch()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = DependencyFlow()
            targets = flow.detect_targets()

        assert "package_files" in targets
        assert "lock_files" in targets
        assert len(targets["package_files"]) == 1
        assert len(targets["lock_files"]) == 1

    def test_detect_targets_javascript(self, tmp_path):
        """Test detection of JavaScript dependencies."""
        (tmp_path / "package.json").touch()
        (tmp_path / "package-lock.json").touch()

        with patch("scripts.cli.wizard_flows.base_flow.Path.cwd", return_value=tmp_path):
            flow = DependencyFlow()
            targets = flow.detect_targets()

        assert len(targets["package_files"]) == 1
        assert len(targets["lock_files"]) == 1

    def test_prompt_user(self):
        """Test user prompting."""
        flow = DependencyFlow()
        flow.prompter = Mock()
        flow.prompter.prompt_yes_no.side_effect = [True, True, False]

        options = flow.prompt_user()

        assert options["generate_sbom"] is True
        assert options["scan_vulns"] is True
        assert options["check_licenses"] is False

    def test_build_command(self, tmp_path):
        """Test command building."""
        flow = DependencyFlow()
        targets = {
            "package_files": [Path("/test/requirements.txt")],
            "lock_files": [Path("/test/poetry.lock")],
            "images": ["myapp:latest"],
        }
        options = {"generate_sbom": True}

        cmd = flow.build_command(targets, options)

        assert "--tools" in cmd
        assert "syft" in cmd
        assert "trivy" in cmd
        assert "--repo" in cmd


class TestPromptHelper:
    """Tests for PromptHelper class."""

    def test_colorize(self):
        """Test text colorization."""
        helper = PromptHelper()
        colored = helper.colorize("test", "blue")

        assert "\x1b[36m" in colored  # Blue color code
        assert "test" in colored
        assert "\x1b[0m" in colored  # Reset code

    def test_prompt_choice_with_default(self, monkeypatch):
        """Test choice prompt with default."""
        monkeypatch.setattr("builtins.input", lambda _: "")
        helper = PromptHelper()

        choice = helper.prompt_choice("Test?", ["a", "b"], default="a")

        assert choice == "a"

    def test_prompt_yes_no_default_yes(self, monkeypatch):
        """Test yes/no prompt with default yes."""
        monkeypatch.setattr("builtins.input", lambda _: "")
        helper = PromptHelper()

        result = helper.prompt_yes_no("Test?", default=True)

        assert result is True

    def test_prompt_yes_no_explicit_no(self, monkeypatch):
        """Test yes/no prompt with explicit no."""
        monkeypatch.setattr("builtins.input", lambda _: "n")
        helper = PromptHelper()

        result = helper.prompt_yes_no("Test?", default=True)

        assert result is False
