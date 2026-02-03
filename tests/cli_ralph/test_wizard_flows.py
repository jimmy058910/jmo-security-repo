#!/usr/bin/env python3
"""
Unit tests for wizard flow modules.

Tests the individual flow classes (CICDFlow, DeploymentFlow, DependencyFlow,
EntireStackFlow, RepoFlow) with mocked PromptHelper to avoid interactive prompts.

Coverage targets:
- cicd_flow.py: detect_targets, build_command, _detect_images_from_ci
- deployment_flow.py: detect_targets, build_command, _detect_environment
- dependency_flow.py: detect_targets, build_command
- stack_flow.py: detect_targets, build_command, _generate_recommendations
- repo_flow.py: detect_targets, build_command

Usage:
    pytest tests/cli_ralph/test_wizard_flows.py -v
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


class MockPromptHelper:
    """Mock PromptHelper that returns predictable values."""

    def __init__(self, **defaults: Any) -> None:
        self._defaults = defaults
        self._prompts: list[str] = []

    def prompt_choice(
        self, prompt: str, choices: list[str], default: str | None = None
    ) -> str:
        self._prompts.append(prompt)
        return self._defaults.get("choice", default or choices[0])

    def prompt_yes_no(self, prompt: str, default: bool = True) -> bool:
        self._prompts.append(prompt)
        return self._defaults.get("yes_no", default)

    def prompt_text(self, prompt: str, default: str = "") -> str:
        self._prompts.append(prompt)
        return self._defaults.get("text", default)

    def print_header(self, title: str, icon: str = "") -> None:
        pass

    def print_info(self, msg: str) -> None:
        pass

    def print_warning(self, msg: str) -> None:
        pass

    def print_summary_box(self, title: str, items: list[str]) -> None:
        pass


class MockTargetDetector:
    """Mock TargetDetector that returns configurable results."""

    def __init__(self, **results: Any) -> None:
        self._results = results

    def detect_repos(self, search_dir: Path | None = None) -> list[Path]:
        return self._results.get("repos", [])

    def detect_images(self, search_dir: Path | None = None) -> list[str]:
        return self._results.get("images", [])

    def detect_iac(self, search_dir: Path | None = None) -> list[Path]:
        return self._results.get("iac", [])

    def detect_web_apps(self) -> list[str]:
        return self._results.get("web", [])

    def detect_package_files(self) -> list[Path]:
        return self._results.get("package_files", [])

    def detect_lock_files(self) -> list[Path]:
        return self._results.get("lock_files", [])


# =============================================================================
# CICDFlow Tests
# =============================================================================


class TestCICDFlowDetectTargets:
    """Test CICDFlow.detect_targets method."""

    def test_detect_targets_with_github_actions(self, tmp_path: Path) -> None:
        """Detects GitHub Actions workflows."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        # Setup workflow files
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI")
        (workflows_dir / "release.yaml").write_text("name: Release")

        with patch("scripts.cli.wizard_flows.cicd_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = CICDFlow.__new__(CICDFlow)
            flow.detector = MockTargetDetector(repos=[tmp_path], images=[], iac=[])
            flow.prompter = MockPromptHelper()

            targets = flow.detect_targets()

            assert len(targets["github_actions"]) == 2
            assert targets["gitlab_ci"] is None
            assert targets["jenkinsfile"] is None

    def test_detect_targets_with_gitlab_ci(self, tmp_path: Path) -> None:
        """Detects GitLab CI config."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        (tmp_path / ".gitlab-ci.yml").write_text("stages:\n  - build")

        with patch("scripts.cli.wizard_flows.cicd_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = CICDFlow.__new__(CICDFlow)
            flow.detector = MockTargetDetector(repos=[tmp_path], images=[], iac=[])
            flow.prompter = MockPromptHelper()

            targets = flow.detect_targets()

            assert targets["gitlab_ci"] is not None
            assert targets["gitlab_ci"].name == ".gitlab-ci.yml"

    def test_detect_targets_with_jenkinsfile(self, tmp_path: Path) -> None:
        """Detects Jenkinsfile."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        (tmp_path / "Jenkinsfile").write_text("pipeline { agent any }")

        with patch("scripts.cli.wizard_flows.cicd_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = CICDFlow.__new__(CICDFlow)
            flow.detector = MockTargetDetector(repos=[tmp_path], images=[], iac=[])
            flow.prompter = MockPromptHelper()

            targets = flow.detect_targets()

            assert targets["jenkinsfile"] is not None
            assert targets["jenkinsfile"].name == "Jenkinsfile"


class TestCICDFlowDetectImagesFromCI:
    """Test CICDFlow._detect_images_from_ci method."""

    def test_extract_images_from_github_actions(self, tmp_path: Path) -> None:
        """Extracts container images from GitHub Actions workflows."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        workflow = tmp_path / "ci.yml"
        workflow.write_text(
            """
jobs:
  build:
    container: python:3.11
    steps:
      - uses: docker://node:18-alpine
        with:
          image: nginx:latest
"""
        )

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([workflow], None, None)

        assert "python:3.11" in images
        assert "nginx:latest" in images

    def test_extract_images_from_gitlab_ci(self, tmp_path: Path) -> None:
        """Extracts container images from GitLab CI config."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        gitlab_ci = tmp_path / ".gitlab-ci.yml"
        gitlab_ci.write_text(
            """
image: python:3.10

build:
  image: node:18
  script: npm build

test:
  image:
    name: postgres:15
  script: pytest
"""
        )

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([], gitlab_ci, None)

        assert "python:3.10" in images
        assert "node:18" in images
        assert "postgres:15" in images

    def test_extract_images_from_jenkinsfile(self, tmp_path: Path) -> None:
        """Extracts container images from Jenkinsfile."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        jenkinsfile = tmp_path / "Jenkinsfile"
        jenkinsfile.write_text(
            """
pipeline {
    agent {
        docker.image('maven:3.9-eclipse-temurin-17')
    }
    stages {
        stage('Build') {
            steps {
                docker.image("gradle:8-jdk17").inside {
                    sh 'gradle build'
                }
            }
        }
    }
}
"""
        )

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([], None, jenkinsfile)

        assert "maven:3.9-eclipse-temurin-17" in images
        assert "gradle:8-jdk17" in images

    def test_handles_missing_files_gracefully(self, tmp_path: Path) -> None:
        """Handles non-existent files without crashing."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        missing_file = tmp_path / "nonexistent.yml"

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([missing_file], None, None)

        assert images == []

    def test_handles_malformed_yaml(self, tmp_path: Path) -> None:
        """Handles malformed YAML gracefully."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        gitlab_ci = tmp_path / ".gitlab-ci.yml"
        gitlab_ci.write_text("{{invalid yaml: [")

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([], gitlab_ci, None)

        assert images == []

    def test_handles_non_dict_yaml(self, tmp_path: Path) -> None:
        """Handles YAML that doesn't parse to dict."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        gitlab_ci = tmp_path / ".gitlab-ci.yml"
        gitlab_ci.write_text("- item1\n- item2")  # List, not dict

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([], gitlab_ci, None)

        assert images == []  # Should not crash

    def test_deduplicates_images(self, tmp_path: Path) -> None:
        """Deduplicates images found in multiple places."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        workflow1 = tmp_path / "ci.yml"
        workflow1.write_text("container: python:3.11")
        workflow2 = tmp_path / "cd.yml"
        workflow2.write_text("container: python:3.11")

        flow = CICDFlow.__new__(CICDFlow)
        images = flow._detect_images_from_ci([workflow1, workflow2], None, None)

        # Should have python:3.11 only once
        assert images.count("python:3.11") == 1


class TestCICDFlowBuildCommand:
    """Test CICDFlow.build_command method."""

    def test_build_basic_ci_command(self) -> None:
        """Builds basic CI command with profile."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        flow = CICDFlow.__new__(CICDFlow)

        targets = {"repos": [Path("/repo")], "pipeline_images": []}
        options = {"profile": "fast", "scan_files": True, "scan_images": False}

        cmd = flow.build_command(targets, options)

        assert "jmo" in cmd
        assert "ci" in cmd
        assert "--profile" in cmd
        assert "fast" in cmd
        assert "--fail-on" in cmd
        assert "HIGH" in cmd
        assert "--repos-dir" in cmd

    def test_build_command_with_pipeline_images(self, tmp_path: Path) -> None:
        """Builds command with pipeline images file."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        # Need to change cwd for images file writing
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            flow = CICDFlow.__new__(CICDFlow)

            targets = {"repos": [], "pipeline_images": ["nginx:latest", "python:3.11"]}
            options = {
                "profile": "balanced",
                "scan_files": False,
                "scan_images": True,
            }

            cmd = flow.build_command(targets, options)

            assert "--images-file" in cmd
            assert "pipeline-images.txt" in cmd[-1]

            # Check the file was written
            images_file = tmp_path / "pipeline-images.txt"
            assert images_file.exists()
            content = images_file.read_text()
            assert "nginx:latest" in content
            assert "python:3.11" in content
        finally:
            os.chdir(original_cwd)


# =============================================================================
# DeploymentFlow Tests
# =============================================================================


class TestDeploymentFlowDetectEnvironment:
    """Test DeploymentFlow._detect_environment method."""

    def test_detect_production_from_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Detects production from ENVIRONMENT env var."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        monkeypatch.setenv("ENVIRONMENT", "production")

        flow = DeploymentFlow.__new__(DeploymentFlow)
        env = flow._detect_environment()

        assert env == "production"

    def test_detect_staging_from_node_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Detects staging from NODE_ENV env var."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        monkeypatch.delenv("ENVIRONMENT", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        monkeypatch.setenv("NODE_ENV", "staging")

        flow = DeploymentFlow.__new__(DeploymentFlow)
        env = flow._detect_environment()

        assert env == "staging"

    def test_detect_from_env_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Detects environment from .env file."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        # Clear env vars
        for var in ["ENVIRONMENT", "ENV", "NODE_ENV", "RAILS_ENV", "FLASK_ENV"]:
            monkeypatch.delenv(var, raising=False)

        env_file = tmp_path / ".env"
        env_file.write_text("ENVIRONMENT=production\nDEBUG=false")

        with patch("scripts.cli.wizard_flows.deployment_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = DeploymentFlow.__new__(DeploymentFlow)
            env = flow._detect_environment()

            assert env == "production"

    def test_detect_from_k8s_namespace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Detects environment from k8s namespace."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        for var in ["ENVIRONMENT", "ENV", "NODE_ENV", "RAILS_ENV", "FLASK_ENV"]:
            monkeypatch.delenv(var, raising=False)

        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yml").write_text(
            "namespace: production\nkind: Deployment"
        )

        with patch("scripts.cli.wizard_flows.deployment_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = DeploymentFlow.__new__(DeploymentFlow)
            env = flow._detect_environment()

            assert env == "production"

    def test_defaults_to_staging(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defaults to staging when no signals found."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        for var in ["ENVIRONMENT", "ENV", "NODE_ENV", "RAILS_ENV", "FLASK_ENV"]:
            monkeypatch.delenv(var, raising=False)

        with patch("scripts.cli.wizard_flows.deployment_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = DeploymentFlow.__new__(DeploymentFlow)
            env = flow._detect_environment()

            assert env == "staging"


class TestDeploymentFlowBuildCommand:
    """Test DeploymentFlow.build_command method."""

    def test_build_deployment_command(self) -> None:
        """Builds deployment command with all target types."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        flow = DeploymentFlow.__new__(DeploymentFlow)

        targets = {
            "images": ["nginx:latest", "api:v1", "db:prod"],
            "iac": [Path("/iac/main.tf"), Path("/iac/network.tf")],
            "web": ["https://app.example.com"],
        }
        options = {
            "environment": "production",
            "profile": "deep",
            "fail_on": "CRITICAL",
        }

        cmd = flow.build_command(targets, options)

        assert "jmo" in cmd
        assert "ci" in cmd
        assert "--profile" in cmd
        assert "deep" in cmd
        assert "--fail-on" in cmd
        assert "CRITICAL" in cmd
        # Should have images (limited to 3)
        assert cmd.count("--image") == 3
        # Should have IaC files
        assert "--terraform-state" in cmd
        # Should have web URL
        assert "--url" in cmd
        assert "https://app.example.com" in cmd


# =============================================================================
# DependencyFlow Tests
# =============================================================================


class TestDependencyFlowDetectTargets:
    """Test DependencyFlow.detect_targets method."""

    def test_detect_targets_delegates_to_detector(self) -> None:
        """Detects package files, lock files, and images via detector."""
        from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

        mock_detector = MockTargetDetector(
            package_files=[Path("package.json"), Path("requirements.txt")],
            lock_files=[Path("package-lock.json")],
            images=["python:3.11"],
        )

        flow = DependencyFlow.__new__(DependencyFlow)
        flow.detector = mock_detector
        flow.prompter = MockPromptHelper()

        targets = flow.detect_targets()

        assert len(targets["package_files"]) == 2
        assert len(targets["lock_files"]) == 1
        assert len(targets["images"]) == 1


class TestDependencyFlowBuildCommand:
    """Test DependencyFlow.build_command method."""

    def test_build_dependency_scan_command(self, tmp_path: Path) -> None:
        """Builds syft+trivy dependency scan command."""
        from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            flow = DependencyFlow.__new__(DependencyFlow)

            targets = {
                "images": ["python:3.11", "node:18"],
                "package_files": [],
                "lock_files": [],
            }
            options = {
                "generate_sbom": True,
                "scan_vulns": True,
                "check_licenses": False,
            }

            cmd = flow.build_command(targets, options)

            assert "jmo" in cmd
            assert "scan" in cmd
            assert "--tools" in cmd
            assert "syft" in cmd
            assert "trivy" in cmd
            assert "--repo" in cmd
            assert "--images-file" in cmd

            # Check images file was created
            images_file = tmp_path / "dependency-images.txt"
            assert images_file.exists()
        finally:
            os.chdir(original_cwd)

    def test_build_command_without_images(self, tmp_path: Path) -> None:
        """Builds command without images file when no images."""
        from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            flow = DependencyFlow.__new__(DependencyFlow)

            targets = {"images": [], "package_files": [], "lock_files": []}
            options = {
                "generate_sbom": True,
                "scan_vulns": True,
                "check_licenses": False,
            }

            cmd = flow.build_command(targets, options)

            assert "--images-file" not in cmd
        finally:
            os.chdir(original_cwd)


# =============================================================================
# EntireStackFlow Tests
# =============================================================================


class TestEntireStackFlowGenerateRecommendations:
    """Test EntireStackFlow._generate_recommendations method."""

    def test_recommends_docker_build_when_dockerfile_no_images(
        self, tmp_path: Path
    ) -> None:
        """Recommends building image when Dockerfile exists but no images."""
        from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

        (tmp_path / "Dockerfile").write_text("FROM python:3.11")

        with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = EntireStackFlow.__new__(EntireStackFlow)
            targets = {"images": [], "repos": [], "iac": [], "web": []}

            recs = flow._generate_recommendations(targets)

            assert any("docker build" in r.lower() for r in recs)

    def test_recommends_terraform_init_when_tf_dir_exists(self, tmp_path: Path) -> None:
        """Recommends terraform init when terraform/ exists but no IaC detected."""
        from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

        (tmp_path / "terraform").mkdir()

        with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = EntireStackFlow.__new__(EntireStackFlow)
            targets = {"images": [], "repos": [], "iac": [], "web": []}

            recs = flow._generate_recommendations(targets)

            assert any("terraform init" in r.lower() for r in recs)

    def test_recommends_k8s_context_when_k8s_dir_exists(self, tmp_path: Path) -> None:
        """Recommends k8s-context when kubernetes/ exists."""
        from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

        (tmp_path / "kubernetes").mkdir()

        with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = EntireStackFlow.__new__(EntireStackFlow)
            targets = {"images": [], "repos": [], "iac": [], "web": []}

            recs = flow._generate_recommendations(targets)

            assert any("--k8s-context" in r for r in recs)

    def test_recommends_cicd_when_github_workflows_exist(self, tmp_path: Path) -> None:
        """Recommends CI/CD audit when GitHub Actions workflows exist."""
        from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI")

        with patch("scripts.cli.wizard_flows.stack_flow.Path") as mock_path:
            mock_path.cwd.return_value = tmp_path

            flow = EntireStackFlow.__new__(EntireStackFlow)
            targets = {"images": [], "repos": [], "iac": [], "web": []}

            recs = flow._generate_recommendations(targets)

            assert any("ci/cd" in r.lower() for r in recs)


class TestEntireStackFlowBuildCommand:
    """Test EntireStackFlow.build_command method."""

    def test_build_full_stack_command(self, tmp_path: Path) -> None:
        """Builds command with all target types."""
        from scripts.cli.wizard_flows.stack_flow import EntireStackFlow

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            flow = EntireStackFlow.__new__(EntireStackFlow)

            targets = {
                "repos": [Path("/repo1")],
                "images": ["app:latest"],
                "iac": [Path("/iac/main.tf")],
                "web": ["https://app.example.com"],
            }
            options = {"profile": "balanced", "emit_artifacts": True, "parallel": True}

            cmd = flow.build_command(targets, options)

            assert "jmo" in cmd
            assert "scan" in cmd
            assert "--profile" in cmd
            assert "balanced" in cmd
            assert "--repos-dir" in cmd
            assert "--images-file" in cmd
            assert "--terraform-state" in cmd
            assert "--url" in cmd
        finally:
            os.chdir(original_cwd)


# =============================================================================
# RepoFlow Tests
# =============================================================================


class TestRepoFlowDetectTargets:
    """Test RepoFlow.detect_targets method."""

    def test_detect_targets_returns_repos(self) -> None:
        """Returns repos from detector."""
        from scripts.cli.wizard_flows.repo_flow import RepoFlow

        mock_detector = MockTargetDetector(repos=[Path("/repo1"), Path("/repo2")])

        flow = RepoFlow.__new__(RepoFlow)
        flow.detector = mock_detector
        flow.prompter = MockPromptHelper()

        targets = flow.detect_targets()

        assert "repos" in targets
        assert len(targets["repos"]) == 2


class TestRepoFlowBuildCommand:
    """Test RepoFlow.build_command method."""

    def test_build_repo_scan_command(self) -> None:
        """Builds command for single repo scan."""
        from scripts.cli.wizard_flows.repo_flow import RepoFlow

        flow = RepoFlow.__new__(RepoFlow)

        targets = {"repos": [Path("/my-project")]}
        options = {"profile": "deep", "emit_artifacts": True}

        cmd = flow.build_command(targets, options)

        assert "jmo" in cmd
        assert "scan" in cmd
        assert "--profile" in cmd
        assert "deep" in cmd
        assert "--repo" in cmd

    def test_build_command_without_repos(self) -> None:
        """Builds command even when no repos detected."""
        from scripts.cli.wizard_flows.repo_flow import RepoFlow

        flow = RepoFlow.__new__(RepoFlow)

        targets = {"repos": []}
        options = {"profile": "fast", "emit_artifacts": False}

        cmd = flow.build_command(targets, options)

        assert "jmo" in cmd
        assert "scan" in cmd
        assert "--repo" not in cmd


# =============================================================================
# Print Method Tests (Coverage for display methods)
# =============================================================================


class TestCICDFlowPrintMethods:
    """Test CICDFlow display methods for coverage."""

    def test_print_detected_pipelines_with_all_types(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Prints summary when all pipeline types detected."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        flow = CICDFlow.__new__(CICDFlow)
        flow.prompter = MockPromptHelper()

        targets = {
            "github_actions": [
                Path("ci.yml"),
                Path("cd.yml"),
                Path("release.yml"),
                Path("extra.yml"),
            ],
            "gitlab_ci": Path(".gitlab-ci.yml"),
            "jenkinsfile": Path("Jenkinsfile"),
            "pipeline_images": ["nginx:latest", "python:3.11"],
        }

        # Should not raise
        flow._print_detected_pipelines(targets)

    def test_print_detected_pipelines_empty(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Prints warning when no pipelines detected."""
        from scripts.cli.wizard_flows.cicd_flow import CICDFlow

        flow = CICDFlow.__new__(CICDFlow)
        flow.prompter = MockPromptHelper()

        targets = {
            "github_actions": [],
            "gitlab_ci": None,
            "jenkinsfile": None,
            "pipeline_images": [],
        }

        # Should not raise
        flow._print_detected_pipelines(targets)


class TestDeploymentFlowPrintMethods:
    """Test DeploymentFlow display methods for coverage."""

    def test_print_detected_deployment_targets_with_all_types(self) -> None:
        """Prints summary when all target types detected."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        flow = DeploymentFlow.__new__(DeploymentFlow)
        flow.prompter = MockPromptHelper()

        targets = {
            "images": ["nginx:latest", "api:v1", "db:prod", "cache:latest"],
            "iac": [
                Path("main.tf"),
                Path("network.tf"),
                Path("storage.tf"),
                Path("extra.tf"),
            ],
            "web": ["https://app.example.com", "https://api.example.com"],
        }

        # Should not raise
        flow._print_detected_deployment_targets(targets)

    def test_print_detected_deployment_targets_empty(self) -> None:
        """Prints warning when no targets detected."""
        from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

        flow = DeploymentFlow.__new__(DeploymentFlow)
        flow.prompter = MockPromptHelper()

        targets = {"images": [], "iac": [], "web": []}

        # Should not raise
        flow._print_detected_deployment_targets(targets)


class TestDependencyFlowPrintMethods:
    """Test DependencyFlow display methods for coverage."""

    def test_print_detected_dependencies_with_all_types(self) -> None:
        """Prints summary when all dependency types detected."""
        from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

        flow = DependencyFlow.__new__(DependencyFlow)
        flow.prompter = MockPromptHelper()

        targets = {
            "package_files": [
                Path("package.json"),
                Path("requirements.txt"),
                Path("go.mod"),
                Path("Cargo.toml"),
                Path("pom.xml"),
                Path("extra.txt"),
            ],
            "lock_files": [
                Path("package-lock.json"),
                Path("poetry.lock"),
                Path("Cargo.lock"),
                Path("extra.lock"),
            ],
            "images": ["python:3.11"],
        }

        # Should not raise
        flow._print_detected_dependencies(targets)

    def test_print_detected_dependencies_empty(self) -> None:
        """Prints warning when no dependencies detected."""
        from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

        flow = DependencyFlow.__new__(DependencyFlow)
        flow.prompter = MockPromptHelper()

        targets = {"package_files": [], "lock_files": [], "images": []}

        # Should not raise
        flow._print_detected_dependencies(targets)


class TestRepoFlowPrintMethods:
    """Test RepoFlow display methods for coverage."""

    def test_print_detected_repos_with_repos(self) -> None:
        """Prints summary when repos detected."""
        from scripts.cli.wizard_flows.repo_flow import RepoFlow

        flow = RepoFlow.__new__(RepoFlow)
        flow.prompter = MockPromptHelper()

        targets = {
            "repos": [
                Path("repo1"),
                Path("repo2"),
                Path("repo3"),
                Path("repo4"),
                Path("repo5"),
                Path("repo6"),
            ]
        }

        # Should not raise
        flow._print_detected_repos(targets)

    def test_print_detected_repos_empty(self) -> None:
        """Prints warning when no repos detected."""
        from scripts.cli.wizard_flows.repo_flow import RepoFlow

        flow = RepoFlow.__new__(RepoFlow)
        flow.prompter = MockPromptHelper()

        targets = {"repos": []}

        # Should not raise
        flow._print_detected_repos(targets)
