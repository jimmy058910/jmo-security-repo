"""Unit tests for wizard_flows/base_flow.py - TargetDetector methods.

TASK-038: Cover TargetDetector methods (detect_repos, detect_images, detect_iac,
detect_web_apps, detect_package_files, detect_lock_files) with unit tests.
"""

from pathlib import Path
from unittest.mock import patch

from scripts.cli.wizard_flows.base_flow import (
    TargetDetector,
    PromptHelper,
    ArtifactGenerator,
    _get_terminal_width,
    _supports_ansi,
)


class TestTargetDetectorDetectRepos:
    """Tests for TargetDetector.detect_repos()."""

    def test_detect_repos_finds_git_repos(self, tmp_path: Path) -> None:
        """Should detect directories containing .git folders."""
        # Create repo1 with .git
        repo1 = tmp_path / "repo1"
        repo1.mkdir()
        (repo1 / ".git").mkdir()

        # Create repo2 with .git
        repo2 = tmp_path / "repo2"
        repo2.mkdir()
        (repo2 / ".git").mkdir()

        # Create non-repo directory (no .git)
        non_repo = tmp_path / "non_repo"
        non_repo.mkdir()

        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)

        assert len(repos) == 2
        assert repo1 in repos
        assert repo2 in repos
        assert non_repo not in repos

    def test_detect_repos_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list for directory with no git repos."""
        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)
        assert repos == []

    def test_detect_repos_nonexistent_directory(self, tmp_path: Path) -> None:
        """Should return empty list for non-existent directory."""
        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path / "nonexistent")
        assert repos == []

    def test_detect_repos_default_to_cwd(self, tmp_path: Path) -> None:
        """Should use current working directory when search_dir is None."""
        # Create repo in tmp_path
        repo = tmp_path / "my_repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        detector = TargetDetector()
        with patch.object(Path, "cwd", return_value=tmp_path):
            repos = detector.detect_repos(None)

        assert len(repos) == 1
        assert repo in repos

    def test_detect_repos_ignores_files(self, tmp_path: Path) -> None:
        """Should only detect directories, not files."""
        # Create a file named .git (not a directory)
        (tmp_path / ".git").write_text("not a directory")

        # Create a file named repo (not a directory)
        (tmp_path / "repo").write_text("file not dir")

        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)
        assert repos == []


class TestTargetDetectorDetectImages:
    """Tests for TargetDetector.detect_images()."""

    def test_detect_images_from_docker_compose(self, tmp_path: Path) -> None:
        """Should extract image names from docker-compose.yml."""
        compose_content = """
services:
  web:
    image: nginx:latest
  db:
    image: postgres:15
  app:
    build: .
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert "nginx:latest" in images
        assert "postgres:15" in images
        assert len(images) == 2  # 'app' has build, not image

    def test_detect_images_from_dockerfile(self, tmp_path: Path) -> None:
        """Should extract FROM images from Dockerfiles."""
        dockerfile_content = """FROM python:3.11-slim AS builder
RUN pip install deps
FROM python:3.11-alpine
COPY --from=builder /app /app
"""
        (tmp_path / "Dockerfile").write_text(dockerfile_content)

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert "python:3.11-slim" in images
        assert "python:3.11-alpine" in images

    def test_detect_images_from_dockerfile_variants(self, tmp_path: Path) -> None:
        """Should detect Dockerfile.dev, Dockerfile.prod, etc."""
        (tmp_path / "Dockerfile.dev").write_text("FROM node:18-alpine")
        (tmp_path / "Dockerfile.prod").write_text("FROM node:18-slim")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert "node:18-alpine" in images
        assert "node:18-slim" in images

    def test_detect_images_combined_sources(self, tmp_path: Path) -> None:
        """Should combine images from docker-compose and Dockerfiles."""
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx:latest"
        )
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:22.04")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert "nginx:latest" in images
        assert "ubuntu:22.04" in images

    def test_detect_images_deduplicates(self, tmp_path: Path) -> None:
        """Should deduplicate identical images."""
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx:latest"
        )
        (tmp_path / "Dockerfile").write_text("FROM nginx:latest")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        # Should have only one nginx:latest
        assert images.count("nginx:latest") == 1

    def test_detect_images_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list when no docker files exist."""
        detector = TargetDetector()
        images = detector.detect_images(tmp_path)
        assert images == []

    def test_detect_images_malformed_docker_compose(self, tmp_path: Path) -> None:
        """Should handle malformed docker-compose.yml gracefully."""
        (tmp_path / "docker-compose.yml").write_text("not: valid: yaml: content: :")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)
        assert images == []

    def test_detect_images_docker_compose_missing_services(
        self, tmp_path: Path
    ) -> None:
        """Should handle docker-compose.yml without services key."""
        (tmp_path / "docker-compose.yml").write_text("version: '3'")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)
        assert images == []

    def test_detect_images_nested_dockerfiles(self, tmp_path: Path) -> None:
        """Should find Dockerfiles in subdirectories."""
        subdir = tmp_path / "services" / "api"
        subdir.mkdir(parents=True)
        (subdir / "Dockerfile").write_text("FROM golang:1.21")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)
        assert "golang:1.21" in images

    def test_detect_images_default_to_cwd(self, tmp_path: Path) -> None:
        """Should use current working directory when search_dir is None."""
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.18")

        detector = TargetDetector()
        with patch.object(Path, "cwd", return_value=tmp_path):
            images = detector.detect_images(None)

        assert "alpine:3.18" in images


class TestTargetDetectorDetectIac:
    """Tests for TargetDetector.detect_iac()."""

    def test_detect_iac_terraform_files(self, tmp_path: Path) -> None:
        """Should detect .tf and .tfstate files."""
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "bucket" {}')
        (tmp_path / "terraform.tfstate").write_text("{}")

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        tf_names = [f.name for f in iac_files]
        assert "main.tf" in tf_names
        assert "terraform.tfstate" in tf_names

    def test_detect_iac_cloudformation_files(self, tmp_path: Path) -> None:
        """Should detect CloudFormation YAML files."""
        (tmp_path / "cloudformation.yml").write_text("AWSTemplateFormatVersion: 2010")
        (tmp_path / "my-cloudformation-stack.yaml").write_text("Resources:")

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        cf_names = [f.name for f in iac_files]
        assert "cloudformation.yml" in cf_names
        assert "my-cloudformation-stack.yaml" in cf_names

    def test_detect_iac_kubernetes_files(self, tmp_path: Path) -> None:
        """Should detect Kubernetes manifest files in k8s/ and kubernetes/ dirs."""
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yml").write_text("apiVersion: apps/v1")

        kubernetes_dir = tmp_path / "kubernetes"
        kubernetes_dir.mkdir()
        (kubernetes_dir / "service.yml").write_text("apiVersion: v1")

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        iac_names = [f.name for f in iac_files]
        assert "deployment.yml" in iac_names
        assert "service.yml" in iac_names

    def test_detect_iac_nested_terraform(self, tmp_path: Path) -> None:
        """Should find Terraform files in subdirectories."""
        modules_dir = tmp_path / "modules" / "vpc"
        modules_dir.mkdir(parents=True)
        (modules_dir / "main.tf").write_text('resource "aws_vpc" "main" {}')

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        assert any(f.name == "main.tf" for f in iac_files)

    def test_detect_iac_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list when no IaC files exist."""
        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)
        assert iac_files == []

    def test_detect_iac_default_to_cwd(self, tmp_path: Path) -> None:
        """Should use current working directory when search_dir is None."""
        (tmp_path / "main.tf").write_text('provider "aws" {}')

        detector = TargetDetector()
        with patch.object(Path, "cwd", return_value=tmp_path):
            iac_files = detector.detect_iac(None)

        assert any(f.name == "main.tf" for f in iac_files)


class TestTargetDetectorDetectWebApps:
    """Tests for TargetDetector.detect_web_apps()."""

    def test_detect_web_apps_from_docker_compose_ports(self, tmp_path: Path) -> None:
        """Should infer URLs from docker-compose port mappings."""
        compose_content = """
services:
  frontend:
    ports:
      - "8080:80"
  api:
    ports:
      - "3000:3000"
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert "http://localhost:8080" in urls
        assert "http://localhost:3000" in urls

    def test_detect_web_apps_from_package_json(self, tmp_path: Path) -> None:
        """Should detect React/Next.js default port from package.json."""
        (tmp_path / "package.json").write_text('{"name": "my-app"}')

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert "http://localhost:3000" in urls

    def test_detect_web_apps_deduplicates(self, tmp_path: Path) -> None:
        """Should deduplicate URLs."""
        compose_content = """
services:
  app:
    ports:
      - "3000:3000"
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)
        (tmp_path / "package.json").write_text("{}")

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        # Both sources suggest 3000, should only appear once
        assert urls.count("http://localhost:3000") == 1

    def test_detect_web_apps_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list when no web apps detected."""
        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)
        assert urls == []

    def test_detect_web_apps_malformed_compose(self, tmp_path: Path) -> None:
        """Should handle malformed docker-compose.yml gracefully."""
        (tmp_path / "docker-compose.yml").write_text("{{{{invalid")

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)
        # Should not crash, just return empty or partial results
        assert isinstance(urls, list)

    def test_detect_web_apps_default_to_cwd(self, tmp_path: Path) -> None:
        """Should use current working directory when search_dir is None."""
        (tmp_path / "package.json").write_text("{}")

        detector = TargetDetector()
        with patch.object(Path, "cwd", return_value=tmp_path):
            urls = detector.detect_web_apps(None)

        assert "http://localhost:3000" in urls


class TestTargetDetectorDetectPackageFiles:
    """Tests for TargetDetector.detect_package_files()."""

    def test_detect_package_files_python(self, tmp_path: Path) -> None:
        """Should detect Python package files."""
        (tmp_path / "requirements.txt").write_text("requests==2.28.0")
        (tmp_path / "pyproject.toml").write_text("[project]")
        (tmp_path / "setup.py").write_text("from setuptools import setup")
        (tmp_path / "Pipfile").write_text("[packages]")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "requirements.txt" in names
        assert "pyproject.toml" in names
        assert "setup.py" in names
        assert "Pipfile" in names

    def test_detect_package_files_javascript(self, tmp_path: Path) -> None:
        """Should detect JavaScript/Node.js package files."""
        (tmp_path / "package.json").write_text("{}")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "package.json" in names

    def test_detect_package_files_go(self, tmp_path: Path) -> None:
        """Should detect Go module files."""
        (tmp_path / "go.mod").write_text("module example.com/mymodule")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "go.mod" in names

    def test_detect_package_files_rust(self, tmp_path: Path) -> None:
        """Should detect Rust package files."""
        (tmp_path / "Cargo.toml").write_text("[package]")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "Cargo.toml" in names

    def test_detect_package_files_java_maven(self, tmp_path: Path) -> None:
        """Should detect Maven pom.xml files."""
        (tmp_path / "pom.xml").write_text("<project></project>")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "pom.xml" in names

    def test_detect_package_files_java_gradle(self, tmp_path: Path) -> None:
        """Should detect Gradle build files."""
        (tmp_path / "build.gradle").write_text("plugins {}")
        (tmp_path / "build.gradle.kts").write_text("plugins {}")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "build.gradle" in names
        assert "build.gradle.kts" in names

    def test_detect_package_files_ruby(self, tmp_path: Path) -> None:
        """Should detect Ruby Gemfile."""
        (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "Gemfile" in names

    def test_detect_package_files_dotnet(self, tmp_path: Path) -> None:
        """Should detect .NET project files."""
        (tmp_path / "MyProject.csproj").write_text("<Project></Project>")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        names = [f.name for f in files]

        assert "MyProject.csproj" in names

    def test_detect_package_files_nested(self, tmp_path: Path) -> None:
        """Should find package files in subdirectories."""
        subdir = tmp_path / "services" / "api"
        subdir.mkdir(parents=True)
        (subdir / "requirements.txt").write_text("flask")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)

        assert any(f.name == "requirements.txt" for f in files)

    def test_detect_package_files_deduplicates(self, tmp_path: Path) -> None:
        """Should deduplicate package files."""
        (tmp_path / "requirements.txt").write_text("requests")

        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)

        # Same file should only appear once
        req_files = [f for f in files if f.name == "requirements.txt"]
        assert len(req_files) == 1

    def test_detect_package_files_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list when no package files exist."""
        detector = TargetDetector()
        files = detector.detect_package_files(tmp_path)
        assert files == []

    def test_detect_package_files_default_to_cwd(self, tmp_path: Path) -> None:
        """Should use current working directory when search_dir is None."""
        (tmp_path / "package.json").write_text("{}")

        detector = TargetDetector()
        with patch.object(Path, "cwd", return_value=tmp_path):
            files = detector.detect_package_files(None)

        assert any(f.name == "package.json" for f in files)


class TestTargetDetectorDetectLockFiles:
    """Tests for TargetDetector.detect_lock_files()."""

    def test_detect_lock_files_python(self, tmp_path: Path) -> None:
        """Should detect Python lock files."""
        (tmp_path / "requirements-lock.txt").write_text("requests==2.28.0")
        (tmp_path / "poetry.lock").write_text("[[package]]")
        (tmp_path / "Pipfile.lock").write_text("{}")

        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)
        names = [f.name for f in files]

        assert "requirements-lock.txt" in names
        assert "poetry.lock" in names
        assert "Pipfile.lock" in names

    def test_detect_lock_files_javascript(self, tmp_path: Path) -> None:
        """Should detect JavaScript lock files."""
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "yarn.lock").write_text("# yarn")
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: 5.4")

        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)
        names = [f.name for f in files]

        assert "package-lock.json" in names
        assert "yarn.lock" in names
        assert "pnpm-lock.yaml" in names

    def test_detect_lock_files_go(self, tmp_path: Path) -> None:
        """Should detect Go sum file."""
        (tmp_path / "go.sum").write_text("github.com/pkg/errors v0.9.1")

        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)
        names = [f.name for f in files]

        assert "go.sum" in names

    def test_detect_lock_files_rust(self, tmp_path: Path) -> None:
        """Should detect Rust Cargo.lock."""
        (tmp_path / "Cargo.lock").write_text("[[package]]")

        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)
        names = [f.name for f in files]

        assert "Cargo.lock" in names

    def test_detect_lock_files_ruby(self, tmp_path: Path) -> None:
        """Should detect Ruby Gemfile.lock."""
        (tmp_path / "Gemfile.lock").write_text("GEM\n  remote:")

        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)
        names = [f.name for f in files]

        assert "Gemfile.lock" in names

    def test_detect_lock_files_nested(self, tmp_path: Path) -> None:
        """Should find lock files in subdirectories."""
        subdir = tmp_path / "frontend"
        subdir.mkdir()
        (subdir / "package-lock.json").write_text("{}")

        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)

        assert any(f.name == "package-lock.json" for f in files)

    def test_detect_lock_files_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list when no lock files exist."""
        detector = TargetDetector()
        files = detector.detect_lock_files(tmp_path)
        assert files == []

    def test_detect_lock_files_default_to_cwd(self, tmp_path: Path) -> None:
        """Should use current working directory when search_dir is None."""
        (tmp_path / "poetry.lock").write_text("[[package]]")

        detector = TargetDetector()
        with patch.object(Path, "cwd", return_value=tmp_path):
            files = detector.detect_lock_files(None)

        assert any(f.name == "poetry.lock" for f in files)


class TestPromptHelperColorize:
    """Tests for PromptHelper.colorize()."""

    def test_colorize_respects_no_color_env(self, monkeypatch) -> None:
        """Should return plain text when NO_COLOR is set."""
        monkeypatch.setenv("NO_COLOR", "1")
        helper = PromptHelper()
        result = helper.colorize("test", "red")
        assert result == "test"
        assert "\x1b[" not in result

    def test_colorize_returns_colored_when_supported(self, monkeypatch) -> None:
        """Should return colored text when ANSI is supported."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        # Patch the module-level flag
        import scripts.cli.wizard_flows.base_flow as base_flow_module

        original_flag = base_flow_module._ANSI_SUPPORTED
        try:
            base_flow_module._ANSI_SUPPORTED = True
            helper = PromptHelper()
            result = helper.colorize("test", "red")
            assert "\x1b[31m" in result  # Red code
            assert "\x1b[0m" in result  # Reset code
        finally:
            base_flow_module._ANSI_SUPPORTED = original_flag


class TestPromptHelperPrintMethods:
    """Tests for PromptHelper print methods (output assertions)."""

    def test_print_header_outputs_box(self, capsys) -> None:
        """Should print a formatted header box."""
        helper = PromptHelper()
        helper.print_header("Test Header", icon="star")
        captured = capsys.readouterr()
        assert "Test Header" in captured.out
        assert (
            "★" in captured.out
            or "star" in captured.out.lower()
            or "Header" in captured.out
        )

    def test_print_step_outputs_progress(self, capsys) -> None:
        """Should print step indicator with progress."""
        helper = PromptHelper()
        helper.print_step(1, 5, "Testing step")
        captured = capsys.readouterr()
        assert "Step 1/5" in captured.out
        assert "Testing step" in captured.out

    def test_print_success_outputs_message(self, capsys) -> None:
        """Should print success message."""
        helper = PromptHelper()
        helper.print_success("Operation completed")
        captured = capsys.readouterr()
        assert "Operation completed" in captured.out

    def test_print_info_outputs_message(self, capsys) -> None:
        """Should print info message."""
        helper = PromptHelper()
        helper.print_info("Information message")
        captured = capsys.readouterr()
        assert "Information message" in captured.out

    def test_print_warning_outputs_message(self, capsys) -> None:
        """Should print warning message."""
        helper = PromptHelper()
        helper.print_warning("Warning message")
        captured = capsys.readouterr()
        assert "Warning message" in captured.out

    def test_print_error_outputs_message(self, capsys) -> None:
        """Should print error message."""
        helper = PromptHelper()
        helper.print_error("Error message")
        captured = capsys.readouterr()
        assert "Error message" in captured.out

    def test_print_summary_box_outputs_items(self, capsys) -> None:
        """Should print summary box with items."""
        helper = PromptHelper()
        helper.print_summary_box("Summary", ["Item 1", "Item 2", "Item 3"])
        captured = capsys.readouterr()
        assert "Summary" in captured.out
        assert "Item 1" in captured.out
        assert "Item 2" in captured.out
        assert "Item 3" in captured.out


class TestArtifactGenerator:
    """Tests for ArtifactGenerator wrapper methods."""

    def test_generate_makefile_calls_wizard_generators(self, tmp_path: Path) -> None:
        """Should call wizard_generators.generate_makefile_target."""
        output_path = tmp_path / "Makefile"
        command = ["jmo", "scan", "--profile", "balanced"]

        generator = ArtifactGenerator()
        with patch(
            "scripts.cli.wizard_generators.generate_makefile_target"
        ) as mock_gen:
            generator.generate_makefile(command, output_path)
            mock_gen.assert_called_once_with(command, output_path)

    def test_generate_github_actions_calls_wizard_generators(
        self, tmp_path: Path
    ) -> None:
        """Should call wizard_generators.generate_github_actions."""
        output_path = tmp_path / ".github" / "workflows" / "security.yml"
        command = ["jmo", "scan", "--profile", "fast"]

        generator = ArtifactGenerator()
        with patch("scripts.cli.wizard_generators.generate_github_actions") as mock_gen:
            generator.generate_github_actions(command, output_path)
            mock_gen.assert_called_once_with(command, output_path)

    def test_generate_shell_script_calls_wizard_generators(
        self, tmp_path: Path
    ) -> None:
        """Should call wizard_generators.generate_shell_script."""
        output_path = tmp_path / "scan.sh"
        command = ["jmo", "scan", "--repo", "."]

        generator = ArtifactGenerator()
        with patch("scripts.cli.wizard_generators.generate_shell_script") as mock_gen:
            generator.generate_shell_script(command, output_path)
            mock_gen.assert_called_once_with(command, output_path)


class TestTerminalUtilities:
    """Tests for terminal utility functions."""

    def test_get_terminal_width_returns_valid_range(self) -> None:
        """Should return width between 40 and 120."""
        width = _get_terminal_width()
        assert 40 <= width <= 120

    def test_get_terminal_width_handles_exception(self, monkeypatch) -> None:
        """Should return 80 when terminal size cannot be determined."""
        # Patch at the module level where _get_terminal_width uses shutil
        import scripts.cli.wizard_flows.base_flow as base_flow_module

        original_get_terminal_size = base_flow_module.shutil.get_terminal_size

        def raise_error(*args, **kwargs):
            raise OSError("No terminal")

        monkeypatch.setattr(base_flow_module.shutil, "get_terminal_size", raise_error)
        try:
            width = _get_terminal_width()
            assert width == 80
        finally:
            # Restore original to avoid affecting other tests
            base_flow_module.shutil.get_terminal_size = original_get_terminal_size

    def test_supports_ansi_respects_no_color(self, monkeypatch) -> None:
        """Should return False when NO_COLOR is set."""
        monkeypatch.setenv("NO_COLOR", "1")
        # _supports_ansi is computed at import time, so we need to call it directly
        # but we can test the logic by checking the function behavior
        assert _supports_ansi() is False

    def test_supports_ansi_detects_windows_terminal(self, monkeypatch) -> None:
        """Should return True for Windows Terminal (WT_SESSION set)."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("WT_SESSION", "some-guid")
        assert _supports_ansi() is True

    def test_supports_ansi_detects_xterm(self, monkeypatch) -> None:
        """Should return True for xterm-256color."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("WT_SESSION", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        assert _supports_ansi() is True
