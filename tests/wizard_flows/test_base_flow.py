"""Tests for base wizard flow components."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from scripts.cli.wizard_flows.base_flow import (
    ArtifactGenerator,
    BaseWizardFlow,
    PromptHelper,
    TargetDetector,
)


class TestTargetDetector:
    """Tests for TargetDetector class."""

    def test_detect_repos_in_directory(self, tmp_path):
        """Test detecting Git repositories in a directory."""
        # Create mock repos
        repo1 = tmp_path / "repo1"
        repo1.mkdir()
        (repo1 / ".git").mkdir()

        repo2 = tmp_path / "repo2"
        repo2.mkdir()
        (repo2 / ".git").mkdir()

        # Create non-repo directory
        not_repo = tmp_path / "not_repo"
        not_repo.mkdir()

        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)

        assert len(repos) == 2
        assert repo1 in repos
        assert repo2 in repos
        assert not_repo not in repos

    def test_detect_repos_current_directory(self):
        """Test detecting repos in current directory when no path provided."""
        detector = TargetDetector()
        with patch("pathlib.Path.cwd") as mock_cwd:
            mock_cwd.return_value = Path("/fake/path")
            with patch.object(Path, "exists", return_value=False):
                repos = detector.detect_repos()
                assert repos == []

    def test_detect_repos_nonexistent_directory(self):
        """Test detecting repos in nonexistent directory."""
        detector = TargetDetector()
        repos = detector.detect_repos(Path("/nonexistent/path"))
        assert repos == []

    def test_detect_images_from_docker_compose(self, tmp_path):
        """Test detecting images from docker-compose.yml."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(
            """
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
"""
        )

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert "nginx:latest" in images
        assert "postgres:14" in images
        assert len(images) == 2

    def test_detect_images_from_dockerfile(self, tmp_path):
        """Test detecting images from Dockerfile."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            """
FROM python:3.11-slim
FROM alpine:latest AS builder
"""
        )

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert "python:3.11-slim" in images
        assert "alpine:latest" in images

    def test_detect_images_deduplication(self, tmp_path):
        """Test that duplicate images are deduplicated."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(
            """
services:
  web1:
    image: nginx:latest
  web2:
    image: nginx:latest
"""
        )

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert images.count("nginx:latest") == 1

    def test_detect_images_invalid_yaml(self, tmp_path):
        """Test handling invalid docker-compose.yml."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("invalid: yaml: content:")

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)
        # Should handle gracefully, return empty or partial results
        assert isinstance(images, list)

    def test_detect_iac_terraform_files(self, tmp_path):
        """Test detecting Terraform files."""
        (tmp_path / "main.tf").touch()
        (tmp_path / "variables.tf").touch()
        (tmp_path / "terraform.tfstate").touch()

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        assert len(iac_files) == 3
        assert any(f.name == "main.tf" for f in iac_files)
        assert any(f.name == "terraform.tfstate" for f in iac_files)

    def test_detect_iac_cloudformation_files(self, tmp_path):
        """Test detecting CloudFormation files."""
        (tmp_path / "stack-cloudformation.yml").touch()
        (tmp_path / "template-cloudformation.yaml").touch()

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        assert len(iac_files) == 2
        assert any("cloudformation" in f.name for f in iac_files)

    def test_detect_iac_kubernetes_files(self, tmp_path):
        """Test detecting Kubernetes manifests."""
        k8s_dir = tmp_path / "k8s"
        k8s_dir.mkdir()
        (k8s_dir / "deployment.yml").touch()
        (k8s_dir / "service.yml").touch()

        kubernetes_dir = tmp_path / "kubernetes"
        kubernetes_dir.mkdir()
        (kubernetes_dir / "ingress.yml").touch()

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        assert len(iac_files) == 3

    def test_detect_web_apps_from_docker_compose_ports(self, tmp_path):
        """Test detecting web apps from docker-compose.yml ports."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(
            """
services:
  web:
    ports:
      - "8080:80"
      - "443:443"
"""
        )

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert "http://localhost:8080" in urls
        assert "http://localhost:443" in urls

    def test_detect_web_apps_from_package_json(self, tmp_path):
        """Test detecting web apps from package.json."""
        (tmp_path / "package.json").write_text('{"name": "my-app"}')

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert "http://localhost:3000" in urls

    def test_detect_web_apps_deduplication(self, tmp_path):
        """Test that duplicate URLs are deduplicated."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(
            """
services:
  web1:
    ports:
      - "3000:80"
  web2:
    ports:
      - "3000:80"
"""
        )

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert urls.count("http://localhost:3000") == 1

    def test_detect_package_files_python(self, tmp_path):
        """Test detecting Python package files."""
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "setup.py").touch()
        (tmp_path / "Pipfile").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 4
        assert any(f.name == "requirements.txt" for f in package_files)
        assert any(f.name == "pyproject.toml" for f in package_files)

    def test_detect_package_files_javascript(self, tmp_path):
        """Test detecting JavaScript package files."""
        (tmp_path / "package.json").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert any(f.name == "package.json" for f in package_files)

    def test_detect_package_files_go(self, tmp_path):
        """Test detecting Go package files."""
        (tmp_path / "go.mod").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert any(f.name == "go.mod" for f in package_files)

    def test_detect_package_files_rust(self, tmp_path):
        """Test detecting Rust package files."""
        (tmp_path / "Cargo.toml").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert any(f.name == "Cargo.toml" for f in package_files)

    def test_detect_package_files_java_maven(self, tmp_path):
        """Test detecting Maven package files."""
        (tmp_path / "pom.xml").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert any(f.name == "pom.xml" for f in package_files)

    def test_detect_package_files_java_gradle(self, tmp_path):
        """Test detecting Gradle package files."""
        (tmp_path / "build.gradle").touch()
        (tmp_path / "build.gradle.kts").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 2
        assert any(f.name == "build.gradle" for f in package_files)

    def test_detect_package_files_ruby(self, tmp_path):
        """Test detecting Ruby package files."""
        (tmp_path / "Gemfile").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert any(f.name == "Gemfile" for f in package_files)

    def test_detect_package_files_dotnet(self, tmp_path):
        """Test detecting .NET package files."""
        (tmp_path / "MyProject.csproj").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert any(f.name.endswith(".csproj") for f in package_files)

    def test_detect_package_files_deduplication(self, tmp_path):
        """Test that duplicate package files are deduplicated."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (tmp_path / "requirements.txt").touch()
        (subdir / "requirements.txt").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        # Should deduplicate
        assert len(package_files) == len(set(package_files))

    def test_detect_lock_files_python(self, tmp_path):
        """Test detecting Python lock files."""
        (tmp_path / "poetry.lock").touch()
        (tmp_path / "Pipfile.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 2
        assert any(f.name == "poetry.lock" for f in lock_files)
        assert any(f.name == "Pipfile.lock" for f in lock_files)

    def test_detect_lock_files_javascript(self, tmp_path):
        """Test detecting JavaScript lock files."""
        (tmp_path / "package-lock.json").touch()
        (tmp_path / "yarn.lock").touch()
        (tmp_path / "pnpm-lock.yaml").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 3
        assert any(f.name == "package-lock.json" for f in lock_files)
        assert any(f.name == "yarn.lock" for f in lock_files)
        assert any(f.name == "pnpm-lock.yaml" for f in lock_files)

    def test_detect_lock_files_go(self, tmp_path):
        """Test detecting Go lock files."""
        (tmp_path / "go.sum").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 1
        assert any(f.name == "go.sum" for f in lock_files)

    def test_detect_lock_files_rust(self, tmp_path):
        """Test detecting Rust lock files."""
        (tmp_path / "Cargo.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 1
        assert any(f.name == "Cargo.lock" for f in lock_files)

    def test_detect_lock_files_ruby(self, tmp_path):
        """Test detecting Ruby lock files."""
        (tmp_path / "Gemfile.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 1
        assert any(f.name == "Gemfile.lock" for f in lock_files)


class TestPromptHelper:
    """Tests for PromptHelper class."""

    def test_colorize(self):
        """Test colorizing text."""
        helper = PromptHelper()
        colored = helper.colorize("test", "blue")

        assert "\x1b[36m" in colored  # Blue color code
        assert "\x1b[0m" in colored  # Reset code
        assert "test" in colored

    def test_colorize_invalid_color(self):
        """Test colorizing with invalid color."""
        helper = PromptHelper()
        colored = helper.colorize("test", "invalid_color")

        # Should still reset
        assert "\x1b[0m" in colored
        assert "test" in colored

    def test_print_header(self, capsys):
        """Test printing header."""
        helper = PromptHelper()
        helper.print_header("Test Header", icon="rocket")

        captured = capsys.readouterr()
        assert "Test Header" in captured.out
        assert "╔" in captured.out
        assert "╚" in captured.out

    def test_print_step(self, capsys):
        """Test printing step indicator."""
        helper = PromptHelper()
        helper.print_step(2, 5, "Processing data")

        captured = capsys.readouterr()
        assert "[Step 2/5]" in captured.out
        assert "Processing data" in captured.out
        assert "40%" in captured.out  # (2/5) * 100

    def test_print_success(self, capsys):
        """Test printing success message."""
        helper = PromptHelper()
        helper.print_success("Operation completed")

        captured = capsys.readouterr()
        assert "Operation completed" in captured.out
        assert helper.ICONS["success"] in captured.out

    def test_print_info(self, capsys):
        """Test printing info message."""
        helper = PromptHelper()
        helper.print_info("Information message")

        captured = capsys.readouterr()
        assert "Information message" in captured.out
        assert helper.ICONS["info"] in captured.out

    def test_print_warning(self, capsys):
        """Test printing warning message."""
        helper = PromptHelper()
        helper.print_warning("Warning message")

        captured = capsys.readouterr()
        assert "Warning message" in captured.out
        assert helper.ICONS["warning"] in captured.out

    def test_print_error(self, capsys):
        """Test printing error message."""
        helper = PromptHelper()
        helper.print_error("Error occurred")

        captured = capsys.readouterr()
        assert "Error occurred" in captured.out
        assert helper.ICONS["cross"] in captured.out

    def test_print_summary_box(self, capsys):
        """Test printing summary box."""
        helper = PromptHelper()
        items = ["Item 1", "Item 2", "Item 3"]
        helper.print_summary_box("Summary", items)

        captured = capsys.readouterr()
        assert "Summary" in captured.out
        assert "Item 1" in captured.out
        assert "Item 2" in captured.out
        assert "Item 3" in captured.out
        assert "┌" in captured.out
        assert "└" in captured.out

    @patch("builtins.input", side_effect=["2"])
    def test_prompt_choice_by_number(self, mock_input):
        """Test prompting for choice by number."""
        helper = PromptHelper()
        choices = ["Option A", "Option B", "Option C"]

        result = helper.prompt_choice("Choose an option:", choices)

        assert result == "Option B"

    @patch("builtins.input", side_effect=[""])
    def test_prompt_choice_default(self, mock_input):
        """Test prompting for choice with default."""
        helper = PromptHelper()
        choices = ["Option A", "Option B", "Option C"]

        result = helper.prompt_choice("Choose an option:", choices, default="Option A")

        assert result == "Option A"

    @patch("builtins.input", side_effect=["invalid", "5", "2"])
    def test_prompt_choice_invalid_then_valid(self, mock_input):
        """Test prompting for choice with invalid inputs then valid."""
        helper = PromptHelper()
        choices = ["Option A", "Option B"]

        result = helper.prompt_choice("Choose an option:", choices)

        assert result == "Option B"
        assert mock_input.call_count == 3

    @patch("builtins.input", side_effect=["y"])
    def test_prompt_yes_no_yes(self, mock_input):
        """Test prompting for yes/no - yes response."""
        helper = PromptHelper()
        result = helper.prompt_yes_no("Continue?")

        assert result is True

    @patch("builtins.input", side_effect=["n"])
    def test_prompt_yes_no_no(self, mock_input):
        """Test prompting for yes/no - no response."""
        helper = PromptHelper()
        result = helper.prompt_yes_no("Continue?")

        assert result is False

    @patch("builtins.input", side_effect=[""])
    def test_prompt_yes_no_default_true(self, mock_input):
        """Test prompting for yes/no - default true."""
        helper = PromptHelper()
        result = helper.prompt_yes_no("Continue?", default=True)

        assert result is True

    @patch("builtins.input", side_effect=[""])
    def test_prompt_yes_no_default_false(self, mock_input):
        """Test prompting for yes/no - default false."""
        helper = PromptHelper()
        result = helper.prompt_yes_no("Continue?", default=False)

        assert result is False

    @patch("builtins.input", side_effect=["invalid", "y"])
    def test_prompt_yes_no_invalid_then_valid(self, mock_input):
        """Test prompting for yes/no - invalid then valid."""
        helper = PromptHelper()
        result = helper.prompt_yes_no("Continue?")

        assert result is True
        assert mock_input.call_count == 2

    @patch("builtins.input", side_effect=["test input"])
    def test_prompt_text(self, mock_input):
        """Test prompting for text input."""
        helper = PromptHelper()
        result = helper.prompt_text("Enter text:")

        assert result == "test input"

    @patch("builtins.input", side_effect=[""])
    def test_prompt_text_default(self, mock_input):
        """Test prompting for text with default."""
        helper = PromptHelper()
        result = helper.prompt_text("Enter text:", default="default value")

        assert result == "default value"

    @patch("builtins.input", side_effect=["y"])
    def test_confirm_yes(self, mock_input):
        """Test confirm action - yes."""
        helper = PromptHelper()
        result = helper.confirm("Are you sure?")

        assert result is True

    @patch("builtins.input", side_effect=["n"])
    def test_confirm_no(self, mock_input):
        """Test confirm action - no."""
        helper = PromptHelper()
        result = helper.confirm("Are you sure?")

        assert result is False


class TestArtifactGenerator:
    """Tests for ArtifactGenerator class."""

    @patch("scripts.cli.wizard_generators.generate_makefile_target")
    def test_generate_makefile(self, mock_generate, tmp_path):
        """Test Makefile generation."""
        generator = ArtifactGenerator()
        command = ["jmo", "scan", "--profile-name", "fast"]
        output_path = tmp_path / "Makefile"

        generator.generate_makefile(command, output_path)

        mock_generate.assert_called_once()
        assert mock_generate.call_args[0][0] == command
        assert mock_generate.call_args[0][1] == output_path

    @patch("scripts.cli.wizard_generators.generate_github_actions")
    def test_generate_github_actions(self, mock_generate, tmp_path):
        """Test GitHub Actions workflow generation."""
        generator = ArtifactGenerator()
        command = ["jmo", "scan", "--profile-name", "balanced"]
        output_path = tmp_path / ".github" / "workflows" / "security.yml"

        generator.generate_github_actions(command, output_path)

        mock_generate.assert_called_once()
        assert mock_generate.call_args[0][0] == command
        assert mock_generate.call_args[0][1] == output_path

    @patch("scripts.cli.wizard_generators.generate_shell_script")
    def test_generate_shell_script(self, mock_generate, tmp_path):
        """Test shell script generation."""
        generator = ArtifactGenerator()
        command = ["jmo", "scan", "--profile-name", "deep"]
        output_path = tmp_path / "scan.sh"

        generator.generate_shell_script(command, output_path)

        mock_generate.assert_called_once()
        assert mock_generate.call_args[0][0] == command
        assert mock_generate.call_args[0][1] == output_path


class ConcreteWizardFlow(BaseWizardFlow):
    """Concrete implementation of BaseWizardFlow for testing."""

    def detect_targets(self) -> dict[str, list]:
        """Detect targets - test implementation."""
        return {"repos": [Path("/test/repo1"), Path("/test/repo2")]}

    def prompt_user(self) -> dict:
        """Prompt user - test implementation."""
        return {"profile": "fast", "threads": 4}

    def build_command(self, targets: dict, options: dict) -> list[str]:
        """Build command - test implementation."""
        return ["jmo", "scan", "--profile-name", options["profile"]]


class TestBaseWizardFlow:
    """Tests for BaseWizardFlow class."""

    def test_initialization(self):
        """Test BaseWizardFlow initialization."""
        flow = ConcreteWizardFlow()

        assert flow.config == {}
        assert isinstance(flow.detector, TargetDetector)
        assert isinstance(flow.generator, ArtifactGenerator)
        assert isinstance(flow.prompter, PromptHelper)

    def test_initialization_with_config(self):
        """Test BaseWizardFlow initialization with config."""
        config = {"profile": "balanced", "threads": 8}
        flow = ConcreteWizardFlow(config)

        assert flow.config == config

    @patch.object(ConcreteWizardFlow, "detect_targets", return_value={})
    def test_execute_no_targets(self, mock_detect):
        """Test execute with no targets detected."""
        flow = ConcreteWizardFlow()
        result = flow.execute()

        assert result == 1
        mock_detect.assert_called_once()

    @patch("subprocess.run")
    @patch("builtins.input", side_effect=["y"])
    @patch.object(
        ConcreteWizardFlow,
        "detect_targets",
        return_value={"repos": [Path("/test/repo1")]},
    )
    @patch.object(ConcreteWizardFlow, "prompt_user", return_value={"profile": "fast"})
    @patch.object(
        ConcreteWizardFlow,
        "build_command",
        return_value=["jmo", "scan", "--profile-name", "fast"],
    )
    def test_execute_success(
        self, mock_build, mock_prompt, mock_detect, mock_input, mock_run
    ):
        """Test successful execution flow."""
        mock_run.return_value = MagicMock(returncode=0)

        flow = ConcreteWizardFlow()
        result = flow.execute()

        assert result == 0
        mock_detect.assert_called_once()
        mock_prompt.assert_called_once()
        mock_build.assert_called_once()
        mock_run.assert_called_once()

    @patch("subprocess.run")
    @patch("builtins.input", side_effect=["y"])
    @patch.object(
        ConcreteWizardFlow,
        "detect_targets",
        return_value={"repos": [Path("/test/repo1")]},
    )
    @patch.object(ConcreteWizardFlow, "prompt_user", return_value={"profile": "fast"})
    @patch.object(
        ConcreteWizardFlow,
        "build_command",
        return_value=["jmo", "scan", "--profile-name", "fast"],
    )
    def test_execute_scan_failure(
        self, mock_build, mock_prompt, mock_detect, mock_input, mock_run
    ):
        """Test execution with scan failure."""
        mock_run.return_value = MagicMock(returncode=1)

        flow = ConcreteWizardFlow()
        result = flow.execute()

        assert result == 1

    @patch("builtins.input", side_effect=["n"])
    @patch.object(
        ConcreteWizardFlow,
        "detect_targets",
        return_value={"repos": [Path("/test/repo1")]},
    )
    @patch.object(ConcreteWizardFlow, "prompt_user", return_value={"profile": "fast"})
    @patch.object(
        ConcreteWizardFlow,
        "build_command",
        return_value=["jmo", "scan", "--profile-name", "fast"],
    )
    def test_execute_user_cancellation(
        self, mock_build, mock_prompt, mock_detect, mock_input
    ):
        """Test execution with user cancellation."""
        flow = ConcreteWizardFlow()
        result = flow.execute()

        assert result == 0  # Cancelled returns 0
        mock_detect.assert_called_once()
        mock_prompt.assert_called_once()
        mock_build.assert_called_once()

    @patch("subprocess.run", side_effect=RuntimeError("Scan failed"))
    @patch("builtins.input", side_effect=["y"])
    @patch.object(
        ConcreteWizardFlow,
        "detect_targets",
        return_value={"repos": [Path("/test/repo1")]},
    )
    @patch.object(ConcreteWizardFlow, "prompt_user", return_value={"profile": "fast"})
    @patch.object(
        ConcreteWizardFlow,
        "build_command",
        return_value=["jmo", "scan", "--profile-name", "fast"],
    )
    def test_execute_exception_handling(
        self, mock_build, mock_prompt, mock_detect, mock_input, mock_run
    ):
        """Test execution exception handling."""
        flow = ConcreteWizardFlow()
        result = flow.execute()

        assert result == 1

    def test_estimate_time_fast_profile(self):
        """Test time estimation for fast profile."""
        flow = ConcreteWizardFlow()
        estimate = flow._estimate_time("fast")

        assert estimate == "5-8 minutes"

    def test_estimate_time_balanced_profile(self):
        """Test time estimation for balanced profile."""
        flow = ConcreteWizardFlow()
        estimate = flow._estimate_time("balanced")

        assert estimate == "15-20 minutes"

    def test_estimate_time_deep_profile(self):
        """Test time estimation for deep profile."""
        flow = ConcreteWizardFlow()
        estimate = flow._estimate_time("deep")

        assert estimate == "30-60 minutes"

    def test_estimate_time_unknown_profile(self):
        """Test time estimation for unknown profile."""
        flow = ConcreteWizardFlow()
        estimate = flow._estimate_time("unknown")

        assert estimate == "15-20 minutes"  # Default
