"""Unit tests for base wizard flow classes and utilities.

Tests cover:
- TargetDetector detection methods (repos, images, IaC, web apps, packages, locks)
- PromptHelper colored output and prompting
- BaseWizardFlow execution template method

Architecture Note:
- Uses tmp_path fixture for file operations
- Mocks subprocess for command execution
- Mocks input() for user prompts
- Tests concrete implementations of abstract methods
"""

from pathlib import Path
from unittest.mock import MagicMock, patch


from scripts.cli.wizard_flows.base_flow import (
    BaseWizardFlow,
    PromptHelper,
    TargetDetector,
)


# ========== Category 1: TargetDetector ==========


def test_detect_repos_with_git_repos(tmp_path):
    """Test detect_repos finds Git repositories."""
    detector = TargetDetector()

    # Create directories with .git
    (tmp_path / "repo1" / ".git").mkdir(parents=True)
    (tmp_path / "repo2" / ".git").mkdir(parents=True)
    (tmp_path / "notrepo").mkdir()

    repos = detector.detect_repos(tmp_path)

    assert len(repos) == 2
    assert tmp_path / "repo1" in repos
    assert tmp_path / "repo2" in repos


def test_detect_repos_no_repos(tmp_path):
    """Test detect_repos with no repositories."""
    detector = TargetDetector()
    repos = detector.detect_repos(tmp_path)
    assert len(repos) == 0


def test_detect_repos_nonexistent_directory():
    """Test detect_repos with non-existent directory."""
    detector = TargetDetector()
    repos = detector.detect_repos(Path("/nonexistent"))
    assert len(repos) == 0


def test_detect_images_from_docker_compose(tmp_path):
    """Test detect_images finds images from docker-compose.yml."""
    detector = TargetDetector()

    compose_content = """
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
"""
    (tmp_path / "docker-compose.yml").write_text(compose_content)

    images = detector.detect_images(tmp_path)

    assert "nginx:latest" in images
    assert "postgres:14" in images


def test_detect_images_from_dockerfile(tmp_path):
    """Test detect_images finds base images from Dockerfile."""
    detector = TargetDetector()

    dockerfile_content = """
FROM python:3.11-slim
FROM node:18-alpine AS builder
"""
    (tmp_path / "Dockerfile").write_text(dockerfile_content)

    images = detector.detect_images(tmp_path)

    assert "python:3.11-slim" in images
    assert "node:18-alpine" in images


def test_detect_images_deduplication(tmp_path):
    """Test detect_images deduplicates images."""
    detector = TargetDetector()

    (tmp_path / "Dockerfile").write_text("FROM nginx:latest\nFROM nginx:latest")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:latest"
    )

    images = detector.detect_images(tmp_path)

    assert images.count("nginx:latest") == 1


def test_detect_images_no_images(tmp_path):
    """Test detect_images with no images found."""
    detector = TargetDetector()
    images = detector.detect_images(tmp_path)
    assert len(images) == 0


def test_detect_images_invalid_compose(tmp_path):
    """Test detect_images handles invalid docker-compose.yml gracefully."""
    detector = TargetDetector()
    (tmp_path / "docker-compose.yml").write_text("invalid: yaml: content:")

    images = detector.detect_images(tmp_path)

    assert len(images) == 0


def test_detect_iac_terraform(tmp_path):
    """Test detect_iac finds Terraform files."""
    detector = TargetDetector()

    (tmp_path / "main.tf").touch()
    (tmp_path / "terraform.tfstate").touch()

    iac_files = detector.detect_iac(tmp_path)

    assert any("main.tf" in str(f) for f in iac_files)
    assert any("terraform.tfstate" in str(f) for f in iac_files)


def test_detect_iac_cloudformation(tmp_path):
    """Test detect_iac finds CloudFormation files."""
    detector = TargetDetector()

    (tmp_path / "cloudformation-stack.yml").touch()
    (tmp_path / "another-cloudformation.yaml").touch()

    iac_files = detector.detect_iac(tmp_path)

    assert any("cloudformation-stack.yml" in str(f) for f in iac_files)
    assert any("another-cloudformation.yaml" in str(f) for f in iac_files)


def test_detect_iac_kubernetes(tmp_path):
    """Test detect_iac finds Kubernetes manifests."""
    detector = TargetDetector()

    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "deployment.yml").touch()
    (tmp_path / "kubernetes").mkdir()
    (tmp_path / "kubernetes" / "service.yml").touch()

    iac_files = detector.detect_iac(tmp_path)

    assert any("deployment.yml" in str(f) for f in iac_files)
    assert any("service.yml" in str(f) for f in iac_files)


def test_detect_iac_no_iac_files(tmp_path):
    """Test detect_iac with no IaC files."""
    detector = TargetDetector()
    iac_files = detector.detect_iac(tmp_path)
    assert len(iac_files) == 0


def test_detect_web_apps_from_compose_ports(tmp_path):
    """Test detect_web_apps infers URLs from docker-compose ports."""
    detector = TargetDetector()

    compose_content = """
services:
  web:
    ports:
      - "8080:80"
      - "3000:3000"
"""
    (tmp_path / "docker-compose.yml").write_text(compose_content)

    urls = detector.detect_web_apps(tmp_path)

    assert "http://localhost:8080" in urls
    assert "http://localhost:3000" in urls


def test_detect_web_apps_from_package_json(tmp_path):
    """Test detect_web_apps infers default port for React/Next.js."""
    detector = TargetDetector()
    (tmp_path / "package.json").write_text('{"name": "my-app"}')

    urls = detector.detect_web_apps(tmp_path)

    assert "http://localhost:3000" in urls


def test_detect_web_apps_no_apps(tmp_path):
    """Test detect_web_apps with no web apps."""
    detector = TargetDetector()
    urls = detector.detect_web_apps(tmp_path)
    assert len(urls) == 0


def test_detect_web_apps_invalid_compose(tmp_path):
    """Test detect_web_apps handles invalid docker-compose.yml gracefully."""
    detector = TargetDetector()
    (tmp_path / "docker-compose.yml").write_text("invalid: yaml:")

    urls = detector.detect_web_apps(tmp_path)

    # Should not crash, may return empty list
    assert isinstance(urls, list)


def test_detect_package_files_python(tmp_path):
    """Test detect_package_files finds Python package manifests."""
    detector = TargetDetector()

    (tmp_path / "requirements.txt").touch()
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "setup.py").touch()
    (tmp_path / "Pipfile").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("requirements.txt" in str(f) for f in package_files)
    assert any("pyproject.toml" in str(f) for f in package_files)
    assert any("setup.py" in str(f) for f in package_files)
    assert any("Pipfile" in str(f) for f in package_files)


def test_detect_package_files_javascript(tmp_path):
    """Test detect_package_files finds JavaScript package manifests."""
    detector = TargetDetector()
    (tmp_path / "package.json").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("package.json" in str(f) for f in package_files)


def test_detect_package_files_go(tmp_path):
    """Test detect_package_files finds Go modules."""
    detector = TargetDetector()
    (tmp_path / "go.mod").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("go.mod" in str(f) for f in package_files)


def test_detect_package_files_rust(tmp_path):
    """Test detect_package_files finds Rust manifests."""
    detector = TargetDetector()
    (tmp_path / "Cargo.toml").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("Cargo.toml" in str(f) for f in package_files)


def test_detect_package_files_java_maven(tmp_path):
    """Test detect_package_files finds Maven pom.xml."""
    detector = TargetDetector()
    (tmp_path / "pom.xml").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("pom.xml" in str(f) for f in package_files)


def test_detect_package_files_java_gradle(tmp_path):
    """Test detect_package_files finds Gradle build files."""
    detector = TargetDetector()
    (tmp_path / "build.gradle").touch()
    (tmp_path / "build.gradle.kts").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("build.gradle" in str(f) for f in package_files)
    assert any("build.gradle.kts" in str(f) for f in package_files)


def test_detect_package_files_ruby(tmp_path):
    """Test detect_package_files finds Ruby Gemfile."""
    detector = TargetDetector()
    (tmp_path / "Gemfile").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("Gemfile" in str(f) for f in package_files)


def test_detect_package_files_dotnet(tmp_path):
    """Test detect_package_files finds .NET csproj files."""
    detector = TargetDetector()
    (tmp_path / "MyApp.csproj").touch()

    package_files = detector.detect_package_files(tmp_path)

    assert any("MyApp.csproj" in str(f) for f in package_files)


def test_detect_lock_files_python(tmp_path):
    """Test detect_lock_files finds Python lock files."""
    detector = TargetDetector()

    (tmp_path / "poetry.lock").touch()
    (tmp_path / "Pipfile.lock").touch()

    lock_files = detector.detect_lock_files(tmp_path)

    assert any("poetry.lock" in str(f) for f in lock_files)
    assert any("Pipfile.lock" in str(f) for f in lock_files)


def test_detect_lock_files_javascript(tmp_path):
    """Test detect_lock_files finds JavaScript lock files."""
    detector = TargetDetector()

    (tmp_path / "package-lock.json").touch()
    (tmp_path / "yarn.lock").touch()
    (tmp_path / "pnpm-lock.yaml").touch()

    lock_files = detector.detect_lock_files(tmp_path)

    assert any("package-lock.json" in str(f) for f in lock_files)
    assert any("yarn.lock" in str(f) for f in lock_files)
    assert any("pnpm-lock.yaml" in str(f) for f in lock_files)


def test_detect_lock_files_go(tmp_path):
    """Test detect_lock_files finds Go lock files."""
    detector = TargetDetector()
    (tmp_path / "go.sum").touch()

    lock_files = detector.detect_lock_files(tmp_path)

    assert any("go.sum" in str(f) for f in lock_files)


def test_detect_lock_files_rust(tmp_path):
    """Test detect_lock_files finds Rust lock files."""
    detector = TargetDetector()
    (tmp_path / "Cargo.lock").touch()

    lock_files = detector.detect_lock_files(tmp_path)

    assert any("Cargo.lock" in str(f) for f in lock_files)


def test_detect_lock_files_ruby(tmp_path):
    """Test detect_lock_files finds Ruby lock files."""
    detector = TargetDetector()
    (tmp_path / "Gemfile.lock").touch()

    lock_files = detector.detect_lock_files(tmp_path)

    assert any("Gemfile.lock" in str(f) for f in lock_files)


# ========== Category 2: PromptHelper ==========


def test_prompter_colorize():
    """Test PromptHelper colorize applies ANSI codes."""
    import scripts.cli.wizard_flows.base_flow as bf

    orig = bf._ANSI_SUPPORTED
    bf._ANSI_SUPPORTED = True
    try:
        prompter = PromptHelper()
        result = prompter.colorize("test", "green")
        assert "\x1b[32mtest\x1b[0m" == result
    finally:
        bf._ANSI_SUPPORTED = orig


def test_prompter_colorize_invalid_color():
    """Test PromptHelper colorize with invalid color (fallback to reset)."""
    import scripts.cli.wizard_flows.base_flow as bf

    orig = bf._ANSI_SUPPORTED
    bf._ANSI_SUPPORTED = True
    try:
        prompter = PromptHelper()
        result = prompter.colorize("test", "invalid")
        assert "test\x1b[0m" == result
    finally:
        bf._ANSI_SUPPORTED = orig


def test_prompter_print_header(capsys):
    """Test PromptHelper print_header outputs formatted header."""
    prompter = PromptHelper()
    prompter.print_header("Test Header", "rocket")

    captured = capsys.readouterr()
    assert "Test Header" in captured.out
    assert "╔" in captured.out
    assert "╚" in captured.out


def test_prompter_print_step(capsys):
    """Test PromptHelper print_step outputs progress bar."""
    prompter = PromptHelper()
    prompter.print_step(2, 5, "Running scan")

    captured = capsys.readouterr()
    assert "Step 2/5" in captured.out
    assert "Running scan" in captured.out
    assert "40%" in captured.out


def test_prompter_print_success(capsys):
    """Test PromptHelper print_success outputs success message."""
    prompter = PromptHelper()
    prompter.print_success("Operation complete")

    captured = capsys.readouterr()
    assert "Operation complete" in captured.out


def test_prompter_print_info(capsys):
    """Test PromptHelper print_info outputs info message."""
    prompter = PromptHelper()
    prompter.print_info("Information")

    captured = capsys.readouterr()
    assert "Information" in captured.out


def test_prompter_print_warning(capsys):
    """Test PromptHelper print_warning outputs warning message."""
    prompter = PromptHelper()
    prompter.print_warning("Warning message")

    captured = capsys.readouterr()
    assert "Warning message" in captured.out


def test_prompter_print_error(capsys):
    """Test PromptHelper print_error outputs error message."""
    prompter = PromptHelper()
    prompter.print_error("Error occurred")

    captured = capsys.readouterr()
    assert "Error occurred" in captured.out


def test_prompter_print_summary_box(capsys):
    """Test PromptHelper print_summary_box outputs formatted box."""
    prompter = PromptHelper()
    items = ["Item 1", "Item 2", "Item 3"]
    prompter.print_summary_box("Summary", items)

    captured = capsys.readouterr()
    assert "Summary" in captured.out
    assert "Item 1" in captured.out
    assert "Item 2" in captured.out
    assert "Item 3" in captured.out


def test_prompter_prompt_choice_numeric():
    """Test PromptHelper prompt_choice with numeric input."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B", "Option C"]

    with patch("builtins.input", return_value="2"):
        result = prompter.prompt_choice("Select:", choices)
        assert result == "Option B"


def test_prompter_prompt_choice_default():
    """Test PromptHelper prompt_choice with default."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B"]

    with patch("builtins.input", return_value=""):
        result = prompter.prompt_choice("Select:", choices, default="Option A")
        assert result == "Option A"


def test_prompter_prompt_choice_invalid_then_valid():
    """Test PromptHelper prompt_choice retries on invalid input."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B"]

    with patch("builtins.input", side_effect=["invalid", "99", "1"]):
        result = prompter.prompt_choice("Select:", choices)
        assert result == "Option A"


def test_prompter_prompt_yes_no_yes():
    """Test PromptHelper prompt_yes_no with 'yes' input."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value="y"):
        result = prompter.prompt_yes_no("Continue?")
        assert result is True


def test_prompter_prompt_yes_no_no():
    """Test PromptHelper prompt_yes_no with 'no' input."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value="n"):
        result = prompter.prompt_yes_no("Continue?")
        assert result is False


def test_prompter_prompt_yes_no_default():
    """Test PromptHelper prompt_yes_no with default."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value=""):
        result = prompter.prompt_yes_no("Continue?", default=True)
        assert result is True


def test_prompter_prompt_text_with_input():
    """Test PromptHelper prompt_text with user input."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value="my value"):
        result = prompter.prompt_text("Enter text:")
        assert result == "my value"


def test_prompter_prompt_text_with_default():
    """Test PromptHelper prompt_text with default."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value=""):
        result = prompter.prompt_text("Enter text:", default="default value")
        assert result == "default value"


def test_prompter_confirm_yes():
    """Test PromptHelper confirm returns True for 'yes'."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value="y"):
        result = prompter.confirm("Proceed?")
        assert result is True


# ========== Category 3: BaseWizardFlow ==========


class ConcreteWizardFlow(BaseWizardFlow):
    """Concrete implementation for testing."""

    def detect_targets(self):
        return {"repos": [Path("/repo1"), Path("/repo2")]}

    def prompt_user(self):
        return {"profile": "balanced"}

    def build_command(self, targets, options):
        return ["jmo", "scan", "--profile", "balanced"]


def test_base_wizard_flow_execute_success():
    """Test BaseWizardFlow execute with successful scan."""
    flow = ConcreteWizardFlow()

    with (
        patch.object(flow.prompter, "confirm", return_value=True),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)

        result = flow.execute()

        assert result == 0
        mock_run.assert_called_once()


def test_base_wizard_flow_execute_cancelled():
    """Test BaseWizardFlow execute when user cancels."""
    flow = ConcreteWizardFlow()

    with patch.object(flow.prompter, "confirm", return_value=False):
        result = flow.execute()

        assert result == 0  # Cancellation is not an error


def test_base_wizard_flow_execute_no_targets():
    """Test BaseWizardFlow execute with no targets detected."""

    class EmptyTargetsFlow(BaseWizardFlow):
        def detect_targets(self):
            return {}

        def prompt_user(self):
            return {}

        def build_command(self, targets, options):
            return []

    flow = EmptyTargetsFlow()
    result = flow.execute()

    assert result == 1  # No targets is an error


def test_base_wizard_flow_execute_scan_failure():
    """Test BaseWizardFlow execute with scan failure."""
    flow = ConcreteWizardFlow()

    with (
        patch.object(flow.prompter, "confirm", return_value=True),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=2)

        result = flow.execute()

        assert result == 2


def test_base_wizard_flow_execute_exception():
    """Test BaseWizardFlow execute handles exceptions."""
    flow = ConcreteWizardFlow()

    with (
        patch.object(flow.prompter, "confirm", return_value=True),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.side_effect = Exception("Command failed")

        result = flow.execute()

        assert result == 1


def test_base_wizard_flow_estimate_time():
    """Test BaseWizardFlow _estimate_time returns correct estimates."""
    flow = ConcreteWizardFlow()

    assert flow._estimate_time("fast") == "5-8 minutes"
    assert flow._estimate_time("balanced") == "15-20 minutes"
    assert flow._estimate_time("deep") == "30-60 minutes"
    assert flow._estimate_time("unknown") == "15-20 minutes"  # Default


def test_base_wizard_flow_execute_all_empty_lists():
    """Test BaseWizardFlow execute with targets that have empty lists."""

    class EmptyListsFlow(BaseWizardFlow):
        def detect_targets(self):
            return {"repos": [], "images": [], "iac": []}

        def prompt_user(self):
            return {}

        def build_command(self, targets, options):
            return []

    flow = EmptyListsFlow()
    result = flow.execute()

    assert result == 1  # All empty lists = no targets


def test_prompter_prompt_choice_text_input():
    """Test PromptHelper prompt_choice with text input (case-insensitive)."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B", "Option C"]

    with patch("builtins.input", return_value="option b"):
        result = prompter.prompt_choice("Select:", choices)
        assert result == "Option B"


def test_prompter_prompt_yes_no_retry():
    """Test PromptHelper prompt_yes_no retries on invalid input."""
    prompter = PromptHelper()

    with patch("builtins.input", side_effect=["maybe", "possibly", "y"]):
        result = prompter.prompt_yes_no("Continue?")
        assert result is True


def test_detect_images_unreadable_dockerfile(tmp_path):
    """Test detect_images handles unreadable Dockerfile gracefully."""
    detector = TargetDetector()

    # Create a subdirectory for the Dockerfile that will fail
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    dockerfile = subdir / "Dockerfile"
    dockerfile.write_bytes(b"\xff\xfe invalid unicode")

    images = detector.detect_images(tmp_path)

    # Should not crash
    assert isinstance(images, list)


def test_detect_web_apps_compose_with_non_string_ports(tmp_path):
    """Test detect_web_apps handles non-string port mappings."""
    detector = TargetDetector()

    # Compose with integer port (no colon, so skip)
    compose_content = """
services:
  web:
    ports:
      - 8080
      - "3000:3000"
"""
    (tmp_path / "docker-compose.yml").write_text(compose_content)

    urls = detector.detect_web_apps(tmp_path)

    # Should get 3000:3000 but not 8080 (no colon)
    assert "http://localhost:3000" in urls


def test_prompter_print_header_long_title(capsys):
    """Test PromptHelper print_header truncates long titles."""
    prompter = PromptHelper()

    # Very long header that should be truncated
    long_title = "A" * 200
    prompter.print_header(long_title, "star")

    captured = capsys.readouterr()
    # Should contain truncation ellipsis
    assert "…" in captured.out


def test_prompter_print_summary_box_long_title(capsys):
    """Test PromptHelper print_summary_box truncates long titles."""
    prompter = PromptHelper()

    # Very long title
    long_title = "B" * 200
    prompter.print_summary_box(long_title, ["Item 1"])

    captured = capsys.readouterr()
    assert "…" in captured.out


def test_prompter_colorize_no_color_env(monkeypatch):
    """Test PromptHelper colorize respects NO_COLOR environment variable."""
    prompter = PromptHelper()

    monkeypatch.setenv("NO_COLOR", "1")
    result = prompter.colorize("test", "green")

    # Should return plain text without ANSI codes
    assert result == "test"


def test_target_detector_defaults_to_cwd(tmp_path, monkeypatch):
    """Test TargetDetector methods default to current working directory."""
    detector = TargetDetector()

    # Change to tmp_path to avoid picking up project files
    monkeypatch.chdir(tmp_path)

    # All methods should accept None and not crash
    repos = detector.detect_repos(None)
    images = detector.detect_images(None)
    iac = detector.detect_iac(None)
    web_apps = detector.detect_web_apps(None)
    packages = detector.detect_package_files(None)
    locks = detector.detect_lock_files(None)

    # All should return lists
    assert isinstance(repos, list)
    assert isinstance(images, list)
    assert isinstance(iac, list)
    assert isinstance(web_apps, list)
    assert isinstance(packages, list)
    assert isinstance(locks, list)


def test_artifact_generator_generate_makefile(tmp_path):
    """Test ArtifactGenerator.generate_makefile delegates to wizard_generators."""
    from scripts.cli.wizard_flows.base_flow import ArtifactGenerator

    generator = ArtifactGenerator()
    output = tmp_path / "Makefile"

    # Mock the underlying generator to avoid complex config requirements
    with patch("scripts.cli.wizard_generators.generate_makefile_target") as mock_gen:
        mock_gen.return_value = "# Mock Makefile\nsecurity-scan:\n\tjmo scan"
        generator.generate_makefile(["jmo", "scan", "--profile", "balanced"], output)

    # Verify the generator was called
    mock_gen.assert_called_once()


def test_artifact_generator_generate_github_actions(tmp_path):
    """Test ArtifactGenerator.generate_github_actions delegates to wizard_generators."""
    from scripts.cli.wizard_flows.base_flow import ArtifactGenerator

    generator = ArtifactGenerator()
    output = tmp_path / ".github" / "workflows" / "security.yml"
    output.parent.mkdir(parents=True)

    # Mock the underlying generator to avoid complex config requirements
    with patch("scripts.cli.wizard_generators.generate_github_actions") as mock_gen:
        mock_gen.return_value = "# Mock GHA workflow"
        generator.generate_github_actions(
            ["jmo", "scan", "--profile", "balanced"], output
        )

    mock_gen.assert_called_once()


def test_artifact_generator_generate_shell_script(tmp_path):
    """Test ArtifactGenerator.generate_shell_script delegates to wizard_generators."""
    from scripts.cli.wizard_flows.base_flow import ArtifactGenerator

    generator = ArtifactGenerator()
    output = tmp_path / "scan.sh"

    # Mock the underlying generator
    with patch("scripts.cli.wizard_generators.generate_shell_script") as mock_gen:
        mock_gen.return_value = "#!/bin/bash\njmo scan"
        generator.generate_shell_script(
            ["jmo", "scan", "--profile", "balanced"], output
        )

    mock_gen.assert_called_once()


# ========== Category 4: ANSI Support Detection ==========


def test_supports_ansi_no_color_env(monkeypatch):
    """Test _supports_ansi respects NO_COLOR environment variable."""
    from scripts.cli.wizard_flows import base_flow

    monkeypatch.setenv("NO_COLOR", "1")

    # Call the function directly
    result = base_flow._supports_ansi()

    assert result is False


def test_supports_ansi_windows_terminal_env(monkeypatch):
    """Test _supports_ansi detects Windows Terminal via WT_SESSION."""
    from scripts.cli.wizard_flows import base_flow

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("WT_SESSION", "some-session-id")

    result = base_flow._supports_ansi()

    assert result is True


def test_supports_ansi_xterm_env(monkeypatch):
    """Test _supports_ansi detects xterm from TERM variable."""
    from scripts.cli.wizard_flows import base_flow

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("WT_SESSION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    result = base_flow._supports_ansi()

    assert result is True


def test_get_terminal_width_fallback():
    """Test _get_terminal_width returns safe default on exception."""
    from scripts.cli.wizard_flows import base_flow

    with patch("shutil.get_terminal_size", side_effect=Exception("test")):
        result = base_flow._get_terminal_width()

    assert result == 80


def test_get_terminal_width_clamping():
    """Test _get_terminal_width clamps to min/max bounds."""
    from scripts.cli.wizard_flows import base_flow

    # Test minimum clamping
    with patch("shutil.get_terminal_size") as mock_size:
        mock_size.return_value = MagicMock(columns=20)
        result = base_flow._get_terminal_width()
        assert result == 40  # Minimum

    # Test maximum clamping
    with patch("shutil.get_terminal_size") as mock_size:
        mock_size.return_value = MagicMock(columns=200)
        result = base_flow._get_terminal_width()
        assert result == 120  # Maximum


def test_base_wizard_flow_abstract_methods():
    """Test BaseWizardFlow abstract methods are enforced."""

    # Verify abstract methods are defined
    abstract_methods = BaseWizardFlow.__abstractmethods__
    assert "detect_targets" in abstract_methods
    assert "prompt_user" in abstract_methods
    assert "build_command" in abstract_methods


def test_prompter_colorize_ansi_not_supported(monkeypatch):
    """Test PromptHelper colorize when ANSI not supported."""
    from scripts.cli.wizard_flows import base_flow

    # Set the module-level flag to False
    original_flag = base_flow._ANSI_SUPPORTED
    base_flow._ANSI_SUPPORTED = False
    monkeypatch.delenv("NO_COLOR", raising=False)

    try:
        prompter = PromptHelper()
        result = prompter.colorize("test", "green")
        assert result == "test"  # No ANSI codes
    finally:
        base_flow._ANSI_SUPPORTED = original_flag
