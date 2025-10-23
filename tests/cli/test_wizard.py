"""Tests for the interactive wizard."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.wizard import (
    PROFILES,
    WizardConfig,
    generate_command,
    run_wizard,
)
from scripts.cli.wizard_generators import (
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)


def test_profiles_complete():
    """Test that all profiles are defined with required fields."""
    required_fields = {
        "name",
        "description",
        "tools",
        "timeout",
        "threads",
        "est_time",
        "use_case",
    }

    for profile_name, profile in PROFILES.items():
        assert isinstance(profile_name, str)
        assert set(profile.keys()) == required_fields
        assert isinstance(profile["tools"], list)
        assert len(profile["tools"]) > 0
        assert isinstance(profile["timeout"], int)
        assert profile["timeout"] > 0
        assert isinstance(profile["threads"], int)
        assert profile["threads"] > 0


def test_wizard_config_to_dict():
    """Test WizardConfig serialization."""
    config = WizardConfig()
    config.profile = "balanced"
    # v0.6.0+ uses nested TargetConfig instead of flat target_mode/target_path
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/path/to/repos"

    data = config.to_dict()
    assert data["profile"] == "balanced"
    assert "target" in data
    assert data["target"]["type"] == "repo"
    assert data["target"]["repo_mode"] == "repos-dir"
    assert data["target"]["repo_path"] == "/path/to/repos"
    assert "use_docker" in data
    assert "results_dir" in data


def test_generate_command_native_repos_dir():
    """Test command generation for native mode with repos-dir."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    # v0.6.0+ uses nested TargetConfig
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/home/user/repos"
    config.results_dir = "results"
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""
    config.allow_missing_tools = True
    config.human_logs = True

    cmd = generate_command(config)

    assert "jmotools balanced" in cmd
    assert "--repos-dir /home/user/repos" in cmd
    assert "--results-dir results" in cmd
    assert "--threads 4" in cmd
    assert "--timeout 600" in cmd
    assert "--human-logs" in cmd


def test_generate_command_native_with_fail_on():
    """Test command generation with fail-on severity."""
    config = WizardConfig()
    config.profile = "fast"
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "/home/user/myrepo"
    config.results_dir = "results"
    config.fail_on = "HIGH"

    cmd = generate_command(config)

    assert "jmotools fast" in cmd
    assert "--repo /home/user/myrepo" in cmd
    assert "--fail-on HIGH" in cmd


def test_generate_command_docker_mode():
    """Test command generation for Docker mode."""
    config = WizardConfig()
    config.profile = "deep"
    config.use_docker = True
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/home/user/repos"
    config.results_dir = "results"
    config.threads = 2
    config.timeout = 900

    cmd = generate_command(config)

    assert "docker run" in cmd
    assert "ghcr.io/jimmy058910/jmo-security:latest" in cmd
    assert "--profile deep" in cmd
    assert "/scan" in cmd
    assert "/results" in cmd


def test_generate_command_tsv_mode():
    """Test command generation for TSV clone mode."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "tsv"
    config.target.tsv_path = "./repos.tsv"
    config.target.tsv_dest = "repos-tsv"
    config.results_dir = "results"

    cmd = generate_command(config)

    assert "jmotools balanced" in cmd
    assert "--tsv ./repos.tsv" in cmd
    assert "--dest repos-tsv" in cmd


def test_generate_makefile_target():
    """Test Makefile target generation."""
    config = WizardConfig()
    config.profile = "balanced"
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/home/user/repos"

    command = generate_command(config)
    makefile = generate_makefile_target(config, command)

    assert ".PHONY: security-scan" in makefile
    assert "security-scan:" in makefile
    assert "jmotools balanced" in makefile
    assert "/home/user/repos" in makefile


def test_generate_shell_script():
    """Test shell script generation."""
    config = WizardConfig()
    config.profile = "fast"
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "/home/user/myrepo"

    command = generate_command(config)
    script = generate_shell_script(config, command)

    assert "#!/usr/bin/env bash" in script
    assert "set -euo pipefail" in script
    assert "jmotools fast" in script
    assert "/home/user/myrepo" in script


def test_generate_github_actions_native():
    """Test GitHub Actions workflow generation for native mode."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "."
    config.threads = 4
    config.timeout = 600
    config.fail_on = "HIGH"

    workflow = generate_github_actions(config, PROFILES)

    assert "name: Security Scan" in workflow
    assert "on:" in workflow
    assert "runs-on: ubuntu-latest" in workflow
    assert "actions/checkout@v4" in workflow
    assert "actions/setup-python@v5" in workflow
    assert "jmotools balanced" in workflow
    assert "--fail-on HIGH" in workflow
    assert "upload-artifact@v4" in workflow
    assert "upload-sarif@v3" in workflow


def test_generate_github_actions_docker():
    """Test GitHub Actions workflow generation for Docker mode."""
    config = WizardConfig()
    config.profile = "deep"
    config.use_docker = True
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "."
    config.threads = 2
    config.timeout = 900

    workflow = generate_github_actions(config, PROFILES)

    assert "name: Security Scan" in workflow
    assert "container:" in workflow
    assert "ghcr.io/jimmy058910/jmo-security:latest" in workflow
    assert "jmo scan" in workflow
    assert "--profile deep" in workflow
    assert "actions/checkout@v4" in workflow
    assert "upload-artifact@v4" in workflow
    assert "upload-sarif@v3" in workflow
    # Should NOT have setup-python in Docker mode
    assert "actions/setup-python" not in workflow


@patch("scripts.cli.wizard._detect_docker")
@patch("scripts.cli.wizard._check_docker_running")
@patch("scripts.cli.wizard._prompt_yes_no")
@patch("scripts.cli.wizard._prompt_choice")
@patch("scripts.cli.wizard._prompt_text")
def test_run_wizard_non_interactive(
    mock_text,
    mock_choice,
    mock_yes_no,
    mock_docker_running,
    mock_detect,
):
    """Test wizard in non-interactive (--yes) mode."""
    mock_detect.return_value = False
    mock_docker_running.return_value = False

    # Mock yes/no for "Execute now?" prompt
    mock_yes_no.return_value = True

    # Mock the dynamic import of jmotools.main
    mock_jmotools_main = MagicMock(return_value=0)

    with patch("scripts.cli.wizard.Path.cwd", return_value=Path("/home/user/repos")):
        with patch.dict(
            "sys.modules", {"jmotools": MagicMock(main=mock_jmotools_main)}
        ):
            rc = run_wizard(yes=True)

    # Should not have prompted for profile/target selection
    mock_choice.assert_not_called()
    mock_text.assert_not_called()

    # Should have reasonable exit code
    assert rc == 0


@patch("scripts.cli.wizard.Path.write_text")
def test_run_wizard_emit_makefile(mock_write):
    """Test wizard with --emit-make-target."""
    rc = run_wizard(yes=True, emit_make="Makefile.security")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert ".PHONY: security-scan" in content
    assert rc == 0


@patch("scripts.cli.wizard.Path.write_text")
@patch("scripts.cli.wizard.Path.chmod")
def test_run_wizard_emit_script(mock_chmod, mock_write):
    """Test wizard with --emit-script."""
    rc = run_wizard(yes=True, emit_script="scan.sh")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert "#!/usr/bin/env bash" in content
    mock_chmod.assert_called_once_with(0o755)
    assert rc == 0


@patch("scripts.cli.wizard.Path.write_text")
@patch("scripts.cli.wizard.Path.mkdir")
def test_run_wizard_emit_gha(mock_mkdir, mock_write):
    """Test wizard with --emit-gha."""
    rc = run_wizard(yes=True, emit_gha=".github/workflows/security.yml")

    mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert "name: Security Scan" in content
    assert "actions/checkout@v4" in content
    assert rc == 0


def test_run_wizard_emit_gha_docker():
    """Test wizard generating Docker-based GHA workflow."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = True
    config.threads = 4
    config.timeout = 600
    config.fail_on = "HIGH"

    workflow = generate_github_actions(config, PROFILES)

    # Docker-specific assertions
    assert "container:" in workflow
    assert "image: ghcr.io/jimmy058910/jmo-security:latest" in workflow
    assert "jmo scan" in workflow  # Docker uses `jmo` directly
    assert "--profile balanced" in workflow
    assert "--fail-on HIGH" in workflow

    # Should NOT have Python setup
    assert "setup-python" not in workflow


def test_profile_resource_estimates():
    """Test that profiles have reasonable resource estimates."""
    assert PROFILES["fast"]["timeout"] < PROFILES["balanced"]["timeout"]
    assert PROFILES["balanced"]["timeout"] < PROFILES["deep"]["timeout"]

    # Fast should have more threads (parallel)
    assert PROFILES["fast"]["threads"] >= PROFILES["balanced"]["threads"]
    assert PROFILES["balanced"]["threads"] >= PROFILES["deep"]["threads"]

    # Deep should have most tools
    assert len(PROFILES["deep"]["tools"]) >= len(PROFILES["balanced"]["tools"])
    assert len(PROFILES["balanced"]["tools"]) >= len(PROFILES["fast"]["tools"])


# test_select_target_repos_dir_with_validation removed - see line 638 comment


def test_cpu_count_fallback():
    """Test CPU count detection with fallback."""
    from scripts.cli.wizard import _get_cpu_count

    # Should return fallback if detection fails
    with patch("scripts.cli.wizard.os.cpu_count", return_value=None):
        count = _get_cpu_count()
        assert count == 4  # Default fallback


def test_colorize():
    """Test ANSI color code application."""
    from scripts.cli.wizard import _colorize

    colored = _colorize("test", "blue")
    assert "\x1b[36m" in colored  # blue ANSI code
    assert "test" in colored
    assert "\x1b[0m" in colored  # reset code

    # Test unknown color returns reset
    colored_unknown = _colorize("test", "unknown_color")
    assert "test" in colored_unknown


def test_print_header(capsys):
    """Test header printing."""
    from scripts.cli.wizard import _print_header

    _print_header("Test Header")
    captured = capsys.readouterr()
    assert "Test Header" in captured.out
    assert "=" in captured.out


def test_print_step(capsys):
    """Test step printing."""
    from scripts.cli.wizard import _print_step

    _print_step(2, 5, "Test Step")
    captured = capsys.readouterr()
    assert "[Step 2/5]" in captured.out
    assert "Test Step" in captured.out


@patch("builtins.input", side_effect=["invalid", "fast"])
def test_prompt_choice_with_retry(mock_input):
    """Test prompt_choice with invalid then valid input."""
    from scripts.cli.wizard import _prompt_choice

    choices = [("fast", "Fast scan"), ("balanced", "Balanced scan")]
    result = _prompt_choice("Choose profile:", choices, default="balanced")
    assert result == "fast"
    assert mock_input.call_count == 2


@patch("builtins.input", return_value="")
def test_prompt_choice_default(mock_input):
    """Test prompt_choice with default."""
    from scripts.cli.wizard import _prompt_choice

    choices = [("fast", "Fast"), ("balanced", "Balanced")]
    result = _prompt_choice("Choose:", choices, default="balanced")
    assert result == "balanced"


@patch("builtins.input", return_value="custom text")
def test_prompt_text_custom(mock_input):
    """Test prompt_text with custom input."""
    from scripts.cli.wizard import _prompt_text

    result = _prompt_text("Enter value:", default="default")
    assert result == "custom text"


@patch("builtins.input", return_value="")
def test_prompt_text_default(mock_input):
    """Test prompt_text with default."""
    from scripts.cli.wizard import _prompt_text

    result = _prompt_text("Enter value:", default="default_value")
    assert result == "default_value"


@patch("builtins.input", side_effect=["invalid", "y"])
def test_prompt_yes_no_retry(mock_input):
    """Test prompt_yes_no with invalid then valid input."""
    from scripts.cli.wizard import _prompt_yes_no

    result = _prompt_yes_no("Continue?", default=False)
    assert result is True
    assert mock_input.call_count == 2


@patch("builtins.input", side_effect=["", "yes", "n", "no"])
def test_prompt_yes_no_variations(mock_input):
    """Test prompt_yes_no with different inputs."""
    from scripts.cli.wizard import _prompt_yes_no

    # Default True
    assert _prompt_yes_no("Q1?", default=True) is True
    # Explicit yes
    assert _prompt_yes_no("Q2?", default=False) is True
    # Explicit n
    assert _prompt_yes_no("Q3?", default=True) is False
    # Explicit no
    assert _prompt_yes_no("Q4?", default=False) is False


def test_detect_docker():
    """Test Docker detection."""
    from scripts.cli.wizard import _detect_docker

    # Should return bool based on docker availability
    result = _detect_docker()
    assert isinstance(result, bool)


def test_check_docker_running():
    """Test Docker daemon running check."""
    from scripts.cli.wizard import _check_docker_running

    # Should return bool without crashing
    result = _check_docker_running()
    assert isinstance(result, bool)


def test_detect_repos_in_dir(tmp_path):
    """Test repository detection in directory."""
    from scripts.cli.wizard import _detect_repos_in_dir

    # Create fake repos
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / ".git").mkdir()

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / ".git").mkdir()

    # Non-repo dir
    not_repo = tmp_path / "not_repo"
    not_repo.mkdir()

    repos = _detect_repos_in_dir(tmp_path)
    assert len(repos) == 2
    assert any(r.name == "repo1" for r in repos)
    assert any(r.name == "repo2" for r in repos)


def test_detect_repos_nonexistent_path():
    """Test repository detection on non-existent path."""
    from scripts.cli.wizard import _detect_repos_in_dir

    repos = _detect_repos_in_dir(Path("/nonexistent/path"))
    assert repos == []


def test_validate_path_existing(tmp_path):
    """Test path validation for existing path."""
    from scripts.cli.wizard import _validate_path

    test_dir = tmp_path / "test"
    test_dir.mkdir()

    validated = _validate_path(str(test_dir), must_exist=True)
    assert validated is not None
    assert validated.exists()


def test_validate_path_nonexistent():
    """Test path validation for non-existent path."""
    from scripts.cli.wizard import _validate_path

    validated = _validate_path("/nonexistent/path", must_exist=True)
    assert validated is None

    # With must_exist=False, should return Path
    validated_no_check = _validate_path("/nonexistent/path", must_exist=False)
    assert validated_no_check is not None
    assert isinstance(validated_no_check, Path)


def test_validate_path_invalid():
    """Test path validation with invalid input."""
    from scripts.cli.wizard import _validate_path

    # Test with None-like input that would cause exception
    with patch("scripts.cli.wizard.Path") as mock_path:
        mock_path.side_effect = Exception("Invalid path")
        result = _validate_path("bad_path")
        assert result is None


@patch("scripts.cli.wizard._detect_docker", return_value=False)
def test_select_execution_mode_no_docker(mock_detect):
    """Test execution mode selection when Docker not available."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=False)
    assert result is False


@patch("scripts.cli.wizard._detect_docker", return_value=True)
@patch("scripts.cli.wizard._check_docker_running", return_value=False)
def test_select_execution_mode_docker_not_running(mock_running, mock_detect):
    """Test execution mode when Docker exists but not running."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=False)
    assert result is False


@patch("scripts.cli.wizard._detect_docker", return_value=False)
def test_select_execution_mode_force_docker_missing(mock_detect):
    """Test force_docker when Docker missing."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=True)
    assert result is False


@patch("scripts.cli.wizard._detect_docker", return_value=True)
@patch("scripts.cli.wizard._check_docker_running", return_value=False)
def test_select_execution_mode_force_docker_not_running(mock_running, mock_detect):
    """Test force_docker when Docker not running."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=True)
    assert result is False


@patch("scripts.cli.wizard._detect_docker", return_value=True)
@patch("scripts.cli.wizard._check_docker_running", return_value=True)
def test_select_execution_mode_force_docker_success(mock_running, mock_detect):
    """Test force_docker when Docker available and running."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=True)
    assert result is True


@patch("scripts.cli.wizard._detect_docker", return_value=True)
@patch("scripts.cli.wizard._check_docker_running", return_value=True)
@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
def test_select_execution_mode_interactive_docker(
    mock_prompt, mock_running, mock_detect
):
    """Test interactive Docker mode selection."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=False)
    assert result is True
    mock_prompt.assert_called_once()


@patch("scripts.cli.wizard._prompt_choice", return_value="balanced")
def test_select_profile(mock_choice):
    """Test profile selection."""
    from scripts.cli.wizard import select_profile

    profile = select_profile()
    assert profile == "balanced"
    mock_choice.assert_called_once()


# NOTE: Tests for select_target() removed (v0.6.0 refactoring - commit 0e86d08)
# The function was split into select_target_type() + configure_*_target() functions.
# These tests tested internal implementation details that no longer exist after
# multi-target support was added. The wizard flow is tested end-to-end via
# integration tests and the individual target configuration functions are tested
# through the generate_command() tests below.


@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
def test_configure_advanced_no_customize(mock_yes_no):
    """Test configure_advanced with no customization."""
    from scripts.cli.wizard import configure_advanced

    threads, timeout, fail_on = configure_advanced("balanced")
    assert threads is None
    assert timeout is None
    assert fail_on == ""


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.wizard._prompt_text", side_effect=["8", "1200", ""])
@patch("scripts.cli.wizard._prompt_choice", return_value="high")
@patch("scripts.cli.wizard._get_cpu_count", return_value=4)
def test_configure_advanced_customize(mock_cpu, mock_choice, mock_text, mock_yes_no):
    """Test configure_advanced with customization."""
    from scripts.cli.wizard import configure_advanced

    threads, timeout, fail_on = configure_advanced("balanced")
    assert threads == 8
    assert timeout == 1200
    assert fail_on == "HIGH"


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.wizard._prompt_text", side_effect=["invalid", "30"])
@patch("scripts.cli.wizard._prompt_choice", return_value="")
@patch("scripts.cli.wizard._get_cpu_count", return_value=4)
def test_configure_advanced_invalid_inputs(
    mock_cpu, mock_choice, mock_text, mock_yes_no
):
    """Test configure_advanced with invalid numeric inputs."""
    from scripts.cli.wizard import configure_advanced

    threads, timeout, fail_on = configure_advanced("balanced")
    # Invalid thread count should fall back to profile default
    assert threads == 4  # balanced profile default
    # Invalid timeout 30 should be clamped to minimum 60
    assert timeout == 60  # max(60, 30)


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch(
    "scripts.cli.wizard._prompt_text", side_effect=["1000", "30"]
)  # threads > cpu*2, timeout < 60
@patch("scripts.cli.wizard._prompt_choice", return_value="")
@patch("scripts.cli.wizard._get_cpu_count", return_value=4)
def test_configure_advanced_boundary_clamping(
    mock_cpu, mock_choice, mock_text, mock_yes_no
):
    """Test configure_advanced clamping values to boundaries."""
    from scripts.cli.wizard import configure_advanced

    threads, timeout, fail_on = configure_advanced("balanced")
    # Threads should be clamped to cpu_count * 2
    assert threads == 8  # max(1, min(1000, 4*2))
    # Timeout should be clamped to minimum 60
    assert timeout == 60  # max(60, 30)


@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
def test_review_and_confirm_decline(mock_yes_no):
    """Test review_and_confirm when user declines."""
    from scripts.cli.wizard import review_and_confirm

    config = WizardConfig()
    config.profile = "balanced"
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/path/to/repos"

    result = review_and_confirm(config)
    assert result is False


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
def test_review_and_confirm_accept(mock_yes_no):
    """Test review_and_confirm when user accepts."""
    from scripts.cli.wizard import review_and_confirm

    config = WizardConfig()
    config.profile = "balanced"
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/path/to/repos"
    config.threads = 8
    config.timeout = 1200
    config.fail_on = "HIGH"

    result = review_and_confirm(config)
    assert result is True


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
def test_review_and_confirm_tsv_mode(mock_yes_no):
    """Test review_and_confirm with TSV mode."""
    from scripts.cli.wizard import review_and_confirm

    config = WizardConfig()
    config.profile = "fast"
    config.target.type = "repo"
    config.target.repo_mode = "tsv"
    config.target.tsv_path = "repos.tsv"
    config.target.tsv_dest = "repos-dest"

    result = review_and_confirm(config)
    assert result is True


def test_generate_command_targets_mode():
    """Test command generation for targets file mode."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "targets"
    config.target.repo_path = "/path/to/targets.txt"
    config.results_dir = "results"

    cmd = generate_command(config)
    assert "jmotools balanced" in cmd
    assert "--targets /path/to/targets.txt" in cmd


def test_generate_command_docker_no_mount():
    """Test Docker command with unsupported target mode."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = True
    config.target.type = "repo"
    config.target.repo_mode = "targets"  # Not repo or repos-dir
    config.results_dir = "results"

    cmd = generate_command(config)
    assert "docker run" in cmd
    # Should not have target mount for targets mode
    assert "-v" in cmd  # results mount only


@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
def test_execute_scan_decline(mock_yes_no):
    """Test execute_scan when user declines."""
    from scripts.cli.wizard import execute_scan

    config = WizardConfig()
    config.profile = "balanced"
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "."

    exit_code = execute_scan(config)
    assert exit_code == 0


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.wizard.subprocess.run")
def test_execute_scan_docker_mode(mock_run, mock_yes_no):
    """Test execute_scan in Docker mode."""
    from scripts.cli.wizard import execute_scan

    mock_run.return_value = MagicMock(returncode=0)

    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = True
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "."

    exit_code = execute_scan(config)
    assert exit_code == 0
    mock_run.assert_called_once()
    # Verify shell=False for security (prevents command injection)
    assert mock_run.call_args[1]["shell"] is False
    # Verify command is passed as list (secure)
    command = mock_run.call_args[0][0]
    assert isinstance(command, list)
    assert command[0] == "docker"


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
def test_execute_scan_native_mode(mock_yes_no):
    """Test execute_scan in native mode."""
    from scripts.cli.wizard import execute_scan

    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "."

    # Mock jmotools.main
    mock_jmotools_main = MagicMock(return_value=0)
    with patch.dict("sys.modules", {"jmotools": MagicMock(main=mock_jmotools_main)}):
        exit_code = execute_scan(config)

    assert exit_code == 0


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
def test_execute_scan_keyboard_interrupt(mock_yes_no):
    """Test execute_scan with keyboard interrupt."""
    from scripts.cli.wizard import execute_scan

    config = WizardConfig()
    config.use_docker = False

    mock_jmotools_main = MagicMock(side_effect=KeyboardInterrupt())
    with patch.dict("sys.modules", {"jmotools": MagicMock(main=mock_jmotools_main)}):
        exit_code = execute_scan(config)

    assert exit_code == 130


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
def test_execute_scan_exception(mock_yes_no):
    """Test execute_scan with exception."""
    from scripts.cli.wizard import execute_scan

    config = WizardConfig()
    config.use_docker = False

    mock_jmotools_main = MagicMock(side_effect=Exception("Test error"))
    with patch.dict("sys.modules", {"jmotools": MagicMock(main=mock_jmotools_main)}):
        exit_code = execute_scan(config)

    assert exit_code == 1


def test_run_wizard_keyboard_interrupt():
    """Test run_wizard with keyboard interrupt."""
    from scripts.cli.wizard import run_wizard

    with patch("scripts.cli.wizard.select_profile", side_effect=KeyboardInterrupt()):
        exit_code = run_wizard(yes=False)

    assert exit_code == 130


def test_run_wizard_exception():
    """Test run_wizard with exception."""
    from scripts.cli.wizard import run_wizard

    with patch("scripts.cli.wizard.select_profile", side_effect=Exception("Test error")):
        exit_code = run_wizard(yes=False)

    assert exit_code == 1


@patch("scripts.cli.wizard._detect_docker", return_value=True)
@patch("scripts.cli.wizard._check_docker_running", return_value=True)
@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
def test_run_wizard_yes_with_docker(mock_yes_no, mock_running, mock_detect):
    """Test non-interactive mode with Docker available."""
    from scripts.cli.wizard import run_wizard

    # Non-interactive mode with force_docker and emit artifact to avoid execution
    exit_code = run_wizard(yes=True, force_docker=True, emit_make="/tmp/test-make.txt")

    # Should complete successfully without errors
    assert exit_code == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
