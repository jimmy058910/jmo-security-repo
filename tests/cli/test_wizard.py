"""Tests for the interactive wizard."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.wizard import (
    WizardConfig,
    generate_command,
    run_wizard,
)
from scripts.cli.wizard_generators import (
    JMO_DOCKER_IMAGE_FULL,
    JMO_DOCKER_TAG,
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)
from scripts.core.tool_registry import TOOL_MATRIX


def _fake_tool_manager() -> MagicMock:
    """A `ToolManager()` replacement for tests that don't care about real
    tool status.

    `configure_advanced()` and `review_and_confirm()` both do
    `from scripts.cli.tool_manager import ToolManager; tm = ToolManager()`
    unconditionally, as part of printing an informational tool-count line -
    not something any test below asserts on. Left unmocked, `tm.check_tool()`
    resolves and shells out to whatever scanner binaries actually happen to
    be on the machine's PATH (#907: on a dev box with a `--user` semgrep
    install, that is a real, unmarked `semgrep --version` spawn on every one
    of these tests). `check_matrix()` returns no statuses, which
    `review_and_confirm()`'s dynamic time-estimate path already handles.
    """
    tm = MagicMock()
    tm.get_tool_summary.return_value = MagicMock(
        execution_ready=10,
        total=len(TOOL_MATRIX),
    )
    tm.check_matrix.return_value = {}
    tm.check_tool.return_value = MagicMock(
        installed=True, version="1.0.0", startup_ok=True
    )
    return tm


def test_wizard_config_to_dict():
    """Test WizardConfig serialization."""
    config = WizardConfig()
    # v0.6.0+ uses nested TargetConfig instead of flat target_mode/target_path
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/path/to/repos"

    data = config.to_dict()
    # v2.0.0: there are no scan profiles, so the config carries none
    assert "profile" not in data
    assert "target" in data
    assert data["target"]["type"] == "repo"
    assert data["target"]["repo_mode"] == "repos-dir"
    assert data["target"]["repo_path"] == "/path/to/repos"
    assert "use_docker" in data
    assert "results_dir" in data


def test_generate_command_native_repos_dir():
    """Test command generation for native mode with repos-dir."""
    config = WizardConfig()
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

    assert cmd.startswith("jmo scan ")
    assert "--profile-name" not in cmd
    assert "--repos-dir /home/user/repos" in cmd
    assert "--results-dir results" in cmd
    assert "--threads 4" in cmd
    assert "--timeout 600" in cmd
    assert "--human-logs" in cmd


def test_generate_command_native_with_fail_on():
    """A severity threshold makes the native command `jmo ci`, not `jmo scan`.

    `jmo scan` defines no --fail-on: argparse resolved `--fail-on HIGH` as the
    prefix of --fail-on-store-error and rejected HIGH, so every wizard run with
    a threshold exited 2. `jmo ci` is scan + report + the threshold.
    """
    config = WizardConfig()
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "/home/user/myrepo"
    config.results_dir = "results"
    config.fail_on = "HIGH"

    cmd = generate_command(config)

    assert cmd.startswith("jmo ci ")
    assert "jmo scan" not in cmd
    assert "--profile-name" not in cmd
    assert "--repo /home/user/myrepo" in cmd
    assert "--fail-on HIGH" in cmd


def test_generate_command_docker_mode():
    """Test command generation for Docker mode."""
    config = WizardConfig()
    config.use_docker = True
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/home/user/repos"
    config.results_dir = "results"
    config.threads = 2
    config.timeout = 900

    cmd = generate_command(config)

    assert "docker run" in cmd
    assert JMO_DOCKER_IMAGE_FULL in cmd
    assert "--profile-name" not in cmd
    assert "/scan" in cmd
    assert "/results" in cmd


def test_docker_tag_tracks_the_shipped_version():
    """The wizard's Docker tag must name the release the user is running.

    #1075: every other assertion about the image compares JMO_DOCKER_IMAGE_FULL
    to a string rendered from that same constant, so all five stayed green while
    the hand-maintained tag sat at v1.0.5 through v1.0.6, v1.0.7 and v1.0.8 --
    `jmo wizard` emitted `docker run ... :v1.0.5` while `jmo --version` said
    1.0.8. A guard has to compare against an independent authority.
    """
    from scripts.cli.jmo import __version__

    assert f"v{__version__}" == JMO_DOCKER_TAG
    assert JMO_DOCKER_IMAGE_FULL.endswith(f":v{__version__}")


def test_generate_command_tsv_mode():
    """Test command generation for TSV clone mode."""
    config = WizardConfig()
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "tsv"
    config.target.tsv_path = "./repos.tsv"
    config.target.tsv_dest = "repos-tsv"
    config.results_dir = "results"

    cmd = generate_command(config)

    assert "jmo scan" in cmd
    assert "--profile-name" not in cmd
    assert "--tsv ./repos.tsv" in cmd
    assert "--dest repos-tsv" in cmd


def test_generate_makefile_target():
    """Test Makefile target generation."""
    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/home/user/repos"

    command = generate_command(config)
    makefile = generate_makefile_target(config, command)

    assert ".PHONY: security-scan" in makefile
    assert "security-scan:" in makefile
    assert "jmo scan" in makefile
    assert "--profile-name" not in makefile
    assert "/home/user/repos" in makefile


def test_generate_shell_script():
    """Test shell script generation."""
    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "/home/user/myrepo"

    command = generate_command(config)
    script = generate_shell_script(config, command)

    assert "#!/usr/bin/env bash" in script
    assert "set -euo pipefail" in script
    assert "jmo scan" in script
    assert "--profile-name" not in script
    assert "/home/user/myrepo" in script


def test_generate_github_actions_native():
    """Test GitHub Actions workflow generation for native mode.

    With a threshold the step runs `jmo ci`, the subcommand that defines
    --fail-on; `jmo scan --fail-on HIGH` is rejected by the parser.
    """
    config = WizardConfig()
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "."
    config.threads = 4
    config.timeout = 600
    config.fail_on = "HIGH"

    workflow = generate_github_actions(config)

    assert "name: Security Scan" in workflow
    assert "on:" in workflow
    assert "runs-on: ubuntu-latest" in workflow
    assert "actions/checkout@v4" in workflow
    assert "actions/setup-python@v5" in workflow
    assert "jmo ci" in workflow
    assert "jmo scan" not in workflow
    assert "--profile-name" not in workflow
    assert "--threads 4" in workflow
    assert "--timeout 600" in workflow
    assert "--fail-on HIGH" in workflow
    assert "upload-artifact@v4" in workflow
    assert "upload-sarif@v3" in workflow


def test_generate_github_actions_docker():
    """Test GitHub Actions workflow generation for Docker mode."""
    config = WizardConfig()
    config.use_docker = True
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "."
    config.threads = 2
    config.timeout = 900

    workflow = generate_github_actions(config)

    assert "name: Security Scan" in workflow
    assert "container:" in workflow
    assert JMO_DOCKER_IMAGE_FULL in workflow
    assert "jmo scan" in workflow
    assert "--profile-name" not in workflow
    # The config's own values win over the jmo.yml / built-in defaults
    assert "--threads 2" in workflow
    assert "--timeout 900" in workflow
    assert "actions/checkout@v4" in workflow
    assert "upload-artifact@v4" in workflow
    assert "upload-sarif@v3" in workflow
    # Should NOT have setup-python in Docker mode
    assert "actions/setup-python" not in workflow


@patch("scripts.cli.wizard.subprocess.run")
@patch("scripts.cli.wizard._detect_docker")
@patch("scripts.cli.wizard._check_docker_running")
@patch("scripts.cli.wizard._prompt_yes_no")
@patch("scripts.cli.wizard._prompt_choice")
@patch("scripts.cli.tool_manager.ToolManager")
def test_run_wizard_non_interactive(
    mock_tool_manager_class,
    mock_choice,
    mock_yes_no,
    mock_docker_running,
    mock_detect,
    mock_subprocess_run,
):
    """Test wizard in non-interactive (--yes) mode."""
    mock_detect.return_value = False
    mock_docker_running.return_value = False

    # Mock yes/no for "Execute now?" prompt
    mock_yes_no.return_value = True

    # Mock subprocess.run to prevent actual scan execution
    mock_subprocess_run.return_value = MagicMock(returncode=0)

    # Mock ToolManager to prevent real tool checks during scan execution
    mock_tool_manager_class.return_value = _fake_tool_manager()

    with patch("scripts.cli.wizard.Path.cwd", return_value=Path("/home/user/repos")):
        rc = run_wizard(yes=True)

    # Should not have prompted for target selection
    mock_choice.assert_not_called()
    # Note: _prompt_text is no longer mocked since it's only used by configure_advanced
    # which is skipped in --yes mode

    # Should have reasonable exit code
    assert rc == 0


@patch("scripts.cli.wizard.Path.write_text")
@patch("scripts.cli.tool_manager.ToolManager")
def test_run_wizard_emit_makefile(mock_tool_manager_class, mock_write):
    """Test wizard with --emit-make-target."""
    mock_tool_manager_class.return_value = _fake_tool_manager()
    rc = run_wizard(yes=True, emit_make="Makefile.security")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert ".PHONY: security-scan" in content
    assert rc == 0


@patch("scripts.cli.wizard.Path.write_text")
@patch("scripts.cli.wizard.Path.chmod")
@patch("scripts.cli.tool_manager.ToolManager")
def test_run_wizard_emit_script(mock_tool_manager_class, mock_chmod, mock_write):
    """Test wizard with --emit-script."""
    mock_tool_manager_class.return_value = _fake_tool_manager()
    rc = run_wizard(yes=True, emit_script="scan.sh")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert "#!/usr/bin/env bash" in content
    mock_chmod.assert_called_once_with(0o755)
    assert rc == 0


@patch("scripts.cli.wizard.Path.write_text")
@patch("scripts.cli.wizard.Path.mkdir")
@patch("scripts.cli.tool_manager.ToolManager")
def test_run_wizard_emit_gha(mock_tool_manager_class, mock_mkdir, mock_write):
    """Test wizard with --emit-gha."""
    mock_tool_manager_class.return_value = _fake_tool_manager()
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
    config.use_docker = True
    config.threads = 4
    config.timeout = 600
    config.fail_on = "HIGH"

    workflow = generate_github_actions(config)

    # Docker-specific assertions
    assert "container:" in workflow
    assert f"image: {JMO_DOCKER_IMAGE_FULL}" in workflow
    # Docker uses `jmo` directly; a threshold makes it `jmo ci`
    assert "jmo ci --results-dir results" in workflow
    assert "--profile-name" not in workflow
    assert "--fail-on HIGH" in workflow

    # Should NOT have Python setup
    assert "setup-python" not in workflow


# test_select_target_repos_dir_with_validation removed - see line 638 comment


def test_cpu_count_fallback():
    """Test CPU count detection with fallback."""
    from scripts.cli.cpu_utils import get_cpu_count

    # Should return fallback if detection fails
    with patch("scripts.cli.cpu_utils.os.cpu_count", return_value=None):
        count = get_cpu_count()
        assert count == 4  # Default fallback


def test_colorize():
    """Test ANSI color code application."""
    import scripts.cli.wizard_flows.base_flow as bf

    # Force ANSI support (CI has no TTY)
    orig = bf._ANSI_SUPPORTED
    bf._ANSI_SUPPORTED = True
    try:
        from scripts.cli.wizard import _colorize

        colored = _colorize("test", "blue")
        assert "\x1b[36m" in colored  # blue ANSI code
        assert "test" in colored
        assert "\x1b[0m" in colored  # reset code

        # Test unknown color returns reset
        colored_unknown = _colorize("test", "unknown_color")
        assert "test" in colored_unknown
    finally:
        bf._ANSI_SUPPORTED = orig


def test_print_header(capsys):
    """Test header printing (v0.9.0 uses box-drawing characters)."""
    from scripts.cli.wizard import _print_header

    _print_header("Test Header")
    captured = capsys.readouterr()
    assert "Test Header" in captured.out
    # v0.9.0 uses Unicode box-drawing characters (╔═╗ instead of ==)
    assert "═" in captured.out or "=" in captured.out  # Support both old and new style


def test_print_step(capsys):
    """Test step printing."""
    from scripts.cli.wizard import _print_step

    _print_step(2, 5, "Test Step")
    captured = capsys.readouterr()
    assert "[Step 2/5]" in captured.out
    assert "Test Step" in captured.out


@patch("builtins.input", side_effect=["invalid", "repo"])
def test_prompt_choice_with_retry(mock_input):
    """Test prompt_choice with invalid then valid input."""
    from scripts.cli.wizard import _prompt_choice

    choices = [("repo", "Repositories"), ("image", "Container images")]
    result = _prompt_choice("Choose target:", choices, default="image")
    assert result == "repo"
    assert mock_input.call_count == 2


@patch("builtins.input", return_value="")
def test_prompt_choice_default(mock_input):
    """Test prompt_choice with default."""
    from scripts.cli.wizard import _prompt_choice

    choices = [("repo", "Repositories"), ("image", "Container images")]
    result = _prompt_choice("Choose:", choices, default="image")
    assert result == "image"


@patch("builtins.input", return_value="custom text")
def test_prompt_text_custom(mock_input):
    """Test prompt_text with custom input."""
    from scripts.cli.wizard_flows.target_configurators import _prompt_text

    result = _prompt_text("Enter value:", default="default")
    assert result == "custom text"


@patch("builtins.input", return_value="")
def test_prompt_text_default(mock_input):
    """Test prompt_text with default."""
    from scripts.cli.wizard_flows.target_configurators import _prompt_text

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
@patch("builtins.input", return_value="1")  # Select Docker mode (choice "1")
def test_select_execution_mode_interactive_docker(
    mock_input, mock_running, mock_detect
):
    """Test interactive Docker mode selection."""
    from scripts.cli.wizard import select_execution_mode

    result = select_execution_mode(force_docker=False)
    assert result is True
    mock_input.assert_called_once()


# NOTE: Tests for select_target() removed (v0.6.0 refactoring - commit 0e86d08)
# The function was split into select_target_type() + configure_*_target() functions.
# These tests tested internal implementation details that no longer exist after
# multi-target support was added. The wizard flow is tested end-to-end via
# integration tests and the individual target configuration functions are tested
# through the generate_command() tests below.


@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
@patch("scripts.cli.tool_manager.ToolManager")
def test_configure_advanced_no_customize(mock_tool_manager_class, mock_yes_no):
    """Test configure_advanced with no customization."""
    from scripts.cli.wizard import configure_advanced

    mock_tool_manager_class.return_value = _fake_tool_manager()
    threads, timeout, fail_on = configure_advanced()
    assert threads is None
    assert timeout is None
    assert fail_on == ""


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("builtins.input", side_effect=["8", "1200", ""])
@patch("scripts.cli.wizard._prompt_choice", return_value="high")
@patch("scripts.cli.wizard.get_cpu_count", return_value=4)
@patch("scripts.cli.tool_manager.ToolManager")
def test_configure_advanced_customize(
    mock_tool_manager_class, mock_cpu, mock_choice, mock_input, mock_yes_no
):
    """Test configure_advanced with customization."""
    from scripts.cli.wizard import configure_advanced

    mock_tool_manager_class.return_value = _fake_tool_manager()
    threads, timeout, fail_on = configure_advanced()
    assert threads == 8
    assert timeout == 1200
    assert fail_on == "HIGH"


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("builtins.input", side_effect=["invalid", "30"])
@patch("scripts.cli.wizard._prompt_choice", return_value="")
@patch("scripts.cli.wizard.get_cpu_count", return_value=4)
@patch("scripts.cli.wizard.scan_defaults", return_value=(3, 777))
@patch("scripts.cli.tool_manager.ToolManager")
def test_configure_advanced_invalid_inputs(
    mock_tool_manager_class,
    mock_defaults,
    mock_cpu,
    mock_choice,
    mock_input,
    mock_yes_no,
):
    """Test configure_advanced with invalid numeric inputs."""
    from scripts.cli.wizard import configure_advanced

    mock_tool_manager_class.return_value = _fake_tool_manager()
    threads, timeout, fail_on = configure_advanced()
    # Invalid thread count falls back to the scan default (jmo.yml top level,
    # else 4) -- a distinctive stub value proves it is read, not hardcoded
    assert threads == 3
    # Invalid timeout 30 should be clamped to minimum 60
    assert timeout == 60  # max(60, 30)


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("builtins.input", side_effect=["not-a-number", "also-not"])
@patch("scripts.cli.wizard._prompt_choice", return_value="")
@patch("scripts.cli.wizard.get_cpu_count", return_value=4)
@patch("scripts.cli.wizard.scan_defaults", return_value=(7, 1234))
@patch("scripts.cli.tool_manager.ToolManager")
def test_configure_advanced_prompts_and_falls_back_to_scan_defaults(
    mock_tool_manager_class,
    mock_defaults,
    mock_cpu,
    mock_choice,
    mock_input,
    mock_yes_no,
):
    """scan_defaults() is both the offered default and the fallback.

    The Threads/Timeout prompts show it as their default, and an unparseable
    answer for either falls back to it -- not to a profile's numbers, which
    no longer exist.
    """
    from scripts.cli.wizard import configure_advanced

    mock_tool_manager_class.return_value = _fake_tool_manager()
    threads, timeout, _fail_on = configure_advanced()

    prompts = [c.args[0] for c in mock_input.call_args_list]
    assert any(p.startswith("Threads [7]") for p in prompts), prompts
    assert any(p.startswith("Timeout [1234]") for p in prompts), prompts
    assert threads == 7
    assert timeout == 1234


def test_scan_defaults_reads_the_top_level_of_jmo_yml(tmp_path):
    """A jmo.yml's top-level threads/timeout are the wizard's defaults."""
    from scripts.cli.wizard_flows.config_models import scan_defaults

    cfg = tmp_path / "jmo.yml"
    cfg.write_bytes(b"threads: 6\ntimeout: 900\n")

    assert scan_defaults(str(cfg)) == (6, 900)


def test_scan_defaults_threads_auto_is_the_default_thread_count(tmp_path):
    """`threads: auto` has no number to show, so it reads as DEFAULT_THREADS."""
    from scripts.cli.wizard_flows.config_models import DEFAULT_THREADS, scan_defaults

    cfg = tmp_path / "jmo.yml"
    cfg.write_bytes(b"threads: auto\ntimeout: 900\n")

    assert scan_defaults(str(cfg)) == (DEFAULT_THREADS, 900)


def test_scan_defaults_without_a_config_file(tmp_path):
    """No jmo.yml means the built-in constants, which are 4 threads / 600 s."""
    from scripts.cli.wizard_flows.config_models import (
        DEFAULT_THREADS,
        DEFAULT_TIMEOUT,
        scan_defaults,
    )

    missing = tmp_path / "no-such-jmo.yml"

    assert scan_defaults(str(missing)) == (DEFAULT_THREADS, DEFAULT_TIMEOUT)
    assert (DEFAULT_THREADS, DEFAULT_TIMEOUT) == (4, 600)


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("builtins.input", side_effect=["1000", "30"])  # threads > cpu*2, timeout < 60
@patch("scripts.cli.wizard._prompt_choice", return_value="")
@patch("scripts.cli.wizard.get_cpu_count", return_value=4)
@patch("scripts.cli.tool_manager.ToolManager")
def test_configure_advanced_boundary_clamping(
    mock_tool_manager_class, mock_cpu, mock_choice, mock_input, mock_yes_no
):
    """Test configure_advanced clamping values to boundaries."""
    from scripts.cli.wizard import configure_advanced

    mock_tool_manager_class.return_value = _fake_tool_manager()
    threads, timeout, fail_on = configure_advanced()
    # Threads should be clamped to cpu_count * 2
    assert threads == 8  # max(1, min(1000, 4*2))
    # Timeout should be clamped to minimum 60
    assert timeout == 60  # max(60, 30)


@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
@patch("scripts.cli.wizard.scan_defaults", return_value=(3, 777))
@patch("scripts.cli.tool_manager.ToolManager")
def test_configure_advanced_shows_scan_defaults(
    mock_tool_manager_class, mock_defaults, mock_yes_no, capsys
):
    """The defaults shown are the scan's own, not a profile's.

    With profiles gone, threads/timeout come from jmo.yml's top level (or
    4/600); configure_advanced must show those and nothing profile-shaped.
    """
    from scripts.cli.wizard import configure_advanced

    tm = _fake_tool_manager()
    tm.get_tool_summary.return_value = MagicMock(execution_ready=9, total=12)
    mock_tool_manager_class.return_value = tm

    configure_advanced()

    out = capsys.readouterr().out
    assert "Threads: 3" in out
    assert "Timeout: 777s" in out
    assert "Tools: 12 (9 ready)" in out
    assert "Profile" not in out
    # The matrix summary is asked for, not a per-profile one
    tm.get_tool_summary.assert_called_once_with()


@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
@patch("scripts.cli.tool_manager.ToolManager")
def test_review_and_confirm_decline(mock_tool_manager_class, mock_yes_no):
    """Test review_and_confirm when user declines."""
    from scripts.cli.wizard import review_and_confirm

    mock_tool_manager_class.return_value = _fake_tool_manager()
    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/path/to/repos"

    result = review_and_confirm(config)
    assert result is False


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.tool_manager.ToolManager")
def test_review_and_confirm_accept(mock_tool_manager_class, mock_yes_no):
    """Test review_and_confirm when user accepts."""
    from scripts.cli.wizard import review_and_confirm

    mock_tool_manager_class.return_value = _fake_tool_manager()
    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/path/to/repos"
    config.threads = 8
    config.timeout = 1200
    config.fail_on = "HIGH"

    result = review_and_confirm(config)
    assert result is True


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.tool_manager.ToolManager")
def test_review_and_confirm_tsv_mode(mock_tool_manager_class, mock_yes_no):
    """Test review_and_confirm with TSV mode."""
    from scripts.cli.wizard import review_and_confirm

    mock_tool_manager_class.return_value = _fake_tool_manager()
    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "tsv"
    config.target.tsv_path = "repos.tsv"
    config.target.tsv_dest = "repos-dest"

    result = review_and_confirm(config)
    assert result is True


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.wizard.scan_defaults", return_value=(3, 777))
@patch("scripts.cli.tool_manager.ToolManager")
def test_review_and_confirm_summary_uses_matrix_and_scan_defaults(
    mock_tool_manager_class, mock_defaults, mock_yes_no, capsys
):
    """Review shows the scan defaults and ready/total over the tool matrix.

    It used to print the chosen profile and profile-sized counts; now the
    denominator is the matrix summary's `total`, and unset threads/timeout
    show what the scan will actually use.
    """
    from scripts.cli.wizard import review_and_confirm

    tm = _fake_tool_manager()
    tm.get_tool_summary.return_value = MagicMock(execution_ready=9, total=12)
    tm.check_matrix.return_value = {
        "trivy": MagicMock(execution_ready=True),
        "zap": MagicMock(execution_ready=False),
    }
    mock_tool_manager_class.return_value = tm

    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "."

    assert review_and_confirm(config) is True

    out = capsys.readouterr().out
    assert "Threads: 3" in out
    assert "Timeout: 777s" in out
    assert "9/12" in out
    assert "Profile" not in out
    # Only execution-ready tools feed the preview and the time estimate
    assert "trivy" in out
    assert "zap" not in out


def test_generate_command_targets_mode():
    """Test command generation for targets file mode."""
    config = WizardConfig()
    config.use_docker = False
    config.target.type = "repo"
    config.target.repo_mode = "targets"
    config.target.repo_path = "/path/to/targets.txt"
    config.results_dir = "results"

    cmd = generate_command(config)
    assert "jmo scan" in cmd
    assert "--profile-name" not in cmd
    assert "--targets /path/to/targets.txt" in cmd


def test_generate_command_docker_no_mount():
    """Test Docker command with unsupported target mode."""
    config = WizardConfig()
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
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "."

    exit_code = execute_scan(config)
    assert exit_code == 0


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.wizard.subprocess.run")
@patch("scripts.cli.tool_manager.ToolManager")
def test_execute_scan_docker_mode(mock_tool_manager_class, mock_run, mock_yes_no):
    """Test execute_scan in Docker mode."""
    from scripts.cli.wizard import execute_scan

    mock_run.return_value = MagicMock(returncode=0)

    # Mock ToolManager to prevent real tool checks
    mock_tool_manager_class.return_value = _fake_tool_manager()

    config = WizardConfig()
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


@patch("subprocess.run")
@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("scripts.cli.tool_manager.ToolManager")
def test_execute_scan_native_mode(mock_tool_manager_class, mock_yes_no, mock_run):
    """Test execute_scan in native mode."""
    from scripts.cli.wizard import execute_scan

    # Mock subprocess.run to prevent actual command execution
    mock_run.return_value = MagicMock(returncode=0)

    # Mock ToolManager to prevent real tool checks
    mock_tool_manager_class.return_value = _fake_tool_manager()

    config = WizardConfig()
    config.use_docker = False
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
    # Native mode should use python directly, not docker
    assert command[0] != "docker"


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("subprocess.run")
def test_execute_scan_keyboard_interrupt(mock_run, mock_yes_no):
    """Test execute_scan with keyboard interrupt."""
    from scripts.cli.wizard import execute_scan

    config = WizardConfig()
    config.use_docker = False

    # Mock subprocess.run to raise KeyboardInterrupt
    mock_run.side_effect = KeyboardInterrupt()
    exit_code = execute_scan(config)

    assert exit_code == 130


@patch("scripts.cli.wizard._prompt_yes_no", return_value=True)
@patch("subprocess.run")
def test_execute_scan_exception(mock_run, mock_yes_no):
    """Test execute_scan with exception."""
    from scripts.cli.wizard import execute_scan

    config = WizardConfig()
    config.use_docker = False

    # Mock subprocess.run to raise OSError (a system error)
    mock_run.side_effect = OSError("Test error")
    exit_code = execute_scan(config)

    assert exit_code == 1


def test_run_wizard_keyboard_interrupt():
    """Test run_wizard with keyboard interrupt."""
    from scripts.cli.wizard import run_wizard

    with patch(
        "scripts.cli.wizard.select_execution_mode", side_effect=KeyboardInterrupt()
    ):
        exit_code = run_wizard(yes=False)

    assert exit_code == 130


def test_run_wizard_exception():
    """Test run_wizard with exception."""
    from scripts.cli.wizard import run_wizard

    with patch(
        "scripts.cli.wizard.select_execution_mode",
        side_effect=Exception("Test error"),
    ):
        exit_code = run_wizard(yes=False)

    assert exit_code == 1


@patch("scripts.cli.wizard._detect_docker", return_value=True)
@patch("scripts.cli.wizard._check_docker_running", return_value=True)
@patch("scripts.cli.wizard._prompt_yes_no", return_value=False)
def test_run_wizard_yes_with_docker(mock_yes_no, mock_running, mock_detect, tmp_path):
    """Test non-interactive mode with Docker available."""
    from scripts.cli.wizard import run_wizard

    # Non-interactive mode with force_docker and emit artifact to avoid execution
    # Use tmp_path for cross-platform compatibility (Windows/Linux/macOS)
    make_file = tmp_path / "test-make.txt"
    exit_code = run_wizard(yes=True, force_docker=True, emit_make=str(make_file))

    # Should complete successfully without errors
    assert exit_code == 0


def test_scan_completion_summary_reports_against_the_matrix(capsys):
    """The completion summary counts executed tools out of TOOL_MATRIX.

    It used to print the profile and platform/content-skipped lists; none of
    those exist now, and the denominator must be the matrix size.
    """
    from scripts.cli.wizard import _print_scan_completion_summary

    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_path = "/some/repo"
    config.results_dir = "no-such-results-dir"

    _print_scan_completion_summary(config, 0, tools_executed=7)

    out = capsys.readouterr().out
    assert f"Tools executed: 7/{len(TOOL_MATRIX)}" in out
    assert "Profile" not in out
    assert "Skipped" not in out
    assert "/some/repo" in out


# ===== Issue #1 Fix: --emit-script default filename tests =====


def test_emit_script_argparse_default():
    """Test that --emit-script uses default filename when no value provided.

    This verifies the fix for Issue #1 where --emit-script without a filename
    caused a TypeError because Path() received a non-string value.
    """
    import argparse

    # Replicate the argparse configuration
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--emit-script",
        metavar="FILE",
        nargs="?",
        const="jmo-scan.sh",
        type=str,
    )

    # Test with no value (uses const default)
    args = parser.parse_args(["--emit-script"])
    assert args.emit_script == "jmo-scan.sh"

    # Test with explicit value
    args = parser.parse_args(["--emit-script", "custom.sh"])
    assert args.emit_script == "custom.sh"

    # Test without flag (None)
    args = parser.parse_args([])
    assert args.emit_script is None


def test_emit_make_target_argparse_default():
    """Test that --emit-make-target uses default filename when no value provided."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--emit-make-target",
        metavar="FILE",
        nargs="?",
        const="Makefile.jmo",
        type=str,
    )

    args = parser.parse_args(["--emit-make-target"])
    assert args.emit_make_target == "Makefile.jmo"


def test_emit_gha_argparse_default():
    """Test that --emit-gha uses default filename when no value provided."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--emit-gha",
        metavar="FILE",
        nargs="?",
        const=".github/workflows/jmo-security.yml",
        type=str,
    )

    args = parser.parse_args(["--emit-gha"])
    assert args.emit_gha == ".github/workflows/jmo-security.yml"


@patch("scripts.cli.wizard.Path.write_text")
@patch("scripts.cli.wizard.Path.chmod")
@patch("scripts.cli.tool_manager.ToolManager")
def test_run_wizard_emit_script_default_filename(
    mock_tool_manager_class, mock_chmod, mock_write
):
    """Test wizard with --emit-script using default filename.

    This is an integration test verifying the full flow works with default filename.
    """
    # Note: We pass the default filename directly to simulate argparse behavior
    # The actual argparse integration is tested in test_emit_script_argparse_default
    mock_tool_manager_class.return_value = _fake_tool_manager()
    rc = run_wizard(yes=True, emit_script="jmo-scan.sh")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert "#!/usr/bin/env bash" in content
    mock_chmod.assert_called_once_with(0o755)
    assert rc == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
