"""Tests for the interactive wizard."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts" / "cli"))

from wizard import (
    PROFILES,
    WizardConfig,
    generate_command,
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
    run_wizard,
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
    config.target_mode = "repos-dir"
    config.target_path = "/path/to/repos"

    data = config.to_dict()
    assert data["profile"] == "balanced"
    assert data["target_mode"] == "repos-dir"
    assert data["target_path"] == "/path/to/repos"
    assert "use_docker" in data
    assert "results_dir" in data


def test_generate_command_native_repos_dir():
    """Test command generation for native mode with repos-dir."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target_mode = "repos-dir"
    config.target_path = "/home/user/repos"
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
    config.target_mode = "repo"
    config.target_path = "/home/user/myrepo"
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
    config.target_mode = "repos-dir"
    config.target_path = "/home/user/repos"
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
    config.target_mode = "tsv"
    config.tsv_path = "./repos.tsv"
    config.tsv_dest = "repos-tsv"
    config.results_dir = "results"

    cmd = generate_command(config)

    assert "jmotools balanced" in cmd
    assert "--tsv ./repos.tsv" in cmd
    assert "--dest repos-tsv" in cmd


def test_generate_makefile_target():
    """Test Makefile target generation."""
    config = WizardConfig()
    config.profile = "balanced"
    config.target_mode = "repos-dir"
    config.target_path = "/home/user/repos"

    makefile = generate_makefile_target(config)

    assert ".PHONY: security-scan" in makefile
    assert "security-scan:" in makefile
    assert "jmotools balanced" in makefile
    assert "/home/user/repos" in makefile


def test_generate_shell_script():
    """Test shell script generation."""
    config = WizardConfig()
    config.profile = "fast"
    config.target_mode = "repo"
    config.target_path = "/home/user/myrepo"

    script = generate_shell_script(config)

    assert "#!/usr/bin/env bash" in script
    assert "set -euo pipefail" in script
    assert "jmotools fast" in script
    assert "/home/user/myrepo" in script


def test_generate_github_actions_native():
    """Test GitHub Actions workflow generation for native mode."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target_mode = "repos-dir"
    config.target_path = "."
    config.threads = 4
    config.timeout = 600
    config.fail_on = "HIGH"

    workflow = generate_github_actions(config)

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
    config.target_mode = "repo"
    config.target_path = "."
    config.threads = 2
    config.timeout = 900

    workflow = generate_github_actions(config)

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


@patch("wizard._detect_docker")
@patch("wizard._check_docker_running")
@patch("wizard._prompt_yes_no")
@patch("wizard._prompt_choice")
@patch("wizard._prompt_text")
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

    with patch("wizard.Path.cwd", return_value=Path("/home/user/repos")):
        with patch.dict(
            "sys.modules", {"jmotools": MagicMock(main=mock_jmotools_main)}
        ):
            rc = run_wizard(yes=True)

    # Should not have prompted for profile/target selection
    mock_choice.assert_not_called()
    mock_text.assert_not_called()

    # Should have reasonable exit code
    assert rc == 0


@patch("wizard.Path.write_text")
def test_run_wizard_emit_makefile(mock_write):
    """Test wizard with --emit-make-target."""
    rc = run_wizard(yes=True, emit_make="Makefile.security")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert ".PHONY: security-scan" in content
    assert rc == 0


@patch("wizard.Path.write_text")
@patch("wizard.Path.chmod")
def test_run_wizard_emit_script(mock_chmod, mock_write):
    """Test wizard with --emit-script."""
    rc = run_wizard(yes=True, emit_script="scan.sh")

    mock_write.assert_called_once()
    content = mock_write.call_args[0][0]
    assert "#!/usr/bin/env bash" in content
    mock_chmod.assert_called_once_with(0o755)
    assert rc == 0


@patch("wizard.Path.write_text")
@patch("wizard.Path.mkdir")
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

    workflow = generate_github_actions(config)

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


@patch("wizard._validate_path")
@patch("wizard._detect_repos_in_dir")
@patch("wizard._prompt_text")
@patch("wizard._prompt_yes_no")
def test_select_target_repos_dir_with_validation(
    mock_yes_no, mock_text, mock_detect, mock_validate
):
    """Test target selection with path validation."""
    from wizard import select_target

    # Mock path validation
    mock_text.return_value = "/home/user/repos"
    mock_validate.return_value = Path("/home/user/repos")
    mock_detect.return_value = [
        Path("/home/user/repos/repo1"),
        Path("/home/user/repos/repo2"),
    ]

    with patch("wizard._prompt_choice", return_value="repos-dir"):
        mode, path, tsv, tsv_dest = select_target()

    assert mode == "repos-dir"
    assert path == "/home/user/repos"
    assert tsv == ""
    assert tsv_dest == ""


def test_cpu_count_fallback():
    """Test CPU count detection with fallback."""
    from wizard import _get_cpu_count

    # Should return fallback if detection fails
    with patch("wizard.os.cpu_count", return_value=None):
        count = _get_cpu_count()
        assert count == 4  # Default fallback


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
