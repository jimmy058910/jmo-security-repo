#!/usr/bin/env python3
"""
Comprehensive tests for wizard.py helper/utility functions.

This test file targets the remaining helper functions to push coverage from 78% to 85%+:
- _prompt_text() (lines 145-166): Text input prompts
- _detect_docker() (lines 202-213): Docker availability check
- _check_docker_running() (lines 240-253): Docker daemon status
- _get_cpu_count() (lines 267-294): CPU detection
- _detect_repos_in_dir() (lines 307-333): Auto-discover git repos
- _validate_url() (lines 571-595): URL validation
- _detect_iac_type() (lines 643-696): IaC file type detection
- _validate_k8s_context() (lines 738-761): K8s context validation
- _validate_path() (lines 799-877): Path validation and expansion

Coverage target: Add 7-10% to reach 85%+
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, mock_open, patch

import pytest

# Add scripts/ to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.cli.wizard import (
    _prompt_text,
    _prompt_yes_no,
    _detect_docker,
    _check_docker_running,
    _get_cpu_count,
    _detect_repos_in_dir,
    _validate_url,
    _detect_iac_type,
    _validate_k8s_context,
    _validate_path,
)


# ============================================================================
# _PROMPT_TEXT TESTS (lines 145-166)
# ============================================================================


@patch("builtins.input")
def test_prompt_text_with_input(mock_input):
    """Test _prompt_text() when user provides input."""
    mock_input.return_value = "my-value"
    result = _prompt_text("Enter value:")
    assert result == "my-value"


@patch("builtins.input")
def test_prompt_text_with_default(mock_input):
    """Test _prompt_text() uses default when input is empty."""
    mock_input.return_value = ""
    result = _prompt_text("Enter value:", default="default-value")
    assert result == "default-value"


@patch("builtins.input")
def test_prompt_text_strips_whitespace(mock_input):
    """Test _prompt_text() strips leading/trailing whitespace."""
    mock_input.return_value = "  spaced value  "
    result = _prompt_text("Enter value:")
    assert result == "spaced value"


@patch("builtins.input")
def test_prompt_text_no_default(mock_input):
    """Test _prompt_text() with empty input and no default."""
    mock_input.return_value = ""
    result = _prompt_text("Enter value:")
    assert result == ""


@patch("builtins.input")
def test_prompt_text_numeric_input(mock_input):
    """Test _prompt_text() handles numeric strings."""
    mock_input.return_value = "12345"
    result = _prompt_text("Enter number:")
    assert result == "12345"


@patch("builtins.input")
def test_prompt_text_special_characters(mock_input):
    """Test _prompt_text() handles special characters."""
    mock_input.return_value = "user@example.com"
    result = _prompt_text("Enter email:")
    assert result == "user@example.com"


# ============================================================================
# _PROMPT_YES_NO TESTS (lines 202-213)
# ============================================================================


@patch("builtins.input")
def test_prompt_yes_no_accepts_y(mock_input):
    """Test _prompt_yes_no() accepts 'y'."""
    mock_input.return_value = "y"
    result = _prompt_yes_no("Continue?")
    assert result is True


@patch("builtins.input")
def test_prompt_yes_no_accepts_yes(mock_input):
    """Test _prompt_yes_no() accepts 'yes'."""
    mock_input.return_value = "yes"
    result = _prompt_yes_no("Continue?")
    assert result is True


@patch("builtins.input")
def test_prompt_yes_no_accepts_uppercase(mock_input):
    """Test _prompt_yes_no() is case-insensitive for 'Y'."""
    mock_input.return_value = "Y"
    result = _prompt_yes_no("Continue?")
    assert result is True


@patch("builtins.input")
def test_prompt_yes_no_declines_n(mock_input):
    """Test _prompt_yes_no() declines on 'n'."""
    mock_input.return_value = "n"
    result = _prompt_yes_no("Continue?")
    assert result is False


@patch("builtins.input")
def test_prompt_yes_no_declines_no(mock_input):
    """Test _prompt_yes_no() declines on 'no'."""
    mock_input.return_value = "no"
    result = _prompt_yes_no("Continue?")
    assert result is False


@patch("builtins.input")
def test_prompt_yes_no_default_true(mock_input):
    """Test _prompt_yes_no() uses default=True for empty input."""
    mock_input.return_value = ""
    result = _prompt_yes_no("Continue?", default=True)
    assert result is True


@patch("builtins.input")
def test_prompt_yes_no_default_false(mock_input):
    """Test _prompt_yes_no() uses default=False for empty input."""
    mock_input.return_value = ""
    result = _prompt_yes_no("Continue?", default=False)
    assert result is False


@patch("builtins.input")
def test_prompt_yes_no_invalid_then_valid(mock_input):
    """Test _prompt_yes_no() re-prompts on invalid input."""
    mock_input.side_effect = ["maybe", "yes"]
    result = _prompt_yes_no("Continue?")
    assert result is True
    assert mock_input.call_count == 2


# ============================================================================
# _DETECT_DOCKER TESTS (lines 202-213)
# ============================================================================


@patch("shutil.which")
def test_detect_docker_available(mock_which):
    """Test _detect_docker() when Docker is available."""
    mock_which.return_value = "/usr/bin/docker"
    result = _detect_docker()
    assert result is True
    mock_which.assert_called_once_with("docker")


@patch("shutil.which")
def test_detect_docker_not_available(mock_which):
    """Test _detect_docker() when Docker is not installed."""
    mock_which.return_value = None
    result = _detect_docker()
    assert result is False


# ============================================================================
# _CHECK_DOCKER_RUNNING TESTS (lines 240-253)
# ============================================================================


@patch("subprocess.run")
def test_check_docker_running_success(mock_run):
    """Test _check_docker_running() when daemon is running."""
    mock_run.return_value = MagicMock(returncode=0, stdout="Server Version: 24.0.0")
    result = _check_docker_running()
    assert result is True


@patch("subprocess.run")
def test_check_docker_running_not_running(mock_run):
    """Test _check_docker_running() when daemon is not running."""
    mock_run.return_value = MagicMock(
        returncode=1, stderr="Cannot connect to Docker daemon"
    )
    result = _check_docker_running()
    assert result is False


@patch("subprocess.run")
def test_check_docker_running_filenotfound(mock_run):
    """Test _check_docker_running() when Docker not installed."""
    mock_run.side_effect = FileNotFoundError()
    result = _check_docker_running()
    assert result is False


# ============================================================================
# _GET_CPU_COUNT TESTS (lines 267-294)
# ============================================================================


@patch("os.cpu_count")
def test_get_cpu_count_normal(mock_cpu_count):
    """Test _get_cpu_count() with normal CPU count."""
    mock_cpu_count.return_value = 8
    result = _get_cpu_count()
    assert result == 8


@patch("os.cpu_count")
def test_get_cpu_count_single_core(mock_cpu_count):
    """Test _get_cpu_count() on single-core system."""
    mock_cpu_count.return_value = 1
    result = _get_cpu_count()
    assert result == 1


@patch("os.cpu_count")
def test_get_cpu_count_none(mock_cpu_count):
    """Test _get_cpu_count() when os.cpu_count() returns None."""
    mock_cpu_count.return_value = None
    result = _get_cpu_count()
    assert result == 4  # Default fallback


@patch("os.cpu_count")
def test_get_cpu_count_large_system(mock_cpu_count):
    """Test _get_cpu_count() on high-core system."""
    mock_cpu_count.return_value = 64
    result = _get_cpu_count()
    assert result == 64


@patch("os.cpu_count")
def test_get_cpu_count_os_error(mock_cpu_count):
    """Test _get_cpu_count() handles OSError."""
    mock_cpu_count.side_effect = OSError("CPU count detection failed")
    result = _get_cpu_count()
    assert result == 4  # Fallback


@patch("os.cpu_count")
def test_get_cpu_count_runtime_error(mock_cpu_count):
    """Test _get_cpu_count() handles RuntimeError."""
    mock_cpu_count.side_effect = RuntimeError("System error")
    result = _get_cpu_count()
    assert result == 4  # Fallback


# ============================================================================
# _DETECT_REPOS_IN_DIR TESTS (lines 307-333)
# ============================================================================


def test_detect_repos_in_dir_with_git_repos(tmp_path):
    """Test _detect_repos_in_dir() finds git repositories."""
    # Create fake repos with .git directories
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / ".git").mkdir()

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / ".git").mkdir()

    # Non-repo directory
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()

    result = _detect_repos_in_dir(tmp_path)
    assert len(result) == 2
    assert repo1 in result
    assert repo2 in result
    assert non_repo not in result


def test_detect_repos_in_dir_no_repos(tmp_path):
    """Test _detect_repos_in_dir() returns empty when no repos."""
    # Create directories without .git
    (tmp_path / "dir1").mkdir()
    (tmp_path / "dir2").mkdir()

    result = _detect_repos_in_dir(tmp_path)
    assert len(result) == 0


def test_detect_repos_in_dir_empty_directory(tmp_path):
    """Test _detect_repos_in_dir() on empty directory."""
    result = _detect_repos_in_dir(tmp_path)
    assert len(result) == 0


def test_detect_repos_in_dir_nested_repos(tmp_path):
    """Test _detect_repos_in_dir() doesn't recurse into subdirectories."""
    # Top-level repo
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / ".git").mkdir()

    # Nested repo (should not be detected - only 1 level deep)
    nested = repo1 / "nested-repo"
    nested.mkdir()
    (nested / ".git").mkdir()

    result = _detect_repos_in_dir(tmp_path)
    assert len(result) == 1
    assert repo1 in result
    assert nested not in result


def test_detect_repos_in_dir_files_ignored(tmp_path):
    """Test _detect_repos_in_dir() ignores files."""
    # Create a file
    (tmp_path / "file.txt").write_text("content")

    # Create a repo
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    result = _detect_repos_in_dir(tmp_path)
    assert len(result) == 1
    assert repo in result


def test_detect_repos_in_dir_git_file_not_directory(tmp_path):
    """Test _detect_repos_in_dir() handles .git as file (submodule case)."""
    # Create directory with .git file instead of directory
    repo = tmp_path / "submodule"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: ../.git/modules/submodule")

    result = _detect_repos_in_dir(tmp_path)
    # Should still detect it as a repo if .git exists (even as file)
    assert len(result) == 1
    assert repo in result


# ============================================================================
# _VALIDATE_URL TESTS (lines 230-254)
# ============================================================================
# NOTE: _validate_url() makes actual HTTP HEAD requests to check reachability


@patch("urllib.request.urlopen")
def test_validate_url_reachable(mock_urlopen):
    """Test _validate_url() with reachable URL."""
    mock_response = MagicMock()
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=False)
    mock_response.status = 200
    mock_urlopen.return_value = mock_response

    result = _validate_url("https://example.com")
    assert result is True


@patch("urllib.request.urlopen")
def test_validate_url_unreachable(mock_urlopen):
    """Test _validate_url() with unreachable URL."""
    import urllib.error

    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

    result = _validate_url("https://nonexistent.example.com")
    assert result is False


@patch("urllib.request.urlopen")
def test_validate_url_timeout(mock_urlopen):
    """Test _validate_url() with timeout."""
    mock_urlopen.side_effect = TimeoutError("Request timeout")

    result = _validate_url("https://slow.example.com")
    assert result is False


@patch("urllib.request.urlopen")
def test_validate_url_http_error(mock_urlopen):
    """Test _validate_url() with HTTP error (404, 500, etc.)."""
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        "https://example.com", 404, "Not Found", {}, None
    )

    result = _validate_url("https://example.com/notfound")
    assert result is False


# ============================================================================
# _DETECT_IAC_TYPE TESTS (lines 643-696)
# ============================================================================


def test_detect_iac_type_terraform(tmp_path):
    """Test _detect_iac_type() detects Terraform files."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_instance" "example" {}')
    result = _detect_iac_type(tf_file)
    assert result == "terraform"


def test_detect_iac_type_terraform_json(tmp_path):
    """Test _detect_iac_type() detects Terraform JSON."""
    tf_file = tmp_path / "main.tf.json"
    tf_file.write_text('{"resource": {}}')
    result = _detect_iac_type(tf_file)
    assert result == "terraform"


def test_detect_iac_type_cloudformation_yaml(tmp_path):
    """Test _detect_iac_type() detects CloudFormation YAML."""
    cf_file = tmp_path / "template.yaml"
    cf_file.write_text('AWSTemplateFormatVersion: "2010-09-09"')
    result = _detect_iac_type(cf_file)
    assert result == "cloudformation"


def test_detect_iac_type_cloudformation_json(tmp_path):
    """Test _detect_iac_type() for JSON files (defaults to terraform)."""
    cf_file = tmp_path / "template.json"
    cf_file.write_text('{"AWSTemplateFormatVersion": "2010-09-09"}')
    result = _detect_iac_type(cf_file)
    assert result == "terraform"  # JSON files default to terraform


def test_detect_iac_type_kubernetes_yaml(tmp_path):
    """Test _detect_iac_type() detects Kubernetes YAML."""
    k8s_file = tmp_path / "deployment.yaml"
    k8s_file.write_text("apiVersion: apps/v1\nkind: Deployment")
    result = _detect_iac_type(k8s_file)
    assert result == "k8s-manifest"  # Actual return value


def test_detect_iac_type_kubernetes_yml(tmp_path):
    """Test _detect_iac_type() detects K8s .yml files."""
    k8s_file = tmp_path / "service.yml"
    k8s_file.write_text("apiVersion: v1\nkind: Service")
    result = _detect_iac_type(k8s_file)
    assert result == "k8s-manifest"


def test_detect_iac_type_unknown_extension(tmp_path):
    """Test _detect_iac_type() defaults to terraform for unknown files."""
    unknown_file = tmp_path / "config.txt"
    unknown_file.write_text("some content")
    result = _detect_iac_type(unknown_file)
    assert result == "terraform"  # Default


def test_detect_iac_type_empty_yaml(tmp_path):
    """Test _detect_iac_type() handles empty YAML (defaults to k8s-manifest)."""
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("")
    result = _detect_iac_type(empty_file)
    assert result == "k8s-manifest"  # Default for YAML


def test_detect_iac_type_tfstate_file(tmp_path):
    """Test _detect_iac_type() detects .tfstate files."""
    tfstate_file = tmp_path / "terraform.tfstate"
    tfstate_file.write_text('{"version": 4}')
    result = _detect_iac_type(tfstate_file)
    assert result == "terraform"


def test_detect_iac_type_cloudformation_in_name(tmp_path):
    """Test _detect_iac_type() detects cloudformation in filename."""
    cf_file = tmp_path / "cloudformation-template.yaml"
    cf_file.write_text("Resources:\n  Bucket: {}")
    result = _detect_iac_type(cf_file)
    assert result == "cloudformation"


def test_detect_iac_type_cfn_in_name(tmp_path):
    """Test _detect_iac_type() detects cfn in filename."""
    cfn_file = tmp_path / "cfn-stack.yml"
    cfn_file.write_text('AWSTemplateFormatVersion: "2010-09-09"')
    result = _detect_iac_type(cfn_file)
    assert result == "cloudformation"


def test_detect_iac_type_yaml_read_error(tmp_path):
    """Test _detect_iac_type() handles file read errors gracefully."""
    # Create a file and make it unreadable
    yaml_file = tmp_path / "unreadable.yaml"
    yaml_file.write_text("content")
    yaml_file.chmod(0o000)  # Remove all permissions

    try:
        result = _detect_iac_type(yaml_file)
        # Should default to k8s-manifest even on read error
        assert result == "k8s-manifest"
    finally:
        yaml_file.chmod(0o644)  # Restore permissions for cleanup


# ============================================================================
# _VALIDATE_K8S_CONTEXT TESTS (lines 738-761)
# ============================================================================


@patch("shutil.which")
@patch("subprocess.run")
def test_validate_k8s_context_valid(mock_run, mock_which):
    """Test _validate_k8s_context() with valid context."""
    mock_which.return_value = "/usr/bin/kubectl"  # kubectl is available
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "minikube\nproduction\nstaging\n"  # str output
    mock_run.return_value = mock_result
    result = _validate_k8s_context("minikube")
    assert result is True


@patch("subprocess.run")
def test_validate_k8s_context_invalid(mock_run):
    """Test _validate_k8s_context() with invalid context."""
    mock_run.return_value = MagicMock(returncode=0, stdout="minikube\nproduction\n")
    result = _validate_k8s_context("nonexistent")
    assert result is False


@patch("subprocess.run")
def test_validate_k8s_context_kubectl_not_found(mock_run):
    """Test _validate_k8s_context() when kubectl not installed."""
    mock_run.side_effect = FileNotFoundError("kubectl not found")
    result = _validate_k8s_context("minikube")
    assert result is False


@patch("subprocess.run")
def test_validate_k8s_context_kubectl_error(mock_run):
    """Test _validate_k8s_context() when kubectl fails."""
    mock_run.return_value = MagicMock(returncode=1, stderr="Error")
    result = _validate_k8s_context("minikube")
    assert result is False


@patch("subprocess.run")
def test_validate_k8s_context_exception(mock_run):
    """Test _validate_k8s_context() handles exceptions."""
    mock_run.side_effect = Exception("Unexpected error")
    result = _validate_k8s_context("minikube")
    assert result is False


@patch("shutil.which")
@patch("subprocess.run")
def test_validate_k8s_context_current(mock_run, mock_which):
    """Test _validate_k8s_context() with 'current' context."""
    mock_which.return_value = "/usr/bin/kubectl"
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "minikube\n"  # Has at least one context
    mock_run.return_value = mock_result
    result = _validate_k8s_context("current")
    assert result is True


@patch("shutil.which")
@patch("subprocess.run")
def test_validate_k8s_context_timeout(mock_run, mock_which):
    """Test _validate_k8s_context() handles timeout."""
    mock_which.return_value = "/usr/bin/kubectl"
    import subprocess

    mock_run.side_effect = subprocess.TimeoutExpired("kubectl", 5)
    result = _validate_k8s_context("minikube")
    assert result is False


# ============================================================================
# _VALIDATE_PATH TESTS (lines 799-877)
# ============================================================================


def test_validate_path_existing_file(tmp_path):
    """Test _validate_path() with existing file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    result = _validate_path(str(test_file), must_exist=True)
    assert result == test_file


def test_validate_path_existing_directory(tmp_path):
    """Test _validate_path() with existing directory."""
    test_dir = tmp_path / "testdir"
    test_dir.mkdir()
    result = _validate_path(str(test_dir), must_exist=True)
    assert result == test_dir


def test_validate_path_nonexistent_must_exist(tmp_path):
    """Test _validate_path() rejects nonexistent path when must_exist=True."""
    nonexistent = tmp_path / "doesnotexist.txt"
    result = _validate_path(str(nonexistent), must_exist=True)
    assert result is None


def test_validate_path_nonexistent_optional(tmp_path):
    """Test _validate_path() accepts nonexistent path when must_exist=False."""
    nonexistent = tmp_path / "newfile.txt"
    result = _validate_path(str(nonexistent), must_exist=False)
    assert result == nonexistent


def test_validate_path_tilde_expansion(tmp_path):
    """Test _validate_path() expands ~ to home directory."""
    with patch.dict(os.environ, {"HOME": str(tmp_path)}):
        result = _validate_path("~/test.txt", must_exist=False)
        assert result is not None
        assert str(result).startswith(str(tmp_path))


def test_validate_path_relative_to_absolute(tmp_path):
    """Test _validate_path() converts relative to absolute."""
    with patch("pathlib.Path.cwd", return_value=tmp_path):
        result = _validate_path("relative/path.txt", must_exist=False)
        assert result is not None
        assert result.is_absolute()


def test_validate_path_empty_string():
    """Test _validate_path() with empty string (returns current dir)."""
    result = _validate_path("", must_exist=False)
    # Empty string treated as current directory
    assert result is not None
    assert result.exists()


def test_validate_path_whitespace_only():
    """Test _validate_path() with whitespace (treated as path string)."""
    result = _validate_path("   ", must_exist=False)
    # Whitespace path is still a valid path object
    assert result is not None


def test_validate_path_parent_doesnt_exist(tmp_path):
    """Test _validate_path() when parent directory doesn't exist."""
    nonexistent_parent = tmp_path / "nodir" / "file.txt"
    result = _validate_path(str(nonexistent_parent), must_exist=False)
    # Should still return the path even if parent doesn't exist
    assert result is not None


def test_validate_path_current_directory():
    """Test _validate_path() handles current directory '.'."""
    result = _validate_path(".", must_exist=True)
    assert result is not None
    assert result.exists()


def test_validate_path_parent_directory():
    """Test _validate_path() handles parent directory '..'."""
    result = _validate_path("..", must_exist=True)
    assert result is not None
    assert result.exists()
