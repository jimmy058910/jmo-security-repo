"""Tests for scripts/cli/wizard_flows/validators.py.

Coverage targets from TASK-039:
- Lines 31-39: validate_path() exception handling branches
- Lines 53-72: validate_url() HTTP error handling
- Lines 90-116: detect_iac_type() content-based detection
- Lines 133-170: validate_k8s_context() kubectl execution paths
"""

from __future__ import annotations

import subprocess
import urllib.error
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

# Suppress Pyright import warning - module exists at runtime
# pyright: reportMissingImports=false

from scripts.cli.wizard_flows.validators import (
    check_docker_running,
    detect_docker,
    detect_iac_type,
    validate_k8s_context,
    validate_path,
    validate_url,
)

if TYPE_CHECKING:
    pass


# =============================================================================
# validate_path() tests - Lines 26-39
# =============================================================================


class TestValidatePath:
    """Tests for validate_path() function."""

    def test_valid_existing_path(self, tmp_path: Path) -> None:
        """validate_path returns Path for existing directory."""
        result = validate_path(str(tmp_path), must_exist=True)
        assert result == tmp_path

    def test_valid_existing_file(self, tmp_path: Path) -> None:
        """validate_path returns Path for existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        result = validate_path(str(test_file), must_exist=True)
        assert result == test_file

    def test_nonexistent_path_must_exist_true(self, tmp_path: Path) -> None:
        """validate_path returns None for non-existent path when must_exist=True."""
        nonexistent = tmp_path / "does_not_exist"
        result = validate_path(str(nonexistent), must_exist=True)
        assert result is None

    def test_nonexistent_path_must_exist_false(self, tmp_path: Path) -> None:
        """validate_path returns Path for non-existent path when must_exist=False."""
        nonexistent = tmp_path / "does_not_exist"
        result = validate_path(str(nonexistent), must_exist=False)
        assert result == nonexistent

    def test_expands_user_home(self, tmp_path: Path) -> None:
        """validate_path expands ~ to user home directory."""
        # Create a file in tmp_path to simulate home directory
        test_file = tmp_path / "testfile.txt"
        test_file.write_text("content")
        # Use patch to mock Path.expanduser to return tmp_path-based path
        original_expanduser = Path.expanduser

        def mock_expanduser(self: Path) -> Path:
            path_str = str(self)
            if path_str.startswith("~"):
                return tmp_path / path_str[2:]  # Remove "~/" or "~\"
            return original_expanduser(self)

        with patch.object(Path, "expanduser", mock_expanduser):
            result = validate_path("~/testfile.txt", must_exist=True)
            assert result == test_file

    def test_oserror_returns_none(self) -> None:
        """validate_path returns None on OSError (permissions, invalid paths)."""
        with patch.object(Path, "expanduser", side_effect=OSError("Permission denied")):
            result = validate_path("/some/path")
            assert result is None

    def test_valueerror_returns_none(self) -> None:
        """validate_path returns None on ValueError (invalid characters)."""
        with patch.object(Path, "expanduser", side_effect=ValueError("Invalid path")):
            result = validate_path("invalid\x00path")
            assert result is None

    def test_typeerror_returns_none(self) -> None:
        """validate_path returns None on TypeError."""
        # Path() with non-string that gets through the type system
        with patch.object(Path, "expanduser", side_effect=TypeError("not a string")):
            result = validate_path("/some/path")
            assert result is None

    def test_runtimeerror_returns_none(self) -> None:
        """validate_path returns None on RuntimeError (symlink loops)."""
        with patch.object(
            Path, "expanduser", side_effect=RuntimeError("infinite symlink")
        ):
            result = validate_path("/some/path")
            assert result is None

    def test_generic_exception_returns_none(self) -> None:
        """validate_path returns None on unexpected exceptions."""
        with patch.object(Path, "expanduser", side_effect=Exception("unexpected")):
            result = validate_path("/some/path")
            assert result is None


# =============================================================================
# validate_url() tests - Lines 42-72
# =============================================================================


class TestValidateUrl:
    """Tests for validate_url() function."""

    def test_successful_url_validation(self) -> None:
        """validate_url returns True for reachable URL with 200 response."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = validate_url("https://example.com")
            assert result is True

    def test_non_200_response(self) -> None:
        """validate_url returns False for non-200 status codes."""
        mock_response = MagicMock()
        mock_response.status = 301  # Redirect
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = validate_url("https://example.com")
            assert result is False

    def test_http_error_404(self) -> None:
        """validate_url returns False on HTTP 404 Not Found."""
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "https://example.com", 404, "Not Found", {}, None
            ),
        ):
            result = validate_url("https://example.com/nonexistent")
            assert result is False

    def test_http_error_500(self) -> None:
        """validate_url returns False on HTTP 500 Server Error."""
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "https://example.com", 500, "Server Error", {}, None
            ),
        ):
            result = validate_url("https://example.com")
            assert result is False

    def test_url_error_connection_refused(self) -> None:
        """validate_url returns False on connection refused."""
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError(ConnectionRefusedError("refused")),
        ):
            result = validate_url("https://localhost:9999")
            assert result is False

    def test_url_error_dns_failure(self) -> None:
        """validate_url returns False on DNS resolution failure."""
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Name or service not known"),
        ):
            result = validate_url("https://nonexistent.invalid")
            assert result is False

    def test_timeout_error(self) -> None:
        """validate_url returns False on timeout."""
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            result = validate_url("https://slow-server.example.com", timeout=1)
            assert result is False

    def test_generic_exception(self) -> None:
        """validate_url returns False on unexpected exceptions."""
        with patch("urllib.request.urlopen", side_effect=Exception("unexpected")):
            result = validate_url("https://example.com")
            assert result is False

    def test_custom_timeout_value(self) -> None:
        """validate_url passes custom timeout to urlopen."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response) as mock_open:
            validate_url("https://example.com", timeout=10)
            # Check timeout was passed
            call_args = mock_open.call_args
            assert (
                call_args.kwargs.get("timeout") == 10
                or call_args[1].get("timeout") == 10
            )


# =============================================================================
# detect_iac_type() tests - Lines 75-119
# =============================================================================


class TestDetectIacType:
    """Tests for detect_iac_type() function."""

    def test_tfstate_extension(self, tmp_path: Path) -> None:
        """detect_iac_type returns terraform for .tfstate files."""
        tfstate = tmp_path / "state.tfstate"
        tfstate.write_text("{}")
        result = detect_iac_type(tfstate)
        assert result == "terraform"

    def test_tfstate_in_name(self, tmp_path: Path) -> None:
        """detect_iac_type returns terraform for files with tfstate in name."""
        tfstate = tmp_path / "backup.tfstate.backup"
        tfstate.write_text("{}")
        result = detect_iac_type(tfstate)
        assert result == "terraform"

    def test_cloudformation_in_name(self, tmp_path: Path) -> None:
        """detect_iac_type returns cloudformation for files with cloudformation in name."""
        cfn = tmp_path / "cloudformation-template.yaml"
        cfn.write_text("AWSTemplateFormatVersion: '2010-09-09'")
        result = detect_iac_type(cfn)
        assert result == "cloudformation"

    def test_cfn_in_name(self, tmp_path: Path) -> None:
        """detect_iac_type returns cloudformation for files with cfn in name."""
        cfn = tmp_path / "cfn-stack.yml"
        cfn.write_text("Resources:")
        result = detect_iac_type(cfn)
        assert result == "cloudformation"

    def test_yaml_with_k8s_content(self, tmp_path: Path) -> None:
        """detect_iac_type returns k8s-manifest for YAML with apiVersion and kind."""
        k8s = tmp_path / "deployment.yaml"
        k8s.write_text("apiVersion: apps/v1\nkind: Deployment")
        result = detect_iac_type(k8s)
        assert result == "k8s-manifest"

    def test_yaml_with_cloudformation_content(self, tmp_path: Path) -> None:
        """detect_iac_type returns cloudformation for YAML with AWSTemplateFormatVersion."""
        cfn = tmp_path / "stack.yaml"
        cfn.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources:")
        result = detect_iac_type(cfn)
        assert result == "cloudformation"

    def test_yaml_with_resources_only(self, tmp_path: Path) -> None:
        """detect_iac_type returns cloudformation for YAML with Resources: key."""
        cfn = tmp_path / "template.yml"
        cfn.write_text("Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket")
        result = detect_iac_type(cfn)
        assert result == "cloudformation"

    def test_generic_yaml_defaults_to_k8s(self, tmp_path: Path) -> None:
        """detect_iac_type returns k8s-manifest for YAML without specific markers."""
        generic = tmp_path / "config.yaml"
        generic.write_text("key: value\nother: data")
        result = detect_iac_type(generic)
        assert result == "k8s-manifest"

    def test_generic_yml_defaults_to_k8s(self, tmp_path: Path) -> None:
        """detect_iac_type returns k8s-manifest for .yml files."""
        generic = tmp_path / "values.yml"
        generic.write_text("replicas: 3")
        result = detect_iac_type(generic)
        assert result == "k8s-manifest"

    def test_non_yaml_defaults_to_terraform(self, tmp_path: Path) -> None:
        """detect_iac_type returns terraform for non-YAML files."""
        tf = tmp_path / "main.tf"
        tf.write_text('resource "aws_instance" "web" {}')
        result = detect_iac_type(tf)
        assert result == "terraform"

    def test_yaml_oserror_defaults_to_k8s(self, tmp_path: Path) -> None:
        """detect_iac_type handles OSError reading YAML and defaults to k8s-manifest."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("content")

        with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
            result = detect_iac_type(yaml_file)
            assert result == "k8s-manifest"

    def test_yaml_unicode_error_defaults_to_k8s(self, tmp_path: Path) -> None:
        """detect_iac_type handles UnicodeDecodeError and defaults to k8s-manifest."""
        yaml_file = tmp_path / "binary.yaml"
        yaml_file.write_bytes(b"\xff\xfe")  # Invalid UTF-8

        result = detect_iac_type(yaml_file)
        assert result == "k8s-manifest"


# =============================================================================
# validate_k8s_context() tests - Lines 122-170
# =============================================================================


class TestValidateK8sContext:
    """Tests for validate_k8s_context() function."""

    def test_kubectl_not_found(self) -> None:
        """validate_k8s_context returns False when kubectl is not installed."""
        with patch("shutil.which", return_value=None):
            result = validate_k8s_context("my-context")
            assert result is False

    def test_successful_context_validation(self) -> None:
        """validate_k8s_context returns True when context exists."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="minikube\nmy-context\nprod"
            )
            result = validate_k8s_context("my-context")
            assert result is True

    def test_context_not_in_list(self) -> None:
        """validate_k8s_context returns False when context doesn't exist."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="minikube\nprod")
            result = validate_k8s_context("nonexistent-context")
            assert result is False

    def test_current_context_with_any_contexts(self) -> None:
        """validate_k8s_context returns True for 'current' when any context exists."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="minikube")
            result = validate_k8s_context("current")
            assert result is True

    def test_current_context_with_no_contexts(self) -> None:
        """validate_k8s_context returns False for 'current' when no contexts exist."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            result = validate_k8s_context("current")
            assert result is False

    def test_kubectl_command_fails(self) -> None:
        """validate_k8s_context returns False when kubectl command fails."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = validate_k8s_context("my-context")
            assert result is False

    def test_timeout_expired(self) -> None:
        """validate_k8s_context returns False on timeout."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("kubectl", 5)
            ),
        ):
            result = validate_k8s_context("my-context", timeout=5)
            assert result is False

    def test_file_not_found(self) -> None:
        """validate_k8s_context returns False when kubectl binary disappears."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run", side_effect=FileNotFoundError("kubectl")),
        ):
            result = validate_k8s_context("my-context")
            assert result is False

    def test_generic_exception(self) -> None:
        """validate_k8s_context returns False on unexpected exception."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run", side_effect=Exception("unexpected")),
        ):
            result = validate_k8s_context("my-context")
            assert result is False

    def test_custom_timeout_passed_to_subprocess(self) -> None:
        """validate_k8s_context passes custom timeout to subprocess."""
        with (
            patch("shutil.which", return_value="/usr/bin/kubectl"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="context1")
            validate_k8s_context("context1", timeout=15)
            mock_run.assert_called_once()
            assert mock_run.call_args.kwargs.get("timeout") == 15


# =============================================================================
# detect_docker() tests - Line 173-180
# =============================================================================


class TestDetectDocker:
    """Tests for detect_docker() function."""

    def test_docker_available(self) -> None:
        """detect_docker returns True when docker is in PATH."""
        with patch("shutil.which", return_value="/usr/bin/docker"):
            assert detect_docker() is True

    def test_docker_not_available(self) -> None:
        """detect_docker returns False when docker is not in PATH."""
        with patch("shutil.which", return_value=None):
            assert detect_docker() is False


# =============================================================================
# check_docker_running() tests - Lines 183-206
# =============================================================================


class TestCheckDockerRunning:
    """Tests for check_docker_running() function."""

    def test_docker_running(self) -> None:
        """check_docker_running returns True when daemon is responsive."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert check_docker_running() is True

    def test_docker_not_running(self) -> None:
        """check_docker_running returns False when daemon is not responsive."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert check_docker_running() is False

    def test_docker_timeout(self) -> None:
        """check_docker_running returns False on timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 5)
        ):
            assert check_docker_running(timeout=5) is False

    def test_docker_file_not_found(self) -> None:
        """check_docker_running returns False when docker not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError("docker")):
            assert check_docker_running() is False

    def test_docker_generic_exception(self) -> None:
        """check_docker_running returns False on unexpected exception."""
        with patch("subprocess.run", side_effect=Exception("unexpected")):
            assert check_docker_running() is False

    def test_custom_timeout_passed(self) -> None:
        """check_docker_running passes custom timeout to subprocess."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            check_docker_running(timeout=10)
            assert mock_run.call_args.kwargs.get("timeout") == 10
