"""Unit tests for wizard validation utilities.

Tests cover:
- Path validation and expansion
- URL validation with HEAD requests
- IaC type detection (Terraform, CloudFormation, K8s)
- Kubernetes context validation
- Docker detection and daemon checks

Architecture Note:
- Uses mocks for subprocess calls (kubectl, docker)
- Uses mocks for urllib for URL validation
- Uses tmp_path fixture for file operations
"""

import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch


from scripts.cli.wizard_flows.validators import (
    validate_path,
    validate_url,
    detect_iac_type,
    validate_k8s_context,
    detect_docker,
    check_docker_running,
)


# ========== Category 1: Path Validation ==========


def test_validate_path_valid_existing(tmp_path):
    """Test validate_path with valid existing path."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    result = validate_path(str(test_file), must_exist=True)

    assert result is not None
    assert result == test_file.resolve()


def test_validate_path_valid_nonexisting():
    """Test validate_path with non-existing path when must_exist=False."""
    result = validate_path("/nonexistent/path", must_exist=False)

    assert result is not None
    assert result == Path("/nonexistent/path").resolve()


def test_validate_path_nonexisting_must_exist():
    """Test validate_path returns None for non-existing path when must_exist=True."""
    result = validate_path("/nonexistent/path", must_exist=True)

    assert result is None


def test_validate_path_home_expansion(tmp_path):
    """Test validate_path expands ~ to home directory."""
    # Create test file in temp directory
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    # Mock Path.expanduser to return tmp_path
    with patch("pathlib.Path.expanduser") as mock_expand:
        mock_expand.return_value = test_file

        result = validate_path("~/test.txt", must_exist=True)

        assert result is not None
        mock_expand.assert_called_once()


def test_validate_path_relative_to_absolute(tmp_path):
    """Test validate_path converts relative to absolute paths."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    # Change to tmp_path and use relative path
    import os

    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = validate_path("test.txt", must_exist=True)

        assert result is not None
        assert result.is_absolute()
    finally:
        os.chdir(old_cwd)


def test_validate_path_oserror_handling():
    """Test validate_path handles OSError gracefully."""
    with patch("pathlib.Path.expanduser") as mock_expand:
        mock_expand.side_effect = OSError("Permission denied")

        result = validate_path("/some/path", must_exist=True)

        assert result is None


def test_validate_path_valueerror_handling():
    """Test validate_path handles ValueError gracefully."""
    with patch("pathlib.Path.expanduser") as mock_expand:
        mock_expand.side_effect = ValueError("Invalid path")

        result = validate_path("invalid", must_exist=True)

        assert result is None


def test_validate_path_typeerror_handling():
    """Test validate_path handles TypeError gracefully."""
    with patch("pathlib.Path.__init__") as mock_init:
        mock_init.side_effect = TypeError("Expected string")

        result = validate_path(None, must_exist=True)

        assert result is None


def test_validate_path_empty_string():
    """Test validate_path with empty string."""
    result = validate_path("", must_exist=False)

    # Should handle empty string gracefully
    assert result is None or result == Path().resolve()


# ========== Category 2: URL Validation ==========


def test_validate_url_success():
    """Test validate_url with reachable URL."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = validate_url("https://example.com")

        assert result is True
        mock_urlopen.assert_called_once()


def test_validate_url_http_error():
    """Test validate_url with HTTP error (404)."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", {}, None
        )

        result = validate_url("https://example.com")

        assert result is False


def test_validate_url_url_error():
    """Test validate_url with URLError (connection refused)."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        result = validate_url("https://example.com")

        assert result is False


def test_validate_url_timeout():
    """Test validate_url with timeout."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = TimeoutError("Request timeout")

        result = validate_url("https://example.com", timeout=2)

        assert result is False


def test_validate_url_generic_exception():
    """Test validate_url with generic exception."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = Exception("Unknown error")

        result = validate_url("https://example.com")

        assert result is False


def test_validate_url_custom_timeout():
    """Test validate_url uses custom timeout."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = validate_url("https://example.com", timeout=10)

        assert result is True
        # Verify timeout was passed
        assert mock_urlopen.call_args[1]["timeout"] == 10


def test_validate_url_non_200_status():
    """Test validate_url returns False for non-200 status."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 301  # Redirect
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = validate_url("https://example.com")

        assert result is False


# ========== Category 3: IaC Type Detection ==========


def test_detect_iac_type_terraform_extension(tmp_path):
    """Test detect_iac_type recognizes .tfstate extension."""
    iac_file = tmp_path / "infrastructure.tfstate"
    iac_file.write_text('{"version": 4}')

    result = detect_iac_type(iac_file)

    assert result == "terraform"


def test_detect_iac_type_cloudformation_name(tmp_path):
    """Test detect_iac_type recognizes cloudformation in filename."""
    iac_file = tmp_path / "my-cloudformation-stack.yaml"
    iac_file.write_text("AWSTemplateFormatVersion: '2010-09-09'")

    result = detect_iac_type(iac_file)

    assert result == "cloudformation"


def test_detect_iac_type_cloudformation_content(tmp_path):
    """Test detect_iac_type recognizes CloudFormation by content."""
    iac_file = tmp_path / "template.yaml"
    iac_file.write_text(
        """
AWSTemplateFormatVersion: '2010-09-09'
Description: My CloudFormation template
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
    )

    result = detect_iac_type(iac_file)

    assert result == "cloudformation"


def test_detect_iac_type_k8s_manifest_content(tmp_path):
    """Test detect_iac_type recognizes K8s manifest by content."""
    iac_file = tmp_path / "deployment.yaml"
    iac_file.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 3
"""
    )

    result = detect_iac_type(iac_file)

    assert result == "k8s-manifest"


def test_detect_iac_type_yaml_default(tmp_path):
    """Test detect_iac_type defaults to k8s-manifest for unknown YAML."""
    iac_file = tmp_path / "config.yaml"
    iac_file.write_text("key: value\nanother: data")

    result = detect_iac_type(iac_file)

    assert result == "k8s-manifest"


def test_detect_iac_type_json_default(tmp_path):
    """Test detect_iac_type defaults to terraform for .json files."""
    iac_file = tmp_path / "config.json"
    iac_file.write_text('{"key": "value"}')

    result = detect_iac_type(iac_file)

    assert result == "terraform"


def test_detect_iac_type_io_error_handling(tmp_path):
    """Test detect_iac_type handles I/O errors gracefully."""
    iac_file = tmp_path / "test.yaml"
    iac_file.write_text("content")

    # Mock read_text to raise IOError
    with patch.object(Path, "read_text", side_effect=IOError("Permission denied")):
        result = detect_iac_type(iac_file)

    # Should return default for YAML
    assert result == "k8s-manifest"


def test_detect_iac_type_unicode_error_handling(tmp_path):
    """Test detect_iac_type handles UnicodeDecodeError gracefully."""
    iac_file = tmp_path / "binary.yaml"
    iac_file.write_bytes(b"\x80\x81\x82")  # Invalid UTF-8

    result = detect_iac_type(iac_file)

    # Should return default for YAML
    assert result == "k8s-manifest"


def test_detect_iac_type_cfn_abbreviation(tmp_path):
    """Test detect_iac_type recognizes 'cfn' abbreviation."""
    iac_file = tmp_path / "my-cfn-template.yaml"
    iac_file.write_text("Resources:\n  MyResource:")

    result = detect_iac_type(iac_file)

    assert result == "cloudformation"


def test_detect_iac_type_case_insensitive(tmp_path):
    """Test detect_iac_type is case insensitive."""
    iac_file = tmp_path / "infrastructure.TFSTATE"
    iac_file.write_text('{"version": 4}')

    result = detect_iac_type(iac_file)

    assert result == "terraform"


# ========== Category 4: Kubernetes Context Validation ==========


def test_validate_k8s_context_kubectl_not_found():
    """Test validate_k8s_context when kubectl not available."""
    with patch("shutil.which", return_value=None):
        result = validate_k8s_context("my-context")

    assert result is False


def test_validate_k8s_context_current_valid():
    """Test validate_k8s_context with 'current' context."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="minikube\ndocker-desktop\n"
            )

            result = validate_k8s_context("current")

    assert result is True


def test_validate_k8s_context_current_no_contexts():
    """Test validate_k8s_context with 'current' but no contexts available."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")

            result = validate_k8s_context("current")

    assert result is False


def test_validate_k8s_context_specific_exists():
    """Test validate_k8s_context with specific existing context."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="minikube\ndocker-desktop\nprod-cluster\n"
            )

            result = validate_k8s_context("prod-cluster")

    assert result is True


def test_validate_k8s_context_specific_not_exists():
    """Test validate_k8s_context with non-existent context."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="minikube\ndocker-desktop\n"
            )

            result = validate_k8s_context("nonexistent")

    assert result is False


def test_validate_k8s_context_kubectl_error():
    """Test validate_k8s_context when kubectl command fails."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")

            result = validate_k8s_context("my-context")

    assert result is False


def test_validate_k8s_context_timeout():
    """Test validate_k8s_context with timeout."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("kubectl", 5)

            result = validate_k8s_context("my-context", timeout=5)

    assert result is False


def test_validate_k8s_context_file_not_found():
    """Test validate_k8s_context with FileNotFoundError."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("kubectl not found")

            result = validate_k8s_context("my-context")

    assert result is False


def test_validate_k8s_context_generic_exception():
    """Test validate_k8s_context with generic exception."""
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Unknown error")

            result = validate_k8s_context("my-context")

    assert result is False


# ========== Category 5: Docker Detection ==========


def test_detect_docker_available():
    """Test detect_docker when docker is available."""
    with patch("shutil.which", return_value="/usr/bin/docker"):
        result = detect_docker()

    assert result is True


def test_detect_docker_not_available():
    """Test detect_docker when docker is not available."""
    with patch("shutil.which", return_value=None):
        result = detect_docker()

    assert result is False


def test_check_docker_running_daemon_running():
    """Test check_docker_running when Docker daemon is running."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        result = check_docker_running()

    assert result is True


def test_check_docker_running_daemon_not_running():
    """Test check_docker_running when Docker daemon is not running."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)

        result = check_docker_running()

    assert result is False


def test_check_docker_running_timeout():
    """Test check_docker_running with timeout."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 5)

        result = check_docker_running(timeout=5)

    assert result is False


def test_check_docker_running_file_not_found():
    """Test check_docker_running when docker command not found."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("docker not found")

        result = check_docker_running()

    assert result is False


def test_check_docker_running_generic_exception():
    """Test check_docker_running with generic exception."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = Exception("Unknown error")

        result = check_docker_running()

    assert result is False


def test_check_docker_running_custom_timeout():
    """Test check_docker_running uses custom timeout."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        result = check_docker_running(timeout=10)

        assert result is True
        # Verify timeout was passed
        assert mock_run.call_args[1]["timeout"] == 10
