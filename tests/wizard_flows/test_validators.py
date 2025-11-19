"""Tests for wizard validation utilities."""

from __future__ import annotations

import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch


from scripts.cli.wizard_flows.validators import (
    check_docker_running,
    detect_docker,
    detect_iac_type,
    validate_k8s_context,
    validate_path,
    validate_url,
)


class TestValidatePath:
    """Tests for validate_path function."""

    def test_validate_existing_path(self, tmp_path):
        """Test validating an existing path."""
        result = validate_path(str(tmp_path), must_exist=True)

        assert result is not None
        assert result == tmp_path

    def test_validate_nonexistent_path_must_exist(self):
        """Test validating nonexistent path when must_exist=True."""
        result = validate_path("/nonexistent/path/to/nowhere", must_exist=True)

        assert result is None

    def test_validate_nonexistent_path_no_requirement(self):
        """Test validating nonexistent path when must_exist=False."""
        result = validate_path("/nonexistent/path/to/nowhere", must_exist=False)

        assert result is not None
        assert isinstance(result, Path)

    def test_validate_path_with_tilde_expansion(self, tmp_path):
        """Test path validation with tilde expansion."""
        with patch("pathlib.Path.expanduser") as mock_expand:
            mock_expand.return_value = tmp_path
            result = validate_path("~/test", must_exist=False)

            assert result is not None
            mock_expand.assert_called_once()

    def test_validate_path_oserror(self):
        """Test path validation with OSError."""
        with patch("pathlib.Path.expanduser", side_effect=OSError("Permission denied")):
            result = validate_path("/some/path", must_exist=False)

            assert result is None

    def test_validate_path_valueerror(self):
        """Test path validation with ValueError."""
        with patch("pathlib.Path.expanduser", side_effect=ValueError("Invalid path")):
            result = validate_path("/some/path", must_exist=False)

            assert result is None

    def test_validate_path_typeerror(self):
        """Test path validation with TypeError."""
        with patch("pathlib.Path.expanduser", side_effect=TypeError("Type error")):
            result = validate_path("/some/path", must_exist=False)

            assert result is None

    def test_validate_path_runtimeerror(self):
        """Test path validation with RuntimeError."""
        with patch(
            "pathlib.Path.expanduser", side_effect=RuntimeError("Runtime error")
        ):
            result = validate_path("/some/path", must_exist=False)

            assert result is None

    def test_validate_path_generic_exception(self):
        """Test path validation with generic exception."""
        with patch(
            "pathlib.Path.expanduser", side_effect=Exception("Unexpected error")
        ):
            result = validate_path("/some/path", must_exist=False)

            assert result is None


class TestValidateUrl:
    """Tests for validate_url function."""

    @patch("urllib.request.urlopen")
    def test_validate_url_success(self, mock_urlopen):
        """Test validating a reachable URL."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = validate_url("https://example.com")

        assert result is True

    @patch("urllib.request.urlopen")
    def test_validate_url_non_200_status(self, mock_urlopen):
        """Test validating URL with non-200 status."""
        mock_response = MagicMock()
        mock_response.status = 404
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = validate_url("https://example.com/notfound")

        assert result is False

    @patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", {}, None
        ),
    )
    def test_validate_url_http_error(self, mock_urlopen):
        """Test validating URL with HTTPError."""
        result = validate_url("https://example.com/notfound")

        assert result is False

    @patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("Connection refused"),
    )
    def test_validate_url_url_error(self, mock_urlopen):
        """Test validating URL with URLError."""
        result = validate_url("https://unreachable.example.com")

        assert result is False

    @patch("urllib.request.urlopen", side_effect=TimeoutError())
    def test_validate_url_timeout(self, mock_urlopen):
        """Test validating URL with timeout."""
        result = validate_url("https://slow.example.com", timeout=1)

        assert result is False

    @patch("urllib.request.urlopen", side_effect=Exception("Unexpected error"))
    def test_validate_url_generic_exception(self, mock_urlopen):
        """Test validating URL with generic exception."""
        result = validate_url("https://example.com")

        assert result is False


class TestDetectIacType:
    """Tests for detect_iac_type function."""

    def test_detect_terraform_tfstate_file(self, tmp_path):
        """Test detecting Terraform from .tfstate file."""
        tfstate_file = tmp_path / "terraform.tfstate"
        tfstate_file.touch()

        result = detect_iac_type(tfstate_file)

        assert result == "terraform"

    def test_detect_terraform_tf_extension(self, tmp_path):
        """Test detecting Terraform from .tf extension."""
        tf_file = tmp_path / "main.tfstate"
        tf_file.touch()

        result = detect_iac_type(tf_file)

        assert result == "terraform"

    def test_detect_cloudformation_from_filename(self, tmp_path):
        """Test detecting CloudFormation from filename."""
        cfn_file = tmp_path / "stack-cloudformation.yml"
        cfn_file.write_text("key: value")

        result = detect_iac_type(cfn_file)

        assert result == "cloudformation"

    def test_detect_cloudformation_from_cfn_filename(self, tmp_path):
        """Test detecting CloudFormation from cfn in filename."""
        cfn_file = tmp_path / "template-cfn.yaml"
        cfn_file.write_text("key: value")

        result = detect_iac_type(cfn_file)

        assert result == "cloudformation"

    def test_detect_k8s_from_content(self, tmp_path):
        """Test detecting Kubernetes from content."""
        k8s_file = tmp_path / "deployment.yaml"
        k8s_file.write_text(
            """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
"""
        )

        result = detect_iac_type(k8s_file)

        assert result == "k8s-manifest"

    def test_detect_cloudformation_from_content(self, tmp_path):
        """Test detecting CloudFormation from content."""
        cfn_file = tmp_path / "template.yml"
        cfn_file.write_text(
            """
AWSTemplateFormatVersion: '2010-09-09'
Description: My template
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        )

        result = detect_iac_type(cfn_file)

        assert result == "cloudformation"

    def test_detect_cloudformation_from_resources_only(self, tmp_path):
        """Test detecting CloudFormation from Resources key only."""
        cfn_file = tmp_path / "template.yaml"
        cfn_file.write_text(
            """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        )

        result = detect_iac_type(cfn_file)

        assert result == "cloudformation"

    def test_detect_iac_yaml_default_to_k8s(self, tmp_path):
        """Test YAML files default to k8s-manifest when ambiguous."""
        yaml_file = tmp_path / "unknown.yaml"
        yaml_file.write_text("key: value\nother: data")

        result = detect_iac_type(yaml_file)

        assert result == "k8s-manifest"

    def test_detect_iac_oserror_handling(self, tmp_path):
        """Test IaC detection with OSError when reading file."""
        yaml_file = tmp_path / "broken.yaml"
        yaml_file.touch()

        with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
            result = detect_iac_type(yaml_file)

            # Should fall back to default for .yaml
            assert result == "k8s-manifest"

    def test_detect_iac_unicode_decode_error(self, tmp_path):
        """Test IaC detection with UnicodeDecodeError."""
        yaml_file = tmp_path / "binary.yaml"
        yaml_file.write_bytes(b"\xff\xfe\xfd")

        result = detect_iac_type(yaml_file)

        # Should fall back to default for .yaml
        assert result == "k8s-manifest"

    def test_detect_iac_non_yaml_defaults_terraform(self, tmp_path):
        """Test non-YAML files default to terraform."""
        other_file = tmp_path / "config.txt"
        other_file.touch()

        result = detect_iac_type(other_file)

        assert result == "terraform"


class TestValidateK8sContext:
    """Tests for validate_k8s_context function."""

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run")
    def test_validate_k8s_context_exists(self, mock_run, mock_which):
        """Test validating existing K8s context."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="minikube\nproduction\nstaging\n"
        )

        result = validate_k8s_context("production")

        assert result is True
        mock_run.assert_called_once()

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run")
    def test_validate_k8s_context_not_exists(self, mock_run, mock_which):
        """Test validating non-existent K8s context."""
        mock_run.return_value = MagicMock(returncode=0, stdout="minikube\nproduction\n")

        result = validate_k8s_context("staging")

        assert result is False

    @patch("shutil.which", return_value=None)
    def test_validate_k8s_context_kubectl_not_found(self, mock_which):
        """Test validation when kubectl not found."""
        result = validate_k8s_context("production")

        assert result is False

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run")
    def test_validate_k8s_context_current(self, mock_run, mock_which):
        """Test validating current context."""
        mock_run.return_value = MagicMock(returncode=0, stdout="minikube\n")

        result = validate_k8s_context("current")

        assert result is True

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run")
    def test_validate_k8s_context_current_no_contexts(self, mock_run, mock_which):
        """Test current context validation with no contexts."""
        mock_run.return_value = MagicMock(returncode=0, stdout="")

        result = validate_k8s_context("current")

        assert result is False

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run")
    def test_validate_k8s_context_command_failure(self, mock_run, mock_which):
        """Test validation when kubectl command fails."""
        mock_run.return_value = MagicMock(returncode=1)

        result = validate_k8s_context("production")

        assert result is False

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("kubectl", 5))
    def test_validate_k8s_context_timeout(self, mock_run, mock_which):
        """Test validation with timeout."""
        result = validate_k8s_context("production", timeout=5)

        assert result is False

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_validate_k8s_context_file_not_found(self, mock_run, mock_which):
        """Test validation with FileNotFoundError."""
        result = validate_k8s_context("production")

        assert result is False

    @patch("shutil.which", return_value="/usr/bin/kubectl")
    @patch("subprocess.run", side_effect=Exception("Unexpected error"))
    def test_validate_k8s_context_generic_exception(self, mock_run, mock_which):
        """Test validation with generic exception."""
        result = validate_k8s_context("production")

        assert result is False


class TestDetectDocker:
    """Tests for detect_docker function."""

    @patch("shutil.which", return_value="/usr/bin/docker")
    def test_detect_docker_found(self, mock_which):
        """Test detecting Docker when available."""
        result = detect_docker()

        assert result is True
        mock_which.assert_called_once_with("docker")

    @patch("shutil.which", return_value=None)
    def test_detect_docker_not_found(self, mock_which):
        """Test detecting Docker when not available."""
        result = detect_docker()

        assert result is False
        mock_which.assert_called_once_with("docker")


class TestCheckDockerRunning:
    """Tests for check_docker_running function."""

    @patch("subprocess.run")
    def test_check_docker_running_success(self, mock_run):
        """Test checking Docker daemon when running."""
        mock_run.return_value = MagicMock(returncode=0)

        result = check_docker_running()

        assert result is True
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_check_docker_running_not_running(self, mock_run):
        """Test checking Docker daemon when not running."""
        mock_run.return_value = MagicMock(returncode=1)

        result = check_docker_running()

        assert result is False

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 5))
    def test_check_docker_running_timeout(self, mock_run):
        """Test checking Docker daemon with timeout."""
        result = check_docker_running(timeout=5)

        assert result is False

    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_check_docker_running_file_not_found(self, mock_run):
        """Test checking Docker daemon with FileNotFoundError."""
        result = check_docker_running()

        assert result is False

    @patch("subprocess.run", side_effect=Exception("Unexpected error"))
    def test_check_docker_running_generic_exception(self, mock_run):
        """Test checking Docker daemon with generic exception."""
        result = check_docker_running()

        assert result is False
