"""
Comprehensive test suite for wizard.py target configuration functions.

This file systematically tests all configure_*_target() functions to achieve 85%+ coverage.
Created fresh with absolute best standards and proper mocks.
"""

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from scripts.cli.wizard import (
    TargetConfig,
    configure_gitlab_target,
    configure_iac_target,
    configure_image_target,
    configure_k8s_target,
    configure_repo_target,
    configure_url_target,
    generate_command_list,
    select_target_type,
)


# =============================================================================
# Test select_target_type() - Lines 507-526
# =============================================================================


@patch("scripts.cli.wizard._prompt_choice")
def test_select_target_type_repo(mock_choice):
    """Test selecting repository target type."""
    mock_choice.return_value = "repo"
    result = select_target_type()
    assert result == "repo"


@patch("scripts.cli.wizard._prompt_choice")
def test_select_target_type_image(mock_choice):
    """Test selecting container image target type."""
    mock_choice.return_value = "image"
    result = select_target_type()
    assert result == "image"


@patch("scripts.cli.wizard._prompt_choice")
def test_select_target_type_iac(mock_choice):
    """Test selecting IaC target type."""
    mock_choice.return_value = "iac"
    result = select_target_type()
    assert result == "iac"


@patch("scripts.cli.wizard._prompt_choice")
def test_select_target_type_url(mock_choice):
    """Test selecting URL target type."""
    mock_choice.return_value = "url"
    result = select_target_type()
    assert result == "url"


@patch("scripts.cli.wizard._prompt_choice")
def test_select_target_type_gitlab(mock_choice):
    """Test selecting GitLab target type."""
    mock_choice.return_value = "gitlab"
    result = select_target_type()
    assert result == "gitlab"


@patch("scripts.cli.wizard._prompt_choice")
def test_select_target_type_k8s(mock_choice):
    """Test selecting Kubernetes target type."""
    mock_choice.return_value = "k8s"
    result = select_target_type()
    assert result == "k8s"


# =============================================================================
# Test configure_repo_target() - Lines 536-595
# =============================================================================


@patch("scripts.cli.wizard._detect_repos_in_dir")
@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_repo_target_repos_dir_with_repos(
    mock_choice, mock_text, mock_validate, mock_detect
):
    """Test configuring repos-dir mode with detected repositories."""
    mock_choice.return_value = "repos-dir"
    mock_text.return_value = "/test/repos"
    mock_validate.return_value = Path("/test/repos")

    # Mock detecting repos
    repo1, repo2 = MagicMock(), MagicMock()
    repo1.name = "repo1"
    repo2.name = "repo2"
    mock_detect.return_value = [repo1, repo2]

    result = configure_repo_target()

    assert result.type == "repo"
    assert result.repo_mode == "repos-dir"
    assert result.repo_path == "/test/repos"


@patch("scripts.cli.wizard._prompt_yes_no")
@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_repo_target_repos_dir_no_repos_continue(
    mock_choice, mock_text, mock_validate, mock_yes_no
):
    """Test configuring repos-dir mode with no repos but user continues anyway."""
    mock_choice.return_value = "repos-dir"
    mock_text.return_value = "/test/empty"
    mock_validate.return_value = Path("/test/empty")
    mock_yes_no.return_value = True  # Continue anyway

    result = configure_repo_target()

    assert result.type == "repo"
    assert result.repo_mode == "repos-dir"
    assert result.repo_path == "/test/empty"


@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_repo_target_single_repo(mock_choice, mock_text, mock_validate):
    """Test configuring single repository mode."""
    mock_choice.return_value = "repo"
    mock_text.return_value = "/test/my-repo"
    mock_validate.return_value = Path("/test/my-repo")

    result = configure_repo_target()

    assert result.type == "repo"
    assert result.repo_mode == "repo"
    assert result.repo_path == "/test/my-repo"


@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_repo_target_targets_file(mock_choice, mock_text, mock_validate):
    """Test configuring targets file mode."""
    mock_choice.return_value = "targets"
    mock_text.return_value = "/test/targets.txt"
    mock_validate.return_value = Path("/test/targets.txt")

    result = configure_repo_target()

    assert result.type == "repo"
    assert result.repo_mode == "targets"
    assert result.repo_path == "/test/targets.txt"


@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_repo_target_tsv_mode(mock_choice, mock_text):
    """Test configuring TSV clone mode."""
    mock_choice.return_value = "tsv"
    mock_text.side_effect = ["/test/repos.tsv", "/test/cloned-repos"]

    result = configure_repo_target()

    assert result.type == "repo"
    assert result.repo_mode == "tsv"
    assert result.tsv_path == "/test/repos.tsv"
    assert result.tsv_dest == "/test/cloned-repos"


# =============================================================================
# Test configure_image_target() - Lines 605-647
# =============================================================================


@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_image_target_single(mock_choice, mock_text):
    """Test configuring single container image."""
    mock_choice.return_value = "single"
    mock_text.return_value = "nginx:1.21"

    result = configure_image_target()

    assert result.type == "image"
    assert result.image_name == "nginx:1.21"


@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_image_target_batch(mock_choice, mock_text, mock_validate, tmp_path):
    """Test configuring batch images from file."""
    images_file = tmp_path / "images.txt"
    images_file.write_text("nginx:latest\nredis:alpine\npostgres:13\n")

    mock_choice.return_value = "batch"
    mock_text.return_value = str(images_file)
    mock_validate.return_value = images_file

    result = configure_image_target()

    assert result.type == "image"
    assert result.images_file == str(images_file)


# =============================================================================
# Test configure_iac_target() - Lines 657-696
# =============================================================================


@patch("scripts.cli.wizard._detect_iac_type")
@patch("scripts.cli.wizard._prompt_choice")
@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
def test_configure_iac_target_terraform(
    mock_text, mock_validate, mock_choice, mock_detect, tmp_path
):
    """Test configuring Terraform IaC target."""
    tf_file = tmp_path / "terraform.tfstate"
    tf_file.write_text('{"version": 4}')

    mock_text.return_value = str(tf_file)
    mock_validate.return_value = tf_file
    mock_detect.return_value = "terraform"
    mock_choice.return_value = "terraform"

    result = configure_iac_target()

    assert result.type == "iac"
    assert result.iac_type == "terraform"
    assert result.iac_path == str(tf_file)


@patch("scripts.cli.wizard._detect_iac_type")
@patch("scripts.cli.wizard._prompt_choice")
@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
def test_configure_iac_target_cloudformation(
    mock_text, mock_validate, mock_choice, mock_detect, tmp_path
):
    """Test configuring CloudFormation IaC target."""
    cf_file = tmp_path / "template.yaml"
    cf_file.write_text("AWSTemplateFormatVersion: '2010-09-09'")

    mock_text.return_value = str(cf_file)
    mock_validate.return_value = cf_file
    mock_detect.return_value = "cloudformation"
    mock_choice.return_value = "cloudformation"

    result = configure_iac_target()

    assert result.type == "iac"
    assert result.iac_type == "cloudformation"
    assert result.iac_path == str(cf_file)


@patch("scripts.cli.wizard._detect_iac_type")
@patch("scripts.cli.wizard._prompt_choice")
@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
def test_configure_iac_target_k8s_manifest(
    mock_text, mock_validate, mock_choice, mock_detect, tmp_path
):
    """Test configuring Kubernetes manifest IaC target."""
    k8s_file = tmp_path / "deployment.yaml"
    k8s_file.write_text("apiVersion: apps/v1\nkind: Deployment")

    mock_text.return_value = str(k8s_file)
    mock_validate.return_value = k8s_file
    mock_detect.return_value = "k8s-manifest"
    mock_choice.return_value = "k8s-manifest"

    result = configure_iac_target()

    assert result.type == "iac"
    assert result.iac_type == "k8s-manifest"
    assert result.iac_path == str(k8s_file)


# =============================================================================
# Test configure_url_target() - Lines 706-769
# =============================================================================


@patch("scripts.cli.wizard._validate_url")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_url_target_single_reachable(
    mock_choice, mock_text, mock_validate_url
):
    """Test configuring single URL that is reachable."""
    mock_choice.return_value = "single"
    mock_text.return_value = "https://example.com"
    mock_validate_url.return_value = True

    result = configure_url_target()

    assert result.type == "url"
    assert result.url == "https://example.com"


@patch("scripts.cli.wizard._prompt_yes_no")
@patch("scripts.cli.wizard._validate_url")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_url_target_single_unreachable_continue(
    mock_choice, mock_text, mock_validate_url, mock_yes_no
):
    """Test configuring single URL that is unreachable but user continues."""
    mock_choice.return_value = "single"
    mock_text.return_value = "https://unreachable.test"
    mock_validate_url.return_value = False
    mock_yes_no.return_value = True  # Use anyway

    result = configure_url_target()

    assert result.type == "url"
    assert result.url == "https://unreachable.test"


@patch("scripts.cli.wizard._validate_path")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_url_target_batch(mock_choice, mock_text, mock_validate, tmp_path):
    """Test configuring batch URLs from file."""
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://example.com\nhttps://test.com\n")

    mock_choice.return_value = "batch"
    mock_text.return_value = str(urls_file)
    mock_validate.return_value = urls_file

    result = configure_url_target()

    assert result.type == "url"
    assert result.urls_file == str(urls_file)


@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_url_target_api_spec(mock_choice, mock_text):
    """Test configuring API target with OpenAPI spec."""
    mock_choice.return_value = "api"
    mock_text.return_value = "./openapi.yaml"

    result = configure_url_target()

    assert result.type == "url"
    assert result.api_spec == "./openapi.yaml"


# =============================================================================
# Test configure_gitlab_target() - Lines 779-836
# =============================================================================


@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_gitlab_target_repo_with_env_token(
    mock_choice, mock_text, monkeypatch
):
    """Test configuring GitLab repo with token from environment."""
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-env-token")

    mock_choice.return_value = "repo"
    mock_text.side_effect = ["https://gitlab.com", "group/project"]

    result = configure_gitlab_target()

    assert result.type == "gitlab"
    assert result.gitlab_url == "https://gitlab.com"
    assert result.gitlab_token == "glpat-env-token"
    assert result.gitlab_repo == "group/project"


@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_gitlab_target_repo_prompt_token(mock_choice, mock_text, monkeypatch):
    """Test configuring GitLab repo with token from prompt."""
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)

    mock_choice.return_value = "repo"
    mock_text.side_effect = [
        "https://gitlab.example.com",
        "glpat-prompt-token",
        "mygroup/myrepo",
    ]

    result = configure_gitlab_target()

    assert result.type == "gitlab"
    assert result.gitlab_url == "https://gitlab.example.com"
    assert result.gitlab_token == "glpat-prompt-token"
    assert result.gitlab_repo == "mygroup/myrepo"


@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_gitlab_target_group(mock_choice, mock_text, monkeypatch):
    """Test configuring GitLab group."""
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-token")

    mock_choice.return_value = "group"
    mock_text.side_effect = ["https://gitlab.com", "my-organization"]

    result = configure_gitlab_target()

    assert result.type == "gitlab"
    assert result.gitlab_group == "my-organization"


# =============================================================================
# Test configure_k8s_target() - Lines 846-906
# =============================================================================


@patch("shutil.which")
@patch("scripts.cli.wizard._validate_k8s_context")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_k8s_target_single_namespace(
    mock_choice, mock_text, mock_validate, mock_which
):
    """Test configuring Kubernetes single namespace."""
    mock_which.return_value = "/usr/bin/kubectl"  # kubectl is available
    mock_text.side_effect = ["prod-cluster", "production"]
    mock_validate.return_value = True  # Context is valid
    mock_choice.return_value = "single"

    result = configure_k8s_target()

    assert result.type == "k8s"
    assert result.k8s_context == "prod-cluster"
    assert result.k8s_namespace == "production"
    assert result.k8s_all_namespaces is False


@patch("shutil.which")
@patch("scripts.cli.wizard._validate_k8s_context")
@patch("scripts.cli.wizard._prompt_text")
@patch("scripts.cli.wizard._prompt_choice")
def test_configure_k8s_target_all_namespaces(
    mock_choice, mock_text, mock_validate, mock_which
):
    """Test configuring Kubernetes all namespaces."""
    mock_which.return_value = "/usr/bin/kubectl"  # kubectl is available
    mock_text.return_value = "staging-cluster"
    mock_validate.return_value = True  # Context is valid
    mock_choice.return_value = "all"

    result = configure_k8s_target()

    assert result.type == "k8s"
    assert result.k8s_context == "staging-cluster"
    assert result.k8s_all_namespaces is True


# =============================================================================
# Test generate_command_list() - Lines 996-1027
# =============================================================================


def test_generate_command_list_native_repo():
    """Test generating native command list for repository scan."""
    from scripts.cli.wizard import WizardConfig

    config = WizardConfig()
    config.use_docker = False
    config.profile = "fast"
    config.target = TargetConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = "/test/repos"
    config.results_dir = "results"
    config.threads = 4
    config.timeout = 300
    config.fail_on = "HIGH"
    config.log_level = "INFO"
    config.human_logs = True

    cmd_list = generate_command_list(config)

    # cmd_list is a flat list of strings: ["jmotools", "fast", "--repos-dir", ...]
    assert isinstance(cmd_list, list)
    assert len(cmd_list) > 0
    assert "jmotools" in cmd_list or any("jmo" in arg.lower() for arg in cmd_list)
    assert "--repos-dir" in cmd_list
    assert "/test/repos" in cmd_list
    assert "fast" in cmd_list  # Profile is included as command


def test_generate_command_list_docker_image():
    """Test generating Docker command list for container image scan."""
    from scripts.cli.wizard import WizardConfig

    config = WizardConfig()
    config.use_docker = True
    config.profile = "balanced"
    config.target = TargetConfig()
    config.target.type = "image"
    config.target.image_name = "nginx:latest"
    config.results_dir = "results"

    cmd_list = generate_command_list(config)

    # Docker command: ["docker", "run", "--rm", "-v", ..., "jmo-security:latest", ...]
    assert isinstance(cmd_list, list)
    assert len(cmd_list) > 0
    assert "docker" in cmd_list
    assert "run" in cmd_list
    assert "--image" in cmd_list
    assert "nginx:latest" in cmd_list


def test_generate_command_list_gitlab():
    """Test generating command list for GitLab scan."""
    from scripts.cli.wizard import WizardConfig

    config = WizardConfig()
    config.use_docker = False
    config.profile = "deep"
    config.target = TargetConfig()
    config.target.type = "gitlab"
    config.target.gitlab_url = "https://gitlab.com"
    config.target.gitlab_token = "glpat-token"
    config.target.gitlab_repo = "group/repo"
    config.results_dir = "results"

    cmd_list = generate_command_list(config)

    assert isinstance(cmd_list, list)
    assert len(cmd_list) > 0
    assert "--gitlab-repo" in cmd_list
    assert "group/repo" in cmd_list


def test_generate_command_list_k8s():
    """Test generating command list for Kubernetes scan."""
    from scripts.cli.wizard import WizardConfig

    config = WizardConfig()
    config.use_docker = False
    config.profile = "balanced"
    config.target = TargetConfig()
    config.target.type = "k8s"
    config.target.k8s_context = "prod"
    config.target.k8s_namespace = "default"
    config.target.k8s_all_namespaces = False
    config.results_dir = "results"

    cmd_list = generate_command_list(config)

    assert isinstance(cmd_list, list)
    assert len(cmd_list) > 0
    assert "--k8s-context" in cmd_list
    assert "prod" in cmd_list
    assert "--k8s-namespace" in cmd_list
    assert "default" in cmd_list
