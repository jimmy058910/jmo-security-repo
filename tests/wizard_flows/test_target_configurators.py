"""Tests for target configurators module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def test_target_configurators_module_imports():
    """Test that target_configurators module can be imported."""
    try:
        from scripts.cli.wizard_flows import target_configurators

        assert target_configurators is not None
    except ImportError as e:
        pytest.fail(f"Failed to import target_configurators: {e}")


# Test _prompt_text helper
@patch("builtins.input", return_value="test_value")
def test_prompt_text_with_input(mock_input):
    """Test _prompt_text returns user input."""
    from scripts.cli.wizard_flows.target_configurators import _prompt_text

    result = _prompt_text("Enter value")
    assert result == "test_value"


@patch("builtins.input", return_value="")
def test_prompt_text_with_default(mock_input):
    """Test _prompt_text returns default when input empty."""
    from scripts.cli.wizard_flows.target_configurators import _prompt_text

    result = _prompt_text("Enter value", default="default_value")
    assert result == "default_value"


# Test configure_repo_target
@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators._detector")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("builtins.input", return_value=".")
def test_configure_repo_target_repos_dir_mode(
    mock_input, mock_validate, mock_detector, mock_prompter, tmp_path
):
    """Test repository configuration in repos-dir mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_repo_target

    # Mock TargetConfig class
    class TargetConfig:
        pass

    # Setup mocks
    mock_prompter.prompt_choice.return_value = "repos-dir"
    mock_validate.return_value = tmp_path
    mock_repo = MagicMock()
    mock_repo.name = "test-repo"
    mock_detector.detect_repos.return_value = [mock_repo]
    mock_prompter.colorize.side_effect = lambda text, color: text

    # Create mock print_step function
    print_step = MagicMock()

    config = configure_repo_target(TargetConfig, print_step)

    assert config.type == "repo"
    assert config.repo_mode == "repos-dir"
    assert config.repo_path == str(tmp_path)


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators._detector")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("builtins.input", side_effect=[".", "y"])
def test_configure_repo_target_repos_dir_no_repos(
    mock_input, mock_validate, mock_detector, mock_prompter, tmp_path
):
    """Test repository configuration when no repos detected."""
    from scripts.cli.wizard_flows.target_configurators import configure_repo_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "repos-dir"
    mock_validate.return_value = tmp_path
    mock_detector.detect_repos.return_value = []
    mock_prompter.prompt_yes_no.return_value = True
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_repo_target(TargetConfig, print_step)

    assert config.type == "repo"
    assert config.repo_mode == "repos-dir"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("builtins.input", side_effect=["repos.tsv", "repos-dest"])
def test_configure_repo_target_tsv_mode(mock_input, mock_prompter):
    """Test repository configuration in TSV mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_repo_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "tsv"

    print_step = MagicMock()
    config = configure_repo_target(TargetConfig, print_step)

    assert config.type == "repo"
    assert config.repo_mode == "tsv"
    assert config.tsv_path == "repos.tsv"
    assert config.tsv_dest == "repos-dest"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("builtins.input", return_value="/repo/path")
def test_configure_repo_target_repo_mode(
    mock_input, mock_validate, mock_prompter, tmp_path
):
    """Test repository configuration in single repo mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_repo_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "repo"
    mock_validate.return_value = tmp_path
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_repo_target(TargetConfig, print_step)

    assert config.type == "repo"
    assert config.repo_mode == "repo"


# Test configure_image_target
@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("builtins.input", return_value="nginx:latest")
def test_configure_image_target_single_mode(mock_input, mock_prompter):
    """Test container image configuration in single mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_image_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "single"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_image_target(TargetConfig, print_step)

    assert config.type == "image"
    assert config.image_name == "nginx:latest"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("builtins.input", return_value="images.txt")
def test_configure_image_target_batch_mode(
    mock_input, mock_validate, mock_prompter, tmp_path
):
    """Test container image configuration in batch mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_image_target

    class TargetConfig:
        pass

    # Create mock images file
    images_file = tmp_path / "images.txt"
    images_file.write_text("nginx:latest\npostgres:14\n# comment\n")

    mock_prompter.prompt_choice.return_value = "batch"
    mock_validate.return_value = images_file
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_image_target(TargetConfig, print_step)

    assert config.type == "image"
    assert config.images_file == str(images_file)


# Test configure_iac_target
@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type")
@patch("builtins.input", return_value="main.tf")
def test_configure_iac_target_terraform(
    mock_input, mock_detect, mock_validate, mock_prompter, tmp_path
):
    """Test IaC configuration for Terraform."""
    from scripts.cli.wizard_flows.target_configurators import configure_iac_target

    class TargetConfig:
        pass

    iac_file = tmp_path / "main.tf"
    iac_file.write_text("{}")

    mock_validate.return_value = iac_file
    mock_detect.return_value = "terraform"
    mock_prompter.prompt_choice.return_value = "terraform"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_iac_target(TargetConfig, print_step)

    assert config.type == "iac"
    assert config.iac_path == str(iac_file)
    assert config.iac_type == "terraform"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type")
@patch("builtins.input", return_value="template.yaml")
def test_configure_iac_target_cloudformation(
    mock_input, mock_detect, mock_validate, mock_prompter, tmp_path
):
    """Test IaC configuration for CloudFormation."""
    from scripts.cli.wizard_flows.target_configurators import configure_iac_target

    class TargetConfig:
        pass

    iac_file = tmp_path / "template.yaml"
    iac_file.write_text("AWSTemplateFormatVersion: '2010-09-09'")

    mock_validate.return_value = iac_file
    mock_detect.return_value = "cloudformation"
    mock_prompter.prompt_choice.return_value = "cloudformation"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_iac_target(TargetConfig, print_step)

    assert config.type == "iac"
    assert config.iac_type == "cloudformation"


# Test configure_url_target
@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_url")
@patch("builtins.input", return_value="https://example.com")
def test_configure_url_target_single_mode(mock_input, mock_validate_url, mock_prompter):
    """Test URL configuration in single mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_url_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "single"
    mock_validate_url.return_value = True
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_url_target(TargetConfig, print_step)

    assert config.type == "url"
    assert config.url == "https://example.com"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_url")
@patch("builtins.input", side_effect=["https://bad.com", "y"])
def test_configure_url_target_unreachable_url(
    mock_input, mock_validate_url, mock_prompter
):
    """Test URL configuration with unreachable URL."""
    from scripts.cli.wizard_flows.target_configurators import configure_url_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "single"
    mock_validate_url.return_value = False
    mock_prompter.prompt_yes_no.return_value = True
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_url_target(TargetConfig, print_step)

    assert config.type == "url"
    assert config.url == "https://bad.com"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_path")
@patch("builtins.input", return_value="urls.txt")
def test_configure_url_target_batch_mode(
    mock_input, mock_validate, mock_prompter, tmp_path
):
    """Test URL configuration in batch mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_url_target

    class TargetConfig:
        pass

    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://example.com\nhttps://test.com\n# comment\n")

    mock_prompter.prompt_choice.return_value = "batch"
    mock_validate.return_value = urls_file
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_url_target(TargetConfig, print_step)

    assert config.type == "url"
    assert config.urls_file == str(urls_file)


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("builtins.input", return_value="openapi.yaml")
def test_configure_url_target_api_mode(mock_input, mock_prompter):
    """Test URL configuration in API spec mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_url_target

    class TargetConfig:
        pass

    mock_prompter.prompt_choice.return_value = "api"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_url_target(TargetConfig, print_step)

    assert config.type == "url"
    assert config.api_spec == "openapi.yaml"


# Test configure_gitlab_target
@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("os.getenv")
@patch("builtins.input", side_effect=["https://gitlab.com", "mygroup/myrepo"])
def test_configure_gitlab_target_repo_mode_with_env_token(
    mock_input, mock_getenv, mock_prompter
):
    """Test GitLab configuration in repo mode with env token."""
    from scripts.cli.wizard_flows.target_configurators import configure_gitlab_target

    class TargetConfig:
        pass

    mock_getenv.return_value = "secret-token"
    mock_prompter.prompt_choice.return_value = "repo"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_gitlab_target(TargetConfig, print_step)

    assert config.type == "gitlab"
    assert config.gitlab_url == "https://gitlab.com"
    assert config.gitlab_token == "secret-token"
    assert config.gitlab_repo == "mygroup/myrepo"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("os.getenv")
@patch(
    "builtins.input",
    side_effect=["https://gitlab.example.com", "manual-token", "mygroup/myrepo"],
)
def test_configure_gitlab_target_repo_mode_with_manual_token(
    mock_input, mock_getenv, mock_prompter
):
    """Test GitLab configuration in repo mode with manual token."""
    from scripts.cli.wizard_flows.target_configurators import configure_gitlab_target

    class TargetConfig:
        pass

    mock_getenv.return_value = None
    mock_prompter.prompt_choice.return_value = "repo"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_gitlab_target(TargetConfig, print_step)

    assert config.type == "gitlab"
    assert config.gitlab_token == "manual-token"
    assert config.gitlab_repo == "mygroup/myrepo"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("os.getenv")
@patch("builtins.input", side_effect=["https://gitlab.com", "mygroup"])
def test_configure_gitlab_target_group_mode(mock_input, mock_getenv, mock_prompter):
    """Test GitLab configuration in group mode."""
    from scripts.cli.wizard_flows.target_configurators import configure_gitlab_target

    class TargetConfig:
        pass

    mock_getenv.return_value = "token"
    mock_prompter.prompt_choice.return_value = "group"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_gitlab_target(TargetConfig, print_step)

    assert config.type == "gitlab"
    assert config.gitlab_group == "mygroup"


# Test configure_k8s_target
@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context")
@patch("shutil.which")
@patch("builtins.input", side_effect=["prod", "default"])
def test_configure_k8s_target_single_namespace(
    mock_input, mock_which, mock_validate_k8s, mock_prompter
):
    """Test Kubernetes configuration for single namespace."""
    from scripts.cli.wizard_flows.target_configurators import configure_k8s_target

    class TargetConfig:
        pass

    mock_which.return_value = "/usr/bin/kubectl"
    mock_validate_k8s.return_value = True
    mock_prompter.prompt_choice.return_value = "single"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_k8s_target(TargetConfig, print_step)

    assert config.type == "k8s"
    assert config.k8s_context == "prod"
    assert config.k8s_namespace == "default"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context")
@patch("shutil.which")
@patch("builtins.input", return_value="prod")
def test_configure_k8s_target_all_namespaces(
    mock_input, mock_which, mock_validate_k8s, mock_prompter
):
    """Test Kubernetes configuration for all namespaces."""
    from scripts.cli.wizard_flows.target_configurators import configure_k8s_target

    class TargetConfig:
        pass

    mock_which.return_value = "/usr/bin/kubectl"
    mock_validate_k8s.return_value = True
    mock_prompter.prompt_choice.return_value = "all"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_k8s_target(TargetConfig, print_step)

    assert config.type == "k8s"
    assert config.k8s_context == "prod"
    assert config.k8s_all_namespaces is True


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("shutil.which")
def test_configure_k8s_target_no_kubectl(mock_which, mock_prompter):
    """Test Kubernetes configuration when kubectl not found."""
    from scripts.cli.wizard_flows.target_configurators import configure_k8s_target

    class TargetConfig:
        pass

    mock_which.return_value = None
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_k8s_target(TargetConfig, print_step)

    assert config.type == "k8s"
    assert config.k8s_context == "current"
    assert config.k8s_namespace == "default"


@patch("scripts.cli.wizard_flows.target_configurators._prompter")
@patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context")
@patch("shutil.which")
@patch("builtins.input", side_effect=["bad-context", "y", "default"])
def test_configure_k8s_target_invalid_context_continue(
    mock_input, mock_which, mock_validate_k8s, mock_prompter
):
    """Test Kubernetes configuration with invalid context but continue."""
    from scripts.cli.wizard_flows.target_configurators import configure_k8s_target

    class TargetConfig:
        pass

    mock_which.return_value = "/usr/bin/kubectl"
    mock_validate_k8s.return_value = False
    mock_prompter.prompt_yes_no.return_value = True
    mock_prompter.prompt_choice.return_value = "single"
    mock_prompter.colorize.side_effect = lambda text, color: text

    print_step = MagicMock()
    config = configure_k8s_target(TargetConfig, print_step)

    assert config.type == "k8s"
    assert config.k8s_context == "bad-context"
