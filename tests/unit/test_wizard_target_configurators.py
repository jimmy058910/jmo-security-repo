"""Unit tests for wizard target configuration helpers.

Tests cover:
- Repository target configuration (4 modes: repo, repos-dir, targets, tsv)
- Container image target configuration (single, batch)
- IaC target configuration (terraform, cloudformation, k8s-manifest)
- URL target configuration (single, batch, api)
- GitLab target configuration (repo, group)
- Kubernetes target configuration (single namespace, all namespaces)

Architecture Note:
- Mocks user input (input() builtin)
- Mocks validators (validate_path, validate_url, etc.)
- Mocks PromptHelper methods (prompt_choice, prompt_yes_no)
- Mocks TargetDetector for repo discovery
- Uses MagicMock for target config objects
"""

from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from scripts.cli.wizard_flows.target_configurators import (
    configure_gitlab_target,
    configure_iac_target,
    configure_image_target,
    configure_k8s_target,
    configure_repo_target,
    configure_url_target,
)


# ========== Category 1: Repository Target Configuration ==========


def test_configure_repo_target_single_repo():
    """Test configure_repo_target with single repo mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", return_value="/path/to/repo"):
        mock_prompter.prompt_choice.return_value = "repo"
        mock_validate.return_value = Path("/path/to/repo")

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.type == "repo"
        assert result.repo_mode == "repo"
        assert result.repo_path == "/path/to/repo"
        mock_validate.assert_called_once_with("/path/to/repo", must_exist=True)


def test_configure_repo_target_repos_dir_with_detected_repos():
    """Test configure_repo_target with repos-dir mode and detected repositories."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    # Mock detected repos
    mock_repo1 = MagicMock(name="repo1")
    mock_repo2 = MagicMock(name="repo2")

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators._detector") as mock_detector, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", return_value="/path/to/repos-dir"):
        mock_prompter.prompt_choice.return_value = "repos-dir"
        mock_validate.return_value = Path("/path/to/repos-dir")
        mock_detector.detect_repos.return_value = [mock_repo1, mock_repo2]

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.type == "repo"
        assert result.repo_mode == "repos-dir"
        assert result.repo_path == "/path/to/repos-dir"
        mock_detector.detect_repos.assert_called_once()


def test_configure_repo_target_repos_dir_no_repos_continue():
    """Test configure_repo_target with repos-dir but no repos detected, user continues."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators._detector") as mock_detector, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", return_value="/path/to/repos-dir"):
        mock_prompter.prompt_choice.return_value = "repos-dir"
        mock_prompter.prompt_yes_no.return_value = True  # Continue anyway
        mock_validate.return_value = Path("/path/to/repos-dir")
        mock_detector.detect_repos.return_value = []

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.type == "repo"
        assert result.repo_mode == "repos-dir"
        assert result.repo_path == "/path/to/repos-dir"
        mock_prompter.prompt_yes_no.assert_called_once()


def test_configure_repo_target_repos_dir_no_repos_retry():
    """Test configure_repo_target with repos-dir, no repos, user declines, then success."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    mock_repo = MagicMock(name="repo1")

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators._detector") as mock_detector, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", side_effect=["/bad/path", "/good/path"]):
        mock_prompter.prompt_choice.return_value = "repos-dir"
        # First attempt: no repos, decline; second attempt: success
        mock_prompter.prompt_yes_no.return_value = False
        mock_validate.side_effect = [Path("/bad/path"), Path("/good/path")]
        mock_detector.detect_repos.side_effect = [[], [mock_repo]]

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.type == "repo"
        assert result.repo_path == "/good/path"
        assert mock_validate.call_count == 2


def test_configure_repo_target_tsv_mode():
    """Test configure_repo_target with TSV mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("builtins.input", side_effect=["./repos.tsv", "repos-tsv"]):
        mock_prompter.prompt_choice.return_value = "tsv"

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.type == "repo"
        assert result.repo_mode == "tsv"
        assert result.tsv_path == "./repos.tsv"
        assert result.tsv_dest == "repos-tsv"


def test_configure_repo_target_targets_mode():
    """Test configure_repo_target with targets file mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", return_value="./targets.txt"):
        mock_prompter.prompt_choice.return_value = "targets"
        mock_validate.return_value = Path("./targets.txt")

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.type == "repo"
        assert result.repo_mode == "targets"
        assert result.repo_path == str(Path("./targets.txt"))


def test_configure_repo_target_empty_path_retry():
    """Test configure_repo_target retries on empty path."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", side_effect=["", "/valid/path"]):
        mock_prompter.prompt_choice.return_value = "repo"
        mock_validate.return_value = Path("/valid/path")

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.repo_path == "/valid/path"


def test_configure_repo_target_invalid_path_retry():
    """Test configure_repo_target retries on invalid path."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", side_effect=["/bad/path", "/good/path"]):
        mock_prompter.prompt_choice.return_value = "repo"
        mock_validate.side_effect = [None, Path("/good/path")]

        result = configure_repo_target(mock_config, mock_print_step)

        assert result.repo_path == "/good/path"
        assert mock_validate.call_count == 2


# ========== Category 2: Container Image Target Configuration ==========


def test_configure_image_target_single_mode():
    """Test configure_image_target with single image mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("builtins.input", return_value="myapp:v1.0"):
        mock_prompter.prompt_choice.return_value = "single"

        result = configure_image_target(mock_config, mock_print_step)

        assert result.type == "image"
        assert result.image_name == "myapp:v1.0"


def test_configure_image_target_single_mode_default():
    """Test configure_image_target with default nginx:latest."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("builtins.input", return_value=""):
        mock_prompter.prompt_choice.return_value = "single"

        result = configure_image_target(mock_config, mock_print_step)

        assert result.type == "image"
        assert result.image_name == "nginx:latest"


def test_configure_image_target_batch_mode():
    """Test configure_image_target with batch file mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    images_content = "nginx:latest\nmyapp:v1.0\n# comment\n\nredis:alpine"

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", return_value="./images.txt"):
        mock_prompter.prompt_choice.return_value = "batch"
        mock_path = MagicMock(spec=Path)
        mock_path.read_text.return_value = images_content
        mock_validate.return_value = mock_path

        result = configure_image_target(mock_config, mock_print_step)

        assert result.type == "image"
        assert result.images_file == str(mock_path)


def test_configure_image_target_batch_invalid_file_retry():
    """Test configure_image_target retries on invalid file."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    images_content = "nginx:latest\nmyapp:v1.0"

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", side_effect=["/bad/file", "./images.txt"]):
        mock_prompter.prompt_choice.return_value = "batch"
        mock_path = MagicMock(spec=Path)
        mock_path.read_text.return_value = images_content
        mock_validate.side_effect = [None, mock_path]

        result = configure_image_target(mock_config, mock_print_step)

        assert result.images_file == str(mock_path)
        assert mock_validate.call_count == 2


# ========== Category 3: IaC Target Configuration ==========


def test_configure_iac_target_terraform():
    """Test configure_iac_target with Terraform state file."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type") as mock_detect, \
         patch("builtins.input", return_value="./infrastructure.tfstate"):
        mock_validate.return_value = Path("./infrastructure.tfstate")
        mock_detect.return_value = "terraform"
        mock_prompter.prompt_choice.return_value = "terraform"

        result = configure_iac_target(mock_config, mock_print_step)

        assert result.type == "iac"
        assert result.iac_path == str(Path("./infrastructure.tfstate"))
        assert result.iac_type == "terraform"


def test_configure_iac_target_cloudformation():
    """Test configure_iac_target with CloudFormation template."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type") as mock_detect, \
         patch("builtins.input", return_value="./template.yaml"):
        mock_validate.return_value = Path("./template.yaml")
        mock_detect.return_value = "cloudformation"
        mock_prompter.prompt_choice.return_value = "cloudformation"

        result = configure_iac_target(mock_config, mock_print_step)

        assert result.type == "iac"
        assert result.iac_path == str(Path("./template.yaml"))
        assert result.iac_type == "cloudformation"


def test_configure_iac_target_k8s_manifest():
    """Test configure_iac_target with Kubernetes manifest."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type") as mock_detect, \
         patch("builtins.input", return_value="./deployment.yaml"):
        mock_validate.return_value = Path("./deployment.yaml")
        mock_detect.return_value = "k8s-manifest"
        mock_prompter.prompt_choice.return_value = "k8s-manifest"

        result = configure_iac_target(mock_config, mock_print_step)

        assert result.type == "iac"
        assert result.iac_path == str(Path("./deployment.yaml"))
        assert result.iac_type == "k8s-manifest"


def test_configure_iac_target_override_detected_type():
    """Test configure_iac_target where user overrides detected type."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type") as mock_detect, \
         patch("builtins.input", return_value="./config.yaml"):
        mock_validate.return_value = Path("./config.yaml")
        mock_detect.return_value = "k8s-manifest"
        mock_prompter.prompt_choice.return_value = "cloudformation"  # Override

        result = configure_iac_target(mock_config, mock_print_step)

        assert result.iac_type == "cloudformation"


def test_configure_iac_target_invalid_path_retry():
    """Test configure_iac_target retries on invalid path."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("scripts.cli.wizard_flows.target_configurators.detect_iac_type") as mock_detect, \
         patch("builtins.input", side_effect=["/bad/path", "./good.tfstate"]):
        mock_validate.side_effect = [None, Path("./good.tfstate")]
        mock_detect.return_value = "terraform"
        mock_prompter.prompt_choice.return_value = "terraform"

        result = configure_iac_target(mock_config, mock_print_step)

        assert result.iac_path == str(Path("./good.tfstate"))
        assert mock_validate.call_count == 2


# ========== Category 4: URL Target Configuration ==========


def test_configure_url_target_single_mode_reachable():
    """Test configure_url_target with single reachable URL."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_url") as mock_validate, \
         patch("builtins.input", return_value="https://myapp.com"):
        mock_prompter.prompt_choice.return_value = "single"
        mock_validate.return_value = True

        result = configure_url_target(mock_config, mock_print_step)

        assert result.type == "url"
        assert result.url == "https://myapp.com"


def test_configure_url_target_single_mode_unreachable_use_anyway():
    """Test configure_url_target with unreachable URL, user chooses to use anyway."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_url") as mock_validate, \
         patch("builtins.input", return_value="https://unreachable.com"):
        mock_prompter.prompt_choice.return_value = "single"
        mock_prompter.prompt_yes_no.return_value = True
        mock_validate.return_value = False

        result = configure_url_target(mock_config, mock_print_step)

        assert result.url == "https://unreachable.com"
        mock_prompter.prompt_yes_no.assert_called_once()


def test_configure_url_target_single_mode_unreachable_retry():
    """Test configure_url_target with unreachable URL, retry with valid URL."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_url") as mock_validate, \
         patch("builtins.input", side_effect=["https://bad.com", "https://good.com"]):
        mock_prompter.prompt_choice.return_value = "single"
        mock_prompter.prompt_yes_no.return_value = False  # Don't use bad URL
        mock_validate.side_effect = [False, True]

        result = configure_url_target(mock_config, mock_print_step)

        assert result.url == "https://good.com"
        assert mock_validate.call_count == 2


def test_configure_url_target_batch_mode():
    """Test configure_url_target with batch file mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    urls_content = "https://app1.com\nhttps://app2.com\n# comment\n\nhttps://app3.com"

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", return_value="./urls.txt"):
        mock_prompter.prompt_choice.return_value = "batch"
        mock_path = MagicMock(spec=Path)
        mock_path.read_text.return_value = urls_content
        mock_validate.return_value = mock_path

        result = configure_url_target(mock_config, mock_print_step)

        assert result.type == "url"
        assert result.urls_file == str(mock_path)


def test_configure_url_target_batch_invalid_file_retry():
    """Test configure_url_target retries on invalid file."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    urls_content = "https://app.com"

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_path") as mock_validate, \
         patch("builtins.input", side_effect=["/bad/file", "./urls.txt"]):
        mock_prompter.prompt_choice.return_value = "batch"
        mock_path = MagicMock(spec=Path)
        mock_path.read_text.return_value = urls_content
        mock_validate.side_effect = [None, mock_path]

        result = configure_url_target(mock_config, mock_print_step)

        assert result.urls_file == str(mock_path)
        assert mock_validate.call_count == 2


def test_configure_url_target_api_mode():
    """Test configure_url_target with API spec mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("builtins.input", return_value="./openapi.yaml"):
        mock_prompter.prompt_choice.return_value = "api"

        result = configure_url_target(mock_config, mock_print_step)

        assert result.type == "url"
        assert result.api_spec == "./openapi.yaml"


# ========== Category 5: GitLab Target Configuration ==========


def test_configure_gitlab_target_repo_mode_with_env_token():
    """Test configure_gitlab_target with repo mode and environment token."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.os.getenv", return_value="token123"), \
         patch("builtins.input", side_effect=["https://gitlab.com", "mygroup/myrepo"]):
        mock_prompter.prompt_choice.return_value = "repo"

        result = configure_gitlab_target(mock_config, mock_print_step)

        assert result.type == "gitlab"
        assert result.gitlab_url == "https://gitlab.com"
        assert result.gitlab_token == "token123"
        assert result.gitlab_repo == "mygroup/myrepo"


def test_configure_gitlab_target_repo_mode_manual_token():
    """Test configure_gitlab_target with manually entered token."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.os.getenv", return_value=None), \
         patch("builtins.input", side_effect=["https://gitlab.com", "manual_token", "mygroup/myrepo"]):
        mock_prompter.prompt_choice.return_value = "repo"

        result = configure_gitlab_target(mock_config, mock_print_step)

        assert result.gitlab_token == "manual_token"
        assert result.gitlab_repo == "mygroup/myrepo"


def test_configure_gitlab_target_repo_mode_no_token():
    """Test configure_gitlab_target with no token provided."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.os.getenv", return_value=None), \
         patch("builtins.input", side_effect=["https://gitlab.com", "", "mygroup/myrepo"]):
        mock_prompter.prompt_choice.return_value = "repo"

        result = configure_gitlab_target(mock_config, mock_print_step)

        # Token not set when empty (code doesn't set it at all)
        # Just verify the result object exists and has expected type
        assert result.type == "gitlab"
        assert result.gitlab_url == "https://gitlab.com"


def test_configure_gitlab_target_group_mode():
    """Test configure_gitlab_target with group mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.os.getenv", return_value="token123"), \
         patch("builtins.input", side_effect=["https://gitlab.com", "mygroup"]):
        mock_prompter.prompt_choice.return_value = "group"

        result = configure_gitlab_target(mock_config, mock_print_step)

        assert result.type == "gitlab"
        assert result.gitlab_group == "mygroup"


# ========== Category 6: Kubernetes Target Configuration ==========


def test_configure_k8s_target_kubectl_not_found():
    """Test configure_k8s_target when kubectl not available."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators.shutil.which", return_value=None):
        result = configure_k8s_target(mock_config, mock_print_step)

        assert result.type == "k8s"
        assert result.k8s_context == "current"
        assert result.k8s_namespace == "default"


def test_configure_k8s_target_single_namespace_valid_context():
    """Test configure_k8s_target with single namespace and valid context."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context", return_value=True), \
         patch("builtins.input", side_effect=["minikube", "default"]):
        mock_prompter.prompt_choice.return_value = "single"

        result = configure_k8s_target(mock_config, mock_print_step)

        assert result.type == "k8s"
        assert result.k8s_context == "minikube"
        assert result.k8s_namespace == "default"


def test_configure_k8s_target_all_namespaces():
    """Test configure_k8s_target with all namespaces mode."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context", return_value=True), \
         patch("builtins.input", return_value="minikube"):
        mock_prompter.prompt_choice.return_value = "all"

        result = configure_k8s_target(mock_config, mock_print_step)

        assert result.type == "k8s"
        assert result.k8s_context == "minikube"
        assert result.k8s_all_namespaces is True


def test_configure_k8s_target_invalid_context_use_anyway():
    """Test configure_k8s_target with invalid context, user chooses to use anyway."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context", return_value=False), \
         patch("builtins.input", side_effect=["invalid-context", "default"]):
        mock_prompter.prompt_choice.return_value = "single"
        mock_prompter.prompt_yes_no.return_value = True

        result = configure_k8s_target(mock_config, mock_print_step)

        assert result.k8s_context == "invalid-context"
        mock_prompter.prompt_yes_no.assert_called_once()


def test_configure_k8s_target_invalid_context_retry():
    """Test configure_k8s_target with invalid context, retry with valid context."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context") as mock_validate, \
         patch("builtins.input", side_effect=["bad-context", "good-context", "default"]):
        mock_prompter.prompt_choice.return_value = "single"
        mock_prompter.prompt_yes_no.return_value = False
        mock_validate.side_effect = [False, True]

        result = configure_k8s_target(mock_config, mock_print_step)

        assert result.k8s_context == "good-context"
        assert mock_validate.call_count == 2


def test_configure_k8s_target_current_context():
    """Test configure_k8s_target with 'current' context."""
    mock_config = MagicMock()
    mock_print_step = MagicMock()

    with patch("scripts.cli.wizard_flows.target_configurators.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("scripts.cli.wizard_flows.target_configurators._prompter") as mock_prompter, \
         patch("scripts.cli.wizard_flows.target_configurators.validate_k8s_context", return_value=True), \
         patch("builtins.input", side_effect=["current", "kube-system"]):
        mock_prompter.prompt_choice.return_value = "single"

        result = configure_k8s_target(mock_config, mock_print_step)

        assert result.k8s_context == "current"
        assert result.k8s_namespace == "kube-system"
