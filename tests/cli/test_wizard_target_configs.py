"""
Comprehensive test suite for wizard.py target configuration functions.

Tests wizard functions that delegate to wizard_flows.target_configurators module.
Uses proper mocking to avoid blocking on user input.

Coverage Target: 85%+
Test Categories:
- select_target_type() wrapper tests
- configure_*_target() delegation tests (smoke tests)
- generate_command_list() integration tests
"""

from unittest.mock import patch


from scripts.cli.wizard import (
    TargetConfig,
    WizardConfig,
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
# Test Helper Functions
# =============================================================================


def create_mock_target_config(target_type: str = "repo", **kwargs) -> TargetConfig:
    """Create mock TargetConfig for testing."""
    config = TargetConfig()
    config.type = target_type

    # Set defaults based on type
    if target_type == "repo":
        config.repo_mode = kwargs.get("repo_mode", "repos-dir")
        config.repo_path = kwargs.get("repo_path", "/test/repos")
    elif target_type == "image":
        config.image_name = kwargs.get("image_name", "nginx:latest")
    elif target_type == "url":
        config.url = kwargs.get("url", "https://example.com")
    elif target_type == "iac":
        config.iac_files = kwargs.get("iac_files", ["/test/terraform.tf"])
    elif target_type == "gitlab":
        config.gitlab_url = kwargs.get("gitlab_url", "https://gitlab.com")
        config.gitlab_repo = kwargs.get("gitlab_repo", "org/repo")
    elif target_type == "k8s":
        config.k8s_context = kwargs.get("k8s_context", "minikube")

    return config


# =============================================================================
# Test select_target_type() - Wrapper Function
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
# Test configure_*_target() - Delegation Smoke Tests
# =============================================================================


@patch("scripts.cli.wizard._configure_repo")
def test_configure_repo_target_delegates_correctly(mock_configure):
    """Test configure_repo_target() delegates to target_configurators module."""
    # Setup mock return value
    expected_config = create_mock_target_config(
        "repo", repo_mode="repos-dir", repo_path="/test"
    )
    mock_configure.return_value = expected_config

    # Call wrapper function
    result = configure_repo_target()

    # Verify delegation
    assert mock_configure.called
    assert result.type == "repo"
    assert result.repo_mode == "repos-dir"
    assert result.repo_path == "/test"


@patch("scripts.cli.wizard._configure_image")
def test_configure_image_target_delegates_correctly(mock_configure):
    """Test configure_image_target() delegates to target_configurators module."""
    expected_config = create_mock_target_config("image", image_name="nginx:latest")
    mock_configure.return_value = expected_config

    result = configure_image_target()

    assert mock_configure.called
    assert result.type == "image"
    assert result.image_name == "nginx:latest"


@patch("scripts.cli.wizard._configure_iac")
def test_configure_iac_target_delegates_correctly(mock_configure):
    """Test configure_iac_target() delegates to target_configurators module."""
    expected_config = create_mock_target_config("iac", iac_files=["/test/main.tf"])
    mock_configure.return_value = expected_config

    result = configure_iac_target()

    assert mock_configure.called
    assert result.type == "iac"
    assert result.iac_files == ["/test/main.tf"]


@patch("scripts.cli.wizard._configure_url")
def test_configure_url_target_delegates_correctly(mock_configure):
    """Test configure_url_target() delegates to target_configurators module."""
    expected_config = create_mock_target_config("url", url="https://example.com")
    mock_configure.return_value = expected_config

    result = configure_url_target()

    assert mock_configure.called
    assert result.type == "url"
    assert result.url == "https://example.com"


@patch("scripts.cli.wizard._configure_gitlab")
def test_configure_gitlab_target_delegates_correctly(mock_configure):
    """Test configure_gitlab_target() delegates to target_configurators module."""
    expected_config = create_mock_target_config(
        "gitlab", gitlab_url="https://gitlab.com", gitlab_repo="org/repo"
    )
    mock_configure.return_value = expected_config

    result = configure_gitlab_target()

    assert mock_configure.called
    assert result.type == "gitlab"
    assert result.gitlab_repo == "org/repo"


@patch("scripts.cli.wizard._configure_k8s")
def test_configure_k8s_target_delegates_correctly(mock_configure):
    """Test configure_k8s_target() delegates to target_configurators module."""
    expected_config = create_mock_target_config("k8s", k8s_context="minikube")
    mock_configure.return_value = expected_config

    result = configure_k8s_target()

    assert mock_configure.called
    assert result.type == "k8s"
    assert result.k8s_context == "minikube"


# =============================================================================
# Test generate_command_list() - Command Builder Integration
# =============================================================================


def test_generate_command_list_repo_target():
    """Test command generation for repository target."""
    config = WizardConfig()
    config.profile = "balanced"
    config.target = create_mock_target_config(
        "repo", repo_mode="repos-dir", repo_path="/test/repos"
    )
    config.use_docker = False

    result = generate_command_list(config)

    # Verify command structure (wizard generates jmo scan commands)
    assert isinstance(result, list)
    assert len(result) > 0
    assert result[0] == "jmo"
    assert result[1] == "scan"
    assert "--repos-dir" in result
    assert "/test/repos" in result
    assert "--profile-name" in result
    assert "balanced" in result


def test_generate_command_list_image_target():
    """Test command generation for container image target."""
    config = WizardConfig()
    config.profile = "fast"
    config.target = create_mock_target_config("image", image_name="nginx:latest")
    config.use_docker = False

    result = generate_command_list(config)

    assert "--image" in result
    assert "nginx:latest" in result
    assert "fast" in result


def test_generate_command_list_url_target():
    """Test command generation for URL target."""
    config = WizardConfig()
    config.profile = "balanced"
    config.target = create_mock_target_config("url", url="https://example.com")
    config.use_docker = False

    result = generate_command_list(config)

    assert "--url" in result
    assert "https://example.com" in result


def test_generate_command_list_with_threads():
    """Test command generation with custom thread count."""
    config = WizardConfig()
    config.profile = "balanced"
    config.target = create_mock_target_config("repo")
    config.use_docker = False
    config.threads = 8

    result = generate_command_list(config)

    assert "--threads" in result
    assert "8" in result


def test_generate_command_list_with_timeout():
    """Test command generation with custom timeout."""
    config = WizardConfig()
    config.profile = "deep"
    config.target = create_mock_target_config("repo")
    config.use_docker = False
    config.timeout = 600

    result = generate_command_list(config)

    assert "--timeout" in result
    assert "600" in result


def test_generate_command_list_docker_mode():
    """Test command generation in Docker mode."""
    config = WizardConfig()
    config.profile = "fast"
    config.target = create_mock_target_config("repo")
    config.use_docker = True

    result = generate_command_list(config)

    # Docker mode should have different command structure
    assert isinstance(result, list)
    assert len(result) > 0


# =============================================================================
# Test TargetConfig to_dict() - Serialization
# =============================================================================


def test_target_config_to_dict_repo():
    """Test TargetConfig serialization for repository target."""
    config = create_mock_target_config(
        "repo", repo_mode="repos-dir", repo_path="/test/repos"
    )

    result = config.to_dict()

    assert result["type"] == "repo"
    assert result["repo_mode"] == "repos-dir"
    assert result["repo_path"] == "/test/repos"


def test_target_config_to_dict_image():
    """Test TargetConfig serialization for image target."""
    config = create_mock_target_config("image", image_name="python:3.11")

    result = config.to_dict()

    assert result["type"] == "image"
    assert result["image_name"] == "python:3.11"


def test_target_config_to_dict_url():
    """Test TargetConfig serialization for URL target."""
    config = create_mock_target_config("url", url="https://api.example.com")

    result = config.to_dict()

    assert result["type"] == "url"
    assert result["url"] == "https://api.example.com"


# =============================================================================
# Test WizardConfig to_dict() - Complete Configuration Serialization
# =============================================================================


def test_wizard_config_to_dict_complete():
    """Test WizardConfig serialization with all fields."""
    config = WizardConfig()
    config.profile = "balanced"
    config.target = create_mock_target_config("repo")
    config.use_docker = False
    config.threads = 4
    config.timeout = 300

    result = config.to_dict()

    assert result["profile"] == "balanced"
    assert result["use_docker"] is False
    assert result["threads"] == 4
    assert result["timeout"] == 300
    assert "target" in result


def test_wizard_config_to_dict_minimal():
    """Test WizardConfig serialization with minimal fields."""
    config = WizardConfig()
    config.profile = "fast"
    config.target = create_mock_target_config("repo")

    result = config.to_dict()

    assert result["profile"] == "fast"
    assert "target" in result


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


def test_generate_command_list_empty_config():
    """Test command generation handles missing fields gracefully."""
    config = WizardConfig()
    config.profile = "fast"
    config.target = TargetConfig()  # Empty target
    config.use_docker = False

    # Should not crash, returns valid command list
    result = generate_command_list(config)
    assert isinstance(result, list)


def test_target_config_to_dict_empty():
    """Test TargetConfig serialization with no fields set."""
    config = TargetConfig()

    result = config.to_dict()

    # Should return dict with type field at minimum
    assert isinstance(result, dict)
    assert "type" in result


def test_wizard_config_no_target():
    """Test WizardConfig serialization without target set."""
    config = WizardConfig()
    config.profile = "fast"
    # No target set

    result = config.to_dict()

    assert result["profile"] == "fast"
    # Should handle missing target gracefully


# =============================================================================
# Integration Test: End-to-End Command Generation
# =============================================================================


def test_end_to_end_repo_scan_command():
    """Test complete workflow: configure target -> generate command."""
    # Create complete config
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.threads = 8
    config.timeout = 600

    # Configure repository target
    target = TargetConfig()
    target.type = "repo"
    target.repo_mode = "repos-dir"
    target.repo_path = "/test/repos"
    config.target = target

    # Generate command
    cmd = generate_command_list(config)

    # Verify command contains all expected elements
    assert cmd[0] == "jmo"
    assert cmd[1] == "scan"
    assert "--repos-dir" in cmd or "repos-dir" in " ".join(cmd)
    assert "/test/repos" in cmd
    assert "--profile-name" in cmd
    assert "balanced" in cmd
    assert "--threads" in cmd or "8" in cmd


def test_end_to_end_multi_image_command():
    """Test command generation for multiple images."""
    config = WizardConfig()
    config.profile = "fast"
    config.use_docker = False

    target = TargetConfig()
    target.type = "image"
    target.images_file = "/test/images.txt"
    config.target = target

    cmd = generate_command_list(config)

    assert cmd[0] == "jmo"
    assert cmd[1] == "scan"
    assert "--profile-name" in cmd
    assert "fast" in cmd
    assert "--images-file" in cmd or "images-file" in " ".join(cmd)


def test_end_to_end_url_scan_with_api_spec():
    """Test command generation for URL with API spec."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False

    target = TargetConfig()
    target.type = "url"
    target.url = "https://api.example.com"
    target.api_spec = "/test/openapi.yaml"
    config.target = target

    cmd = generate_command_list(config)

    assert cmd[0] == "jmo"
    assert cmd[1] == "scan"
    assert "--profile-name" in cmd
    assert "balanced" in cmd
    assert "--url" in cmd or "https://api.example.com" in " ".join(cmd)
