#!/usr/bin/env python3
"""
Comprehensive tests for wizard.py main() function and telemetry features.

This test file targets the remaining coverage gaps to push from 66% to 85%+:
- main() function (lines 1490-1634): sys.argv mocking, interactive/non-interactive paths
- Telemetry prompts (line 1460): input() mocking
- _save_telemetry_preference() (lines 1373-1393): YAML file I/O
- review_and_confirm() target type variations (lines 996-1027)
- Advanced configuration edge cases

Coverage goals:
- main() interactive mode with all 6 target types
- main() non-interactive mode (--yes flag)
- Telemetry prompt variations
- YAML file save operations
- review_and_confirm() display logic for all target types
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch


# Add scripts/ to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.cli.wizard import (
    prompt_telemetry_opt_in,
    _save_telemetry_preference,
    main,
    review_and_confirm,
    WizardConfig,
    TargetConfig,
)


# ============================================================================
# MAIN FUNCTION TESTS - INTERACTIVE MODE (lines 1528-1558)
# ============================================================================
@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_repo_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard._save_telemetry_preference")
@patch("scripts.cli.wizard.prompt_telemetry_opt_in")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_repo_target_success(
    mock_print,
    mock_load_cfg,
    mock_telem_prompt,
    mock_save_telem,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_repo,
    mock_advanced,
    mock_review,
    mock_exec,
):
    """Test main() interactive mode with repo target - happy path."""
    sys.argv = ["wizard"]  # No --yes flag

    # Config doesn't exist, trigger telemetry prompt
    with patch.object(Path, "exists", return_value=False):
        mock_telem_prompt.return_value = True
        mock_profile.return_value = "balanced"
        mock_exec_mode.return_value = False  # Native mode
        mock_target_type.return_value = "repo"

        repo_target = TargetConfig()
        repo_target.type = "repo"
        repo_target.repo_path = Path("/fake/repo")
        mock_repo.return_value = repo_target

        mock_advanced.return_value = (4, 600, "")
        mock_review.return_value = True  # User confirms
        mock_exec.return_value = 0  # Success

        result = main()

    assert result == 0
    mock_telem_prompt.assert_called_once()
    mock_save_telem.assert_called_once()
    mock_profile.assert_called_once()
    mock_target_type.assert_called_once()
    mock_repo.assert_called_once()
    mock_review.assert_called_once()
    mock_exec.assert_called_once()


@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_image_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard._save_telemetry_preference")
@patch("scripts.cli.wizard.prompt_telemetry_opt_in")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_image_target(
    mock_print,
    mock_load_cfg,
    mock_telem_prompt,
    mock_save_telem,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_image,
    mock_advanced,
    mock_review,
    mock_exec,
):
    """Test main() interactive mode with container image target."""
    sys.argv = ["wizard"]

    with patch.object(Path, "exists", return_value=False):
        mock_telem_prompt.return_value = False  # Decline telemetry
        mock_profile.return_value = "fast"
        mock_exec_mode.return_value = True  # Docker mode
        mock_target_type.return_value = "image"

        img_target = TargetConfig()
        img_target.type = "image"
        img_target.image_name = "nginx:latest"
        mock_image.return_value = img_target

        mock_advanced.return_value = (8, 300, "HIGH")
        mock_review.return_value = True
        mock_exec.return_value = 0

        result = main()

    assert result == 0
    mock_image.assert_called_once()


@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_iac_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_iac_target(
    mock_print,
    mock_load_cfg,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_iac,
    mock_advanced,
    mock_review,
    mock_exec,
):
    """Test main() interactive mode with IaC target."""
    sys.argv = ["wizard"]

    # Config exists with telemetry already set
    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = True
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_profile.return_value = "deep"
        mock_exec_mode.return_value = False
        mock_target_type.return_value = "iac"

        iac_target = TargetConfig()
        iac_target.type = "iac"
        iac_target.iac_type = "terraform"
        iac_target.iac_path = Path("/fake/main.tf")
        mock_iac.return_value = iac_target

        mock_advanced.return_value = (2, 900, "CRITICAL")
        mock_review.return_value = True
        mock_exec.return_value = 0

        result = main()

    assert result == 0
    mock_iac.assert_called_once()


@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_url_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_url_target(
    mock_print,
    mock_load_cfg,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_url,
    mock_advanced,
    mock_review,
    mock_exec,
):
    """Test main() interactive mode with URL target."""
    sys.argv = ["wizard"]

    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = False
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_profile.return_value = "balanced"
        mock_exec_mode.return_value = False
        mock_target_type.return_value = "url"

        url_target = TargetConfig()
        url_target.type = "url"
        url_target.url = "https://example.com"
        mock_url.return_value = url_target

        mock_advanced.return_value = (4, 600, "")
        mock_review.return_value = True
        mock_exec.return_value = 0

        result = main()

    assert result == 0
    mock_url.assert_called_once()


@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_gitlab_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_gitlab_target(
    mock_print,
    mock_load_cfg,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_gitlab,
    mock_advanced,
    mock_review,
    mock_exec,
):
    """Test main() interactive mode with GitLab target."""
    sys.argv = ["wizard"]

    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = True
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_profile.return_value = "balanced"
        mock_exec_mode.return_value = False
        mock_target_type.return_value = "gitlab"

        gitlab_target = TargetConfig()
        gitlab_target.type = "gitlab"
        gitlab_target.gitlab_url = "https://gitlab.com"
        gitlab_target.gitlab_token = "secret"
        gitlab_target.gitlab_repo = "mygroup/myrepo"
        mock_gitlab.return_value = gitlab_target

        mock_advanced.return_value = (4, 600, "")
        mock_review.return_value = True
        mock_exec.return_value = 0

        result = main()

    assert result == 0
    mock_gitlab.assert_called_once()


@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_k8s_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_k8s_target(
    mock_print,
    mock_load_cfg,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_k8s,
    mock_advanced,
    mock_review,
    mock_exec,
):
    """Test main() interactive mode with Kubernetes target."""
    sys.argv = ["wizard"]

    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = True
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_profile.return_value = "balanced"
        mock_exec_mode.return_value = False
        mock_target_type.return_value = "k8s"

        k8s_target = TargetConfig()
        k8s_target.type = "k8s"
        k8s_target.k8s_context = "minikube"
        k8s_target.k8s_namespace = "default"
        k8s_target.k8s_all_namespaces = False
        mock_k8s.return_value = k8s_target

        mock_advanced.return_value = (4, 600, "")
        mock_review.return_value = True
        mock_exec.return_value = 0

        result = main()

    assert result == 0
    mock_k8s.assert_called_once()


@patch("scripts.cli.wizard.review_and_confirm")
@patch("scripts.cli.wizard.configure_advanced")
@patch("scripts.cli.wizard.configure_repo_target")
@patch("scripts.cli.wizard.select_target_type")
@patch("scripts.cli.wizard.select_execution_mode")
@patch("scripts.cli.wizard.select_profile")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_interactive_user_cancels_at_review(
    mock_print,
    mock_load_cfg,
    mock_profile,
    mock_exec_mode,
    mock_target_type,
    mock_repo,
    mock_advanced,
    mock_review,
):
    """Test main() when user cancels at review step (line 1556-1557)."""
    sys.argv = ["wizard"]

    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = True
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_profile.return_value = "balanced"
        mock_exec_mode.return_value = False
        mock_target_type.return_value = "repo"

        repo_target = TargetConfig()
        repo_target.type = "repo"
        repo_target.repo_path = Path("/fake/repo")
        mock_repo.return_value = repo_target

        mock_advanced.return_value = (4, 600, "")
        mock_review.return_value = False  # USER CANCELS

        result = main()

    assert result == 0
    mock_review.assert_called_once()
    # Verify cancellation message printed
    cancel_calls = [str(call) for call in mock_print.call_args_list]
    assert any("cancelled" in call.lower() for call in cancel_calls)


# ============================================================================
# MAIN FUNCTION TESTS - NON-INTERACTIVE MODE (lines 1516-1527)
# ============================================================================
@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard._check_docker_running")
@patch("scripts.cli.wizard._detect_docker")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_non_interactive_yes_flag(
    mock_print,
    mock_load_cfg,
    mock_detect_docker,
    mock_docker_running,
    mock_exec,
):
    """Test main() with --yes flag (non-interactive mode, line 1516-1527)."""
    sys.argv = ["wizard", "--yes"]

    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = True
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_detect_docker.return_value = False
        mock_exec.return_value = 0

        result = main()

    assert result == 0
    mock_exec.assert_called_once()


@patch("scripts.cli.wizard.execute_scan")
@patch("scripts.cli.wizard._check_docker_running")
@patch("scripts.cli.wizard._detect_docker")
@patch("scripts.cli.wizard.load_config")
@patch("builtins.print")
def test_main_non_interactive_scan_failure(
    mock_print,
    mock_load_cfg,
    mock_detect_docker,
    mock_docker_running,
    mock_exec,
):
    """Test main() non-interactive mode handles scan failure."""
    sys.argv = ["wizard", "--yes"]

    mock_cfg = MagicMock()
    mock_cfg.telemetry.enabled = False
    mock_load_cfg.return_value = mock_cfg

    with patch.object(Path, "exists", return_value=True):
        mock_detect_docker.return_value = False
        mock_exec.return_value = 1  # Scan failed

        result = main()

    assert result == 1


# ============================================================================
# TELEMETRY TESTS (line 1460, lines 1502-1504, 1509-1511)
# ============================================================================
@patch("builtins.input")
def test_prompt_telemetry_opt_in_accepts_y(mock_input):
    """Test prompt_telemetry_opt_in() when user enters 'y' (line 1460)."""
    mock_input.return_value = "y"
    result = prompt_telemetry_opt_in()
    assert result is True


@patch("builtins.input")
def test_prompt_telemetry_opt_in_accepts_uppercase_Y(mock_input):
    """Test prompt_telemetry_opt_in() with 'Y'."""
    mock_input.return_value = "Y"
    result = prompt_telemetry_opt_in()
    assert result is True


@patch("builtins.input")
def test_prompt_telemetry_opt_in_declines_n(mock_input):
    """Test prompt_telemetry_opt_in() when user enters 'n'."""
    mock_input.return_value = "n"
    result = prompt_telemetry_opt_in()
    assert result is False


@patch("builtins.input")
def test_prompt_telemetry_opt_in_declines_empty(mock_input):
    """Test prompt_telemetry_opt_in() with empty input (default no)."""
    mock_input.return_value = ""
    result = prompt_telemetry_opt_in()
    assert result is False


@patch("builtins.input")
def test_prompt_telemetry_opt_in_garbage_input(mock_input):
    """Test prompt_telemetry_opt_in() with non-y/n input defaults to no."""
    mock_input.return_value = "maybe"
    result = prompt_telemetry_opt_in()
    assert result is False


# ============================================================================
# _SAVE_TELEMETRY_PREFERENCE TESTS (lines 1373-1393)
# ============================================================================
@patch("builtins.print")
@patch("builtins.open", new_callable=mock_open)
@patch("yaml.dump")
@patch("yaml.safe_load")
def test_save_telemetry_creates_new_file(
    mock_yaml_load,
    mock_yaml_dump,
    mock_file,
    mock_print,
):
    """Test _save_telemetry_preference() creating new config (lines 1382-1393)."""
    config_path = Path("/fake/.jmo/config.yml")

    with patch.object(Path, "exists", return_value=False):
        _save_telemetry_preference(config_path=config_path, enabled=True)

    mock_yaml_dump.assert_called_once()
    dumped_config = mock_yaml_dump.call_args[0][0]
    assert dumped_config == {"telemetry": {"enabled": True}}

    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("enabled" in call.lower() for call in print_calls)


@patch("builtins.print")
@patch("builtins.open", new_callable=mock_open, read_data="existing: config\n")
@patch("yaml.dump")
@patch("yaml.safe_load")
def test_save_telemetry_updates_existing_file(
    mock_yaml_load,
    mock_yaml_dump,
    mock_file,
    mock_print,
):
    """Test _save_telemetry_preference() updating existing config (line 1376-1390)."""
    config_path = Path("/fake/.jmo/config.yml")
    mock_yaml_load.return_value = {"existing": "config"}

    with patch.object(Path, "exists", return_value=True):
        _save_telemetry_preference(config_path=config_path, enabled=False)

    mock_yaml_load.assert_called_once()
    mock_yaml_dump.assert_called_once()
    dumped_config = mock_yaml_dump.call_args[0][0]
    assert dumped_config == {"existing": "config", "telemetry": {"enabled": False}}


@patch("builtins.print")
@patch("builtins.open", new_callable=mock_open)
@patch("yaml.dump")
@patch("yaml.safe_load")
def test_save_telemetry_handles_yaml_exception(
    mock_yaml_load,
    mock_yaml_dump,
    mock_file,
    mock_print,
):
    """Test _save_telemetry_preference() handles YAML errors (line 1380-1381)."""
    config_path = Path("/fake/.jmo/config.yml")
    mock_yaml_load.side_effect = Exception("YAML error")

    with patch.object(Path, "exists", return_value=True):
        _save_telemetry_preference(config_path=config_path, enabled=True)

    # Should create new config despite error
    dumped_config = mock_yaml_dump.call_args[0][0]
    assert dumped_config == {"telemetry": {"enabled": True}}


@patch("builtins.print")
@patch("builtins.open", new_callable=mock_open)
@patch("yaml.dump")
@patch("yaml.safe_load")
def test_save_telemetry_handles_none_yaml(
    mock_yaml_load,
    mock_yaml_dump,
    mock_file,
    mock_print,
):
    """Test _save_telemetry_preference() when YAML returns None (line 1379)."""
    config_path = Path("/fake/.jmo/config.yml")
    mock_yaml_load.return_value = None

    with patch.object(Path, "exists", return_value=True):
        _save_telemetry_preference(config_path=config_path, enabled=True)

    dumped_config = mock_yaml_dump.call_args[0][0]
    assert dumped_config == {"telemetry": {"enabled": True}}


# ============================================================================
# REVIEW_AND_CONFIRM TARGET TYPE DISPLAY TESTS (lines 996-1027)
# ============================================================================
@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_image_single(mock_print, mock_input):
    """Test review_and_confirm() displays single image (line 997-998)."""
    config = WizardConfig()
    config.profile = "fast"
    config.use_docker = True
    config.target = TargetConfig()

    config.target.type = "image"
    config.target.image_name = "nginx:latest"
    config.results_dir = Path("/results")
    config.threads = 8
    config.timeout = 300
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("nginx:latest" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_image_file(mock_print, mock_input):
    """Test review_and_confirm() displays images file (line 999-1000)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "image"
    config.target.images_file = Path("/fake/images.txt")
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("images.txt" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_iac(mock_print, mock_input):
    """Test review_and_confirm() displays IaC target (line 1002-1004)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "iac"
    config.target.iac_type = "terraform"
    config.target.iac_path = Path("/fake/main.tf")
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "yes"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("terraform" in call.lower() for call in print_calls)
    assert any("main.tf" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_url_single(mock_print, mock_input):
    """Test review_and_confirm() displays single URL (line 1007-1008)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = True
    config.target = TargetConfig()

    config.target.type = "url"
    config.target.url = "https://example.com"
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("example.com" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_url_file(mock_print, mock_input):
    """Test review_and_confirm() displays URLs file (line 1009-1010)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "url"
    config.target.urls_file = Path("/fake/urls.txt")
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("urls.txt" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_url_api_spec(mock_print, mock_input):
    """Test review_and_confirm() displays API spec (line 1011-1012)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "url"
    config.target.api_spec = Path("/fake/openapi.yaml")
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("openapi.yaml" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_gitlab_repo(mock_print, mock_input):
    """Test review_and_confirm() displays GitLab repo (line 1014-1020)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "gitlab"
    config.target.gitlab_url = "https://gitlab.com"
    config.target.gitlab_token = "secret"
    config.target.gitlab_repo = "mygroup/myrepo"
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("gitlab.com" in call for call in print_calls)
    assert any("***" in call for call in print_calls)  # Token masked
    assert any("mygroup/myrepo" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_gitlab_group(mock_print, mock_input):
    """Test review_and_confirm() displays GitLab group (line 1019-1020)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "gitlab"
    config.target.gitlab_url = "https://gitlab.com"
    config.target.gitlab_token = "secret"
    config.target.gitlab_group = "engineering"
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("engineering" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_gitlab_no_token(mock_print, mock_input):
    """Test review_and_confirm() shows 'NOT SET' for missing token (line 1016)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "gitlab"
    config.target.gitlab_url = "https://gitlab.com"
    config.target.gitlab_token = None
    config.target.gitlab_repo = "mygroup/myrepo"
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("NOT SET" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_k8s_namespace(mock_print, mock_input):
    """Test review_and_confirm() displays K8s namespace (line 1027)."""
    config = WizardConfig()
    config.profile = "balanced"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "k8s"
    config.target.k8s_context = "minikube"
    config.target.k8s_namespace = "production"
    config.target.k8s_all_namespaces = False
    config.results_dir = Path("/results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = ""

    mock_input.return_value = "y"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("minikube" in call for call in print_calls)
    assert any("production" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_confirms_k8s_all_namespaces(mock_print, mock_input):
    """Test review_and_confirm() displays 'ALL' for all namespaces (line 1024-1025)."""
    config = WizardConfig()
    config.profile = "deep"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "k8s"
    config.target.k8s_context = "prod-cluster"
    config.target.k8s_all_namespaces = True
    config.results_dir = Path("/results")
    config.threads = 2
    config.timeout = 900
    config.fail_on = "CRITICAL"

    mock_input.return_value = "yes"
    result = review_and_confirm(config)

    assert result is True
    print_calls = [str(call) for call in mock_print.call_args_list]
    assert any("ALL" in call for call in print_calls)


@patch("builtins.input")
@patch("builtins.print")
def test_review_user_rejects_n(mock_print, mock_input):
    """Test review_and_confirm() returns False when user enters 'n'."""
    config = WizardConfig()
    config.profile = "fast"
    config.use_docker = True
    config.target = TargetConfig()

    config.target.type = "repo"
    config.target.repo_path = Path("/fake/repo")
    config.results_dir = Path("/results")
    config.threads = 8
    config.timeout = 300
    config.fail_on = ""

    mock_input.return_value = "n"
    result = review_and_confirm(config)

    assert result is False


@patch("builtins.input")
@patch("builtins.print")
def test_review_user_accepts_empty_default(mock_print, mock_input):
    """Test review_and_confirm() accepts empty input (default=True)."""
    config = WizardConfig()
    config.profile = "fast"
    config.use_docker = False
    config.target = TargetConfig()

    config.target.type = "repo"
    config.target.repo_path = Path("/repo")
    config.results_dir = Path("/results")
    config.threads = 8
    config.timeout = 300
    config.fail_on = ""

    mock_input.return_value = ""
    result = review_and_confirm(config)

    assert result is True  # default=True in review_and_confirm
