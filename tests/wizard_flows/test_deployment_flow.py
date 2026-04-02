"""Tests for deployment flow module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_deployment_flow_module_imports():
    """Test that deployment_flow module can be imported."""
    try:
        from scripts.cli.wizard_flows import deployment_flow

        assert deployment_flow is not None
    except ImportError as e:
        pytest.fail(f"Failed to import deployment_flow: {e}")


def test_deployment_flow_class_exists():
    """Test that DeploymentFlow class exists."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    assert DeploymentFlow is not None


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_initialization(mock_base_init):
    """Test DeploymentFlow initialization."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    assert flow is not None


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_detect_targets(mock_base_init, tmp_path):
    """Test deployment flow target detection."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    # Create mock deployment files
    (tmp_path / "docker-compose.yml").touch()
    (tmp_path / "Dockerfile").touch()

    # Initialize flow and mock detector
    flow = DeploymentFlow()
    flow.detector = MagicMock()
    flow.detector.detect_images.return_value = ["nginx:latest", "postgres:14"]
    flow.detector.detect_iac.return_value = []
    flow.detector.detect_web_apps.return_value = []

    targets = flow.detect_targets()

    assert isinstance(targets, dict)
    assert "images" in targets
    assert "iac" in targets
    assert "web" in targets
    assert "environment" in targets


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_build_command(mock_base_init):
    """Test deployment flow command building."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    targets = {
        "images": ["nginx:latest"],
        "iac": [Path("main.tf")],
        "web": ["http://localhost:8080"],
    }

    options = {
        "environment": "staging",
        "profile": "balanced",
        "fail_on": "HIGH",
    }

    cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "ci" in cmd
    assert "--profile" in cmd
    assert "balanced" in cmd


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_prompt_user_staging(mock_base_init):
    """Test prompt_user for staging environment."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    flow.detected_targets = {
        "environment": "staging",
        "images": ["nginx:latest"],
        "iac": [],
        "web": [],
    }
    flow.prompter = MagicMock()
    flow.prompter.prompt_choice.side_effect = ["staging", "balanced", "HIGH"]

    options = flow.prompt_user()

    assert options["environment"] == "staging"
    assert options["profile"] == "balanced"
    assert options["fail_on"] == "HIGH"
    # Verify production requirements NOT shown for staging (only detected targets shown)
    assert flow.prompter.print_summary_box.call_count == 1
    call_args = flow.prompter.print_summary_box.call_args
    assert "Detected Deployment Targets" in call_args[0][0]


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_prompt_user_production(mock_base_init):
    """Test prompt_user for production environment with requirements."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    flow.detected_targets = {
        "environment": "production",
        "images": ["nginx:latest"],
        "iac": [],
        "web": [],
    }
    flow.prompter = MagicMock()
    flow.prompter.prompt_choice.side_effect = ["production", "deep", "CRITICAL"]

    options = flow.prompt_user()

    assert options["environment"] == "production"
    assert options["profile"] == "deep"
    assert options["fail_on"] == "CRITICAL"
    # Verify production requirements shown (2 calls: detected targets + production requirements)
    assert flow.prompter.print_summary_box.call_count == 2
    # First call: detected targets
    first_call = flow.prompter.print_summary_box.call_args_list[0]
    assert "Detected Deployment Targets" in first_call[0][0]
    # Second call: production requirements
    second_call = flow.prompter.print_summary_box.call_args_list[1]
    assert "Production Deployment Requirements" in second_call[0][0]


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_print_detected_deployment_targets_all(mock_base_init):
    """Test printing all deployment target types."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    flow.prompter = MagicMock()

    iac1 = MagicMock()
    iac1.name = "main.tf"

    targets = {
        "images": ["nginx:latest", "postgres:14"],
        "iac": [iac1],
        "web": ["http://localhost:8080"],
    }

    flow._print_detected_deployment_targets(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "Container images: 2 detected" in items
    assert "IaC files: 1 detected" in items
    assert "Web URLs: 1 detected for DAST" in items


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_print_detected_deployment_targets_many_images(mock_base_init):
    """Test printing >3 images with truncation."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    flow.prompter = MagicMock()

    targets = {
        "images": ["nginx:latest", "postgres:14", "redis:7", "mongo:6", "mysql:8"],
        "iac": [],
        "web": [],
    }

    flow._print_detected_deployment_targets(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "Container images: 5 detected" in items
    assert "  ... and 2 more" in items


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_print_detected_deployment_targets_many_iac(mock_base_init):
    """Test printing >3 IaC files with truncation."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    flow.prompter = MagicMock()

    # Create 5 mock IaC files
    iac_files = []
    for i in range(5):
        iac = MagicMock()
        iac.name = f"file{i}.tf"
        iac_files.append(iac)

    targets = {"images": [], "iac": iac_files, "web": []}

    flow._print_detected_deployment_targets(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "IaC files: 5 detected" in items
    assert "  ... and 2 more" in items


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_print_detected_deployment_targets_none(mock_base_init):
    """Test printing when no deployment targets detected."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    flow.prompter = MagicMock()

    targets = {"images": [], "iac": [], "web": []}

    flow._print_detected_deployment_targets(targets)

    flow.prompter.print_warning.assert_called_once_with(
        "No deployment targets detected"
    )


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_build_command_many_images(mock_base_init):
    """Test build_command truncates to 3 images max."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    targets = {
        "images": ["nginx:latest", "postgres:14", "redis:7", "mongo:6", "mysql:8"],
        "iac": [],
        "web": [],
    }

    options = {"environment": "production", "profile": "deep", "fail_on": "CRITICAL"}

    cmd = flow.build_command(targets, options)

    # Count --image flags (should be 3 max)
    image_count = cmd.count("--image")
    assert image_count == 3
    assert "nginx:latest" in cmd
    assert "postgres:14" in cmd
    assert "redis:7" in cmd
    assert "mongo:6" not in cmd  # 4th image excluded


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_build_command_many_iac(mock_base_init):
    """Test build_command truncates to 5 IaC files max."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    # Create 7 IaC files
    iac_files = [Path(f"file{i}.tf") for i in range(7)]

    targets = {"images": [], "iac": iac_files, "web": []}

    options = {"environment": "staging", "profile": "balanced", "fail_on": "HIGH"}

    cmd = flow.build_command(targets, options)

    # Count --terraform-state flags (should be 5 max)
    tf_count = cmd.count("--terraform-state")
    assert tf_count == 5
    assert "file0.tf" in cmd
    assert "file4.tf" in cmd
    assert "file5.tf" not in cmd  # 6th file excluded


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_deployment_flow_build_command_empty_targets(mock_base_init):
    """Test build_command with no targets."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    targets = {"images": [], "iac": [], "web": []}

    options = {"environment": "staging", "profile": "fast", "fail_on": "MEDIUM"}

    cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "ci" in cmd
    assert "--image" not in cmd
    assert "--terraform-state" not in cmd
    assert "--url" not in cmd


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
@patch.dict("os.environ", {"ENVIRONMENT": "production"}, clear=True)
def test_deployment_flow_detect_environment_env_var_production(mock_base_init):
    """Test environment detection from ENVIRONMENT variable (production)."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    env = flow._detect_environment()

    assert env == "production"


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
@patch.dict("os.environ", {"NODE_ENV": "staging"}, clear=True)
def test_deployment_flow_detect_environment_env_var_staging(mock_base_init):
    """Test environment detection from NODE_ENV variable (staging)."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()
    env = flow._detect_environment()

    assert env == "staging"


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
@patch.dict("os.environ", {}, clear=True)
def test_deployment_flow_detect_environment_env_file_production(
    mock_base_init, tmp_path
):
    """Test environment detection from .env file (production)."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    # Create .env file with production
    env_file = tmp_path / ".env"
    env_file.write_text("ENVIRONMENT=production\n")

    # Change to tmp_path to test .env detection
    import os

    original_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        env = flow._detect_environment()
        assert env == "production"
    finally:
        os.chdir(original_cwd)


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
@patch.dict("os.environ", {}, clear=True)
def test_deployment_flow_detect_environment_k8s_manifest(mock_base_init, tmp_path):
    """Test environment detection from Kubernetes manifest."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    # Create k8s manifest with staging namespace
    k8s_dir = tmp_path / "k8s"
    k8s_dir.mkdir()
    manifest = k8s_dir / "deployment.yml"
    manifest.write_text("namespace: staging\n")

    # Change to tmp_path to test k8s detection
    import os

    original_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        env = flow._detect_environment()
        assert env == "staging"
    finally:
        os.chdir(original_cwd)


@patch(
    "scripts.cli.wizard_flows.deployment_flow.BaseWizardFlow.__init__",
    return_value=None,
)
@patch.dict("os.environ", {}, clear=True)
def test_deployment_flow_detect_environment_default_staging(mock_base_init, tmp_path):
    """Test environment detection defaults to staging when no signals found."""
    from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow

    flow = DeploymentFlow()

    # Change to empty tmp_path (no .env, no k8s)
    import os

    original_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        env = flow._detect_environment()
        assert env == "staging"
    finally:
        os.chdir(original_cwd)
