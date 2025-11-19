"""Tests for dependency flow module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_dependency_flow_module_imports():
    """Test that dependency_flow module can be imported."""
    try:
        from scripts.cli.wizard_flows import dependency_flow

        assert dependency_flow is not None
    except ImportError as e:
        pytest.fail(f"Failed to import dependency_flow: {e}")


def test_dependency_flow_class_exists():
    """Test that DependencyFlow class exists."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    assert DependencyFlow is not None


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_initialization(mock_base_init):
    """Test DependencyFlow initialization."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()

    assert flow is not None


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_detect_targets(mock_base_init, tmp_path):
    """Test dependency flow target detection."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    # Create mock package files
    (tmp_path / "requirements.txt").touch()
    (tmp_path / "package.json").touch()

    # Initialize flow and mock detector
    flow = DependencyFlow()
    flow.detector = MagicMock()
    flow.detector.detect_package_files.return_value = [
        tmp_path / "requirements.txt",
        tmp_path / "package.json",
    ]
    flow.detector.detect_lock_files.return_value = [tmp_path / "package-lock.json"]
    flow.detector.detect_images.return_value = ["python:3.10"]

    targets = flow.detect_targets()

    assert isinstance(targets, dict)
    assert "package_files" in targets
    assert "lock_files" in targets
    assert "images" in targets


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_build_command(mock_base_init):
    """Test dependency flow command building."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()

    targets = {
        "package_files": [Path("requirements.txt")],
        "lock_files": [Path("package-lock.json")],
        "images": ["python:3.10"],
    }

    options = {
        "generate_sbom": True,
        "scan_vulns": True,
        "check_licenses": False,
    }

    cmd = flow.build_command(targets, options)

    assert isinstance(cmd, list)
    assert "jmo" in cmd
    assert "scan" in cmd
    assert "--tools" in cmd


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_prompt_user(mock_base_init):
    """Test dependency flow user prompts."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()
    flow.prompter = MagicMock()
    flow.prompter.prompt_yes_no.side_effect = [True, True, False]

    options = flow.prompt_user()

    assert options["generate_sbom"] is True
    assert options["scan_vulns"] is True
    assert options["check_licenses"] is False


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_build_command_no_images(mock_base_init):
    """Test build_command without images."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()

    targets = {
        "package_files": [Path("requirements.txt")],
        "lock_files": [],
        "images": [],  # No images
    }
    options = {"generate_sbom": True, "scan_vulns": True, "check_licenses": False}

    cmd = flow.build_command(targets, options)

    assert "--images-file" not in cmd


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_print_detected_dependencies_all(mock_base_init):
    """Test printing all detected dependency types."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()
    flow.prompter = MagicMock()

    pkg1 = MagicMock()
    pkg1.name = "package.json"
    lock1 = MagicMock()
    lock1.name = "package-lock.json"

    targets = {
        "package_files": [pkg1],
        "lock_files": [lock1],
        "images": ["node:18"],
    }

    flow._print_detected_dependencies(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "Package manifests: 1 detected" in items
    assert "Lock files: 1 detected (reproducible scans)" in items
    assert "Container images: 1 detected" in items


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_print_detected_dependencies_many_packages(mock_base_init):
    """Test printing >5 package files."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()
    flow.prompter = MagicMock()

    # Create 7 package files
    package_files = []
    for i in range(7):
        pkg = MagicMock()
        pkg.name = f"package{i}.json"
        package_files.append(pkg)

    targets = {"package_files": package_files, "lock_files": [], "images": []}

    flow._print_detected_dependencies(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "Package manifests: 7 detected" in items
    assert "  ... and 2 more" in items


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_print_detected_dependencies_many_locks(mock_base_init):
    """Test printing >3 lock files."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()
    flow.prompter = MagicMock()

    # Create 5 lock files
    lock_files = []
    for i in range(5):
        lock = MagicMock()
        lock.name = f"lock{i}.json"
        lock_files.append(lock)

    targets = {"package_files": [], "lock_files": lock_files, "images": []}

    flow._print_detected_dependencies(targets)

    call_args = flow.prompter.print_summary_box.call_args
    items = call_args[0][1]
    assert "Lock files: 5 detected (reproducible scans)" in items
    assert "  ... and 2 more" in items


@patch(
    "scripts.cli.wizard_flows.dependency_flow.BaseWizardFlow.__init__",
    return_value=None,
)
def test_dependency_flow_print_detected_dependencies_none(mock_base_init):
    """Test printing when no dependencies detected."""
    from scripts.cli.wizard_flows.dependency_flow import DependencyFlow

    flow = DependencyFlow()
    flow.prompter = MagicMock()

    targets = {"package_files": [], "lock_files": [], "images": []}

    flow._print_detected_dependencies(targets)

    flow.prompter.print_warning.assert_called_once_with("No dependency files detected")
