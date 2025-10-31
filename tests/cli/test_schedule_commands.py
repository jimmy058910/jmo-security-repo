"""Unit tests for jmo schedule command handlers.

Tests cover all 9 schedule subcommands:
- create: Create new schedule
- list: List all schedules
- get: Get schedule details
- update: Update schedule
- export: Export workflow file
- install: Install to local cron
- uninstall: Remove from cron
- delete: Delete schedule
- validate: Validate schedule configuration

Architecture Note:
- Tests use mock ScheduleManager to avoid file I/O
- Tests use mock CronInstaller to avoid system crontab changes
- Tests use mock workflow generators for export tests
"""

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from typing import Any, Dict, Optional

import pytest
import yaml

from scripts.cli.schedule_commands import (
    cmd_schedule,
    _cmd_schedule_create,
    _cmd_schedule_list,
    _cmd_schedule_get,
    _cmd_schedule_update,
    _cmd_schedule_export,
    _cmd_schedule_install,
    _cmd_schedule_uninstall,
    _cmd_schedule_delete,
    _cmd_schedule_validate,
)
from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    ScheduleStatus,
    BackendConfig,
    JobTemplateSpec,
)
from scripts.core.cron_installer import (
    UnsupportedPlatformError,
    CronNotAvailableError,
    CronInstallError,
)


def create_mock_args(**kwargs: Any) -> MagicMock:
    """Create mock argparse Namespace with explicit attributes.

    This avoids MagicMock auto-creation issues where attributes
    return MagicMock objects instead of None.

    Args:
        **kwargs: Attribute name-value pairs to set

    Returns:
        MagicMock with explicitly set attributes
    """
    args = MagicMock(spec=[])

    # Define ALL expected attributes with None defaults
    all_attrs = {
        "schedule_action": None,
        "name": None,
        "cron": None,
        "timezone": "UTC",
        "backend": "local-cron",
        "profile": "balanced",
        "description": None,
        "label": None,
        "repos_dir": None,
        "image": None,
        "url": None,
        "slack_webhook": None,
        "format": "table",
        "output": None,
        "suspend": False,
        "resume": False,
        "force": False,
    }

    # Override with provided values
    all_attrs.update(kwargs)

    # Explicitly set attributes
    for key, value in all_attrs.items():
        setattr(args, key, value)

    return args


@pytest.fixture
def sample_schedule():
    """Create a sample schedule for testing."""
    return ScanSchedule(
        metadata=ScheduleMetadata(
            name="nightly-deep",
            labels={"env": "prod", "team": "security"},
            annotations={"description": "Nightly deep scan"},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
            jobTemplate=JobTemplateSpec(
                profile="deep",
                targets={
                    "repositories": {"repos_dir": "~/repos"},
                    "images": ["nginx:latest", "redis:alpine"],
                    "web": {"urls": ["https://example.com"]},
                },
                options={"allow_missing_tools": True, "threads": 4},
                results={"retention_days": 90},
                notifications={
                    "enabled": True,
                    "channels": [
                        {
                            "type": "slack",
                            "url": "https://hooks.slack.com/test",
                            "events": ["failure", "success"],
                        }
                    ],
                },
            ),
        ),
        status=ScheduleStatus(),
    )


# ========== Test Category 1: cmd_schedule (Router) ==========


def test_cmd_schedule_routes_to_create():
    """Test cmd_schedule routes to create subcommand."""
    args = create_mock_args(schedule_action="create", name="test", cron="0 2 * * *", repos_dir="~/repos")

    with patch("scripts.cli.schedule_commands._cmd_schedule_create") as mock_create:
        mock_create.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_create.assert_called_once()


def test_cmd_schedule_routes_to_list():
    """Test cmd_schedule routes to list subcommand."""
    args = create_mock_args(schedule_action="list")

    with patch("scripts.cli.schedule_commands._cmd_schedule_list") as mock_list:
        mock_list.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_list.assert_called_once()


def test_cmd_schedule_routes_to_get():
    """Test cmd_schedule routes to get subcommand."""
    args = create_mock_args(schedule_action="get", name="test")

    with patch("scripts.cli.schedule_commands._cmd_schedule_get") as mock_get:
        mock_get.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_get.assert_called_once()


def test_cmd_schedule_routes_to_update():
    """Test cmd_schedule routes to update subcommand."""
    args = create_mock_args(schedule_action="update", name="test")

    with patch("scripts.cli.schedule_commands._cmd_schedule_update") as mock_update:
        mock_update.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_update.assert_called_once()


def test_cmd_schedule_routes_to_export():
    """Test cmd_schedule routes to export subcommand."""
    args = create_mock_args(schedule_action="export", name="test")

    with patch("scripts.cli.schedule_commands._cmd_schedule_export") as mock_export:
        mock_export.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_export.assert_called_once()


def test_cmd_schedule_routes_to_install():
    """Test cmd_schedule routes to install subcommand."""
    args = create_mock_args(schedule_action="install", name="test")

    with patch("scripts.cli.schedule_commands._cmd_schedule_install") as mock_install:
        mock_install.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_install.assert_called_once()


def test_cmd_schedule_routes_to_uninstall():
    """Test cmd_schedule routes to uninstall subcommand."""
    args = create_mock_args(schedule_action="uninstall", name="test")

    with patch("scripts.cli.schedule_commands._cmd_schedule_uninstall") as mock_uninstall:
        mock_uninstall.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_uninstall.assert_called_once()


def test_cmd_schedule_routes_to_delete():
    """Test cmd_schedule routes to delete subcommand."""
    args = create_mock_args(schedule_action="delete", name="test", force=True)

    with patch("scripts.cli.schedule_commands._cmd_schedule_delete") as mock_delete:
        mock_delete.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_delete.assert_called_once()


def test_cmd_schedule_routes_to_validate():
    """Test cmd_schedule routes to validate subcommand."""
    args = create_mock_args(schedule_action="validate", name="test")

    with patch("scripts.cli.schedule_commands._cmd_schedule_validate") as mock_validate:
        mock_validate.return_value = 0
        result = cmd_schedule(args)

    assert result == 0
    mock_validate.assert_called_once()


def test_cmd_schedule_unknown_action():
    """Test cmd_schedule with unknown action."""
    args = create_mock_args(schedule_action="unknown")

    with patch("scripts.cli.schedule_commands._error") as mock_error:
        result = cmd_schedule(args)

    assert result == 1
    mock_error.assert_called_once()
    assert "Unknown schedule action" in mock_error.call_args[0][0]


def test_cmd_schedule_exception_handling():
    """Test cmd_schedule handles exceptions gracefully."""
    args = create_mock_args(schedule_action="create", name="test", cron="0 2 * * *", repos_dir="~/repos")

    with patch("scripts.cli.schedule_commands._cmd_schedule_create") as mock_create:
        mock_create.side_effect = ValueError("Test error")
        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = cmd_schedule(args)

    assert result == 1
    mock_error.assert_called_once_with("Test error")


# ========== Test Category 2: _cmd_schedule_create ==========


def test_create_schedule_success():
    """Test creating a new schedule successfully."""
    args = create_mock_args(
        schedule_action="create",
        name="test-schedule",
        cron="0 2 * * *",
        timezone="UTC",
        backend="github-actions",
        profile="balanced",
        description="Test description",
        label=["env=prod", "team=security"],
        repos_dir="~/repos",
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.create = MagicMock()

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            with patch("scripts.cli.schedule_commands._info") as mock_info:
                result = _cmd_schedule_create(args, mock_manager)

    assert result == 0
    mock_manager.create.assert_called_once()
    mock_success.assert_called()


def test_create_schedule_invalid_cron():
    """Test creating schedule with invalid cron expression."""
    args = create_mock_args(
        name="test",
        cron="invalid cron",
        repos_dir="~/repos",
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_create(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Invalid cron expression" in mock_error.call_args[0][0]


def test_create_schedule_invalid_label_format():
    """Test creating schedule with invalid label format."""
    args = create_mock_args(
        name="test",
        cron="0 2 * * *",
        label=["invalid"],  # Missing = separator
        repos_dir="~/repos",
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_create(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Invalid label format" in mock_error.call_args[0][0]


def test_create_schedule_no_targets():
    """Test creating schedule without any targets."""
    args = create_mock_args(
        name="test",
        cron="0 2 * * *",
        # No repos_dir, image, or url
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_create(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "No targets specified" in mock_error.call_args[0][0]


def test_create_schedule_with_images():
    """Test creating schedule with container images."""
    args = create_mock_args(
        name="test",
        cron="0 2 * * *",
        image=["nginx:latest", "redis:alpine"],
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.create = MagicMock()

        with patch("scripts.cli.schedule_commands._success"):
            with patch("scripts.cli.schedule_commands._info"):
                result = _cmd_schedule_create(args, mock_manager)

    assert result == 0
    # Verify targets include images
    create_call = mock_manager.create.call_args[0][0]
    assert "images" in create_call.spec.jobTemplate.targets
    assert create_call.spec.jobTemplate.targets["images"] == ["nginx:latest", "redis:alpine"]


def test_create_schedule_with_slack_notifications():
    """Test creating schedule with Slack notifications."""
    args = create_mock_args(
        name="test",
        cron="0 2 * * *",
        repos_dir="~/repos",
        slack_webhook="https://hooks.slack.com/test",
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.create = MagicMock()

        with patch("scripts.cli.schedule_commands._success"):
            with patch("scripts.cli.schedule_commands._info"):
                result = _cmd_schedule_create(args, mock_manager)

    assert result == 0
    # Verify notifications configured
    create_call = mock_manager.create.call_args[0][0]
    assert create_call.spec.jobTemplate.notifications["enabled"] is True
    assert len(create_call.spec.jobTemplate.notifications["channels"]) == 1


# ========== Test Category 3: _cmd_schedule_list ==========


def test_list_schedules_table_format(sample_schedule):
    """Test listing schedules in table format."""
    args = create_mock_args(format="table")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.list.return_value = [sample_schedule]

        with patch("scripts.cli.schedule_commands._print_schedules_table") as mock_print:
            result = _cmd_schedule_list(args, mock_manager)

    assert result == 0
    mock_print.assert_called_once_with([sample_schedule])


def test_list_schedules_json_format(sample_schedule, capsys):
    """Test listing schedules in JSON format."""
    args = create_mock_args(format="json")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.list.return_value = [sample_schedule]

        result = _cmd_schedule_list(args, mock_manager)

    assert result == 0
    captured = capsys.readouterr()
    # Verify valid JSON output
    parsed = json.loads(captured.out)
    assert len(parsed) == 1
    assert parsed[0]["metadata"]["name"] == "nightly-deep"


def test_list_schedules_yaml_format(sample_schedule, capsys):
    """Test listing schedules in YAML format."""
    args = create_mock_args(format="yaml")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.list.return_value = [sample_schedule]

        result = _cmd_schedule_list(args, mock_manager)

    assert result == 0
    captured = capsys.readouterr()
    # Verify valid YAML output
    parsed = yaml.safe_load(captured.out)
    assert len(parsed) == 1
    assert parsed[0]["metadata"]["name"] == "nightly-deep"


def test_list_schedules_with_label_filter(sample_schedule):
    """Test listing schedules with label filters."""
    args = create_mock_args(
        format="table",
        label=["env=prod", "team=security"],
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.list.return_value = [sample_schedule]

        with patch("scripts.cli.schedule_commands._print_schedules_table") as mock_print:
            result = _cmd_schedule_list(args, mock_manager)

    assert result == 0
    mock_print.assert_called_once_with([sample_schedule])


def test_list_schedules_invalid_label_format():
    """Test listing schedules with invalid label format."""
    args = create_mock_args(
        format="table",
        label=["invalid"],  # Missing = separator
    )

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_list(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Invalid label filter" in mock_error.call_args[0][0]


# ========== Test Category 4: _cmd_schedule_get ==========


def test_get_schedule_json_format(sample_schedule, capsys):
    """Test getting schedule in JSON format."""
    args = create_mock_args(name="nightly-deep", format="json")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        result = _cmd_schedule_get(args, mock_manager)

    assert result == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["metadata"]["name"] == "nightly-deep"


def test_get_schedule_yaml_format(sample_schedule, capsys):
    """Test getting schedule in YAML format."""
    args = create_mock_args(name="nightly-deep", format="yaml")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        result = _cmd_schedule_get(args, mock_manager)

    assert result == 0
    captured = capsys.readouterr()
    parsed = yaml.safe_load(captured.out)
    assert parsed["metadata"]["name"] == "nightly-deep"


def test_get_schedule_not_found():
    """Test getting non-existent schedule."""
    args = create_mock_args(name="nonexistent", format="json")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = None

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_get(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "not found" in mock_error.call_args[0][0]


# ========== Test Category 5: _cmd_schedule_update ==========


def test_update_schedule_cron(sample_schedule):
    """Test updating schedule cron expression."""
    args = create_mock_args(name="nightly-deep", cron="0 3 * * *")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule
        mock_manager.update = MagicMock()

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            result = _cmd_schedule_update(args, mock_manager)

    assert result == 0
    mock_manager.update.assert_called_once()
    assert sample_schedule.spec.schedule == "0 3 * * *"
    mock_success.assert_called()


def test_update_schedule_profile(sample_schedule):
    """Test updating schedule profile."""
    args = create_mock_args(name="nightly-deep", profile="fast")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule
        mock_manager.update = MagicMock()

        with patch("scripts.cli.schedule_commands._success"):
            result = _cmd_schedule_update(args, mock_manager)

    assert result == 0
    assert sample_schedule.spec.jobTemplate.profile == "fast"


def test_update_schedule_suspend(sample_schedule):
    """Test suspending a schedule."""
    args = create_mock_args(name="nightly-deep", suspend=True)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule
        mock_manager.update = MagicMock()

        with patch("scripts.cli.schedule_commands._success"):
            result = _cmd_schedule_update(args, mock_manager)

    assert result == 0
    assert sample_schedule.spec.suspend is True


def test_update_schedule_resume(sample_schedule):
    """Test resuming a suspended schedule."""
    sample_schedule.spec.suspend = True
    args = create_mock_args(name="nightly-deep", resume=True)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule
        mock_manager.update = MagicMock()

        with patch("scripts.cli.schedule_commands._success"):
            result = _cmd_schedule_update(args, mock_manager)

    assert result == 0
    assert sample_schedule.spec.suspend is False


def test_update_schedule_not_found():
    """Test updating non-existent schedule."""
    args = create_mock_args(name="nonexistent", cron="0 3 * * *")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = None

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_update(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


def test_update_schedule_invalid_cron(sample_schedule):
    """Test updating schedule with invalid cron expression."""
    args = create_mock_args(name="nightly-deep", cron="invalid cron")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_update(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Invalid cron expression" in mock_error.call_args[0][0]


# ========== Test Category 6: _cmd_schedule_export ==========


def test_export_github_actions_workflow(sample_schedule, capsys):
    """Test exporting GitHub Actions workflow."""
    args = create_mock_args(name="nightly-deep", backend=None, output=None)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.GitHubActionsGenerator") as MockGen:
            mock_gen = MockGen.return_value
            mock_gen.generate.return_value = "name: test\non: schedule\n"

            result = _cmd_schedule_export(args, mock_manager)

    assert result == 0
    captured = capsys.readouterr()
    assert "name: test" in captured.out


def test_export_gitlab_ci_workflow(sample_schedule, capsys):
    """Test exporting GitLab CI workflow."""
    sample_schedule.spec.backend.type = "gitlab-ci"
    args = create_mock_args(name="nightly-deep", backend=None, output=None)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.GitLabCIGenerator") as MockGen:
            mock_gen = MockGen.return_value
            mock_gen.generate.return_value = "security-scan:\n  script: jmo scan\n"

            result = _cmd_schedule_export(args, mock_manager)

    assert result == 0
    captured = capsys.readouterr()
    assert "security-scan:" in captured.out


def test_export_to_file(sample_schedule, tmp_path):
    """Test exporting workflow to file."""
    output_file = tmp_path / "workflow.yml"
    args = create_mock_args(name="nightly-deep", backend=None, output=str(output_file))

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.GitHubActionsGenerator") as MockGen:
            mock_gen = MockGen.return_value
            mock_gen.generate.return_value = "name: test\n"

            with patch("scripts.cli.schedule_commands._success") as mock_success:
                result = _cmd_schedule_export(args, mock_manager)

    assert result == 0
    assert output_file.exists()
    assert output_file.read_text() == "name: test\n"
    mock_success.assert_called()


def test_export_schedule_not_found():
    """Test exporting non-existent schedule."""
    args = create_mock_args(name="nonexistent", backend=None, output=None)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = None

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_export(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


def test_export_unsupported_backend(sample_schedule):
    """Test exporting with unsupported backend type."""
    sample_schedule.spec.backend.type = "local-cron"
    args = create_mock_args(name="nightly-deep", backend=None, output=None)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_export(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Cannot export backend type" in mock_error.call_args[0][0]


# ========== Test Category 7: _cmd_schedule_install ==========


def test_install_schedule_success(sample_schedule):
    """Test installing schedule to crontab."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
            mock_installer = MockInstaller.return_value
            mock_installer.install.return_value = True

            with patch("scripts.cli.schedule_commands._success") as mock_success:
                with patch("scripts.cli.schedule_commands._info") as mock_info:
                    result = _cmd_schedule_install(args, mock_manager)

    assert result == 0
    mock_success.assert_called()
    mock_info.assert_called()


def test_install_schedule_not_found():
    """Test installing non-existent schedule."""
    args = create_mock_args(name="nonexistent")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = None

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_install(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


def test_install_schedule_unsupported_platform(sample_schedule):
    """Test installing on unsupported platform (e.g., Windows)."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
            MockInstaller.side_effect = UnsupportedPlatformError("Windows not supported")

            with patch("scripts.cli.schedule_commands._error") as mock_error:
                result = _cmd_schedule_install(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


def test_install_schedule_cron_not_available(sample_schedule):
    """Test installing when crontab command not available."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
            mock_installer = MockInstaller.return_value
            mock_installer.install.side_effect = CronNotAvailableError("crontab not found")

            with patch("scripts.cli.schedule_commands._error") as mock_error:
                result = _cmd_schedule_install(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Cron installation failed" in mock_error.call_args[0][0]


def test_install_schedule_cron_install_error(sample_schedule):
    """Test installing when crontab install fails."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
            mock_installer = MockInstaller.return_value
            mock_installer.install.side_effect = CronInstallError("Permission denied")

            with patch("scripts.cli.schedule_commands._error") as mock_error:
                result = _cmd_schedule_install(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


# ========== Test Category 8: _cmd_schedule_uninstall ==========


def test_uninstall_schedule_success():
    """Test uninstalling schedule from crontab."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
        mock_installer = MockInstaller.return_value
        mock_installer.uninstall.return_value = True

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            result = _cmd_schedule_uninstall(args, mock_installer)

    assert result == 0
    mock_success.assert_called()


def test_uninstall_schedule_not_found():
    """Test uninstalling non-existent schedule from crontab."""
    args = create_mock_args(name="nonexistent")

    with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
        mock_installer = MockInstaller.return_value
        mock_installer.uninstall.return_value = False

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_uninstall(args, mock_installer)

    assert result == 1
    mock_error.assert_called()
    assert "not found in crontab" in mock_error.call_args[0][0]


def test_uninstall_schedule_unsupported_platform():
    """Test uninstalling on unsupported platform."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.CronInstaller") as MockInstaller:
        MockInstaller.side_effect = UnsupportedPlatformError("Windows not supported")

        with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
            mock_manager = MockManager.return_value
            with patch("scripts.cli.schedule_commands._error") as mock_error:
                result = _cmd_schedule_uninstall(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


# ========== Test Category 9: _cmd_schedule_delete ==========


def test_delete_schedule_with_force(sample_schedule):
    """Test deleting schedule with --force flag."""
    args = create_mock_args(name="nightly-deep", force=True)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule
        mock_manager.delete = MagicMock()

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            result = _cmd_schedule_delete(args, mock_manager)

    assert result == 0
    mock_manager.delete.assert_called_once_with("nightly-deep")
    mock_success.assert_called()


def test_delete_schedule_with_confirmation(sample_schedule):
    """Test deleting schedule with user confirmation."""
    args = create_mock_args(name="nightly-deep", force=False)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule
        mock_manager.delete = MagicMock()

        with patch("builtins.input", return_value="yes"):
            with patch("scripts.cli.schedule_commands._warn") as mock_warn:
                with patch("scripts.cli.schedule_commands._success") as mock_success:
                    result = _cmd_schedule_delete(args, mock_manager)

    assert result == 0
    mock_warn.assert_called()
    mock_manager.delete.assert_called_once()
    mock_success.assert_called()


def test_delete_schedule_cancelled(sample_schedule):
    """Test cancelling schedule deletion."""
    args = create_mock_args(name="nightly-deep", force=False)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("builtins.input", return_value="no"):
            with patch("scripts.cli.schedule_commands._info") as mock_info:
                result = _cmd_schedule_delete(args, mock_manager)

    assert result == 0
    mock_info.assert_called()
    # Verify delete was NOT called
    mock_manager.delete.assert_not_called()


def test_delete_schedule_not_found():
    """Test deleting non-existent schedule."""
    args = create_mock_args(name="nonexistent", force=True)

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = None

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_delete(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


# ========== Test Category 10: _cmd_schedule_validate ==========


def test_validate_schedule_success(sample_schedule):
    """Test validating a valid schedule."""
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            result = _cmd_schedule_validate(args, mock_manager)

    assert result == 0
    # Should be called 4 times: cron valid, targets valid, backend valid, overall valid
    assert mock_success.call_count == 4


def test_validate_schedule_not_found():
    """Test validating non-existent schedule."""
    args = create_mock_args(name="nonexistent")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = None

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_validate(args, mock_manager)

    assert result == 1
    mock_error.assert_called()


def test_validate_schedule_invalid_cron(sample_schedule):
    """Test validating schedule with invalid cron expression."""
    sample_schedule.spec.schedule = "invalid cron"
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands._error") as mock_error:
            result = _cmd_schedule_validate(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Invalid cron expression" in mock_error.call_args[0][0]


def test_validate_schedule_no_targets(sample_schedule):
    """Test validating schedule with no targets."""
    sample_schedule.spec.jobTemplate.targets = {}
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            with patch("scripts.cli.schedule_commands._error") as mock_error:
                result = _cmd_schedule_validate(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "No targets configured" in mock_error.call_args[0][0]


def test_validate_schedule_unknown_backend(sample_schedule):
    """Test validating schedule with unknown backend type."""
    sample_schedule.spec.backend.type = "unknown-backend"
    args = create_mock_args(name="nightly-deep")

    with patch("scripts.cli.schedule_commands.ScheduleManager") as MockManager:
        mock_manager = MockManager.return_value
        mock_manager.get.return_value = sample_schedule

        with patch("scripts.cli.schedule_commands._success") as mock_success:
            with patch("scripts.cli.schedule_commands._error") as mock_error:
                result = _cmd_schedule_validate(args, mock_manager)

    assert result == 1
    mock_error.assert_called()
    assert "Unknown backend type" in mock_error.call_args[0][0]


# ========== Test Category 11: Utility Functions ==========


def test_print_schedules_table_empty():
    """Test printing empty schedules table."""
    with patch("scripts.cli.schedule_commands._info") as mock_info:
        from scripts.cli.schedule_commands import _print_schedules_table

        _print_schedules_table([])

    mock_info.assert_called_once_with("No schedules found")


def test_print_schedules_table_with_data(sample_schedule, capsys):
    """Test printing schedules table with data."""
    from scripts.cli.schedule_commands import _print_schedules_table

    _print_schedules_table([sample_schedule])

    captured = capsys.readouterr()
    assert "NAME" in captured.out
    assert "BACKEND" in captured.out
    assert "PROFILE" in captured.out
    assert "CRON" in captured.out
    assert "STATUS" in captured.out
    assert "nightly-deep" in captured.out
    assert "github-actions" in captured.out
    assert "deep" in captured.out
    assert "ACTIVE" in captured.out


def test_print_schedules_table_suspended(sample_schedule, capsys):
    """Test printing schedules table with suspended schedule."""
    sample_schedule.spec.suspend = True
    from scripts.cli.schedule_commands import _print_schedules_table

    _print_schedules_table([sample_schedule])

    captured = capsys.readouterr()
    assert "SUSPENDED" in captured.out


def test_success_message(capsys):
    """Test success message formatting."""
    from scripts.cli.schedule_commands import _success

    _success("Test message")

    captured = capsys.readouterr()
    assert "Test message" in captured.err
    assert "\x1b[32m" in captured.err  # Green color code


def test_info_message(capsys):
    """Test info message formatting."""
    from scripts.cli.schedule_commands import _info

    _info("Test message")

    captured = capsys.readouterr()
    assert "Test message" in captured.err


def test_warn_message(capsys):
    """Test warning message formatting."""
    from scripts.cli.schedule_commands import _warn

    _warn("Test message")

    captured = capsys.readouterr()
    assert "Test message" in captured.err
    assert "\x1b[33m" in captured.err  # Yellow color code


def test_error_message(capsys):
    """Test error message formatting."""
    from scripts.cli.schedule_commands import _error

    _error("Test message")

    captured = capsys.readouterr()
    assert "Test message" in captured.err
    assert "\x1b[31m" in captured.err  # Red color code
