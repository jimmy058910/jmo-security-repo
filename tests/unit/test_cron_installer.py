"""Unit tests for local cron installer.

Tests cover:
- Install to crontab
- Uninstall from crontab
- List installed schedules
- Prevent duplicate schedules
- Marker-based removal
- Unsupported platform error (Windows)
"""

import platform
import subprocess
from unittest.mock import patch, MagicMock
import pytest

from scripts.core.cron_installer import (
    CronInstaller,
    UnsupportedPlatformError,
    CronNotAvailableError,
    CronInstallError,
)
from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    BackendConfig,
    JobTemplateSpec,
)


@pytest.fixture
def sample_schedule():
    """Create a sample schedule for testing."""
    return ScanSchedule(
        metadata=ScheduleMetadata(
            name="test-schedule",
            labels={},
            annotations={"description": "Test schedule"},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="local-cron"),
            jobTemplate=JobTemplateSpec(
                profile="balanced",
                targets={"repositories": {"repos_dir": "~/repos"}},
                options={},
                results={},
                notifications={"enabled": False},
            ),
        ),
        status={},
    )


def test_install_to_crontab(sample_schedule):
    """Test installing a schedule to crontab."""
    with patch("subprocess.run") as mock_run:
        # Mock crontab -l (empty)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # crontab -l
            MagicMock(returncode=0),  # crontab -
        ]

        installer = CronInstaller()
        result = installer.install(sample_schedule)

        assert result is True
        assert mock_run.call_count == 2

        # Verify crontab - was called with correct content
        install_call = mock_run.call_args_list[1]
        cron_content = install_call[1]["input"]

        assert "# JMo Security Schedule: test-schedule" in cron_content
        assert "0 2 * * *" in cron_content
        assert "jmo scan --profile balanced" in cron_content
        assert "# End JMo Schedule" in cron_content


def test_uninstall_from_crontab(sample_schedule):
    """Test removing a schedule from crontab."""
    existing_crontab = """# JMo Security Schedule: test-schedule
0 2 * * * jmo scan --profile balanced --repos-dir ~/repos
# End JMo Schedule
"""

    with patch("subprocess.run") as mock_run:
        # Mock crontab -l (with existing schedule)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=existing_crontab),  # crontab -l
            MagicMock(returncode=0),  # crontab -
        ]

        installer = CronInstaller()
        result = installer.uninstall("test-schedule")

        assert result is True
        assert mock_run.call_count == 2

        # Verify schedule was removed
        install_call = mock_run.call_args_list[1]
        cron_content = install_call[1]["input"]

        assert "test-schedule" not in cron_content
        assert "0 2 * * *" not in cron_content


def test_list_installed_schedules():
    """Test listing all JMo schedules in crontab."""
    existing_crontab = """# JMo Security Schedule: nightly-deep
0 2 * * * jmo scan --profile deep
# End JMo Schedule

# JMo Security Schedule: weekly-balanced
0 3 * * 0 jmo scan --profile balanced
# End JMo Schedule

# Other cron job
0 1 * * * /usr/bin/backup.sh
"""

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=existing_crontab)

        installer = CronInstaller()
        schedules = installer.list_installed()

        assert len(schedules) == 2
        assert "nightly-deep" in schedules
        assert "weekly-balanced" in schedules


def test_prevent_duplicates(sample_schedule):
    """Test that installing the same schedule twice replaces the old entry."""
    existing_crontab = """# JMo Security Schedule: test-schedule
0 1 * * * jmo scan --profile fast
# End JMo Schedule
"""

    with patch("subprocess.run") as mock_run:
        # Mock crontab -l (with existing schedule)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=existing_crontab),  # crontab -l
            MagicMock(returncode=0),  # crontab -
        ]

        installer = CronInstaller()
        result = installer.install(sample_schedule)

        assert result is True

        # Verify old entry was replaced (not duplicated)
        install_call = mock_run.call_args_list[1]
        cron_content = install_call[1]["input"]

        # Should only appear once
        assert cron_content.count("# JMo Security Schedule: test-schedule") == 1
        assert cron_content.count("0 2 * * *") == 1  # New cron expression
        assert "0 1 * * *" not in cron_content  # Old expression removed


def test_marker_based_removal():
    """Test that marker-based removal doesn't affect other cron jobs."""
    existing_crontab = """# JMo Security Schedule: remove-me
0 2 * * * jmo scan --profile balanced
# End JMo Schedule

# Important backup job
0 1 * * * /usr/bin/backup.sh

# JMo Security Schedule: keep-me
0 3 * * * jmo scan --profile deep
# End JMo Schedule
"""

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=existing_crontab),  # crontab -l
            MagicMock(returncode=0),  # crontab -
        ]

        installer = CronInstaller()
        result = installer.uninstall("remove-me")

        assert result is True

        # Verify correct removal
        install_call = mock_run.call_args_list[1]
        cron_content = install_call[1]["input"]

        # "remove-me" should be gone
        assert "remove-me" not in cron_content

        # "keep-me" should remain
        assert "keep-me" in cron_content
        assert "0 3 * * * jmo scan --profile deep" in cron_content

        # Other cron jobs should remain
        assert "/usr/bin/backup.sh" in cron_content


@patch("platform.system")
def test_unsupported_platform_error(mock_platform):
    """Test that Windows raises UnsupportedPlatformError."""
    mock_platform.return_value = "Windows"

    with pytest.raises(UnsupportedPlatformError) as excinfo:
        CronInstaller()

    assert "not supported on Windows" in str(excinfo.value)
    assert "GitHub Actions" in str(excinfo.value)


def test_cron_not_available_error():
    """Test error when crontab command not found."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("crontab not found")

        installer = CronInstaller()

        with pytest.raises(CronNotAvailableError) as excinfo:
            installer._get_crontab()

        assert "crontab command not found" in str(excinfo.value)


def test_cron_install_error(sample_schedule):
    """Test error handling when crontab installation fails."""
    with patch("subprocess.run") as mock_run:
        # crontab -l succeeds, crontab - fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # crontab -l
            subprocess.CalledProcessError(1, "crontab", stderr="Permission denied"),  # crontab -
        ]

        installer = CronInstaller()

        with pytest.raises(CronInstallError) as excinfo:
            installer.install(sample_schedule)

        assert "Failed to install crontab" in str(excinfo.value)
