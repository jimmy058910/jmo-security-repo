#!/usr/bin/env python3
"""
Schedule Command Tests for JMo Security CLI.

Tests the schedule command for managing scheduled security scans.

Usage:
    pytest tests/cli_ralph/test_schedule_command.py -v
"""

from __future__ import annotations

import json

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import unix_only


class TestScheduleBasicFunctionality:
    """Test schedule command basic functionality."""

    def test_schedule_help(self, jmo_runner):
        """Verify schedule --help shows available options."""
        result = jmo_runner(["schedule", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "schedule" in output
        # Should show subcommands
        assert "create" in output or "list" in output

    def test_schedule_requires_subcommand(self, jmo_runner):
        """Schedule command requires a subcommand."""
        result = jmo_runner(["schedule"], timeout=30)

        # Should show error about missing subcommand or show help
        combined = result.stdout.lower() + result.stderr.lower()
        assert (
            result.returncode != 0
            or "required" in combined
            or "usage" in combined
            or "choose" in combined
        )


class TestScheduleCreateSubcommand:
    """Test schedule create subcommand."""

    def test_schedule_create_help(self, jmo_runner):
        """Verify schedule create --help shows required arguments."""
        result = jmo_runner(["schedule", "create", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "--name" in output
        assert "--cron" in output
        assert "--profile" in output

    def test_schedule_create_requires_name(self, jmo_runner, tmp_path):
        """Schedule create requires --name argument."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=30,
        )

        # Should fail without --name
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "required" in combined or "--name" in combined

    def test_schedule_create_requires_cron(self, jmo_runner, tmp_path):
        """Schedule create requires --cron argument."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "test-schedule",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=30,
        )

        # Should fail without --cron
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "required" in combined or "--cron" in combined

    def test_schedule_create_requires_profile(self, jmo_runner, tmp_path):
        """Schedule create requires --profile argument."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "test-schedule",
                "--cron",
                "0 2 * * *",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=30,
        )

        # Should fail without --profile
        combined = result.stdout.lower() + result.stderr.lower()
        assert (
            result.returncode != 0 or "required" in combined or "--profile" in combined
        )

    def test_schedule_create_valid_cron(self, jmo_runner, tmp_path):
        """Schedule create accepts valid cron expression."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "nightly-scan",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=60,
        )

        # May fail for other reasons but cron should be valid
        combined = result.stdout.lower() + result.stderr.lower()
        assert "invalid cron" not in combined

    def test_schedule_create_profiles(self, jmo_runner, tmp_path):
        """Schedule create accepts all valid profiles."""
        for profile in ["fast", "balanced", "deep"]:
            result = jmo_runner(
                [
                    "schedule",
                    "create",
                    "--name",
                    f"test-{profile}",
                    "--cron",
                    "0 3 * * *",
                    "--profile",
                    profile,
                    "--repos-dir",
                    str(tmp_path),
                ],
                timeout=60,
            )

            combined = result.stdout.lower() + result.stderr.lower()
            assert "invalid" not in combined or profile not in combined

    def test_schedule_create_backend_options(self, jmo_runner, tmp_path):
        """Schedule create accepts different backend options."""
        backends = ["github-actions", "gitlab-ci", "local-cron"]

        for backend in backends:
            result = jmo_runner(
                [
                    "schedule",
                    "create",
                    "--name",
                    f"test-{backend}",
                    "--cron",
                    "0 4 * * *",
                    "--profile",
                    "fast",
                    "--repos-dir",
                    str(tmp_path),
                    "--backend",
                    backend,
                ],
                timeout=60,
            )

            combined = result.stdout.lower() + result.stderr.lower()
            assert "unrecognized" not in combined

    def test_schedule_create_with_timezone(self, jmo_runner, tmp_path):
        """Schedule create accepts --timezone option."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "timezone-test",
                "--cron",
                "0 9 * * 1",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
                "--timezone",
                "America/New_York",
            ],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_create_with_description(self, jmo_runner, tmp_path):
        """Schedule create accepts --description option."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "described-scan",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
                "--description",
                "Weekly security scan for production repos",
            ],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_create_with_labels(self, jmo_runner, tmp_path):
        """Schedule create accepts --label option."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "labeled-scan",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
                "--label",
                "env=prod",
                "--label",
                "team=security",
            ],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_create_with_slack_webhook(self, jmo_runner, tmp_path):
        """Schedule create accepts --slack-webhook option."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "slack-notify-scan",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
                "--slack-webhook",
                "https://hooks.slack.com/services/xxx/yyy/zzz",
            ],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestScheduleListSubcommand:
    """Test schedule list subcommand."""

    def test_schedule_list_help(self, jmo_runner):
        """Verify schedule list --help shows options."""
        result = jmo_runner(["schedule", "list", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "--format" in output or "list" in output

    def test_schedule_list_basic(self, jmo_runner):
        """Schedule list should work without arguments."""
        result = jmo_runner(["schedule", "list"], timeout=60)

        # Should complete (may be empty if no schedules)
        assert result.returncode == 0

    def test_schedule_list_format_table(self, jmo_runner):
        """Schedule list accepts --format table."""
        result = jmo_runner(["schedule", "list", "--format", "table"], timeout=60)

        assert result.returncode == 0

    def test_schedule_list_format_json(self, jmo_runner):
        """Schedule list accepts --format json."""
        result = jmo_runner(["schedule", "list", "--format", "json"], timeout=60)

        assert result.returncode == 0
        # Output should be valid JSON
        if result.stdout.strip():
            try:
                json.loads(result.stdout)
            except json.JSONDecodeError:
                # Empty result is OK
                assert result.stdout.strip() in ("", "[]", "{}")

    def test_schedule_list_format_yaml(self, jmo_runner):
        """Schedule list accepts --format yaml."""
        result = jmo_runner(["schedule", "list", "--format", "yaml"], timeout=60)

        assert result.returncode == 0

    def test_schedule_list_with_label_filter(self, jmo_runner):
        """Schedule list accepts --label filter."""
        result = jmo_runner(
            ["schedule", "list", "--label", "env=prod"],
            timeout=60,
        )

        assert result.returncode == 0


class TestScheduleGetSubcommand:
    """Test schedule get subcommand."""

    def test_schedule_get_help(self, jmo_runner):
        """Verify schedule get --help shows options."""
        result = jmo_runner(["schedule", "get", "--help"], timeout=30)

        assert result.returncode == 0

    def test_schedule_get_requires_name(self, jmo_runner):
        """Schedule get requires schedule name."""
        result = jmo_runner(["schedule", "get"], timeout=30)

        # Should show error about missing name
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "required" in combined or "usage" in combined

    def test_schedule_get_nonexistent(self, jmo_runner):
        """Schedule get handles nonexistent schedule."""
        result = jmo_runner(["schedule", "get", "nonexistent-schedule-xyz"], timeout=60)

        # Should fail gracefully
        combined = result.stdout.lower() + result.stderr.lower()
        assert (
            result.returncode != 0
            or "not found" in combined
            or "does not exist" in combined
        )

    def test_schedule_get_format_json(self, jmo_runner):
        """Schedule get accepts --format json."""
        result = jmo_runner(
            ["schedule", "get", "test-schedule", "--format", "json"],
            timeout=60,
        )

        # May fail if schedule doesn't exist but format should be accepted
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_get_format_yaml(self, jmo_runner):
        """Schedule get accepts --format yaml."""
        result = jmo_runner(
            ["schedule", "get", "test-schedule", "--format", "yaml"],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestScheduleUpdateSubcommand:
    """Test schedule update subcommand."""

    def test_schedule_update_help(self, jmo_runner):
        """Verify schedule update --help shows options."""
        result = jmo_runner(["schedule", "update", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "--cron" in output or "--profile" in output

    def test_schedule_update_cron(self, jmo_runner):
        """Schedule update accepts new cron expression."""
        result = jmo_runner(
            ["schedule", "update", "test-schedule", "--cron", "0 6 * * *"],
            timeout=60,
        )

        # May fail if schedule doesn't exist
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_update_profile(self, jmo_runner):
        """Schedule update accepts new profile."""
        result = jmo_runner(
            ["schedule", "update", "test-schedule", "--profile", "balanced"],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_update_suspend(self, jmo_runner):
        """Schedule update accepts --suspend flag."""
        result = jmo_runner(
            ["schedule", "update", "test-schedule", "--suspend"],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_update_resume(self, jmo_runner):
        """Schedule update accepts --resume flag."""
        result = jmo_runner(
            ["schedule", "update", "test-schedule", "--resume"],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestScheduleExportSubcommand:
    """Test schedule export subcommand."""

    def test_schedule_export_help(self, jmo_runner):
        """Verify schedule export --help shows options."""
        result = jmo_runner(["schedule", "export", "--help"], timeout=30)

        assert result.returncode == 0

    def test_schedule_export_github_actions(self, jmo_runner):
        """Schedule export accepts github-actions backend."""
        result = jmo_runner(
            [
                "schedule",
                "export",
                "test-schedule",
                "--backend",
                "github-actions",
            ],
            timeout=60,
        )

        # May fail if schedule doesn't exist
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_export_gitlab_ci(self, jmo_runner):
        """Schedule export accepts gitlab-ci backend."""
        result = jmo_runner(
            ["schedule", "export", "test-schedule", "--backend", "gitlab-ci"],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_schedule_export_to_file(self, jmo_runner, tmp_path):
        """Schedule export accepts --output option."""
        output_file = tmp_path / "workflow.yml"
        result = jmo_runner(
            ["schedule", "export", "test-schedule", "--output", str(output_file)],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestScheduleDeleteSubcommand:
    """Test schedule delete subcommand."""

    def test_schedule_delete_help(self, jmo_runner):
        """Verify schedule delete --help shows options."""
        result = jmo_runner(["schedule", "delete", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "--force" in output or "delete" in output

    def test_schedule_delete_requires_name(self, jmo_runner):
        """Schedule delete requires schedule name."""
        result = jmo_runner(["schedule", "delete"], timeout=30)

        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "required" in combined

    def test_schedule_delete_force_flag(self, jmo_runner):
        """Schedule delete accepts --force flag."""
        result = jmo_runner(
            ["schedule", "delete", "test-schedule", "--force"],
            timeout=60,
        )

        # May fail if schedule doesn't exist
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestScheduleValidateSubcommand:
    """Test schedule validate subcommand."""

    def test_schedule_validate_help(self, jmo_runner):
        """Verify schedule validate --help shows options."""
        result = jmo_runner(["schedule", "validate", "--help"], timeout=30)

        assert result.returncode == 0

    def test_schedule_validate_basic(self, jmo_runner):
        """Schedule validate checks schedule configuration."""
        result = jmo_runner(["schedule", "validate", "test-schedule"], timeout=60)

        # May fail if schedule doesn't exist
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestScheduleInstallUninstall:
    """Test schedule install/uninstall for local cron."""

    @unix_only
    def test_schedule_install_help(self, jmo_runner):
        """Verify schedule install --help shows options."""
        result = jmo_runner(["schedule", "install", "--help"], timeout=30)

        assert result.returncode == 0

    @unix_only
    def test_schedule_uninstall_help(self, jmo_runner):
        """Verify schedule uninstall --help shows options."""
        result = jmo_runner(["schedule", "uninstall", "--help"], timeout=30)

        assert result.returncode == 0


class TestScheduleCronExpressions:
    """Test cron expression parsing and validation."""

    @pytest.mark.parametrize(
        "cron_expr,description",
        [
            ("0 2 * * *", "Daily at 2 AM"),
            ("0 0 * * 0", "Weekly on Sunday"),
            ("0 */6 * * *", "Every 6 hours"),
            ("30 8 * * 1-5", "Weekdays at 8:30 AM"),
            ("0 0 1 * *", "Monthly on the 1st"),
        ],
    )
    def test_schedule_create_valid_cron_expressions(
        self, jmo_runner, tmp_path, cron_expr, description
    ):
        """Schedule create accepts various valid cron expressions."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                f"cron-test-{hash(cron_expr) % 10000}",
                "--cron",
                cron_expr,
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        # Should not show cron validation error
        assert "invalid cron" not in combined


class TestScheduleEdgeCases:
    """Test schedule edge cases and error handling."""

    def test_schedule_unknown_subcommand(self, jmo_runner):
        """Unknown subcommand should be rejected."""
        result = jmo_runner(["schedule", "unknown_action_xyz"], timeout=30)

        assert result.returncode != 0

    def test_schedule_create_invalid_profile(self, jmo_runner, tmp_path):
        """Invalid profile should be rejected."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "invalid-profile-test",
                "--cron",
                "0 2 * * *",
                "--profile",
                "invalid_profile_xyz",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=30,
        )

        # Should fail or warn about invalid profile
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "invalid" in combined

    def test_schedule_create_invalid_backend(self, jmo_runner, tmp_path):
        """Invalid backend should be rejected."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "invalid-backend-test",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
                "--backend",
                "invalid_backend_xyz",
            ],
            timeout=30,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "invalid" in combined

    def test_schedule_name_with_spaces(self, jmo_runner, tmp_path):
        """Schedule name with spaces should be handled."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "schedule with spaces",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=60,
        )

        # Should either accept or reject gracefully
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_schedule_name_with_special_chars(self, jmo_runner, tmp_path):
        """Schedule name with special characters should be handled."""
        result = jmo_runner(
            [
                "schedule",
                "create",
                "--name",
                "test@schedule#1",
                "--cron",
                "0 2 * * *",
                "--profile",
                "fast",
                "--repos-dir",
                str(tmp_path),
            ],
            timeout=60,
        )

        # Should either accept or reject gracefully
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined
