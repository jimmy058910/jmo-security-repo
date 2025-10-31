"""Integration tests for GitHub Actions workflow generation.

Tests validate generated workflows work end-to-end:
- Workflow file validity (YAML parsing)
- Actionlint validation (if available)
- Workflow triggers correctly
- Schedule runs at correct time
"""

import pytest
import subprocess
import tempfile
from pathlib import Path
import yaml

from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    BackendConfig,
    JobTemplateSpec,
)
from scripts.core.workflow_generators.github_actions import GitHubActionsGenerator


def test_workflow_file_validity():
    """Test that generated workflow is valid YAML and well-formed."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="validity-test",
            annotations={"description": "Test workflow validity"},
            labels={},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
            jobTemplate=JobTemplateSpec(
                profile="balanced",
                targets={
                    "repositories": {"repos_dir": "~/repos"},
                    "images": ["nginx:latest"],
                    "web": {"urls": ["https://example.com"]},
                },
                options={},
                results={},
                notifications={"enabled": False},
            ),
        ),
        status={},
    )

    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(schedule)

    # Parse YAML
    workflow = yaml.safe_load(workflow_yaml)

    # Validate required keys
    assert "name" in workflow
    assert "on" in workflow
    assert "permissions" in workflow
    assert "jobs" in workflow

    # Validate job structure
    assert "security-scan" in workflow["jobs"]
    job = workflow["jobs"]["security-scan"]
    assert "runs-on" in job
    assert "steps" in job
    assert len(job["steps"]) >= 4  # checkout, scan, upload results, upload SARIF

    # Validate permissions
    assert workflow["permissions"]["contents"] == "read"
    assert workflow["permissions"]["security-events"] == "write"

    # Validate triggers
    assert "schedule" in workflow["on"]
    assert "workflow_dispatch" in workflow["on"]


@pytest.mark.skipif(
    subprocess.run(["which", "actionlint"], capture_output=True).returncode != 0,
    reason="actionlint not installed"
)
def test_actionlint_validation():
    """Test that workflow passes actionlint validation (if actionlint available)."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="actionlint-test",
            annotations={"description": "Test actionlint validation"},
            labels={},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
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

    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(schedule)

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(workflow_yaml)
        temp_file = Path(f.name)

    try:
        # Run actionlint
        result = subprocess.run(
            ["actionlint", str(temp_file)],
            capture_output=True,
            text=True,
            check=False,
        )

        # Should pass without errors
        assert result.returncode == 0, f"actionlint failed:\n{result.stdout}\n{result.stderr}"
    finally:
        temp_file.unlink()


def test_workflow_triggers_correctly():
    """Test that workflow has correct trigger configuration."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="trigger-test",
            annotations={"description": "Test workflow triggers"},
            labels={},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="*/15 * * * *",  # Every 15 minutes
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
            jobTemplate=JobTemplateSpec(
                profile="fast",
                targets={"repositories": {"repos_dir": "~/repos"}},
                options={},
                results={},
                notifications={"enabled": False},
            ),
        ),
        status={},
    )

    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(schedule)
    workflow = yaml.safe_load(workflow_yaml)

    # Validate schedule trigger
    assert workflow["on"]["schedule"] == [{"cron": "*/15 * * * *"}]

    # Validate manual trigger
    assert "workflow_dispatch" in workflow["on"]


def test_schedule_runs_at_correct_time():
    """Test that cron expression is correctly passed to GitHub Actions."""
    test_cases = [
        ("0 2 * * *", "Daily at 2 AM UTC"),
        ("0 */6 * * *", "Every 6 hours"),
        ("0 0 * * 0", "Weekly on Sunday"),
        ("0 0 1 * *", "Monthly on 1st"),
    ]

    for cron_expr, description in test_cases:
        schedule = ScanSchedule(
            metadata=ScheduleMetadata(
                name=f"schedule-{cron_expr.replace(' ', '-')}",
                labels={},
                annotations={"description": description},
                creationTimestamp="2025-10-31T00:00:00Z",
            ),
            spec=ScheduleSpec(
                schedule=cron_expr,
                timezone="UTC",
                suspend=False,
                backend=BackendConfig(type="github-actions"),
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

        generator = GitHubActionsGenerator()
        workflow_yaml = generator.generate(schedule)
        workflow = yaml.safe_load(workflow_yaml)

        # Verify cron expression matches
        assert workflow["on"]["schedule"] == [{"cron": cron_expr}]


def test_workflow_with_notifications():
    """Test workflow generation with Slack notifications."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="notification-test",
            annotations={"description": "Test with Slack notifications"},
            labels={},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
            jobTemplate=JobTemplateSpec(
                profile="balanced",
                targets={"repositories": {"repos_dir": "~/repos"}},
                options={},
                results={},
                notifications={
                    "enabled": True,
                    "channels": [
                        {
                            "type": "slack",
                            "url": "https://hooks.slack.com/...",
                            "events": ["failure", "success"],
                        }
                    ],
                },
            ),
        ),
        status={},
    )

    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(schedule)
    workflow = yaml.safe_load(workflow_yaml)

    # Verify notification steps present
    job = workflow["jobs"]["security-scan"]
    step_names = [s["name"] for s in job["steps"]]

    assert "Notify Slack on failure" in step_names
    assert "Notify Slack on success" in step_names

    # Verify Slack action used
    slack_steps = [s for s in job["steps"] if "Slack" in s["name"]]
    for step in slack_steps:
        assert step["uses"] == "slackapi/slack-github-action@v1"
        assert "webhook-url" in step["with"]
        assert "payload" in step["with"]
