"""Unit tests for GitHub Actions workflow generator.

Tests cover:
- Basic workflow generation
- Multi-target support (all 6 target types)
- Notification steps (Slack)
- SARIF upload step
- Artifact upload step
- Cron triggers
- YAML formatting
- Actionlint validation (if actionlint available)
"""

import pytest
import yaml

from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    BackendConfig,
    JobTemplateSpec,
)
from scripts.core.workflow_generators.github_actions import GitHubActionsGenerator


@pytest.fixture
def basic_schedule():
    """Create a basic schedule for testing."""
    return ScanSchedule(
        metadata=ScheduleMetadata(
            name="nightly-scan",
            labels={},
            annotations={"description": "Nightly security scan"},
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


def test_basic_workflow_generation(basic_schedule):
    """Test basic workflow generation with minimal configuration."""
    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(basic_schedule)

    # Parse YAML
    workflow = yaml.safe_load(workflow_yaml)

    # Verify structure
    assert workflow["name"] == "JMo Security Scan: nightly-scan"
    assert "on" in workflow
    assert workflow["on"]["schedule"] == [{"cron": "0 2 * * *"}]
    assert "workflow_dispatch" in workflow["on"]
    assert "permissions" in workflow
    assert workflow["permissions"]["contents"] == "read"
    assert workflow["permissions"]["security-events"] == "write"
    assert "jobs" in workflow
    assert "security-scan" in workflow["jobs"]


def test_multi_target_support():
    """Test workflow generation with all 6 target types."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="comprehensive-scan",
            labels={},
            annotations={"description": "Scan all target types"},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 3 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
            jobTemplate=JobTemplateSpec(
                profile="deep",
                targets={
                    "repositories": {"repos_dir": "~/repos"},
                    "images": ["nginx:latest", "postgres:15"],
                    "iac": {"terraform_state": "terraform.tfstate"},
                    "web": {"urls": ["https://example.com"]},
                    "gitlab": {"repo": "mygroup/myrepo", "token": "secret"},
                    "kubernetes": {"context": "prod", "namespace": "default"},
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
    workflow = yaml.safe_load(workflow_yaml)

    # Extract scan command from run step
    job = workflow["jobs"]["security-scan"]
    scan_step = [s for s in job["steps"] if "Run JMo Security Scan" in s["name"]][0]
    scan_cmd = scan_step["run"]

    # Verify all target types present
    assert "--repos-dir ~/repos" in scan_cmd
    assert "--image nginx:latest" in scan_cmd
    assert "--image postgres:15" in scan_cmd
    assert "--terraform-state terraform.tfstate" in scan_cmd
    assert "--url https://example.com" in scan_cmd
    assert "--gitlab-repo mygroup/myrepo" in scan_cmd
    assert "--gitlab-token" in scan_cmd
    assert "--k8s-context prod" in scan_cmd
    assert "--k8s-namespace default" in scan_cmd
    assert "--profile deep" in scan_cmd


def test_notification_steps():
    """Test Slack notification steps generation."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="notify-scan",
            labels={},
            annotations={"description": "Scan with Slack notifications"},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 4 * * *",
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

    # Check notification steps present
    job = workflow["jobs"]["security-scan"]
    step_names = [s["name"] for s in job["steps"]]

    assert "Notify Slack on failure" in step_names
    assert "Notify Slack on success" in step_names

    # Verify failure step uses failure() condition
    failure_step = [s for s in job["steps"] if s["name"] == "Notify Slack on failure"][
        0
    ]
    assert failure_step["if"] == "failure()"
    assert failure_step["uses"] == "slackapi/slack-github-action@v1"

    # Verify success step uses success() condition
    success_step = [s for s in job["steps"] if s["name"] == "Notify Slack on success"][
        0
    ]
    assert success_step["if"] == "success()"


def test_sarif_upload_step(basic_schedule):
    """Test SARIF upload step for GitHub Security."""
    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(basic_schedule)
    workflow = yaml.safe_load(workflow_yaml)

    # Verify SARIF upload step
    job = workflow["jobs"]["security-scan"]
    sarif_step = [s for s in job["steps"] if "Upload SARIF" in s["name"]][0]

    assert sarif_step["uses"] == "github/codeql-action/upload-sarif@v3"
    assert sarif_step["with"]["sarif_file"] == "results/summaries/findings.sarif"
    assert sarif_step["if"] == "always()"


def test_artifact_upload_step():
    """Test artifact upload step with retention policy."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="artifact-scan",
            labels={},
            annotations={"description": "Scan with artifact upload"},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 6 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="github-actions"),
            jobTemplate=JobTemplateSpec(
                profile="balanced",
                targets={"repositories": {"repos_dir": "~/repos"}},
                options={},
                results={"retention_days": 30},
                notifications={"enabled": False},
            ),
        ),
        status={},
    )

    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(schedule)
    workflow = yaml.safe_load(workflow_yaml)

    # Verify artifact upload step
    job = workflow["jobs"]["security-scan"]
    artifact_step = [s for s in job["steps"] if "Upload scan results" in s["name"]][0]

    assert artifact_step["uses"] == "actions/upload-artifact@v4"
    assert "artifact-scan" in artifact_step["with"]["name"]
    assert artifact_step["with"]["path"] == "results/summaries/"
    assert artifact_step["with"]["retention-days"] == 30
    assert artifact_step["if"] == "always()"


def test_cron_trigger():
    """Test cron trigger and manual workflow_dispatch."""
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name="cron-test",
            labels={},
            annotations={"description": "Test cron trigger"},
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

    # Verify triggers
    assert workflow["on"]["schedule"] == [{"cron": "*/15 * * * *"}]
    assert "workflow_dispatch" in workflow["on"]


def test_yaml_formatting(basic_schedule):
    """Test that generated YAML is valid and well-formatted."""
    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(basic_schedule)

    # Parse and re-serialize to verify validity
    workflow = yaml.safe_load(workflow_yaml)
    _ = yaml.dump(workflow)  # Verify it can be re-serialized

    assert workflow is not None
    assert isinstance(workflow, dict)
    assert "name" in workflow
    assert "jobs" in workflow


@pytest.mark.skipif(True, reason="Requires actionlint installed")
def test_actionlint_validation(basic_schedule):
    """Test that workflow passes actionlint validation.

    This test requires actionlint to be installed.
    Skip by default since it's an external dependency.
    """
    import subprocess
    import tempfile
    from pathlib import Path

    generator = GitHubActionsGenerator()
    workflow_yaml = generator.generate(basic_schedule)

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
        assert (
            result.returncode == 0
        ), f"actionlint failed: {result.stdout}\n{result.stderr}"
    finally:
        temp_file.unlink()
