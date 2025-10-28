"""Integration tests for GitLab CI workflow generation."""

import os
import sys
import pytest
import yaml
from scripts.core.schedule_manager import (
    ScheduleManager,
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    JobTemplateSpec,
)
from scripts.core.workflow_generators.gitlab_ci import GitLabCIGenerator


@pytest.mark.skipif(
    os.getenv("CI") == "true" and sys.version_info[:2] in [(3, 10), (3, 12)],
    reason="Intermittent timeout on Ubuntu CI with Python 3.10/3.12 (passes locally)",
)
def test_end_to_end_gitlab_ci_generation(tmp_path):
    """Test complete workflow: create schedule -> generate GitLab CI -> validate YAML."""
    # Step 1: Create schedule using ScheduleManager
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")

    metadata = ScheduleMetadata(
        name="nightly-security-scan",
        labels={"env": "production", "team": "security"},
        annotations={"description": "Nightly comprehensive security audit"},
    )

    spec = ScheduleSpec(
        schedule="0 2 * * *",
        timezone="UTC",
        startingDeadlineSeconds=3600,
        jobTemplate=JobTemplateSpec(
            profile="deep",
            targets={
                "repositories": {
                    "repos_dir": ".",
                    "include": ["src/**"],
                    "exclude": ["node_modules/**"],
                },
                "images": ["myapp:latest"],
                "urls": ["https://api.myapp.com"],
            },
            results={
                "base_dir": "./jmo-results",
                "path_template": "{schedule.name}/{date}/{time}",
                "retention_days": 90,
            },
            options={"allow_missing_tools": True, "threads": 4, "fail_on": "HIGH"},
            notifications={
                "enabled": True,
                "channels": [
                    {
                        "type": "slack",
                        "url": "${SLACK_WEBHOOK_URL}",
                        "events": ["failure", "success"],
                    }
                ],
            },
        ),
    )

    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created_schedule = manager.create(schedule)

    # Verify schedule was created
    assert created_schedule.metadata.uid is not None
    assert created_schedule.status.nextScheduleTime is not None

    # Step 2: Generate GitLab CI workflow
    generator = GitLabCIGenerator()
    workflow_yaml = generator.generate(created_schedule)

    # Step 3: Parse and validate generated YAML
    workflow = yaml.safe_load(workflow_yaml)

    # Validate global variables
    assert "variables" in workflow
    assert "RESULTS_DIR" in workflow["variables"]
    assert "nightly-security-scan" in workflow["variables"]["RESULTS_DIR"]

    # Validate security-scan job
    assert "security-scan" in workflow
    job = workflow["security-scan"]
    assert job["image"] == "ghcr.io/jimmy058910/jmo-security:latest"
    assert job["stage"] == "test"
    assert job["timeout"] == "1h"  # 3600 seconds / 60 = 60 minutes = 1h
    assert job["allow_failure"] is True  # allow_missing_tools

    # Validate script commands
    script = job["script"]
    assert isinstance(script, list)
    assert "mkdir -p ${RESULTS_DIR}" in script
    scan_cmd = " ".join(script)
    assert "--profile deep" in scan_cmd
    assert "--repos-dir ." in scan_cmd
    assert "--include-pattern 'src/**'" in scan_cmd
    assert "--exclude-pattern 'node_modules/**'" in scan_cmd
    assert "--image 'myapp:latest'" in scan_cmd
    assert "--url 'https://api.myapp.com'" in scan_cmd
    assert "--fail-on HIGH" in scan_cmd
    assert "--threads 4" in scan_cmd
    assert "--allow-missing-tools" in scan_cmd

    # Validate artifacts configuration
    artifacts = job["artifacts"]
    assert artifacts["when"] == "always"
    assert "${RESULTS_DIR}/summaries/" in artifacts["paths"]
    assert artifacts["reports"]["sast"] == "${RESULTS_DIR}/summaries/findings.sarif"
    assert artifacts["expire_in"] == "90 days"

    # Validate rules
    rules = job["rules"]
    assert len(rules) == 2
    assert rules[0]["if"] == '$CI_PIPELINE_SOURCE == "schedule"'
    assert rules[1]["if"] == '$CI_PIPELINE_SOURCE == "web"'

    # Validate notification jobs
    assert "notify-slack-failure-0" in workflow
    assert "notify-slack-success-0" in workflow

    failure_job = workflow["notify-slack-failure-0"]
    assert failure_job["stage"] == ".post"
    assert failure_job["image"] == "curlimages/curl:latest"
    assert failure_job["rules"][0]["when"] == "on_failure"

    success_job = workflow["notify-slack-success-0"]
    assert success_job["rules"][0]["when"] == "on_success"

    # Step 4: Verify workflow can be written to file
    workflow_file = tmp_path / ".gitlab-ci.yml"
    workflow_file.write_text(workflow_yaml, encoding="utf-8")

    # Verify file is valid YAML
    with open(workflow_file, encoding="utf-8") as f:
        reloaded = yaml.safe_load(f)
    assert reloaded["security-scan"]["image"] == job["image"]


def test_minimal_gitlab_ci_generation(tmp_path):
    """Test GitLab CI generation with minimal configuration."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")

    metadata = ScheduleMetadata(name="minimal-scan")
    spec = ScheduleSpec(
        schedule="0 3 * * *",
        timezone="America/New_York",
        jobTemplate=JobTemplateSpec(
            profile="fast",
            targets={"repositories": {"repos_dir": "."}},
            results={},
            options={},
            notifications={"enabled": False},
        ),
    )

    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created_schedule = manager.create(schedule)

    # Generate workflow
    generator = GitLabCIGenerator()
    workflow_yaml = generator.generate(created_schedule)
    workflow = yaml.safe_load(workflow_yaml)

    # Verify minimal configuration works
    job = workflow["security-scan"]
    assert job["timeout"] == "10m"  # fast profile
    assert "allow_failure" not in job  # not set when allow_missing_tools is False

    # Verify no threshold check logic needed (GitLab fails on exit code)
    script = " ".join(job["script"])
    assert "--fail-on" not in script

    # Verify no notification jobs
    assert "notify-slack-failure-0" not in workflow
    assert "notify-slack-success-0" not in workflow

    # Verify timezone is in header comment
    assert "America/New_York" in workflow_yaml


def test_gitlab_ci_with_all_target_types(tmp_path):
    """Test GitLab CI generation with all target types configured."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")

    metadata = ScheduleMetadata(name="comprehensive-scan")
    spec = ScheduleSpec(
        schedule="0 1 * * 0",  # Weekly Sunday 1 AM
        timezone="UTC",
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={
                "repositories": {
                    "repos_dir": "./repos",
                    "include": ["app-*", "service-*"],
                    "exclude": ["*-deprecated"],
                },
                "images": ["nginx:latest", "postgres:16-alpine", "redis:7-alpine"],
                "urls": [
                    "https://api.example.com",
                    "https://app.example.com",
                    "https://admin.example.com",
                ],
            },
            results={"base_dir": "./results", "retention_days": 60},
            options={"threads": 8, "timeout": 600, "allow_missing_tools": True},
            notifications={"enabled": False},
        ),
    )

    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created_schedule = manager.create(schedule)

    # Generate workflow
    generator = GitLabCIGenerator()
    workflow_yaml = generator.generate(created_schedule)
    workflow = yaml.safe_load(workflow_yaml)

    # Verify all target types are in the scan command
    script = " ".join(workflow["security-scan"]["script"])

    # Repository targets
    assert "--repos-dir ./repos" in script
    assert "--include-pattern 'app-*'" in script
    assert "--include-pattern 'service-*'" in script
    assert "--exclude-pattern '*-deprecated'" in script

    # Image targets
    assert "--image 'nginx:latest'" in script
    assert "--image 'postgres:16-alpine'" in script
    assert "--image 'redis:7-alpine'" in script

    # URL targets
    assert "--url 'https://api.example.com'" in script
    assert "--url 'https://app.example.com'" in script
    assert "--url 'https://admin.example.com'" in script

    # Options
    assert "--threads 8" in script
    assert "--timeout 600" in script
    assert "--allow-missing-tools" in script


def test_gitlab_ci_artifact_retention(tmp_path):
    """Test artifact retention days configuration."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")

    # Test default retention (90 days)
    metadata = ScheduleMetadata(name="default-retention")
    spec = ScheduleSpec(
        schedule="0 2 * * *",
        timezone="UTC",
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={"repositories": {"repos_dir": "."}},
            results={},  # No retention_days specified
            options={},
            notifications={"enabled": False},
        ),
    )
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)

    generator = GitLabCIGenerator()
    workflow = yaml.safe_load(generator.generate(created))
    assert workflow["security-scan"]["artifacts"]["expire_in"] == "90 days"

    # Test custom retention
    metadata.name = "custom-retention"
    spec.jobTemplate.results = {"retention_days": 30}
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)

    workflow = yaml.safe_load(generator.generate(created))
    assert workflow["security-scan"]["artifacts"]["expire_in"] == "30 days"


def test_gitlab_ci_timeout_formats(tmp_path):
    """Test timeout formatting for different durations."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")
    generator = GitLabCIGenerator()

    # Test timeout < 60 minutes (format: "30m")
    metadata = ScheduleMetadata(name="short-timeout")
    spec = ScheduleSpec(
        schedule="0 2 * * *",
        timezone="UTC",
        startingDeadlineSeconds=1800,  # 30 minutes
        jobTemplate=JobTemplateSpec(
            profile="fast",
            targets={"repositories": {"repos_dir": "."}},
            results={},
            options={},
            notifications={"enabled": False},
        ),
    )
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))
    assert workflow["security-scan"]["timeout"] == "30m"

    # Test timeout = 60 minutes (format: "1h")
    metadata.name = "one-hour"
    spec.startingDeadlineSeconds = 3600
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))
    assert workflow["security-scan"]["timeout"] == "1h"

    # Test timeout with hours and minutes (format: "2h 30m")
    metadata.name = "mixed-timeout"
    spec.startingDeadlineSeconds = 9000  # 150 minutes = 2h 30m
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))
    assert workflow["security-scan"]["timeout"] == "2h 30m"

    # Test profile-based defaults
    metadata.name = "profile-default"
    spec.startingDeadlineSeconds = None
    spec.jobTemplate.profile = "deep"
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))
    assert workflow["security-scan"]["timeout"] == "1h"  # deep = 60 minutes


def test_gitlab_ci_notification_events(tmp_path):
    """Test notification job generation for different event types."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")
    generator = GitLabCIGenerator()

    # Test failure-only notification
    metadata = ScheduleMetadata(name="failure-only")
    spec = ScheduleSpec(
        schedule="0 2 * * *",
        timezone="UTC",
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={"repositories": {"repos_dir": "."}},
            results={},
            options={},
            notifications={
                "enabled": True,
                "channels": [
                    {
                        "type": "slack",
                        "url": "https://hooks.slack.com/services/FAILURE",
                        "events": ["failure"],
                    }
                ],
            },
        ),
    )
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))

    assert "notify-slack-failure-0" in workflow
    assert "notify-slack-success-0" not in workflow

    # Test success-only notification
    metadata.name = "success-only"
    spec.jobTemplate.notifications["channels"][0]["events"] = ["success"]
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))

    assert "notify-slack-failure-0" not in workflow
    assert "notify-slack-success-0" in workflow

    # Test multiple channels
    metadata.name = "multi-channel"
    spec.jobTemplate.notifications["channels"] = [
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/CHANNEL1",
            "events": ["failure"],
        },
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/CHANNEL2",
            "events": ["success"],
        },
    ]
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)
    workflow = yaml.safe_load(generator.generate(created))

    assert "notify-slack-failure-0" in workflow
    assert "notify-slack-success-1" in workflow


def test_gitlab_ci_header_comments(tmp_path):
    """Test that generated YAML includes helpful header comments."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")
    generator = GitLabCIGenerator()

    metadata = ScheduleMetadata(
        name="test-schedule", annotations={"description": "Test security scan"}
    )
    spec = ScheduleSpec(
        schedule="0 2 * * *",
        timezone="America/Los_Angeles",
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={"repositories": {"repos_dir": "."}},
            results={},
            options={},
            notifications={"enabled": False},
        ),
    )
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)

    workflow_yaml = generator.generate(created)

    # Verify header comments
    assert "# This file was generated by JMo Security Schedule Manager" in workflow_yaml
    assert "# Schedule: test-schedule" in workflow_yaml
    assert "# Cron: 0 2 * * *" in workflow_yaml
    assert "# Profile: balanced" in workflow_yaml
    assert "# Timezone: America/Los_Angeles" in workflow_yaml
    assert "# Description: Test security scan" in workflow_yaml
    assert "jmo schedule export test-schedule" in workflow_yaml
    assert "Settings > CI/CD > Schedules" in workflow_yaml


def test_gitlab_ci_rules_configuration(tmp_path):
    """Test that GitLab CI rules allow both scheduled and manual triggers."""
    manager = ScheduleManager(config_dir=tmp_path / ".jmo")
    generator = GitLabCIGenerator()

    metadata = ScheduleMetadata(name="test-rules")
    spec = ScheduleSpec(
        schedule="0 2 * * *",
        timezone="UTC",
        jobTemplate=JobTemplateSpec(
            profile="fast",
            targets={"repositories": {"repos_dir": "."}},
            results={},
            options={},
            notifications={"enabled": False},
        ),
    )
    schedule = ScanSchedule(metadata=metadata, spec=spec)
    created = manager.create(schedule)

    workflow = yaml.safe_load(generator.generate(created))
    rules = workflow["security-scan"]["rules"]

    # Verify rules allow both scheduled and manual (web) pipelines
    assert len(rules) == 2
    assert any(r["if"] == '$CI_PIPELINE_SOURCE == "schedule"' for r in rules)
    assert any(r["if"] == '$CI_PIPELINE_SOURCE == "web"' for r in rules)
