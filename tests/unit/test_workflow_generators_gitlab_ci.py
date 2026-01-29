"""Unit tests for GitLab CI workflow generator edge cases.

These tests cover branch partials not exercised by integration tests.
"""

import yaml
from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    JobTemplateSpec,
)
from scripts.core.workflow_generators.gitlab_ci import GitLabCIGenerator


class TestGitLabCIGeneratorBranchCoverage:
    """Tests for branch partials in gitlab_ci.py."""

    def test_generate_script_no_repositories_target(self):
        """Test _generate_script when repositories target is absent (line 130->141)."""
        generator = GitLabCIGenerator()

        metadata = ScheduleMetadata(name="images-only")
        spec = ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            jobTemplate=JobTemplateSpec(
                profile="fast",
                targets={
                    # No repositories - just images
                    "images": ["nginx:latest"],
                },
                results={},
                options={},
                notifications={"enabled": False},
            ),
        )
        schedule = ScanSchedule(metadata=metadata, spec=spec)

        workflow_yaml = generator.generate(schedule)
        workflow = yaml.safe_load(workflow_yaml)

        script = " ".join(workflow["security-scan"]["script"])

        # Should not have repos-dir since no repositories target
        assert "--repos-dir" not in script
        # Should have image target
        assert "--image 'nginx:latest'" in script

    def test_generate_script_repositories_without_repos_dir(self):
        """Test _generate_script when repos dict has no repos_dir (line 132->134)."""
        generator = GitLabCIGenerator()

        metadata = ScheduleMetadata(name="patterns-only")
        spec = ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            jobTemplate=JobTemplateSpec(
                profile="fast",
                targets={
                    "repositories": {
                        # No repos_dir - just include/exclude patterns
                        "include": ["src/**"],
                        "exclude": ["test/**"],
                    },
                },
                results={},
                options={},
                notifications={"enabled": False},
            ),
        )
        schedule = ScanSchedule(metadata=metadata, spec=spec)

        workflow_yaml = generator.generate(schedule)
        workflow = yaml.safe_load(workflow_yaml)

        script = " ".join(workflow["security-scan"]["script"])

        # Should not have repos-dir
        assert "--repos-dir" not in script
        # Should have include/exclude patterns
        assert "--include-pattern 'src/**'" in script
        assert "--exclude-pattern 'test/**'" in script

    def test_generate_notification_jobs_empty_channels(self):
        """Test _generate_notification_jobs with empty channels list (line 224->223)."""
        generator = GitLabCIGenerator()

        metadata = ScheduleMetadata(name="empty-channels")
        spec = ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            jobTemplate=JobTemplateSpec(
                profile="fast",
                targets={"repositories": {"repos_dir": "."}},
                results={},
                options={},
                notifications={
                    "enabled": True,
                    "channels": [],  # Empty channels list
                },
            ),
        )
        schedule = ScanSchedule(metadata=metadata, spec=spec)

        workflow_yaml = generator.generate(schedule)
        workflow = yaml.safe_load(workflow_yaml)

        # Should only have security-scan and variables, no notification jobs
        assert "security-scan" in workflow
        assert "variables" in workflow
        # No notify- jobs
        notify_jobs = [k for k in workflow.keys() if k.startswith("notify-")]
        assert len(notify_jobs) == 0

    def test_generate_script_urls_only_no_repos_no_images(self):
        """Test _generate_script with only URL targets."""
        generator = GitLabCIGenerator()

        metadata = ScheduleMetadata(name="urls-only")
        spec = ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            jobTemplate=JobTemplateSpec(
                profile="fast",
                targets={
                    "urls": ["https://api.example.com"],
                },
                results={},
                options={},
                notifications={"enabled": False},
            ),
        )
        schedule = ScanSchedule(metadata=metadata, spec=spec)

        workflow_yaml = generator.generate(schedule)
        workflow = yaml.safe_load(workflow_yaml)

        script = " ".join(workflow["security-scan"]["script"])

        # No repos-dir or image
        assert "--repos-dir" not in script
        assert "--image" not in script
        # Only URL
        assert "--url 'https://api.example.com'" in script

    def test_format_timeout_unknown_profile_uses_default(self):
        """Test _format_timeout with unknown profile falls back to 30 minutes."""
        generator = GitLabCIGenerator()

        metadata = ScheduleMetadata(name="unknown-profile")
        spec = ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            startingDeadlineSeconds=None,  # No explicit timeout
            jobTemplate=JobTemplateSpec(
                profile="custom-unknown",  # Unknown profile
                targets={"repositories": {"repos_dir": "."}},
                results={},
                options={},
                notifications={"enabled": False},
            ),
        )
        schedule = ScanSchedule(metadata=metadata, spec=spec)

        workflow_yaml = generator.generate(schedule)
        workflow = yaml.safe_load(workflow_yaml)

        # Unknown profile should use default 30 minutes
        assert workflow["security-scan"]["timeout"] == "30m"

    def test_to_yaml_no_description_annotation(self):
        """Test _to_yaml when no description annotation is present."""
        generator = GitLabCIGenerator()

        metadata = ScheduleMetadata(
            name="no-description",
            annotations={},  # No description
        )
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

        workflow_yaml = generator.generate(schedule)

        # Should not have "Description:" in header when annotation is missing
        lines = workflow_yaml.split("\n")
        description_lines = [l for l in lines if "Description:" in l]
        assert len(description_lines) == 0
