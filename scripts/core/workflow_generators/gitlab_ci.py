"""Generate GitLab CI workflow files from ScanSchedule specs."""

from typing import Dict, Any, List
from scripts.core.schedule_manager import ScanSchedule


class GitLabCIGenerator:
    """Generate .gitlab-ci.yml from ScanSchedule."""

    def generate(self, schedule: ScanSchedule) -> str:
        """Generate complete GitLab CI workflow YAML.

        Args:
            schedule: ScanSchedule resource to convert

        Returns:
            Complete GitLab CI workflow YAML as string
        """
        workflow = {}

        # Add global variables if needed
        variables = self._generate_variables(schedule)
        if variables:
            workflow["variables"] = variables

        # Add security-scan job
        workflow["security-scan"] = self._generate_security_scan_job(schedule)

        # Add notification job if notifications enabled
        if schedule.spec.jobTemplate.notifications.get("enabled"):
            workflow.update(self._generate_notification_jobs(schedule))

        return self._to_yaml(schedule, workflow)

    def _generate_variables(self, schedule: ScanSchedule) -> Dict[str, str]:
        """Generate global variables.

        Args:
            schedule: ScanSchedule resource

        Returns:
            Dictionary of global variables
        """
        base_dir = schedule.spec.jobTemplate.results.get("base_dir", "./jmo-results")
        path_template = schedule.spec.jobTemplate.results.get(
            "path_template", "{schedule.name}/{date}/{time}"
        )

        # Expand path template using GitLab CI variables
        expanded_path = path_template.replace("{schedule.name}", schedule.metadata.name)
        expanded_path = expanded_path.replace("{date}", "${CI_PIPELINE_CREATED_AT}")
        expanded_path = expanded_path.replace("{time}", "${CI_PIPELINE_IID}")

        return {"RESULTS_DIR": f"{base_dir}/{expanded_path}"}

    def _generate_security_scan_job(self, schedule: ScanSchedule) -> Dict[str, Any]:
        """Generate security-scan job definition.

        Args:
            schedule: ScanSchedule resource

        Returns:
            GitLab CI job specification
        """
        job = {
            "image": "ghcr.io/jimmy058910/jmo-security:latest",
            "stage": "test",
            "timeout": self._format_timeout(schedule),
            "script": self._generate_script(schedule),
            "artifacts": self._generate_artifacts(schedule),
            "rules": self._generate_rules(schedule),
        }

        # Add allow_failure if allow_missing_tools is set
        if schedule.spec.jobTemplate.options.get("allow_missing_tools"):
            job["allow_failure"] = True

        return job

    def _format_timeout(self, schedule: ScanSchedule) -> str:
        """Format timeout for GitLab CI.

        Args:
            schedule: ScanSchedule resource

        Returns:
            Timeout string in GitLab CI format (e.g., "1h 30m")
        """
        # Use startingDeadlineSeconds if set, otherwise profile-based defaults
        if schedule.spec.startingDeadlineSeconds:
            minutes = schedule.spec.startingDeadlineSeconds // 60
        else:
            # Profile-based defaults
            profile_timeouts = {"fast": 10, "balanced": 30, "deep": 60}
            profile = schedule.spec.jobTemplate.profile
            minutes = profile_timeouts.get(profile, 30)

        # Convert to GitLab CI format (hours and minutes)
        if minutes >= 60:
            hours = minutes // 60
            remaining_minutes = minutes % 60
            if remaining_minutes > 0:
                return f"{hours}h {remaining_minutes}m"
            return f"{hours}h"
        return f"{minutes}m"

    def _generate_script(self, schedule: ScanSchedule) -> List[str]:
        """Generate script commands for security scan.

        Args:
            schedule: ScanSchedule resource

        Returns:
            List of shell commands
        """
        spec = schedule.spec.jobTemplate
        commands = []

        # Create results directory
        commands.append("mkdir -p ${RESULTS_DIR}")

        # Build jmo scan command
        cmd_parts = ["jmo scan"]
        cmd_parts.append(f"--profile {spec.profile}")

        # Targets
        targets = spec.targets
        if "repositories" in targets:
            repos = targets["repositories"]
            if "repos_dir" in repos:
                cmd_parts.append(f"--repos-dir {repos['repos_dir']}")
            if "include" in repos:
                for pattern in repos["include"]:
                    cmd_parts.append(f"--include-pattern '{pattern}'")
            if "exclude" in repos:
                for pattern in repos["exclude"]:
                    cmd_parts.append(f"--exclude-pattern '{pattern}'")

        if "images" in targets:
            for image in targets["images"]:
                cmd_parts.append(f"--image '{image}'")

        if "urls" in targets:
            for url in targets["urls"]:
                cmd_parts.append(f"--url '{url}'")

        # Results directory
        cmd_parts.append("--results-dir ${RESULTS_DIR}")

        # Options
        opts = spec.options
        if opts.get("allow_missing_tools"):
            cmd_parts.append("--allow-missing-tools")
        if "threads" in opts:
            cmd_parts.append(f"--threads {opts['threads']}")
        if "timeout" in opts:
            cmd_parts.append(f"--timeout {opts['timeout']}")
        if "fail_on" in opts:
            cmd_parts.append(f"--fail-on {opts['fail_on']}")

        cmd_parts.append("--human-logs")

        # Join command with line continuations for readability
        commands.append(" \\\n    ".join(cmd_parts))

        return commands

    def _generate_artifacts(self, schedule: ScanSchedule) -> Dict[str, Any]:
        """Generate artifacts configuration.

        Args:
            schedule: ScanSchedule resource

        Returns:
            GitLab CI artifacts specification
        """
        retention_days = schedule.spec.jobTemplate.results.get("retention_days", 90)

        artifacts = {
            "when": "always",
            "paths": ["${RESULTS_DIR}/summaries/"],
            "reports": {
                # GitLab accepts SARIF for SAST reports
                # JMo outputs findings.sarif which is SARIF 2.1.0 compliant
                "sast": "${RESULTS_DIR}/summaries/findings.sarif"
            },
            "expire_in": f"{retention_days} days",
        }

        return artifacts

    def _generate_rules(self, schedule: ScanSchedule) -> List[Dict[str, Any]]:
        """Generate job execution rules.

        Args:
            schedule: ScanSchedule resource

        Returns:
            List of GitLab CI rules
        """
        # Run on scheduled pipelines and manual triggers
        return [
            {"if": '$CI_PIPELINE_SOURCE == "schedule"'},
            {"if": '$CI_PIPELINE_SOURCE == "web"'},
        ]

    def _generate_notification_jobs(
        self, schedule: ScanSchedule
    ) -> Dict[str, Dict[str, Any]]:
        """Generate notification jobs (Slack, etc.).

        Args:
            schedule: ScanSchedule resource

        Returns:
            Dictionary of notification job definitions
        """
        jobs = {}
        channels = schedule.spec.jobTemplate.notifications.get("channels", [])

        for idx, channel in enumerate(channels):
            if channel["type"] == "slack":
                events = channel.get("events", [])

                # Slack failure notification
                if "failure" in events:
                    jobs[f"notify-slack-failure-{idx}"] = {
                        "stage": ".post",
                        "image": "curlimages/curl:latest",
                        "script": self._generate_slack_script(
                            schedule, channel, "failure"
                        ),
                        "rules": [
                            {
                                "if": '$CI_PIPELINE_SOURCE == "schedule"',
                                "when": "on_failure",
                            }
                        ],
                    }

                # Slack success notification
                if "success" in events:
                    jobs[f"notify-slack-success-{idx}"] = {
                        "stage": ".post",
                        "image": "curlimages/curl:latest",
                        "script": self._generate_slack_script(
                            schedule, channel, "success"
                        ),
                        "rules": [
                            {
                                "if": '$CI_PIPELINE_SOURCE == "schedule"',
                                "when": "on_success",
                            }
                        ],
                    }

        return jobs

    def _generate_slack_script(
        self, schedule: ScanSchedule, channel: Dict[str, Any], event: str
    ) -> List[str]:
        """Generate Slack notification script.

        Args:
            schedule: ScanSchedule resource
            channel: Slack channel configuration
            event: Event type (success/failure)

        Returns:
            List of shell commands for Slack notification
        """
        webhook_url = channel["url"]

        if event == "failure":
            emoji = "🚨"
            status = "Failed"
            color = "#dc3545"
        else:
            emoji = "✅"
            status = "Completed"
            color = "#28a745"

        # Build JSON payload
        payload = {
            "text": f"{emoji} JMo Security Scan {status}",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {
                            "title": "Schedule",
                            "value": schedule.metadata.name,
                            "short": True,
                        },
                        {
                            "title": "Pipeline",
                            "value": "${CI_PIPELINE_ID}",
                            "short": True,
                        },
                        {
                            "title": "Project",
                            "value": "${CI_PROJECT_PATH}",
                            "short": True,
                        },
                        {
                            "title": "Branch",
                            "value": "${CI_COMMIT_REF_NAME}",
                            "short": True,
                        },
                    ],
                    "actions": [
                        {
                            "type": "button",
                            "text": "View Pipeline",
                            "url": "${CI_PIPELINE_URL}",
                        }
                    ],
                }
            ],
        }

        # Convert to single-line JSON for curl
        import json

        payload_json = json.dumps(payload)

        return [
            f"curl -X POST '{webhook_url}' \\",
            "  -H 'Content-Type: application/json' \\",
            f"  -d '{payload_json}'",
        ]

    def _to_yaml(self, schedule: ScanSchedule, data: Dict) -> str:
        """Convert dict to properly formatted YAML string.

        Args:
            schedule: ScanSchedule resource (for metadata)
            data: Dictionary to convert

        Returns:
            YAML string with proper formatting for GitLab CI
        """
        import yaml
        from datetime import datetime

        # Use safe_dump with custom options for clean YAML
        yaml_str = yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
            indent=2,
        )

        # Add header comment with schedule information
        description = schedule.metadata.annotations.get("description", "")
        header_parts = [
            "# This file was generated by JMo Security Schedule Manager",
            f"# Schedule: {schedule.metadata.name}",
        ]
        if description:
            header_parts.append(f"# Description: {description}")
        header_parts.extend(
            [
                f"# Cron: {schedule.spec.schedule}",
                f"# Timezone: {schedule.spec.timezone}",
                f"# Profile: {schedule.spec.jobTemplate.profile}",
                f"# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "#",
                "# IMPORTANT: Configure schedule via GitLab UI:",
                "#   Settings > CI/CD > Schedules > New schedule",
            ]
        )
        if description:
            header_parts.append(f"#   - Description: {description}")
        header_parts.extend(
            [
                f"#   - Interval Pattern: {schedule.spec.schedule}",
                "#   - Target Branch: main (or your default branch)",
                f"#   - Timezone: {schedule.spec.timezone}",
                "#",
                "# DO NOT EDIT MANUALLY - Regenerate using:",
                f"#   jmo schedule export {schedule.metadata.name} > .gitlab-ci.yml",
                "#",
                "",
            ]
        )

        header = "\n".join(header_parts)

        return header + yaml_str
