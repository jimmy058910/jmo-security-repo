"""Generate GitLab CI workflow files from ScanSchedule specs."""

from __future__ import annotations

import logging
import shlex
from datetime import UTC
from typing import Any

from scripts.core.schedule_manager import ScanSchedule

logger = logging.getLogger(__name__)

# Top-level `targets` keys this generator knows how to put on a command line.
# Anything outside this set is warned about rather than dropped in silence --
# the point of #928 was never that GitLab supported less, it was that it said
# nothing while doing so.
_HANDLED_TARGET_KEYS = frozenset(
    {"repositories", "images", "iac", "web", "gitlab", "kubernetes", "urls"}
)

# Keys that are real features with no `jmo scan` flag to carry them.
#
# `repositories.include` / `exclude` reach a scan through `jmo.yml`'s `include:`
# / `exclude:` (read at jmo.py's ScanConfig construction as `eff.get("include")`
# / `eff.get("exclude")`), not through the command line -- `jmo scan` defines no
# `--include-pattern` or `--exclude-pattern`. This generator emitted both
# anyway, so the one target key it handled and its peers did not produced a
# command that exits 2. Naming them here keeps the warning specific enough to
# be actionable instead of "unsupported key".
_CONFIG_ONLY_REPOSITORY_KEYS = {
    "include": "include",
    "exclude": "exclude",
}


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

    def _generate_variables(self, schedule: ScanSchedule) -> dict[str, str]:
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

    def _generate_security_scan_job(self, schedule: ScanSchedule) -> dict[str, Any]:
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
            job["allow_failure"] = True  # type: ignore[assignment]  # GitLab CI YAML expects bool for allow_failure

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

    def _generate_script(self, schedule: ScanSchedule) -> list[str]:
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
        cmd_parts.append(f"--profile {shlex.quote(spec.profile)}")

        # Targets
        #
        # All six documented target types, mirroring
        # `github_actions.py::_build_scan_args` and `cron_installer.py`. This
        # generator handled three of them -- repositories, images and
        # web.urls -- so an IaC, GitLab or Kubernetes target exported correctly
        # to GitHub Actions and to local cron, and exported to GitLab CI with
        # the target missing from the command line: valid YAML, rc 0, no
        # warning (#928). `web.api_spec` was a fourth casualty the issue did
        # not name; both peers emit it.
        targets = spec.targets
        name = schedule.metadata.name

        unhandled = sorted(set(targets) - _HANDLED_TARGET_KEYS)
        if unhandled:
            logger.warning(
                "%s: GitLab CI export ignores target key(s) %s -- the generated "
                "`jmo scan` command will not include them.",
                name,
                ", ".join(unhandled),
            )

        # 1. Repositories
        if "repositories" in targets:
            repos = targets["repositories"]
            if "repo" in repos:
                cmd_parts.append(f"--repo {shlex.quote(repos['repo'])}")
            if "repos_dir" in repos:
                cmd_parts.append(f"--repos-dir {shlex.quote(repos['repos_dir'])}")
            for key, config_key in _CONFIG_ONLY_REPOSITORY_KEYS.items():
                if repos.get(key):
                    logger.warning(
                        "%s: repositories.%s cannot be expressed on the "
                        "`jmo scan` command line; set `%s:` in jmo.yml instead. "
                        "(This generator used to emit --%s-pattern, which "
                        "`jmo scan` does not define -- the exported command "
                        "exited 2.)",
                        name,
                        key,
                        config_key,
                        key,
                    )

        # 2. Container images
        if "images" in targets:
            for image in targets["images"]:
                cmd_parts.append(f"--image {shlex.quote(image)}")

        # 3. IaC files
        if "iac" in targets:
            iac = targets["iac"]
            if "terraform_state" in iac:
                cmd_parts.append(
                    f"--terraform-state {shlex.quote(iac['terraform_state'])}"
                )
            if "cloudformation" in iac:
                cmd_parts.append(
                    f"--cloudformation {shlex.quote(iac['cloudformation'])}"
                )
            if "k8s_manifest" in iac:
                cmd_parts.append(f"--k8s-manifest {shlex.quote(iac['k8s_manifest'])}")

        # 4. Web URLs and API specs
        #
        # Web URLs live under targets["web"]["urls"] -- that is what the CLI
        # writes and what the GitHub Actions generator and the cron installer
        # both read. This generator read a flat targets["urls"] that nothing
        # produces, so `jmo schedule create --url ...` exported correctly to
        # GitHub Actions and dropped the URL entirely on GitLab, silently and
        # at rc 0. The flat form is still accepted for any schedule written
        # before this fix.
        web = targets.get("web", {})
        urls = web.get("urls", []) or targets.get("urls", [])
        for url in urls:
            cmd_parts.append(f"--url {shlex.quote(url)}")
        if "api_spec" in web:
            cmd_parts.append(f"--api-spec {shlex.quote(web['api_spec'])}")

        # 5. GitLab repos
        #
        # The token is passed as a CI variable reference, not a literal, so the
        # rendered .gitlab-ci.yml never carries a secret. `$GITLAB_TOKEN` is a
        # masked project variable in GitLab's own model, matching what the
        # GitHub generator does with `${{ secrets.GITLAB_TOKEN }}`.
        if "gitlab" in targets:
            gitlab = targets["gitlab"]
            if "repo" in gitlab:
                cmd_parts.append(f"--gitlab-repo {shlex.quote(gitlab['repo'])}")
            if "group" in gitlab:
                cmd_parts.append(f"--gitlab-group {shlex.quote(gitlab['group'])}")
            if "token" in gitlab:
                cmd_parts.append("--gitlab-token ${GITLAB_TOKEN}")

        # 6. Kubernetes clusters
        if "kubernetes" in targets:
            k8s = targets["kubernetes"]
            if "context" in k8s:
                cmd_parts.append(f"--k8s-context {shlex.quote(k8s['context'])}")
            if "namespace" in k8s:
                cmd_parts.append(f"--k8s-namespace {shlex.quote(k8s['namespace'])}")
            elif k8s.get("all_namespaces"):
                cmd_parts.append("--k8s-all-namespaces")

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

    def _generate_artifacts(self, schedule: ScanSchedule) -> dict[str, Any]:
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

    def _generate_rules(self, schedule: ScanSchedule) -> list[dict[str, Any]]:
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
    ) -> dict[str, dict[str, Any]]:
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
        self, schedule: ScanSchedule, channel: dict[str, Any], event: str
    ) -> list[str]:
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

    def _to_yaml(self, schedule: ScanSchedule, data: dict) -> str:
        """Convert dict to properly formatted YAML string.

        Args:
            schedule: ScanSchedule resource (for metadata)
            data: Dictionary to convert

        Returns:
            YAML string with proper formatting for GitLab CI
        """
        from datetime import datetime

        import yaml

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
                f"# Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
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
