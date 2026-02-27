"""GitHub Actions workflow generator for JMo Security scheduled scans.

Generates .github/workflows/*.yml files from ScanSchedule objects.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from scripts.core.schedule_manager import ScanSchedule


class GitHubActionsGenerator:
    """Generate GitHub Actions workflows from ScanSchedule."""

    def __init__(self):
        """Initialize the generator."""
        pass

    def generate(self, schedule: ScanSchedule) -> str:
        """Generate complete GitHub Actions workflow YAML.

        Args:
            schedule: ScanSchedule object to convert

        Returns:
            str: Complete YAML workflow content

        Example:
            >>> gen = GitHubActionsGenerator()
            >>> yaml_content = gen.generate(schedule)
            >>> with open('.github/workflows/jmo-nightly.yml', 'w') as f:
            ...     f.write(yaml_content)
        """
        workflow = {
            "name": self._workflow_name(schedule),
            "on": self._generate_triggers(schedule),
            "permissions": {
                "contents": "read",
                "security-events": "write",  # Required for SARIF upload
            },
            "jobs": {"security-scan": self._generate_job(schedule)},
        }

        return yaml.dump(workflow, sort_keys=False, default_flow_style=False)

    def _workflow_name(self, schedule: ScanSchedule) -> str:
        """Generate workflow name from schedule metadata.

        Args:
            schedule: ScanSchedule object

        Returns:
            str: Human-readable workflow name
        """
        return f"JMo Security Scan: {schedule.metadata.name}"

    def _generate_triggers(self, schedule: ScanSchedule) -> dict[str, Any]:
        """Generate workflow triggers (cron + manual dispatch).

        Args:
            schedule: ScanSchedule object

        Returns:
            dict: GitHub Actions trigger configuration
        """
        return {
            "schedule": [{"cron": schedule.spec.schedule}],
            "workflow_dispatch": {},  # Allow manual triggers
        }

    def _generate_job(self, schedule: ScanSchedule) -> dict[str, Any]:
        """Generate security-scan job definition.

        Args:
            schedule: ScanSchedule object

        Returns:
            dict: Complete job configuration
        """
        steps: list[dict[str, Any]] = [
            self._checkout_step(),
            self._scan_step(schedule),
            self._upload_results_step(schedule),
            self._upload_sarif_step(),
        ]

        # Add notification steps if enabled
        if schedule.spec.jobTemplate.notifications.get("enabled"):
            steps.extend(self._notification_steps(schedule))

        job = {"runs-on": "ubuntu-latest", "steps": steps}

        return job

    def _checkout_step(self) -> dict[str, Any]:
        """Generate repository checkout step.

        Returns:
            dict: Checkout step configuration
        """
        return {"name": "Checkout code", "uses": "actions/checkout@v4"}

    def _scan_step(self, schedule: ScanSchedule) -> dict[str, Any]:
        """Generate JMo scan step using Docker image.

        Args:
            schedule: ScanSchedule object

        Returns:
            dict: Scan step configuration with all target types
        """
        args = self._build_scan_args(schedule)

        return {
            "name": "Run JMo Security Scan",
            "run": f"docker run --rm -v $(pwd):/workspace ghcr.io/jimmy058910/jmo-security:latest {args}",
        }

    def _build_scan_args(self, schedule: ScanSchedule) -> str:
        """Build jmo scan command arguments.

        Supports all 6 target types:
        - Repositories (--repo, --repos-dir)
        - Container images (--image)
        - IaC files (--terraform-state, --cloudformation, --k8s-manifest)
        - Web URLs (--url, --api-spec)
        - GitLab repos (--gitlab-repo, --gitlab-group)
        - Kubernetes clusters (--k8s-context, --k8s-namespace)

        Args:
            schedule: ScanSchedule object

        Returns:
            str: Complete command line arguments
        """
        spec = schedule.spec.jobTemplate
        args = ["scan", "--profile", spec.profile]

        # Add targets based on type
        targets = spec.targets

        # 1. Repositories
        if "repositories" in targets:
            repos = targets["repositories"]
            if "repo" in repos:
                args.extend(["--repo", repos["repo"]])
            if "repos_dir" in repos:
                args.extend(["--repos-dir", repos["repos_dir"]])

        # 2. Container Images
        if "images" in targets:
            for image in targets["images"]:
                args.extend(["--image", image])

        # 3. IaC Files
        if "iac" in targets:
            iac = targets["iac"]
            if "terraform_state" in iac:
                args.extend(["--terraform-state", iac["terraform_state"]])
            if "cloudformation" in iac:
                args.extend(["--cloudformation", iac["cloudformation"]])
            if "k8s_manifest" in iac:
                args.extend(["--k8s-manifest", iac["k8s_manifest"]])

        # 4. Web URLs
        if "web" in targets:
            web = targets["web"]
            if "urls" in web:
                for url in web["urls"]:
                    args.extend(["--url", url])
            if "api_spec" in web:
                args.extend(["--api-spec", web["api_spec"]])

        # 5. GitLab Repos
        if "gitlab" in targets:
            gitlab = targets["gitlab"]
            if "repo" in gitlab:
                args.extend(["--gitlab-repo", gitlab["repo"]])
            if "group" in gitlab:
                args.extend(["--gitlab-group", gitlab["group"]])
            if "token" in gitlab:
                args.extend(["--gitlab-token", "${{ secrets.GITLAB_TOKEN }}"])

        # 6. Kubernetes Clusters
        if "kubernetes" in targets:
            k8s = targets["kubernetes"]
            if "context" in k8s:
                args.extend(["--k8s-context", k8s["context"]])
            if "namespace" in k8s:
                args.extend(["--k8s-namespace", k8s["namespace"]])
            elif k8s.get("all_namespaces"):
                args.append("--k8s-all-namespaces")

        # Add results directory
        args.extend(["--results-dir", "/workspace/results"])

        # Add options
        opts = spec.options
        if opts.get("allow_missing_tools"):
            args.append("--allow-missing-tools")
        if "threads" in opts:
            args.extend(["--threads", str(opts["threads"])])
        if "fail_on" in opts:
            args.extend(["--fail-on", opts["fail_on"]])

        # Human-readable logs for GitHub Actions
        args.append("--human-logs")

        return " ".join(args)

    def _upload_results_step(self, schedule: ScanSchedule) -> dict[str, Any]:
        """Generate artifact upload step.

        Args:
            schedule: ScanSchedule object

        Returns:
            dict: Upload artifact step configuration
        """
        retention_days = schedule.spec.jobTemplate.results.get("retention_days", 90)

        return {
            "name": "Upload scan results",
            "uses": "actions/upload-artifact@v4",
            "with": {
                "name": f"jmo-results-{schedule.metadata.name}-${{{{ github.run_number }}}}",
                "path": "results/summaries/",
                "retention-days": retention_days,
            },
            "if": "always()",
        }

    def _upload_sarif_step(self) -> dict[str, Any]:
        """Generate SARIF upload step for GitHub Security.

        Returns:
            dict: SARIF upload step configuration
        """
        return {
            "name": "Upload SARIF to GitHub Security",
            "uses": "github/codeql-action/upload-sarif@v3",
            "with": {"sarif_file": "results/summaries/findings.sarif"},
            "if": "always()",
        }

    def _notification_steps(self, schedule: ScanSchedule) -> list[dict[str, Any]]:
        """Generate Slack/email notification steps.

        Args:
            schedule: ScanSchedule object

        Returns:
            list: List of notification step configurations
        """
        steps = []
        channels = schedule.spec.jobTemplate.notifications.get("channels", [])

        for channel in channels:
            if channel["type"] == "slack":
                # Failure notification
                if "failure" in channel.get("events", []):
                    steps.append(
                        {
                            "name": "Notify Slack on failure",
                            "if": "failure()",
                            "uses": "slackapi/slack-github-action@v1",
                            "with": {
                                "webhook-url": "${{ secrets.SLACK_WEBHOOK_URL }}",
                                "payload": self._slack_payload(schedule, "failure"),
                            },
                        }
                    )

                # Success notification
                if "success" in channel.get("events", []):
                    steps.append(
                        {
                            "name": "Notify Slack on success",
                            "if": "success()",
                            "uses": "slackapi/slack-github-action@v1",
                            "with": {
                                "webhook-url": "${{ secrets.SLACK_WEBHOOK_URL }}",
                                "payload": self._slack_payload(schedule, "success"),
                            },
                        }
                    )

        return steps

    def _slack_payload(self, schedule: ScanSchedule, event_type: str) -> str:
        """Generate Slack notification payload.

        Args:
            schedule: ScanSchedule object
            event_type: "success" or "failure"

        Returns:
            str: JSON-encoded Slack payload
        """
        if event_type == "failure":
            emoji = "🚨"
            title = "JMo Security Scan Failed"
            message = f"Security scan *{schedule.metadata.name}* failed"
        else:
            emoji = "✅"
            title = "JMo Security Scan Completed"
            message = f"Security scan *{schedule.metadata.name}* completed successfully"

        payload = {
            "text": f"{emoji} {title}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{message}\nRun: <${{{{ github.server_url }}}}/${{{{ github.repository }}}}/actions/runs/${{{{ github.run_id }}}}|View Details>",
                    },
                }
            ],
        }

        return json.dumps(payload)
