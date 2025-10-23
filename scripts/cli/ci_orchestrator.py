#!/usr/bin/env python3
"""CI orchestration logic for JMo Security."""

from __future__ import annotations

from pathlib import Path


def cmd_ci(args, cmd_scan_fn, cmd_report_fn) -> int:
    """Run CI command: scan + report in one step.

    Args:
        args: Parsed CLI arguments
        cmd_scan_fn: Function to run scan command (args) -> int
        cmd_report_fn: Function to run report command (args, _log_fn) -> int

    Returns:
        Exit code from report command (respects --fail-on threshold)
    """

    class ScanArgs:
        """Arguments adapter for scan command."""

        def __init__(self, a):
            self.repo = getattr(a, "repo", None)
            self.repos_dir = getattr(a, "repos_dir", None)
            self.targets = getattr(a, "targets", None)
            # Container image scanning
            self.image = getattr(a, "image", None)
            self.images_file = getattr(a, "images_file", None)
            # IaC scanning
            self.terraform_state = getattr(a, "terraform_state", None)
            self.cloudformation = getattr(a, "cloudformation", None)
            self.k8s_manifest = getattr(a, "k8s_manifest", None)
            # Web app/API scanning
            self.url = getattr(a, "url", None)
            self.urls_file = getattr(a, "urls_file", None)
            self.api_spec = getattr(a, "api_spec", None)
            # GitLab integration
            self.gitlab_url = getattr(a, "gitlab_url", None)
            self.gitlab_token = getattr(a, "gitlab_token", None)
            self.gitlab_group = getattr(a, "gitlab_group", None)
            self.gitlab_repo = getattr(a, "gitlab_repo", None)
            # Kubernetes cluster scanning
            self.k8s_context = getattr(a, "k8s_context", None)
            self.k8s_namespace = getattr(a, "k8s_namespace", None)
            self.k8s_all_namespaces = getattr(a, "k8s_all_namespaces", False)
            # Other options
            self.results_dir = getattr(a, "results_dir", "results")
            self.config = getattr(a, "config", "jmo.yml")
            self.tools = getattr(a, "tools", None)
            self.timeout = getattr(a, "timeout", 600)
            self.threads = getattr(a, "threads", None)
            self.allow_missing_tools = getattr(a, "allow_missing_tools", False)
            self.profile_name = getattr(a, "profile_name", None)
            self.log_level = getattr(a, "log_level", None)
            self.human_logs = getattr(a, "human_logs", False)

    # Run scan phase
    cmd_scan_fn(ScanArgs(args))

    class ReportArgs:
        """Arguments adapter for report command."""

        def __init__(self, a):
            rd = str(Path(getattr(a, "results_dir", "results")))
            # Set all possible fields that cmd_report normalizes
            self.results_dir = rd
            self.results_dir_pos = rd
            self.results_dir_opt = rd
            self.out = None
            self.config = getattr(a, "config", "jmo.yml")
            self.fail_on = getattr(a, "fail_on", None)
            self.profile = getattr(a, "profile", False)
            self.threads = getattr(a, "threads", None)
            self.log_level = getattr(a, "log_level", None)
            self.human_logs = getattr(a, "human_logs", False)
            # Output format flags (used by report_orchestrator)
            self.json = getattr(a, "json", False)
            self.md = getattr(a, "md", False)
            self.html = getattr(a, "html", False)
            self.sarif = getattr(a, "sarif", False)
            self.yaml = getattr(a, "yaml", False)

    # Import _log here to avoid circular dependency
    from scripts.cli.jmo import _log

    # Run report phase and return its exit code
    rc_report: int = int(cmd_report_fn(ReportArgs(args), _log))
    return rc_report
