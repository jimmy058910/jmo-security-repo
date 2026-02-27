#!/usr/bin/env python3
"""CI orchestration logic for JMo Security."""

from __future__ import annotations

import sys
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
    # v1.0.0: Strict version check for reproducible CI builds
    if getattr(args, "strict_versions", False):
        from scripts.cli.tool_manager import ToolManager

        profile = getattr(args, "profile_name", None) or "balanced"
        manager = ToolManager()
        drift = manager.get_version_drift(profile)

        if drift:
            # Categorize by direction
            ahead = [d for d in drift if d.get("direction") == "ahead"]
            behind = [d for d in drift if d.get("direction") == "behind"]
            unknown = [d for d in drift if d.get("direction") == "unknown"]

            # Only fail on behind or unknown (ahead is generally OK)
            problematic = behind + unknown
            if problematic:
                sys.stderr.write(
                    f"ERROR: --strict-versions: {len(problematic)} tool(s) require attention\n"
                )
                if behind:
                    sys.stderr.write(f"\n{len(behind)} tool(s) BEHIND expected:\n")
                    for d in behind:
                        marker = " [CRITICAL]" if d["critical"] else ""
                        sys.stderr.write(
                            f"  {d['tool']}: {d['installed']} < {d['expected']}{marker}\n"
                        )
                if unknown:
                    sys.stderr.write(
                        f"\n{len(unknown)} tool(s) with unknown version:\n"
                    )
                    for d in unknown:
                        marker = " [CRITICAL]" if d["critical"] else ""
                        sys.stderr.write(
                            f"  {d['tool']}: installed={d['installed']} "
                            f"expected={d['expected']}{marker}\n"
                        )
                sys.stderr.write("\nRun 'jmo tools update' to synchronize versions.\n")
                return 1
            elif ahead:
                # Only ahead - info message, don't fail
                sys.stderr.write(
                    f"INFO: {len(ahead)} tool(s) ahead of versions.yaml (OK)\n"
                )

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
            # History database flags
            self.store_history = getattr(a, "store_history", False)
            self.history_db = getattr(a, "history_db", None)

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
            # History database flags
            self.store_history = getattr(a, "store_history", False)
            self.history_db = getattr(a, "history_db", None)
            self.profile_name = getattr(a, "profile_name", None)
            # Policy flags (Phase 5.1)
            self.policies = getattr(a, "policies", None)
            self.fail_on_policy_violation = getattr(
                a, "fail_on_policy_violation", False
            )

    # Import _log here to avoid circular dependency
    from scripts.cli.jmo import _log

    # Run report phase and return its exit code
    rc_report: int = int(cmd_report_fn(ReportArgs(args), _log))
    return rc_report
