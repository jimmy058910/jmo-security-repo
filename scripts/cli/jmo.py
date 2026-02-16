#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.core.exceptions import (
    ConfigurationException,
)
from scripts.core.config import load_config
from scripts.core.tool_registry import PROFILE_TOOLS
from scripts.cli.report_orchestrator import cmd_report as _cmd_report_impl
from scripts.cli.ci_orchestrator import cmd_ci as _cmd_ci_impl
from scripts.cli.schedule_commands import cmd_schedule
from scripts.cli.history_commands import cmd_history
from scripts.cli.diff_commands import cmd_diff
from scripts.cli.trend_commands import cmd_trends
from scripts.cli.build_commands import cmd_build, add_build_args

# PHASE 1 REFACTORING: Import refactored modules
from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanConfig
from scripts.cli.cpu_utils import auto_detect_threads as _auto_detect_threads_shared
from scripts.cli.policy_commands import cmd_policy

# Telemetry
from scripts.core.telemetry import (
    send_event,
    bucket_duration,
    bucket_findings,
    bucket_targets,
    detect_ci_environment,
    infer_scan_frequency,
)

# Configure logging
logger = logging.getLogger(__name__)

# Version (from pyproject.toml)
__version__ = "1.0.0"


# Windows-safe Unicode fallback mappings for cp1252 compatibility
_UNICODE_FALLBACKS = {
    "🎉": "[*]",  # Party (U+1F389)
    "📧": "[@]",  # Email (U+1F4E7)
    "💚": "<3",  # Green heart (U+1F49A)
    "👍": "[+1]",  # Thumbs up (U+1F44D)
    "✅": "[OK]",  # Check mark
    "❌": "[X]",  # Cross mark
    "⚠️": "[!]",  # Warning
    "→": "->",  # Right arrow
    "•": "*",  # Bullet
}


def _safe_print(text: str) -> None:
    """Print with Unicode fallback for Windows cp1252 compatibility."""
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        if encoding.lower() in ("cp1252", "ascii", "latin-1", "iso-8859-1"):
            for unicode_char, ascii_fallback in _UNICODE_FALLBACKS.items():
                text = text.replace(unicode_char, ascii_fallback)
        print(text)
    except UnicodeEncodeError:
        for unicode_char, ascii_fallback in _UNICODE_FALLBACKS.items():
            text = text.replace(unicode_char, ascii_fallback)
        print(text)


def _merge_dict(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a) if a else {}
    if b:
        out.update(b)
    return out


def _effective_scan_settings(args) -> dict[str, Any]:
    """Compute effective scan settings from CLI, config, and optional profile.

    Returns dict with keys: tools, threads, timeout, include, exclude, retries, per_tool, skip_tools

    Note: Tool lists come from PROFILE_TOOLS in tool_registry.py (single source of truth).
    jmo.yml profiles only configure threads, timeout, per_tool settings - not tool lists.
    """
    cfg = load_config(getattr(args, "config", None))
    profile_name = getattr(args, "profile_name", None) or cfg.default_profile
    profile = {}
    if profile_name and isinstance(cfg.profiles, dict):
        profile = cfg.profiles.get(profile_name, {}) or {}

    # Tool list priority: CLI --tools > PROFILE_TOOLS registry > config default
    # Note: jmo.yml profiles no longer contain tools: arrays (moved to tool_registry.py)
    tools = getattr(args, "tools", None)
    if not tools:
        if profile_name and profile_name in PROFILE_TOOLS:
            tools = PROFILE_TOOLS[profile_name]
        else:
            tools = cfg.tools  # Fallback to top-level config tools
    threads = getattr(args, "threads", None) or profile.get("threads") or cfg.threads
    timeout = (
        getattr(args, "timeout", None) or profile.get("timeout") or cfg.timeout or 600
    )
    include = profile.get("include", cfg.include) or cfg.include
    exclude = profile.get("exclude", cfg.exclude) or cfg.exclude
    retries = cfg.retries
    if isinstance(profile.get("retries"), int):
        retries = profile["retries"]
    per_tool = _merge_dict(cfg.per_tool, profile.get("per_tool", {}))

    # Handle --skip-tools flag to exclude specific tools
    skip_tools = getattr(args, "skip_tools", None) or []
    if skip_tools and tools:
        tools = [t for t in tools if t not in skip_tools]

    return {
        "tools": tools,
        "threads": threads,
        "timeout": timeout,
        "include": include,
        "exclude": exclude,
        "retries": max(0, int(retries or 0)),
        "per_tool": per_tool,
        "skip_tools": skip_tools,
    }


def _add_target_args(parser, target_group=None):
    """Add common target scanning arguments (repos, images, IaC, URLs, GitLab, K8s)."""
    # Repository targets (mutually exclusive if in a group)
    if target_group:
        g = target_group
        g.add_argument("--repo", help="Path to a single repository to scan")
        g.add_argument(
            "--repos-dir", help="Directory whose immediate subfolders are repos to scan"
        )
        g.add_argument("--targets", help="File listing repo paths (one per line)")
    else:
        parser.add_argument("--repo", help="Path to a single repository to scan")
        parser.add_argument(
            "--repos-dir", help="Directory whose immediate subfolders are repos to scan"
        )
        parser.add_argument("--targets", help="File listing repo paths (one per line)")

    # Container image scanning
    parser.add_argument(
        "--image", help="Container image to scan (format: registry/image:tag)"
    )
    parser.add_argument("--images-file", help="File with one image per line")

    # IaC/Terraform state scanning
    parser.add_argument("--terraform-state", help="Terraform state file to scan")
    parser.add_argument("--cloudformation", help="CloudFormation template to scan")
    parser.add_argument("--k8s-manifest", help="Kubernetes manifest file to scan")

    # Live web app/API scanning
    parser.add_argument("--url", help="Web application URL to scan")
    parser.add_argument("--urls-file", help="File with URLs (one per line)")
    parser.add_argument("--api-spec", help="OpenAPI/Swagger spec URL or file")

    # GitLab integration
    parser.add_argument(
        "--gitlab-url", help="GitLab instance URL (e.g., https://gitlab.com)"
    )
    parser.add_argument(
        "--gitlab-token", help="GitLab access token (or use GITLAB_TOKEN env var)"
    )
    parser.add_argument("--gitlab-group", help="GitLab group to scan")
    parser.add_argument("--gitlab-repo", help="Single GitLab repo (format: group/repo)")

    # Kubernetes cluster scanning
    parser.add_argument("--k8s-context", help="Kubernetes context to scan")
    parser.add_argument("--k8s-namespace", help="Kubernetes namespace to scan")
    parser.add_argument(
        "--k8s-all-namespaces", action="store_true", help="Scan all namespaces"
    )


def _add_scan_config_args(parser):
    """Add common scan configuration arguments."""
    parser.add_argument(
        "--results-dir",
        default="results",
        help="Base results directory (default: results)",
    )
    parser.add_argument(
        "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
    )
    parser.add_argument("--tools", nargs="*", help="Override tools list from config")
    parser.add_argument(
        "--skip-tools",
        nargs="*",
        default=[],
        help="Tools to skip (e.g., --skip-tools dependency-check cdxgen)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-tool timeout seconds (default: from config or 600)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Concurrent repos to scan (default: auto)",
    )
    parser.add_argument(
        "--allow-missing-tools",
        action="store_true",
        help="If a tool is missing, create empty JSON instead of failing",
    )
    parser.add_argument(
        "--profile-name",
        default=None,
        help="Optional profile name from config.profiles to apply for scanning",
    )
    parser.add_argument(
        "--no-store-history",
        action="store_false",
        dest="store_history",
        default=True,
        help="Disable automatic history storage (default: enabled)",
    )
    parser.add_argument(
        "--history-db",
        default=None,
        help="Path to history database (default: .jmo/history.db)",
    )
    parser.add_argument(
        "--no-store-raw-findings",
        action="store_true",
        help="Don't store raw finding data in history database (security: prevents secret persistence)",
    )
    parser.add_argument(
        "--encrypt-findings",
        action="store_true",
        help="Encrypt raw finding data in history database (requires JMO_ENCRYPTION_KEY env var)",
    )
    parser.add_argument(
        "--collect-metadata",
        action="store_true",
        help="Collect hostname/username metadata (default: disabled for privacy)",
    )


def _add_logging_args(parser):
    """Add common logging arguments."""
    parser.add_argument(
        "--log-level",
        default=None,
        help="Log level: DEBUG|INFO|WARN|ERROR (default: from config)",
    )
    parser.add_argument(
        "--human-logs",
        action="store_true",
        help="Emit human-friendly colored logs instead of JSON",
    )


def _add_scan_args(subparsers):
    """Add 'scan' subcommand arguments."""
    sp = subparsers.add_parser(
        "scan", help="Run configured tools on repos and write JSON outputs"
    )
    g = sp.add_mutually_exclusive_group(required=False)
    _add_target_args(sp, target_group=g)
    _add_scan_config_args(sp)
    _add_logging_args(sp)
    return sp


def _add_report_args(subparsers):
    """Add 'report' subcommand arguments."""
    rp = subparsers.add_parser("report", help="Aggregate findings and emit reports")
    # Allow both positional and optional for results dir (backward compatible)
    rp.add_argument(
        "results_dir_pos",
        nargs="?",
        default=None,
        help="Directory with individual-repos/* tool outputs",
    )
    rp.add_argument(
        "--results-dir",
        dest="results_dir_opt",
        default=None,
        help="Directory with individual-repos/* tool outputs (optional form)",
    )
    rp.add_argument(
        "--out",
        default=None,
        help="Output directory (default: <results_dir>/summaries)",
    )
    rp.add_argument(
        "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
    )
    rp.add_argument(
        "--fail-on", default=None, help="Severity threshold to exit non-zero"
    )
    rp.add_argument(
        "--profile",
        action="store_true",
        help="Collect per-tool timing and write timings.json",
    )
    rp.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Override worker threads for aggregation (default: auto)",
    )
    rp.add_argument(
        "--policy",
        action="append",
        dest="policies",
        help="Policy to evaluate (can be specified multiple times, e.g., --policy owasp-top-10 --policy zero-secrets)",
    )
    _add_logging_args(rp)
    # Accept --allow-missing-tools for symmetry with scan (no-op during report)
    rp.add_argument(
        "--allow-missing-tools",
        action="store_true",
        help="Accepted for compatibility; reporting tolerates missing tool outputs by default",
    )
    return rp


def _add_ci_args(subparsers):
    """Add 'ci' subcommand arguments."""
    cp = subparsers.add_parser(
        "ci", help="Run scan then report with thresholds; convenient for CI"
    )
    cg = cp.add_mutually_exclusive_group(required=False)
    _add_target_args(cp, target_group=cg)
    _add_scan_config_args(cp)
    cp.add_argument(
        "--fail-on",
        default=None,
        help="Severity threshold to exit non-zero (for report)",
    )
    cp.add_argument(
        "--profile", action="store_true", help="Collect timings.json during report"
    )
    cp.add_argument(
        "--policy",
        action="append",
        dest="policies",
        help="Policy to evaluate in CI mode (can be specified multiple times, e.g., --policy owasp-top-10 --policy zero-secrets)",
    )
    cp.add_argument(
        "--fail-on-policy-violation",
        action="store_true",
        help="Fail CI (exit code 1) if any policy violations found",
    )
    cp.add_argument(
        "--strict-versions",
        action="store_true",
        help="Fail CI if tool versions don't match versions.yaml (v1.0.0: reproducible builds)",
    )
    _add_logging_args(cp)
    return cp


def _add_profile_args(subparsers, profile_name: str, description: str):
    """Add profile-based scan command (fast/balanced/full)."""
    profile_parser = subparsers.add_parser(profile_name, help=description)

    # Target selection (mutually exclusive)
    target_group = profile_parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument("--repo", help="Path to a single repository to scan")
    target_group.add_argument(
        "--repos-dir", help="Directory whose immediate subfolders are repos to scan"
    )
    target_group.add_argument(
        "--targets", help="File listing repo paths (one per line)"
    )

    # Scan configuration
    profile_parser.add_argument(
        "--results-dir",
        default="results",
        help="Results directory (default: results)",
    )
    profile_parser.add_argument(
        "--threads", type=int, default=None, help="Override threads"
    )
    profile_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Override per-tool timeout seconds",
    )
    profile_parser.add_argument(
        "--fail-on",
        default=None,
        help="Optional severity threshold to fail the run (CRITICAL/HIGH/MEDIUM/LOW/INFO)",
    )
    profile_parser.add_argument(
        "--no-open", action="store_true", help="Do not open results after run"
    )
    profile_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if tools are missing (disable stubs)",
    )
    profile_parser.add_argument(
        "--human-logs", action="store_true", help="Human-friendly logs"
    )
    profile_parser.add_argument(
        "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
    )

    return profile_parser


def _add_wizard_args(subparsers):
    """Add 'wizard' subcommand for interactive guided scanning."""
    wizard_parser = subparsers.add_parser(
        "wizard", help="Interactive wizard for guided security scanning"
    )
    wizard_parser.add_argument(
        "--yes",
        action="store_true",
        help="Non-interactive mode: use defaults for all prompts",
    )
    wizard_parser.add_argument(
        "--mode",
        choices=["scan", "diff"],
        default="scan",
        help="Wizard mode: scan (default) or diff comparison",
    )

    # Diff mode arguments (use with --mode diff --yes)
    diff_group = wizard_parser.add_argument_group(
        "diff options",
        "Options for diff mode (use with --mode diff --yes for non-interactive)",
    )
    diff_group.add_argument(
        "--baseline",
        metavar="DIR",
        help="Baseline results directory for diff comparison",
    )
    diff_group.add_argument(
        "--current",
        metavar="DIR",
        help="Current results directory for diff comparison",
    )

    # Preset flags for automation (enables non-interactive wizard runs)
    preset_group = wizard_parser.add_argument_group(
        "preset options",
        "Preset wizard choices for automation (use with --yes for fully non-interactive)",
    )
    preset_group.add_argument(
        "--profile",
        choices=["fast", "slim", "balanced", "deep"],
        help="Scan profile (fast=9 tools, slim=14, balanced=18, deep=29)",
    )
    preset_group.add_argument(
        "--target-type",
        choices=["repo", "image", "iac", "url"],
        help="Target type to scan",
    )
    preset_group.add_argument(
        "--target",
        metavar="PATH_OR_IMAGE",
        help="Target value (repo path, image name, IaC path, or URL)",
    )

    # Execution mode
    exec_group = wizard_parser.add_mutually_exclusive_group()
    exec_group.add_argument(
        "--native",
        action="store_true",
        help="Use native execution mode (tools installed locally)",
    )
    exec_group.add_argument(
        "--docker",
        action="store_true",
        help="Use Docker execution mode (tools bundled in container)",
    )

    # Tool installation flags
    install_group = wizard_parser.add_argument_group(
        "tool installation",
        "Control automatic tool installation during wizard",
    )
    install_group.add_argument(
        "--auto-fix",
        action="store_true",
        help="Automatically install missing tools without prompting",
    )
    install_group.add_argument(
        "--install-deps",
        action="store_true",
        help="Automatically install missing dependencies (Java, Node.js)",
    )

    # Advanced configuration
    advanced_group = wizard_parser.add_argument_group(
        "advanced options",
        "Override advanced scan settings",
    )
    advanced_group.add_argument(
        "--threads",
        type=int,
        metavar="N",
        help="Number of parallel threads for scanning",
    )
    advanced_group.add_argument(
        "--timeout",
        type=int,
        metavar="SECONDS",
        help="Per-tool timeout in seconds",
    )
    advanced_group.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Severity threshold for CI failures",
    )
    advanced_group.add_argument(
        "--results-dir",
        metavar="DIR",
        help="Output directory for scan results (default: results)",
    )

    # Artifact generation
    wizard_parser.add_argument(
        "--emit-script",
        metavar="FILE",
        nargs="?",
        const="jmo-scan.sh",
        type=str,
        help="Generate shell script (default: jmo-scan.sh)",
    )
    wizard_parser.add_argument(
        "--emit-make-target",
        metavar="FILE",
        nargs="?",
        const="Makefile.jmo",
        type=str,
        help="Generate Makefile target (default: Makefile.jmo)",
    )
    wizard_parser.add_argument(
        "--emit-gha",
        metavar="FILE",
        nargs="?",
        const=".github/workflows/jmo-security.yml",
        type=str,
        help="Generate GitHub Actions workflow (default: .github/workflows/jmo-security.yml)",
    )

    # Trend analysis (post-scan)
    wizard_parser.add_argument(
        "--analyze-trends",
        action="store_true",
        help="Automatically analyze trends after scan (non-interactive)",
    )
    wizard_parser.add_argument(
        "--export-trends-html",
        action="store_true",
        help="Export trend report as HTML after scan",
    )
    wizard_parser.add_argument(
        "--export-trends-json",
        action="store_true",
        help="Export trend report as JSON after scan",
    )

    # Policy evaluation
    wizard_parser.add_argument(
        "--policy",
        action="append",
        dest="policies",
        help="Policy to evaluate after scan (can be specified multiple times, e.g., --policy owasp-top-10 --policy zero-secrets)",
    )
    wizard_parser.add_argument(
        "--skip-policies",
        action="store_true",
        help="Skip policy evaluation entirely (overrides config defaults)",
    )
    wizard_parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to SQLite history database (default: ~/.jmo/history.db)",
    )
    return wizard_parser


def _add_setup_args(subparsers):
    """Add 'setup' subcommand for tool verification and installation."""
    setup_parser = subparsers.add_parser(
        "setup", help="Verify and optionally auto-install security tools"
    )
    setup_parser.add_argument(
        "--auto-install",
        action="store_true",
        help="Attempt to auto-install missing tools",
    )
    setup_parser.add_argument(
        "--print-commands",
        action="store_true",
        help="Print installation commands without executing",
    )
    setup_parser.add_argument(
        "--force-reinstall",
        action="store_true",
        help="Force reinstallation of all tools",
    )
    setup_parser.add_argument(
        "--human-logs", action="store_true", help="Human-friendly logs"
    )
    setup_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with error if any tools are missing",
    )
    return setup_parser


def _add_tools_args(subparsers):
    """Add 'tools' subcommand for tool management."""
    tools_parser = subparsers.add_parser(
        "tools",
        help="Check, install, and update security tools",
        description="""
Manage security tools for JMo scans.

Commands:
  check      Verify tool installation status
  install    Install missing tools
  update     Update outdated tools
  list       List available tools and profiles
  outdated   Show outdated tools

Examples:
  jmo tools check                     # Check all tool status
  jmo tools check --profile balanced  # Check profile tools
  jmo tools install                   # Install missing (interactive)
  jmo tools install --yes             # Install without prompts
  jmo tools update --critical-only    # Update critical tools
  jmo tools list --profiles           # Show available profiles
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    tools_subparsers = tools_parser.add_subparsers(dest="tools_command")

    # CHECK
    check_parser = tools_subparsers.add_parser(
        "check", help="Check tool installation status"
    )
    check_parser.add_argument("tools", nargs="*", help="Specific tools to check")
    check_parser.add_argument(
        "--profile",
        choices=["fast", "slim", "balanced", "deep"],
        help="Check tools for specific profile",
    )
    check_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # INSTALL
    install_parser = tools_subparsers.add_parser(
        "install", help="Install missing tools"
    )
    install_parser.add_argument("tools", nargs="*", help="Specific tools to install")
    install_parser.add_argument(
        "--profile",
        choices=["fast", "slim", "balanced", "deep"],
        default="balanced",
        help="Install tools for profile (default: balanced)",
    )
    install_parser.add_argument(
        "--yes", "-y", action="store_true", help="Non-interactive mode"
    )
    install_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be installed"
    )
    install_parser.add_argument(
        "--print-script", action="store_true", help="Print install script"
    )
    install_parser.add_argument(
        "--sequential",
        "-S",
        action="store_true",
        help="Install tools sequentially (slower, for debugging)",
    )
    install_parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=4,
        metavar="N",
        help="Number of parallel installation jobs (default: 4, max: 8)",
    )

    # UPDATE
    update_parser = tools_subparsers.add_parser("update", help="Update outdated tools")
    update_parser.add_argument("tools", nargs="*", help="Specific tools to update")
    update_parser.add_argument(
        "--critical-only", action="store_true", help="Only update critical tools"
    )
    update_parser.add_argument(
        "--yes", "-y", action="store_true", help="Non-interactive mode"
    )

    # LIST
    list_parser = tools_subparsers.add_parser("list", help="List available tools")
    list_parser.add_argument(
        "--profile",
        choices=["fast", "slim", "balanced", "deep"],
        help="List tools in profile",
    )
    list_parser.add_argument(
        "--profiles", action="store_true", help="List available profiles"
    )
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # OUTDATED
    outdated_parser = tools_subparsers.add_parser(
        "outdated", help="Show outdated tools"
    )
    outdated_parser.add_argument(
        "--critical-only", action="store_true", help="Only show critical tools"
    )
    outdated_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # UNINSTALL
    uninstall_parser = tools_subparsers.add_parser(
        "uninstall",
        help="Uninstall JMo Security suite and optionally tools",
        description="""
Uninstall JMo Security from your system.

Options:
  (default)    Remove JMo suite only, keep security tools installed
  --all        Remove JMo AND all security tools

What gets removed with --all:
  - ~/.jmo/ directory (config, cache, history, bins)
  - jmo-security pip package (if installed)
  - pip-installed tools (semgrep, checkov, bandit, etc.)
  - npm-installed tools (retire.js, etc.)
  - Binary tools in ~/.jmo/bin/
  - ~/.kubescape/ directory

Examples:
  jmo tools uninstall              # Remove JMo only
  jmo tools uninstall --all        # Remove everything
  jmo tools uninstall --dry-run    # Preview what would be removed
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    uninstall_parser.add_argument(
        "--all", "-a", action="store_true", help="Also uninstall all security tools"
    )
    uninstall_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed without removing",
    )
    uninstall_parser.add_argument(
        "--yes", "-y", action="store_true", help="Skip confirmation prompt"
    )

    # Debug command - troubleshoot version detection
    debug_parser = tools_subparsers.add_parser(
        "debug",
        help="Debug version detection for specific tools",
        description="""
Debug version detection issues for security tools.

Shows detailed information about:
  - Binary location and path
  - Version command executed
  - Raw stdout/stderr output
  - Regex pattern used
  - Pattern match results

Examples:
  jmo tools debug shellcheck        # Debug one tool
  jmo tools debug zap dependency-check  # Debug multiple tools
  jmo tools debug --all             # Debug all tools
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    debug_parser.add_argument(
        "tools", nargs="*", help="Tools to debug version detection"
    )
    debug_parser.add_argument(
        "--all", "-a", action="store_true", help="Debug all tools in balanced profile"
    )

    # CLEAN - Phase 5: Clean isolated virtual environments
    clean_parser = tools_subparsers.add_parser(
        "clean",
        help="Clean isolated venvs (pip conflict tools)",
        description="""
Clean isolated virtual environments used for tools with pip conflicts.

Some tools (prowler, scancode) have conflicting dependencies (e.g., pydantic
version conflicts) and are installed in isolated venvs at ~/.jmo/tools/venvs/.

Use this command to:
  - Reclaim disk space
  - Fix corrupted isolated venv installations
  - Reset before reinstalling conflicting tools

Examples:
  jmo tools clean           # Show what would be removed (dry run)
  jmo tools clean --force   # Actually remove the isolated venvs

After cleaning, reinstall tools with:
  jmo tools install prowler scancode
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    clean_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Actually remove (default is dry run)",
    )

    return tools_parser


def _add_adapters_args(subparsers):
    """Add 'adapters' subcommand arguments for plugin management."""
    adapters_parser = subparsers.add_parser("adapters", help="Manage adapter plugins")
    adapters_subparsers = adapters_parser.add_subparsers(dest="adapters_command")

    # List command
    adapters_subparsers.add_parser("list", help="List all loaded adapter plugins")

    # Validate command
    validate_parser = adapters_subparsers.add_parser(
        "validate", help="Validate an adapter plugin file"
    )
    validate_parser.add_argument("file", help="Path to adapter plugin file")

    return adapters_parser


def _add_schedule_args(subparsers):
    """Add 'schedule' subcommand arguments for scheduled scan management."""
    schedule_parser = subparsers.add_parser(
        "schedule",
        help="Manage scheduled security scans",
        description="Manage scheduled scans using CI/CD or local cron",
    )
    schedule_subparsers = schedule_parser.add_subparsers(
        dest="schedule_action", required=True
    )

    # CREATE
    create_parser = schedule_subparsers.add_parser("create", help="Create new schedule")
    create_parser.add_argument("--name", required=True, help="Schedule name")
    create_parser.add_argument(
        "--cron", required=True, help="Cron expression (e.g., '0 2 * * *')"
    )
    create_parser.add_argument(
        "--profile",
        required=True,
        choices=["fast", "balanced", "deep"],
        help="Scan profile",
    )
    create_parser.add_argument("--repos-dir", help="Repository directory to scan")
    create_parser.add_argument(
        "--image",
        action="append",
        help="Container image to scan (can specify multiple)",
    )
    create_parser.add_argument(
        "--url", action="append", help="Web URL to scan (can specify multiple)"
    )
    create_parser.add_argument(
        "--backend",
        default="github-actions",
        choices=["github-actions", "gitlab-ci", "local-cron"],
        help="Backend type",
    )
    create_parser.add_argument(
        "--timezone", default="UTC", help="Timezone for schedule (default: UTC)"
    )
    create_parser.add_argument("--description", help="Human-readable description")
    create_parser.add_argument(
        "--label", action="append", help="Label in KEY=VALUE format"
    )
    create_parser.add_argument(
        "--slack-webhook", help="Slack webhook URL for notifications"
    )

    # LIST
    list_parser = schedule_subparsers.add_parser("list", help="List schedules")
    list_parser.add_argument(
        "--format",
        choices=["table", "json", "yaml"],
        default="table",
        help="Output format",
    )
    list_parser.add_argument(
        "--label", action="append", help="Filter by label (KEY=VALUE)"
    )

    # GET
    get_parser = schedule_subparsers.add_parser("get", help="Get schedule details")
    get_parser.add_argument("name", help="Schedule name")
    get_parser.add_argument(
        "--format", choices=["json", "yaml"], default="yaml", help="Output format"
    )

    # UPDATE
    update_parser = schedule_subparsers.add_parser("update", help="Update schedule")
    update_parser.add_argument("name", help="Schedule name")
    update_parser.add_argument("--cron", help="New cron expression")
    update_parser.add_argument(
        "--profile", choices=["fast", "balanced", "deep"], help="New scan profile"
    )
    update_parser.add_argument(
        "--suspend", action="store_true", help="Suspend schedule"
    )
    update_parser.add_argument("--resume", action="store_true", help="Resume schedule")

    # EXPORT
    export_parser = schedule_subparsers.add_parser(
        "export", help="Export workflow file"
    )
    export_parser.add_argument("name", help="Schedule name")
    export_parser.add_argument(
        "--backend",
        choices=["github-actions", "gitlab-ci"],
        help="Override backend type",
    )
    export_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # INSTALL
    install_parser = schedule_subparsers.add_parser(
        "install", help="Install to local cron (Linux/macOS only)"
    )
    install_parser.add_argument("name", help="Schedule name")

    # UNINSTALL
    uninstall_parser = schedule_subparsers.add_parser(
        "uninstall", help="Remove from local cron"
    )
    uninstall_parser.add_argument("name", help="Schedule name")

    # DELETE
    delete_parser = schedule_subparsers.add_parser("delete", help="Delete schedule")
    delete_parser.add_argument("name", help="Schedule name")
    delete_parser.add_argument(
        "--force", action="store_true", help="Skip confirmation prompt"
    )

    # VALIDATE
    validate_parser = schedule_subparsers.add_parser(
        "validate", help="Validate schedule configuration"
    )
    validate_parser.add_argument("name", help="Schedule name")

    return schedule_parser


def _add_mcp_args(subparsers):
    """Add 'mcp-server' subcommand arguments for AI remediation server."""
    mcp_parser = subparsers.add_parser(
        "mcp-server",
        help="Start MCP server for AI-powered remediation (GitHub Copilot, Claude Code, etc.)",
        description="""
Start JMo Security MCP Server for AI-powered remediation orchestration.

The MCP server provides a standardized interface for AI tools to query security
findings and suggest fixes. Supports GitHub Copilot, Claude Code, OpenAI Codex,
and any MCP-compatible client.

Usage:
    # Development mode (stdio transport for Claude Desktop)
    uv run mcp dev scripts/mcp/server.py

    # Production mode (via jmo CLI)
    jmo mcp-server --results-dir ./results --repo-root .

Environment Variables:
    MCP_RESULTS_DIR: Path to results directory (overrides --results-dir)
    MCP_REPO_ROOT: Path to repository root (overrides --repo-root)
    MCP_API_KEY: API key for authentication (optional, dev mode if not set)

See: docs/MCP_SETUP.md for GitHub Copilot and Claude Code integration guides.
        """,
    )
    mcp_parser.add_argument(
        "--results-dir",
        default="./results",
        help="Path to results directory (default: ./results)",
    )
    mcp_parser.add_argument(
        "--repo-root",
        default=".",
        help="Path to repository root (default: current directory)",
    )
    mcp_parser.add_argument(
        "--api-key",
        help="API key for authentication (optional, enables production mode)",
    )
    _add_logging_args(mcp_parser)
    return mcp_parser


def _add_history_args(subparsers):
    """Add 'history' subcommand arguments for historical scan management."""
    history_parser = subparsers.add_parser(
        "history",
        help="Manage historical scan database (store, query, analyze trends)",
        description="""
Manage historical scan database for trend analysis and security posture tracking.

The history database stores all scans in SQLite for:
- Historical comparison (track security improvements over time)
- Machine-readable diffs (identify new/resolved findings between scans)
- Trend analysis (multi-scan intelligence and regression detection)
- Compliance tracking (demonstrate security improvements for audits)

Database Location: .jmo/history.db (default)

Usage Examples:
    # Manually store a completed scan
    jmo history store --results-dir ./results --profile balanced

    # List recent scans
    jmo history list --limit 10

    # Show detailed scan information
    jmo history show abc123

    # Query scans by branch
    jmo history list --branch main

    # Show database statistics
    jmo history stats

    # Delete scans older than 90 days
    jmo history prune --older-than 90d

    # Export all scans as JSON
    jmo history export --format json > history.json

See: docs/HISTORY_GUIDE.md for complete documentation.
        """,
    )
    history_subparsers = history_parser.add_subparsers(dest="history_command")

    # Common arguments
    def add_db_arg(parser):
        """Add --db argument to argparse parser for SQLite database location.

        Adds a command-line argument that allows users to specify a custom path
        for the SQLite history database. Used by history and trends commands.

        Args:
            parser (argparse.ArgumentParser): Parser to modify in-place

        Returns:
            None (modifies parser in-place by adding argument)

        Example:
            >>> parser = argparse.ArgumentParser()
            >>> add_db_arg(parser)
            >>> args = parser.parse_args(['--db', '/custom/path.db'])
            >>> print(args.db)
            /custom/path.db

        Note:
            Default database location is .jmo/history.db relative to current directory.
            Database file is created automatically if it doesn't exist.

        """
        parser.add_argument(
            "--db",
            default=None,
            help="Path to SQLite database (default: .jmo/history.db)",
        )

    # STORE
    store_parser = history_subparsers.add_parser(
        "store", help="Manually store a completed scan"
    )
    store_parser.add_argument(
        "--results-dir",
        required=True,
        help="Path to results directory (must contain summaries/findings.json)",
    )
    store_parser.add_argument(
        "--profile",
        default="balanced",
        choices=["fast", "balanced", "deep"],
        help="Scan profile that was used (default: balanced)",
    )
    store_parser.add_argument(
        "--commit", help="Git commit hash (optional, auto-detected if not provided)"
    )
    store_parser.add_argument(
        "--branch", help="Git branch name (optional, auto-detected if not provided)"
    )
    store_parser.add_argument(
        "--tag", help="Git tag (optional, auto-detected if not provided)"
    )
    add_db_arg(store_parser)

    # LIST
    list_parser = history_subparsers.add_parser("list", help="List all scans")
    list_parser.add_argument("--branch", help="Filter by branch name")
    list_parser.add_argument(
        "--profile",
        choices=["fast", "balanced", "deep"],
        help="Filter by profile",
    )
    list_parser.add_argument(
        "--since", help="Filter by time delta (e.g., 7d, 30d, 90d)"
    )
    list_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum number of results (default: 50)"
    )
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")
    add_db_arg(list_parser)

    # SHOW
    show_parser = history_subparsers.add_parser(
        "show", help="Show detailed scan information"
    )
    show_parser.add_argument(
        "scan_id", help="Scan UUID (full or partial, e.g., 'abc123')"
    )
    show_parser.add_argument(
        "--findings", action="store_true", help="Include all findings in output"
    )
    show_parser.add_argument("--json", action="store_true", help="Output as JSON")
    add_db_arg(show_parser)

    # QUERY
    query_parser = history_subparsers.add_parser(
        "query", help="Execute custom SQL query"
    )
    query_parser.add_argument("query", help="SQL query to execute")
    query_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    add_db_arg(query_parser)

    # PRUNE
    prune_parser = history_subparsers.add_parser("prune", help="Delete old scans")
    prune_parser.add_argument(
        "--older-than",
        required=True,
        help="Delete scans older than time delta (e.g., 30d, 90d, 180d)",
    )
    prune_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting",
    )
    prune_parser.add_argument(
        "--force", action="store_true", help="Skip confirmation prompt"
    )
    add_db_arg(prune_parser)

    # EXPORT
    export_parser = history_subparsers.add_parser(
        "export", help="Export scans to JSON/CSV"
    )
    export_parser.add_argument(
        "--scan-id", help="Export specific scan by UUID (optional)"
    )
    export_parser.add_argument(
        "--since", help="Export scans from time delta (e.g., 30d)"
    )
    export_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    add_db_arg(export_parser)

    # STATS
    stats_parser = history_subparsers.add_parser(
        "stats", help="Show database statistics"
    )
    stats_parser.add_argument("--json", action="store_true", help="Output as JSON")
    add_db_arg(stats_parser)

    # diff subcommand
    diff_parser = history_subparsers.add_parser(
        "diff", help="Compare two scans and show differences"
    )
    diff_parser.add_argument("scan_id_1", help="First scan ID (baseline)")
    diff_parser.add_argument("scan_id_2", help="Second scan ID (comparison)")
    diff_parser.add_argument("--json", action="store_true", help="Output as JSON")
    add_db_arg(diff_parser)

    # trends subcommand
    trends_parser = history_subparsers.add_parser(
        "trends", help="Show security trends over time for a branch"
    )
    trends_parser.add_argument(
        "--branch", default="main", help="Branch name (default: main)"
    )
    trends_parser.add_argument(
        "--days", type=int, default=30, help="Number of days to analyze (default: 30)"
    )
    trends_parser.add_argument("--json", action="store_true", help="Output as JSON")
    add_db_arg(trends_parser)

    # OPTIMIZE (Phase 4.1)
    optimize_parser = history_subparsers.add_parser(
        "optimize", help="Optimize database performance (VACUUM, ANALYZE)"
    )
    optimize_parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    add_db_arg(optimize_parser)

    # MIGRATE (Phase 4.3)
    migrate_parser = history_subparsers.add_parser(
        "migrate", help="Apply pending database schema migrations"
    )
    migrate_parser.add_argument(
        "--target-version",
        default=None,
        help="Target schema version (default: apply all pending migrations)",
    )
    migrate_parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    add_db_arg(migrate_parser)

    # VERIFY (Phase 4.4)
    verify_parser = history_subparsers.add_parser(
        "verify", help="Verify database integrity (PRAGMA checks)"
    )
    verify_parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    add_db_arg(verify_parser)

    # REPAIR (Phase 4.4)
    repair_parser = history_subparsers.add_parser(
        "repair", help="Repair corrupted database (dump/reimport)"
    )
    repair_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt and proceed with repair",
    )
    repair_parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    add_db_arg(repair_parser)

    return history_parser


def _add_trends_args(subparsers):
    """Add 'trends' subcommand arguments for security trend analysis."""
    trends_parser = subparsers.add_parser(
        "trends",
        help="Analyze security trends over time (Phase 1-3 complete)",
        description="""
Analyze security trends over time using SQLite historical data.

Features:
- Statistical trend validation (Mann-Kendall test)
- Regression detection (CRITICAL/HIGH increases)
- Security posture scoring (0-100 scale)
- Automated insights generation
- Side-by-side scan comparisons

Usage Examples:
    # Analyze last 10 scans
    jmo trends analyze --last 10

    # Analyze last 30 days with statistical validation
    jmo trends analyze --days 30 --validate-statistics

    # Show regression detections
    jmo trends regressions --severity CRITICAL

    # Security score history
    jmo trends score --last 30

    # Compare two scans
    jmo trends compare abc123 def456

    # Show insights
    jmo trends insights

See: dev-only/archive/feature-plans/TREND_ANALYSIS.md for complete documentation.
        """,
    )
    trends_subparsers = trends_parser.add_subparsers(dest="trends_command")

    # Common arguments
    def add_common_trend_args(parser):
        """Add common trend analysis arguments to argparse parser.

        Adds arguments shared by multiple trend subcommands (analyze, show, insights)
        including database path and branch selection.

        Args:
            parser (argparse.ArgumentParser): Parser to modify in-place

        Returns:
            None (modifies parser in-place by adding arguments)

        Example:
            >>> parser = argparse.ArgumentParser()
            >>> add_common_trend_args(parser)
            >>> args = parser.parse_args(['--db', 'custom.db', '--branch', 'dev'])
            >>> print(args.db, args.branch)
            custom.db dev

        Note:
            These arguments are automatically added to all trend analysis subcommands
            (analyze, show, regressions, score, compare, insights, explain, developers).

        """
        parser.add_argument(
            "--db",
            default=None,
            help="Path to SQLite database (default: .jmo/history.db)",
        )
        parser.add_argument(
            "--branch",
            default="main",
            help="Git branch to analyze (default: main)",
        )

    # ANALYZE
    analyze_parser = trends_subparsers.add_parser(
        "analyze", help="Analyze security trends with flexible filters"
    )
    analyze_parser.add_argument(
        "--days",
        type=int,
        help="Number of days to analyze (e.g., 30)",
    )
    analyze_parser.add_argument(
        "--last",
        type=int,
        help="Last N scans to analyze (e.g., 10)",
    )
    analyze_parser.add_argument(
        "--scan-ids",
        nargs="+",
        help="Specific scan IDs to analyze",
    )
    analyze_parser.add_argument(
        "--validate-statistics",
        action="store_true",
        help="Run Mann-Kendall statistical validation",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    analyze_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output (top rules, etc.)",
    )
    analyze_parser.add_argument(
        "--export-json",
        help="Export analysis to JSON file",
    )
    analyze_parser.add_argument(
        "--export-html",
        help="Export analysis to HTML file (Phase 4)",
    )
    add_common_trend_args(analyze_parser)

    # SHOW
    show_parser = trends_subparsers.add_parser(
        "show", help="Show trend context for a specific scan"
    )
    show_parser.add_argument(
        "scan_id",
        help="Scan ID to show context for",
    )
    show_parser.add_argument(
        "--context",
        type=int,
        default=5,
        help="Number of scans before/after to show (default: 5)",
    )
    add_common_trend_args(show_parser)

    # REGRESSIONS
    regressions_parser = trends_subparsers.add_parser(
        "regressions", help="List all detected regressions"
    )
    regressions_parser.add_argument(
        "--last",
        type=int,
        help="Last N scans to analyze",
    )
    regressions_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH"],
        help="Filter by severity",
    )
    regressions_parser.add_argument(
        "--fail-on-any",
        action="store_true",
        help="Exit with error code 1 if any regressions found (for CI)",
    )
    add_common_trend_args(regressions_parser)

    # SCORE
    score_parser = trends_subparsers.add_parser(
        "score", help="Show security posture score history"
    )
    score_parser.add_argument(
        "--last",
        type=int,
        help="Last N scans to analyze",
    )
    score_parser.add_argument(
        "--days",
        type=int,
        help="Number of days to analyze",
    )
    add_common_trend_args(score_parser)

    # COMPARE
    compare_parser = trends_subparsers.add_parser(
        "compare", help="Compare two specific scans side-by-side"
    )
    compare_parser.add_argument(
        "scan_id_1",
        help="First scan ID",
    )
    compare_parser.add_argument(
        "scan_id_2",
        help="Second scan ID",
    )
    compare_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show sample findings from diff",
    )
    add_common_trend_args(compare_parser)

    # INSIGHTS
    insights_parser = trends_subparsers.add_parser(
        "insights", help="List all automated insights"
    )
    insights_parser.add_argument(
        "--last",
        type=int,
        help="Last N scans to analyze",
    )
    add_common_trend_args(insights_parser)

    # EXPLAIN
    explain_parser = trends_subparsers.add_parser(
        "explain", help="Explain how trend metrics are calculated"
    )
    explain_parser.add_argument(
        "metric",
        nargs="?",
        choices=["score", "mann-kendall", "regressions", "trend", "all"],
        default="all",
        help="Metric to explain (default: all)",
    )

    # DEVELOPERS
    developers_parser = trends_subparsers.add_parser(
        "developers", help="Show developer remediation rankings (Phase 5)"
    )
    developers_parser.add_argument(
        "--last",
        type=int,
        help="Last N scans to analyze",
    )
    developers_parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Show top N developers (default: 10)",
    )
    add_common_trend_args(developers_parser)

    return trends_parser


def _add_policy_args(subparsers):
    """Add 'policy' subcommand arguments for Policy-as-Code management."""
    policy_parser = subparsers.add_parser(
        "policy",
        help="Manage Policy-as-Code (OPA) for security governance",
        description="""
Manage OPA-based policies for custom security governance and compliance enforcement.

Commands:
- list      List all available policies (builtin + user)
- validate  Validate policy syntax with OPA
- test      Test policy against sample findings
- show      Display policy metadata and content
- install   Install builtin policy to user directory for customization

Policy Locations:
- Built-in: policies/builtin/
- User:     ~/.jmo/policies/

Usage Examples:
    # List all policies
    jmo policy list

    # Validate policy syntax
    jmo policy validate zero-secrets

    # Test policy with findings
    jmo policy test zero-secrets --findings-file results/summaries/findings.json

    # Show policy details
    jmo policy show owasp-top-10

    # Install policy for customization
    jmo policy install pci-dss

See: docs/POLICY_AS_CODE.md for complete documentation.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    policy_subparsers = policy_parser.add_subparsers(
        dest="policy_command", required=True
    )

    # LIST
    policy_subparsers.add_parser("list", help="List all available policies")

    # VALIDATE
    validate_parser = policy_subparsers.add_parser(
        "validate", help="Validate policy syntax"
    )
    validate_parser.add_argument("policy", help="Policy name (without .rego extension)")

    # TEST
    test_parser = policy_subparsers.add_parser(
        "test", help="Test policy with findings file"
    )
    test_parser.add_argument("policy", help="Policy name (without .rego extension)")
    test_parser.add_argument(
        "--findings-file",
        required=True,
        help="Path to JSON file with findings (e.g., results/summaries/findings.json)",
    )

    # SHOW
    show_parser = policy_subparsers.add_parser(
        "show", help="Display policy metadata and content"
    )
    show_parser.add_argument("policy", help="Policy name (without .rego extension)")

    # INSTALL
    install_parser = policy_subparsers.add_parser(
        "install", help="Install builtin policy to user directory"
    )
    install_parser.add_argument(
        "policy", help="Policy name to install (without .rego extension)"
    )
    install_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing policy if already installed",
    )

    return policy_parser


def _add_attest_args(subparsers):
    """Add 'attest' subcommand arguments for generating attestations."""
    attest_parser = subparsers.add_parser(
        "attest",
        help="Generate SLSA attestation for scan results",
        description="""
Generate cryptographic attestation for findings using SLSA provenance v1.0.

The attestation proves:
- What was scanned (subject with multi-hash digests)
- How it was scanned (tools, profile, parameters)
- When it was scanned (timestamps)
- Where it was scanned (builder ID, CI context)

Example:
  jmo attest results/summaries/findings.json
  jmo attest findings.json --sign --rekor
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    attest_parser.add_argument("subject", help="File to attest (e.g., findings.json)")
    attest_parser.add_argument(
        "--output",
        "-o",
        help="Output path for attestation (default: <subject>.att.json)",
    )
    attest_parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign attestation with Sigstore (requires cosign)",
    )
    attest_parser.add_argument(
        "--rekor", action="store_true", help="Upload to Rekor transparency log"
    )
    attest_parser.add_argument(
        "--scan-args", help="JSON file with original scan arguments"
    )
    attest_parser.add_argument(
        "--tools", nargs="+", help="Tools used in scan (e.g., trivy semgrep)"
    )
    attest_parser.add_argument(
        "--human-logs",
        action="store_true",
        help="Use human-friendly colored logs instead of JSON",
    )
    attest_parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARN", "ERROR"], help="Set log level"
    )


def _add_verify_args(subparsers):
    """Add 'verify' subcommand arguments for verifying attestations."""
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify SLSA attestation for scan results",
        description="""
Verify cryptographic attestation and detect tampering.

Verification checks:
- Subject digest matches attestation
- Attestation format is valid
- Signature verification (if signed)
- Rekor transparency log (if published)

Exit codes:
  0 - Verification succeeded
  1 - Verification failed or tampering detected

Example:
  jmo verify findings.json
  jmo verify findings.json --rekor-check
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    verify_parser.add_argument("subject", help="File to verify (e.g., findings.json)")
    verify_parser.add_argument(
        "--attestation", "-a", help="Attestation file (default: <subject>.att.json)"
    )
    verify_parser.add_argument(
        "--rekor-check",
        action="store_true",
        help="Verify against Rekor transparency log",
    )
    verify_parser.add_argument(
        "--policy", help="Policy file for additional verification rules"
    )
    verify_parser.add_argument(
        "--human-logs",
        action="store_true",
        help="Use human-friendly colored logs instead of JSON",
    )
    verify_parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARN", "ERROR"], help="Set log level"
    )


def _add_diff_args(subparsers):
    """Add 'diff' subcommand arguments for comparing scans."""
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two security scans",
        description="""
Compare security scans to show new, resolved, and modified findings.

Supports three modes:
1. Auto mode: Auto-detect scans based on Git context (NEW in v1.0.0)
   jmo diff --auto

2. Directory mode: Compare scan result directories (default)
   jmo diff baseline-results/ current-results/

3. SQLite mode: Compare historical scan IDs
   jmo diff --scan abc123 --scan def456
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Auto-detection mode (NEW)
    diff_parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-detect baseline/current scans and suggest format based on Git context",
    )

    # Mode selection - positional directories OR --scan flags
    diff_parser.add_argument(
        "directories",
        nargs="*",
        help="Two directories to compare (baseline current)",
    )
    diff_parser.add_argument(
        "--scan",
        action="append",
        dest="scan_ids",
        help="SQLite scan ID (use twice: --scan abc123 --scan def456)",
    )

    # Output options
    diff_parser.add_argument(
        "--format",
        choices=["json", "md", "html", "sarif"],
        default="md",
        help="Output format (default: md)",
    )
    diff_parser.add_argument(
        "--output", type=Path, help="Output file path (default: stdout for md/json)"
    )

    # Modification detection (Decision 4)
    diff_parser.add_argument(
        "--no-modifications",
        action="store_true",
        help="Disable modification detection (faster)",
    )

    # Filtering
    diff_parser.add_argument(
        "--severity",
        help="Filter by severity (comma-separated): CRITICAL,HIGH",
    )
    diff_parser.add_argument(
        "--tool",
        help="Filter by tool (comma-separated): semgrep,trivy",
    )
    diff_parser.add_argument(
        "--only",
        choices=["new", "resolved", "modified"],
        help="Show only specific category",
    )

    # SQLite options
    diff_parser.add_argument(
        "--db",
        type=Path,
        help="Path to SQLite database (default: ~/.jmo/scans.db)",
    )

    return diff_parser


def parse_args():
    """Parse command-line arguments for jmo CLI."""
    ap = argparse.ArgumentParser(
        prog="jmo",
        description="JMo Security Audit Suite - Unified security scanning with 12+ tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
BEGINNER-FRIENDLY COMMANDS:
  wizard              Interactive wizard for guided security scanning
  fast                Quick scan with 3 best-in-class tools (5-8 min)
  balanced            Balanced scan with 8 production-ready tools (15-20 min)
  full                Comprehensive scan with all 12 tools (30-60 min)
  setup               Verify and install security tools

ADVANCED COMMANDS:
  scan                Run configured tools on repositories (low-level)
  report              Aggregate findings and emit reports
  ci                  Scan + report with failure thresholds (for CI/CD)
  adapters            Manage adapter plugins
  policy              Policy-as-Code management (install, validate, test, list, show)
  mcp-server          Start MCP server for AI-powered remediation
  build               Build Docker images (replaces make docker-build)

QUICK START:
  jmo wizard                         # Interactive guided scanning
  jmo fast --repo ./myapp            # Fast scan of single repository
  jmo balanced --repos-dir ~/repos   # Scan all repositories in directory
  jmo scan --help                    # Show advanced options

Documentation: https://docs.jmotools.com
        """,
    )
    ap.add_argument(
        "--version",
        action="version",
        version=f"JMo Security v{__version__}",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # Beginner-friendly commands
    _add_wizard_args(sub)
    _add_profile_args(sub, "fast", "Quick scan with 3 best-in-class tools (5-8 min)")
    _add_profile_args(
        sub, "balanced", "Balanced scan with 8 production-ready tools (15-20 min)"
    )
    _add_profile_args(sub, "full", "Comprehensive scan with all 12 tools (30-60 min)")
    _add_setup_args(sub)

    # Advanced commands
    _add_scan_args(sub)
    _add_report_args(sub)
    _add_ci_args(sub)
    _add_diff_args(sub)
    _add_attest_args(sub)  # SLSA attestation
    _add_verify_args(sub)  # Attestation verification
    _add_adapters_args(sub)
    _add_schedule_args(sub)
    _add_mcp_args(sub)
    _add_history_args(sub)
    _add_trends_args(sub)
    _add_policy_args(sub)  # Policy-as-Code commands
    _add_tools_args(sub)  # Tool management commands
    add_build_args(sub)  # Docker build commands

    try:
        return ap.parse_args()
    except SystemExit as e:
        import os

        # Only suppress exit(0) for help/version during pytest
        # Let errors (exit code != 0) propagate naturally
        if os.getenv("PYTEST_CURRENT_TEST") and e.code == 0:
            return argparse.Namespace()
        raise


def _iter_repos(args) -> list[Path]:
    repos: list[Path] = []
    if args.repo:
        p = Path(args.repo)
        if p.exists():
            repos.append(p)
    elif args.repos_dir:
        base = Path(args.repos_dir)
        if base.exists():
            repos.extend([p for p in base.iterdir() if p.is_dir()])
    elif args.targets:
        t = Path(args.targets)
        if t.exists():
            for line in t.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                p = Path(s)
                if p.exists():
                    repos.append(p)
    return repos


def _iter_images(args) -> list[str]:
    """Collect container images to scan."""
    images: list[str] = []
    if getattr(args, "image", None):
        images.append(args.image)
    if getattr(args, "images_file", None):
        p = Path(args.images_file)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                images.append(s)
    return images


def _iter_iac_files(args) -> list[tuple[str, Path]]:
    """Collect IaC files to scan. Returns list of (type, path) tuples."""
    iac_files: list[tuple[str, Path]] = []
    if getattr(args, "terraform_state", None):
        p = Path(args.terraform_state)
        if p.exists():
            iac_files.append(("terraform", p))
    if getattr(args, "cloudformation", None):
        p = Path(args.cloudformation)
        if p.exists():
            iac_files.append(("cloudformation", p))
    if getattr(args, "k8s_manifest", None):
        p = Path(args.k8s_manifest)
        if p.exists():
            iac_files.append(("k8s-manifest", p))
    return iac_files


def _iter_urls(args) -> list[str]:
    """Collect web URLs to scan."""
    urls: list[str] = []
    if getattr(args, "url", None):
        urls.append(args.url)
    if getattr(args, "urls_file", None):
        p = Path(args.urls_file)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                urls.append(s)
    if getattr(args, "api_spec", None):
        # API spec is handled separately but we track it as a special URL
        spec = args.api_spec
        if not spec.startswith("http://") and not spec.startswith("https://"):
            # Local file - check existence
            p = Path(spec)
            if p.exists():
                urls.append(f"file://{p.absolute()}")
        else:
            urls.append(spec)
    return urls


def _iter_gitlab_repos(args) -> list[dict[str, str]]:
    """Collect GitLab repos to scan. Returns list of repo metadata dicts."""
    import os

    gitlab_repos: list[dict[str, str]] = []
    gitlab_url = getattr(args, "gitlab_url", None) or "https://gitlab.com"
    gitlab_token = getattr(args, "gitlab_token", None) or os.getenv("GITLAB_TOKEN")

    if not gitlab_token:
        return []

    if getattr(args, "gitlab_repo", None):
        # Single repo: group/repo format
        parts = args.gitlab_repo.split("/")
        if len(parts) >= 2:
            gitlab_repos.append(
                {
                    "url": gitlab_url,
                    "group": parts[0],
                    "repo": "/".join(parts[1:]),
                    "full_path": args.gitlab_repo,
                }
            )
    elif getattr(args, "gitlab_group", None):
        # Group scan - need to fetch all repos in group
        # This will be implemented with API calls in the actual scan logic
        gitlab_repos.append(
            {
                "url": gitlab_url,
                "group": args.gitlab_group,
                "repo": "*",  # Wildcard for all repos in group
                "full_path": f"{args.gitlab_group}/*",
            }
        )

    return gitlab_repos


def _iter_k8s_resources(args) -> list[dict[str, str]]:
    """Collect Kubernetes resources to scan. Returns list of resource metadata dicts."""
    k8s_resources: list[dict[str, str]] = []

    k8s_context = getattr(args, "k8s_context", None)
    k8s_namespace = getattr(args, "k8s_namespace", None)
    k8s_all_namespaces = getattr(args, "k8s_all_namespaces", False)

    if k8s_context or k8s_namespace or k8s_all_namespaces:
        k8s_resources.append(
            {
                "context": k8s_context or "current",
                "namespace": k8s_namespace
                or ("*" if k8s_all_namespaces else "default"),
                "all_namespaces": str(k8s_all_namespaces),
            }
        )

    return k8s_resources


def _check_scan_tools(args, requested_tools: list[str]) -> tuple[list[str], list[str]]:
    """
    Check tool availability before scan and handle missing tools.

    This is the scan-time pre-flight check that:
    1. Detects which requested tools are installed
    2. If any are missing and not --allow-missing-tools, prompts user
    3. Offers to install missing tools or continue without them

    Args:
        args: Parsed command line arguments
        requested_tools: List of tool names requested for the scan

    Returns:
        Tuple of (available_tools, missing_tool_names)
        If user cancels, returns ([], []) to signal abort
    """
    import sys

    try:
        from scripts.cli.tool_manager import get_missing_tools_for_scan

        available, missing_statuses = get_missing_tools_for_scan(requested_tools)

        if not missing_statuses:
            # All tools available
            return available, []

        missing_names = [s.name for s in missing_statuses]

        # If --allow-missing-tools, just return available tools
        if getattr(args, "allow_missing_tools", False):
            return available, missing_names

        # Check if any tools are available
        if not available:
            _log(
                args,
                "ERROR",
                f"None of the requested tools are installed: {', '.join(missing_names)}",
            )
            print("\nRun 'jmo tools install' to install required tools.")
            return [], missing_names

        # Interactive prompt (skip if not a TTY)
        if not sys.stdin.isatty():
            # Non-interactive: use available tools
            return available, missing_names

        # Show what's missing
        print(
            f"\n{len(missing_statuses)} of {len(requested_tools)} tool(s) not installed:"
        )
        for status in missing_statuses[:5]:
            print(f"  - {status.name}")
        if len(missing_statuses) > 5:
            print(f"  ... and {len(missing_statuses) - 5} more")

        print(f"\n{len(available)} tool(s) available for scanning.")
        print("\nOptions:")
        print("  [1] Install missing tools now")
        print("  [2] Continue with available tools")
        print("  [3] Cancel scan")

        while True:
            try:
                choice = input("\nChoice [2]: ").strip() or "2"
            except (EOFError, KeyboardInterrupt):
                return [], missing_names

            if choice == "1":
                # Install missing tools
                return _install_and_retry(missing_statuses, available)
            elif choice == "2":
                return available, missing_names
            elif choice == "3":
                return [], missing_names
            else:
                print("Please enter 1, 2, or 3")

    except ImportError as e:
        # Tool manager not available - continue with all requested tools
        logger.debug(f"Tool check unavailable: {e}")
        return requested_tools, []
    except Exception as e:
        logger.warning(f"Tool check failed: {e}")
        return requested_tools, []


def _install_and_retry(
    missing_statuses: list,
    available: list[str],
) -> tuple[list[str], list[str]]:
    """
    Install missing tools and return updated available list.

    Args:
        missing_statuses: List of ToolStatus for missing tools
        available: Currently available tool names

    Returns:
        Tuple of (updated_available, still_missing)
    """
    try:
        from scripts.cli.tool_installer import ToolInstaller, InstallProgress

        print(f"\nInstalling {len(missing_statuses)} missing tool(s)...")

        installer = ToolInstaller()

        progress = InstallProgress(total=len(missing_statuses))
        still_missing = []

        for status in missing_statuses:
            print(f"  Installing {status.name}...", end=" ", flush=True)
            result = installer.install_tool(status.name)
            progress.add_result(result)
            if result.success:
                available.append(status.name)
                print("done")
            else:
                still_missing.append(status.name)
                print(f"failed ({result.message[:30]})")

        print()
        if not still_missing:
            print(f"All {progress.successful} tool(s) installed successfully!")
        else:
            print(f"{progress.successful} installed, {len(still_missing)} failed")

        return available, still_missing

    except ImportError as e:
        logger.warning(f"Tool installer unavailable: {e}")
        print(f"\nInstaller unavailable: {e}")
        return available, [s.name for s in missing_statuses]
    except Exception as e:
        logger.error(f"Installation failed: {e}")
        print(f"\nInstallation error: {e}")
        return available, [s.name for s in missing_statuses]


def _warn_critical_updates() -> None:
    """
    Show non-blocking warning if critical tools have updates.

    This is called at the start of scans to remind users about important updates.
    It does not block execution, just prints a warning.
    """
    import os

    # Skip in Docker (tools bundled in image)
    if os.environ.get("DOCKER_CONTAINER"):
        return

    try:
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        critical_outdated = manager.get_critical_outdated()

        if critical_outdated:
            _safe_print("\n" + "=" * 60)
            _safe_print("  CRITICAL TOOL UPDATES AVAILABLE")
            _safe_print("=" * 60)
            for status in critical_outdated[:3]:
                _safe_print(
                    f"  - {status.name}: {status.installed_version} -> {status.expected_version}"
                )
            if len(critical_outdated) > 3:
                _safe_print(f"  ... and {len(critical_outdated) - 3} more")
            _safe_print("\n  Run 'jmo tools update --critical-only' to update")
            _safe_print("=" * 60 + "\n")
    except ImportError:
        pass  # Tool manager not available
    except Exception as e:
        logger.debug(f"Critical update check failed: {e}")


def _check_first_run() -> bool:
    """Check if this is user's first time running jmo."""
    config_path = Path.home() / ".jmo" / "config.yml"
    if not config_path.exists():
        return True
    try:
        import yaml

        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
        return not config.get("onboarding_completed", False)
    except (FileNotFoundError, OSError) as e:
        logger.debug(f"Config file not found or inaccessible: {e}")
        return False
    except ImportError as e:
        logger.debug(f"PyYAML not available: {e}")
        return False
    except (yaml.YAMLError, ValueError, TypeError) as e:
        # YAML parsing errors, invalid config structure, type errors
        logger.debug(f"Config file parsing error: {e}")
        return False


def _collect_email_opt_in(args) -> None:
    """Non-intrusive email collection on first run."""
    import os
    import sys

    # Skip if not interactive (Docker, CI/CD, etc.)
    if not sys.stdin.isatty():
        return

    # Skip if running in Docker or CI environment
    if os.environ.get("JMO_NON_INTERACTIVE") or os.environ.get("CI"):
        return

    # Skip if running in a Docker container (detected by DOCKER_CONTAINER env)
    if os.environ.get("DOCKER_CONTAINER") == "1":
        return

    _safe_print("\n🎉 Welcome to JMo Security!\n")
    _safe_print("📧 Get notified about new features, updates, and security tips?")
    print("   (We'll never spam you. Unsubscribe anytime.)\n")

    try:
        email = input("   Enter email (or press Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        # Handle non-interactive environments gracefully
        return

    config_path = Path.home() / ".jmo" / "config.yml"
    config_path.parent.mkdir(exist_ok=True)

    if email and "@" in email:
        # Attempt to send welcome email (fails silently if resend not installed)
        try:
            from scripts.core.email_service import send_welcome_email, validate_email

            if validate_email(email):
                success = send_welcome_email(email, source="cli")

                # Save to config
                import yaml

                config = {
                    "email": email,
                    "email_opt_in": True,
                    "onboarding_completed": True,
                }
                with open(config_path, "w") as f:
                    yaml.dump(config, f)

                if success:
                    _safe_print(
                        "\n✅ Thanks! Check your inbox for a welcome message.\n"
                    )
                else:
                    _safe_print("\n✅ Thanks! You're all set.\n")
                    _log(
                        args,
                        "DEBUG",
                        "Email collection succeeded but welcome email not sent (resend may not be configured)",
                    )
            else:
                _safe_print("\n❌ Invalid email address. Skipping...\n")
                # Mark onboarding complete even if email invalid
                import yaml

                config = {"onboarding_completed": True}
                with open(config_path, "w") as f:
                    yaml.dump(config, f)
        except ImportError:
            # email_service module not available (resend not installed)
            _safe_print("\n✅ Thanks! You're all set.\n")
            import yaml

            config = {
                "email": email,
                "email_opt_in": True,
                "onboarding_completed": True,
            }
            with open(config_path, "w") as f:
                yaml.dump(config, f)
            _log(
                args,
                "DEBUG",
                "Email recorded but welcome email not sent (install resend: pip install resend)",
            )
        except (OSError, PermissionError, UnicodeEncodeError) as e:
            # File write errors - fail gracefully
            logger.debug(f"Failed to write config during email collection: {e}")
            _safe_print("\n✅ Thanks! You're all set.\n")
            import yaml

            config = {
                "email": email,
                "email_opt_in": True,
                "onboarding_completed": True,
            }
            with open(config_path, "w") as f:
                yaml.dump(config, f)
            _log(args, "DEBUG", f"Email collection error (non-blocking): {e}")
    else:
        _safe_print("\n👍 No problem! You can always add your email later with:")
        print("   jmo config --email your@email.com\n")

        # Mark onboarding complete even if skipped
        import yaml

        config = {"onboarding_completed": True}
        with open(config_path, "w") as f:
            yaml.dump(config, f)


def _show_kofi_reminder(args) -> None:
    """Show Ko-Fi support reminder every 5th scan (non-intrusive).

    Tracks scan count in ~/.jmo/config.yml and displays friendly reminder
    every 5 scans to support full-time development.
    """
    config_path = Path.home() / ".jmo" / "config.yml"
    config_path.parent.mkdir(exist_ok=True)

    # Load existing config
    config: dict[str, Any] = {}
    if config_path.exists():
        try:
            import yaml

            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except (ImportError, OSError) as e:
            logger.debug(f"Failed to load config file: {e}")
        except (yaml.YAMLError, ValueError, TypeError) as e:
            # YAML parsing errors, invalid config structure, type errors
            logger.debug(f"Config file parsing error: {e}")

    # Increment scan count
    scan_count = config.get("scan_count", 0) + 1
    config["scan_count"] = scan_count

    # Save updated config
    try:
        import yaml

        with open(config_path, "w") as f:
            yaml.safe_dump(config, f, default_flow_style=False)
    except (ImportError, OSError, PermissionError, UnicodeEncodeError) as e:
        logger.debug(
            f"Failed to save scan count to config: {e}"
        )  # Fail silently, don't block workflow

    # Show Ko-Fi message every 3rd scan
    if scan_count % 3 == 0:
        _safe_print(
            "\n"
            + "=" * 70
            + "\n"
            + "💚 Enjoying JMo Security? Support full-time development!\n"
            + "   → https://ko-fi.com/jmogaming\n"
            + "\n"
            + "   Your support funds ongoing development of this open-source\n"
            + "   security orchestrator and helps keep it free for everyone.\n"
            + "\n"
            + f"   You've run {scan_count} scans - thank you for using JMo Security!\n"
            + "=" * 70
            + "\n"
        )


def _get_max_workers(args, eff: dict, cfg) -> int | None:
    """Determine max_workers from CLI args, effective settings, env var, or config.

    Priority order:
    1. --threads CLI flag
    2. JMO_THREADS environment variable
    3. Profile threads setting
    4. Config file threads
    5. Auto-detect (75% of CPU cores, min 2, max 16)

    Returns:
        int: Number of worker threads, or None to let ThreadPoolExecutor decide

    """
    import os

    # Check effective settings (from CLI or profile)
    threads_val = eff.get("threads")
    if threads_val is not None:
        # Support 'auto' keyword
        if isinstance(threads_val, str) and threads_val.lower() == "auto":
            return _auto_detect_threads(args)
        return max(1, int(threads_val))

    # Check environment variable
    env_threads = os.getenv("JMO_THREADS")
    if env_threads:
        try:
            if env_threads.lower() == "auto":
                return _auto_detect_threads(args)
            return max(1, int(env_threads))
        except (ValueError, TypeError) as e:
            logger.debug(f"Invalid JMO_THREADS value: {e}")

    # Check config file
    if cfg.threads is not None:
        if isinstance(cfg.threads, str) and cfg.threads.lower() == "auto":
            return _auto_detect_threads(args)
        return max(1, int(cfg.threads))

    # Default: Auto-detect
    return _auto_detect_threads(args)


def _auto_detect_threads(args) -> int:
    """Auto-detect optimal thread count based on CPU cores.

    Wrapper around shared cpu_utils.auto_detect_threads() with logging.

    Args:
        args: CLI arguments (for logging)

    Returns:
        int: Optimal thread count

    """
    return _auto_detect_threads_shared(log_fn=lambda level, msg: _log(args, level, msg))


class ProgressTracker:
    """Simple progress tracker for scan operations (no external dependencies).

    Tracks completed/total targets and provides formatted progress updates.
    Thread-safe for concurrent scan operations.

    Features:
    - Spinner animation for running tools (distinguishes from completed)
    - Elapsed time display for long-running tools
    - Background refresh thread for smooth animation
    """

    # Suffixes for multi-phase tools (e.g., noseyparker-init, noseyparker-scan)
    # These phases should be counted as a single logical tool
    _PHASE_SUFFIXES = ("-init", "-scan", "-report")

    # Braille spinner frames for smooth animation
    _SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, total: int, args, total_tools: int = 0):
        """Initialize progress tracker.

        Args:
            total: Total number of targets to scan
            args: CLI arguments (for logging)
            total_tools: Total number of tools to run (for tool-level progress)

        """
        import threading

        self.total = total
        self.completed = 0
        self.args = args
        self._lock = threading.Lock()
        self._start_time: float | None = None
        # Tool-level progress tracking
        self.total_tools = total_tools
        self.tools_completed = 0
        self.tools_in_progress: set[str] = set()
        # Track completed logical tools (base names, not phases)
        self._completed_base_tools: set[str] = set()
        # Elapsed time tracking for running tools
        self._tool_start_times: dict[str, float] = {}
        # Spinner animation state
        self._spinner_idx = 0
        # Background refresh thread control
        self._stop_refresh = False
        self._refresh_thread: threading.Thread | None = None

    def _get_base_tool_name(self, tool_name: str) -> str:
        """Extract base tool name from a potentially phased tool name.

        Multi-phase tools like noseyparker run as:
        - noseyparker-init
        - noseyparker-scan
        - noseyparker-report

        All should be counted as one logical tool "noseyparker".

        Args:
            tool_name: The tool name (may include phase suffix)

        Returns:
            Base tool name without phase suffix
        """
        for suffix in self._PHASE_SUFFIXES:
            if tool_name.endswith(suffix):
                return tool_name[: -len(suffix)]
        return tool_name

    def start(self):
        """Start progress tracking timer and background refresh thread."""
        import time

        self._start_time = time.time()
        self._start_refresh_thread()

    def stop(self):
        """Stop the background refresh thread."""
        self._stop_refresh = True
        if self._refresh_thread and self._refresh_thread.is_alive():
            self._refresh_thread.join(timeout=0.5)

    def _start_refresh_thread(self):
        """Start background thread to refresh display every 250ms."""
        import threading

        def refresh_loop():
            import time

            while not self._stop_refresh:
                time.sleep(0.25)
                with self._lock:
                    if self.tools_in_progress:
                        self._refresh_display()

        self._stop_refresh = False
        self._refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self._refresh_thread.start()

    def _format_elapsed(self, elapsed: float) -> str:
        """Format elapsed time as human-readable string."""
        if elapsed < 60:
            return f"{int(elapsed)}s"
        else:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            return f"{mins}m{secs}s"

    def _refresh_display(self):
        """Refresh progress line with current elapsed time and spinner.

        Called by background thread to keep display updated during long-running tools.
        Must be called with self._lock held.
        """
        import sys
        import time

        if not self.tools_in_progress or self.total_tools <= 0:
            return

        # Show longest-running tool (most relevant for user waiting)
        oldest_tool = min(
            self.tools_in_progress,
            key=lambda t: self._tool_start_times.get(t, time.time()),
        )
        base_name = self._get_base_tool_name(oldest_tool)
        elapsed = time.time() - self._tool_start_times.get(oldest_tool, time.time())
        elapsed_str = self._format_elapsed(elapsed)

        spinner = self._SPINNER_FRAMES[self._spinner_idx % len(self._SPINNER_FRAMES)]
        self._spinner_idx += 1

        percentage = int((self.tools_completed / self.total_tools) * 100)
        progress_line = (
            f"\r[{self.tools_completed}/{self.total_tools}] "
            f"{spinner} {base_name} ({elapsed_str}) [{percentage}%]"
        )
        print(f"{progress_line:<70}", end="", file=sys.stderr, flush=True)

    def update(self, target_type: str, target_name: str, elapsed: float):
        """Update progress after completing a target scan.

        Args:
            target_type: Type of target (repo, image, url, etc.)
            target_name: Name/identifier of target
            elapsed: Elapsed time in seconds for this target

        """
        import time

        with self._lock:
            self.completed += 1
            percentage = int((self.completed / self.total) * 100)
            status_symbol = "✓" if elapsed >= 0 else "✗"

            # Calculate ETA
            if self._start_time and self.completed > 0:
                total_elapsed = time.time() - self._start_time
                avg_time_per_target = total_elapsed / self.completed
                remaining = self.total - self.completed
                eta_seconds = int(avg_time_per_target * remaining)
                eta_str = self._format_duration(eta_seconds)
            else:
                eta_str = "calculating..."

            # Format progress message
            message = (
                f"[{self.completed}/{self.total}] {status_symbol} {target_type}: {target_name} "
                f"({self._format_duration(int(elapsed))}) | "
                f"Progress: {percentage}% | ETA: {eta_str}"
            )

            _log(self.args, "INFO", message)

    def _format_duration(self, seconds: int) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            mins = seconds // 60
            secs = seconds % 60
            return f"{mins}m {secs}s"
        else:
            hours = seconds // 3600
            mins = (seconds % 3600) // 60
            return f"{hours}h {mins}m"

    def log(self, level: str, message: str) -> None:
        """Log message, clearing the \\r line first for clean output.

        Args:
            level: Log level (INFO, WARN, ERROR)
            message: Log message
        """
        import sys

        with self._lock:
            # Clear current \r line, print on new line
            print("\r" + " " * 70 + "\r", end="", file=sys.stderr, flush=True)
            print(f"[{level}] {message}", file=sys.stderr)

    def update_tool(
        self,
        tool_name: str,
        status: str,
        findings_count: int = 0,  # noqa: ARG002
        *,
        message: str = "",
        attempt: int = 1,
        max_attempts: int = 1,
        **kwargs,  # noqa: ARG002 - Forward compatibility
    ) -> None:
        """Update progress when a tool starts or completes.

        Multi-phase tools (e.g., noseyparker-init, noseyparker-scan, noseyparker-report)
        are counted as a single logical tool for progress display. This ensures the
        progress shows "12/12 tools" not "15/12 tools" when phases are involved.

        Args:
            tool_name: Name of the tool (may include phase suffix)
            status: "start"/"success"/"error"/"retrying"/"timeout"
            findings_count: Number of findings (unused for now)
            message: Optional message (e.g., timeout reason)
            attempt: Current attempt number (for retries)
            max_attempts: Maximum attempts configured
            **kwargs: Forward compatibility for future parameters
        """
        import sys

        # Get the base tool name (strip phase suffixes like -init, -scan, -report)
        base_tool_name = self._get_base_tool_name(tool_name)

        with self._lock:
            # Handle intermediate statuses (retrying/timeout)
            if status == "retrying":
                self.log(
                    "WARN",
                    f"{base_tool_name}: Retry {attempt}/{max_attempts} - {message}",
                )
                return  # Don't update completion count

            if status == "timeout":
                self.log(
                    "ERROR",
                    f"{base_tool_name}: Timed out after {max_attempts} attempts",
                )
                # Fall through to mark as failed

            if status == "start":
                import time

                self.tools_in_progress.add(tool_name)
                self._tool_start_times[tool_name] = time.time()

                # Show running tool with spinner (distinguishes from completed)
                if self.total_tools > 0:
                    percentage = int((self.tools_completed / self.total_tools) * 100)
                    spinner = self._SPINNER_FRAMES[
                        self._spinner_idx % len(self._SPINNER_FRAMES)
                    ]
                    self._spinner_idx += 1
                    progress_line = (
                        f"\r[{self.tools_completed}/{self.total_tools}] "
                        f"{spinner} {base_tool_name} (0s) [{percentage}%]"
                    )
                    print(f"{progress_line:<70}", end="", file=sys.stderr, flush=True)
            else:
                # Tool/phase completed (success, error, or timeout)
                self.tools_in_progress.discard(tool_name)
                # Clean up start time
                self._tool_start_times.pop(tool_name, None)

                # Only count this as a completed tool if the base tool hasn't been
                # counted yet. This handles multi-phase tools correctly.
                if base_tool_name not in self._completed_base_tools:
                    self._completed_base_tools.add(base_tool_name)
                    self.tools_completed += 1

                if self.total_tools > 0:
                    percentage = int((self.tools_completed / self.total_tools) * 100)
                    # Checkmark for success, X for failure - clearly shows COMPLETED
                    status_icon = "✓" if status == "success" else "✗"

                    # Show inline progress (overwrites previous line)
                    # Display the base tool name for consistency
                    progress_line = (
                        f"\r[{self.tools_completed}/{self.total_tools}] "
                        f"{status_icon} {base_tool_name} [{percentage}%]"
                    )
                    # Pad to clear leftover characters
                    print(f"{progress_line:<70}", end="", file=sys.stderr, flush=True)

                    # Print newline and stop refresh when all tools complete
                    if self.tools_completed >= self.total_tools:
                        self._stop_refresh = True
                        print("", file=sys.stderr)


def cmd_scan(args) -> int:
    """Scan security targets (repos, images, IaC, URLs, GitLab, K8s) with multiple tools.

    REFACTORED VERSION: Uses scan_orchestrator and scan_jobs modules for clean separation.
    Complexity reduced from 321 to ~15 (95% improvement).
    """
    # Track scan start time for telemetry
    import time

    from scripts.core.telemetry import (
        should_show_telemetry_banner,
        show_telemetry_banner,
    )

    # Clear tool warning deduplication tracker at scan start (Fix 1.3 - Issue #3)
    from scripts.cli.scan_utils import clear_tool_warnings

    clear_tool_warnings()

    scan_start_time = time.time()

    # Show telemetry banner on first 3 scans (opt-out model)
    if should_show_telemetry_banner():
        show_telemetry_banner(mode="cli")

    # Check for critical tool updates (non-blocking warning)
    _warn_critical_updates()

    # Check for first-run email prompt (non-blocking)
    if _check_first_run():
        _collect_email_opt_in(args)

    # Load effective settings with profile/per-tool overrides
    eff = _effective_scan_settings(args)
    cfg = load_config(args.config)
    tools = eff["tools"]
    results_dir = Path(args.results_dir)

    # Security: Validate tool names to prevent command injection
    import re

    invalid_chars = re.compile(r"[;&|`$()<>]")
    for tool in tools:
        if invalid_chars.search(tool):
            _log(
                args,
                "ERROR",
                "Invalid tool name: contains shell metacharacters",
            )
            return 1  # Return non-zero exit code for security rejection

    # Tool availability pre-flight check (skip in Docker mode)
    import os

    missing_tools: list[str] = []
    if not os.environ.get("DOCKER_CONTAINER"):
        tools, missing_tools = _check_scan_tools(args, tools)
        if not tools:
            # All tools missing and user cancelled
            return 1
        if missing_tools:
            _log(
                args,
                "WARN",
                f"Skipping {len(missing_tools)} missing tool(s): {', '.join(missing_tools)}",
            )

    # Create ScanConfig from effective settings
    scan_config = ScanConfig(
        tools=tools,
        results_dir=results_dir,
        timeout=int(eff["timeout"] or 600),
        retries=int(eff["retries"] or 0),
        max_workers=_get_max_workers(args, eff, cfg),
        include_patterns=eff.get("include", []) or [],
        exclude_patterns=eff.get("exclude", []) or [],
        allow_missing_tools=getattr(args, "allow_missing_tools", False),
    )

    # Use ScanOrchestrator to discover all targets
    orchestrator = ScanOrchestrator(scan_config)
    targets = orchestrator.discover_targets(args)

    # Validate at least one target
    if targets.is_empty():
        _log(
            args,
            "WARN",
            "No scan targets provided (repos, images, IaC files, URLs, GitLab, or K8s resources).",
        )
        return 0

    # Log scan targets summary
    _log(args, "INFO", f"Scan targets: {targets.summary()}")

    # Send scan.started telemetry event
    import os

    mode = "wizard" if getattr(args, "from_wizard", False) else "cli"
    if os.environ.get("DOCKER_CONTAINER") == "1":
        mode = "docker"

    profile_name = (
        getattr(args, "profile_name", None) or cfg.default_profile or "custom"
    )
    total_targets = (
        len(targets.repos)
        + len(targets.images)
        + len(targets.iac_files)
        + len(targets.urls)
        + len(targets.gitlab_repos)
        + len(targets.k8s_resources)
    )
    num_target_types = sum(
        [
            len(targets.repos) > 0,
            len(targets.images) > 0,
            len(targets.iac_files) > 0,
            len(targets.urls) > 0,
            len(targets.gitlab_repos) > 0,
            len(targets.k8s_resources) > 0,
        ]
    )

    send_event(
        "scan.started",
        {
            "mode": mode,
            "profile": profile_name,
            "tools": tools,
            "target_types": {
                "repos": len(targets.repos),
                "images": len(targets.images),
                "urls": len(targets.urls),
                "iac": len(targets.iac_files),
                "gitlab": len(targets.gitlab_repos),
                "k8s": len(targets.k8s_resources),
            },
            # Business metrics
            "ci_detected": detect_ci_environment(),
            "multi_target_scan": num_target_types > 1,
            "compliance_usage": True,  # Always enabled in v0.5.1+
            "total_targets_bucket": bucket_targets(total_targets),
            "scan_frequency_hint": infer_scan_frequency(),
        },
        {},
        version=__version__,
    )

    # Setup results directories for each target type
    orchestrator.setup_results_directories(targets)

    # Prepare per-tool config
    per_tool_config = eff.get("per_tool", {}) or {}

    # Setup signal handling for graceful shutdown
    stop_flag = {"stop": False}

    def _handle_stop(signum, frame):
        stop_flag["stop"] = True
        _log(
            args,
            "WARN",
            "Received stop signal. Finishing current scans, then exiting...",
        )

    import signal

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    # Initialize progress tracker with tool count
    # Use Rich progress display for wizard scans with human-readable output
    total_tools = len(tools)
    use_rich_progress = (
        getattr(args, "from_wizard", False)
        and getattr(args, "human_logs", False)
        and sys.stderr.isatty()
    )

    # Log scan start message with context about tools being used
    # Use ToolStatusSummary for consistent counts with wizard display
    profile_name = getattr(args, "profile_name", None) or cfg.default_profile
    try:
        from scripts.cli.tool_manager import ToolManager

        tm = ToolManager()
        summary = tm.get_tool_summary(profile_name)  # type: ignore[arg-type]
        platform_applicable = summary.platform_applicable
    except Exception:
        platform_applicable = total_tools  # Fallback to actual tool count

    skipped_count = len(missing_tools) if missing_tools else 0
    if skipped_count > 0:
        # Provide context about skipped tools with consistent denominator
        _log(
            args,
            "INFO",
            f"Starting scan with {total_tools}/{platform_applicable} tools for {total_targets} target(s) "
            f"({skipped_count} skipped: {', '.join(missing_tools[:3])}{'...' if skipped_count > 3 else ''})",
        )
    else:
        _log(
            args,
            "INFO",
            f"Starting scan with {total_tools}/{platform_applicable} tools for {total_targets} target(s)...",
        )

    if use_rich_progress:
        # Use Rich-based progress tracker for clean, thread-safe display
        from scripts.cli.rich_progress import RichScanProgressTracker

        rich_progress = RichScanProgressTracker(
            total_targets=total_targets,
            total_tools=total_tools,
            args=args,
        )

        # Execute scans with Rich progress context
        try:
            with rich_progress:
                all_results = orchestrator.scan_all(
                    targets,
                    per_tool_config,
                    progress_callback=rich_progress.update,
                    tool_progress_callback=rich_progress.update_tool,
                )
        except KeyboardInterrupt:
            _log(args, "WARN", "Scan interrupted by user")
            return 130
        except Exception as e:
            _log(args, "ERROR", f"Scan failed: {e}")
            if not scan_config.allow_missing_tools:
                raise
            return 1
    else:
        # Use original carriage-return based progress tracker
        progress = ProgressTracker(total_targets, args, total_tools=total_tools)
        progress.start()

        # Create progress callback for orchestrator (target-level)
        def progress_callback(target_type, target_id, statuses):
            """Update progress tracker when scan completes."""
            progress.update(target_type, target_id, elapsed=1.0)

        # Create tool-level progress callback
        def tool_progress_callback(
            tool_name: str, status: str, findings_count: int = 0, **kwargs
        ):
            """Update progress tracker when individual tool starts/completes."""
            progress.update_tool(tool_name, status, findings_count)

        # Execute scans via orchestrator (replaces 158 lines of inline logic)
        try:
            all_results = orchestrator.scan_all(
                targets,
                per_tool_config,
                progress_callback,
                tool_progress_callback=tool_progress_callback,
            )
        except KeyboardInterrupt:
            _log(args, "WARN", "Scan interrupted by user")
            return 130
        except Exception as e:
            _log(args, "ERROR", f"Scan failed: {e}")
            if not scan_config.allow_missing_tools:
                raise
            return 1

    # Show Ko-Fi support reminder
    _show_kofi_reminder(args)

    # Send scan.completed telemetry event
    scan_duration = time.time() - scan_start_time
    tools_succeeded = sum(1 for _, statuses in all_results if any(statuses.values()))
    tools_failed = sum(1 for _, statuses in all_results if not all(statuses.values()))

    send_event(
        "scan.completed",
        {
            "mode": mode,
            "profile": profile_name,
            "duration_bucket": bucket_duration(scan_duration),
            "tools_succeeded": tools_succeeded,
            "tools_failed": tools_failed,
            "total_findings_bucket": bucket_findings(
                0
            ),  # Will be counted in report phase
        },
        {},
        version=__version__,
    )

    _log(args, "INFO", f"Scan complete. Results written to {results_dir}")

    # Write scan metadata for report phase (Bug #3 fix: preserve profile name)
    scan_metadata_path = results_dir / ".scan_metadata.json"
    scan_metadata = {
        "profile": profile_name,
        "tools": tools,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_count": total_targets,
    }
    scan_metadata_path.write_text(json.dumps(scan_metadata), encoding="utf-8")

    # BUG #2 FIX: Automatically run report phase to aggregate findings and store history
    # This ensures --no-store-history flag (default: enabled) actually works
    _log(args, "INFO", "Running report phase to aggregate findings...")

    # Add missing report-specific arguments to namespace
    if not hasattr(args, "results_dir_pos"):
        args.results_dir_pos = None
    if not hasattr(args, "results_dir_opt"):
        args.results_dir_opt = str(results_dir)
    if not hasattr(args, "out"):
        args.out = None  # Will default to results_dir/summaries
    if not hasattr(args, "fail_on"):
        args.fail_on = None
    if not hasattr(args, "profile"):
        args.profile = False
    if not hasattr(args, "threads"):
        args.threads = None
    if not hasattr(args, "policies"):
        args.policies = None
    if not hasattr(args, "allow_missing_tools"):
        args.allow_missing_tools = False

    report_code = _cmd_report_impl(args, _log)

    # Return report exit code if it failed, otherwise 0 (scan succeeded)
    return report_code if report_code != 0 else 0


def cmd_report(args) -> int:
    """Wrapper for report orchestrator."""
    return _cmd_report_impl(args, _log)


def cmd_ci(args) -> int:
    """Wrapper for CI orchestrator."""
    return _cmd_ci_impl(args, cmd_scan, _cmd_report_impl)


def cmd_adapters(args) -> int:
    """Handle 'jmo adapters' subcommand for plugin management."""
    from scripts.core.plugin_loader import get_plugin_registry, get_available_adapters

    if args.adapters_command == "list":
        # List all available adapters (lazy-loads each to get metadata)
        registry = get_plugin_registry()
        available = get_available_adapters()

        print(f"Found {len(available)} adapter plugins:\n")

        for name in sorted(available):
            # Trigger lazy load to get metadata
            adapter = registry.get(name)
            if adapter:
                metadata = registry.get_metadata(name)
                if metadata:
                    print(f"  {name:<15} v{metadata.version:<8} {metadata.description}")
                else:
                    print(f"  {name:<15} (loaded, no metadata)")
            else:
                print(f"  {name:<15} (failed to load)")

        return 0

    elif args.adapters_command == "validate":
        # Validate specific adapter file
        plugin_file = Path(args.file)
        if not plugin_file.exists():
            print(f"Error: File not found: {plugin_file}")
            return 1

        try:
            # Try to load plugin
            from scripts.core.plugin_loader import PluginLoader, PluginRegistry

            plugin_registry = PluginRegistry()
            loader = PluginLoader(plugin_registry)
            loader._load_plugin(plugin_file)

            _safe_print(f"✅ Valid plugin: {plugin_file}")
            return 0
        except Exception as e:
            _safe_print(f"❌ Invalid plugin: {e}")
            return 1

    return 0


def cmd_wizard(args):
    """Run interactive wizard for guided scanning."""
    # Import wizard module
    wizard_script = Path(__file__).resolve().parent / "wizard.py"
    if not wizard_script.exists():
        sys.stderr.write("ERROR: wizard.py not found\n")
        return 1

    # Import and run wizard
    sys.path.insert(0, str(wizard_script.parent))
    from wizard import run_wizard

    # Determine execution mode from flags
    # --docker means use_docker=True, --native means use_docker=False
    # Neither flag means None (let wizard detect/prompt)
    use_docker = None
    if getattr(args, "docker", False):
        use_docker = True
    elif getattr(args, "native", False):
        use_docker = False

    # Handle --mode diff: delegate to diff wizard
    if getattr(args, "mode", "scan") == "diff":
        from wizard import run_diff_wizard

        return run_diff_wizard(
            use_docker=use_docker or False,
            yes=getattr(args, "yes", False),
            baseline=getattr(args, "baseline", None),
            current=getattr(args, "current", None),
        )

    return run_wizard(
        yes=args.yes,
        emit_script=args.emit_script,
        emit_make=args.emit_make_target,
        emit_gha=args.emit_gha,
        analyze_trends=getattr(args, "analyze_trends", False),
        export_trends_html=getattr(args, "export_trends_html", False),
        export_trends_json=getattr(args, "export_trends_json", False),
        policies=getattr(args, "policies", None),
        skip_policies=getattr(args, "skip_policies", False),
        db_path=getattr(args, "db", None),
        # Preset options for automation
        profile=getattr(args, "profile", None),
        target_type=getattr(args, "target_type", None),
        target=getattr(args, "target", None),
        use_docker=use_docker,
        auto_fix=getattr(args, "auto_fix", False),
        install_deps=getattr(args, "install_deps", False),
        threads=getattr(args, "threads", None),
        timeout=getattr(args, "timeout", None),
        fail_on=getattr(args, "fail_on", None),
        results_dir=getattr(args, "results_dir", None),
    )


def cmd_setup(args):
    """Run tool verification and installation.

    This is a wrapper around `jmo tools` commands for backwards compatibility.
    Replaces the previous bash script implementation to work cross-platform.
    """
    import argparse

    from scripts.cli.tool_commands import cmd_tools_check, cmd_tools_install

    # --print-commands: Show what would be installed without installing
    if args.print_commands:
        # Create args for tools install --dry-run --print-script
        tools_args = argparse.Namespace(
            profile="balanced",
            tools=[],
            dry_run=False,
            print_script=True,
            yes=True,
            sequential=False,
            jobs=4,
        )
        return cmd_tools_install(tools_args)

    # --auto-install: Install missing tools
    if args.auto_install:
        tools_args = argparse.Namespace(
            profile="balanced",
            tools=[],
            dry_run=False,
            print_script=False,
            yes=True,  # Non-interactive
            sequential=False,
            jobs=4,
            force=getattr(args, "force_reinstall", False),
        )
        rc = cmd_tools_install(tools_args)
        if rc != 0 and args.strict:
            sys.stderr.write("ERROR: Tool setup failed\n")
        return rc

    # Default: Check tool status
    tools_args = argparse.Namespace(
        profile="balanced",
        tools=[],
        json=False,
    )
    rc = cmd_tools_check(tools_args)

    # In strict mode, exit non-zero if tools are missing
    if args.strict and rc != 0:
        sys.stderr.write("ERROR: Some tools are missing (strict mode)\n")
        return 1

    return rc


def cmd_profile(args, profile_name: str):
    """Run scan with specific profile (fast/balanced/full)."""
    # Map profile names
    profile_map = {
        "fast": "fast",
        "balanced": "balanced",
        "full": "deep",
    }

    actual_profile = profile_map.get(profile_name, "balanced")

    # Create a modified args object for cmd_ci
    # Copy all attributes from args
    ci_args = argparse.Namespace(**vars(args))

    # Set profile-specific attributes
    ci_args.cmd = "ci"  # Route through CI command for scan + report
    ci_args.profile_name = actual_profile
    ci_args.allow_missing_tools = not args.strict

    # Run CI command (scan + report + threshold check)
    exit_code = cmd_ci(ci_args)

    # Open results if not disabled
    if not args.no_open and exit_code == 0:
        _open_results(args)

    return exit_code


def _check_mcp_dependencies() -> tuple[bool, str | None]:
    """Check if MCP dependencies are properly installed.

    Returns:
        Tuple of (is_ok, error_message). If is_ok is True, error_message is None.
    """
    # Check 1: Is pydantic v2+ installed? (MCP requires TypeAdapter from pydantic v2)
    import pydantic

    if not hasattr(pydantic, "TypeAdapter"):
        return False, "pydantic_v1"

    # Check 2: Is MCP SDK installed?
    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
    except ImportError:
        return False, "mcp_missing"

    return True, None


def _prompt_install_dependency(dep_type: str) -> bool:
    """Prompt user to install missing dependency and run pip install if confirmed.

    Args:
        dep_type: Either 'pydantic_v1' or 'mcp_missing'

    Returns:
        True if installation was attempted, False if user declined.
    """
    import subprocess

    if dep_type == "pydantic_v1":
        sys.stderr.write(
            "\n⚠️  MCP requires pydantic v2+, but you have pydantic v1 installed.\n"
        )
        sys.stderr.write(
            "   This is a common issue when other packages pin pydantic to v1.\n\n"
        )
        package = "pydantic>=2.11.0"
    else:
        sys.stderr.write("\n⚠️  MCP SDK is not installed.\n\n")
        package = "mcp[cli]>=1.0.0"

    try:
        response = input(f"Install {package}? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False

    if response in ("", "y", "yes"):
        sys.stderr.write(f"\nInstalling {package}...\n")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                sys.stderr.write(f"✓ {package} installed successfully!\n\n")
                return True
            else:
                sys.stderr.write(f"✗ Installation failed: {result.stderr[:200]}\n")
                sys.stderr.write(f"  Try manually: pip install '{package}'\n")
                return False
        except subprocess.TimeoutExpired:
            sys.stderr.write("✗ Installation timed out. Try manually.\n")
            return False
    else:
        sys.stderr.write(f"\nSkipped. To install manually: pip install '{package}'\n")
        return False


def cmd_mcp_server(args):
    """Start MCP server for AI-powered remediation."""
    import os
    from pathlib import Path

    # Check MCP dependencies before attempting import
    is_ok, dep_issue = _check_mcp_dependencies()
    if not is_ok and dep_issue:
        if _prompt_install_dependency(dep_issue):
            # Re-check after installation
            is_ok, dep_issue = _check_mcp_dependencies()
            if not is_ok:
                sys.stderr.write(f"\n✗ Dependencies still not satisfied: {dep_issue}\n")
                sys.stderr.write(
                    "  You may need to restart your terminal or check for conflicts.\n"
                )
                sys.stderr.write("  Run: pip check | grep pydantic\n")
                return 1
        else:
            return 1

    # Set environment variables for MCP server configuration
    os.environ["MCP_RESULTS_DIR"] = str(Path(args.results_dir).resolve())
    os.environ["MCP_REPO_ROOT"] = str(Path(args.repo_root).resolve())

    if args.api_key:
        os.environ["MCP_API_KEY"] = args.api_key

    # Configure logging based on args
    if args.human_logs:
        os.environ["MCP_HUMAN_LOGS"] = "1"
    if args.log_level:
        os.environ["MCP_LOG_LEVEL"] = args.log_level

    try:
        # Import MCP server (lazy import to avoid startup cost)
        from scripts.jmo_mcp.jmo_server import mcp

        # Log server start info
        sys.stderr.write("Starting JMo Security MCP Server...\n")
        sys.stderr.write(f"Results directory: {os.environ['MCP_RESULTS_DIR']}\n")
        sys.stderr.write(f"Repository root: {os.environ['MCP_REPO_ROOT']}\n")
        sys.stderr.write("Transport: stdio (for Claude Desktop, GitHub Copilot)\n")
        sys.stderr.write("\nServer ready. AI tools can now connect.\n")
        sys.stderr.write("Press Ctrl+C to stop.\n\n")

        # Run MCP server (blocking call - uses stdio transport by default)
        mcp.run()

        return 0

    except ImportError as e:
        sys.stderr.write("ERROR: MCP SDK not installed.\n")
        sys.stderr.write("Install with: pip install 'mcp[cli]>=1.0.0'\n")
        sys.stderr.write("Or: uv add 'mcp[cli]>=1.0.0'\n")
        sys.stderr.write(f"\nDetails: {e}\n")
        return 1
    except FileNotFoundError as e:
        sys.stderr.write("ERROR: Scan results not found.\n")
        sys.stderr.write("Run a scan first: jmo scan --repo <path>\n")
        sys.stderr.write(f"\nDetails: {e}\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("\n\nMCP server stopped by user.\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"ERROR: MCP server failed: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def _open_results(args):
    """Open scan results in browser/editor."""
    import os
    import shutil
    import subprocess  # nosec B404

    results_dir = Path(args.results_dir) / "summaries"
    if not results_dir.exists():
        return

    html = results_dir / "dashboard.html"
    md = results_dir / "SUMMARY.md"

    opener = None
    if sys.platform.startswith("linux"):
        opener = shutil.which("xdg-open")
    elif sys.platform == "darwin":
        opener = shutil.which("open")
    elif os.name == "nt":
        opener = "start"

    paths = [p for p in [html, md] if p.exists()]
    if not paths:
        return

    # Allowlist for safety
    allowed_openers = {"xdg-open", "open", "start"}
    opener_name = (
        os.path.basename(opener) if opener and os.path.isabs(opener) else opener
    )

    if opener and opener_name in allowed_openers:
        for p in paths:
            try:
                if opener == "start":
                    os.startfile(str(p))  # nosec B606
                else:
                    subprocess.Popen(  # nosec B603
                        [opener, str(p)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
            except Exception:
                pass


def cmd_attest(args) -> int:
    """Generate attestation for scan results.

    Args:
        args: Parsed command-line arguments

    Returns:
        0 on success, non-zero on error

    """
    import json

    subject_path = Path(args.subject)
    if not subject_path.exists():
        _log(args, "ERROR", f"Subject file not found: {args.subject}")
        return 1

    # Load scan arguments if provided
    scan_args = {}
    if hasattr(args, "scan_args") and args.scan_args:
        with open(args.scan_args) as f:
            scan_args = json.load(f)

    # Get tools list
    tools = getattr(args, "tools", None) or scan_args.get("tools", [])

    # Generate provenance
    from scripts.core.attestation.provenance import ProvenanceGenerator

    generator = ProvenanceGenerator()
    statement = generator.generate(
        findings_path=subject_path,
        profile=scan_args.get("profile_name", "default"),
        tools=tools,
        targets=scan_args.get("repos", []),
    )

    # Determine output path
    if hasattr(args, "output") and args.output:
        output_path = args.output
    else:
        output_path = str(subject_path) + ".att.json"

    # Save attestation
    attestation_path = Path(output_path)
    attestation_path.parent.mkdir(parents=True, exist_ok=True)
    attestation_path.write_text(json.dumps(statement, indent=2))

    _log(args, "INFO", f"Generated attestation: {output_path}")

    # Sign if requested (Phase 3: implemented)
    if hasattr(args, "sign") and args.sign:
        try:
            from scripts.core.attestation.signer import SigstoreSigner

            _log(args, "INFO", "Signing attestation with Sigstore...")
            signer = SigstoreSigner()
            sign_result = signer.sign(str(attestation_path))

            _log(args, "INFO", "✅ Attestation signed successfully")
            _log(args, "INFO", f"  Signature: {sign_result['signature_path']}")
            _log(args, "INFO", f"  Certificate: {sign_result['certificate_path']}")
            _log(args, "INFO", f"  Bundle: {sign_result['bundle_path']}")
            if sign_result.get("rekor_entry"):
                _log(args, "INFO", f"  Rekor entry: {sign_result['rekor_entry']}")

        except Exception as e:
            _log(args, "ERROR", f"Signing failed: {e}")
            return 1

    # Note: Rekor upload happens automatically during signing
    if (
        hasattr(args, "rekor")
        and args.rekor
        and not (hasattr(args, "sign") and args.sign)
    ):
        _log(
            args,
            "WARN",
            "Rekor upload requires --sign flag (signing automatically uploads to Rekor)",
        )

    return 0


def cmd_verify(args) -> int:
    """Verify attestation for scan results.

    Args:
        args: Parsed command-line arguments

    Returns:
        0 if verification succeeds, non-zero on error or tampering

    """
    from scripts.core.attestation.verifier import AttestationVerifier

    subject_path = Path(args.subject)
    if not subject_path.exists():
        _log(args, "ERROR", f"Subject file not found: {args.subject}")
        return 1

    # Determine attestation path
    if hasattr(args, "attestation") and args.attestation:
        attestation_path = args.attestation
    else:
        attestation_path = str(subject_path) + ".att.json"

    if not Path(attestation_path).exists():
        _log(args, "ERROR", f"Attestation not found: {attestation_path}")
        return 1

    # Create verifier
    verifier = AttestationVerifier()

    # Verify attestation
    result = verifier.verify(
        subject_path=str(subject_path),
        attestation_path=attestation_path,
        check_rekor=getattr(args, "rekor_check", False),
        policy_path=getattr(args, "policy", None),
    )

    if result.is_valid:
        _log(args, "INFO", "✅ Attestation verified successfully")
        _log(args, "INFO", f"  Subject: {result.subject_name}")
        _log(args, "INFO", f"  SHA-256: {result.subject_digest}")
        _log(args, "INFO", f"  Builder: {result.builder_id}")
        _log(args, "INFO", f"  Build time: {result.build_time}")

        if result.rekor_entry:
            _log(args, "INFO", f"  Rekor entry: {result.rekor_entry}")

        return 0
    else:
        _log(args, "ERROR", "❌ Attestation verification FAILED")
        _log(args, "ERROR", f"  Reason: {result.error_message}")

        if result.tamper_detected:
            _log(args, "ERROR", "  ⚠️  TAMPER DETECTED - Subject has been modified!")

        return 1


def main():
    args = parse_args()

    # Handle empty namespace (--help called during pytest)
    if not hasattr(args, "cmd"):
        return 0

    # Route to appropriate command handler
    if args.cmd == "wizard":
        return cmd_wizard(args)
    elif args.cmd == "setup":
        return cmd_setup(args)
    elif args.cmd in ("fast", "balanced", "full"):
        return cmd_profile(args, args.cmd)
    elif args.cmd == "report":
        return cmd_report(args)
    elif args.cmd == "scan":
        return cmd_scan(args)
    elif args.cmd == "ci":
        return cmd_ci(args)
    elif args.cmd == "adapters":
        return cmd_adapters(args)
    elif args.cmd == "schedule":
        return cmd_schedule(args)
    elif args.cmd == "mcp-server":
        return cmd_mcp_server(args)
    elif args.cmd == "history":
        return cmd_history(args)
    elif args.cmd == "trends":
        return cmd_trends(args)
    elif args.cmd == "diff":
        return cmd_diff(args)
    elif args.cmd == "attest":
        return cmd_attest(args)
    elif args.cmd == "verify":
        return cmd_verify(args)
    elif args.cmd == "policy":
        return cmd_policy(args)
    elif args.cmd == "tools":
        from scripts.cli.tool_commands import cmd_tools

        return cmd_tools(args)
    elif args.cmd == "build":
        return cmd_build(args)
    else:
        sys.stderr.write(f"Unknown command: {args.cmd}\n")
        return 1


def _log(args, level: str, message: str) -> None:
    import json
    from datetime import datetime, timezone

    level = level.upper()
    cfg_level = None
    try:
        cfg = load_config(getattr(args, "config", None))
        cfg_level = getattr(cfg, "log_level", None)
    except (FileNotFoundError, ConfigurationException, AttributeError) as e:
        logger.debug(f"Config loading failed in _log: {e}")
        cfg_level = None
    cli_level = getattr(args, "log_level", None)
    effective = (cli_level or cfg_level or "INFO").upper()
    rank = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
    if rank.get(level, 20) < rank.get(effective, 20):
        return
    if getattr(args, "human_logs", False):
        color = {
            "DEBUG": "\x1b[36m",
            "INFO": "\x1b[32m",
            "WARN": "\x1b[33m",
            "ERROR": "\x1b[31m",
        }.get(level, "")
        reset = "\x1b[0m"
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        # Windows-safe Unicode handling for stderr
        safe_message = message
        try:
            encoding = getattr(sys.stderr, "encoding", None) or "utf-8"
            if encoding.lower() in ("cp1252", "ascii", "latin-1", "iso-8859-1"):
                for unicode_char, ascii_fallback in _UNICODE_FALLBACKS.items():
                    safe_message = safe_message.replace(unicode_char, ascii_fallback)
        except (AttributeError, LookupError):
            pass
        sys.stderr.write(f"{color}{level:5}{reset} {ts} {safe_message}\n")
        return
    rec = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "level": level,
        "msg": message,
    }
    sys.stderr.write(json.dumps(rec) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
