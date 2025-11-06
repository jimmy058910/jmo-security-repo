#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from scripts.core.exceptions import (
    ConfigurationException,
)
from scripts.core.config import load_config
from scripts.cli.report_orchestrator import cmd_report as _cmd_report_impl
from scripts.cli.ci_orchestrator import cmd_ci as _cmd_ci_impl
from scripts.cli.schedule_commands import cmd_schedule
from scripts.cli.history_commands import cmd_history
from scripts.cli.diff_commands import cmd_diff
from scripts.cli.trend_commands import cmd_trends

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
__version__ = "0.7.0-dev"  # Will be updated to 0.7.0 at release


def _merge_dict(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a) if a else {}
    if b:
        out.update(b)
    return out


def _effective_scan_settings(args) -> dict[str, Any]:
    """Compute effective scan settings from CLI, config, and optional profile.

    Returns dict with keys: tools, threads, timeout, include, exclude, retries, per_tool
    """
    cfg = load_config(getattr(args, "config", None))
    profile_name = getattr(args, "profile_name", None) or cfg.default_profile
    profile = {}
    if profile_name and isinstance(cfg.profiles, dict):
        profile = cfg.profiles.get(profile_name, {}) or {}
    tools = getattr(args, "tools", None) or profile.get("tools") or cfg.tools
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
    return {
        "tools": tools,
        "threads": threads,
        "timeout": timeout,
        "include": include,
        "exclude": exclude,
        "retries": max(0, int(retries or 0)),
        "per_tool": per_tool,
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
        "--store-history",
        action="store_true",
        help="Store scan results in history database (.jmo/history.db) after completion",
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
        "--emit-script",
        action="store_true",
        help="Emit shell script instead of running",
    )
    wizard_parser.add_argument(
        "--emit-make-target",
        action="store_true",
        help="Emit Makefile target instead of running",
    )
    wizard_parser.add_argument(
        "--emit-gha",
        action="store_true",
        help="Emit GitHub Actions workflow instead of running",
    )
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

See: dev-only/1.0.0/TREND_ANALYSIS_COMPLETE_PLAN.md for complete documentation.
        """,
    )
    trends_subparsers = trends_parser.add_subparsers(dest="trends_command")

    # Common arguments
    def add_common_trend_args(parser):
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
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command", required=True)

    # LIST
    list_parser = policy_subparsers.add_parser(
        "list",
        help="List all available policies"
    )

    # VALIDATE
    validate_parser = policy_subparsers.add_parser(
        "validate",
        help="Validate policy syntax"
    )
    validate_parser.add_argument(
        "policy",
        help="Policy name (without .rego extension)"
    )

    # TEST
    test_parser = policy_subparsers.add_parser(
        "test",
        help="Test policy with findings file"
    )
    test_parser.add_argument(
        "policy",
        help="Policy name (without .rego extension)"
    )
    test_parser.add_argument(
        "--findings-file",
        required=True,
        help="Path to JSON file with findings (e.g., results/summaries/findings.json)"
    )

    # SHOW
    show_parser = policy_subparsers.add_parser(
        "show",
        help="Display policy metadata and content"
    )
    show_parser.add_argument(
        "policy",
        help="Policy name (without .rego extension)"
    )

    # INSTALL
    install_parser = policy_subparsers.add_parser(
        "install",
        help="Install builtin policy to user directory"
    )
    install_parser.add_argument(
        "policy",
        help="Policy name to install (without .rego extension)"
    )
    install_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing policy if already installed"
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

QUICK START:
  jmo wizard                         # Interactive guided scanning
  jmo fast --repo ./myapp            # Fast scan of single repository
  jmo balanced --repos-dir ~/repos   # Scan all repositories in directory
  jmo scan --help                    # Show advanced options

Documentation: https://docs.jmotools.com
        """,
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

    try:
        return ap.parse_args()
    except SystemExit:
        import os

        if os.getenv("PYTEST_CURRENT_TEST"):
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
    import sys

    # Skip if not interactive (Docker, CI/CD, etc.)
    if not sys.stdin.isatty():
        return

    print("\n🎉 Welcome to JMo Security!\n")
    print("📧 Get notified about new features, updates, and security tips?")
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
                    print("\n✅ Thanks! Check your inbox for a welcome message.\n")
                else:
                    print("\n✅ Thanks! You're all set.\n")
                    _log(
                        args,
                        "DEBUG",
                        "Email collection succeeded but welcome email not sent (resend may not be configured)",
                    )
            else:
                print("\n❌ Invalid email address. Skipping...\n")
                # Mark onboarding complete even if email invalid
                import yaml

                config = {"onboarding_completed": True}
                with open(config_path, "w") as f:
                    yaml.dump(config, f)
        except ImportError:
            # email_service module not available (resend not installed)
            print("\n✅ Thanks! You're all set.\n")
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
            print("\n✅ Thanks! You're all set.\n")
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
        print("\n👍 No problem! You can always add your email later with:")
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
        print(
            "\n"
            + "=" * 70
            + "\n"
            + "💚 Enjoying JMo Security? Support full-time development!\n"
            + "   → https://ko-fi.com/jmogaming\n"
            + "\n"
            + "   Your support helps maintain 11+ security tools, add new features,\n"
            + "   and provide free security scanning for the community.\n"
            + "\n"
            + f"   You've run {scan_count} scans - thank you for using JMo Security!\n"
            + "=" * 70
            + "\n"
        )


def _get_max_workers(args, eff: dict, cfg) -> int | None:
    """
    Determine max_workers from CLI args, effective settings, env var, or config.

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
    """
    Auto-detect optimal thread count based on CPU cores.

    Wrapper around shared cpu_utils.auto_detect_threads() with logging.

    Args:
        args: CLI arguments (for logging)

    Returns:
        int: Optimal thread count
    """
    return _auto_detect_threads_shared(log_fn=lambda level, msg: _log(args, level, msg))


class ProgressTracker:
    """
    Simple progress tracker for scan operations (no external dependencies).

    Tracks completed/total targets and provides formatted progress updates.
    Thread-safe for concurrent scan operations.
    """

    def __init__(self, total: int, args):
        """
        Initialize progress tracker.

        Args:
            total: Total number of targets to scan
            args: CLI arguments (for logging)
        """
        import threading

        self.total = total
        self.completed = 0
        self.args = args
        self._lock = threading.Lock()
        self._start_time: float | None = None

    def start(self):
        """Start progress tracking timer."""
        import time

        self._start_time = time.time()

    def update(self, target_type: str, target_name: str, elapsed: float):
        """
        Update progress after completing a target scan.

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


def cmd_scan(args) -> int:
    """
    Scan security targets (repos, images, IaC, URLs, GitLab, K8s) with multiple tools.

    REFACTORED VERSION: Uses scan_orchestrator and scan_jobs modules for clean separation.
    Complexity reduced from 321 to ~15 (95% improvement).
    """
    # Track scan start time for telemetry
    import time

    from scripts.core.telemetry import (
        should_show_telemetry_banner,
        show_telemetry_banner,
    )

    scan_start_time = time.time()

    # Show telemetry banner on first 3 scans (opt-out model)
    if should_show_telemetry_banner():
        show_telemetry_banner(mode="cli")

    # Check for first-run email prompt (non-blocking)
    if _check_first_run():
        _collect_email_opt_in(args)

    # Load effective settings with profile/per-tool overrides
    eff = _effective_scan_settings(args)
    cfg = load_config(args.config)
    tools = eff["tools"]
    results_dir = Path(args.results_dir)

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

    # Initialize progress tracker
    progress = ProgressTracker(total_targets, args)
    progress.start()

    # Create progress callback for orchestrator
    def progress_callback(target_type, target_id, statuses):
        """Update progress tracker when scan completes."""
        progress.update(target_type, target_id, elapsed=1.0)

    # Execute scans via orchestrator (replaces 158 lines of inline logic)
    try:
        all_results = orchestrator.scan_all(targets, per_tool_config, progress_callback)
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
    return 0


def cmd_report(args) -> int:
    """Wrapper for report orchestrator."""
    return _cmd_report_impl(args, _log)


def cmd_ci(args) -> int:
    """Wrapper for CI orchestrator."""
    return _cmd_ci_impl(args, cmd_scan, _cmd_report_impl)


def cmd_adapters(args) -> int:
    """Handle 'jmo adapters' subcommand for plugin management."""
    from scripts.core.plugin_loader import discover_adapters, get_plugin_registry

    if args.adapters_command == "list":
        # Discover and list all plugins
        count = discover_adapters()
        registry = get_plugin_registry()

        print(f"Loaded {count} adapter plugins:\n")

        for name in sorted(registry.list_plugins()):
            metadata = registry.get_metadata(name)
            if metadata:
                print(f"  {name:<15} v{metadata.version:<8} {metadata.description}")
            else:
                print(f"  {name:<15} (no metadata)")

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

            registry = PluginRegistry()
            loader = PluginLoader(registry)
            loader._load_plugin(plugin_file)

            print(f"✅ Valid plugin: {plugin_file}")
            return 0
        except Exception as e:
            print(f"❌ Invalid plugin: {e}")
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

    return run_wizard(
        yes=args.yes,
        emit_script=args.emit_script,
        emit_make_target=args.emit_make_target,
        emit_gha=args.emit_gha,
        policies=getattr(args, "policies", None),
        skip_policies=getattr(args, "skip_policies", False),
    )


def cmd_setup(args):
    """Run tool verification and installation."""
    import subprocess  # nosec B404 - needed for tool installation

    script = (
        Path(__file__).resolve().parent.parent / "core" / "check_and_install_tools.sh"
    )
    if not script.exists():
        sys.stderr.write(f"ERROR: Tool setup script not found: {script}\n")
        return 1

    cmd = ["bash", str(script)]

    if args.auto_install:
        cmd.append("--install")
    elif args.print_commands:
        cmd.append("--print-commands")

    if args.strict:
        cmd.append("--strict")

    rc = subprocess.run(cmd).returncode  # nosec B603 - controlled command

    if rc != 0 and args.strict:
        sys.stderr.write("ERROR: Tool setup failed\n")
        return rc

    return 0


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


def cmd_mcp_server(args):
    """Start MCP server for AI-powered remediation."""
    import os
    from pathlib import Path

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
                    os.startfile(str(p))  # type: ignore[attr-defined]  # nosec B606
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
    else:
        sys.stderr.write(f"Unknown command: {args.cmd}\n")
        return 1


def _log(args, level: str, message: str) -> None:
    import json
    import datetime

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
        ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
        sys.stderr.write(f"{color}{level:5}{reset} {ts} {message}\n")
        return
    rec = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "level": level,
        "msg": message,
    }
    sys.stderr.write(json.dumps(rec) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
