#!/usr/bin/env python3
"""
Interactive wizard for guided security scanning.

Provides step-by-step prompts for beginners to:
- Select scanning profile (fast/balanced/deep)
- Choose target repositories
- Configure execution mode (native/Docker)
- Preview and execute scan
- Generate reusable artifacts (Makefile/shell/GitHub Actions)

Examples:
    jmotools wizard                          # Interactive mode
    jmotools wizard --yes                    # Use defaults
    jmotools wizard --docker                 # Force Docker mode
    jmotools wizard --emit-gha workflow.yml  # Generate GHA workflow
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 - CLI needs subprocess
import sys
from pathlib import Path
from typing import Any, cast

from scripts.core.exceptions import ToolExecutionException
from scripts.cli.cpu_utils import get_cpu_count
from scripts.cli.wizard_generators import (
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)
from scripts.cli.wizard_flows.base_flow import PromptHelper, TargetDetector
from scripts.cli.wizard_flows.validators import (
    validate_path,
    validate_url,
    detect_iac_type,
    validate_k8s_context,
    detect_docker,
    check_docker_running,
)
from scripts.cli.wizard_flows.command_builder import build_command_parts
from scripts.cli.wizard_flows.target_configurators import (
    configure_repo_target as _configure_repo,
    configure_image_target as _configure_image,
    configure_iac_target as _configure_iac,
    configure_url_target as _configure_url,
    configure_gitlab_target as _configure_gitlab,
    configure_k8s_target as _configure_k8s,
)
from scripts.cli.wizard_flows.telemetry_helper import (
    send_wizard_telemetry,
)


# Configure logging
logger = logging.getLogger(__name__)


# Windows-safe Unicode fallback mappings for cp1252 compatibility
_UNICODE_FALLBACKS = {
    "📊": "[#]",  # Chart
    "📖": "[?]",  # Book
    "⚠": "[!]",  # Warning
    "✅": "[OK]",  # Check mark
    "❌": "[X]",  # Cross mark
    "✗": "[x]",  # X mark
    "✓": "[v]",  # Check mark small
    "•": "*",  # Bullet
    "→": "->",  # Arrow
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


# Module-level custom db_path storage (set by run_wizard)
_custom_db_path: str | None = None


def _get_db_path() -> Path:
    """Get the history database path, respecting custom --db flag.

    Returns:
        Path to SQLite history database
    """
    if _custom_db_path:
        return Path(_custom_db_path).expanduser().resolve()
    return Path.home() / ".jmo" / "history.db"


# Version (from pyproject.toml)
__version__ = "0.7.1"

# Profile definitions with resource estimates (v1.0.0)
PROFILES = {
    "fast": {
        "name": "Fast",
        "description": "Quick scans with 8 core tools (secrets, SAST, SCA, IaC)",
        "tools": [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "nuclei",
            "shellcheck",
        ],
        "timeout": 300,
        "threads": 8,
        "est_time": "5-10 minutes",
        "use_case": "Pre-commit checks, quick validation, CI/CD gate",
    },
    "slim": {
        "name": "Slim",
        "description": "Cloud/IaC focused scans with 14 tools (AWS, Azure, GCP, K8s)",
        "tools": [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "nuclei",
            "prowler",
            "kubescape",
            "grype",
            "bearer",
            "horusec",
            "dependency-check",
            "shellcheck",
        ],
        "timeout": 500,
        "threads": 4,
        "est_time": "12-18 minutes",
        "use_case": "Cloud infrastructure, Kubernetes, IaC security",
    },
    "balanced": {
        "name": "Balanced",
        "description": "Production CI/CD with 18 tools (cloud, API, DAST, license)",
        "tools": [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
            "nuclei",
            "prowler",
            "kubescape",
            "scancode",
            "cdxgen",
            "gosec",
            "grype",
            "bearer",
            "horusec",
            "dependency-check",
            "shellcheck",
        ],
        "timeout": 600,
        "threads": 4,
        "est_time": "18-25 minutes",
        "use_case": "CI/CD pipelines, regular audits, production scans",
    },
    "deep": {
        "name": "Deep",
        "description": "Comprehensive audits with all 28 tools (mobile, fuzzing, runtime)",
        "tools": [
            "trufflehog",
            "noseyparker",
            "semgrep",
            "semgrep-secrets",
            "bandit",
            "syft",
            "trivy",
            "trivy-rbac",
            "checkov",
            "checkov-cicd",
            "hadolint",
            "zap",
            "nuclei",
            "prowler",
            "kubescape",
            "akto",
            "scancode",
            "cdxgen",
            "gosec",
            "yara",
            "grype",
            "bearer",
            "horusec",
            "dependency-check",
            "falco",
            "afl++",
            "mobsf",
            "lynis",
        ],
        "timeout": 900,
        "threads": 2,
        "est_time": "40-70 minutes",
        "use_case": "Security audits, compliance scans, pre-release validation",
    },
}

# Wizard step configuration - ensures consistent "Step X/Y" display
WIZARD_TOTAL_STEPS = (
    7  # Profile, Execution, Target Type, Target Config, Advanced, Review, Execute
)
DIFF_WIZARD_TOTAL_STEPS = 5  # Mode, Directories, Filters, Format, Execute

# Empirical per-tool timing estimates in seconds (Fix 2.2 - Issue #10)
# Based on actual runs against medium-sized repos (~10k-50k LOC)
TOOL_TIME_ESTIMATES: dict[str, int] = {
    # Fast tools (< 30s)
    "trufflehog": 15,
    "semgrep": 25,
    "hadolint": 5,
    "shellcheck": 10,
    # Medium tools (30s - 2min)
    "trivy": 45,
    "grype": 40,
    "syft": 30,
    "checkov": 60,
    "bearer": 50,
    "nuclei": 90,
    "noseyparker": 45,
    "bandit": 30,
    "gosec": 45,
    # Slow tools (2min+)
    "zap": 300,  # 5 min for DAST baseline
    "horusec": 180,
    "dependency-check": 240,
    "prowler": 120,
    "kubescape": 90,
    "scancode": 150,
    "cdxgen": 60,
    "akto": 180,
    "yara": 45,
    "falco": 90,
    "afl++": 120,
    "mobsf": 300,
    "lynis": 60,
    # Default for unknown tools
    "_default": 60,
}


def calculate_time_estimate(available_tools: list[str]) -> tuple[int, int]:
    """Calculate dynamic time estimate based on available tools.

    Uses TOOL_TIME_ESTIMATES with 20% buffer for overhead.

    Args:
        available_tools: List of tool names that will actually run

    Returns:
        Tuple of (min_seconds, max_seconds) estimate
    """
    total = 0
    for tool in available_tools:
        total += TOOL_TIME_ESTIMATES.get(tool, TOOL_TIME_ESTIMATES["_default"])

    # Add buffer for overhead (parallel execution reduces time, but overhead adds)
    min_time = int(total * 0.6)  # Best case with parallelization
    max_time = int(total * 1.2)  # Worst case with retries

    return min_time, max_time


def format_time_range(min_sec: int, max_sec: int) -> str:
    """Format time range as human-readable string.

    Args:
        min_sec: Minimum time in seconds
        max_sec: Maximum time in seconds

    Returns:
        Human-readable time range (e.g., "4 min - 7 min")
    """

    def fmt(s: int) -> str:
        if s < 60:
            return f"{s}s"
        elif s < 3600:
            return f"{s // 60} min"
        else:
            return f"{s // 3600}h {(s % 3600) // 60}m"

    return f"{fmt(min_sec)} - {fmt(max_sec)}"


# Use PromptHelper from wizard_flows for all prompting/coloring
_prompter = PromptHelper()
_colorize = _prompter.colorize
_print_header = _prompter.print_header
_print_step = _prompter.print_step


def _prompt_text(question: str, default: str = "") -> str:
    """Simple text prompt helper (used by configure_advanced)."""
    prompt = f"{question} [{default}]: " if default else f"{question}: "
    value = input(prompt).strip()
    return value if value else default


def _prompt_choice(
    question: str, choices: list[tuple[str, str]], default: str = ""
) -> str:
    """
    Prompt user for a choice from a list with numbered display.

    Accepts both numeric input (1, 2, 3) and key input (balanced, fast)
    for backward compatibility.

    Args:
        question: Question to ask
        choices: List of (key, description) tuples
        default: Default choice key

    Returns:
        Selected choice key
    """
    choice_keys = [c[0] for c in choices]

    # Print question and choices with numbered format
    print(f"\n{question}")
    for i, (key, desc) in enumerate(choices, 1):
        default_marker = " (default)" if key == default else ""
        print(f"  {i}. {key:<12} - {desc}{default_marker}")

    # Build prompt
    choice_range = f"1-{len(choices)}"
    if default:
        prompt = f"Choice ({choice_range}) [{default}]: "
    else:
        prompt = f"Choice ({choice_range}): "

    while True:
        raw = input(prompt).strip()

        # Handle empty input with default
        if not raw and default:
            return default

        # Handle numeric input
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return choice_keys[idx - 1]
            print(_colorize(f"Invalid choice. Enter 1-{len(choices)}", "red"))
            continue

        # Handle key input (backward compatibility, case-insensitive)
        raw_lower = raw.lower()
        for key in choice_keys:
            if key.lower() == raw_lower:
                return key

        print(
            _colorize(
                f"Invalid choice. Enter 1-{len(choices)} or type option name",
                "red",
            )
        )


# Use PromptHelper.prompt_yes_no for all yes/no prompts
_prompt_yes_no = _prompter.prompt_yes_no  # Direct delegation to PromptHelper


def _select_mode(title: str, modes: list[tuple[str, str]], default: str = "") -> str:
    """
    Helper to select from modes with consistent formatting.

    Uses numbered selection format with backward-compatible key input.

    Args:
        title: Mode category title (e.g., "Repository modes")
        modes: List of (key, description) tuples
        default: Default mode key

    Returns:
        Selected mode key
    """
    # _prompt_choice handles the display and input
    return _prompt_choice(f"{title}:", modes, default=default)


# Use Docker detection from validators module
_detect_docker = detect_docker
_check_docker_running = check_docker_running


# Use TargetDetector from wizard_flows for all target detection
_detector = TargetDetector()
_detect_repos_in_dir = _detector.detect_repos  # Backward compat alias

# Use validators from wizard_flows module (imported above)
_validate_path = validate_path
_validate_url = validate_url
_detect_iac_type = detect_iac_type
_validate_k8s_context = validate_k8s_context


class TargetConfig:
    """Target-specific configuration for a single scan target."""

    def __init__(self) -> None:
        self.type: str = "repo"  # repo, image, iac, url, gitlab, k8s

        # Repository targets (existing)
        self.repo_mode: str = ""  # repo, repos-dir, targets, tsv
        self.repo_path: str = ""
        self.tsv_path: str = ""
        self.tsv_dest: str = "repos-tsv"

        # Container image targets (v0.6.0+)
        self.image_name: str = ""
        self.images_file: str = ""

        # IaC targets (v0.6.0+)
        self.iac_type: str = ""  # terraform, cloudformation, k8s-manifest
        self.iac_path: str = ""

        # Web URL targets (v0.6.0+)
        self.url: str = ""
        self.urls_file: str = ""
        self.api_spec: str = ""

        # GitLab targets (v0.6.0+)
        self.gitlab_url: str = "https://gitlab.com"
        self.gitlab_token: str = ""  # Prefer GITLAB_TOKEN env var
        self.gitlab_repo: str = ""  # group/repo format
        self.gitlab_group: str = ""

        # Kubernetes targets (v0.6.0+)
        self.k8s_context: str = ""
        self.k8s_namespace: str = ""
        self.k8s_all_namespaces: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "repo_mode": self.repo_mode,
            "repo_path": self.repo_path,
            "tsv_path": self.tsv_path,
            "tsv_dest": self.tsv_dest,
            "image_name": self.image_name,
            "images_file": self.images_file,
            "iac_type": self.iac_type,
            "iac_path": self.iac_path,
            "url": self.url,
            "urls_file": self.urls_file,
            "api_spec": self.api_spec,
            "gitlab_url": self.gitlab_url,
            "gitlab_token": "***" if self.gitlab_token else "",  # Redact token
            "gitlab_repo": self.gitlab_repo,
            "gitlab_group": self.gitlab_group,
            "k8s_context": self.k8s_context,
            "k8s_namespace": self.k8s_namespace,
            "k8s_all_namespaces": self.k8s_all_namespaces,
        }


class WizardConfig:
    """Configuration collected by the wizard."""

    def __init__(self) -> None:
        self.profile: str = "balanced"
        self.use_docker: bool = False
        self.target: TargetConfig = TargetConfig()
        self.results_dir: str = "results"
        self.threads: int | None = None
        self.timeout: int | None = None
        self.fail_on: str = ""
        self.allow_missing_tools: bool = True
        self.human_logs: bool = True
        # Trend analysis flags (v1.0.0+)
        self.analyze_trends: bool = False
        self.export_trends_html: bool = False
        self.export_trends_json: bool = False
        # Policy evaluation flag (set by OPA pre-flight check)
        self.policies_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile": self.profile,
            "use_docker": self.use_docker,
            "target": self.target.to_dict(),
            "results_dir": self.results_dir,
            "threads": self.threads,
            "timeout": self.timeout,
            "fail_on": self.fail_on,
            "allow_missing_tools": self.allow_missing_tools,
            "human_logs": self.human_logs,
            "analyze_trends": self.analyze_trends,
            "export_trends_html": self.export_trends_html,
            "export_trends_json": self.export_trends_json,
            "policies_enabled": self.policies_enabled,
        }


def select_profile() -> str:
    """Step 1: Select scanning profile.

    Shows profile comparison to help users differentiate between profiles (Fix 3.1).
    """
    _print_step(1, WIZARD_TOTAL_STEPS, "Select Scanning Profile")

    print("\nAvailable profiles:")
    for key, info in PROFILES.items():
        name = cast(str, info["name"])
        tools = cast(list[str], info["tools"])
        print(f"\n  {_colorize(name, 'bold')} ({key})")
        print(f"    {info['description']}")
        print(f"    Time: {info['est_time']} | Tools: {len(tools)}")
        print(f"    Use: {info['use_case']}")

    # Profile comparison to help differentiate (Fix 3.1)
    print("\n" + _colorize("Profile comparison:", "bold"))
    print("  fast (8):      Core scanners - quick pre-commit checks")
    print("  slim (14):     fast + Cloud/IaC (prowler, kubescape)")
    print("  balanced (18): slim + Full SCA + DAST (zap, cdxgen)")
    print("  deep (28):     balanced + Fuzzing, compliance, advanced")

    # Use _select_mode helper (simpler than full custom display)
    return _select_mode(
        "Profiles",
        [(k, str(PROFILES[k]["name"])) for k in PROFILES.keys()],
        default="balanced",
    )


def select_execution_mode(force_docker: bool = False) -> bool:
    """Step 2: Select execution mode (native vs Docker).

    Uses numbered selection for consistency (Fix 3.2).
    """
    _print_step(2, WIZARD_TOTAL_STEPS, "Select Execution Mode")

    has_docker = _detect_docker()
    docker_running = _check_docker_running() if has_docker else False

    if force_docker:
        if not has_docker:
            print(_colorize("Warning: Docker requested but not found", "yellow"))
            return False
        if not docker_running:
            print(_colorize("Warning: Docker not running", "yellow"))
            return False
        print("Docker mode: " + _colorize("FORCED (via --docker flag)", "green"))
        return True

    # Show status
    print(
        f"\nDocker available: {_colorize('Yes' if has_docker else 'No', 'green' if has_docker else 'red')}"
    )
    if has_docker:
        print(
            f"Docker running: {_colorize('Yes' if docker_running else 'No', 'green' if docker_running else 'yellow')}"
        )

    if not has_docker:
        print(_colorize("\nDocker not detected. Using native mode.", "yellow"))
        return False

    if not docker_running:
        print(_colorize("\nDocker daemon not running. Using native mode.", "yellow"))
        return False

    # Numbered selection for consistency (Fix 3.2)
    print("\nExecution mode:")
    print("  1. Docker - Isolated container (recommended)")
    print("  2. Native - Direct tool execution")

    choice = input("\nChoice [1]: ").strip()
    use_docker = choice != "2"  # Default to Docker (1)

    # Warn Windows users about limited native tool availability
    if not use_docker and sys.platform == "win32":
        print(
            _colorize(
                "\n⚠️  Note: Some security tools (lynis, shellcheck, falco) may not be "
                "available natively on Windows. Consider using Docker mode for full "
                "tool coverage, or run 'jmo tools check' to verify installed tools.",
                "yellow",
            )
        )

    return use_docker


def select_target_type() -> str:
    """
    Step 3a: Select target TYPE (repo, image, iac, url, gitlab, k8s).

    Returns:
        Target type string
    """
    _print_step(3, WIZARD_TOTAL_STEPS, "Select Scan Target Type")

    # Use _select_mode helper
    return _select_mode(
        "Target types",
        [
            ("repo", "Repositories (local Git repos)"),
            ("image", "Container images (Docker/OCI)"),
            ("iac", "Infrastructure as Code (Terraform/CloudFormation/K8s)"),
            ("url", "Web applications and APIs (DAST)"),
            ("gitlab", "GitLab repositories (remote)"),
            ("k8s", "Kubernetes clusters (live)"),
        ],
        default="repo",
    )


# Target configuration functions now delegated to target_configurators module
def configure_repo_target() -> TargetConfig:
    """Configure repository scanning (delegates to target_configurators module)."""
    config = _configure_repo(TargetConfig, _print_step, WIZARD_TOTAL_STEPS)
    return config  # type: ignore[no-any-return]  # Delegated function returns TargetConfig


def configure_image_target() -> TargetConfig:
    """Configure container image scanning (delegates to target_configurators module)."""
    config = _configure_image(TargetConfig, _print_step, WIZARD_TOTAL_STEPS)
    return config  # type: ignore[no-any-return]  # Delegated function returns TargetConfig


def configure_iac_target() -> TargetConfig:
    """Configure IaC file scanning (delegates to target_configurators module)."""
    config = _configure_iac(TargetConfig, _print_step, WIZARD_TOTAL_STEPS)
    return config  # type: ignore[no-any-return]  # Delegated function returns TargetConfig


def configure_url_target() -> TargetConfig:
    """Configure web URL scanning (delegates to target_configurators module)."""
    config = _configure_url(TargetConfig, _print_step, WIZARD_TOTAL_STEPS)
    return config  # type: ignore[no-any-return]  # Delegated function returns TargetConfig


def configure_gitlab_target() -> TargetConfig:
    """Configure GitLab scanning (delegates to target_configurators module)."""
    config = _configure_gitlab(TargetConfig, _print_step, WIZARD_TOTAL_STEPS)
    return config  # type: ignore[no-any-return]  # Delegated function returns TargetConfig


def configure_k8s_target() -> TargetConfig:
    """Configure Kubernetes scanning (delegates to target_configurators module)."""
    config = _configure_k8s(TargetConfig, _print_step, WIZARD_TOTAL_STEPS)
    return config  # type: ignore[no-any-return]  # Delegated function returns TargetConfig


def configure_advanced(profile: str) -> tuple[int | None, int | None, str]:
    """
    Step 5: Configure advanced options.

    Returns:
        Tuple of (threads, timeout, fail_on)
    """
    _print_step(5, WIZARD_TOTAL_STEPS, "Advanced Configuration")

    profile_info = PROFILES[profile]
    cpu_count = get_cpu_count()
    profile_threads = cast(int, profile_info["threads"])
    profile_timeout = cast(int, profile_info["timeout"])
    profile_tools = cast(list[str], profile_info["tools"])

    print("\nProfile defaults:")
    print(f"  Threads: {profile_threads}")
    print(f"  Timeout: {profile_timeout}s")
    print(f"  Tools: {len(profile_tools)}")
    print(f"\nSystem: {cpu_count} CPU cores detected")

    if not _prompt_yes_no("\nCustomize advanced settings?", default=False):
        return None, None, ""

    # Threads
    print(f"\nThread count (1-{cpu_count * 2})")
    print("  Lower = more thorough, Higher = faster (if I/O bound)")
    threads_str = _prompt_text("Threads", default=str(profile_threads))
    try:
        threads = int(threads_str)
        threads = max(1, min(threads, cpu_count * 2))
    except ValueError:
        threads = profile_threads

    # Timeout
    print("\nPer-tool timeout in seconds")
    timeout_str = _prompt_text("Timeout", default=str(profile_timeout))
    try:
        timeout = int(timeout_str)
        timeout = max(60, timeout)
    except ValueError:
        timeout = profile_timeout

    # Fail-on severity
    print("\nFail on severity threshold (for CI/CD)")
    print("  CRITICAL > HIGH > MEDIUM > LOW > INFO")
    fail_on_choices = [
        ("", "Don't fail (default)"),
        ("critical", "CRITICAL only"),
        ("high", "HIGH or above"),
        ("medium", "MEDIUM or above"),
    ]
    fail_on = _prompt_choice("Fail on:", fail_on_choices, default="")

    return threads, timeout, fail_on.upper() if fail_on else ""


def _display_target_details(target: TargetConfig) -> None:
    """Display target configuration details."""
    if target.type == "repo":
        print(f"    Mode: {target.repo_mode}")
        if target.repo_mode == "tsv":
            print(f"    TSV: {target.tsv_path}")
            print(f"    Dest: {target.tsv_dest}")
        else:
            print(f"    Path: {target.repo_path}")
    elif target.type == "image":
        if target.image_name:
            print(f"    Image: {target.image_name}")
        elif target.images_file:
            print(f"    Images file: {target.images_file}")
    elif target.type == "iac":
        print(f"    Type: {target.iac_type}")
        print(f"    File: {target.iac_path}")
    elif target.type == "url":
        if target.url:
            print(f"    URL: {target.url}")
        elif target.urls_file:
            print(f"    URLs file: {target.urls_file}")
        elif target.api_spec:
            print(f"    API spec: {target.api_spec}")
    elif target.type == "gitlab":
        print(f"    GitLab URL: {target.gitlab_url}")
        print(f"    Token: {'***' if target.gitlab_token else 'NOT SET'}")
        if target.gitlab_repo:
            print(f"    Repo: {target.gitlab_repo}")
        elif target.gitlab_group:
            print(f"    Group: {target.gitlab_group}")
    elif target.type == "k8s":
        print(f"    Context: {target.k8s_context}")
        if target.k8s_all_namespaces:
            print("    Namespaces: ALL")
        else:
            print(f"    Namespace: {target.k8s_namespace}")


def review_and_confirm(config: WizardConfig) -> bool:
    """
    Step 6: Review configuration and confirm.

    Shows dynamic time estimate based on available tools (Fix 2.2 - Issue #10).

    Returns:
        True if user confirms, False otherwise
    """
    _print_step(6, WIZARD_TOTAL_STEPS, "Review Configuration")

    profile_info = PROFILES[config.profile]
    profile_name = cast(str, profile_info["name"])
    profile_threads = cast(int, profile_info["threads"])
    profile_timeout = cast(int, profile_info["timeout"])
    profile_tools = cast(list[str], profile_info["tools"])

    # Get available tools for dynamic time estimate (Fix 2.2)
    try:
        from scripts.cli.tool_manager import ToolManager

        tm = ToolManager()
        tool_statuses = tm.check_profile(config.profile)
        available_tools = [
            name for name, status in tool_statuses.items() if status.execution_ready
        ]
        available_count = len(available_tools)

        # Calculate dynamic estimate based on available tools
        min_time, max_time = calculate_time_estimate(available_tools)
        dynamic_estimate = format_time_range(min_time, max_time)
    except Exception:
        # Fallback to static estimate if tool check fails
        available_tools = profile_tools
        available_count = len(profile_tools)
        dynamic_estimate = cast(str, profile_info["est_time"])

    print("\n" + _colorize("Configuration Summary:", "bold"))
    print(f"  Profile: {_colorize(profile_name, 'green')} ({config.profile})")
    print(f"  Mode: {_colorize('Docker' if config.use_docker else 'Native', 'green')}")
    print(f"  Target Type: {_colorize(config.target.type, 'green')}")

    # Display target-specific details using helper
    _display_target_details(config.target)

    print(f"  Results: {config.results_dir}")

    threads = config.threads or profile_threads
    timeout = config.timeout or profile_timeout
    print(f"  Threads: {threads}")
    print(f"  Timeout: {timeout}s")

    if config.fail_on:
        print(f"  Fail on: {_colorize(config.fail_on, 'yellow')}")

    # Show tools available vs total (Fix 2.2)
    print(
        f"\n  Tools: {_colorize(f'{available_count}/{len(profile_tools)}', 'green')} available"
    )
    # Show first 3 available tools
    tools_preview = ", ".join(available_tools[:3])
    if len(available_tools) > 3:
        tools_preview += "..."
    print(f"         ({tools_preview})")

    # Dynamic time estimate
    print(f"  Estimated time: {_colorize(dynamic_estimate, 'yellow')}")

    return _prompt_yes_no("\nProceed with scan?", default=True)


# Use command builder from wizard_flows module
_build_command_parts = build_command_parts


def generate_command(config: WizardConfig) -> str:
    """
    Generate the jmotools/jmo command from config (for display/export).

    Supports all 6 target types: repo, image, iac, url, gitlab, k8s.
    """
    return " ".join(_build_command_parts(config))


def generate_command_list(config: WizardConfig) -> list[str]:
    """
    Generate the command as a list for secure subprocess execution.

    This function builds the command as a list of arguments to avoid shell injection.
    Use this for actual execution, not generate_command() which is for display only.
    """
    return _build_command_parts(config)


def execute_scan(config: WizardConfig, yes: bool = False) -> int:
    """
    Step 7: Execute the scan.

    Args:
        config: Wizard configuration
        yes: Skip prompts and use defaults

    Returns:
        Exit code from scan
    """
    _print_step(7, WIZARD_TOTAL_STEPS, "Execute Scan")

    command = generate_command(config)

    print("\n" + _colorize("Generated command:", "bold"))
    print(_colorize(f"  {command}", "green"))
    print()

    # In non-interactive mode, auto-execute without prompting
    if not yes and not _prompt_yes_no("Execute now?", default=True):
        print("\nCommand saved. You can run it later:")
        print(f"  {command}")
        return 0

    print(_colorize("\nStarting scan...", "blue"))
    print()

    # Execute via subprocess
    try:
        # Both Docker and native execution use subprocess for consistency and security
        command_list = generate_command_list(config)
        result = subprocess.run(
            command_list,
            shell=False,  # IMPORTANT: shell=False prevents command injection
            check=False,
        )
        # Print results guide after scan completes
        if result.returncode == 0 or result.returncode == 1:
            print(
                "\n"
                + _colorize("📖 Learn how to triage and act on your findings:", "blue")
            )
            print("  - Quick triage (30 min): docs/RESULTS_QUICK_REFERENCE.md")
            print("  - Complete guide: docs/RESULTS_GUIDE.md")
        return result.returncode

    except KeyboardInterrupt:
        print(_colorize("\n\nScan cancelled by user", "yellow"))
        return 130
    except ToolExecutionException as e:
        # Tool execution failed (exit code, timeout, etc.)
        print(_colorize(f"\n\nTool execution failed: {e.tool}", "red"))
        logger.error(f"Tool execution failed: {e}")
        return e.return_code if hasattr(e, "return_code") else 1
    except (OSError, subprocess.CalledProcessError) as e:
        # System errors (permissions, missing files, subprocess failures)
        print(_colorize(f"\n\nScan failed: {e}", "red"))
        logger.error(f"Scan execution error: {e}", exc_info=True)
        return 1
    except Exception as e:
        # Unexpected errors - log with full traceback
        print(_colorize(f"\n\nScan failed: {e}", "red"))
        logger.error(f"Unexpected scan failure: {e}", exc_info=True)
        return 1


# Telemetry functions now imported from telemetry_helper module


def check_tools_for_profile(
    profile: str,
    yes: bool = False,
    use_docker: bool = False,
) -> tuple[bool, list[str]]:
    """
    Check tool availability for the selected profile.

    This is the pre-flight tool check that runs before scan execution.
    If tools are missing, offers to install them or continue anyway.

    Args:
        profile: Selected scan profile (fast, slim, balanced, deep)
        yes: Non-interactive mode (skip prompts)
        use_docker: True if using Docker (tools bundled in image)

    Returns:
        Tuple of (should_continue: bool, available_tools: list[str])
    """
    # Docker mode has all tools bundled - skip check
    if use_docker:
        return True, []

    _print_step(2, WIZARD_TOTAL_STEPS, "Tool Pre-flight Check")

    try:
        from scripts.cli.tool_manager import (
            ToolManager,
            get_remediation_for_tool,
        )
        from scripts.core.tool_registry import PROFILE_TOOLS, detect_platform

        manager = ToolManager()
        platform = detect_platform()
        tools_in_profile = PROFILE_TOOLS.get(profile, [])

        print(f"\nChecking {len(tools_in_profile)} tools for '{profile}' profile...")

        statuses = manager.check_profile(profile)
        missing = [s for s in statuses.values() if not s.installed]
        outdated = [s for s in statuses.values() if s.is_outdated]
        # Use execution_ready for "available" (consistent with summary display)
        available = [name for name, s in statuses.items() if s.execution_ready]
        not_ready = [
            s for s in statuses.values() if s.installed and not s.execution_ready
        ]

        # Combine all tools that need attention
        tools_needing_attention = missing + not_ready

        # All tools present and ready
        if not tools_needing_attention:
            print(
                _colorize(
                    f"\n{_UNICODE_FALLBACKS.get('✅', '[OK]')} All {len(tools_in_profile)} tools ready!",
                    "green",
                )
            )
            if outdated:
                print(
                    _colorize(
                        f"{_UNICODE_FALLBACKS.get('⚠', '[!]')} {len(outdated)} tool(s) outdated - run 'jmo tools update' when convenient",
                        "yellow",
                    )
                )
            return True, available

        # Show consolidated status
        print(
            _colorize(
                f"\n{_UNICODE_FALLBACKS.get('✅', '[OK]')} {len(available)} tools ready",
                "green",
            )
        )
        print(
            _colorize(
                f"{_UNICODE_FALLBACKS.get('⚠', '[!]')} {len(tools_needing_attention)} tool(s) need attention:",
                "yellow",
            )
        )

        # Collect fix commands for display and potential auto-execution
        fix_info: list[dict] = []

        # Track manual-only tools separately for clearer display
        manual_only_count = 0

        for status in tools_needing_attention:
            if not status.installed:
                issue = "NOT INSTALLED"
            # Phase 4: Detect startup crashes (pydantic conflicts, import errors)
            elif status.version_error:
                issue = f"STARTUP CRASH: {status.version_error}"
            else:
                issue = status.execution_warning or "Missing dependencies"

            remediation = get_remediation_for_tool(status.name, platform)
            fix_info.append(
                {
                    "name": status.name,
                    "issue": issue,
                    "installed": status.installed,
                    "remediation": remediation,
                    "version_error": status.version_error,  # Phase 4
                }
            )

            # Display the issue - distinguish different issue types
            is_manual = remediation.get("is_manual", False)
            is_startup_crash = status.version_error is not None  # Phase 4

            if is_manual:
                manual_only_count += 1
                icon = _UNICODE_FALLBACKS.get("📖", "[?]")
                # Show manual reason instead of generic issue
                issue = remediation.get("manual_reason", issue)
            elif is_startup_crash:
                # Phase 4: Special display for startup crashes
                icon = _UNICODE_FALLBACKS.get("💥", "[!!]")
            elif not status.installed:
                icon = _UNICODE_FALLBACKS.get("❌", "[X]")
            else:
                icon = _UNICODE_FALLBACKS.get("⚠", "[!]")

            print(f"\n  {icon} {_colorize(status.name, 'yellow')}: {issue}")

            # Show fix command or manual guidance
            if is_manual:
                url = remediation.get("manual_url", "docs/MANUAL_INSTALLATION.md")
                print(f"     See: {url}")
            elif is_startup_crash:
                # Phase 4: Suggest reinstalling in isolated venv
                print(
                    _colorize(
                        "     Fix: jmo tools clean && jmo tools install "
                        f"{status.name}",
                        "cyan",
                    )
                )
                print(
                    _colorize(
                        "     (Reinstalls in isolated venv to avoid pip conflicts)",
                        "dim",
                    )
                )
            elif remediation["commands"]:
                print(f"     Fix: {remediation['commands'][0]}")
                if len(remediation["commands"]) > 1:
                    for cmd in remediation["commands"][1:]:
                        print(f"          {cmd}")
            elif remediation["jmo_install"]:
                print(f"     Fix: {remediation['jmo_install']}")

        if outdated:
            print(
                _colorize(
                    f"\n{_UNICODE_FALLBACKS.get('⚠', '[!]')} {len(outdated)} tool(s) outdated - run 'jmo tools update' when convenient",
                    "yellow",
                )
            )

        # Non-interactive mode: continue with available tools
        if yes:
            print(
                _colorize(
                    f"\nNon-interactive mode: continuing with {len(available)} available tools",
                    "yellow",
                )
            )
            if tools_needing_attention:
                skipped = [t["name"] for t in fix_info]
                print(f"Skipping: {', '.join(skipped)}")
            return True, available

        # Interactive: offer choices with auto-fix option
        print("\n" + "─" * 50)
        print(_colorize("Options:", "blue"))
        print(f"  [1] Auto-fix all issues ({len(tools_needing_attention)} tools)")
        print(
            f"  [2] Continue with {len(available)} working tools (skip: {', '.join(t['name'] for t in fix_info[:3])}{'...' if len(fix_info) > 3 else ''})"
        )
        print("  [3] Show all fix commands (copy/paste manually)")
        print("  [4] Cancel wizard")

        while True:
            choice = input("\nChoice [1]: ").strip() or "1"
            if choice == "1":
                # Auto-fix: run remediation commands
                return _auto_fix_tools(fix_info, platform, profile, available)
            elif choice == "2":
                print(
                    _colorize(
                        f"\nContinuing with {len(available)} available tools", "yellow"
                    )
                )
                print("Note: Some scan categories may be skipped")
                return True, available
            elif choice == "3":
                # Show all commands for manual execution
                _show_all_fix_commands(fix_info, platform)
                # Ask again after showing commands
                continue
            elif choice == "4":
                return False, []
            else:
                print("Please enter 1, 2, 3, or 4")

    except ImportError as e:
        # Tool manager not available - continue anyway
        logger.warning(f"Tool check unavailable: {e}")
        print(_colorize("\nTool check unavailable - continuing anyway", "yellow"))
        return True, []
    except Exception as e:
        logger.warning(f"Tool check failed: {e}")
        print(_colorize(f"\nTool check failed: {e} - continuing anyway", "yellow"))
        return True, []


def _show_all_fix_commands(fix_info: list[dict], platform: str) -> None:
    """Show all fix commands in a copy-paste friendly format."""
    print("\n" + "═" * 60)
    print(_colorize("  FIX COMMANDS (copy and run in terminal)", "blue"))
    print("═" * 60)

    for info in fix_info:
        print(f"\n# {info['name']}: {info['issue']}")
        remediation = info["remediation"]
        if remediation["commands"]:
            for cmd in remediation["commands"]:
                print(cmd)
        elif remediation["jmo_install"]:
            print(remediation["jmo_install"])

    print("\n" + "═" * 60)
    print("After running these commands, restart the wizard with: jmo wizard")
    print("═" * 60 + "\n")


def _auto_fix_tools(
    fix_info: list[dict],
    platform: str,
    profile: str,
    available: list[str],
) -> tuple[bool, list[str]]:
    """
    Automatically fix tools with issues using parallel installation.

    Uses three-phase strategy:
    1. Skip manual-only tools (show guidance instead of failing)
    2. Parallel installation for JMo-manageable tools (pip, npm, binary downloads)
    3. Sequential execution for platform-specific commands (brew, apt, choco)

    Args:
        fix_info: List of dicts with tool name, issue, and remediation info
        platform: Current platform (linux, macos, windows)
        profile: Profile name
        available: Currently available tool names

    Returns:
        Tuple of (should_continue, updated_available_tools)
    """
    # Phase 0: Separate manual-only tools from auto-fixable tools
    manual_tools: list[dict] = []
    auto_fix_info: list[dict] = []

    for info in fix_info:
        remediation = info["remediation"]
        if remediation.get("is_manual"):
            manual_tools.append(info)
        else:
            auto_fix_info.append(info)

    # Show manual tools guidance upfront (don't attempt install)
    if manual_tools:
        print(
            _colorize(
                f"\n{_UNICODE_FALLBACKS.get('📖', '[?]')} {len(manual_tools)} tool(s) require manual installation:",
                "yellow",
            )
        )
        print("─" * 50)
        for info in manual_tools:
            tool_name = info["name"]
            remediation = info["remediation"]
            reason = remediation.get("manual_reason", "Manual installation required")
            url = remediation.get("manual_url", "docs/MANUAL_INSTALLATION.md")

            print(
                f"\n  {_UNICODE_FALLBACKS.get('⚠', '[!]')} {_colorize(tool_name, 'yellow')}"
            )
            print(f"     Reason: {reason}")
            print(f"     See: {url}")
        print("\n" + "─" * 50)
        print(
            _colorize(
                "Tip: Use Docker mode for full tool support, or continue without these tools.",
                "blue",
            )
        )

    # If no auto-fixable tools, return early
    if not auto_fix_info:
        print(
            _colorize(
                f"\n{_UNICODE_FALLBACKS.get('⚠', '[!]')} No tools can be auto-installed on this platform.",
                "yellow",
            )
        )
        return True, available

    print(
        _colorize(
            f"\n{_UNICODE_FALLBACKS.get('🔧', '[*]')} Auto-fixing {len(auto_fix_info)} tool(s)...",
            "blue",
        )
    )
    print("─" * 50)

    # Separate tools into JMo-installable vs platform-specific commands
    jmo_tools: list[str] = []
    platform_commands: list[tuple[str, list[str]]] = []  # (tool_name, commands)

    for info in auto_fix_info:
        tool_name = info["name"]
        remediation = info["remediation"]

        # Check if this tool can be installed via JMo's ToolInstaller
        jmo_install = remediation.get("jmo_install")
        commands = remediation.get("commands", [])

        if jmo_install and "jmo tools install" in jmo_install:
            # Tool can be installed via JMo - use parallel installer
            jmo_tools.append(tool_name)
        elif commands:
            # Has platform-specific commands - run separately
            platform_commands.append((tool_name, commands))
        else:
            # Default to JMo install
            jmo_tools.append(tool_name)

    fixed = 0
    failed = 0
    failed_tools: list[str] = []

    # Phase 1: Parallel installation for JMo-manageable tools
    if jmo_tools:
        print(
            _colorize(
                f"\n{_UNICODE_FALLBACKS.get('⚡', '[*]')} Installing {len(jmo_tools)} tools in parallel...",
                "cyan",
            )
        )

        try:
            from scripts.cli.tool_installer import ToolInstaller

            installer = ToolInstaller()

            # Use parallel installation
            progress = installer.install_profile_parallel(
                profile=profile,
                skip_installed=False,  # We want to install these specific tools
                max_workers=4,
                show_progress=True,
            )

            # Count results
            for result in progress.results:
                if result.tool_name in jmo_tools:
                    if result.success:
                        if result.method != "skipped":
                            fixed += 1
                            print(
                                _colorize(
                                    f"   {_UNICODE_FALLBACKS.get('✅', '[OK]')} {result.tool_name} installed!",
                                    "green",
                                )
                            )
                            if result.tool_name not in available:
                                available.append(result.tool_name)
                    else:
                        failed += 1
                        failed_tools.append(result.tool_name)
                        print(
                            _colorize(
                                f"   {_UNICODE_FALLBACKS.get('❌', '[X]')} {result.tool_name}: {result.message[:60]}",
                                "red",
                            )
                        )

        except ImportError as e:
            logger.warning(f"Could not import ToolInstaller: {e}")
            # Fall back to sequential installation
            for tool_name in jmo_tools:
                platform_commands.append(
                    (tool_name, [f"jmo tools install {tool_name} --yes"])
                )

    # Phase 2: Platform-specific commands (sequential, can't parallelize safely)
    if platform_commands:
        print(
            _colorize(
                f"\n{_UNICODE_FALLBACKS.get('🔧', '[*]')} Running {len(platform_commands)} platform-specific commands...",
                "blue",
            )
        )

        for tool_name, commands in platform_commands:
            print(f"\n{_UNICODE_FALLBACKS.get('⏳', '[.]')} Fixing {tool_name}...")

            success = True
            for cmd in commands:
                if not cmd:
                    continue

                # Add --yes flag to jmo tools install commands to avoid interactive prompt
                if cmd.startswith("jmo tools install") and "--yes" not in cmd:
                    cmd = cmd + " --yes"

                print(f"   Running: {cmd[:60]}{'...' if len(cmd) > 60 else ''}")

                try:
                    proc_result = subprocess.run(
                        cmd,
                        shell=True,  # nosec B602 - User-initiated fix commands
                        capture_output=True,
                        text=True,
                        timeout=300,  # 5 minute timeout per command
                    )

                    if proc_result.returncode != 0:
                        if (
                            "error" in proc_result.stderr.lower()
                            or "failed" in proc_result.stderr.lower()
                        ):
                            print(
                                _colorize(
                                    f"   {_UNICODE_FALLBACKS.get('❌', '[X]')} Failed: {proc_result.stderr[:100]}",
                                    "red",
                                )
                            )
                            success = False
                            break
                        else:
                            logger.debug(
                                f"Command returned {proc_result.returncode} but continuing"
                            )

                except subprocess.TimeoutExpired:
                    print(
                        _colorize(
                            f"   {_UNICODE_FALLBACKS.get('❌', '[X]')} Timeout after 5 minutes",
                            "red",
                        )
                    )
                    success = False
                    break
                except Exception as e:
                    print(
                        _colorize(
                            f"   {_UNICODE_FALLBACKS.get('❌', '[X]')} Error: {e}",
                            "red",
                        )
                    )
                    success = False
                    break

            if success:
                print(
                    _colorize(
                        f"   {_UNICODE_FALLBACKS.get('✅', '[OK]')} {tool_name} fixed!",
                        "green",
                    )
                )
                fixed += 1
                if tool_name not in available:
                    available.append(tool_name)
            else:
                failed += 1
                failed_tools.append(tool_name)

    # Summary
    print("\n" + "─" * 50)
    if failed == 0:
        print(
            _colorize(
                f"{_UNICODE_FALLBACKS.get('✅', '[OK]')} All {fixed} tool(s) fixed successfully!",
                "green",
            )
        )
    else:
        print(
            _colorize(
                f"{_UNICODE_FALLBACKS.get('⚠', '[!]')} {fixed} fixed, {failed} failed",
                "yellow",
            )
        )
        print(f"Failed tools: {', '.join(failed_tools)}")
        print("These may require manual installation. See: docs/MANUAL_INSTALLATION.md")

    # Re-check tool status to update available list
    print("\nRe-checking tool status...")
    try:
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        statuses = manager.check_profile(profile)
        available = [name for name, s in statuses.items() if s.execution_ready]
        ready_count = len(available)
        total_count = len(statuses)

        if ready_count == total_count:
            print(
                _colorize(
                    f"{_UNICODE_FALLBACKS.get('✅', '[OK]')} All {total_count} tools now ready!",
                    "green",
                )
            )
        else:
            not_ready = total_count - ready_count
            print(
                _colorize(
                    f"{_UNICODE_FALLBACKS.get('✅', '[OK]')} {ready_count}/{total_count} tools ready ({not_ready} still need attention)",
                    "yellow",
                )
            )

    except Exception as e:
        logger.warning(f"Re-check failed: {e}")

    # Continue with whatever we have
    return True, available


def _install_missing_tools_interactive(
    missing: list,
    profile: str,
    available: list[str],
) -> tuple[bool, list[str]]:
    """
    Install missing tools with progress display.

    Args:
        missing: List of ToolStatus for missing tools
        profile: Profile name
        available: Currently available tool names

    Returns:
        Tuple of (should_continue, updated_available_tools)
    """
    try:
        from scripts.cli.tool_installer import ToolInstaller

        print(_colorize(f"\nInstalling {len(missing)} missing tool(s)...", "blue"))

        installer = ToolInstaller()

        def progress_callback(tool_name: str, current: int, total: int) -> None:
            print(f"  [{current}/{total}] Installing {tool_name}...")

        installer.set_progress_callback(progress_callback)

        # Install only the missing tools
        from scripts.cli.tool_installer import InstallProgress

        progress = InstallProgress(total=len(missing))
        for status in missing:
            result = installer.install_tool(status.name)
            progress.add_result(result)
            if result.success:
                available.append(status.name)

        # Summary
        print()
        if progress.failed == 0:
            print(
                _colorize(
                    f"{_UNICODE_FALLBACKS.get('✅', '[OK]')} All {progress.successful} tool(s) installed!",
                    "green",
                )
            )
        else:
            print(
                _colorize(
                    f"{progress.successful} installed, {progress.failed} failed",
                    "yellow",
                )
            )
            if progress.failed > 0:
                print(
                    "Some tools require manual installation. See: docs/MANUAL_INSTALLATION.md"
                )

        # Continue with whatever we have
        return True, available

    except ImportError as e:
        logger.warning(f"Tool installer unavailable: {e}")
        print(_colorize(f"\nInstaller unavailable: {e}", "red"))
        print("Install manually using: jmo tools install --profile " + profile)

        cont = input("Continue anyway? [y/N]: ").strip().lower()
        return cont == "y", available
    except Exception as e:
        logger.error(f"Installation failed: {e}")
        print(_colorize(f"\nInstallation error: {e}", "red"))

        cont = input("Continue anyway? [y/N]: ").strip().lower()
        return cont == "y", available


def _check_policy_tools(
    policies: list[str] | None,
    skip_policies: bool,
    yes: bool = False,
    use_docker: bool = False,
) -> tuple[bool, bool]:
    """
    Check if OPA is available when policies are configured.

    This pre-flight check runs in Step 2 (after tool check) when the user
    has specified --policy flags. OPA is required for policy evaluation.

    Args:
        policies: List of policies to evaluate (e.g., ['owasp-top-10', 'zero-secrets'])
        skip_policies: Whether --skip-policies was specified
        yes: Non-interactive mode
        use_docker: Whether Docker mode is active (OPA bundled in image)

    Returns:
        Tuple of (should_continue: bool, policies_enabled: bool)
        - should_continue: Whether wizard should proceed
        - policies_enabled: Whether policy evaluation will run
    """
    # No policies configured or explicitly skipped - nothing to check
    if not policies or skip_policies:
        return True, False

    # Docker mode has OPA bundled - skip check
    if use_docker:
        return True, True

    # Check if OPA is available
    from scripts.cli.scan_utils import tool_exists

    print(
        f"\nChecking policy tool availability ({len(policies)} policies configured)..."
    )

    if tool_exists("opa", warn=False):
        print(
            _colorize(
                f"{_UNICODE_FALLBACKS.get('✅', '[OK]')} OPA available - policy evaluation enabled",
                "green",
            )
        )
        return True, True

    # OPA not found - warn user
    print(
        _colorize(
            f"\n{_UNICODE_FALLBACKS.get('⚠', '[!]')} OPA not installed",
            "yellow",
        )
    )
    print("Policy evaluation requires OPA (Open Policy Agent).")
    print(f"Configured policies: {', '.join(policies)}")

    # Non-interactive: continue without policies
    if yes:
        print(
            _colorize(
                "\nNon-interactive mode: continuing without policy evaluation",
                "yellow",
            )
        )
        return True, False

    # Interactive: offer choices
    print("\n" + "─" * 50)
    print(_colorize("Options:", "blue"))
    print("  [1] Continue scan without policy evaluation")
    print("  [2] Install OPA and continue")
    print("  [3] Cancel wizard")

    while True:
        choice = input("\nChoice [1]: ").strip() or "1"
        if choice == "1":
            print(
                _colorize(
                    "\nContinuing without policy evaluation",
                    "yellow",
                )
            )
            return True, False
        elif choice == "2":
            # Attempt OPA installation
            return _install_opa_tool()
        elif choice == "3":
            return False, False
        else:
            print("Please enter 1, 2, or 3")


def _install_opa_tool() -> tuple[bool, bool]:
    """
    Install OPA tool.

    Returns:
        Tuple of (should_continue, policies_enabled)
    """
    print("\nInstalling OPA...")

    try:
        from scripts.cli.tool_installer import ToolInstaller

        installer = ToolInstaller()
        result = installer.install_tool("opa")

        if result.success:
            print(
                _colorize(
                    f"{_UNICODE_FALLBACKS.get('✅', '[OK]')} OPA installed successfully",
                    "green",
                )
            )
            return True, True
        else:
            print(
                _colorize(
                    f"{_UNICODE_FALLBACKS.get('❌', '[X]')} OPA installation failed: {result.message}",
                    "red",
                )
            )
            print("Continuing without policy evaluation")
            return True, False

    except ImportError as e:
        logger.warning(f"Tool installer unavailable: {e}")
        print(_colorize(f"\nInstaller unavailable: {e}", "red"))
        print(
            "Install OPA manually: https://www.openpolicyagent.org/docs/latest/#running-opa"
        )
        return True, False
    except Exception as e:
        logger.warning(f"OPA installation failed: {e}")
        print(_colorize(f"\nInstallation failed: {e}", "red"))
        print("Continuing without policy evaluation")
        return True, False


def run_wizard(
    yes: bool = False,
    force_docker: bool = False,
    emit_make: str | None = None,
    emit_script: str | None = None,
    emit_gha: str | None = None,
    analyze_trends: bool = False,
    export_trends_html: bool = False,
    export_trends_json: bool = False,
    policies: list[str] | None = None,
    skip_policies: bool = False,
    db_path: str | None = None,
) -> int:
    """
    Run the interactive wizard.

    Args:
        yes: Skip prompts and use defaults
        force_docker: Force Docker mode
        emit_make: Generate Makefile target to this file
        emit_script: Generate shell script to this file
        emit_gha: Generate GitHub Actions workflow to this file
        analyze_trends: Automatically analyze trends after scan (non-interactive)
        export_trends_html: Export trend report as HTML after scan
        export_trends_json: Export trend report as JSON after scan
        policies: List of policies to evaluate after scan (e.g., ['owasp-top-10', 'zero-secrets'])
        skip_policies: Skip policy evaluation entirely
        db_path: Path to SQLite history database (default: ~/.jmo/history.db)

    Returns:
        Exit code
    """
    import time

    from scripts.core.telemetry import (
        should_show_telemetry_banner,
        show_telemetry_banner,
    )

    # Set custom db_path for this wizard run (module-level for helper access)
    global _custom_db_path
    _custom_db_path = db_path

    wizard_start_time = time.time()

    _print_header("JMo Security Wizard")
    print("Welcome! This wizard will guide you through your first security scan.")
    print("Press Ctrl+C at any time to cancel.")

    # Show telemetry banner on first 3 wizard runs (opt-out model)
    if should_show_telemetry_banner():
        show_telemetry_banner(mode="wizard")

    config = WizardConfig()

    try:
        if yes:
            # Non-interactive mode: use defaults (repo scanning)
            print("\n" + _colorize("Non-interactive mode: using defaults", "yellow"))
            config.profile = "balanced"
            config.use_docker = (
                force_docker and _detect_docker() and _check_docker_running()
            )
            # Default to repo scanning with current directory
            config.target.type = "repo"
            config.target.repo_mode = "repos-dir"
            config.target.repo_path = str(Path.cwd())
            config.results_dir = "results"

            # Tool check for non-interactive mode
            should_continue, _ = check_tools_for_profile(
                config.profile, yes=True, use_docker=config.use_docker
            )
            if not should_continue:
                return 0

            # OPA pre-flight check (for policy evaluation)
            should_continue, policies_enabled = _check_policy_tools(
                policies, skip_policies, yes=True, use_docker=config.use_docker
            )
            if not should_continue:
                return 0
            config.policies_enabled = policies_enabled
        else:
            # Interactive mode with new multi-target selection
            config.profile = select_profile()
            config.use_docker = select_execution_mode(force_docker)

            # Tool pre-flight check (only for native mode)
            should_continue, _ = check_tools_for_profile(
                config.profile, yes=False, use_docker=config.use_docker
            )
            if not should_continue:
                print(_colorize("\nWizard cancelled", "yellow"))
                return 0

            # Version drift check (only for native mode)
            if not config.use_docker:
                from scripts.cli.scan_utils import check_version_drift_before_scan

                if not check_version_drift_before_scan(
                    config.profile, interactive=True
                ):
                    print(_colorize("\nWizard cancelled", "yellow"))
                    return 0

            # OPA pre-flight check (for policy evaluation)
            should_continue, policies_enabled = _check_policy_tools(
                policies, skip_policies, yes=False, use_docker=config.use_docker
            )
            if not should_continue:
                print(_colorize("\nWizard cancelled", "yellow"))
                return 0
            config.policies_enabled = policies_enabled

            # Step 3a: Select target type
            target_type = select_target_type()

            # Step 3b: Configure target (dispatch to appropriate function)
            if target_type == "repo":
                config.target = configure_repo_target()
            elif target_type == "image":
                config.target = configure_image_target()
            elif target_type == "iac":
                config.target = configure_iac_target()
            elif target_type == "url":
                config.target = configure_url_target()
            elif target_type == "gitlab":
                config.target = configure_gitlab_target()
            elif target_type == "k8s":
                config.target = configure_k8s_target()

            threads, timeout, fail_on = configure_advanced(config.profile)
            config.threads = threads
            config.timeout = timeout
            config.fail_on = fail_on

            if not review_and_confirm(config):
                print(_colorize("\nWizard cancelled", "yellow"))
                return 0

        # Handle artifact generation
        if emit_make:
            command = generate_command(config)
            content = generate_makefile_target(config, command)
            Path(emit_make).write_text(content)
            print(f"\n{_colorize('Generated:', 'green')} {emit_make}")
            send_wizard_telemetry(
                wizard_start_time, config, __version__, artifact_type="makefile"
            )
            return 0

        if emit_script:
            command = generate_command(config)
            content = generate_shell_script(config, command)
            script_path = Path(emit_script)
            script_path.write_text(content)
            # Set execute permission (no effect on Windows, which lacks Unix permission bits)
            try:
                script_path.chmod(0o755)
            except OSError:
                pass  # Windows doesn't support Unix permissions
            print(f"\n{_colorize('Generated:', 'green')} {emit_script}")
            send_wizard_telemetry(
                wizard_start_time, config, __version__, artifact_type="shell"
            )
            return 0

        if emit_gha:
            content = generate_github_actions(config, PROFILES)
            gha_path = Path(emit_gha)
            gha_path.parent.mkdir(parents=True, exist_ok=True)
            gha_path.write_text(content)
            print(f"\n{_colorize('Generated:', 'green')} {emit_gha}")
            send_wizard_telemetry(
                wizard_start_time, config, __version__, artifact_type="gha"
            )
            return 0

        # Execute scan
        result = execute_scan(config, yes=yes)

        # Handle trend analysis after successful scan (if ≥2 scans exist)
        if result == 0 or result == 1:  # Success (0 = clean, 1 = findings)
            history_db_path = _get_db_path()

            # Non-interactive trend analysis
            if analyze_trends or export_trends_html or export_trends_json:
                if not history_db_path.exists():
                    print(
                        _colorize(
                            "\n⚠ No history database found (need ≥2 scans)", "yellow"
                        )
                    )
                else:
                    try:
                        from scripts.core.history_db import get_connection

                        conn = get_connection(history_db_path)
                        cursor = conn.execute("SELECT COUNT(*) FROM scans")
                        scan_count = cursor.fetchone()[0]

                        if scan_count < 2:
                            print(
                                _colorize(
                                    f"\n⚠ Only {scan_count} scan(s) in history (need ≥2)",
                                    "yellow",
                                )
                            )
                        else:
                            if analyze_trends:
                                print(
                                    _colorize("\n📊 Running trend analysis...", "blue")
                                )
                                _run_trend_command_interactive(
                                    history_db_path, "analyze", last_n=30
                                )

                            if export_trends_html or export_trends_json:
                                print(
                                    _colorize("\n📊 Exporting trend reports...", "blue")
                                )
                                from scripts.core.trend_analyzer import TrendAnalyzer
                                from scripts.cli.trend_formatters import (
                                    format_html_report,
                                    format_json_report,
                                )

                                analyzer = TrendAnalyzer(history_db_path)
                                report = analyzer.analyze_trends(last_n=30)

                                if export_trends_html:
                                    output_file = (
                                        Path(config.results_dir)
                                        / "summaries"
                                        / "trend_report.html"
                                    )
                                    output_file.parent.mkdir(
                                        parents=True, exist_ok=True
                                    )
                                    html_content = format_html_report(report)
                                    output_file.write_text(
                                        html_content, encoding="utf-8"
                                    )
                                    print(
                                        _colorize(
                                            f"✓ HTML report: {output_file}", "green"
                                        )
                                    )

                                if export_trends_json:
                                    output_file = (
                                        Path(config.results_dir)
                                        / "summaries"
                                        / "trend_report.json"
                                    )
                                    output_file.parent.mkdir(
                                        parents=True, exist_ok=True
                                    )
                                    json_content = format_json_report(report)
                                    output_file.write_text(
                                        json_content, encoding="utf-8"
                                    )
                                    print(
                                        _colorize(
                                            f"✓ JSON report: {output_file}", "green"
                                        )
                                    )

                    except Exception as e:
                        _safe_print(
                            _colorize(f"\n⚠ Trend analysis failed: {e}", "yellow")
                        )
                        logger.debug(f"Trend analysis error: {e}")
            else:
                # Interactive offers (only if no non-interactive flags)
                # 1. Policy evaluation (Phase 2.5)
                # Create args-like object with policy flags
                import argparse

                policy_args = argparse.Namespace(
                    policies=policies,
                    skip_policies=skip_policies,
                    yes=yes,
                )
                offer_policy_evaluation_after_scan(
                    config.results_dir, config.profile, policy_args
                )
                # 2. Trend analysis
                offer_trend_analysis_after_scan(config.results_dir)

        send_wizard_telemetry(
            wizard_start_time, config, __version__, artifact_type=None
        )
        return result

    except KeyboardInterrupt:
        print(_colorize("\n\nWizard cancelled", "yellow"))
        return 130
    except (OSError, ValueError, RuntimeError) as e:
        # System/configuration errors (file I/O, invalid inputs, etc.)
        print(_colorize(f"\n\nWizard error: {e}", "red"))
        logger.error(f"Wizard configuration error: {e}", exc_info=True)
        return 1
    except Exception as e:
        # Unexpected errors - log with full traceback
        print(_colorize(f"\n\nWizard error: {e}", "red"))
        logger.error(f"Unexpected wizard failure: {e}", exc_info=True)
        return 1


def offer_trend_analysis_after_scan(results_dir: str) -> None:
    """
    Offer trend analysis after scan completes (if ≥2 scans exist).

    Checks SQLite history for scan count and offers interactive trend exploration.
    Only shown if user has run at least 2 scans.

    Args:
        results_dir: Results directory from completed scan
    """
    # Check if history database exists and has ≥2 scans
    history_db_path = _get_db_path()

    if not history_db_path.exists():
        # No history yet, skip trend offer
        return

    try:
        from scripts.core.history_db import get_connection

        conn = get_connection(history_db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        scan_count = cursor.fetchone()[0]

        if scan_count < 2:
            # Not enough scans for trends
            return

        print("\n" + _colorize("=" * 60, "blue"))
        _safe_print(_colorize("📊 Trend Analysis Available", "bold"))
        print(_colorize("=" * 60, "blue"))
        print(f"\nYou have {_colorize(str(scan_count), 'green')} scans in history.")
        print("Would you like to explore security trends?")
        _safe_print("  • View overall security trend")
        _safe_print("  • Identify regressions")
        _safe_print("  • Track remediation velocity")
        _safe_print("  • See top remediators")

        if _prompt_yes_no("\nExplore trends now?", default=False):
            explore_trends_interactive(history_db_path, results_dir)

    except Exception as e:
        # Don't block user if trend offer fails
        logger.debug(f"Trend offer failed: {e}")


def offer_policy_evaluation_after_scan(results_dir: str, profile: str, args) -> None:
    """
    Offer policy evaluation after scan completes.

    Prompts user to evaluate security policies against scan findings.
    Respects CLI flags: --policies, --skip-policies.

    Args:
        results_dir: Results directory from completed scan
        profile: Scan profile name (fast/balanced/deep)
        args: Parsed CLI arguments with policy flags
    """
    from pathlib import Path
    import json

    # Check if user explicitly skipped policies via CLI
    if getattr(args, "skip_policies", False):
        logger.debug("Policy evaluation skipped via --skip-policies flag")
        return

    # Load findings from scan results
    findings_path = Path(results_dir) / "summaries" / "findings.json"
    if not findings_path.exists():
        logger.debug(
            f"Findings not found at {findings_path}, skipping policy evaluation"
        )
        return

    try:
        findings_data = json.loads(findings_path.read_text())
        findings = findings_data.get("findings", [])

        if not findings:
            logger.debug("No findings to evaluate, skipping policy evaluation")
            return

        # Import policy flow module
        from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu

        # Determine non-interactive mode
        non_interactive = getattr(args, "yes", False)

        # Call policy evaluation menu
        policy_results = policy_evaluation_menu(
            Path(results_dir),
            profile,
            findings,
            non_interactive=non_interactive,
        )

        if policy_results:
            logger.info(
                f"Policy evaluation completed: {len(policy_results)} policies evaluated"
            )

    except Exception as e:
        # Don't block user if policy evaluation fails
        _safe_print(_colorize(f"\n⚠ Policy evaluation failed: {e}", "yellow"))
        logger.debug(f"Policy evaluation error: {e}")


def explore_trends_interactive(db_path: Path, results_dir: str = "results") -> None:
    """
    Interactive menu for exploring trend analysis.

    9-option menu with:
    1. Overall security trend
    2. Regressions
    3. Remediation velocity
    4. Top remediators
    5. Security score history
    6. Compare two scans
    7. Export report
    8. Explain metrics
    9. Back to main menu

    Args:
        db_path: Path to SQLite history database
        results_dir: Results directory for exports
    """
    while True:
        print("\n" + _colorize("=" * 60, "blue"))
        _safe_print(_colorize("📊 Trend Analysis Menu", "bold"))
        print(_colorize("=" * 60, "blue"))

        print("\n  [1] Overall security trend (last 30 days)")
        print("  [2] Show regressions (new CRITICAL/HIGH findings)")
        print("  [3] Remediation velocity (fixes per day)")
        print("  [4] Top remediators (developer rankings)")
        print("  [5] Security score history (0-100 scale)")
        print("  [6] Compare two specific scans")
        print("  [7] Export trend report (HTML/JSON)")
        print("  [8] Explain metrics (help)")
        print("  [9] Back to main menu")

        choice = _prompt_choice(
            "\nSelect option:",
            [
                ("1", "Overall trend"),
                ("2", "Regressions"),
                ("3", "Remediation velocity"),
                ("4", "Top remediators"),
                ("5", "Security score"),
                ("6", "Compare scans"),
                ("7", "Export report"),
                ("8", "Explain metrics"),
                ("9", "Back"),
            ],
            default="1",
        )

        if choice == "9":
            print(_colorize("\nReturning to main menu...", "yellow"))
            break

        if choice == "1":
            _run_trend_command_interactive(db_path, "analyze", last_n=30)
        elif choice == "2":
            _run_trend_command_interactive(db_path, "regressions", last_n=30)
        elif choice == "3":
            _run_trend_command_interactive(db_path, "velocity", last_n=30)
        elif choice == "4":
            _run_trend_command_interactive(db_path, "developers", last_n=30)
        elif choice == "5":
            _run_trend_command_interactive(db_path, "score", last_n=30)
        elif choice == "6":
            _compare_scans_interactive(db_path)
        elif choice == "7":
            _export_trends_interactive(db_path, results_dir)
        elif choice == "8":
            _explain_metrics_interactive()


def _run_trend_command_interactive(
    db_path: Path, command: str, last_n: int = 30
) -> None:
    """
    Execute a trend analysis command interactively.

    Args:
        db_path: Path to SQLite history database
        command: Trend command (analyze/regressions/velocity/developers/score)
        last_n: Number of days to analyze
    """
    try:
        from scripts.cli.trend_commands import (  # type: ignore[attr-defined]  # Dynamic import for optional trend analysis
            cmd_trends_analyze,
            cmd_trends_regressions,
            cmd_trends_velocity,
            cmd_trends_developers,
            cmd_trends_score,
        )

        # Build mock args
        class TrendArgs:
            """
            Argument container for trend analysis workflows in the interactive wizard.

            This class stores user preferences collected during the wizard's trend analysis
            flow, enabling post-scan trend analysis and security posture tracking.

            Attributes:
                db (str): Path to SQLite history database.
                last (int): Number of most recent scans to analyze.
                format (str): Output format ('terminal', 'json', 'html', 'csv', 'prometheus', 'grafana', 'dashboard').
                output (Optional[str]): Output file path (None = stdout).
                top (int): Number of top items to display (default: 10).
                team_file (Optional[str]): Path to team mapping file (default: None).
                threshold (Optional[int]): Threshold for regression detection (default: None).
                repo (str): Repository path for git blame attribution (default: current directory).

            Example:
                >>> args = TrendArgs()
                >>> args.last = 50
                >>> args.format = 'html'
                >>> # Used internally by wizard to generate trend commands

            See Also:
                - jmo trends analyze: Core trend analysis command
                - scripts/cli/trend_commands.py: Trend command implementations
                - scripts/core/trend_analyzer.py: Statistical trend analysis engine

            Note:
                This class is used internally by the wizard and not exposed as a public API.
                For programmatic access, use `jmo trends` commands directly.
            """

            def __init__(self):
                self.db = str(db_path)
                self.last = last_n
                self.format = "terminal"  # Human-readable terminal output
                self.output = None  # Print to stdout
                self.top = 10  # Top N items
                self.team_file = None  # No team mapping
                self.threshold = None  # No threshold
                self.repo = str(Path.cwd())  # Current directory for git blame

        args = TrendArgs()

        # Dispatch to appropriate command
        command_map = {
            "analyze": cmd_trends_analyze,
            "regressions": cmd_trends_regressions,
            "velocity": cmd_trends_velocity,
            "developers": cmd_trends_developers,
            "score": cmd_trends_score,
        }

        cmd_func = command_map.get(command)
        if not cmd_func:
            print(_colorize(f"Unknown command: {command}", "red"))
            return

        print(_colorize(f"\n=== {command.title()} ===\n", "bold"))
        result = cmd_func(args)

        if result != 0:
            _safe_print(
                _colorize(f"\n⚠ Command failed with exit code {result}", "yellow")
            )

        # Pause for user to read output
        input(_colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        _safe_print(
            _colorize(
                "\n⚠ Trend analysis not available (missing dependencies)", "yellow"
            )
        )
        input(_colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        _safe_print(_colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Trend command failed: {e}", exc_info=True)
        input(_colorize("\nPress Enter to continue...", "blue"))


def _compare_scans_interactive(db_path: Path) -> None:
    """
    Interactive scan comparison workflow.

    Lists recent scans and prompts user to select two for comparison.
    Uses diff-engine for detailed comparison.

    Args:
        db_path: Path to SQLite history database
    """
    try:
        from scripts.core.history_db import list_recent_scans
        from scripts.cli.trend_commands import cmd_trends_compare

        # Load recent scans
        scans = list_recent_scans(db_path, limit=20)

        if len(scans) < 2:
            _safe_print(_colorize("\n⚠ Need at least 2 scans in history", "yellow"))
            input(_colorize("\nPress Enter to continue...", "blue"))
            return

        # Display scans
        print("\n" + _colorize("Recent Scans:", "bold"))
        print(
            f"{'#':<4} {'ID':<10} {'Timestamp':<20} {'Profile':<12} {'Branch':<15} {'Findings':<10}"
        )
        print("-" * 80)

        for i, scan in enumerate(scans, 1):
            scan_id = scan.get("id", "")[:8]
            timestamp = scan.get("timestamp_iso", "unknown")[:19]
            profile = scan.get("profile", "unknown")
            branch = scan.get("branch", "unknown")[:14]
            total = scan.get("total_findings", 0)

            print(
                f"{i:<4} {scan_id:<10} {timestamp:<20} {profile:<12} {branch:<15} {total:<10}"
            )

        # Select scans
        print()
        while True:
            try:
                baseline_choice = input(
                    _colorize("Select baseline scan number: ", "bold")
                ).strip()
                baseline_idx = int(baseline_choice) - 1
                if 0 <= baseline_idx < len(scans):
                    break
                print(_colorize("Invalid selection", "red"))
            except ValueError:
                print(_colorize("Invalid input", "red"))

        while True:
            try:
                current_choice = input(
                    _colorize("Select current scan number: ", "bold")
                ).strip()
                current_idx = int(current_choice) - 1
                if 0 <= current_idx < len(scans):
                    if current_idx != baseline_idx:
                        break
                    print(_colorize("Must select different scans", "red"))
                else:
                    print(_colorize("Invalid selection", "red"))
            except ValueError:
                print(_colorize("Invalid input", "red"))

        baseline_id = scans[baseline_idx]["id"]
        current_id = scans[current_idx]["id"]

        # Build args
        class CompareArgs:
            """
            Argument container for historical scan comparison workflows in the wizard.

            Stores user selections for comparing two historical scans from the SQLite
            database, enabling regression detection and remediation tracking.

            Attributes:
                db (str): Path to SQLite history database.
                scan_ids (list[str]): List of two scan IDs to compare [baseline_id, current_id].
                format (str): Output format ('terminal', 'json', 'md', 'html').
                output (Optional[str]): Output file path (None = stdout).

            Example:
                >>> args = CompareArgs()
                >>> args.scan_ids = ['baseline_abc123', 'current_def456']
                >>> args.format = 'md'
                >>> # Generates: jmo history compare baseline_abc123 current_def456 --format md

            See Also:
                - jmo history compare: Historical scan comparison
                - jmo diff: Result directory comparison
                - scripts/core/diff_engine.py: Diff computation engine

            Note:
                Wizard validates that both scan IDs exist in database before execution.
            """

            def __init__(self):
                self.db = str(db_path)
                self.scan_ids = [baseline_id, current_id]
                self.format = "terminal"
                self.output = None

        args = CompareArgs()

        _safe_print(
            _colorize(
                f"\n=== Comparing {baseline_id[:8]} → {current_id[:8]} ===\n", "bold"
            )
        )
        result = cmd_trends_compare(args)

        if result != 0:
            _safe_print(
                _colorize(f"\n⚠ Comparison failed with exit code {result}", "yellow")
            )

        input(_colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        _safe_print(
            _colorize(
                "\n⚠ Trend comparison not available (missing dependencies)", "yellow"
            )
        )
        input(_colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        _safe_print(_colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Scan comparison failed: {e}", exc_info=True)
        input(_colorize("\nPress Enter to continue...", "blue"))


def _export_trends_interactive(db_path: Path, results_dir: str) -> None:
    """
    Export trend report interactively.

    Prompts for format (HTML/JSON) and time range, then exports report.

    Args:
        db_path: Path to SQLite history database
        results_dir: Results directory for output
    """
    try:
        from scripts.cli.trend_formatters import format_html_report, format_json_report
        from scripts.core.trend_analyzer import TrendAnalyzer

        # Select format
        format_choice = _prompt_choice(
            "\nSelect export format:",
            [
                ("html", "Interactive HTML report"),
                ("json", "Machine-readable JSON"),
            ],
            default="html",
        )

        # Select time range
        print("\nTime range:")
        print("  [1] Last 7 days")
        print("  [2] Last 30 days")
        print("  [3] Last 90 days")
        print("  [4] All time")

        range_choice = _prompt_choice(
            "Select range:",
            [("1", "7 days"), ("2", "30 days"), ("3", "90 days"), ("4", "All")],
            default="2",
        )

        last_n = {"1": 7, "2": 30, "3": 90, "4": None}[range_choice]

        # Generate report
        print(_colorize("\n=== Generating Trend Report ===\n", "bold"))

        analyzer = TrendAnalyzer(db_path)
        report = analyzer.analyze_trends(last_n=last_n)

        if format_choice == "html":
            output_file = Path(results_dir) / "summaries" / "trend_report.html"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            html_content = format_html_report(report)
            output_file.write_text(html_content, encoding="utf-8")

            _safe_print(_colorize(f"✓ HTML report exported: {output_file}", "green"))

            if _prompt_yes_no("\nOpen report in browser?", default=True):
                import webbrowser

                webbrowser.open(f"file://{output_file.resolve()}")
        else:
            output_file = Path(results_dir) / "summaries" / "trend_report.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            json_content = format_json_report(report)
            output_file.write_text(json_content, encoding="utf-8")

            _safe_print(_colorize(f"✓ JSON report exported: {output_file}", "green"))

        input(_colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        _safe_print(
            _colorize("\n⚠ Trend export not available (missing dependencies)", "yellow")
        )
        input(_colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        _safe_print(_colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Trend export failed: {e}", exc_info=True)
        input(_colorize("\nPress Enter to continue...", "blue"))


def _explain_metrics_interactive() -> None:
    """
    Explain trend analysis metrics to users.

    Displays help text for each metric with examples.
    """
    print("\n" + _colorize("=" * 60, "bold"))
    _safe_print(_colorize("📖 Trend Analysis Metrics Explained", "bold"))
    print(_colorize("=" * 60, "bold"))

    _safe_print(
        """
1. OVERALL SECURITY TREND
   • Shows direction: improving, worsening, stable
   • Mann-Kendall test validates statistical significance
   • p < 0.05 = trend is significant (not random)

2. REGRESSIONS
   • New CRITICAL or HIGH findings in latest scan
   • Indicates code changes introducing vulnerabilities
   • Requires immediate action

3. REMEDIATION VELOCITY
   • Measures fixes per day (average)
   • Higher velocity = faster security improvements
   • Tracks team productivity

4. TOP REMEDIATORS
   • Developers who fixed most security issues
   • Based on git blame analysis
   • Shows focus areas and tool expertise

5. SECURITY SCORE
   • 0-100 scale: 100 = no findings, 0 = critical issues
   • Tracks progress over time
   • Weighted by severity (CRITICAL > HIGH > MEDIUM > LOW)

6. COMPARISON
   • Detailed diff between two scans
   • Shows new, resolved, modified findings
   • Identifies root causes of changes

Examples:
  • Trend: "Downward" = findings decreasing (good!)
  • Velocity: "3.2 fixes/day" = team resolving ~3 issues daily
  • Score: "85/100" = mostly clean, some medium issues

For more details, see: docs/USER_GUIDE.md#trend-analysis
"""
    )

    input(_colorize("\nPress Enter to continue...", "blue"))


def run_diff_wizard(use_docker: bool = False) -> int:
    """
    Run interactive diff wizard.

    Guides user through:
    1. Scan selection from history (or directory paths)
    2. Filter options (severity, tools, categories)
    3. Output format selection
    4. Diff execution and preview

    Returns:
        Exit code (0 = success, 1 = error, 130 = cancelled)
    """
    try:
        from scripts.core.history_db import list_recent_scans
        from scripts.cli.diff_commands import cmd_diff

        print(_colorize("\n=== JMo Security Diff Wizard ===\n", "bold"))
        print("This wizard helps you compare two security scan results.\n")

        # Step 1: Select comparison mode
        _print_step(1, DIFF_WIZARD_TOTAL_STEPS, "Select Comparison Mode")
        modes = [
            ("history", "Compare scans from history database"),
            ("directory", "Compare two result directories"),
        ]

        mode = _select_mode("Comparison modes", modes, default="history")

        baseline_path = None
        current_path = None
        baseline_id = None
        current_id = None

        if mode == "history":
            # Load recent scans from SQLite
            history_db_path = _get_db_path()

            if not history_db_path.exists():
                print(
                    _colorize(
                        f"\nError: History database not found at {history_db_path}",
                        "red",
                    )
                )
                print("Run some scans first to populate the history database.")
                return 1

            try:
                scans = list_recent_scans(history_db_path, limit=20)

                if len(scans) < 2:
                    print(_colorize("\nError: Need at least 2 scans in history", "red"))
                    print("Run more scans or use directory mode instead.")
                    return 1

                # Display available scans
                print("\nRecent scans:")
                for i, scan in enumerate(scans, 1):
                    timestamp = scan.get("timestamp_iso", "unknown")
                    profile = scan.get("profile", "unknown")
                    branch = scan.get("branch", "unknown")
                    total = scan.get("total_findings", 0)
                    scan_id = scan.get("id", "")[:8]

                    print(
                        f"  [{i:2d}] {scan_id}  {timestamp}  {profile:10s}  {branch:15s}  ({total} findings)"
                    )

                # Select baseline
                while True:
                    try:
                        choice = input(
                            _colorize("\nSelect baseline scan number: ", "bold")
                        ).strip()
                        idx = int(choice) - 1
                        if 0 <= idx < len(scans):
                            baseline_id = scans[idx]["id"]
                            break
                        print(_colorize("Invalid selection", "red"))
                    except (ValueError, KeyboardInterrupt):
                        raise KeyboardInterrupt

                # Select current
                while True:
                    try:
                        choice = input(
                            _colorize("Select current scan number: ", "bold")
                        ).strip()
                        idx = int(choice) - 1
                        if 0 <= idx < len(scans):
                            current_id = scans[idx]["id"]
                            if current_id != baseline_id:
                                break
                            print(_colorize("Must select different scans", "red"))
                        else:
                            print(_colorize("Invalid selection", "red"))
                    except (ValueError, KeyboardInterrupt):
                        raise KeyboardInterrupt

            except Exception as e:
                print(_colorize(f"\nError loading scan history: {e}", "red"))
                return 1
        else:
            # Directory mode
            _print_step(2, DIFF_WIZARD_TOTAL_STEPS, "Select Directories")

            baseline_path = input(
                _colorize("Baseline results directory: ", "bold")
            ).strip()
            if not Path(baseline_path).exists():
                print(_colorize(f"Error: Directory not found: {baseline_path}", "red"))
                return 1

            current_path = input(
                _colorize("Current results directory: ", "bold")
            ).strip()
            if not Path(current_path).exists():
                print(_colorize(f"Error: Directory not found: {current_path}", "red"))
                return 1

        # Step 2: Filter options
        _print_step(3, DIFF_WIZARD_TOTAL_STEPS, "Configure Filters (optional)")

        print("\nSeverity filtering:")
        print("  [1] All severities")
        print("  [2] CRITICAL only")
        print("  [3] CRITICAL + HIGH")
        print("  [4] CRITICAL + HIGH + MEDIUM")

        sev_choice = _prompt_choice(
            "Select severity filter:",
            [
                ("1", "All"),
                ("2", "CRITICAL"),
                ("3", "CRITICAL,HIGH"),
                ("4", "CRITICAL,HIGH,MEDIUM"),
            ],
            default="1",
        )
        severity_filter = {
            "1": "",
            "2": "CRITICAL",
            "3": "CRITICAL,HIGH",
            "4": "CRITICAL,HIGH,MEDIUM",
        }[sev_choice]

        print("\nCategory filtering:")
        print("  [1] All changes")
        print("  [2] New findings only")
        print("  [3] Resolved findings only")
        print("  [4] Modified findings only")

        cat_choice = _prompt_choice(
            "Select category filter:",
            [("1", "All"), ("2", "New"), ("3", "Resolved"), ("4", "Modified")],
            default="1",
        )
        category_filter = {"1": None, "2": "new", "3": "resolved", "4": "modified"}[
            cat_choice
        ]

        # Step 3: Output format
        _print_step(4, DIFF_WIZARD_TOTAL_STEPS, "Select Output Format")

        formats = [
            ("json", "Machine-readable JSON"),
            ("md", "Markdown (GitHub/GitLab comments)"),
            ("html", "Interactive HTML dashboard"),
            ("sarif", "SARIF 2.1.0 (GitHub Security)"),
        ]

        output_format = _select_mode("Output formats", formats, default="html")

        output_file = f"diff-report.{output_format}"
        custom_output = input(
            _colorize(f"Output file [{output_file}]: ", "bold")
        ).strip()
        if custom_output:
            output_file = custom_output

        # Step 4: Review and execute
        _print_step(5, DIFF_WIZARD_TOTAL_STEPS, "Review and Execute")

        print("\n" + _colorize("Diff Configuration:", "bold"))
        if mode == "history":
            print(f"  Mode: {_colorize('History Database', 'green')}")
            print(f"  Baseline: {_colorize(baseline_id[:12], 'yellow')}")  # type: ignore[index]  # ID validated before slice
            print(f"  Current: {_colorize(current_id[:12], 'yellow')}")  # type: ignore[index]  # ID validated before slice
        else:
            print(f"  Mode: {_colorize('Directory Comparison', 'green')}")
            print(f"  Baseline: {baseline_path}")
            print(f"  Current: {current_path}")

        if severity_filter:
            print(f"  Severity: {_colorize(severity_filter, 'yellow')}")
        if category_filter:
            print(f"  Category: {_colorize(category_filter, 'yellow')}")

        print(f"  Format: {_colorize(output_format, 'green')}")
        print(f"  Output: {output_file}")

        if not _prompt_yes_no("\nGenerate diff report?", default=True):
            print(_colorize("\nDiff cancelled", "yellow"))
            return 0

        # Build command args (mock argparse namespace)
        class DiffArgs:
            """
            Argument container for result directory diff workflows in the wizard.

            Stores user selections for comparing two result directories, enabling
            regression detection in CI/CD pipelines and PR reviews.

            Attributes:
                directories (Optional[list[str]]): List of two result directories [baseline, current] (directory mode).
                scan_ids (Optional[list[str]]): List of two scan IDs [baseline, current] (history mode).
                db (str): Path to SQLite history database (for history mode).
                severity (Optional[list[str]]): Filter by severity levels (e.g., ['CRITICAL', 'HIGH']).
                tool (Optional[str]): Filter by specific tool (default: None = all tools).
                only (str): Filter by change type ('all', 'new', 'fixed', 'modified').
                no_modifications (bool): Skip modification detection for faster diffs (default: False).
                format (str): Output format ('json', 'md', 'html', 'sarif').
                output (str): Output file path.

            Example:
                >>> args = DiffArgs()
                >>> args.directories = ['results-main', 'results-feature-branch']
                >>> args.severity = ['HIGH', 'CRITICAL']
                >>> args.only = 'new'
                >>> args.format = 'md'
                >>> # Generates: jmo diff results-main/ results-feature-branch/ --severity HIGH CRITICAL --only new --format md

            See Also:
                - jmo diff: Result directory comparison
                - jmo history compare: Historical scan comparison
                - docs/examples/diff-workflows.md: CI/CD integration examples

            Note:
                Wizard validates that both directories exist and contain summaries/findings.json.
            """

            def __init__(self):
                self.directories = (
                    [baseline_path, current_path] if mode == "directory" else None
                )
                self.scan_ids = [baseline_id, current_id] if mode == "history" else None
                self.db = str(_get_db_path())
                self.severity = severity_filter if severity_filter else None
                self.tool = None
                self.only = category_filter
                self.no_modifications = False
                self.format = output_format
                self.output = output_file

        args = DiffArgs()

        # Execute diff
        print(_colorize("\n=== Generating Diff Report ===\n", "bold"))
        result = cmd_diff(args)

        if result == 0:
            _safe_print(_colorize(f"\n✓ Diff report generated: {output_file}", "green"))

            # Auto-open HTML reports
            if output_format == "html" and Path(output_file).exists():
                if _prompt_yes_no("\nOpen report in browser?", default=True):
                    import webbrowser

                    webbrowser.open(f"file://{Path(output_file).resolve()}")
        else:
            _safe_print(_colorize("\n✗ Diff generation failed", "red"))

        return result

    except KeyboardInterrupt:
        print(_colorize("\n\nDiff wizard cancelled", "yellow"))
        return 130
    except Exception as e:
        print(_colorize(f"\n\nDiff wizard error: {e}", "red"))
        logger.error(f"Diff wizard failure: {e}", exc_info=True)
        return 1


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Interactive wizard for security scanning and diff analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Add mode selector
    parser.add_argument(
        "--mode",
        choices=["scan", "diff"],
        default="scan",
        help="Wizard mode: scan (default) or diff",
    )

    parser.add_argument(
        "--yes", "-y", action="store_true", help="Non-interactive mode (use defaults)"
    )
    parser.add_argument(
        "--docker", action="store_true", help="Force Docker execution mode"
    )
    parser.add_argument(
        "--emit-make-target",
        metavar="FILE",
        nargs="?",
        const="Makefile.jmo",
        type=str,
        help="Generate Makefile target (default: Makefile.jmo)",
    )
    parser.add_argument(
        "--emit-script",
        metavar="FILE",
        nargs="?",
        const="jmo-scan.sh",
        type=str,
        help="Generate shell script (default: jmo-scan.sh)",
    )
    parser.add_argument(
        "--emit-gha",
        metavar="FILE",
        nargs="?",
        const=".github/workflows/jmo-security.yml",
        type=str,
        help="Generate GitHub Actions workflow (default: .github/workflows/jmo-security.yml)",
    )

    # Trend analysis flags (v1.0.0+)
    parser.add_argument(
        "--analyze-trends",
        action="store_true",
        help="Automatically analyze trends after scan (non-interactive)",
    )
    parser.add_argument(
        "--export-trends-html",
        action="store_true",
        help="Export trend report as HTML after scan",
    )
    parser.add_argument(
        "--export-trends-json",
        action="store_true",
        help="Export trend report as JSON after scan",
    )

    # Policy evaluation flags (v1.0.0+)
    parser.add_argument(
        "--policy",
        action="append",
        dest="policies",
        help="Policy to evaluate after scan (can be specified multiple times, e.g., --policy owasp-top-10 --policy zero-secrets)",
    )
    parser.add_argument(
        "--skip-policies",
        action="store_true",
        help="Skip policy evaluation entirely (overrides config defaults)",
    )

    args = parser.parse_args()

    if args.mode == "diff":
        return run_diff_wizard(use_docker=args.docker)
    else:
        return run_wizard(
            yes=args.yes,
            force_docker=args.docker,
            emit_make=args.emit_make_target,
            emit_script=args.emit_script,
            emit_gha=args.emit_gha,
            analyze_trends=args.analyze_trends,
            export_trends_html=args.export_trends_html,
            export_trends_json=args.export_trends_json,
            policies=args.policies,
            skip_policies=args.skip_policies,
        )


if __name__ == "__main__":
    raise SystemExit(main())
