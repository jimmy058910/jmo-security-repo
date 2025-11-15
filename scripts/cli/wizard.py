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
            "trivy",
            "checkov",
            "checkov-cicd",
            "hadolint",
            "syft",
            "osv-scanner",
        ],
        "timeout": 300,
        "threads": 8,
        "est_time": "5-10 minutes",
        "use_case": "Pre-commit checks, quick validation, CI/CD gate",
    },
    "balanced": {
        "name": "Balanced",
        "description": "Production CI/CD with 21 tools (cloud, API, DAST, license)",
        "tools": [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
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
            "osv-scanner",
            "yara",
            "grype",
            "bearer",
            "horusec",
            "dependency-check",
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
            "osv-scanner",
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
    Prompt user for a choice from a list (legacy wrapper).

    DEPRECATED: Use _prompter.prompt_choice() directly for new code.
    This function is kept for backward compatibility with existing wizard code.

    Args:
        question: Question to ask
        choices: List of (key, description) tuples
        default: Default choice key

    Returns:
        Selected choice key
    """
    # Convert (key, desc) tuples to list of keys for PromptHelper
    choice_keys = [c[0] for c in choices]

    # Print question and choices in legacy format
    print(f"\n{question}")
    for key, desc in choices:
        prefix = ">" if key == default else " "
        print(f"  {prefix} [{key}] {desc}")

    if default:
        prompt = f"Choice [{default}]: "
    else:
        prompt = "Choice: "

    while True:
        choice = input(prompt).strip().lower()
        if not choice and default:
            return default
        if choice in choice_keys:
            return choice
        print(
            _colorize(
                f"Invalid choice. Please enter one of: {', '.join(choice_keys)}",
                "red",
            )
        )


# Use PromptHelper.prompt_yes_no for all yes/no prompts
_prompt_yes_no = _prompter.prompt_yes_no  # Direct delegation to PromptHelper


def _select_mode(title: str, modes: list[tuple[str, str]], default: str = "") -> str:
    """
    Helper to select from modes with consistent formatting.

    Args:
        title: Mode category title (e.g., "Repository modes")
        modes: List of (key, description) tuples
        default: Default mode key

    Returns:
        Selected mode key
    """
    print(f"\n{title}:")
    for key, desc in modes:
        print(f"  [{key:10}] {desc}")

    return _prompt_choice("\nSelect mode:", modes, default=default)


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
        }


def select_profile() -> str:
    """Step 1: Select scanning profile."""
    _print_step(1, 6, "Select Scanning Profile")

    print("\nAvailable profiles:")
    for key, info in PROFILES.items():
        name = cast(str, info["name"])
        tools = cast(list[str], info["tools"])
        print(f"\n  {_colorize(name, 'bold')} ({key})")
        print(f"    Tools: {', '.join(tools[:3])}{'...' if len(tools) > 3 else ''}")
        print(f"    Time: {info['est_time']}")
        print(f"    Use: {info['use_case']}")

    # Use _select_mode helper (simpler than full custom display)
    return _select_mode(
        "Profiles",
        [(k, str(PROFILES[k]["name"])) for k in PROFILES.keys()],
        default="balanced",
    )


def select_execution_mode(force_docker: bool = False) -> bool:
    """Step 2: Select execution mode (native vs Docker)."""
    _print_step(2, 6, "Select Execution Mode")

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

    print("\nExecution modes:")
    print("  [native] Use locally installed tools")
    print("  [docker] Use pre-built Docker image (zero installation)")
    print()
    print(
        f"Docker available: {_colorize('Yes' if has_docker else 'No', 'green' if has_docker else 'red')}"
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

    use_docker = _prompt_yes_no(
        "\nUse Docker mode? (Recommended for first-time users)", default=True
    )
    return use_docker


def select_target_type() -> str:
    """
    Step 3a: Select target TYPE (repo, image, iac, url, gitlab, k8s).

    Returns:
        Target type string
    """
    _print_step(3, 7, "Select Scan Target Type")

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
    config = _configure_repo(TargetConfig, _print_step)
    return config  # type: ignore[no-any-return]


def configure_image_target() -> TargetConfig:
    """Configure container image scanning (delegates to target_configurators module)."""
    config = _configure_image(TargetConfig, _print_step)
    return config  # type: ignore[no-any-return]


def configure_iac_target() -> TargetConfig:
    """Configure IaC file scanning (delegates to target_configurators module)."""
    config = _configure_iac(TargetConfig, _print_step)
    return config  # type: ignore[no-any-return]


def configure_url_target() -> TargetConfig:
    """Configure web URL scanning (delegates to target_configurators module)."""
    config = _configure_url(TargetConfig, _print_step)
    return config  # type: ignore[no-any-return]


def configure_gitlab_target() -> TargetConfig:
    """Configure GitLab scanning (delegates to target_configurators module)."""
    config = _configure_gitlab(TargetConfig, _print_step)
    return config  # type: ignore[no-any-return]


def configure_k8s_target() -> TargetConfig:
    """Configure Kubernetes scanning (delegates to target_configurators module)."""
    config = _configure_k8s(TargetConfig, _print_step)
    return config  # type: ignore[no-any-return]


def configure_advanced(profile: str) -> tuple[int | None, int | None, str]:
    """
    Step 5: Configure advanced options.

    Returns:
        Tuple of (threads, timeout, fail_on)
    """
    _print_step(5, 7, "Advanced Configuration")

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

    Returns:
        True if user confirms, False otherwise
    """
    _print_step(6, 7, "Review Configuration")

    profile_info = PROFILES[config.profile]
    profile_name = cast(str, profile_info["name"])
    profile_threads = cast(int, profile_info["threads"])
    profile_timeout = cast(int, profile_info["timeout"])
    profile_est_time = cast(str, profile_info["est_time"])
    profile_tools = cast(list[str], profile_info["tools"])

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

    print(f"\n  Estimated time: {_colorize(profile_est_time, 'yellow')}")
    print(f"  Tools: {len(profile_tools)} ({', '.join(profile_tools[:3])}...)")

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
    _print_step(7, 7, "Execute Scan")

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

    Returns:
        Exit code
    """
    import time

    from scripts.core.telemetry import (
        should_show_telemetry_banner,
        show_telemetry_banner,
    )

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
        else:
            # Interactive mode with new multi-target selection
            config.profile = select_profile()
            config.use_docker = select_execution_mode(force_docker)

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
            script_path.chmod(0o755)
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
            db_path = Path.home() / ".jmo" / "history.db"

            # Non-interactive trend analysis
            if analyze_trends or export_trends_html or export_trends_json:
                if not db_path.exists():
                    print(
                        _colorize(
                            "\n⚠ No history database found (need ≥2 scans)", "yellow"
                        )
                    )
                else:
                    try:
                        from scripts.core.history_db import get_connection

                        conn = get_connection(db_path)
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
                                    db_path, "analyze", last_n=30
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

                                analyzer = TrendAnalyzer(db_path)
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
                                    output_file.write_text(html_content)
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
                                    output_file.write_text(json_content)
                                    print(
                                        _colorize(
                                            f"✓ JSON report: {output_file}", "green"
                                        )
                                    )

                    except Exception as e:
                        print(_colorize(f"\n⚠ Trend analysis failed: {e}", "yellow"))
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
    from pathlib import Path

    # Check if history database exists and has ≥2 scans
    db_path = Path.home() / ".jmo" / "history.db"

    if not db_path.exists():
        # No history yet, skip trend offer
        return

    try:
        from scripts.core.history_db import get_connection

        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        scan_count = cursor.fetchone()[0]

        if scan_count < 2:
            # Not enough scans for trends
            return

        print("\n" + _colorize("=" * 60, "blue"))
        print(_colorize("📊 Trend Analysis Available", "bold"))
        print(_colorize("=" * 60, "blue"))
        print(f"\nYou have {_colorize(str(scan_count), 'green')} scans in history.")
        print("Would you like to explore security trends?")
        print("  • View overall security trend")
        print("  • Identify regressions")
        print("  • Track remediation velocity")
        print("  • See top remediators")

        if _prompt_yes_no("\nExplore trends now?", default=False):
            explore_trends_interactive(db_path, results_dir)

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
        print(_colorize(f"\n⚠ Policy evaluation failed: {e}", "yellow"))
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
        print(_colorize("📊 Trend Analysis Menu", "bold"))
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
        from scripts.cli.trend_commands import (  # type: ignore[attr-defined]
            cmd_trends_analyze,
            cmd_trends_regressions,
            cmd_trends_velocity,
            cmd_trends_developers,
            cmd_trends_score,
        )

        # Build mock args
        class TrendArgs:
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
            print(_colorize(f"\n⚠ Command failed with exit code {result}", "yellow"))

        # Pause for user to read output
        input(_colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        print(
            _colorize(
                "\n⚠ Trend analysis not available (missing dependencies)", "yellow"
            )
        )
        input(_colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        print(_colorize(f"\n✗ Error: {e}", "red"))
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
            print(_colorize("\n⚠ Need at least 2 scans in history", "yellow"))
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
            def __init__(self):
                self.db = str(db_path)
                self.scan_ids = [baseline_id, current_id]
                self.format = "terminal"
                self.output = None

        args = CompareArgs()

        print(
            _colorize(
                f"\n=== Comparing {baseline_id[:8]} → {current_id[:8]} ===\n", "bold"
            )
        )
        result = cmd_trends_compare(args)

        if result != 0:
            print(_colorize(f"\n⚠ Comparison failed with exit code {result}", "yellow"))

        input(_colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        print(
            _colorize(
                "\n⚠ Trend comparison not available (missing dependencies)", "yellow"
            )
        )
        input(_colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        print(_colorize(f"\n✗ Error: {e}", "red"))
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
            output_file.write_text(html_content)

            print(_colorize(f"✓ HTML report exported: {output_file}", "green"))

            if _prompt_yes_no("\nOpen report in browser?", default=True):
                import webbrowser

                webbrowser.open(f"file://{output_file.resolve()}")
        else:
            output_file = Path(results_dir) / "summaries" / "trend_report.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            json_content = format_json_report(report)
            output_file.write_text(json_content)

            print(_colorize(f"✓ JSON report exported: {output_file}", "green"))

        input(_colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        print(
            _colorize("\n⚠ Trend export not available (missing dependencies)", "yellow")
        )
        input(_colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        print(_colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Trend export failed: {e}", exc_info=True)
        input(_colorize("\nPress Enter to continue...", "blue"))


def _explain_metrics_interactive() -> None:
    """
    Explain trend analysis metrics to users.

    Displays help text for each metric with examples.
    """
    print("\n" + _colorize("=" * 60, "bold"))
    print(_colorize("📖 Trend Analysis Metrics Explained", "bold"))
    print(_colorize("=" * 60, "bold"))

    print(
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
        _print_step(1, 5, "Select Comparison Mode")
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
            db_path = Path.home() / ".jmo" / "history.db"

            if not db_path.exists():
                print(
                    _colorize(
                        f"\nError: History database not found at {db_path}", "red"
                    )
                )
                print("Run some scans first to populate the history database.")
                return 1

            try:
                scans = list_recent_scans(db_path, limit=20)

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
            _print_step(2, 5, "Select Directories")

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
        _print_step(3, 5, "Configure Filters (optional)")

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
        _print_step(4, 5, "Select Output Format")

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
        _print_step(5, 5, "Review and Execute")

        print("\n" + _colorize("Diff Configuration:", "bold"))
        if mode == "history":
            print(f"  Mode: {_colorize('History Database', 'green')}")
            print(f"  Baseline: {_colorize(baseline_id[:12], 'yellow')}")  # type: ignore[index]
            print(f"  Current: {_colorize(current_id[:12], 'yellow')}")  # type: ignore[index]
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
            def __init__(self):
                self.directories = (
                    [baseline_path, current_path] if mode == "directory" else None
                )
                self.scan_ids = [baseline_id, current_id] if mode == "history" else None
                self.db = str(Path.home() / ".jmo" / "history.db")
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
            print(_colorize(f"\n✓ Diff report generated: {output_file}", "green"))

            # Auto-open HTML reports
            if output_format == "html" and Path(output_file).exists():
                if _prompt_yes_no("\nOpen report in browser?", default=True):
                    import webbrowser

                    webbrowser.open(f"file://{Path(output_file).resolve()}")
        else:
            print(_colorize("\n✗ Diff generation failed", "red"))

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
        "--emit-make-target", metavar="FILE", help="Generate Makefile target"
    )
    parser.add_argument("--emit-script", metavar="FILE", help="Generate shell script")
    parser.add_argument(
        "--emit-gha", metavar="FILE", help="Generate GitHub Actions workflow"
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
