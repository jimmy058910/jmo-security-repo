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
from typing import Any, Dict, List, Optional, Tuple, cast

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
    question: str, choices: List[Tuple[str, str]], default: str = ""
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


def _select_mode(title: str, modes: List[Tuple[str, str]], default: str = "") -> str:
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

    def to_dict(self) -> Dict[str, Any]:
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
        self.threads: Optional[int] = None
        self.timeout: Optional[int] = None
        self.fail_on: str = ""
        self.allow_missing_tools: bool = True
        self.human_logs: bool = True

    def to_dict(self) -> Dict[str, Any]:
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
        }


def select_profile() -> str:
    """Step 1: Select scanning profile."""
    _print_step(1, 6, "Select Scanning Profile")

    print("\nAvailable profiles:")
    for key, info in PROFILES.items():
        name = cast(str, info["name"])
        tools = cast(List[str], info["tools"])
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


def configure_advanced(profile: str) -> Tuple[Optional[int], Optional[int], str]:
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
    profile_tools = cast(List[str], profile_info["tools"])

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
    profile_tools = cast(List[str], profile_info["tools"])

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


def execute_scan(config: WizardConfig) -> int:
    """
    Step 7: Execute the scan.

    Returns:
        Exit code from scan
    """
    _print_step(7, 7, "Execute Scan")

    command = generate_command(config)

    print("\n" + _colorize("Generated command:", "bold"))
    print(_colorize(f"  {command}", "green"))
    print()

    if not _prompt_yes_no("Execute now?", default=True):
        print("\nCommand saved. You can run it later:")
        print(f"  {command}")
        return 0

    print(_colorize("\nStarting scan...", "blue"))
    print()

    # Execute via subprocess
    try:
        if config.use_docker:
            # Docker execution - use list for security (no shell=True)
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
                    + _colorize(
                        "📖 Learn how to triage and act on your findings:", "blue"
                    )
                )
                print("  - Quick triage (30 min): docs/RESULTS_QUICK_REFERENCE.md")
                print("  - Complete guide: docs/RESULTS_GUIDE.md")
            return result.returncode
        else:
            # Native execution via jmotools
            sys.path.insert(0, str(Path(__file__).parent))
            from jmotools import main as jmotools_main

            # Build argv from secure list
            command_list = generate_command_list(config)
            argv = command_list[1:]  # Skip 'jmotools'
            exit_code: int = jmotools_main(argv)
            return exit_code

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
    emit_make: Optional[str] = None,
    emit_script: Optional[str] = None,
    emit_gha: Optional[str] = None,
) -> int:
    """
    Run the interactive wizard.

    Args:
        yes: Skip prompts and use defaults
        force_docker: Force Docker mode
        emit_make: Generate Makefile target to this file
        emit_script: Generate shell script to this file
        emit_gha: Generate GitHub Actions workflow to this file

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
        result = execute_scan(config)
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


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Interactive wizard for security scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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

    args = parser.parse_args()

    return run_wizard(
        yes=args.yes,
        force_docker=args.docker,
        emit_make=args.emit_make_target,
        emit_script=args.emit_script,
        emit_gha=args.emit_gha,
    )


if __name__ == "__main__":
    raise SystemExit(main())
