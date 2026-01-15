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
from typing import cast

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

# Phase 1 refactor: Import from new modules
from scripts.cli.wizard_flows.config_models import (
    TargetConfig,
    WizardConfig,
)
from scripts.cli.wizard_flows.profile_config import (
    PROFILES,
    WIZARD_TOTAL_STEPS,
    TOOL_TIME_ESTIMATES,  # noqa: F401 - re-exported for backward compat
    calculate_time_estimate,
    format_time_range,
)
from scripts.cli.wizard_flows.ui_helpers import (
    UNICODE_FALLBACKS as _UNICODE_FALLBACKS,  # noqa: F401 - re-exported for tests
    safe_print as _safe_print,
    prompt_text as _prompt_text,
    prompt_choice as _prompt_choice,
    select_mode as _select_mode,
)

# Phase 2 refactor: Import tool checking from tool_checker module
# Used functions
from scripts.cli.wizard_flows.tool_checker import (
    check_tools_for_profile,
    _check_policy_tools,
)

# Re-exported for backward compatibility with tests
from scripts.cli.wizard_flows.tool_checker import (  # noqa: F401
    _auto_fix_tools,
    _show_all_fix_commands,
    _collect_missing_dependencies,
    _install_missing_tools_interactive,
    _install_opa_tool,
)

# Phase 3 refactor: Import trend analysis from trend_flow module
# Used functions
from scripts.cli.wizard_flows.trend_flow import (
    offer_trend_analysis_after_scan,
    _run_trend_command_interactive,
)

# Re-exported for backward compatibility with tests
from scripts.cli.wizard_flows.trend_flow import (  # noqa: F401
    explore_trends_interactive,
    _compare_scans_interactive,
    _export_trends_interactive,
    _explain_metrics_interactive,
    TrendArgs,
    CompareArgs,
)

# Phase 4 refactor: Import diff wizard from diff_flow module
from scripts.cli.wizard_flows.diff_flow import (
    run_diff_wizard_impl,
)

# Re-exported for backward compatibility with tests
from scripts.cli.wizard_flows.diff_flow import DiffArgs  # noqa: F401


# Configure logging
logger = logging.getLogger(__name__)


# Backward-compat: _get_db_path delegates to WizardConfig.get_db_path
def _get_db_path() -> Path:
    """Get the history database path, respecting custom --db flag.

    Returns:
        Path to SQLite history database
    """
    return WizardConfig.get_db_path()


# Version (from pyproject.toml)
__version__ = "0.7.1"

# Standardized error message templates for tool issues
# These provide consistent, actionable guidance for different failure scenarios
TOOL_ISSUE_TEMPLATES: dict[str, str] = {
    "linux_only": """  [{icon}] {tool}: Linux only
       {reason}
       Options:
         - Docker: {docker_command}
         - WSL2: wsl --install -d Ubuntu
       Docs: {docs_url}""",
    "no_windows_binary": """  [{icon}] {tool}: No Windows binary available
       {reason}
       Options:
         - Docker: {docker_command}
         - WSL2: wsl --install -d Ubuntu
       Docs: {docs_url}""",
    "missing_dependency": """  [{icon}] {tool}: {dependency} {min_version}+ required
       {tool} requires {dependency} to run.
       Auto-fix will install {dependency} automatically.
       Manual: {manual_command}""",
    "startup_crash": """  [!!] {tool}: STARTUP CRASH - {error_type}
       Error: {error_detail}
       Fix: jmo tools clean --force && jmo tools install {tool}
            (Reinstalls in isolated virtual environment)""",
    "docker_only": """  [{icon}] {tool}: Docker required
       {reason}
       Docker command:
         {docker_command}
       Docs: {docs_url}""",
    "windows_registry": """  [{icon}] {tool}: Windows configuration required
       {reason}
       Fix (requires admin PowerShell):
         {registry_command}
       Then reboot and re-run: jmo tools install {tool}
       Alternative: Use Docker mode""",
}


# Use PromptHelper from wizard_flows for all prompting/coloring
_prompter = PromptHelper()
_colorize = _prompter.colorize
_print_header = _prompter.print_header
_print_step = _prompter.print_step


# Use PromptHelper.prompt_yes_no for all yes/no prompts
_prompt_yes_no = _prompter.prompt_yes_no  # Direct delegation to PromptHelper


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
# Tool checking functions now imported from tool_checker module (Phase 2 refactor)


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

    # Set custom db_path for this wizard run (via WizardConfig class method)
    WizardConfig.set_db_path(db_path)

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


# Trend analysis functions moved to wizard_flows/trend_flow.py (Phase 3 refactor)


def run_diff_wizard(use_docker: bool = False) -> int:
    """Run the diff wizard for comparing scans.

    This is a thin wrapper that delegates to the implementation
    in wizard_flows/diff_flow.py (Phase 4 refactor).

    Guides user through:
    1. Scan selection from history (or directory paths)
    2. Filter options (severity, tools, categories)
    3. Output format selection
    4. Diff execution and preview

    Args:
        use_docker: Whether to use Docker mode

    Returns:
        Exit code (0 = success, 1 = error, 130 = cancelled)
    """
    return run_diff_wizard_impl(use_docker=use_docker)


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
