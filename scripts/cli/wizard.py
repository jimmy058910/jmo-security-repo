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

import os
import shutil
import subprocess  # nosec B404 - CLI needs subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

# Profile definitions with resource estimates (v0.5.0)
PROFILES = {
    "fast": {
        "name": "Fast",
        "description": "Speed + coverage with 3 best-in-breed tools",
        "tools": ["trufflehog", "semgrep", "trivy"],
        "timeout": 300,
        "threads": 8,
        "est_time": "5-8 minutes",
        "use_case": "Pre-commit checks, quick validation, CI/CD gate",
    },
    "balanced": {
        "name": "Balanced",
        "description": "Production-ready with DAST and comprehensive coverage",
        "tools": [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
        ],
        "timeout": 600,
        "threads": 4,
        "est_time": "15-20 minutes",
        "use_case": "CI/CD pipelines, regular audits, production scans",
    },
    "deep": {
        "name": "Deep",
        "description": "Maximum coverage with runtime monitoring and fuzzing",
        "tools": [
            "trufflehog",
            "noseyparker",
            "semgrep",
            "bandit",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
            "falco",
            "afl++",
        ],
        "timeout": 900,
        "threads": 2,
        "est_time": "30-60 minutes",
        "use_case": "Security audits, compliance scans, pre-release validation",
    },
}


def _colorize(text: str, color: str) -> str:
    """Apply ANSI color codes."""
    colors = {
        "blue": "\x1b[36m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "red": "\x1b[31m",
        "bold": "\x1b[1m",
        "reset": "\x1b[0m",
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def _print_header(text: str) -> None:
    """Print a formatted section header."""
    print()
    print(_colorize("=" * 70, "blue"))
    print(_colorize(text.center(70), "bold"))
    print(_colorize("=" * 70, "blue"))
    print()


def _print_step(step: int, total: int, text: str) -> None:
    """Print a step indicator."""
    print(_colorize(f"\n[Step {step}/{total}] {text}", "blue"))


def _prompt_choice(
    question: str, choices: List[Tuple[str, str]], default: str = ""
) -> str:
    """
    Prompt user for a choice from a list.

    Args:
        question: Question to ask
        choices: List of (key, description) tuples
        default: Default choice key

    Returns:
        Selected choice key
    """
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
        if any(c[0] == choice for c in choices):
            return choice
        print(
            _colorize(
                f"Invalid choice. Please enter one of: {', '.join(c[0] for c in choices)}",
                "red",
            )
        )


def _prompt_text(question: str, default: str = "") -> str:
    """Prompt user for text input."""
    if default:
        prompt = f"{question} [{default}]: "
    else:
        prompt = f"{question}: "

    value = input(prompt).strip()
    return value if value else default


def _prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt user for yes/no."""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{question} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ("y", "yes"):
            return True
        if response in ("n", "no"):
            return False
        print(_colorize("Please enter 'y' or 'n'", "red"))


def _detect_docker() -> bool:
    """Check if Docker is available."""
    return shutil.which("docker") is not None


def _check_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(  # nosec B603 - controlled command
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _get_cpu_count() -> int:
    """Get CPU count for thread recommendations."""
    try:
        return os.cpu_count() or 4
    except Exception:
        return 4


def _detect_repos_in_dir(path: Path) -> List[Path]:
    """Detect git repositories in a directory."""
    repos: List[Path] = []
    if not path.exists() or not path.is_dir():
        return repos

    # Check immediate subdirectories
    for item in path.iterdir():
        if item.is_dir() and (item / ".git").exists():
            repos.append(item)

    return repos


def _validate_path(path_str: str, must_exist: bool = True) -> Optional[Path]:
    """Validate and expand a path."""
    try:
        path = Path(path_str).expanduser().resolve()
        if must_exist and not path.exists():
            return None
        return path
    except Exception:
        return None


class WizardConfig:
    """Configuration collected by the wizard."""

    def __init__(self) -> None:
        self.profile: str = "balanced"
        self.use_docker: bool = False
        self.target_mode: str = ""  # repo, repos-dir, targets, tsv
        self.target_path: str = ""
        self.tsv_path: str = ""
        self.tsv_dest: str = "repos-tsv"
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
            "target_mode": self.target_mode,
            "target_path": self.target_path,
            "tsv_path": self.tsv_path,
            "tsv_dest": self.tsv_dest,
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

    choices = [(k, str(PROFILES[k]["name"])) for k in PROFILES.keys()]
    return _prompt_choice("\nSelect profile:", choices, default="balanced")


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


def select_target() -> Tuple[str, str, str, str]:
    """
    Step 3: Select scan target.

    Returns:
        Tuple of (mode, path, tsv_path, tsv_dest)
    """
    _print_step(3, 6, "Select Scan Target")

    print("\nTarget options:")
    print("  [repo]      Single repository")
    print("  [repos-dir] Directory containing multiple repos")
    print("  [targets]   File listing repo paths")
    print("  [tsv]       Clone repos from TSV file")

    choices = [
        ("repo", "Single repository"),
        ("repos-dir", "Directory with repos"),
        ("targets", "Targets file"),
        ("tsv", "Clone from TSV"),
    ]
    mode = _prompt_choice("\nSelect target type:", choices, default="repos-dir")

    if mode == "tsv":
        tsv_path = _prompt_text("Path to TSV file", default="./repos.tsv")
        tsv_dest = _prompt_text("Clone destination", default="repos-tsv")
        return mode, "", tsv_path, tsv_dest

    # For other modes, prompt for path
    prompts = {
        "repo": "Path to repository",
        "repos-dir": "Path to repos directory",
        "targets": "Path to targets file",
    }

    while True:
        path = _prompt_text(prompts[mode])
        if not path:
            print(_colorize("Path cannot be empty", "red"))
            continue

        validated = _validate_path(path, must_exist=(mode != "tsv"))
        if validated:
            # For repos-dir, show detected repos
            if mode == "repos-dir":
                repos = _detect_repos_in_dir(validated)
                if repos:
                    print(
                        f"\n{_colorize(f'Found {len(repos)} repositories:', 'green')}"
                    )
                    for repo in repos[:5]:
                        print(f"  - {repo.name}")
                    if len(repos) > 5:
                        print(f"  ... and {len(repos) - 5} more")
                else:
                    print(_colorize("Warning: No git repositories detected", "yellow"))
                    if not _prompt_yes_no("Continue anyway?", default=False):
                        continue

            return mode, str(validated), "", ""

        print(_colorize(f"Path not found: {path}", "red"))


def configure_advanced(profile: str) -> Tuple[Optional[int], Optional[int], str]:
    """
    Step 4: Configure advanced options.

    Returns:
        Tuple of (threads, timeout, fail_on)
    """
    _print_step(4, 6, "Advanced Configuration")

    profile_info = PROFILES[profile]
    cpu_count = _get_cpu_count()
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


def review_and_confirm(config: WizardConfig) -> bool:
    """
    Step 5: Review configuration and confirm.

    Returns:
        True if user confirms, False otherwise
    """
    _print_step(5, 6, "Review Configuration")

    profile_info = PROFILES[config.profile]
    profile_name = cast(str, profile_info["name"])
    profile_threads = cast(int, profile_info["threads"])
    profile_timeout = cast(int, profile_info["timeout"])
    profile_est_time = cast(str, profile_info["est_time"])
    profile_tools = cast(List[str], profile_info["tools"])

    print("\n" + _colorize("Configuration Summary:", "bold"))
    print(f"  Profile: {_colorize(profile_name, 'green')} ({config.profile})")
    print(f"  Mode: {_colorize('Docker' if config.use_docker else 'Native', 'green')}")
    print(f"  Target: {_colorize(config.target_mode, 'green')}")

    if config.target_mode == "tsv":
        print(f"    TSV: {config.tsv_path}")
        print(f"    Dest: {config.tsv_dest}")
    else:
        print(f"    Path: {config.target_path}")

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


def generate_command(config: WizardConfig) -> str:
    """Generate the jmotools command from config."""
    profile_info = PROFILES[config.profile]
    profile_threads = cast(int, profile_info["threads"])
    profile_timeout = cast(int, profile_info["timeout"])

    if config.use_docker:
        # Docker command
        target_mount = ""
        if config.target_mode == "repo":
            target_mount = f"-v {config.target_path}:/scan"
        elif config.target_mode == "repos-dir":
            target_mount = f"-v {config.target_path}:/scan"

        results_mount = f"-v $(pwd)/{config.results_dir}:/results"

        cmd_parts = [
            "docker run --rm",
            target_mount,
            results_mount,
            "ghcr.io/jimmy058910/jmo-security:latest",
            "scan",
        ]

        if config.target_mode in ("repo", "repos-dir"):
            cmd_parts.append("--repos-dir /scan")
        cmd_parts.append("--results /results")
        cmd_parts.append(f"--profile {config.profile}")

    else:
        # Native command
        cmd_parts = ["jmotools", config.profile]

        if config.target_mode == "repo":
            cmd_parts.extend(["--repo", config.target_path])
        elif config.target_mode == "repos-dir":
            cmd_parts.extend(["--repos-dir", config.target_path])
        elif config.target_mode == "targets":
            cmd_parts.extend(["--targets", config.target_path])
        elif config.target_mode == "tsv":
            cmd_parts.extend(["--tsv", config.tsv_path, "--dest", config.tsv_dest])

        cmd_parts.extend(["--results-dir", config.results_dir])

    # Common options
    threads = config.threads or profile_threads
    timeout = config.timeout or profile_timeout

    cmd_parts.extend(["--threads", str(threads)])
    cmd_parts.extend(["--timeout", str(timeout)])

    if config.fail_on:
        cmd_parts.extend(["--fail-on", config.fail_on])

    # Note: --allow-missing-tools is implicitly enabled for jmotools wrapper
    # No need to add it explicitly as it's not exposed in jmotools interface

    if config.human_logs:
        cmd_parts.append("--human-logs")

    return " ".join(cmd_parts)


def execute_scan(config: WizardConfig) -> int:
    """
    Step 6: Execute the scan.

    Returns:
        Exit code from scan
    """
    _print_step(6, 6, "Execute Scan")

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
            # Docker execution
            result = subprocess.run(  # nosec B603 - controlled command
                command,
                shell=True,  # nosec B602 - command built from controlled inputs
                check=False,
            )
            return result.returncode
        else:
            # Native execution via jmotools
            sys.path.insert(0, str(Path(__file__).parent))
            from jmotools import main as jmotools_main

            # Build argv
            argv = command.split()[1:]  # Skip 'jmotools'
            exit_code: int = jmotools_main(argv)
            return exit_code

    except KeyboardInterrupt:
        print(_colorize("\n\nScan cancelled by user", "yellow"))
        return 130
    except Exception as e:
        print(_colorize(f"\n\nScan failed: {e}", "red"))
        return 1


def generate_makefile_target(config: WizardConfig) -> str:
    """Generate a Makefile target."""
    command = generate_command(config)

    return f"""
# JMo Security Scan Target (generated by wizard)
.PHONY: security-scan
security-scan:
\t{command}
"""


def generate_shell_script(config: WizardConfig) -> str:
    """Generate a shell script."""
    command = generate_command(config)

    return f"""#!/usr/bin/env bash
# JMo Security Scan Script (generated by wizard)
set -euo pipefail

{command}
"""


def generate_github_actions(config: WizardConfig) -> str:
    """Generate a GitHub Actions workflow."""
    profile_info = PROFILES[config.profile]
    profile_threads = cast(int, profile_info["threads"])
    profile_timeout = cast(int, profile_info["timeout"])
    threads = config.threads or profile_threads
    timeout = config.timeout or profile_timeout

    if config.use_docker:
        # Docker-based workflow
        scan_cmd_lines = [
            f"jmo scan --repo . --results results --profile {config.profile}",
            f"--threads {threads}",
            f"--timeout {timeout}",
        ]
        if config.fail_on:
            scan_cmd_lines.append(f"--fail-on {config.fail_on}")
        scan_cmd = " \\\n            ".join(scan_cmd_lines)

        return f"""name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        run: |
          {scan_cmd}

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
"""
    else:
        # Native workflow
        scan_cmd_lines = [
            f"jmotools {config.profile} --repos-dir . --results-dir results",
            f"--threads {threads}",
            f"--timeout {timeout}",
        ]
        if config.fail_on:
            scan_cmd_lines.append(f"--fail-on {config.fail_on}")
        scan_cmd = " \\\n            ".join(scan_cmd_lines)

        profile_tools = cast(List[str], profile_info["tools"])
        tools_list = ", ".join(profile_tools)

        return f"""name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install JMo Security
        run: pip install jmo-security

      - name: Install Security Tools
        run: |
          # Install based on profile: {config.profile}
          # Tools: {tools_list}
          # See: https://github.com/jimmy058910/jmo-security-repo#tool-installation

      - name: Run Security Scan
        run: |
          {scan_cmd}

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
"""


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
    _print_header("JMo Security Wizard")
    print("Welcome! This wizard will guide you through your first security scan.")
    print("Press Ctrl+C at any time to cancel.")

    config = WizardConfig()

    try:
        if yes:
            # Non-interactive mode: use defaults
            print("\n" + _colorize("Non-interactive mode: using defaults", "yellow"))
            config.profile = "balanced"
            config.use_docker = (
                force_docker and _detect_docker() and _check_docker_running()
            )
            config.target_mode = "repos-dir"
            config.target_path = str(Path.cwd())
            config.results_dir = "results"
        else:
            # Interactive mode
            config.profile = select_profile()
            config.use_docker = select_execution_mode(force_docker)
            mode, path, tsv, tsv_dest = select_target()
            config.target_mode = mode
            config.target_path = path
            config.tsv_path = tsv
            config.tsv_dest = tsv_dest

            threads, timeout, fail_on = configure_advanced(config.profile)
            config.threads = threads
            config.timeout = timeout
            config.fail_on = fail_on

            if not review_and_confirm(config):
                print(_colorize("\nWizard cancelled", "yellow"))
                return 0

        # Handle artifact generation
        if emit_make:
            content = generate_makefile_target(config)
            Path(emit_make).write_text(content)
            print(f"\n{_colorize('Generated:', 'green')} {emit_make}")
            return 0

        if emit_script:
            content = generate_shell_script(config)
            script_path = Path(emit_script)
            script_path.write_text(content)
            script_path.chmod(0o755)
            print(f"\n{_colorize('Generated:', 'green')} {emit_script}")
            return 0

        if emit_gha:
            content = generate_github_actions(config)
            gha_path = Path(emit_gha)
            gha_path.parent.mkdir(parents=True, exist_ok=True)
            gha_path.write_text(content)
            print(f"\n{_colorize('Generated:', 'green')} {emit_gha}")
            return 0

        # Execute scan
        return execute_scan(config)

    except KeyboardInterrupt:
        print(_colorize("\n\nWizard cancelled", "yellow"))
        return 130
    except Exception as e:
        print(_colorize(f"\n\nWizard error: {e}", "red"))
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
