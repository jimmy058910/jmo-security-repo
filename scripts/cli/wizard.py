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
import os
import shutil
import subprocess  # nosec B404 - CLI needs subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

from scripts.core.exceptions import ToolExecutionException
from scripts.core.config import load_config
from scripts.cli.cpu_utils import get_cpu_count
from scripts.cli.wizard_generators import (
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)
from scripts.core.telemetry import send_event

# Configure logging
logger = logging.getLogger(__name__)

# Version (from pyproject.toml)
__version__ = "0.7.1"

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
    """
    Get CPU count for thread recommendations.

    DEPRECATED: Use scripts.cli.cpu_utils.get_cpu_count() instead.
    This function is kept for backward compatibility in tests.
    """
    return get_cpu_count()


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


def _validate_url(url: str) -> bool:
    """
    Validate URL is reachable with a quick HEAD request.

    Args:
        url: URL to validate

    Returns:
        True if URL is reachable, False otherwise
    """
    import urllib.request
    import urllib.error

    try:
        # Quick HEAD request with 2s timeout
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(
            req, timeout=2
        ) as response:  # nosec B310 - user-provided URL, validated
            is_ok: bool = response.status == 200
            return is_ok
    except urllib.error.HTTPError as e:
        # HTTP errors (4xx, 5xx)
        logger.debug(f"URL validation failed for {url}: HTTP {e.code} {e.reason}")
        return False
    except urllib.error.URLError as e:
        # Network/DNS errors
        logger.debug(
            f"URL validation failed for {url}: {type(e.reason).__name__}: {e.reason}"
        )
        return False
    except TimeoutError:
        # Timeout errors
        logger.debug(f"URL validation timeout for {url}: exceeded 2s")
        return False
    except Exception as e:
        # Unexpected errors
        logger.debug(f"URL validation failed for {url}: {type(e).__name__}: {e}")
        return False


def _detect_iac_type(file_path: Path) -> str:
    """
    Auto-detect IaC type from file extension and content.

    Args:
        file_path: Path to IaC file

    Returns:
        Detected type: terraform, cloudformation, or k8s-manifest
    """
    # Check extension first
    suffix = file_path.suffix.lower()
    name = file_path.name.lower()

    if ".tfstate" in name or suffix == ".tfstate":
        return "terraform"

    if "cloudformation" in name or "cfn" in name:
        return "cloudformation"

    # For YAML files, check content
    if suffix in (".yaml", ".yml"):
        try:
            content = file_path.read_text(encoding="utf-8")
            # K8s manifests have apiVersion and kind
            if "apiVersion:" in content and "kind:" in content:
                return "k8s-manifest"
            # CloudFormation templates have AWSTemplateFormatVersion or Resources
            if "AWSTemplateFormatVersion:" in content or "Resources:" in content:
                return "cloudformation"
        except (IOError, OSError) as e:
            # File read can fail: permissions, I/O errors
            logger.debug(
                f"Skipping IaC file {file_path}: I/O error - {type(e).__name__}: {e}"
            )
        except UnicodeDecodeError as e:
            # Encoding issues
            logger.debug(
                f"Skipping IaC file {file_path}: encoding error at position {e.start}"
            )

    # Default to k8s-manifest for YAML files
    if suffix in (".yaml", ".yml"):
        return "k8s-manifest"

    # Default
    return "terraform"


def _validate_k8s_context(context: str) -> bool:
    """
    Validate Kubernetes context exists.

    Args:
        context: K8s context name or 'current' for current context

    Returns:
        True if context exists, False otherwise
    """
    try:
        # Check if kubectl is available
        if not shutil.which("kubectl"):
            return False

        # Get contexts list
        result = subprocess.run(  # nosec B603 - controlled command
            ["kubectl", "config", "get-contexts", "-o", "name"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )

        if result.returncode != 0:
            return False

        # If "current" requested, any context is fine
        if context == "current":
            return len(result.stdout.strip()) > 0

        # Check if specific context exists
        contexts = result.stdout.strip().split("\n")
        return context in contexts
    except subprocess.TimeoutExpired:
        logger.debug(f"K8s context validation timeout for {context}: exceeded 5s")
        return False
    except FileNotFoundError:
        logger.debug("K8s context validation failed: kubectl not found")
        return False
    except Exception as e:
        logger.debug(
            f"K8s context validation failed for {context}: {type(e).__name__}: {e}"
        )
        return False


def _validate_path(path_str: str, must_exist: bool = True) -> Optional[Path]:
    """Validate and expand a path."""
    try:
        path = Path(path_str).expanduser().resolve()
        if must_exist and not path.exists():
            return None
        return path
    except (OSError, ValueError, TypeError, RuntimeError, Exception) as e:
        # Path expansion/resolution can fail:
        # - OSError: permissions, invalid paths, symlink loops
        # - ValueError: invalid characters, empty path
        # - TypeError: non-string input
        # - RuntimeError: infinite symlink recursion
        # - Exception: catch-all for unexpected errors (defensive)
        logger.debug(f"Failed to resolve path '{path_str}': {e}")
        return None


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


def select_target_type() -> str:
    """
    Step 3a: Select target TYPE (repo, image, iac, url, gitlab, k8s).

    Returns:
        Target type string
    """
    _print_step(3, 7, "Select Scan Target Type")

    print("\nTarget types:")
    print("  [repo]    Repositories (local Git repos)")
    print("  [image]   Container images (Docker/OCI)")
    print("  [iac]     Infrastructure as Code (Terraform/CloudFormation/K8s)")
    print("  [url]     Web applications and APIs (DAST)")
    print("  [gitlab]  GitLab repositories (remote)")
    print("  [k8s]     Kubernetes clusters (live)")

    choices = [
        ("repo", "Repositories"),
        ("image", "Container images"),
        ("iac", "Infrastructure as Code"),
        ("url", "Web applications/APIs"),
        ("gitlab", "GitLab integration"),
        ("k8s", "Kubernetes clusters"),
    ]
    # Default to repo (most common use case)
    return _prompt_choice("\nSelect target type:", choices, default="repo")


def configure_repo_target() -> TargetConfig:
    """
    Step 3b-repo: Configure repository scanning.

    Returns:
        TargetConfig for repository targets
    """
    _print_step(4, 7, "Configure Repository Target")

    config = TargetConfig()
    config.type = "repo"

    print("\nRepository modes:")
    print("  [repo]      Single repository")
    print("  [repos-dir] Directory with multiple repos (most common)")
    print("  [targets]   File listing repo paths")
    print("  [tsv]       Clone from TSV file")

    choices = [
        ("repo", "Single repository"),
        ("repos-dir", "Directory with repos"),
        ("targets", "Targets file"),
        ("tsv", "Clone from TSV"),
    ]
    mode = _prompt_choice("\nSelect mode:", choices, default="repos-dir")
    config.repo_mode = mode

    if mode == "tsv":
        config.tsv_path = _prompt_text("Path to TSV file", default="./repos.tsv")
        config.tsv_dest = _prompt_text("Clone destination", default="repos-tsv")
        return config

    # For other modes, prompt for path
    prompts = {
        "repo": "Path to repository",
        "repos-dir": "Path to repos directory",
        "targets": "Path to targets file",
    }

    while True:
        path = _prompt_text(prompts[mode], default="." if mode == "repos-dir" else "")
        if not path:
            print(_colorize("Path cannot be empty", "red"))
            continue

        validated = _validate_path(path, must_exist=True)
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

            config.repo_path = str(validated)
            return config

        print(_colorize(f"Path not found: {path}", "red"))


def configure_image_target() -> TargetConfig:
    """
    Step 3b-image: Configure container image scanning.

    Returns:
        TargetConfig for container image targets
    """
    _print_step(4, 7, "Configure Container Image Target")

    config = TargetConfig()
    config.type = "image"

    print("\nContainer image modes:")
    print("  [single] Scan a single image")
    print("  [batch]  Scan images from file")

    mode = _prompt_choice(
        "\nSelect mode:",
        [("single", "Single image"), ("batch", "Batch file")],
        default="single",
    )

    if mode == "single":
        config.image_name = _prompt_text(
            "Container image (e.g., nginx:latest, myregistry.io/app:v1.0)",
            default="nginx:latest",
        )
        print(_colorize(f"Will scan: {config.image_name}", "green"))
    else:
        while True:
            path = _prompt_text("Path to images file", default="./images.txt")
            validated = _validate_path(path, must_exist=True)
            if validated:
                config.images_file = str(validated)
                # Show preview
                lines = validated.read_text(encoding="utf-8").splitlines()
                images = [
                    line.strip()
                    for line in lines
                    if line.strip() and not line.startswith("#")
                ]
                print(f"\n{_colorize(f'Found {len(images)} images:', 'green')}")
                for img in images[:5]:
                    print(f"  - {img}")
                if len(images) > 5:
                    print(f"  ... and {len(images) - 5} more")
                break
            print(_colorize(f"File not found: {path}", "red"))

    return config


def configure_iac_target() -> TargetConfig:
    """
    Step 3b-iac: Configure IaC file scanning.

    Returns:
        TargetConfig for IaC targets
    """
    _print_step(4, 7, "Configure Infrastructure as Code Target")

    config = TargetConfig()
    config.type = "iac"

    # Prompt for file path first
    while True:
        path = _prompt_text(
            "Path to IaC file (.tfstate, .yaml, .json)",
            default="./infrastructure.tfstate",
        )
        validated = _validate_path(path, must_exist=True)
        if validated:
            config.iac_path = str(validated)

            # Auto-detect type
            detected_type = _detect_iac_type(validated)
            print(
                f"\n{_colorize(f'Detected type: {detected_type}', 'green')} (based on file)"
            )

            # Confirm or override
            print("\nIaC file types:")
            print("  [terraform]      Terraform state file (.tfstate)")
            print("  [cloudformation] CloudFormation template (.yaml/.json)")
            print("  [k8s-manifest]   Kubernetes manifest (.yaml)")

            choices = [
                ("terraform", "Terraform state"),
                ("cloudformation", "CloudFormation"),
                ("k8s-manifest", "Kubernetes manifest"),
            ]
            iac_type = _prompt_choice(
                "\nConfirm or override type:", choices, default=detected_type
            )
            config.iac_type = iac_type

            return config

        print(_colorize(f"File not found: {path}", "red"))


def configure_url_target() -> TargetConfig:
    """
    Step 3b-url: Configure web URL scanning.

    Returns:
        TargetConfig for web URL targets
    """
    _print_step(4, 7, "Configure Web Application/API Target")

    config = TargetConfig()
    config.type = "url"

    print("\nWeb application modes:")
    print("  [single] Scan a single URL")
    print("  [batch]  Scan URLs from file")
    print("  [api]    Scan API from OpenAPI spec")

    mode = _prompt_choice(
        "\nSelect mode:",
        [("single", "Single URL"), ("batch", "Batch file"), ("api", "API spec")],
        default="single",
    )

    if mode == "single":
        while True:
            url = _prompt_text("Web application URL", default="https://example.com")
            # Validate URL is reachable
            print(_colorize("Validating URL...", "blue"))
            if _validate_url(url):
                print(_colorize(f"URL is reachable: {url}", "green"))
                config.url = url
                break
            else:
                print(
                    _colorize(
                        f"Warning: URL not reachable (timeout or error): {url}",
                        "yellow",
                    )
                )
                if _prompt_yes_no("Use this URL anyway?", default=False):
                    config.url = url
                    break

    elif mode == "batch":
        while True:
            path = _prompt_text("Path to URLs file", default="./urls.txt")
            validated = _validate_path(path, must_exist=True)
            if validated:
                config.urls_file = str(validated)
                # Show preview
                lines = validated.read_text(encoding="utf-8").splitlines()
                urls = [
                    line.strip()
                    for line in lines
                    if line.strip() and not line.startswith("#")
                ]
                print(f"\n{_colorize(f'Found {len(urls)} URLs:', 'green')}")
                for url in urls[:5]:
                    print(f"  - {url}")
                if len(urls) > 5:
                    print(f"  ... and {len(urls) - 5} more")
                break
            print(_colorize(f"File not found: {path}", "red"))

    else:  # api
        config.api_spec = _prompt_text(
            "OpenAPI spec URL or file path", default="./openapi.yaml"
        )
        print(_colorize(f"Will scan API spec: {config.api_spec}", "green"))

    return config


def configure_gitlab_target() -> TargetConfig:
    """
    Step 3b-gitlab: Configure GitLab scanning.

    Returns:
        TargetConfig for GitLab targets
    """
    _print_step(4, 7, "Configure GitLab Target")

    config = TargetConfig()
    config.type = "gitlab"

    # GitLab URL
    config.gitlab_url = _prompt_text("GitLab URL", default="https://gitlab.com")

    # GitLab token (check env first)
    env_token = os.getenv("GITLAB_TOKEN")
    if env_token:
        print(f"\n{_colorize('GitLab token found in GITLAB_TOKEN env var', 'green')}")
        config.gitlab_token = env_token
    else:
        print(_colorize("\nWarning: GITLAB_TOKEN env var not set", "yellow"))
        print("For security, it's recommended to set GITLAB_TOKEN env var")
        token = _prompt_text("GitLab access token (or press Enter to skip)")
        if token:
            config.gitlab_token = token
        else:
            print(
                _colorize(
                    "Note: Scan will fail without token. Set GITLAB_TOKEN before running.",
                    "yellow",
                )
            )

    # Repo or group
    print("\nGitLab scope:")
    print("  [repo]  Single repository (group/repo)")
    print("  [group] Entire group (all repos)")

    mode = _prompt_choice(
        "\nSelect scope:",
        [("repo", "Single repo"), ("group", "Entire group")],
        default="repo",
    )

    if mode == "repo":
        config.gitlab_repo = _prompt_text(
            "Repository (format: group/repo)", default="mygroup/myrepo"
        )
        print(
            _colorize(
                f"Will scan GitLab repo: {config.gitlab_url}/{config.gitlab_repo}",
                "green",
            )
        )
    else:
        config.gitlab_group = _prompt_text("Group name", default="mygroup")
        print(
            _colorize(
                f"Will scan all repos in group: {config.gitlab_url}/{config.gitlab_group}",
                "green",
            )
        )

    return config


def configure_k8s_target() -> TargetConfig:
    """
    Step 3b-k8s: Configure Kubernetes scanning.

    Returns:
        TargetConfig for Kubernetes targets
    """
    _print_step(4, 7, "Configure Kubernetes Target")

    config = TargetConfig()
    config.type = "k8s"

    # Check if kubectl is available
    if not shutil.which("kubectl"):
        print(
            _colorize(
                "Warning: kubectl not found. Install kubectl to scan K8s clusters.",
                "yellow",
            )
        )
        config.k8s_context = "current"
        config.k8s_namespace = "default"
        return config

    # Context
    while True:
        context = _prompt_text(
            "Kubernetes context (or 'current' for default)", default="current"
        )
        # Validate context
        if _validate_k8s_context(context):
            print(_colorize(f"Context validated: {context}", "green"))
            config.k8s_context = context
            break
        else:
            print(_colorize(f"Warning: Context not found: {context}", "yellow"))
            if _prompt_yes_no("Use this context anyway?", default=False):
                config.k8s_context = context
                break

    # Namespace
    print("\nNamespace scope:")
    print("  [single] Single namespace")
    print("  [all]    All namespaces")

    mode = _prompt_choice(
        "\nSelect scope:",
        [("single", "Single namespace"), ("all", "All namespaces")],
        default="single",
    )

    if mode == "single":
        config.k8s_namespace = _prompt_text("Namespace name", default="default")
        print(
            _colorize(
                f"Will scan namespace: {config.k8s_context}/{config.k8s_namespace}",
                "green",
            )
        )
    else:
        config.k8s_all_namespaces = True
        print(
            _colorize(
                f"Will scan all namespaces in context: {config.k8s_context}", "green"
            )
        )

    return config


def configure_advanced(profile: str) -> Tuple[Optional[int], Optional[int], str]:
    """
    Step 5: Configure advanced options.

    Returns:
        Tuple of (threads, timeout, fail_on)
    """
    _print_step(5, 7, "Advanced Configuration")

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

    # Target-specific details
    if config.target.type == "repo":
        print(f"    Mode: {config.target.repo_mode}")
        if config.target.repo_mode == "tsv":
            print(f"    TSV: {config.target.tsv_path}")
            print(f"    Dest: {config.target.tsv_dest}")
        else:
            print(f"    Path: {config.target.repo_path}")

    elif config.target.type == "image":
        if config.target.image_name:
            print(f"    Image: {config.target.image_name}")
        elif config.target.images_file:
            print(f"    Images file: {config.target.images_file}")

    elif config.target.type == "iac":
        print(f"    Type: {config.target.iac_type}")
        print(f"    File: {config.target.iac_path}")

    elif config.target.type == "url":
        if config.target.url:
            print(f"    URL: {config.target.url}")
        elif config.target.urls_file:
            print(f"    URLs file: {config.target.urls_file}")
        elif config.target.api_spec:
            print(f"    API spec: {config.target.api_spec}")

    elif config.target.type == "gitlab":
        print(f"    GitLab URL: {config.target.gitlab_url}")
        print(f"    Token: {'***' if config.target.gitlab_token else 'NOT SET'}")
        if config.target.gitlab_repo:
            print(f"    Repo: {config.target.gitlab_repo}")
        elif config.target.gitlab_group:
            print(f"    Group: {config.target.gitlab_group}")

    elif config.target.type == "k8s":
        print(f"    Context: {config.target.k8s_context}")
        if config.target.k8s_all_namespaces:
            print("    Namespaces: ALL")
        else:
            print(f"    Namespace: {config.target.k8s_namespace}")

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


def _build_command_parts(config: WizardConfig) -> list[str]:
    """
    Build command parts as a list (shared by generate_command and generate_command_list).

    Returns list of command components for both string and list representations.
    """
    # Load profile info (threads/timeout may be overridden below)
    profile_info = PROFILES[config.profile]  # noqa: F841 - used for reference

    if config.use_docker:
        # Docker command
        cmd_parts = ["docker", "run", "--rm"]

        # Volume mounts (only for file-based targets)
        # Convert to absolute paths for Docker volume mounts
        if config.target.type == "repo":
            if config.target.repo_path:
                repo_abs = str(Path(config.target.repo_path).resolve())
                cmd_parts.extend(["-v", f"{repo_abs}:/scan"])
        elif config.target.type == "iac":
            if config.target.iac_path:
                iac_abs = str(Path(config.target.iac_path).resolve())
                cmd_parts.extend(["-v", f"{iac_abs}:/scan/iac-file"])

        # Results mount (convert to absolute path)
        results_abs = str(Path(config.results_dir).resolve())
        cmd_parts.extend(["-v", f"{results_abs}:/results"])

        # Image and base command
        cmd_parts.append("ghcr.io/jimmy058910/jmo-security:latest")
        cmd_parts.append("scan")

        # Target-specific flags
        if config.target.type == "repo":
            if config.target.repo_mode in ("repo", "repos-dir"):
                cmd_parts.extend(["--repos-dir", "/scan"])
        elif config.target.type == "image":
            if config.target.image_name:
                cmd_parts.extend(["--image", config.target.image_name])
        elif config.target.type == "iac":
            cmd_parts.append(f"--{config.target.iac_type.replace('-', '-')}")
            cmd_parts.append("/scan/iac-file")
        elif config.target.type == "url":
            if config.target.url:
                cmd_parts.extend(["--url", config.target.url])
        elif config.target.type == "gitlab":
            if config.target.gitlab_repo:
                cmd_parts.extend(["--gitlab-repo", config.target.gitlab_repo])
            if config.target.gitlab_token:
                cmd_parts.extend(["--gitlab-token", config.target.gitlab_token])
        elif config.target.type == "k8s":
            if config.target.k8s_context:
                cmd_parts.extend(["--k8s-context", config.target.k8s_context])
            if config.target.k8s_namespace:
                cmd_parts.extend(["--k8s-namespace", config.target.k8s_namespace])

        cmd_parts.extend(["--results", "/results"])
        cmd_parts.extend(["--profile", config.profile])

    else:
        # Native command
        cmd_parts = ["jmotools", config.profile]

        # Target-specific flags
        if config.target.type == "repo":
            if config.target.repo_mode == "repo":
                cmd_parts.extend(["--repo", config.target.repo_path])
            elif config.target.repo_mode == "repos-dir":
                cmd_parts.extend(["--repos-dir", config.target.repo_path])
            elif config.target.repo_mode == "targets":
                cmd_parts.extend(["--targets", config.target.repo_path])
            elif config.target.repo_mode == "tsv":
                cmd_parts.extend(["--tsv", config.target.tsv_path])
                if hasattr(config.target, "tsv_dest") and config.target.tsv_dest:
                    cmd_parts.extend(["--dest", config.target.tsv_dest])
        elif config.target.type == "image":
            if config.target.image_name:
                cmd_parts.extend(["--image", config.target.image_name])
        elif config.target.type == "iac":
            cmd_parts.append(f"--{config.target.iac_type}")
            cmd_parts.append(config.target.iac_path)
        elif config.target.type == "url":
            if config.target.url:
                cmd_parts.extend(["--url", config.target.url])
        elif config.target.type == "gitlab":
            if config.target.gitlab_repo:
                cmd_parts.extend(["--gitlab-repo", config.target.gitlab_repo])
            if config.target.gitlab_token:
                cmd_parts.extend(["--gitlab-token", config.target.gitlab_token])
        elif config.target.type == "k8s":
            if config.target.k8s_context:
                cmd_parts.extend(["--k8s-context", config.target.k8s_context])
            if config.target.k8s_namespace:
                cmd_parts.extend(["--k8s-namespace", config.target.k8s_namespace])

        # Advanced options (check both config.advanced and direct attributes for backward compat)
        threads = (
            getattr(config.advanced, "threads", None)
            if hasattr(config, "advanced") and config.advanced
            else getattr(config, "threads", None)
        )
        timeout = (
            getattr(config.advanced, "timeout", None)
            if hasattr(config, "advanced") and config.advanced
            else getattr(config, "timeout", None)
        )
        fail_on = (
            getattr(config.advanced, "fail_on", None)
            if hasattr(config, "advanced") and config.advanced
            else getattr(config, "fail_on", None)
        )
        results_dir = getattr(config, "results_dir", "results")
        allow_missing_tools = getattr(config, "allow_missing_tools", False)
        human_logs = getattr(config, "human_logs", False)

        if results_dir:
            cmd_parts.extend(["--results-dir", results_dir])
        # Include threads/timeout if explicitly set (non-None)
        if threads is not None:
            cmd_parts.extend(["--threads", str(threads)])
        if timeout is not None:
            cmd_parts.extend(["--timeout", str(timeout)])
        if fail_on:
            cmd_parts.extend(["--fail-on", fail_on.upper()])
        if allow_missing_tools:
            cmd_parts.append("--allow-missing-tools")
        if human_logs:
            cmd_parts.append("--human-logs")

    return cmd_parts


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


def _save_telemetry_preference(config_path: Path, enabled: bool) -> None:
    """
    Save telemetry preference to jmo.yml.

    Args:
        config_path: Path to jmo.yml
        enabled: Whether telemetry is enabled
    """
    import yaml

    # Load existing config or create new one
    if config_path.exists():
        try:
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}
        except Exception:
            config_data = {}
    else:
        config_data = {}

    # Update telemetry section
    config_data["telemetry"] = {"enabled": enabled}

    # Write back to file
    with open(config_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

    status = "enabled" if enabled else "disabled"
    print(f"\n✅ Telemetry {status}. You can change this later in {config_path}\n")


def _send_wizard_telemetry(
    wizard_start_time: float, config: Any, artifact_type: Optional[str] = None
) -> None:
    """
    Send wizard.completed telemetry event.

    Args:
        wizard_start_time: Time when wizard started (from time.time())
        config: WizardConfig object
        artifact_type: Type of artifact generated ("makefile", "shell", "gha", or None)
    """
    import time

    try:
        cfg = load_config("jmo.yml") if Path("jmo.yml").exists() else None
        if cfg:
            wizard_duration = int(time.time() - wizard_start_time)
            execution_mode = "docker" if config.use_docker else "native"

            send_event(
                "wizard.completed",
                {
                    "profile_selected": config.profile,
                    "execution_mode": execution_mode,
                    "artifact_generated": artifact_type,
                    "duration_seconds": wizard_duration,
                },
                {},
                version=__version__,
            )
    except Exception as e:
        # Never let telemetry errors break the wizard
        logger.debug(f"Telemetry send failed: {e}")


def prompt_telemetry_opt_in() -> bool:
    """
    Prompt user to enable telemetry on first run.

    Returns:
        True if user opts in, False otherwise
    """
    print("\n" + "=" * 70)
    print("📊 Help Improve JMo Security")
    print("=" * 70)
    print("We'd like to collect anonymous usage stats to prioritize features.")
    print()
    print("✅ What we collect:")
    print("   • Tool usage (which tools ran)")
    print("   • Scan duration (fast/slow)")
    print("   • Execution mode (CLI/Docker/Wizard)")
    print("   • Platform (Linux/macOS/Windows)")
    print()
    print("❌ What we DON'T collect:")
    print("   • Repository names or paths")
    print("   • Finding details or secrets")
    print("   • IP addresses or user info")
    print()
    print("📄 Privacy policy: https://jmotools.com/privacy")
    print("📖 Full details: docs/TELEMETRY_IMPLEMENTATION_GUIDE.md")
    print("💡 You can change this later in jmo.yml")
    print()

    response = input("Enable anonymous telemetry? [y/N]: ").strip().lower()
    return response == "y"


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

    wizard_start_time = time.time()

    _print_header("JMo Security Wizard")
    print("Welcome! This wizard will guide you through your first security scan.")
    print("Press Ctrl+C at any time to cancel.")

    # Check if telemetry preference already set
    config_path = Path("jmo.yml")
    telemetry_enabled = False
    if config_path.exists():
        try:
            cfg = load_config(str(config_path))
            telemetry_set = hasattr(cfg, "telemetry") and hasattr(
                cfg.telemetry, "enabled"
            )
            if not telemetry_set and not yes:
                # First run: prompt for telemetry
                telemetry_enabled = prompt_telemetry_opt_in()
                # Save preference to jmo.yml
                _save_telemetry_preference(config_path, telemetry_enabled)
        except Exception as e:
            logger.debug(f"Config loading failed during telemetry check: {e}")
    elif not yes:
        # No config file exists, prompt for telemetry
        telemetry_enabled = prompt_telemetry_opt_in()
        # Create minimal jmo.yml with telemetry preference
        _save_telemetry_preference(config_path, telemetry_enabled)

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
            _send_wizard_telemetry(wizard_start_time, config, artifact_type="makefile")
            return 0

        if emit_script:
            command = generate_command(config)
            content = generate_shell_script(config, command)
            script_path = Path(emit_script)
            script_path.write_text(content)
            script_path.chmod(0o755)
            print(f"\n{_colorize('Generated:', 'green')} {emit_script}")
            _send_wizard_telemetry(wizard_start_time, config, artifact_type="shell")
            return 0

        if emit_gha:
            content = generate_github_actions(config, PROFILES)
            gha_path = Path(emit_gha)
            gha_path.parent.mkdir(parents=True, exist_ok=True)
            gha_path.write_text(content)
            print(f"\n{_colorize('Generated:', 'green')} {emit_gha}")
            _send_wizard_telemetry(wizard_start_time, config, artifact_type="gha")
            return 0

        # Execute scan
        result = execute_scan(config)
        _send_wizard_telemetry(wizard_start_time, config, artifact_type=None)
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
