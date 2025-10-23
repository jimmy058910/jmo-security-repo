#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Tuple, Optional

from scripts.core.exceptions import (
    ConfigurationException,
)
from scripts.core.config import load_config
from scripts.cli.report_orchestrator import cmd_report as _cmd_report_impl
from scripts.cli.ci_orchestrator import cmd_ci as _cmd_ci_impl

# PHASE 1 REFACTORING: Import refactored modules
from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanConfig
from scripts.cli.scan_jobs import (
    scan_repository,
    scan_image,
    scan_iac_file,
    scan_url,
    scan_gitlab_repo,
    scan_k8s_resource,
)
from scripts.cli.scan_utils import (
    tool_exists as _tool_exists,
    write_stub as _write_stub,
)
from scripts.cli.cpu_utils import auto_detect_threads as _auto_detect_threads_shared

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


def _merge_dict(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a) if a else {}
    if b:
        out.update(b)
    return out


def _effective_scan_settings(args) -> Dict[str, Any]:
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
    _add_logging_args(cp)
    return cp


def parse_args():
    """Parse command-line arguments for jmo CLI."""
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")

    _add_scan_args(sub)
    _add_report_args(sub)
    _add_ci_args(sub)

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


def _run_cmd(
    cmd: list[str],
    timeout: int,
    retries: int = 0,
    capture_stdout: bool = False,
    ok_rcs: Tuple[int, ...] | None = None,
) -> Tuple[int, str, str, int]:
    """Run a command with timeout and optional retries.

    Returns a tuple: (returncode, stdout, stderr, used_attempts).
    stdout is empty when capture_stdout=False. used_attempts is how many tries were made.
    """
    import subprocess  # nosec B404: imported for controlled, vetted CLI invocations below
    import time

    attempts = max(0, retries) + 1
    used_attempts = 0
    last_exc: Exception | None = None
    rc = 1
    for i in range(attempts):
        used_attempts = i + 1
        try:
            cp = subprocess.run(  # nosec B603: executing fixed CLI tools, no shell, args vetted
                cmd,
                stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            rc = cp.returncode
            success = (rc == 0) if ok_rcs is None else (rc in ok_rcs)
            if success or i == attempts - 1:
                return (
                    rc,
                    (cp.stdout or "") if capture_stdout else "",
                    (cp.stderr or ""),
                    used_attempts,
                )
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue
        except subprocess.TimeoutExpired as e:
            last_exc = e
            rc = 124
        except subprocess.CalledProcessError as e:
            # Command failed with non-zero exit code
            last_exc = e
            rc = e.returncode
            logger.debug(f"Command failed with exit code {e.returncode}: {e}")
        except (OSError, FileNotFoundError, PermissionError) as e:
            # System errors (command not found, permissions, etc.)
            last_exc = e
            rc = 1
            logger.error(f"Command execution error: {e}")
        except Exception as e:
            # Unexpected errors
            last_exc = e
            rc = 1
            logger.error(f"Unexpected command execution error: {e}", exc_info=True)
        if i < attempts - 1:
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue
    return rc, "", str(last_exc or ""), used_attempts or 1


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
    config: Dict[str, Any] = {}
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


def _get_max_workers(args, eff: Dict, cfg) -> Optional[int]:
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
        self._start_time = None

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

    scan_start_time = time.time()

    # Check for first-run email prompt (non-blocking)
    if _check_first_run():
        _collect_email_opt_in(args)

    from concurrent.futures import ThreadPoolExecutor

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

    # Track scan results
    all_results = []
    futures = []

    # Initialize progress tracker
    progress = ProgressTracker(total_targets, args)
    progress.start()

    # Use ThreadPoolExecutor for parallel scanning
    max_workers = scan_config.max_workers
    executor = (
        ThreadPoolExecutor(max_workers=max_workers)
        if max_workers
        else ThreadPoolExecutor()
    )

    try:
        # === REPOSITORIES ===
        if targets.repos:
            _log(args, "INFO", f"Scanning {len(targets.repos)} repositories...")
            for repo in targets.repos:
                if stop_flag["stop"]:
                    break
                future = executor.submit(
                    scan_repository,
                    repo,
                    results_dir / "individual-repos",
                    tools,
                    scan_config.timeout,
                    scan_config.retries,
                    per_tool_config,
                    scan_config.allow_missing_tools,
                    _tool_exists,  # Pass for test monkeypatching
                    _write_stub,  # Pass for test monkeypatching
                )
                futures.append(("repo", repo.name, future))

        # === CONTAINER IMAGES ===
        if targets.images:
            _log(args, "INFO", f"Scanning {len(targets.images)} container images...")
            for image in targets.images:
                if stop_flag["stop"]:
                    break
                future = executor.submit(
                    scan_image,
                    image,
                    results_dir,
                    tools,
                    scan_config.timeout,
                    scan_config.retries,
                    per_tool_config,
                    scan_config.allow_missing_tools,
                    _tool_exists,  # Pass for test monkeypatching
                    _write_stub,  # Pass for test monkeypatching
                )
                futures.append(("image", image, future))

        # === IAC FILES ===
        if targets.iac_files:
            _log(args, "INFO", f"Scanning {len(targets.iac_files)} IaC files...")
            for iac_type, iac_path in targets.iac_files:
                if stop_flag["stop"]:
                    break
                future = executor.submit(
                    scan_iac_file,
                    iac_type,
                    iac_path,
                    results_dir,
                    tools,
                    scan_config.timeout,
                    scan_config.retries,
                    per_tool_config,
                    scan_config.allow_missing_tools,
                    _tool_exists,  # Pass for test monkeypatching
                    _write_stub,  # Pass for test monkeypatching
                )
                futures.append(("iac", f"{iac_type}:{iac_path.name}", future))

        # === WEB URLS ===
        if targets.urls:
            _log(args, "INFO", f"Scanning {len(targets.urls)} web URLs...")
            for url in targets.urls:
                if stop_flag["stop"]:
                    break
                future = executor.submit(
                    scan_url,
                    url,
                    results_dir,
                    tools,
                    scan_config.timeout,
                    scan_config.retries,
                    per_tool_config,
                    scan_config.allow_missing_tools,
                    _tool_exists,  # Pass for test monkeypatching
                    _write_stub,  # Pass for test monkeypatching
                )
                futures.append(("url", url, future))

        # === GITLAB REPOS ===
        if targets.gitlab_repos:
            _log(
                args,
                "INFO",
                f"Scanning {len(targets.gitlab_repos)} GitLab repositories...",
            )
            for gitlab_info in targets.gitlab_repos:
                if stop_flag["stop"]:
                    break
                future = executor.submit(
                    scan_gitlab_repo,
                    gitlab_info,
                    results_dir,
                    tools,
                    scan_config.timeout,
                    scan_config.retries,
                    per_tool_config,
                    scan_config.allow_missing_tools,
                    _tool_exists,  # Pass for test monkeypatching
                    _write_stub,  # Pass for test monkeypatching
                )
                futures.append(("gitlab", gitlab_info.get("name", "unknown"), future))

        # === KUBERNETES RESOURCES ===
        if targets.k8s_resources:
            _log(
                args,
                "INFO",
                f"Scanning {len(targets.k8s_resources)} Kubernetes resources...",
            )
            for k8s_info in targets.k8s_resources:
                if stop_flag["stop"]:
                    break
                future = executor.submit(
                    scan_k8s_resource,
                    k8s_info,
                    results_dir,
                    tools,
                    scan_config.timeout,
                    scan_config.retries,
                    per_tool_config,
                    scan_config.allow_missing_tools,
                    _tool_exists,  # Pass for test monkeypatching
                    _write_stub,  # Pass for test monkeypatching
                )
                futures.append(("k8s", k8s_info.get("name", "unknown"), future))

        # Wait for all futures to complete with progress tracking
        for target_type, target_name, future in futures:
            if stop_flag["stop"]:
                future.cancel()
                continue

            try:
                import time

                target_start = time.time()
                name, statuses = future.result()
                target_elapsed = time.time() - target_start

                # Update progress tracker
                progress.update(target_type, target_name, target_elapsed)

                all_results.append((target_type, name, statuses))
            except Exception as e:
                _log(args, "ERROR", f"Failed to scan {target_type} {target_name}: {e}")

                # Update progress tracker (negative elapsed indicates failure)
                progress.update(target_type, target_name, -1.0)

                if not scan_config.allow_missing_tools:
                    raise

    finally:
        executor.shutdown(wait=True)

    # Show Ko-Fi support reminder
    _show_kofi_reminder(args)

    # Send scan.completed telemetry event
    scan_duration = time.time() - scan_start_time
    tools_succeeded = sum(1 for _, _, statuses in all_results if any(statuses.values()))
    tools_failed = sum(
        1 for _, _, statuses in all_results if not all(statuses.values())
    )

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


def main():
    args = parse_args()
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "ci":
        return cmd_ci(args)
    return 0


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
