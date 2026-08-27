"""
Scan orchestration for JMo Security.

This module provides the ScanOrchestrator class for discovering scan targets,
filtering repositories, and coordinating multi-target scans.

Created as part of PHASE 1 refactoring to extract orchestration logic from cmd_scan().

Security: Uses centralized validation from scripts.core.validation for
URL and container image validation to prevent injection attacks.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.core.config import RetryConfig
from scripts.core.tool_registry import filter_tools_for_scan_type
from scripts.core.validation import validate_container_image, validate_url

logger = logging.getLogger(__name__)


def _detect_msys_path_mangling(path_str: str) -> bool:
    """
    Detect if a path has been mangled by Git Bash's MSYS layer on Windows.

    When running Docker commands from Git Bash on Windows, the MSYS layer
    automatically converts Unix-style paths (like /scan/repo) to Windows paths
    (like C:/Program Files/Git/scan/repo). This breaks Docker volume mounts.

    Args:
        path_str: The path string to check

    Returns:
        True if the path appears to be MSYS-mangled, False otherwise
    """
    if not path_str:
        return False

    # Pattern: Windows drive letter followed by path containing "Program Files/Git"
    # This is the telltale sign of MSYS path conversion
    msys_pattern = r"^[A-Za-z]:[/\\].*Program Files[/\\]Git"
    if re.match(msys_pattern, path_str):
        return True

    # Also detect any Windows path inside a Docker Linux container
    # Check if we're in Docker AND the path looks like a Windows path
    if os.environ.get("DOCKER_CONTAINER") == "1":
        # Windows drive letter pattern: C:/ or D:\
        if re.match(r"^[A-Za-z]:[/\\]", path_str):
            return True

    return False


def _warn_msys_path_mangling(path_str: str) -> None:
    """
    Print a helpful warning about MSYS path mangling with solutions.

    Args:
        path_str: The mangled path that was detected
    """
    warning = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ ⚠️  MSYS PATH CONVERSION DETECTED                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ The path '{path_str[:50]}...'
║ appears to have been converted by Git Bash's MSYS layer.
║
║ This happens when running Docker from Git Bash on Windows.
║ The path /scan/... was converted to a Windows path.
║
║ SOLUTIONS:
║
║ 1. Set environment variable (recommended):
║    MSYS_NO_PATHCONV=1 docker run ...
║
║ 2. Use PowerShell or CMD instead of Git Bash
║
║ 3. Use double-slash prefix:
║    docker run ... --repo //scan/repo
║
║ Example:
║    MSYS_NO_PATHCONV=1 docker run --rm -v "C:\\Projects\\myrepo:/scan" \\
║      jmo-security:fast scan --repo /scan --profile fast
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    sys.stderr.write(warning)


@dataclass
class ScanTargets:
    """
    Container for all discovered scan targets across 6 target types.

    Attributes:
        repos: List of repository paths (local Git repos)
        images: List of container image names (Docker/OCI)
        iac_files: List of (type, path) tuples for IaC files
        urls: List of web URLs for DAST scanning
        gitlab_repos: List of GitLab repository info dicts
        k8s_resources: List of Kubernetes resource info dicts
    """

    repos: list[Path] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    iac_files: list[tuple[str, Path]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    gitlab_repos: list[dict[str, str]] = field(default_factory=list)
    k8s_resources: list[dict[str, str]] = field(default_factory=list)
    # Targets the caller asked for that discovery refused, with the reason.
    # Without this, a mistyped path was indistinguishable from asking for
    # nothing: both produced an empty ScanTargets and the same message.
    rejected: list[str] = field(default_factory=list)

    def total_count(self) -> int:
        """Return total number of scan targets across all types."""
        return (
            len(self.repos)
            + len(self.images)
            + len(self.iac_files)
            + len(self.urls)
            + len(self.gitlab_repos)
            + len(self.k8s_resources)
        )

    def is_empty(self) -> bool:
        """Check if no targets were discovered."""
        return self.total_count() == 0

    def summary(self) -> str:
        """Generate human-readable summary of targets."""
        return (
            f"{len(self.repos)} repos, "
            f"{len(self.images)} images, "
            f"{len(self.iac_files)} IaC files, "
            f"{len(self.urls)} URLs, "
            f"{len(self.gitlab_repos)} GitLab repos, "
            f"{len(self.k8s_resources)} K8s resources"
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "repos": [str(r) for r in self.repos],
            "images": self.images,
            "iac_files": [(t, str(p)) for t, p in self.iac_files],
            "urls": self.urls,
            "gitlab_repos": self.gitlab_repos,
            "k8s_resources": self.k8s_resources,
            "total_count": self.total_count(),
        }


@dataclass
class ScanConfig:
    """
    Scan configuration extracted from CLI arguments and config file.

    Attributes:
        tools: List of tool names to run
        results_dir: Base directory for scan results
        timeout: Tool timeout in seconds
        retries: Number of retry attempts
        max_workers: Maximum parallel workers (None = auto)
        include_patterns: Repository name patterns to include
        exclude_patterns: Repository name patterns to exclude
        allow_missing_tools: Allow scan to continue if tools missing
    """

    tools: list[str]
    results_dir: Path
    timeout: int = 600
    retries: int | RetryConfig = 0
    max_workers: int | None = None
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    allow_missing_tools: bool = False

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.tools:
            raise ValueError("At least one tool must be specified")
        if self.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {self.timeout}")
        if isinstance(self.retries, int) and self.retries < 0:
            raise ValueError(f"Retries must be non-negative, got {self.retries}")
        if self.max_workers is not None and self.max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {self.max_workers}")


# How one target's scan ended, derived from the per-tool status map every
# scanner in scan_jobs/ returns. Named constants rather than bare strings so a
# typo at a comparison site is a NameError instead of a silently false branch.
TARGET_OK = "ok"
TARGET_PARTIAL = "partial"
TARGET_FAILED = "failed"


def classify_target_outcome(statuses: Mapping[str, Any] | None) -> str:
    """Classify one target's scan from the booleans its scanner returned.

    Args:
        statuses: The per-tool status map from a ``scan_jobs`` scanner. Keys
            beginning ``__`` are metadata (``__attempts__``), not tools.

    Returns:
        ``TARGET_OK`` if every tool succeeded, ``TARGET_PARTIAL`` if some did,
        ``TARGET_FAILED`` if none did.

    **An empty map is ``TARGET_FAILED``, not vacuous success.** It is what
    ``scan_all`` appends when a scanner raised, and what a scanner returns when
    no requested tool applied to this target type -- both cases where the target
    contributed nothing. ``all([])`` being True is exactly the reading that
    would let those render as a clean scan.

    This exists because the information was already correct everywhere and
    consulted nowhere: every scanner reports ``dict.fromkeys(tools, False)`` on
    its failure paths, and the progress display decided the success symbol from
    an elapsed time the caller hardcoded to ``1.0`` (#809).
    """
    if not statuses:
        return TARGET_FAILED
    outcomes = [bool(ok) for name, ok in statuses.items() if not name.startswith("__")]
    if not outcomes:
        return TARGET_FAILED
    if all(outcomes):
        return TARGET_OK
    if any(outcomes):
        return TARGET_PARTIAL
    return TARGET_FAILED


def _run_timed(scan_job, *args: Any, **kwargs: Any) -> tuple[str, dict, float]:
    """Run one scan job and return its result plus the seconds it took.

    Timed **inside the worker**, not around ``future.result()``: with more
    targets than workers a future sits queued, and charging that wait to the
    target would report a scheduling backlog as a slow scan. ``perf_counter``
    rather than ``time.time`` because the latter is coarser than the former on
    Windows (~15 ms vs ~1 ms) and a fast target would round to zero.
    """
    started = time.perf_counter()
    name, statuses = scan_job(*args, **kwargs)
    return name, statuses, time.perf_counter() - started


class ScanOrchestrator:
    """
    Orchestrate multi-target security scans.

    This class handles:
    1. Target discovery (repos, images, IaC, URLs, GitLab, K8s)
    2. Repository filtering (include/exclude patterns)
    3. Results directory setup
    4. Target validation

    Example:
        >>> orchestrator = ScanOrchestrator(config)
        >>> targets = orchestrator.discover_targets(args)
        >>> print(targets.summary())
        "5 repos, 2 images, 1 IaC files, 0 URLs, 0 GitLab repos, 0 K8s resources"
        >>> orchestrator.setup_results_directories(targets)
    """

    def __init__(self, config: ScanConfig):
        """
        Initialize ScanOrchestrator.

        Args:
            config: Scan configuration
        """
        self.config = config
        # Initialized here, not in discover_targets, because the _discover_*
        # methods are also called directly (7 tests do exactly that) and must
        # not depend on state their usual caller happens to set first.
        self._rejected: list[str] = []

    def discover_targets(self, args) -> ScanTargets:
        """
        Discover all scan targets from CLI arguments.

        Args:
            args: Parsed CLI arguments (from argparse)

        Returns:
            ScanTargets with all discovered targets
        """
        targets = ScanTargets()
        # Reset per call - discover_targets may run more than once per process
        # (the wizard and `jmo ci` both build orchestrators).
        self._rejected = []

        # Discover repositories
        targets.repos = self._discover_repos(args)

        # Discover container images
        targets.images = self._discover_images(args)

        # Discover IaC files
        targets.iac_files = self._discover_iac_files(args)

        # Discover URLs
        targets.urls = self._discover_urls(args)

        # Discover GitLab repositories
        targets.gitlab_repos = self._discover_gitlab_repos(args)

        # Discover Kubernetes resources
        targets.k8s_resources = self._discover_k8s_resources(args)

        # Apply repository filters (include/exclude patterns)
        targets.repos = self._filter_repos(targets.repos)

        targets.rejected = list(self._rejected)
        return targets

    def _reject(self, flag: str, value: object, reason: str) -> None:
        """Record and log a target that was asked for but will not be scanned.

        `--image` and `--url` already warned on bad input; the six path-based
        flags dropped silently, so a typo read exactly like passing no target
        at all. Everything that refuses a target now goes through here.
        """
        message = f"{flag} {value!s}: {reason}"
        self._rejected.append(message)
        logger.warning("Not scanning %s", message)

    def _discover_repos(self, args) -> list[Path]:
        """
        Discover local Git repositories from CLI arguments.

        Supports three input modes:
        - --repo: Single repository path
        - --repos-dir: Directory containing multiple repos
        - --targets: File with list of repository paths

        Also detects MSYS path mangling from Git Bash on Windows and provides
        helpful error messages with solutions.
        """
        repos: list[Path] = []

        # Single repository
        if getattr(args, "repo", None):
            repo_path = args.repo

            # Check for MSYS path mangling (Git Bash on Windows + Docker)
            if _detect_msys_path_mangling(repo_path):
                _warn_msys_path_mangling(repo_path)
                self._reject("--repo", repo_path, "path looks MSYS-mangled")
                return repos  # Return empty - path is invalid

            p = Path(repo_path)
            if p.exists():
                repos.append(p)
            else:
                self._reject("--repo", repo_path, "path does not exist")

        # Directory of repositories
        elif getattr(args, "repos_dir", None):
            repos_dir_path = args.repos_dir

            # Check for MSYS path mangling
            if _detect_msys_path_mangling(repos_dir_path):
                _warn_msys_path_mangling(repos_dir_path)
                self._reject("--repos-dir", repos_dir_path, "path looks MSYS-mangled")
                return repos

            base = Path(repos_dir_path)
            if not base.exists():
                self._reject("--repos-dir", repos_dir_path, "directory does not exist")
            elif not base.is_dir():
                self._reject("--repos-dir", repos_dir_path, "is not a directory")
            else:
                # Find all subdirectories (assumed to be repos)
                repos.extend([p for p in base.iterdir() if p.is_dir()])
                if not repos:
                    self._reject(
                        "--repos-dir", repos_dir_path, "contains no subdirectories"
                    )

        # Targets file (list of repository paths)
        elif getattr(args, "targets", None):
            targets_file = Path(args.targets)
            if not targets_file.exists():
                self._reject("--targets", args.targets, "file does not exist")
            else:
                listed = 0
                for line in targets_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    listed += 1
                    p = Path(line)
                    if p.exists():
                        repos.append(p)
                    else:
                        self._reject("--targets", line, "listed path does not exist")
                if listed == 0:
                    self._reject("--targets", args.targets, "file lists no paths")

        return repos

    def _discover_images(self, args) -> list[str]:
        """
        Discover container images from CLI arguments.

        Supports two input modes:
        - --image: Single container image
        - --images-file: File with list of image names

        Security: Validates container image references to prevent injection.
        """
        images: list[str] = []

        # Single image
        if getattr(args, "image", None):
            image = args.image
            if validate_container_image(image):
                images.append(image)
            else:
                self._reject("--image", image, "not a valid container image reference")

        # Images file
        if getattr(args, "images_file", None):
            images_file = Path(args.images_file)
            if not images_file.exists():
                self._reject("--images-file", args.images_file, "file does not exist")
            else:
                for line in images_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if validate_container_image(line):
                        images.append(line)
                    else:
                        self._reject(
                            "--images-file",
                            line,
                            "not a valid container image reference",
                        )

        return images

    def _discover_iac_files(self, args) -> list[tuple[str, Path]]:
        """
        Discover IaC files from CLI arguments.

        Returns list of (type, path) tuples where type is:
        - "terraform": Terraform state files
        - "cloudformation": CloudFormation templates
        - "k8s": Kubernetes manifests
        """
        iac_files: list[tuple[str, Path]] = []

        for flag, attr, iac_type in (
            ("--terraform-state", "terraform_state", "terraform"),
            ("--cloudformation", "cloudformation", "cloudformation"),
            ("--k8s-manifest", "k8s_manifest", "k8s"),
        ):
            value = getattr(args, attr, None)
            if not value:
                continue
            p = Path(value)
            if p.exists():
                iac_files.append((iac_type, p))
            else:
                self._reject(flag, value, "file does not exist")

        return iac_files

    def _discover_urls(self, args) -> list[str]:
        """
        Discover web URLs from CLI arguments.

        Supports two input modes:
        - --url: Single URL
        - --urls-file: File with list of URLs

        Security: Validates URLs to ensure only http/https protocols
        and prevent injection attacks.
        """
        urls: list[str] = []

        # Single URL
        if getattr(args, "url", None):
            url = args.url
            if validate_url(url):
                urls.append(url)
            else:
                self._reject("--url", url, "only http/https URLs are scanned")

        # URLs file
        if getattr(args, "urls_file", None):
            urls_file = Path(args.urls_file)
            if not urls_file.exists():
                self._reject("--urls-file", args.urls_file, "file does not exist")
            else:
                for line in urls_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if validate_url(line):
                        urls.append(line)
                    else:
                        self._reject(
                            "--urls-file", line, "only http/https URLs are scanned"
                        )

        # OpenAPI/Swagger spec. This is advertised in `jmo scan --help` but was
        # handled only by jmo.py's _iter_urls, which nothing had called since
        # discovery moved here - so the flag was silently accepted and dropped
        # (#807). That dead helper has since been deleted (#808).
        if getattr(args, "api_spec", None):
            spec = args.api_spec
            if spec.startswith(("http://", "https://")):
                urls.append(spec)
            else:
                p = Path(spec)
                if p.exists():
                    urls.append(f"file://{p.absolute()}")
                else:
                    self._reject("--api-spec", spec, "spec file does not exist")

        return urls

    def _discover_gitlab_repos(self, args) -> list[dict[str, str]]:
        """
        Discover GitLab repositories from CLI arguments.

        Supports:
        - --gitlab-repo: Single repository (format: group/project)
        - --gitlab-group: All repos in a group

        Returns:
            List of dicts with keys: full_path, url, token, repo, group, name
        """
        gitlab_repos: list[dict[str, str]] = []

        # Single GitLab repository
        if getattr(args, "gitlab_repo", None):
            full_path = args.gitlab_repo
            parts = full_path.split("/")
            group = parts[0] if len(parts) > 1 else ""
            repo = parts[1] if len(parts) > 1 else full_path

            gitlab_repos.append(
                {
                    "full_path": full_path,
                    "url": getattr(args, "gitlab_url", "https://gitlab.com"),
                    "token": getattr(args, "gitlab_token", ""),
                    "repo": repo,
                    "group": group,
                    "name": full_path.replace("/", "_"),
                }
            )

        # GitLab group (would need API call to enumerate)
        if getattr(args, "gitlab_group", None):
            # Note: Actual implementation would query GitLab API
            # For now, create a placeholder entry
            group = args.gitlab_group
            gitlab_repos.append(
                {
                    "full_path": f"group:{group}",
                    "url": getattr(args, "gitlab_url", "https://gitlab.com"),
                    "token": getattr(args, "gitlab_token", ""),
                    "repo": "",
                    "group": group,
                    "name": f"group_{group}",
                }
            )

        return gitlab_repos

    def _discover_k8s_resources(self, args) -> list[dict[str, str]]:
        """
        Discover Kubernetes resources from CLI arguments.

        Supports:
        - --k8s-context: Kubernetes context name
        - --k8s-namespace: Specific namespace
        - --k8s-all-namespaces: All namespaces flag

        Returns:
            List of dicts with keys: context, namespace, name
        """
        k8s_resources: list[dict[str, str]] = []

        if getattr(args, "k8s_context", None):
            context = args.k8s_context
            namespace = getattr(args, "k8s_namespace", None)
            all_namespaces = getattr(args, "k8s_all_namespaces", False)

            if all_namespaces:
                k8s_resources.append(
                    {
                        "context": context,
                        "namespace": "*",
                        "name": f"{context}_all-namespaces",
                    }
                )
            elif namespace:
                k8s_resources.append(
                    {
                        "context": context,
                        "namespace": namespace,
                        "name": f"{context}_{namespace}",
                    }
                )
            else:
                k8s_resources.append(
                    {
                        "context": context,
                        "namespace": "default",
                        "name": f"{context}_default",
                    }
                )

        return k8s_resources

    def _filter_repos(self, repos: list[Path]) -> list[Path]:
        """
        Apply include/exclude patterns to repository list.

        Args:
            repos: List of repository paths

        Returns:
            Filtered list of repositories
        """
        # Apply include patterns
        if self.config.include_patterns:
            repos = [
                r
                for r in repos
                if any(
                    fnmatch.fnmatch(r.name, pat) for pat in self.config.include_patterns
                )
            ]

        # Apply exclude patterns
        if self.config.exclude_patterns:
            repos = [
                r
                for r in repos
                if not any(
                    fnmatch.fnmatch(r.name, pat) for pat in self.config.exclude_patterns
                )
            ]

        return repos

    def setup_results_directories(self, targets: ScanTargets) -> None:
        """
        Create results directory structure for all target types.

        Creates:
        - results/individual-repos/ (always)
        - results/individual-images/ (if images present)
        - results/individual-iac/ (if IaC files present)
        - results/individual-web/ (if URLs present)
        - results/individual-gitlab/ (if GitLab repos present)
        - results/individual-k8s/ (if K8s resources present)

        Args:
            targets: Discovered scan targets
        """
        base = self.config.results_dir

        # Always create repos directory (legacy compatibility)
        # mode=0o700: restrictive permissions for security scan results
        (base / "individual-repos").mkdir(parents=True, exist_ok=True, mode=0o700)

        # Create directories for other target types (only if targets present)
        if targets.images:
            (base / "individual-images").mkdir(parents=True, exist_ok=True, mode=0o700)

        if targets.iac_files:
            (base / "individual-iac").mkdir(parents=True, exist_ok=True, mode=0o700)

        if targets.urls:
            (base / "individual-web").mkdir(parents=True, exist_ok=True, mode=0o700)

        if targets.gitlab_repos:
            (base / "individual-gitlab").mkdir(parents=True, exist_ok=True, mode=0o700)

        if targets.k8s_resources:
            (base / "individual-k8s").mkdir(parents=True, exist_ok=True, mode=0o700)

    def validate_targets(self, targets: ScanTargets) -> bool:
        """
        Validate that at least one scan target was discovered.

        Args:
            targets: Discovered scan targets

        Returns:
            True if targets exist, False if no targets found
        """
        return not targets.is_empty()

    def get_effective_max_workers(self) -> int:
        """
        Calculate effective max_workers value.

        Priority:
        1. ScanConfig.max_workers (if set)
        2. JMO_THREADS environment variable
        3. Default: 4

        Returns:
            Number of parallel workers to use
        """
        import os

        if self.config.max_workers is not None:
            return self.config.max_workers

        if os.getenv("JMO_THREADS"):
            try:
                return max(1, int(os.getenv("JMO_THREADS", "4")))
            except ValueError:
                pass

        return 4  # Default

    def get_summary(self, targets: ScanTargets) -> dict[str, Any]:
        """
        Generate summary of orchestration configuration.

        Args:
            targets: Discovered scan targets

        Returns:
            Dictionary with summary information
        """
        return {
            "config": {
                "tools": self.config.tools,
                "results_dir": str(self.config.results_dir),
                "timeout": self.config.timeout,
                "retries": self.config.retries,
                "max_workers": self.get_effective_max_workers(),
                "include_patterns": self.config.include_patterns,
                "exclude_patterns": self.config.exclude_patterns,
            },
            "targets": targets.to_dict(),
            "validation": {
                "has_targets": not targets.is_empty(),
                "total_count": targets.total_count(),
            },
        }

    def scan_all(
        self,
        targets: ScanTargets,
        per_tool_config: dict,
        progress_callback=None,
        tool_progress_callback=None,
        session=None,
        session_path=None,
    ) -> list[tuple[str, dict[str, bool]]]:
        """
        Execute scans on all discovered targets in parallel.

        This method encapsulates ALL scanning logic that was previously inline in cmd_scan.
        It handles parallel execution, progress tracking, and result aggregation for all 6 target types.

        Args:
            targets: Discovered scan targets
            per_tool_config: Per-tool configuration overrides
            progress_callback: Optional target-level progress callback, invoked
                as ``(target_type, target_id, statuses, elapsed=<seconds>)``.
                ``statuses`` is the scanner's per-tool boolean map -- pass it to
                ``classify_target_outcome``; do not infer success from
                ``elapsed``, which is a duration and says nothing about outcome.
            tool_progress_callback: Optional callback for tool-level progress (tool_name, status, count)
                                   Called when each tool starts and completes
            session: Optional ScanSession for checkpointing (skip completed targets)
            session_path: Optional Path to session file for checkpoint writes

        Returns:
            List of (target_name, statuses_dict) tuples for all scanned targets
        """
        from concurrent.futures import ThreadPoolExecutor

        from scripts.cli.scan_jobs import (
            scan_gitlab_repo,
            scan_iac_file,
            scan_image,
            scan_k8s_resource,
            scan_repository,
            scan_url,
        )

        all_results = []
        futures = []
        max_workers = self.get_effective_max_workers()

        # Helper to check if a target was already completed in a previous session
        def _is_completed(target_id: str) -> bool:
            if session is not None:
                return bool(session.is_target_completed(target_id))
            return False

        # Helper to checkpoint after each target completes
        def _checkpoint(target_id: str, statuses: dict[str, bool]) -> None:
            if session is not None and session_path is not None:
                session.mark_target_complete(target_id, statuses)
                from scripts.cli.scan_session import save_session as _save

                _save(session, session_path)

        # Filter tools by scan type for smarter tool selection
        # This avoids running URL-only tools on repos, repo-only tools on images, etc.
        repo_tools = filter_tools_for_scan_type(self.config.tools, "repo")
        image_tools = filter_tools_for_scan_type(self.config.tools, "image")
        iac_tools = filter_tools_for_scan_type(self.config.tools, "iac")
        url_tools = filter_tools_for_scan_type(self.config.tools, "url")
        gitlab_tools = filter_tools_for_scan_type(self.config.tools, "gitlab")
        k8s_tools = filter_tools_for_scan_type(self.config.tools, "k8s")

        # A requested tool that matches no target type present in this scan runs
        # nowhere and contributes nothing, and until now said nothing either:
        # `filter_tools_for_scan_type` drops silently, and the per-target
        # scanners can only report on tools that were handed to them. On a deep
        # scan of a repository that made `nuclei` (URL-only) and `lynis` vanish
        # completely - absent from every stream, artifact and diagnostic.
        #
        # Computed against the target types actually being scanned, not each
        # filter in isolation: nuclei is correctly skipped for a repository, but
        # if the same run also has URLs then it does run and must not be named.
        routed: set[str] = set()
        for present, applicable in (
            (targets.repos, repo_tools),
            (targets.images, image_tools),
            (targets.iac_files, iac_tools),
            (targets.urls, url_tools),
            (targets.gitlab_repos, gitlab_tools),
            (targets.k8s_resources, k8s_tools),
        ):
            if present:
                routed.update(applicable)

        unrouted = [t for t in self.config.tools if t not in routed]
        if unrouted:
            logger.warning(
                "Requested but applicable to no target type in this scan, so "
                "not run and contributing no findings: %s",
                ", ".join(sorted(unrouted)),
            )

        skipped_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit repositories - use repo-filtered tools
            for repo in targets.repos:
                if _is_completed(repo.name):
                    skipped_count += 1
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_repository,
                    repo,
                    self.config.results_dir / "individual-repos",
                    repo_tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                    progress_callback=tool_progress_callback,
                )
                futures.append(("repo", repo.name, future))

            # Submit images - use image-filtered tools (trivy, syft only)
            for image in targets.images:
                if _is_completed(image):
                    skipped_count += 1
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_image,
                    image,
                    self.config.results_dir / "individual-images",
                    image_tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                )
                futures.append(("image", image, future))

            # Submit IaC files - use IaC-filtered tools
            for iac_type, iac_path in targets.iac_files:
                iac_id = str(iac_path)
                if _is_completed(iac_id):
                    skipped_count += 1
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_iac_file,
                    iac_type,
                    iac_path,
                    self.config.results_dir / "individual-iac",
                    iac_tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                )
                futures.append(("iac", iac_id, future))

            # Submit URLs - use URL-filtered tools (nuclei, zap, akto only)
            for url in targets.urls:
                if _is_completed(url):
                    skipped_count += 1
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_url,
                    url,
                    self.config.results_dir / "individual-web",
                    url_tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                )
                futures.append(("url", url, future))

            # Submit GitLab repos - use gitlab-filtered tools
            for gitlab_repo_info in targets.gitlab_repos:
                gl_id = gitlab_repo_info.get("full_path", "unknown")
                if _is_completed(gl_id):
                    skipped_count += 1
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_gitlab_repo,
                    gitlab_repo_info,
                    self.config.results_dir / "individual-gitlab",
                    gitlab_tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                )
                futures.append(("gitlab", gl_id, future))

            # Submit K8s resources - use k8s-filtered tools (trivy only)
            for k8s_resource_info in targets.k8s_resources:
                ctx = k8s_resource_info.get("context", "unknown")
                ns = k8s_resource_info.get("namespace", "unknown")
                k8s_id = f"{ctx}:{ns}"
                if _is_completed(k8s_id):
                    skipped_count += 1
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_k8s_resource,
                    k8s_resource_info,
                    self.config.results_dir / "individual-k8s",
                    k8s_tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                )
                futures.append(("k8s", k8s_id, future))

            if skipped_count > 0:
                # WARNING, not INFO. `configure_scan_logging` sets the `scripts`
                # logger to WARNING by default, so this was invisible at the
                # default verbosity -- measured: present with `--log-level INFO`,
                # absent with `--log-level WARN`. Meanwhile jmo.py's own `_log`
                # prints INFO, so the two logging systems have different
                # effective floors and this line was on the quiet one.
                #
                # It is the only thing that tells a reader their results cover
                # fewer targets than they asked for, and the progress display
                # ends part-way (`[1/2] ... Progress: 50%`) with no other
                # explanation. That is not routine chatter.
                logger.warning(
                    "Resuming scan: skipped %d previously completed target(s); "
                    "this run's results cover only the remaining ones",
                    skipped_count,
                )

            # Collect results as they complete
            for target_type, target_id, future in futures:
                try:
                    name, statuses, elapsed = future.result()
                    all_results.append((name, statuses))

                    # Checkpoint after each completed target
                    _checkpoint(target_id, statuses)

                    # Call progress callback if provided
                    if progress_callback:
                        progress_callback(
                            target_type, target_id, statuses, elapsed=elapsed
                        )

                except Exception as e:
                    # Log error but continue with other targets
                    logger.error(
                        f"Scan failed for {target_type} {target_id}: {e}", exc_info=True
                    )
                    # Still append partial result. An empty status map is
                    # classify_target_outcome's TARGET_FAILED, so this target is
                    # counted as having produced nothing rather than vanishing.
                    all_results.append((target_id, {}))

                    # The callback used to be skipped on this path, so a target
                    # whose scanner *raised* never reached the progress display
                    # at all: the run ended showing fewer completed targets than
                    # it had, with no line saying which one was missing. A crash
                    # is the loudest outcome there is and it was the quietest.
                    #
                    # Guarded, matching ToolRunner's callback handling: this call
                    # sits *inside* an except block, so anything it raises would
                    # replace a single target's failure with the death of the
                    # whole scan. A progress display must not be able to do that.
                    if progress_callback:
                        try:
                            progress_callback(target_type, target_id, {}, elapsed=0.0)
                        except Exception:
                            logger.debug(
                                "Progress callback failed for %s %s",
                                target_type,
                                target_id,
                                exc_info=True,
                            )

        return all_results
