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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.cli.path_sanitizers import _sanitize_path_component
from scripts.core.config import RetryConfig
from scripts.core.scan_timings import OFF_TARGET_REASONS, Reason, State, ToolRun
from scripts.core.tool_registry import TOOL_SCAN_TYPES
from scripts.core.validation import validate_container_image, validate_url

logger = logging.getLogger(__name__)


def _user_path(value: str) -> Path:
    """Build a ``Path`` from user-supplied text, expanding a leading ``~``.

    ``Path("~/repos")`` is a relative path whose first component is the single
    character ``~``. Nothing in the scan layer expanded it, so a schedule
    created with ``--repos-dir ~/repos`` scanned a directory of that literal
    name relative to the cwd -- which does not exist, so the run reported
    nothing to scan and no error (#926).

    The cron backend cannot fix this for us: ``cron_installer`` passes the
    value through ``shlex.quote``, and a *quoted* tilde is not expanded by the
    shell either. Un-quoting would reintroduce the shell injection that
    quoting closed, so the expansion belongs here -- in the process that
    actually has a home directory, independent of how the command was quoted.

    Applied to every path-valued target flag rather than only ``--repos-dir``:
    a user who types ``~`` means their home directory whichever flag they typed
    it on, and a per-flag rule is how the next one of these gets filed.
    """
    return Path(value).expanduser()


def _unreadable(exc: OSError) -> str:
    """Rejection text for a target the process was not allowed to inspect.

    The ownership sentence is attached only to ``PermissionError``: a user
    reading "cannot be read" against a path they can see in their own shell has
    no way to guess that the *container's* uid is what could not see it, and
    re-types the path instead of fixing the mount. Anything else keeps the bare
    errno text, because inventing a cause is worse than reporting one.
    """
    detail = exc.strerror or type(exc).__name__
    if isinstance(exc, PermissionError):
        return (
            f"cannot be read: {detail}. If this is a container bind mount, the "
            f"published images run as uid 1000 and cannot read a path owned by "
            f"another uid"
        )
    return f"cannot be read: {detail}"


def _probe(check: Callable[[], bool], missing: str) -> str | None:
    """Run one filesystem predicate, answering why the target is unusable.

    ``Path.exists()`` is not total. Through 3.11 it swallowed every ``OSError``
    from the underlying ``stat`` and answered ``False``; 3.12 narrowed that to
    ``ValueError``, so ``PermissionError`` propagates. Discovery called it
    unguarded, so a path the process may not stat produced a traceback and exit
    1 instead of a scan or a legible refusal -- which is what every user
    bind-mounting a directory owned by another uid got from the shipped v1.1.0
    image (#1163).

    Returns ``None`` when the target is usable, else the reason to reject it.
    Chaining with ``or`` therefore stops at the first real problem::

        _probe(base.exists, "directory does not exist") or _probe(
            base.is_dir, "is not a directory"
        )
    """
    try:
        return None if check() else missing
    except OSError as exc:
        return _unreadable(exc)


def _probe_children(base: Path) -> tuple[list[Path], str | None]:
    """Subdirectories of ``base``, or why they could not be listed.

    ``iterdir()`` and the ``is_dir()`` on each entry are further syscalls that
    fail independently of the ``exists()`` that got us here -- a directory can
    be stattable and still not readable.
    """
    try:
        return [p for p in base.iterdir() if p.is_dir()], None
    except OSError as exc:
        return [], _unreadable(exc)


def _read_lines(path: Path) -> tuple[list[str], str | None]:
    """Lines of a user-supplied list file, or why it could not be read.

    ``exists()`` answering True does not promise ``open()`` will work: a
    traversable directory holding a mode-000 file gives exactly that split.
    """
    try:
        return path.read_text(encoding="utf-8").splitlines(), None
    except OSError as exc:
        return [], _unreadable(exc)


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
║      ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan
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
    # Each repository's results folder, parallel to `repos` and unique in the
    # scan (#1303). Filled by `discover_targets`; see `repo_result_names`.
    repo_names: list[str] = field(default_factory=list)

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
    # True when `tools` came from `--tools` or `jmo.yml`, not the matrix
    # default: only a tool someone named is worth a warning when no target in
    # the scan is one it reads (#1279).
    explicit_tools: bool = False

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


# How one target's scan ended, derived from its accounting rows. Named
# constants rather than bare strings so a typo at a comparison site is a
# NameError instead of a silently false branch.
TARGET_OK = "ok"
TARGET_PARTIAL = "partial"
TARGET_FAILED = "failed"
# Every tool that reads this kind of target was skipped: not installed under
# `--allow-missing-tools`, or nothing of its kind in the tree. Distinct from
# FAILED, which means tools ran and produced nothing. It must not redden the
# run, and it must still be said out loud, because an empty stub from a secret
# scanner that never ran satisfies a zero-secrets policy (#825).
TARGET_NOT_ATTEMPTED = "not-attempted"


def classify_target_outcome(rows: Mapping[str, ToolRun] | None) -> str:
    """Classify one target's scan from its rows.

    Returns ``TARGET_OK`` if every tool that ran counts, ``TARGET_PARTIAL`` if
    some failed, ``TARGET_FAILED`` if all did or if no requested tool reads
    this kind of target, and ``TARGET_NOT_ATTEMPTED`` if every tool that reads
    it was skipped.

    **No rows, or only off-target rows, is ``TARGET_FAILED``, not vacuous
    success**: the target contributed nothing. ``all([])`` being True is the
    reading that would render it a clean scan (#809).

    A skipped tool gets no vote. Counting it as a failure would make a target
    where one tool ran cleanly and two were not installed a partial failure.
    """
    if not rows:
        return TARGET_FAILED
    in_scope = [r for r in rows.values() if r.reason not in OFF_TARGET_REASONS]
    if not in_scope:
        return TARGET_FAILED
    ran = sum(r.state is State.RAN for r in in_scope)
    failed = sum(r.state is State.FAILED for r in in_scope)
    if not ran and not failed:
        return TARGET_NOT_ATTEMPTED
    if not failed:
        return TARGET_OK
    return TARGET_PARTIAL if ran else TARGET_FAILED


@dataclass(frozen=True)
class TargetSummary:
    """What the progress lines say about one finished target."""

    outcome: str
    failed: list[str]  # tools that failed
    not_installed: list[str]  # skipped because not installed
    skipped: list[str]  # "tool (reason)" for every other in-scope skip


def summarize_target(rows: Mapping[str, ToolRun] | None) -> TargetSummary:
    """The outcome and the tool lists both progress trackers print."""
    rows = rows or {}
    return TargetSummary(
        outcome=classify_target_outcome(rows),
        failed=sorted(r.tool for r in rows.values() if r.state is State.FAILED),
        not_installed=sorted(
            r.tool
            for r in rows.values()
            if r.state is State.SKIPPED and r.reason is Reason.NOT_INSTALLED
        ),
        skipped=sorted(
            f"{r.tool} ({r.reason})"
            for r in rows.values()
            if r.state is State.SKIPPED and r.reason not in OFF_TARGET_REASONS
        ),
    )


def unique_names(names: list[str], prefixes: list[str] | None = None) -> list[str]:
    """Make each results folder name unique within one target type's folder.

    Two targets sharing a folder are scanned concurrently into it, and the last
    writer's findings stand for both (#1303, #1312). A name that collides,
    case-insensitively as Windows does, takes its prefix when there is one
    (``alice__app``), and a numeric suffix settles a collision that survives
    that. A name that does not collide is unchanged.
    """
    counts: dict[str, int] = {}
    for name in names:
        counts[name.casefold()] = counts.get(name.casefold(), 0) + 1
    unique: list[str] = []
    used: set[str] = set()
    for i, name in enumerate(names):
        if prefixes is not None and counts[name.casefold()] > 1:
            name = f"{prefixes[i]}__{name}"
        candidate, n = name, 2
        while candidate.casefold() in used:
            candidate = f"{name}-{n}"
            n += 1
        used.add(candidate.casefold())
        unique.append(candidate)
    return unique


def repo_result_names(repos: list[Path]) -> list[str]:
    """Each repository's results folder, unique within the scan (#1303).

    Results land in ``individual-repos/<name>``, and two repositories with one
    folder name (``~/work/app`` and ``~/oss/app``, or two forks cloned from a
    TSV) shared one folder. A collision takes the parent's name as its prefix
    (``alice__app``, ``bob__app``). The name is also the repository's name in
    every accounting record.
    """
    # `Path(".").name` is "", which sanitized to "unknown" (#1315). `abspath`,
    # not `resolve`: a symlinked repository keeps the name it was given.
    paths = [Path(os.path.abspath(repo)) for repo in repos]
    return unique_names(
        [_sanitize_path_component(p.name) for p in paths],
        [_sanitize_path_component(p.parent.name) for p in paths],
    )


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
        targets.repo_names = repo_result_names(targets.repos)

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

        Supports four input modes:
        - --repo: Single repository path
        - --repos-dir: Directory containing multiple repos
        - --targets: File with list of repository paths
        - --tsv: TSV of repositories, cloned into --dest first

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

            p = _user_path(repo_path)
            why = _probe(p.exists, "path does not exist")
            if why:
                self._reject("--repo", repo_path, why)
            else:
                repos.append(p)

        # Directory of repositories
        elif getattr(args, "repos_dir", None):
            repos_dir_path = args.repos_dir

            # Check for MSYS path mangling
            if _detect_msys_path_mangling(repos_dir_path):
                _warn_msys_path_mangling(repos_dir_path)
                self._reject("--repos-dir", repos_dir_path, "path looks MSYS-mangled")
                return repos

            base = _user_path(repos_dir_path)
            why = _probe(base.exists, "directory does not exist") or _probe(
                base.is_dir, "is not a directory"
            )
            if why:
                self._reject("--repos-dir", repos_dir_path, why)
            else:
                # Find all subdirectories (assumed to be repos)
                found, listing_why = _probe_children(base)
                repos.extend(found)
                if listing_why:
                    self._reject("--repos-dir", repos_dir_path, listing_why)
                elif not repos:
                    self._reject(
                        "--repos-dir", repos_dir_path, "contains no subdirectories"
                    )

        # Targets file (list of repository paths)
        elif getattr(args, "targets", None):
            targets_file = _user_path(args.targets)
            why = _probe(targets_file.exists, "file does not exist")
            if why:
                self._reject("--targets", args.targets, why)
            else:
                lines, read_why = _read_lines(targets_file)
                if read_why:
                    self._reject("--targets", args.targets, read_why)
                else:
                    listed = 0
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        listed += 1
                        p = _user_path(line)
                        entry_why = _probe(p.exists, "listed path does not exist")
                        if entry_why:
                            self._reject("--targets", line, entry_why)
                        else:
                            repos.append(p)
                    if listed == 0:
                        self._reject("--targets", args.targets, "file lists no paths")

        # TSV of repositories to clone, then scan (#1299)
        elif getattr(args, "tsv", None):
            repos.extend(self._clone_tsv(args.tsv, getattr(args, "dest", None)))

        return repos

    def _clone_tsv(self, tsv: str, dest: str | None) -> list[Path]:
        """Clone every repository a TSV lists into `dest`; return the clones.

        Each row that is refused or fails to clone is rejected by name, and a
        file whose every row failed is rejected as a whole: a scan of nothing
        is not a clean scan.
        """
        import csv

        from scripts.cli.clone_from_tsv import (
            clone_or_update,
            parse_tsv,
            redact,
            repo_name,
        )

        if not dest:
            # No default: the working directory puts clones inside whatever
            # repository the user runs from, and the results directory is
            # uploaded whole by CI and deleted between runs.
            self._reject("--tsv", tsv, "needs --dest DIR, where to clone the rows")
            return []
        path = _user_path(tsv)
        why = _probe(path.exists, "file does not exist")
        if why:
            self._reject("--tsv", tsv, why)
            return []
        try:
            urls = parse_tsv(path)
        except OSError as exc:
            self._reject("--tsv", tsv, _unreadable(exc))
            return []
        except (RuntimeError, UnicodeDecodeError, csv.Error) as exc:
            self._reject("--tsv", tsv, str(exc))
            return []
        if not urls:
            self._reject("--tsv", tsv, "file lists no repositories")
            return []
        dest_path = _user_path(dest)
        try:
            dest_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._reject("--tsv", tsv, f"--dest {dest} cannot be used: {exc}")
            return []

        clones: list[Path] = []
        filtered = 0
        for url in dict.fromkeys(urls):  # a row listed twice is scanned once
            # include/exclude match the folder a row clones into, which the URL
            # already names: a row they drop is never cloned or fetched.
            name = repo_name(url)
            if name is not None and not self._passes_filters(name):
                logger.info("Not cloning %s: excluded by include/exclude", redact(url))
                filtered += 1
                continue
            clone, why = clone_or_update(url, dest_path)
            if clone is None:
                self._reject("--tsv", redact(url), why or "clone failed")
                continue
            clones.append(clone)
        if not clones:
            self._reject(
                "--tsv",
                tsv,
                "include/exclude left no row to clone"
                if filtered and filtered == len(dict.fromkeys(urls))
                else "no listed repository could be cloned",
            )
        return clones

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
            images_file = _user_path(args.images_file)
            why = _probe(images_file.exists, "file does not exist")
            if why:
                self._reject("--images-file", args.images_file, why)
            else:
                lines, read_why = _read_lines(images_file)
                if read_why:
                    self._reject("--images-file", args.images_file, read_why)
                for line in lines:
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

        # An image listed twice is scanned once: two targets with one name put
        # two rows per tool under it (#1312).
        return list(dict.fromkeys(images))

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
            p = _user_path(value)
            why = _probe(p.exists, "file does not exist")
            if why:
                self._reject(flag, value, why)
            else:
                iac_files.append((iac_type, p))

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
            urls_file = _user_path(args.urls_file)
            why = _probe(urls_file.exists, "file does not exist")
            if why:
                self._reject("--urls-file", args.urls_file, why)
            else:
                lines, read_why = _read_lines(urls_file)
                if read_why:
                    self._reject("--urls-file", args.urls_file, read_why)
                for line in lines:
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
                p = _user_path(spec)
                why = _probe(p.exists, "spec file does not exist")
                if why:
                    self._reject("--api-spec", spec, why)
                else:
                    urls.append(f"file://{p.absolute()}")

        # A URL listed twice is scanned once, as a TSV row is (#1312).
        return list(dict.fromkeys(urls))

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
        # The name the repository is recorded under: `--repo .` is not "".
        return [r for r in repos if self._passes_filters(Path(os.path.abspath(r)).name)]

    def _passes_filters(self, name: str) -> bool:
        """Whether a repository folder name survives `include` and `exclude`."""
        if self.config.include_patterns and not any(
            fnmatch.fnmatch(name, pat) for pat in self.config.include_patterns
        ):
            return False
        return not any(
            fnmatch.fnmatch(name, pat) for pat in self.config.exclude_patterns
        )

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
    ) -> list[tuple[str, str, dict[str, ToolRun]]]:
        """
        Execute scans on all discovered targets in parallel.

        Every job gets every requested tool and returns one row per tool, so a
        tool that does not read a target type is a `skipped` row there rather
        than a name filtered away before anything could report it.

        Args:
            targets: Discovered scan targets
            per_tool_config: Per-tool configuration overrides
            progress_callback: Optional target-level progress callback, invoked
                as ``(target_type, target_id, rows, elapsed=<seconds>)``. Pass
                ``rows`` to ``classify_target_outcome``; ``elapsed`` is a
                duration and says nothing about outcome.
            tool_progress_callback: Optional callback for tool-level progress (tool_name, status, count)
                                   Called when each tool starts and completes
            session: Optional ScanSession for checkpointing (skip completed targets)
            session_path: Optional Path to session file for checkpoint writes

        Returns:
            (target type, target name, rows by tool) for every scanned target
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
        from scripts.cli.scan_jobs.iac_scanner import iac_target_name
        from scripts.cli.scan_jobs.tool_loop import rows_without_running
        from scripts.cli.scan_jobs.url_scanner import url_folder_name

        all_results: list[tuple[str, str, dict[str, ToolRun]]] = []
        futures = []
        max_workers = self.get_effective_max_workers()
        tools = list(self.config.tools)

        # Helper to check if a target was already completed in a previous session
        def _is_completed(target_id: str) -> bool:
            if session is not None:
                return bool(session.is_target_completed(target_id))
            return False

        # A resumed scan does not scan a completed target again, but its rows
        # are still this scan's record: `tool_runs`, history, the reconciler.
        def _resumed(target_type: str, target_id: str) -> None:
            kept = session.completed_rows(target_id) if session is not None else None
            if kept is not None:
                all_results.append((target_type, kept[0], kept[1]))

        # Helper to checkpoint after each target completes
        def _checkpoint(target_id: str, name: str, rows: Mapping[str, ToolRun]) -> None:
            if session is not None and session_path is not None:
                session.mark_target_complete(target_id, rows, name=name)
                from scripts.cli.scan_session import save_session as _save

                _save(session, session_path)

        # A tool someone named that no target in this scan reads runs nowhere.
        # Its rows say `skipped` on every target; this line says it once. Only
        # for a tool someone named: the matrix default puts zap and nuclei in
        # every repository scan, where the line fired although nothing was
        # requested (#1279). Computed against the target types present, not each
        # in isolation: nuclei is skipped on a repository, but runs if the same
        # scan also has URLs.
        if self.config.explicit_tools:
            routed: set[str] = set()
            for target_type, present in (
                ("repo", targets.repos),
                ("image", targets.images),
                ("iac", targets.iac_files),
                ("url", targets.urls),
                ("gitlab", targets.gitlab_repos),
                ("k8s", targets.k8s_resources),
            ):
                if present:
                    routed.update(TOOL_SCAN_TYPES[target_type])
            unrouted = [t for t in tools if t not in routed]
            if unrouted:
                logger.warning(
                    "Requested but applicable to no target type in this scan, so "
                    "not run and contributing no findings: %s",
                    ", ".join(sorted(unrouted)),
                )

        skipped_count = 0
        repo_names = targets.repo_names or repo_result_names(targets.repos)
        # Each target's folder, unique within its type (#1312). Assigned over
        # every target, completed or not, so a resumed scan assigns the same.
        # One file per IaC flag, so a shared stem is two types: `k8s__main`.
        image_folders = unique_names(
            [_sanitize_path_component(image) for image in targets.images]
        )
        iac_folders = unique_names(
            [_sanitize_path_component(path.stem) for _, path in targets.iac_files],
            [iac_type for iac_type, _ in targets.iac_files],
        )
        url_folders = unique_names([url_folder_name(url) for url in targets.urls])

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for repo, result_name in zip(targets.repos, repo_names, strict=True):
                if _is_completed(result_name):
                    skipped_count += 1
                    _resumed("repo", result_name)
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_repository,
                    repo,
                    self.config.results_dir / "individual-repos",
                    tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                    progress_callback=tool_progress_callback,
                    result_name=result_name,
                )
                futures.append(("repo", result_name, future))

            for image, folder in zip(targets.images, image_folders, strict=True):
                if _is_completed(image):
                    skipped_count += 1
                    _resumed("image", image)
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_image,
                    image,
                    self.config.results_dir / "individual-images",
                    tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                    result_name=folder,
                )
                futures.append(("image", image, future))

            for (iac_type, iac_path), folder in zip(
                targets.iac_files, iac_folders, strict=True
            ):
                # The name its job records, so a scanner that raises is
                # recorded under the name success would have used (#1315).
                iac_id = iac_target_name(iac_type, iac_path)
                if _is_completed(iac_id):
                    skipped_count += 1
                    _resumed("iac", iac_id)
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_iac_file,
                    iac_type,
                    iac_path,
                    self.config.results_dir / "individual-iac",
                    tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                    result_name=folder,
                )
                futures.append(("iac", iac_id, future))

            for url, folder in zip(targets.urls, url_folders, strict=True):
                if _is_completed(url):
                    skipped_count += 1
                    _resumed("url", url)
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_url,
                    url,
                    self.config.results_dir / "individual-web",
                    tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                    result_name=folder,
                )
                futures.append(("url", url, future))

            for gitlab_repo_info in targets.gitlab_repos:
                gl_id = gitlab_repo_info.get("full_path", "unknown")
                if _is_completed(gl_id):
                    skipped_count += 1
                    _resumed("gitlab", gl_id)
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_gitlab_repo,
                    gitlab_repo_info,
                    self.config.results_dir / "individual-gitlab",
                    tools,
                    self.config.timeout,
                    self.config.retries,
                    per_tool_config,
                    self.config.allow_missing_tools,
                )
                futures.append(("gitlab", gl_id, future))

            for k8s_resource_info in targets.k8s_resources:
                ctx = k8s_resource_info.get("context", "unknown")
                ns = k8s_resource_info.get("namespace", "unknown")
                k8s_id = f"{ctx}:{ns}"
                if _is_completed(k8s_id):
                    skipped_count += 1
                    _resumed("k8s", k8s_id)
                    continue
                future = executor.submit(
                    _run_timed,
                    scan_k8s_resource,
                    k8s_resource_info,
                    self.config.results_dir / "individual-k8s",
                    tools,
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
                # It is the only thing that explains a progress display that
                # ends part-way (`[1/2] ... Progress: 50%`). The results still
                # cover every target: the report reads the skipped targets'
                # folders, and their rows come back from the session (#1317).
                logger.warning(
                    "Resuming scan: %d target(s) completed earlier were not "
                    "scanned again; their earlier results are reused",
                    skipped_count,
                )

            # Collect results as they complete
            for target_type, target_id, future in futures:
                try:
                    name, rows, elapsed = future.result()
                    all_results.append((target_type, name, rows))

                    # Checkpoint after each completed target
                    _checkpoint(target_id, name, rows)

                    # Call progress callback if provided
                    if progress_callback:
                        progress_callback(target_type, target_id, rows, elapsed=elapsed)

                except Exception as e:
                    # Log error but continue with other targets
                    logger.error(
                        f"Scan failed for {target_type} {target_id}: {e}", exc_info=True
                    )
                    # `target_id` is the name the job records. Still a row per
                    # tool, so this target is counted as having produced
                    # nothing (TARGET_FAILED) rather than vanishing, and
                    # reaches history with the reason.
                    failed_rows = rows_without_running(
                        tools,
                        target_type,
                        Reason.SCANNER_ERROR,
                        detail=f"{type(e).__name__}: {e}",
                    )
                    all_results.append((target_type, target_id, failed_rows))

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
                            progress_callback(
                                target_type, target_id, failed_rows, elapsed=0.0
                            )
                        except Exception:
                            logger.debug(
                                "Progress callback failed for %s %s",
                                target_type,
                                target_id,
                                exc_info=True,
                            )

        return all_results
