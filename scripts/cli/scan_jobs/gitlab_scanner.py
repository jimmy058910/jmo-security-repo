"""
GitLab Repository Scanner

Scans a GitLab repository by cloning it and running the full repository
scanner, then scans each container image it names as an image target of its
own (#1311).

1. Clone the repository into a temporary directory that holds the clone and
   nothing else: its results go straight to
   `individual-gitlab/<group>_<repo>/`, so a project named `results` is never
   scanned with its own output (#1364).
2. Run scan_repository() with every requested tool.
3. Discover the images its Dockerfiles (`FROM`), docker-compose files and
   Kubernetes manifests (`image:`) name.
4. Scan each with scan_image(), with every requested tool as `--image` would,
   into `individual-images/<group>_<repo>__<image>/`. Its rows go back to the
   orchestrator, which records it as an image target beside this one.
5. Remove the clone.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import yaml

from scripts.core.config import RetryConfig
from scripts.core.scan_timings import (
    OUTCOME_FAILED_BEFORE_TOOLS,
    Reason,
    TargetRows,
    write_scan_timings,
)
from scripts.core.secure_temp import secure_temp_dir
from scripts.core.tool_descriptors import DOCKERFILE_PATTERNS, is_dockerfile
from scripts.core.validation import (
    sanitize_subprocess_output,
    validate_container_image,
)

from ..path_sanitizers import _sanitize_path_component
from ..scan_orchestrator import unique_names
from .image_scanner import scan_image
from .repository_scanner import scan_repository
from .tool_loop import collect_files, rows_without_running

logger = logging.getLogger(__name__)

# `FROM [--platform=<p>] <image> [AS <stage>]`: any flags come first.
_FROM_LINE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE
)


class DiscoveredImages:
    """The images one scan's GitLab targets name, shared by their jobs.

    A reference is scanned once in a scan, as an image listed twice is
    (#1312): two targets with one name would put two rows per tool under it,
    and history keeps one of them. The first job to claim one scans it, and
    `found_in` hands its rows to the orchestrator. It is not retried if that
    scan fails: its one image target says so. Jobs run concurrently, so every
    method goes through a lock.
    """

    def __init__(
        self, images_dir: Path, scanned: Mapping[str, str] | None = None
    ) -> None:
        """`images_dir`: the scan's `individual-images`, where each claimed
        image's folder goes. `scanned`: each reference this scan already scans
        as an image target, and the target it is scanned for (`--image`, a
        GitLab path)."""
        self.images_dir = images_dir
        self._lock = threading.Lock()
        self._claimed: dict[str, str] = dict(scanned or {})
        self._found: dict[str, list[tuple[str, TargetRows]]] = {}

    def claim(self, image: str, by: str) -> str | None:
        """None when `by` is the first to name `image`, which it then scans;
        otherwise the target it is already scanned for."""
        with self._lock:
            if image in self._claimed:
                return self._claimed[image]
            self._claimed[image] = by
            return None

    def add(self, found_in: str, image: str, rows: TargetRows) -> None:
        """Record the rows of an image the GitLab target `found_in` named."""
        with self._lock:
            self._found.setdefault(found_in, []).append((image, rows))

    def found_in(self, target: str) -> list[tuple[str, TargetRows]]:
        """The (reference, rows) of each image `target` named and scanned."""
        with self._lock:
            return list(self._found.get(target, ()))


def _gitlab_out_dir(results_dir: Path, full_path: str) -> Path:
    """The directory this target's artifacts land in.

    Derived here as well as at the success path's copy step, because the
    failure paths return before that step runs and still need somewhere to put
    a timings document.
    """
    return results_dir / full_path.replace("/", "_").replace("*", "all")


def _record_abandoned_target(
    results_dir: Path,
    full_path: str,
    tools: list[str],
    started: float,
    reason: str,
) -> TargetRows:
    """Write the rows of a target abandoned before any tool ran (#824).

    On the four failure paths no tool reached `ToolRunner`, and an absent
    timings file is indistinguishable from a target nobody asked for. Every
    requested tool that reads a repository gets `failed:target not scanned`,
    with the reason as its detail. A failure after the repository's scan does
    not come here: its outputs are written, and its rows are its own.
    """
    return _abandon(
        _gitlab_out_dir(results_dir, full_path),
        full_path,
        "gitlab",
        tools,
        started,
        reason,
    )


def _abandon(
    out_dir: Path,
    target: str,
    target_type: str,
    tools: list[str],
    started: float,
    reason: str,
) -> TargetRows:
    """A target no tool was run on: `failed:target not scanned` rows, and its
    timings document saying why, in the folder the report reads."""
    rows = rows_without_running(tools, target_type, Reason.BEFORE_TOOLS, detail=reason)
    # No tool has written output, so the target's directory does not exist
    # yet. `write_scan_timings` deliberately does not create one -- an absent
    # destination there must mean "nothing written".
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # A diagnostic must never be the reason a scan result is lost.
        logger.warning("Could not create %s for scan timings: %s", out_dir, exc)
        return rows
    write_scan_timings(
        out_dir,
        rows,
        target=target,
        target_type=target_type,
        wall_seconds=time.perf_counter() - started,
        outcome=OUTCOME_FAILED_BEFORE_TOOLS,
        error=reason,
    )
    return rows


def _templated(image: str, source: Path, repo_path: Path) -> bool:
    """Whether a reference is set by a build argument or a variable (`$BASE`,
    `${TAG}`): it names no image until a build supplies it, so it is skipped,
    and the file is named."""
    if "$" not in image:
        return False
    logger.info(
        "%s: %s is set by a build argument or variable, so it is not scanned",
        source.relative_to(repo_path).as_posix(),
        image,
    )
    return True


def _discover_container_images(repo_path: Path) -> set[str]:
    """
    Discover container images referenced in repository files.

    Scans for:
    - Dockerfile FROM lines
    - docker-compose.yml service images
    - Kubernetes manifests (*.k8s.yaml, *.k8s.yml) image references

    Args:
        repo_path: Path to cloned repository

    Returns:
        Set of discovered image names (e.g., 'nginx:latest', 'python:3.11-slim'),
        as the repository spells them: the job refuses one that is not an
        image reference before any tool sees it.
    """
    images: set[str] = set()

    # Pattern 1: Dockerfile FROM lines
    # FROM nginx:latest
    # FROM --platform=linux/amd64 python:3.11-slim AS builder
    # The files hadolint's row reads, by the one definition of a Dockerfile,
    # through the same walk: `*Dockerfile*` read `pkg/dockerfile_utils.py`
    # (`from os import path`) and a `Dockerfile.md` ("From the root..."), and
    # each named an image to pull from Docker Hub (measured: `os`, `the`), and
    # a vendored tree's Dockerfile too.
    dockerfiles = [
        Path(found)
        for found in collect_files(repo_path, DOCKERFILE_PATTERNS, "image discovery")
        if is_dockerfile(Path(found).name)
    ]
    for dockerfile in dockerfiles:
        try:
            content = dockerfile.read_text(encoding="utf-8", errors="ignore")
            stages: set[str] = set()
            for line in content.splitlines():
                match = _FROM_LINE.match(line)
                if not match:
                    continue
                image, stage = match.group(1), match.group(2)
                if stage:
                    # A build stage's base is skipped, as it always was, and
                    # its name is a stage, not an image, when a later FROM
                    # names it.
                    stages.add(stage.lower())
                    continue
                if image.lower() in ("scratch", *stages):
                    continue
                if not _templated(image, dockerfile, repo_path):
                    images.add(image)
        except Exception as e:
            logger.debug(
                f"Skipping Dockerfile {dockerfile}: failed to parse - {type(e).__name__}: {e}"
            )
            continue  # Skip files that can't be read

    # Pattern 2: docker-compose.yml images
    # services:
    #   web:
    #     image: nginx:latest
    for compose_file in repo_path.rglob("docker-compose*.y*ml"):
        try:
            with open(compose_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "services" in data:
                services = data["services"]
                if isinstance(services, dict):
                    for service_name, service_config in services.items():
                        if (
                            isinstance(service_config, dict)
                            and "image" in service_config
                        ):
                            image = str(service_config["image"])
                            if (
                                image
                                and image.lower() != "scratch"
                                and not _templated(image, compose_file, repo_path)
                            ):
                                images.add(image)
        except Exception as e:
            logger.debug(
                f"Skipping docker-compose file {compose_file}: failed to parse - {type(e).__name__}: {e}"
            )
            continue  # Skip files that can't be parsed

    # Pattern 3: Kubernetes manifests
    # spec:
    #   containers:
    #   - image: nginx:latest
    for k8s_file in list(repo_path.rglob("*.k8s.yaml")) + list(
        repo_path.rglob("*.k8s.yml")
    ):
        try:
            with open(k8s_file, encoding="utf-8") as f:
                # K8s manifests can contain multiple documents
                docs = yaml.safe_load_all(f)
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    # Look for containers in pod specs
                    spec = doc.get("spec", {})
                    if isinstance(spec, dict):
                        containers = spec.get("containers", [])
                        if isinstance(containers, list):
                            for container in containers:
                                if isinstance(container, dict) and "image" in container:
                                    image = str(container["image"])
                                    if (
                                        image
                                        and image.lower() != "scratch"
                                        and not _templated(image, k8s_file, repo_path)
                                    ):
                                        images.add(image)
        except Exception as e:
            logger.debug(
                f"Skipping Kubernetes manifest {k8s_file}: failed to parse - {type(e).__name__}: {e}"
            )
            continue  # Skip files that can't be parsed

    return images


def _scan_named_images(
    clone_path: Path,
    full_path: str,
    gitlab_folder: str,
    images: DiscoveredImages,
    *,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    find_tool_func: Callable[[str], str | None] | None,
    write_stub_func: Callable[[str, Path], None] | None,
) -> None:
    """Scan each image the repository names as an image target of its own,
    as `--image` would: every requested tool, and a tool that reads no image
    skipped (#1311). A reference this scan already scans (an `--image`,
    another GitLab target) is not scanned twice.

    Past the repository's scan, whatever fails here is the images' own. The
    repository's outputs are already where the report reads them, so its rows
    stand; a failure here used to relabel it `failed-before-tools`. And every
    image this job claimed gets rows, since no other target will scan it.
    """
    mine: list[str] = []
    try:
        for image in sorted(_discover_container_images(clone_path)):
            covering = images.claim(image, full_path)
            if covering is None:
                mine.append(image)
            else:
                logger.info(
                    "%s names %s, which this scan already scans for %s: "
                    "not scanned again",
                    full_path,
                    image,
                    covering,
                )
        # Each folder is unique in the scan: its GitLab target's folder is,
        # and two references in one repository can sanitize alike (#1312).
        folders = unique_names(
            [f"{gitlab_folder}__{_sanitize_path_component(i)}" for i in mine]
        )
        for image, folder in zip(mine, folders, strict=True):
            started = time.perf_counter()
            if not validate_container_image(image):
                # It never reaches a tool's command line, where it would be
                # their first argument (`--file=<path>` is a syft flag, and the
                # repository is not JMo's to trust), and it is not dropped: a
                # private registry with a port lands here too.
                logger.warning(
                    "%s names %r, which is not a container image reference "
                    "JMo passes to a scanner: recorded as a failed image target",
                    full_path,
                    image,
                )
                rows = _abandon(
                    images.images_dir / folder,
                    image,
                    "image",
                    tools,
                    started,
                    f"not a container image reference JMo passes to a scanner: {image}",
                )
            else:
                try:
                    # Created before scan_image resolves it. The orchestrator
                    # makes it up front only for `--image` targets, and on
                    # Windows a directory another job creates during
                    # `resolve()` can come back `\\?\`-prefixed, which
                    # scan_image's traversal check refuses (measured: 823 of
                    # 1500 racing resolves disagreed). Inside the `try`: an
                    # image this job claimed gets its rows whatever fails.
                    images.images_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                    _image, rows = scan_image(
                        image=image,
                        results_dir=images.images_dir,
                        tools=tools,
                        timeout=timeout,
                        retries=retries,
                        per_tool_config=per_tool_config,
                        allow_missing_tools=allow_missing_tools,
                        find_tool_func=find_tool_func,
                        write_stub_func=write_stub_func,
                        result_name=folder,
                    )
                except Exception as e:
                    # Still a row per tool, as the orchestrator gives a target
                    # whose job raised, so the image is counted as having
                    # produced nothing rather than vanishing.
                    logger.error(
                        f"Container image scan failed for {image} (named in {full_path}): {type(e).__name__}: {e}",
                        exc_info=True,
                    )
                    rows = rows_without_running(
                        tools,
                        "image",
                        Reason.SCANNER_ERROR,
                        detail=f"{type(e).__name__}: {e}",
                    )
            images.add(full_path, image, rows)
    except Exception as e:
        logger.error(
            f"Container image discovery failed for {full_path}: {type(e).__name__}: {e}",
            exc_info=True,
        )
        recorded = {image for image, _rows in images.found_in(full_path)}
        for image in mine:
            if image not in recorded:
                images.add(
                    full_path,
                    image,
                    rows_without_running(
                        tools,
                        "image",
                        Reason.SCANNER_ERROR,
                        detail=f"{type(e).__name__}: {e}",
                    ),
                )


def scan_gitlab_repo(
    gitlab_info: dict[str, str],
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    find_tool_func: Callable[[str], str | None] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
    images: DiscoveredImages | None = None,
) -> tuple[str, TargetRows]:
    """
    Scan a GitLab repo by cloning it and running the full repository scanner,
    then scan each image it names as an image target of its own.

    Args:
        gitlab_info: Dict with keys: full_path, url, token, repo, group
        results_dir: `<results>/individual-gitlab`
        tools: List of tools to run, on the repository and on each image
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        find_tool_func: Optional tool resolver (for testing)
        write_stub_func: Optional function to write stub files (for testing)
        images: The scan's discovered images, and where they go: this job
            claims each one it names and records its rows there, for the
            orchestrator to report as an image target (#1311); one another
            target already claimed is not scanned again. Without one, the
            repository alone is scanned.

    Returns:
        (full_path, rows by tool) for the repository
    """
    started = time.perf_counter()
    full_path = gitlab_info["full_path"]
    gitlab_url = gitlab_info["url"]
    # `or`, not a .get default: the dict always carries "token" (None without
    # --gitlab-token), so the default never applied and GITLAB_TOKEN, which
    # --help offers as the alternative, was never read.
    gitlab_token = gitlab_info.get("token") or os.getenv("GITLAB_TOKEN")

    if not gitlab_token:
        # No token - cannot clone, return failure for all tools
        logger.error(
            f"GitLab token missing for {full_path}: set GITLAB_TOKEN env var or pass --gitlab-token"
        )
        statuses = _record_abandoned_target(
            results_dir, full_path, tools, started, "no GitLab token"
        )
        return full_path, statuses

    # Create secure temporary directory for clone (0o700 permissions, auto-cleanup)
    # The context manager ensures cleanup even on exceptions
    with secure_temp_dir(prefix="jmo-gitlab-") as temp_dir:
        try:
            # Construct clone URL WITHOUT embedded token (security: avoid token in process list)
            clone_url = gitlab_url.rstrip("/")
            if not clone_url.startswith("http"):
                clone_url = "https://gitlab.com"

            repo_url = f"{clone_url}/{full_path}.git"
            clone_path = temp_dir / full_path.split("/")[-1]

            # Clone the repository (shallow clone for speed)
            clone_cmd = [
                "git",
                "clone",
                "--depth",
                "1",  # Shallow clone
                "--single-branch",  # Only default branch
                "--quiet",
                repo_url,
                str(clone_path),
            ]

            # Create askpass script for secure credential passing
            # This avoids exposing token in process list or command line
            askpass_script = temp_dir / "git-askpass.py"
            askpass_script.write_text(
                '#!/usr/bin/env python3\nimport sys\nif "password" in sys.argv[1].lower():\n    print(sys.argv[2])\nelse:\n    print("oauth2")\n',
                encoding="utf-8",
            )
            askpass_script.chmod(0o700)

            # Set up environment for secure git authentication
            clone_env = os.environ.copy()
            clone_env["GIT_ASKPASS"] = str(askpass_script)
            clone_env["GIT_TERMINAL_PROMPT"] = "0"
            # Pass token as argument to askpass script (not visible in process list)
            clone_env["GIT_ASKPASS_TOKEN"] = gitlab_token

            # Update askpass script to read token from environment
            askpass_script.write_text(
                '#!/usr/bin/env python3\nimport os, sys\nif "password" in sys.argv[1].lower():\n    print(os.environ.get("GIT_ASKPASS_TOKEN", ""))\nelse:\n    print("oauth2")\n',
                encoding="utf-8",
            )

            # Run clone with timeout using secure credential passing
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                timeout=timeout,
                check=False,
                env=clone_env,
            )

            if result.returncode != 0:
                # Clone failed - return failure for all tools
                # Sanitize stderr to prevent leaking tokens/credentials in logs
                stderr_raw = result.stderr.decode("utf-8", errors="ignore").strip()
                stderr_msg = sanitize_subprocess_output(stderr_raw, max_length=200)
                logger.error(
                    f"GitLab clone failed for {full_path}: git returned {result.returncode} - {stderr_msg}"
                )
                statuses = _record_abandoned_target(
                    results_dir,
                    full_path,
                    tools,
                    started,
                    f"git clone returned {result.returncode}: {stderr_msg}",
                )
                return full_path, statuses

            # The results go straight to the target's folder, so the
            # temporary directory holds the clone and nothing it writes: a
            # project named `results` was cloned into the directory its scan
            # then wrote to, and every tool read the others' output (#1364).
            safe_name = _gitlab_out_dir(results_dir, full_path).name
            _name, statuses = scan_repository(
                repo=clone_path,
                results_dir=results_dir,
                tools=tools,
                timeout=timeout,
                retries=retries,
                per_tool_config=per_tool_config,
                allow_missing_tools=allow_missing_tools,
                write_stub_func=write_stub_func,
                find_tool_func=find_tool_func,
                result_name=safe_name,
                target_type="gitlab",
                label=full_path,
            )

            if images is not None:
                _scan_named_images(
                    clone_path,
                    full_path,
                    safe_name,
                    images,
                    tools=tools,
                    timeout=timeout,
                    retries=retries,
                    per_tool_config=per_tool_config,
                    allow_missing_tools=allow_missing_tools,
                    find_tool_func=find_tool_func,
                    write_stub_func=write_stub_func,
                )
            return full_path, statuses

        except subprocess.TimeoutExpired:
            # Clone timeout - return failure for all tools
            logger.error(
                f"GitLab clone timeout for {full_path}: git clone exceeded {timeout}s timeout",
                exc_info=True,
            )
            statuses = _record_abandoned_target(
                results_dir,
                full_path,
                tools,
                started,
                f"git clone exceeded the {timeout}s timeout",
            )
            return full_path, statuses
        except Exception as e:
            # Any other error - return failure for all tools
            logger.error(
                f"GitLab scan failed for {full_path}: {type(e).__name__}: {e}",
                exc_info=True,
            )
            statuses = _record_abandoned_target(
                results_dir,
                full_path,
                tools,
                started,
                f"{type(e).__name__}: {e}",
            )
            return full_path, statuses
        # Note: No finally block needed - secure_temp_dir context manager handles cleanup
