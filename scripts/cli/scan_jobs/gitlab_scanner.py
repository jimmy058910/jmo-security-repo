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
3. When a requested tool reads an image, discover the images its Dockerfiles
   (`FROM`), `docker-compose*.yml` files and `*.k8s.yaml` Pods (`image:`)
   name.
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
from collections.abc import Callable, Iterator, Mapping
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
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    DOCKERFILE_PATTERNS,
    is_dockerfile,
)
from scripts.core.validation import (
    image_reference_problem,
    sanitize_subprocess_output,
)

from ..path_sanitizers import _sanitize_path_component
from ..scan_orchestrator import unique_names
from .image_scanner import scan_image
from .repository_scanner import scan_repository
from .tool_loop import collect_files, rows_without_running

logger = logging.getLogger(__name__)

# `FROM [--platform=<p>] <image> [AS <stage>]`: any flags come first. Matched
# against a whole instruction (`_instructions`), never a physical line.
_FROM_LINE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE
)

# A parser directive (`# escape=``), read only before anything else, and only
# a directive Docker knows: an unknown one is a comment, and ends them.
_DIRECTIVE = re.compile(r"\s*#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$")
_DIRECTIVES = frozenset({"syntax", "escape", "check"})
# A heredoc's opening word (`<<EOF`, `<<-EOF`, `<<"EOF"`), as a word of its
# own: `<<<` is a here-string. Its body runs to the line holding the word
# alone, leading tabs stripped first for `<<-`.
_HEREDOC = re.compile(r"(?:^|\s)\d*<<(-?)([\"']?)([^\s\"'<]+)\2(?=\s|$)")
_HEREDOC_INSTRUCTIONS = frozenset({"run", "copy", "add"})

# Docker's own grammar for an image reference (distribution's `reference`
# package): what a `FROM` or an `image:` must be for Docker to pull it. A
# registry with a port is one; `{{`, `\` and `debian:%%SUITE%%` are not.
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_REFERENCE = re.compile(
    rf"(?:{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*(?::[0-9]+)?/)?"
    rf"{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*"
    r"(?::\w[\w.-]{0,127})?"
    r"(?:@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,})?",
    re.ASCII,
)


def _instructions(text: str) -> Iterator[tuple[int, str]]:
    """Each instruction of a Dockerfile, with the line it starts on, read as
    Docker reads one.

    A `FROM` matched against physical lines read a line that is no
    instruction: `FROM \\` continued on the next line gave the image `\\`,
    Python in a BuildKit heredoc (`COPY <<EOF app.py`) or in a continued
    `RUN python -c` gave `flask` and `os` (measured). So continuations are
    joined, with the escape character a `# escape=` directive sets, a comment
    or blank line inside one is dropped, and a heredoc's body is skipped.
    """
    lines = text.splitlines()
    escape = "\\"
    at = 0
    while at < len(lines):
        directive = _DIRECTIVE.match(lines[at])
        if not directive or directive.group(1).lower() not in _DIRECTIVES:
            break
        if directive.group(1).lower() == "escape" and directive.group(2) in "\\`":
            escape = directive.group(2)
        at += 1
    continued = re.compile(re.escape(escape) + r"[ \t]*$")
    while at < len(lines):
        start, line = at + 1, lines[at].strip()
        at += 1
        if not line or line.startswith("#"):
            continue
        while continued.search(line):
            line = continued.sub("", line)
            while at < len(lines) and (
                not lines[at].strip() or lines[at].lstrip().startswith("#")
            ):
                at += 1
            if at == len(lines):
                break
            line += lines[at]
            at += 1
        yield start, line
        if line.split(None, 1)[0].lower() in _HEREDOC_INSTRUCTIONS:
            for chomp, _quote, word in _HEREDOC.findall(line):
                while at < len(lines):
                    body = lines[at].lstrip("\t") if chomp else lines[at]
                    at += 1
                    if body == word:
                        break


class _Located(str):
    """A YAML string that knows its line, for a WARNING to name it."""

    line: int | None = None


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_located(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> _Located:
    value = _Located(loader.construct_scalar(node))
    value.line = node.start_mark.line + 1
    return value


_LineLoader.add_constructor("tag:yaml.org,2002:str", _construct_located)


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


def _scannable(image: str, where: str) -> bool:
    """Whether a reference a repository file names is an image to scan.

    `scratch` is no image. One set by a build argument or a variable (`$BASE`,
    `${TAG}`) names none until a build supplies it, and is named at INFO. One
    that is not an image reference in Docker's own grammar (`{{`,
    `debian:%%SUITE%%`) could not be pulled by Docker either: it is named at
    WARNING, file and line, and never becomes an image target, which would
    fail and make the scan exit 1."""
    if not image or image.lower() == "scratch":
        return False
    if "$" in image:
        logger.info(
            "%s: %s is set by a build argument or variable, so it is not scanned",
            where,
            image,
        )
        return False
    if not _REFERENCE.fullmatch(image):
        logger.warning(
            "%s names %r, which is not an image reference: not scanned", where, image
        )
        return False
    return True


def _where(source: Path, repo_path: Path, line: int | None, label: str) -> str:
    """`<label>: <file>:<line>`, the file relative to the repository."""
    place = source.relative_to(repo_path).as_posix()
    if line is not None:
        place = f"{place}:{line}"
    return f"{label}: {place}" if label else place


def _image_value(
    value: object, source: Path, repo_path: Path, label: str
) -> tuple[str, str]:
    """An `image:` value and where it is."""
    line = value.line if isinstance(value, _Located) else None
    return str(value), _where(source, repo_path, line, label)


def _discover_container_images(repo_path: Path, label: str = "") -> set[str]:
    """
    Discover container images referenced in repository files.

    Reads:
    - each Dockerfile's FROM instructions (`is_dockerfile`)
    - each `docker-compose*.yml`/`.yaml` service's `image:`, unless the service
      has `build:`
    - each `*.k8s.yaml`/`*.k8s.yml` document's `spec.containers` images (a
      Pod's; not `initContainers`, nor a Deployment's template)

    Args:
        repo_path: Path to cloned repository
        label: The GitLab target, for a log line to name

    Returns:
        Set of discovered image references (e.g., 'nginx:latest',
        'python:3.11-slim'), as the repository spells them. Each is an image
        reference in Docker's grammar; the job still refuses one JMo does not
        pass to a scanner (a registry with a port) before any tool sees it.
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
            # `utf-8-sig`: a byte-order mark hid the first FROM (measured).
            content = dockerfile.read_text(encoding="utf-8-sig", errors="ignore")
            stages: set[str] = set()
            for line, instruction in _instructions(content):
                match = _FROM_LINE.match(instruction)
                if not match:
                    continue
                image, stage = match.group(1), match.group(2)
                if stage:
                    # A build stage's base is skipped, as it always was, and
                    # its name is a stage, not an image, when a later FROM
                    # names it.
                    stages.add(stage.lower())
                    continue
                if image.lower() in stages:
                    continue
                if _scannable(image, _where(dockerfile, repo_path, line, label)):
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
                data = yaml.load(f, Loader=_LineLoader)  # nosec B506 - a SafeLoader subclass
            if isinstance(data, dict) and "services" in data:
                services = data["services"]
                if isinstance(services, dict):
                    for service_name, service_config in services.items():
                        # With `build:`, compose builds the image and tags it
                        # `image:`: a name for its own build, not one to pull.
                        # Pulled, it failed, or scanned a stranger's image of
                        # that name (measured: syft pulled it, exit 1).
                        if (
                            isinstance(service_config, dict)
                            and "image" in service_config
                            and "build" not in service_config
                        ):
                            image, where = _image_value(
                                service_config["image"], compose_file, repo_path, label
                            )
                            if _scannable(image, where):
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
                docs = yaml.load_all(f, Loader=_LineLoader)  # nosec B506 - a SafeLoader subclass
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
                                    image, where = _image_value(
                                        container["image"], k8s_file, repo_path, label
                                    )
                                    if _scannable(image, where):
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

    Only when a requested tool reads an image. Otherwise each image target
    would have every row `skipped:not for this target type`, so it counted as
    having produced nothing and failed a scan that asked for no image
    (measured: `--tools hadolint` exited 1); one line says what was found.

    Past the repository's scan, whatever fails here is the images' own. The
    repository's outputs are already where the report reads them, so its rows
    stand; a failure here used to relabel it `failed-before-tools`. And every
    image this job claimed gets rows, since no other target will scan it.
    """
    mine: list[str] = []
    try:
        found = sorted(_discover_container_images(clone_path, full_path))
        if not any("image" in DESCRIPTORS[tool].invocations for tool in tools):
            if found:
                logger.info(
                    "%s names %d image(s), and no requested tool reads an "
                    "image: not scanned",
                    full_path,
                    len(found),
                )
            return
        for image in found:
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
            # Checked quietly: the WARNING below is the one line it gets, where
            # the validator would add an ERROR for an outcome that is not one.
            problem = image_reference_problem(image)
            if problem is not None:
                # An image reference (discovery keeps no other) that never
                # reaches a tool's command line, where it would be their first
                # argument, and it is not dropped: a private registry with a
                # port lands here.
                logger.warning(
                    "%s names an image reference JMo does not pass to a "
                    "scanner (%s): recorded as a failed image target",
                    full_path,
                    problem,
                )
                rows = _abandon(
                    images.images_dir / folder,
                    image,
                    "image",
                    tools,
                    started,
                    f"JMo does not pass this reference to a scanner: {problem}",
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
