"""
GitLab Repository Scanner

Scans GitLab repositories by cloning them and running the full repository scanner.

Architecture (v0.6.1+):
1. Clone GitLab repo to temporary directory
2. Run scan_repository() with all configured tools
3. Discover container images referenced in Dockerfiles, docker-compose.yml, K8s manifests
4. Run scan_image() for each discovered image
5. Move results to individual-gitlab/<group>_<repo>/
6. Clean up temporary clone

This provides GitLab repos with the same tool coverage as local repositories:
- TruffleHog: Verified secrets scanning
- Nosey Parker: Deep secrets detection
- Semgrep: Static analysis (SAST)
- Bandit: Python security analysis
- Syft: SBOM generation
- Trivy: Vulnerability and secrets scanning
- Checkov: IaC policy checks
- Hadolint: Dockerfile linting
- ZAP: Web vulnerability scanning
- Falco: Runtime security monitoring
- AFL++: Coverage-guided fuzzing

Plus container image discovery and scanning:
- Scans Dockerfile, docker-compose.yml, *.k8s.yaml for image references
- Automatically scans discovered images with trivy + syft
- Stores results in individual-images/<image>/ directory

Integrates with repository_scanner and image_scanner for comprehensive coverage.
"""

import logging
import os
import re
import subprocess
import shutil
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Tuple, Set

from .repository_scanner import scan_repository
from .image_scanner import scan_image

logger = logging.getLogger(__name__)


def _discover_container_images(repo_path: Path) -> Set[str]:
    """
    Discover container images referenced in repository files.

    Scans for:
    - Dockerfile FROM lines
    - docker-compose.yml service images
    - Kubernetes manifests (*.k8s.yaml, *.k8s.yml) image references

    Args:
        repo_path: Path to cloned repository

    Returns:
        Set of discovered image names (e.g., 'nginx:latest', 'python:3.11-slim')
    """
    images: Set[str] = set()

    # Pattern 1: Dockerfile FROM lines
    # FROM nginx:latest
    # FROM python:3.11-slim AS builder
    dockerfile_pattern = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE)
    for dockerfile in repo_path.rglob("*Dockerfile*"):
        try:
            content = dockerfile.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                match = dockerfile_pattern.match(line)
                if match:
                    image = match.group(1)
                    # Skip build stages (AS keyword)
                    if " AS " not in line.upper():
                        # Skip scratch images
                        if image.lower() != "scratch":
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
            with open(compose_file, "r", encoding="utf-8") as f:
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
                            if image and image.lower() != "scratch":
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
            with open(k8s_file, "r", encoding="utf-8") as f:
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
                                    if image and image.lower() != "scratch":
                                        images.add(image)
        except Exception as e:
            logger.debug(
                f"Skipping Kubernetes manifest {k8s_file}: failed to parse - {type(e).__name__}: {e}"
            )
            continue  # Skip files that can't be parsed

    return images


def scan_gitlab_repo(
    gitlab_info: Dict[str, str],
    results_dir: Path,
    tools: List[str],
    timeout: int,
    retries: int,
    per_tool_config: Dict,
    allow_missing_tools: bool,
    tool_exists_func=None,
    write_stub_func=None,
) -> Tuple[str, Dict[str, bool]]:
    """
    Scan a GitLab repo by cloning it and running the full repository scanner.

    Args:
        gitlab_info: Dict with keys: full_path, url, token, repo, group
        results_dir: Base results directory
        tools: List of tools to run (all repository tools supported)
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check tool existence (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (full_path, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    full_path = gitlab_info["full_path"]
    gitlab_url = gitlab_info["url"]
    gitlab_token = gitlab_info.get("token", os.getenv("GITLAB_TOKEN"))

    if not gitlab_token:
        # No token - cannot clone, return failure for all tools
        logger.error(
            f"GitLab token missing for {full_path}: set GITLAB_TOKEN env var or pass --gitlab-token"
        )
        statuses = {tool: False for tool in tools}
        return full_path, statuses

    # Create temporary directory for clone
    temp_dir = Path(tempfile.mkdtemp(prefix="jmo-gitlab-"))

    try:
        # Construct clone URL with embedded token for authentication
        # Format: https://oauth2:TOKEN@gitlab.com/group/repo.git
        clone_url = gitlab_url.rstrip("/")
        if not clone_url.startswith("http"):
            clone_url = "https://gitlab.com"

        # Build authenticated URL
        if clone_url.startswith("https://"):
            auth_url = clone_url.replace("https://", f"https://oauth2:{gitlab_token}@")
        elif clone_url.startswith("http://"):
            auth_url = clone_url.replace("http://", f"http://oauth2:{gitlab_token}@")
        else:
            auth_url = f"https://oauth2:{gitlab_token}@gitlab.com"

        repo_url = f"{auth_url}/{full_path}.git"
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

        # Run clone with timeout
        result = subprocess.run(
            clone_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            # Clone failed - return failure for all tools
            stderr_msg = result.stderr.decode("utf-8", errors="ignore").strip()
            logger.error(
                f"GitLab clone failed for {full_path}: git returned {result.returncode} - {stderr_msg}"
            )
            statuses = {tool: False for tool in tools}
            return full_path, statuses

        # Create temporary results directory
        temp_results = temp_dir / "results"
        temp_results.mkdir(parents=True, exist_ok=True)

        # Run full repository scanner on cloned repo
        repo_name, statuses = scan_repository(
            repo=clone_path,
            results_dir=temp_results,
            tools=tools,
            timeout=timeout,
            retries=retries,
            per_tool_config=per_tool_config,
            allow_missing_tools=allow_missing_tools,
            tool_exists_func=tool_exists_func,
            write_stub_func=write_stub_func,
        )

        # Discover container images in cloned repo
        discovered_images = _discover_container_images(clone_path)

        # Scan discovered container images (if trivy or syft in tools)
        image_tools = [t for t in tools if t in ["trivy", "syft"]]
        if discovered_images and image_tools:
            # Create temp directory for image results
            temp_image_results = temp_dir / "image-results"
            temp_image_results.mkdir(parents=True, exist_ok=True)

            for image in discovered_images:
                try:
                    _, image_statuses = scan_image(
                        image=image,
                        results_dir=temp_image_results,
                        tools=image_tools,
                        timeout=timeout,
                        retries=retries,
                        per_tool_config=per_tool_config,
                        allow_missing_tools=allow_missing_tools,
                        tool_exists_func=tool_exists_func,
                        write_stub_func=write_stub_func,
                    )
                    # Merge image statuses into main statuses
                    for tool, status in image_statuses.items():
                        if tool not in statuses or not statuses[tool]:
                            # Only update if tool wasn't already successful
                            statuses[f"image:{image}:{tool}"] = status
                except Exception as e:
                    # Image scan failed - continue with other images
                    logger.error(
                        f"Container image scan failed for {image} (discovered in {full_path}): {type(e).__name__}: {e}",
                        exc_info=True,
                    )
                    continue

        # Move results from temp location to final GitLab results directory
        safe_name = full_path.replace("/", "_").replace("*", "all")
        final_out_dir = results_dir / "individual-gitlab" / safe_name
        final_out_dir.mkdir(parents=True, exist_ok=True)

        # Copy all tool output files from temp to final location
        temp_repo_results = temp_results / repo_name
        if temp_repo_results.exists():
            for tool_file in temp_repo_results.glob("*.json"):
                shutil.copy2(tool_file, final_out_dir / tool_file.name)

        return full_path, statuses

    except subprocess.TimeoutExpired:
        # Clone timeout - return failure for all tools
        logger.error(
            f"GitLab clone timeout for {full_path}: git clone exceeded {timeout}s timeout",
            exc_info=True,
        )
        statuses = {tool: False for tool in tools}
        return full_path, statuses
    except Exception as e:
        # Any other error - return failure for all tools
        logger.error(
            f"GitLab scan failed for {full_path}: {type(e).__name__}: {e}",
            exc_info=True,
        )
        statuses = {tool: False for tool in tools}
        return full_path, statuses
    finally:
        # Always clean up temporary directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.debug(
                f"Failed to clean up temp directory {temp_dir}: {type(e).__name__}: {e}"
            )
