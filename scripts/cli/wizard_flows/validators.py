"""Validation utilities for wizard workflows."""

from __future__ import annotations

import logging
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


def validate_path(path_str: str, must_exist: bool = True) -> Path | None:
    """
    Validate and expand a path.

    Args:
        path_str: Path string to validate
        must_exist: Whether path must exist

    Returns:
        Validated Path object or None if invalid
    """
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


def validate_url(url: str, timeout: int = 2) -> bool:
    """
    Validate URL is reachable with a quick HEAD request.

    Args:
        url: URL to validate
        timeout: Request timeout in seconds

    Returns:
        True if URL is reachable, False otherwise
    """
    try:
        # Quick HEAD request with configurable timeout
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec B310
            is_ok: bool = response.status == 200
            return is_ok
    except urllib.error.HTTPError as e:
        logger.debug(f"URL validation failed for {url}: HTTP {e.code} {e.reason}")
        return False
    except urllib.error.URLError as e:
        logger.debug(
            f"URL validation failed for {url}: {type(e.reason).__name__}: {e.reason}"
        )
        return False
    except TimeoutError:
        logger.debug(f"URL validation timeout for {url}: exceeded {timeout}s")
        return False
    except Exception as e:
        logger.debug(f"URL validation failed for {url}: {type(e).__name__}: {e}")
        return False


def detect_iac_type(file_path: Path) -> str:
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
        except OSError as e:
            logger.debug(
                f"Skipping IaC file {file_path}: I/O error - {type(e).__name__}: {e}"
            )
        except UnicodeDecodeError as e:
            logger.debug(
                f"Skipping IaC file {file_path}: encoding error at position {e.start}"
            )

    # Default to k8s-manifest for YAML files
    if suffix in (".yaml", ".yml"):
        return "k8s-manifest"

    # Default
    return "terraform"


def validate_k8s_context(context: str, timeout: int = 5) -> bool:
    """
    Validate Kubernetes context exists.

    Args:
        context: K8s context name or 'current' for current context
        timeout: Command timeout in seconds

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
            timeout=timeout,
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
        logger.debug(
            f"K8s context validation timeout for {context}: exceeded {timeout}s"
        )
        return False
    except FileNotFoundError:
        logger.debug("K8s context validation failed: kubectl not found")
        return False
    except Exception as e:
        logger.debug(
            f"K8s context validation failed for {context}: {type(e).__name__}: {e}"
        )
        return False


def detect_docker() -> bool:
    """
    Check if Docker is available.

    Returns:
        True if docker command exists, False otherwise
    """
    return shutil.which("docker") is not None


def check_docker_running(timeout: int = 5) -> bool:
    """
    Check if Docker daemon is running.

    Args:
        timeout: Command timeout in seconds

    Returns:
        True if Docker daemon is running, False otherwise
    """
    try:
        result = subprocess.run(  # nosec B603 - controlled command
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    except Exception as e:
        logger.debug(f"Docker daemon check failed: {type(e).__name__}: {e}")
        return False
