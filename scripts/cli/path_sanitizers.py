#!/usr/bin/env python3
"""
Path sanitization utilities for preventing directory traversal attacks.

Security: MEDIUM-001 (Path Traversal Prevention)
These functions prevent malicious path inputs from escaping the results directory.
All user-controlled path components must pass through _sanitize_path_component().
"""

from __future__ import annotations

import re
from pathlib import Path


def _sanitize_path_component(name: str) -> str:
    """
    Sanitize a path component to prevent traversal.

    Security: Removes path separators, traversal sequences, and hidden files.
    Used for all user-controlled directory names in results paths.

    Args:
        name: User-controlled path component (e.g., repo.name, image name)

    Returns:
        Sanitized path component safe for filesystem operations

    Examples:
        >>> _sanitize_path_component("../../../etc/passwd")
        '___etc_passwd'
        >>> _sanitize_path_component("normal-repo")
        'normal-repo'
        >>> _sanitize_path_component("..hidden")
        'hidden'
        >>> _sanitize_path_component("nginx:latest")
        'nginx_latest'

    Related: MEDIUM-001 (Path Traversal Prevention)
    """
    # Remove path separators (works cross-platform)
    safe = name.replace("/", "_").replace("\\", "_")

    # Remove traversal sequences
    safe = safe.replace("..", "_")

    # Remove leading dots (hidden files, relative paths)
    safe = safe.lstrip(".")

    # Ensure non-empty (fallback for edge cases)
    if not safe:
        safe = "unknown"

    # Remove other potentially dangerous characters
    # Windows: < > : " | ? *
    # Common escapes: null bytes, control characters
    safe = re.sub(r'[<>:"|?*\x00-\x1f]', "_", safe)

    return safe


def _validate_output_path(base_dir: Path, output_dir: Path) -> Path:
    """
    Validate that output_dir is within base_dir (prevent traversal).

    Security: Defense-in-depth validation to catch sanitization bypasses.
    Raises ValueError if path escapes intended directory.

    Args:
        base_dir: Intended parent directory
        output_dir: Output directory to validate

    Returns:
        Resolved output_dir path

    Raises:
        ValueError: If output_dir is outside base_dir

    Examples:
        >>> base = Path("/tmp/results")
        >>> _validate_output_path(base, base / "repo1")  # OK
        PosixPath('/tmp/results/repo1')

        >>> _validate_output_path(base, base / ".." / "etc")  # BLOCKS
        ValueError: Path traversal detected: /tmp/etc outside /tmp/results

    Related: MEDIUM-001 (Defense-in-Depth Validation)
    """
    base_resolved = base_dir.resolve()
    output_resolved = output_dir.resolve()

    try:
        # Verify output is relative to base (throws ValueError if not)
        output_resolved.relative_to(base_resolved)
        return output_resolved
    except ValueError as e:
        raise ValueError(
            f"Path traversal detected: {output_dir} outside {base_dir}"
        ) from e
