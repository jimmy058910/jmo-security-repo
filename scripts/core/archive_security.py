"""
Archive extraction security utilities for JMo Security.

Provides safe extraction functions that prevent path traversal attacks
(CWE-22, Zip Slip) by validating all archive member paths before extraction.

These functions are critical security controls and should be used for all
archive extraction operations in the codebase.
"""

from __future__ import annotations

import logging
import tarfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _is_safe_path(base_dir: Path, member_path: str) -> bool:
    """Check if extracted path stays within base directory.

    Prevents path traversal attacks (CWE-22, Zip Slip) by ensuring
    the resolved path doesn't escape the extraction directory.

    Args:
        base_dir: The target extraction directory
        member_path: Path from the archive member

    Returns:
        True if path is safe, False if it would escape base_dir
    """
    # Resolve the full path (handles .., symlinks, etc.)
    target_path = (base_dir / member_path).resolve()

    # Ensure it's still under base_dir
    try:
        target_path.relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def safe_tar_extract(tar: tarfile.TarFile, extract_dir: Path) -> None:
    """Safely extract tarfile, filtering dangerous members.

    Security: Validates each member path to prevent:
    - Path traversal via ../ sequences (CWE-22)
    - Absolute paths escaping extraction directory
    - Symlink attacks

    Args:
        tar: Open tarfile object
        extract_dir: Directory to extract to

    Raises:
        ValueError: If archive contains malicious paths
    """
    for member in tar.getmembers():
        # Skip dangerous member types
        if member.islnk() or member.issym():
            # Check symlink target is safe
            if member.linkname and not _is_safe_path(extract_dir, member.linkname):
                logger.warning(
                    f"Skipping potentially unsafe symlink: {member.name} -> {member.linkname}"
                )
                continue

        # Check the member path itself
        if not _is_safe_path(extract_dir, member.name):
            raise ValueError(f"Archive contains path traversal attempt: {member.name}")

    # All members validated above, extract with data filter (safest option)
    tar.extractall(extract_dir, filter="data")  # nosec B202 - paths validated above


def safe_zip_extract(zip_ref: zipfile.ZipFile, extract_dir: Path) -> None:
    """Safely extract zipfile, filtering dangerous members.

    Security: Validates each member path to prevent:
    - Path traversal via ../ sequences (CWE-22, Zip Slip)
    - Absolute paths escaping extraction directory

    Args:
        zip_ref: Open ZipFile object
        extract_dir: Directory to extract to

    Raises:
        ValueError: If archive contains malicious paths
    """
    for member in zip_ref.namelist():
        if not _is_safe_path(extract_dir, member):
            raise ValueError(f"Archive contains path traversal attempt: {member}")

    # All members validated, safe to extract
    # Security: All member paths validated above via _is_safe_path()
    zip_ref.extractall(extract_dir)  # nosec B202 - paths validated above


__all__ = ["_is_safe_path", "safe_tar_extract", "safe_zip_extract"]
