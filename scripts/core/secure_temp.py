"""Secure temporary file handling utilities for JMo Security.

Provides context managers for creating temporary files and directories
with proper security controls:
- Restrictive permissions (owner-only: 0o700 for dirs, 0o600 for files)
- Automatic cleanup on context exit (even on exceptions)
- Platform-appropriate security settings

Usage:
    >>> from scripts.core.secure_temp import secure_temp_dir, secure_temp_file
    >>>
    >>> with secure_temp_dir(prefix='jmo_scan_') as temp_path:
    ...     # temp_path is a Path with 0o700 permissions
    ...     (temp_path / 'results.json').write_text('{}')
    >>> # Directory automatically cleaned up
    >>>
    >>> with secure_temp_file(suffix='.json') as temp_path:
    ...     temp_path.write_text('{"findings": []}')
    >>> # File automatically deleted

Security Notes:
    - All temp files/dirs are owner-readable/writable only
    - Cleanup is guaranteed via context manager __exit__
    - Designed to prevent information leakage on shared systems

See Also:
    - OWASP: Insecure Temporary File (CWE-377)
    - Python tempfile module documentation
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Owner-only permissions for security
DIR_PERMISSIONS = stat.S_IRWXU  # 0o700 - rwx------
FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600 - rw-------


@contextmanager
def secure_temp_dir(
    prefix: str = "jmo_",
    suffix: str = "",
    parent_dir: Path | str | None = None,
) -> Iterator[Path]:
    """Create a secure temporary directory with owner-only permissions.

    The directory is created with 0o700 permissions (owner read/write/execute only)
    and is automatically deleted when the context manager exits, even if an
    exception occurs.

    Args:
        prefix: Prefix for the directory name (default: 'jmo_')
        suffix: Suffix for the directory name (default: '')
        parent_dir: Parent directory for temp dir. If None, uses system default.

    Yields:
        Path: Path object pointing to the secure temporary directory

    Raises:
        OSError: If directory creation or permission setting fails

    Example:
        >>> with secure_temp_dir(prefix='scan_') as temp_path:
        ...     results_file = temp_path / 'results.json'
        ...     results_file.write_text('{}')
        >>> # temp_path is now deleted
    """
    temp_dir = None
    try:
        # Create temp directory
        temp_dir = Path(
            tempfile.mkdtemp(
                prefix=prefix,
                suffix=suffix,
                dir=str(parent_dir) if parent_dir else None,
            )
        )

        # Immediately restrict permissions to owner-only
        os.chmod(temp_dir, DIR_PERMISSIONS)
        logger.debug(f"Created secure temp directory: {temp_dir}")

        yield temp_dir

    finally:
        # Always attempt cleanup
        if temp_dir is not None and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up secure temp directory: {temp_dir}")
            except Exception as e:
                # Log but don't raise - cleanup failure shouldn't mask original errors
                logger.warning(
                    f"Failed to clean up temp directory {temp_dir}: {type(e).__name__}: {e}"
                )


@contextmanager
def secure_temp_file(
    prefix: str = "jmo_",
    suffix: str = "",
    parent_dir: Path | str | None = None,
    mode: str = "w",
    encoding: str = "utf-8",
) -> Iterator[Path]:
    """Create a secure temporary file with owner-only permissions.

    The file is created with 0o600 permissions (owner read/write only)
    and is automatically deleted when the context manager exits, even if an
    exception occurs.

    Args:
        prefix: Prefix for the file name (default: 'jmo_')
        suffix: Suffix for the file name (default: '')
        parent_dir: Parent directory for temp file. If None, uses system default.
        mode: File mode (unused, kept for API compatibility)
        encoding: File encoding (unused, kept for API compatibility)

    Yields:
        Path: Path object pointing to the secure temporary file

    Raises:
        OSError: If file creation or permission setting fails

    Example:
        >>> with secure_temp_file(suffix='.json') as temp_path:
        ...     temp_path.write_text('{"data": "sensitive"}')
        ...     # Use temp_path...
        >>> # temp_path is now deleted
    """
    fd = None
    temp_path = None
    try:
        # Create temp file with secure permissions
        fd, temp_file = tempfile.mkstemp(
            prefix=prefix,
            suffix=suffix,
            dir=str(parent_dir) if parent_dir else None,
        )
        temp_path = Path(temp_file)

        # Restrict permissions to owner-only
        os.chmod(temp_path, FILE_PERMISSIONS)

        # Close the file descriptor - caller will use Path methods
        os.close(fd)
        fd = None

        logger.debug(f"Created secure temp file: {temp_path}")

        yield temp_path

    finally:
        # Close fd if still open (shouldn't happen normally)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

        # Always attempt cleanup
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
                logger.debug(f"Cleaned up secure temp file: {temp_path}")
            except Exception as e:
                # Log but don't raise - cleanup failure shouldn't mask original errors
                logger.warning(
                    f"Failed to clean up temp file {temp_path}: {type(e).__name__}: {e}"
                )


def get_temp_dir_permissions(path: Path) -> int:
    """Get the permissions of a path as an octal integer.

    Utility function for testing and verification.

    Args:
        path: Path to check permissions of

    Returns:
        int: Permission bits (e.g., 0o700, 0o600)
    """
    return stat.S_IMODE(path.stat().st_mode)


def is_secure_permissions(path: Path, is_directory: bool = False) -> bool:
    """Check if a path has secure (owner-only) permissions.

    Verifies that the path has the expected restrictive permissions:
    - Directories: 0o700 (rwx------)
    - Files: 0o600 (rw-------)

    Args:
        path: Path to check
        is_directory: Whether to check as directory (True) or file (False)

    Returns:
        bool: True if permissions are secure, False otherwise
    """
    actual_perms = get_temp_dir_permissions(path)
    expected_perms = DIR_PERMISSIONS if is_directory else FILE_PERMISSIONS
    return actual_perms == expected_perms
