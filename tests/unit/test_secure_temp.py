"""Tests for secure temporary file handling utilities.

This module tests the secure_temp module which provides secure temporary
file and directory handling with proper permissions and cleanup.
"""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from scripts.core.secure_temp import (
    secure_temp_dir,
    secure_temp_file,
    get_temp_dir_permissions,
    is_secure_permissions,
    DIR_PERMISSIONS,
    FILE_PERMISSIONS,
)

if TYPE_CHECKING:
    pass

# Skip permission tests on Windows where Unix permission model doesn't apply
IS_WINDOWS = platform.system() == "Windows"


class TestSecureTempDir:
    """Tests for secure_temp_dir context manager."""

    def test_creates_directory(self) -> None:
        """Test that secure_temp_dir creates a directory."""
        with secure_temp_dir() as temp_path:
            assert temp_path.exists()
            assert temp_path.is_dir()

    def test_directory_cleaned_up_on_exit(self) -> None:
        """Test that directory is removed after context exits."""
        with secure_temp_dir() as temp_path:
            assert temp_path.exists()
            # Create a file inside to test recursive cleanup
            (temp_path / "test_file.txt").write_text("test content")
        assert not temp_path.exists()

    def test_directory_cleaned_up_on_exception(self) -> None:
        """Test that directory is cleaned up even on exception."""
        try:
            with secure_temp_dir() as temp_path:
                saved_path = temp_path
                assert temp_path.exists()
                raise ValueError("Test exception")
        except ValueError:
            pass
        assert not saved_path.exists()

    def test_prefix_applied(self) -> None:
        """Test that custom prefix is applied to directory name."""
        with secure_temp_dir(prefix="jmo_test_") as temp_path:
            assert "jmo_test_" in temp_path.name

    def test_suffix_applied(self) -> None:
        """Test that custom suffix is applied to directory name."""
        with secure_temp_dir(suffix="_scan") as temp_path:
            assert temp_path.name.endswith("_scan")

    def test_nested_files_cleaned_up(self) -> None:
        """Test that nested directories and files are cleaned up."""
        with secure_temp_dir() as temp_path:
            # Create nested structure
            nested = temp_path / "level1" / "level2"
            nested.mkdir(parents=True)
            (nested / "deep_file.txt").write_text("deep content")
            (temp_path / "shallow_file.txt").write_text("shallow content")
        assert not temp_path.exists()

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_directory_has_secure_permissions(self) -> None:
        """Test that directory has 0o700 permissions (owner-only)."""
        with secure_temp_dir() as temp_path:
            perms = get_temp_dir_permissions(temp_path)
            # Should be 0o700 (rwx------)
            assert perms == DIR_PERMISSIONS

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_is_secure_permissions_directory(self) -> None:
        """Test is_secure_permissions helper for directories."""
        with secure_temp_dir() as temp_path:
            assert is_secure_permissions(temp_path, is_directory=True)

    def test_returns_path_object(self) -> None:
        """Test that secure_temp_dir yields a Path object."""
        with secure_temp_dir() as temp_path:
            assert isinstance(temp_path, Path)

    def test_can_create_files_inside(self) -> None:
        """Test that files can be created inside the temp directory."""
        with secure_temp_dir() as temp_path:
            test_file = temp_path / "test.json"
            test_file.write_text('{"key": "value"}')
            assert test_file.exists()
            assert test_file.read_text() == '{"key": "value"}'

    def test_custom_parent_dir(self, tmp_path: Path) -> None:
        """Test creating temp directory in custom parent."""
        with secure_temp_dir(parent_dir=tmp_path) as temp_path:
            assert temp_path.parent == tmp_path
            assert temp_path.exists()
        assert not temp_path.exists()


class TestSecureTempFile:
    """Tests for secure_temp_file context manager."""

    def test_creates_file(self) -> None:
        """Test that secure_temp_file creates a file."""
        with secure_temp_file() as temp_path:
            assert temp_path.exists()
            assert temp_path.is_file()

    def test_file_cleaned_up_on_exit(self) -> None:
        """Test that file is removed after context exits."""
        with secure_temp_file() as temp_path:
            assert temp_path.exists()
        assert not temp_path.exists()

    def test_file_cleaned_up_on_exception(self) -> None:
        """Test that file is cleaned up even on exception."""
        try:
            with secure_temp_file() as temp_path:
                saved_path = temp_path
                assert temp_path.exists()
                raise ValueError("Test exception")
        except ValueError:
            pass
        assert not saved_path.exists()

    def test_prefix_applied(self) -> None:
        """Test that custom prefix is applied to file name."""
        with secure_temp_file(prefix="jmo_policy_") as temp_path:
            assert "jmo_policy_" in temp_path.name

    def test_suffix_applied(self) -> None:
        """Test that custom suffix is applied to file name."""
        with secure_temp_file(suffix=".json") as temp_path:
            assert temp_path.name.endswith(".json")

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_file_has_secure_permissions(self) -> None:
        """Test that file has 0o600 permissions (owner-only)."""
        with secure_temp_file() as temp_path:
            perms = get_temp_dir_permissions(temp_path)
            # Should be 0o600 (rw-------)
            assert perms == FILE_PERMISSIONS

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_is_secure_permissions_file(self) -> None:
        """Test is_secure_permissions helper for files."""
        with secure_temp_file() as temp_path:
            assert is_secure_permissions(temp_path, is_directory=False)

    def test_returns_path_object(self) -> None:
        """Test that secure_temp_file yields a Path object."""
        with secure_temp_file() as temp_path:
            assert isinstance(temp_path, Path)

    def test_can_write_and_read(self) -> None:
        """Test that content can be written and read from temp file."""
        with secure_temp_file(suffix=".json") as temp_path:
            temp_path.write_text('{"findings": []}', encoding="utf-8")
            content = temp_path.read_text(encoding="utf-8")
            assert content == '{"findings": []}'

    def test_binary_write(self) -> None:
        """Test that binary content can be written to temp file."""
        with secure_temp_file(suffix=".bin") as temp_path:
            temp_path.write_bytes(b"\x00\x01\x02\x03")
            content = temp_path.read_bytes()
            assert content == b"\x00\x01\x02\x03"

    def test_custom_parent_dir(self, tmp_path: Path) -> None:
        """Test creating temp file in custom parent directory."""
        with secure_temp_file(parent_dir=tmp_path) as temp_path:
            assert temp_path.parent == tmp_path
            assert temp_path.exists()
        assert not temp_path.exists()


class TestPermissionHelpers:
    """Tests for permission helper functions."""

    def test_get_temp_dir_permissions(self, tmp_path: Path) -> None:
        """Test get_temp_dir_permissions returns correct value."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        perms = get_temp_dir_permissions(test_file)
        # Should return an octal permission value
        assert isinstance(perms, int)
        assert perms >= 0

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_get_temp_dir_permissions_specific_value(self, tmp_path: Path) -> None:
        """Test get_temp_dir_permissions returns expected value for set permissions."""
        test_file = tmp_path / "test_perms.txt"
        test_file.write_text("test")
        os.chmod(test_file, 0o644)
        perms = get_temp_dir_permissions(test_file)
        assert perms == 0o644

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_is_secure_permissions_false_for_world_readable(self, tmp_path: Path) -> None:
        """Test that world-readable permissions are not considered secure."""
        test_file = tmp_path / "world_readable.txt"
        test_file.write_text("test")
        os.chmod(test_file, 0o644)  # rw-r--r--
        assert not is_secure_permissions(test_file, is_directory=False)

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_is_secure_permissions_dir_constants(self) -> None:
        """Test that DIR_PERMISSIONS constant is correct."""
        assert DIR_PERMISSIONS == stat.S_IRWXU  # 0o700

    @pytest.mark.skipif(IS_WINDOWS, reason="Unix permission model not applicable")
    def test_is_secure_permissions_file_constants(self) -> None:
        """Test that FILE_PERMISSIONS constant is correct."""
        assert FILE_PERMISSIONS == (stat.S_IRUSR | stat.S_IWUSR)  # 0o600


class TestEdgeCases:
    """Edge case tests for secure temp utilities."""

    def test_multiple_sequential_temp_dirs(self) -> None:
        """Test creating multiple temp directories sequentially."""
        paths = []
        for i in range(3):
            with secure_temp_dir(prefix=f"test{i}_") as temp_path:
                paths.append(temp_path)
                assert temp_path.exists()
        # All should be cleaned up
        for path in paths:
            assert not path.exists()

    def test_nested_secure_temp_contexts(self) -> None:
        """Test nested secure_temp_dir contexts."""
        with secure_temp_dir(prefix="outer_") as outer:
            assert outer.exists()
            with secure_temp_dir(prefix="inner_") as inner:
                assert inner.exists()
                assert outer.exists()
            # Inner should be cleaned up
            assert not inner.exists()
            assert outer.exists()
        # Outer should be cleaned up
        assert not outer.exists()

    def test_empty_prefix_and_suffix(self) -> None:
        """Test with empty prefix and suffix."""
        with secure_temp_dir(prefix="", suffix="") as temp_path:
            assert temp_path.exists()
        assert not temp_path.exists()

    def test_unicode_content(self) -> None:
        """Test writing unicode content to secure temp file."""
        with secure_temp_file(suffix=".txt") as temp_path:
            unicode_content = "こんにちは世界 🔒 безопасность"
            temp_path.write_text(unicode_content, encoding="utf-8")
            assert temp_path.read_text(encoding="utf-8") == unicode_content

    def test_large_content(self) -> None:
        """Test writing large content to secure temp file."""
        with secure_temp_file(suffix=".txt") as temp_path:
            large_content = "x" * 1_000_000  # 1MB
            temp_path.write_text(large_content)
            assert len(temp_path.read_text()) == 1_000_000
