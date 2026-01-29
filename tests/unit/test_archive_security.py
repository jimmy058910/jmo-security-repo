"""Tests for archive security utilities (path traversal prevention)."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.archive_security import (
    _is_safe_path,
    safe_tar_extract,
    safe_zip_extract,
)


class TestIsSafePath:
    """Tests for _is_safe_path() helper function."""

    def test_safe_path_simple_file(self, tmp_path: Path) -> None:
        """Simple filename stays within base directory."""
        assert _is_safe_path(tmp_path, "file.txt") is True

    def test_safe_path_nested_directory(self, tmp_path: Path) -> None:
        """Nested path stays within base directory."""
        assert _is_safe_path(tmp_path, "subdir/nested/file.txt") is True

    def test_unsafe_path_parent_traversal(self, tmp_path: Path) -> None:
        """Path traversal via ../ is detected as unsafe."""
        assert _is_safe_path(tmp_path, "../escape.txt") is False

    def test_unsafe_path_deep_traversal(self, tmp_path: Path) -> None:
        """Deep traversal attempting to escape is detected."""
        assert _is_safe_path(tmp_path, "subdir/../../escape.txt") is False

    def test_unsafe_path_absolute(self, tmp_path: Path) -> None:
        """Absolute path outside base is detected as unsafe."""
        # This depends on OS, but /etc or C:\Windows are outside tmp_path
        assert _is_safe_path(tmp_path, "/etc/passwd") is False

    def test_safe_path_with_dots_in_name(self, tmp_path: Path) -> None:
        """Filenames with dots (not traversal) are safe."""
        assert _is_safe_path(tmp_path, "file..name.txt") is True
        assert _is_safe_path(tmp_path, "...hidden") is True

    def test_safe_path_nested_then_back(self, tmp_path: Path) -> None:
        """Going deeper then back but staying inside is safe."""
        # subdir/../file.txt resolves to file.txt in base
        assert _is_safe_path(tmp_path, "subdir/../file.txt") is True


class TestSafeTarExtract:
    """Tests for safe_tar_extract() function."""

    def test_extract_simple_file(self, tmp_path: Path) -> None:
        """Extracts a simple file without path traversal."""
        # Create a tar in memory with a simple file
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            content = b"safe content"
            info = tarfile.TarInfo(name="safe_file.txt")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            safe_tar_extract(tar, tmp_path)

        assert (tmp_path / "safe_file.txt").exists()
        assert (tmp_path / "safe_file.txt").read_bytes() == b"safe content"

    def test_extract_nested_directory(self, tmp_path: Path) -> None:
        """Extracts files in nested directories."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add a directory
            dir_info = tarfile.TarInfo(name="subdir/")
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)

            # Add a file in the directory
            content = b"nested content"
            file_info = tarfile.TarInfo(name="subdir/nested.txt")
            file_info.size = len(content)
            tar.addfile(file_info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            safe_tar_extract(tar, tmp_path)

        assert (tmp_path / "subdir" / "nested.txt").exists()

    def test_rejects_path_traversal(self, tmp_path: Path) -> None:
        """Rejects archive with path traversal attempt."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            content = b"malicious"
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            with pytest.raises(ValueError, match="path traversal"):
                safe_tar_extract(tar, tmp_path)

    def test_skips_unsafe_symlink(self, tmp_path: Path, caplog) -> None:
        """Logs warning for symlinks pointing outside extraction directory.

        Note: Python 3.12+ data filter raises LinkOutsideDestinationError even
        after our validation loop skips the member. This is defense in depth.
        """
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add a symlink pointing outside
            info = tarfile.TarInfo(name="bad_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../etc/passwd"
            tar.addfile(info)

            # Add a safe file
            content = b"safe"
            safe_info = tarfile.TarInfo(name="safe.txt")
            safe_info.size = len(content)
            tar.addfile(safe_info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            # Python 3.12+ data filter provides additional protection
            with pytest.raises(tarfile.LinkOutsideDestinationError):
                safe_tar_extract(tar, tmp_path)

        # Warning was logged by our validation
        assert "Skipping potentially unsafe symlink" in caplog.text
        assert "bad_link" in caplog.text

    def test_skips_unsafe_hardlink(self, tmp_path: Path, caplog) -> None:
        """Logs warning for hardlinks pointing outside extraction directory.

        Note: Python 3.12+ data filter raises LinkOutsideDestinationError even
        after our validation loop skips the member. This is defense in depth.
        """
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add a hardlink pointing outside
            info = tarfile.TarInfo(name="bad_hardlink")
            info.type = tarfile.LNKTYPE
            info.linkname = "../../../etc/passwd"
            tar.addfile(info)

            # Add a safe file
            content = b"safe"
            safe_info = tarfile.TarInfo(name="safe.txt")
            safe_info.size = len(content)
            tar.addfile(safe_info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            # Python 3.12+ data filter provides additional protection
            with pytest.raises(tarfile.LinkOutsideDestinationError):
                safe_tar_extract(tar, tmp_path)

        # Warning was logged by our validation
        assert "Skipping potentially unsafe symlink" in caplog.text
        assert "bad_hardlink" in caplog.text

    def test_allows_safe_symlink(self, tmp_path: Path) -> None:
        """Allows symlinks pointing within extraction directory."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add a target file first
            content = b"target"
            target_info = tarfile.TarInfo(name="target.txt")
            target_info.size = len(content)
            tar.addfile(target_info, io.BytesIO(content))

            # Add a symlink pointing to it
            info = tarfile.TarInfo(name="link_to_target")
            info.type = tarfile.SYMTYPE
            info.linkname = "target.txt"
            tar.addfile(info)

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            safe_tar_extract(tar, tmp_path)

        assert (tmp_path / "target.txt").exists()
        # Note: link may exist as symlink or file depending on platform

    def test_symlink_with_empty_linkname(self, tmp_path: Path) -> None:
        """Symlinks with empty linkname are extracted (no target check needed)."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="empty_link")
            info.type = tarfile.SYMTYPE
            info.linkname = ""  # Empty linkname
            tar.addfile(info)

            content = b"safe"
            safe_info = tarfile.TarInfo(name="safe.txt")
            safe_info.size = len(content)
            tar.addfile(safe_info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            # Should not raise - empty linkname doesn't trigger safety check
            safe_tar_extract(tar, tmp_path)

        assert (tmp_path / "safe.txt").exists()

    def test_python_311_fallback_path(self, tmp_path: Path) -> None:
        """Tests fallback path for Python <3.12 (no filter parameter)."""
        # Create a tar with a simple file
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            content = b"fallback test"
            info = tarfile.TarInfo(name="fallback.txt")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            # Mock extractall to raise TypeError as Python <3.12 would
            original_extractall = tar.extractall

            def mock_extractall_no_filter(path, members=None, *, numeric_owner=False, filter=None):
                if filter is not None:
                    raise TypeError("extractall() got an unexpected keyword argument 'filter'")
                # Don't actually extract - we just want to trigger the fallback
                return original_extractall(path, members, numeric_owner=numeric_owner)

            with patch.object(tar, "extractall", side_effect=mock_extractall_no_filter):
                safe_tar_extract(tar, tmp_path)

        assert (tmp_path / "fallback.txt").exists()

    def test_python_311_fallback_skips_unsafe_symlinks(self, tmp_path: Path, caplog) -> None:
        """Tests that fallback path also skips unsafe symlinks."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add an unsafe symlink
            info = tarfile.TarInfo(name="unsafe_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../etc/passwd"
            tar.addfile(info)

            # Add a safe file
            content = b"safe"
            safe_info = tarfile.TarInfo(name="safe.txt")
            safe_info.size = len(content)
            tar.addfile(safe_info, io.BytesIO(content))

        tar_buffer.seek(0)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            # Mock extractall to raise TypeError (simulate Python <3.12)
            def mock_extractall(*args, **kwargs):
                if "filter" in kwargs:
                    raise TypeError("extractall() got an unexpected keyword argument 'filter'")

            with patch.object(tar, "extractall", side_effect=mock_extractall):
                safe_tar_extract(tar, tmp_path)

        # Safe file extracted, unsafe link skipped
        assert (tmp_path / "safe.txt").exists()
        assert not (tmp_path / "unsafe_link").exists()
        assert "Skipping potentially unsafe symlink" in caplog.text


class TestSafeZipExtract:
    """Tests for safe_zip_extract() function."""

    def test_extract_simple_file(self, tmp_path: Path) -> None:
        """Extracts a simple file without path traversal."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("safe_file.txt", "safe content")

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            safe_zip_extract(zf, tmp_path)

        assert (tmp_path / "safe_file.txt").exists()
        assert (tmp_path / "safe_file.txt").read_text() == "safe content"

    def test_extract_nested_directory(self, tmp_path: Path) -> None:
        """Extracts files in nested directories."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("subdir/nested.txt", "nested content")

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            safe_zip_extract(zf, tmp_path)

        assert (tmp_path / "subdir" / "nested.txt").exists()

    def test_rejects_path_traversal(self, tmp_path: Path) -> None:
        """Rejects archive with path traversal attempt."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Manually add a malicious path (writestr normalizes paths)
            info = zipfile.ZipInfo("../escape.txt")
            zf.writestr(info, "malicious")

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            with pytest.raises(ValueError, match="path traversal"):
                safe_zip_extract(zf, tmp_path)

    def test_rejects_deep_traversal(self, tmp_path: Path) -> None:
        """Rejects archive with deep path traversal."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            info = zipfile.ZipInfo("subdir/../../escape.txt")
            zf.writestr(info, "malicious")

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            with pytest.raises(ValueError, match="path traversal"):
                safe_zip_extract(zf, tmp_path)

    def test_extract_multiple_files(self, tmp_path: Path) -> None:
        """Extracts multiple files correctly."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("dir/file2.txt", "content2")
            zf.writestr("dir/subdir/file3.txt", "content3")

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            safe_zip_extract(zf, tmp_path)

        assert (tmp_path / "file1.txt").read_text() == "content1"
        assert (tmp_path / "dir" / "file2.txt").read_text() == "content2"
        assert (tmp_path / "dir" / "subdir" / "file3.txt").read_text() == "content3"

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        """Rejects archive with absolute path."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            info = zipfile.ZipInfo("/etc/passwd")
            zf.writestr(info, "malicious")

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            with pytest.raises(ValueError, match="path traversal"):
                safe_zip_extract(zf, tmp_path)
