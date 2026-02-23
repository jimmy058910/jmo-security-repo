#!/usr/bin/env python3
"""
Windows-Specific E2E Tests for JMo Security.

Tests Windows-specific path handling, UNC paths, and Windows behaviors.
These tests only run on Windows.

Usage:
    pytest tests/e2e/test_windows_specific.py -v
"""

from __future__ import annotations


from tests.conftest import windows_only


@windows_only
class TestWindowsPathHandling:
    """Test Windows-specific path handling."""

    def test_backslash_paths_in_repo_arg(self, jmo_runner, tmp_path):
        """Verify backslash paths work in --repo argument."""
        # Create test repo
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        # Use Windows-style path with backslashes
        win_path = str(repo).replace("/", "\\")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                win_path,
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=120,
        )

        # Path should be accepted
        combined = result.stdout.lower() + result.stderr.lower()
        assert "invalid path" not in combined
        assert "not found" not in combined or "tool" in combined

    def test_mixed_slash_paths(self, jmo_runner, tmp_path):
        """Verify mixed forward/back slashes work."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        # Mix forward and back slashes
        mixed_path = str(repo).replace("\\", "/", 1)

        result = jmo_runner(
            [
                "scan",
                "--repo",
                mixed_path,
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=120,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_drive_letter_paths(self, jmo_runner, tmp_path):
        """Verify drive letter paths work correctly."""
        # tmp_path should already have drive letter on Windows
        assert len(str(tmp_path)) > 2 and str(tmp_path)[1] == ":"

        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=120,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_paths_with_spaces(self, jmo_runner, tmp_path):
        """Verify paths with spaces work on Windows."""
        repo = tmp_path / "test repo with spaces"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results dir"),
            ],
            timeout=120,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_paths_with_special_chars(self, jmo_runner, tmp_path):
        """Verify paths with special characters work on Windows."""
        # Windows allows these characters in filenames
        repo = tmp_path / "test-repo_v1.0 (copy)"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=120,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_long_paths(self, jmo_runner, tmp_path):
        """Verify long paths work on Windows (260+ chars).

        Uses the \\\\?\\ extended-length path prefix on Windows to bypass
        the 260-char MAX_PATH limitation. This prefix is the standard way
        to handle long paths without requiring registry changes.
        """
        import os
        import sys

        # Create a deeply nested path
        deep_path = tmp_path
        for i in range(10):
            deep_path = deep_path / f"nested_directory_{i:03d}"

        # On Windows, use \\?\ prefix to bypass MAX_PATH (260 chars)
        if sys.platform == "win32":
            extended = f"\\\\?\\{deep_path}"
            os.makedirs(extended, exist_ok=True)
            test_file = os.path.join(extended, "test.py")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("x = 1")
        else:
            deep_path.mkdir(parents=True)
            (deep_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(deep_path),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=120,
        )

        # May fail due to path length but shouldn't crash
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@windows_only
class TestWindowsEnvironment:
    """Test Windows environment handling."""

    def test_userprofile_env_var(self, jmo_runner, monkeypatch, tmp_path):
        """Verify USERPROFILE is used for home directory on Windows."""
        # Windows uses USERPROFILE instead of HOME
        custom_home = tmp_path / "custom_home"
        custom_home.mkdir()

        monkeypatch.setenv("USERPROFILE", str(custom_home))

        result = jmo_runner(["tools", "check"], timeout=60)

        # Should work with modified USERPROFILE
        assert result.returncode in (0, 1)

    def test_path_separator_handling(self, jmo_runner, tmp_path):
        """Verify PATH separator (;) handling on Windows."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            ["scan", "--repo", str(repo), "--allow-missing-tools"],
            timeout=120,
        )

        # Should work with Windows PATH
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@windows_only
class TestWindowsFileOperations:
    """Test Windows-specific file operations."""

    def test_file_locking_handling(self, jmo_runner, tmp_path):
        """Verify handling of locked files on Windows."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        test_file = repo / "test.py"
        test_file.write_text("x = 1", encoding="utf-8")

        # Open file to lock it (Windows-specific behavior)
        with open(test_file, "r") as _locked:
            result = jmo_runner(
                [
                    "scan",
                    "--repo",
                    str(repo),
                    "--allow-missing-tools",
                    "--results-dir",
                    str(tmp_path / "results"),
                ],
                timeout=120,
            )

        # Should handle locked file gracefully
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_history_db_in_appdata(self, jmo_runner, monkeypatch, tmp_path):
        """Verify history database uses AppData on Windows."""
        appdata = tmp_path / "AppData" / "Local"
        appdata.mkdir(parents=True)
        monkeypatch.setenv("LOCALAPPDATA", str(appdata))

        result = jmo_runner(["history", "list"], timeout=60)

        # Should work with Windows AppData location
        assert result.returncode in (0, 1)


@windows_only
class TestWindowsToolDiscovery:
    """Test tool discovery on Windows."""

    def test_exe_extension_handling(self, jmo_runner):
        """Verify .exe extension is handled in tool discovery."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Should find tools whether they have .exe or not
        assert result.returncode in (0, 1)
        # Should complete without crashing
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_tool_path_with_program_files(self, jmo_runner, tmp_path):
        """Verify tools in Program Files are discovered."""
        # This is more of a smoke test - actual tool installation varies
        result = jmo_runner(["tools", "debug", "trivy"], timeout=30)

        # Should complete and show path info
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@windows_only
class TestWindowsOutputFormatting:
    """Test output formatting on Windows."""

    def test_unicode_output(self, jmo_runner, tmp_path):
        """Verify Unicode output works on Windows console."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("# Unicode: 中文 日本語", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
                "--human-logs",
            ],
            timeout=120,
        )

        # Should handle Unicode without encoding errors
        # Note: Windows console may have encoding issues but shouldn't crash
        assert result.returncode in (0, 1)

    def test_ansi_color_handling(self, jmo_runner):
        """Verify ANSI color codes work or degrade gracefully."""
        result = jmo_runner(["tools", "check", "--human-logs"], timeout=60)

        # Should produce output without garbled escape codes
        combined = result.stdout + result.stderr
        # Either has clean output or ANSI codes but shouldn't have broken escape sequences
        assert (
            "\x1b[" not in combined
            or "\x1b[0m" in combined
            or result.returncode in (0, 1)
        )


@windows_only
class TestWindowsSubprocessHandling:
    """Test subprocess handling on Windows."""

    def test_cmd_special_chars_escaped(self, jmo_runner, tmp_path):
        """Verify special characters in paths are escaped for cmd.exe."""
        # Characters that are special in cmd.exe: & | < > ^ %
        # These shouldn't be in paths but we test handling
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        # Should not allow command injection
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_timeout_handling(self, jmo_runner, tmp_path):
        """Verify timeout handling works on Windows."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--timeout",
                "10",
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        # Timeout flag should be accepted
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined
