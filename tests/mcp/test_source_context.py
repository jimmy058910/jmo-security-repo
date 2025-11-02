"""
Unit tests for SourceContextExtractor class.

Tests source code extraction, language detection, and error handling.
Coverage target: ≥90%
"""

from pathlib import Path
import pytest

from scripts.mcp.utils.source_context import SourceContextExtractor


class TestSourceContextExtractorInit:
    """Test SourceContextExtractor initialization."""

    def test_init_with_valid_repo_root(self, repo_root_with_files: Path):
        """Test initialization with valid repository root."""
        extractor = SourceContextExtractor(repo_root_with_files)
        assert extractor.repo_root == repo_root_with_files
        assert extractor.repo_root.exists()

    def test_init_with_nonexistent_repo_root(self, tmp_path: Path):
        """Test initialization with nonexistent repository root."""
        nonexistent_dir = tmp_path / "does_not_exist"
        extractor = SourceContextExtractor(nonexistent_dir)
        # Should initialize without error (lazy validation)
        assert extractor.repo_root == nonexistent_dir


class TestGetContext:
    """Test extracting source code context around findings."""

    def test_get_context_single_line(self, repo_root_with_files: Path):
        """Test extracting context for single-line finding."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=9,  # eval(user_input) line
            context_lines=3,
        )

        assert context["path"] == "src/app.py"
        assert context["language"] == "python"
        assert "eval(user_input)" in context["lines"]
        assert context["start_line"] == 6  # 9 - 3
        assert context["end_line"] == 12  # 9 + 3

    def test_get_context_multi_line(self, repo_root_with_files: Path):
        """Test extracting context for multi-line finding."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.js",
            start_line=6,
            end_line=7,
            context_lines=2,
        )

        assert context["path"] == "src/app.js"
        assert context["language"] == "javascript"
        assert "res.send" in context["lines"]
        assert context["start_line"] == 4  # 6 - 2
        assert context["end_line"] == 9  # 7 + 2

    def test_get_context_at_file_start(self, repo_root_with_files: Path):
        """Test extracting context at beginning of file."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=1,
            context_lines=5,
        )

        assert context["start_line"] == 1  # Can't go below line 1
        assert "#!/usr/bin/env python3" in context["lines"]

    def test_get_context_at_file_end(self, repo_root_with_files: Path):
        """Test extracting context at end of file."""
        extractor = SourceContextExtractor(repo_root_with_files)

        # Get last line of app.py
        context = extractor.get_context(
            file_path="src/app.py",
            start_line=14,  # Last line
            context_lines=5,
        )

        assert 'hello("World")' in context["lines"]
        # end_line should be capped at file length
        assert context["end_line"] <= 14

    def test_get_context_large_window(self, repo_root_with_files: Path):
        """Test extracting context with large context window."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=9,
            context_lines=50,  # Larger than file
        )

        # Should return entire file
        assert context["start_line"] == 1
        assert "#!/usr/bin/env python3" in context["lines"]
        assert 'hello("World")' in context["lines"]

    def test_get_context_default_window(self, repo_root_with_files: Path):
        """Test extracting context with default context_lines=20."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=9,
        )

        # Default is 20 lines
        # File is small, so should get entire file
        assert "#!/usr/bin/env python3" in context["lines"]
        assert "eval(user_input)" in context["lines"]

    def test_get_context_file_not_found(self, repo_root_with_files: Path):
        """Test extracting context for non-existent file."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="nonexistent/file.py",
            start_line=10,
        )

        assert context["path"] == "nonexistent/file.py"
        assert context["lines"] == ""
        assert context["language"] == "unknown"
        assert context["error"] == "File not found"

    def test_get_context_binary_file(self, repo_root_with_files: Path):
        """Test extracting context from binary file."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="binary.bin",
            start_line=1,
        )

        assert context["path"] == "binary.bin"
        # Binary data with low bytes is readable with errors='replace'
        # The test fixture has bytes 0x00-0x09 which are valid ASCII control chars
        assert context["language"] == "unknown"  # .bin has no language mapping
        # No error since file was successfully read (errors='replace' handles it)
        assert "error" not in context

    def test_get_context_truly_binary_file(self, tmp_path: Path):
        """Test extracting context from file with invalid UTF-8 sequences."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        # Create binary file with invalid UTF-8 bytes
        binary_file = repo_root / "binary.dat"
        # These byte sequences are invalid UTF-8
        binary_file.write_bytes(b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8")

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context("binary.dat", 1)

        # Should be readable with errors='replace' (replacement characters)
        assert context["path"] == "binary.dat"
        assert len(context["lines"]) > 0  # Should have replacement characters
        assert "error" not in context  # errors='replace' handles it gracefully

    def test_get_context_none_end_line(self, repo_root_with_files: Path):
        """Test extracting context with None end_line defaults to start_line."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=9,
            end_line=None,
            context_lines=2,
        )

        # Should treat as single-line finding
        assert context["start_line"] == 7  # 9 - 2
        assert context["end_line"] == 11  # 9 + 2


class TestLanguageDetection:
    """Test programming language detection from file extensions."""

    def test_detect_python(self, repo_root_with_files: Path):
        """Test detecting Python files."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context("src/app.py", 1)
        assert context["language"] == "python"

    def test_detect_javascript(self, repo_root_with_files: Path):
        """Test detecting JavaScript files."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context("src/app.js", 1)
        assert context["language"] == "javascript"

    def test_detect_dockerfile(self, repo_root_with_files: Path):
        """Test detecting Dockerfile (special case)."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context("Dockerfile", 1)
        assert context["language"] == "dockerfile"

    @pytest.mark.parametrize(
        "file_path,expected_language",
        [
            ("test.ts", "typescript"),
            ("test.tsx", "typescript"),
            ("test.jsx", "javascript"),
            ("test.go", "go"),
            ("test.rs", "rust"),
            ("test.rb", "ruby"),
            ("test.php", "php"),
            ("test.java", "java"),
            ("test.c", "c"),
            ("test.cpp", "cpp"),
            ("test.cc", "cpp"),
            ("test.h", "c"),
            ("test.hpp", "cpp"),
            ("test.cs", "csharp"),
            ("test.swift", "swift"),
            ("test.kt", "kotlin"),
            ("test.sh", "bash"),
            ("test.bash", "bash"),
            ("test.zsh", "zsh"),
            ("test.ps1", "powershell"),
            ("test.yml", "yaml"),
            ("test.yaml", "yaml"),
            ("test.json", "json"),
            ("test.xml", "xml"),
            ("test.toml", "toml"),
            ("test.html", "html"),
            ("test.css", "css"),
            ("test.scss", "scss"),
            ("test.sql", "sql"),
            ("test.tf", "terraform"),
            ("test.md", "markdown"),
            ("Makefile", "makefile"),
            (".gitignore", "gitignore"),
            (".env", "dotenv"),
        ],
    )
    def test_detect_language_comprehensive(
        self, tmp_path: Path, file_path: str, expected_language: str
    ):
        """Test comprehensive language detection for all supported languages."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        # Create file with minimal content
        file_full_path = repo_root / file_path
        file_full_path.parent.mkdir(parents=True, exist_ok=True)
        file_full_path.write_text("test content\n")

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context(file_path, 1)

        assert context["language"] == expected_language, f"Failed for {file_path}"

    def test_detect_unknown_extension(self, tmp_path: Path):
        """Test detecting unknown file extension."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        unknown_file = repo_root / "test.xyz"
        unknown_file.write_text("test content\n")

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context("test.xyz", 1)

        assert context["language"] == "unknown"


class TestGetFullFileContent:
    """Test getting entire file content."""

    def test_get_full_file_content_success(self, repo_root_with_files: Path):
        """Test getting full file content successfully."""
        extractor = SourceContextExtractor(repo_root_with_files)

        result = extractor.get_full_file_content("src/app.py")

        assert result["path"] == "src/app.py"
        assert result["language"] == "python"
        assert "#!/usr/bin/env python3" in result["content"]
        assert "eval(user_input)" in result["content"]
        assert result["line_count"] == 12  # Actual line count from fixture

    def test_get_full_file_content_javascript(self, repo_root_with_files: Path):
        """Test getting full JavaScript file."""
        extractor = SourceContextExtractor(repo_root_with_files)

        result = extractor.get_full_file_content("src/app.js")

        assert result["language"] == "javascript"
        assert "const express" in result["content"]
        assert result["line_count"] == 10

    def test_get_full_file_content_not_found(self, repo_root_with_files: Path):
        """Test getting full file content for non-existent file."""
        extractor = SourceContextExtractor(repo_root_with_files)

        result = extractor.get_full_file_content("nonexistent.py")

        assert result["path"] == "nonexistent.py"
        assert result["content"] == ""
        assert result["language"] == "unknown"
        assert result["error"] == "File not found"

    def test_get_full_file_content_empty_file(self, tmp_path: Path):
        """Test getting full file content for empty file."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        empty_file = repo_root / "empty.py"
        empty_file.write_text("")

        extractor = SourceContextExtractor(repo_root)
        result = extractor.get_full_file_content("empty.py")

        assert result["content"] == ""
        assert result["line_count"] == 0
        assert result["language"] == "python"
        assert "error" not in result


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_context_with_unicode_characters(self, tmp_path: Path):
        """Test extracting context from file with Unicode characters."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        unicode_file = repo_root / "unicode.py"
        unicode_file.write_text(
            "# -*- coding: utf-8 -*-\n# Comment with émojis 🔥\nprint('Hello 世界')\n"
        )

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context("unicode.py", 3)

        assert "Hello 世界" in context["lines"]
        assert "🔥" in context["lines"]

    def test_context_with_very_long_lines(self, tmp_path: Path):
        """Test extracting context from file with very long lines."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        long_file = repo_root / "long.py"
        long_line = "x = " + "a" * 10000 + "\n"
        long_file.write_text(long_line)

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context("long.py", 1)

        # Should handle long lines without error
        assert "x = " in context["lines"]
        assert len(context["lines"]) > 5000

    def test_context_with_mixed_line_endings(self, tmp_path: Path):
        """Test extracting context from file with mixed line endings."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        mixed_file = repo_root / "mixed.py"
        # Mix Unix (\n) and Windows (\r\n) line endings
        content = "line1\nline2\r\nline3\nline4\r\n"
        mixed_file.write_bytes(content.encode("utf-8"))

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context("mixed.py", 2, context_lines=1)

        # Should handle mixed line endings gracefully
        assert "line2" in context["lines"]

    def test_context_zero_context_lines(self, repo_root_with_files: Path):
        """Test extracting context with zero context lines."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=9,
            context_lines=0,
        )

        # Should return just the line itself
        assert context["start_line"] == 9
        assert context["end_line"] == 9
        assert "eval(user_input)" in context["lines"]

    def test_context_negative_line_number(self, repo_root_with_files: Path):
        """Test extracting context with negative line number."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=-1,  # Invalid line number
            context_lines=5,
        )

        # Should handle gracefully by clamping to line 1
        assert context["start_line"] >= 1

    def test_context_line_number_exceeds_file(self, repo_root_with_files: Path):
        """Test extracting context with line number beyond file end."""
        extractor = SourceContextExtractor(repo_root_with_files)

        context = extractor.get_context(
            file_path="src/app.py",
            start_line=1000,  # Way beyond file end
            context_lines=5,
        )

        # Should handle gracefully
        # The context window calculation might return empty or clamp to file end
        assert isinstance(context["lines"], str)

    def test_path_with_special_characters(self, tmp_path: Path):
        """Test file path with special characters."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        # Create directory with spaces and special chars
        special_dir = repo_root / "dir with spaces" / "sub-dir_123"
        special_dir.mkdir(parents=True)

        special_file = special_dir / "file-name_123.py"
        special_file.write_text("print('test')\n")

        extractor = SourceContextExtractor(repo_root)
        context = extractor.get_context(
            "dir with spaces/sub-dir_123/file-name_123.py", 1
        )

        assert context["path"] == "dir with spaces/sub-dir_123/file-name_123.py"
        assert "print('test')" in context["lines"]
        assert context["language"] == "python"

    def test_symlink_file(self, tmp_path: Path):
        """Test extracting context from symlinked file."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        # Create original file
        original_file = repo_root / "original.py"
        original_file.write_text("print('original')\n")

        # Create symlink (skip on Windows if not supported)
        try:
            symlink_file = repo_root / "symlink.py"
            symlink_file.symlink_to(original_file)

            extractor = SourceContextExtractor(repo_root)
            context = extractor.get_context("symlink.py", 1)

            assert "print('original')" in context["lines"]
        except OSError:
            # Symlinks might not be supported (Windows without admin)
            pytest.skip("Symlinks not supported on this system")
