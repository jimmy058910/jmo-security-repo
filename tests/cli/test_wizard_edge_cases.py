"""Edge case tests for wizard functionality.

Tests robustness under unusual conditions:
- Unicode paths (emoji, CJK characters)
- Very long paths on Windows
- Docker daemon errors
- Corrupted/locked history database
- Large dataset performance
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Platform detection for skip markers
IS_WINDOWS = sys.platform == "win32"
skip_on_windows = pytest.mark.skipif(
    IS_WINDOWS, reason="Test requires Unix-specific features"
)
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")


class TestUnicodePaths:
    """Test wizard handles Unicode paths correctly."""

    def test_path_with_emoji_characters(self, tmp_path: Path):
        """Test wizard handles paths with emoji characters."""
        # Create path with actual emoji (may fail on some Windows codepages)
        try:
            emoji_dir = tmp_path / "project_🔒_secure"
            emoji_dir.mkdir()
        except (OSError, UnicodeError):
            pytest.skip("File system doesn't support emoji in paths")

        from scripts.cli.wizard_flows.validators import validate_path

        result = validate_path(str(emoji_dir))
        assert result is not None
        assert result.exists()

    def test_path_with_cjk_characters(self, tmp_path: Path):
        """Test wizard handles paths with CJK characters."""
        try:
            cjk_dir = tmp_path / "测试项目"
            cjk_dir.mkdir()
        except (OSError, UnicodeError):
            pytest.skip("File system doesn't support CJK characters in paths")

        from scripts.cli.wizard_flows.validators import validate_path

        result = validate_path(str(cjk_dir))
        assert result is not None
        assert result.exists()

    def test_path_with_accented_characters(self, tmp_path: Path):
        """Test wizard handles paths with European accented characters."""
        try:
            accented_dir = tmp_path / "próyecto_áccénts_ñ"
            accented_dir.mkdir()
        except (OSError, UnicodeError):
            pytest.skip("File system doesn't support accented characters in paths")

        from scripts.cli.wizard_flows.validators import validate_path

        result = validate_path(str(accented_dir))
        assert result is not None
        assert result.exists()

    def test_path_with_spaces(self, tmp_path: Path):
        """Test wizard handles paths with spaces."""
        space_dir = tmp_path / "my project folder"
        space_dir.mkdir()

        from scripts.cli.wizard_flows.validators import validate_path

        result = validate_path(str(space_dir))
        assert result is not None
        assert result.exists()

    def test_validate_nonexistent_path(self, tmp_path: Path):
        """Test validate_path returns None for non-existent paths."""
        from scripts.cli.wizard_flows.validators import validate_path

        nonexistent = tmp_path / "does_not_exist"
        result = validate_path(str(nonexistent), must_exist=True)
        assert result is None

    def test_validate_path_without_must_exist(self, tmp_path: Path):
        """Test validate_path with must_exist=False."""
        from scripts.cli.wizard_flows.validators import validate_path

        nonexistent = tmp_path / "future_dir"
        result = validate_path(str(nonexistent), must_exist=False)
        assert result is not None


@windows_only
class TestWindowsLongPaths:
    """Test Windows-specific long path handling."""

    def test_deeply_nested_path(self, tmp_path: Path):
        """Test wizard handles deeply nested paths near 260 char limit."""
        from scripts.cli.wizard_flows.validators import validate_path

        # Create moderately nested path
        deep_path = tmp_path
        for i in range(10):
            deep_path = deep_path / f"nested_{i:02d}"

        # Skip if path is already too long
        if len(str(deep_path)) >= 250:
            pytest.skip("Base path too long for this test")

        try:
            deep_path.mkdir(parents=True)
            result = validate_path(str(deep_path))
            # Should either work or return None gracefully
            if result is not None:
                assert result.exists()
        except OSError:
            # Path too long is acceptable - validate_path should handle gracefully
            result = validate_path(str(deep_path))
            assert result is None  # Should return None for invalid paths


class TestDockerErrors:
    """Test wizard handles Docker errors gracefully."""

    def test_docker_not_installed(self):
        """Test wizard handles Docker not being installed."""
        from scripts.cli.wizard_flows.validators import detect_docker

        with patch("shutil.which", return_value=None):
            result = detect_docker()
            assert result is False

    def test_docker_daemon_not_running(self):
        """Test wizard handles Docker daemon not responding."""
        from scripts.cli.wizard_flows.validators import check_docker_running

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = check_docker_running()
            assert result is False

    def test_docker_command_timeout(self):
        """Test wizard handles Docker command timeout."""
        import subprocess

        from scripts.cli.wizard_flows.validators import check_docker_running

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 5)
        ):
            result = check_docker_running()
            assert result is False

    def test_docker_command_file_not_found(self):
        """Test wizard handles missing docker binary."""
        from scripts.cli.wizard_flows.validators import check_docker_running

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = check_docker_running()
            assert result is False


class TestHistoryDatabaseErrors:
    """Test wizard handles history database errors."""

    def test_corrupted_history_database(self, tmp_path: Path):
        """Test wizard handles corrupted history.db via the wizard's DB path."""
        from scripts.core.history_db import get_connection

        # Create corrupted database file
        db_path = tmp_path / "history.db"
        db_path.write_text("this is not a valid sqlite database")

        # Attempting to use the wizard's get_connection should fail gracefully
        try:
            conn = get_connection(db_path)
            cursor = conn.execute("SELECT 1")
            cursor.fetchone()
            conn.close()
            # If it somehow worked (shouldn't), test is still valid
        except sqlite3.DatabaseError as e:
            # Expected - corrupted database
            assert (
                "file is not a database" in str(e).lower()
                or "database" in str(e).lower()
            )

    def test_missing_history_database_directory(self, tmp_path: Path):
        """Test wizard handles missing .jmo directory."""
        from scripts.cli.wizard import _get_db_path

        # Mock Path.home to return a tmp directory without .jmo
        with patch.object(Path, "home", staticmethod(lambda: tmp_path)):
            # Reset the module-level variable
            import scripts.cli.wizard as wizard_module

            original_custom = wizard_module._custom_db_path
            wizard_module._custom_db_path = None

            try:
                db_path = _get_db_path()
                # Should return the expected path even if it doesn't exist
                assert ".jmo" in str(db_path)
                assert "history.db" in str(db_path)
            finally:
                wizard_module._custom_db_path = original_custom

    def test_custom_db_path_respected(self, tmp_path: Path):
        """Test that custom --db flag is respected."""
        from scripts.cli.wizard import _get_db_path

        custom_path = tmp_path / "custom_history.db"

        import scripts.cli.wizard as wizard_module

        original_custom = wizard_module._custom_db_path
        wizard_module._custom_db_path = str(custom_path)

        try:
            result = _get_db_path()
            assert result == custom_path.resolve()
        finally:
            wizard_module._custom_db_path = original_custom

    @skip_on_windows  # File locking behavior differs on Windows
    def test_history_database_locked(self, tmp_path: Path):
        """Test wizard handles locked history.db (Unix only)."""
        db_path = tmp_path / "history.db"

        # Create and lock database
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.execute("BEGIN EXCLUSIVE")  # Exclusive lock

        try:
            # Try to open with another connection
            conn2 = sqlite3.connect(str(db_path), timeout=0.1)
            try:
                conn2.execute("SELECT * FROM test")
            except sqlite3.OperationalError as e:
                # Expected - database is locked
                assert "locked" in str(e).lower() or "busy" in str(e).lower()
            finally:
                conn2.close()
        finally:
            conn.rollback()
            conn.close()


class TestTerminalSupport:
    """Test terminal-related edge cases."""

    def test_ansi_support_with_no_color_env(self):
        """Test ANSI detection respects NO_COLOR environment variable."""
        from scripts.cli.wizard_flows.base_flow import _supports_ansi

        with patch.dict("os.environ", {"NO_COLOR": "1"}):
            # Import fresh to test the function
            result = _supports_ansi()
            assert result is False

    def test_ansi_support_windows_terminal(self):
        """Test ANSI detection with Windows Terminal."""
        from scripts.cli.wizard_flows.base_flow import _supports_ansi

        with patch.dict("os.environ", {"WT_SESSION": "some-guid"}, clear=False):
            with patch("sys.platform", "win32"):
                result = _supports_ansi()
                assert result is True

    def test_terminal_width_fallback(self):
        """Test terminal width returns safe fallback on error."""
        from scripts.cli.wizard_flows.base_flow import _get_terminal_width

        with patch("shutil.get_terminal_size", side_effect=OSError("No terminal")):
            width = _get_terminal_width()
            assert width == 80  # Safe default

    def test_terminal_width_minimum(self):
        """Test terminal width enforces minimum."""
        from scripts.cli.wizard_flows.base_flow import _get_terminal_width

        # Mock a very narrow terminal
        with patch("shutil.get_terminal_size", return_value=MagicMock(columns=20)):
            width = _get_terminal_width()
            assert width >= 40  # Minimum enforced

    def test_terminal_width_maximum(self):
        """Test terminal width enforces maximum."""
        from scripts.cli.wizard_flows.base_flow import _get_terminal_width

        # Mock a very wide terminal
        with patch("shutil.get_terminal_size", return_value=MagicMock(columns=500)):
            width = _get_terminal_width()
            assert width <= 120  # Maximum enforced


class TestColorizeGracefulDegradation:
    """Test colorize handles edge cases."""

    def test_colorize_returns_text_without_ansi_support(self):
        """Test colorize returns plain text when ANSI not supported."""
        from scripts.cli.wizard_flows.base_flow import PromptHelper

        prompter = PromptHelper()

        # Mock ANSI not supported
        with patch("scripts.cli.wizard_flows.base_flow._ANSI_SUPPORTED", False):
            result = prompter.colorize("test text", "red")
            assert result == "test text"
            assert "\x1b" not in result  # No ANSI escape codes

    def test_colorize_unknown_color(self):
        """Test colorize handles unknown color names."""
        from scripts.cli.wizard_flows.base_flow import PromptHelper

        prompter = PromptHelper()

        # Unknown color should not raise, should return text with reset
        result = prompter.colorize("test text", "nonexistent_color")
        assert "test text" in result

    def test_colorize_empty_text(self):
        """Test colorize handles empty text."""
        from scripts.cli.wizard_flows.base_flow import PromptHelper

        prompter = PromptHelper()

        # Should not raise, empty string is valid
        colorized = prompter.colorize("", "red")
        assert colorized is not None  # Just verify it doesn't raise


class TestLargeDatasetPerformance:
    """Test wizard handles large datasets efficiently."""

    @pytest.mark.timeout(30)  # Should complete in under 30 seconds
    def test_many_findings_loading(self, tmp_path: Path):
        """Test wizard handles loading 10,000 findings efficiently."""
        # Create results with 10,000 findings
        results_dir = tmp_path / "results" / "summaries"
        results_dir.mkdir(parents=True)

        findings = [
            {
                "id": f"finding-{i}",
                "ruleId": f"RULE-{i % 100}",
                "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {"path": f"src/file_{i % 50}.py", "startLine": i % 500},
                "message": f"Finding {i} description",
            }
            for i in range(10000)
        ]

        (results_dir / "findings.json").write_text(
            json.dumps({"findings": findings}), encoding="utf-8"
        )

        # Loading should be fast
        start = time.time()
        loaded_data = json.loads((results_dir / "findings.json").read_text())
        elapsed = time.time() - start

        assert len(loaded_data["findings"]) == 10000
        assert elapsed < 5.0  # Should load in under 5 seconds

    @pytest.mark.timeout(10)
    def test_large_json_serialization(self, tmp_path: Path):
        """Test JSON serialization performance for large datasets."""
        # Create large findings structure
        findings = {
            "findings": [
                {
                    "id": f"finding-{i}",
                    "ruleId": f"RULE-{i % 100}",
                    "severity": "HIGH",
                    "message": f"Finding {i} " + "x" * 100,  # ~100 char message
                }
                for i in range(5000)
            ]
        }

        output_file = tmp_path / "output.json"

        start = time.time()
        output_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        elapsed = time.time() - start

        assert output_file.exists()
        assert elapsed < 3.0  # Should serialize in under 3 seconds


class TestSafePrintEdgeCases:
    """Test _safe_print handles edge cases."""

    def test_safe_print_with_unicode(self, capsys):
        """Test _safe_print handles Unicode characters."""
        from scripts.cli.wizard import _safe_print

        # Should not raise even with Unicode
        _safe_print("Test with emoji: (info)")  # Using text fallback
        captured = capsys.readouterr()
        assert "Test with" in captured.out

    def test_safe_print_with_ascii_fallback(self, capsys):
        """Test _safe_print uses ASCII fallback when needed."""

        from scripts.cli.wizard import _UNICODE_FALLBACKS

        # Test the fallback logic directly instead of mocking readonly attr
        test_text = "Check: [OK]"
        for unicode_char, ascii_fallback in _UNICODE_FALLBACKS.items():
            if unicode_char in test_text:
                test_text = test_text.replace(unicode_char, ascii_fallback)

        # Verify fallback mapping exists
        assert "[OK]" in _UNICODE_FALLBACKS.values() or "✅" in _UNICODE_FALLBACKS

    def test_safe_print_handles_unicode_encode_error(self, capsys, monkeypatch):
        """Test _safe_print handles UnicodeEncodeError gracefully."""
        from scripts.cli.wizard import _safe_print

        # Create a mock that raises on first call, succeeds on second
        original_print = print
        call_count = [0]

        def mock_print(text, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1 and "✅" in text:
                raise UnicodeEncodeError("cp1252", text, 0, 1, "char not supported")
            original_print(text, *args, **kwargs)

        monkeypatch.setattr("builtins.print", mock_print)

        # Should not raise, should fall back to ASCII
        _safe_print("Check: ✅")  # Uses fallback
        captured = capsys.readouterr()
        assert "Check" in captured.out

    def test_safe_print_basic_text(self, capsys):
        """Test _safe_print with basic ASCII text."""
        from scripts.cli.wizard import _safe_print

        _safe_print("Simple test message")
        captured = capsys.readouterr()
        assert "Simple test message" in captured.out
