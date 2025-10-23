#!/usr/bin/env python3
"""Tests for scripts/cli/cpu_utils.py - CPU detection and thread optimization."""

import pytest
from unittest.mock import patch

from scripts.cli.cpu_utils import get_cpu_count, auto_detect_threads


class TestGetCpuCount:
    """Tests for get_cpu_count() function."""

    def test_normal_cpu_detection(self):
        """Test CPU detection returns positive integer."""
        cpu_count = get_cpu_count()
        assert isinstance(cpu_count, int)
        assert cpu_count >= 1

    def test_cpu_detection_fallback(self):
        """Test CPU detection falls back to 4 on error."""
        with patch("os.cpu_count", return_value=None):
            assert get_cpu_count() == 4

    def test_cpu_detection_os_error(self):
        """Test CPU detection handles OSError."""
        with patch("os.cpu_count", side_effect=OSError("mock error")):
            assert get_cpu_count() == 4

    def test_cpu_detection_runtime_error(self):
        """Test CPU detection handles RuntimeError."""
        with patch("os.cpu_count", side_effect=RuntimeError("mock error")):
            assert get_cpu_count() == 4


class TestAutoDetectThreads:
    """Tests for auto_detect_threads() function."""

    def test_auto_detect_with_8_cores(self):
        """Test auto-detection with 8 cores (typical laptop)."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=8):
            threads = auto_detect_threads()
            assert threads == 6  # 75% of 8 = 6

    def test_auto_detect_with_16_cores(self):
        """Test auto-detection with 16 cores (workstation)."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=16):
            threads = auto_detect_threads()
            assert threads == 12  # 75% of 16 = 12

    def test_auto_detect_with_32_cores(self):
        """Test auto-detection caps at 16 threads (server)."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=32):
            threads = auto_detect_threads()
            assert threads == 16  # Capped at maximum

    def test_auto_detect_with_2_cores(self):
        """Test auto-detection with 2 cores (minimum)."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=2):
            threads = auto_detect_threads()
            assert threads == 2  # Minimum threshold

    def test_auto_detect_with_1_core(self):
        """Test auto-detection with 1 core (uses minimum)."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=1):
            threads = auto_detect_threads()
            assert threads == 2  # Enforces minimum

    def test_auto_detect_with_4_cores(self):
        """Test auto-detection with 4 cores (typical VM)."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=4):
            threads = auto_detect_threads()
            assert threads == 3  # 75% of 4 = 3

    def test_auto_detect_with_logging(self):
        """Test auto-detection calls log function."""
        log_calls = []

        def mock_log(level, message):
            log_calls.append((level, message))

        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=8):
            threads = auto_detect_threads(log_fn=mock_log)
            assert threads == 6
            assert len(log_calls) == 1
            assert log_calls[0][0] == "INFO"
            assert "8 CPU cores" in log_calls[0][1]
            assert "6 threads" in log_calls[0][1]

    def test_auto_detect_without_logging(self):
        """Test auto-detection works without log function."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=8):
            threads = auto_detect_threads(log_fn=None)
            assert threads == 6  # Should work without logging


class TestThreadCalculationLogic:
    """Tests for thread calculation edge cases."""

    def test_thread_calculation_rounds_down(self):
        """Test 75% calculation rounds down correctly."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=5):
            threads = auto_detect_threads()
            # 75% of 5 = 3.75 → rounds down to 3
            assert threads == 3

    def test_thread_calculation_odd_cores(self):
        """Test calculation with odd number of cores."""
        with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=7):
            threads = auto_detect_threads()
            # 75% of 7 = 5.25 → rounds down to 5
            assert threads == 5

    def test_minimum_threads_enforced(self):
        """Test minimum thread count is always 2."""
        for cpu_count in [1, 2]:
            with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=cpu_count):
                threads = auto_detect_threads()
                assert threads >= 2

    def test_maximum_threads_enforced(self):
        """Test maximum thread count is capped at 16."""
        # CPU counts where 75% exceeds 16 threads
        for cpu_count in [22, 32, 64, 128]:
            with patch("scripts.cli.cpu_utils.get_cpu_count", return_value=cpu_count):
                threads = auto_detect_threads()
                assert (
                    threads == 16
                ), f"Expected 16 threads for {cpu_count} cores, got {threads}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
