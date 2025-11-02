"""Unit tests for scan_utils.py.

Tests cover:
- tool_exists() with found and missing tools
- write_stub() for all supported tool formats (JSON and NDJSON)
- run_cmd() happy path (command succeeds)
- run_cmd() with timeout handling
- run_cmd() with retries (failure then success)
- run_cmd() with acceptable return codes (ok_rcs)
- run_cmd() with capture_stdout
- run_cmd() exception handling (FileNotFoundError, PermissionError, OSError)
"""

import json
import subprocess
from unittest.mock import patch, MagicMock


from scripts.cli.scan_utils import tool_exists, write_stub, run_cmd, TOOL_INSTALL_HINTS


# ========== Category 1: tool_exists() Tests ==========


def test_tool_exists_found():
    """Test tool_exists returns True when tool found in PATH."""
    with patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/trivy"

        result = tool_exists("trivy")

        assert result is True
        mock_which.assert_called_once_with("trivy")


def test_tool_exists_not_found_with_hint():
    """Test tool_exists returns False and logs hint when tool not found."""
    with patch("shutil.which") as mock_which, patch("logging.getLogger") as mock_logger:
        mock_which.return_value = None
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        result = tool_exists("semgrep")

        assert result is False
        mock_which.assert_called_once_with("semgrep")

        # Verify error logged with installation hint
        mock_log.error.assert_called_once()
        error_msg = mock_log.error.call_args[0][0]
        assert "semgrep" in error_msg
        assert "not found" in error_msg
        assert "Install" in error_msg or "pip install semgrep" in error_msg


def test_tool_exists_not_found_without_hint():
    """Test tool_exists handles unknown tool without specific hint."""
    with patch("shutil.which") as mock_which, patch("logging.getLogger") as mock_logger:
        mock_which.return_value = None
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        result = tool_exists("unknown-tool")

        assert result is False

        # Should log generic hint
        mock_log.error.assert_called_once()
        error_msg = mock_log.error.call_args[0][0]
        assert "unknown-tool" in error_msg
        assert "Install unknown-tool" in error_msg


# ========== Category 2: write_stub() Tests - JSON Tools ==========


def test_write_stub_trufflehog(tmp_path):
    """Test write_stub creates correct empty stub for trufflehog."""
    out_path = tmp_path / "trufflehog.json"

    write_stub("trufflehog", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == []


def test_write_stub_semgrep(tmp_path):
    """Test write_stub creates correct empty stub for semgrep."""
    out_path = tmp_path / "semgrep.json"

    write_stub("semgrep", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"results": []}


def test_write_stub_trivy(tmp_path):
    """Test write_stub creates correct empty stub for trivy."""
    out_path = tmp_path / "trivy.json"

    write_stub("trivy", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"Results": []}


def test_write_stub_checkov(tmp_path):
    """Test write_stub creates correct empty stub for checkov."""
    out_path = tmp_path / "checkov.json"

    write_stub("checkov", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"results": {"failed_checks": []}}


def test_write_stub_syft(tmp_path):
    """Test write_stub creates correct empty stub for syft."""
    out_path = tmp_path / "syft.json"

    write_stub("syft", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"artifacts": []}


def test_write_stub_bandit(tmp_path):
    """Test write_stub creates correct empty stub for bandit."""
    out_path = tmp_path / "bandit.json"

    write_stub("bandit", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"results": []}


def test_write_stub_zap(tmp_path):
    """Test write_stub creates correct empty stub for ZAP."""
    out_path = tmp_path / "zap.json"

    write_stub("zap", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"site": []}


def test_write_stub_aflplusplus(tmp_path):
    """Test write_stub creates correct empty stub for AFL++."""
    out_path = tmp_path / "afl++.json"

    write_stub("afl++", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"crashes": []}


def test_write_stub_noseyparker(tmp_path):
    """Test write_stub creates correct empty stub for noseyparker."""
    out_path = tmp_path / "noseyparker.json"

    write_stub("noseyparker", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"matches": []}


# ========== Category 3: write_stub() Tests - NDJSON Tools ==========


def test_write_stub_nuclei_ndjson(tmp_path):
    """Test write_stub creates empty string for NDJSON tools (nuclei)."""
    out_path = tmp_path / "nuclei.json"

    write_stub("nuclei", out_path)

    assert out_path.exists()
    content = out_path.read_text()
    assert content == ""  # Empty string for NDJSON


# ========== Category 4: write_stub() Tests - Unknown Tools ==========


def test_write_stub_unknown_tool(tmp_path):
    """Test write_stub creates empty dict for unknown tools."""
    out_path = tmp_path / "unknown.json"

    write_stub("unknown-tool", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {}


def test_write_stub_creates_parent_directories(tmp_path):
    """Test write_stub creates parent directories if missing."""
    out_path = tmp_path / "nested" / "dirs" / "tool.json"

    write_stub("trivy", out_path)

    assert out_path.exists()
    assert out_path.parent.exists()


# ========== Category 5: run_cmd() Happy Path Tests ==========


def test_run_cmd_success_no_capture():
    """Test run_cmd successful execution without capturing stdout."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")

        rc, stdout, stderr, attempts = run_cmd(
            ["echo", "test"], timeout=30, capture_stdout=False
        )

        assert rc == 0
        assert stdout == ""  # Not captured
        assert stderr == ""
        assert attempts == 1


def test_run_cmd_success_with_capture():
    """Test run_cmd successful execution with stdout capture."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="command output", stderr="some warning"
        )

        rc, stdout, stderr, attempts = run_cmd(
            ["trivy", "scan"], timeout=30, capture_stdout=True
        )

        assert rc == 0
        assert stdout == "command output"
        assert stderr == "some warning"
        assert attempts == 1


def test_run_cmd_with_ok_rcs_accepts_nonzero():
    """Test run_cmd accepts non-zero exit codes in ok_rcs tuple."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1, stdout="findings detected", stderr=""
        )

        rc, stdout, stderr, attempts = run_cmd(
            ["semgrep", "scan"],
            timeout=30,
            capture_stdout=True,
            ok_rcs=(0, 1, 2),  # Semgrep uses 0=clean, 1=findings, 2=errors
        )

        assert rc == 1
        assert stdout == "findings detected"
        assert attempts == 1


# ========== Category 6: run_cmd() Timeout Tests ==========


def test_run_cmd_timeout_expired():
    """Test run_cmd handles TimeoutExpired exception."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["slow-command"], timeout=5
        )

        rc, stdout, stderr, attempts = run_cmd(["slow-command"], timeout=5, retries=0)

        assert rc == 124  # Timeout exit code
        assert stdout == ""
        assert "timed out" in stderr or "TimeoutExpired" in stderr
        assert attempts == 1


def test_run_cmd_timeout_with_retry():
    """Test run_cmd retries after timeout, then succeeds."""
    with (
        patch("subprocess.run") as mock_run,
        patch("time.sleep"),
    ):  # Skip actual sleep delays
        # First attempt: timeout, second attempt: success
        mock_run.side_effect = [
            subprocess.TimeoutExpired(cmd=["cmd"], timeout=5),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        rc, stdout, stderr, attempts = run_cmd(["cmd"], timeout=5, retries=1)

        assert rc == 0
        assert attempts == 2


# ========== Category 7: run_cmd() Retry Logic Tests ==========


def test_run_cmd_retries_on_failure_then_success():
    """Test run_cmd retries command failures, succeeds on second attempt."""
    with patch("subprocess.run") as mock_run, patch("time.sleep"):  # Skip actual sleep
        # First attempt: fail (rc=1), second attempt: success (rc=0)
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="error"),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        rc, stdout, stderr, attempts = run_cmd(["flaky-tool"], timeout=30, retries=1)

        assert rc == 0
        assert attempts == 2


def test_run_cmd_retries_exhausted():
    """Test run_cmd returns failure after exhausting retries."""
    with patch("subprocess.run") as mock_run, patch("time.sleep"):
        # All attempts fail
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="error"),
            MagicMock(returncode=1, stdout="", stderr="error"),
            MagicMock(returncode=1, stdout="", stderr="error"),
        ]

        rc, stdout, stderr, attempts = run_cmd(
            ["unreliable-tool"],
            timeout=30,
            retries=2,  # 1 initial + 2 retries = 3 total
        )

        assert rc == 1
        assert attempts == 3


def test_run_cmd_no_retry_on_acceptable_rc():
    """Test run_cmd doesn't retry when returncode in ok_rcs."""
    with patch("subprocess.run") as mock_run:
        # First call returns 1 (acceptable), should NOT retry
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

        rc, stdout, stderr, attempts = run_cmd(
            ["semgrep"], timeout=30, retries=2, ok_rcs=(0, 1)
        )

        assert rc == 1
        assert attempts == 1  # No retry
        assert mock_run.call_count == 1


# ========== Category 8: run_cmd() Exception Handling Tests ==========


def test_run_cmd_file_not_found_error():
    """Test run_cmd handles FileNotFoundError (command not in PATH)."""
    with patch("subprocess.run") as mock_run, patch("logging.getLogger") as mock_logger:
        mock_run.side_effect = FileNotFoundError("command not found")
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        rc, stdout, stderr, attempts = run_cmd(
            ["nonexistent-tool"], timeout=30, retries=0
        )

        assert rc == 1
        assert stdout == ""
        assert "command not found" in stderr or "FileNotFoundError" in stderr
        assert attempts == 1

        # Verify error logged
        mock_log.error.assert_called_once()


def test_run_cmd_permission_error():
    """Test run_cmd handles PermissionError."""
    with patch("subprocess.run") as mock_run, patch("logging.getLogger") as mock_logger:
        mock_run.side_effect = PermissionError("permission denied")
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        rc, stdout, stderr, attempts = run_cmd(
            ["restricted-tool"], timeout=30, retries=0
        )

        assert rc == 1
        assert "permission denied" in stderr or "PermissionError" in stderr
        assert attempts == 1

        mock_log.error.assert_called_once()


def test_run_cmd_os_error():
    """Test run_cmd handles generic OSError."""
    with patch("subprocess.run") as mock_run, patch("logging.getLogger") as mock_logger:
        mock_run.side_effect = OSError("system error")
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        rc, stdout, stderr, attempts = run_cmd(["tool"], timeout=30, retries=0)

        assert rc == 1
        assert "system error" in stderr or "OSError" in stderr
        assert attempts == 1


def test_run_cmd_called_process_error():
    """Test run_cmd handles CalledProcessError."""
    with patch("subprocess.run") as mock_run, patch("logging.getLogger") as mock_logger:
        error = subprocess.CalledProcessError(
            returncode=2, cmd=["tool"], stderr="tool error"
        )
        mock_run.side_effect = error
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        rc, stdout, stderr, attempts = run_cmd(["tool"], timeout=30, retries=0)

        assert rc == 2
        assert "non-zero exit status" in stderr or "CalledProcessError" in stderr
        assert attempts == 1

        # Verify debug log
        mock_log.debug.assert_called_once()


def test_run_cmd_unexpected_exception():
    """Test run_cmd handles unexpected exceptions."""
    with patch("subprocess.run") as mock_run, patch("logging.getLogger") as mock_logger:
        mock_run.side_effect = RuntimeError("unexpected error")
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        rc, stdout, stderr, attempts = run_cmd(["tool"], timeout=30, retries=0)

        assert rc == 1
        assert "unexpected error" in stderr or "RuntimeError" in stderr
        assert attempts == 1

        # Verify error logged with exc_info
        mock_log.error.assert_called_once()
        call_args = mock_log.error.call_args
        assert call_args[1].get("exc_info") is True


# ========== Category 9: run_cmd() Sleep Delays Between Retries ==========


def test_run_cmd_sleep_between_retries():
    """Test run_cmd sleeps between retry attempts."""
    with patch("subprocess.run") as mock_run, patch("time.sleep") as mock_sleep:
        # Fail twice, succeed on third
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr=""),
            MagicMock(returncode=1, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        rc, stdout, stderr, attempts = run_cmd(["tool"], timeout=30, retries=2)

        assert rc == 0
        assert attempts == 3

        # Verify sleep called between retries (not after success)
        assert mock_sleep.call_count == 2

        # Sleep durations: min(1.0 * (i+1), 3.0) where i=0,1
        # First sleep: min(1.0, 3.0) = 1.0
        # Second sleep: min(2.0, 3.0) = 2.0
        sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
        assert sleep_calls == [1.0, 2.0]


# ========== Category 10: TOOL_INSTALL_HINTS Coverage ==========


def test_tool_install_hints_complete():
    """Test TOOL_INSTALL_HINTS contains all supported tools."""
    expected_tools = [
        "trufflehog",
        "semgrep",
        "trivy",
        "syft",
        "checkov",
        "hadolint",
        "nuclei",
        "bandit",
        "noseyparker",
        "zap",
        "falco",
        "afl++",
    ]

    for tool in expected_tools:
        assert tool in TOOL_INSTALL_HINTS
        hint = TOOL_INSTALL_HINTS[tool]
        assert "Install" in hint or "see" in hint
