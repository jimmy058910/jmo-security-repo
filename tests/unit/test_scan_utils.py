"""Unit tests for scan_utils.py.

Tests cover:
- tool_exists() with found and missing tools
- write_stub() for all supported tool formats (JSON and NDJSON)
"""

import json
from unittest.mock import MagicMock, patch

from scripts.cli.scan_utils import TOOL_INSTALL_HINTS, tool_exists, write_stub

# ========== Category 1: tool_exists() Tests ==========


def test_tool_exists_found():
    """Test tool_exists returns True when the resolver finds the tool."""
    with patch("scripts.core.tool_utils.find_tool") as mock_find:
        mock_find.return_value = "/usr/bin/trivy"

        result = tool_exists("trivy")

        assert result is True
        mock_find.assert_called_once_with("trivy")


def test_tool_exists_not_found_with_hint():
    """Test tool_exists returns False and logs hint when tool not found.

    Patches `find_tool`, the seam `tool_exists` actually depends on (#1105).
    This used to patch `shutil.which`, but `find_tool` also searches the
    isolated venvs, `~/.jmo/bin/` and the interpreter's own `Scripts/`, so on
    any machine with a semgrep isolated venv the test failed with
    `assert True is False` while CI stayed green only because semgrep is
    absent there. A test that inherits its precondition from the host is not
    stating one.
    """
    with (
        patch("scripts.core.tool_utils.find_tool") as mock_find,
        patch("logging.getLogger") as mock_logger,
    ):
        mock_find.return_value = None
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        result = tool_exists("semgrep")

        assert result is False
        mock_find.assert_called_once_with("semgrep")

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


def test_write_stub_grype(tmp_path):
    """Test write_stub creates correct empty stub for grype.

    Bug #2 fix: grype was missing from stub dictionary, causing
    grype failures to produce {} instead of {"matches": []}.
    """
    out_path = tmp_path / "grype.json"

    write_stub("grype", out_path)

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


class TestFilterTrivyFlags:
    """jmo.yml configures flags per tool; trivy's flag surface is per subcommand.

    All four shipped profiles set --no-progress, which `trivy config` rejects
    fatally at argument parsing - so every IaC scan produced 0 findings where
    the same file and tool yield 12 (#804).
    """

    def test_no_progress_is_dropped_for_trivy_config(self):
        from scripts.cli.scan_utils import filter_trivy_flags

        assert filter_trivy_flags("config", ["--no-progress"]) == []

    def test_other_subcommands_keep_it(self):
        from scripts.cli.scan_utils import filter_trivy_flags

        for subcommand in ("fs", "image", "k8s"):
            assert filter_trivy_flags(subcommand, ["--no-progress"]) == [
                "--no-progress"
            ]

    def test_supported_flags_survive_and_keep_their_values(self):
        """--scanners is accepted by every subcommand, including config, and
        takes a value - dropping a flag must never orphan its argument."""
        from scripts.cli.scan_utils import filter_trivy_flags

        flags = ["--no-progress", "--scanners", "vuln,secret,misconfig"]

        assert filter_trivy_flags("config", flags) == [
            "--scanners",
            "vuln,secret,misconfig",
        ]

    def test_the_drop_is_announced(self, caplog):
        import logging

        from scripts.cli.scan_utils import filter_trivy_flags

        with caplog.at_level(logging.WARNING):
            filter_trivy_flags("config", ["--no-progress"])

        assert "--no-progress" in caplog.text

    def test_unknown_subcommand_is_left_alone(self):
        from scripts.cli.scan_utils import filter_trivy_flags

        assert filter_trivy_flags("rootfs", ["--no-progress"]) == ["--no-progress"]
