"""
Tests for URL Scanner

Tests the url_scanner module with various scenarios. Each test resolves its
tools explicitly: the scan loop only reads a result for a tool it planned.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.url_scanner import scan_url
from scripts.core.scan_timings import Reason, State
from scripts.core.tool_runner import ToolResult

ZAP = str(Path("/opt/zap/zap.sh"))


def _found(tool_name):
    if tool_name in ("zap.sh", "zap"):
        return ZAP
    return f"/usr/bin/{tool_name}"


def _scan(tmp_path, results, tools, find=_found, **kw):
    with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = results
        url, rows = scan_url(
            url=kw.pop("url", "https://example.com"),
            results_dir=kw.pop("results_dir", tmp_path),
            tools=tools,
            timeout=600,
            retries=kw.pop("retries", 0),
            per_tool_config=kw.pop("per_tool_config", {}),
            allow_missing_tools=kw.pop("allow_missing_tools", False),
            find_tool_func=find,
            **kw,
        )
    return url, rows, MockRunner


def _defs(MockRunner):
    MockRunner.assert_called_once()
    args, kwargs = MockRunner.call_args
    return kwargs.get("tools") or (args[0] if args else [])


class TestUrlScanner:
    """Test URL scanner functionality"""

    def test_scan_url_basic(self, tmp_path):
        url, rows, _ = _scan(
            tmp_path, [ToolResult(tool="zap", status="success", attempts=1)], ["zap"]
        )

        assert url == "https://example.com"
        assert rows["zap"].state is State.RAN

    def test_scan_url_with_retries(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=2)],
            ["zap"],
            retries=1,
        )

        assert rows["zap"].attempts == 2

    def test_scan_url_sanitizes_domain(self, tmp_path):
        web_results_dir = tmp_path / "individual-web"

        _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=1)],
            ["zap"],
            url="https://sub.example.com:8080/path",
            results_dir=web_results_dir,
        )

        assert (web_results_dir / "sub.example.com_8080").exists()

    def test_scan_url_file_protocol_rejected(self, tmp_path):
        """file:// URLs are rejected (MEDIUM-001 security fix)"""
        test_file = tmp_path / "test.html"
        test_file.write_text("<html><body>Test</body></html>")

        with pytest.raises(ValueError) as exc_info:
            scan_url(
                url=f"file://{test_file}",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert "Invalid URL scheme 'file'" in str(exc_info.value)
        assert "Use --repo for local filesystem scanning" in str(exc_info.value)

    def test_scan_url_ftp_protocol_rejected(self, tmp_path):
        with pytest.raises(ValueError) as exc_info:
            scan_url(
                url="ftp://ftp.example.com/file.txt",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert "Invalid URL scheme 'ftp'" in str(exc_info.value)
        assert "Only HTTP(S) URLs are supported" in str(exc_info.value)

    def test_scan_url_with_tool_timeout_override(self, tmp_path):
        _, _, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=1)],
            ["zap"],
            per_tool_config={
                "zap": {"timeout": 1200, "flags": ["-config", "api.disablekey=true"]}
            },
        )

        zap_def = next((t for t in _defs(MockRunner) if t.name == "zap"), None)
        assert zap_def is not None, "zap tool definition not found"
        assert zap_def.timeout == 1200
        assert "-config" in zap_def.command
        assert "api.disablekey=true" in zap_def.command

    def test_zap_runs_from_its_own_directory_with_an_absolute_output(
        self, tmp_path, monkeypatch
    ):
        """zap.bat resolves its jar against the working directory: from anywhere
        else it fails "Unable to access jarfile zap-2.17.0.jar" (measured on
        Windows, 2026-09-25). Its output path must then be absolute, or zap
        writes it under its own directory."""
        # The relative results directory is the point; it must not land in the
        # repository the suite runs from.
        monkeypatch.chdir(tmp_path)
        _, _, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=1)],
            ["zap"],
            results_dir=Path("relative-results"),
        )
        (zap_def,) = _defs(MockRunner)

        assert zap_def.cwd == Path(ZAP).parent
        out = zap_def.command[zap_def.command.index("-quickout") + 1]
        assert Path(out).is_absolute()
        assert out == str(
            (Path("relative-results") / "example.com" / "zap.json").absolute()
        )

    def test_nuclei_writes_jsonl(self, tmp_path):
        """nuclei 3 dropped `-json`: "flag provided but not defined: -json",
        exit 2, on every URL scan (measured 3.11.0). It is `-jsonl` now."""
        _, _, MockRunner = _scan(
            tmp_path, [ToolResult(tool="nuclei", status="success")], ["nuclei"]
        )
        (nuclei_def,) = _defs(MockRunner)

        assert "-jsonl" in nuclei_def.command
        assert "-json" not in nuclei_def.command

    def test_scan_url_tool_failure(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="zap", status="error", returncode=3, failure="crash")],
            ["zap"],
        )

        assert rows["zap"].label == "failed:unaccepted exit code"
        assert rows["zap"].exit_code == 3

    def test_scan_url_creates_output_directory(self, tmp_path):
        web_results_dir = tmp_path / "individual-web"

        _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=1)],
            ["zap"],
            url="https://test.example.com",
            results_dir=web_results_dir,
        )

        assert (web_results_dir / "test.example.com").exists()

    def test_allow_missing_tools_writes_stubs(self, tmp_path):
        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, str(output_path)))
            output_path.write_text("{}")

        _, rows, _ = _scan(
            tmp_path,
            [],
            ["zap", "nuclei"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=mock_write_stub,
        )

        assert len(stub_calls) == 2
        assert rows["zap"].label == "skipped:not installed"
        assert rows["nuclei"].label == "skipped:not installed"

    def test_a_repository_tool_is_skipped_on_a_url(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=1)],
            ["zap", "semgrep"],
        )

        assert rows["semgrep"].label == "skipped:not for this target type"

    def test_per_tool_flags_applied(self, tmp_path):
        _, _, MockRunner = _scan(
            tmp_path,
            [
                ToolResult(tool="zap", status="success", attempts=1),
                ToolResult(tool="nuclei", status="success", attempts=1),
            ],
            ["zap", "nuclei"],
            url="https://test.example.com",
            per_tool_config={
                "zap": {"flags": ["-config", "spider.maxDuration=5"]},
                "nuclei": {"flags": ["-severity", "critical,high"]},
            },
        )

        defs = _defs(MockRunner)
        zap_def = next((t for t in defs if t.name == "zap"), None)
        assert zap_def is not None
        assert "spider.maxDuration=5" in zap_def.command
        nuclei_def = next((t for t in defs if t.name == "nuclei"), None)
        assert nuclei_def is not None
        assert "critical,high" in nuclei_def.command

    def test_scan_url_zap_command_selection(self, tmp_path):
        """zap.sh first, then zap, as its binary."""
        _, _, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="zap", status="success", attempts=1)],
            ["zap"],
            find=lambda t: "/usr/share/zap/zap.sh" if t == "zap.sh" else None,
        )

        zap_def = next((t for t in _defs(MockRunner) if t.name == "zap"), None)
        assert zap_def is not None
        assert "/usr/share/zap/zap.sh" in zap_def.command[0]

    def test_scan_url_tool_not_found_error(self, tmp_path):
        """A tool that resolved and then failed to exec is NOT a success.

        Reaching this branch means zap resolved and then could not be executed,
        which is a bug (a resolver returning a non-path, or a binary vanishing
        mid-scan), not something ``--allow-missing-tools`` consents to.
        Recording it clean is what let a machine with no yara at all report a
        successful malware scan.
        """
        _, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(
                    tool="zap",
                    status="error",
                    returncode=-1,
                    duration=0.1,
                    error_message="Tool not found: zap",
                    failure="missing_tool",
                ),
            ],
            ["zap"],
            allow_missing_tools=True,
        )

        assert rows["zap"].state is State.FAILED
        assert rows["zap"].reason is Reason.NOT_FOUND_AT_RUN


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
