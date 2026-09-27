"""
Tests for Container Image Scanner

Tests the image_scanner module with various scenarios. Each test resolves its
tools explicitly: the scan loop only reads a result for a tool it planned, so
a test that let the real `find_tool` decide would depend on the machine.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.image_scanner import scan_image
from scripts.core.scan_timings import Reason, State
from scripts.core.tool_runner import ToolResult


def _all_found(tool_name):
    return f"/usr/bin/{tool_name}"


def _scan(tmp_path, results, tools, find=_all_found, **kw):
    with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = results
        image, rows = scan_image(
            image=kw.pop("image", "nginx:latest"),
            results_dir=kw.pop("results_dir", tmp_path),
            tools=tools,
            timeout=600,
            retries=kw.pop("retries", 0),
            per_tool_config=kw.pop("per_tool_config", {}),
            allow_missing_tools=kw.pop("allow_missing_tools", False),
            find_tool_func=find,
            **kw,
        )
    return image, rows, MockRunner


def _defs(MockRunner):
    MockRunner.assert_called_once()
    args, kwargs = MockRunner.call_args
    return kwargs.get("tools") or (args[0] if args else [])


class TestImageScanner:
    """Test image scanner functionality"""

    def test_scan_image_basic(self, tmp_path):
        """Test basic image scanning with trivy and syft"""
        image, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(tool="trivy", status="success", attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
            ],
            ["trivy", "syft"],
        )

        assert image == "nginx:latest"
        assert rows["trivy"].state is State.RAN
        assert rows["syft"].state is State.RAN
        assert rows["trivy"].attempts == 1

    def test_scan_image_with_retries(self, tmp_path):
        """The retry count reaches the row."""
        _, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(tool="trivy", status="success", attempts=2),  # Retried
                ToolResult(tool="syft", status="success", attempts=1),
            ],
            ["trivy", "syft"],
            retries=1,
        )

        assert rows["trivy"].state is State.RAN
        assert rows["trivy"].attempts == 2

    def test_scan_image_sanitizes_name(self, tmp_path):
        """Test that image names are sanitized for directory names"""
        image_results_dir = tmp_path / "individual-images"

        _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy"],
            image="registry.example.com:5000/my-app:v1.2.3",
            results_dir=image_results_dir,
        )

        expected_dir = image_results_dir / "registry.example.com_5000_my-app_v1.2.3"
        assert expected_dir.exists()

    def test_scan_image_with_tool_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        _, _, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy"],
            find=lambda t: f"/usr/bin/{t}" if t == "trivy" else None,
            per_tool_config={"trivy": {"timeout": 1200, "flags": ["--no-progress"]}},
        )

        trivy_def = next((t for t in _defs(MockRunner) if t.name == "trivy"), None)
        assert trivy_def is not None, "trivy tool definition not found"
        assert trivy_def.timeout == 1200
        assert "--no-progress" in trivy_def.command

    def test_scan_image_tool_failure(self, tmp_path):
        """A crash fails its row with the exit code; the other tool still ran."""
        _, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(
                    tool="trivy",
                    status="error",
                    returncode=2,
                    attempts=1,
                    failure="crash",
                ),
                ToolResult(tool="syft", status="success", attempts=1),
            ],
            ["trivy", "syft"],
        )

        assert rows["trivy"].label == "failed:unaccepted exit code"
        assert rows["trivy"].exit_code == 2
        assert rows["syft"].state is State.RAN

    def test_scan_image_only_trivy(self, tmp_path):
        """Only requested tools get a row."""
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy"],
        )

        assert list(rows) == ["trivy"]

    def test_a_tool_that_reads_no_image_is_skipped_not_dropped(self, tmp_path):
        """#1227's class on an image target: semgrep reads repositories, so it
        gets a `skipped` row rather than vanishing."""
        _, rows, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy", "semgrep", "zap"],
        )

        assert rows["semgrep"].label == "skipped:not for this target type"
        assert rows["zap"].label == "skipped:needs --url"
        assert [d.name for d in _defs(MockRunner)] == ["trivy"]

    def test_scan_image_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        image_results_dir = tmp_path / "individual-images"

        _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy"],
            image="alpine:latest",
            results_dir=image_results_dir,
        )

        assert (image_results_dir / "alpine_latest").exists()

    def test_allow_missing_tools_writes_stubs(self, tmp_path):
        """Test that allow_missing_tools writes stubs for missing tools"""
        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, str(output_path)))
            output_path.write_text("{}")

        _, rows, _ = _scan(
            tmp_path,
            [],
            ["trivy", "syft"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=mock_write_stub,
        )

        assert len(stub_calls) == 2
        assert any("trivy" in path for _, path in stub_calls)
        assert any("syft" in path for _, path in stub_calls)
        # Stubbed, so neither ran (#825): the row says so, not the file.
        assert rows["trivy"].label == "skipped:not installed"
        assert rows["syft"].label == "skipped:not installed"

    def test_missing_without_the_flag_fails_and_writes_no_stub(self, tmp_path):
        stub_calls = []
        _, rows, _ = _scan(
            tmp_path,
            [],
            ["trivy"],
            find=lambda t: None,
            write_stub_func=lambda tool, path: stub_calls.append(tool),
        )

        assert rows["trivy"].state is State.FAILED
        assert rows["trivy"].reason is Reason.NOT_INSTALLED
        assert stub_calls == []

    def test_per_tool_flags_applied(self, tmp_path):
        """Test that per_tool_config flags are correctly applied"""
        _, _, MockRunner = _scan(
            tmp_path,
            [
                ToolResult(tool="trivy", status="success", attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
            ],
            ["trivy", "syft"],
            image="alpine:3.18",
            per_tool_config={
                "trivy": {"flags": ["--severity", "CRITICAL,HIGH"]},
                "syft": {"flags": ["-o", "cyclonedx-json"]},
            },
        )

        defs = _defs(MockRunner)
        trivy_def = next((t for t in defs if t.name == "trivy"), None)
        assert trivy_def is not None
        assert "--severity" in trivy_def.command
        syft_def = next((t for t in defs if t.name == "syft"), None)
        assert syft_def is not None
        assert "-o" in syft_def.command

    def test_scan_image_syft_stdout_capture(self, tmp_path):
        """syft prints its SBOM; the loop writes it to syft.json."""
        out = tmp_path / "nginx_latest" / "syft.json"
        _, rows, MockRunner = _scan(
            tmp_path,
            [
                ToolResult(
                    tool="syft",
                    status="success",
                    stdout='{"artifacts": [{"name": "nginx"}]}',
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=out,
                    capture_stdout=True,
                ),
            ],
            ["syft"],
        )

        syft_def = next((t for t in _defs(MockRunner) if t.name == "syft"), None)
        assert syft_def is not None
        assert syft_def.capture_stdout is True
        assert out.read_text(encoding="utf-8") == '{"artifacts": [{"name": "nginx"}]}'
        assert rows["syft"].seconds == pytest.approx(5.0)

    def test_scan_image_custom_find_tool_func(self, tmp_path):
        """Test using custom find_tool_func"""
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy", "syft"],
            find=lambda t: f"/custom/path/{t}" if t == "trivy" else None,
            allow_missing_tools=True,
        )

        assert rows["trivy"].state is State.RAN
        assert rows["syft"].label == "skipped:not installed"

    def test_scan_image_custom_write_stub_func(self, tmp_path):
        """Test using custom write_stub_func"""
        stub_calls = []

        _scan(
            tmp_path,
            [],
            ["trivy", "syft"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=lambda tool, path: stub_calls.append((tool, path)),
        )

        assert len(stub_calls) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
