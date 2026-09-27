"""
Tests for IaC Scanner

Tests the iac_scanner module with various scenarios. Each test resolves its
tools explicitly: the scan loop only reads a result for a tool it planned.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.iac_scanner import scan_iac_file
from scripts.core.scan_timings import State
from scripts.core.tool_runner import ToolResult


def _all_found(tool_name):
    return f"/usr/bin/{tool_name}"


def _scan(tmp_path, results, tools, find=_all_found, **kw):
    iac_path = kw.pop("iac_path", None)
    if iac_path is None:
        iac_path = tmp_path / "main.tf"
        iac_path.write_text('resource "aws_s3_bucket" "b" {}', encoding="utf-8")
    with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = results
        identifier, rows = scan_iac_file(
            iac_type=kw.pop("iac_type", "terraform"),
            iac_path=iac_path,
            results_dir=kw.pop("results_dir", tmp_path),
            tools=tools,
            timeout=600,
            retries=kw.pop("retries", 0),
            per_tool_config=kw.pop("per_tool_config", {}),
            allow_missing_tools=kw.pop("allow_missing_tools", False),
            find_tool_func=find,
            **kw,
        )
    return identifier, rows, MockRunner


def _defs(MockRunner):
    MockRunner.assert_called_once()
    args, kwargs = MockRunner.call_args
    return kwargs.get("tools") or (args[0] if args else [])


class TestIacScanner:
    """Test IaC scanner functionality"""

    def test_scan_iac_basic(self, tmp_path):
        identifier, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(tool="checkov", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ],
            ["checkov", "trivy"],
        )

        assert identifier == "terraform:main.tf"
        assert rows["checkov"].state is State.RAN
        assert rows["trivy"].state is State.RAN

    def test_checkov_runs_on_a_file_target_with_no_tree_to_walk(self, tmp_path):
        """checkov's content trigger reads a tree. An IaC file target has none,
        and the file is itself checkov's content: it must run, not be skipped
        as `no IaC or workflow files` (a defect caught while writing B3)."""
        _, rows, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="checkov", status="success", attempts=1)],
            ["checkov"],
        )

        assert rows["checkov"].state is State.RAN
        (checkov_def,) = _defs(MockRunner)
        assert checkov_def.command[1:3] == ["-f", str(tmp_path / "main.tf")]

    def test_scan_iac_with_retries(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(tool="checkov", status="success", attempts=2),
                ToolResult(tool="trivy", status="success", attempts=1),
            ],
            ["checkov", "trivy"],
            retries=1,
        )

        assert rows["checkov"].state is State.RAN
        assert rows["checkov"].attempts == 2

    def test_scan_iac_uses_filename_as_dirname(self, tmp_path):
        """Test that IaC file stem is used for directory name"""
        iac_file = tmp_path / "my-infrastructure.tf"
        iac_file.write_text('resource "null_resource" "test" {}')
        iac_results_dir = tmp_path / "individual-iac"

        _scan(
            tmp_path,
            [ToolResult(tool="checkov", status="success", attempts=1)],
            ["checkov"],
            iac_path=iac_file,
            results_dir=iac_results_dir,
        )

        assert (iac_results_dir / "my-infrastructure").exists()

    def test_scan_iac_with_tool_timeout_override(self, tmp_path):
        iac_file = tmp_path / "deployment.yaml"
        iac_file.write_text("apiVersion: v1\nkind: Pod")

        _, _, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy"],
            find=lambda t: f"/usr/bin/{t}" if t == "trivy" else None,
            iac_path=iac_file,
            iac_type="k8s",
            per_tool_config={
                "trivy": {"timeout": 900, "flags": ["--severity", "HIGH"]}
            },
        )

        trivy_def = next((t for t in _defs(MockRunner) if t.name == "trivy"), None)
        assert trivy_def is not None, "trivy tool definition not found"
        assert trivy_def.timeout == 900
        assert "--severity" in trivy_def.command
        assert "HIGH" in trivy_def.command
        assert trivy_def.command[1] == "config"

    def test_scan_iac_tool_failure(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [
                ToolResult(
                    tool="checkov", status="error", returncode=3, failure="crash"
                ),
                ToolResult(tool="trivy", status="success", attempts=1),
            ],
            ["checkov", "trivy"],
        )

        assert rows["checkov"].label == "failed:unaccepted exit code"
        assert rows["trivy"].state is State.RAN

    def test_scan_iac_only_checkov(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="checkov", status="success", attempts=1)],
            ["checkov"],
        )

        assert list(rows) == ["checkov"]

    def test_a_repository_tool_is_skipped_on_a_file(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="checkov", status="success", attempts=1)],
            ["checkov", "hadolint", "nuclei"],
        )

        assert rows["hadolint"].label == "skipped:not for this target type"
        assert rows["nuclei"].label == "skipped:needs --url"

    def test_scan_iac_creates_output_directory(self, tmp_path):
        iac_file = tmp_path / "network.tf"
        iac_file.write_text('resource "aws_vpc" "main" {}')
        iac_results_dir = tmp_path / "individual-iac"

        _scan(
            tmp_path,
            [ToolResult(tool="checkov", status="success", attempts=1)],
            ["checkov"],
            iac_path=iac_file,
            results_dir=iac_results_dir,
        )

        assert (iac_results_dir / "network").exists()

    def test_allow_missing_tools_writes_stubs(self, tmp_path):
        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, str(output_path)))
            output_path.write_text("{}")

        _, rows, _ = _scan(
            tmp_path,
            [],
            ["checkov", "trivy"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=mock_write_stub,
        )

        assert len(stub_calls) == 2
        assert rows["checkov"].label == "skipped:not installed"
        assert rows["trivy"].label == "skipped:not installed"

    def test_per_tool_flags_applied(self, tmp_path):
        iac_file = tmp_path / "stack.yaml"
        iac_file.write_text("AWSTemplateFormatVersion: 2010-09-09")

        _, _, MockRunner = _scan(
            tmp_path,
            [
                ToolResult(tool="checkov", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ],
            ["checkov", "trivy"],
            iac_path=iac_file,
            iac_type="cloudformation",
            per_tool_config={
                "checkov": {"flags": ["--framework", "cloudformation"]},
                "trivy": {"flags": ["--severity", "HIGH,CRITICAL"]},
            },
        )

        defs = _defs(MockRunner)
        checkov_def = next((t for t in defs if t.name == "checkov"), None)
        assert checkov_def is not None
        assert "--framework" in checkov_def.command
        trivy_def = next((t for t in defs if t.name == "trivy"), None)
        assert trivy_def is not None
        assert "--severity" in trivy_def.command

    def test_trivy_config_drops_a_flag_it_rejects(self, tmp_path):
        """`trivy config` rejects --no-progress at parse time (TRIVY_UNSUPPORTED_FLAGS)."""
        _, _, MockRunner = _scan(
            tmp_path,
            [ToolResult(tool="trivy", status="success", attempts=1)],
            ["trivy"],
            per_tool_config={
                "trivy": {"flags": ["--no-progress", "--severity", "HIGH"]}
            },
        )

        (trivy_def,) = _defs(MockRunner)
        assert "--no-progress" not in trivy_def.command
        assert "--severity" in trivy_def.command

    def test_scan_iac_custom_find_tool_func(self, tmp_path):
        _, rows, _ = _scan(
            tmp_path,
            [ToolResult(tool="checkov", status="success", attempts=1)],
            ["checkov", "trivy"],
            find=lambda t: f"/custom/{t}" if t == "checkov" else None,
            allow_missing_tools=True,
        )

        assert rows["checkov"].state is State.RAN
        assert rows["trivy"].label == "skipped:not installed"

    def test_scan_iac_custom_write_stub_func(self, tmp_path):
        stub_calls = []

        _scan(
            tmp_path,
            [],
            ["checkov", "trivy"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=lambda tool, path: stub_calls.append((tool, path)),
        )

        assert len(stub_calls) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
