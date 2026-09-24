"""
Tests for Repository Scanner

Tests the repository_scanner module with various scenarios.
"""

import ast
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs import repository_scanner
from scripts.cli.scan_jobs.repository_scanner import scan_repository
from scripts.cli.scan_utils import (
    NOT_ATTEMPTED_KEY,
    NOT_ATTEMPTED_MISSING,
    NOT_ATTEMPTED_NOTHING_APPLICABLE,
    not_attempted_tools,
)
from scripts.core.tool_registry import (
    TOOL_MATRIX,
    TOOL_SCAN_TYPES,
    filter_tools_for_scan_type,
)


class TestRepositoryScanner:
    """Test repository scanner functionality"""

    def test_scan_repository_basic(self, tmp_path):
        """Test basic repository scanning with trufflehog and semgrep"""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "README.md").write_text("# Test Repo")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="semgrep", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert name == "test-repo"
            assert statuses["trufflehog"] is True
            assert statuses["semgrep"] is True

    def test_scan_repository_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        repo = tmp_path / "my-app"
        repo.mkdir()

        # Mock tool_exists to return True for trivy
        def mock_find_tool(tool_name):
            if tool_name == "trivy":
                return "/usr/bin/trivy"
            return None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "trivy": {"timeout": 1200, "flags": ["--severity", "HIGH,CRITICAL"]}
            }

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None, "trivy tool definition not found"
            assert trivy_def.timeout == 1200
            assert "--severity" in trivy_def.command

    def test_scan_repository_multiple_tools(self, tmp_path):
        """Test scanning with multiple tools"""
        repo = tmp_path / "multi-tool-repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep", "trivy", "syft"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert len(statuses) == 4
            assert all(
                statuses[tool] for tool in ["trufflehog", "semgrep", "trivy", "syft"]
            )

    def test_scan_repository_with_retries(self, tmp_path):
        """Test repository scanning with retries"""
        repo = tmp_path / "retry-repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="semgrep", status="success", attempts=3),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep"],
                timeout=600,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["semgrep"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["semgrep"] == 3

    def test_scan_repository_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        repo = tmp_path / "output-test"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check directory was created with repo name
            assert (tmp_path / "output-test").exists()

    def test_zap_builds_no_command_even_with_web_files_and_its_helper(self, tmp_path):
        """ZAP takes no repository target, however inviting the tree looks.

        This asserted the opposite until #1159. The invocation it verified --
        `zap-baseline.py -t <a file path>` -- exits 3 on every real run, because
        `-t` takes a URL. Kept rather than deleted, and inverted, because this
        is the exact input that used to build the broken command: web files
        present AND `zap-baseline.py` resolvable.
        """
        repo = tmp_path / "web-app-repo"
        repo.mkdir()
        (repo / "index.html").write_text("<html><body>Test</body></html>")
        (repo / "app.js").write_text("console.log('test');")

        def mock_tool_exists(tool_name):
            # ZAP requires either zap-baseline.py OR docker to be available
            return tool_name in ("zap-baseline.py", "docker")

        def mock_find_tool(tool_name):
            # Return a fake path for zap-baseline.py
            if tool_name == "zap-baseline.py":
                return "/usr/bin/zap-baseline.py"
            return None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            # No ToolResult for zap: it is not scheduled on a repository
            # target, so a runner that returns one is asserting something the
            # scanner cannot produce -- and it would write statuses["zap"] =
            # True over the False record_not_attempted just made.
            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            zap_def = next((t for t in tool_defs if t.name == "zap"), None)

            assert zap_def is None, "zap must not be given a repository target"
            assert statuses.get("zap") is not True, (
                "a tool that never ran must not be recorded as a success (#825)"
            )
            assert (statuses.get(NOT_ATTEMPTED_KEY) or {}).get("zap") == (
                NOT_ATTEMPTED_NOTHING_APPLICABLE
            )

    def test_zap_stub_when_no_web_files(self, tmp_path):
        """Test ZAP writes stub when no web files found"""
        repo = tmp_path / "non-web-repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')")

        def mock_find_tool(tool_name):
            if tool_name == "zap-baseline.py":
                return "/usr/bin/zap-baseline.py"
            return None

        def mock_write_stub(tool_name, output_path):
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # Stubbed, not run. `False` plus a `__not_attempted__` record is
            # the point of #825: an empty zap report from a scan that never
            # looked is not a clean web scan. This assertion read `is True`,
            # which pinned the defect as the contract.
            assert statuses["zap"] is False
            assert not_attempted_tools(statuses) == ["zap"]
            # No tool definitions should be created (stub written directly)
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            assert not any(t.name == "zap" for t in tool_defs)

    def test_every_repo_tool_in_the_matrix_runs(self, tmp_path):
        """Every matrix tool that applies to a repository runs when installed.

        The list is the matrix's repository slice rather than a literal, so a
        tool added to or removed from TOOL_MATRIX is covered without editing
        this test. The repo carries a Dockerfile, a shell script and a Go file
        so hadolint, shellcheck and gosec -- which build no command without
        matching content -- have something to scan. zap is the one repository
        tool that never runs on a directory (#1159).
        """
        from scripts.core.tool_runner import ToolResult

        repo = tmp_path / "matrix-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "Dockerfile").write_text("FROM ubuntu\n", encoding="utf-8")
        (repo / "build.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
        (repo / "main.go").write_text("package main\n", encoding="utf-8")

        tools = filter_tools_for_scan_type(list(TOOL_MATRIX), "repo")
        assert tools, "the matrix has no repository tools"

        def runner_for(tools, **_kwargs):
            # Succeed exactly the definitions the scanner built. A canned
            # result for a tool it never scheduled would set a status the
            # scanner itself could not have produced.
            runner = MagicMock()
            runner.run_all_parallel.return_value = [
                ToolResult(tool=d.name, status="success", attempts=1) for d in tools
            ]
            return runner

        with patch(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner",
            side_effect=runner_for,
        ):
            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=tools,
                timeout=900,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda tool_name: f"/usr/bin/{tool_name}",
            )

        assert name == "matrix-repo"
        for tool in tools:
            if tool == "zap":
                continue
            assert statuses.get(tool) is True, f"{tool} failed or was not executed"
        assert statuses["zap"] is False
        assert statuses[NOT_ATTEMPTED_KEY] == {"zap": NOT_ATTEMPTED_NOTHING_APPLICABLE}

    def test_allow_missing_tools_writes_stubs(self, tmp_path):
        """Test that allow_missing_tools writes stubs for all missing tools"""
        repo = tmp_path / "missing-tools-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        # Mock tool_exists to return False for all tools
        def mock_tool_exists(tool_name):
            return False

        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, output_path))
            output_path.write_text('{"results": []}')

        def mock_find_tool_none(tool_name):
            # No tools available
            return None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep", "trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool_none,
                write_stub_func=mock_write_stub,
            )

            # All 3 tools should have stubs written
            assert len(stub_calls) == 3
            assert any("trufflehog" in str(call[1]) for call in stub_calls)
            assert any("semgrep" in str(call[1]) for call in stub_calls)
            assert any("trivy" in str(call[1]) for call in stub_calls)

            # All three were stubbed, so none of them succeeded (#825).
            for tool in ("trufflehog", "semgrep", "trivy"):
                assert statuses[tool] is False, f"{tool} was stubbed, not run"
            assert not_attempted_tools(statuses) == [
                "semgrep",
                "trivy",
                "trufflehog",
            ]

    def test_allow_missing_tools_all_scanners(self, tmp_path):
        """allow_missing_tools stubs every repository tool in the matrix."""
        repo = tmp_path / "all-missing-repo"
        repo.mkdir()

        def mock_find_tool_none(tool_name):
            # No tools available
            return None

        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, str(output_path)))
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            all_tools = filter_tools_for_scan_type(list(TOOL_MATRIX), "repo")
            assert all_tools, "the matrix has no repository tools"

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=all_tools,
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool_none,
                write_stub_func=mock_write_stub,
            )

            # One stub per tool: none of them resolves.
            assert len(stub_calls) == len(all_tools)
            for tool in all_tools:
                assert statuses[tool] is False, f"{tool} was stubbed, not run"
                assert tool in not_attempted_tools(statuses), (
                    f"{tool} was stubbed but not recorded as not-attempted"
                )
                assert any(tool in path for _, path in stub_calls), (
                    f"Stub should be written for {tool}"
                )

    def test_per_tool_flags_applied(self, tmp_path):
        """Test that per_tool_config flags are correctly applied"""
        repo = tmp_path / "flags-test-repo"
        repo.mkdir()

        def mock_find_tool(tool_name):
            tool_paths = {"semgrep": "/usr/bin/semgrep", "trivy": "/usr/bin/trivy"}
            return tool_paths.get(tool_name)

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "semgrep": {
                    "flags": ["--exclude", "node_modules", "--exclude", ".git"]
                },
                "trivy": {"flags": ["--severity", "HIGH,CRITICAL", "--no-progress"]},
            }

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep", "trivy"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])

            # Verify semgrep flags
            semgrep_def = next((t for t in tool_defs if t.name == "semgrep"), None)
            assert semgrep_def is not None
            assert "--exclude" in semgrep_def.command
            assert "node_modules" in semgrep_def.command

            # Verify trivy flags
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None
            assert "--severity" in trivy_def.command
            assert "HIGH,CRITICAL" in trivy_def.command

    def test_per_tool_timeout_overrides(self, tmp_path):
        """Test that per_tool_config timeout overrides work for multiple tools"""
        repo = tmp_path / "timeout-override-repo"
        repo.mkdir()

        def mock_find_tool(tool_name):
            tool_paths = {
                "trufflehog": "/usr/bin/trufflehog",
                "semgrep": "/usr/bin/semgrep",
                "trivy": "/usr/bin/trivy",
            }
            return tool_paths.get(tool_name)

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "trufflehog": {"timeout": 300},
                "semgrep": {"timeout": 900},
                "trivy": {"timeout": 1200},
            }

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep", "trivy"],
                timeout=600,  # Default timeout
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])

            # Verify each tool has its override timeout
            trufflehog_def = next(
                (t for t in tool_defs if t.name == "trufflehog"), None
            )
            assert trufflehog_def.timeout == 300

            semgrep_def = next((t for t in tool_defs if t.name == "semgrep"), None)
            assert semgrep_def.timeout == 900

            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def.timeout == 1200

    def test_mixed_available_and_missing_tools(self, tmp_path):
        """Test scanning with mix of available and missing tools"""
        repo = tmp_path / "mixed-tools-repo"
        repo.mkdir()

        def mock_find_tool(tool_name):
            # Only trufflehog and trivy available
            if tool_name in ["trufflehog", "trivy"]:
                return f"/usr/bin/{tool_name}"
            return None

        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append(tool_name)
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep", "trivy", "checkov"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # Available tools should run
            assert statuses["trufflehog"] is True
            assert statuses["trivy"] is True

            # Missing tools should have stubs, and a stub is not a success.
            # This is the discriminating case: trufflehog and trivy really ran,
            # so the True above and the False here cannot both come from a
            # constant (#825).
            assert statuses["semgrep"] is False
            assert statuses["checkov"] is False
            assert not_attempted_tools(statuses) == ["checkov", "semgrep"]

            # Stubs should be written for missing tools only
            assert "semgrep" in list(stub_calls)
            assert "checkov" in list(stub_calls)
            assert len(stub_calls) == 2  # Only semgrep and checkov

    def test_timeout_writes_stub_file(self, tmp_path):
        """Test that tools that timeout get stub files written"""
        repo = tmp_path / "timeout-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        def mock_find_tool(tool_name):
            tool_paths = {
                "semgrep": "/usr/bin/semgrep",
                "trivy": "/usr/bin/trivy",
            }
            return tool_paths.get(tool_name)

        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append(tool_name)
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            # Simulate trivy timing out
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(
                    tool="trivy",
                    status="error",
                    attempts=2,
                    timed_out=True,
                    error_message="Timeout after 900s",
                ),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep", "trivy"],
                timeout=900,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # semgrep should succeed
            assert statuses["semgrep"] is True

            # trivy should fail but have stub written
            assert statuses["trivy"] is False

            # Stub should be written for timed out tool
            assert "trivy" in stub_calls

    def test_timeout_records_attempts(self, tmp_path):
        """Test that timed out tools record their attempt counts"""
        repo = tmp_path / "timeout-attempts-repo"
        repo.mkdir()

        def mock_find_tool(tool_name):
            if tool_name == "semgrep":
                return "/usr/bin/semgrep"
            return None

        def mock_write_stub(tool_name, output_path):
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            # Simulate tool timing out after 3 attempts
            mock_runner.run_all_parallel.return_value = [
                ToolResult(
                    tool="semgrep",
                    status="retry_exhausted",
                    attempts=3,
                    timed_out=True,
                    error_message="Timeout after 900s",
                ),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep"],
                timeout=900,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # Tool should be marked as failed
            assert statuses["semgrep"] is False

            # Attempts should be recorded in metadata
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["semgrep"] == 3

    def test_scan_repository_custom_find_tool_func(self, tmp_path):
        """Test using custom find_tool_func for testing"""
        repo = tmp_path / "test-repo"
        repo.mkdir()

        def mock_find_tool(tool: str):
            return "/usr/bin/trivy" if tool == "trivy" else None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trivy", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
            )

            # Only trivy should run; semgrep should have stub written
            assert "trivy" in statuses
            assert "semgrep" in statuses

    def test_scan_repository_custom_write_stub_func(self, tmp_path):
        """Test using custom write_stub_func for testing"""
        repo = tmp_path / "test-repo"
        repo.mkdir()

        stub_calls = []

        def mock_write_stub(tool: str, path) -> None:
            stub_calls.append((tool, path))

        def mock_find_tool(tool: str):
            return None  # No tools found

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trivy", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            assert len(stub_calls) == 2
            assert any("trivy" in str(p) for _, p in stub_calls)
            assert any("semgrep" in str(p) for _, p in stub_calls)


class TestNoRepositoryToolIsUnimplemented:
    """A default repository scan must name no tool as unimplemented.

    `scan_repository` warns "Requested but not applicable to repository targets
    (no repository implementation)" for every tool it is handed and has no
    block for. Before v2.0.0 that fired on every default scan: opa was routed
    to `repo` by TOOL_SCAN_TYPES and had no block, and five variant tools were
    reported the same way while their blocks ran.

    The orchestrator hands this scanner `filter_tools_for_scan_type(tools,
    "repo")`, so what must be implemented is all of TOOL_SCAN_TYPES["repo"],
    not only the part TOOL_MATRIX names by default.
    """

    @staticmethod
    def _unimplemented(tmp_path, caplog, tools):
        """The "no repository implementation" warnings a scan of `tools` logs."""
        repo = tmp_path / "repo"
        repo.mkdir(parents=True)
        (repo / "app.py").write_bytes(b"print('x')\n")
        caplog.clear()
        with (
            patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner,
            caplog.at_level(logging.WARNING, logger=repository_scanner.__name__),
        ):
            MockRunner.return_value.run_all_parallel.return_value = []
            scan_repository(
                repo,
                tmp_path / "individual-repos",
                tools,
                60,
                0,
                {},
                True,
                find_tool_func=lambda _name: None,
                write_stub_func=lambda _tool, path: path.write_bytes(b"[]"),
            )
        return [
            r.getMessage()
            for r in caplog.records
            if "no repository implementation" in r.getMessage()
        ]

    def test_default_matrix_leaves_no_repo_tool_unimplemented(self, tmp_path, caplog):
        default = filter_tools_for_scan_type(list(TOOL_MATRIX), "repo")
        assert default, "the default matrix routes nothing to a repository"
        tools = sorted(set(default) | TOOL_SCAN_TYPES["repo"])

        assert self._unimplemented(tmp_path / "default", caplog, tools) == []

        # The oracle is live in this process: the same call with one tool that
        # has no repository block (nuclei is URL-only) must name it. Without
        # this, a log record that never reached caplog would read as a pass.
        named = self._unimplemented(tmp_path / "control", caplog, [*tools, "nuclei"])
        assert len(named) == 1, named
        assert named[0].endswith(": nuclei"), named

    def test_every_repository_block_is_a_repo_applicable_tool(self):
        """The reverse direction: no block for a tool the router never sends.

        A block for a tool outside TOOL_SCAN_TYPES["repo"] is dead code -- the
        orchestrator filters the tool out before this module sees it. Read from
        the source rather than a list here, so a block added or deleted without
        the routing table following fails in either direction.
        """
        source = Path(repository_scanner.__file__).read_bytes().decode("utf-8")
        blocks = {
            node.test.left.value
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Constant)
            and isinstance(node.test.left.value, str)
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.In)
            and ast.unparse(node.test.comparators[0]) == "tools"
        }

        assert blocks, 'found no `if "<tool>" in tools:` block; extractor broken'
        assert blocks == TOOL_SCAN_TYPES["repo"]


class TestFailedToolsAreReported:
    """A tool that does not deliver findings must say so on a durable stream.

    Measured against bridgecrewio/terragoat with the `deep` profile: prowler,
    yara and dependency-check (Windows) and prowler, noseyparker and cdxgen
    (Linux) each ended as a transient `✗` glyph in the progress display and
    nothing else. No message on any stream, no artifact, no exit code. A
    non-TTY run - CI, cron, a detached scan - renders no progress bar at all,
    so the failure left no trace whatsoever.

    What that costs: a `--tools prowler yara dependency-check` scan of that
    deliberately-vulnerable repository produced zero output files, zero
    findings, `Policy evaluation complete: 2/2 passed`, and exit code 0.

    Which tools land in the silent branch is platform-dependent, so a
    single-platform run "confirms" the honest path for a different subset each
    time. These tests pin the contract instead: every non-success result names
    itself and its reason.
    """

    def _run(self, tmp_path, results, tools):
        """Scan with ToolRunner stubbed to return `results`, tools resolvable.

        find_tool must succeed: an unresolvable tool takes the `unresolved`
        branch, which already logs. Letting that happen would make these tests
        pass without the fix under test.
        """
        repo = tmp_path / "test-repo"
        repo.mkdir()
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = results
            return scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=tools,
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda t: f"/usr/bin/{t}",
            )

    def test_non_zero_exit_reports_tool_and_reason(self, tmp_path, caplog):
        """The generic error branch must not discard result.error_message."""
        import logging

        from scripts.core.tool_runner import ToolResult

        with caplog.at_level(logging.ERROR):
            _, statuses = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="semgrep",
                        status="error",
                        returncode=3,
                        error_message="exited with return code 3",
                        attempts=1,
                    )
                ],
                ["semgrep"],
            )

        assert statuses["semgrep"] is False
        assert "semgrep" in caplog.text
        assert "exited with return code 3" in caplog.text

    def test_timeout_reports_tool_and_reason(self, tmp_path, caplog):
        """A timed-out tool wrote a stub; the stub must not be the only signal.

        A stub file is indistinguishable from a genuinely empty result once the
        report phase reads it, so the timeout has to be stated at scan time.
        """
        import logging

        from scripts.core.tool_runner import ToolResult

        with caplog.at_level(logging.ERROR):
            _, statuses = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="checkov",
                        status="error",
                        timed_out=True,
                        error_message="Timeout after 1200s",
                        attempts=1,
                    )
                ],
                ["checkov"],
            )

        assert statuses["checkov"] is False
        assert "checkov" in caplog.text
        assert "1200" in caplog.text

    def test_missing_binary_reports_tool_and_reason(self, tmp_path, caplog):
        """`Tool not found` at run time, without --allow-missing-tools."""
        import logging

        from scripts.core.tool_runner import ToolResult

        with caplog.at_level(logging.ERROR):
            _, statuses = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="yara",
                        status="error",
                        error_message="Tool not found: yara",
                        attempts=1,
                    )
                ],
                ["yara"],
            )

        assert statuses["yara"] is False
        assert "yara" in caplog.text

    def test_no_output_is_reported_durably(self, tmp_path, caplog):
        """An accepted return code with nothing written must reach the log.

        This status is also announced by the progress tracker in jmo.py, which
        is easy to mistake for "already reported". It is not: that is a UI
        surface - bare text rather than the log stream, and overwritten in
        place on a TTY - so suppressing the log line here would leave the #700
        failure class (tool returns 0, writes nothing) with no durable record
        at all, which is the exact bug this whole area exists to prevent.
        """
        import logging

        from scripts.core.tool_runner import ToolResult

        with caplog.at_level(logging.ERROR):
            _, statuses = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="gosec",
                        status="no_output",
                        returncode=1,
                        error_message="Exited 1 (an accepted code) but wrote no output",
                        attempts=1,
                    )
                ],
                ["gosec"],
            )

        assert statuses["gosec"] is False
        assert "gosec" in caplog.text, (
            "a tool that exited 0 and wrote nothing left no durable record:\n"
            f"{caplog.text}"
        )
        assert "wrote no output" in caplog.text

    def test_successful_tool_is_not_reported_as_failed(self, tmp_path, caplog):
        """The guard must stay silent on success, or it is just noise."""
        import logging

        from scripts.core.tool_runner import ToolResult

        with caplog.at_level(logging.ERROR):
            _, statuses = self._run(
                tmp_path,
                [ToolResult(tool="trivy", status="success", attempts=1)],
                ["trivy"],
            )

        assert statuses["trivy"] is True
        assert "trivy" not in caplog.text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestVendoredTreesAreExcluded:
    """#1080 and #1132: the scanner hands each tool its exclusion flags.

    The spellings themselves are pinned in tests/unit/test_scan_utils.py; these
    assert the flags actually reach the argv `scan_repository` builds, and that
    JMo's own file walk skips the same trees.
    """

    @staticmethod
    def _built_commands(tmp_path, tools):
        """Build the real argv for `tools` without needing a tool installed."""
        repo = tmp_path / "repo"
        repo.mkdir(parents=True)

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=tmp_path / "out",
                tools=tools,
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda name: "/usr/bin/" + name,
            )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            return {t.name: t.command for t in tool_defs}

    def test_semgrep_is_told_to_skip_it(self, tmp_path):
        commands = self._built_commands(tmp_path, ["semgrep"])

        assert "--exclude=node_modules" in commands["semgrep"]

    def test_trivy_is_told_to_skip_it(self, tmp_path):
        commands = self._built_commands(tmp_path, ["trivy"])
        command = commands["trivy"]

        values = [
            command[i + 1] for i, tok in enumerate(command) if tok == "--skip-dirs"
        ]
        assert "**/node_modules" in values

    def test_checkov_is_told_to_skip_the_vendored_trees(self, tmp_path):
        """#1080: checkov got no exclusion flags at all, and timed out.

        Measured on this repository at 3ffc73a8, `--profile-name` unset,
        300 s cap: checkov, trivy and semgrep each hit the cap and contributed
        nothing, against 36,705 files on disk for 985 tracked ones.

        The value must be bare. `--skip-path` is a regex and checkov drops an
        unparseable one in silence, so `**/node_modules` would leave the
        command looking correct and excluding nothing - see
        test_checkov_must_not_be_given_the_trivy_spelling in
        tests/unit/test_scan_utils.py for the measurement.
        """
        commands = self._built_commands(tmp_path, ["checkov"])
        command = commands["checkov"]

        assert "--skip-path" in command
        values = [
            command[i + 1] for i, tok in enumerate(command) if tok == "--skip-path"
        ]
        assert "node_modules" in values
        assert ".venv" in values
        assert not any(v.startswith("**") for v in values), values

    def test_checkovs_exclusions_precede_the_users_flags(self, tmp_path):
        """An explicit per_tool entry has to be able to win.

        `--skip-path` accumulates, so ordering does not change the result
        today; it is asserted because the ordering convention is what makes
        bandit's last-wins `-x` behave, and a later tool copying this call site
        would inherit whichever order it finds (#1132).
        """
        repo = tmp_path / "repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=tmp_path / "out",
                tools=["checkov"],
                timeout=600,
                retries=0,
                per_tool_config={"checkov": {"flags": ["--compact"]}},
                allow_missing_tools=False,
                find_tool_func=lambda name: "/usr/bin/" + name,
            )
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            command = {t.name: t.command for t in tool_defs}["checkov"]

        assert "--compact" in command
        assert command.index("--skip-path") < command.index("--compact")

    def test_jmos_own_file_walk_skips_a_vendored_tree(self, tmp_path):
        """hadolint and shellcheck take explicit file arguments, so JMo's own
        enumeration is a walk like any other.

        Without this, a dependency's Dockerfiles and shell scripts are
        collected beside the repository's own, and the duplicates count against
        MAX_FILE_ARGS, evicting real files from a large repository.
        """
        from scripts.cli.scan_jobs.repository_scanner import _collect_files

        repo = tmp_path / "repo"
        (repo / "docker").mkdir(parents=True)
        (repo / "docker" / "Dockerfile").write_text("FROM alpine:3.19\n")
        vendored = repo / "node_modules" / "some-pkg" / "docker"
        vendored.mkdir(parents=True)
        (vendored / "Dockerfile").write_text("FROM alpine:3.19\n")

        found = _collect_files(repo, ("**/Dockerfile",), "hadolint")

        assert len(found) == 1, f"the vendored copy was collected too: {found}"
        assert "node_modules" not in found[0]


class TestTruffleHogSkipsVcsAndJmoInternals:
    """#1134: the scan phase has to hand TruffleHog the exclude file."""

    @staticmethod
    def _run(tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out_root = tmp_path / "out"

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=out_root,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda name: "/usr/bin/" + name,
            )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            return next(t for t in tool_defs if t.name == "trufflehog")

    def test_the_command_carries_an_exclude_paths_file(self, tmp_path):
        definition = self._run(tmp_path)
        command = definition.command

        assert "--exclude-paths" in command
        exclude_file = Path(command[command.index("--exclude-paths") + 1])
        assert exclude_file.is_file(), "the flag names a file that was not written"

    def test_the_written_file_excludes_git_and_jmo(self, tmp_path):
        """The flag is worthless if the file it names is empty or wrong, so
        assert the contents rather than only the flag's presence."""
        definition = self._run(tmp_path)
        command = definition.command
        exclude_file = Path(command[command.index("--exclude-paths") + 1])

        patterns = exclude_file.read_bytes().decode("utf-8").splitlines()

        assert patterns == [r"[\\/]\.git[\\/]", r"[\\/]\.jmo[\\/]"]

    def test_user_flags_still_come_last(self, tmp_path):
        """JMo's exclusion precedes per_tool flags so an explicit user
        --exclude-paths overrides it, matching the exclusion table's rule."""
        repo = tmp_path / "repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=tmp_path / "out",
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={"trufflehog": {"flags": ["--results", "verified"]}},
                allow_missing_tools=False,
                find_tool_func=lambda name: "/usr/bin/" + name,
            )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            command = next(t for t in tool_defs if t.name == "trufflehog").command

        assert command.index("--exclude-paths") < command.index("--results")


class TestZapDoesNotTakeARepositoryTarget:
    """#1159: zap's repository mode could not work, in any configuration.

    `zap-baseline.py -t` takes a URL. JMo passed it `web_files[0]` -- the first
    `.html`, `.js` or `.php` file in the tree -- and the dogfood measured the
    result: `Return code 3 not in (0, 1, 2)`, `retry_exhausted`, no `zap.json`.
    Compounding it, `zap-baseline.py` is not in the package `jmo tools install
    zap` lays down at all; it ships in the ZAP Docker image. So without Docker
    the tool never started, and with it the tool started and exited 3.

    **This supersedes TestZapIsNotReportedBothWays (#1136).** That class guarded
    a scan reporting zap as never started AND as failed, which came from probing
    two binaries and recording an unresolved entry on the first miss. Nothing
    probes a binary for zap on a repository target now, so the defect is
    unreachable by construction rather than by bookkeeping -- and
    `test_the_1136_defect_is_unreachable` below is the negative control saying
    so, because "we deleted the code that reported it" and "we deleted the
    report" look identical from the outside.

    zap is untouched on **url** targets, where it works.
    """

    @staticmethod
    def _scan(tmp_path, repo, resolvable, caplog):
        import logging

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            with caplog.at_level(
                logging.INFO, logger="scripts.cli.scan_jobs.repository_scanner"
            ):
                _name, statuses = scan_repository(
                    repo=repo,
                    results_dir=tmp_path / "out",
                    tools=["zap"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                    find_tool_func=(
                        lambda n: ("/usr/bin/" + n) if n in resolvable else None
                    ),
                )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            return [t.name for t in tool_defs], statuses, caplog.text

    @staticmethod
    def _web_repo(tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "index.html").write_text("<html></html>", encoding="utf-8")
        (repo / "app.js").write_text("const x = 1;\n", encoding="utf-8")
        return repo

    # ---- the new contract --------------------------------------------------

    def test_zap_builds_no_command_for_a_repository(self, tmp_path, caplog):
        """Even with both binaries resolvable, which is the case that used to
        exit 3."""
        names, _statuses, _log = self._scan(
            tmp_path, self._web_repo(tmp_path), {"zap-baseline.py", "docker"}, caplog
        )

        assert "zap" not in names

    def test_the_reason_is_nothing_to_scan_not_missing(self, tmp_path, caplog):
        """The distinction #1081 exists to preserve.

        Asserting only that zap did not run would read identically for "the
        binary is absent", which is a gap the user can close and this is not.
        """
        _names, statuses, _log = self._scan(
            tmp_path, self._web_repo(tmp_path), {"zap-baseline.py", "docker"}, caplog
        )

        assert (statuses.get(NOT_ATTEMPTED_KEY) or {}).get("zap") == (
            NOT_ATTEMPTED_NOTHING_APPLICABLE
        )

    def test_a_stub_is_still_written(self, tmp_path, caplog):
        """The report phase globs for one output file per requested tool."""
        self._scan(
            tmp_path, self._web_repo(tmp_path), {"zap-baseline.py", "docker"}, caplog
        )

        assert (tmp_path / "out" / "repo" / "zap.json").exists()

    def test_html_in_the_tree_changes_nothing(self, tmp_path):
        """The old gate was `web_files[0]`, so a repository with no `.html`,
        `.js` or `.php` took a different branch. Both are the same branch now,
        and a guard that only ever saw one of them could not tell."""
        bare = tmp_path / "bare"
        bare.mkdir()
        (bare / "main.py").write_text("x = 1\n", encoding="utf-8")

        import logging

        from _pytest.logging import LogCaptureFixture  # noqa: F401

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []
            _name, statuses = scan_repository(
                repo=bare,
                results_dir=tmp_path / "out2",
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda n: "/usr/bin/" + n,
            )
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])

        assert "zap" not in [t.name for t in tool_defs]
        assert (statuses.get(NOT_ATTEMPTED_KEY) or {}).get("zap") == (
            NOT_ATTEMPTED_NOTHING_APPLICABLE
        )
        assert logging  # keep the import meaningful under lint

    # ---- the superseded defect stays gone ----------------------------------

    def test_the_1136_defect_is_unreachable(self, tmp_path, caplog):
        """zap must never be reported as a missing dependency on a repository.

        #1136 was one scan saying `zap requested but its dependency
        zap-baseline.py could not be found - it did NOT run` AND, nine seconds
        later, that it had failed. With nothing resolvable at all -- the harshest
        input for that message -- neither half may appear, because zap is not
        attempted here for reasons that have nothing to do with what is
        installed.
        """
        names, statuses, log = self._scan(
            tmp_path, self._web_repo(tmp_path), set(), caplog
        )

        assert "zap" not in names
        assert "did NOT run" not in log, log
        assert "zap-baseline.py" not in log, log
        assert (statuses.get(NOT_ATTEMPTED_KEY) or {}).get("zap") == (
            NOT_ATTEMPTED_NOTHING_APPLICABLE
        ), "an absent binary must not change the reason: zap is not attempted here"


class TestGosecOnlyRunsWhenThereIsSomethingToScan:
    """#1081: gosec reported ERROR "findings are MISSING" on every repo.

    gosec exits in ~100 ms with no output file when a repository has no Go --
    which is most repositories. `tool_runner` grades an accepted return code
    with no output as `no_output` and logs

        [ERROR] gosec: exited with an accepted code but wrote no output file
        - its findings are MISSING from this scan

    That is the line that catches a genuinely broken scanner (a Windows `.exe`
    omission once made trufflehog scan nothing, exit 0, and pass the
    `zero-secrets` policy). Firing it on every Node, Python, Java, Ruby or PHP
    repository trains the reader to ignore it.

    The fix is not to suppress the message: it is to never build the
    `ToolDefinition`, so the tool never runs and `no_output` is unreachable --
    the same shape zap uses.
    """

    @staticmethod
    def _scan(tmp_path, repo, tools):
        """Run `scan_repository` with every requested tool resolvable.

        Returns (tool_def_names, statuses). `allow_missing_tools=False` so a
        stub can only come from the content predicate, never from the
        missing-binary branch.
        """
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            _name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path / "out",
                tools=tools,
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda n: "/usr/bin/" + n,
            )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            return [t.name for t in tool_defs], statuses

    @staticmethod
    def _reason(statuses, tool):
        """The recorded reason, or None.

        Reached through NOT_ATTEMPTED_KEY rather than `not_attempted_tools`,
        which returns only the tool NAMES and so reads identically whether the
        reason is "not installed" or "nothing for it to scan" -- the exact
        distinction #1081 is about. Asserting on membership alone would pass
        against the unfixed code.
        """
        return (statuses.get(NOT_ATTEMPTED_KEY) or {}).get(tool)

    # ---- gosec -------------------------------------------------------------

    def test_gosec_is_skipped_on_a_repo_with_no_go(self, tmp_path):
        repo = tmp_path / "node-app"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "index.js").write_text("console.log(1)", encoding="utf-8")
        (repo / "README.md").write_text("# no go here", encoding="utf-8")

        names, statuses = self._scan(tmp_path, repo, ["gosec"])

        assert "gosec" not in names, "gosec must not be run with nothing to load"
        assert statuses["gosec"] is False
        assert self._reason(statuses, "gosec") == NOT_ATTEMPTED_NOTHING_APPLICABLE

    def test_gosec_runs_when_a_go_file_is_present(self, tmp_path):
        repo = tmp_path / "go-app"
        (repo / "cmd").mkdir(parents=True)
        (repo / "cmd" / "main.go").write_text("package main", encoding="utf-8")

        names, statuses = self._scan(tmp_path, repo, ["gosec"])

        assert "gosec" in names
        assert self._reason(statuses, "gosec") is None

    def test_gosec_runs_on_a_go_mod_with_no_checked_in_sources(self, tmp_path):
        """`go.mod` alone is enough. A module whose sources are generated at
        build time still has one, and skipping it would drop the scanner on a
        real Go repository -- the failure direction that matters."""
        repo = tmp_path / "go-mod-only"
        repo.mkdir()
        (repo / "go.mod").write_text("module example.com/m\n", encoding="utf-8")

        names, _statuses = self._scan(tmp_path, repo, ["gosec"])

        assert "gosec" in names

    def test_go_inside_a_vendored_tree_does_not_trigger_gosec(self, tmp_path):
        """The predicate reads the same directory list the scan flags are built
        from, so a `.go` under `node_modules/` is not the repo's own code.

        Measurable on jmo-security-repo itself: its only `.go` outside the test
        fixtures is `.venv/.../pre_commit/resources/empty_template_main.go`,
        shipped by pre-commit. Counting that would trigger gosec on every
        Python repository with a virtualenv in the tree.
        """
        repo = tmp_path / "js-app"
        vendored = repo / "node_modules" / "some-pkg"
        vendored.mkdir(parents=True)
        (vendored / "helper.go").write_text("package main", encoding="utf-8")
        (repo / "index.js").write_text("console.log(1)", encoding="utf-8")

        names, statuses = self._scan(tmp_path, repo, ["gosec"])

        assert "gosec" not in names
        assert self._reason(statuses, "gosec") == NOT_ATTEMPTED_NOTHING_APPLICABLE

    # ---- the two reasons stay distinct -------------------------------------

    def test_a_missing_binary_still_reports_not_installed(self, tmp_path):
        """Suppressing the false ERROR must not suppress the true one. A repo
        that DOES have Go, with gosec absent, is an environment gap the user can
        close -- a different outcome, and it must keep saying so."""
        repo = tmp_path / "go-app"
        repo.mkdir()
        (repo / "main.go").write_text("package main", encoding="utf-8")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            _name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path / "out",
                tools=["gosec"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=lambda _n: None,
            )

        assert self._reason(statuses, "gosec") == NOT_ATTEMPTED_MISSING


class TestTheInTreeResultsDirectoryIsKeptOutOfTheScan:
    """#1156, at the scanner. `jmo scan . --out ./results` puts JMo's output
    inside the tree the next scan walks.

    Measured end to end, scanning a two-file repository twice with the results
    directory in the tree: **11 findings, 8 of them inside `results/`** plus 2
    inside horusec's staging copy of it. After: 2 findings, both the real ones.

    The scanners are handed `<results_root>/individual-<type>`, NOT the root.
    Excluding what this function receives is the bug that made a first pass
    look right and leave 5 of 8 findings behind: `summaries/findings.json`,
    `findings.yaml` and `dashboard.html` sit beside `individual-repos/` and
    each embeds every finding verbatim, so they are the richest source of the
    re-reporting rather than the raw tool output.
    """

    @staticmethod
    def _flags_for(tmp_path, tool, results_dir):
        """The command `scan_repository` builds for `tool`, as a string."""
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True, exist_ok=True)
        (repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=results_dir,
                tools=[tool],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda n: "/usr/bin/" + n,
            )
            args, kwargs = MockRunner.call_args
            defs = kwargs.get("tools") or (args[0] if args else [])
            td = next((t for t in defs if t.name == tool), None)
            return " ".join(str(c) for c in td.command) if td else ""

    def test_the_results_ROOT_is_excluded_not_the_per_type_subdirectory(self, tmp_path):
        """The scanner receives `<root>/individual-repos`. It must exclude
        `results`, which also covers `summaries/`."""
        repo_results = tmp_path / "repo" / "results"

        cmd = self._flags_for(tmp_path, "checkov", repo_results / "individual-repos")

        assert "--skip-path results" in cmd, cmd
        assert "individual-repos" not in cmd.split("--skip-path")[-1], (
            "excluded the per-type subdirectory, leaving summaries/ in the walk"
        )

    def test_a_results_dir_outside_the_repo_adds_no_exclusion(self, tmp_path):
        """The usual CI shape. Nothing to exclude, and excluding a directory
        named `results` anyway could hide the user's own code."""
        cmd = self._flags_for(
            tmp_path, "checkov", tmp_path / "outside" / "individual-repos"
        )

        # On the flag values, not the whole command line: pytest's own tmp_path
        # is named after this test and therefore contains "results" itself -- a
        # substring check on `cmd` fails for a reason that has nothing to do
        # with the code under test.
        skipped = [
            cmd.split()[i + 1]
            for i, tok in enumerate(cmd.split())
            if tok == "--skip-path"
        ]
        assert "results" not in skipped, skipped

    def test_the_go_predicate_ignores_a_previous_scans_output(self, tmp_path):
        """#1081's predicates walk the tree too, so JMo's own output can
        satisfy them. A `.go` file inside `results/` is not the repo's code."""
        from scripts.cli.scan_jobs.repository_scanner import _repo_has_go_sources

        repo = tmp_path / "repo"
        (repo / "results" / "individual-repos").mkdir(parents=True)
        (repo / "results" / "individual-repos" / "vendored.go").write_text(
            "package main", encoding="utf-8"
        )
        (repo / "app.js").write_text("1", encoding="utf-8")

        assert _repo_has_go_sources(repo) is True, "control: found without the skip"
        assert _repo_has_go_sources(repo, (repo / "results").resolve()) is False

    def test_the_file_walk_skips_by_PATH_not_by_name(self, tmp_path):
        """The flags can only take a name; this side can be exact.

        A user directory that merely shares the results directory's name must
        still be scanned here, which is what makes the Python-side skip worth
        having separately.
        """
        from scripts.cli.scan_jobs.repository_scanner import _collect_files

        repo = tmp_path / "repo"
        (repo / "results").mkdir(parents=True)
        (repo / "src" / "results").mkdir(parents=True)
        (repo / "results" / "own.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (repo / "src" / "results" / "theirs.sh").write_text(
            "#!/bin/sh\n", encoding="utf-8"
        )

        found = _collect_files(
            repo, ("**/*.sh",), "shellcheck", (repo / "results").resolve()
        )

        assert any("theirs.sh" in f for f in found), (
            "the user's own src/results/ was skipped by name"
        )
        assert not any("own.sh" in f for f in found), "JMo's output was scanned"
