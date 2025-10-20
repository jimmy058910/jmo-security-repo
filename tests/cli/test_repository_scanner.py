"""
Tests for Repository Scanner

Tests the repository_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.repository_scanner import scan_repository


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
        def mock_tool_exists(tool_name):
            return tool_name == "trivy"

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
                tool_exists_func=mock_tool_exists,
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

    def test_noseyparker_multi_phase_execution(self, tmp_path):
        """Test noseyparker multi-phase execution (init, scan, report)"""
        repo = tmp_path / "noseyparker-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        def mock_tool_exists(tool_name):
            return tool_name == "noseyparker"

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            # Simulate successful multi-phase execution
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="noseyparker-init", status="success", attempts=1),
                ToolResult(tool="noseyparker-scan", status="success", attempts=1),
                ToolResult(
                    tool="noseyparker-report",
                    status="success",
                    attempts=1,
                    output_file=tmp_path / "noseyparker-repo" / "noseyparker.json",
                    stdout='{"matches": []}',
                    capture_stdout=True,
                ),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["noseyparker"],
                timeout=900,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            assert statuses["noseyparker"] is True
            # Verify all three phases were executed
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            phase_names = [t.name for t in tool_defs]
            assert "noseyparker-init" in phase_names
            assert "noseyparker-scan" in phase_names
            assert "noseyparker-report" in phase_names

    def test_noseyparker_docker_fallback(self, tmp_path):
        """Test noseyparker Docker fallback when local binary missing"""
        repo = tmp_path / "docker-fallback-repo"
        repo.mkdir()

        def mock_tool_exists(tool_name):
            # noseyparker not available, but docker is
            return tool_name == "docker"

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="noseyparker", status="success", attempts=1),
            ]

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["noseyparker"],
                timeout=900,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            # Verify Docker fallback was used
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            np_def = next((t for t in tool_defs if t.name == "noseyparker"), None)
            assert np_def is not None
            # Docker command should include bash and run_noseyparker_docker.sh
            assert "bash" in np_def.command

    def test_zap_repository_scanning_with_web_files(self, tmp_path):
        """Test ZAP scanning when repository contains web files"""
        repo = tmp_path / "web-app-repo"
        repo.mkdir()
        (repo / "index.html").write_text("<html><body>Test</body></html>")
        (repo / "app.js").write_text("console.log('test');")

        def mock_tool_exists(tool_name):
            return tool_name == "zap-baseline.py"

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            assert statuses["zap"] is True
            # Verify ZAP was invoked with web file
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            zap_def = next((t for t in tool_defs if t.name == "zap"), None)
            assert zap_def is not None
            assert "zap-baseline.py" in zap_def.command

    def test_zap_stub_when_no_web_files(self, tmp_path):
        """Test ZAP writes stub when no web files found"""
        repo = tmp_path / "non-web-repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')")

        def mock_tool_exists(tool_name):
            return tool_name == "zap-baseline.py"

        def mock_write_stub(tool_name, output_path):
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                tool_exists_func=mock_tool_exists,
                write_stub_func=mock_write_stub,
            )

            assert statuses["zap"] is True
            # No tool definitions should be created (stub written directly)
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            assert not any(t.name == "zap" for t in tool_defs)

    def test_falco_validates_rule_files(self, tmp_path):
        """Test Falco validates rule files when present"""
        repo = tmp_path / "falco-repo"
        repo.mkdir()
        (repo / "custom-falco-rules.yaml").write_text(
            """
- rule: Detect Shell in Container
  desc: Alert on shell execution
  condition: spawned_process and container
  output: "Shell spawned in container"
  priority: WARNING
"""
        )

        def mock_tool_exists(tool_name):
            return tool_name == "falco"

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="falco", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["falco"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            assert statuses["falco"] is True
            # Verify Falco validation was invoked
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            falco_def = next((t for t in tool_defs if t.name == "falco"), None)
            assert falco_def is not None
            assert "--validate" in falco_def.command

    def test_falco_stub_when_no_rules(self, tmp_path):
        """Test Falco writes stub when no rule files found"""
        repo = tmp_path / "no-falco-repo"
        repo.mkdir()
        (repo / "README.md").write_text("# No Falco rules")

        def mock_tool_exists(tool_name):
            return tool_name == "falco"

        def mock_write_stub(tool_name, output_path):
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["falco"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                tool_exists_func=mock_tool_exists,
                write_stub_func=mock_write_stub,
            )

            assert statuses["falco"] is True

    def test_aflplusplus_fuzzes_binaries(self, tmp_path):
        """Test AFL++ fuzzes binaries when found"""
        repo = tmp_path / "afl-repo"
        repo.mkdir()
        bin_dir = repo / "bin"
        bin_dir.mkdir()
        binary = bin_dir / "test-fuzzer"
        binary.write_bytes(b"\x7fELF")  # Minimal ELF header
        binary.chmod(0o755)

        def mock_tool_exists(tool_name):
            return tool_name in ["afl-fuzz", "afl-analyze"]

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="afl++", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["afl++"],
                timeout=1800,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            assert statuses["afl++"] is True
            # Verify AFL++ was invoked
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            afl_def = next((t for t in tool_defs if t.name == "afl++"), None)
            assert afl_def is not None
            assert "afl-fuzz" in afl_def.command

    def test_aflplusplus_stub_when_no_binaries(self, tmp_path):
        """Test AFL++ writes stub when no binaries found"""
        repo = tmp_path / "no-binaries-repo"
        repo.mkdir()
        (repo / "source.c").write_text("#include <stdio.h>\nint main() {}")

        def mock_tool_exists(tool_name):
            return tool_name in ["afl-fuzz", "afl-analyze"]

        def mock_write_stub(tool_name, output_path):
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["afl++"],
                timeout=1800,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                tool_exists_func=mock_tool_exists,
                write_stub_func=mock_write_stub,
            )

            assert statuses["afl++"] is True

    def test_deep_profile_all_11_tools(self, tmp_path):
        """Test deep profile executes all 11 tools correctly"""
        repo = tmp_path / "deep-profile-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "index.html").write_text("<html></html>")
        (repo / "falco-rules.yaml").write_text("rules: []")
        bin_dir = repo / "bin"
        bin_dir.mkdir()
        binary = bin_dir / "app"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        (repo / "Dockerfile").write_text("FROM ubuntu")

        def mock_tool_exists(tool_name):
            return tool_name in [
                "trufflehog",
                "noseyparker",
                "semgrep",
                "bandit",
                "syft",
                "trivy",
                "checkov",
                "hadolint",
                "zap-baseline.py",
                "falco",
                "afl-fuzz",
                "afl-analyze",
            ]

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            # Simulate success for all 11 tools (noseyparker has 3 phases)
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="noseyparker-init", status="success", attempts=1),
                ToolResult(tool="noseyparker-scan", status="success", attempts=1),
                ToolResult(
                    tool="noseyparker-report",
                    status="success",
                    attempts=1,
                    output_file=tmp_path / "deep-profile-repo" / "noseyparker.json",
                    stdout='{"matches": []}',
                    capture_stdout=True,
                ),
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(tool="bandit", status="success", attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
                ToolResult(tool="checkov", status="success", attempts=1),
                ToolResult(tool="hadolint", status="success", attempts=1),
                ToolResult(tool="zap", status="success", attempts=1),
                ToolResult(tool="falco", status="success", attempts=1),
                ToolResult(tool="afl++", status="success", attempts=1),
            ]

            deep_profile_tools = [
                "trufflehog",
                "noseyparker",
                "semgrep",
                "bandit",
                "syft",
                "trivy",
                "checkov",
                "hadolint",
                "zap",
                "falco",
                "afl++",
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=deep_profile_tools,
                timeout=900,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            assert name == "deep-profile-repo"
            # Verify all 11 tools succeeded
            for tool in deep_profile_tools:
                assert statuses.get(tool) is True, f"Tool {tool} failed or not executed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
