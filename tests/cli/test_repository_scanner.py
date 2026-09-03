"""
Tests for Repository Scanner

Tests the repository_scanner module with various scenarios.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.repository_scanner import scan_repository
from scripts.cli.scan_utils import not_attempted_tools


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

    def test_noseyparker_multi_phase_execution(self, tmp_path):
        """noseyparker runs as scan-then-report, in that order.

        This test previously asserted a `noseyparker-init` phase existed and
        mocked all three phases to success. Both halves described something
        that could not happen: `datastore init` fails with "File exists
        (os error 17)" against the directory this scanner pre-created, so the
        local-binary path had never produced a finding (#1127). Asserting the
        phase list while mocking its outcome cannot see that.
        """
        repo = tmp_path / "noseyparker-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        def mock_find_tool(tool_name):
            if tool_name == "noseyparker":
                return "/usr/bin/noseyparker"
            return None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            from scripts.core.tool_runner import ToolResult

            waves: list[list[str]] = []

            def make_runner(*args, **kwargs):
                defs = kwargs.get("tools") or (args[0] if args else [])
                names = [t.name for t in defs]
                waves.append(names)
                runner = MagicMock()
                if "noseyparker-report" in names:
                    runner.run_all_parallel.return_value = [
                        ToolResult(
                            tool="noseyparker-report",
                            status="success",
                            attempts=1,
                            output_file=repo_out / "noseyparker.json",
                            stdout='{"matches": []}',
                            capture_stdout=True,
                        )
                    ]
                else:
                    runner.run_all_parallel.return_value = [
                        ToolResult(
                            tool="noseyparker-scan", status="success", attempts=1
                        )
                    ]
                return runner

            repo_out = tmp_path / "noseyparker-repo"
            MockRunner.side_effect = make_runner

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["noseyparker"],
                timeout=900,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            assert statuses["noseyparker"] is True

            # `datastore init` is gone: `scan` creates the datastore itself,
            # and init cannot succeed twice against one results directory.
            all_names = [n for wave in waves for n in wave]
            assert "noseyparker-init" not in all_names

            # report must not be submitted alongside scan. run_all_parallel
            # gives no ordering, and `report` against an unpopulated datastore
            # exits 2 with "unable to open database file".
            assert len(waves) == 2, f"expected two waves, got {waves}"
            assert "noseyparker-scan" in waves[0]
            assert "noseyparker-report" not in waves[0]
            assert waves[1] == ["noseyparker-report"]

    def test_noseyparker_datastore_root_is_not_pre_created(self, tmp_path):
        """noseyparker creates the datastore root and refuses an existing one.

        Measured with noseyparker 0.24.0: `datastore init` against a directory
        that already exists exits 2 with "Failed to create datastore root
        directory ...: File exists (os error 17)", and `scan` against a
        pre-created empty one exits 2 with "Unsupported schema version 0".
        The parent must exist; the root must not.
        """
        repo = tmp_path / "np-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        def mock_find_tool(tool_name):
            return "/usr/bin/noseyparker" if tool_name == "noseyparker" else None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["noseyparker"],
                timeout=900,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

        datastore = tmp_path / "np-repo" / ".noseyparker_datastore"
        assert not datastore.exists(), (
            "the datastore root was pre-created; noseyparker will refuse it "
            "with 'File exists (os error 17)' and contribute no findings"
        )
        assert datastore.parent.exists(), (
            "the datastore's parent must exist -- noseyparker does not create "
            "parents and fails with 'No such file or directory (os error 2)'"
        )

    def test_a_failed_noseyparker_phase_says_why(self, tmp_path):
        """A failing phase must report like every other tool.

        The phase branch `continue`d before the failure reporting the rest of
        the loop does, so a failed phase left only "Return code 2 not in
        (0,)" in scan-timings and nothing in the log. That is why the
        datastore error stayed invisible.
        """
        repo = tmp_path / "np-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        def mock_find_tool(tool_name):
            return "/usr/bin/noseyparker" if tool_name == "noseyparker" else None

        from scripts.core.tool_runner import ToolResult

        with (
            patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner,
            patch(
                "scripts.cli.scan_jobs.repository_scanner.report_tool_failure"
            ) as mock_report,
        ):
            MockRunner.return_value.run_all_parallel.return_value = [
                ToolResult(
                    tool="noseyparker-scan",
                    status="error",
                    returncode=2,
                    attempts=1,
                    error_message="Return code 2 not in (0, 1)",
                )
            ]

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["noseyparker"],
                timeout=900,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

        assert mock_report.called, (
            "a failed noseyparker phase was swallowed; nothing in the log or "
            "the scan summary says the tool did not run"
        )
        reported = [c.args[0].tool for c in mock_report.call_args_list]
        assert "noseyparker-scan" in reported

    def test_noseyparker_docker_fallback(self, tmp_path):
        """Test noseyparker Docker fallback when local binary missing"""
        repo = tmp_path / "docker-fallback-repo"
        repo.mkdir()

        def mock_find_tool(tool_name):
            # noseyparker not available, but docker is
            if tool_name == "docker":
                return "/usr/bin/docker"
            return None

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
                find_tool_func=mock_find_tool,
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
                find_tool_func=mock_find_tool,
            )

            assert statuses["zap"] is True
            # Verify ZAP was invoked with web file
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            zap_def = next((t for t in tool_defs if t.name == "zap"), None)
            assert zap_def is not None
            # command is a list, check if zap-baseline.py is in any element
            assert any("zap-baseline.py" in str(c) for c in zap_def.command)

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

    def test_falco_validates_rule_files(self, tmp_path):
        """Test Falco validates rule files when present"""
        repo = tmp_path / "falco-repo"
        repo.mkdir()
        (repo / "custom-falco-rules.yaml").write_text("""
- rule: Detect Shell in Container
  desc: Alert on shell execution
  condition: spawned_process and container
  output: "Shell spawned in container"
  priority: WARNING
""")

        def mock_find_tool(tool_name):
            if tool_name == "falco":
                return "/usr/bin/falco"
            return None

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
                find_tool_func=mock_find_tool,
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

        def mock_find_tool(tool_name):
            if tool_name == "falco":
                return "/usr/bin/falco"
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
                tools=["falco"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            assert statuses["falco"] is False
            assert not_attempted_tools(statuses) == ["falco"]

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows doesn't have Unix-style execute bits for binary detection",
    )
    def test_aflplusplus_fuzzes_binaries(self, tmp_path):
        """Test AFL++ fuzzes binaries when found"""
        repo = tmp_path / "afl-repo"
        repo.mkdir()
        bin_dir = repo / "bin"
        bin_dir.mkdir()
        binary = bin_dir / "test-fuzzer"
        binary.write_bytes(b"\x7fELF")  # Minimal ELF header
        binary.chmod(0o755)

        def mock_find_tool(tool_name):
            tool_paths = {
                "afl-fuzz": "/usr/bin/afl-fuzz",
                "afl-analyze": "/usr/bin/afl-analyze",
            }
            return tool_paths.get(tool_name)

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
                find_tool_func=mock_find_tool,
            )

            assert statuses["afl++"] is True
            # Verify AFL++ was invoked
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            afl_def = next((t for t in tool_defs if t.name == "afl++"), None)
            assert afl_def is not None
            # command is a list, check if afl-fuzz is in any element
            assert any("afl-fuzz" in str(c) for c in afl_def.command)

    def test_aflplusplus_stub_when_no_binaries(self, tmp_path):
        """Test AFL++ writes stub when no binaries found"""
        repo = tmp_path / "no-binaries-repo"
        repo.mkdir()
        (repo / "source.c").write_text("#include <stdio.h>\nint main() {}")

        def mock_find_tool(tool_name):
            tool_paths = {
                "afl-fuzz": "/usr/bin/afl-fuzz",
                "afl-analyze": "/usr/bin/afl-analyze",
            }
            return tool_paths.get(tool_name)

        def mock_write_stub(tool_name, output_path):
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            mock_runner.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["afl++"],
                timeout=1800,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            assert statuses["afl++"] is False
            assert not_attempted_tools(statuses) == ["afl++"]

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

        def mock_find_tool(tool_name):
            tool_paths = {
                "trufflehog": "/usr/bin/trufflehog",
                "noseyparker": "/usr/bin/noseyparker",
                "semgrep": "/usr/bin/semgrep",
                "bandit": "/usr/bin/bandit",
                "syft": "/usr/bin/syft",
                "trivy": "/usr/bin/trivy",
                "checkov": "/usr/bin/checkov",
                "hadolint": "/usr/bin/hadolint",
                "zap-baseline.py": "/usr/bin/zap-baseline.py",
                "falco": "/usr/bin/falco",
                "afl-fuzz": "/usr/bin/afl-fuzz",
                "afl-analyze": "/usr/bin/afl-analyze",
                "": "/usr/bin/",
            }
            return tool_paths.get(tool_name)

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
                find_tool_func=mock_find_tool,
            )

            assert name == "deep-profile-repo"
            # Verify all 11 tools succeeded
            for tool in deep_profile_tools:
                assert statuses.get(tool) is True, f"Tool {tool} failed or not executed"

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
        """Test allow_missing_tools for all 11 deep profile tools"""
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

            all_tools = [
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
                tools=all_tools,
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool_none,
                write_stub_func=mock_write_stub,
            )

            # All 11 tools should have stubs written
            assert len(stub_calls) == 11
            for tool in all_tools:
                assert statuses[tool] is False, f"{tool} was stubbed, not run"
                assert tool in not_attempted_tools(
                    statuses
                ), f"{tool} was stubbed but not recorded as not-attempted"
                # For afl++, check for "aflplusplus" in path (++ is sanitized)
                search_term = "aflplusplus" if tool == "afl++" else tool
                assert any(
                    search_term in path for _, path in stub_calls
                ), f"Stub should be written for {tool} (searched for '{search_term}')"

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
                tools=["trufflehog", "semgrep", "trivy", "bandit"],
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
            assert statuses["bandit"] is False
            assert not_attempted_tools(statuses) == ["bandit", "semgrep"]

            # Stubs should be written for missing tools only
            assert "semgrep" in list(stub_calls)
            assert "bandit" in list(stub_calls)
            assert len(stub_calls) == 2  # Only semgrep and bandit

    def test_timeout_writes_stub_file(self, tmp_path):
        """Test that tools that timeout get stub files written"""
        repo = tmp_path / "timeout-repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        def mock_find_tool(tool_name):
            tool_paths = {
                "semgrep": "/usr/bin/semgrep",
                "semgrep-secrets": "/usr/bin/semgrep-secrets",
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

            # Simulate semgrep-secrets timing out
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(
                    tool="semgrep-secrets",
                    status="error",
                    attempts=2,
                    timed_out=True,
                    error_message="Timeout after 900s",
                ),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep", "semgrep-secrets"],
                timeout=900,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # semgrep should succeed
            assert statuses["semgrep"] is True

            # semgrep-secrets should fail but have stub written
            assert statuses["semgrep-secrets"] is False

            # Stub should be written for timed out tool
            assert "semgrep-secrets" in stub_calls

    def test_timeout_records_attempts(self, tmp_path):
        """Test that timed out tools record their attempt counts"""
        repo = tmp_path / "timeout-attempts-repo"
        repo.mkdir()

        def mock_find_tool(tool_name):
            if tool_name == "semgrep-secrets":
                return "/usr/bin/semgrep-secrets"
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
                    tool="semgrep-secrets",
                    status="retry_exhausted",
                    attempts=3,
                    timed_out=True,
                    error_message="Timeout after 900s",
                ),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep-secrets"],
                timeout=900,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # Tool should be marked as failed
            assert statuses["semgrep-secrets"] is False

            # Attempts should be recorded in metadata
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["semgrep-secrets"] == 3

    def test_scan_repository_checkov_cicd_directory_handling(self, tmp_path):
        """Test checkov-cicd special directory handling (temp dir + file move)"""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('hello')")
        workflows = repo / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("name: CI\non: [push]")

        def mock_find_tool(tool: str):
            return "/usr/bin/checkov" if tool == "checkov" else None

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            # Create the temp file that checkov would create
            temp_dir = tmp_path / "test-repo" / "checkov-cicd-temp"
            temp_dir.mkdir(parents=True)
            temp_file = temp_dir / "results_json.json"
            temp_file.write_text("{}")

            mock_runner.run_all_parallel.return_value = [
                ToolResult(
                    tool="checkov-cicd",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=temp_file,
                    capture_stdout=False,
                    error_message="",
                ),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["checkov-cicd"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            assert statuses["checkov-cicd"] is True
            # Verify final checkov-cicd.json exists after file move
            final_file = tmp_path / "test-repo" / "checkov-cicd.json"
            assert final_file.exists()

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


class TestAccountingNamesProfileToolsOnly:
    """The three accounting diagnostics must speak in profile-tool names.

    `_find_tool` records whatever binary it was asked to resolve, but several
    blocks resolve a binary that is not the tool the user asked for:
    checkov-cicd runs `checkov`, trivy-rbac runs `trivy`, semgrep-secrets runs
    `semgrep`, zap runs `zap-baseline.py` plus `docker`, afl++ runs `afl-fuzz`.

    Two consequences, both measured on terragoat with `--profile-name deep`:

      Requested but not applicable to repository targets (no repository
      implementation): checkov-cicd, opa, semgrep-secrets, trivy-rbac, zap

    three of those five wrote output files in the same run - because
    `not_implemented` is `set(tools) - considered` and `considered` only ever
    saw the binary names. And:

      docker: requested but its executable could not be found - it did NOT run
      and its findings are MISSING from this scan

    `docker` is not a tool in any profile; it is a dependency of one.
    """

    def _scan(self, tmp_path, tools, resolvable, caplog):
        import logging

        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        (repo / "index.html").write_text("<html></html>")

        with (
            patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner,
            caplog.at_level(logging.DEBUG),
        ):
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []
            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=tools,
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=lambda t: (f"/usr/bin/{t}" if t in resolvable else None),
            )
        return caplog.text

    def test_variant_tool_is_not_called_unimplemented(self, tmp_path, caplog):
        """checkov-cicd is implemented; it must not be reported otherwise."""
        text = self._scan(
            tmp_path,
            tools=["checkov-cicd"],
            resolvable={"checkov"},
            caplog=caplog,
        )
        assert "no repository implementation" not in text or "checkov-cicd" not in (
            text.split("no repository implementation")[1]
            if "no repository implementation" in text
            else ""
        ), f"checkov-cicd was called unimplemented while its block ran:\n{text}"

    def test_missing_dependency_is_reported_against_its_own_tool(
        self, tmp_path, caplog
    ):
        """zap's missing helper must be reported as zap, not as `docker`."""
        text = self._scan(
            tmp_path,
            tools=["zap"],
            resolvable=set(),  # neither zap-baseline.py nor docker resolve
            caplog=caplog,
        )
        assert "docker: requested but" not in text, (
            f"`docker` is a dependency, not a profile tool, and was reported as "
            f"a tool whose findings are missing:\n{text}"
        )
        assert "zap" in text, f"zap's own failure went unreported:\n{text}"


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
                        tool="prowler",
                        status="error",
                        returncode=3,
                        error_message="exited with return code 3",
                        attempts=1,
                    )
                ],
                ["prowler"],
            )

        assert statuses["prowler"] is False
        assert "prowler" in caplog.text
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
                        tool="dependency-check",
                        status="error",
                        timed_out=True,
                        error_message="Timeout after 1200s",
                        attempts=1,
                    )
                ],
                ["dependency-check"],
            )

        assert statuses["dependency-check"] is False
        assert "dependency-check" in caplog.text
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


class TestScancodeIsAskedToDetectSomething:
    """#835: scancode ran for up to 20 minutes and could not produce a finding.

    ScanCode emits detection data only for the detectors it is asked for. JMo
    asked for none, so it walked the tree and wrote structure only -- `path`,
    `type`, `scan_errors` -- while `scancode_adapter` reads `license_detections`
    and `copyrights`. Neither key could exist in output produced that way.

    Measured against the real scancode 32.5.0 rather than its documentation,
    which is what the issue asked for before shipping:

    | invocation | keys/entry | license_detections | adapter findings |
    |---|---|---|---|
    | as JMo invoked it | 3 | 0 | **0** |
    | `--license --copyright` | 11 | 2 | **2** |
    | + `--package --info` | 34 | 2 | **2** |

    The last row is why the flag set is two and not the four the issue
    suggested: the extra pair adds 23 keys per entry that nothing reads, on a
    tree that ran to 30,496 entries in the recorded juice-shop scan.
    """

    def _scancode_command(self, tmp_path) -> list[str]:
        """The argv `scan_repository` builds for scancode, captured."""
        from scripts.core.tool_runner import ToolResult

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "LICENSE").write_text("MIT License\n")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="scancode", status="success", attempts=1)
            ]
            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["scancode"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                # `_find_tool` is a closure over `scan_repository`, so it cannot
                # be patched on the module. The function takes this injection
                # point for exactly this reason.
                find_tool_func=lambda name: (
                    "/usr/bin/scancode" if name == "scancode" else None
                ),
            )
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])

        scancode_defs = [d for d in tool_defs if d.name == "scancode"]
        assert (
            len(scancode_defs) == 1
        ), f"expected exactly one scancode invocation, got {len(scancode_defs)}"
        return list(scancode_defs[0].command)

    def test_the_detectors_the_adapter_reads_are_requested(self, tmp_path):
        cmd = self._scancode_command(tmp_path)
        assert "--license" in cmd, (
            "scancode is invoked with no license detector, so "
            "`license_detections` cannot appear in its output and the adapter "
            f"cannot produce a finding: {cmd}"
        )
        assert "--copyright" in cmd, f"no copyright detector requested: {cmd}"

    def test_the_flag_set_stays_minimal(self, tmp_path):
        """Negative control, and the reason it is two flags and not four.

        Without this, adding every detector scancode offers would pass the test
        above while making a `deep` scan slower and its output larger for data
        no adapter reads.
        """
        cmd = self._scancode_command(tmp_path)
        unread_detectors = [
            f for f in ("--package", "--info", "--email", "--url") if f in cmd
        ]
        assert not unread_detectors, (
            "these detectors produce keys `scancode_adapter` never reads, at a "
            f"cost paid on every entry of the scanned tree: {unread_detectors}"
        )

    def test_per_tool_flags_are_still_appended(self, tmp_path):
        """The defaults must not displace configuration.

        `get_tool_flags("scancode")` resolves `per_tool.scancode.flags`, and a
        user who adds a detector must still get it.
        """
        from scripts.core.tool_runner import ToolResult

        repo = tmp_path / "repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="scancode", status="success", attempts=1)
            ]
            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["scancode"],
                timeout=600,
                retries=0,
                per_tool_config={"scancode": {"flags": ["--max-depth", "3"]}},
                allow_missing_tools=False,
                find_tool_func=lambda name: (
                    "/usr/bin/scancode" if name == "scancode" else None
                ),
            )
            args, kwargs = MockRunner.call_args
            defs = kwargs.get("tools") or (args[0] if args else [])

        cmd = next(d.command for d in defs if d.name == "scancode")
        assert "--max-depth" in cmd and "3" in cmd, f"per-tool flags dropped: {cmd}"
        assert "--license" in cmd, f"defaults dropped by per-tool config: {cmd}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestHorusecStagingDirIsExcluded:
    """#1132: horusec stages a copy of the whole repository at
    `<repo>/.horusec/<uuid>` and deletes it while every other scanner is still
    walking the tree. There is no horusec flag to relocate it - measured against
    `horusec start --help` - so the defence is to exclude it everywhere else.
    """

    @staticmethod
    def _built_commands(tmp_path, tools):
        """Build the real argv for `tools` without needing a tool installed."""
        repo = tmp_path / "repo"
        (repo / "k8s").mkdir(parents=True)
        # trivy-rbac only builds a command when the repo has K8s manifests.
        (repo / "k8s" / "deployment.yaml").write_text("kind: Deployment\n")

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

        assert "--exclude=.horusec" in commands["semgrep"]

    def test_semgrep_secrets_is_told_to_skip_it(self, tmp_path):
        """semgrep-secrets is where the 346 measured errors came from.

        It is a separate profile entry with a separate command builder, so
        covering only the tool the binary is named after would have left the
        measured defect exactly where it was.
        """
        commands = self._built_commands(tmp_path, ["semgrep-secrets"])

        assert "--exclude=.horusec" in commands["semgrep-secrets"]

    def test_trivy_is_told_to_skip_it(self, tmp_path):
        commands = self._built_commands(tmp_path, ["trivy"])
        command = commands["trivy"]

        assert "--skip-dirs" in command
        assert command[command.index("--skip-dirs") + 1] == ".horusec"

    def test_trivy_rbac_is_told_to_skip_it(self, tmp_path):
        commands = self._built_commands(tmp_path, ["trivy-rbac"])
        command = commands["trivy-rbac"]

        assert "--skip-dirs" in command
        assert command[command.index("--skip-dirs") + 1] == ".horusec"

    def test_bandit_is_told_to_skip_it_without_losing_its_defaults(self, tmp_path):
        """bandit's -x replaces upstream's list, so JMo has to re-send it.

        The expected value is spelled out rather than derived from the source
        constant: a guard that reads its expectation from the thing it guards
        cannot fail when that thing empties (#1061).
        """
        commands = self._built_commands(tmp_path, ["bandit"])
        command = commands["bandit"]

        assert "-x" in command
        assert (
            command[command.index("-x") + 1]
            == ".svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.horusec"
        )

    def test_dependency_check_is_told_to_skip_it(self, tmp_path):
        """ODC was the loudest casualty: 8499 non-fatal analysis exceptions on
        jmoadaptivegolf, almost all naming a vanished `.horusec/<uuid>/` path.

        It takes an Ant pattern, so a bare directory name would not match.
        """
        commands = self._built_commands(tmp_path, ["dependency-check"])
        command = commands["dependency-check"]

        assert "--exclude" in command
        assert command[command.index("--exclude") + 1] == "**/.horusec/**"

    def test_jmos_own_file_walk_skips_the_staging_copy(self, tmp_path):
        """hadolint and shellcheck take explicit file arguments, so JMo's own
        enumeration is a walk like any other.

        Without this, every Dockerfile and shell script is collected twice -
        once at its real path and once inside the staged copy, which may be
        deleted before the tool opens it - and the duplicates count against
        MAX_FILE_ARGS, evicting real files from a large repository.
        """
        from scripts.cli.scan_jobs.repository_scanner import _collect_files

        repo = tmp_path / "repo"
        (repo / "docker").mkdir(parents=True)
        (repo / "docker" / "Dockerfile").write_text("FROM alpine:3.19\n")
        staged = repo / ".horusec" / "8317cf15-dead-beef" / "docker"
        staged.mkdir(parents=True)
        (staged / "Dockerfile").write_text("FROM alpine:3.19\n")

        found = _collect_files(repo, ("**/Dockerfile",), "hadolint")

        assert len(found) == 1, f"staged copy was collected too: {found}"
        assert ".horusec" not in found[0]
