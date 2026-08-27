"""
Tests for Kubernetes Scanner

Tests the k8s_scanner module with various scenarios.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.k8s_scanner import scan_k8s_resource
from scripts.cli.scan_utils import not_attempted_tools


class TestK8sScanner:
    """Test K8s scanner functionality"""

    def test_scan_k8s_basic(self, tmp_path):
        """Test basic K8s scanning with trivy"""
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "minikube",
                "namespace": "default",
            }

            identifier, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert identifier == "minikube:default"
            assert statuses["trivy"] is True

    def test_scan_k8s_all_namespaces(self, tmp_path):
        """Test K8s scanning with all namespaces"""

        # Mock find_tool to return path for trivy
        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "prod",
                "namespace": "all",
                "all_namespaces": "True",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            # trivy has no --all-namespaces flag; it scans every namespace
            # unless --include-namespaces narrows it. This asserted
            # "--all-namespaces" in the command until #803 - which trivy 0.70.0
            # answers with `FATAL unknown flag: --all-namespaces`, killing the
            # run at argument parsing. The test passed because it only ever
            # inspected the command JMo built, never what trivy accepts.
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None, "trivy tool definition not found"
            assert "--all-namespaces" not in trivy_def.command
            assert "--include-namespaces" not in trivy_def.command

    def test_scan_k8s_custom_context(self, tmp_path):
        """Test K8s scanning with custom context"""

        # Mock find_tool to return path for trivy
        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "production",
                "namespace": "app",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            # trivy's usage is `trivy kubernetes [flags] [CONTEXT]` - context is
            # POSITIONAL and must be last. There is no --context flag; passing
            # one is `FATAL unknown flag: --context` (#803).
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None, "trivy tool definition not found"
            assert "--context" not in trivy_def.command
            assert trivy_def.command[-1] == "production", (
                "context must be the trailing positional argument, got: "
                f"{trivy_def.command}"
            )
            # The old command also appended a literal "all" after -o, which
            # trivy read as the context name.
            assert "all" not in trivy_def.command

    def test_scan_k8s_sanitizes_name(self, tmp_path):
        """Test that context/namespace are sanitized for directory names"""
        # Create individual-k8s subdirectory (matches production usage in scan_orchestrator)
        k8s_results_dir = tmp_path / "individual-k8s"

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "cluster-01",
                "namespace": "kube-system",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=k8s_results_dir,  # Pass individual-k8s directory (matches production)
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check sanitized directory
            expected_dir = k8s_results_dir / "cluster-01_kube-system"
            assert expected_dir.exists()

    def test_scan_k8s_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""

        # Mock find_tool to return path for trivy
        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "trivy": {"timeout": 1200, "flags": ["--severity", "CRITICAL"]}
            }

            k8s_info = {
                "context": "current",
                "namespace": "default",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
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
            assert "CRITICAL" in trivy_def.command

    def test_scan_k8s_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="error", returncode=1, attempts=1),
            ]

            k8s_info = {
                "context": "broken",
                "namespace": "test",
            }

            identifier, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is False

    def test_scan_k8s_with_retries(self, tmp_path):
        """Test K8s scanning with retries"""
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=2),
            ]

            k8s_info = {
                "context": "retry-test",
                "namespace": "app",
            }

            identifier, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["trivy"] == 2

    def test_allow_missing_tools_writes_stubs(self, tmp_path):
        """Test that allow_missing_tools writes stubs for missing tools"""

        def mock_find_tool(tool_name):
            return None  # No tools found

        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, str(output_path)))
            output_path.write_text("{}")

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            k8s_info = {
                "context": "prod",
                "namespace": "default",
            }

            identifier, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            # Trivy should have stub written
            assert len(stub_calls) == 1
            assert any("trivy" in path for _, path in stub_calls)
            # Stubbed, so it did not succeed. This read `is True`, which
            # encoded the defect as the contract (#825).
            assert statuses["trivy"] is False
            assert not_attempted_tools(statuses) == ["trivy"]

    def test_per_tool_flags_applied(self, tmp_path):
        """Test that per_tool_config flags are correctly applied"""

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "trivy": {
                    "flags": ["--severity", "CRITICAL", "--scanners", "config,secret"]
                }
            }

            k8s_info = {
                "context": "staging",
                "namespace": "app",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
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

            # Verify trivy flags
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None
            assert "--severity" in trivy_def.command
            assert "CRITICAL" in trivy_def.command

    def test_scan_k8s_current_context(self, tmp_path):
        """Test K8s scanning with current context (no --context flag added)"""

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "current",
                "namespace": "default",
                "all_namespaces": "False",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            # Verify trivy command does NOT include --context flag
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None
            assert "--context" not in trivy_def.command

    def test_scan_k8s_specific_namespace(self, tmp_path):
        """A named namespace narrows the scan with --include-namespaces.

        Not -n: trivy answers that with `FATAL unknown shorthand flag: 'n'`
        (#803).
        """

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "prod",
                "namespace": "monitoring",
                "all_namespaces": "False",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None
            assert "-n" not in trivy_def.command
            assert "--include-namespaces" in trivy_def.command
            ns_index = trivy_def.command.index("--include-namespaces")
            assert trivy_def.command[ns_index + 1] == "monitoring"

    def test_scan_k8s_default_namespace_no_n_flag(self, tmp_path):
        """Test K8s scanning with default namespace does NOT add -n flag"""

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "prod",
                "namespace": "default",
                "all_namespaces": "False",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None
            assert "-n" not in trivy_def.command
            assert "--include-namespaces" not in trivy_def.command

    def test_trivy_k8s_command_is_accepted_by_trivys_own_grammar(self, tmp_path):
        """Pin the whole command shape, not one flag at a time.

        Every flag in the pre-#803 command was rejected by trivy, and four
        separate tests passed anyway because each asserted only on the argv JMo
        built. This asserts the grammar trivy documents -
        `trivy kubernetes [flags] [CONTEXT]` - so a regression in any single
        position fails here.
        """

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value = MagicMock()

            from scripts.core.tool_runner import ToolResult

            MockRunner.return_value.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            scan_k8s_resource(
                k8s_info={"context": "prod", "namespace": "monitoring"},
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            cmd = next(t for t in tool_defs if t.name == "trivy").command

            assert cmd[1] == "k8s"
            # Flags trivy 0.70.0 does not have on `k8s`, each measured as a
            # FATAL parse error before any cluster contact.
            for rejected in ("--context", "-n", "--all-namespaces"):
                assert rejected not in cmd, f"trivy k8s rejects {rejected}"
            # Context is the trailing positional, and nothing follows it.
            assert cmd[-1] == "prod"
            # -o must still carry the output path.
            assert cmd[cmd.index("-o") + 1].endswith("trivy.json")

    def test_all_namespaces_is_reachable_via_the_star_namespace(self, tmp_path):
        """The live discovery path signals all-namespaces with namespace="*".

        scan_orchestrator._discover_k8s_resources writes namespace="*" and no
        all_namespaces key at all, so reading only the key made
        --k8s-all-namespaces unreachable in production (#803).
        """

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value = MagicMock()

            from scripts.core.tool_runner import ToolResult

            MockRunner.return_value.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            scan_k8s_resource(
                k8s_info={"context": "prod", "namespace": "*"},
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            cmd = next(t for t in tool_defs if t.name == "trivy").command

            # No namespace filter at all == every namespace, which is trivy's
            # default. A literal "*" must never be passed through.
            assert "--include-namespaces" not in cmd
            assert "*" not in cmd

    def test_scan_k8s_sanitized_directory_special_chars(self, tmp_path):
        """Test directory name sanitization for context/namespace with special chars"""
        k8s_results_dir = tmp_path / "individual-k8s"

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "prod/west",
                "namespace": "app*",
                "all_namespaces": "False",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=k8s_results_dir,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            # Verify sanitized directory created (/ -> _, * -> all)
            sanitized_dir = k8s_results_dir / "prod_west_appall"
            assert sanitized_dir.exists()

    def test_scan_k8s_custom_find_tool_func(self, tmp_path):
        """Test using custom find_tool_func"""

        def mock_find_tool(tool_name):
            return f"/usr/bin/{tool_name}" if tool_name == "trivy" else None

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            k8s_info = {
                "context": "prod",
                "namespace": "default",
            }

            identifier, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
            )

            assert "trivy" in statuses

    def test_scan_k8s_custom_write_stub_func(self, tmp_path):
        """Test using custom write_stub_func"""
        stub_calls = []

        def mock_find_tool(tool_name):
            return None  # No tools found

        def mock_write_stub(tool: str, path) -> None:
            stub_calls.append((tool, path))

        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner
            mock_runner.run_all_parallel.return_value = []

            k8s_info = {
                "context": "prod",
                "namespace": "default",
            }

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=mock_find_tool,
                write_stub_func=mock_write_stub,
            )

            assert len(stub_calls) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
