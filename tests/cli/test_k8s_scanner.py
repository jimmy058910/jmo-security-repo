"""
Tests for Kubernetes Scanner

Tests the k8s_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.k8s_scanner import scan_k8s_resource


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
            )

            # Verify --all-namespaces flag is used
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs["tools"]
            trivy_def = tool_defs[0]
            assert "--all-namespaces" in trivy_def.command

    def test_scan_k8s_custom_context(self, tmp_path):
        """Test K8s scanning with custom context"""
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
            )

            # Verify --context flag is used
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs["tools"]
            trivy_def = tool_defs[0]
            assert "--context" in trivy_def.command
            assert "production" in trivy_def.command

    def test_scan_k8s_sanitizes_name(self, tmp_path):
        """Test that context/namespace are sanitized for directory names"""
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
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check sanitized directory
            expected_dir = tmp_path / "individual-k8s" / "cluster-01_kube-system"
            assert expected_dir.exists()

    def test_scan_k8s_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
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
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs["tools"]
            trivy_def = next(t for t in tool_defs if t.name == "trivy")
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
