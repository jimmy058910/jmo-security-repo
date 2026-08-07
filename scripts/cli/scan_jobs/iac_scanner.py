"""
Infrastructure as Code (IaC) Scanner

Scans IaC files using:
- Checkov: Policy-as-code scanner for Terraform, CloudFormation, Kubernetes
- Trivy: Configuration scanning for misconfigurations

Integrates with ToolRunner for execution management.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from ...core.config import RetryConfig
from ...core.scan_timings import write_scan_timings
from ...core.tool_runner import ToolDefinition, ToolRunner
from ..path_sanitizers import _sanitize_path_component, _validate_output_path
from ..scan_utils import find_tool, report_tool_failure, write_stub


def scan_iac_file(
    iac_type: str,
    iac_path: Path,
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    find_tool_func: Callable[[str], str | None] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
) -> tuple[str, dict[str, bool]]:
    """
    Scan an IaC file with checkov and trivy.

    Args:
        iac_type: Type of IaC file (terraform, cloudformation, k8s)
        iac_path: Path to IaC file
        results_dir: Base results directory
        tools: List of tools to run (must include 'checkov' and/or 'trivy')
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        find_tool_func: Optional function to find tool path (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (iac_identifier, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    # Use provided functions or defaults
    _find_tool = find_tool_func or find_tool
    _write_stub = write_stub_func or write_stub

    statuses: dict[str, bool] = {}
    tool_defs = []

    # Use filename as directory name (sanitized to prevent path traversal)
    safe_name = _sanitize_path_component(iac_path.stem)
    out_dir = results_dir / safe_name
    _validate_output_path(results_dir, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def get_tool_timeout(tool: str, default: int) -> int:
        """Get timeout override for specific tool."""
        tool_cfg = per_tool_config.get(tool, {})
        if isinstance(tool_cfg, dict):
            override = tool_cfg.get("timeout")
            if isinstance(override, int) and override > 0:
                return override
        return default

    def get_tool_flags(tool: str) -> list[str]:
        """Get additional flags for specific tool."""
        tool_cfg = per_tool_config.get(tool, {})
        if isinstance(tool_cfg, dict):
            flags = tool_cfg.get("flags", [])
            if isinstance(flags, list):
                return [str(f) for f in flags]
        return []

    # Checkov IaC scan
    if "checkov" in tools:
        checkov_out = out_dir / "checkov.json"
        checkov_path = _find_tool("checkov")
        if checkov_path:
            checkov_flags = get_tool_flags("checkov")
            checkov_cmd = [
                checkov_path,
                "-f",
                str(iac_path),
                "-o",
                "json",
                *checkov_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="checkov",
                    command=checkov_cmd,
                    output_file=checkov_out,
                    timeout=get_tool_timeout("checkov", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),  # 0=clean, 1=findings
                    capture_stdout=True,  # Checkov writes to stdout
                )
            )
        elif allow_missing_tools:
            _write_stub("checkov", checkov_out)
            statuses["checkov"] = True

    # Trivy config scan for IaC files
    if "trivy" in tools:
        trivy_out = out_dir / "trivy.json"
        trivy_path = _find_tool("trivy")
        if trivy_path:
            trivy_flags = get_tool_flags("trivy")
            trivy_cmd = [
                trivy_path,
                "config",
                "-q",
                "-f",
                "json",
                *trivy_flags,
                str(iac_path),
                "-o",
                str(trivy_out),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="trivy",
                    command=trivy_cmd,
                    output_file=trivy_out,
                    timeout=get_tool_timeout("trivy", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),  # 0=clean, 1=findings
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("trivy", trivy_out)
            statuses["trivy"] = True

    # Execute all tools with ToolRunner
    runner = ToolRunner(
        tools=tool_defs,
    )
    tools_started = time.perf_counter()
    results = runner.run_all_parallel()

    # ToolRunner already timed and classified every invocation. Record that
    # before the loop below reduces the results to booleans (#722).
    write_scan_timings(
        out_dir,
        results,
        target=safe_name,
        target_type="iac",
        wall_seconds=time.perf_counter() - tools_started,
    )

    # Process results
    attempts_map: dict[str, int] = {}
    for result in results:
        if result.status == "success":
            # Write stdout to file ONLY if we captured it (capture_stdout=True)
            if result.output_file and result.capture_stdout:
                result.output_file.write_text(result.stdout or "", encoding="utf-8")
            statuses[result.tool] = True
            if result.attempts > 1:
                attempts_map[result.tool] = result.attempts
        elif result.status == "error" and "Tool not found" in result.error_message:
            # The tool resolved in pre-flight and then could not be executed -
            # always a defect, never something --allow-missing-tools consents
            # to. See repository_scanner for the measured case: find_tool's
            # "python:yara" pseudo-path passed pre-flight, raised
            # FileNotFoundError at exec, and was recorded as a clean scan.
            statuses[result.tool] = False
            report_tool_failure(result, "its executable was not found at run time")
        else:
            # Other errors (timeout, non-zero exit, etc.)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts

    # Include attempts metadata if any retries occurred
    if attempts_map:
        statuses["__attempts__"] = attempts_map  # type: ignore[assignment]  # Store retry metadata alongside bool statuses

    return f"{iac_type}:{iac_path.name}", statuses
