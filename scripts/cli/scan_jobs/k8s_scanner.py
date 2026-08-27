"""
Kubernetes Cluster Scanner

Scans Kubernetes clusters using:
- Trivy: Kubernetes security scanning for misconfigurations, vulnerabilities

Integrates with ToolRunner for execution management.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from ...core.config import RetryConfig
from ...core.scan_timings import write_scan_timings
from ...core.tool_runner import ToolDefinition, ToolRunner
from ..scan_utils import (
    find_tool,
    record_not_attempted,
    report_tool_failure,
    tool_flags,
    tool_timeout,
    write_stub,
)


def scan_k8s_resource(
    k8s_info: dict[str, str],
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
    Scan a Kubernetes cluster with trivy.

    Args:
        k8s_info: Dict with keys: context, namespace, all_namespaces
        results_dir: Base results directory
        tools: List of tools to run (must include 'trivy')
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        find_tool_func: Optional function to find tool path (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (cluster_identifier, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    # Use provided functions or defaults
    _find_tool = find_tool_func or find_tool
    _write_stub = write_stub_func or write_stub

    statuses: dict[str, bool] = {}
    tool_defs = []

    context = k8s_info["context"]
    namespace = k8s_info["namespace"]
    # Two producers build this dict and they disagree: the live discovery path
    # (scan_orchestrator._discover_k8s_resources) signals "every namespace" by
    # writing namespace="*" and sets no all_namespaces key at all, so reading
    # only the key made --k8s-all-namespaces unreachable. Accept both shapes.
    all_namespaces = (
        str(k8s_info.get("all_namespaces", "False")) == "True" or namespace == "*"
    )

    safe_name = f"{context}_{namespace}".replace("/", "_").replace("*", "all")
    out_dir = results_dir / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    def get_tool_timeout(tool: str, default: int) -> int:
        """Timeout for this tool, honouring the slow-tool floor.

        Delegates to the shared implementation. This copy had no floor, so a
        tool with a `TOOL_TIMEOUT_DEFAULTS` minimum got only the profile default
        here while the same tool got its floor on a repository target -- `zap`
        runs on both and is 300 s short on a `balanced` URL scan.
        """
        return tool_timeout(per_tool_config, tool, default)

    def get_tool_flags(tool: str) -> list[str]:
        """Extra flags for this tool, minus any JMo must own.

        Delegates to the shared implementation: this was one of five identical
        copies, none of which filtered anything, so a `per_tool` flag could
        override JMo's own `-f`/`-o` and silently destroy the tool's findings
        (#822).
        """
        return tool_flags(per_tool_config, tool)

    # Trivy Kubernetes scan
    if "trivy" in tools:
        trivy_out = out_dir / "trivy.json"
        trivy_path = _find_tool("trivy")
        if trivy_path:
            trivy_flags = get_tool_flags("trivy")

            trivy_cmd = [
                trivy_path,
                "k8s",
                "-q",
                "-f",
                "json",
                *trivy_flags,
            ]

            # Namespace selection. trivy scans every namespace unless told
            # otherwise, so "all namespaces" is the absence of a filter rather
            # than a flag - there is no --all-namespaces. "default" is the
            # sentinel _discover_k8s_resources writes when the user named no
            # namespace, so it means "unspecified" here, not the namespace
            # literally called default.
            if not all_namespaces and namespace not in ("", "*", "default"):
                trivy_cmd.extend(["--include-namespaces", namespace])

            trivy_cmd.extend(["-o", str(trivy_out)])

            # Context is a POSITIONAL argument - `trivy kubernetes [flags]
            # [CONTEXT]` - so it goes last and takes no flag. This previously
            # passed --context, which trivy rejects outright, and then appended
            # a literal "all" that trivy read as the context name. Both killed
            # the run at argument parsing, before any cluster contact.
            if context and context != "current":
                trivy_cmd.append(context)

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
            record_not_attempted(statuses, "trivy")

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
        target_type="k8s",
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
        elif result.timed_out:
            # A timeout gets a stub so the report phase sees a consistent file
            # tree -- but the stub must never be the only signal. Once read, an
            # empty stub is indistinguishable from a tool that ran and found
            # nothing, so the timeout has to be stated on the log or it is lost.
            tool_out = out_dir / f"{result.tool}.json"
            if not tool_out.exists():
                _write_stub(result.tool, tool_out)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts
            report_tool_failure(result, "it timed out")
        else:
            # Other errors (non-zero exit, no output, etc.). This used to record
            # False and return without logging anything at all, so a tool that
            # failed contributed nothing to the scan and said so on no stream
            # (#727). A non-TTY run renders no progress display, which makes the
            # log the only durable record.
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts
            report_tool_failure(
                result,
                (
                    "it exited with an accepted code but wrote no output"
                    if result.status == "no_output"
                    else "it failed"
                ),
            )

    # Include attempts metadata if any retries occurred
    if attempts_map:
        statuses["__attempts__"] = attempts_map  # type: ignore[assignment]  # Store retry metadata alongside bool statuses

    # Return identifier in format "context:namespace"
    context = k8s_info.get("context", "unknown")
    namespace = k8s_info.get("namespace", "unknown")
    return f"{context}:{namespace}", statuses
