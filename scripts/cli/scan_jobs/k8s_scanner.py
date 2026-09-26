"""
Kubernetes Cluster Scanner

Scans a cluster with the tool that reads one (`trivy k8s`), through the loop
in `tool_loop`; every other requested tool gets a `skipped` row.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ...core.config import RetryConfig
from ...core.scan_timings import TargetRows
from ...core.tool_runner import ToolRunner
from .tool_loop import run_tools


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
) -> tuple[str, TargetRows]:
    """Scan a cluster. `k8s_info` has context, namespace, and optionally
    all_namespaces (the trivy builder reads both producers' shapes).

    Returns:
        ("<context>:<namespace>", rows by tool)
    """
    context = k8s_info["context"]
    namespace = k8s_info["namespace"]
    safe_name = f"{context}_{namespace}".replace("/", "_").replace("*", "all")
    out_dir = results_dir / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = run_tools(
        tools=tools,
        target_type="k8s",
        target=k8s_info,
        target_label=safe_name,
        out_dir=out_dir,
        timeout=timeout,
        retries=retries,
        per_tool_config=per_tool_config,
        allow_missing_tools=allow_missing_tools,
        runner_cls=ToolRunner,
        find_tool_func=find_tool_func,
        write_stub_func=write_stub_func,
    )
    return f"{context}:{namespace}", rows
