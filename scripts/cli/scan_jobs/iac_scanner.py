"""
Infrastructure as Code (IaC) Scanner

Scans one IaC file with the tools that read one (checkov `-f`, `trivy
config`), through the loop in `tool_loop`; every other requested tool gets a
`skipped` row.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ...core.config import RetryConfig
from ...core.scan_timings import TargetRows
from ...core.tool_runner import ToolRunner
from ..path_sanitizers import _sanitize_path_component, _validate_output_path
from .tool_loop import run_tools


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
) -> tuple[str, TargetRows]:
    """Scan an IaC file (terraform, cloudformation, k8s manifest).

    Returns:
        ("<iac_type>:<file name>", rows by tool)
    """
    # The file's stem names the folder (sanitized against path traversal).
    safe_name = _sanitize_path_component(iac_path.stem)
    out_dir = results_dir / safe_name
    _validate_output_path(results_dir, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    rows = run_tools(
        tools=tools,
        target_type="iac",
        target=iac_path,
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
    return f"{iac_type}:{iac_path.name}", rows
