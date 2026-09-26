"""
Repository Scanner

Scans a local repository with every requested matrix tool, through the one
loop in `tool_loop`: each tool's command line, content trigger and exclusion
spelling are declared in `scripts/core/tool_descriptors.py`. Every requested
tool comes back with exactly one accounting row, including the ones that did
not run and why (#1227).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from ...core.config import RetryConfig
from ...core.scan_timings import TargetRows
from ...core.tool_runner import ToolRunner
from ..path_sanitizers import _sanitize_path_component, _validate_output_path
from ..scan_utils import TOOL_TIMEOUT_DEFAULTS, in_tree_results_name
from .tool_loop import run_tools

logger = logging.getLogger(__name__)

# TOOL_TIMEOUT_DEFAULTS is re-exported for the readers that reach for it by
# this name; it is derived from the descriptors in scan_utils.
__all__ = ["TOOL_TIMEOUT_DEFAULTS", "scan_repository"]


def scan_repository(
    repo: Path,
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    write_stub_func: Callable[[str, Path], None] | None = None,
    find_tool_func: Callable[[str], str | None] | None = None,
    progress_callback: Callable[[str, str, int], None] | None = None,
    result_name: str | None = None,
    target_type: str = "repo",
) -> tuple[str, TargetRows]:
    """Scan a repository with every requested tool.

    Args:
        repo: The repository to scan.
        results_dir: `<results>/individual-repos` (or a GitLab job's temp dir).
        tools: The requested tools, all of them; one row comes back for each.
        timeout: Default per-tool timeout in seconds.
        retries: Retries for flaky tools.
        per_tool_config: Per-tool configuration overrides.
        allow_missing_tools: A missing tool is `skipped:not installed` rather
            than `failed:not installed`.
        write_stub_func: Optional stub writer (for testing).
        find_tool_func: Optional tool resolver (for testing).
        progress_callback: Optional callback(tool_name, status, findings_count).
        result_name: This repository's results folder, unique within the scan
            (#1303). Defaults to the sanitized folder name.
        target_type: 'repo', or 'gitlab' for a GitLab clone.

    Returns:
        (results folder name, rows by tool)
    """
    name = result_name or _sanitize_path_component(repo.name)
    out_dir = results_dir / name
    _validate_output_path(results_dir, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # `jmo scan . --results-dir ./results` puts JMo's output inside the tree
    # the next scan walks, so every tool reads JMo's own artifacts back.
    # Measured on juice-shop: 90 of 831 findings (10.8%) were tools reporting a
    # previous scan's `results/`, scaling with how often the user had scanned
    # (#1156). `results_dir` is `<root>/individual-repos`, not the root: the
    # root holds `summaries/`, whose findings.json, findings.yaml and
    # dashboard.html each embed every finding verbatim. Guarded rather than
    # assumed, so a caller that one day hands over the root still works.
    results_root = (
        results_dir.parent
        if results_dir.name.startswith("individual-")
        else results_dir
    )
    results_name = in_tree_results_name(repo, results_root)
    if results_name:
        logger.debug(
            "Results directory %s is inside %s; excluding '%s' from the scan",
            results_root,
            repo.name,
            results_name,
        )
    rows = run_tools(
        tools=tools,
        target_type=target_type,
        target=repo,
        target_label=name,
        out_dir=out_dir,
        timeout=timeout,
        retries=retries,
        per_tool_config=per_tool_config,
        allow_missing_tools=allow_missing_tools,
        runner_cls=ToolRunner,
        find_tool_func=find_tool_func,
        write_stub_func=write_stub_func,
        progress_callback=progress_callback,
        repo_root=repo,
        results_name=results_name,
        # The precise form, for JMo's own walk: the exact directory, not every
        # directory of that name.
        results_tree=results_root.resolve() if results_name else None,
    )
    return name, rows
