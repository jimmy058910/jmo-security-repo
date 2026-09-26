"""
Web URL Scanner (DAST)

Scans a live web application with the tools that read a URL (zap, nuclei),
through the loop in `tool_loop`; every other requested tool gets a `skipped`
row.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from ...core.config import RetryConfig
from ...core.scan_timings import TargetRows
from ...core.tool_runner import ToolRunner
from .tool_loop import run_tools

ALLOWED_SCHEMES = frozenset({"http", "https"})


def url_folder_name(url: str) -> str:
    """The folder a URL's results land in: its host, sanitized. Two URLs on
    one host share it, so a scan makes each unique (#1312)."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", urlparse(url).netloc or "unknown")


def scan_url(
    url: str,
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    find_tool_func: Callable[[str], str | None] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
    result_name: str | None = None,
) -> tuple[str, TargetRows]:
    """Scan a live URL (http:// or https://).

    Args:
        result_name: This URL's results folder, unique within the scan
            (#1312). Defaults to `url_folder_name`.

    Returns:
        (url, rows by tool)
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. "
            f"Only HTTP(S) URLs are supported for web scanning. "
            f"Use --repo for local filesystem scanning."
        )

    safe_name = result_name or url_folder_name(url)
    out_dir = results_dir / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = run_tools(
        tools=tools,
        target_type="url",
        target=url,
        target_label=url,
        out_dir=out_dir,
        timeout=timeout,
        retries=retries,
        per_tool_config=per_tool_config,
        allow_missing_tools=allow_missing_tools,
        runner_cls=ToolRunner,
        find_tool_func=find_tool_func,
        write_stub_func=write_stub_func,
    )
    return url, rows
