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
) -> tuple[str, TargetRows]:
    """Scan a live URL (http:// or https://).

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

    # The folder is the host, sanitized.
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.netloc or "unknown")
    out_dir = results_dir / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = run_tools(
        tools=tools,
        target_type="url",
        target=url,
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
    return url, rows
