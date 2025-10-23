"""
Web URL Scanner (DAST)

Scans live web applications and APIs using:
- OWASP ZAP: Dynamic Application Security Testing (DAST)
- Nuclei: Fast vulnerability scanner with 4000+ templates (CVEs, misconfigs, exposures)

Integrates with ToolRunner for execution management.
"""

import re
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Callable, Optional

from ...core.tool_runner import ToolRunner, ToolDefinition
from ..scan_utils import tool_exists, write_stub


def scan_url(
    url: str,
    results_dir: Path,
    tools: List[str],
    timeout: int,
    retries: int,
    per_tool_config: Dict,
    allow_missing_tools: bool,
    tool_exists_func: Optional[Callable[[str], bool]] = None,
    write_stub_func: Optional[Callable[[str, Path], None]] = None,
) -> Tuple[str, Dict[str, bool]]:
    """
    Scan a live web URL with DAST tools (ZAP and Nuclei).

    Args:
        url: Web application URL (http:// or https://)
        results_dir: Base results directory
        tools: List of tools to run ('zap' and/or 'nuclei')
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check if tool exists (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (url, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    # Use provided functions or defaults
    _tool_exists = tool_exists_func or tool_exists
    _write_stub = write_stub_func or write_stub

    statuses: Dict[str, bool] = {}
    tool_defs = []

    # Validate URL scheme - only HTTP(S) allowed for DAST scanning
    parsed = urlparse(url)
    ALLOWED_SCHEMES = {"http", "https"}
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. "
            f"Only HTTP(S) URLs are supported for web scanning. "
            f"Use --repo for local filesystem scanning."
        )

    # Sanitize URL for directory name (extract domain)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.netloc or "unknown")

    out_dir = results_dir / "individual-web" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    def get_tool_timeout(tool: str, default: int) -> int:
        """Get timeout override for specific tool."""
        tool_cfg = per_tool_config.get(tool, {})
        if isinstance(tool_cfg, dict):
            override = tool_cfg.get("timeout")
            if isinstance(override, int) and override > 0:
                return override
        return default

    def get_tool_flags(tool: str) -> List[str]:
        """Get additional flags for specific tool."""
        tool_cfg = per_tool_config.get(tool, {})
        if isinstance(tool_cfg, dict):
            flags = tool_cfg.get("flags", [])
            if isinstance(flags, list):
                return [str(f) for f in flags]
        return []

    # ZAP scan for web URLs
    if "zap" in tools:
        zap_out = out_dir / "zap.json"
        if _tool_exists("zap"):
            zap_flags = get_tool_flags("zap")

            # Determine ZAP command (zap.sh on Linux/macOS, zap on Windows)
            import shutil

            zap_cmd = "zap.sh" if shutil.which("zap.sh") else "zap"

            zap_cmd_list = [
                zap_cmd,
                "-cmd",
                "-quickurl",
                url,
                "-quickout",
                str(zap_out),
                "-quickprogress",
                *zap_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="zap",
                    command=zap_cmd_list,
                    output_file=zap_out,
                    timeout=get_tool_timeout("zap", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1, 2),  # ZAP may return 1 or 2 for findings
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("zap", zap_out)
            statuses["zap"] = True

    # Nuclei scan for web URLs (CVEs, misconfigurations, exposures)
    if "nuclei" in tools:
        nuclei_out = out_dir / "nuclei.json"
        if _tool_exists("nuclei"):
            nuclei_flags = get_tool_flags("nuclei")

            # Nuclei command for URL scanning
            nuclei_cmd_list = [
                "nuclei",
                "-u",
                url,
                "-json",  # NDJSON output format
                "-o",
                str(nuclei_out),
                "-silent",  # Reduce console noise
                "-no-color",
                *nuclei_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="nuclei",
                    command=nuclei_cmd_list,
                    output_file=nuclei_out,
                    timeout=get_tool_timeout("nuclei", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),  # 0=clean, 1=findings
                    capture_stdout=False,  # Nuclei writes to file
                )
            )
        elif allow_missing_tools:
            _write_stub("nuclei", nuclei_out)
            statuses["nuclei"] = True

    # Execute all tools with ToolRunner
    runner = ToolRunner(
        tools=tool_defs,
    )
    results = runner.run_all_parallel()

    # Process results
    attempts_map: Dict[str, int] = {}
    for result in results:
        if result.status == "success":
            # Write stdout to file ONLY if we captured it (capture_stdout=True)
            if result.output_file and result.capture_stdout:
                result.output_file.write_text(result.stdout or "", encoding="utf-8")
            statuses[result.tool] = True
            if result.attempts > 1:
                attempts_map[result.tool] = result.attempts
        elif result.status == "error" and "Tool not found" in result.error_message:
            # Tool doesn't exist - write stub if allow_missing_tools
            if allow_missing_tools:
                tool_out = out_dir / f"{result.tool}.json"
                _write_stub(result.tool, tool_out)
                statuses[result.tool] = True
            else:
                statuses[result.tool] = False
        else:
            # Other errors (timeout, non-zero exit, etc.)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts

    # Include attempts metadata if any retries occurred
    if attempts_map:
        statuses["__attempts__"] = attempts_map  # type: ignore

    return url, statuses
