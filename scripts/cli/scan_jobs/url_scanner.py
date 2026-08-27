"""
Web URL Scanner (DAST)

Scans live web applications and APIs using:
- OWASP ZAP: Dynamic Application Security Testing (DAST)
- Nuclei: Fast vulnerability scanner with 4000+ templates (CVEs, misconfigs, exposures)
- Akto: API Security testing for OWASP Top 10 API vulnerabilities (v1.0.0)

Integrates with ToolRunner for execution management.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

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
) -> tuple[str, dict[str, bool]]:
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
        find_tool_func: Optional function to find tool path (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (url, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    # Use provided functions or defaults
    _find_tool = find_tool_func or find_tool
    _write_stub = write_stub_func or write_stub

    statuses: dict[str, bool] = {}
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

    # ZAP scan for web URLs
    if "zap" in tools:
        zap_out = out_dir / "zap.json"
        # Find ZAP binary (zap.sh on Linux/macOS, zap on Windows)
        # find_tool checks PATH and ~/.jmo/bin/zap/zap.sh
        zap_path = _find_tool("zap.sh") or _find_tool("zap")
        if zap_path:
            zap_flags = get_tool_flags("zap")

            zap_cmd_list = [
                zap_path,  # Use full path from find_tool
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
            record_not_attempted(statuses, "zap")

    # Nuclei scan for web URLs (CVEs, misconfigurations, exposures)
    if "nuclei" in tools:
        nuclei_out = out_dir / "nuclei.json"
        nuclei_path = _find_tool("nuclei")
        if nuclei_path:
            nuclei_flags = get_tool_flags("nuclei")

            # Nuclei command for URL scanning
            nuclei_cmd_list = [
                nuclei_path,
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
            record_not_attempted(statuses, "nuclei")

    # Akto: API Security testing (OWASP Top 10 API vulnerabilities)
    # v1.0.0 addition
    if "akto" in tools:
        akto_out = out_dir / "akto.json"
        akto_path = _find_tool("akto")
        if akto_path:
            akto_flags = get_tool_flags("akto")

            # Akto requires API endpoint testing
            # Assumes Akto is running as a service and accessible via CLI
            akto_cmd_list = [
                akto_path,
                "test",
                "--url",
                url,
                "--output",
                str(akto_out),
                "--format",
                "json",
                *akto_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="akto",
                    command=akto_cmd_list,
                    output_file=akto_out,
                    timeout=get_tool_timeout("akto", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),  # 0=clean, 1=vulnerabilities found
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("akto", akto_out)
            record_not_attempted(statuses, "akto")

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
        target_type="url",
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

    return url, statuses
