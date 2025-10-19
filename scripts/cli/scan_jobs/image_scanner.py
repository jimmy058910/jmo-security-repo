"""
Container Image Scanner

Scans container images using:
- Trivy: Vulnerability, secret, and misconfiguration scanning
- Syft: Software Bill of Materials (SBOM) generation

Integrates with ToolRunner for execution management.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Callable, Optional

from ...core.tool_runner import ToolRunner, ToolDefinition
from ..scan_utils import tool_exists, write_stub


def scan_image(
    image: str,
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
    Scan a container image with trivy and syft.

    Args:
        image: Container image name (e.g., nginx:latest, registry/image:tag)
        results_dir: Base results directory
        tools: List of tools to run (must include 'trivy' and/or 'syft')
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check if tool exists (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (image_name, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    # Use provided functions or defaults
    _tool_exists = tool_exists_func or tool_exists
    _write_stub = write_stub_func or write_stub

    statuses: Dict[str, bool] = {}
    tool_defs = []

    # Sanitize image name for directory (replace special chars with underscores)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", image)
    out_dir = results_dir / "individual-images" / safe_name
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

    # Trivy image scan
    if "trivy" in tools:
        trivy_out = out_dir / "trivy.json"
        if _tool_exists("trivy"):
            trivy_flags = get_tool_flags("trivy")
            trivy_cmd = [
                "trivy",
                "image",
                "-q",
                "-f",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                *trivy_flags,
                image,
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

    # Syft SBOM generation
    if "syft" in tools:
        syft_out = out_dir / "syft.json"
        if _tool_exists("syft"):
            syft_flags = get_tool_flags("syft")
            syft_cmd = [
                "syft",
                image,
                "-o",
                "json",
                *syft_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="syft",
                    command=syft_cmd,
                    output_file=syft_out,
                    timeout=get_tool_timeout("syft", timeout),
                    retries=retries,
                    ok_return_codes=(0,),
                    capture_stdout=True,  # Syft writes to stdout
                )
            )
        elif allow_missing_tools:
            _write_stub("syft", syft_out)
            statuses["syft"] = True

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

    return image, statuses
