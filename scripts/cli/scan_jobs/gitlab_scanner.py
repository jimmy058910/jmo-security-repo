"""
GitLab Repository Scanner

Scans GitLab repositories using:
- TruffleHog: Verified secrets scanning for GitLab

Integrates with ToolRunner for execution management.
"""

import os
import json
import shutil
from pathlib import Path
from typing import Dict, List, Tuple

from ...core.tool_runner import ToolRunner, ToolDefinition


def _tool_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None


def _write_stub(tool: str, out_path: Path) -> None:
    """Write empty JSON stub for missing tool."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stubs = {
        "gitleaks": [],
        "trufflehog": [],
        "semgrep": {"results": []},
        "noseyparker": {"matches": []},
        "syft": {"artifacts": []},
        "trivy": {"Results": []},
        "hadolint": [],
        "checkov": {"results": {"failed_checks": []}},
        "tfsec": {"results": []},
        "bandit": {"results": []},
        "osv-scanner": {"results": []},
        "zap": {"site": []},
        "falco": [],
        "afl++": {"crashes": []},
    }
    payload = stubs.get(tool, {})
    out_path.write_text(json.dumps(payload), encoding="utf-8")


def scan_gitlab_repo(
    gitlab_info: Dict[str, str],
    results_dir: Path,
    tools: List[str],
    timeout: int,
    retries: int,
    per_tool_config: Dict,
    allow_missing_tools: bool,
    tool_exists_func=None,
) -> Tuple[str, Dict[str, bool]]:
    """
    Scan a GitLab repo with trufflehog.

    Args:
        gitlab_info: Dict with keys: full_path, url, token, repo, group
        results_dir: Base results directory
        tools: List of tools to run (must include 'trufflehog')
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check tool existence (for testing)

    Returns:
        Tuple of (full_path, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    statuses: Dict[str, bool] = {}
    tool_defs = []

    full_path = gitlab_info["full_path"]
    safe_name = full_path.replace("/", "_").replace("*", "all")
    out_dir = results_dir / "individual-gitlab" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    gitlab_url = gitlab_info["url"]
    gitlab_token = gitlab_info.get("token", os.getenv("GITLAB_TOKEN"))

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

    # TruffleHog GitLab scan
    if "trufflehog" in tools:
        trufflehog_out = out_dir / "trufflehog.json"
        trufflehog_flags = get_tool_flags("trufflehog")

        if gitlab_info.get("repo") == "*":
            # Group scan
            trufflehog_cmd = [
                "trufflehog",
                "gitlab",
                "--endpoint",
                gitlab_url,
                "--token",
                gitlab_token,
                "--group",
                gitlab_info["group"],
                "--json",
                "--no-update",
                *trufflehog_flags,
            ]
        else:
            # Single repo scan
            trufflehog_cmd = [
                "trufflehog",
                "gitlab",
                "--endpoint",
                gitlab_url,
                "--token",
                gitlab_token,
                "--repo",
                full_path,
                "--json",
                "--no-update",
                *trufflehog_flags,
            ]

        tool_defs.append(
            ToolDefinition(
                name="trufflehog",
                command=trufflehog_cmd,
                output_file=trufflehog_out,
                timeout=get_tool_timeout("trufflehog", timeout),
                retries=retries,
                ok_return_codes=(0, 1),  # 0=clean, 1=findings
                capture_stdout=True,  # TruffleHog writes to stdout
            )
        )

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

    return gitlab_info["full_path"], statuses
