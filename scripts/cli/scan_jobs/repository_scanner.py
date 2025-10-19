"""
Repository Scanner

Scans local Git repositories using multiple security tools:
- TruffleHog: Verified secrets scanning
- Semgrep: Static analysis (SAST)
- Nosey Parker: Deep secrets detection (with Docker fallback)
- Trivy: Vulnerability and secrets scanning
- Syft: SBOM generation
- Checkov: IaC policy checks
- Hadolint: Dockerfile linting
- Bandit: Python security analysis
- ZAP: Web application scanning (if applicable)
- Falco: Runtime security monitoring
- AFL++: Fuzzing

Integrates with ToolRunner for execution management.
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple, Callable, Optional

from ...core.tool_runner import ToolRunner, ToolDefinition
from ..scan_utils import tool_exists, write_stub


def scan_repository(
    repo: Path,
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
    Scan a Git repository with multiple security tools.

    Args:
        repo: Path to Git repository to scan
        results_dir: Base results directory (individual-repos)
        tools: List of tools to run
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check if tool exists (for testing)
        write_stub_func: Optional function to write stub files (for testing)

    Returns:
        Tuple of (repo_name, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    statuses: Dict[str, bool] = {}
    tool_defs = []

    # Use provided functions or defaults
    _tool_exists = tool_exists_func or tool_exists
    _write_stub = write_stub_func or write_stub

    name = repo.name
    out_dir = results_dir / name
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

    # TruffleHog: Verified secrets scanning
    if "trufflehog" in tools:
        trufflehog_out = out_dir / "trufflehog.json"
        if _tool_exists("trufflehog"):
            trufflehog_flags = get_tool_flags("trufflehog")
            trufflehog_cmd = [
                "trufflehog",
                "git",
                f"file://{repo}",
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
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("trufflehog", trufflehog_out)
            statuses["trufflehog"] = True

    # Semgrep: Static analysis
    if "semgrep" in tools:
        semgrep_out = out_dir / "semgrep.json"
        if _tool_exists("semgrep"):
            semgrep_flags = get_tool_flags("semgrep")
            semgrep_cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--output",
                str(semgrep_out),
                *semgrep_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="semgrep",
                    command=semgrep_cmd,
                    output_file=semgrep_out,
                    timeout=get_tool_timeout("semgrep", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1, 2),  # 0=clean, 1=findings, 2=errors
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("semgrep", semgrep_out)
            statuses["semgrep"] = True


    # Trivy: Vulnerability and secrets scanning
    if "trivy" in tools:
        trivy_out = out_dir / "trivy.json"
        if _tool_exists("trivy"):
            trivy_flags = get_tool_flags("trivy")
            trivy_cmd = [
                "trivy",
                "fs",
                "-q",
                "-f",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                *trivy_flags,
                str(repo),
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
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("trivy", trivy_out)
            statuses["trivy"] = True


    # Syft: SBOM generation
    if "syft" in tools:
        syft_out = out_dir / "syft.json"
        if _tool_exists("syft"):
            syft_flags = get_tool_flags("syft")
            syft_cmd = [
                "syft",
                f"dir:{repo}",
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
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("syft", syft_out)
            statuses["syft"] = True


    # Checkov: IaC policy checks
    if "checkov" in tools:
        checkov_out = out_dir / "checkov.json"
        if _tool_exists("checkov"):
            checkov_flags = get_tool_flags("checkov")
            checkov_cmd = [
                "checkov",
                "-d",
                str(repo),
                "-o",
                "json",
                *checkov_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="checkov",
                    command=checkov_cmd,
                    output_file=checkov_out,
                    timeout=get_tool_timeout("checkov", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("checkov", checkov_out)
            statuses["checkov"] = True


    # Hadolint: Dockerfile linting
    if "hadolint" in tools:
        hadolint_out = out_dir / "hadolint.json"
        if _tool_exists("hadolint"):
            hadolint_flags = get_tool_flags("hadolint")

            # Find Dockerfiles in repository
            dockerfiles = list(repo.glob("**/Dockerfile*"))
            if dockerfiles:
                # Hadolint scans one file at a time; use first Dockerfile found
                dockerfile = dockerfiles[0]
                hadolint_cmd = [
                    "hadolint",
                    "-f",
                    "json",
                    *hadolint_flags,
                    str(dockerfile),
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="hadolint",
                        command=hadolint_cmd,
                        output_file=hadolint_out,
                        timeout=get_tool_timeout("hadolint", timeout),
                        retries=retries,
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
        elif allow_missing_tools:
            _write_stub("hadolint", hadolint_out)
            statuses["hadolint"] = True

    # Bandit: Python security analysis
    if "bandit" in tools:
        bandit_out = out_dir / "bandit.json"
        if _tool_exists("bandit"):
            bandit_flags = get_tool_flags("bandit")
            bandit_cmd = [
                "bandit",
                "-r",
                str(repo),
                "-f",
                "json",
                "-o",
                str(bandit_out),
                *bandit_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="bandit",
                    command=bandit_cmd,
                    output_file=bandit_out,
                    timeout=get_tool_timeout("bandit", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("bandit", bandit_out)
            statuses["bandit"] = True


    # NOTE: Nosey Parker, ZAP, Falco, AFL++ are complex tools with special requirements
    # These will be handled separately if needed in the integration phase

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
            # Tools with capture_stdout=False write their own files (semgrep, trivy, bandit)
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

    return name, statuses
