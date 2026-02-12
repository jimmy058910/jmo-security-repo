#!/usr/bin/env python3
"""
Analyze wizard scan results for Ralph Loop.

This script performs thorough analysis of wizard scan output:
- Validates each tool's output file against the 12 required Juice Shop tools
- Checks findings.json quality
- Parses log files for errors
- Generates success/failure report with per-tool status

Usage:
    python tools/ralph-testing/analyze_wizard_results.py [results_dir] [log_file]

Example:
    python tools/ralph-testing/analyze_wizard_results.py \
        tools/ralph-testing/wizard-results/repo \
        tools/ralph-testing/iteration-logs/wizard-20260201-120000.log
"""

import json
import platform
import re
import sys
from pathlib import Path
from typing import Any

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# ============================================================================
# JUICE SHOP REQUIRED TOOLS (v2.1)
# These 12 tools MUST produce output for a valid Juice Shop repo scan
# ============================================================================

JUICE_SHOP_REQUIRED_TOOLS = [
    "trufflehog",  # Secret detection (filesystem mode)
    "semgrep",  # SAST - code vulnerabilities
    "syft",  # SBOM generation
    "trivy",  # Vuln + secrets + misconfig
    "checkov",  # IaC/Dockerfile scanning
    "hadolint",  # Dockerfile linting
    "kubescape",  # K8s manifest scanning (content-triggered)
    "scancode",  # License compliance
    "cdxgen",  # CycloneDX SBOM
    "grype",  # Vulnerability scanning
    "horusec",  # Multi-language SAST
    "shellcheck",  # Shell script linting (content-triggered)
]

# Tools that may have no output if the target lacks relevant content
# These are marked CONTENT_TRIGGERED instead of FAILED when missing
CONTENT_TRIGGERED_TOOLS = ["kubescape", "shellcheck"]

# Tools that may produce empty (0-byte) output when they find nothing
# This is a valid result, not a failure (e.g., trufflehog finds no secrets)
EMPTY_OUTPUT_OK_TOOLS = ["trufflehog", "gitleaks", "kubescape", "shellcheck"]

# Tools with known Windows installation issues
# These should create a task ONCE, not fail every iteration
WINDOWS_PROBLEMATIC_TOOLS = ["scancode", "shellcheck", "kubescape"]

# ============================================================================
# JUICE SHOP EXPECTED FINDINGS (v2.2)
# Benchmark finding counts for Juice Shop repo - used to detect quality issues
# Tools with 0 findings when benchmark > 0 trigger [WIZARD-QUALITY] alerts
# ============================================================================

JUICE_SHOP_EXPECTED_FINDINGS = {
    # SAST tools - should find JS/TS vulnerabilities
    "semgrep": 25,  # XSS, injection, insecure patterns
    "horusec": 100,  # Multi-language SAST (usually finds 200-500)
    # SCA tools - should find npm vulnerabilities
    "trivy": 3,  # Known CVEs in dependencies
    "grype": 3,  # Known CVEs in dependencies
    # IaC tools - Juice Shop has Dockerfiles
    "hadolint": 5,  # Dockerfile best practice issues
    "checkov": 2,  # Dockerfile/IaC misconfigurations
    # SBOM tools - produce component lists, not "findings"
    "syft": 0,  # SBOM generator (components, not findings)
    "cdxgen": 0,  # SBOM generator (components, not findings)
    # Secret detection - may legitimately find 0
    "trufflehog": 0,  # May find 0 if no secrets committed
    # Content-triggered tools - 0 is often valid
    "kubescape": 0,  # Only if K8s manifests present
    "shellcheck": 0,  # Only if shell scripts present
    "scancode": 0,  # License scan - depends on content
}

# SBOM tools produce components, not findings - different validation
SBOM_TOOLS = ["syft", "cdxgen"]

# Tool to category mapping for finding result files
TOOL_CATEGORIES = {
    "trufflehog": "secrets",
    "semgrep": "sast",
    "syft": "sca",
    "trivy": "sca",
    "checkov": "iac",
    "hadolint": "iac",
    "kubescape": "iac",
    "scancode": "license",
    "cdxgen": "sca",
    "grype": "sca",
    "horusec": "sast",
    "shellcheck": "sast",
}

# Legacy category-based expected tools (for backwards compatibility)
EXPECTED_TOOLS = {
    "sast": ["semgrep", "bandit"],
    "sca": ["trivy", "grype", "syft", "cdxgen"],
    "secrets": ["trufflehog", "gitleaks"],
    "iac": ["checkov", "kics"],
}

# Minimum thresholds for success
MIN_RESULT_FILES = 12
MIN_FINDINGS = 10
MIN_UNIQUE_TOOLS = 8
MAX_RUNTIME_SECONDS = 1200
MIN_FILE_SIZE_BYTES = 50

# Version extraction patterns for tool output
VERSION_PATTERNS = {
    "semgrep": r"\[semgrep\]\s+v?(\d+\.\d+\.\d+)",
    "trivy": r"\[trivy\]\s+v?(\d+\.\d+\.\d+)",
    "grype": r"\[grype\]\s+v?(\d+\.\d+\.\d+)",
    "trufflehog": r"\[trufflehog\]\s+v?(\d+\.\d+\.\d+)",
    "horusec": r"\[horusec\]\s+v?(\d+\.\d+\.\d+)",
    "checkov": r"\[checkov\]\s+v?(\d+\.\d+\.\d+)",
    "hadolint": r"\[hadolint\]\s+v?(\d+\.\d+\.\d+)",
    "syft": r"\[syft\]\s+v?(\d+\.\d+\.\d+)",
    "cdxgen": r"\[cdxgen\]\s+v?(\d+\.\d+\.\d+)",
    "kubescape": r"\[kubescape\]\s+v?(\d+\.\d+\.\d+)",
    "shellcheck": r"\[shellcheck\]\s+v?(\d+\.\d+\.\d+)",
    "scancode": r"\[scancode\]\s+v?(\d+\.\d+\.\d+)",
}


def analyze_log_file(log_path: Path) -> dict[str, Any]:
    """Parse log file for errors, warnings, tool status, and versions."""
    result = {
        "errors": [],
        "warnings": [],
        "timeouts": [],
        "tracebacks": [],
        "tool_mentions": {},
        "install_failures": [],
        "tools_completed": [],  # Tools that showed ✔ (success) in log
        "tools_failed": [],  # Tools that showed ✗ (failure) in log
        "tool_versions": {},  # Extracted tool versions from log
        "tool_findings_count": {},  # Findings count from log if available
    }

    if not log_path.exists():
        result["errors"].append(f"Log file not found: {log_path}")
        return result

    content = log_path.read_text(encoding="utf-8", errors="replace")
    lines = content.split("\n")

    # Patterns to search for
    error_pattern = re.compile(r"(?:ERROR|error|Error)[:]\s*(.+)", re.IGNORECASE)
    warning_pattern = re.compile(
        r"(?:WARNING|warning|Warning)[:]\s*(.+)", re.IGNORECASE
    )
    timeout_pattern = re.compile(r"(?:timeout|timed out|killed)", re.IGNORECASE)
    traceback_pattern = re.compile(r"Traceback \(most recent call last\)")
    install_fail_pattern = re.compile(
        r"(?:failed to install|installation failed|could not install)", re.IGNORECASE
    )
    # Pattern for tool completion markers: [9/14] ✔ horusec [64%]
    tool_success_pattern = re.compile(r"\[\d+/\d+\]\s*[✔✓]\s*(\w+)")
    tool_failure_pattern = re.compile(r"\[\d+/\d+\]\s*[✗✘×]\s*(\w+)")
    # Pattern for findings count: "semgrep: 40 findings" or "Found 40 issues"
    findings_count_pattern = re.compile(
        r"\[?(\w+)\]?\s*:?\s*(\d+)\s+(?:findings?|issues?|vulnerabilit)", re.IGNORECASE
    )
    # Alternative pattern: "0 findings" at end of line
    zero_findings_pattern = re.compile(r"\[?(\w+)\]?\s*.*?0\s+findings?", re.IGNORECASE)

    # Tool name patterns
    tool_names = list(JUICE_SHOP_REQUIRED_TOOLS)
    for tools in EXPECTED_TOOLS.values():
        tool_names.extend(tools)
    tool_names = list(set(tool_names))  # Dedupe

    in_traceback = False
    traceback_lines = []

    for i, line in enumerate(lines):
        # Collect tracebacks
        if traceback_pattern.search(line):
            in_traceback = True
            traceback_lines = [line]
            continue

        if in_traceback:
            traceback_lines.append(line)
            if line.strip() and not line.startswith(" "):
                result["tracebacks"].append("\n".join(traceback_lines))
                in_traceback = False
                traceback_lines = []
            continue

        # Check for errors
        if error_match := error_pattern.search(line):
            result["errors"].append(f"Line {i + 1}: {error_match.group(0)}")

        # Check for warnings
        if warning_match := warning_pattern.search(line):
            result["warnings"].append(f"Line {i + 1}: {warning_match.group(0)}")

        # Check for timeouts
        if timeout_pattern.search(line):
            result["timeouts"].append(f"Line {i + 1}: {line.strip()}")

        # Check for install failures
        if install_fail_pattern.search(line):
            result["install_failures"].append(f"Line {i + 1}: {line.strip()}")

        # Track tool completion status (✔ or ✗ markers)
        if success_match := tool_success_pattern.search(line):
            tool_name = success_match.group(1).lower()
            if tool_name not in result["tools_completed"]:
                result["tools_completed"].append(tool_name)
        if failure_match := tool_failure_pattern.search(line):
            tool_name = failure_match.group(1).lower()
            if tool_name not in result["tools_failed"]:
                result["tools_failed"].append(tool_name)

        # Track tool mentions
        for tool in tool_names:
            if tool.lower() in line.lower():
                if tool not in result["tool_mentions"]:
                    result["tool_mentions"][tool] = []
                result["tool_mentions"][tool].append(
                    f"Line {i + 1}: {line.strip()[:100]}"
                )

        # Extract tool versions from log
        for tool, pattern in VERSION_PATTERNS.items():
            if version_match := re.search(pattern, line, re.IGNORECASE):
                result["tool_versions"][tool] = version_match.group(1)

        # Extract findings counts from log
        if findings_match := findings_count_pattern.search(line):
            tool_name = findings_match.group(1).lower()
            count = int(findings_match.group(2))
            result["tool_findings_count"][tool_name] = count
        elif zero_match := zero_findings_pattern.search(line):
            tool_name = zero_match.group(1).lower()
            if tool_name not in result["tool_findings_count"]:
                result["tool_findings_count"][tool_name] = 0

    return result


def find_tool_result_file(results_dir: Path, tool: str) -> Path | None:
    """Find the result file for a specific tool.

    Supports multiple directory structures:
    1. Category-based: individual-sast/, individual-sca/, etc.
    2. Repo-based: individual-repos/<repo-name>/ (used by wizard scan)
    3. Flat: results dir root
    """
    # Try category-specific directories first
    category = TOOL_CATEGORIES.get(tool, "")
    if category:
        cat_dir = results_dir / f"individual-{category}"
        if cat_dir.exists():
            matches = list(cat_dir.glob(f"*{tool}*.json"))
            if matches:
                return matches[0]

    # Try all individual-* directories (including individual-repos/*/))
    for subdir in results_dir.glob("individual-*"):
        # Check direct children
        matches = list(subdir.glob(f"*{tool}*.json"))
        if matches:
            return matches[0]
        # Check nested directories (for individual-repos/<repo-name>/ structure)
        for nested_dir in subdir.iterdir():
            if nested_dir.is_dir():
                matches = list(nested_dir.glob(f"*{tool}*.json"))
                if matches:
                    return matches[0]

    # Try root results directory
    matches = list(results_dir.glob(f"*{tool}*.json"))
    if matches:
        return matches[0]

    # Try recursive search as last resort
    matches = list(results_dir.rglob(f"*{tool}*.json"))
    if matches:
        return matches[0]

    return None


def count_findings(data: Any) -> int:
    """Count findings from various JSON formats."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in [
            "findings",
            "results",
            "vulnerabilities",
            "matches",
            "issues",
            "Results",
        ]:
            if key in data:
                items = data[key]
                if isinstance(items, list):
                    return len(items)
                if isinstance(items, int):
                    return items
        # For SBOM tools (syft, cdxgen), check for artifacts/components
        if "artifacts" in data:
            return len(data["artifacts"])
        if "components" in data:
            return len(data["components"])
    return 0


def is_sbom_output(data: Any) -> bool:
    """Check if the JSON data is an SBOM (not findings)."""
    if isinstance(data, dict):
        # CycloneDX format
        if "bomFormat" in data or "components" in data:
            return True
        # Syft format
        if "artifacts" in data and "source" in data:
            return True
    return False


def validate_finding_counts(
    tool_status: dict[str, Any], log_analysis: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """
    Validate finding counts against Juice Shop benchmarks.

    Flags tools that produced 0 findings when the benchmark expects > 0.
    This catches scenarios where a tool "runs" but produces no useful output.

    Args:
        tool_status: Per-tool status dict from validate_juice_shop_tools()
        log_analysis: Optional log analysis with findings counts from log

    Returns:
        List of quality alert dicts for tools failing benchmark
    """
    alerts = []
    log_findings = log_analysis.get("tool_findings_count", {}) if log_analysis else {}

    for tool, expected in JUICE_SHOP_EXPECTED_FINDINGS.items():
        if expected == 0:
            # No benchmark for this tool (content-triggered or SBOM)
            continue

        status = tool_status.get(tool, {})
        if status.get("status") not in ("OK", "CONTENT_TRIGGERED"):
            # Tool didn't run successfully - different issue
            continue

        # Skip SBOM tools - they produce components, not findings
        if tool in SBOM_TOOLS:
            continue

        actual_findings = status.get("findings", 0)

        # Cross-reference with log if available
        if tool.lower() in log_findings:
            log_count = log_findings[tool.lower()]
            # Use log count if it's higher (more accurate)
            actual_findings = max(actual_findings, log_count)

        if actual_findings == 0 and expected > 0:
            alerts.append(
                {
                    "tool": tool,
                    "tag": "[WIZARD-QUALITY]",
                    "title": f"{tool}: 0 findings when {expected}+ expected",
                    "symptom": f"{tool} produced 0 findings but Juice Shop benchmark expects ~{expected}",
                    "expected": expected,
                    "actual": actual_findings,
                    "priority": "Medium",
                    "file_hint": f"scripts/core/adapters/{tool}_adapter.py",
                }
            )

    return alerts


def verify_empty_output(
    tool_status: dict[str, Any],
    log_analysis: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Verify empty outputs are legitimate (0 findings confirmed in log).

    For tools that produced empty or near-empty output files, check the log
    to see if "0 findings" was explicitly reported. If not, the tool may have
    crashed before completing.

    Args:
        tool_status: Per-tool status dict from validate_juice_shop_tools()
        log_analysis: Log analysis with tool completion and findings info

    Returns:
        List of suspicious empty alerts
    """
    alerts = []
    if not log_analysis:
        return alerts

    tools_completed = [t.lower() for t in log_analysis.get("tools_completed", [])]
    log_findings = log_analysis.get("tool_findings_count", {})

    for tool, status in tool_status.items():
        # Only check tools that are "OK" but have 0 findings and small file
        if status.get("status") != "OK":
            continue

        findings = status.get("findings", 0)
        size = status.get("size", 0)

        # Skip SBOM tools
        if tool in SBOM_TOOLS:
            continue

        # Empty/small file with no findings
        if findings == 0 and size < 100:
            tool_lower = tool.lower()

            # Check if tool completed successfully
            tool_ran = tool_lower in tools_completed

            # Check if log confirms 0 findings
            confirmed_zero = (
                tool_lower in log_findings and log_findings[tool_lower] == 0
            )

            # Tool ran but no log confirmation of 0 findings - suspicious
            if tool_ran and not confirmed_zero:
                # Check if it's in the EMPTY_OUTPUT_OK list
                if tool not in EMPTY_OUTPUT_OK_TOOLS:
                    alerts.append(
                        {
                            "tool": tool,
                            "tag": "[WIZARD-OUTPUT]",
                            "title": f"{tool}: Empty output without log confirmation",
                            "symptom": f"{tool} produced empty output but log doesn't confirm 0 findings",
                            "status": "SUSPICIOUS_EMPTY",
                            "priority": "High",
                            "file_hint": f"scripts/core/adapters/{tool}_adapter.py",
                        }
                    )

    return alerts


def validate_juice_shop_tools(
    results_dir: Path, log_analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Validate the 12 required Juice Shop tools.

    Args:
        results_dir: Path to the results directory
        log_analysis: Optional log analysis from analyze_log_file() to detect
                      tools that ran (✔) but produced no output (BUG)

    Returns a dict with:
    - success: bool - all required tools OK or CONTENT_TRIGGERED or WINDOWS_UNAVAILABLE
    - failed_tools: list - tools that failed validation (excluding Windows limitations)
    - tool_status: dict - per-tool status details
    - tasks_to_create: list - suggested tasks for IMPLEMENTATION_PLAN.md
    """
    tool_status = {}
    tasks_to_create = []

    # Get list of tools that showed ✔ (completed successfully) in the log
    tools_completed_in_log = []
    if log_analysis:
        tools_completed_in_log = [
            t.lower() for t in log_analysis.get("tools_completed", [])
        ]

    for tool in JUICE_SHOP_REQUIRED_TOOLS:
        result_file = find_tool_result_file(results_dir, tool)
        tool_ran_successfully = tool.lower() in tools_completed_in_log

        if result_file is None:
            # Tool ran successfully (✔ in log) but no output file = BUG
            if tool_ran_successfully and tool not in CONTENT_TRIGGERED_TOOLS:
                tool_status[tool] = {
                    "status": "BUG_NO_OUTPUT",
                    "reason": "Tool ran successfully but no output file produced",
                    "file": None,
                    "findings": 0,
                    "size": 0,
                }
                tasks_to_create.append(
                    {
                        "tool": tool,
                        "tag": "[WIZARD-OUTPUT]",
                        "title": f"{tool}: Ran successfully but no output file (BUG)",
                        "symptom": f"{tool} showed ✔ in log but no JSON file written to results",
                        "priority": "High",
                        "file_hint": f"scripts/core/adapters/{tool}_adapter.py or scripts/cli/scan_orchestrator.py",
                    }
                )
            elif tool in CONTENT_TRIGGERED_TOOLS:
                tool_status[tool] = {
                    "status": "CONTENT_TRIGGERED",
                    "reason": f"No output (may have no {tool.replace('kube', 'k8s ')} content)",
                    "file": None,
                    "findings": 0,
                    "size": 0,
                }
            elif IS_WINDOWS and tool in WINDOWS_PROBLEMATIC_TOOLS:
                tool_status[tool] = {
                    "status": "WINDOWS_UNAVAILABLE",
                    "reason": f"Known Windows installation issue for {tool}",
                    "file": None,
                    "findings": 0,
                    "size": 0,
                }
                tasks_to_create.append(
                    {
                        "tool": tool,
                        "tag": "[WIZARD-CONFIG]",
                        "title": f"{tool}: Windows installation failure",
                        "symptom": f"{tool} failed to install on Windows",
                        "priority": "Medium",
                    }
                )
            else:
                tool_status[tool] = {
                    "status": "FAILED",
                    "reason": "No output file found",
                    "file": None,
                    "findings": 0,
                    "size": 0,
                }
                tasks_to_create.append(
                    {
                        "tool": tool,
                        "tag": "[WIZARD-OUTPUT]",
                        "title": f"{tool}: No output file produced",
                        "symptom": f"{tool} did not produce an output file",
                        "priority": "High",
                    }
                )
        else:
            size = result_file.stat().st_size
            if size < MIN_FILE_SIZE_BYTES:
                if tool in CONTENT_TRIGGERED_TOOLS:
                    tool_status[tool] = {
                        "status": "CONTENT_TRIGGERED",
                        "reason": "Empty output (no relevant content to scan)",
                        "file": str(result_file),
                        "findings": 0,
                        "size": size,
                    }
                elif tool in EMPTY_OUTPUT_OK_TOOLS:
                    # Tools like trufflehog legitimately produce 0-byte files when no findings
                    tool_status[tool] = {
                        "status": "OK",
                        "file": str(result_file),
                        "findings": 0,
                        "size": size,
                        "reason": f"No {tool} findings (empty output is valid)",
                    }
                else:
                    tool_status[tool] = {
                        "status": "EMPTY",
                        "reason": f"Output file too small ({size} bytes < {MIN_FILE_SIZE_BYTES})",
                        "file": str(result_file),
                        "findings": 0,
                        "size": size,
                    }
            else:
                try:
                    with open(result_file, encoding="utf-8") as f:
                        data = json.load(f)

                    findings = count_findings(data)
                    sbom = is_sbom_output(data)

                    tool_status[tool] = {
                        "status": "OK",
                        "file": str(result_file),
                        "findings": findings,
                        "size": size,
                        "sbom": sbom,
                    }

                except json.JSONDecodeError as e:
                    tool_status[tool] = {
                        "status": "INVALID_JSON",
                        "reason": str(e),
                        "file": str(result_file),
                        "findings": 0,
                        "size": size,
                    }
                except Exception as e:
                    tool_status[tool] = {
                        "status": "ERROR",
                        "reason": str(e),
                        "file": str(result_file),
                        "findings": 0,
                        "size": size,
                    }

    # Determine success - these statuses are ACCEPTABLE (not failures):
    # - OK: Tool ran and produced output
    # - CONTENT_TRIGGERED: No relevant content to scan (e.g., no K8s manifests)
    # - WINDOWS_UNAVAILABLE: Known Windows installation limitation
    # - SKIPPED: Agent marked as skipped (Windows issue or no content)
    #
    # These statuses are FAILURES:
    # - FAILED: Tool should have run but didn't
    # - EMPTY: Output file exists but is unexpectedly empty
    # - INVALID_JSON: Output file has invalid JSON
    # - ERROR: Unexpected error during processing
    # - BUG_NO_OUTPUT: Tool ran successfully (✔) but no output file (code bug)
    acceptable_statuses = ("OK", "CONTENT_TRIGGERED", "WINDOWS_UNAVAILABLE", "SKIPPED")
    failed_tools = [
        t for t, s in tool_status.items() if s["status"] not in acceptable_statuses
    ]

    # Count by status
    ok_count = len([t for t, s in tool_status.items() if s["status"] == "OK"])
    content_triggered_count = len(
        [t for t, s in tool_status.items() if s["status"] == "CONTENT_TRIGGERED"]
    )
    windows_unavailable_count = len(
        [t for t, s in tool_status.items() if s["status"] == "WINDOWS_UNAVAILABLE"]
    )
    failed_count = len(failed_tools)

    # Run quality validations (Phase 1.1-1.2)
    quality_alerts = validate_finding_counts(tool_status, log_analysis)
    empty_alerts = verify_empty_output(tool_status, log_analysis)

    # Add quality alerts to tasks
    tasks_to_create.extend(quality_alerts)
    tasks_to_create.extend(empty_alerts)

    # Extract tool versions from log for tracking
    tool_versions = {}
    if log_analysis:
        tool_versions = log_analysis.get("tool_versions", {})

    # Determine blocking issue (highest priority failure)
    blocking_issue = None
    if failed_tools:
        # BUG_NO_OUTPUT is highest priority
        for tool in failed_tools:
            if tool_status[tool]["status"] == "BUG_NO_OUTPUT":
                blocking_issue = f"{tool}: Tool ran but no output"
                break
        if not blocking_issue:
            blocking_issue = (
                f"{failed_tools[0]}: {tool_status[failed_tools[0]]['status']}"
            )
    elif quality_alerts:
        # Quality issues are second priority
        blocking_issue = (
            f"{quality_alerts[0]['tool']}: Quality issue - {quality_alerts[0]['title']}"
        )

    return {
        "success": len(failed_tools) == 0,
        "failed_tools": failed_tools,
        "tool_status": tool_status,
        "tasks_to_create": tasks_to_create,
        "quality_alerts": quality_alerts,
        "empty_alerts": empty_alerts,
        "tool_versions": tool_versions,
        "blocking_issue": blocking_issue,
        "summary": {
            "total": len(JUICE_SHOP_REQUIRED_TOOLS),
            "ok": ok_count,
            "content_triggered": content_triggered_count,
            "windows_unavailable": windows_unavailable_count,
            "failed": failed_count,
            "quality_issues": len(quality_alerts),
            "suspicious_empty": len(empty_alerts),
        },
    }


def analyze_result_files(results_dir: Path) -> dict[str, Any]:
    """Analyze all result files in the results directory (legacy method)."""
    result = {
        "tool_status": {},
        "total_files": 0,
        "valid_files": 0,
        "empty_files": [],
        "invalid_json_files": [],
        "missing_tools": [],
    }

    if not results_dir.exists():
        result["missing_tools"] = list(
            tool for tools in EXPECTED_TOOLS.values() for tool in tools
        )
        return result

    # Find all JSON files
    json_files = list(results_dir.rglob("*.json"))
    result["total_files"] = len(json_files)

    # Check each expected tool
    for category, tools in EXPECTED_TOOLS.items():
        cat_dir = results_dir / f"individual-{category}"

        for tool in tools:
            tool_info = {
                "status": "MISSING",
                "file": None,
                "size": 0,
                "findings": 0,
                "valid_json": False,
                "error": None,
            }

            if cat_dir.exists():
                # Find file matching tool name
                matches = list(cat_dir.glob(f"*{tool}*.json"))
                if not matches:
                    # Try alternative patterns
                    matches = list(cat_dir.glob(f"*{tool.replace('-', '_')}*.json"))

                if matches:
                    filepath = matches[0]
                    tool_info["file"] = str(filepath)
                    tool_info["size"] = filepath.stat().st_size

                    if tool_info["size"] < MIN_FILE_SIZE_BYTES:
                        tool_info["status"] = "EMPTY"
                        result["empty_files"].append(str(filepath))
                    else:
                        try:
                            with open(filepath, encoding="utf-8") as f:
                                data = json.load(f)

                            tool_info["valid_json"] = True

                            # Count findings (handle different formats)
                            if isinstance(data, list):
                                tool_info["findings"] = len(data)
                            elif isinstance(data, dict):
                                for key in [
                                    "findings",
                                    "results",
                                    "vulnerabilities",
                                    "matches",
                                    "issues",
                                ]:
                                    if key in data:
                                        items = data[key]
                                        if isinstance(items, list):
                                            tool_info["findings"] = len(items)
                                            break

                            tool_info["status"] = "OK"
                            result["valid_files"] += 1

                        except json.JSONDecodeError as e:
                            tool_info["status"] = "INVALID_JSON"
                            tool_info["error"] = str(e)
                            result["invalid_json_files"].append(str(filepath))
                        except Exception as e:
                            tool_info["status"] = "ERROR"
                            tool_info["error"] = str(e)

            if tool_info["status"] == "MISSING":
                result["missing_tools"].append(tool)

            result["tool_status"][tool] = tool_info

    return result


def analyze_findings_json(results_dir: Path) -> dict[str, Any]:
    """Analyze the aggregated findings.json file."""
    result = {
        "exists": False,
        "valid_json": False,
        "total_findings": 0,
        "by_severity": {},
        "by_tool": {},
        "missing_fields": {},
        "unique_tools": 0,
        "error": None,
    }

    findings_path = results_dir / "findings.json"
    if not findings_path.exists():
        result["error"] = "findings.json not found"
        return result

    result["exists"] = True

    try:
        with open(findings_path, encoding="utf-8") as f:
            findings = json.load(f)

        result["valid_json"] = True
        result["total_findings"] = len(findings)

        # Analyze findings
        required_fields = ["ruleId", "severity", "message", "location"]
        result["missing_fields"] = {field: 0 for field in required_fields}

        for finding in findings:
            # Count by severity
            sev = finding.get("severity", "UNKNOWN")
            result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1

            # Count by tool
            tool_info = finding.get("tool", {})
            tool_name = (
                tool_info.get("name", "UNKNOWN")
                if isinstance(tool_info, dict)
                else "UNKNOWN"
            )
            result["by_tool"][tool_name] = result["by_tool"].get(tool_name, 0) + 1

            # Check required fields
            for field in required_fields:
                if field not in finding or not finding[field]:
                    result["missing_fields"][field] += 1

        result["unique_tools"] = len(result["by_tool"])

    except json.JSONDecodeError as e:
        result["error"] = f"Invalid JSON: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def evaluate_success(
    log_analysis: dict,
    file_analysis: dict,
    findings_analysis: dict,
    juice_shop_validation: dict,
    runtime: int = 0,
) -> dict[str, Any]:
    """Evaluate all success criteria including Juice Shop tool validation."""
    criteria = {
        "exit_code_zero": {"required": True, "actual": None, "passed": None},
        "no_timeouts": {
            "required": 0,
            "actual": len(log_analysis.get("timeouts", [])),
            "passed": len(log_analysis.get("timeouts", [])) == 0,
        },
        "no_exceptions": {
            "required": 0,
            "actual": len(log_analysis.get("tracebacks", [])),
            "passed": len(log_analysis.get("tracebacks", [])) == 0,
        },
        "result_files": {
            "required": MIN_RESULT_FILES,
            "actual": file_analysis.get("total_files", 0),
            "passed": file_analysis.get("total_files", 0) >= MIN_RESULT_FILES,
        },
        "no_empty_outputs": {
            "required": 0,
            "actual": len(file_analysis.get("empty_files", [])),
            "passed": len(file_analysis.get("empty_files", [])) == 0,
        },
        "valid_json": {
            "required": "100%",
            "actual": f"{file_analysis.get('valid_files', 0)}/{file_analysis.get('total_files', 0)}",
            "passed": len(file_analysis.get("invalid_json_files", [])) == 0,
        },
        "findings_count": {
            "required": MIN_FINDINGS,
            "actual": findings_analysis.get("total_findings", 0),
            # N/A if findings.json doesn't exist (wizard scans don't aggregate)
            "passed": (
                findings_analysis.get("total_findings", 0) >= MIN_FINDINGS
                if findings_analysis.get("exists", False)
                else None  # N/A - no aggregated findings
            ),
        },
        "unique_tools": {
            "required": MIN_UNIQUE_TOOLS,
            "actual": findings_analysis.get("unique_tools", 0),
            # N/A if findings.json doesn't exist (wizard scans don't aggregate)
            "passed": (
                findings_analysis.get("unique_tools", 0) >= MIN_UNIQUE_TOOLS
                if findings_analysis.get("exists", False)
                else None  # N/A - no aggregated findings
            ),
        },
        "runtime_ok": {
            "required": f"< {MAX_RUNTIME_SECONDS}s",
            "actual": f"{runtime}s",
            "passed": runtime < MAX_RUNTIME_SECONDS if runtime > 0 else None,
        },
        "autofix_worked": {
            "required": 0,
            "actual": len(log_analysis.get("install_failures", [])),
            "passed": len(log_analysis.get("install_failures", [])) == 0,
        },
        # NEW: Juice Shop 12-tool validation
        "juice_shop_tools": {
            "required": "12/12 tools OK or CONTENT_TRIGGERED",
            "actual": f"{juice_shop_validation['summary']['ok']} OK, {juice_shop_validation['summary']['content_triggered']} content-triggered, {juice_shop_validation['summary']['failed']} failed",
            "passed": juice_shop_validation["success"],
            "failed_tools": juice_shop_validation["failed_tools"],
        },
    }

    all_passed = all(c["passed"] for c in criteria.values() if c["passed"] is not None)

    return {"criteria": criteria, "all_passed": all_passed}


def print_report(
    log_analysis: dict,
    file_analysis: dict,
    findings_analysis: dict,
    juice_shop_validation: dict,
    success_eval: dict,
) -> None:
    """Print a comprehensive analysis report."""
    print("\n" + "=" * 70)
    print("WIZARD SCAN ANALYSIS REPORT (v2.1 - 12-Tool Validation)")
    print("=" * 70)

    # Juice Shop Tool Status (NEW - primary validation)
    print("\n--- JUICE SHOP REQUIRED TOOLS (12) ---")
    print(f"{'Tool':<15} {'Status':<20} {'Size':>8} {'Findings':>10} {'Notes'}")
    print("-" * 70)
    for tool in JUICE_SHOP_REQUIRED_TOOLS:
        info = juice_shop_validation["tool_status"].get(tool, {})
        status = info.get("status", "UNKNOWN")
        size = f"{info.get('size', 0):,}" if info.get("size") else "-"
        findings = str(info.get("findings", 0)) if info.get("findings", 0) else "-"
        notes = ""
        if info.get("sbom"):
            notes = "SBOM"
        if info.get("reason"):
            notes = info["reason"][:25]

        # Color-code status
        if status == "OK":
            status_display = "OK"
        elif status == "CONTENT_TRIGGERED":
            status_display = "CONTENT_TRIGGERED"
        else:
            status_display = f"**{status}**"

        print(f"{tool:<15} {status_display:<20} {size:>8} {findings:>10} {notes}")

    # Summary
    summary = juice_shop_validation["summary"]
    print("-" * 70)
    summary_parts = [f"{summary['ok']}/12 OK"]
    if summary.get("content_triggered", 0) > 0:
        summary_parts.append(f"{summary['content_triggered']}/12 content-triggered")
    if summary.get("windows_unavailable", 0) > 0:
        summary_parts.append(f"{summary['windows_unavailable']}/12 Windows-unavailable")
    if summary.get("failed", 0) > 0:
        summary_parts.append(f"{summary['failed']}/12 failed")
    if summary.get("quality_issues", 0) > 0:
        summary_parts.append(f"{summary['quality_issues']} quality issues")
    print(f"Summary: {', '.join(summary_parts)}")

    if juice_shop_validation["failed_tools"]:
        print(f"FAILED TOOLS: {', '.join(juice_shop_validation['failed_tools'])}")

    # Show blocking issue if any
    if juice_shop_validation.get("blocking_issue"):
        print(f"\n** BLOCKING ISSUE: {juice_shop_validation['blocking_issue']} **")

    # Show tool versions if extracted
    if juice_shop_validation.get("tool_versions"):
        print("\n--- TOOL VERSIONS ---")
        for tool, version in sorted(juice_shop_validation["tool_versions"].items()):
            print(f"  {tool}: v{version}")

    # Print quality alerts (separate from general tasks)
    if juice_shop_validation.get("quality_alerts"):
        print("\n--- QUALITY ALERTS [WIZARD-QUALITY] ---")
        for alert in juice_shop_validation["quality_alerts"]:
            print(f"  {alert['tool']}: {alert['title']}")
            print(
                f"    Expected: ~{alert.get('expected', 'N/A')} findings, Got: {alert.get('actual', 0)}"
            )

    # Print empty output alerts
    if juice_shop_validation.get("empty_alerts"):
        print("\n--- SUSPICIOUS EMPTY OUTPUTS [WIZARD-OUTPUT] ---")
        for alert in juice_shop_validation["empty_alerts"]:
            print(f"  {alert['tool']}: {alert['title']}")
            print(f"    Status: {alert.get('status', 'SUSPICIOUS_EMPTY')}")

    # Print suggested tasks
    if juice_shop_validation.get("tasks_to_create"):
        print("\n--- SUGGESTED TASKS FOR IMPLEMENTATION_PLAN.md ---")
        for task in juice_shop_validation["tasks_to_create"]:
            print(f"  {task['tag']} {task['tool']}: {task['title']}")
            print(f"    Symptom: {task['symptom']}")
            print(f"    Priority: {task['priority']}")

    # Legacy Tool Status (for backwards compatibility)
    print("\n--- LEGACY TOOL STATUS ---")
    print(f"{'Tool':<20} {'Status':<12} {'Size':>8} {'Findings':>10}")
    print("-" * 52)
    for tool, info in sorted(file_analysis.get("tool_status", {}).items()):
        status = info["status"]
        size = f"{info['size']:,}" if info["size"] else "-"
        findings = str(info["findings"]) if info["findings"] else "-"
        print(f"{tool:<20} {status:<12} {size:>8} {findings:>10}")

    # Findings Analysis
    print("\n--- FINDINGS ANALYSIS ---")
    print(f"Total findings: {findings_analysis.get('total_findings', 0)}")
    print(f"Unique tools: {findings_analysis.get('unique_tools', 0)}")

    if findings_analysis.get("by_severity"):
        print("\nBy severity:")
        for sev, count in sorted(findings_analysis["by_severity"].items()):
            print(f"  {sev}: {count}")

    if findings_analysis.get("by_tool"):
        print("\nBy tool:")
        for tool, count in sorted(
            findings_analysis["by_tool"].items(), key=lambda x: -x[1]
        ):
            print(f"  {tool}: {count}")

    # Log Analysis
    print("\n--- LOG ANALYSIS ---")
    print(f"Errors found: {len(log_analysis.get('errors', []))}")
    print(f"Warnings found: {len(log_analysis.get('warnings', []))}")
    print(f"Timeouts found: {len(log_analysis.get('timeouts', []))}")
    print(f"Tracebacks found: {len(log_analysis.get('tracebacks', []))}")
    print(f"Install failures: {len(log_analysis.get('install_failures', []))}")

    if log_analysis.get("tracebacks"):
        print("\nTracebacks:")
        for tb in log_analysis["tracebacks"][:3]:  # Show first 3
            print(f"  {tb[:200]}...")

    if log_analysis.get("timeouts"):
        print("\nTimeout indicators:")
        for to in log_analysis["timeouts"][:5]:
            print(f"  {to}")

    # Success Criteria
    print("\n--- SUCCESS CRITERIA ---")
    all_passed = success_eval.get("all_passed", False)
    print(f"Overall: {'PASS' if all_passed else 'FAIL'}")
    print()
    for name, info in success_eval.get("criteria", {}).items():
        status = (
            "PASS" if info["passed"] else ("FAIL" if info["passed"] is False else "N/A")
        )
        actual = info["actual"]
        required = info["required"]
        print(f"[{status:4}] {name}: {actual} (required: {required})")
        if name == "juice_shop_tools" and info.get("failed_tools"):
            print(f"        Failed: {', '.join(info['failed_tools'])}")

    print("\n" + "=" * 70)
    print(f"RESULT: {'SUCCESS' if all_passed else 'FAILURE'}")
    print("=" * 70)


def generate_state_update(juice_shop_validation: dict) -> dict:
    """Generate the tool status update for unified-state.json (v2.2 schema)."""
    # Get tool versions from validation result
    tool_versions = juice_shop_validation.get("tool_versions", {})

    return {
        "total": juice_shop_validation["summary"]["total"],
        "ok": juice_shop_validation["summary"]["ok"],
        "content_triggered": juice_shop_validation["summary"]["content_triggered"],
        "windows_unavailable": juice_shop_validation["summary"].get(
            "windows_unavailable", 0
        ),
        "failed": juice_shop_validation["summary"]["failed"],
        "quality_issues": juice_shop_validation["summary"].get("quality_issues", 0),
        "suspicious_empty": juice_shop_validation["summary"].get("suspicious_empty", 0),
        "details": {
            tool: {
                "status": info["status"],
                "findings": info.get("findings", 0),
                "sbom": info.get("sbom", False),
                "reason": info.get("reason"),
                # v2.2: Add version tracking
                "version": tool_versions.get(tool),
                "execution_verified": info["status"] == "OK"
                and info.get("findings", 0) > 0,
            }
            for tool, info in juice_shop_validation["tool_status"].items()
        },
        "tasks_to_create": juice_shop_validation.get("tasks_to_create", []),
        "quality_alerts": juice_shop_validation.get("quality_alerts", []),
        "blocking_issue": juice_shop_validation.get("blocking_issue"),
    }


# ============================================================================
# CROSS-ITERATION LEARNING (v2.2)
# Track patterns across iterations to detect recurring/flaky issues
# ============================================================================

LEARNINGS_FILE = Path("tools/ralph-testing/learnings.json")


def load_learnings() -> dict[str, Any]:
    """Load learnings from file, creating default structure if not exists."""
    if not LEARNINGS_FILE.exists():
        return {
            "version": "1.0.0",
            "description": "Cross-iteration learning for Ralph Loop",
            "recurring_failures": {},
            "flaky_tools": {},
            "known_windows_issues": list(WINDOWS_PROBLEMATIC_TOOLS),
            "iteration_count": 0,
        }

    try:
        with open(LEARNINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return load_learnings()  # Return default on error


def save_learnings(learnings: dict[str, Any]) -> None:
    """Save learnings to file."""
    LEARNINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LEARNINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(learnings, f, indent=2)


def update_learnings(
    juice_shop_validation: dict[str, Any],
    overall_success: bool,
) -> dict[str, Any]:
    """
    Update learnings with results from this iteration.

    Tracks:
    - recurring_failures: Tools that fail consistently
    - flaky_tools: Tools that succeed intermittently

    Args:
        juice_shop_validation: Validation results from this iteration
        overall_success: Whether the overall iteration was successful

    Returns:
        Updated learnings dict with any detected patterns
    """
    learnings = load_learnings()
    learnings["iteration_count"] = learnings.get("iteration_count", 0) + 1
    learnings["last_success"] = overall_success

    tool_status = juice_shop_validation.get("tool_status", {})

    for tool, status_info in tool_status.items():
        status = status_info.get("status", "UNKNOWN")

        # Track failures
        if status not in ("OK", "CONTENT_TRIGGERED", "WINDOWS_UNAVAILABLE", "SKIPPED"):
            # Initialize if needed
            if tool not in learnings["recurring_failures"]:
                learnings["recurring_failures"][tool] = {
                    "count": 0,
                    "statuses": [],
                    "status": "new",
                }

            learnings["recurring_failures"][tool]["count"] += 1
            # Keep last 5 statuses
            learnings["recurring_failures"][tool]["statuses"].append(status)
            if len(learnings["recurring_failures"][tool]["statuses"]) > 5:
                learnings["recurring_failures"][tool]["statuses"].pop(0)

            # Mark as known issue if 3+ consecutive failures
            if learnings["recurring_failures"][tool]["count"] >= 3:
                learnings["recurring_failures"][tool]["status"] = "known_issue"

        else:
            # Tool succeeded - check if it was previously failing (flaky detection)
            if tool in learnings["recurring_failures"]:
                prev_failures = learnings["recurring_failures"][tool]["count"]
                if prev_failures > 0:
                    # Tool was failing, now passing - might be flaky
                    if tool not in learnings["flaky_tools"]:
                        learnings["flaky_tools"][tool] = {
                            "success_count": 0,
                            "failure_count": prev_failures,
                            "success_rate": 0.0,
                        }
                    learnings["flaky_tools"][tool]["success_count"] += 1
                    total = (
                        learnings["flaky_tools"][tool]["success_count"]
                        + learnings["flaky_tools"][tool]["failure_count"]
                    )
                    learnings["flaky_tools"][tool]["success_rate"] = round(
                        learnings["flaky_tools"][tool]["success_count"] / total, 2
                    )

    save_learnings(learnings)
    return learnings


def check_known_patterns(learnings: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Check for known patterns that should be reported.

    Args:
        learnings: Current learnings dict

    Returns:
        List of pattern alerts to display
    """
    alerts = []

    # Check for recurring failures
    for tool, info in learnings.get("recurring_failures", {}).items():
        if info.get("status") == "known_issue":
            alerts.append(
                {
                    "type": "recurring_failure",
                    "tool": tool,
                    "message": f"{tool} has failed {info['count']} times consecutively",
                    "suggestion": "Consider skipping or investigating root cause",
                }
            )

    # Check for flaky tools
    for tool, info in learnings.get("flaky_tools", {}).items():
        if info.get("success_rate", 1.0) < 0.8:
            alerts.append(
                {
                    "type": "flaky_tool",
                    "tool": tool,
                    "message": f"{tool} has {info['success_rate']*100:.0f}% success rate",
                    "suggestion": "Tool may have intermittent issues",
                }
            )

    return alerts


def main():
    """Main entry point."""
    # Parse arguments
    results_dir = Path(
        sys.argv[1] if len(sys.argv) > 1 else "tools/ralph-testing/wizard-results"
    )
    log_file = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    # If no log file specified, find the most recent one
    if not log_file:
        log_dir = Path("tools/ralph-testing/iteration-logs")
        if log_dir.exists():
            logs = sorted(log_dir.glob("wizard-*.log"), reverse=True)
            if logs:
                log_file = logs[0]

    print(f"Results directory: {results_dir}")
    print(f"Log file: {log_file}")

    # Run analysis
    log_analysis = analyze_log_file(log_file) if log_file else {}
    file_analysis = analyze_result_files(results_dir)
    findings_analysis = analyze_findings_json(results_dir)

    # NEW: Juice Shop 12-tool validation
    juice_shop_validation = validate_juice_shop_tools(results_dir, log_analysis)

    # Evaluate success (now includes Juice Shop validation)
    success_eval = evaluate_success(
        log_analysis, file_analysis, findings_analysis, juice_shop_validation
    )

    # Print report
    print_report(
        log_analysis,
        file_analysis,
        findings_analysis,
        juice_shop_validation,
        success_eval,
    )

    # Update cross-iteration learnings
    all_passed = success_eval.get("all_passed", False)
    learnings = update_learnings(juice_shop_validation, all_passed)

    # Check for known patterns
    pattern_alerts = check_known_patterns(learnings)
    if pattern_alerts:
        print("\n--- CROSS-ITERATION PATTERNS ---")
        for alert in pattern_alerts:
            print(f"  [{alert['type']}] {alert['tool']}: {alert['message']}")
            print(f"    Suggestion: {alert['suggestion']}")

    # Output state update for unified-state.json (for scripting)
    if "--json" in sys.argv:
        state_update = generate_state_update(juice_shop_validation)
        print("\n--- STATE UPDATE (for unified-state.json) ---")
        print(json.dumps(state_update, indent=2))

    # Exit with appropriate code
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
