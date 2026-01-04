#!/usr/bin/env python3
"""
ShellCheck adapter - Maps ShellCheck shell script linter JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Static analysis for shell scripts (bash, sh, dash, ksh)
- Security-focused checks for command injection risks
- Best practices and portability warnings
- Integration with Hadolint for Dockerfile RUN commands

Tool Version: 0.10.0+
Output Format: JSON array of issues (shellcheck --format=json)
Exit Codes: 0 (clean), 1 (findings)

Rule Categories (SC1xxx - SC3xxx):
- SC1xxx: Parser errors and syntax issues
- SC2xxx: Shell script warnings (most common)
- SC3xxx: Portability issues between shells

Level Mapping (ShellCheck -> CommonFinding):
- error: HIGH (syntax errors, critical issues)
- warning: MEDIUM (potential bugs, bad practices)
- info: LOW (suggestions, style issues)
- style: INFO (cosmetic, pedantic checks)

Common Security-Relevant Rules:
- SC2086: Double quote to prevent globbing and word splitting
- SC2046: Quote command substitution to prevent word splitting
- SC2091: Remove surrounding $() to avoid executing output
- SC2116: Useless echo (command injection risk)
- SC2155: Declare and assign separately to avoid masking return values
- SC2162: read without -r mangles backslashes
- SC2164: Use cd ... || exit in case cd fails
- SC2206: Quote to prevent word splitting in arrays
- SC2012: Use find instead of ls to handle filenames safely

Example:
    >>> adapter = ShellCheckAdapter()
    >>> findings = adapter.parse(Path('shellcheck.json'))
    >>> # Returns shell script linting issues as findings

See Also:
    - https://www.shellcheck.net/
    - https://github.com/koalaman/shellcheck
    - ShellCheck Wiki for rule explanations
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)


# ShellCheck level to CommonFinding severity mapping
SHELLCHECK_LEVEL_MAP: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
    "style": "INFO",
}


def _map_shellcheck_level(level: str) -> str:
    """Map ShellCheck level to CommonFinding severity.

    Args:
        level: ShellCheck level (error, warning, info, style)

    Returns:
        CommonFinding severity (HIGH, MEDIUM, LOW, INFO)
    """
    return SHELLCHECK_LEVEL_MAP.get(level.lower(), "MEDIUM")


@adapter_plugin(
    PluginMetadata(
        name="shellcheck",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for ShellCheck shell script linter",
        tool_name="shellcheck",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class ShellCheckAdapter(AdapterPlugin):
    """Adapter for ShellCheck shell script linter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse ShellCheck JSON output and return normalized findings.

        Args:
            output_path: Path to shellcheck.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0

        Expected JSON structure:
            [
                {
                    "file": "script.sh",
                    "line": 10,
                    "endLine": 10,
                    "column": 5,
                    "endColumn": 15,
                    "level": "warning",
                    "code": 2086,
                    "message": "Double quote to prevent globbing..."
                }
            ]
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_shellcheck_internal(output_path)

        # Convert dicts to Finding objects
        findings = []
        for f_dict in findings_dicts:
            finding = Finding(
                schemaVersion=f_dict.get("schemaVersion", "1.2.0"),
                id=f_dict.get("id", ""),
                ruleId=f_dict.get("ruleId", ""),
                severity=f_dict.get("severity", "INFO"),
                tool=f_dict.get("tool", {}),
                location=f_dict.get("location", {}),
                message=f_dict.get("message", ""),
                title=f_dict.get("title"),
                description=f_dict.get("description"),
                remediation=f_dict.get("remediation"),
                references=f_dict.get("references", []),
                tags=f_dict.get("tags", []),
                cvss=f_dict.get("cvss"),
                risk=f_dict.get("risk"),
                compliance=f_dict.get("compliance"),
                context=f_dict.get("context"),
                raw=f_dict.get("raw"),
            )
            findings.append(finding)

        return findings


def _load_shellcheck_internal(path: str | Path) -> list[dict[str, Any]]:
    """Load and normalize ShellCheck JSON output.

    Args:
        path: Path to shellcheck.json output file

    Returns:
        List of CommonFinding dictionaries (schema v1.2.0)

    Handles:
        - Empty files (returns [])
        - Non-list JSON (returns [])
        - Missing fields (uses defaults)
    """
    data = safe_load_json_file(path, default=None)
    if not isinstance(data, list):
        return []

    out: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        # Extract fields with fallbacks
        file_path = str(item.get("file") or "unknown.sh")
        line = item.get("line")
        start_line = int(line) if isinstance(line, int) else 0
        end_line = item.get("endLine")
        end_line_int = int(end_line) if isinstance(end_line, int) else start_line

        column = item.get("column")
        start_column = int(column) if isinstance(column, int) else 0
        end_column = item.get("endColumn")
        end_column_int = int(end_column) if isinstance(end_column, int) else start_column

        level = str(item.get("level") or "warning")
        code = item.get("code")
        code_str = f"SC{code}" if isinstance(code, int) else str(code or "SC0000")
        message = str(item.get("message") or code_str)

        # Map level to severity
        severity = _map_shellcheck_level(level)
        severity_normalized = normalize_severity(severity)

        # Create fingerprint
        fid = fingerprint("shellcheck", code_str, file_path, start_line, message)

        # Build tags
        tags = ["shell", "lint", "shellcheck"]
        if code_str.startswith("SC1"):
            tags.append("syntax")
        elif code_str.startswith("SC2"):
            tags.append("warning")
        elif code_str.startswith("SC3"):
            tags.append("portability")

        # Build reference URL
        wiki_url = f"https://www.shellcheck.net/wiki/{code_str}"

        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": code_str,
            "title": code_str,
            "message": message,
            "description": message,
            "severity": severity_normalized,
            "tool": {"name": "shellcheck", "version": "unknown"},
            "location": {
                "path": file_path,
                "startLine": start_line,
                "endLine": end_line_int,
                "startColumn": start_column,
                "endColumn": end_column_int,
            },
            "remediation": f"See {wiki_url} for explanation and fix",
            "references": [wiki_url],
            "tags": tags,
            "context": {
                "level": level,
                "code": code,
            },
            "raw": item,
        }
        out.append(finding)

    return out
