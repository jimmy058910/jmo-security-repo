#!/usr/bin/env python3
"""
Hadolint adapter - Maps Hadolint Dockerfile linter JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Dockerfile best practices linting
- ShellCheck integration for RUN instructions
- Docker image security hardening checks
- CIS Docker Benchmark compliance

Tool Version: 2.12.0+
Output Format: JSON array of issues
Exit Codes: 0 (clean), 1 (findings)

Rule Categories:
- DL1xxx: General Dockerfile issues
- DL3xxx: Shell best practices (via ShellCheck integration)
- DL4xxx: Performance and caching issues
- SC1xxx-SC2xxx: ShellCheck rules for RUN commands

Level Mapping (Hadolint -> CommonFinding):
- error: HIGH
- warning: MEDIUM
- info: LOW
- style: INFO

Common Rules:
- DL3008: Pin versions in apt-get install
- DL3009: Delete apt-get cache after installing
- DL3013: Pin versions in pip install
- DL3015: Avoid additional packages with apt-get
- DL3018: Pin versions in apk add
- DL3020: Use COPY instead of ADD for files
- DL4006: Set SHELL to fail pipelines

Example:
    >>> adapter = HadolintAdapter()
    >>> findings = adapter.parse(Path('hadolint.json'))
    >>> # Returns Dockerfile linting issues as findings

See Also:
    - https://github.com/hadolint/hadolint
    - CIS Docker Benchmark
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


@adapter_plugin(
    PluginMetadata(
        name="hadolint",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Hadolint Dockerfile linter",
        tool_name="hadolint",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class HadolintAdapter(AdapterPlugin):
    """Adapter for Hadolint Dockerfile linter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to hadolint.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_hadolint_internal(output_path)

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


def _load_hadolint_internal(path: str | Path) -> list[dict[str, Any]]:
    data = safe_load_json_file(path, default=None)
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for it in data:
        if not isinstance(it, dict):
            continue
        code = str(it.get("code") or "HADOLINT")
        file_path = str(it.get("file") or "Dockerfile")
        line = int(it.get("line") or 0)
        msg = str(it.get("message") or code)
        sev = normalize_severity(it.get("level") or "MEDIUM")
        fid = fingerprint("hadolint", code, file_path, line, msg)
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": code,
            "title": code,
            "message": msg,
            "description": msg,
            "severity": sev,
            "tool": {"name": "hadolint", "version": "unknown"},
            "location": {"path": file_path, "startLine": line},
            "remediation": str(it.get("reference") or "See rule documentation"),
            "tags": ["dockerfile", "lint"],
            "raw": it,
        }
        out.append(finding)
    return out
