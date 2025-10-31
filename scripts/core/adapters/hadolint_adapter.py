#!/usr/bin/env python3
"""

REFACTORED: v0.9.0 - Now uses plugin architecture
Hadolint adapter: normalize hadolint JSON output to CommonFinding
Expected input: array of issues with fields like: {"code":"DL3008","file":"Dockerfile","line":12,"level":"error","message":"..."}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance
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
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
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


def _load_hadolint_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function that returns dicts (refactored from original load_hadolint)."""


def _load_hadolint_internal(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: List[Dict[str, Any]] = []
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
            "schemaVersion": "1.0.0",
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
        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)
    return out
