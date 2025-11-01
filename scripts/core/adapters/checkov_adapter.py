#!/usr/bin/env python3
"""

REFACTORED: v0.9.0 - Now uses plugin architecture
Checkov adapter: normalize Checkov JSON output (SAST for IaC) to CommonFinding.
Expected input may include a top-level results dictionary with "failed_checks" entries.
"""

from __future__ import annotations

import json
import logging
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

# Configure logging
logger = logging.getLogger(__name__)


@adapter_plugin(
    PluginMetadata(
        name="checkov",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Checkov IaC security scanner",
        tool_name="checkov",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class CheckovAdapter(AdapterPlugin):
    """Adapter for Checkov IaC security scanner (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to checkov.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_checkov_internal(output_path)

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


def _load_checkov_internal(path: str | Path) -> List[Dict[str, Any]]:
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

    out: List[Dict[str, Any]] = []
    # Handle structure: {"results":{"failed_checks":[...]}}
    results = data.get("results") if isinstance(data, dict) else None
    failed = results.get("failed_checks") if isinstance(results, dict) else None
    if isinstance(failed, list):
        for it in failed:
            if not isinstance(it, dict):
                continue
            rid = str(it.get("check_id") or it.get("check_name") or "CHECKOV")
            file_path = str(it.get("file_path") or it.get("repo_file_path") or "")
            # Line number may be provided as a list range, a scalar, or invalid; default to 0 on errors
            line_val = it.get("file_line_range")
            line = 0
            try:
                if isinstance(line_val, list) and line_val:
                    line = int(line_val[0])
                elif isinstance(line_val, (int, str)):
                    line = int(line_val)
                else:
                    line = 0
            except (ValueError, TypeError) as e:
                # Line number parsing failed - default to 0
                logger.debug(f"Failed to parse line number in checkov output: {e}")
                line = 0
            msg = str(it.get("check_name") or it.get("check_id") or "Policy failure")
            sev = normalize_severity(it.get("severity") or "MEDIUM")
            fid = fingerprint("checkov", rid, file_path, line, msg)
            finding = {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": rid,
                "title": rid,
                "message": msg,
                "description": str(it.get("guideline") or msg),
                "severity": sev,
                "tool": {
                    "name": "checkov",
                    "version": str(data.get("checkov_version") or "unknown"),
                },
                "location": {"path": file_path, "startLine": line},
                "remediation": str(it.get("guideline") or "Review policy guidance"),
                "tags": ["iac", "policy"],
                "raw": it,
            }
            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)
    return out
