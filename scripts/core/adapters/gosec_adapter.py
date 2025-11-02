#!/usr/bin/env python3
"""
Gosec adapter - Maps Gosec JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Go-specific SAST scanner
- Detects: Hardcoded credentials, SQL injection, weak crypto, command injection, etc.
- Confidence levels: HIGH, MEDIUM, LOW
- Severity levels: HIGH, MEDIUM, LOW

Tool Version: 2.20.0+
Output Format: JSON with Issues[] array
Exit Codes: 0 (clean), 1 (findings), 2+ (errors)

Supported Rule Categories:
- G101-G602: Go-specific security issues
- Common detections: Hardcoded credentials, SQL injection, weak crypto, insecure random, etc.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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
        name="gosec",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Gosec Go security scanner (SAST)",
        tool_name="gosec",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class GosecAdapter(AdapterPlugin):
    """Adapter for Gosec Go security scanner (plugin architecture).

    v1.0.0 Features:
    - Go-specific SAST (hardcoded credentials, SQL injection, weak crypto, etc.)
    - Confidence-based filtering (HIGH, MEDIUM, LOW)
    - 100+ security rules (G101-G602)

    Findings are automatically tagged as 'sast' and 'golang'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to gosec.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_gosec_internal(output_path)

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


def _load_gosec_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Gosec JSON output.

    Args:
        path: Path to gosec.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse Gosec JSON: {path}")
        return []

    out: list[dict[str, Any]] = []

    # Gosec JSON structure: {"Issues": [...], "Stats": {...}}
    issues = data.get("Issues") if isinstance(data, dict) else None
    if not isinstance(issues, list):
        return []

    for issue in issues:
        if not isinstance(issue, dict):
            continue

        # Extract core fields
        rule_id = str(issue.get("rule_id") or "GOSEC")
        file_path = str(issue.get("file") or "")
        line_str = str(issue.get("line") or "0")

        # Parse line number (may be single number or range like "12-15")
        line = 0
        try:
            if "-" in line_str:
                # Range format: take first line number
                line = int(line_str.split("-")[0])
            else:
                line = int(line_str)
        except (ValueError, AttributeError):
            logger.debug(f"Failed to parse line number in Gosec output: {line_str}")
            line = 0

        # Extract details and code
        details = str(issue.get("details") or "Security issue detected")
        code_snippet = str(issue.get("code") or "")

        # Map Gosec severity to CommonFinding severity
        # Gosec uses uppercase: HIGH, MEDIUM, LOW
        gosec_severity = str(issue.get("severity") or "MEDIUM").upper()
        severity = normalize_severity(gosec_severity)

        # Extract confidence (HIGH, MEDIUM, LOW)
        confidence = str(issue.get("confidence") or "MEDIUM").upper()

        # Generate stable fingerprint
        fid = fingerprint("gosec", rule_id, file_path, line, details)

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": rule_id,
            "title": rule_id,
            "message": details,
            "description": details,
            "severity": severity,
            "tool": {
                "name": "gosec",
                "version": str(data.get("Golang errors", {}).get("gosec", "unknown")),
            },
            "location": {
                "path": file_path,
                "startLine": line,
            },
            "remediation": f"Review Go code for {rule_id}. Confidence: {confidence}",
            "tags": ["sast", "golang"],
            "context": {
                "confidence": confidence,
                "code_snippet": code_snippet if code_snippet else None,
            },
            "raw": issue,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
