#!/usr/bin/env python3
"""
ScanCode adapter - Maps ScanCode Toolkit JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- License compliance scanner
- Detects: Licenses, copyrights, authors, package metadata
- SPDX license expressions support
- Detailed match scoring and provenance

Tool Version: 32.0.0+
Output Format: JSON with headers + files[]
Exit Codes: 0 (success), 1+ (errors)

Supported Detections:
- Licenses (SPDX expressions, match scores, rule identifiers)
- Copyrights (statements, holders, authors)
- Emails, URLs, package data
- Programming language classification
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint
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
        name="scancode",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for ScanCode Toolkit (license compliance scanner)",
        tool_name="scancode",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "success", 1: "error"},
    )
)
class ScancodeAdapter(AdapterPlugin):
    """Adapter for ScanCode Toolkit (plugin architecture).

    v1.0.0 Features:
    - License detection with SPDX expressions
    - Copyright, author, and holder extraction
    - Match scoring and provenance tracking
    - Package metadata discovery

    Findings represent license detections and copyright statements.
    Tagged as 'license-compliance'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to scancode.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_scancode_internal(output_path)

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


def _load_scancode_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse ScanCode JSON output.

    Args:
        path: Path to scancode.json output file

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
        logger.warning(f"Failed to parse ScanCode JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # ScanCode JSON structure: {"headers": [...], "files": [...]}
    if not isinstance(data, dict):
        return []

    # Extract tool version from headers
    tool_version = "unknown"
    headers = data.get("headers", [])
    if isinstance(headers, list):
        for header in headers:
            if isinstance(header, dict) and "tool_version" in header:
                tool_version = str(header["tool_version"])
                break

    # Extract files array
    files = data.get("files", [])
    if not isinstance(files, list):
        return []

    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue

        file_path = str(file_entry.get("path", ""))
        file_type = str(file_entry.get("type", "file"))

        # Skip directories (only scan files)
        if file_type == "directory":
            continue

        # Extract license detections
        license_detections = file_entry.get("license_detections", [])
        if isinstance(license_detections, list):
            for detection in license_detections:
                if not isinstance(detection, dict):
                    continue

                # Extract license expression
                license_expr = str(detection.get("license_expression", ""))
                if not license_expr:
                    continue

                # Extract identifier (unique detection ID)
                detection_id = str(detection.get("identifier", ""))

                # Extract matches for scoring
                matches = detection.get("matches", [])
                max_score = 0.0
                rule_id = ""
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, dict):
                            score = float(match.get("score", 0))
                            if score > max_score:
                                max_score = score
                                rule_id = str(match.get("rule_identifier", ""))

                # Build message
                message = f"License detected: {license_expr}"
                if max_score > 0:
                    message += f" (confidence: {max_score:.1f}%)"

                # Determine severity based on license type (informational, but flag copyleft)
                severity = "INFO"
                if any(copyleft in license_expr.lower() for copyleft in ["gpl", "agpl", "lgpl", "mpl", "cddl", "epl"]):
                    severity = "LOW"  # Copyleft licenses require review

                # Generate stable fingerprint
                fid = fingerprint("scancode", license_expr, file_path, 0, message)

                # Build finding dict
                finding = {
                    "schemaVersion": "1.2.0",
                    "id": fid,
                    "ruleId": license_expr,
                    "title": license_expr,
                    "message": message,
                    "description": f"License {license_expr} detected in {file_path}",
                    "severity": severity,
                    "tool": {
                        "name": "scancode",
                        "version": tool_version,
                    },
                    "location": {
                        "path": file_path,
                        "startLine": 0,  # License detections don't have line numbers
                    },
                    "remediation": None,  # License compliance is informational
                    "references": [],
                    "tags": ["license-compliance", "spdx"],
                    "context": {
                        "license_expression": license_expr,
                        "detection_id": detection_id if detection_id else None,
                        "match_score": max_score if max_score > 0 else None,
                        "rule_identifier": rule_id if rule_id else None,
                    },
                    "raw": detection,
                }

                # Enrich with compliance framework mappings
                finding = enrich_finding_with_compliance(finding)
                out.append(finding)

        # Extract copyright statements
        copyrights = file_entry.get("copyrights", [])
        if isinstance(copyrights, list):
            for copyright_entry in copyrights:
                if not isinstance(copyright_entry, dict):
                    continue

                # Extract copyright statement
                copyright_value = str(copyright_entry.get("value", ""))
                if not copyright_value:
                    continue

                # Extract line range
                start_line = int(copyright_entry.get("start_line", 0))
                end_line = int(copyright_entry.get("end_line", 0))

                # Build message
                message = f"Copyright: {copyright_value}"

                # Generate stable fingerprint
                fid = fingerprint("scancode", "COPYRIGHT", file_path, start_line, copyright_value)

                # Build finding dict
                finding = {
                    "schemaVersion": "1.2.0",
                    "id": fid,
                    "ruleId": "COPYRIGHT",
                    "title": "Copyright Statement",
                    "message": message,
                    "description": f"Copyright statement found in {file_path}",
                    "severity": "INFO",
                    "tool": {
                        "name": "scancode",
                        "version": tool_version,
                    },
                    "location": {
                        "path": file_path,
                        "startLine": start_line,
                        "endLine": end_line if end_line > start_line else None,
                    },
                    "remediation": None,
                    "references": [],
                    "tags": ["license-compliance", "copyright"],
                    "context": {
                        "copyright_statement": copyright_value,
                        "line_range": [start_line, end_line] if end_line > start_line else [start_line],
                    },
                    "raw": copyright_entry,
                }

                # Enrich with compliance framework mappings
                finding = enrich_finding_with_compliance(finding)
                out.append(finding)

    return out
