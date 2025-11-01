#!/usr/bin/env python3
"""
Bearer CLI adapter - Maps Bearer JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Data privacy and security SAST scanner
- Detects: PII exposure, third-party data flows, insecure data handling
- Supports: Ruby, JavaScript, TypeScript, Python, Go, PHP, Java
- Privacy-first security scanning

Tool Version: 1.40.0+
Output Format: JSON with dataflow/security findings
Exit Codes: 0 (pass), 1 (findings), 2+ (errors)

Supported Detections:
- Data privacy violations (PII, sensitive data exposure)
- Third-party data flows
- Insecure data handling patterns
- SAST security rules
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
        name="bearer",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Bearer CLI (data privacy and security SAST)",
        tool_name="bearer",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "pass", 1: "findings", 2: "error"},
    )
)
class BearerAdapter(AdapterPlugin):
    """Adapter for Bearer CLI (plugin architecture).

    v1.0.0 Features:
    - Data privacy scanning (PII, sensitive data)
    - Third-party data flow tracking
    - Insecure data handling detection
    - Multi-language SAST support

    Findings are automatically tagged as 'data-privacy'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to bearer.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_bearer_internal(output_path)

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


def _load_bearer_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse Bearer JSON output.

    Args:
        path: Path to bearer.json output file

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
        logger.warning(f"Failed to parse Bearer JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # Bearer JSON can have multiple report formats:
    # - Dataflow report: {"data_types": [...], with detectors and locations}
    # - Security report: {"findings": [...]}
    # - Privacy report: {"subjects": [...], "third_party": [...]}
    if not isinstance(data, dict):
        return []

    # Process dataflow report (data types with detections)
    data_types = data.get("data_types", [])
    if isinstance(data_types, list):
        for data_type_entry in data_types:
            if not isinstance(data_type_entry, dict):
                continue

            data_type_name = str(data_type_entry.get("name", "unknown"))

            # Extract detectors
            detectors = data_type_entry.get("detectors", [])
            if isinstance(detectors, list):
                for detector in detectors:
                    if not isinstance(detector, dict):
                        continue

                    # Extract locations
                    locations = detector.get("locations", [])
                    if isinstance(locations, list):
                        for loc in locations:
                            if not isinstance(loc, dict):
                                continue

                            # Extract location details
                            filename = str(loc.get("filename", ""))
                            line_number = int(loc.get("line_number", 0))
                            field_name = str(loc.get("field_name", ""))
                            subject_name = str(loc.get("subject_name", ""))

                            # Build message
                            message = f"Data type '{data_type_name}' detected"
                            if subject_name:
                                message += f" (subject: {subject_name})"
                            if field_name:
                                message += f" in field '{field_name}'"

                            # Generate stable fingerprint
                            fid = fingerprint(
                                "bearer",
                                f"DATA.{data_type_name}",
                                filename,
                                line_number,
                                message,
                            )

                            # Build finding dict
                            finding = {
                                "schemaVersion": "1.2.0",
                                "id": fid,
                                "ruleId": f"DATA.{data_type_name}",
                                "title": f"Data Type: {data_type_name}",
                                "message": message,
                                "description": f"Sensitive data type '{data_type_name}' detected in application",
                                "severity": "MEDIUM",  # Data privacy findings default to MEDIUM
                                "tool": {
                                    "name": "bearer",
                                    "version": "1.40.0",  # Bearer v1.40.0+
                                },
                                "location": {
                                    "path": filename,
                                    "startLine": line_number,
                                },
                                "remediation": f"Review handling of sensitive data type '{data_type_name}'",
                                "references": [],
                                "tags": ["data-privacy", "sensitive-data"],
                                "context": {
                                    "data_type": data_type_name,
                                    "subject_name": (
                                        subject_name if subject_name else None
                                    ),
                                    "field_name": field_name if field_name else None,
                                },
                                "raw": loc,
                            }

                            # Enrich with compliance framework mappings
                            finding = enrich_finding_with_compliance(finding)
                            out.append(finding)

    # Process security findings (if present)
    findings = data.get("findings", [])
    if isinstance(findings, list):
        for finding_entry in findings:
            if not isinstance(finding_entry, dict):
                continue

            # Extract finding details
            rule_id = str(finding_entry.get("rule_id", "BEARER"))
            severity_raw = str(finding_entry.get("severity", "MEDIUM"))
            severity = normalize_severity(severity_raw)
            filename = str(finding_entry.get("filename", ""))
            line_number = int(finding_entry.get("line_number", 0))
            description = str(finding_entry.get("description", ""))

            # Build message
            message = description if description else f"Security finding: {rule_id}"

            # Generate stable fingerprint
            fid = fingerprint("bearer", rule_id, filename, line_number, message)

            # Build finding dict
            finding_dict = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": rule_id,
                "title": rule_id,
                "message": message,
                "description": (
                    description if description else f"Security rule {rule_id} triggered"
                ),
                "severity": severity,
                "tool": {
                    "name": "bearer",
                    "version": "1.40.0",
                },
                "location": {
                    "path": filename,
                    "startLine": line_number,
                },
                "remediation": "Review security finding and apply recommended fixes",
                "references": [],
                "tags": ["data-privacy", "security"],
                "context": {
                    "rule_id": rule_id,
                },
                "raw": finding_entry,
            }

            # Enrich with compliance framework mappings
            finding_dict = enrich_finding_with_compliance(finding_dict)
            out.append(finding_dict)

    return out
