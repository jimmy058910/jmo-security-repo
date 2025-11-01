#!/usr/bin/env python3
"""
Lynis adapter - Maps Lynis Security Audit data format to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- System hardening and security auditing
- Linux/Unix/macOS security assessments
- Compliance checking (PCI-DSS, HIPAA, ISO 27001)
- Configuration hardening recommendations

Tool Version: 3.1.0+
Output Format: JSON converted from lynis-report.dat (key-value pairs)
Exit Codes: 0 (success), 1 (errors)

Supported Platforms:
- Linux (all distributions)
- Unix systems
- macOS
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
        name="lynis",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Lynis security auditing and system hardening",
        tool_name="lynis",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "success", 1: "error"},
    )
)
class LynisAdapter(AdapterPlugin):
    """Adapter for Lynis security auditing tool (plugin architecture).

    v1.0.0 Features:
    - System hardening audits (Linux, Unix, macOS)
    - Security configuration checks
    - Compliance assessments (PCI-DSS, HIPAA, ISO 27001, SOC 2)
    - Vulnerability detection and recommendations

    Findings are automatically tagged as 'system-hardening'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to lynis.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_lynis_internal(output_path)

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


def _load_lynis_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse Lynis JSON output.

    Args:
        path: Path to lynis.json output file (converted from lynis-report.dat)

    Returns:
        List of dicts (converted to Finding objects by parse() method)

    Note:
        Lynis native format is key-value pairs in lynis-report.dat.
        This adapter expects JSON format with warnings/suggestions arrays.
        Use a converter tool or custom parser to convert lynis-report.dat to JSON.
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
        logger.warning(f"Failed to parse Lynis JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # Lynis JSON structure: {"warnings": [...], "suggestions": [...], "system_info": {...}}
    if not isinstance(data, dict):
        return []

    # Extract system info for location context
    system_info = data.get("system_info", {})
    hostname = str(system_info.get("hostname", "localhost"))
    os_name = str(system_info.get("os", "unknown"))
    os_version = str(system_info.get("os_version", ""))

    # Process warnings (HIGH severity)
    warnings = data.get("warnings", [])
    if isinstance(warnings, list):
        for warning in warnings:
            if not isinstance(warning, dict):
                continue

            # Extract warning metadata
            test_id = str(warning.get("test_id", warning.get("id", "")))
            message = str(warning.get("message", warning.get("description", "")))
            details = str(warning.get("details", ""))

            # Build title from test_id
            title = f"Security Warning: {test_id}" if test_id else "Security Warning"

            # Generate stable fingerprint
            fid = fingerprint("lynis", test_id or "warning", hostname, 0, message)

            # Build references (Lynis test details)
            references = []
            if test_id:
                references.append(f"https://cisofy.com/lynis/controls/{test_id}/")

            # Build tags
            tags = ["system-hardening", "compliance", "configuration", "warning"]

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": test_id if test_id else "lynis-warning",
                "title": title,
                "message": message,
                "description": details if details else message,
                "severity": "HIGH",  # Warnings are high severity
                "tool": {
                    "name": "lynis",
                    "version": "3.1.0",  # Lynis v3.1.0+
                },
                "location": {
                    "path": hostname,
                    "startLine": 0,  # System-level findings don't have line numbers
                },
                "remediation": details if details else "Review the security warning and apply recommended hardening measures",
                "references": references,
                "tags": tags,
                "context": {
                    "test_id": test_id if test_id else None,
                    "finding_type": "warning",
                    "hostname": hostname,
                    "os": os_name,
                    "os_version": os_version if os_version else None,
                },
                "raw": warning,
            }

            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    # Process suggestions (MEDIUM severity)
    suggestions = data.get("suggestions", [])
    if isinstance(suggestions, list):
        for suggestion in suggestions:
            if not isinstance(suggestion, dict):
                continue

            # Extract suggestion metadata
            test_id = str(suggestion.get("test_id", suggestion.get("id", "")))
            message = str(suggestion.get("message", suggestion.get("description", "")))
            details = str(suggestion.get("details", ""))

            # Build title from test_id
            title = f"Security Suggestion: {test_id}" if test_id else "Security Suggestion"

            # Generate stable fingerprint
            fid = fingerprint("lynis", test_id or "suggestion", hostname, 0, message)

            # Build references
            references = []
            if test_id:
                references.append(f"https://cisofy.com/lynis/controls/{test_id}/")

            # Build tags
            tags = ["system-hardening", "compliance", "configuration", "suggestion"]

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": test_id if test_id else "lynis-suggestion",
                "title": title,
                "message": message,
                "description": details if details else message,
                "severity": "MEDIUM",  # Suggestions are medium severity
                "tool": {
                    "name": "lynis",
                    "version": "3.1.0",
                },
                "location": {
                    "path": hostname,
                    "startLine": 0,
                },
                "remediation": details if details else "Review the security suggestion and consider implementing the recommended improvement",
                "references": references,
                "tags": tags,
                "context": {
                    "test_id": test_id if test_id else None,
                    "finding_type": "suggestion",
                    "hostname": hostname,
                    "os": os_name,
                    "os_version": os_version if os_version else None,
                },
                "raw": suggestion,
            }

            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    # Process vulnerabilities (CRITICAL severity)
    vulnerabilities = data.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            # Extract vulnerability metadata
            vuln_id = str(vulnerability.get("id", ""))
            cve = str(vulnerability.get("cve", ""))
            message = str(vulnerability.get("message", vulnerability.get("description", "")))
            package = str(vulnerability.get("package", ""))

            # Build title
            title = f"Vulnerability: {cve}" if cve else f"Vulnerability: {vuln_id}"

            # Generate stable fingerprint
            fid = fingerprint("lynis", vuln_id or cve, hostname, 0, message)

            # Build references
            references = []
            if cve:
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

            # Build tags
            tags = ["system-hardening", "vulnerability", "compliance"]
            if package:
                tags.append("package")
            if cve:
                tags.append("cve")

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": cve if cve else vuln_id,
                "title": title,
                "message": message,
                "description": message,
                "severity": "CRITICAL",  # Vulnerabilities are critical
                "tool": {
                    "name": "lynis",
                    "version": "3.1.0",
                },
                "location": {
                    "path": f"{hostname}:{package}" if package else hostname,
                    "startLine": 0,
                },
                "remediation": f"Update {package} to the latest version" if package else "Update vulnerable package",
                "references": references,
                "tags": tags,
                "context": {
                    "vulnerability_id": vuln_id if vuln_id else None,
                    "cve": cve if cve else None,
                    "finding_type": "vulnerability",
                    "hostname": hostname,
                    "package": package if package else None,
                    "os": os_name,
                    "os_version": os_version if os_version else None,
                },
                "raw": vulnerability,
            }

            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    return out
