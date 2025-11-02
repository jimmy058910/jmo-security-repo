#!/usr/bin/env python3
"""
Horusec adapter - Maps Horusec multi-language SAST JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Multi-language SAST (18+ languages)
- Security vulnerability detection
- OWASP Top 10 coverage
- CWE-based vulnerability classification

Tool Version: 2.8.0+
Output Format: JSON with analysisVulnerabilities array
Exit Codes: 0 (success), 1+ (findings/errors)

Supported Languages:
- C#, Java, Kotlin, Python, Ruby, Golang
- JavaScript, TypeScript, Dart, Elixir
- PHP, C, HTML, JSON, Shell, Nginx
- Terraform, Kubernetes manifests
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
        name="horusec",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Horusec multi-language SAST scanner",
        tool_name="horusec",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "success", 1: "findings"},
    )
)
class HorusecAdapter(AdapterPlugin):
    """Adapter for Horusec multi-language SAST (plugin architecture).

    v1.0.0 Features:
    - Multi-language static analysis (18+ languages)
    - Security vulnerability detection
    - OWASP Top 10 coverage
    - Comprehensive CWE mappings

    Findings are automatically tagged as 'sast' and 'horusec'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to horusec.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_horusec_internal(output_path)

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


def _load_horusec_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Horusec JSON output.

    Args:
        path: Path to horusec.json output file

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
        logger.warning(f"Failed to parse Horusec JSON: {path}")
        return []

    out: list[dict[str, Any]] = []

    # Horusec JSON structure: {"analysisVulnerabilities": [...], "totalVulnerabilities": N}
    if not isinstance(data, dict):
        return []

    # Extract Horusec version for tool metadata
    horusec_version = str(data.get("version", "2.8.0"))

    # Process analysisVulnerabilities array
    vulnerabilities = data.get("analysisVulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return []

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue

        # Extract vulnerability metadata
        vuln_id = str(vuln.get("vulnerabilityID", vuln.get("id", "")))
        severity_raw = str(vuln.get("severity", "MEDIUM"))
        file_path = str(vuln.get("file", ""))
        line = int(vuln.get("line", 0))
        details = str(vuln.get("details", ""))
        security_tool = str(vuln.get("securityTool", ""))
        vuln_type = str(vuln.get("type", ""))
        code_snippet = str(vuln.get("code", ""))

        # Normalize severity
        severity = normalize_severity(severity_raw)

        # Build message
        message = (
            details if details else f"Security vulnerability detected: {vuln_type}"
        )

        # Build title
        title = vuln_type if vuln_type else vuln_id

        # Generate stable fingerprint
        fid = fingerprint("horusec", vuln_id or vuln_type, file_path, line, message)

        # Build references
        references = []
        # Horusec vulnerabilities often don't have direct CWE mappings in output
        # but they reference security best practices
        if security_tool:
            references.append(
                f"https://docs.horusec.io/docs/vulnerabilities/{security_tool.lower()}/"
            )

        # Build tags
        tags = ["sast", "horusec", "multi-language"]
        if security_tool:
            tags.append(security_tool.lower())
        if vuln_type:
            vuln_type_lower = vuln_type.lower()
            if "sql" in vuln_type_lower:
                tags.append("sql-injection")
            if "xss" in vuln_type_lower or "cross-site" in vuln_type_lower:
                tags.append("xss")
            if "csrf" in vuln_type_lower:
                tags.append("csrf")
            if "command" in vuln_type_lower or "injection" in vuln_type_lower:
                tags.append("injection")
            if "hardcoded" in vuln_type_lower or "secret" in vuln_type_lower:
                tags.append("hardcoded-secret")

        # Build remediation
        remediation = (
            details
            if details
            else "Review and remediate the identified security vulnerability according to OWASP best practices."
        )

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": vuln_id if vuln_id else vuln_type,
            "title": title,
            "message": message,
            "description": details,
            "severity": severity,
            "tool": {
                "name": "horusec",
                "version": horusec_version,
            },
            "location": {
                "path": file_path,
                "startLine": line,
            },
            "remediation": remediation,
            "references": references,
            "tags": tags,
            "context": {
                "vulnerability_id": vuln_id if vuln_id else None,
                "security_tool": security_tool if security_tool else None,
                "vulnerability_type": vuln_type if vuln_type else None,
                "code_snippet": code_snippet if code_snippet else None,
            },
            "raw": vuln,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
