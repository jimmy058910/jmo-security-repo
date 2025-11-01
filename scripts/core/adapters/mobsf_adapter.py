#!/usr/bin/env python3
"""
MobSF adapter - Maps Mobile Security Framework JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Mobile application security testing (Android/iOS/Windows)
- Static and dynamic analysis
- OWASP Mobile Top 10 detection
- Code analysis, manifest analysis, binary analysis

Tool Version: 4.4.0+
Output Format: JSON with code_analysis and manifest_analysis sections
Exit Codes: 0 (success), 1+ (errors)

Supported Platforms:
- Android (APK, XAPK, AAB)
- iOS (IPA)
- Windows (APPX)
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
        name="mobsf",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Mobile Security Framework (MobSF)",
        tool_name="mobsf",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "success", 1: "error"},
    )
)
class MobsfAdapter(AdapterPlugin):
    """Adapter for Mobile Security Framework (plugin architecture).

    v1.0.0 Features:
    - Mobile app security testing (Android, iOS, Windows)
    - OWASP Mobile Top 10 detection
    - Code analysis (hardcoded secrets, insecure crypto, SQL injection)
    - Manifest analysis (permissions, components)

    Findings are automatically tagged as 'mobile-security'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to mobsf.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_mobsf_internal(output_path)

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


def _load_mobsf_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse MobSF JSON output.

    Args:
        path: Path to mobsf.json output file

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
        logger.warning(f"Failed to parse MobSF JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # MobSF JSON structure: {"code_analysis": {...}, "manifest_analysis": {...}, ...}
    if not isinstance(data, dict):
        return []

    # Extract file name for location
    file_name = str(data.get("file_name", "mobile_app"))
    app_name = str(data.get("app_name", file_name))

    # Process code_analysis findings
    code_analysis = data.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        for finding_key, finding_data in code_analysis.items():
            if not isinstance(finding_data, dict):
                continue

            # Extract metadata
            metadata = finding_data.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            title = str(metadata.get("description", finding_key))
            severity_raw = str(metadata.get("severity", "info")).upper()
            cwe = str(metadata.get("cwe", ""))
            owasp = str(metadata.get("owasp-mobile", ""))
            masvs = str(metadata.get("masvs", ""))

            # Normalize severity (MobSF uses: high, warning, info, secure)
            if severity_raw == "HIGH":
                severity = "HIGH"
            elif severity_raw == "WARNING":
                severity = "MEDIUM"
            elif severity_raw == "INFO":
                severity = "LOW"
            else:
                severity = "INFO"

            # Extract file paths where issue was found
            files = finding_data.get("files", [])
            if not isinstance(files, list):
                files = []

            # Create finding for each file location
            if not files:
                # No specific files, create one finding
                files = [{"file_path": app_name, "match_position": []}]

            for file_entry in files:
                if not isinstance(file_entry, dict):
                    continue

                file_path = str(file_entry.get("file_path", app_name))
                match_positions = file_entry.get("match_position", [])

                # Extract line number (use first match position if available)
                line_number = 0
                if isinstance(match_positions, list) and match_positions:
                    first_match = match_positions[0]
                    if isinstance(first_match, dict):
                        line_number = int(first_match.get("start", 0))

                # Build message
                message = title

                # Generate stable fingerprint
                fid = fingerprint("mobsf", finding_key, file_path, line_number, message)

                # Build references
                references = []
                if cwe:
                    references.append(
                        f"https://cwe.mitre.org/data/definitions/{cwe}.html"
                    )
                if owasp:
                    references.append(f"https://owasp.org/www-project-mobile-top-10/")

                # Build tags
                tags = ["mobile-security", "sast"]
                if owasp:
                    tags.append("owasp-mobile")
                if cwe:
                    tags.append(f"cwe-{cwe}")
                if masvs:
                    tags.append("masvs")

                # Build finding dict
                finding = {
                    "schemaVersion": "1.2.0",
                    "id": fid,
                    "ruleId": finding_key,
                    "title": title,
                    "message": message,
                    "description": title,
                    "severity": severity,
                    "tool": {
                        "name": "mobsf",
                        "version": "4.4.0",  # MobSF v4.4.0+
                    },
                    "location": {
                        "path": file_path,
                        "startLine": line_number,
                    },
                    "remediation": "Review mobile security best practices and remediate the identified issue",
                    "references": references,
                    "tags": tags,
                    "context": {
                        "finding_key": finding_key,
                        "cwe": cwe if cwe else None,
                        "owasp_mobile": owasp if owasp else None,
                        "masvs": masvs if masvs else None,
                        "app_name": app_name,
                        "match_count": (
                            len(match_positions)
                            if isinstance(match_positions, list)
                            else 0
                        ),
                    },
                    "raw": finding_data,
                }

                # Enrich with compliance framework mappings
                finding = enrich_finding_with_compliance(finding)
                out.append(finding)

    # Process manifest_analysis findings
    manifest_analysis = data.get("manifest_analysis", {})
    if isinstance(manifest_analysis, dict):
        for finding_key, finding_data in manifest_analysis.items():
            if not isinstance(finding_data, dict):
                continue

            # Skip non-security findings
            severity_raw = str(finding_data.get("severity", "info")).upper()
            if severity_raw == "SECURE":
                continue

            # Extract metadata
            title = str(finding_data.get("title", finding_key))
            description = str(finding_data.get("description", title))

            # Normalize severity
            if severity_raw == "HIGH":
                severity = "HIGH"
            elif severity_raw == "WARNING":
                severity = "MEDIUM"
            elif severity_raw == "INFO":
                severity = "LOW"
            else:
                severity = "INFO"

            # Build message
            message = description

            # Generate stable fingerprint (manifest findings don't have line numbers)
            fid = fingerprint("mobsf", finding_key, "AndroidManifest.xml", 0, message)

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": finding_key,
                "title": title,
                "message": message,
                "description": description,
                "severity": severity,
                "tool": {
                    "name": "mobsf",
                    "version": "4.4.0",
                },
                "location": {
                    "path": "AndroidManifest.xml",
                    "startLine": 0,
                },
                "remediation": "Review manifest configuration and apply security best practices",
                "references": [],
                "tags": ["mobile-security", "manifest", "configuration"],
                "context": {
                    "finding_key": finding_key,
                    "analysis_type": "manifest",
                    "app_name": app_name,
                },
                "raw": finding_data,
            }

            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    return out
