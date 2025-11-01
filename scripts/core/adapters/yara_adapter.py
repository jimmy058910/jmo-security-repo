#!/usr/bin/env python3
"""
YARA adapter - Maps YARA malware detection JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Malware pattern matching and detection
- 200-500 curated rules from Neo23x0/signature-base
- Web shells, backdoors, APTs, cryptominers, ransomware detection
- Performance optimized (<10s for 1,000 files)

Tool Version: 4.3.0+
Output Format: JSON with matches array
Exit Codes: 0 (no matches), 1+ (matches found)

Supported Detection Categories:
- Web shells (PHP, ASPX, JSP)
- Backdoors and trojans
- APT indicators
- Cryptominers and ransomware
- Exploits and vulnerabilities
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
        name="yara",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for YARA malware detection scanner",
        tool_name="yara",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "matches"},
    )
)
class YaraAdapter(AdapterPlugin):
    """Adapter for YARA malware detection (plugin architecture).

    v1.0.0 Features:
    - Malware pattern matching (web shells, backdoors, APTs, cryptominers)
    - 200-500 curated rules from Neo23x0/signature-base
    - Tag-based categorization (webshell, apt, trojan, exploit)
    - Performance optimized for development security

    Findings are automatically tagged as 'malware-detection'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to yara.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_yara_internal(output_path)

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


def _load_yara_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse YARA JSON output.

    Args:
        path: Path to yara.json output file

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
        logger.warning(f"Failed to parse YARA JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # YARA JSON structure (with --json-output flag):
    # Single match: {"rule": "...", "namespace": "...", "tags": [...], "meta": {...}, "strings": [...]}
    # Multiple matches: Array of match objects

    # Handle both single match and array of matches
    matches = []
    if isinstance(data, dict):
        # Single match object
        matches = [data]
    elif isinstance(data, list):
        # Array of matches
        matches = data
    else:
        return []

    for match in matches:
        if not isinstance(match, dict):
            continue

        # Extract rule name
        rule_name = str(match.get("rule", ""))
        if not rule_name:
            continue

        # Extract namespace
        namespace = str(match.get("namespace", "default"))

        # Extract tags
        tags_list = match.get("tags", [])
        if not isinstance(tags_list, list):
            tags_list = []
        rule_tags = [str(tag) for tag in tags_list]

        # Extract metadata
        meta = match.get("meta", {})
        if not isinstance(meta, dict):
            meta = {}

        # Extract description and severity from metadata
        description = str(meta.get("description", rule_name))
        author = str(meta.get("author", ""))
        reference = str(meta.get("reference", ""))

        # Determine severity from rule tags and metadata
        severity_raw = str(meta.get("severity", "")).upper()
        if not severity_raw:
            # Infer severity from tags
            if any(tag.lower() in ["critical", "apt", "ransomware", "backdoor"] for tag in rule_tags):
                severity_raw = "CRITICAL"
            elif any(tag.lower() in ["high", "webshell", "trojan", "exploit"] for tag in rule_tags):
                severity_raw = "HIGH"
            elif any(tag.lower() in ["medium", "suspicious"] for tag in rule_tags):
                severity_raw = "MEDIUM"
            else:
                severity_raw = "HIGH"  # Default for malware detection

        severity = normalize_severity(severity_raw)

        # Extract matched strings
        strings_matched = match.get("strings", [])
        if not isinstance(strings_matched, list):
            strings_matched = []

        # Extract file path (YARA includes "scans" array with file paths in some formats)
        # Fallback: use rule name as location if no file path available
        file_path = ""
        if "scans" in match and isinstance(match["scans"], list):
            if len(match["scans"]) > 0 and isinstance(match["scans"][0], dict):
                file_path = str(match["scans"][0].get("file", ""))

        if not file_path:
            # Try alternative format where file path is directly in match
            file_path = str(match.get("file", ""))

        if not file_path:
            # Fallback to rule name
            file_path = f"malware:{rule_name}"

        # Build message
        message = f"YARA rule '{rule_name}' matched: {description}"
        if strings_matched:
            message += f" ({len(strings_matched)} string matches)"

        # Generate stable fingerprint
        fid = fingerprint("yara", rule_name, file_path, 0, message)

        # Build references
        references = []
        if reference:
            references.append(reference)

        # Build tags (combine tool-specific and rule-specific tags)
        tags = ["malware-detection", "yara"]
        tags.extend([tag.lower().replace(" ", "-") for tag in rule_tags])
        if namespace != "default":
            tags.append(f"namespace:{namespace.lower()}")

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": rule_name,
            "title": f"Malware Detected: {rule_name}",
            "message": message,
            "description": description,
            "severity": severity,
            "tool": {
                "name": "yara",
                "version": "4.3.0",  # YARA v4.3.0+
            },
            "location": {
                "path": file_path,
                "startLine": 0,  # Binary files don't have line numbers
            },
            "remediation": f"Review file for malware indicators. YARA rule '{rule_name}' detected malicious patterns.",
            "references": references,
            "tags": tags,
            "context": {
                "rule_name": rule_name,
                "namespace": namespace,
                "author": author if author else None,
                "rule_tags": rule_tags,
                "matched_strings_count": len(strings_matched),
                "matched_strings": strings_matched if strings_matched else None,
            },
            "raw": match,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
