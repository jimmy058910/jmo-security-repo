#!/usr/bin/env python3
"""
yara-x adapter - Maps the yara-x runner's JSON matches to the CommonFinding schema.

The input is what `scripts/core/yara_runner.py` writes: one object per match,
with the rule's metadata, the matched pattern identifiers and the file. The
rules are Neo23x0/signature-base's, under the Detection Rule License 1.1, which
requires each rule's author (and its reference, when it has one) with what it
detects: both reach the finding's context and its message.

Output Format: JSON array of matches
Exit Codes: 0 (no matches), 1 (matches found), 2 (did not scan)

Supported Detection Categories:
- Web shells (PHP, ASPX, JSP)
- Backdoors and trojans
- APT indicators
- Cryptominers and ransomware
- Exploits and vulnerabilities
"""

from __future__ import annotations

import importlib.metadata
import logging
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

# Configure logging
logger = logging.getLogger(__name__)


@adapter_plugin(
    PluginMetadata(
        name="yara_x",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for the yara-x malware detection scanner",
        tool_name="yara-x",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "matches"},
    )
)
class YaraXAdapter(AdapterPlugin):
    """Adapter for yara-x malware detection (plugin architecture).

    Findings are tagged 'malware-detection', with each rule's own tags beside.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to the yara-x.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_yara_x_internal(output_path)

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


def _text(value: Any) -> str:
    """A metadata value as text. The runner hands a key a rule repeats over as
    a list of its values."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    return "" if value is None else str(value)


def _engine_version() -> str:
    try:
        return importlib.metadata.version("yara-x")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _load_yara_x_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse the yara-x runner's JSON output.

    Args:
        path: Path to the yara-x.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    data = safe_load_json_file(path, default=None)
    if data is None:
        return []

    out: list[dict[str, Any]] = []
    version = _engine_version()

    # The runner writes an array of
    # {"rule", "namespace", "tags", "meta", "strings", "file"}; one bare
    # object is read as an array of one.

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
        description = _text(meta.get("description")) or rule_name
        author = _text(meta.get("author"))
        ref_value = meta.get("reference")
        refs = [
            str(r)
            for r in (ref_value if isinstance(ref_value, list) else [ref_value])
            if r
        ]
        reference = ", ".join(refs)

        # Determine severity from rule tags and metadata
        severity_raw = str(meta.get("severity", "")).upper()
        if not severity_raw:
            # Infer severity from tags
            if any(
                tag.lower() in ["critical", "apt", "ransomware", "backdoor"]
                for tag in rule_tags
            ):
                severity_raw = "CRITICAL"
            elif any(
                tag.lower() in ["high", "webshell", "trojan", "exploit"]
                for tag in rule_tags
            ):
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

        # Build message. DRL 1.1: the rule's author, and its reference when it
        # has one, travel with what it detects (decision 5).
        message = f"YARA rule '{rule_name}' matched: {description}"
        if strings_matched:
            message += f" ({len(strings_matched)} string matches)"
        if author:
            message += f". Rule by {author}"
            if reference:
                message += f" ({reference})"
        elif reference:
            message += f". Rule reference: {reference}"

        # Generate stable fingerprint
        fid = fingerprint("yara-x", rule_name, file_path, 0, message)

        # Build tags (combine tool-specific and rule-specific tags)
        tags = ["malware-detection", "yara-x"]
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
            "tool": {"name": "yara-x", "version": version},
            "location": {
                "path": file_path,
                "startLine": 0,  # Binary files don't have line numbers
            },
            "remediation": f"Review file for malware indicators. YARA rule '{rule_name}' detected malicious patterns.",
            "references": refs,
            "tags": tags,
            "context": {
                "rule_name": rule_name,
                "namespace": namespace,
                "author": author or None,
                "reference": reference or None,
                "rule_tags": rule_tags,
                "matched_strings_count": len(strings_matched),
                "matched_strings": strings_matched or None,
            },
            "raw": match,
        }

        out.append(finding)

    return out
