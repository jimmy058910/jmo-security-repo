"""
Base Adapter for Tool Output Normalization

This module provides the BaseAdapter abstract class that all tool adapters
should inherit from. It enforces:
- Consistent schema versioning
- Standardized fingerprinting for deduplication
- Common loading interface
- Tool name/version metadata

Usage:
    class MyToolAdapter(BaseAdapter):
        def __init__(self):
            super().__init__("mytool", "1.0.0")

        def _parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
            # Parse tool-specific JSON format
            ...

        def _extract_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
            # Map to CommonFinding schema
            ...
"""

import hashlib
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from ..constants import (
    SCHEMA_VERSION_CURRENT,
    FINGERPRINT_MESSAGE_MAX_LENGTH,
    FINGERPRINT_HASH_LENGTH,
)

# Re-export for backward compatibility
CURRENT_SCHEMA_VERSION = SCHEMA_VERSION_CURRENT


class BaseAdapter(ABC):
    """
    Abstract base class for all tool adapters.

    Provides:
    - Consistent schema versioning
    - Stable fingerprinting for deduplication
    - Common loading interface
    - Tool metadata injection

    Subclasses must implement:
    - _parse_output(): Parse tool-specific JSON
    - _extract_finding(): Map to CommonFinding schema
    """

    def __init__(self, tool_name: str, tool_version: str = "unknown"):
        """
        Initialize adapter with tool metadata.

        Args:
            tool_name: Name of the security tool (e.g., "trivy", "semgrep")
            tool_version: Version of the tool (e.g., "0.67.2")
        """
        self.tool_name = tool_name
        self.tool_version = tool_version

    def load(self, output_file: Path) -> List[Dict[str, Any]]:
        """
        Load tool output and convert to CommonFinding format.

        This is the main entry point for all adapters. It:
        1. Checks if output file exists
        2. Parses tool-specific output
        3. Extracts findings into CommonFinding format
        4. Generates stable fingerprint IDs
        5. Injects schema version and tool metadata

        Args:
            output_file: Path to tool output file (JSON)

        Returns:
            List of CommonFinding dictionaries with schema v1.2.0
        """
        if not output_file.exists():
            return []

        # Parse tool-specific output
        raw_findings = self._parse_output(output_file)
        common_findings = []

        for raw in raw_findings:
            # Extract finding into CommonFinding format
            finding = self._extract_finding(raw)

            # Generate stable fingerprint for deduplication
            finding["id"] = self._generate_fingerprint(finding)

            # Inject schema version
            finding["schemaVersion"] = CURRENT_SCHEMA_VERSION

            # Inject tool metadata
            finding["tool"] = {
                "name": self.tool_name,
                "version": self.tool_version,
            }

            # Store raw finding for debugging (optional)
            if "raw" not in finding:
                finding["raw"] = raw

            common_findings.append(finding)

        return common_findings

    @abstractmethod
    def _parse_output(self, output_file: Path) -> List[Dict[str, Any]]:
        """
        Parse tool-specific JSON output.

        This method should load the JSON file and extract the raw findings
        in their native format. No normalization should happen here.

        Args:
            output_file: Path to tool output file

        Returns:
            List of raw finding dictionaries in tool's native format

        Example:
            def _parse_output(self, output_file: Path):
                with open(output_file) as f:
                    data = json.load(f)
                return data.get("results", [])
        """
        pass

    @abstractmethod
    def _extract_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract CommonFinding fields from raw finding.

        This method should map the tool-specific finding format to the
        CommonFinding schema defined in docs/schemas/common_finding.v1.json.

        Required CommonFinding fields:
        - ruleId: str
        - severity: str (CRITICAL|HIGH|MEDIUM|LOW|INFO)
        - message: str
        - location: dict with path, startLine, endLine

        Optional CommonFinding fields:
        - title: str
        - description: str
        - remediation: str
        - references: list[str]
        - tags: list[str]
        - cvss: dict
        - risk: dict (CWE, confidence, likelihood, impact)
        - compliance: dict (6 frameworks)
        - context: dict

        Args:
            raw: Raw finding dictionary in tool's native format

        Returns:
            CommonFinding dictionary (without id, schemaVersion, tool)

        Example:
            def _extract_finding(self, raw):
                return {
                    "ruleId": raw["check_id"],
                    "severity": self._map_severity(raw["severity"]),
                    "message": raw["message"],
                    "location": {
                        "path": raw["path"],
                        "startLine": raw["start"]["line"],
                        "endLine": raw["end"]["line"],
                    }
                }
        """
        pass

    def _generate_fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Generate stable fingerprint ID for deduplication.

        The fingerprint is generated from:
        - Tool name
        - Rule ID
        - File path
        - Start line number
        - Message (first 120 chars)

        This ensures the same finding across multiple scans gets the same ID,
        enabling deduplication and tracking fixes over time.

        Args:
            finding: CommonFinding dictionary

        Returns:
            16-character hex fingerprint (SHA256 truncated)
        """
        parts = [
            self.tool_name,
            finding.get("ruleId", ""),
            finding.get("location", {}).get("path", ""),
            str(finding.get("location", {}).get("startLine", 0)),
            finding.get("message", "")[:FINGERPRINT_MESSAGE_MAX_LENGTH],
        ]
        fingerprint_str = "|".join(parts)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[
            :FINGERPRINT_HASH_LENGTH
        ]

    def _map_severity(self, tool_severity: str) -> str:
        """
        Map tool-specific severity to CommonFinding severity.

        CommonFinding severity levels:
        - CRITICAL: Immediate action required
        - HIGH: High priority
        - MEDIUM: Medium priority
        - LOW: Low priority
        - INFO: Informational

        Args:
            tool_severity: Tool-specific severity string

        Returns:
            CommonFinding severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)
        """
        severity_upper = str(tool_severity).upper()

        # Direct matches
        if severity_upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            return severity_upper

        # Common aliases
        severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "WARN": "MEDIUM",
            "NOTE": "LOW",
            "INFORMATIONAL": "INFO",
            "INFORMATION": "INFO",
        }

        return severity_map.get(severity_upper, "INFO")


def load_json_file(path: Path) -> Dict[str, Any]:
    """
    Helper function to load JSON file safely.

    Args:
        path: Path to JSON file

    Returns:
        Parsed JSON as dictionary

    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    with open(path, encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)
        return data
