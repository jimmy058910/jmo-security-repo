"""
{Tool} adapter - Maps {tool} JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

Tool Version: {version}
Output Format: {format_summary}
Exit Codes: {exit_code_mapping}

Common Pitfalls (from memory):
{list_of_pitfalls}
"""

import json
import logging
from pathlib import Path
from typing import List, Optional

# REQUIRED: Import plugin system
from scripts.core.plugin_api import (
    AdapterPlugin,
    PluginMetadata,
    Finding,
    adapter_plugin
)

logger = logging.getLogger(__name__)


@adapter_plugin(PluginMetadata(
    name="{tool}",  # CRITICAL: Must match {tool}.json filename
    version="1.0.0",
    author="JMo Security Contributors",
    description="{tool} adapter for JMo Security",
    tool_name="{tool}",
    schema_version="1.2.0",
    output_format="json",
    exit_codes={
        "0": "clean",
        "1": "findings",
        "2": "error"
    }
))
class {Tool}Adapter(AdapterPlugin):
    """{Tool} scanner adapter.

    Parses {tool} JSON output and converts to CommonFinding schema.

    Supported Output Format: {format_description}
    Exit Codes:
        0: No findings (clean scan)
        1: Findings detected
        2: Tool error (malformed input, missing flags, etc.)
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata.

        Required by AdapterPlugin base class.
        """
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse {tool} output and return findings.

        Args:
            output_path: Path to {tool} JSON output file

        Returns:
            List of Finding objects (CommonFinding schema v1.2.0)

        Raises:
            No exceptions raised - errors logged and empty list returned
        """
        if not output_path.exists():
            logger.debug(f"{tool} output not found: {output_path}")
            return []

        try:
            data = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            # Common Pitfall: Missing --json flag
            logger.warning(f"{self.metadata.tool_name} output malformed: {e}")
            return []

        findings = []

        # Extract vulnerabilities from {tool} format
        # (Schema learned from Phase 1 or memory)
        for result in data.get("results", []):
            for vuln in result.get("vulnerabilities", []):
                # Use Finding dataclass (NOT dict!)
                finding = Finding(
                    schemaVersion="1.2.0",
                    id=self.get_fingerprint(
                        tool=self.metadata.tool_name,
                        ruleId=vuln.get("id", "UNKNOWN"),
                        path=vuln.get("file", ""),
                        startLine=vuln.get("line", 0),
                        message=vuln.get("title", "")[:120]
                    ),
                    ruleId=vuln.get("id", "UNKNOWN"),
                    severity=self._map_severity(vuln.get("severity", "info")),
                    tool={
                        "name": self.metadata.tool_name,
                        "version": self.metadata.version
                    },
                    location={
                        "path": vuln.get("file", ""),
                        "startLine": vuln.get("line", 0),
                        "endLine": vuln.get("line", 0)
                    },
                    message=vuln.get("title", ""),
                    description=vuln.get("description", ""),
                    remediation=vuln.get("remediation", ""),
                    references=vuln.get("references", []),
                    cvss={
                        "score": vuln.get("cvssScore", 0.0),
                        "vector": vuln.get("cvssVector", "")
                    } if vuln.get("cvssScore") else None,
                    # Note: Compliance enrichment is handled centrally in
                    # normalize_and_report.py via enrich_findings_with_compliance()
                    # Adapters should NOT call enrichment - just return raw findings
                    raw=vuln  # Original tool payload for debugging
                )
                findings.append(finding)

        logger.info(f"{self.metadata.tool_name}: parsed {len(findings)} findings")
        return findings

    def _map_severity(self, severity: str) -> str:
        """Map {tool} severity to CommonFinding severity.

        Args:
            severity: Tool-specific severity string

        Returns:
            Normalized severity: CRITICAL, HIGH, MEDIUM, LOW, INFO

        Note:
            Use map_tool_severity() from common_finding.py for tools with
            custom severity levels - add mappings to TOOL_SEVERITY_MAPPINGS.
        """
        mapping = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "informational": "INFO"
        }
        return mapping.get(severity.lower(), "INFO")

    # NOTE: Compliance enrichment removed from adapters (Scenario 8 optimization)
    # All findings are enriched centrally in normalize_and_report.py via
    # enrich_findings_with_compliance() after collection and deduplication.
    # This single-pass batch operation is more efficient than 29 individual calls.
