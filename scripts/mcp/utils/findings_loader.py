"""
Load and filter security findings from JMo scan results.

This module provides utilities for reading findings.json and applying
filters for MCP tool queries.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class FindingsLoader:
    """Load and filter findings from JMo scan results"""

    def __init__(self, results_dir: Path):
        """
        Initialize findings loader.

        Args:
            results_dir: Path to results directory (contains summaries/findings.json)

        Raises:
            FileNotFoundError: If findings.json doesn't exist
        """
        self.results_dir = Path(results_dir)
        self.findings_file = self.results_dir / "summaries" / "findings.json"

        if not self.findings_file.exists():
            raise FileNotFoundError(
                f"Findings file not found: {self.findings_file}\n"
                f"Run a scan first: jmo scan --repo <path>"
            )

    def load_findings(self) -> List[Dict[str, Any]]:
        """
        Load all findings from findings.json.

        Returns:
            List of finding dictionaries (CommonFinding schema v1.2.0)

        Raises:
            json.JSONDecodeError: If findings.json is invalid JSON
        """
        try:
            with open(self.findings_file, "r", encoding="utf-8") as f:
                findings = json.load(f)

            # findings.json is a list of findings
            if not isinstance(findings, list):
                raise ValueError("findings.json must contain a list of findings")

            logger.info(f"Loaded {len(findings)} findings from {self.findings_file}")
            return findings

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in findings file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading findings: {e}")
            raise

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        severity: Optional[List[str]] = None,
        tool: Optional[str] = None,
        rule_id: Optional[str] = None,
        path: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Filter findings based on criteria.

        Args:
            findings: List of findings to filter
            severity: Filter by severity levels (e.g., ["HIGH", "CRITICAL"])
            tool: Filter by tool name (e.g., "semgrep")
            rule_id: Filter by rule ID (e.g., "CWE-79")
            path: Filter by file path (substring match)
            limit: Maximum number of results (default: 100)
            offset: Pagination offset (default: 0)

        Returns:
            Filtered list of findings
        """
        filtered = findings

        # Filter by severity
        if severity:
            severity_set = {s.upper() for s in severity}
            filtered = [
                f for f in filtered if f.get("severity", "").upper() in severity_set
            ]

        # Filter by tool
        if tool:
            filtered = [
                f for f in filtered if f.get("tool", {}).get("name", "") == tool
            ]

        # Filter by rule ID
        if rule_id:
            filtered = [f for f in filtered if f.get("ruleId", "") == rule_id]

        # Filter by path (substring match)
        if path:
            filtered = [
                f for f in filtered if path in f.get("location", {}).get("path", "")
            ]

        # Get total before pagination
        total = len(filtered)

        # Apply pagination
        filtered = filtered[offset : offset + limit]

        logger.info(
            f"Filtered to {len(filtered)} findings (total matching: {total}, "
            f"limit: {limit}, offset: {offset})"
        )
        return filtered

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a single finding by fingerprint ID.

        Args:
            finding_id: Fingerprint ID of finding (e.g., "fingerprint-abc123")

        Returns:
            Finding dictionary or None if not found
        """
        findings = self.load_findings()
        for finding in findings:
            if finding.get("id") == finding_id:
                logger.info(f"Found finding: {finding_id}")
                return finding

        logger.warning(f"Finding not found: {finding_id}")
        return None

    def get_total_count(self) -> int:
        """
        Get total count of findings.

        Returns:
            Total number of findings
        """
        findings = self.load_findings()
        return len(findings)

    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Get distribution of findings by severity.

        Returns:
            Dictionary mapping severity → count
        """
        findings = self.load_findings()
        distribution: dict[str, int] = {}

        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            distribution[severity] = distribution.get(severity, 0) + 1

        return distribution
