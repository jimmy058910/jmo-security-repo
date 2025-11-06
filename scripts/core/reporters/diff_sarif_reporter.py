"""SARIF 2.1.0 reporter for diff results.

Generates SARIF format for code scanning integration with GitHub/GitLab.
Uses baselineState and suppressions to represent diff categories.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.diff_engine import DiffResult

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def write_sarif_diff(diff: DiffResult, out_path: Path) -> None:
    """
    Write diff in SARIF 2.1.0 format for code scanning platforms.

    Args:
        diff: DiffResult object from DiffEngine
        out_path: Output file path for SARIF JSON

    SARIF Diff Representation:
    - New findings: baselineState = "new"
    - Resolved findings: baselineState = "absent" + suppressions
    - Modified findings: baselineState = "updated" + change details
    """
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JMo Security Diff",
                        "version": "1.0.0",
                        "informationUri": "https://jmotools.com",
                        "semanticVersion": "1.0.0",
                    }
                },
                "properties": {
                    "baseline": {
                        "source_type": diff.baseline_source.source_type,
                        "path": diff.baseline_source.path,
                        "timestamp": diff.baseline_source.timestamp,
                        "profile": diff.baseline_source.profile,
                        "total_findings": diff.baseline_source.total_findings,
                    },
                    "current": {
                        "source_type": diff.current_source.source_type,
                        "path": diff.current_source.path,
                        "timestamp": diff.current_source.timestamp,
                        "profile": diff.current_source.profile,
                        "total_findings": diff.current_source.total_findings,
                    },
                    "statistics": diff.statistics,
                },
                "results": [],
            }
        ],
    }

    # Add new findings (baselineState: "new")
    for finding in diff.new:
        sarif["runs"][0]["results"].append({  # type: ignore[index]
            "ruleId": finding.get("ruleId", "unknown"),
            "level": _map_severity_to_sarif(finding.get("severity")),  # type: ignore[arg-type]
            "message": {"text": f"{finding.get('message', '')} (NEW in current scan)"},
            "locations": [_convert_location_to_sarif(finding.get("location"))],  # type: ignore[arg-type]
            "baselineState": "new",
            "properties": {
                "diff_category": "new",
                "baseline_scan": diff.baseline_source.path,
                "current_scan": diff.current_source.path,
                "tool": finding.get("tool", {}),
            },
        })

    # Add resolved findings (baselineState: "absent", suppressed)
    for finding in diff.resolved:
        sarif["runs"][0]["results"].append({  # type: ignore[index]
            "ruleId": finding.get("ruleId", "unknown"),
            "level": _map_severity_to_sarif(finding.get("severity")),  # type: ignore[arg-type]
            "message": {"text": f"{finding.get('message', '')} (RESOLVED since baseline)"},
            "locations": [_convert_location_to_sarif(finding.get("location"))],  # type: ignore[arg-type]
            "baselineState": "absent",
            "suppressions": [
                {
                    "kind": "inSource",
                    "status": "accepted",
                    "justification": "Resolved in current scan",
                }
            ],
            "properties": {
                "diff_category": "resolved",
                "tool": finding.get("tool", {}),
            },
        })

    # Add modified findings (baselineState: "updated")
    for mod in diff.modified:
        # Build change description
        change_desc = ", ".join(
            f"{k}: {v[0]} → {v[1]}" if isinstance(v, list) and len(v) == 2
            else f"{k}: {v}"
            for k, v in mod.changes.items()
        )

        sarif["runs"][0]["results"].append({  # type: ignore[index]
            "ruleId": mod.current.get("ruleId", "unknown"),
            "level": _map_severity_to_sarif(mod.current.get("severity")),  # type: ignore[arg-type]
            "message": {"text": f"{mod.current.get('message', '')} (MODIFIED: {change_desc})"},
            "locations": [_convert_location_to_sarif(mod.current.get("location"))],  # type: ignore[arg-type]
            "baselineState": "updated",
            "properties": {
                "diff_category": "modified",
                "changes": mod.changes,
                "risk_delta": mod.risk_delta,
                "baseline_severity": mod.baseline.get("severity"),
                "current_severity": mod.current.get("severity"),
                "tool": mod.current.get("tool", {}),
            },
        })

    # Write to file
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")


def _map_severity_to_sarif(severity: str) -> str:
    """
    Map CommonFinding severity to SARIF level.

    Args:
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO

    Returns:
        SARIF level: error, warning, or note
    """
    sev = (severity or "INFO").upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _convert_location_to_sarif(location: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert CommonFinding location to SARIF physicalLocation.

    Args:
        location: CommonFinding location dict

    Returns:
        SARIF physicalLocation object
    """
    if not location:
        location = {}

    result = {
        "physicalLocation": {
            "artifactLocation": {"uri": location.get("path", "unknown")},
            "region": {"startLine": location.get("startLine", 1)},
        }
    }

    # Add endLine if available
    if location.get("endLine"):
        result["physicalLocation"]["region"]["endLine"] = location["endLine"]

    # Add startColumn if available
    if location.get("startColumn"):
        result["physicalLocation"]["region"]["startColumn"] = location["startColumn"]

    # Add endColumn if available
    if location.get("endColumn"):
        result["physicalLocation"]["region"]["endColumn"] = location["endColumn"]

    return result
