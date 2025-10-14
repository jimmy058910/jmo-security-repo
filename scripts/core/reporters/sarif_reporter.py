#!/usr/bin/env python3
"""SARIF 2.1.0 reporter with enriched metadata.

Generates SARIF (Static Analysis Results Interchange Format) output
with code snippets, fix suggestions, and taxonomy mappings where available.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

SARIF_VERSION = "2.1.0"


def to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert normalized findings to SARIF 2.1.0 format.

    Args:
        findings: List of CommonFinding dictionaries

    Returns:
        SARIF document as dict
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results = []

    for f in findings:
        rule_id = f.get("ruleId", "rule")

        # Enhanced rule metadata
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f.get("title") or rule_id,
                "shortDescription": {"text": f.get("message", "")},
                "fullDescription": {"text": f.get("description", "")},
                "help": {
                    "text": f.get("remediation", "See rule documentation"),
                    "markdown": f.get("remediation", "See rule documentation"),
                },
                "properties": {
                    "tags": f.get("tags", []),
                    "precision": "high",
                },
            },
        )

        # Build location with optional snippet
        location_obj = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.get("location", {}).get("path", "")},
                "region": {
                    "startLine": f.get("location", {}).get("startLine", 0),
                },
            }
        }

        # Add code snippet if available in context
        if f.get("context", {}).get("snippet"):
            location_obj["physicalLocation"]["region"]["snippet"] = {
                "text": f["context"]["snippet"]
            }

        # End line if available
        if f.get("location", {}).get("endLine"):
            location_obj["physicalLocation"]["region"]["endLine"] = f["location"][
                "endLine"
            ]

        result = {
            "ruleId": rule_id,
            "message": {"text": f.get("message", "")},
            "level": _severity_to_level(f.get("severity")),
            "locations": [location_obj],
        }

        # Add fix suggestions if available
        remediation = f.get("remediation")
        if remediation and isinstance(remediation, str) and len(remediation) > 0:
            result["fixes"] = [
                {
                    "description": {"text": remediation},
                }
            ]

        # Add CWE/OWASP/CVE taxonomy if present in tags
        taxa = []
        for tag in f.get("tags", []):
            tag_str = str(tag).upper()
            if tag_str.startswith("CWE-"):
                taxa.append(
                    {
                        "id": tag_str,
                        "toolComponent": {"name": "CWE"},
                    }
                )
            elif tag_str.startswith("OWASP-"):
                taxa.append(
                    {
                        "id": tag_str,
                        "toolComponent": {"name": "OWASP"},
                    }
                )
            elif tag_str.startswith("CVE-"):
                taxa.append(
                    {
                        "id": tag_str,
                        "toolComponent": {"name": "CVE"},
                    }
                )
        if taxa:
            result["taxa"] = taxa

        # Add CVSS score if present
        if f.get("cvss"):
            if "properties" not in result:
                result["properties"] = {}
            result["properties"]["cvss"] = f["cvss"]

        results.append(result)

    # Read version from pyproject.toml if possible
    version = "0.4.0"  # Default
    try:
        import tomli

        pyproject_path = Path(__file__).parent.parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as fp:
                pyproject = tomli.load(fp)
                version = pyproject.get("project", {}).get("version", version)
    except Exception:
        pass

    tool = {
        "driver": {
            "name": "jmo-security",
            "informationUri": "https://github.com/jimmy058910/jmo-security-repo",
            "version": version,
            "rules": list(rules.values()),
        }
    }

    return {
        "version": SARIF_VERSION,
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{"tool": tool, "results": results}],
    }


def _severity_to_level(sev: str | None) -> str:
    """Map severity to SARIF level.

    Args:
        sev: Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    Returns:
        SARIF level: error, warning, or note
    """
    s = (sev or "INFO").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def write_sarif(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    """Write findings to SARIF 2.1.0 JSON file.

    Args:
        findings: List of normalized findings
        out_path: Output file path
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    sarif = to_sarif(findings)
    p.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
