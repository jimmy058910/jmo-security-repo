#!/usr/bin/env python3
"""
Nuclei adapter: normalize Nuclei JSON to CommonFinding schema.

Expected input: JSON output from 'nuclei -json' command.
Output schema: CommonFinding v1.2.0 with compliance enrichment.

Tool version tested: v3.3.7+
Last updated: 2025-01-19

Nuclei is a fast vulnerability scanner based on simple YAML templates.
It excels at detecting CVEs, misconfigurations, and security issues across
web applications, APIs, and cloud configurations.

Output format: NDJSON (newline-delimited JSON)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def _nuclei_severity_to_severity(severity: str) -> str:
    """Map Nuclei severity to CommonFinding severity.

    Nuclei uses: info, low, medium, high, critical, unknown
    CommonFinding uses: INFO, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    """
    severity_map = {
        "info": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
        "unknown": "UNKNOWN",
    }
    return severity_map.get(severity.lower(), "UNKNOWN")


def load_nuclei(path: str | Path) -> List[Dict[str, Any]]:
    """Load and normalize Nuclei findings to CommonFinding schema.

    Args:
        path: Path to nuclei.json output file (NDJSON format)

    Returns:
        List of CommonFinding dictionaries (schema v1.2.0)

    Error Handling:
        - Returns [] if file doesn't exist
        - Returns [] if file is empty
        - Skips malformed JSON lines (NDJSON format)
    """
    p = Path(path)
    if not p.exists():
        return []

    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []

    out: List[Dict[str, Any]] = []

    # Nuclei outputs NDJSON (one JSON object per line)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue  # Skip empty lines

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue  # Skip malformed lines

        if not isinstance(item, dict):
            continue

        # Extract required fields
        # Nuclei structure:
        # {
        #   "template-id": "CVE-2021-44228",
        #   "info": {
        #     "name": "Apache Log4j RCE",
        #     "severity": "critical",
        #     "description": "...",
        #     "reference": ["https://..."],
        #     "classification": {
        #       "cve-id": ["CVE-2021-44228"],
        #       "cwe-id": ["CWE-502"]
        #     },
        #     "tags": ["cve", "log4j", "rce"]
        #   },
        #   "matched-at": "https://example.com/api",
        #   "matcher-name": "...",
        #   "type": "http"
        # }

        template_id = str(
            item.get("template-id") or item.get("templateID") or "UNKNOWN"
        )
        info = item.get("info", {})
        if not isinstance(info, dict):
            info = {}

        name = info.get("name") or template_id
        description = info.get("description") or name
        severity_raw = info.get("severity") or "MEDIUM"
        severity = _nuclei_severity_to_severity(severity_raw)

        # Location: matched URL
        matched_at = item.get("matched-at") or item.get("matched") or ""
        host = item.get("host") or ""
        url = matched_at or host or ""

        # Use matcher-name for additional context
        matcher_name = item.get("matcher-name") or ""
        if matcher_name:
            msg = f"{name} (matcher: {matcher_name})"
        else:
            msg = name

        # Generate stable fingerprint
        # For web findings, use URL instead of file path
        fid = fingerprint("nuclei", template_id, url, 0, msg)

        finding: Dict[str, Any] = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": template_id,
            "title": name,
            "message": msg,
            "description": description,
            "severity": severity,
            "tool": {
                "name": "nuclei",
                "version": str(item.get("version") or "unknown"),
            },
            "location": {
                "path": url,  # Use URL as "path" for web findings
                "startLine": 0,  # Web findings don't have line numbers
            },
            "tags": ["dast", "web-security", "api-security"],
            "raw": item,
        }

        # Extract remediation if available
        remediation = info.get("remediation")
        if remediation:
            finding["remediation"] = remediation
        else:
            finding["remediation"] = (
                "Review finding and apply vendor-recommended fixes."
            )

        # Extract CWE IDs from classification
        risk = {}
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cwe_ids = classification.get("cwe-id") or classification.get("cwe")
            if cwe_ids:
                if isinstance(cwe_ids, list):
                    risk["cwe"] = [str(c) for c in cwe_ids]
                elif isinstance(cwe_ids, str):
                    risk["cwe"] = [cwe_ids]

            # Extract CVE IDs (not part of risk object, but useful for references)
            cve_ids = classification.get("cve-id") or classification.get("cve")
            if cve_ids and not finding.get("references"):
                refs = []
                if isinstance(cve_ids, list):
                    refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cve_ids]
                elif isinstance(cve_ids, str):
                    refs = [f"https://nvd.nist.gov/vuln/detail/{cve_ids}"]
                if refs:
                    finding["references"] = refs

        # Add references from info
        if info.get("reference") and not finding.get("references"):
            refs = info["reference"]
            if isinstance(refs, list):
                finding["references"] = [str(r) for r in refs]
            elif isinstance(refs, str):
                finding["references"] = [refs]

        # Add tags from info
        if info.get("tags"):
            tags = info["tags"]
            if isinstance(tags, list):
                finding["tags"].extend([str(t) for t in tags])
            elif isinstance(tags, str):
                finding["tags"].append(tags)

        if risk:
            finding["risk"] = risk

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)

        out.append(finding)

    return out
