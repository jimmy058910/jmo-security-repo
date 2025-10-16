#!/usr/bin/env python3
"""
Trivy adapter: normalize Trivy JSON to CommonFinding
Supports filesystem scan output (trivy fs -f json .) and generic Results array.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import (
    extract_code_snippet,
    fingerprint,
    normalize_severity,
)
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_trivy(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    results = data.get("Results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []

    out: List[Dict[str, Any]] = []
    for r in results:
        target = r.get("Target") or ""
        vulns = r.get("Vulnerabilities")
        secrets = r.get("Secrets")
        misconfigs = r.get("Misconfigurations")
        for arr, tag in (
            (vulns, "vulnerability"),
            (secrets, "secret"),
            (misconfigs, "misconfig"),
        ):
            if not isinstance(arr, list):
                continue
            for item in arr:
                rule_id = (
                    item.get("VulnerabilityID")
                    or item.get("Title")
                    or item.get("RuleID")
                    or tag
                )
                msg = item.get("Title") or item.get("Description") or tag
                severity = normalize_severity(item.get("Severity"))
                path_str = item.get("Target") or target or ""
                line = item.get("StartLine") or 0
                fid = fingerprint(
                    "trivy",
                    str(rule_id),
                    str(path_str),
                    int(line) if isinstance(line, int) else 0,
                    str(msg),
                )

                # Code context (for misconfigurations)
                context = None
                if tag == "misconfig" and path_str and line:
                    context = extract_code_snippet(
                        str(path_str), int(line), context_lines=2
                    )

                # Risk metadata for vulnerabilities
                risk = {}
                if tag == "vulnerability":
                    cvss_dict = item.get("CVSS", {})
                    if isinstance(cvss_dict, dict):
                        # Extract CWE
                        cwe_ids = item.get("CweIDs", [])
                        if cwe_ids and isinstance(cwe_ids, list):
                            risk["cwe"] = cwe_ids

                finding: Dict[str, Any] = {
                    "schemaVersion": "1.1.0",
                    "id": fid,
                    "ruleId": str(rule_id),
                    "title": str(rule_id),
                    "message": str(msg),
                    "description": str(item.get("Description") or msg),
                    "severity": severity,
                    "tool": {
                        "name": "trivy",
                        "version": str(data.get("Version") or "unknown"),
                    },
                    "location": {
                        "path": str(path_str),
                        "startLine": int(line) if isinstance(line, int) else 0,
                    },
                    "remediation": str(item.get("PrimaryURL") or "See advisory"),
                    "tags": [tag],
                    "raw": item,
                }

                # Add optional v1.1.0 fields if present
                if context:
                    finding["context"] = context
                if risk:
                    finding["risk"] = risk

                # Enrich with compliance framework mappings
                finding = enrich_finding_with_compliance(finding)
                out.append(finding)
    return out
