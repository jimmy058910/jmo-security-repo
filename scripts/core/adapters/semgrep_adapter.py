#!/usr/bin/env python3
"""
Semgrep adapter: normalize Semgrep JSON to CommonFinding
Expected input shape often contains {"results": [ ... ]}
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


SEMGREP_TO_SEV = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def load_semgrep(path: str | Path) -> List[Dict[str, Any]]:
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

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []

    out: List[Dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        check_id = str(r.get("check_id") or r.get("ruleId") or r.get("id") or "SEMGR")
        msg = (
            (r.get("extra") or {}).get("message")
            or r.get("message")
            or "Semgrep finding"
        )
        sev_raw = (r.get("extra") or {}).get("severity") or r.get("severity")
        sev_norm = SEMGREP_TO_SEV.get(str(sev_raw).upper(), None)
        severity = normalize_severity(sev_norm or str(sev_raw))
        path_str = r.get("path") or (r.get("location") or {}).get("path") or ""
        start_line = 0
        if isinstance(r.get("start"), dict) and isinstance(r["start"].get("line"), int):
            start_line = r["start"]["line"]
        else:
            line_val = (r.get("start") or {}).get("line")
            if isinstance(line_val, int):
                start_line = line_val
        loc = r.get("location")
        if (
            isinstance(loc, dict)
            and isinstance(loc.get("start"), dict)
            and isinstance(loc["start"].get("line"), int)
        ):
            start_line = loc["start"]["line"]
        fid = fingerprint("semgrep", check_id, path_str, start_line, msg)

        # Extract v1.1.0 fields
        extra = r.get("extra", {})

        # Remediation with autofix
        remediation: str | dict[str, Any] = "Review and remediate per rule guidance."
        autofix = extra.get("fix")
        if autofix:
            remediation = {
                "summary": msg,
                "fix": autofix,
                "steps": [
                    "Apply the suggested fix above",
                    "Test the changes",
                    "Commit the fix",
                ],
            }

        # Risk metadata (CWE, OWASP, confidence)
        risk = {}
        metadata = extra.get("metadata", {})
        if metadata:
            # CWE
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, list) and cwe_list:
                risk["cwe"] = cwe_list
            elif isinstance(cwe_list, str):
                risk["cwe"] = [cwe_list]

            # OWASP
            owasp = metadata.get("owasp", [])
            if isinstance(owasp, list) and owasp:
                risk["owasp"] = owasp
            elif isinstance(owasp, str):
                risk["owasp"] = [owasp]

            # Confidence
            confidence = metadata.get("confidence", "").upper()
            if confidence in ["HIGH", "MEDIUM", "LOW"]:
                risk["confidence"] = confidence

            # Likelihood/Impact
            likelihood = metadata.get("likelihood", "").upper()
            if likelihood in ["HIGH", "MEDIUM", "LOW"]:
                risk["likelihood"] = likelihood
            impact = metadata.get("impact", "").upper()
            if impact in ["HIGH", "MEDIUM", "LOW"]:
                risk["impact"] = impact

        # Code context
        context = None
        if path_str and start_line:
            context = extract_code_snippet(path_str, start_line, context_lines=2)

        finding: Dict[str, Any] = {
            "schemaVersion": "1.1.0",
            "id": fid,
            "ruleId": check_id,
            "title": check_id,
            "message": msg,
            "description": msg,
            "severity": severity,
            "tool": {
                "name": "semgrep",
                "version": str(
                    (data.get("version") if isinstance(data, dict) else None)
                    or "unknown"
                ),
            },
            "location": {"path": path_str, "startLine": start_line},
            "remediation": remediation,
            "tags": ["sast"],
            "raw": r,
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
