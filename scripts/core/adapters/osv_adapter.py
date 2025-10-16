#!/usr/bin/env python3
"""
OSV-Scanner adapter: normalize OSV JSON to CommonFinding
Expected input: JSON from `osv-scanner --json ...` containing a top-level 'results' array with vulnerabilities.
This adapter focuses on essential fields: package, id, severity (via CVSS), affected file, and details.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint
from scripts.core.compliance_mapper import enrich_finding_with_compliance


SEV_FROM_CVSS: Dict[str, str] = {
    # Rough mapping; better to parse CVSS vector or score
}


def _cvss_to_sev(score: float | None) -> str:
    if score is None:
        return "MEDIUM"
    try:
        s = float(score)
    except Exception:
        return "MEDIUM"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "INFO"


def load_osv(path: str | Path) -> List[Dict[str, Any]]:
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
    for res in results:
        vulns = res.get("vulnerabilities") if isinstance(res, dict) else None
        pkg = (
            (res.get("packages") or [{}])[0].get("name")
            if isinstance(res, dict)
            else None
        )
        source = (
            (res.get("source") or {}).get("path") if isinstance(res, dict) else None
        )
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            vid = v.get("id") or v.get("aliases", ["OSV"])[0]
            summary = v.get("summary") or v.get("details") or vid
            score = None
            for s in v.get("severity") or []:
                try:
                    score = float(s.get("score"))
                    break
                except (TypeError, ValueError):
                    continue
            sev = _cvss_to_sev(score)
            path_str = source or ""
            msg = f"{vid} in {pkg or 'unknown'}: {summary}"
            fid = fingerprint("osv", str(vid), path_str, 0, msg)
            finding = {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": str(vid),
                "title": vid,
                "message": msg,
                "description": summary,
                "severity": sev,
                "tool": {
                    "name": "osv-scanner",
                    "version": str(data.get("version") or "unknown"),
                },
                "location": {"path": path_str, "startLine": 0},
                "remediation": "Update to a non-vulnerable version per advisory.",
                "tags": ["dependency", "vulnerability"],
                "risk": {"cwe": ["CWE-1104"]},
                "raw": v,
            }
            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)
    return out
