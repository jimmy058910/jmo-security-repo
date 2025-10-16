#!/usr/bin/env python3
"""
tfsec adapter: normalize tfsec JSON output to CommonFinding
Expected input includes a top-level "results" list
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_tfsec(path: str | Path) -> List[Dict[str, Any]]:
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
    for it in results:
        if not isinstance(it, dict):
            continue
        rid = str(it.get("rule_id") or it.get("id") or "TFSEC")
        file_path = str(
            (it.get("location") or {}).get("filename") or it.get("filename") or ""
        )
        line = int(
            (it.get("location") or {}).get("start_line") or it.get("start_line") or 0
        )
        msg = str(it.get("description") or it.get("impact") or rid)
        sev = normalize_severity(it.get("severity") or "MEDIUM")
        fid = fingerprint("tfsec", rid, file_path, line, msg)
        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": rid,
            "title": rid,
            "message": msg,
            "description": str(it.get("resolution") or msg),
            "severity": sev,
            "tool": {
                "name": "tfsec",
                "version": str(data.get("version") or "unknown"),
            },
            "location": {"path": file_path, "startLine": line},
            "remediation": str(it.get("resolution") or "Review resolution guidance"),
            "tags": ["iac", "terraform"],
            "raw": it,
        }
        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)
    return out
